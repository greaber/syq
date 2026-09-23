//! macOS ACLs use ordered UUID-based entries, independently of POSIX mode bits.
//! Transfer explicit values and rebuild through the public ACL API; no native
//! pointer or internal ACL structure crosses the wire.
use super::{MacAce, MacAcl};
use anyhow::{ensure, Context, Result};
use std::{ffi::c_void, fs::File, io, os::fd::AsRawFd, ptr};

type Acl = *mut c_void;
const EXTENDED: libc::c_int = 0x100;
const MAX_ENTRIES: usize = 128;
const ACL_FLAGS: u32 = 1 | (1 << 17);
const ENTRY_FLAGS: u32 = 0x1f0;

unsafe extern "C" {
    fn filesec_init() -> *mut c_void;
    fn filesec_free(security: *mut c_void);
    fn filesec_set_property(
        security: *mut c_void,
        property: libc::c_int,
        value: *const c_void,
    ) -> libc::c_int;
    fn fchmodx_np(fd: libc::c_int, security: *mut c_void) -> libc::c_int;
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> Acl;
    fn acl_set_fd_np(fd: libc::c_int, acl: Acl, kind: libc::c_int) -> libc::c_int;
    fn acl_init(count: libc::c_int) -> Acl;
    fn acl_free(object: *mut c_void) -> libc::c_int;
    fn acl_get_entry(acl: Acl, index: libc::c_int, entry: *mut Acl) -> libc::c_int;
    fn acl_create_entry(acl: *mut Acl, entry: *mut Acl) -> libc::c_int;
    fn acl_get_tag_type(entry: Acl, tag: *mut u32) -> libc::c_int;
    fn acl_set_tag_type(entry: Acl, tag: u32) -> libc::c_int;
    fn acl_get_qualifier(entry: Acl) -> *mut c_void;
    fn acl_set_qualifier(entry: Acl, principal: *const c_void) -> libc::c_int;
    fn acl_get_permset_mask_np(entry: Acl, mask: *mut u64) -> libc::c_int;
    fn acl_set_permset_mask_np(entry: Acl, mask: u64) -> libc::c_int;
    fn acl_get_flagset_np(object: Acl, flags: *mut Acl) -> libc::c_int;
    fn acl_get_flag_np(flags: Acl, flag: libc::c_int) -> libc::c_int;
    fn acl_clear_flags_np(flags: Acl) -> libc::c_int;
    fn acl_add_flag_np(flags: Acl, flag: libc::c_int) -> libc::c_int;
}

struct OwnedAcl(Acl);
impl Drop for OwnedAcl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}
fn checked(result: libc::c_int, what: &'static str) -> Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error()).context(what)
    } else {
        Ok(())
    }
}
fn get_flags(object: Acl) -> Result<u32> {
    let mut set = ptr::null_mut();
    checked(
        unsafe { acl_get_flagset_np(object, &mut set) },
        "read macOS ACL flags",
    )?;
    let mut value = 0;
    // Reading all bits prevents new flags from being silently dropped. An
    // unsupported flag is rejected when constructing the destination ACL.
    for bit in 0..32 {
        let flag = 1u32 << bit;
        let present = unsafe { acl_get_flag_np(set, flag as _) };
        checked(present, "read macOS ACL flag")?;
        if present != 0 {
            value |= flag;
        }
    }
    Ok(value)
}
fn set_flags(object: Acl, value: u32, allowed: u32) -> Result<()> {
    ensure!(
        value & !allowed == 0,
        "unsupported macOS ACL flags: {value:#x}"
    );
    let mut set = ptr::null_mut();
    checked(
        unsafe { acl_get_flagset_np(object, &mut set) },
        "access macOS ACL flags",
    )?;
    checked(unsafe { acl_clear_flags_np(set) }, "clear macOS ACL flags")?;
    if value != 0 {
        checked(
            unsafe { acl_add_flag_np(set, value as _) },
            "set macOS ACL flags",
        )?;
    }
    Ok(())
}

pub(super) fn read(file: &File) -> Result<MacAcl> {
    let raw = unsafe { acl_get_fd_np(file.as_raw_fd(), EXTENDED) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(MacAcl::default());
        }
        return Err(error).context("read macOS ACL on held inode");
    }
    let acl = OwnedAcl(raw);
    let mut result = MacAcl {
        flags: get_flags(acl.0)?,
        entries: Vec::new(),
    };
    for index in 0..=MAX_ENTRIES {
        let mut entry = ptr::null_mut();
        if unsafe { acl_get_entry(acl.0, index as _, &mut entry) } == -1 {
            let error = io::Error::last_os_error();
            // Darwin returns EINVAL at the end, unlike the POSIX iterator.
            if error.raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(error).context("read macOS ACL entry");
        }
        ensure!(index < MAX_ENTRIES, "macOS ACL exceeds 128 entries");
        let mut tag = 0;
        let mut permissions = 0;
        checked(
            unsafe { acl_get_tag_type(entry, &mut tag) },
            "read macOS ACL tag",
        )?;
        checked(
            unsafe { acl_get_permset_mask_np(entry, &mut permissions) },
            "read macOS ACL permissions",
        )?;
        let qualifier = unsafe { acl_get_qualifier(entry) };
        ensure!(
            !qualifier.is_null(),
            "read macOS ACL principal: {}",
            io::Error::last_os_error()
        );
        let mut principal = [0; 16];
        unsafe {
            ptr::copy_nonoverlapping(
                qualifier.cast::<u8>(),
                principal.as_mut_ptr(),
                principal.len(),
            );
            acl_free(qualifier);
        }
        result.entries.push(MacAce {
            principal,
            tag,
            permissions,
            flags: get_flags(entry)?,
        });
    }
    Ok(result)
}

pub(super) fn apply(file: &File, value: &MacAcl) -> Result<()> {
    if &read(file)? == value {
        return Ok(());
    }
    let acl = build(value)?;
    checked(
        unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, EXTENDED) },
        "restore macOS ACL on held inode",
    )
}

// Publish mode and ACL together: neither a mode-only nor an ACL-only update
// may temporarily grant access denied by the final combination.
pub(super) fn apply_with_mode(file: &File, value: &MacAcl, mode: u32) -> Result<()> {
    let acl = build(value)?;
    struct Security(*mut c_void);
    impl Drop for Security {
        fn drop(&mut self) {
            unsafe { filesec_free(self.0) };
        }
    }
    let security = Security(unsafe { filesec_init() });
    ensure!(
        !security.0.is_null(),
        "allocate macOS file security: {}",
        io::Error::last_os_error()
    );
    let mode = (mode & 0o7777) as libc::mode_t;
    checked(
        unsafe { filesec_set_property(security.0, 4, (&mode as *const libc::mode_t).cast()) },
        "set final macOS mode",
    )?;
    checked(
        unsafe { filesec_set_property(security.0, 5, (&acl.0 as *const Acl).cast()) },
        "set final macOS ACL",
    )?;
    checked(
        unsafe { fchmodx_np(file.as_raw_fd(), security.0) },
        "restore macOS mode and ACL on published inode",
    )
}

fn build(value: &MacAcl) -> Result<OwnedAcl> {
    ensure!(
        value.entries.len() <= MAX_ENTRIES,
        "macOS ACL exceeds 128 entries"
    );
    let raw = unsafe { acl_init(value.entries.len() as _) };
    ensure!(
        !raw.is_null(),
        "allocate macOS ACL: {}",
        io::Error::last_os_error()
    );
    let mut acl = OwnedAcl(raw);
    set_flags(acl.0, value.flags, ACL_FLAGS)?;
    for value in &value.entries {
        ensure!(
            matches!(value.tag, 1 | 2),
            "unsupported macOS ACL entry tag"
        );
        let mut entry = ptr::null_mut();
        checked(
            unsafe { acl_create_entry(&mut acl.0, &mut entry) },
            "create macOS ACL entry",
        )?;
        checked(
            unsafe { acl_set_tag_type(entry, value.tag) },
            "set macOS ACL tag",
        )?;
        checked(
            unsafe { acl_set_qualifier(entry, value.principal.as_ptr().cast()) },
            "set macOS ACL principal",
        )?;
        checked(
            unsafe { acl_set_permset_mask_np(entry, value.permissions) },
            "set macOS ACL permissions",
        )?;
        set_flags(entry, value.flags, ENTRY_FLAGS)?;
    }
    Ok(acl)
}
