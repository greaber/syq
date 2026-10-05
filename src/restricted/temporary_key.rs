//! Short-lived, forced-command authorization for a live approved copy.
use super::*;

pub(crate) struct TemporaryKey {
    home: PathBuf,
    entry: AuthorizedKeyEntry,
}

impl TemporaryKey {
    pub(crate) fn install(public_key: &str, ticket: &str) -> Result<Self> {
        let (_, home) = current_account()?;
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        Self::install_at(&home, &executable, public_key, ticket)
    }

    pub(crate) fn install_at(
        home: &Path,
        executable: &Path,
        public_key: &str,
        ticket: &str,
    ) -> Result<Self> {
        let key = EnrollmentPublicKey::parse(public_key)?;
        let entry =
            AuthorizedKeyEntry::copy_worker(EnrollmentId::random(), executable, ticket, &key)?;
        let ssh = ensure_directory_chain(home, &[".ssh"])?;
        let directory = open_directory(&ssh)?;
        lock_directory(&directory)?;
        let original = read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?
            .unwrap_or_default();
        let retained = prune_inactive(&original);
        let (updated, _) = enrollment::install_authorized_key(&retained, &entry)?;
        atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
        Ok(Self {
            home: home.to_path_buf(),
            entry,
        })
    }

    fn remove(&self) -> Result<()> {
        let directory = open_directory(&self.home.join(".ssh"))?;
        lock_directory(&directory)?;
        let Some(original) = read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?
        else {
            return Ok(());
        };
        let (updated, change) = enrollment::revoke_authorized_key(&original, &self.entry)?;
        if change == AuthorizedKeysChange::Revoked {
            atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
        }
        Ok(())
    }
}

fn prune_inactive(original: &[u8]) -> Vec<u8> {
    original
        .split_inclusive(|byte| *byte == b'\n')
        .filter(|line| {
            let text = line.strip_suffix(b"\n").unwrap_or(line);
            let inactive = std::str::from_utf8(text)
                .ok()
                .and_then(AuthorizedKeyEntry::copy_worker_ticket)
                .is_some_and(crate::destination::worker_ticket_inactive);
            !inactive
        })
        .flatten()
        .copied()
        .collect()
}

impl Drop for TemporaryKey {
    fn drop(&mut self) {
        // Removing the live worker socket independently invalidates this key.
        // Preserve concurrent edits if the exact entry cannot be removed.
        if let Err(error) = self.remove() {
            crate::output::diagnostic!("syq: could not remove inactive copy SSH key: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket(socket: &Path) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({"socket": socket, "secret": "a".repeat(43)}))
                .unwrap(),
        )
    }

    #[test]
    fn pre_cleanup_ticket_format_is_still_recognized() {
        // Frozen spelling supported by 8673c83f; do not regenerate with the writer.
        let line = r#"restrict,command="/usr/bin/syq --return-ssh-worker eyJzb2NrZXQiOiIvbm9uZXhpc3RlbnQvc3lxLWNvcHktd29ya2VyLWZpeHR1cmUvcyIsInNlY3JldCI6ImFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEifQ" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH syq-copy-worker-00112233445566778899aabbccddeeff"#;
        assert!(AuthorizedKeyEntry::copy_worker_ticket(line).is_some());
        // Existing tickets remain readable, but a missing local socket does
        // not prove that the copy ended on a host sharing authorized_keys.
        assert_eq!(prune_inactive(line.as_bytes()), line.as_bytes());
    }

    #[test]
    fn next_install_prunes_only_inactive_unchanged_copy_entries() {
        use std::os::unix::net::UnixListener;
        let root = crate::test_support::short_tempdir().unwrap();
        let service = root.path().join("syq-copy-worker-test");
        fs::create_dir(&service).unwrap();
        let socket = service.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        let key = generate_enrollment_key(EnrollmentId::random()).unwrap();
        let public = key.public_key().to_openssh().unwrap();
        let live = TemporaryKey::install_at(
            root.path(),
            Path::new("/usr/bin/syq"),
            &public,
            &ticket(&socket),
        )
        .unwrap();
        let path = root.path().join(".ssh/authorized_keys");
        let original = fs::read(&path).unwrap();
        assert_eq!(prune_inactive(&original), original, "live copy was pruned");
        let edited = format!("{} # keep edited entry\n", live.entry.line());
        let mut contents = b"# admin comment \xff\nssh-ed25519 AAAA user-key\n".to_vec();
        contents.extend_from_slice(edited.as_bytes());
        contents.extend_from_slice(&original);
        fs::write(&path, &contents).unwrap();
        // This models an installed entry surviving the crashed service.
        std::mem::forget(live);
        drop(listener);
        #[cfg(target_os = "linux")]
        assert!(
            prune_inactive(&original).is_empty(),
            "dead socket was retained"
        );
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            prune_inactive(&original),
            original,
            "ambiguous socket was removed"
        );
        let replacement_key = generate_enrollment_key(EnrollmentId::random()).unwrap();
        let replacement = TemporaryKey::install_at(
            root.path(),
            Path::new("/usr/bin/syq"),
            &replacement_key.public_key().to_openssh().unwrap(),
            "new_ticket",
        )
        .unwrap();
        let after = fs::read(&path).unwrap();
        let retained_len = if cfg!(target_os = "linux") {
            contents.len() - original.len()
        } else {
            contents.len()
        };
        assert_eq!(&after[..retained_len], &contents[..retained_len]);
        assert_eq!(
            &after[retained_len..],
            format!("{}\n", replacement.entry.line()).as_bytes()
        );
        drop(replacement);
        assert_eq!(fs::read(path).unwrap(), contents[..retained_len]);
    }

    #[test]
    fn copy_with_no_local_socket_survives_next_install_in_shared_home() {
        let root = crate::test_support::short_tempdir().unwrap();
        let public = |id| {
            generate_enrollment_key(id)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap()
        };
        let remote = TemporaryKey::install_at(
            root.path(),
            Path::new("/usr/bin/syq"),
            &public(EnrollmentId::random()),
            &ticket(&root.path().join("syq-copy-worker-other-host/s")),
        )
        .unwrap();
        let path = root.path().join(".ssh/authorized_keys");
        let original = fs::read(&path).unwrap();
        let local = TemporaryKey::install_at(
            root.path(),
            Path::new("/usr/bin/syq"),
            &public(EnrollmentId::random()),
            "local_ticket",
        )
        .unwrap();
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains(remote.entry.line()));
        drop(local);
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(remote);
        assert!(fs::read(&path).unwrap().is_empty());
    }

    #[test]
    fn malformed_copy_tickets_and_modified_options_are_preserved() {
        let key = generate_enrollment_key(EnrollmentId::random()).unwrap();
        let public = EnrollmentPublicKey::parse(&key.public_key().to_openssh().unwrap()).unwrap();
        let entry = AuthorizedKeyEntry::copy_worker(
            EnrollmentId::random(),
            Path::new("/usr/bin/syq"),
            "invalid_ticket",
            &public,
        )
        .unwrap();
        for line in [
            entry.line().to_string(),
            entry.line().replacen("restrict,", "", 1),
        ] {
            assert_eq!(prune_inactive(line.as_bytes()), line.as_bytes());
        }
    }

    #[test]
    fn cleanup_preserves_unrelated_authorized_keys_edits() {
        let root = crate::test_support::tempdir().unwrap();
        let ssh = root.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        let path = ssh.join("authorized_keys");
        fs::write(&path, b"# original without final newline").unwrap();
        let key = generate_enrollment_key(EnrollmentId::random()).unwrap();
        let public = key.public_key().to_openssh().unwrap();
        let guard =
            TemporaryKey::install_at(root.path(), Path::new("/usr/bin/syq"), &public, "ticket")
                .unwrap();
        let installed = fs::read_to_string(&path).unwrap();
        assert!(installed.contains("restrict,command=\"/usr/bin/syq --return-ssh-worker ticket\""));
        assert!(installed.contains("syq-copy-worker-"));
        fs::write(&path, format!("{installed}# concurrent edit\n")).unwrap();
        drop(guard);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"# original without final newline\n# concurrent edit\n"
        );
    }

    #[test]
    fn unsafe_key_and_worker_command_are_rejected_before_writes() {
        let root = crate::test_support::tempdir().unwrap();
        let key = generate_enrollment_key(EnrollmentId::random()).unwrap();
        let public = key.public_key().to_openssh().unwrap();
        for (key, ticket) in [("bad", "ticket"), (public.as_str(), "ticket;id")] {
            assert!(
                TemporaryKey::install_at(root.path(), Path::new("/usr/bin/syq"), key, ticket)
                    .is_err()
            );
            assert!(!root.path().join(".ssh").exists());
        }
    }
}
