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
        let (updated, _) = enrollment::install_authorized_key(&original, &entry)?;
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
    fn install_and_cleanup_preserve_other_copies_without_local_listeners() {
        use std::os::unix::net::UnixListener;
        // Both home and TMPDIR may be shared across hosts. Neither a missing
        // socket nor a visible socket without a local listener proves that
        // another copy has ended on its host.
        for socket_exists in [false, true] {
            let root = crate::test_support::short_tempdir().unwrap();
            let service = root.path().join("syq-copy-worker-other-host");
            fs::create_dir(&service).unwrap();
            let socket = service.join("s");
            if socket_exists {
                drop(UnixListener::bind(&socket).unwrap());
            }
            let public = || {
                generate_enrollment_key(EnrollmentId::random())
                    .unwrap()
                    .public_key()
                    .to_openssh()
                    .unwrap()
            };
            let other = TemporaryKey::install_at(
                root.path(),
                Path::new("/usr/bin/syq"),
                &public(),
                &ticket(&socket),
            )
            .unwrap();
            let path = root.path().join(".ssh/authorized_keys");
            let original = fs::read(&path).unwrap();
            let local = TemporaryKey::install_at(
                root.path(),
                Path::new("/usr/bin/syq"),
                &public(),
                "local_ticket",
            )
            .unwrap();
            let mut expected = original.clone();
            expected.extend_from_slice(format!("{}\n", local.entry.line()).as_bytes());
            assert_eq!(fs::read(&path).unwrap(), expected);
            drop(local);
            assert_eq!(fs::read(&path).unwrap(), original);
            drop(other);
            assert!(fs::read(&path).unwrap().is_empty());
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
