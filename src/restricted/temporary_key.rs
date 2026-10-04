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
