use super::*;
use clap::Parser;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn enrollment_upload_selects_and_verifies_the_remote_platform() {
    use ed25519_dalek::{Signer, SigningKey};
    use flate2::{write::GzEncoder, Compression};
    use sha2::{Digest, Sha256};
    if let Ok(case) = std::env::var("SYQ_ENROLLMENT_TEST_CHILD") {
        let result = run_management_over_route(
            &endpoint("receiver", "fixture", None).unwrap(),
            EnrollmentRoute::Direct,
            EnrollmentId::test_v4(1),
            ManagementAction::Install,
            b"{}",
        );
        assert_eq!(
            result.is_ok(),
            matches!(
                case.as_str(),
                "valid" | "local-release" | "source-helpers" | "local-source-helpers"
            ),
            "{result:?}"
        );
        return;
    }
    let (os, arch, target) = if crate::remote_helper::Target::local().unwrap().key == "macos-arm64"
    {
        ("Linux", "x86_64", "linux-x86_64")
    } else {
        ("Darwin", "arm64", "macos-arm64")
    };
    let binary = b"receiver executable for the destination platform";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(binary).unwrap();
    let archive = encoder.finish().unwrap();
    let digest = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let signing = SigningKey::from_bytes(&[19; 32]);
    for case in [
        "valid",
        "local-release",
        "manifest-tampered",
        "archive-tampered",
        "source-build",
        "source-helpers",
        "local-source-helpers",
    ] {
        let (os, arch) = if matches!(case, "local-release" | "local-source-helpers") {
            (
                if cfg!(target_os = "linux") {
                    "Linux"
                } else {
                    "Darwin"
                },
                std::env::consts::ARCH,
            )
        } else {
            (os, arch)
        };
        let target = if case == "local-source-helpers" {
            crate::remote_helper::Target::local().unwrap().key
        } else {
            target
        };
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        fs::create_dir(root.join("bin")).unwrap();
        fs::write(
            root.join("bin/ssh"),
            br#"#!/bin/sh
for argument do command=$argument; done
case "$command" in
    *'uname -s'*) printf '%s\n%s\n' "$SYQ_TEST_REMOTE_OS" "$SYQ_TEST_REMOTE_ARCH" ;;
    *'--restricted-install'*) cat > "$SYQ_TEST_UPLOAD" ;;
    *) exit 91 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(root.join("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        let mut manifest = serde_json::json!({
            "schema": 1, "repository": "https://github.com/greaber/syq",
            "version": env!("CARGO_PKG_VERSION"), "tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "artifacts": {(target): {
                "binary": {"name": format!("syq-{target}"), "sha256": digest(binary), "size": binary.len()},
                "archive": {"name": format!("syq-{target}.gz"), "sha256": digest(&archive), "size": archive.len()}
            }},
            "installer": {"name":"install.sh", "sha256":"1".repeat(64), "size":1},
            "homebrew_formula": {"name":"syq.rb", "sha256":"2".repeat(64), "size":1},
            "signature_scheme":"ed25519-jcs-v1"
        });
        let canonical = serde_json_canonicalizer::to_vec(&manifest).unwrap();
        manifest["signature"] = base64::engine::general_purpose::STANDARD
            .encode(signing.sign(&canonical).to_bytes())
            .into();
        if case == "manifest-tampered" {
            manifest["installer"]["size"] = 2.into();
        }
        fs::write(
            root.join("syq-release-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let mut bytes = archive.clone();
        if case == "archive-tampered" {
            bytes[0] ^= 1;
        }
        fs::write(root.join(format!("syq-{target}.gz")), bytes).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restricted::tests::enrollment_upload_selects_and_verifies_the_remote_platform",
                "--nocapture",
            ])
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", root.join("bin").display()),
            )
            .env("HOME", root)
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("SYQ_ENROLLMENT_TEST_CHILD", case)
            .env(
                "SYQ_TEST_RELEASE_BUILD",
                if matches!(
                    case,
                    "source-build" | "source-helpers" | "local-source-helpers"
                ) {
                    "0"
                } else {
                    "1"
                },
            )
            .env(
                "SYQ_TEST_RELEASE_HELPERS",
                if case.ends_with("source-helpers") {
                    "1"
                } else {
                    "0"
                },
            )
            .env(
                "SYQ_TEST_RELEASE_PUBLIC_KEY",
                base64::engine::general_purpose::STANDARD
                    .encode(signing.verifying_key().to_bytes()),
            )
            .env(
                "SYQ_TEST_RELEASE_DOWNLOADS",
                "https://release.invalid/download",
            )
            .env("SYQ_TEST_FIXTURES", root)
            .env("SYQ_TEST_UPLOAD", root.join("uploaded"))
            .env("SYQ_TEST_REMOTE_OS", os)
            .env("SYQ_TEST_REMOTE_ARCH", arch)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if matches!(case, "valid" | "source-helpers" | "local-source-helpers") {
            assert_eq!(fs::read(root.join("uploaded")).unwrap(), binary);
        } else if case == "local-release" {
            assert_eq!(
                fs::read(root.join("uploaded")).unwrap(),
                fs::read(std::env::current_exe().unwrap()).unwrap()
            );
        } else {
            assert!(!root.join("uploaded").exists(), "{case}");
        }
    }
}

#[test]
fn signed_tcp_congestion_requires_the_exact_approved_algorithm() {
    let temporary = crate::test_support::tempdir().unwrap();
    let mut authority = tcp_test_authority(temporary.path());
    let listener = |algorithm: Option<&str>| Request::TcpListen {
        key: Some(vec![0; crate::tcp_records::KEY_LEN]),
        token: vec![0; 16],
        port_lo: 47_600,
        port_hi: 47_699,
        congestion_control: algorithm.map(str::to_owned),
    };
    assert!(authority
        .authorize(&mut listener(Some("cubic")), true)
        .is_err());
    authority.tcp_congestion = Some("cubic".into());
    assert!(authority.authorize(&mut listener(None), true).is_err());
    assert!(authority
        .authorize(&mut listener(Some("bbr")), true)
        .is_err());
    assert!(authority
        .authorize(&mut listener(Some("cubic")), false)
        .is_err());
    authority
        .authorize(&mut listener(Some("cubic")), true)
        .unwrap();
}

#[test]
fn receiver_configuration_preserves_released_v041_bytes() {
    // Unmodified output of the checksum-verified released v0.4.1
    // --restricted-install, produced in a disposable account/container.
    let encoded = include_bytes!("../../tests/fixtures/restricted-enrollment-v0.4.1.json");
    let config: ReceiverEnrollment = serde_json::from_slice(encoded).unwrap();
    assert_eq!(config.version, 3);
    // The old representation is still readable, but cannot authorize a
    // generation-4 receiver. Enrollment must be recreated after upgrade.
    assert_ne!(config.version, CONFIG_VERSION);
    assert_eq!(
        config.id,
        EnrollmentId::parse("00112233445546778899aabbccddeeff").unwrap()
    );
    assert_eq!(serde_json::to_vec(&config).unwrap(), encoded);
}

#[test]
fn enrollment_ssh_failures_distinguish_transport_from_remote_rejection() {
    let target = SshEndpoint::from_parts("backup", "host-b", Some(2222)).unwrap();
    let transport = enrollment_ssh_error(&target, true, "connection refused");
    assert!(is_enrollment_transport_failure(&transport));
    assert!(transport.to_string().contains("backup@host-b:2222"));

    let rejection = enrollment_ssh_error(&target, false, "remote exit status: 1");
    assert!(!is_enrollment_transport_failure(&rejection));
    assert!(rejection.to_string().contains("backup@host-b:2222"));
}

#[test]
fn receiver_publication_is_atomic_private_and_executable() {
    let temporary = crate::test_support::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = open_directory(temporary.path()).unwrap();
    atomic_replace_executable_locked(&directory, "syq-receiver", b"receiver-binary").unwrap();
    atomic_replace_executable_locked(&directory, "syq-receiver", b"replacement-receiver").unwrap();

    let path = temporary.path().join("syq-receiver");
    assert_eq!(fs::read(&path).unwrap(), b"replacement-receiver");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
}

#[test]
fn receiver_gc_detects_any_remaining_managed_enrollment() {
    assert!(!contains_managed_enrollment(b"ssh-ed25519 unrelated\n"));
    assert!(!contains_managed_enrollment(
        b"  # revoked key syq-enrollment:old\n"
    ));
    assert!(contains_managed_enrollment(
        b"restrict,command=\"syq\" ssh-ed25519 key syq-enrollment:id\n"
    ));
}

#[test]
fn revoke_validates_all_state_before_rewriting_authorized_keys() {
    for unsafe_enrollment in [false, true] {
        let (account, account_home) = current_account().unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("syq-revoke-order-")
            .tempdir_in(account_home)
            .unwrap();
        let home = temporary.path();
        fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();

        let id = EnrollmentId::test_v4(41);
        let state_base = home.join(".local/share/syq/restricted");
        fs::create_dir_all(&state_base).unwrap();
        fs::set_permissions(
            &state_base,
            fs::Permissions::from_mode(if unsafe_enrollment { 0o700 } else { 0o755 }),
        )
        .unwrap();
        if unsafe_enrollment {
            let state = state_base.join(id.to_string());
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let ssh = home.join(".ssh");
        fs::create_dir(&ssh).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();

        let key = generate_enrollment_key(id).unwrap();
        let public_key = key.public_key().to_openssh().unwrap();
        let transport = EnrollmentPublicKey::parse(&public_key).unwrap();
        let entry = AuthorizedKeyEntry::new(id, &receiver_install_path(home), &transport).unwrap();
        let original = format!("{}\n", entry.line()).into_bytes();
        let authorized_keys = ssh.join("authorized_keys");
        fs::write(&authorized_keys, &original).unwrap();
        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600)).unwrap();

        let request = RevokeRequest {
            version: CONFIG_VERSION,
            id,
            target_login: account.clone(),
            public_key,
        };
        let error = revoke_for_account(&request, &account, home).unwrap_err();
        assert!(error.to_string().contains("must have mode 0700"));
        assert_eq!(fs::read(authorized_keys).unwrap(), original);
    }
}

#[test]
fn final_enrollment_cleanup_preserves_general_account_directories() {
    let temporary = crate::test_support::tempdir().unwrap();
    let home = temporary.path();
    let local = home.join(".local");
    let share = local.join("share");
    let syq = share.join("syq");
    let restricted = syq.join("restricted");
    let libexec = local.join("libexec");
    fs::create_dir_all(&restricted).unwrap();
    fs::create_dir(&libexec).unwrap();
    fs::set_permissions(&local, fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(&share, fs::Permissions::from_mode(0o751)).unwrap();
    fs::set_permissions(&libexec, fs::Permissions::from_mode(0o710)).unwrap();

    remove_final_enrollment_state_directories(home).unwrap();

    assert!(!restricted.exists());
    assert!(!syq.exists());
    assert_eq!(fs::metadata(&local).unwrap().mode() & 0o7777, 0o750);
    assert_eq!(fs::metadata(&share).unwrap().mode() & 0o7777, 0o751);
    assert_eq!(fs::metadata(&libexec).unwrap().mode() & 0o7777, 0o710);
}

#[test]
fn local_management_executable_check_is_scoped_to_the_open_file() {
    let temporary = crate::test_support::tempdir().unwrap();
    let executable = temporary.path().join("syq");
    fs::write(&executable, b"test executable").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        read_local_management_executable(&executable).unwrap(),
        b"test executable"
    );

    fs::set_permissions(&executable, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        read_local_management_executable(&executable).unwrap(),
        b"test executable"
    );

    let error = read_local_management_executable(temporary.path()).unwrap_err();
    assert!(error.to_string().contains("must be a regular file"));
}

#[test]
fn management_stage_is_scoped_to_one_shell_session() {
    fn invoke(home: &Path, stage: &str, script: &[u8], request: &[u8]) -> std::process::Output {
        let remote = management_remote_command(stage, ManagementAction::Install, request)
            .expect("build management command");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(remote)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(script).unwrap();
        child.wait_with_output().unwrap()
    }

    let temporary = crate::test_support::tempdir().unwrap();
    let request = br#"{"value":"' ; exit 91; #"}"#;
    let output = invoke(
        temporary.path(),
        ".syq-receiver-test-success",
        b"#!/bin/sh\ncat\n",
        request,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, request);
    assert!(!temporary
        .path()
        .join(".local/libexec/.syq-receiver-test-success")
        .exists());
    assert!(temporary.path().join(".local/libexec").is_dir());

    let output = invoke(
        temporary.path(),
        ".syq-receiver-test-failure",
        b"#!/bin/sh\nexit 23\n",
        b"failure request",
    );
    assert_eq!(output.status.code(), Some(23));
    assert!(!temporary
        .path()
        .join(".local/libexec/.syq-receiver-test-failure")
        .exists());
}

fn test_authority(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
) -> RestrictedAuthority {
    test_authority_with_rate(root, deletion, maximum_bytes, 0)
}

/// Maximum authenticated worker connections granted by the test
/// authorities above.
pub(crate) const TEST_AUTHORITY_MAX_CONNECTIONS: u16 = 2;

/// A signed-grant authority for exercising the TCP data listener from
/// other modules' tests.
pub(crate) fn tcp_test_authority(root: &Path) -> RestrictedAuthority {
    test_authority(root, DeletionPolicy::Forbid, 1024)
}

fn test_authority_with_rate(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
    max_file_data_bytes_per_second: u64,
) -> RestrictedAuthority {
    test_authority_with_policy(
        root,
        deletion,
        maximum_bytes,
        max_file_data_bytes_per_second,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
    )
}

fn test_authority_with_policy(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    publication: PublicationPolicy,
) -> RestrictedAuthority {
    test_authority_with_existence(
        root,
        deletion,
        maximum_bytes,
        max_file_data_bytes_per_second,
        filters,
        publication,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap()
}

fn test_receipt_policy() -> crate::receipt::ReceiptPolicy {
    crate::receipt::ReceiptPolicy {
        required: true,
        hashed: false,
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::receipt::ReceiptDelivery::DetachedSignedPlaintext,
    }
}

#[allow(clippy::too_many_arguments)]
fn test_authority_with_existence(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    publication: PublicationPolicy,
    existing: ExistingDestinationPolicy,
    placement: DestinationPlacement,
    root_existence: RootExistence,
) -> Result<RestrictedAuthority> {
    test_authority_with_receipt(
        root,
        deletion,
        maximum_bytes,
        max_file_data_bytes_per_second,
        filters,
        publication,
        existing,
        placement,
        root_existence,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn test_authority_with_receipt(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
    max_file_data_bytes_per_second: u64,
    mut filters: FilterPolicy,
    publication: PublicationPolicy,
    existing: ExistingDestinationPolicy,
    placement: DestinationPlacement,
    root_existence: RootExistence,
    receipt_policy: Option<(PrivateKey, crate::receipt::ReceiptPolicy)>,
) -> Result<RestrictedAuthority> {
    let opened = Root::open(root).unwrap();
    let identity = opened.identity();
    let id = EnrollmentId::random();
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id,
        target_login: "receiver".into(),
        signer: signer_name(id),
        root: root.to_str().unwrap().into(),
        root_dev: identity.dev,
        root_ino: identity.ino,
        ssh_keygen: "/usr/bin/ssh-keygen".into(),
        receiver_path: "/usr/bin/syq".into(),
    };
    let destination = root.join("target");
    if !filters.ignore.is_empty() && filters.destination_roots.is_empty() {
        filters.destination_roots = vec![destination.as_os_str().as_bytes().to_vec()];
    }
    let grant = Grant {
        enrollment_id: id,
        target_login: "receiver".into(),
        signer: signer_name(id),
        request_id: RequestId::fresh(1_900_000_000).unwrap(),
        issued_at: 1,
        not_before: 1,
        start_by: 100,
        finish_by: 100,
        operation: GrantOperation::Copy(CopyOperation {
            destination: destination.as_os_str().as_bytes().to_vec(),
            mutation_scopes: vec![MutationScope {
                path: destination.as_os_str().as_bytes().to_vec(),
                descendants: true,
            }],
            policy: CopyPolicy {
                placement,
                existing,
                deletion,
                publication,
            },
            options: CopyOptions {
                recursive: true,
                preserve_symlinks: true,
                preserve_permissions: false,
                receiver_managed_modes: true,
                preserve_times: false,
                preserve_owner: false,
                preserve_group: false,
                preserve_devices: false,
                compare_existing_by_content: false,
                dry_run: false,
                verify_only: false,
                compressed_transport: true,
                tcp_port_lo: 47_600,
                tcp_port_hi: 47_699,
            },
            limits: CopyLimits {
                max_entries: 8,
                max_total_bytes: maximum_bytes,
                max_file_bytes: maximum_bytes,
                hash_block_bytes: 4 << 20,
                max_connections: TEST_AUTHORITY_MAX_CONNECTIONS,
                max_deletions: u64::from(deletion != DeletionPolicy::Forbid) * 2,
            },
        }),
    };
    let (receipt_key, receipt_policy) = match receipt_policy {
        Some((key, policy)) => (key, policy),
        None => (generate_receipt_key(id)?, test_receipt_policy()),
    };
    RestrictedAuthority::new(
        &config,
        grant,
        GrantConstraints {
            tcp_congestion: None,
            mapping: None,
            hashing: None,
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_policy,
        },
        [0; 32],
        receipt_key,
        Instant::now() + std::time::Duration::from_secs(60),
        &[],
    )
}

#[test]
fn restricted_destinations_cannot_overlap_receiver_control_paths() {
    let protected = receiver_control_paths(
        Path::new("/home/receiver"),
        Path::new("/home/receiver/.local/libexec/syq-receiver"),
        Some(Path::new("/usr/bin/ssh-keygen")),
    )
    .unwrap();

    reject_control_plane_path(b"/home/receiver/archive", &protected)
        .expect("an unrelated destination remains available");
    reject_control_plane_path(b"/home/receiver/.ssh-backup", &protected)
        .expect("component boundaries distinguish similar names");

    for path in [
        b"/home/receiver".as_slice(),
        b"/home/receiver/.ssh".as_slice(),
        b"/home/receiver/.ssh/incoming".as_slice(),
    ] {
        let error = reject_control_plane_path(path, &protected).unwrap_err();
        assert!(error.to_string().contains("protected SSH configuration"));
    }

    for (path, label) in [
        (
            b"/home/receiver/.local/libexec/syq-receiver".as_slice(),
            "receiver executable directory",
        ),
        (
            b"/home/receiver/.local/share/syq/restricted/enrollment".as_slice(),
            "enrollment state directory",
        ),
        (
            b"/usr/bin/ssh-keygen".as_slice(),
            "signature verifier executable",
        ),
    ] {
        let error = reject_control_plane_path(path, &protected).unwrap_err();
        assert!(error.to_string().contains(label));
    }
}

#[test]
fn managed_crlf_and_commented_tombstones_normalize_without_touching_other_content() {
    let marker = "syq-enrollment:00112233445566778899aabbccddeeff";
    let original =
        format!("# unrelated\r\n# restrict ssh-ed25519 AAAA {marker}\r\nssh-ed25519 BBBB user\r\n");
    assert_eq!(
        normalize_managed_authorized_keys(original.as_bytes(), marker),
        b"# unrelated\nssh-ed25519 BBBB user\n"
    );
}

#[test]
fn enrolled_destinations_accept_any_leaf_bytes() {
    use std::os::unix::ffi::OsStrExt as _;
    let metadata = LocalEnrollment {
        version: 1,
        id: EnrollmentId::random(),
        host: "hostB".into(),
        port: None,
        target_login: "backup".into(),
        remote_home: "/home/backup".into(),
        requested_parent: "/home/backup/archive".into(),
        canonical_root: "/srv/archive".into(),
        receiver_path: "/usr/bin/syq".into(),
        receipt_public_key: String::new(),
    };
    // A destination whose leaf is not UTF-8 still resolves inside the
    // enrollment's (UTF-8, administrative) scope.
    let mut requested = b"archive/leaf-".to_vec();
    requested.push(0xff);
    let canonical = destination_for(&metadata, &requested).unwrap().unwrap();
    let mut expected = b"/srv/archive/leaf-".to_vec();
    expected.push(0xff);
    assert_eq!(canonical, expected);
    assert_eq!(
        std::ffi::OsStr::from_bytes(&canonical),
        Path::new("/srv/archive")
            .join(std::ffi::OsStr::from_bytes(b"leaf-\xff"))
            .as_os_str()
    );
    // Outside the enrolled parent, no match.
    assert!(destination_for(&metadata, b"elsewhere/leaf")
        .unwrap()
        .is_none());
}

#[test]
fn relative_destination_resolution_rejects_parent_components() {
    assert_eq!(
        normalize_absolute(
            std::ffi::OsStr::new("archive/file"),
            Path::new("/home/backup")
        )
        .unwrap(),
        Path::new("/home/backup/archive/file")
    );
    assert!(normalize_absolute(
        std::ffi::OsStr::new("archive/../escape"),
        Path::new("/home/backup")
    )
    .is_err());
}

#[test]
fn receiver_command_accepts_only_one_encoded_signed_grant() {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"signed grant");
    assert_eq!(
        decode_receiver_command(&format!("syq --server --restricted-grant={encoded}")).unwrap(),
        b"signed grant"
    );
    assert!(
        decode_receiver_command(&format!("syq --server --restricted-grant={encoded} extra"))
            .is_err()
    );
    assert!(decode_receiver_command(&format!(
        "env X=1 syq --server --restricted-grant={encoded}"
    ))
    .is_err());
}

#[test]
fn receipt_keys_are_distinct_and_persist_for_an_enrollment() {
    let id = EnrollmentId::random();
    let key = generate_receipt_key(id).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(public.ends_with(&format!("syq-receipt:{id}")));
    let again = generate_receipt_key(id).unwrap();
    assert_ne!(again.public_key().to_openssh().unwrap(), public);
    ssh_key::PublicKey::from_openssh(&public).unwrap();

    // An install keeps the key it finds, so a refresh or a retried
    // install reports the same public key the local side already has.
    let (_, home) = current_account().unwrap();
    let temporary = tempfile::tempdir_in(home).unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = temporary.path().join("state");
    ensure_directory(&state, 0o700).unwrap();
    let first = ensure_receipt_key(&state, id).unwrap();
    let second = ensure_receipt_key(&state, id).unwrap();
    assert_eq!(
        first.public_key().to_openssh().unwrap(),
        second.public_key().to_openssh().unwrap()
    );
    assert!(state.join(RECEIPT_KEY_FILE).is_file());
}

#[test]
fn pending_enrollment_keeps_its_key_until_active_metadata_is_durable() {
    let (_, home) = current_account().unwrap();
    let temporary = tempfile::tempdir_in(home).unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let id = EnrollmentId::random();
    let directory = temporary.path().join(id.to_string());
    ensure_directory(&directory, 0o700).unwrap();
    let pending = PendingEnrollment {
        version: CONFIG_VERSION,
        id,
        host: "host-b".into(),
        port: None,
        target_login: "backup".into(),
        requested_destination: "/archive/item".into(),
    };
    let private_key = generate_enrollment_key(id).unwrap();
    store_pending_files(&directory, &pending, &private_key).unwrap();
    assert!(directory.join("pending.json").is_file());
    assert_eq!(
        fs::metadata(directory.join("enrollment-key"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        load_private_key(&directory)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        private_key.public_key().to_openssh().unwrap()
    );

    let metadata = LocalEnrollment {
        version: CONFIG_VERSION,
        id,
        host: pending.host,
        port: pending.port,
        target_login: pending.target_login,
        remote_home: "/home/backup".into(),
        requested_parent: "/archive".into(),
        canonical_root: "/archive".into(),
        receiver_path: "/home/backup/.local/libexec/syq-receiver".into(),
        receipt_public_key: generate_receipt_key(id)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
    };
    complete_local_enrollment(&directory, &metadata).unwrap();
    assert!(!directory.join("pending.json").exists());
    assert!(directory.join("metadata.json").is_file());
    assert!(directory.join("enrollment-key").is_file());
}

#[test]
fn prune_lookup_is_confined_to_authorized_observation_paths() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 4);
    let target = root.join("target");
    fs::write(&target, b"data").unwrap();
    let mut request = Request::PruneLookup {
        paths: vec![target.as_os_str().as_bytes().to_vec()],
        guard: None,
    };
    authority.authorize(&mut request, false).unwrap();
    let response = crate::fsops::FsOps::new().handle(&request);
    let proto::Response::Stats(stats) = response else {
        panic!("prune lookup failed: {response:?}")
    };
    assert_eq!(stats[0].as_ref().unwrap().size, 4);
    let mut outside = Request::PruneLookup {
        paths: vec![temporary
            .path()
            .join("outside")
            .as_os_str()
            .as_bytes()
            .to_vec()],
        guard: None,
    };
    assert!(authority.authorize(&mut outside, false).is_err());
}

#[test]
fn authority_overwrites_client_guards_and_rejects_scope_and_option_escalation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 4);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let outside = temporary
        .path()
        .join("outside")
        .as_os_str()
        .as_bytes()
        .to_vec();

    let mut stat = Request::StatMany {
        paths: vec![target.clone()],
        sources: None,
        follow: false,
        guard: Some(ContainerGuard {
            root: outside.clone(),
            dev: 1,
            ino: 2,
        }),
    };
    authority.authorize(&mut stat, false).unwrap();
    let Request::StatMany {
        guard: Some(guard), ..
    } = stat
    else {
        panic!("authority did not install a guard")
    };
    assert_eq!(guard.root, root.as_os_str().as_bytes());

    let mut plan = Request::PlanBatch {
        partial_paths: vec![target.clone()],
        copy_id: [3; 16],
        directories: vec![target.clone()],
        others: vec![target.clone()],
        guard: None,
    };
    authority.authorize(&mut plan, false).unwrap();
    let Request::PlanBatch {
        guard: Some(guard), ..
    } = plan
    else {
        panic!("authority did not guard the combined planning request")
    };
    assert_eq!(guard.root, root.as_os_str().as_bytes());

    let mut outside_stat = Request::StatMany {
        paths: vec![outside.clone()],
        sources: None,
        follow: false,
        guard: None,
    };
    assert!(authority.authorize(&mut outside_stat, false).is_err());

    let mut mkdir = Request::Apply {
        ops: vec![Op::Mkdir {
            path: target.clone(),
            mode: 0o777,
            condition: proto::TargetCondition::Absent,
        }],
        guard: None,
    };
    authority.authorize(&mut mkdir, false).unwrap();
    let Request::Apply { ops, .. } = mkdir else {
        unreachable!()
    };
    assert!(matches!(ops[0], Op::Mkdir { mode: 0o700, .. }));

    let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
        path: target.clone(),
        copy_id: [1; 16],
        data: vec![0; 4],
        hash: [0; 32],
        meta: proto::Meta {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: proto::flags::RECEIVER_MODE,
        inplace: false,
        condition: proto::TargetCondition::Any,
        guard: Some(ContainerGuard {
            root: outside,
            dev: 1,
            ino: 2,
        }),
    }]);
    authority.authorize(&mut small, false).unwrap();
    let Request::PutSmallBatch(puts) = small else {
        unreachable!()
    };
    assert_eq!(
        puts[0].guard.as_ref().unwrap().root,
        root.as_os_str().as_bytes()
    );

    let mut write = Request::WriteRange {
        path: target,
        inplace: false,
        copy_id: [0; 16],
        attempt: 0,
        off: 0,
        hash: [0; 32],
        data: vec![0; 5].into(),
        guard: None,
    };
    assert!(authority.authorize(&mut write, false).is_err());
}

#[test]
fn exact_destination_observation_scope_excludes_its_parent() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 4);
    let destination = root.join("target").as_os_str().as_bytes().to_vec();
    let parent = root.as_os_str().as_bytes().to_vec();

    let mut exact = Request::StatMany {
        paths: vec![destination],
        sources: None,
        follow: false,
        guard: None,
    };
    authority.authorize(&mut exact, false).unwrap();

    let mut parent = Request::Canonicalize {
        path: parent,
        guard: None,
    };
    let error = authority.authorize(&mut parent, false).unwrap_err();
    assert!(error
        .to_string()
        .contains("observation is outside the signed destination scopes"));
}

#[test]
fn signed_filters_bind_scans_mutations_and_prune_protection() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let policy = FilterPolicy {
        ignore: vec!["ignored/".into(), "!ignored/file".into()],
        destination_roots: Vec::new(),
        delete_excluded: false,
    };
    let authority = test_authority_with_policy(
        &root,
        DeletionPolicy::DeleteDestinationOnly,
        16,
        0,
        policy.clone(),
        PublicationPolicy::AtomicStaged,
    );
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let ignored = root
        .join("target/ignored/file")
        .as_os_str()
        .as_bytes()
        .to_vec();
    let included = root.join("target/included").as_os_str().as_bytes().to_vec();

    let scan = |ignore: Vec<String>| Request::Scan {
        root: target.clone(),
        source: None,
        follow_root: false,
        ignore,
        report_ignored: true,
        guard: None,
    };
    let mut matching_scan = scan(policy.ignore.clone());
    authority.authorize(&mut matching_scan, false).unwrap();
    let mut altered_scan = scan(Vec::new());
    assert!(authority.authorize(&mut altered_scan, false).is_err());

    let prepare = |path| Request::Prepare {
        path,
        size: 4,
        inplace: false,
        copy_id: [1; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    let mut included_prepare = prepare(included);
    authority.authorize(&mut included_prepare, false).unwrap();
    let mut ignored_prepare = prepare(ignored.clone());
    assert!(authority.authorize(&mut ignored_prepare, false).is_err());
    let mut protected_delete = Request::Apply {
        ops: vec![Op::Unlink {
            path: ignored.clone(),
        }],
        guard: None,
    };
    assert!(authority.authorize(&mut protected_delete, false).is_err());

    let delete_excluded = test_authority_with_policy(
        &root,
        DeletionPolicy::DeleteDestinationOnly,
        16,
        0,
        FilterPolicy {
            ignore: policy.ignore,
            destination_roots: Vec::new(),
            delete_excluded: true,
        },
        PublicationPolicy::AtomicStaged,
    );
    let mut permitted_delete = Request::Apply {
        ops: vec![Op::Unlink { path: ignored }],
        guard: None,
    };
    delete_excluded
        .authorize(&mut permitted_delete, false)
        .unwrap();
}

#[test]
fn mixed_filter_mappings_keep_an_explicit_named_source_root() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let destination = root.join("target").as_os_str().as_bytes().to_vec();
    let mut args = Args::try_parse_from([
        "syq rsync",
        "-r",
        "host-a:tree/",
        "host-a:cache",
        "host-b:/target",
    ])
    .unwrap();
    args.normalize();
    args.placement = Placement::Into;
    let sources = [
        Location::parse("host-a:tree/").unwrap(),
        Location::parse("host-a:cache").unwrap(),
    ];
    let destination_roots = filter_destination_roots(&args, &sources, &destination).unwrap();
    let cache = root.join("target/cache").as_os_str().as_bytes().to_vec();
    assert_eq!(destination_roots, vec![destination, cache.clone()]);

    let authority = test_authority_with_policy(
        &root,
        DeletionPolicy::Forbid,
        16,
        0,
        FilterPolicy {
            ignore: vec!["cache/".into()],
            destination_roots,
            delete_excluded: false,
        },
        PublicationPolicy::AtomicStaged,
    );
    let prepare = |path| Request::Prepare {
        path,
        size: 4,
        inplace: false,
        copy_id: [2; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    let mut cache_root = prepare(cache.clone());
    authority.authorize(&mut cache_root, false).unwrap();
    let mut cache_child = prepare(crate::fsops::join(&cache, b"file"));
    authority.authorize(&mut cache_child, false).unwrap();
}

#[test]
fn signed_inplace_policy_requires_inplace_file_mutations() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority_with_policy(
        &root,
        DeletionPolicy::Forbid,
        16,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
    );
    let target = root.join("target/file").as_os_str().as_bytes().to_vec();
    let prepare = |inplace| Request::Prepare {
        path: target.clone(),
        size: 4,
        inplace,
        copy_id: [1; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    let mut inplace = prepare(true);
    authority.authorize(&mut inplace, false).unwrap();
    let mut staged = prepare(false);
    assert!(authority.authorize(&mut staged, false).is_err());
}

fn existence_authority(
    root: &Path,
    existing: ExistingDestinationPolicy,
    placement: DestinationPlacement,
    root_existence: RootExistence,
) -> Result<RestrictedAuthority> {
    test_authority_with_existence(
        root,
        DeletionPolicy::DeleteDestinationOnly,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        existing,
        placement,
        root_existence,
    )
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn plain_meta() -> proto::Meta {
    proto::Meta {
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        mtime_nsec: 0,
    }
}

fn prepare_request(path: &Path) -> Request {
    Request::Prepare {
        path: path_bytes(path),
        size: 4,
        inplace: false,
        copy_id: [1; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    }
}

fn finalize_request(path: &Path, condition: proto::TargetCondition) -> Request {
    Request::Finalize {
        expected_hash: None,
        path: path_bytes(path),
        inplace: false,
        copy_id: [1; 16],
        meta: plain_meta(),
        flags: 0,
        condition,
        guard: None,
    }
}

fn finalize_condition(request: &Request) -> proto::TargetCondition {
    let Request::Finalize { condition, .. } = request else {
        unreachable!()
    };
    *condition
}

fn small_put(path: &Path) -> Request {
    Request::PutSmallBatch(vec![proto::SmallPut {
        path: path_bytes(path),
        copy_id: [1; 16],
        data: b"new".to_vec(),
        hash: crate::fsops::content_digest(b"new"),
        meta: plain_meta(),
        flags: 0,
        inplace: false,
        condition: proto::TargetCondition::Any,
        guard: None,
    }])
}

fn small_put_condition(request: &Request) -> proto::TargetCondition {
    let Request::PutSmallBatch(puts) = request else {
        unreachable!()
    };
    puts[0].condition
}

fn apply(op: Op) -> Request {
    Request::Apply {
        ops: vec![op],
        guard: None,
    }
}

fn op_condition(request: &Request) -> proto::TargetCondition {
    let Request::Apply { ops, .. } = request else {
        unreachable!()
    };
    match &ops[0] {
        Op::Mkdir { condition, .. }
        | Op::Symlink { condition, .. }
        | Op::Mknod { condition, .. }
        | Op::SetMeta { condition, .. }
        | Op::SetFileMetaIfSame { condition, .. } => *condition,
        Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => unreachable!(),
    }
}

fn mkdir(path: &Path) -> Op {
    Op::Mkdir {
        path: path_bytes(path),
        mode: 0o755,
        condition: proto::TargetCondition::Any,
    }
}

fn symlink_op(path: &Path) -> Op {
    Op::Symlink {
        path: path_bytes(path),
        target: b"elsewhere".to_vec(),
        condition: proto::TargetCondition::Any,
    }
}

fn set_meta(path: &Path) -> Op {
    Op::SetMeta {
        path: path_bytes(path),
        meta: plain_meta(),
        flags: 0,
        condition: proto::TargetCondition::Any,
    }
}

#[test]
fn signed_only_new_rejects_existing_directory_mutation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let dir = root.join("target/dir");
    let new_dir = root.join("target/new-dir");
    fs::create_dir_all(&dir).unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let mut existing = apply(mkdir(&dir));
    authority.authorize(&mut existing, false).unwrap();
    assert_eq!(op_condition(&existing), proto::TargetCondition::Absent);
    assert!(authority
        .authorize(&mut apply(set_meta(&dir)), false)
        .is_err());
    let mut create = apply(mkdir(&new_dir));
    let settlement = authority.authorize(&mut create, false).unwrap();
    assert_eq!(op_condition(&create), proto::TargetCondition::Absent);
    authority.settle(settlement, &proto::Response::Applied(vec![None]));
    authority
        .authorize(&mut apply(set_meta(&new_dir)), false)
        .unwrap();
}

#[test]
fn signed_skip_records_directory_created_after_foreign_directory_disappears() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let dir = root.join("target/dir");
    fs::create_dir_all(&dir).unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let mut create = apply(mkdir(&dir));
    let settlement = authority.authorize(&mut create, false).unwrap();
    fs::remove_dir(&dir).unwrap();
    let Request::Apply { ops, guard } = &create else {
        unreachable!()
    };
    let results = crate::fsops::FsOps::new().apply(ops, guard.as_ref());
    assert!(results.iter().all(Option::is_none), "{results:?}");
    authority.settle(settlement, &proto::Response::Applied(results));
    assert!(dir.is_dir());
    authority
        .authorize(&mut apply(set_meta(&dir)), false)
        .unwrap();
}

#[test]
fn signed_skip_directory_race_preserves_metadata_and_allows_siblings() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for before_authorization in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        let raced = target.join("raced");
        let sibling = target.join("sibling");
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicy::Skip,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
        )
        .unwrap();
        let create_foreign = || {
            fs::create_dir(&raced).unwrap();
            fs::set_permissions(&raced, fs::Permissions::from_mode(0o555)).unwrap();
        };
        if before_authorization {
            create_foreign();
        }
        let mut batch = Request::Apply {
            ops: vec![mkdir(&raced), mkdir(&sibling)],
            guard: None,
        };
        let settlement = authority.authorize(&mut batch, false).unwrap();
        if !before_authorization {
            create_foreign();
        }
        let before = fs::metadata(&raced).unwrap();
        let Request::Apply { ops, guard } = &batch else {
            unreachable!()
        };
        let results = crate::fsops::FsOps::new().apply(ops, guard.as_ref());
        assert!(results[0].is_some());
        assert!(results[1].is_none(), "{results:?}");
        authority.settle(settlement, &proto::Response::Applied(results));
        assert!(sibling.is_dir());
        let after = fs::metadata(&raced).unwrap();
        assert_eq!(after.mode(), before.mode());
        assert_eq!(
            (after.mtime(), after.mtime_nsec()),
            (before.mtime(), before.mtime_nsec())
        );
        assert!(authority
            .authorize(&mut apply(set_meta(&raced)), false)
            .is_err());
        authority
            .authorize(&mut apply(set_meta(&sibling)), false)
            .unwrap();
        fs::set_permissions(&raced, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn admit_test_mapping(authority: &mut RestrictedAuthority, destination: &str) {
    let manifest = format!(r#"{{"src":{{"encoding":"utf-8","value":"source"}},"dst":{{"encoding":"utf-8","value":"{destination}"}}}}
"#).into_bytes();
    authority.mapping = Some(Mutex::new(crate::mapping::Admission::new(
        crate::mapping::Authorization::from_contents(&manifest),
        authority.copy.limits.max_entries,
    )));
    let settlement = authority
        .authorize(
            &mut Request::MappingChunk {
                offset: 0,
                data: manifest,
                finish: true,
            },
            true,
        )
        .unwrap();
    authority.settle(settlement, &proto::Response::Ok);
}

#[test]
fn mapping_parents_cannot_be_recreated_under_only_existing() {
    for nested in [false, true] {
        let root = crate::test_support::tempdir().unwrap();
        let target = root.path().join("target");
        let parent = if nested {
            target.join("parent")
        } else {
            target
        };
        fs::create_dir_all(&parent).unwrap();
        let mut authority = existence_authority(
            root.path(),
            ExistingDestinationPolicy::MustExist,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
        )
        .unwrap();
        admit_test_mapping(&mut authority, if nested { "parent/item" } else { "item" });
        let mut request = apply(mkdir(&parent));
        let admitted = authority.authorize(&mut request, false);
        // The independent remover acts after authorization. The request
        // may be refused up front, but an admitted request cannot create.
        fs::remove_dir(&parent).unwrap();
        if let Ok(settlement) = admitted {
            let response = crate::fsops::FsOps::new().handle(&request);
            authority.settle(settlement, &response);
            assert!(
                matches!(response, proto::Response::Applied(ref errors)
                    if errors.iter().all(Option::is_some)),
                "{response:?}"
            );
        }
        assert!(!parent.exists(), "only-existing recreated a mapping parent");
        assert!(!authority.created_by_this_grant(&path_bytes(&parent)));
    }
}

#[test]
fn mapping_parent_reopening_keeps_requested_identity() {
    for fingerprint in [false, true] {
        let root = crate::test_support::tempdir().unwrap();
        let parent = root.path().join("target/parent");
        fs::create_dir_all(&parent).unwrap();
        let metadata = fs::metadata(&parent).unwrap();
        let mut authority = test_authority(root.path(), DeletionPolicy::Forbid, 1024);
        admit_test_mapping(&mut authority, "parent/item");
        let condition = if fingerprint {
            proto::TargetCondition::MatchesFingerprint {
                dev: metadata.dev(),
                ino: metadata.ino(),
                ctime: metadata.ctime(),
                ctime_nsec: metadata.ctime_nsec() as u32,
            }
        } else {
            proto::TargetCondition::Matches {
                dev: metadata.dev(),
                ino: metadata.ino(),
            }
        };
        let mut request = apply(Op::Mkdir {
            path: path_bytes(&parent),
            mode: 0o755,
            condition,
        });
        let settlement = authority.authorize(&mut request, false).unwrap();
        let Request::Apply { ops, .. } = &request else {
            unreachable!()
        };
        assert!(matches!(&ops[0], Op::Mkdir { condition: actual, .. } if *actual == condition));
        fs::remove_dir(&parent).unwrap();
        let response = crate::fsops::FsOps::new().handle(&request);
        authority.settle(settlement, &response);
        assert!(
            matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_some)),
            "{response:?}"
        );
        assert!(!parent.exists());
    }
}

#[test]
fn mapping_parents_reopen_and_restore_receiver_permissions() {
    use std::os::unix::fs::PermissionsExt;
    for preserve in [false, true] {
        for policy in [
            ExistingDestinationPolicy::Replace,
            ExistingDestinationPolicy::MustExist,
            ExistingDestinationPolicy::Skip,
        ] {
            let root = crate::test_support::tempdir().unwrap();
            let parent = root.path().join("target/parent");
            fs::create_dir_all(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o2550)).unwrap();
            let original = fs::metadata(&parent).unwrap();
            let mut authority = existence_authority(
                root.path(),
                policy,
                DestinationPlacement::ExactPath,
                RootExistence::Any,
            )
            .unwrap();
            authority.copy.options.preserve_permissions = preserve;
            authority.copy.options.receiver_managed_modes = !preserve;
            admit_test_mapping(&mut authority, "parent/item");
            let mut request = apply(mkdir(&parent));
            let settlement = authority.authorize(&mut request, false).unwrap();
            let response = crate::fsops::FsOps::new().handle(&request);
            authority.settle(settlement, &response);
            if policy == ExistingDestinationPolicy::Skip {
                assert!(
                    matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_some))
                );
                assert_eq!(fs::metadata(&parent).unwrap().mode(), original.mode());
                assert!(authority
                    .authorize(&mut apply(set_meta(&parent)), false)
                    .is_err());
            } else {
                assert!(
                    matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
                    "{response:?}"
                );
                assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o7777, 0o2750);
                let mut restore = apply(Op::SetMeta {
                    path: path_bytes(&parent),
                    meta: proto::Meta {
                        mode: 0o7777,
                        ..plain_meta()
                    },
                    flags: if preserve {
                        proto::flags::MODE
                    } else {
                        proto::flags::RECEIVER_MODE
                    },
                    condition: proto::TargetCondition::Any,
                });
                let settlement = authority.authorize(&mut restore, false).unwrap();
                let response = crate::fsops::FsOps::new().handle(&restore);
                authority.settle(settlement, &response);
                assert!(
                    matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
                    "{response:?}"
                );
                let restored = fs::metadata(&parent).unwrap();
                assert_eq!(restored.mode(), original.mode());
                assert_eq!(
                    (restored.mtime(), restored.mtime_nsec()),
                    (original.mtime(), original.mtime_nsec())
                );
                assert_eq!(restored.gid(), original.gid());
            }
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

#[test]
fn mapping_new_parents_have_final_modes_without_metadata_updates() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for preserve in [false, true] {
        let root = crate::test_support::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o2755)).unwrap();
        // A sibling made with the same mkdir mode observes the process
        // umask and kernel setgid inheritance without changing global state.
        let expected = target.join("expected");
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&expected)
            .unwrap();
        let parent = target.join("parent");
        let mut authority = test_authority(root.path(), DeletionPolicy::Forbid, 1024);
        authority.copy.options.preserve_permissions = preserve;
        authority.copy.options.receiver_managed_modes = !preserve;
        admit_test_mapping(&mut authority, "parent/item");
        let mut request = apply(Op::Mkdir {
            path: path_bytes(&parent),
            mode: 0o7777,
            condition: proto::TargetCondition::Any,
        });
        let settlement = authority.authorize(&mut request, false).unwrap();
        let response = crate::fsops::FsOps::new().handle(&request);
        authority.settle(settlement, &response);
        assert!(
            matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
            "{response:?}"
        );
        assert_eq!(
            fs::metadata(&parent).unwrap().mode(),
            fs::metadata(&expected).unwrap().mode()
        );
        assert!(authority.created_by_this_grant(&path_bytes(&parent)));
    }
}

#[test]
fn mapping_pending_parent_creation_cannot_authorize_foreign_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::test_support::tempdir().unwrap();
    let parent = root.path().join("target/parent");
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o550)).unwrap();
    let mut authority = test_authority(root.path(), DeletionPolicy::Forbid, 1024);
    admit_test_mapping(&mut authority, "parent/item");
    let mut request = Request::Apply {
        ops: vec![
            Op::Mkdir {
                path: path_bytes(&parent),
                mode: 0o755,
                condition: proto::TargetCondition::Absent,
            },
            Op::SetMeta {
                path: path_bytes(&parent),
                meta: plain_meta(),
                flags: proto::flags::RECEIVER_MODE,
                condition: proto::TargetCondition::Any,
            },
        ],
        guard: None,
    };
    // Reject during authorization, without relying on the executor to
    // abort metadata after the guarded mkdir inevitably fails.
    let error = authority.authorize(&mut request, false).unwrap_err();
    assert!(
        error.to_string().contains("existing implicit parent"),
        "{error:#}"
    );
    assert!(!authority.created_by_this_grant(&path_bytes(&parent)));
    assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o550);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn mapping_failed_parent_creation_cannot_authorize_foreign_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::test_support::tempdir().unwrap();
    let parent = root.path().join("target/parent");
    fs::create_dir_all(parent.parent().unwrap()).unwrap();
    let mut authority = test_authority(root.path(), DeletionPolicy::Forbid, 1024);
    admit_test_mapping(&mut authority, "parent/item");
    let mut create = apply(Op::Mkdir {
        path: path_bytes(&parent),
        mode: 0o755,
        condition: proto::TargetCondition::Absent,
    });
    let settlement = authority.authorize(&mut create, false).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o550)).unwrap();
    let response = crate::fsops::FsOps::new().handle(&create);
    authority.settle(settlement, &response);
    assert!(
        matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_some)),
        "{response:?}"
    );
    let mut restore = apply(Op::SetMeta {
        path: path_bytes(&parent),
        meta: plain_meta(),
        flags: proto::flags::RECEIVER_MODE,
        condition: proto::TargetCondition::Any,
    });
    assert!(authority.authorize(&mut restore, false).is_err());
    assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o550);
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn mapping_receiver_confines_entries_and_protects_existing_parents() {
    let root = crate::test_support::tempdir().unwrap();
    let target = root.path().join("target");
    fs::create_dir_all(target.join("existing")).unwrap();
    let outside = crate::test_support::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), target.join("escape")).unwrap();
    let manifest = ["fresh/item", "existing/item", "escape/item"].map(|dst| {
            format!(r#"{{"src":{{"encoding":"utf-8","value":"source"}},"dst":{{"encoding":"utf-8","value":"{dst}"}}}}
"#)
        }).concat().into_bytes();
    let mut authority = tcp_test_authority(root.path());
    authority.copy.limits.max_entries = 100;
    authority.mapping = Some(Mutex::new(crate::mapping::Admission::new(
        crate::mapping::Authorization::from_contents(&manifest),
        authority.copy.limits.max_entries,
    )));
    assert!(authority
        .authorize(&mut prepare_request(&target.join("existing/item")), false)
        .is_err());
    let mut admission = Request::MappingChunk {
        offset: 0,
        data: manifest,
        finish: true,
    };
    assert!(authority.authorize(&mut admission, false).is_err());
    let settlement = authority.authorize(&mut admission, true).unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    assert!(authority
        .authorize(
            &mut Request::Scan {
                root: target.as_os_str().as_bytes().to_vec(),
                source: None,
                follow_root: false,
                ignore: vec![],
                report_ignored: false,
                guard: None,
            },
            true
        )
        .is_err());
    assert!(authority
        .authorize(&mut prepare_request(&target.join("unlisted")), false)
        .is_err());
    assert!(authority
        .authorize(&mut prepare_request(&target.join("existing")), false)
        .is_err());
    assert!(authority
        .authorize(&mut apply(set_meta(&target.join("existing"))), false)
        .is_err());
    assert!(authority
        .authorize(
            &mut prepare_request(&target.join("existing/item/child")),
            false
        )
        .is_err());
    let run = |mut request| {
        let settlement = authority.authorize(&mut request, false)?;
        let response = crate::fsops::FsOps::new().handle(&request);
        authority.settle(settlement, &response);
        Ok::<_, anyhow::Error>(response)
    };
    let created = run(apply(mkdir(&target.join("fresh")))).unwrap();
    assert!(
        matches!(created, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
        "{created:?}"
    );
    assert!(run(apply(set_meta(&target.join("fresh")))).is_ok());
    let written = run(small_put(&target.join("fresh/item"))).unwrap();
    assert!(
        matches!(written, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
        "{written:?}"
    );
    assert_eq!(fs::read(target.join("fresh/item")).unwrap(), b"new");
    let escaped = run(small_put(&target.join("escape/item")));
    assert!(
        !matches!(escaped, Ok(proto::Response::Applied(ref errors)) if errors.iter().all(Option::is_none))
    );
    assert!(!outside.path().join("item").exists());
}

#[test]
fn timestamp_selection_preserves_independent_existing_authority() {
    use clap::Parser;
    let mut args = Args::parse_from(["syq", "--update", "source", "destination"]);
    let sources = [Location::parse("hostA:source").unwrap()];
    for (existing, policy) in [
        (false, ExistingDestinationPolicy::Replace),
        (true, ExistingDestinationPolicy::MustExist),
    ] {
        args.existing = existing;
        let grant = grant_for(
            &args,
            &sources,
            EnrollmentId::random(),
            "receiver",
            b"/destination",
        )
        .unwrap();
        let GrantOperation::Copy(copy) = grant.operation;
        assert_eq!(copy.policy.existing, policy);
        assert!(args.update);
    }
}

#[test]
fn special_file_creation_checks_kind_and_masks_mode() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path();
    fs::create_dir(root.join("target")).unwrap();
    for preserve_permissions in [false, true] {
        for kind in [
            libc::S_IFREG,
            libc::S_IFDIR,
            libc::S_IFLNK,
            0,
            libc::S_IFIFO,
            libc::S_IFSOCK,
            libc::S_IFCHR,
            libc::S_IFBLK,
        ] {
            let mut authority = test_authority(root, DeletionPolicy::Forbid, 1024);
            authority.copy.options.preserve_devices = true;
            authority.copy.options.preserve_permissions = preserve_permissions;
            #[allow(clippy::unnecessary_cast)]
            let kind = kind as u32;
            let mut request = apply(Op::Mknod {
                path: path_bytes(&root.join("target/node")),
                mode: kind | 0x8000_0000 | 0o6754,
                rdev: 0,
                condition: proto::TargetCondition::Any,
            });
            let allowed = matches!(
                kind_from_mode(kind),
                proto::Kind::Fifo
                    | proto::Kind::Socket
                    | proto::Kind::CharDev
                    | proto::Kind::BlockDev
            );
            let result = authority.authorize(&mut request, false);
            if !allowed {
                assert!(result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("special-file creation requires"));
                continue;
            }
            result.unwrap();
            let Request::Apply { ops, .. } = request else {
                unreachable!()
            };
            let Op::Mknod { mode, .. } = ops[0] else {
                unreachable!()
            };
            assert_eq!(
                mode,
                kind | if preserve_permissions { 0o6754 } else { 0o600 }
            );
        }
    }
    assert!(!root.join("target/node").exists());
}

#[test]
fn signed_skip_allows_seeding_and_retrying_a_new_file() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let fresh = target.join("fresh");
    let candidate = target.join(".fresh.syq-tmp.abcdefghijklmnop");
    fs::write(&candidate, b"new").unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let mut ops = crate::fsops::FsOps::new();
    let mut prepare = prepare_request(&fresh);
    let settlement = authority.authorize(&mut prepare, false).unwrap();
    let response = ops.handle(&prepare);
    assert!(matches!(&response, proto::Response::Prepared(prepared) if prepared.has_candidates));
    authority.settle(settlement, &response);
    assert!(authority.state.lock().unwrap().file_lifecycles.is_empty());
    for attempt in 0..2 {
        let mut seed = Request::SeedBasis {
            final_ranges: None,
            path: path_bytes(&fresh),
            copy_id: [1; 16],
            len: 3,
            block: authority.copy.limits.hash_block_bytes,
            attempt,
            guard: None,
        };
        let settlement = authority.authorize(&mut seed, false).unwrap();
        let response = ops.handle(&seed);
        assert!(matches!(&response, proto::Response::SeededBasis(seed)
                if seed.hashes == vec![crate::fsops::content_digest(b"new")]));
        authority.settle(settlement, &response);
        assert!(!fresh.exists());
    }
    let mut publish = finalize_request(&fresh, proto::TargetCondition::Any);
    let settlement = authority.authorize(&mut publish, false).unwrap();
    assert_eq!(finalize_condition(&publish), proto::TargetCondition::Absent);
    let response = ops.handle(&publish);
    assert!(matches!(response, proto::Response::Ok), "{response:?}");
    authority.settle(settlement, &response);
    assert_eq!(fs::read(&fresh).unwrap(), b"new");
    assert_eq!(fs::read(&candidate).unwrap(), b"new");
}

#[test]
fn signed_skip_policy_retains_preexisting_objects() {
    use proto::TargetCondition::{Absent, Any, Matches};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let dir = target.join("dir");
    let kept = target.join("kept");
    let fresh = target.join("fresh");
    let small = target.join("small");
    let new_dir = target.join("new-dir");
    let link = target.join("link");
    fs::create_dir_all(&dir).unwrap();
    fs::write(&kept, b"old").unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();

    // New files are staged and published without replacing anything;
    // staging for a pre-existing object fails before bytes move.
    let mut prepare_fresh = prepare_request(&fresh);
    authority.authorize(&mut prepare_fresh, false).unwrap();
    let mut prepare_kept = prepare_request(&kept);
    assert!(authority.authorize(&mut prepare_kept, false).is_err());
    let mut publish_fresh = finalize_request(&fresh, Any);
    let settlement = authority.authorize(&mut publish_fresh, false).unwrap();
    assert_eq!(finalize_condition(&publish_fresh), Absent);
    authority.settle(settlement, &proto::Response::Ok);
    let mut publish_kept = finalize_request(&kept, Any);
    assert!(authority.authorize(&mut publish_kept, false).is_err());
    // What this grant created, and the executor confirmed, is its own to
    // republish.
    let mut republish_fresh = finalize_request(&fresh, Matches { dev: 1, ino: 1 });
    authority.authorize(&mut republish_fresh, false).unwrap();
    assert_eq!(
        finalize_condition(&republish_fresh),
        Matches { dev: 1, ino: 1 }
    );
    let mut small_kept = small_put(&kept);
    assert!(authority.authorize(&mut small_kept, false).is_err());
    let mut small_new = small_put(&small);
    authority.authorize(&mut small_new, false).unwrap();
    assert_eq!(small_put_condition(&small_new), Absent);

    // Existing directories cannot be reopened: the individual creation
    // is no-replace. New directories are created without replacement too.
    let mut reuse_dir = apply(mkdir(&dir));
    authority.authorize(&mut reuse_dir, false).unwrap();
    assert_eq!(op_condition(&reuse_dir), Absent);
    let mut dir_over_file = apply(mkdir(&kept));
    assert!(authority.authorize(&mut dir_over_file, false).is_err());
    let mut create_dir = apply(mkdir(&new_dir));
    authority.authorize(&mut create_dir, false).unwrap();
    assert_eq!(op_condition(&create_dir), Absent);

    // Symlinks follow the same rule, and metadata may follow only this
    // grant's own creations.
    let mut link_over_file = apply(symlink_op(&kept));
    assert!(authority.authorize(&mut link_over_file, false).is_err());
    let mut create_link = apply(symlink_op(&link));
    let settlement = authority.authorize(&mut create_link, false).unwrap();
    assert_eq!(op_condition(&create_link), Absent);
    authority.settle(settlement, &proto::Response::Applied(vec![None]));
    let mut meta_link = apply(set_meta(&link));
    authority.authorize(&mut meta_link, false).unwrap();
    let mut meta_dir = apply(set_meta(&dir));
    assert!(authority.authorize(&mut meta_dir, false).is_err());
    let mut meta_kept = apply(set_meta(&kept));
    assert!(authority.authorize(&mut meta_kept, false).is_err());
    let mut same_kept = apply(Op::SetFileMetaIfSame {
        path: path_bytes(&kept),
        condition: Any,
        meta: plain_meta(),
        flags: 0,
    });
    assert!(authority.authorize(&mut same_kept, false).is_err());

    // Content repair of a pre-existing file is refused; deletion remains
    // governed by the separately signed deletion policy.
    let mut finish = Request::FinishBasis {
        expected_hash: None,
        path: path_bytes(&kept),
        copy_id: [1; 16],
        meta: plain_meta(),
        flags: 0,
        condition: Any,
        guard: None,
    };
    assert!(authority.authorize(&mut finish, false).is_err());
    let mut seed = Request::SeedBasis {
        final_ranges: None,
        path: path_bytes(&kept),
        copy_id: [1; 16],
        len: 3,
        block: proto::MIN_HASH_BLOCK_BYTES,
        attempt: 0,
        guard: None,
    };
    assert!(authority.authorize(&mut seed, false).is_err());
    let mut delete = apply(Op::Unlink {
        path: path_bytes(&kept),
    });
    authority.authorize(&mut delete, false).unwrap();
}

#[test]
fn signed_must_exist_policy_creates_nothing() {
    use proto::TargetCondition::{Absent, Any, Matches};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let dir = target.join("dir");
    let present = target.join("present");
    let link = target.join("link");
    let missing = target.join("missing");
    fs::create_dir_all(&dir).unwrap();
    fs::write(&present, b"old").unwrap();
    std::os::unix::fs::symlink("present", &link).unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();

    let mut prepare_present = prepare_request(&present);
    authority.authorize(&mut prepare_present, false).unwrap();
    let mut prepare_missing = prepare_request(&missing);
    assert!(authority.authorize(&mut prepare_missing, false).is_err());
    let mut update_present = finalize_request(&present, Any);
    authority.authorize(&mut update_present, false).unwrap();
    let present_identity = fs::symlink_metadata(&present).unwrap();
    assert_eq!(
        finalize_condition(&update_present),
        Matches {
            dev: present_identity.dev(),
            ino: present_identity.ino(),
        }
    );
    let mut create_present = finalize_request(&present, Absent);
    assert!(authority.authorize(&mut create_present, false).is_err());
    let mut publish_missing = finalize_request(&missing, Any);
    assert!(authority.authorize(&mut publish_missing, false).is_err());
    let mut small_missing = small_put(&missing);
    assert!(authority.authorize(&mut small_missing, false).is_err());
    let mut small_present = small_put(&present);
    authority.authorize(&mut small_present, false).unwrap();

    let mut reuse_dir = apply(mkdir(&dir));
    authority.authorize(&mut reuse_dir, false).unwrap();
    let mut create_dir = apply(mkdir(&missing));
    assert!(authority.authorize(&mut create_dir, false).is_err());
    let mut dir_over_file = apply(mkdir(&present));
    assert!(authority.authorize(&mut dir_over_file, false).is_err());
    let mut replace_link = apply(symlink_op(&link));
    authority.authorize(&mut replace_link, false).unwrap();
    let link_identity = fs::symlink_metadata(&link).unwrap();
    assert_eq!(
        op_condition(&replace_link),
        Matches {
            dev: link_identity.dev(),
            ino: link_identity.ino(),
        }
    );
    let mut create_link = apply(symlink_op(&missing));
    assert!(authority.authorize(&mut create_link, false).is_err());

    let mut finish = Request::FinishBasis {
        expected_hash: None,
        path: path_bytes(&present),
        copy_id: [1; 16],
        meta: plain_meta(),
        flags: 0,
        condition: Any,
        guard: None,
    };
    authority.authorize(&mut finish, false).unwrap();
    let mut meta_present = apply(set_meta(&present));
    authority.authorize(&mut meta_present, false).unwrap();
}

#[test]
fn provisional_creations_are_forgotten_when_execution_fails() {
    use proto::TargetCondition::{Absent, Any, Matches};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let fresh = target.join("fresh");
    let kept = target.join("kept");
    let dir_a = target.join("dir-a");
    let dir_b = target.join("dir-b");

    // A failed no-replace publication leaves nothing behind, so a foreign
    // object that appears afterwards is retained like any other.
    authority
        .authorize(&mut prepare_request(&fresh), false)
        .unwrap();
    let mut publish = finalize_request(&fresh, Any);
    let settlement = authority.authorize(&mut publish, false).unwrap();
    authority.settle(settlement, &proto::Response::Err("raced".into()));
    fs::write(&fresh, b"foreign").unwrap();
    let mut republish = finalize_request(&fresh, Any);
    assert!(authority.authorize(&mut republish, false).is_err());

    // A successful one stays this grant's own.
    let mut publish = small_put(&kept);
    let settlement = authority.authorize(&mut publish, false).unwrap();
    authority.settle(settlement, &proto::Response::Applied(vec![None]));
    authority
        .authorize(&mut prepare_request(&kept), false)
        .unwrap();
    let mut republish = finalize_request(&kept, Matches { dev: 1, ino: 1 });
    authority.authorize(&mut republish, false).unwrap();

    // Per-operation results settle a batch operation by operation.
    let mut batch = Request::Apply {
        ops: vec![mkdir(&dir_a), mkdir(&dir_b)],
        guard: None,
    };
    let settlement = authority.authorize(&mut batch, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::Applied(vec![None, Some("raced".into())]),
    );
    let mut again_a = apply(mkdir(&dir_a));
    authority.authorize(&mut again_a, false).unwrap();
    assert_eq!(op_condition(&again_a), Any);
    let mut again_b = apply(mkdir(&dir_b));
    authority.authorize(&mut again_b, false).unwrap();
    assert_eq!(op_condition(&again_b), Absent);
}

#[test]
fn a_refused_request_leaves_no_provisional_creations_behind() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let kept = target.join("kept");
    let fresh = target.join("fresh");
    let link = target.join("link");
    fs::create_dir_all(&target).unwrap();
    fs::write(&kept, b"old").unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();

    // The first entry is authorized before the second is refused; nothing
    // of the batch runs, so the first must not count as created.
    let mut batch = Request::Apply {
        ops: vec![mkdir(&fresh), symlink_op(&kept)],
        guard: None,
    };
    assert!(authority.authorize(&mut batch, false).is_err());
    let mut again = apply(mkdir(&fresh));
    authority.authorize(&mut again, false).unwrap();
    assert_eq!(op_condition(&again), Absent);

    // Until the executor confirms a creation, a second creation of the
    // same path is not this grant's own either: it races at the kernel.
    let mut concurrent = apply(mkdir(&fresh));
    authority.authorize(&mut concurrent, false).unwrap();
    assert_eq!(op_condition(&concurrent), Absent);

    // Metadata may follow a creation within the same request.
    let mut create_and_touch = Request::Apply {
        ops: vec![symlink_op(&link), set_meta(&link)],
        guard: None,
    };
    authority.authorize(&mut create_and_touch, false).unwrap();
    let Request::Apply { ops, .. } = &create_and_touch else {
        unreachable!()
    };
    assert!(matches!(ops[1], Op::SetMeta { condition: Any, .. }));
}

#[test]
fn must_exist_accepts_only_the_observed_identity() {
    use proto::TargetCondition::{Matches, MatchesFingerprint};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let present = target.join("present");
    fs::create_dir_all(&target).unwrap();
    fs::write(&present, b"old").unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let identity = fs::symlink_metadata(&present).unwrap();
    let mut bogus = finalize_request(&present, Matches { dev: 1, ino: 1 });
    assert!(authority.authorize(&mut bogus, false).is_err());
    let mut stale = finalize_request(
        &present,
        MatchesFingerprint {
            dev: identity.dev(),
            ino: identity.ino(),
            ctime: identity.ctime() + 1,
            ctime_nsec: identity.ctime_nsec() as u32,
        },
    );
    assert!(authority.authorize(&mut stale, false).is_err());
    authority
        .authorize(&mut prepare_request(&present), false)
        .unwrap();
    let mut exact = finalize_request(
        &present,
        Matches {
            dev: identity.dev(),
            ino: identity.ino(),
        },
    );
    authority.authorize(&mut exact, false).unwrap();
}

#[test]
fn must_exist_pins_update_only_operations() {
    use proto::TargetCondition::{Any, Matches};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let present = target.join("present");
    let missing = target.join("missing");
    fs::create_dir_all(&target).unwrap();
    fs::write(&present, b"old").unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let identity = fs::symlink_metadata(&present).unwrap();
    let expected = Matches {
        dev: identity.dev(),
        ino: identity.ino(),
    };

    let mut meta = apply(set_meta(&present));
    authority.authorize(&mut meta, false).unwrap();
    assert_eq!(op_condition(&meta), expected);
    let mut same = apply(Op::SetFileMetaIfSame {
        path: path_bytes(&present),
        condition: Any,
        meta: plain_meta(),
        flags: 0,
    });
    authority.authorize(&mut same, false).unwrap();
    assert_eq!(op_condition(&same), expected);
    let mut finish = Request::FinishBasis {
        expected_hash: None,
        path: path_bytes(&present),
        copy_id: [1; 16],
        meta: plain_meta(),
        flags: 0,
        condition: Any,
        guard: None,
    };
    authority.authorize(&mut finish, false).unwrap();
    let Request::FinishBasis { condition, .. } = &finish else {
        unreachable!()
    };
    assert_eq!(*condition, expected);

    let mut bogus = apply(Op::SetMeta {
        path: path_bytes(&present),
        meta: plain_meta(),
        flags: 0,
        condition: Matches { dev: 1, ino: 1 },
    });
    assert!(authority.authorize(&mut bogus, false).is_err());
    let mut absent = apply(set_meta(&missing));
    assert!(authority.authorize(&mut absent, false).is_err());
}

#[test]
fn must_exist_replacement_and_metadata_execute_as_one_batch() {
    use proto::TargetCondition::{Any, Matches};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let link = target.join("link");
    fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink("old-target", &link).unwrap();
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let before = fs::symlink_metadata(&link).unwrap();

    // A changed symlink is replaced and then given its metadata in one
    // ordinary batch. The replacement is pinned to the old inode; the
    // metadata must land on the new one.
    let mut batch = Request::Apply {
        ops: vec![symlink_op(&link), set_meta(&link)],
        guard: None,
    };
    let settlement = authority.authorize(&mut batch, false).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &batch
    else {
        unreachable!()
    };
    assert!(matches!(
        ops[0],
        Op::Symlink { condition: Matches { dev, ino }, .. }
            if (dev, ino) == (before.dev(), before.ino())
    ));
    assert!(matches!(ops[1], Op::SetMeta { condition: Any, .. }));
    let results = crate::fsops::FsOps::new().apply(ops, Some(guard));
    assert!(results.iter().all(Option::is_none), "{results:?}");
    authority.settle(settlement, &proto::Response::Applied(results));
    assert_eq!(
        fs::read_link(&link).unwrap().as_os_str().as_bytes(),
        b"elsewhere"
    );
    let after = fs::symlink_metadata(&link).unwrap();
    assert_ne!(after.ino(), before.ino());

    // A later request must observe and pin the replacement afresh; it
    // is not a creation the grant may now treat as its own, so neither a
    // type change nor an unpinned publication is possible.
    let mut touch = apply(set_meta(&link));
    authority.authorize(&mut touch, false).unwrap();
    assert_eq!(
        op_condition(&touch),
        Matches {
            dev: after.dev(),
            ino: after.ino(),
        }
    );
    let mut as_directory = apply(mkdir(&link));
    assert!(authority.authorize(&mut as_directory, false).is_err());
    authority
        .authorize(&mut prepare_request(&link), false)
        .unwrap();
    let mut publish = finalize_request(&link, Any);
    authority.authorize(&mut publish, false).unwrap();
    assert_eq!(
        finalize_condition(&publish),
        Matches {
            dev: after.dev(),
            ino: after.ino(),
        }
    );
}

fn existence_authority_with_receipt(
    root: &Path,
    policy: &crate::receipt::ReceiptPolicy,
    deadline_ms: u64,
) -> RestrictedAuthority {
    let key = generate_receipt_key(EnrollmentId::random()).unwrap();
    let mut authority = test_authority_with_receipt(
        root,
        DeletionPolicy::DeleteDestinationOnly,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy.clone())),
    )
    .unwrap();
    // Waiting for in-flight requests is bounded by the grant deadline;
    // keep tests from sitting out the full minute.
    authority.deadline = Instant::now() + std::time::Duration::from_millis(deadline_ms);
    authority
}

#[test]
fn receipt_attests_confirmed_outcomes_and_closes_the_grant() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let kept = target.join("kept");
    let fresh = target.join("fresh");
    let gone = target.join("gone");
    fs::create_dir_all(&target).unwrap();
    fs::write(&kept, b"old").unwrap();
    fs::write(&gone, b"bye").unwrap();
    let key = generate_receipt_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = encrypted_policy(true);
    let authority = test_authority_with_receipt(
        &root,
        DeletionPolicy::DeleteDestinationOnly,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy.clone())),
    )
    .unwrap();

    // An observation the coordinator asked for is hostB's own view.
    let mut hash = Request::FileHash {
        path: path_bytes(&kept),
        source: None,
        guard: None,
    };
    let settlement = authority.authorize(&mut hash, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::FileHash {
            size: 3,
            hash: [9; 32],
        },
    );

    // A confirmed staged publication, a confirmed deletion, and a
    // refused request.
    let settlement = authority
        .authorize(&mut prepare_request(&fresh), false)
        .unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    let mut publish = finalize_request(&fresh, proto::TargetCondition::Any);
    let settlement = authority.authorize(&mut publish, false).unwrap();
    fs::write(&fresh, b"data").unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    let mut delete = apply(Op::Unlink {
        path: path_bytes(&gone),
    });
    let settlement = authority.authorize(&mut delete, false).unwrap();
    fs::remove_file(&gone).unwrap();
    authority.settle(settlement, &proto::Response::Applied(vec![None]));
    let mut outside = prepare_request(&root.join("elsewhere"));
    assert!(authority.authorize(&mut outside, false).is_err());

    let mut verified = open_issued(&authority, &secret, &policy);
    assert_eq!(verified.terminal.summary.refusals, 1);
    assert_eq!(verified.terminal.summary.published_files, 1);
    assert_eq!(verified.terminal.summary.deletions, 1);
    let mut records = Vec::new();
    verified
        .for_each_record(|record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::Operation(operation)
            if operation.path == b"kept"
                && operation.disposition
                    == crate::receipt::OperationDisposition::Observed
    )));
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == b"fresh"
                && matches!(
                    state.object,
                    crate::receipt::FinalObject::Present {
                        digest: Some(digest),
                        ..
                    } if digest == *blake3::hash(b"data").as_bytes()
                )
    )));
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == b"gone"
                && state.object == crate::receipt::FinalObject::Absent
    )));

    // Issuing the receipt closes the grant: no mutation, no second copy,
    // no further observation.
    assert!(authority
        .authorize(&mut prepare_request(&target.join("late")), false)
        .is_err());
    assert!(authority.issue_receipt().is_err());
    let mut observe = Request::StatMany {
        paths: vec![path_bytes(&kept)],
        sources: None,
        follow: false,
        guard: None,
    };
    assert!(authority.authorize(&mut observe, false).is_err());

    // A request still in flight holds the receipt back.
    let waiting = existence_authority_with_receipt(&root, &policy, 200);
    let settlement = waiting
        .authorize(&mut prepare_request(&target.join("inflight")), false)
        .unwrap();
    assert!(waiting.issue_receipt().is_err());
    waiting.settle(settlement, &proto::Response::Ok);

    // A published file that cannot be read back at closure is attested
    // present with the hash failure recorded rather than silently
    // unhashed.
    let (hashing_secret, hashing_policy) = encrypted_policy(true);
    let hashing = existence_authority_with_receipt(&root, &hashing_policy, 5_000);
    let unreadable = target.join("unreadable");
    let settlement = hashing
        .authorize(&mut prepare_request(&unreadable), false)
        .unwrap();
    hashing.settle(settlement, &proto::Response::Ok);
    let mut publish = finalize_request(&unreadable, proto::TargetCondition::Any);
    let settlement = hashing.authorize(&mut publish, false).unwrap();
    fs::write(&unreadable, b"sealed").unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
    hashing.settle(settlement, &proto::Response::Ok);
    let mut verified = open_issued(&hashing, &hashing_secret, &hashing_policy);
    let mut records = Vec::new();
    verified
        .for_each_record(|record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == b"unreadable"
                && matches!(
                    &state.object,
                    crate::receipt::FinalObject::Present {
                        digest: None,
                        observation_error: Some(_),
                        ..
                    }
                )
    )));

    // The receipt states the final tree, not settlement order: a file
    // republished then deleted is absent, and one deleted then
    // republished is present.
    let (racing_secret, racing_policy) = encrypted_policy(false);
    let racing = existence_authority_with_receipt(&root, &racing_policy, 5_000);
    let vanished = target.join("vanished");
    let returned = target.join("returned");
    fs::write(&returned, b"back").unwrap();
    for path in [&vanished, &returned] {
        let settlement = racing.authorize(&mut prepare_request(path), false).unwrap();
        racing.settle(settlement, &proto::Response::Ok);
        let mut publish = finalize_request(path, proto::TargetCondition::Any);
        let settlement = racing.authorize(&mut publish, false).unwrap();
        racing.settle(settlement, &proto::Response::Ok);
        let mut delete = apply(Op::Unlink {
            path: path_bytes(path),
        });
        let settlement = racing.authorize(&mut delete, false).unwrap();
        racing.settle(settlement, &proto::Response::Applied(vec![None]));
    }
    let mut verified = open_issued(&racing, &racing_secret, &racing_policy);
    let mut records = Vec::new();
    verified
        .for_each_record(|record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == b"vanished"
                && state.object == crate::receipt::FinalObject::Absent
    )));
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == b"returned"
                && matches!(
                    state.object,
                    crate::receipt::FinalObject::Present { size: 4, .. }
                )
    )));
}

#[test]
fn observation_only_prepare_releases_absent_reservation_and_skips_lifecycle() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = test_authority_with_receipt(
        &root,
        DeletionPolicy::Forbid,
        4,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((
            generate_receipt_key(EnrollmentId::random()).unwrap(),
            test_receipt_policy(),
        )),
    )
    .unwrap();
    let prepare = |path: &Path| {
        let mut request = prepare_request(path);
        let Request::Prepare {
            create_if_missing, ..
        } = &mut request
        else {
            unreachable!()
        };
        *create_if_missing = false;
        request
    };

    let mut absent = prepare(&target.join("absent"));
    let first = authority.authorize(&mut absent, false).unwrap();
    let mut same_absent = prepare(&target.join("absent"));
    let second = authority.authorize(&mut same_absent, false).unwrap();
    authority.settle(
        first,
        &proto::Response::Prepared(proto::Preparation::default()),
    );
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 4);
    authority.settle(
        second,
        &proto::Response::Prepared(proto::Preparation::default()),
    );
    {
        let state = authority.state.lock().unwrap();
        assert!(state.file_lifecycles.is_empty());
        assert!(state.reserved.is_empty());
        assert_eq!(state.reserved_bytes, 0);
    }

    let present_path = target.join("present");
    let mut present = prepare(&present_path);
    let settlement = authority.authorize(&mut present, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::Prepared(proto::Preparation {
            partial_size: Some(0),
            has_candidates: false,
        }),
    );
    let state = authority.state.lock().unwrap();
    assert!(state
        .file_lifecycles
        .contains_key(&(path_bytes(&present_path), [1; 16])));
    assert_eq!(state.reserved_bytes, 4);
}

#[test]
fn older_observation_does_not_release_newer_real_reservation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = test_authority_with_receipt(
        &root,
        DeletionPolicy::Forbid,
        4,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((
            generate_receipt_key(EnrollmentId::random()).unwrap(),
            test_receipt_policy(),
        )),
    )
    .unwrap();
    let path = target.join("shared");
    let mut observation = prepare_request(&path);
    let Request::Prepare {
        create_if_missing, ..
    } = &mut observation
    else {
        unreachable!()
    };
    *create_if_missing = false;

    let older = authority.authorize(&mut observation, false).unwrap();
    let mut real = prepare_request(&path);
    let newer = authority.authorize(&mut real, false).unwrap();
    authority.settle(
        older,
        &proto::Response::Prepared(proto::Preparation::default()),
    );

    {
        let state = authority.state.lock().unwrap();
        let reservation = state.reserved.get(&(path_bytes(&path), [1; 16])).unwrap();
        assert_eq!(reservation.retained, Some(4));
        assert!(reservation.observations.is_empty());
        assert_eq!(state.reserved_bytes, 4);
    }
    let mut another = prepare_request(&target.join("another"));
    let error = authority.authorize(&mut another, false).unwrap_err();
    assert!(error
        .to_string()
        .contains("signed grant total-byte limit exceeded"));
    authority.settle(
        newer,
        &proto::Response::Prepared(proto::Preparation::default()),
    );
}

#[test]
fn receipt_policy_records_each_outcome_and_closure_state_then_encrypts_it() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    // Exercise a raw byte name where the filesystem allows one.
    let copied_name = if crate::test_support::filesystem_accepts_non_utf8_names() {
        vec![b'c', b'o', b'p', 0xff]
    } else {
        b"copied".to_vec()
    };
    let copied = target.join(OsString::from_vec(copied_name.clone()));
    let failed = target.join("failed");
    let removed = target.join("removed");
    fs::create_dir_all(&target).unwrap();
    fs::write(&removed, b"old").unwrap();

    let receipt_key = generate_receipt_key(EnrollmentId::random()).unwrap();
    let receipt_public = receipt_key.public_key().to_openssh().unwrap();
    let (recipient_secret, recipient_public_key) = crate::receipt::generate_recipient().unwrap();
    let policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: true,
        max_records: 64,
        max_plaintext_bytes: 1 << 20,
        delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
            suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key,
        },
    };
    let authority = test_authority_with_receipt(
        &root,
        DeletionPolicy::DeleteDestinationOnly,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((receipt_key, policy.clone())),
    )
    .unwrap();
    let put = |path: &Path| proto::SmallPut {
        path: path_bytes(path),
        copy_id: [7; 16],
        data: b"new".to_vec(),
        hash: crate::fsops::content_digest(b"new"),
        meta: plain_meta(),
        flags: 0,
        inplace: false,
        condition: proto::TargetCondition::Any,
        guard: None,
    };
    let mut batch = Request::PutSmallBatch(vec![put(&copied), put(&failed)]);
    let settlement = authority.authorize(&mut batch, false).unwrap();
    fs::write(&copied, b"new").unwrap();
    authority.settle(
        settlement,
        &proto::Response::Applied(vec![None, Some("executor rejected it".into())]),
    );
    let mut delete = apply(Op::Unlink {
        path: path_bytes(&removed),
    });
    let settlement = authority.authorize(&mut delete, false).unwrap();
    fs::remove_file(&removed).unwrap();
    authority.settle(settlement, &proto::Response::Applied(vec![None]));
    assert!(authority
        .authorize(&mut prepare_request(&root.join("outside")), false)
        .is_err());

    let issued = authority.issue_receipt().unwrap();
    let mut late = prepare_request(&target.join("late"));
    assert!(authority.authorize(&mut late, false).is_err());
    assert!(authority.issue_receipt().is_err());
    let mut frames = Vec::new();
    crate::receipt::emit_receipt_frames(issued, |frame| {
        frames.push(Ok(frame));
        Ok(())
    })
    .unwrap();
    let mut verified = crate::receipt::open_attached_frames(
        frames,
        &recipient_secret,
        &receipt_public,
        authority.enrollment_id,
        authority.request_id,
        [0; 32],
        &policy,
    )
    .unwrap();
    assert_eq!(
        verified.terminal.status,
        crate::receipt::ReceiptStatus::Failed
    );
    assert_eq!(verified.terminal.summary.operations, 3);
    assert_eq!(verified.terminal.summary.refusals, 1);
    assert_eq!(verified.terminal.summary.final_states, 3);
    assert_eq!(verified.terminal.summary.published_files, 1);
    assert_eq!(verified.terminal.summary.deletions, 1);

    let mut records = Vec::new();
    verified
        .for_each_record(|record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::Operation(operation)
            if operation.path == copied_name
                && operation.disposition == crate::receipt::OperationDisposition::Succeeded
    )));
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::Operation(operation)
            if operation.path == b"failed"
                && operation.disposition == crate::receipt::OperationDisposition::Failed
    )));
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == copied_name
                && matches!(
                    state.object,
                    crate::receipt::FinalObject::Present {
                        digest: Some(digest),
                        ..
                    } if digest == *blake3::hash(b"new").as_bytes()
                )
    )));
    assert!(records.iter().any(|record| matches!(
        record,
        crate::receipt::ReceiptRecord::FinalState(state)
            if state.path == b"removed"
                && state.object == crate::receipt::FinalObject::Absent
    )));
}

#[test]
fn in_place_files_appear_in_the_receipt_before_their_final_step() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let image = target.join("image");
    fs::create_dir_all(&target).unwrap();
    let key = generate_receipt_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = encrypted_policy(false);
    let authority = test_authority_with_receipt(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy.clone())),
    )
    .unwrap();
    let mut prepare = Request::Prepare {
        path: path_bytes(&image),
        size: 4,
        inplace: true,
        copy_id: [1; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    let settlement = authority.authorize(&mut prepare, false).unwrap();
    fs::write(&image, b"half").unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    let mut write = Request::WriteRange {
        path: path_bytes(&image),
        inplace: true,
        copy_id: [1; 16],
        attempt: 0,
        off: 0,
        hash: crate::fsops::content_digest(b"ha"),
        data: b"ha".to_vec().into(),
        guard: None,
    };
    let settlement = authority.authorize(&mut write, false).unwrap();
    authority.settle(settlement, &proto::Response::Ok);

    // Without a final step the receipt still records the file; the
    // incomplete lifecycle fails the receipt.
    let verified = open_issued(&authority, &secret, &policy);
    assert_eq!(
        verified.terminal.status,
        crate::receipt::ReceiptStatus::Failed
    );
    assert!(verified.terminal.summary.incomplete > 0);

    // With it, the same file is complete and the receipt is clean.
    let key = generate_receipt_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = encrypted_policy(false);
    let finished = test_authority_with_receipt(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy.clone())),
    )
    .unwrap();
    let mut prepare = Request::Prepare {
        path: path_bytes(&image),
        size: 4,
        inplace: true,
        copy_id: [2; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    let settlement = finished.authorize(&mut prepare, false).unwrap();
    finished.settle(settlement, &proto::Response::Ok);
    let mut finalize = Request::Finalize {
        expected_hash: None,
        path: path_bytes(&image),
        inplace: true,
        copy_id: [2; 16],
        meta: plain_meta(),
        flags: 0,
        condition: proto::TargetCondition::Any,
        guard: None,
    };
    let settlement = finished.authorize(&mut finalize, false).unwrap();
    finished.settle(settlement, &proto::Response::Ok);
    let verified = open_issued(&finished, &secret, &policy);
    assert_eq!(
        verified.terminal.status,
        crate::receipt::ReceiptStatus::Clean
    );
    assert_eq!(verified.terminal.summary.incomplete, 0);
}

fn racing_public(authority: &RestrictedAuthority) -> String {
    authority.receipt_key.public_key().to_openssh().unwrap()
}

fn encrypted_policy(
    hashed: bool,
) -> (
    crate::receipt::RecipientSecret,
    crate::receipt::ReceiptPolicy,
) {
    let (secret, recipient_public_key) = crate::receipt::generate_recipient().unwrap();
    (
        secret,
        crate::receipt::ReceiptPolicy {
            required: true,
            hashed,
            max_records: 64,
            max_plaintext_bytes: 1 << 20,
            delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
                suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key,
            },
        },
    )
}

fn open_issued(
    authority: &RestrictedAuthority,
    secret: &crate::receipt::RecipientSecret,
    policy: &crate::receipt::ReceiptPolicy,
) -> crate::receipt::VerifiedReceipt {
    let issued = authority.issue_receipt().unwrap();
    let mut frames = Vec::new();
    crate::receipt::emit_receipt_frames(issued, |frame| {
        frames.push(Ok(frame));
        Ok(())
    })
    .unwrap();
    crate::receipt::open_attached_frames(
        frames,
        secret,
        &racing_public(authority),
        authority.enrollment_id,
        authority.request_id,
        [0; 32],
        policy,
    )
    .unwrap()
}

#[test]
fn guarded_executor_honors_creation_conditions() {
    use proto::TargetCondition::{Absent, Any, Matches};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let file = target.join("file");
    let dir = target.join("dir");
    let link = target.join("link");
    let fresh = target.join("fresh");
    fs::create_dir_all(&dir).unwrap();
    fs::write(&file, b"keep").unwrap();
    std::os::unix::fs::symlink("file", &link).unwrap();
    let root_identity = fs::metadata(&root).unwrap();
    let guard = ContainerGuard {
        root: path_bytes(&root),
        dev: root_identity.dev(),
        ino: root_identity.ino(),
    };
    let identity = |path: &Path| {
        let metadata = fs::symlink_metadata(path).unwrap();
        Matches {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    };
    let run = |op: Op| crate::fsops::FsOps::new().apply(&[op], Some(&guard))[0].clone();
    let with = |op: Op, condition| match op {
        Op::Mkdir { path, mode, .. } => Op::Mkdir {
            path,
            mode,
            condition,
        },
        Op::Symlink { path, target, .. } => Op::Symlink {
            path,
            target,
            condition,
        },
        other => other,
    };

    // No-replace creation never removes what is there.
    assert!(run(with(mkdir(&file), Absent)).is_some());
    assert!(run(with(symlink_op(&file), Absent)).is_some());
    assert!(run(with(mkdir(&dir), Absent)).is_some());
    assert_eq!(fs::read(&file).unwrap(), b"keep");
    assert!(run(with(mkdir(&fresh), Absent)).is_none());
    assert!(fresh.is_dir());

    // Matched replacement requires the observed object and its type.
    assert!(run(with(symlink_op(&link), Matches { dev: 1, ino: 1 })).is_some());
    assert!(run(with(symlink_op(&file), identity(&file))).is_some());
    assert_eq!(fs::read(&file).unwrap(), b"keep");
    assert!(run(with(symlink_op(&link), identity(&link))).is_none());
    assert!(run(with(mkdir(&file), identity(&file))).is_some());
    assert!(run(with(mkdir(&dir), identity(&dir))).is_none());

    // The unconditioned form keeps the ordinary replace behavior.
    assert!(run(with(symlink_op(&file), Any)).is_none());
    assert!(file.is_symlink());
}

#[test]
fn new_directory_placement_root_must_be_created_as_a_directory() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let target = root.join("target");
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryAsChild,
        RootExistence::New,
    )
    .unwrap();
    let mut as_file = finalize_request(&target, Any);
    assert!(authority.authorize(&mut as_file, false).is_err());
    let mut as_small_file = small_put(&target);
    assert!(authority.authorize(&mut as_small_file, false).is_err());
    let mut as_link = apply(symlink_op(&target));
    assert!(authority.authorize(&mut as_link, false).is_err());
    let mut as_directory = apply(mkdir(&target));
    authority.authorize(&mut as_directory, false).unwrap();
    assert_eq!(op_condition(&as_directory), Absent);
}

#[test]
fn inplace_publication_cannot_honor_no_replace_policies() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let inplace = |existing, placement, root_existence| {
        test_authority_with_existence(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::InPlace,
            existing,
            placement,
            root_existence,
        )
    };
    assert!(inplace(
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .is_err());
    assert!(inplace(
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::New,
    )
    .is_err());
    // In-place preparation cannot be pinned to an observed object either,
    // so MustExist is refused as well; only Replace remains, and a new
    // directory root is fine because mkdir creates it.
    assert!(inplace(
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .is_err());
    inplace(
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::New,
    )
    .unwrap();

    // The coordinator refuses the same combination before signing. The
    // rsync-shaped parser already makes --inplace and --ignore-existing
    // conflict, so the reachable case is the native --as-new placement.
    let mut args = Args::try_parse_from([
        "syq rsync",
        "-r",
        "--inplace",
        "host-a:source",
        "host-b:/backup",
    ])
    .unwrap();
    args.normalize();
    validate_restricted_args(&args).unwrap();
    args.placement = Placement::As;
    args.target_existence = Existence::New;
    assert!(validate_restricted_args(&args).is_err());
    args.placement = Placement::Into;
    validate_restricted_args(&args).unwrap();
}

#[test]
fn signed_root_existence_is_checked_at_redemption_and_forced_on_creation() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let target = root.join("target");
    let replace = ExistingDestinationPolicy::Replace;

    // A root that must be new is refused when present, and otherwise may
    // only be created without replacement; afterwards it is this grant's.
    fs::create_dir(&target).unwrap();
    assert!(existence_authority(
        &root,
        replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::New,
    )
    .is_err());
    fs::remove_dir(&target).unwrap();
    let authority = existence_authority(
        &root,
        replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::New,
    )
    .unwrap();
    let mut create_root = apply(mkdir(&target));
    let settlement = authority.authorize(&mut create_root, false).unwrap();
    assert_eq!(op_condition(&create_root), Absent);
    fs::create_dir(&target).unwrap();
    authority.settle(settlement, &proto::Response::Applied(vec![None]));
    let mut revisit_root = apply(mkdir(&target));
    authority.authorize(&mut revisit_root, false).unwrap();
    assert_eq!(op_condition(&revisit_root), Any);
    authority
        .authorize(&mut prepare_request(&target.join("child")), false)
        .unwrap();
    let mut child = finalize_request(&target.join("child"), Any);
    authority.authorize(&mut child, false).unwrap();
    assert_eq!(finalize_condition(&child), Any);

    // A root that must exist needs the object, and a directory whenever
    // the placement puts names inside it.
    fs::remove_dir(&target).unwrap();
    assert!(existence_authority(
        &root,
        replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Existing,
    )
    .is_err());
    fs::write(&target, b"file").unwrap();
    assert!(existence_authority(
        &root,
        replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Existing,
    )
    .is_err());
    existence_authority(
        &root,
        replace,
        DestinationPlacement::ExactPath,
        RootExistence::Existing,
    )
    .unwrap();
    fs::remove_file(&target).unwrap();
    fs::create_dir(&target).unwrap();
    existence_authority(
        &root,
        replace,
        DestinationPlacement::DirectoryAsChild,
        RootExistence::Existing,
    )
    .unwrap();

    // The one existing-object policy the receiver cannot enforce is
    // refused when the grant is redeemed rather than trusted.
    assert!(existence_authority(
        &root,
        ExistingDestinationPolicy::UpdateIfOlder,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .is_err());
}

#[test]
fn grant_distinguishes_receiver_modes_from_source_permission_preservation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let metadata = |flags| Request::Apply {
        ops: vec![Op::SetMeta {
            path: target.clone(),
            meta: proto::Meta {
                mode: 0o640,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags,
            condition: proto::TargetCondition::Any,
        }],
        guard: None,
    };

    let receiver_modes = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut receiver_mode = metadata(proto::flags::RECEIVER_MODE);
    receiver_modes.authorize(&mut receiver_mode, false).unwrap();
    let mut source_mode = metadata(proto::flags::MODE);
    assert!(receiver_modes.authorize(&mut source_mode, false).is_err());
    let mut mixed = metadata(proto::flags::MODE_MASK);
    assert!(receiver_modes.authorize(&mut mixed, false).is_err());

    let mut source_modes = test_authority(&root, DeletionPolicy::Forbid, 1024);
    source_modes.copy.options.preserve_permissions = true;
    source_modes.copy.options.receiver_managed_modes = false;
    let mut source_mkdir = Request::Apply {
        ops: vec![Op::Mkdir {
            path: target.clone(),
            mode: 0o750,
            condition: proto::TargetCondition::Any,
        }],
        guard: None,
    };
    source_modes.authorize(&mut source_mkdir, false).unwrap();
    let Request::Apply { ops, .. } = source_mkdir else {
        unreachable!()
    };
    assert!(matches!(ops[0], Op::Mkdir { mode: 0o750, .. }));
    let mut source_mode = metadata(proto::flags::MODE);
    source_modes.authorize(&mut source_mode, false).unwrap();
    let mut receiver_mode = metadata(proto::flags::RECEIVER_MODE);
    assert!(source_modes.authorize(&mut receiver_mode, false).is_err());
}

#[test]
fn explicit_ownership_flags_require_existing_grant_authority() {
    use proto::flags;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    for (attribute, required) in [
        (flags::OWNER, flags::REQUIRE_OWNER),
        (flags::GROUP, flags::REQUIRE_GROUP),
    ] {
        assert!(authority.check_flags(required).is_err());
        assert!(authority.check_flags(attribute | required).is_err());
    }
    authority.copy.options.preserve_owner = true;
    authority
        .check_flags(flags::OWNER | flags::REQUIRE_OWNER)
        .unwrap();
    assert!(authority
        .check_flags(flags::GROUP | flags::REQUIRE_GROUP)
        .is_err());
    authority.copy.options.preserve_group = true;
    authority
        .check_flags(flags::GROUP | flags::REQUIRE_GROUP)
        .unwrap();
    assert!(authority.check_flags(flags::REQUIRE_GROUP).is_err());
}

#[test]
fn receiver_managed_modes_preserve_existing_objects_and_mask_new_ones() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let existing_directory = target.join("existing-dir");
    let new_directory = target.join("new-dir");
    fs::create_dir_all(&existing_directory).unwrap();
    fs::set_permissions(&existing_directory, fs::Permissions::from_mode(0o500)).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.receiver_umask = 0o022;
    let path = |path: &Path| path.as_os_str().as_bytes().to_vec();

    let mut mkdir = Request::Apply {
        ops: vec![
            Op::Mkdir {
                path: path(&existing_directory),
                mode: 0o7777,
                condition: proto::TargetCondition::Any,
            },
            Op::Mkdir {
                path: path(&new_directory),
                mode: 0o7777,
                condition: proto::TargetCondition::Any,
            },
        ],
        guard: None,
    };
    authority.authorize(&mut mkdir, false).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &mkdir
    else {
        panic!("authority did not guard directory creation")
    };
    assert!(ops
        .iter()
        .all(|operation| matches!(operation, Op::Mkdir { mode: 0o700, .. })));
    assert!(crate::fsops::FsOps::new()
        .apply(ops, Some(guard))
        .into_iter()
        .all(|error| error.is_none()));
    assert_eq!(
        fs::metadata(&existing_directory).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(fs::metadata(&new_directory).unwrap().mode() & 0o7777, 0o700);

    let receiver_meta = |path: &Path| Op::SetMeta {
        path: path.as_os_str().as_bytes().to_vec(),
        meta: proto::Meta {
            mode: 0o7777,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: proto::flags::RECEIVER_MODE,
        condition: proto::TargetCondition::Any,
    };
    let mut metadata = Request::Apply {
        ops: vec![
            receiver_meta(&existing_directory),
            receiver_meta(&new_directory),
        ],
        guard: None,
    };
    authority.authorize(&mut metadata, false).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &metadata
    else {
        panic!("authority did not guard directory metadata")
    };
    assert!(matches!(
        &ops[0],
        Op::SetMeta {
            meta: proto::Meta { mode: 0o500, .. },
            flags: proto::flags::MODE,
            ..
        }
    ));
    assert!(matches!(
        &ops[1],
        Op::SetMeta {
            meta: proto::Meta { mode: 0o755, .. },
            flags: proto::flags::MODE,
            ..
        }
    ));
    assert!(crate::fsops::FsOps::new()
        .apply(ops, Some(guard))
        .into_iter()
        .all(|error| error.is_none()));
    assert_eq!(
        fs::metadata(&existing_directory).unwrap().mode() & 0o7777,
        0o500
    );
    assert_eq!(fs::metadata(&new_directory).unwrap().mode() & 0o7777, 0o755);

    let raced_directory = target.join("raced-dir");
    fs::create_dir(&raced_directory).unwrap();
    fs::set_permissions(&raced_directory, fs::Permissions::from_mode(0o500)).unwrap();
    let mut raced_mkdir = Request::Apply {
        ops: vec![Op::Mkdir {
            path: path(&raced_directory),
            mode: 0o7777,
            condition: proto::TargetCondition::Any,
        }],
        guard: None,
    };
    authority.authorize(&mut raced_mkdir, false).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &raced_mkdir
    else {
        unreachable!()
    };
    assert!(crate::fsops::FsOps::new()
        .apply(ops, Some(guard))
        .into_iter()
        .all(|error| error.is_none()));
    let mut raced_metadata = Request::Apply {
        ops: vec![receiver_meta(&raced_directory)],
        guard: None,
    };
    authority.authorize(&mut raced_metadata, false).unwrap();
    let displaced_directory = File::open(&raced_directory).unwrap();
    fs::remove_dir(&raced_directory).unwrap();
    fs::create_dir(&raced_directory).unwrap();
    fs::set_permissions(&raced_directory, fs::Permissions::from_mode(0o700)).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &raced_metadata
    else {
        unreachable!()
    };
    assert!(crate::fsops::FsOps::new()
        .apply(ops, Some(guard))
        .into_iter()
        .all(|error| error.is_some()));
    drop(displaced_directory);
    assert_eq!(
        fs::metadata(&raced_directory).unwrap().mode() & 0o7777,
        0o700
    );

    let existing_file = target.join("existing-file");
    let new_file = target.join("new-file");
    fs::write(&existing_file, b"old").unwrap();
    fs::set_permissions(&existing_file, fs::Permissions::from_mode(0o600)).unwrap();
    let put = |path: &Path, mode| proto::SmallPut {
        path: path.as_os_str().as_bytes().to_vec(),
        copy_id: [1; 16],
        data: b"new".to_vec(),
        hash: crate::fsops::content_digest(b"new"),
        meta: proto::Meta {
            mode,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: proto::flags::RECEIVER_MODE,
        inplace: false,
        condition: proto::TargetCondition::Any,
        guard: None,
    };
    let mut files =
        Request::PutSmallBatch(vec![put(&existing_file, 0o7777), put(&new_file, 0o7777)]);
    authority.authorize(&mut files, false).unwrap();
    let Request::PutSmallBatch(puts) = &files else {
        unreachable!()
    };
    assert_eq!(
        (puts[0].meta.mode, puts[0].flags),
        (0o600, proto::flags::MODE)
    );
    assert_eq!(
        (puts[1].meta.mode, puts[1].flags),
        (0o755, proto::flags::MODE)
    );
    assert!(matches!(
        puts[0].condition,
        proto::TargetCondition::MatchesFingerprint { .. }
    ));
    assert_eq!(puts[1].condition, proto::TargetCondition::Any);
    let response = crate::fsops::FsOps::new().handle(&files);
    let proto::Response::Applied(errors) = response else {
        panic!("unexpected small-publication response")
    };
    assert!(errors.iter().all(Option::is_none), "{errors:?}");
    assert_eq!(fs::read(&existing_file).unwrap(), b"new");
    assert_eq!(fs::metadata(&existing_file).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(fs::read(&new_file).unwrap(), b"new");
    assert_eq!(fs::metadata(&new_file).unwrap().mode() & 0o7777, 0o755);

    let mut repeated = Request::PutSmallBatch(vec![put(&new_file, 0o600)]);
    authority.authorize(&mut repeated, false).unwrap();
    let Request::PutSmallBatch(puts) = repeated else {
        unreachable!()
    };
    assert_eq!(
        (puts[0].meta.mode, puts[0].flags),
        (0o755, proto::flags::MODE)
    );

    // A later type replacement cannot reuse an existing directory's
    // receiver-owned mode (including any directory-only special bits) for
    // a newly published regular file.
    let mut replacement = Request::PutSmallBatch(vec![put(&existing_directory, 0o7777)]);
    authority.authorize(&mut replacement, false).unwrap();
    let Request::PutSmallBatch(puts) = replacement else {
        unreachable!()
    };
    assert_eq!(
        (puts[0].meta.mode, puts[0].flags),
        (0o755, proto::flags::MODE)
    );

    let raced_file = target.join("raced-file");
    fs::write(&raced_file, b"old").unwrap();
    fs::set_permissions(&raced_file, fs::Permissions::from_mode(0o6777)).unwrap();
    let mut raced = Request::PutSmallBatch(vec![put(&raced_file, 0o600)]);
    authority.authorize(&mut raced, false).unwrap();
    fs::remove_file(&raced_file).unwrap();
    let response = crate::fsops::FsOps::new().handle(&raced);
    assert!(matches!(
        response,
        proto::Response::Applied(errors) if errors.iter().all(Option::is_some)
    ));
    assert!(!raced_file.exists());
}

#[test]
fn receiver_managed_missing_root_preserves_receiver_umask_and_inherited_setgid() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o2755)).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.receiver_umask = 0o022;

    let mut mkdir = Request::Apply {
        ops: vec![Op::Mkdir {
            path: target.as_os_str().as_bytes().to_vec(),
            mode: 0o7777,
            condition: proto::TargetCondition::Any,
        }],
        guard: None,
    };
    authority.authorize(&mut mkdir, false).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &mkdir
    else {
        unreachable!()
    };
    assert!(matches!(ops[0], Op::Mkdir { mode: 0o700, .. }));
    assert!(crate::fsops::FsOps::new()
        .apply(ops, Some(guard))
        .into_iter()
        .all(|error| error.is_none()));
    // Linux propagates a parent's setgid bit to new directories; BSD-derived
    // kernels (macOS) inherit the group without the bit.
    let inherited_setgid = if cfg!(target_os = "linux") { 0o2000 } else { 0 };
    assert_eq!(
        fs::metadata(&target).unwrap().mode() & 0o7777,
        0o700 | inherited_setgid
    );

    let mut metadata = Request::Apply {
        ops: vec![Op::SetMeta {
            path: target.as_os_str().as_bytes().to_vec(),
            meta: proto::Meta {
                // None of these source-proposed special bits are trusted.
                mode: 0o7777,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: proto::flags::RECEIVER_MODE,
            condition: proto::TargetCondition::Any,
        }],
        guard: None,
    };
    authority.authorize(&mut metadata, false).unwrap();
    let Request::Apply {
        ops,
        guard: Some(guard),
    } = &metadata
    else {
        unreachable!()
    };
    assert!(matches!(
        ops[0],
        Op::SetMeta {
            meta: proto::Meta { mode, .. },
            flags: proto::flags::MODE,
            condition: proto::TargetCondition::MatchesFingerprint { .. },
            ..
        } if mode == 0o755 | inherited_setgid
    ));
    assert!(crate::fsops::FsOps::new()
        .apply(ops, Some(guard))
        .into_iter()
        .all(|error| error.is_none()));
    assert_eq!(
        fs::metadata(&target).unwrap().mode() & 0o7777,
        0o755 | inherited_setgid
    );
}

#[test]
fn signed_hash_block_and_response_bounds_are_enforced() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, DEFAULT_MAX_BYTES);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let request = |block, len| Request::HashBlocks {
        path: target.clone(),
        source: None,
        which: proto::Which::Final,
        copy_id: [0; 16],
        block,
        len,
        attempt: 0,
        guard: None,
    };

    let mut valid = request(4 << 20, 8 << 20);
    authority.authorize(&mut valid, false).unwrap();
    for block in [0, 1, 8 << 20] {
        let mut altered = request(block, 8 << 20);
        assert!(authority.authorize(&mut altered, false).is_err());
    }

    authority.copy.limits.hash_block_bytes = proto::MIN_HASH_BLOCK_BYTES;
    let excessive_entries = proto::MAX_FRAME as u64 / 32 + 1;
    let mut excessive = request(
        proto::MIN_HASH_BLOCK_BYTES,
        excessive_entries * proto::MIN_HASH_BLOCK_BYTES,
    );
    assert_eq!(
        authority
            .authorize(&mut excessive, false)
            .unwrap_err()
            .to_string(),
        "hash response would exceed protocol limits"
    );
}

#[test]
fn signed_file_data_rate_is_enforced_across_requests() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority_with_rate(&root, DeletionPolicy::Forbid, 1024, 1024);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let request = |off| Request::WriteRange {
        path: target.clone(),
        inplace: false,
        copy_id: [0; 16],
        attempt: 0,
        off,
        hash: [0; 32],
        data: vec![0; 256].into(),
        guard: None,
    };

    // Writes must land in a partial this grant declared.
    assert!(authority.authorize(&mut request(0), false).is_err());
    let mut prepare = Request::Prepare {
        path: target.clone(),
        size: 1024,
        inplace: false,
        copy_id: [0; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    authority.authorize(&mut prepare, false).unwrap();

    let started = Instant::now();
    authority.authorize(&mut request(0), false).unwrap();
    authority.authorize(&mut request(256), false).unwrap();
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(200),
        "signed aggregate rate limit did not pace consecutive writes"
    );

    let mut oversized = request(0);
    if let Request::WriteRange { data, .. } = &mut oversized {
        *data = vec![0; 513].into();
    }
    assert_eq!(
        authority
            .authorize(&mut oversized, false)
            .unwrap_err()
            .to_string(),
        "request exceeds the signed file-data rate-limit burst"
    );
}

#[test]
fn command_restricted_validation_accepts_a_signed_rate_limit() {
    let mut args = Args::try_parse_from(["syq", "source", "destination"]).unwrap();
    args.normalize();
    args.bwlimit_bytes = 1024;
    validate_restricted_args(&args).unwrap();
}

#[test]
fn ordinary_helper_selection_does_not_change_the_restricted_grant() {
    let mut args = Args::try_parse_from(["syq", "source", "destination"]).unwrap();
    args.normalize();
    args.syq_path = Some("/tmp/development-syq".to_owned());
    validate_restricted_args(&args).unwrap();
    args.syq_path = None;
    args.no_bootstrap = true;
    validate_restricted_args(&args).unwrap();
}

#[test]
fn authority_binds_one_encrypted_listener_and_known_metadata_flags() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut listener = Request::TcpListen {
        key: Some(vec![7; crate::tcp_records::KEY_LEN]),
        token: vec![8; 16],
        port_lo: 47_600,
        port_hi: 47_699,
        congestion_control: None,
    };
    authority.authorize(&mut listener, true).unwrap();
    assert!(authority.authorize(&mut listener, true).is_err());
    assert!(authority.control_is_open());
    authority.close_control();
    assert!(!authority.control_is_open());

    let wrong_range = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut listener = Request::TcpListen {
        key: Some(vec![7; crate::tcp_records::KEY_LEN]),
        token: vec![8; 16],
        port_lo: 1,
        port_hi: 2,
        congestion_control: None,
    };
    assert!(wrong_range.authorize(&mut listener, true).is_err());

    let congestion_override = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut listener = Request::TcpListen {
        key: Some(vec![7; crate::tcp_records::KEY_LEN]),
        token: vec![8; 16],
        port_lo: 47_600,
        port_hi: 47_699,
        congestion_control: Some("reno".into()),
    };
    assert!(congestion_override.authorize(&mut listener, true).is_err());

    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let mut metadata = Request::Apply {
        ops: vec![Op::SetMeta {
            path: target,
            meta: proto::Meta {
                mode: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0x80,
            condition: proto::TargetCondition::Any,
        }],
        guard: None,
    };
    assert!(wrong_range.authorize(&mut metadata, false).is_err());
}

#[test]
fn receiver_rejects_descriptor_copy_operations() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    for operation in [
        crate::descriptor_copy::Operation::Open {
            entry: 1,
            dry_run: false,
            only_new: false,
            only_existing: false,
            path: path_bytes(&root.join("file")),
            write: true,
            follow: false,
            root: None,
            placement: Default::default(),
            metadata: Default::default(),
            source_meta: None,
            settings: Default::default(),
        },
        crate::descriptor_copy::Operation::Finish { entry: 1, size: 0 },
        crate::descriptor_copy::Operation::Abort { entry: 1 },
    ] {
        let mut request = Request::DescriptorCopy(operation);
        assert!(authority.authorize(&mut request, true).is_err());
        assert!(!request.allowed_on_source_worker());
    }
    let mut rebind = Request::BindStream(None);
    assert!(authority.authorize(&mut rebind, true).is_err());
    assert!(!rebind.allowed_on_source_worker());
}

#[test]
fn receiver_enforces_authorized_hashing_and_supplies_omitted_expectation() {
    use crate::hashing::{CopyHashing, Digest, HashAlgorithm, HashPolicy};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let target = root.join("target");
    fs::write(&target, b"data").unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let policy = HashPolicy {
        algorithm: HashAlgorithm::Xxh3,
        transfer_integrity: false,
        transfer_hash_type: None,
    };
    let expected = Digest::hash_bytes(HashAlgorithm::Sha256, b"data");
    authority.hashing = Some(CopyHashing {
        policy,
        expected_hash: Some(expected.clone()),
    });
    let mut accepted = Request::ConfigureHashing(policy);
    authority.authorize(&mut accepted, false).unwrap();
    let mut changed = Request::ConfigureHashing(HashPolicy {
        transfer_integrity: true,
        transfer_hash_type: None,
        ..policy
    });
    assert!(authority.authorize(&mut changed, false).is_err());
    let mut finish = Request::FinishBasis {
        expected_hash: None,
        path: path_bytes(&target),
        copy_id: [1; 16],
        meta: plain_meta(),
        flags: 0,
        condition: proto::TargetCondition::Any,
        guard: None,
    };
    authority.authorize(&mut finish, false).unwrap();
    assert!(
        matches!(finish, Request::FinishBasis { expected_hash: Some(ref value), .. } if *value == expected)
    );
    assert!(authority.authorize(&mut small_put(&target), false).is_err());
}

#[test]
fn signed_read_only_modes_reject_every_destination_mutation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.copy.options.dry_run = true;
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let mut mutation = Request::Apply {
        ops: vec![Op::Mkdir {
            path: target.clone(),
            mode: 0o700,
            condition: proto::TargetCondition::Absent,
        }],
        guard: None,
    };
    assert!(authority.authorize(&mut mutation, false).is_err());

    let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
        path: target.clone(),
        copy_id: [1; 16],
        data: vec![0],
        hash: [0; 32],
        meta: proto::Meta {
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        inplace: false,
        condition: proto::TargetCondition::Any,
        guard: None,
    }]);
    assert!(authority.authorize(&mut small, false).is_err());

    let mut observation = Request::StatMany {
        paths: vec![target],
        sources: None,
        follow: false,
        guard: None,
    };
    authority.authorize(&mut observation, false).unwrap();
}

#[test]
fn directory_as_child_scope_does_not_authorize_unrelated_siblings() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let allowed = root.join("target/source").as_os_str().as_bytes().to_vec();
    authority.copy.mutation_scopes = vec![
        MutationScope {
            path: target.clone(),
            descendants: false,
        },
        MutationScope {
            path: allowed,
            descendants: true,
        },
    ];
    let mut request = Request::Apply {
        ops: vec![Op::Mkdir {
            path: root
                .join("target/unrelated")
                .as_os_str()
                .as_bytes()
                .to_vec(),
            mode: 0o700,
            condition: proto::TargetCondition::Absent,
        }],
        guard: None,
    };
    assert!(authority.authorize(&mut request, false).is_err());

    let mut observe_container = Request::StatMany {
        paths: vec![target],
        sources: None,
        follow: false,
        guard: None,
    };
    authority.authorize(&mut observe_container, false).unwrap();
}

#[test]
fn entry_ceiling_survives_resubmission_of_a_rejected_path() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    // The helper grant allows eight entries.
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let stat = |name: String| Request::StatMany {
        paths: vec![root
            .join("target")
            .join(name)
            .as_os_str()
            .as_bytes()
            .to_vec()],
        sources: None,
        follow: false,
        guard: None,
    };
    for index in 0..8 {
        authority
            .authorize(&mut stat(format!("entry-{index}")), false)
            .unwrap();
    }
    assert!(authority
        .authorize(&mut stat("entry-8".into()), false)
        .is_err());
    // Resubmitting the rejected path must not slip through as counted.
    assert!(authority
        .authorize(&mut stat("entry-8".into()), false)
        .is_err());
    // Paths already inside the ceiling remain usable.
    authority
        .authorize(&mut stat("entry-0".into()), false)
        .unwrap();
}

#[test]
fn forbidden_deletion_keeps_the_unfiltered_scan_but_refuses_removals() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority_with_policy(
        &root,
        DeletionPolicy::Forbid,
        16,
        0,
        FilterPolicy {
            ignore: vec!["ignored/".into()],
            destination_roots: Vec::new(),
            delete_excluded: true,
        },
        PublicationPolicy::AtomicStaged,
    );
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let mut unfiltered_scan = Request::Scan {
        root: target,
        source: None,
        follow_root: false,
        ignore: Vec::new(),
        report_ignored: true,
        guard: None,
    };
    authority.authorize(&mut unfiltered_scan, false).unwrap();
    let ignored = root
        .join("target/ignored/file")
        .as_os_str()
        .as_bytes()
        .to_vec();
    let mut delete = Request::Apply {
        ops: vec![Op::Unlink { path: ignored }],
        guard: None,
    };
    assert!(authority.authorize(&mut delete, false).is_err());
}

#[test]
fn preparation_and_seeding_are_charged_against_the_byte_ceiling() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    // The helper grant allows 16 bytes in total and per file.
    let authority = test_authority(&root, DeletionPolicy::Forbid, 16);
    let prepare = |name: &str, size| Request::Prepare {
        path: root
            .join("target")
            .join(name)
            .as_os_str()
            .as_bytes()
            .to_vec(),
        size,
        inplace: false,
        copy_id: [1; 16],
        mode: 0o600,
        attempt: 0,
        create_if_missing: true,
        guard: None,
    };
    authority.authorize(&mut prepare("a", 10), false).unwrap();
    // A second file would take the aggregate past the ceiling.
    assert!(authority.authorize(&mut prepare("b", 10), false).is_err());
    // Re-preparing the same file at the same or a larger size charges only
    // the difference; a retry never double counts.
    authority.authorize(&mut prepare("a", 10), false).unwrap();
    authority.authorize(&mut prepare("a", 14), false).unwrap();
    assert!(authority.authorize(&mut prepare("b", 3), false).is_err());
    authority.authorize(&mut prepare("b", 2), false).unwrap();
    let mut seed = Request::SeedBasis {
        final_ranges: None,
        path: root.join("target/b").as_os_str().as_bytes().to_vec(),
        copy_id: [1; 16],
        len: 3,
        block: proto::MIN_HASH_BLOCK_BYTES,
        attempt: 0,
        guard: None,
    };
    assert!(authority.authorize(&mut seed, false).is_err());

    // An empty file is declared at zero length and can be published.
    authority
        .authorize(&mut prepare("empty", 0), false)
        .unwrap();
    let mut publish_empty = Request::Finalize {
        expected_hash: None,
        path: root.join("target/empty").as_os_str().as_bytes().to_vec(),
        inplace: false,
        copy_id: [1; 16],
        meta: proto::Meta {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        condition: proto::TargetCondition::Any,
        guard: None,
    };
    authority.authorize(&mut publish_empty, false).unwrap();
    // A file never declared under this grant cannot be published.
    let mut publish_foreign = Request::Finalize {
        expected_hash: None,
        path: root.join("target/foreign").as_os_str().as_bytes().to_vec(),
        inplace: false,
        copy_id: [9; 16],
        meta: proto::Meta {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        condition: proto::TargetCondition::Any,
        guard: None,
    };
    assert!(authority.authorize(&mut publish_foreign, false).is_err());
}

#[test]
fn scanned_entries_count_against_the_entry_ceiling() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    // The helper grant allows eight entries.
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let mut scan = Request::Scan {
        root: target.clone(),
        source: None,
        follow_root: false,
        ignore: Vec::new(),
        report_ignored: false,
        guard: None,
    };
    authority.authorize(&mut scan, false).unwrap();
    let names: Vec<Vec<u8>> = (0..7)
        .map(|index| format!("entry-{index}").into_bytes())
        .collect();
    let mut batch: Vec<&[u8]> = vec![b""];
    batch.extend(names.iter().map(Vec::as_slice));
    // Root plus seven descendants fills the ceiling exactly.
    authority.record_scanned(&target, batch).unwrap();
    assert!(authority
        .record_scanned(&target, [b"entry-7".as_slice()])
        .is_err());
    // Already counted entries may be listed again.
    authority
        .record_scanned(&target, [b"entry-0".as_slice()])
        .unwrap();
}

#[test]
fn worker_authorizations_use_128_or_a_smaller_explicit_setting() {
    let source = Location::parse("host-a:source").unwrap();
    for (setting, expected) in [
        (None, 128),
        (Some("--resource-limits=workers=3"), 3),
        (Some("--resource-limits=workers=1000"), 128),
        (Some("--performance-tuning=workers=32"), 32),
        (Some("--performance-tuning=workers=128"), 128),
    ] {
        let mut argv: Vec<_> = [
            "cp", "--from", "host-a", "source", "--to", "host-b", "--as", "/backup",
        ]
        .map(std::ffi::OsString::from)
        .into();
        argv.extend(setting.map(std::ffi::OsString::from));
        let args = Args::parse_args(&argv).unwrap();
        validate_restricted_args(&args).unwrap();
        let grant = grant_for(
            &args,
            std::slice::from_ref(&source),
            EnrollmentId::random(),
            "backup",
            b"/backup",
        )
        .unwrap();
        let GrantOperation::Copy(copy) = grant.operation;
        assert_eq!(copy.limits.max_connections, expected);
    }
    let args = Args::parse_args(
        &[
            "cp",
            "--from",
            "host-a",
            "source",
            "--to",
            "host-b",
            "--as",
            "/backup",
            "--performance-tuning=workers=129",
        ]
        .map(std::ffi::OsString::from),
    )
    .unwrap();
    assert!(validate_restricted_args(&args).is_err());
}

#[test]
fn receiver_admission_keeps_each_authorizations_worker_allowance() {
    let temporary = crate::test_support::tempdir().unwrap();
    for workers in [2, 32, 64, 128] {
        let mut authority = test_authority(temporary.path(), DeletionPolicy::Forbid, 1024);
        authority.copy.limits.max_connections = workers;
        for _ in 0..workers {
            authority.acquire_connection().unwrap();
        }
        assert!(authority.acquire_connection().is_err());
        authority.release_connection();
        authority.acquire_connection().unwrap();
        assert!(authority.acquire_connection().is_err());
    }
}

#[test]
fn ceiling_ranges_are_checked_before_any_enrollment_side_effect() {
    let parse = |options: &[&str]| {
        let mut argv = vec!["syq rsync", "-r"];
        argv.extend_from_slice(options);
        argv.extend_from_slice(&["host-a:source", "host-b:/backup"]);
        let mut args = Args::try_parse_from(argv).unwrap();
        args.normalize();
        args
    };
    // validate_restricted_args runs first in prepare_transfer, before
    // the enrollment lookup or installation.
    let mut args = parse(&[]);
    validate_restricted_args(&args).unwrap();
    args.receiver_max_entries = Some(0);
    assert!(validate_restricted_args(&args).is_err());
    args.receiver_max_entries = Some(delegation::MAX_ENTRIES + 1);
    assert!(validate_restricted_args(&args).is_err());
    let mut args = parse(&[]);
    args.receiver_max_bytes = Some(0);
    assert!(validate_restricted_args(&args).is_err());
    assert!(validate_restricted_args(&parse(&["--max-size", "0"])).is_err());
    assert!(validate_restricted_args(&parse(&["--delete"])).is_err());
    validate_restricted_args(&parse(&["--delete", "--max-delete", "0"])).unwrap();

    // A zero deletion budget signs a grant that forbids deletion outright.
    let id = EnrollmentId::random();
    let source = Location::parse("host-a:source").unwrap();
    let grant = grant_for(
        &parse(&["--delete", "--max-delete", "0"]),
        std::slice::from_ref(&source),
        id,
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::Forbid);
    assert_eq!(copy.limits.max_deletions, 0);
}

#[test]
fn native_comparison_block_size_sets_the_signed_receiver_limit() {
    let args = Args::parse_args(
        &[
            "cp",
            "--from",
            "host-a",
            "source",
            "--to",
            "host-b",
            "--as",
            "/backup",
            "--performance-tuning=comparison-block-size=64K,request-size=4M",
        ]
        .map(std::ffi::OsString::from),
    )
    .unwrap();
    let source = Location::parse("host-a:source").unwrap();
    let grant = grant_for(
        &args,
        &[source],
        EnrollmentId::random(),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = grant.operation;
    assert_eq!(copy.limits.hash_block_bytes, 64 << 10);
}

#[test]
fn explicit_ceilings_are_signed_and_deletion_needs_a_stated_budget() {
    let id = EnrollmentId::random();
    let source = Location::parse("host-a:source").unwrap();
    let parse = |options: &[&str]| {
        let mut argv = vec!["syq rsync", "-r"];
        argv.extend_from_slice(options);
        argv.extend_from_slice(&["host-a:source", "host-b:/backup"]);
        let mut args = Args::try_parse_from(argv).unwrap();
        args.normalize();
        args
    };

    // Defaults are the wide built-in ceilings and the 24-hour validity.
    let default_args = parse(&[]);
    let default_grant = grant_for(
        &default_args,
        std::slice::from_ref(&source),
        id,
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(default_copy) = &default_grant.operation;
    assert_eq!(default_copy.limits.max_entries, DEFAULT_MAX_ENTRIES);
    assert_eq!(default_copy.limits.max_total_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(default_copy.limits.max_file_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(
        default_grant.start_by - default_grant.not_before,
        GRANT_VALIDITY_SECONDS
    );
    assert_eq!(
        default_grant.finish_by - default_grant.issued_at,
        FINISH_WINDOW_SECONDS
    );

    // Explicit ceilings land in the signed limits; the per-file bound
    // never exceeds the total, and the validity shrinks to the runtime.
    let mut ceilings = parse(&["--max-size", "3M"]);
    ceilings.receiver_max_entries = Some(12);
    ceilings.receiver_max_bytes = Some(2 << 20);
    let grant = grant_for(
        &ceilings,
        std::slice::from_ref(&source),
        id,
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.limits.max_entries, 12);
    assert_eq!(copy.limits.max_total_bytes, 2 << 20);
    assert_eq!(copy.limits.max_file_bytes, 2 << 20);
    assert_eq!(grant.issued_at - grant.not_before, CLOCK_SKEW_SECONDS);

    // Deletion authority must be stated; it is then capped by the entry
    // ceiling so the grant stays self-consistent.
    let unbounded = parse(&["--delete"]);
    assert!(grant_for(
        &unbounded,
        std::slice::from_ref(&source),
        id,
        "backup",
        b"/backup"
    )
    .is_err());
    let mut bounded = parse(&["--delete", "--max-delete", "40"]);
    bounded.receiver_max_entries = Some(30);
    let grant = grant_for(
        &bounded,
        std::slice::from_ref(&source),
        id,
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::DeleteDestinationOnly);
    assert_eq!(copy.limits.max_deletions, 30);
    // A read-only run plans no deletion, so it needs no budget.
    let preview = parse(&["--delete", "--dry-run"]);
    let grant = grant_for(&preview, &[source], id, "backup", b"/backup").unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::Forbid);
}

#[test]
fn signed_scopes_distinguish_named_children_from_directory_contents() {
    let id = EnrollmentId::random();
    let mut named_args =
        Args::try_parse_from(["syq rsync", "-r", "host-a:source", "host-b:/backup"]).unwrap();
    named_args.normalize();
    let named_source = Location::parse("host-a:source").unwrap();
    let named = grant_for(&named_args, &[named_source], id, "backup", b"/backup").unwrap();
    let GrantOperation::Copy(named) = named.operation;
    assert_eq!(
        named.mutation_scopes,
        vec![
            MutationScope {
                path: b"/backup".to_vec(),
                descendants: false,
            },
            MutationScope {
                path: b"/backup/source".to_vec(),
                descendants: true,
            },
        ]
    );

    let mut contents_args =
        Args::try_parse_from(["syq rsync", "-r", "host-a:source/", "host-b:/backup"]).unwrap();
    contents_args.normalize();
    let contents_source = Location::parse("host-a:source/").unwrap();
    let contents = grant_for(&contents_args, &[contents_source], id, "backup", b"/backup").unwrap();
    let GrantOperation::Copy(contents) = contents.operation;
    assert_eq!(
        contents.mutation_scopes,
        vec![MutationScope {
            path: b"/backup".to_vec(),
            descendants: true,
        }]
    );

    let mut nonrecursive_args =
        Args::try_parse_from(["syq rsync", "host-a:file", "host-b:/backup"]).unwrap();
    nonrecursive_args.normalize();
    let file = Location::parse("host-a:file").unwrap();
    let nonrecursive = grant_for(&nonrecursive_args, &[file], id, "backup", b"/backup").unwrap();
    let GrantOperation::Copy(nonrecursive) = nonrecursive.operation;
    assert!(nonrecursive
        .mutation_scopes
        .iter()
        .all(|scope| !scope.descendants));

    let mut unsupported = nonrecursive_args;
    unsupported.min_size = Some("1".into());
    let file = Location::parse("host-a:file").unwrap();
    assert!(grant_for(&unsupported, &[file], id, "backup", b"/backup").is_err());
}

#[test]
fn rooted_scan_and_hash_never_follow_a_payload_symlink() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(target.join("inside"), b"inside").unwrap();
    fs::write(outside.join("secret"), b"secret").unwrap();
    symlink(&outside, target.join("escape")).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);

    let mut scan = Request::Scan {
        root: target.as_os_str().as_bytes().to_vec(),
        source: None,
        follow_root: false,
        ignore: Vec::new(),
        report_ignored: false,
        guard: None,
    };
    authority.authorize(&mut scan, true).unwrap();
    let Request::Scan {
        guard: Some(guard), ..
    } = scan
    else {
        panic!("authority did not install a scan guard")
    };
    let mut entries = Vec::new();
    crate::scan::scan_rooted(
        target.as_os_str().as_bytes(),
        false,
        &[],
        false,
        &guard,
        &mut |batch| {
            entries.extend(batch);
            Ok(())
        },
        &mut |_| Ok(()),
        &mut |_| {},
    )
    .unwrap();
    assert!(entries.iter().any(|entry| entry.path == b"inside"));
    assert!(entries
        .iter()
        .any(|entry| { entry.path == b"escape" && entry.kind == proto::Kind::Symlink }));
    assert!(!entries.iter().any(|entry| entry.path == b"escape/secret"));

    let response = crate::fsops::FsOps::new().handle(&Request::HashBlocks {
        path: target.join("escape").as_os_str().as_bytes().to_vec(),
        source: None,
        which: proto::Which::Final,
        copy_id: [0; 16],
        block: 4096,
        len: 1,
        attempt: 0,
        guard: Some(guard),
    });
    assert!(matches!(response, proto::Response::EndpointError(_)));
    assert_eq!(fs::metadata(outside.join("secret")).unwrap().len(), 6);
}

#[test]
fn restricted_authority_rejects_caller_source_registration() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut request = Request::RegisterSourceRoots {
        base: proto::SourceRootBase::default(),
        selections: vec![proto::SourceRootSelection {
            path: root.as_os_str().as_bytes().to_vec(),
            follow_root: false,
        }],
        symlink_policy: proto::OperatorSymlinkPolicy::Refuse,
        allow_unconfined_paths: false,
        shared_workers: 0,
        independent_handoff_workers: 0,
    };
    let error = authority.authorize(&mut request, true).unwrap_err();
    assert!(error
        .to_string()
        .contains("not valid on a root-confined receiver"));

    let session = crate::descriptor_broker::DescriptorSessionSlot::default();
    let ticket = session.register(fs::File::open(&root).unwrap()).unwrap();
    let source = proto::RegisteredPath::new(ticket.root_id(), Vec::new()).unwrap();
    let mut scan = Request::Scan {
        root: root.as_os_str().as_bytes().to_vec(),
        source: Some(source.clone()),
        follow_root: false,
        ignore: Vec::new(),
        report_ignored: false,
        guard: None,
    };
    let error = authority.authorize(&mut scan, true).unwrap_err();
    assert!(error
        .to_string()
        .contains("source references are not valid"));

    for mut request in [
        Request::FileHash {
            path: root.join("file").as_os_str().as_bytes().to_vec(),
            source: Some(source.clone()),
            guard: None,
        },
        Request::HashBlocks {
            path: root.join("file").as_os_str().as_bytes().to_vec(),
            source: Some(source),
            which: proto::Which::Final,
            copy_id: [0; 16],
            block: proto::MIN_HASH_BLOCK_BYTES,
            len: 1,
            attempt: 0,
            guard: None,
        },
    ] {
        let error = authority.authorize(&mut request, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("source references are not valid"));
    }
}
