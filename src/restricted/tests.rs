use super::*;
use crate::process::CommandExt as _;
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
            ManagementAction::Revoke,
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
        crate::test_support::write_executable(
            &root.join("bin/ssh"),
            br#"#!/bin/sh
for argument do command=$argument; done
case "$command" in
    *'uname -s'*) printf '%s\n%s\n' "$SYQ_TEST_REMOTE_OS" "$SYQ_TEST_REMOTE_ARCH" ;;
    *'--restricted-revoke'*) cat > "$SYQ_TEST_UPLOAD" ;;
    *) exit 91 ;;
esac
"#,
            0o700,
        );
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
            .capture_output()
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
        send_rate: None,
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
    assert!(authority
        .authorize(&mut Request::CreateSendBudget { rate: 1024 }, true)
        .is_err());
    let mut paced = listener(Some("cubic"));
    if let Request::TcpListen { send_rate, .. } = &mut paced {
        *send_rate = Some(1024);
    }
    assert!(authority.authorize(&mut paced, true).is_err());
}

#[test]
fn released_enrollment_state_is_never_read_or_touched() {
    // Unmodified output from checksum-verified v0.7.1 in the disposable SSH lab.
    let receiver = include_bytes!("../../tests/fixtures/restricted-enrollment-v0.7.1.json");
    let local = include_bytes!("../../tests/fixtures/restricted-local-enrollment-v0.7.1.json");
    let released = "8ae0ca10655849f7823a0bc50a8c83c2";
    let (account, account_home) = current_account().unwrap();
    let temporary = tempfile::Builder::new()
        .prefix("syq-released-")
        .tempdir_in(account_home)
        .unwrap();
    let home = temporary.path();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    let private = |path: &Path| {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    };
    let write = |path: &Path, contents: &[u8], mode: u32| {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    // The released layout on both sides, as v0.7.1 wrote it.
    let old_state = home.join(".local/share/syq/restricted").join(released);
    let old_local = home.join(".local/state/syq/restricted").join(released);
    private(&old_state);
    private(&old_local);
    write(&old_state.join("config.json"), receiver, 0o600);
    write(&old_local.join("metadata.json"), local, 0o600);
    private(&home.join(".local/libexec"));
    let old_receiver = home.join(".local/libexec/syq-receiver");
    write(&old_receiver, b"released receiver", 0o700);
    private(&home.join(".ssh"));
    let old_key = generate_test_key("released").unwrap();
    let old_line = format!(
        "restrict,command=\"{}/.local/libexec/syq-receiver --restricted-receiver --enrollment={released}\" {} syq-enrollment:{released}\n",
        home.display(),
        old_key.public_key().to_openssh().unwrap()
    );
    let original = format!("# unrelated\n{old_line}");
    let authorized_keys = home.join(".ssh/authorized_keys");
    write(&authorized_keys, original.as_bytes(), 0o600);

    // A new enrollment for the same account goes beside it.
    let login = generate_test_key("login").unwrap();
    let entry = generate_test_key("entry").unwrap();
    let id = EnrollmentId::random();
    let request = InstallRequest {
        version: CONFIG_VERSION,
        id,
        target_login: account.clone(),
        entry_public_key: entry.public_key().to_openssh().unwrap(),
        signer: delegation::TrustedSigner::new(login.public_key(), None, None).unwrap(),
        refresh: false,
        replaces: None,
    };
    let InstallResponse::Installed { generation, .. } =
        install_for_account(&request, &account, home).unwrap()
    else {
        panic!("install did not install");
    };
    assert_eq!(generation, 1);
    let updated = fs::read_to_string(&authorized_keys).unwrap();
    assert!(updated.starts_with(&original), "{updated}");
    assert_eq!(updated.lines().count(), 3);
    assert_eq!(fs::read(old_state.join("config.json")).unwrap(), receiver);
    assert_eq!(fs::read(old_local.join("metadata.json")).unwrap(), local);
    assert_eq!(fs::read(&old_receiver).unwrap(), b"released receiver");
    assert!(enrollment_state(home, id).join("config.json").is_file());

    // The new receiver has no state for the released ID, and refuses
    // released state wherever it finds it.
    let released_id = EnrollmentId::parse(released).unwrap();
    assert!(read_receiver_config(&enrollment_state(home, released_id))
        .unwrap()
        .is_none());
    let misplaced = enrollment_state(home, released_id);
    private(&misplaced);
    write(&misplaced.join("config.json"), receiver, 0o600);
    assert!(read_receiver_config(&misplaced).is_err());

    // `syq receiver list` points at the docs, and changes nothing.
    let notice = released_enrollment_notice(home).unwrap();
    assert!(notice.contains("0.4.0 to 0.7.1"), "{notice}");
    assert!(
        notice.contains("#enrollments-from-older-versions"),
        "{notice}"
    );
    assert!(released_enrollment_notice(&home.join("missing")).is_none());

    // The enrolling machine lists only current enrollments.
    let base = home.join(".local/state/syq/enrollments");
    private(&base.join(released));
    write(&base.join(released).join(ENROLLMENT_FILE), local, 0o600);
    assert!(load_local_enrollments_in(&base).unwrap().is_empty());
}
/// A temporary home in the real account's home, with a private `.ssh`.
fn enrollment_home() -> (String, tempfile::TempDir) {
    let (account, account_home) = current_account().unwrap();
    let temporary = tempfile::Builder::new()
        .prefix("syq-enroll-")
        .tempdir_in(account_home)
        .unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let ssh = temporary.path().join(".ssh");
    fs::create_dir(&ssh).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    (account, temporary)
}

fn install_request(
    account: &str,
    id: EnrollmentId,
    entry: &PrivateKey,
    login: &PrivateKey,
    refresh: bool,
) -> InstallRequest {
    InstallRequest {
        version: CONFIG_VERSION,
        id,
        target_login: account.to_owned(),
        entry_public_key: entry.public_key().to_openssh().unwrap(),
        signer: delegation::TrustedSigner::new(login.public_key(), None, None).unwrap(),
        refresh,
        replaces: None,
    }
}

fn installed(response: InstallResponse) -> (u64, bool) {
    match response {
        InstallResponse::Installed {
            generation,
            changed,
            release,
            ..
        } => {
            assert_eq!(release, crate::identity::build());
            (generation, changed)
        }
        InstallResponse::StateMissing { .. } => panic!("install reported missing state"),
    }
}

#[test]
fn rotation_rewrites_only_the_signer_and_raises_the_generation() {
    let (account, home) = enrollment_home();
    let home = home.path();
    let id = EnrollmentId::random();
    let entry = generate_test_key("entry").unwrap();
    let first_login = generate_test_key("first login").unwrap();
    let request = install_request(&account, id, &entry, &first_login, false);
    assert_eq!(
        installed(install_for_account(&request, &account, home).unwrap()),
        (1, true)
    );
    let authorized_keys = home.join(".ssh/authorized_keys");
    let line = fs::read_to_string(&authorized_keys).unwrap();
    assert!(line.contains("--generation=1\""), "{line}");
    let receiver = store_receiver_path(home);
    assert!(line.starts_with(&format!("restrict,command=\"{}", receiver.display())));
    assert!(receiver.is_file());
    // The comment names the trusted login key.
    let words: Vec<_> = first_login
        .public_key()
        .to_openssh()
        .unwrap()
        .split_whitespace()
        .take(2)
        .map(str::to_owned)
        .collect();
    assert!(line
        .trim_end()
        .ends_with(&format!("signer {} {}", words[0], words[1])));

    // The same request again changes nothing.
    let mut refresh = install_request(&account, id, &entry, &first_login, true);
    assert_eq!(
        installed(install_for_account(&refresh, &account, home).unwrap()),
        (1, false)
    );
    assert_eq!(fs::read_to_string(&authorized_keys).unwrap(), line);

    // A new certificate for the same key, or a new touch or PIN policy,
    // changes only the recorded signer. The line, and so the generation and
    // the connections it admits, stay.
    let original_signer = refresh.signer.clone();
    refresh.signer =
        delegation::TrustedSigner::new(first_login.public_key(), None, Some(4_000_000_000))
            .unwrap();
    assert_eq!(
        installed(install_for_account(&refresh, &account, home).unwrap()),
        (1, true)
    );
    assert_eq!(fs::read_to_string(&authorized_keys).unwrap(), line);
    let config = read_receiver_config(&enrollment_state(home, id))
        .unwrap()
        .unwrap();
    assert_eq!((config.generation, &config.signer), (1, &refresh.signer));
    refresh.signer = original_signer;
    assert_eq!(
        installed(install_for_account(&refresh, &account, home).unwrap()),
        (1, true)
    );

    // A new login key replaces only the trusted signer: the entry key, and
    // so connections it admits, stay.
    let second_login = generate_test_key("second login").unwrap();
    refresh.signer = delegation::TrustedSigner::new(second_login.public_key(), None, None).unwrap();
    assert_eq!(
        installed(install_for_account(&refresh, &account, home).unwrap()),
        (2, true)
    );
    let rotated = fs::read_to_string(&authorized_keys).unwrap();
    assert_eq!(rotated.lines().count(), 1);
    assert!(rotated.contains("--generation=2\""));
    assert!(rotated.contains(
        entry
            .public_key()
            .to_openssh()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
    ));
    assert!(!rotated.contains(&words[1]));
    let config = read_receiver_config(&enrollment_state(home, id))
        .unwrap()
        .unwrap();
    assert_eq!(config.generation, 2);
    assert_eq!(config.signer, refresh.signer);
    assert_eq!(config.entry_public_key, request.entry_public_key);

    // A receiver recorded for another build is refreshed too.
    let mut stale = config.clone();
    stale.release = "v0.0.0-old".into();
    atomic_write(
        &enrollment_state(home, id),
        "config.json",
        &serde_json::to_vec(&stale).unwrap(),
        0o600,
    )
    .unwrap();
    assert_eq!(
        installed(install_for_account(&refresh, &account, home).unwrap()),
        (3, true)
    );

    // Another entry key for the same enrollment is refused.
    let other_entry = generate_test_key("other entry").unwrap();
    let error = install_for_account(
        &install_request(&account, id, &other_entry, &second_login, true),
        &account,
        home,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("different entry key"),
        "{error:#}"
    );
}

#[test]
fn lost_server_state_means_a_new_enrollment_that_replaces_the_old_line() {
    let (account, home) = enrollment_home();
    let home = home.path();
    let id = EnrollmentId::random();
    let entry = generate_test_key("entry").unwrap();
    let login = generate_test_key("login").unwrap();
    install_for_account(
        &install_request(&account, id, &entry, &login, false),
        &account,
        home,
    )
    .unwrap();
    let authorized_keys = home.join(".ssh/authorized_keys");
    let before = fs::read(&authorized_keys).unwrap();
    fs::remove_dir_all(enrollment_state(home, id)).unwrap();

    // A refresh finds no state and changes nothing: re-creating it would
    // start an empty record of used grants.
    let response = install_for_account(
        &install_request(&account, id, &entry, &login, true),
        &account,
        home,
    )
    .unwrap();
    assert!(matches!(response, InstallResponse::StateMissing { id: missing, .. } if missing == id));
    assert_eq!(fs::read(&authorized_keys).unwrap(), before);
    assert!(!enrollment_state(home, id).exists());

    // The new enrollment removes the old one's line.
    let new_id = EnrollmentId::random();
    let new_entry = generate_test_key("new entry").unwrap();
    let mut request = install_request(&account, new_id, &new_entry, &login, false);
    request.replaces = Some(ReplacedEnrollment {
        id,
        entry_public_key: entry.public_key().to_openssh().unwrap(),
    });
    assert_eq!(
        installed(install_for_account(&request, &account, home).unwrap()),
        (1, true)
    );
    let after = fs::read_to_string(&authorized_keys).unwrap();
    assert_eq!(after.lines().count(), 1);
    assert!(after.contains(&format!("syq-enrollment:{new_id}")));
    assert!(!after.contains(&format!("syq-enrollment:{id}")));

    // A grant for the lost enrollment, or for an older generation, is refused.
    let config = read_receiver_config(&enrollment_state(home, new_id))
        .unwrap()
        .unwrap();
    let source = Location::parse("host-a:source").unwrap();
    let args = {
        let mut args =
            Args::try_parse_from(["syq rsync", "-r", "host-a:source", "host-b:/backup"]).unwrap();
        args.normalize();
        args
    };
    let replay_path = enrollment_state(home, new_id).join("replay");
    let replay = delegation::ReplayStore::open(&replay_path).unwrap();
    let signer = keys::LoginSigner::File(Box::new(login.clone()));
    for (grant_id, generation, accepted) in [(id, 1, false), (new_id, 2, false), (new_id, 1, true)]
    {
        let grant = grant_for(
            &args,
            std::slice::from_ref(&source),
            (grant_id, generation),
            &account,
            b"/backup",
        )
        .unwrap();
        let encoded = delegation::sign_grant_with(
            grant,
            GrantConstraints {
                tcp_congestion: None,
                mapping: None,
                hashing: None,
                max_file_data_bytes_per_second: 0,
                filters: FilterPolicy::default(),
                root_existence: RootExistence::Any,
                receipt_policy: results_policy().1,
                extra_options: Default::default(),
            },
            |payload| signer.sign(delegation::SSHSIG_NAMESPACE, payload),
        )
        .unwrap();
        let expected_signer = signer_name(new_id, config.generation);
        let context = delegation::ReceiverContext {
            enrollment_id: new_id,
            target_login: &account,
            expected_signer: &expected_signer,
            clock: delegation::ClockObservation {
                unix_seconds: now().unwrap(),
                monotonic: Instant::now(),
            },
            clock_skew_seconds: CLOCK_SKEW_SECONDS,
        };
        assert_eq!(
            delegation::verify_and_redeem(&encoded, &context, &config.signer, &replay).is_ok(),
            accepted,
            "{grant_id} {generation}"
        );
    }
}

#[test]
fn a_lost_reply_to_a_replacement_enrollment_is_retried_not_duplicated() {
    let (_, home) = current_account().unwrap();
    let temporary = tempfile::tempdir_in(home).unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let replaced = || ReplacedEnrollment {
        id: EnrollmentId::random(),
        entry_public_key: generate_test_key("old")
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
    };
    // No earlier attempt: a new enrollment.
    let fresh = replacement_plan(temporary.path(), None, replaced()).unwrap();
    assert!(fresh.entry_key.is_none() && !fresh.refresh && fresh.replaces.is_some());
    // An earlier attempt whose reply was lost: the same ID and entry key.
    let id = EnrollmentId::random();
    let directory = temporary.path().join(id.to_string());
    ensure_directory(&directory, 0o700).unwrap();
    let entry = generate_test_key("entry").unwrap();
    store_entry_key(&directory, &entry).unwrap();
    let pending = PendingEnrollment {
        version: CONFIG_VERSION,
        id,
        host: "host-b".into(),
        port: None,
        target_login: "backup".into(),
    };
    let retried = replacement_plan(
        temporary.path(),
        Some((pending, directory.clone())),
        replaced(),
    )
    .unwrap();
    assert_eq!(retried.id, id);
    assert_eq!(retried.directory, directory);
    assert_eq!(retried.entry_key.unwrap().public_key(), entry.public_key());
    assert!(!retried.refresh && retried.replaces.is_some());
}

#[test]
fn a_receiver_from_an_older_line_refuses_new_copies() {
    let login = generate_test_key("login").unwrap();
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id: EnrollmentId::random(),
        target_login: "backup".into(),
        generation: 4,
        release: "v0.8.0".into(),
        receiver_path: "/home/backup/.local/lib/syq/v0.8.0/linux-x86_64/syq".into(),
        entry_public_key: generate_test_key("entry")
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        signer: delegation::TrustedSigner::new(login.public_key(), None, None).unwrap(),
    };
    require_current_receiver(&config, 4, "v0.8.0").unwrap();
    for (generation, build) in [(3, "v0.8.0"), (4, "v0.7.9"), (5, "v0.8.0")] {
        let error = require_current_receiver(&config, generation, build).unwrap_err();
        assert!(error.to_string().contains("outdated receiver"), "{error}");
    }
    // The state names no device or inode.
    let encoded = serde_json::to_string(&config).unwrap();
    for field in ["dev", "ino", "root"] {
        assert!(!encoded.contains(&format!("\"{field}")), "{encoded}");
    }
}

/// Every key of a JSON document, at any depth.
fn json_keys(value: &serde_json::Value, keys: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                keys.insert(key.clone());
                json_keys(value, keys);
            }
        }
        serde_json::Value::Array(values) => values.iter().for_each(|value| json_keys(value, keys)),
        _ => {}
    }
}

fn file_keys(path: &Path) -> std::collections::BTreeSet<String> {
    let mut keys = Default::default();
    json_keys(
        &serde_json::from_slice(&fs::read(path).unwrap()).unwrap(),
        &mut keys,
    );
    keys
}

#[test]
fn enrollment_state_names_no_device_or_inode_and_sessions_compare_none() {
    let expected = |names: &[&str]| -> std::collections::BTreeSet<String> {
        names.iter().map(|name| name.to_string()).collect()
    };
    // The server's state, as an install writes it.
    let (account, home) = enrollment_home();
    let home = home.path();
    let id = EnrollmentId::random();
    let entry = generate_test_key("entry").unwrap();
    let login = generate_test_key("login").unwrap();
    install_for_account(
        &install_request(&account, id, &entry, &login, false),
        &account,
        home,
    )
    .unwrap();
    let state = enrollment_state(home, id);
    assert_eq!(
        file_keys(&state.join("config.json")),
        expected(&[
            "version",
            "id",
            "target_login",
            "generation",
            "release",
            "receiver_path",
            "entry_public_key",
            "signer",
            "public_key",
        ])
    );

    // The enrolling machine's records, pending and complete.
    let directory = home.join("local").join(id.to_string());
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    store_entry_key(&directory, &entry).unwrap();
    atomic_write(
        &directory,
        PENDING_FILE,
        &serde_json::to_vec(&PendingEnrollment {
            version: CONFIG_VERSION,
            id,
            host: "host-b".into(),
            port: Some(2222),
            target_login: account.clone(),
        })
        .unwrap(),
        0o600,
    )
    .unwrap();
    assert_eq!(
        file_keys(&directory.join(PENDING_FILE)),
        expected(&["version", "id", "host", "port", "target_login"])
    );
    complete_local_enrollment(
        &directory,
        &LocalEnrollment {
            version: CONFIG_VERSION,
            id,
            host: "host-b".into(),
            port: Some(2222),
            target_login: account.clone(),
            remote_home: home.to_string_lossy().into_owned(),
            generation: 1,
            release: crate::identity::build().into(),
            receiver_path: store_receiver_path(home).to_string_lossy().into_owned(),
            results_public_key: generate_results_key(id)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            signer: delegation::TrustedSigner::new(login.public_key(), None, Some(1_900_000_000))
                .unwrap(),
            identity_file: Some(home.join("id_ed25519")),
            receiving_state: Vec::new(),
        },
    )
    .unwrap();
    assert_eq!(
        file_keys(&directory.join(ENROLLMENT_FILE)),
        expected(&[
            "version",
            "id",
            "host",
            "port",
            "target_login",
            "remote_home",
            "generation",
            "release",
            "receiver_path",
            "results_public_key",
            "signer",
            "public_key",
            "valid_before",
            "identity_file",
        ])
    );

    // A receiver session uses its state and the filesystem as it finds
    // them: what an earlier session opened is nowhere to compare against.
    let parent = home.join("mounted");
    fs::create_dir(&parent).unwrap();
    let destination = parent.join("archive");
    let session = || {
        let config = read_receiver_config(&state).unwrap().unwrap();
        require_current_receiver(&config, 1, crate::identity::build()).unwrap();
        ConfinedRoot::resolve(destination.as_os_str().as_bytes(), &[]).unwrap()
    };
    let first = session().identity();
    fs::rename(&parent, home.join("unmounted")).unwrap();
    fs::create_dir(&parent).unwrap();
    let second = session().identity();
    assert_ne!(first, second);
}

#[test]
fn protected_destinations_are_refused_from_their_names_before_enrolling() {
    let home = Path::new("/home/backup");
    // What the server's login reported: no XDG variables, no TMPDIR.
    let receiving = server_receiving_state(home, "1000", "Linux", ("", "", ""));
    let refused = |placement: &str, destination: &str| {
        let contents = placement == "contents";
        let source = Location::parse(if contents {
            "host-a:data/"
        } else {
            "host-a:data"
        })
        .unwrap();
        let mut args = Args::try_parse_from([
            "syq rsync",
            "-r",
            if contents {
                "host-a:data/"
            } else {
                "host-a:data"
            },
            &format!("host-b:{destination}"),
        ])
        .unwrap();
        args.normalize();
        if placement == "as" {
            args.placement = Placement::As;
        }
        refuse_protected_destination(
            &args,
            std::slice::from_ref(&source),
            destination.as_bytes(),
            "backup",
            (home, &receiving),
        )
        .err()
        .map(|error| error.to_string())
    };
    for (placement, destination, label) in [
        ("into", "~/.ssh", "SSH configuration directory"),
        ("as", ".ssh/authorized_keys", "SSH configuration directory"),
        (
            "as",
            "/home/backup/.ssh/authorized_keys",
            "SSH configuration directory",
        ),
        (
            "into",
            "/home/backup/.local/lib/syq",
            "store of syq executables",
        ),
        (
            "into",
            "~/.local/share/syq/enrollments",
            "enrollment state directory",
        ),
        (
            "into",
            ".local/state/syq/enrollments/x",
            "enrollment state directory",
        ),
        (
            "into",
            "~/.local/libexec",
            "released receiver executable directory",
        ),
        (
            "into",
            "~/.syq-destinations-v3",
            "named destination authority state",
        ),
        (
            "into",
            "~/.config/syq",
            "background receiving control state",
        ),
        (
            "into",
            "~/.syq-receiver-identity",
            "background receiving control state",
        ),
        (
            "into",
            "/tmp/syq-persist-1000",
            "background receiving control state",
        ),
        (
            "as",
            "/tmp/syq-persist-1000/global",
            "background receiving control state",
        ),
        // Contents copied into a directory reach everything beneath it.
        ("contents", "~", "SSH configuration directory"),
        (
            "contents",
            "~/.config",
            "background receiving control state",
        ),
        ("contents", "/tmp", "background receiving control state"),
    ] {
        let error =
            refused(placement, destination).unwrap_or_else(|| panic!("{destination} was accepted"));
        assert!(error.contains(label), "{destination}: {error}");
    }
    // Named sources copied into a directory change only that directory and
    // the sources' own names in it, so a directory above a protected one is
    // fine.
    for (placement, destination) in [
        ("into", "~/archive"),
        ("into", "/srv/archive"),
        ("as", ".ssh-backup"),
        ("into", "~/.config/other"),
        ("into", "~"),
        ("into", "/tmp"),
        ("into", "~/.config"),
        ("into", "~/.local/state"),
        ("into", "~/.local/lib"),
        ("contents", "/tmp/other"),
    ] {
        assert_eq!(refused(placement, destination), None, "{destination}");
    }
    // Where the server's environment moves its receiving state.
    let moved = server_receiving_state(
        home,
        "1000",
        "Linux",
        ("/srv/config", "/run/user/1000", "/var/tmp"),
    );
    assert_eq!(
        moved,
        [
            home.join(".syq-receiver-identity"),
            PathBuf::from("/srv/config/syq"),
            PathBuf::from("/run/user/1000/syq-persist-1000"),
        ]
    );
    assert_eq!(
        server_receiving_state(home, "501", "Darwin", ("", "", "/var/folders/x"))[2],
        Path::new("/tmp/syq-persist-501")
    );
    assert_eq!(
        server_receiving_state(home, "7", "Linux", ("relative", "relative", "/var/tmp"))[1..],
        [
            home.join(".config/syq"),
            PathBuf::from("/var/tmp/syq-persist-7")
        ]
    );
}

#[test]
fn receivers_refuse_protected_paths_beneath_a_recursive_destination_only() {
    let temporary = crate::test_support::tempdir().unwrap();
    let parent = temporary.path().join("parent");
    let target = parent.join("target");
    fs::create_dir_all(target.join("inner")).unwrap();
    let protected = vec![ReceiverControlPath {
        path: target.join("inner").as_os_str().as_bytes().to_vec(),
        label: "test control directory",
    }];
    let authority = |source: &str, placement: Placement, destination: &Path| {
        let mut args = Args::try_parse_from(["syq rsync", "-r", source, "host-b:/unused"]).unwrap();
        args.normalize();
        args.placement = placement;
        let location = Location::parse(source).unwrap();
        let named = destination.as_os_str().as_bytes();
        let grant = grant_for(
            &args,
            std::slice::from_ref(&location),
            (EnrollmentId::random(), 1),
            "receiver",
            named,
        )
        .unwrap();
        ConfinedRoot::resolve(named, &protected).and_then(|confined| {
            RestrictedAuthority::new(
                confined,
                grant,
                GrantConstraints::default(),
                [0; 32],
                generate_results_key(EnrollmentId::random()).unwrap(),
                Instant::now() + std::time::Duration::from_secs(60),
                &protected,
            )
        })
    };
    // Named sources into the directory above the protected one.
    authority("host-a:data", Placement::Into, &target).unwrap();
    // Its contents could reach the protected directory.
    let error = authority("host-a:data/", Placement::Into, &target)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("test control directory"),
        "{error:#}"
    );
    // At or beneath it, whatever the placement.
    for (source, placement, destination) in [
        ("host-a:data", Placement::Into, target.join("inner")),
        ("host-a:file", Placement::As, target.join("inner/file")),
    ] {
        let error = authority(source, placement, &destination).err().unwrap();
        assert!(
            error.to_string().contains("test control directory"),
            "{error:#}"
        );
    }
}

#[test]
fn a_destination_is_resolved_afresh_by_every_copy() {
    // The directory a destination goes in is opened when each copy starts,
    // so replacing it, as a remount does, changes nothing for the
    // enrollment.
    let temporary = crate::test_support::tempdir().unwrap();
    let parent = temporary.path().join("mounted");
    fs::create_dir(&parent).unwrap();
    let destination = parent.join("archive");
    let named = destination.as_os_str().as_bytes();
    let first = ConfinedRoot::resolve(named, &[]).unwrap();
    let first_identity = first.identity();
    drop(first);
    fs::rename(&parent, temporary.path().join("unmounted")).unwrap();
    fs::create_dir(&parent).unwrap();
    let second = ConfinedRoot::resolve(named, &[]).unwrap();
    assert_ne!(second.identity(), first_identity);
    assert_eq!(second.identity(), Root::open(&parent).unwrap().identity());

    // Through a link, the directory is where the link leads, and a
    // protected directory is refused by identity whatever the names say.
    let protected_directory = temporary.path().join("protected");
    fs::create_dir_all(protected_directory.join("inside")).unwrap();
    let protected = vec![ReceiverControlPath {
        path: protected_directory.as_os_str().as_bytes().to_vec(),
        label: "test control directory",
    }];
    symlink(
        protected_directory.join("inside"),
        temporary.path().join("link"),
    )
    .unwrap();
    let through_link = temporary.path().join("link/archive");
    let error = ConfinedRoot::resolve(through_link.as_os_str().as_bytes(), &protected)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("test control directory"),
        "{error:#}"
    );
    ConfinedRoot::resolve(named, &protected).unwrap();
    // A directory above a protected one is fine: the copy writes only
    // beneath its destination.
    ConfinedRoot::resolve(
        protected_directory.join("sibling").as_os_str().as_bytes(),
        &[ReceiverControlPath {
            path: protected_directory
                .join("inside")
                .as_os_str()
                .as_bytes()
                .to_vec(),
            label: "test control directory",
        }],
    )
    .unwrap();
    let error = ConfinedRoot::resolve(
        protected_directory
            .join("inside/archive")
            .as_os_str()
            .as_bytes(),
        &protected,
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("test control directory"),
        "{error:#}"
    );
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
        let state_base = home.join(".local/share/syq/enrollments");
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

        let entry_key = generate_test_key("entry").unwrap();
        let login = generate_test_key("login").unwrap();
        let entry_public = entry_key.public_key().to_openssh().unwrap();
        let line = AuthorizedKeyEntry::enrollment(
            id,
            &store_receiver_path(home),
            1,
            &EnrollmentPublicKey::parse(&entry_public).unwrap(),
            &EnrollmentPublicKey::login(&login.public_key().to_openssh().unwrap()).unwrap(),
        )
        .unwrap();
        let original = format!("{}\n", line.line()).into_bytes();
        let authorized_keys = ssh.join("authorized_keys");
        fs::write(&authorized_keys, &original).unwrap();
        fs::set_permissions(&authorized_keys, fs::Permissions::from_mode(0o600)).unwrap();

        let request = RevokeRequest {
            version: CONFIG_VERSION,
            id,
            target_login: account.clone(),
            entry_public_key: entry_public,
        };
        let error = revoke_for_account(&request, &account, home).unwrap_err();
        assert!(
            error.to_string().contains("must have mode 0700"),
            "{error:#}"
        );
        assert_eq!(fs::read(authorized_keys).unwrap(), original);
    }
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
        let remote = management_remote_command(stage, ManagementAction::Revoke, request)
            .expect("build management command");
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(remote)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_guarded()
            .unwrap();
        child.stdin.take().unwrap().write_all(script).unwrap();
        child.wait_with_output().unwrap()
    }

    let temporary = crate::test_support::tempdir().unwrap();
    let request = br#"{"value":"' ; exit 91; #"}"#;
    let output = invoke(
        temporary.path(),
        ".syq-stage-test-success",
        b"#!/bin/sh\ncat\n",
        request,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, request);
    let store = temporary.path().join(".local/lib/syq");
    assert!(!store.join(".syq-stage-test-success").exists());
    assert!(store.is_dir());
    // The store's own directory is private; the ones above it are not
    // syq's to restrict.
    assert_eq!(fs::metadata(&store).unwrap().mode() & 0o777, 0o700);

    let output = invoke(
        temporary.path(),
        ".syq-stage-test-failure",
        b"#!/bin/sh\nexit 23\n",
        b"failure request",
    );
    assert_eq!(output.status.code(), Some(23));
    assert!(!store.join(".syq-stage-test-failure").exists());
}

#[test]
fn the_enrollment_session_installs_with_a_stored_build_instead_of_an_upload() {
    let temporary = crate::test_support::tempdir().unwrap();
    let home = temporary.path();
    let run = |input: &[u8]| -> Vec<String> {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(install_remote_command(".syq-stage-test"))
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_guarded()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    };
    // Lines 0 to 6 are the platform and state locations; line 7 lists the
    // platforms the store has this build for, and line 8 starts
    // authorized_keys.
    let mut upload = b"{\"request\":1}\n\n".to_vec();
    upload.extend_from_slice(b"#!/bin/sh\nprintf 'sent %s ' \"$*\"; cat\n");
    let greeting = run(&upload);
    assert_eq!(greeting[7].trim(), "");
    assert_eq!(greeting[8], "0");
    assert_eq!(greeting[9], r#"sent --restricted-install {"request":1}"#);

    let build = home.join(BINARY_STORE).join(crate::identity::build());
    crate::test_support::write_executable(
        &build.join("linux-x86_64/syq"),
        "#!/bin/sh\nprintf 'stored %s ' \"$*\"; cat\n",
        0o700,
    );
    // Another build, and a file that is not executable, are not offered.
    crate::test_support::write_executable(
        &home.join(BINARY_STORE).join("v0.0.0-old/linux-aarch64/syq"),
        "#!/bin/sh\nexit 1\n",
        0o700,
    );
    fs::create_dir_all(build.join("macos-aarch64")).unwrap();
    fs::write(build.join("macos-aarch64/syq"), "not a program").unwrap();
    let greeting = run(b"{\"request\":2}\nlinux-x86_64\n");
    assert_eq!(greeting[7].trim(), "linux-x86_64");
    assert_eq!(greeting[9], r#"stored --restricted-install {"request":2}"#);
    assert!(fs::read_dir(home.join(BINARY_STORE))
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".syq-stage")));
}
/// Execute authorized Apply operations as a connection of `authority`'s
/// copy executes them.
fn execute_ops(authority: &RestrictedAuthority, ops: &[Op]) -> Vec<Option<proto::WireError>> {
    match authority
        .test_ops()
        .handle(&Request::Apply { ops: ops.to_vec() })
    {
        proto::Response::Applied(results) => results,
        other => panic!("unexpected response {other:?}"),
    }
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

/// A signed-grant authority over `root/target` that preserves times,
/// manages modes on the receiver, and admits files of up to 1 MiB, for
/// other modules' tests.
pub(crate) fn time_preserving_test_authority(root: &Path) -> RestrictedAuthority {
    time_preserving_test_authority_of(root, 1 << 20)
}

/// The same, admitting files of up to `maximum_bytes`.
pub(crate) fn time_preserving_test_authority_of(
    root: &Path,
    maximum_bytes: u64,
) -> RestrictedAuthority {
    let mut authority = test_authority(root, DeletionPolicy::Forbid, maximum_bytes);
    authority.copy.options.preserve_times = true;
    authority
}

/// The same, for up to `entries` paths, preserving the sources' permissions
/// when `permissions` is set.
pub(crate) fn time_preserving_test_authority_for(
    root: &Path,
    maximum_bytes: u64,
    entries: u64,
    permissions: bool,
) -> RestrictedAuthority {
    let mut authority = time_preserving_test_authority_of(root, maximum_bytes);
    authority.copy.limits.max_entries = entries;
    authority.copy.options.preserve_permissions = permissions;
    authority
}

/// A signed-grant authority over `root/target` that lets the copy update
/// existing files in place (`--in-place=update`), preserving times, for up
/// to `entries` paths, for other modules' tests.
pub(crate) fn in_place_update_test_authority_for(root: &Path, entries: u64) -> RestrictedAuthority {
    let mut authority = test_authority_with_policy(
        root,
        DeletionPolicy::Forbid,
        64 << 20,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlaceUpdate,
    );
    authority.copy.options.preserve_times = true;
    authority.copy.limits.max_entries = entries;
    authority
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

/// A grant's results policy naming a fresh recipient, and the recipient's
/// secret.
fn results_policy() -> (
    crate::destination_results::RecipientSecret,
    crate::destination_results::ReceiptPolicy,
) {
    let (secret, public) = crate::destination_results::generate_recipient().unwrap();
    (
        secret,
        crate::destination_results::ReceiptPolicy::for_recipient(public),
    )
}

/// Start an authority's results, as a coordinator between two servers does
/// before anything else, and read them as the invoking machine does.
fn start_results(
    authority: &RestrictedAuthority,
    secret: crate::destination_results::RecipientSecret,
) -> crate::destination_results::Reader {
    authority.start_results(true).unwrap();
    crate::destination_results::Reader::new(crate::destination_results::Expectation {
        public_key: authority.results_key.public_key().to_openssh().unwrap(),
        binding: crate::destination_results::Binding {
            enrollment_id: authority.enrollment_id,
            request_id: authority.request_id,
            grant_digest: authority.grant_digest,
        },
        secret,
        records: true,
    })
}

struct ReadResults {
    records: Vec<serde_json::Value>,
    totals: crate::destination_results::Totals,
}

impl ReadResults {
    /// Each listed change as (action, destination path, disposition).
    fn changes(&self) -> Vec<(String, Vec<u8>, String)> {
        self.records
            .iter()
            .filter(|record| record["type"] == "operation_result")
            .map(|record| {
                let dst = &record["dst"];
                let path = match dst["encoding"].as_str() {
                    Some("base64") => {
                        use base64::Engine as _;
                        base64::engine::general_purpose::STANDARD
                            .decode(dst["value"].as_str().unwrap())
                            .unwrap()
                    }
                    _ => dst["value"].as_str().unwrap().as_bytes().to_vec(),
                };
                (
                    record["action"].as_str().unwrap().to_owned(),
                    path,
                    record["disposition"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    fn has(&self, action: &str, path: &[u8], disposition: &str) -> bool {
        self.changes()
            .iter()
            .any(|(a, p, d)| a == action && p == path && d == disposition)
    }
}

/// End an authority's results and verify everything it sent.
fn finish_results(
    authority: &RestrictedAuthority,
    reader: &mut crate::destination_results::Reader,
) -> ReadResults {
    authority.finish_results().unwrap();
    let mut records = Vec::new();
    for frame in authority.take_results_frames() {
        reader
            .accept(&frame, |record| {
                records.push(record);
                Ok(())
            })
            .unwrap();
    }
    ReadResults {
        records,
        totals: reader.finish().unwrap(),
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
    test_authority_with_results(
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
fn test_authority_with_results(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
    max_file_data_bytes_per_second: u64,
    filters: FilterPolicy,
    publication: PublicationPolicy,
    existing: ExistingDestinationPolicy,
    placement: DestinationPlacement,
    root_existence: RootExistence,
    results: Option<(PrivateKey, crate::destination_results::ReceiptPolicy)>,
) -> Result<RestrictedAuthority> {
    test_authority_with_options(
        root,
        deletion,
        maximum_bytes,
        max_file_data_bytes_per_second,
        filters,
        publication,
        existing,
        placement,
        root_existence,
        results,
        (Default::default(), &[]),
    )
}

/// `test_authority_with_results` with signed extra copy options and the
/// receiver's protected paths.
#[allow(clippy::too_many_arguments)]
fn test_authority_with_options(
    root: &Path,
    deletion: DeletionPolicy,
    maximum_bytes: u64,
    max_file_data_bytes_per_second: u64,
    mut filters: FilterPolicy,
    publication: PublicationPolicy,
    existing: ExistingDestinationPolicy,
    placement: DestinationPlacement,
    root_existence: RootExistence,
    results: Option<(PrivateKey, crate::destination_results::ReceiptPolicy)>,
    (extra_options, protected): (crate::delegation::ExtraCopyOptions, &[ReceiverControlPath]),
) -> Result<RestrictedAuthority> {
    let identity = Root::open(root).unwrap().identity();
    let id = EnrollmentId::random();
    let confined = ConfinedRoot::opened(root, identity)?;
    let destination = root.join("target");
    if !filters.ignore.is_empty() && filters.destination_roots.is_empty() {
        filters.destination_roots = vec![destination.as_os_str().as_bytes().to_vec()];
    }
    let grant = Grant {
        enrollment_id: id,
        target_login: "receiver".into(),
        signer: signer_name(id, 1),
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
    let (results_key, receipt_policy) = match results {
        Some((key, policy)) => (key, policy),
        None => (generate_results_key(id)?, results_policy().1),
    };
    RestrictedAuthority::new(
        confined,
        grant,
        GrantConstraints {
            tcp_congestion: None,
            mapping: None,
            hashing: None,
            max_file_data_bytes_per_second,
            filters,
            root_existence,
            receipt_policy,
            extra_options,
        },
        [0; 32],
        results_key,
        Instant::now() + std::time::Duration::from_secs(60),
        protected,
    )
}

#[test]
fn restricted_destinations_cannot_overlap_receiver_control_paths() {
    let protected = receiver_control_paths(
        Path::new("/home/receiver"),
        None,
        ControlPaths::Elsewhere(&[]),
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
            b"/home/receiver/.local/lib/syq/v1.0.0/linux-x86_64/syq".as_slice(),
            "store of syq executables",
        ),
        (
            b"/home/receiver/.local/share/syq/enrollments/enrollment".as_slice(),
            "enrollment state directory",
        ),
        (
            b"/home/receiver/.local/state/syq/enrollments/enrollment".as_slice(),
            "enrollment state directory",
        ),
        (
            b"/home/receiver/.local/share/syq/restricted/enrollment".as_slice(),
            "released enrollment state directory",
        ),
        (
            b"/home/receiver/.local/libexec/syq-receiver".as_slice(),
            "released receiver executable directory",
        ),
        (
            b"/home/receiver/.syq-destinations-v3/x".as_slice(),
            "named destination authority state",
        ),
    ] {
        let error = reject_control_plane_path(path, &protected).unwrap_err();
        assert!(error.to_string().contains(label), "{error}");
    }
}
#[test]
fn enrolled_destinations_accept_any_bytes() {
    use std::os::unix::ffi::OsStrExt as _;
    // A destination whose name is not UTF-8 is named in the grant as it is.
    let mut requested = b"archive/leaf-".to_vec();
    requested.push(0xff);
    let normalized = normalize_absolute(
        std::ffi::OsStr::from_bytes(&requested),
        Path::new("/home/backup"),
    )
    .unwrap();
    let mut expected = b"/home/backup/archive/leaf-".to_vec();
    expected.push(0xff);
    assert_eq!(normalized.as_os_str().as_bytes(), expected);
    for (requested, expected) in [
        ("~", "/home/backup"),
        ("~/a", "/home/backup/a"),
        ("/srv/a/./b", "/srv/a/b"),
    ] {
        assert_eq!(
            normalize_absolute(std::ffi::OsStr::new(requested), Path::new("/home/backup")).unwrap(),
            Path::new(expected)
        );
    }
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
fn results_keys_are_distinct_and_persist_for_an_enrollment() {
    let id = EnrollmentId::random();
    let key = generate_results_key(id).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(public.ends_with(&format!("syq-results:{id}")));
    let again = generate_results_key(id).unwrap();
    assert_ne!(again.public_key().to_openssh().unwrap(), public);
    ssh_key::PublicKey::from_openssh(&public).unwrap();

    // An install keeps the key it finds, so a refresh or a retried
    // install reports the same public key the local side already has.
    let (_, home) = current_account().unwrap();
    let temporary = tempfile::tempdir_in(home).unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = temporary.path().join("state");
    ensure_directory(&state, 0o700).unwrap();
    let first = ensure_results_key(&state, id).unwrap();
    let second = ensure_results_key(&state, id).unwrap();
    assert_eq!(
        first.public_key().to_openssh().unwrap(),
        second.public_key().to_openssh().unwrap()
    );
    assert!(state.join(RESULTS_KEY_FILE).is_file());
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
    };
    let entry_key = generate_test_key("entry").unwrap();
    store_entry_key(&directory, &entry_key).unwrap();
    atomic_write(
        &directory,
        PENDING_FILE,
        &serde_json::to_vec(&pending).unwrap(),
        0o600,
    )
    .unwrap();
    assert!(directory.join(PENDING_FILE).is_file());
    assert_eq!(
        fs::metadata(directory.join("entry-key")).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(
        load_entry_key(&directory).unwrap().public_key(),
        entry_key.public_key()
    );
    assert!(load_local_enrollments_in(temporary.path())
        .unwrap()
        .is_empty());

    let login = generate_test_key("login").unwrap();
    let metadata = LocalEnrollment {
        version: CONFIG_VERSION,
        id,
        host: pending.host,
        port: pending.port,
        target_login: pending.target_login,
        remote_home: "/home/backup".into(),
        generation: 1,
        release: crate::identity::build().into(),
        receiver_path: "/home/backup/.local/lib/syq/v1/linux-x86_64/syq".into(),
        results_public_key: generate_results_key(id)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        signer: delegation::TrustedSigner::new(login.public_key(), None, None).unwrap(),
        identity_file: None,
        receiving_state: Vec::new(),
    };
    complete_local_enrollment(&directory, &metadata).unwrap();
    assert!(!directory.join(PENDING_FILE).exists());
    assert!(directory.join(ENROLLMENT_FILE).is_file());
    assert!(directory.join("entry-key").is_file());
    let listed = load_local_enrollments_in(temporary.path()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0.id, id);
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
    };
    authority.authorize(&mut request, false).unwrap();
    let response = authority.test_ops().handle(&request);
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
    };
    assert!(authority.authorize(&mut outside, false).is_err());
}

#[test]
fn authority_rejects_scope_and_option_escalation() {
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
    };
    authority.authorize(&mut stat, false).unwrap();

    let mut plan = Request::PlanBatch {
        partial_paths: vec![target.clone()],
        copy_id: [3; 16],
        directories: vec![target.clone()],
        others: vec![target.clone()],
        strict_metadata: false,
    };
    authority.authorize(&mut plan, false).unwrap();

    let mut outside_stat = Request::StatMany {
        paths: vec![outside.clone()],
        sources: None,
        follow: false,
    };
    assert!(authority.authorize(&mut outside_stat, false).is_err());

    let mut mkdir = Request::Apply {
        ops: vec![Op::Mkdir {
            path: target.clone(),
            mode: 0o7777,
            condition: proto::TargetCondition::Absent,
        }],
    };
    authority.authorize(&mut mkdir, false).unwrap();
    let Request::Apply { ops, .. } = mkdir else {
        unreachable!()
    };
    // Without -p the sender proposes no special bits.
    assert!(matches!(ops[0], Op::Mkdir { mode: 0o777, .. }));

    let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
        path: target.clone(),
        copy_id: [1; 16],
        data: vec![0; 4],
        hash: [0; 32],
        meta: proto::Meta {
            inode_metadata: None,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: proto::flags::RECEIVER_MODE,
        inplace: false,
        condition: proto::TargetCondition::Any,
        replaces: false,
        scanned: crate::proto::ScannedDestination::Unknown,
    }]);
    authority.authorize(&mut small, false).unwrap();

    let mut write = Request::WriteRange {
        path: target,
        inplace: false,
        copy_id: [0; 16],
        attempt: 0,
        off: 0,
        hash: [0; 32],
        data: vec![0; 5].into(),
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
    };
    authority.authorize(&mut exact, false).unwrap();

    let mut parent = Request::Canonicalize { path: parent };
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
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
    };
    let mut included_prepare = prepare(included);
    authority.authorize(&mut included_prepare, false).unwrap();
    let mut ignored_prepare = prepare(ignored.clone());
    assert!(authority.authorize(&mut ignored_prepare, false).is_err());
    let mut protected_delete = Request::Apply {
        ops: vec![Op::Unlink {
            path: ignored.clone(),
        }],
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
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
    };
    let mut cache_root = prepare(cache.clone());
    authority.authorize(&mut cache_root, false).unwrap();
    let mut cache_child = prepare(crate::fsops::join(&cache, b"file"));
    authority.authorize(&mut cache_child, false).unwrap();
}

#[test]
fn signed_in_place_policies_admit_in_place_and_staged_file_mutations() {
    // Under an in-place policy the receiver writes in place only a file it
    // creates, and replaces anything else through a stage, so staged
    // requests are admitted too. The policy of earlier releases is read
    // as the narrower one. A staged policy admits no in-place request.
    for (policy, admits_in_place) in [
        (PublicationPolicy::InPlace, true),
        (PublicationPolicy::InPlaceNew, true),
        (PublicationPolicy::AtomicStaged, false),
    ] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority_with_policy(
            &root,
            DeletionPolicy::Forbid,
            16,
            0,
            FilterPolicy::default(),
            policy,
        );
        let target = root.join("target/file").as_os_str().as_bytes().to_vec();
        let prepare = |inplace| Request::Prepare {
            path: target.clone(),
            size: 4,
            inplace,
            copy_id: [1; 16],
            mode: 0o600,
            flags: 0,
            acl: false,
            scanned: crate::proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
        };
        let mut inplace = prepare(true);
        assert_eq!(
            authority.authorize(&mut inplace, false).is_ok(),
            admits_in_place,
            "{policy:?}"
        );
        let mut staged = prepare(false);
        authority.authorize(&mut staged, false).unwrap();
    }
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

/// The signed grant bounds what the receiver widens: nothing unless approved;
/// under `rsync`, directories the copy includes, to change their entries but
/// never to enter one it could not read; under `all`, also the directory the
/// copy goes into, here the confinement root, whose identity the receiver pins.
/// Never a directory above the root, nor one beside the copy.
#[test]
fn restricted_widening_follows_the_approved_mode() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(target.join("sub")).unwrap();
    fs::create_dir_all(root.join("other")).unwrap();
    let identity = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        proto::TargetCondition::Matches {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    };
    let widen = |path: &Path, access: u32, condition| Request::WidenDirectories {
        access,
        remember: true,
        directories: vec![(path_bytes(path), condition)],
    };
    for mode in [
        DirectoryWidening::None,
        DirectoryWidening::Rsync,
        DirectoryWidening::All,
    ] {
        let mut authority = existence_authority(
            &root,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
        )
        .unwrap();
        authority.extra_options.widen_dirs = mode;
        let sub = target.join("sub");
        let allowed = |request: &mut Request| authority.authorize(request, false).is_ok();
        assert_eq!(
            allowed(&mut widen(&sub, 0o300, identity(&sub))),
            mode != DirectoryWidening::None,
            "{mode:?}"
        );
        assert_eq!(
            allowed(&mut widen(&sub, 0o500, identity(&sub))),
            mode == DirectoryWidening::All,
            "{mode:?}"
        );
        for path in [temp.path(), &root.join("other")] {
            assert!(
                !allowed(&mut widen(path, 0o300, identity(path))),
                "{mode:?}: {}",
                path.display()
            );
        }
        let mut outer = widen(&root, 0o300, proto::TargetCondition::Any);
        let authorized = authority.authorize(&mut outer, false);
        assert_eq!(
            authorized.is_ok(),
            mode == DirectoryWidening::All,
            "{mode:?}"
        );
        let Ok(settlement) = authorized else {
            continue;
        };
        let Request::WidenDirectories { directories, .. } = &outer else {
            unreachable!()
        };
        assert_eq!(directories[0].1, identity(&root));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        let mut ops = authority.test_ops();
        let response = ops.handle(&outer);
        authority.settle(settlement, &response);
        let widened = fs::metadata(&root).unwrap().mode() & 0o777;
        assert!(
            matches!(response, proto::Response::WidenedDirectories(ref outcomes)
                if outcomes.len() == 1 && outcomes[0].is_ok()),
            "{response:?}"
        );
        assert_eq!(widened, 0o700);
        // Its metadata can only be restored: whatever mode the sender asks
        // for, it gets back the one it had.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let restore = Request::Apply {
            ops: vec![Op::SetMeta {
                path: path_bytes(&root),
                meta: proto::Meta {
                    mode: 0o777,
                    ..plain_meta()
                },
                flags: proto::flags::MODE,
                condition: identity(&root),
                directory: false,
            }],
        };
        let response = execute_authorized(&authority, &mut ops, restore);
        assert!(
            matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
            "{response:?}"
        );
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o500);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

/// Under an approved `all`, a restricted receiver gives the owned directories
/// from its confinement root down to the destination, the root included, the
/// search permission reaching it needs, as an ordinary receiver does, and
/// restores them when asked. It never walks above the root, and refuses a
/// destination named outside it.
#[test]
fn restricted_all_widens_ancestors_beneath_the_enrolled_root() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("root");
    let middle = root.join("middle");
    let destination = middle.join("target");
    fs::create_dir_all(&destination).unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().mode() & 0o777;
    let above = mode(temp.path());
    let prepare = |path: &Path| Request::PrepareDestinationPath {
        path: path_bytes(path),
        symlink_policy: proto::OperatorSymlinkPolicy::FollowAll,
        create_missing: true,
    };
    for widen in [
        DirectoryWidening::None,
        DirectoryWidening::Rsync,
        DirectoryWidening::All,
    ] {
        let mut authority = existence_authority(
            &root,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
        )
        .unwrap();
        // A destination deeper than its root, as a download's can be.
        authority.destination = path_bytes(&destination);
        authority.extra_options.widen_dirs = widen;
        let mut request = prepare(&destination);
        let authorized = authority.authorize(&mut request, false);
        assert_eq!(
            authorized.is_ok(),
            widen == DirectoryWidening::All,
            "{widen:?}"
        );
        let Ok(settlement) = authorized else {
            continue;
        };
        assert!(authority
            .authorize(&mut prepare(temp.path()), false)
            .is_err());
        fs::set_permissions(&middle, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o600)).unwrap();
        let mut ops = authority.test_ops();
        let response = ops.handle(&request);
        authority.settle(settlement, &response);
        assert!(matches!(response, proto::Response::Ok), "{response:?}");
        assert_eq!([mode(&root), mode(&middle)], [0o700, 0o700]);
        assert_eq!(mode(temp.path()), above);
        let response = execute_authorized(&authority, &mut ops, Request::RestoreDestinationPath);
        assert!(matches!(response, proto::Response::Ok), "{response:?}");
        assert_eq!(mode(&root), 0o600);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(mode(&middle), 0o600);
        fs::set_permissions(&middle, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

fn plain_meta() -> proto::Meta {
    proto::Meta {
        inode_metadata: None,
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
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
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
        scanned: crate::proto::ScannedDestination::Unknown,
        condition,
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
        replaces: false,
        scanned: crate::proto::ScannedDestination::Unknown,
    }])
}

fn small_put_condition(request: &Request) -> proto::TargetCondition {
    let Request::PutSmallBatch(puts) = request else {
        unreachable!()
    };
    puts[0].condition
}

fn apply(op: Op) -> Request {
    Request::Apply { ops: vec![op] }
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
        Op::Hardlink { .. } | Op::Remove { .. } | Op::Rmdir { .. } | Op::Unlink { .. } => {
            unreachable!()
        }
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
        meta: Default::default(),
        flags: 0,
    }
}

fn set_meta(path: &Path) -> Op {
    Op::SetMeta {
        path: path_bytes(path),
        meta: plain_meta(),
        flags: 0,
        condition: proto::TargetCondition::Any,
        directory: false,
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
    let Request::Apply { ops } = &create else {
        unreachable!()
    };
    let results = execute_ops(&authority, ops);
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
        };
        let settlement = authority.authorize(&mut batch, false).unwrap();
        if !before_authorization {
            create_foreign();
        }
        let before = fs::metadata(&raced).unwrap();
        let Request::Apply { ops } = &batch else {
            unreachable!()
        };
        let results = execute_ops(&authority, ops);
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
            let response = authority.test_ops().handle(&request);
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
        let response = authority.test_ops().handle(&request);
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
            authority.extra_options.widen_dirs = DirectoryWidening::Rsync;
            admit_test_mapping(&mut authority, "parent/item");
            // The connection that widens a directory restores it.
            let mut ops = authority.test_ops();
            let mut request = apply(mkdir(&parent));
            let settlement = authority.authorize(&mut request, false).unwrap();
            let response = ops.handle(&request);
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
                assert_eq!(fs::metadata(&parent).unwrap().mode(), original.mode());
                let mut access = Request::WidenDirectories {
                    access: 0o300,
                    remember: true,
                    directories: vec![(
                        path_bytes(&parent),
                        proto::TargetCondition::Matches {
                            dev: original.dev(),
                            ino: original.ino(),
                        },
                    )],
                };
                let settlement = authority.authorize(&mut access, false).unwrap();
                let response = ops.handle(&access);
                authority.settle(settlement, &response);
                assert!(
                    matches!(response, proto::Response::WidenedDirectories(ref outcomes)
                        if outcomes.len() == 1 && outcomes[0].is_ok()),
                    "{response:?}"
                );
                assert_eq!(
                    fs::metadata(&parent).unwrap().mode() & 0o7777,
                    if unsafe { libc::geteuid() } == 0 {
                        0o2550
                    } else {
                        0o2750
                    }
                );
                let mut restore = apply(Op::SetMeta {
                    path: path_bytes(&parent),
                    meta: proto::Meta {
                        inode_metadata: None,
                        mode: 0o7777,
                        ..plain_meta()
                    },
                    flags: if preserve {
                        proto::flags::MODE
                    } else {
                        proto::flags::RECEIVER_MODE
                    },
                    condition: proto::TargetCondition::Any,
                    directory: false,
                });
                let settlement = authority.authorize(&mut restore, false).unwrap();
                let response = ops.handle(&restore);
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
        let response = authority.test_ops().handle(&request);
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
                directory: false,
            },
        ],
    };
    // The metadata asks only for a mode the receiver chooses, which keeps
    // the mode of a directory it did not create.
    let settlement = authority.authorize(&mut request, false).unwrap();
    let response = authority.test_ops().handle(&request);
    authority.settle(settlement, &response);
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
    let response = authority.test_ops().handle(&create);
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
        directory: false,
    });
    let settlement = authority.authorize(&mut restore, false).unwrap();
    let response = authority.test_ops().handle(&restore);
    authority.settle(settlement, &response);
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
        .authorize(
            &mut apply(Op::SetMeta {
                path: path_bytes(&target.join("existing")),
                meta: plain_meta(),
                flags: proto::flags::TIMES,
                condition: proto::TargetCondition::Any,
                directory: false,
            }),
            false
        )
        .is_err());
    assert!(authority
        .authorize(
            &mut prepare_request(&target.join("existing/item/child")),
            false
        )
        .is_err());
    let run = |mut request| {
        let settlement = authority.authorize(&mut request, false)?;
        let response = authority.test_ops().handle(&request);
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
            (EnrollmentId::random(), 1),
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
                meta: Default::default(),
                flags: 0,
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
                kind | if preserve_permissions { 0o6754 } else { 0o754 }
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
    let mut ops = authority.test_ops();
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
            clone_final: false,
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
    let mut authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    // Requests the executor refuses still count until they settle.
    authority.copy.limits.max_entries = 64;

    // New files are staged and published without replacing anything,
    // which the executor refuses where a name exists: a pre-existing
    // object needs no look here.
    let mut prepare_fresh = prepare_request(&fresh);
    authority.authorize(&mut prepare_fresh, false).unwrap();
    let mut prepare_kept = prepare_request(&kept);
    authority.authorize(&mut prepare_kept, false).unwrap();
    let mut publish_fresh = finalize_request(&fresh, Any);
    let settlement = authority.authorize(&mut publish_fresh, false).unwrap();
    assert_eq!(finalize_condition(&publish_fresh), Absent);
    authority.settle(settlement, &proto::Response::Ok);
    let mut publish_kept = finalize_request(&kept, Any);
    authority.authorize(&mut publish_kept, false).unwrap();
    assert_eq!(finalize_condition(&publish_kept), Absent);
    let mut replace_kept = finalize_request(&kept, Matches { dev: 1, ino: 1 });
    assert!(authority.authorize(&mut replace_kept, false).is_err());
    // What this grant created, and the executor confirmed, is its own to
    // republish.
    let mut republish_fresh = finalize_request(&fresh, Matches { dev: 1, ino: 1 });
    authority.authorize(&mut republish_fresh, false).unwrap();
    assert_eq!(
        finalize_condition(&republish_fresh),
        Matches { dev: 1, ino: 1 }
    );
    let mut small_kept = small_put(&kept);
    authority.authorize(&mut small_kept, false).unwrap();
    assert_eq!(small_put_condition(&small_kept), Absent);
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
    authority.authorize(&mut link_over_file, false).unwrap();
    assert_eq!(op_condition(&link_over_file), Absent);
    let mut create_link = apply(symlink_op(&link));
    let settlement = authority.authorize(&mut create_link, false).unwrap();
    assert_eq!(op_condition(&create_link), Absent);
    // As executing the creation leaves it.
    symlink("target", &link).unwrap();
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
    };
    assert!(authority.authorize(&mut finish, false).is_err());
    let mut seed = Request::SeedBasis {
        final_ranges: None,
        path: path_bytes(&kept),
        copy_id: [1; 16],
        len: 3,
        block: proto::MIN_HASH_BLOCK_BYTES,
        attempt: 0,
        clone_final: false,
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
    authority.authorize(&mut republish, false).unwrap();
    assert_eq!(finalize_condition(&republish), Absent);

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
        ops: vec![mkdir(&fresh), mkdir(&kept)],
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
        directory: false,
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
    let mut authority = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    authority.copy.options.preserve_times = true;
    let before = fs::symlink_metadata(&link).unwrap();

    // A changed symlink is replaced, given its metadata as it is created.
    // The replacement is pinned to the old inode; the metadata lands on the
    // new one.
    let mut with_metadata = symlink_op(&link);
    if let Op::Symlink { meta, flags, .. } = &mut with_metadata {
        meta.mtime = 1_600_000_000;
        *flags = proto::flags::TIMES;
    }
    let mut batch = Request::Apply {
        ops: vec![with_metadata],
    };
    let settlement = authority.authorize(&mut batch, false).unwrap();
    let Request::Apply { ops } = &batch else {
        unreachable!()
    };
    assert!(matches!(
        ops[0],
        Op::Symlink { condition: Matches { dev, ino }, .. }
            if (dev, ino) == (before.dev(), before.ino())
    ));
    assert_eq!(ops.len(), 1);
    let results = execute_ops(&authority, ops);
    assert!(results.iter().all(Option::is_none), "{results:?}");
    authority.settle(settlement, &proto::Response::Applied(results));
    assert_eq!(
        fs::read_link(&link).unwrap().as_os_str().as_bytes(),
        b"elsewhere"
    );
    let after = fs::symlink_metadata(&link).unwrap();
    assert_ne!(after.ino(), before.ino());
    assert_eq!(after.mtime(), 1_600_000_000);

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

fn existence_authority_with_results(
    root: &Path,
    policy: &crate::destination_results::ReceiptPolicy,
    deadline_ms: u64,
) -> RestrictedAuthority {
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let mut authority = test_authority_with_results(
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
fn results_report_confirmed_changes_and_end_the_grant() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let kept = target.join("kept");
    let fresh = target.join("fresh");
    let gone = target.join("gone");
    fs::create_dir_all(&target).unwrap();
    fs::write(&kept, b"old").unwrap();
    fs::write(&gone, b"bye").unwrap();
    let (secret, policy) = results_policy();
    let authority = existence_authority_with_results(&root, &policy, 60_000);
    let mut reader = start_results(&authority, secret);

    // An observation changes nothing and is not listed.
    let mut hash = Request::FileHash {
        path: path_bytes(&kept),
        source: None,
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

    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.refused, 1);
    assert_eq!(results.totals.files_transferred, 1);
    assert_eq!(results.totals.deletions_completed, 1);
    assert_eq!(results.totals.failed, 0);
    assert_eq!(
        results.changes(),
        [
            (
                "transfer_file".to_owned(),
                b"fresh".to_vec(),
                "succeeded".to_owned()
            ),
            (
                "delete".to_owned(),
                b"gone".to_vec(),
                "succeeded".to_owned()
            ),
        ]
    );
    assert_eq!(results.records[0]["bytes"], 4);

    // The end closes the grant: no change, no second end, no further
    // observation.
    assert!(authority
        .authorize(&mut prepare_request(&target.join("late")), false)
        .is_err());
    assert!(authority.finish_results().is_err());
    let mut observe = Request::StatMany {
        paths: vec![path_bytes(&kept)],
        sources: None,
        follow: false,
    };
    assert!(authority.authorize(&mut observe, false).is_err());

    // A request still in flight holds the end back.
    let (secret, policy) = results_policy();
    let waiting = existence_authority_with_results(&root, &policy, 200);
    let _reader = start_results(&waiting, secret);
    let settlement = waiting
        .authorize(&mut prepare_request(&target.join("inflight")), false)
        .unwrap();
    assert!(waiting.finish_results().is_err());
    waiting.settle(settlement, &proto::Response::Ok);

    // The results list changes in the order they settled: a file published
    // then deleted appears twice.
    let (secret, policy) = results_policy();
    let racing = existence_authority_with_results(&root, &policy, 5_000);
    let mut reader = start_results(&racing, secret);
    let vanished = target.join("vanished");
    let settlement = racing
        .authorize(&mut prepare_request(&vanished), false)
        .unwrap();
    racing.settle(settlement, &proto::Response::Ok);
    let mut publish = finalize_request(&vanished, proto::TargetCondition::Any);
    let settlement = racing.authorize(&mut publish, false).unwrap();
    racing.settle(settlement, &proto::Response::Ok);
    let mut delete = apply(Op::Unlink {
        path: path_bytes(&vanished),
    });
    let settlement = racing.authorize(&mut delete, false).unwrap();
    racing.settle(settlement, &proto::Response::Applied(vec![None]));
    let results = finish_results(&racing, &mut reader);
    assert!(results.has("transfer_file", b"vanished", "succeeded"));
    assert!(results.has("delete", b"vanished", "succeeded"));
}

#[test]
fn results_start_before_any_change_or_not_at_all() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    // A coordinator that changed something first cannot start results that
    // would leave the change out.
    let (_, policy) = results_policy();
    let late = existence_authority_with_results(&root, &policy, 5_000);
    let mut mkdir = apply(Op::Mkdir {
        path: path_bytes(&target.join("early")),
        mode: 0o755,
        condition: proto::TargetCondition::Any,
    });
    let settlement = late.authorize(&mut mkdir, false).unwrap();
    late.settle(settlement, &proto::Response::Applied(vec![None]));
    assert!(late.start_results(true).is_err());
    // Nor after a refusal.
    let refused = existence_authority_with_results(&root, &policy, 5_000);
    assert!(refused
        .authorize(&mut prepare_request(&root.join("elsewhere")), false)
        .is_err());
    assert!(refused.start_results(true).is_err());
    // Results run only on the signed control connection, start once, and
    // never record anything for a copy that did not ask for them.
    let quiet = existence_authority_with_results(&root, &policy, 5_000);
    let mut start = Request::DestinationResults { records: true };
    assert!(quiet.authorize(&mut start, false).is_err());
    let settlement = quiet
        .authorize(&mut prepare_request(&target.join("plain")), false)
        .unwrap();
    quiet.settle(settlement, &proto::Response::Ok);
    assert!(quiet.state.lock().unwrap().file_lifecycles.is_empty());
    assert!(quiet.take_results_frames().is_empty());
    assert!(quiet.finish_results().is_err());
    let (_, policy) = results_policy();
    let twice = existence_authority_with_results(&root, &policy, 5_000);
    twice.start_results(false).unwrap();
    assert!(twice.start_results(false).is_err());
}

#[test]
fn observation_only_prepare_releases_absent_reservation_and_skips_lifecycle() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = test_authority_with_results(
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
            generate_results_key(EnrollmentId::random()).unwrap(),
            results_policy().1,
        )),
    )
    .unwrap();
    // Files are tracked until published only for results a coordinator
    // started.
    authority.start_results(false).unwrap();
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
    let authority = test_authority_with_results(
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
            generate_results_key(EnrollmentId::random()).unwrap(),
            results_policy().1,
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
fn results_count_directories_as_an_ordinary_copy_does() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(&root).unwrap();
    for (placement, root_counted) in [
        (DestinationPlacement::DirectoryContents, false),
        (DestinationPlacement::ExactPath, true),
    ] {
        let _ = fs::remove_dir_all(root.join("target"));
        let key = generate_results_key(EnrollmentId::random()).unwrap();
        let (secret, policy) = results_policy();
        let authority = test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            placement,
            RootExistence::Any,
            Some((key, policy)),
        )
        .unwrap();
        let mut reader = start_results(&authority, secret);
        for path in [root.join("target"), root.join("target/sub")] {
            let mut mkdir = apply(Op::Mkdir {
                path: path_bytes(&path),
                mode: 0o755,
                condition: proto::TargetCondition::Any,
            });
            let settlement = authority.authorize(&mut mkdir, false).unwrap();
            fs::create_dir(&path).unwrap();
            authority.settle(settlement, &proto::Response::Applied(vec![None]));
        }
        let results = finish_results(&authority, &mut reader);
        // The directory a copy goes into is neither counted nor listed; a
        // copied directory at an exact path is counted.
        assert_eq!(
            results.totals.directories_created,
            1 + u64::from(root_counted),
            "{placement:?}"
        );
        assert_eq!(
            results.changes(),
            [(
                "create_directory".to_owned(),
                b"sub".to_vec(),
                "succeeded".to_owned()
            )],
            "{placement:?}"
        );
    }
}

#[test]
fn a_small_file_batch_with_links_reports_each_failed_write() {
    // Files with more than one link are published with their identities;
    // a file that failed is neither written nor this copy's own.
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let written = target.join("written");
    let failed = target.join("failed");
    fs::create_dir_all(&target).unwrap();
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy)),
    )
    .unwrap();
    let mut reader = start_results(&authority, secret);
    let put = |path: &Path| proto::SmallPut {
        path: path_bytes(path),
        copy_id: [7; 16],
        data: b"new".to_vec(),
        hash: crate::fsops::content_digest(b"new"),
        meta: plain_meta(),
        flags: 0,
        inplace: false,
        condition: proto::TargetCondition::Any,
        replaces: false,
        scanned: crate::proto::ScannedDestination::Unknown,
    };
    let mut batch = Request::PutSmallBatch(vec![put(&written), put(&failed)]);
    let settlement = authority.authorize(&mut batch, false).unwrap();
    fs::write(&written, b"new").unwrap();
    authority.settle(
        settlement,
        &proto::Response::PublishedBatch(vec![
            Ok(Some((1, 2))),
            Err(proto::WireError {
                message: "No space left on device".into(),
                io_kind: Some(proto::WireIoKind::NoSpace),
                raw_os_error: Some(28),
                condition_not_met: false,
                unchanged: false,
            }),
        ]),
    );
    assert!(authority.created_by_this_grant(&path_bytes(&written)));
    // Another process may create it now; keeping existing files must not
    // let a later write replace that one.
    assert!(!authority.created_by_this_grant(&path_bytes(&failed)));
    let results = finish_results(&authority, &mut reader);
    assert_eq!(
        (results.totals.files_transferred, results.totals.failed),
        (1, 1)
    );
    assert!(results.has("transfer_file", b"written", "succeeded"));
    assert!(results.has("transfer_file", b"failed", "failed"));
}

#[test]
fn results_list_each_settled_change_in_ordinary_form() {
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

    let (secret, policy) = results_policy();
    let authority = existence_authority_with_results(&root, &policy, 60_000);
    let mut reader = start_results(&authority, secret);
    let put = |path: &Path| proto::SmallPut {
        path: path_bytes(path),
        copy_id: [7; 16],
        data: b"new".to_vec(),
        hash: crate::fsops::content_digest(b"new"),
        meta: plain_meta(),
        flags: 0,
        inplace: false,
        condition: proto::TargetCondition::Any,
        replaces: false,
        scanned: crate::proto::ScannedDestination::Unknown,
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

    let results = finish_results(&authority, &mut reader);
    let mut late = prepare_request(&target.join("late"));
    assert!(authority.authorize(&mut late, false).is_err());
    assert_eq!(results.totals.refused, 1);
    assert_eq!(results.totals.failed, 1);
    assert_eq!(results.totals.files_transferred, 1);
    assert_eq!(results.totals.deletions_completed, 1);
    assert!(results.has("transfer_file", &copied_name, "succeeded"));
    assert!(results.has("delete", b"removed", "succeeded"));
    // The receiver does not look up what kind of name it removed.
    let deletion = results
        .records
        .iter()
        .find(|record| record["action"] == "delete")
        .unwrap();
    assert!(deletion.get("kind").is_none(), "{deletion}");
    let failure = results
        .records
        .iter()
        .find(|record| record["dst"]["value"] == "failed")
        .unwrap();
    assert_eq!(failure["disposition"], "failed");
    assert_eq!(failure["class"], "io");
    assert_eq!(failure["message"], "executor rejected it");
}

/// A metadata change the receiver declines to make in place is not a
/// failure: the copy replaces the file, and the results report that
/// replacement as the file's transfer, and nothing as failed.
#[test]
fn results_report_a_declined_metadata_change_as_the_replacement() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let linked = target.join("linked");
    let small = target.join("small");
    fs::create_dir_all(&target).unwrap();
    fs::write(&linked, b"same").unwrap();
    fs::write(&small, b"new").unwrap();
    let (secret, policy) = results_policy();
    let authority = existence_authority_with_results(&root, &policy, 60_000);
    let mut reader = start_results(&authority, secret);
    let declined = || proto::WireError {
        message: "must be replaced to change its metadata".into(),
        io_kind: Some(proto::WireIoKind::ReplaceRequired(
            proto::ReplaceReason::OtherNames,
        )),
        raw_os_error: None,
        condition_not_met: false,
        unchanged: false,
    };

    // A metadata repair the receiver declines, then the replacement.
    let identity = fs::metadata(&linked).unwrap();
    let mut repair = apply(Op::SetFileMetaIfSame {
        path: path_bytes(&linked),
        meta: plain_meta(),
        flags: proto::flags::RECEIVER_MODE,
        condition: proto::TargetCondition::Matches {
            dev: identity.dev(),
            ino: identity.ino(),
        },
    });
    let settlement = authority.authorize(&mut repair, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::Applied(vec![Some(declined())]),
    );
    let mut prepare = prepare_request(&linked);
    let settlement = authority.authorize(&mut prepare, false).unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    let mut finalize = finalize_request(&linked, proto::TargetCondition::Any);
    let settlement = authority.authorize(&mut finalize, false).unwrap();
    authority.settle(settlement, &proto::Response::Ok);

    // A small file that matched but whose metadata the receiver would not
    // change in place, then its replacement.
    let block = authority.copy.limits.hash_block_bytes;
    let mut hash = Request::HashExistingBatch {
        block,
        files: vec![existing_read(&small, 3)],
    };
    let settlement = authority.authorize(&mut hash, false).unwrap();
    let response = authority.test_ops().handle(&hash);
    authority.settle(settlement, &response);
    let proto::Response::ExistingHashes(mut existing) = response else {
        panic!("unexpected hash response {response:?}")
    };
    let existing = existing.remove(0).unwrap();
    let mut matched = small_patch(&small, 3, block, vec![], b"new");
    matched.basis = existing.fingerprint;
    let mut patch = Request::PatchSmallBatch(vec![matched]);
    let settlement = authority.authorize(&mut patch, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::PatchedBatch(vec![Err(proto::SmallPatchError {
            error: declined(),
            matched: true,
            stale_condition: false,
            written: false,
        })]),
    );
    let mut put = small_put(&small);
    let settlement = authority.authorize(&mut put, false).unwrap();
    authority.settle(settlement, &proto::Response::Applied(vec![None]));

    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.failed, 0, "{:?}", results.records);
    assert_eq!(results.totals.files_transferred, 2, "{:?}", results.records);
    assert!(results.has("transfer_file", b"linked", "succeeded"));
    assert!(results.has("transfer_file", b"small", "succeeded"));
    assert!(
        !results.changes().iter().any(|(_, _, d)| d == "failed"),
        "{:?}",
        results.records
    );
    assert!(
        !results
            .records
            .iter()
            .any(|record| record["type"] == "error"),
        "{:?}",
        results.records
    );
}

#[test]
fn unfinished_in_place_files_are_reported_failed() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let image = target.join("image");
    fs::create_dir_all(&target).unwrap();
    let in_place = |finished: bool| {
        let key = generate_results_key(EnrollmentId::random()).unwrap();
        let (secret, policy) = results_policy();
        let authority = test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::InPlace,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
            Some((key, policy)),
        )
        .unwrap();
        let mut reader = start_results(&authority, secret);
        let mut prepare = Request::Prepare {
            path: path_bytes(&image),
            size: 4,
            inplace: true,
            copy_id: [1; 16],
            mode: 0o600,
            flags: 0,
            acl: false,
            scanned: crate::proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
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
        };
        let settlement = authority.authorize(&mut write, false).unwrap();
        authority.settle(settlement, &proto::Response::Ok);
        if finished {
            let mut finalize = Request::Finalize {
                expected_hash: None,
                path: path_bytes(&image),
                inplace: true,
                copy_id: [1; 16],
                meta: plain_meta(),
                flags: 0,
                scanned: crate::proto::ScannedDestination::Unknown,
                condition: proto::TargetCondition::Any,
            };
            let settlement = authority.authorize(&mut finalize, false).unwrap();
            authority.settle(settlement, &proto::Response::Ok);
            // A published file is no longer tracked.
            assert!(authority.state.lock().unwrap().file_lifecycles.is_empty());
        }
        finish_results(&authority, &mut reader)
    };

    // Without a final step the file is reported unfinished.
    let results = in_place(false);
    assert_eq!(results.totals.failed, 1);
    assert_eq!(results.totals.files_transferred, 0);
    assert_eq!(
        results.records[0]["message"], "syq: image: the file was not finished",
        "{:?}",
        results.records
    );
    assert_eq!(results.records[1]["message"], "the file was not finished");
    assert!(results.has("transfer_file", b"image", "failed"));

    // With it, the same file is published once.
    let results = in_place(true);
    assert_eq!(results.totals.failed, 0);
    assert_eq!(results.totals.files_transferred, 1);
    assert_eq!(
        results.changes(),
        [(
            "transfer_file".to_owned(),
            b"image".to_vec(),
            "succeeded".to_owned()
        )]
    );
}

#[test]
fn refused_preparations_leave_nothing_behind() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let (secret, policy) = results_policy();
    let authority = existence_authority_with_results(&root, &policy, 60_000);
    let mut reader = start_results(&authority, secret);
    // A coordinator can ask for any number of files the grant refuses.
    for index in 0..100 {
        let mut prepare = Request::Prepare {
            path: path_bytes(&target.join(format!("large-{index}"))),
            size: 1 << 20,
            inplace: false,
            copy_id: [1; 16],
            mode: 0o600,
            flags: 0,
            acl: false,
            scanned: crate::proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
        };
        let error = authority.authorize(&mut prepare, false).unwrap_err();
        assert!(
            format!("{error:#}").contains("per-file byte limit"),
            "{error:#}"
        );
    }
    assert!(authority.state.lock().unwrap().file_lifecycles.is_empty());
    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.refused, 100);
    assert_eq!(results.changes().len(), 100);
}

#[test]
fn a_refused_write_to_an_unfinished_file_lists_it_once() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let image = target.join("image");
    fs::create_dir_all(&target).unwrap();
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy)),
    )
    .unwrap();
    let mut reader = start_results(&authority, secret);
    let mut prepare = Request::Prepare {
        path: path_bytes(&image),
        size: 4,
        inplace: true,
        copy_id: [1; 16],
        mode: 0o600,
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
    };
    let settlement = authority.authorize(&mut prepare, false).unwrap();
    fs::write(&image, b"half").unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    // A write past the grant's per-file limit is refused.
    let mut write = Request::WriteRange {
        path: path_bytes(&image),
        inplace: true,
        copy_id: [1; 16],
        attempt: 0,
        off: 1023,
        hash: crate::fsops::content_digest(b"ha"),
        data: b"ha".to_vec().into(),
    };
    let error = authority.authorize(&mut write, false).unwrap_err();
    assert!(format!("{error:#}").contains("per-file"), "{error:#}");
    let results = finish_results(&authority, &mut reader);
    assert_eq!((results.totals.refused, results.totals.failed), (1, 0));
    // Once, as refused, and not again as unfinished.
    assert_eq!(
        results.changes(),
        [(
            "transfer_file".to_owned(),
            b"image".to_vec(),
            "failed".to_owned()
        )],
        "{:?}",
        results.records
    );
    let errors: Vec<_> = results
        .records
        .iter()
        .filter(|record| record["type"] == "error")
        .collect();
    assert_eq!(errors.len(), 1, "{:?}", results.records);
    assert_eq!(errors[0]["class"], "safety_limit");
}

#[test]
fn in_place_final_step_honors_the_fingerprint_the_receiver_takes_after_the_writes() {
    // Without -p the final step carries RECEIVER_MODE: the authority chooses
    // the mode and binds its approval to the file's identity and ctime as
    // they are then, after the data was written. The receiver must check
    // that against the file as it is now, not as it was when it opened it
    // before the writes. Both a new and an existing destination, which is
    // replaced through a stage.
    for existing in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let image = target.join("image");
        fs::create_dir_all(&target).unwrap();
        if existing {
            fs::write(&image, b"an older and longer version").unwrap();
        }
        let authority = test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::InPlace,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
            None,
        )
        .unwrap();
        // The receiver works beneath the root the authority holds.
        let mut receiver = authority.test_ops();
        let copy_id = [7; 16];
        let mut run = |mut request: Request| {
            let settlement = authority.authorize(&mut request, false).unwrap();
            let response = receiver.handle_in_place(&mut request);
            authority.settle(settlement, &response);
            response
        };
        let prepared = run(Request::Prepare {
            path: path_bytes(&image),
            size: 8,
            inplace: true,
            copy_id,
            mode: 0o644,
            flags: 0,
            acl: false,
            scanned: crate::proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
        });
        assert!(
            matches!(prepared, proto::Response::Prepared(_)),
            "{existing}: {prepared:?}"
        );
        let written = run(Request::WriteRange {
            path: path_bytes(&image),
            inplace: true,
            copy_id,
            attempt: 0,
            off: 0,
            hash: crate::fsops::content_digest(b"contents"),
            data: b"contents".to_vec().into(),
        });
        assert!(
            matches!(written, proto::Response::Ok),
            "{existing}: {written:?}"
        );
        let finalized = run(Request::Finalize {
            expected_hash: None,
            path: path_bytes(&image),
            inplace: true,
            copy_id,
            meta: plain_meta(),
            flags: proto::flags::RECEIVER_MODE,
            scanned: crate::proto::ScannedDestination::Unknown,
            condition: proto::TargetCondition::Any,
        });
        assert!(
            matches!(
                finalized,
                proto::Response::Ok | proto::Response::Published { .. }
            ),
            "{existing}: {finalized:?}"
        );
        assert_eq!(fs::read(&image).unwrap(), b"contents", "{existing}");
    }
}

#[test]
fn restricted_executor_honors_creation_conditions() {
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
    let mut receiver = crate::fsops::FsOps::test_restricted(&root);
    let identity = |path: &Path| {
        let metadata = fs::symlink_metadata(path).unwrap();
        Matches {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    };
    let mut run = |op: Op| match receiver.handle(&Request::Apply { ops: vec![op] }) {
        proto::Response::Applied(mut results) => results.remove(0),
        other => panic!("unexpected response {other:?}"),
    };
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
            meta: Default::default(),
            flags: 0,
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
fn in_place_publication_honors_every_existing_object_policy() {
    // In place, the receiver writes only a file it creates; anything else
    // at the name is staged and published under the existing-object policy,
    // as without the option. So every policy the receiver enforces combines
    // with it.
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
            PublicationPolicy::InPlaceNew,
            existing,
            placement,
            root_existence,
        )
    };
    for existing in [
        ExistingDestinationPolicy::Skip,
        ExistingDestinationPolicy::MustExist,
        ExistingDestinationPolicy::Replace,
    ] {
        inplace(
            existing,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
        )
        .unwrap();
    }
    inplace(
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::New,
    )
    .unwrap();
    inplace(
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::New,
    )
    .unwrap();

    // The coordinator accepts the same combinations before signing. The
    // rsync-shaped parser already makes --inplace and --ignore-existing
    // conflict.
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
    validate_restricted_args(&args).unwrap();
    args.target_existence = Existence::Any;
    args.existing = true;
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
                inode_metadata: None,
                mode: 0o640,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags,
            condition: proto::TargetCondition::Any,
            directory: false,
        }],
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
        assert!(authority.check_flags(required, 0).is_err());
        assert!(authority.check_flags(attribute | required, 0).is_err());
    }
    authority.copy.options.preserve_owner = true;
    authority
        .check_flags(flags::OWNER | flags::REQUIRE_OWNER, 0)
        .unwrap();
    assert!(authority
        .check_flags(flags::GROUP | flags::REQUIRE_GROUP, 0)
        .is_err());
    authority.copy.options.preserve_group = true;
    authority
        .check_flags(flags::GROUP | flags::REQUIRE_GROUP, 0)
        .unwrap();
    assert!(authority.check_flags(flags::REQUIRE_GROUP, 0).is_err());
}

/// The mode the kernel gives a new directory or file in `parent` created
/// with `mode`, from a sibling made that way.
fn created_mode(parent: &Path, mode: u32, directory: bool) -> u32 {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let sibling = parent.join(format!("expected-{mode:o}-{directory}"));
    if directory {
        std::fs::DirBuilder::new()
            .mode(mode)
            .create(&sibling)
            .unwrap();
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&sibling)
            .unwrap();
    }
    let created = fs::metadata(&sibling).unwrap().mode() & 0o7777;
    if directory {
        fs::remove_dir(&sibling).unwrap();
    } else {
        fs::remove_file(&sibling).unwrap();
    }
    created
}

#[test]
fn receiver_chosen_modes_keep_existing_objects_and_limit_new_ones() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let existing_directory = target.join("existing-dir");
    let new_directory = target.join("new-dir");
    fs::create_dir_all(&existing_directory).unwrap();
    fs::set_permissions(&existing_directory, fs::Permissions::from_mode(0o500)).unwrap();
    let new_directory_mode = created_mode(&target, 0o777, true);
    let new_file_mode = created_mode(&target, 0o777, false);
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.extra_options.widen_dirs = DirectoryWidening::Rsync;
    let mut ops = authority.test_ops();
    let path = |path: &Path| path.as_os_str().as_bytes().to_vec();
    let applied = |response: proto::Response| matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none));

    // The sender's special bits never reach a directory it creates, and
    // an existing directory is left alone.
    let mkdir = |path: &Path| Op::Mkdir {
        path: path.as_os_str().as_bytes().to_vec(),
        mode: 0o7777,
        condition: proto::TargetCondition::Any,
    };
    assert!(applied(execute_authorized(
        &authority,
        &mut ops,
        Request::Apply {
            ops: vec![mkdir(&existing_directory), mkdir(&new_directory)],
        },
    )));
    assert_eq!(
        fs::metadata(&existing_directory).unwrap().mode() & 0o7777,
        0o500
    );
    assert_eq!(
        fs::metadata(&new_directory).unwrap().mode() & 0o7777,
        new_directory_mode
    );

    // A directory the receiver widened gets back the mode it had; one it
    // did not create private keeps its mode, whatever the proposal.
    let observed = fs::metadata(&existing_directory).unwrap();
    let response = execute_authorized(
        &authority,
        &mut ops,
        Request::WidenDirectories {
            access: 0o300,
            remember: true,
            directories: vec![(
                path(&existing_directory),
                proto::TargetCondition::Matches {
                    dev: observed.dev(),
                    ino: observed.ino(),
                },
            )],
        },
    );
    assert!(
        matches!(response, proto::Response::WidenedDirectories(ref outcomes)
        if outcomes.len() == 1 && outcomes[0].is_ok()),
        "{response:?}"
    );
    let receiver_meta = |path: &Path| Op::SetMeta {
        path: path.as_os_str().as_bytes().to_vec(),
        meta: proto::Meta {
            inode_metadata: None,
            mode: 0o7777,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: proto::flags::RECEIVER_MODE,
        condition: proto::TargetCondition::Any,
        directory: false,
    };
    assert!(applied(execute_authorized(
        &authority,
        &mut ops,
        Request::Apply {
            ops: vec![
                receiver_meta(&existing_directory),
                receiver_meta(&new_directory),
            ],
        },
    )));
    assert_eq!(
        fs::metadata(&existing_directory).unwrap().mode() & 0o7777,
        0o500
    );
    assert_eq!(
        fs::metadata(&new_directory).unwrap().mode() & 0o7777,
        new_directory_mode
    );

    // A file published over a regular file takes its mode, special bits
    // included; a new one takes the proposal's permission bits as
    // creating it limits them.
    let existing_file = target.join("existing-file");
    let setuid_file = target.join("setuid-file");
    let new_file = target.join("new-file");
    fs::write(&existing_file, b"old").unwrap();
    fs::set_permissions(&existing_file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&setuid_file, b"old").unwrap();
    fs::set_permissions(&setuid_file, fs::Permissions::from_mode(0o4750)).unwrap();
    let put = |path: &Path| proto::SmallPut {
        path: path.as_os_str().as_bytes().to_vec(),
        copy_id: [1; 16],
        data: b"new".to_vec(),
        hash: crate::fsops::content_digest(b"new"),
        meta: proto::Meta {
            inode_metadata: None,
            mode: 0o7777,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: proto::flags::RECEIVER_MODE,
        inplace: false,
        condition: proto::TargetCondition::Any,
        replaces: false,
        scanned: crate::proto::ScannedDestination::Unknown,
    };
    let mut files =
        Request::PutSmallBatch(vec![put(&existing_file), put(&setuid_file), put(&new_file)]);
    let settlement = authority.authorize(&mut files, false).unwrap();
    let Request::PutSmallBatch(puts) = &files else {
        unreachable!()
    };
    // The authority leaves the choice to the receiver.
    assert!(puts.iter().all(|put| {
        (put.meta.mode, put.flags, put.condition)
            == (
                0o7777,
                proto::flags::RECEIVER_MODE,
                proto::TargetCondition::Any,
            )
    }));
    let response = ops.handle(&files);
    authority.settle(settlement, &response);
    assert!(applied(response));
    for (file, mode) in [
        (&existing_file, 0o600),
        (&setuid_file, 0o4750),
        (&new_file, new_file_mode),
    ] {
        assert_eq!(fs::read(file).unwrap(), b"new");
        assert_eq!(
            fs::metadata(file).unwrap().mode() & 0o7777,
            mode,
            "{file:?}"
        );
    }
}

#[test]
fn receiver_chosen_mode_opens_a_private_directory_with_its_inherited_setgid() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o2755)).unwrap();
    // Linux propagates a parent's setgid bit to new directories; BSD-derived
    // kernels (macOS) inherit the group without the bit.
    let inherited_setgid = if cfg!(target_os = "linux") { 0o2000 } else { 0 };
    let opened = created_mode(&root, 0o777, true);
    assert_eq!(opened & 0o2000, inherited_setgid);
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut ops = authority.test_ops();
    let response = execute_authorized(
        &authority,
        &mut ops,
        apply(Op::Mkdir {
            path: path_bytes(&target),
            mode: 0o700,
            condition: proto::TargetCondition::Any,
        }),
    );
    assert!(
        matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
        "{response:?}"
    );
    assert_eq!(
        fs::metadata(&target).unwrap().mode() & 0o7777,
        0o700 | inherited_setgid
    );
    let receiver_meta = || {
        apply(Op::SetMeta {
            path: path_bytes(&target),
            meta: proto::Meta {
                inode_metadata: None,
                // None of these source-proposed special bits are trusted.
                mode: 0o7777,
                ..plain_meta()
            },
            flags: proto::flags::RECEIVER_MODE,
            condition: proto::TargetCondition::Any,
            directory: false,
        })
    };
    // Another connection did not create it, so its mode stays.
    let response = execute_authorized(&authority, &mut authority.test_ops(), receiver_meta());
    assert!(
        matches!(response, proto::Response::Applied(_)),
        "{response:?}"
    );
    assert_eq!(
        fs::metadata(&target).unwrap().mode() & 0o7777,
        0o700 | inherited_setgid
    );
    // The connection that created it private gives it its creation mode.
    let response = execute_authorized(&authority, &mut ops, receiver_meta());
    assert!(
        matches!(response, proto::Response::Applied(ref errors) if errors.iter().all(Option::is_none)),
        "{response:?}"
    );
    assert_eq!(fs::metadata(&target).unwrap().mode() & 0o7777, opened);
}

#[test]
fn signed_hash_block_and_response_bounds_are_enforced() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, DEFAULT_MAX_BYTES);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let request = |block, len| Request::HashBlocks {
        off: 0,
        path: target.clone(),
        source: None,
        which: proto::Which::Final,
        copy_id: [0; 16],
        block,
        len,
        attempt: 0,
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
    };

    let mut prepare = Request::Prepare {
        path: target.clone(),
        size: 1024,
        inplace: false,
        copy_id: [0; 16],
        mode: 0o600,
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
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
        send_rate: None,
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
        send_rate: None,
        key: Some(vec![7; crate::tcp_records::KEY_LEN]),
        token: vec![8; 16],
        port_lo: 1,
        port_hi: 2,
        congestion_control: None,
    };
    assert!(wrong_range.authorize(&mut listener, true).is_err());

    let congestion_override = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut listener = Request::TcpListen {
        send_rate: None,
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
                inode_metadata: None,
                mode: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0x80,
            condition: proto::TargetCondition::Any,
            directory: false,
        }],
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
    };
    authority.authorize(&mut finish, false).unwrap();
    assert!(
        matches!(finish, Request::FinishBasis { expected_hash: Some(ref value), .. } if *value == crate::hashing::ExpectedHashes::Single(expected))
    );
    assert!(authority.authorize(&mut small_put(&target), false).is_err());
}

/// A grant that allows no changes, a preview or verify-only one, never lets
/// the receiver create a file to learn whom its files show. Once the
/// destination's results have ended, the request is refused.
#[test]
fn grants_that_allow_no_changes_create_no_owner_probe() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    for case in ["preview", "verify", "after results ended", "copy"] {
        let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
        match case {
            "preview" => authority.copy.options.dry_run = true,
            "verify" => authority.copy.options.verify_only = true,
            "after results ended" => authority.state.lock().unwrap().results_closing = true,
            _ => {}
        }
        let mut request = Request::NewFileOwner {
            path: path_bytes(&target),
            probe: true,
        };
        let authorized = authority.authorize(&mut request, false);
        if case == "after results ended" {
            assert!(authorized.is_err());
            continue;
        }
        authorized.unwrap();
        let Request::NewFileOwner { probe, .. } = request else {
            unreachable!()
        };
        assert_eq!(probe, case == "copy", "{case}");
        let _distrusted = crate::fsops::distrust_owners_for_test();
        let before = crate::rooted::probes_for_test();
        let response = authority.test_ops().handle(&request);
        assert!(
            matches!(response, proto::Response::NewFileOwner(_)),
            "{case}: {response:?}"
        );
        if case != "copy" {
            assert_eq!(crate::rooted::probes_for_test(), before, "{case}");
        }
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0, "{case}");
    }
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
    };
    assert!(authority.authorize(&mut mutation, false).is_err());

    let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
        path: target.clone(),
        copy_id: [1; 16],
        data: vec![0],
        hash: [0; 32],
        meta: proto::Meta {
            inode_metadata: None,
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        inplace: false,
        condition: proto::TargetCondition::Any,
        replaces: false,
        scanned: crate::proto::ScannedDestination::Unknown,
    }]);
    assert!(authority.authorize(&mut small, false).is_err());

    // Previews never widen, so a read-only grant needs no authority for it.
    let existing = fs::metadata(&root).unwrap();
    let mut widen = Request::WidenDirectories {
        access: 0o700,
        directories: vec![(
            path_bytes(&root),
            proto::TargetCondition::Matches {
                dev: existing.dev(),
                ino: existing.ino(),
            },
        )],
        remember: true,
    };
    assert!(authority.authorize(&mut widen, false).is_err());

    let mut observation = Request::StatMany {
        paths: vec![target],
        sources: None,
        follow: false,
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
    };
    assert!(authority.authorize(&mut request, false).is_err());

    let mut observe_container = Request::StatMany {
        paths: vec![target],
        sources: None,
        follow: false,
    };
    authority.authorize(&mut observe_container, false).unwrap();
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
    };
    authority.authorize(&mut unfiltered_scan, false).unwrap();
    let ignored = root
        .join("target/ignored/file")
        .as_os_str()
        .as_bytes()
        .to_vec();
    let mut delete = Request::Apply {
        ops: vec![Op::Unlink { path: ignored }],
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
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
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
        clone_final: false,
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
            inode_metadata: None,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        scanned: crate::proto::ScannedDestination::Unknown,
        condition: proto::TargetCondition::Any,
    };
    authority.authorize(&mut publish_empty, false).unwrap();
    // A file this receiver does not hold for the grant cannot be published.
    let mut publish_foreign = Request::Finalize {
        expected_hash: None,
        path: root.join("target/foreign").as_os_str().as_bytes().to_vec(),
        inplace: false,
        copy_id: [9; 16],
        meta: proto::Meta {
            inode_metadata: None,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        },
        flags: 0,
        scanned: crate::proto::ScannedDestination::Unknown,
        condition: proto::TargetCondition::Any,
    };
    let settlement = authority.authorize(&mut publish_foreign, false).unwrap();
    let response = authority.test_ops().handle(&publish_foreign);
    authority.settle(settlement, &response);
    assert!(
        matches!(response, proto::Response::EndpointError(ref error)
            if error.as_str().contains("is not open in this receiver")),
        "{response:?}"
    );
    assert!(!root.join("target/foreign").exists());
}

/// The entry limit counts the changes a copy makes, each time it makes
/// one, and nothing it only looks at: scans and lookups of the destination
/// count nothing, and a refused request counts nothing either.
#[test]
fn changes_count_against_the_entry_ceiling_and_lookups_do_not() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    // The helper grant allows eight entries.
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let target = root.join("target");
    let path = |name: &str| target.join(name).as_os_str().as_bytes().to_vec();
    for _ in 0..20 {
        let mut scan = Request::Scan {
            root: target.as_os_str().as_bytes().to_vec(),
            source: None,
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: false,
        };
        authority.authorize(&mut scan, false).unwrap();
        let mut stat = Request::StatMany {
            paths: (0..10)
                .map(|index| path(&format!("look-{index}")))
                .collect(),
            sources: None,
            follow: false,
        };
        authority.authorize(&mut stat, false).unwrap();
    }
    let mkdirs = |names: &[&str]| Request::Apply {
        ops: names
            .iter()
            .map(|name| Op::Mkdir {
                path: path(name),
                mode: 0o755,
                condition: proto::TargetCondition::Any,
            })
            .collect(),
    };
    authority
        .authorize(&mut mkdirs(&["a", "b", "c", "d", "e", "f"]), false)
        .unwrap();
    // A request that would go past the limit is refused whole, and counts
    // nothing; the same directory made again counts again.
    assert!(authority
        .authorize(&mut mkdirs(&["g", "h", "i"]), false)
        .is_err());
    authority
        .authorize(&mut mkdirs(&["a", "g"]), false)
        .unwrap();
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        8
    );
    assert!(authority.authorize(&mut mkdirs(&["h"]), false).is_err());
}

#[test]
fn worker_authorizations_use_128_or_a_smaller_resource_limit() {
    let source = Location::parse("host-a:source").unwrap();
    // A worker count fixed for a benchmark leaves the approval's ceiling
    // alone.
    for (setting, expected) in [
        (None, 128),
        (Some("--resource-limits=workers=3"), 3),
        (Some("--resource-limits=workers=1000"), 128),
        (Some("--performance-tuning=workers=32"), 128),
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
            (EnrollmentId::random(), 1),
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
    validate_restricted_args(&parse(&["--delete"])).unwrap();
    validate_restricted_args(&parse(&["--delete", "--max-delete", "0"])).unwrap();
    // Selection options and size limits act as for an ordinary copy.
    for options in [
        &["--min-size", "1"][..],
        &["--delete", "--max-size", "3M"],
        &["--files-from", "list"],
    ] {
        validate_restricted_args(&parse(options)).unwrap();
    }

    // A zero deletion budget signs a grant that forbids deletion outright.
    let id = EnrollmentId::random();
    let source = Location::parse("host-a:source").unwrap();
    let grant = grant_for(
        &parse(&["--delete", "--max-delete", "0"]),
        std::slice::from_ref(&source),
        (id, 1),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::Forbid);
    assert_eq!(copy.limits.max_deletions, 0);
}

/// Options that work on ordinary routes work on restricted ones too:
/// `--pscope` selects which local connections are kept, and `--max-size 0`
/// copies only empty files, so its grant admits no file data at all.
#[test]
fn restricted_routes_accept_a_persistence_scope_and_a_zero_size_limit() {
    let parse = |options: &[&str]| {
        let mut argv = vec!["syq", "-r"];
        argv.extend_from_slice(options);
        argv.extend_from_slice(&["host-a:source", "host-b:/backup"]);
        let mut args = Args::try_parse_from(argv).unwrap();
        args.normalize();
        args
    };
    let mut scoped = parse(&[]);
    scoped.pscope = Some(PathBuf::from("/tmp/scope"));
    scoped.pscope_explicit = true;
    validate_restricted_args(&scoped).unwrap();
    let empty_only = parse(&["--max-size", "0"]);
    validate_restricted_args(&empty_only).unwrap();
    let id = EnrollmentId::random();
    let grant = grant_for(
        &empty_only,
        &[Location::parse("host-a:source").unwrap()],
        (id, 1),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.limits.max_file_bytes, 0);
    let key = generate_results_key(id).unwrap();
    let signed = delegation::sign_grant(grant, GrantConstraints::default(), &key).unwrap();
    delegation::SignedGrantEnvelope::decode(&signed).unwrap();
}

#[test]
fn receivers_refuse_root_and_effective_capabilities() {
    assert!(privilege::privileged(0, 0));
    // CAP_DAC_OVERRIDE alone lets a process write any file.
    assert!(privilege::privileged(1000, 1 << 1));
    assert!(!privilege::privileged(1000, 0));
    let status = "Name:\tsyq\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n";
    assert_eq!(
        privilege::parse_effective_capabilities(status),
        Some(0x1ff_ffff_ffff)
    );
    let ordinary = "Name:\tsyq\nCapEff:\t0000000000000000\n";
    assert_eq!(privilege::parse_effective_capabilities(ordinary), Some(0));
    assert_eq!(
        privilege::parse_effective_capabilities("Name:\tsyq\n"),
        None
    );
    // The refusal points to the alternatives, and to removing a root
    // enrollment only when there is one.
    let fresh = privilege::privileged_receiver_message(None);
    assert!(fresh.contains("--coordinate-at local"), "{fresh}");
    assert!(fresh.contains("--peer-auth broker"), "{fresh}");
    assert!(!fresh.contains("revoke"), "{fresh}");
    let existing = privilege::privileged_receiver_message(Some("0123abcd"));
    assert!(
        existing.ends_with("`syq receiver revoke 0123abcd` removes this root enrollment"),
        "{existing}"
    );
}

#[test]
fn only_enrolled_grants_leave_bandwidth_to_the_sender() {
    assert!(enrolled_grant("c2lnbmVkLWdyYW50"));
    assert!(!enrolled_grant("named-v2:route"));
    assert!(!enrolled_grant(crate::destination::RETURN_GRANT));
    assert!(!enrolled_grant(crate::destination::peer_bridge::GRANT));
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
        (EnrollmentId::random(), 1),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = grant.operation;
    assert_eq!(copy.limits.hash_block_bytes, 64 << 10);
}

#[test]
fn explicit_ceilings_are_signed_and_deletion_defaults_to_the_entry_ceiling() {
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
        (id, 1),
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
        (id, 1),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.limits.max_entries, 12);
    assert_eq!(copy.limits.max_total_bytes, 2 << 20);
    assert_eq!(copy.limits.max_file_bytes, 2 << 20);
    assert_eq!(grant.issued_at - grant.not_before, CLOCK_SKEW_SECONDS);

    // Without --max-delete, pruning may remove as many entries as the copy
    // may touch; a stated budget is capped by the entry ceiling so the
    // grant stays self-consistent.
    let mut unbounded = parse(&["--delete"]);
    unbounded.receiver_max_entries = Some(30);
    let grant = grant_for(
        &unbounded,
        std::slice::from_ref(&source),
        (id, 1),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::DeleteDestinationOnly);
    assert_eq!(copy.limits.max_deletions, 30);
    let mut bounded = parse(&["--delete", "--max-delete", "40"]);
    bounded.receiver_max_entries = Some(30);
    let grant = grant_for(
        &bounded,
        std::slice::from_ref(&source),
        (id, 1),
        "backup",
        b"/backup",
    )
    .unwrap();
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::DeleteDestinationOnly);
    assert_eq!(copy.limits.max_deletions, 30);
    // A read-only run plans no deletion, so it needs no budget.
    let preview = parse(&["--delete", "--dry-run"]);
    let grant = grant_for(&preview, &[source], (id, 1), "backup", b"/backup").unwrap();
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
    let named = grant_for(&named_args, &[named_source], (id, 1), "backup", b"/backup").unwrap();
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
    let contents = grant_for(
        &contents_args,
        &[contents_source],
        (id, 1),
        "backup",
        b"/backup",
    )
    .unwrap();
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
    let nonrecursive =
        grant_for(&nonrecursive_args, &[file], (id, 1), "backup", b"/backup").unwrap();
    let GrantOperation::Copy(nonrecursive) = nonrecursive.operation;
    assert!(nonrecursive
        .mutation_scopes
        .iter()
        .all(|scope| !scope.descendants));
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
    };
    authority.authorize(&mut scan, true).unwrap();
    // The receiver scans beneath the root the authority holds.
    let ops = authority.test_ops();
    let (scan_root, relative) = ops
        .destination_scan_root(target.as_os_str().as_bytes())
        .unwrap()
        .unwrap();
    let mut entries = Vec::new();
    crate::scan::scan_descriptor(
        scan_root,
        &relative,
        None,
        false,
        false,
        &[],
        false,
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

    let response = authority.test_ops().handle(&Request::HashBlocks {
        off: 0,
        path: target.join("escape").as_os_str().as_bytes().to_vec(),
        source: None,
        which: proto::Which::Final,
        copy_id: [0; 16],
        block: 4096,
        len: 1,
        attempt: 0,
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
    };
    let error = authority.authorize(&mut scan, true).unwrap_err();
    assert!(error
        .to_string()
        .contains("source references are not valid"));

    for mut request in [
        Request::FileHash {
            path: root.join("file").as_os_str().as_bytes().to_vec(),
            source: Some(source.clone()),
        },
        Request::HashBlocks {
            off: 0,
            path: root.join("file").as_os_str().as_bytes().to_vec(),
            source: Some(source),
            which: proto::Which::Final,
            copy_id: [0; 16],
            block: proto::MIN_HASH_BLOCK_BYTES,
            len: 1,
            attempt: 0,
        },
    ] {
        let error = authority.authorize(&mut request, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("source references are not valid"));
    }
}

#[test]
fn hardlinks_need_the_signed_option_and_keep_to_the_existing_object_policy() {
    use std::os::unix::fs::MetadataExt;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("target/source"), b"payload").unwrap();
    fs::write(root.join("target/existing"), b"existing").unwrap();
    fs::write(root.join("outside"), b"outside").unwrap();
    let link = |path: &str, source: &str| Request::Apply {
        ops: vec![Op::Hardlink {
            path: path_bytes(&root.join(path)),
            source: path_bytes(&root.join(source)),
            dev: 1,
            ino: 2,
            condition: proto::TargetCondition::Any,
        }],
    };
    let condition = |request: &Request| match request {
        Request::Apply { ops, .. } => match &ops[0] {
            Op::Hardlink { condition, .. } => *condition,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };
    let with_policy = |existing| {
        let mut authority = test_authority_with_existence(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            existing,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
        )
        .unwrap();
        authority.extra_options.hardlinks = true;
        authority
    };

    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let error = authority
        .authorize(&mut link("target/new", "target/source"), false)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("hardlink creation is not authorized"),
        "{error:#}"
    );
    assert!(authority
        .check_flags(proto::flags::REPORT_IDENTITY, 0)
        .is_err());
    authority.extra_options.hardlinks = true;
    authority
        .check_flags(proto::flags::REPORT_IDENTITY, 0)
        .unwrap();

    // Either name outside the signed scopes is refused.
    let replace = with_policy(ExistingDestinationPolicy::Replace);
    assert!(replace
        .authorize(&mut link("target/new", "outside"), false)
        .is_err());
    assert!(replace
        .authorize(&mut link("outside-link", "target/source"), false)
        .is_err());
    let mut request = link("target/existing", "target/source");
    replace.authorize(&mut request, false).unwrap();
    assert_eq!(condition(&request), proto::TargetCondition::Any);

    // Keeping existing entries: a new name only, never a replacement,
    // which the link itself refuses where the name exists.
    let keep = with_policy(ExistingDestinationPolicy::Skip);
    let mut request = link("target/existing", "target/source");
    keep.authorize(&mut request, false).unwrap();
    assert_eq!(condition(&request), proto::TargetCondition::Absent);
    let mut request = link("target/new", "target/source");
    keep.authorize(&mut request, false).unwrap();
    assert_eq!(condition(&request), proto::TargetCondition::Absent);

    // Changing existing entries only: the name observed, and nothing else.
    let update = with_policy(ExistingDestinationPolicy::MustExist);
    assert!(update
        .authorize(&mut link("target/new", "target/source"), false)
        .is_err());
    let mut request = link("target/existing", "target/source");
    update.authorize(&mut request, false).unwrap();
    let observed = fs::metadata(root.join("target/existing")).unwrap();
    assert_eq!(
        condition(&request),
        proto::TargetCondition::Matches {
            dev: observed.dev(),
            ino: observed.ino(),
        }
    );
}

/// A name already linked to its file changes nothing, so the results report
/// no change for it, as an ordinary copy reports it unchanged. The link is
/// held to that file: if the name changes before it runs, it fails, and the
/// results report that, rather than linking it again.
#[test]
fn a_name_already_linked_records_no_operation_unless_it_changes() {
    use std::os::unix::fs::MetadataExt;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("target/a"), b"shared").unwrap();
    fs::hard_link(root.join("target/a"), root.join("target/b")).unwrap();
    fs::write(root.join("target/c"), b"other").unwrap();
    let file = fs::metadata(root.join("target/a")).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.extra_options.hardlinks = true;
    authority.start_results(false).unwrap();
    let link = |name: &str, before: &dyn Fn()| {
        let mut request = Request::Apply {
            ops: vec![Op::Hardlink {
                path: path_bytes(&root.join("target").join(name)),
                source: path_bytes(&root.join("target/a")),
                dev: file.dev(),
                ino: file.ino(),
                condition: proto::TargetCondition::Any,
            }],
        };
        let settlement = authority.authorize(&mut request, false).unwrap();
        before();
        let Request::Apply { ops } = &request else {
            unreachable!()
        };
        let results = execute_ops(&authority, ops);
        authority.settle(settlement, &proto::Response::Applied(results));
        let totals = authority.results.lock().unwrap().as_ref().unwrap().totals();
        (totals.files_transferred, totals.failed)
    };
    assert_eq!(link("b", &|| ()), (0, 0));
    // The name is replaced by another file between the check and the link.
    let replace_b = || {
        fs::remove_file(root.join("target/b")).unwrap();
        fs::write(root.join("target/b"), b"someone else's").unwrap();
    };
    assert_eq!(link("b", &replace_b), (0, 1));
    assert_eq!(fs::read(root.join("target/b")).unwrap(), b"someone else's");
    assert_eq!(link("c", &|| ()), (1, 1));
    assert_eq!(
        fs::metadata(root.join("target/c")).unwrap().ino(),
        file.ino()
    );
}

#[test]
fn signed_grants_authorize_only_their_inode_metadata() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let everything = crate::inode_metadata::Selection {
        acls: true,
        xattrs: true,
        atimes: true,
        crtimes: true,
        open_noatime: true,
    };
    let configuration = |selection, sparse| Request::ConfigurePreservation {
        narrow_new_directories: false,
        own_links: false,
        skips_unmet_conditions: false,
        unchecked_keep: false,
        sparse,
        selection,
        destination: true,
    };
    let acl_meta = || {
        let mut meta = plain_meta();
        meta.inode_metadata = Some(Box::new(crate::inode_metadata::InodeMetadata {
            acls: Some(crate::inode_metadata::PosixAcls {
                access: None,
                default: None,
            }),
            ..Default::default()
        }));
        meta
    };
    let time_meta = || {
        let mut meta = plain_meta();
        meta.inode_metadata = Some(Box::new(crate::inode_metadata::InodeMetadata {
            atime: Some(crate::inode_metadata::Timestamp {
                seconds: 1,
                nanoseconds: 0,
            }),
            ..Default::default()
        }));
        meta
    };
    assert!(authority
        .authorize(&mut configuration(everything, true), true)
        .is_err());
    let error = authority
        .check_metadata(b"/unmapped", &acl_meta(), 0)
        .unwrap_err();
    assert!(
        error.to_string().contains("inode metadata not authorized"),
        "{error:#}"
    );
    assert!(authority
        .check_metadata(b"/unmapped", &time_meta(), 0)
        .is_err());

    authority.extra_options.acls = true;
    authority.extra_options.sparse = true;
    let acls_only = crate::inode_metadata::Selection {
        acls: true,
        ..Default::default()
    };
    authority
        .authorize(&mut configuration(acls_only, true), true)
        .unwrap();
    assert!(authority
        .authorize(&mut configuration(everything, true), true)
        .is_err());
    authority
        .check_metadata(b"/unmapped", &acl_meta(), 0)
        .unwrap();
    assert!(authority
        .check_metadata(b"/unmapped", &time_meta(), 0)
        .is_err());
    // The receiver's own creation rules are not the sender's to choose.
    let mut rsync_directories = Request::ConfigurePreservation {
        narrow_new_directories: true,
        own_links: false,
        skips_unmet_conditions: false,
        unchecked_keep: false,
        sparse: false,
        selection: acls_only,
        destination: true,
    };
    assert!(authority.authorize(&mut rsync_directories, true).is_err());
}

#[test]
fn signed_comparison_requests_enforce_scope_identity_and_bounds() {
    let tree = crate::test_support::tempdir().unwrap();
    let root = tree.path().join("root");
    fs::create_dir(&root).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 16 << 20);
    let target = root.join("target").as_os_str().as_bytes().to_vec();
    let outside = tree.path().join("outside").as_os_str().as_bytes().to_vec();
    let id = [104; 16];
    let stage = |path, len| Request::StageBasis {
        path,
        copy_id: id,
        len,
        block: 4 << 20,
        allow_final: true,
        attempt: 0,
    };
    let hash = |path, off, len| Request::HashWindow {
        final_basis: true,
        path,
        copy_id: id,
        off,
        len,
        block: 4 << 20,
        attempt: 0,
    };
    let reuse = |path, copy_id, off, len| Request::ReuseComparedRange {
        path,
        copy_id,
        attempt: 0,
        off,
        len,
    };
    // Blocks reused past what the file declared, or into a file this
    // receiver does not hold, are refused as it writes them
    // (`fsops::stages`).
    assert!(authority
        .authorize(&mut stage(outside.clone(), 8 << 20), false)
        .is_err());
    assert!(authority
        .authorize(&mut stage(target.clone(), 17 << 20), false)
        .is_err());
    let mut allowed = stage(target.clone(), 8 << 20);
    authority.authorize(&mut allowed, false).unwrap();
    let mut allowed = hash(target.clone(), 0, 4 << 20);
    authority.authorize(&mut allowed, false).unwrap();
    for mut request in [
        hash(outside.clone(), 0, 4 << 20),
        hash(target.clone(), u64::MAX, 4 << 20),
        hash(target.clone(), 0, (64 << 20) + 1),
        reuse(outside, id, 0, 4 << 20),
        reuse(target.clone(), id, u64::MAX, 1),
        reuse(target.clone(), id, 0, 0),
    ] {
        assert!(
            authority.authorize(&mut request, false).is_err(),
            "{request:?}"
        );
    }
    let mut allowed = reuse(target.clone(), id, 0, 4 << 20);
    authority.authorize(&mut allowed, false).unwrap();
    // An in-place grant stages an existing file too, so it compares and
    // reuses blocks as a staged grant does.
    authority.copy.policy.publication = PublicationPolicy::InPlaceNew;
    authority
        .authorize(&mut stage(target.clone(), 8 << 20), false)
        .unwrap();
    authority
        .authorize(&mut reuse(target, id, 0, 4 << 20), false)
        .unwrap();
}

fn existing_read(path: &Path, len: u64) -> proto::ExistingRead {
    proto::ExistingRead {
        path: path_bytes(path),
        len,
        condition: proto::TargetCondition::Any,
    }
}

fn small_patch(
    path: &Path,
    len: u64,
    block: u64,
    reuse: Vec<Option<proto::ContentDigest>>,
    data: &[u8],
) -> proto::SmallPatch {
    proto::SmallPatch {
        path: path_bytes(path),
        copy_id: [1; 16],
        len,
        block,
        reuse,
        data: data.to_vec(),
        hash: crate::fsops::content_digest(data),
        basis: None,
        meta: plain_meta(),
        flags: 0,
        unchanged_flags: 0,
        condition: proto::TargetCondition::Any,
        update_in_place: false,
    }
}

#[test]
fn grouped_comparison_keeps_and_patches_files_within_the_grant() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let same = target.join("same");
    let edited = target.join("edited");
    fs::create_dir_all(&target).unwrap();
    fs::write(&same, b"same").unwrap();
    fs::write(&edited, b"old!").unwrap();
    for path in [&same, &edited] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
    }
    let same_inode = fs::metadata(&same).unwrap().ino();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let block = authority.copy.limits.hash_block_bytes;

    let mut hash = Request::HashExistingBatch {
        block,
        files: vec![existing_read(&same, 4), existing_read(&edited, 4)],
    };
    let settlement = authority.authorize(&mut hash, false).unwrap();
    let response = authority.test_ops().handle(&hash);
    authority.settle(settlement, &response);
    let proto::Response::ExistingHashes(existing) = response else {
        panic!("unexpected hash response {response:?}")
    };
    let existing: Vec<_> = existing.into_iter().map(Result::unwrap).collect();

    // Unrestricted modes are proposed; the receiver keeps the existing ones.
    let receiver_mode = |mut patch: proto::SmallPatch, basis: &proto::ExistingHashes| {
        patch.basis = basis.fingerprint;
        patch.meta.mode = 0o7777;
        patch.flags = proto::flags::RECEIVER_MODE;
        patch.unchanged_flags = proto::flags::RECEIVER_MODE;
        patch
    };
    let mut patch = Request::PatchSmallBatch(vec![
        receiver_mode(
            small_patch(&same, 4, block, vec![Some(existing[0].hashes[0])], b""),
            &existing[0],
        ),
        receiver_mode(
            small_patch(&edited, 4, block, vec![None], b"new!"),
            &existing[1],
        ),
    ]);
    let settlement = authority.authorize(&mut patch, false).unwrap();
    let Request::PatchSmallBatch(patches) = &patch else {
        unreachable!()
    };
    for patch in patches {
        // The authority leaves the choice of mode to the receiver.
        assert_eq!(
            (patch.meta.mode, patch.flags, patch.unchanged_flags),
            (
                0o7777,
                proto::flags::RECEIVER_MODE,
                proto::flags::RECEIVER_MODE
            )
        );
        assert_eq!(patch.condition, proto::TargetCondition::Any);
    }
    {
        let state = authority.state.lock().unwrap();
        // Only the new data crossed the transport; both publications are
        // held until the reply says which file was kept.
        assert_eq!(
            authority
                .transferred_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            4
        );
        assert_eq!(state.reserved_bytes, 8);
    }
    let response = authority.test_ops().handle(&patch);
    authority.settle(settlement, &response);
    let proto::Response::PatchedBatch(patched) = response else {
        panic!("unexpected patch response {response:?}")
    };
    assert_eq!(
        patched,
        vec![
            Ok(proto::SmallPatched {
                kept: true,
                identity: None,
                replaced: None
            }),
            Ok(proto::SmallPatched {
                kept: false,
                identity: None,
                replaced: None
            }),
        ]
    );
    assert_eq!(fs::metadata(&same).unwrap().ino(), same_inode);
    assert_eq!(fs::read(&edited).unwrap(), b"new!");
    for path in [&same, &edited] {
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o640);
    }
    // The kept file released its hold; the published one keeps its size.
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 4);
}

/// Authorize, execute and settle `request` as the receiver's server does.
fn execute_authorized(
    authority: &RestrictedAuthority,
    ops: &mut crate::fsops::FsOps,
    mut request: Request,
) -> proto::Response {
    let settlement = authority.authorize(&mut request, false).unwrap();
    let response = ops.handle(&request);
    authority.settle(settlement, &response);
    response
}

/// Hash `paths` and patch each from every block it holds, with
/// receiver-managed modes and new times.
fn compare_and_keep(
    authority: &RestrictedAuthority,
    ops: &mut crate::fsops::FsOps,
    paths: &[&Path],
) -> Vec<std::result::Result<proto::SmallPatched, proto::SmallPatchError>> {
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let hash = Request::HashExistingBatch {
        block,
        files: paths.iter().map(|path| existing_read(path, 4)).collect(),
    };
    let proto::Response::ExistingHashes(existing) = execute_authorized(authority, ops, hash) else {
        panic!("unexpected hash response")
    };
    let patches = paths
        .iter()
        .zip(existing)
        .map(|(path, hashed)| {
            let hashed = hashed.unwrap();
            let mut patch = small_patch(path, 4, block, vec![Some(hashed.hashes[0])], b"");
            patch.basis = hashed.fingerprint;
            patch.meta.mtime = 1_600_000_000;
            patch.flags = proto::flags::RECEIVER_MODE | proto::flags::TIMES;
            patch.unchanged_flags = patch.flags;
            patch
        })
        .collect();
    match execute_authorized(authority, ops, Request::PatchSmallBatch(patches)) {
        proto::Response::PatchedBatch(results) => results,
        other => panic!("unexpected patch response {other:?}"),
    }
}

#[test]
fn a_linked_file_whose_times_change_is_replaced_name_by_name() {
    // A file with other names is never changed in place: each name whose
    // contents match gets a new file built from those contents, with the
    // times the copy sets, and the old file keeps its own. The receiver
    // says why it replaced each.
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let (a, b) = (target.join("a"), target.join("b"));
    fs::create_dir_all(&target).unwrap();
    fs::write(&a, b"same").unwrap();
    fs::hard_link(&a, &b).unwrap();
    let before = fs::metadata(&a).unwrap();
    let authority = time_preserving_test_authority(&root);
    let mut ops = authority.test_ops();
    let replaced = || {
        Ok(proto::SmallPatched {
            kept: false,
            identity: None,
            replaced: Some(proto::ReplaceReason::OtherNames),
        })
    };
    let results = compare_and_keep(&authority, &mut ops, &[&a, &b]);
    assert_eq!(results, vec![replaced(), replaced()]);
    let inodes: Vec<_> = [&a, &b]
        .into_iter()
        .map(|path| {
            let metadata = fs::metadata(path).unwrap();
            assert_ne!(metadata.ino(), before.ino());
            assert_eq!(metadata.mtime(), 1_600_000_000);
            assert_eq!(fs::read(path).unwrap(), b"same");
            metadata.ino()
        })
        .collect();
    assert_ne!(inodes[0], inodes[1]);

    // Contents changed after they were hashed, under a condition that still
    // holds, fail as before: the file is neither kept nor stale.
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let hash = Request::HashExistingBatch {
        block,
        files: vec![existing_read(&a, 4)],
    };
    let proto::Response::ExistingHashes(mut existing) =
        execute_authorized(&authority, &mut ops, hash)
    else {
        panic!("unexpected hash response")
    };
    let hashed = existing.remove(0).unwrap();
    // A new change time shows that the file changed, as a fingerprint
    // would.
    std::thread::sleep(std::time::Duration::from_millis(50));
    fs::write(&a, b"SAME").unwrap();
    let mut patch = small_patch(&a, 4, block, vec![Some(hashed.hashes[0])], b"");
    patch.basis = hashed.fingerprint;
    patch.flags = proto::flags::RECEIVER_MODE;
    patch.unchanged_flags = patch.flags;
    let response = execute_authorized(&authority, &mut ops, Request::PatchSmallBatch(vec![patch]));
    assert!(
        matches!(
            &response,
            proto::Response::PatchedBatch(results) if matches!(
                results.as_slice(),
                [Err(proto::SmallPatchError {
                    matched: false,
                    stale_condition: false,
                    ..
                })]
            )
        ),
        "{response:?}"
    );
    assert_eq!(fs::read(&a).unwrap(), b"SAME");
}

#[test]
fn a_stale_patch_holds_no_bytes_and_leaves_its_record_to_the_retry() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let (a, b) = (target.join("a"), target.join("b"));
    fs::create_dir_all(&target).unwrap();
    fs::write(&a, b"same").unwrap();
    fs::hard_link(&a, &b).unwrap();
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let mut authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        8,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy)),
    )
    .unwrap();
    authority.copy.options.preserve_times = true;
    let mut reader = start_results(&authority, secret);
    let mut ops = authority.test_ops();
    let kept = Ok(proto::SmallPatched {
        kept: true,
        identity: None,
        replaced: None,
    });
    // Both names are hashed, and the second is then replaced by another
    // file. A patch pinned to the file it hashed, as an exact destination
    // or an update-only grant pins it, is refused as stale for that name.
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let hash = Request::HashExistingBatch {
        block,
        files: vec![existing_read(&a, 4), existing_read(&b, 4)],
    };
    let proto::Response::ExistingHashes(existing) = execute_authorized(&authority, &mut ops, hash)
    else {
        panic!("unexpected hash response")
    };
    let replacement = target.join("replacement");
    fs::write(&replacement, b"same").unwrap();
    fs::rename(&replacement, &b).unwrap();
    let patches = [&a, &b]
        .into_iter()
        .zip(existing)
        .map(|(path, hashed)| {
            let hashed = hashed.unwrap();
            let fingerprint = hashed.fingerprint.unwrap();
            let mut patch = small_patch(path, 4, block, vec![Some(hashed.hashes[0])], b"");
            patch.basis = Some(fingerprint);
            patch.meta.mtime = 1_600_000_000;
            patch.flags = proto::flags::RECEIVER_MODE | proto::flags::TIMES;
            patch.unchanged_flags = patch.flags;
            patch.condition = proto::TargetCondition::Matches {
                dev: fingerprint.dev,
                ino: fingerprint.ino,
            };
            patch
        })
        .collect();
    let proto::Response::PatchedBatch(results) =
        execute_authorized(&authority, &mut ops, Request::PatchSmallBatch(patches))
    else {
        panic!("unexpected patch response")
    };
    assert_eq!(results[0], kept);
    assert!(
        matches!(
            &results[1],
            Err(proto::SmallPatchError {
                stale_condition: true,
                ..
            })
        ),
        "{:?}",
        results[1]
    );
    // Nothing was written for it, so it holds none of the grant's bytes.
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 0);
    assert_eq!(compare_and_keep(&authority, &mut ops, &[&b]), vec![kept]);
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 0);

    // Both names were kept, which lists no change, and nothing failed:
    // the stale attempt left its outcome to the retry.
    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.failed, 0);
    assert_eq!(results.totals.files_transferred, 0);
    assert!(results.records.is_empty(), "{:?}", results.records);
}

#[test]
fn grouped_comparison_refuses_what_the_grant_does_not_authorize() {
    use crate::hashing::{CopyHashing, Digest, HashAlgorithm, HashPolicy};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let file = target.join("file");
    let outside = root.join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::write(&file, b"data").unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let block = authority.copy.limits.hash_block_bytes;
    let hash = |files| Request::HashExistingBatch { block, files };
    let patch = |patch| Request::PatchSmallBatch(vec![patch]);
    let reused = |path: &Path| small_patch(path, 4, block, vec![Some([0; 32])], b"");

    let mut allowed = hash(vec![existing_read(&file, 4)]);
    authority.authorize(&mut allowed, false).unwrap();
    let mut allowed = patch(reused(&file));
    authority.authorize(&mut allowed, false).unwrap();
    // The grouped comparison is not bound to the grant's block, which the
    // per-file comparison uses.
    assert_ne!(block, proto::MIN_HASH_BLOCK_BYTES);
    let small = proto::MIN_HASH_BLOCK_BYTES;
    let mut allowed = Request::HashExistingBatch {
        block: small,
        files: vec![existing_read(&file, 4)],
    };
    authority.authorize(&mut allowed, false).unwrap();
    let mut allowed = patch(small_patch(&file, 4, small, vec![Some([0; 32])], b""));
    authority.authorize(&mut allowed, false).unwrap();

    let mut altered = small_patch(&file, 4, block, vec![None], b"data");
    altered.flags = proto::flags::RECEIVER_MODE;
    let mut flags_differ = small_patch(&file, 4, block, vec![None], b"data");
    flags_differ.unchanged_flags = proto::flags::OWNER;
    for (mut request, error) in [
        (
            hash(vec![existing_read(&file, 4), existing_read(&outside, 4)]),
            "receiver observation is outside the signed destination scopes",
        ),
        (
            Request::HashExistingBatch {
                block: 4096,
                files: vec![existing_read(&file, 4)],
            },
            "comparison block size is outside protocol limits",
        ),
        (
            hash(vec![existing_read(&file, 1025)]),
            "signed grant per-file byte limit exceeded",
        ),
        (
            patch(reused(&outside)),
            "receiver mutation is outside the signed destination scopes",
        ),
        (
            patch(small_patch(&file, 4, 4096, vec![Some([0; 32])], b"")),
            "comparison block size is outside protocol limits",
        ),
        (
            patch(small_patch(&file, 1025, block, vec![Some([0; 32])], b"")),
            "signed grant per-file byte limit exceeded",
        ),
        (
            patch(altered),
            "kept and published metadata flags differ beyond times",
        ),
        (
            patch(flags_differ),
            "kept and published metadata flags differ beyond times",
        ),
    ] {
        assert_eq!(
            authority
                .authorize(&mut request, false)
                .unwrap_err()
                .to_string(),
            error,
            "{request:?}"
        );
    }

    // Each file's hashes may fit a response while the batch's do not.
    authority.copy.limits.max_file_bytes = u64::MAX;
    let half = (proto::MAX_FRAME as u64 / 33 / 2 + 1) * proto::MIN_HASH_BLOCK_BYTES;
    let mut excessive = Request::HashExistingBatch {
        block: proto::MIN_HASH_BLOCK_BYTES,
        files: vec![existing_read(&file, half), existing_read(&file, half)],
    };
    assert_eq!(
        authority
            .authorize(&mut excessive, false)
            .unwrap_err()
            .to_string(),
        "hash response would exceed protocol limits"
    );
    authority.copy.limits.max_file_bytes = 1024;

    // Files with an expected hash keep checked finalization.
    authority.hashing = Some(CopyHashing {
        policy: HashPolicy {
            algorithm: HashAlgorithm::Blake3,
            transfer_integrity: true,
            transfer_hash_type: None,
        },
        expected_hash: Some(Digest::hash_bytes(HashAlgorithm::Sha256, b"data")),
    });
    assert_eq!(
        authority
            .authorize(&mut patch(reused(&target)), false)
            .unwrap_err()
            .to_string(),
        "expected-hash files require checked finalization"
    );
    authority.hashing = None;

    authority.copy.options.dry_run = true;
    assert!(authority
        .authorize(&mut patch(reused(&file)), false)
        .is_err());
    authority.copy.options.dry_run = false;
    // An in-place grant stages an existing file as a staged grant does.
    authority.copy.policy.publication = PublicationPolicy::InPlaceNew;
    authority
        .authorize(&mut patch(reused(&file)), false)
        .unwrap();
    authority.copy.policy.publication = PublicationPolicy::AtomicStaged;

    // A grant that retains existing files lets a patch neither keep nor
    // replace one.
    let retaining = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryAsChild,
        RootExistence::Any,
    )
    .unwrap();
    assert!(retaining
        .authorize(&mut patch(reused(&file)), false)
        .is_err());
}

#[test]
fn grouped_patches_charge_their_new_data_and_hold_their_published_size() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = test_authority_with_rate(&root, DeletionPolicy::Forbid, 200_000, 4096);
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let burst = authority.file_data_limit.as_ref().unwrap().burst_bytes() as usize;
    let len = block + 100;
    let patch = |name: &str, data: &[u8]| {
        small_patch(
            &target.join(name),
            len,
            block,
            vec![Some([0; 32]), None],
            data,
        )
    };

    // Reused blocks are not charged against the rate limit; new data is,
    // a whole batch within one burst.
    let mut over = Request::PatchSmallBatch(vec![
        patch("a", &vec![0; burst / 2 + 1]),
        patch("b", &vec![0; burst / 2 + 1]),
    ]);
    assert_eq!(
        authority
            .authorize(&mut over, false)
            .unwrap_err()
            .to_string(),
        "small-file batch exceeds the signed file-data rate-limit burst"
    );
    let mut within = Request::PatchSmallBatch(vec![patch("a", &[0; 100])]);
    let settlement = authority.authorize(&mut within, false).unwrap();
    {
        let state = authority.state.lock().unwrap();
        assert_eq!(
            authority
                .transferred_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            100
        );
        assert_eq!(state.reserved_bytes, len);
    }
    authority.settle(
        settlement,
        &proto::Response::PatchedBatch(vec![Ok(proto::SmallPatched {
            kept: false,
            identity: None,
            replaced: None,
        })]),
    );
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, len);

    // Publishing the same partial again declares nothing new, while a
    // batch whose sizes would exceed the signed total holds none of them.
    let mut again = Request::PatchSmallBatch(vec![patch("a", &[0; 100])]);
    let settlement = authority.authorize(&mut again, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::PatchedBatch(vec![Ok(proto::SmallPatched {
            kept: true,
            identity: None,
            replaced: None,
        })]),
    );
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, len);
    let mut excessive = Request::PatchSmallBatch(vec![
        patch("b", &[0; 100]),
        patch("c", &[0; 100]),
        patch("d", &[0; 100]),
    ]);
    assert_eq!(
        authority
            .authorize(&mut excessive, false)
            .unwrap_err()
            .to_string(),
        "signed grant total-byte limit exceeded by file preparation"
    );
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, len);
}

#[test]
fn grouped_patch_batches_are_bounded_by_the_file_bytes_they_describe() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 128 << 20);
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let len = 40 << 20;
    // Each patch reuses every block, so it carries no data, and repeating
    // the same path and copy ID declares its size only once.
    let patch = || {
        small_patch(
            &target.join("file"),
            len,
            block,
            vec![Some([0; 32]); (len / block) as usize],
            b"",
        )
    };
    let mut repeated = Request::PatchSmallBatch(vec![patch(), patch()]);
    assert_eq!(
        authority
            .authorize(&mut repeated, false)
            .unwrap_err()
            .to_string(),
        "small-file patch batch describes more file bytes than the protocol allows"
    );
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 0);
    // A batch of one file may describe a whole group file.
    let mut single = Request::PatchSmallBatch(vec![patch()]);
    let settlement = authority.authorize(&mut single, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::Err("no file to reuse blocks from".into()),
    );
}

#[test]
fn grouped_patch_results_list_published_and_failed_files() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let kept = target.join("kept");
    let published = target.join("published");
    let failed = target.join("failed");
    let unkept = target.join("unkept");
    fs::create_dir_all(&target).unwrap();
    for path in [&kept, &published, &failed, &unkept] {
        fs::write(path, b"old").unwrap();
    }
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy)),
    )
    .unwrap();
    let mut reader = start_results(&authority, secret);
    let block = authority.copy.limits.hash_block_bytes;
    let mut batch = Request::PatchSmallBatch(vec![
        small_patch(&kept, 3, block, vec![Some([0; 32])], b""),
        small_patch(&published, 3, block, vec![None], b"new"),
        small_patch(&failed, 3, block, vec![None], b"new"),
        small_patch(&unkept, 3, block, vec![Some([0; 32])], b""),
    ]);
    let settlement = authority.authorize(&mut batch, false).unwrap();
    fs::write(&published, b"new").unwrap();
    authority.settle(
        settlement,
        &proto::Response::PatchedBatch(vec![
            Ok(proto::SmallPatched {
                kept: true,
                identity: None,
                replaced: None,
            }),
            Ok(proto::SmallPatched {
                kept: false,
                identity: None,
                replaced: None,
            }),
            // Writing it in place began and failed, so it is not copied
            // again.
            Err(proto::SmallPatchError {
                error: "writing it in place failed".into(),
                matched: false,
                stale_condition: false,
                written: true,
            }),
            Err(proto::SmallPatchError {
                error: "keeping it failed".into(),
                matched: true,
                stale_condition: false,
                written: false,
            }),
        ]),
    );

    // A file that matched holds nothing new, whether or not it was kept.
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 6);

    // Kept files list no change; a file that failed to be kept counts.
    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.files_transferred, 1);
    assert_eq!(results.totals.failed, 2);
    let mut changes = results.changes();
    changes.sort();
    assert_eq!(
        changes,
        [
            (
                "transfer_file".to_owned(),
                b"failed".to_vec(),
                "failed".to_owned()
            ),
            (
                "transfer_file".to_owned(),
                b"published".to_vec(),
                "succeeded".to_owned()
            ),
            // Its metadata could not be applied when keeping it.
            (
                "transfer_file".to_owned(),
                b"unkept".to_vec(),
                "failed".to_owned()
            ),
        ]
    );
}

#[test]
fn a_failed_patch_is_listed_unless_the_senders_retry_settles_it() {
    // A patch that fails with nothing written, and a batch that fails
    // whole, are files the sender copies again. The retry's outcome is the
    // file's; without one, the failure is listed when the results end.
    for (whole_batch, retry) in [(false, true), (false, false), (true, true), (true, false)] {
        let case = format!("whole_batch={whole_batch} retry={retry}");
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let file = target.join("file");
        fs::create_dir_all(&target).unwrap();
        fs::write(&file, b"old").unwrap();
        let key = generate_results_key(EnrollmentId::random()).unwrap();
        let (secret, policy) = results_policy();
        let authority = test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
            Some((key, policy)),
        )
        .unwrap();
        let mut reader = start_results(&authority, secret);
        let mut ops = authority.test_ops();
        let block = proto::MIN_HASH_BLOCK_BYTES;
        if whole_batch {
            // The receiver's executor failed the batch as a whole.
            let mut batch =
                Request::PatchSmallBatch(vec![small_patch(&file, 3, block, vec![None], b"new")]);
            let settlement = authority.authorize(&mut batch, false).unwrap();
            authority.settle(
                settlement,
                &proto::Response::EndpointError("the batch failed".into()),
            );
        } else {
            // The patch reuses a block the file does not hold, so it fails
            // with nothing written (`small_compare`'s `Compared::Differs`).
            let patch = small_patch(&file, 3, block, vec![Some([0; 32])], b"");
            let proto::Response::PatchedBatch(patched) =
                execute_authorized(&authority, &mut ops, Request::PatchSmallBatch(vec![patch]))
            else {
                panic!("{case}: unexpected patch response")
            };
            assert!(
                matches!(
                    &patched[..],
                    [Err(error @ proto::SmallPatchError { stale_condition: false, .. })]
                        if error.retried()
                ),
                "{case}: {patched:?}"
            );
        }
        assert_eq!(fs::read(&file).unwrap(), b"old", "{case}");
        if retry {
            let proto::Response::Applied(errors) =
                execute_authorized(&authority, &mut ops, small_put(&file))
            else {
                panic!("{case}: unexpected put response")
            };
            assert_eq!(errors, [None], "{case}");
            assert_eq!(fs::read(&file).unwrap(), b"new", "{case}");
        }

        let results = finish_results(&authority, &mut reader);
        let disposition = if retry { "succeeded" } else { "failed" };
        assert_eq!(
            results.changes(),
            [(
                "transfer_file".to_owned(),
                b"file".to_vec(),
                disposition.to_owned()
            )],
            "{case}"
        );
        assert_eq!(results.totals.failed, u64::from(!retry), "{case}");
        assert_eq!(results.totals.files_transferred, u64::from(retry), "{case}");
    }
}

#[test]
fn a_metadata_change_does_not_settle_a_failed_patch() {
    // After a patch fails with nothing written, a metadata change to the
    // same file, whatever the sender claims, says nothing of its contents:
    // the file is still listed failed when the results end.
    let metadata_changes = |path: &Path| {
        let mut meta = plain_meta();
        meta.mtime = 1_600_000_000;
        [
            Op::SetMeta {
                path: path_bytes(path),
                meta: meta.clone(),
                flags: proto::flags::TIMES,
                condition: proto::TargetCondition::Any,
                directory: false,
            },
            Op::SetFileMetaIfSame {
                path: path_bytes(path),
                condition: proto::TargetCondition::Any,
                meta,
                flags: proto::flags::TIMES,
            },
        ]
    };
    for (case, op) in metadata_changes(Path::new("")).into_iter().enumerate() {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let file = target.join("file");
        fs::create_dir_all(&target).unwrap();
        fs::write(&file, b"old").unwrap();
        let key = generate_results_key(EnrollmentId::random()).unwrap();
        let (secret, policy) = results_policy();
        let mut authority = test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
            Some((key, policy)),
        )
        .unwrap();
        authority.copy.options.preserve_times = true;
        let mut reader = start_results(&authority, secret);
        let mut ops = authority.test_ops();
        let block = proto::MIN_HASH_BLOCK_BYTES;
        let patch = small_patch(&file, 3, block, vec![Some([0; 32])], b"");
        let proto::Response::PatchedBatch(patched) =
            execute_authorized(&authority, &mut ops, Request::PatchSmallBatch(vec![patch]))
        else {
            panic!("{case}: unexpected patch response")
        };
        assert!(
            matches!(&patched[..], [Err(error)] if error.retried()),
            "{case}: {patched:?}"
        );
        // The executor reports the metadata change done.
        let op = match op {
            Op::SetMeta {
                meta,
                flags,
                condition,
                directory,
                ..
            } => Op::SetMeta {
                path: path_bytes(&file),
                meta,
                flags,
                condition,
                directory,
            },
            Op::SetFileMetaIfSame {
                meta,
                flags,
                condition,
                ..
            } => Op::SetFileMetaIfSame {
                path: path_bytes(&file),
                condition,
                meta,
                flags,
            },
            _ => unreachable!(),
        };
        let mut request = apply(op);
        let settlement = authority.authorize(&mut request, false).unwrap();
        authority.settle(settlement, &proto::Response::Applied(vec![None]));
        assert_eq!(fs::read(&file).unwrap(), b"old", "{case}");

        let results = finish_results(&authority, &mut reader);
        assert_eq!(results.totals.failed, 1, "{case}: {:?}", results.records);
        assert_eq!(results.totals.files_transferred, 0, "{case}");
        assert_eq!(
            results.changes(),
            [(
                "transfer_file".to_owned(),
                b"file".to_vec(),
                "failed".to_owned()
            )],
            "{case}"
        );
    }
}

#[test]
fn data_corrupted_in_transit_is_listed_as_an_integrity_failure() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
        Some((key, policy)),
    )
    .unwrap();
    let mut reader = start_results(&authority, secret);
    let mut ops = authority.test_ops();
    ops.set_hash_policy(authority.hash_policy());
    // A file whose data does not match the payload hash the source sent:
    // it changed on the way. Another file in the batch fails otherwise.
    let mut corrupted = small_put(&target.join("corrupted"));
    let Request::PutSmallBatch(puts) = &mut corrupted else {
        unreachable!()
    };
    puts[0].hash = [0; 32];
    let mut missing = small_put(&target.join("missing/file"));
    let Request::PutSmallBatch(missing) = &mut missing else {
        unreachable!()
    };
    puts.append(missing);
    let proto::Response::Applied(errors) = execute_authorized(&authority, &mut ops, corrupted)
    else {
        panic!("unexpected put response")
    };
    assert_eq!(
        errors[0].as_ref().and_then(|error| error.io_kind),
        Some(proto::WireIoKind::CorruptedInTransit),
        "{errors:?}"
    );
    assert!(errors[1].is_some(), "{errors:?}");
    // A range of a file copied per file fails the same way. The file is
    // listed unfinished when the results end, with that failure.
    let image = target.join("image");
    let mut prepare = Request::Prepare {
        path: path_bytes(&image),
        size: 4,
        inplace: false,
        copy_id: [2; 16],
        mode: 0o600,
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
    };
    let settlement = authority.authorize(&mut prepare, false).unwrap();
    authority.settle(settlement, &proto::Response::Ok);
    let mut write = Request::WriteRange {
        path: path_bytes(&image),
        inplace: false,
        copy_id: [2; 16],
        attempt: 0,
        off: 0,
        hash: [0; 32],
        data: b"data".to_vec().into(),
    };
    let settlement = authority.authorize(&mut write, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::EndpointError(crate::fsops::wire_error(&anyhow::Error::new(
            crate::fsops::CorruptedInTransit,
        ))),
    );

    // The receiver lists each as an ordinary copy reports it: an integrity
    // failure, with the message saying to rerun the command.
    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.failed, 3);
    let failed = |name: &str| {
        results
            .records
            .iter()
            .find(|record| record["type"] == "operation_result" && record["dst"]["value"] == name)
            .unwrap_or_else(|| panic!("{name}: {:?}", results.records))
            .clone()
    };
    for name in ["corrupted", "image"] {
        let corrupted = failed(name);
        assert_eq!(corrupted["disposition"], "failed", "{name}");
        assert_eq!(corrupted["class"], "integrity", "{name}");
        assert_eq!(
            corrupted["message"], "data corrupted in transit; rerun the command to retry",
            "{name}"
        );
    }
    assert_eq!(failed("missing/file")["class"], "io");
    let mut errors: Vec<_> = results
        .records
        .iter()
        .filter(|record| record["type"] == "error")
        .map(|record| record["class"].as_str().unwrap())
        .collect();
    errors.sort();
    assert_eq!(errors, ["integrity", "integrity", "io"]);
}

/// Authorize, execute and settle a request on the connection whose
/// streamed patch `gate` holds, as the receiver's server does, failing the
/// open patch when one of its pieces is refused. Returns the refusal, if any.
fn execute_on_connection(
    gate: &mut PatchStreamGate,
    ops: &mut crate::fsops::FsOps,
    mut request: Request,
) -> std::result::Result<proto::Response, String> {
    let settlement = match gate.authorize(&mut request, false) {
        Ok(settlement) => settlement,
        Err(error) => {
            let error = format!("{error:#}");
            match request {
                Request::PatchData { .. } => ops.fail_patch_stream(&error),
                Request::PatchEnd { .. } => {
                    ops.abandon_patch_stream();
                    gate.abandon(&error);
                }
                _ => {}
            }
            return Err(error);
        }
    };
    let response = ops.handle(&request);
    gate.settle(settlement, &response, ops.patch_stream_open());
    Ok(response)
}

#[test]
fn streamed_patches_keep_to_the_grant_from_their_begin_to_their_end() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let len = 64 * block;
    let old: Vec<u8> = (0..len).map(|i| (i % 233) as u8).collect();
    // More new data than one rate-limit burst.
    let mut new = old.clone();
    new[..20 * block as usize].fill(1);
    new[40 * block as usize] ^= 1;
    for name in ["refused", "published", "dropped", "outside-begin"] {
        fs::write(target.join(name), &old).unwrap();
    }
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    // 8 MiB/s: a burst of 1 MiB.
    let authority = std::sync::Arc::new(
        test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            64 << 20,
            8 << 20,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::Any,
            Some((key, policy)),
        )
        .unwrap(),
    );
    let mut reader = start_results(&authority, secret);
    let burst = authority.file_data_limit.as_ref().unwrap().burst_bytes();
    assert_eq!(burst, 1 << 20);
    let mut ops = authority.test_ops();
    let paths: Vec<_> = ["refused", "published", "dropped"]
        .iter()
        .map(|name| target.join(name))
        .collect();
    let hash = Request::HashExistingBatch {
        block,
        files: paths.iter().map(|path| existing_read(path, len)).collect(),
    };
    let proto::Response::ExistingHashes(existing) = execute_authorized(&authority, &mut ops, hash)
    else {
        panic!("unexpected hash response")
    };
    let algorithm = crate::hashing::HashPolicy::default().algorithm;
    let payload = crate::hashing::HashPolicy::default().payload_algorithm();
    let patch = |path: &Path, hashed: &proto::ExistingHashes| {
        let reuse: Vec<_> = new
            .chunks(block as usize)
            .zip(&hashed.hashes)
            .map(|(chunk, old)| (algorithm.hash(chunk) == *old).then_some(*old))
            .collect();
        let mut patch = small_patch(path, len, block, reuse, b"");
        patch.basis = hashed.fingerprint;
        patch
    };
    let begin = |patch: &proto::SmallPatch| Request::PatchBegin {
        patch: Box::new(patch.clone()),
        data_len: patch.new_bytes(),
    };
    let piece = |data: &[u8]| Request::PatchData {
        data: data.to_vec().into(),
        hash: payload.hash(data),
    };
    let new_data = |patch: &proto::SmallPatch| -> Vec<u8> {
        new.chunks(block as usize)
            .zip(&patch.reuse)
            .filter(|(_, reuse)| reuse.is_none())
            .flat_map(|(chunk, _)| chunk.to_vec())
            .collect()
    };
    let in_flight = || authority.state.lock().unwrap().in_flight;
    let sidecars = || {
        fs::read_dir(&target)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".syq-tmp.")
            })
            .count()
    };
    let hashed: Vec<_> = existing.into_iter().map(Result::unwrap).collect();
    let mut gate = PatchStreamGate::new(authority.clone());

    // Pieces and ends need an open patch; a begin must carry no data,
    // declare what its blocks hold, and pass every rule of a batch patch.
    let refused_patch = patch(&paths[0], &hashed[0]);
    let data = new_data(&refused_patch);
    for request in [
        piece(&data[..block as usize]),
        Request::PatchEnd { commit: true },
    ] {
        let error = execute_on_connection(&mut gate, &mut ops, request).unwrap_err();
        assert!(error.contains("no streamed patch is open"), "{error}");
    }
    let mut carrying = refused_patch.clone();
    carrying.data = data.clone();
    let mut short = begin(&refused_patch);
    if let Request::PatchBegin { data_len, .. } = &mut short {
        *data_len -= 1;
    }
    for (request, refusal) in [
        (
            Request::PatchBegin {
                patch: Box::new(carrying),
                data_len: data.len() as u64,
            },
            "a streamed patch carries its data in pieces",
        ),
        (short, "streamed patch declares"),
        (
            begin(&patch(&root.join("outside-begin"), &hashed[0])),
            "outside the signed destination scopes",
        ),
    ] {
        let error = execute_on_connection(&mut gate, &mut ops, request).unwrap_err();
        assert!(error.contains(refusal), "{error}");
    }
    assert!(!gate.is_open() && !ops.patch_stream_open());
    assert_eq!(in_flight(), 0);

    // A begin holds its file's size and counts as in flight until its end;
    // a second begin on its connection is refused.
    let reserved = authority.state.lock().unwrap().reserved_bytes;
    assert!(matches!(
        execute_on_connection(&mut gate, &mut ops, begin(&refused_patch)),
        Ok(proto::Response::Ok)
    ));
    assert!(gate.is_open());
    assert_eq!(in_flight(), 1);
    assert_eq!(
        authority.state.lock().unwrap().reserved_bytes,
        reserved + len
    );
    let error = execute_on_connection(&mut gate, &mut ops, begin(&refused_patch)).unwrap_err();
    assert!(error.contains("already open"), "{error}");
    let second = begin(&patch(&paths[1], &hashed[1]));
    let error = gate.authorize(&mut second.clone(), true).unwrap_err();
    assert!(format!("{error:#}").contains("already open"), "{error:#}");
    // A refused begin holds none of its file's size.
    assert_eq!(
        authority.state.lock().unwrap().reserved_bytes,
        reserved + len
    );
    // A piece is charged as written data, within one rate-limit burst; a
    // refused piece fails its patch, which then publishes nothing.
    let transferred = authority
        .transferred_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        execute_on_connection(&mut gate, &mut ops, piece(&data[..block as usize])),
        Ok(proto::Response::Ok)
    ));
    assert_eq!(
        authority
            .transferred_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        transferred + block
    );
    let oversized = vec![0; burst as usize + 1];
    let error = execute_on_connection(&mut gate, &mut ops, piece(&oversized)).unwrap_err();
    assert!(error.contains("rate-limit burst"), "{error}");
    let error = execute_on_connection(&mut gate, &mut ops, piece(&data)).unwrap_err();
    assert!(
        error.contains("runs past the length its begin declared"),
        "{error}"
    );
    assert_eq!(sidecars(), 0);
    let ended = execute_on_connection(&mut gate, &mut ops, Request::PatchEnd { commit: true });
    assert!(
        matches!(&ended, Ok(proto::Response::PatchedBatch(outcome)) if outcome[0].is_err()),
        "{ended:?}"
    );
    assert!(!gate.is_open());
    assert_eq!(in_flight(), 0);
    assert_eq!(fs::read(&paths[0]).unwrap(), old);

    // A patch whose pieces stay within its begin is published at its end.
    let published = patch(&paths[1], &hashed[1]);
    let data = new_data(&published);
    assert!(matches!(
        execute_on_connection(&mut gate, &mut ops, begin(&published)),
        Ok(proto::Response::Ok)
    ));
    for chunk in data.chunks(2 * block as usize) {
        assert!(matches!(
            execute_on_connection(&mut gate, &mut ops, piece(chunk)),
            Ok(proto::Response::Ok)
        ));
    }
    let ended = execute_on_connection(&mut gate, &mut ops, Request::PatchEnd { commit: true });
    assert!(
        matches!(&ended, Ok(proto::Response::PatchedBatch(outcome)) if outcome[0].is_ok()),
        "{ended:?}"
    );
    assert_eq!(fs::read(&paths[1]).unwrap(), new);

    // A connection that closes with a patch open removes its stage, and
    // its patch is settled as failed, with nothing published.
    {
        let mut gate = PatchStreamGate::new(authority.clone());
        let mut ops = authority.test_ops();
        let dropped = patch(&paths[2], &hashed[2]);
        assert!(matches!(
            execute_on_connection(&mut gate, &mut ops, begin(&dropped)),
            Ok(proto::Response::Ok)
        ));
        assert_eq!(sidecars(), 1);
        assert_eq!(in_flight(), 1);
    }
    assert_eq!(sidecars(), 0);
    assert_eq!(in_flight(), 0);
    assert_eq!(fs::read(&paths[2]).unwrap(), old);

    // The results list each publication, as for batch patches, and each
    // refused begin by its path: three for `refused` (data in the begin, a
    // short declaration, a second begin) and one for `published` (a begin
    // while another was open). The begin outside the destination is not
    // listed by path. A patch that failed with nothing published, here
    // `refused` once its piece was refused and `dropped`, is held for the
    // sender to copy again; as no copy follows, each is listed failed when
    // the results end.
    let results = finish_results(&authority, &mut reader);
    let mut changes = results.changes();
    changes.sort();
    let publish = |path: &[u8], disposition: &str| {
        (
            "transfer_file".to_owned(),
            path.to_vec(),
            disposition.to_owned(),
        )
    };
    assert_eq!(
        changes,
        [
            publish(b"dropped", "failed"),
            publish(b"published", "failed"),
            publish(b"published", "succeeded"),
            publish(b"refused", "failed"),
            publish(b"refused", "failed"),
            publish(b"refused", "failed"),
            publish(b"refused", "failed"),
        ]
    );
    let refusals = results
        .records
        .iter()
        .filter(|record| record["type"] == "error" && record["class"] == "safety_limit")
        .count();
    assert_eq!(refusals as u64, results.totals.refused);
}

#[test]
fn a_streamed_patch_is_refused_wherever_a_batch_patch_is() {
    use crate::hashing::{CopyHashing, Digest, HashAlgorithm, HashPolicy};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    let file = target.join("file");
    fs::create_dir_all(&target).unwrap();
    fs::write(&file, vec![1; 4 << 16]).unwrap();
    let block = proto::MIN_HASH_BLOCK_BYTES;
    let begin = |patch: proto::SmallPatch| Request::PatchBegin {
        data_len: patch.new_bytes(),
        patch: Box::new(patch),
    };
    let streamed_at = |path: &Path, len: u64, block: u64| {
        let mut reuse = vec![Some([0; 32]); len.div_ceil(block) as usize];
        reuse[0] = None;
        small_patch(path, len, block, reuse, b"")
    };
    let streamed = |len: u64, block: u64| streamed_at(&file, len, block);
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1 << 20);
    authority
        .authorize(&mut begin(streamed(4 * block, block)), false)
        .unwrap();
    let mut flags_differ = streamed(4 * block, block);
    flags_differ.unchanged_flags = proto::flags::OWNER;
    for (request, error) in [
        (
            begin(streamed(4 * block, 4096)),
            "comparison block size is outside protocol limits",
        ),
        (
            begin(streamed((1 << 20) + 1, block)),
            "signed grant per-file byte limit exceeded",
        ),
        (
            begin(flags_differ),
            "kept and published metadata flags differ beyond times",
        ),
        (
            begin(small_patch(
                &root.join("outside"),
                block,
                block,
                vec![None],
                b"",
            )),
            "receiver mutation is outside the signed destination scopes",
        ),
    ] {
        let mut request = request;
        assert_eq!(
            authority
                .authorize(&mut request, false)
                .unwrap_err()
                .to_string(),
            error
        );
    }
    authority.hashing = Some(CopyHashing {
        policy: HashPolicy {
            algorithm: HashAlgorithm::Blake3,
            transfer_integrity: true,
            transfer_hash_type: None,
        },
        expected_hash: Some(Digest::hash_bytes(HashAlgorithm::Sha256, b"data")),
    });
    // The expected hash is the destination's own, a single file.
    assert_eq!(
        authority
            .authorize(&mut begin(streamed_at(&target, 4 * block, block)), false)
            .unwrap_err()
            .to_string(),
        "expected-hash files require checked finalization"
    );
    authority.hashing = None;
    // An in-place grant stages an existing file as a staged grant does.
    authority.copy.policy.publication = PublicationPolicy::InPlaceNew;
    authority
        .authorize(&mut begin(streamed(4 * block, block)), false)
        .unwrap();
    authority.copy.policy.publication = PublicationPolicy::AtomicStaged;
    // A grant that retains existing files lets a patch neither keep nor
    // replace one, streamed or not.
    let retaining = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryAsChild,
        RootExistence::Any,
    )
    .unwrap();
    assert!(retaining
        .authorize(&mut begin(streamed(4 * block, block)), false)
        .is_err());
    // A refused begin holds none of the grant's bytes; the one admitted
    // above, never settled, still holds its file's.
    assert_eq!(authority.state.lock().unwrap().reserved_bytes, 4 * block);
}

/// One receiver of a parity check: ordinary, with the destination registered
/// as its coordinator registers it, or command-restricted, authorizing each
/// request against a grant before carrying it out.
struct ParityReceiver {
    authority: Option<RestrictedAuthority>,
    ops: crate::fsops::FsOps,
}

impl ParityReceiver {
    fn new(root: &Path, restricted: bool, preserve: bool, publication: PublicationPolicy) -> Self {
        let target = root.join("target");
        let authority = restricted.then(|| {
            let mut authority = test_authority_with_policy(
                root,
                DeletionPolicy::Forbid,
                1 << 20,
                0,
                FilterPolicy::default(),
                publication,
            );
            authority.copy.options.preserve_permissions = preserve;
            authority.copy.options.receiver_managed_modes = !preserve;
            authority.copy.options.preserve_devices = true;
            authority.copy.limits.max_entries = 1000;
            authority.extra_options.widen_dirs = DirectoryWidening::Rsync;
            authority
        });
        let ops = match &authority {
            Some(authority) => authority.test_ops(),
            None => crate::fsops::FsOps::test_destination(&target),
        };
        Self { authority, ops }
    }

    fn send(&mut self, mut request: Request) -> proto::Response {
        let response = match &self.authority {
            Some(authority) => {
                let settlement = authority.authorize(&mut request, false).unwrap();
                let response = self.ops.handle(&request);
                authority.settle(settlement, &response);
                response
            }
            None => self.ops.handle(&request),
        };
        assert!(
            match &response {
                proto::Response::Applied(errors) => errors.iter().all(Option::is_none),
                proto::Response::WidenedDirectories(outcomes) => outcomes.iter().all(Result::is_ok),
                proto::Response::Err(_) | proto::Response::EndpointError(_) => false,
                _ => true,
            },
            "{response:?}"
        );
        response
    }
}

/// The same requests, as a coordinator sends them without and with -p,
/// through an ordinary receiver and a command-restricted one, in two copies
/// of one tree. Returns each entry's mode after each.
fn parity_modes(preserve: bool, inplace: bool) -> [Vec<(String, u32)>; 2] {
    let mode_flag = if preserve {
        proto::flags::MODE
    } else {
        proto::flags::RECEIVER_MODE
    };
    [false, true].map(|restricted| {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(target.join("setgid")).unwrap();
        fs::set_permissions(target.join("setgid"), fs::Permissions::from_mode(0o2775)).unwrap();
        fs::create_dir(target.join("existing-dir")).unwrap();
        fs::set_permissions(
            target.join("existing-dir"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        fs::create_dir(target.join("read-only-dir")).unwrap();
        fs::set_permissions(
            target.join("read-only-dir"),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        for (name, mode) in [
            ("existing-file", 0o600),
            ("existing-setuid", 0o4750),
            ("existing-large", 0o604),
        ] {
            fs::write(target.join(name), b"old").unwrap();
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        let publication = if inplace {
            PublicationPolicy::InPlace
        } else {
            PublicationPolicy::AtomicStaged
        };
        let mut receiver = ParityReceiver::new(&root, restricted, preserve, publication);
        let path = |name: &str| path_bytes(&target.join(name));
        let meta = |mode| proto::Meta {
            mode,
            ..plain_meta()
        };
        // Directories, as the planner creates them: without -p a proposal of
        // the source's permission bits.
        let mkdir = |name: &str, mode: u32| Op::Mkdir {
            path: path(name),
            mode: if preserve { mode } else { mode & 0o777 },
            condition: proto::TargetCondition::Any,
        };
        #[allow(clippy::unnecessary_cast)] // macOS mode constants are narrower.
        let fifo = libc::S_IFIFO as u32;
        receiver.send(Request::Apply {
            ops: vec![
                mkdir("new-dir", 0o1755),
                mkdir("new-read-only-dir", 0o555),
                mkdir("setgid/child", 0o750),
                mkdir("existing-dir", 0o777),
                mkdir("private-dir", 0o700),
                Op::Mknod {
                    path: path("fifo"),
                    mode: fifo | 0o644,
                    rdev: 0,
                    condition: proto::TargetCondition::Any,
                    meta: Default::default(),
                    flags: 0,
                },
            ],
        });
        // A directory widened for writing, and one created private, take
        // their final modes at the end.
        let observed = fs::metadata(target.join("read-only-dir")).unwrap();
        let widened = receiver.send(Request::WidenDirectories {
            access: 0o300,
            remember: !preserve,
            directories: vec![(
                path("read-only-dir"),
                proto::TargetCondition::Matches {
                    dev: observed.dev(),
                    ino: observed.ino(),
                },
            )],
        });
        let proto::Response::WidenedDirectories(outcomes) = widened else {
            unreachable!()
        };
        let saved = outcomes[0].clone().unwrap();
        let restore_mode = saved.map_or(0o555, |saved| saved.mode);
        receiver.send(Request::Apply {
            ops: vec![
                Op::SetMeta {
                    path: path("read-only-dir"),
                    meta: meta(restore_mode),
                    flags: mode_flag,
                    condition: proto::TargetCondition::Matches {
                        dev: observed.dev(),
                        ino: observed.ino(),
                    },
                    directory: false,
                },
                Op::SetMeta {
                    path: path("private-dir"),
                    meta: meta(0o755),
                    flags: mode_flag,
                    condition: proto::TargetCondition::Any,
                    directory: false,
                },
                // A native receiver does not narrow a new directory to a
                // source without owner access; only `syq rsync` does.
                Op::SetMeta {
                    path: path("new-read-only-dir"),
                    meta: meta(0o555),
                    flags: mode_flag,
                    condition: proto::TargetCondition::Any,
                    directory: false,
                },
            ],
        });
        // Files published whole, as small ones are, unless written in place.
        if !inplace {
            let put = |name: &str, mode| proto::SmallPut {
                path: path(name),
                copy_id: [1; 16],
                data: b"new".to_vec(),
                hash: crate::fsops::content_digest(b"new"),
                meta: meta(mode),
                flags: mode_flag,
                inplace: false,
                condition: proto::TargetCondition::Any,
                replaces: false,
                scanned: crate::proto::ScannedDestination::Unknown,
            };
            receiver.send(Request::PutSmallBatch(vec![
                put("new-file", 0o755),
                put("existing-file", 0o644),
                put("existing-setuid", 0o755),
                put("setgid/new-file", 0o4640),
            ]));
        }
        // Files written by ranges into a sidecar, or in place.
        for (name, proposed) in [
            ("new-large", 0o640),
            ("new-read-only", 0o444),
            ("existing-large", 0o644),
        ] {
            let data = b"contents".to_vec();
            receiver.send(Request::Prepare {
                path: path(name),
                size: data.len() as u64,
                inplace,
                copy_id: [2; 16],
                mode: proposed,
                flags: mode_flag,
                acl: false,
                scanned: crate::proto::ScannedDestination::Unknown,
                attempt: 0,
                create_if_missing: true,
                group: None,
                update: None,
            });
            receiver.send(Request::WriteRange {
                path: path(name),
                inplace,
                copy_id: [2; 16],
                attempt: 0,
                off: 0,
                hash: crate::fsops::content_digest(&data),
                data: data.into(),
            });
            receiver.send(Request::Finalize {
                expected_hash: None,
                path: path(name),
                inplace,
                copy_id: [2; 16],
                meta: meta(proposed),
                flags: mode_flag,
                scanned: crate::proto::ScannedDestination::Unknown,
                condition: proto::TargetCondition::Any,
            });
        }
        let mut modes = Vec::new();
        for entry in walkdir_entries(&target) {
            let metadata = fs::symlink_metadata(&entry).unwrap();
            let name = entry.strip_prefix(&target).unwrap().display().to_string();
            modes.push((name, metadata.mode() & 0o7777));
        }
        modes.sort();
        modes
    })
}

/// Every entry beneath `directory`.
fn walkdir_entries(directory: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if fs::symlink_metadata(&path).unwrap().is_dir() {
            entries.extend(walkdir_entries(&path));
        }
        entries.push(path);
    }
    entries
}

#[test]
fn ordinary_and_restricted_receivers_choose_the_same_modes() {
    let umask = crate::fsops::process_umask();
    for preserve in [false, true] {
        for inplace in [false, true] {
            let case = format!("preserve={preserve} inplace={inplace}");
            let [ordinary, restricted] = parity_modes(preserve, inplace);
            assert_eq!(ordinary, restricted, "{case}");
            let mode = |name: &str| {
                ordinary
                    .iter()
                    .find(|(entry, _)| entry == name)
                    .unwrap_or_else(|| panic!("{case}: {name} missing"))
                    .1
            };
            if preserve {
                continue;
            }
            // Without -p, existing entries keep their modes, special bits
            // included, and new ones get the proposal's permission bits
            // through the receiver's umask, never its special bits.
            let created = |proposed: u32| proposed & 0o777 & !umask;
            assert_eq!(mode("existing-dir"), 0o750, "{case}");
            assert_eq!(mode("read-only-dir"), 0o555, "{case}");
            assert_eq!(mode("existing-large"), 0o604, "{case}");
            assert_eq!(mode("new-large"), created(0o640), "{case}");
            assert_eq!(mode("new-read-only"), created(0o444), "{case}");
            assert_eq!(mode("fifo"), created(0o644), "{case}");
            assert_eq!(mode("private-dir"), created(0o755), "{case}");
            // A new directory keeps owner access, as native cp has always
            // created it, and inherits a parent's setgid bit.
            assert_eq!(mode("new-dir"), created(0o755), "{case}");
            assert_eq!(mode("new-read-only-dir"), created(0o755), "{case}");
            let inherited_setgid = if cfg!(target_os = "linux") { 0o2000 } else { 0 };
            assert_eq!(
                mode("setgid/child"),
                created(0o750) | inherited_setgid,
                "{case}"
            );
            if !inplace {
                assert_eq!(mode("existing-file"), 0o600, "{case}");
                assert_eq!(mode("existing-setuid"), 0o4750, "{case}");
                assert_eq!(mode("new-file"), created(0o755), "{case}");
                assert_eq!(mode("setgid/new-file"), created(0o640), "{case}");
            }
        }
    }
}

#[test]
fn only_an_ordinary_receiver_takes_a_senders_word_for_what_a_file_replaces() {
    // A sender misreports files already there: as absent, or as files of
    // another mode. An ordinary receiver takes its word, sparing a lookup,
    // and gives them the mode creating them would give, or the reported
    // one; a command-restricted receiver looks and keeps their modes.
    let umask = crate::fsops::process_umask();
    let claims = [
        (proto::ScannedDestination::Absent, 0o755 & !umask),
        (proto::ScannedDestination::File(0o640), 0o640),
    ];
    for (scanned, ordinary_mode) in claims {
        for restricted in [false, true] {
            let temporary = crate::test_support::tempdir().unwrap();
            let root = temporary.path().join("root");
            let target = root.join("target");
            fs::create_dir_all(&target).unwrap();
            for name in ["small", "large"] {
                fs::write(target.join(name), b"old").unwrap();
                fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o600)).unwrap();
            }
            let mut receiver =
                ParityReceiver::new(&root, restricted, false, PublicationPolicy::AtomicStaged);
            let path = |name: &str| path_bytes(&target.join(name));
            let meta = proto::Meta {
                mode: 0o755,
                ..plain_meta()
            };
            receiver.send(Request::PutSmallBatch(vec![proto::SmallPut {
                path: path("small"),
                copy_id: [1; 16],
                data: b"new".to_vec(),
                hash: crate::fsops::content_digest(b"new"),
                meta: meta.clone(),
                flags: proto::flags::RECEIVER_MODE,
                inplace: false,
                condition: proto::TargetCondition::Any,
                replaces: false,
                scanned,
            }]));
            let data = b"contents".to_vec();
            receiver.send(Request::Prepare {
                path: path("large"),
                size: data.len() as u64,
                inplace: false,
                copy_id: [2; 16],
                mode: 0o755,
                flags: proto::flags::RECEIVER_MODE,
                acl: false,
                scanned,
                attempt: 0,
                create_if_missing: true,
                group: None,
                update: None,
            });
            receiver.send(Request::WriteRange {
                path: path("large"),
                inplace: false,
                copy_id: [2; 16],
                attempt: 0,
                off: 0,
                hash: crate::fsops::content_digest(&data),
                data: data.into(),
            });
            receiver.send(Request::Finalize {
                expected_hash: None,
                path: path("large"),
                inplace: false,
                copy_id: [2; 16],
                meta: meta.clone(),
                flags: proto::flags::RECEIVER_MODE,
                scanned,
                condition: proto::TargetCondition::Any,
            });
            let expected = if restricted { 0o600 } else { ordinary_mode };
            for name in ["small", "large"] {
                let mode = fs::metadata(target.join(name)).unwrap().mode() & 0o7777;
                assert_eq!(mode, expected, "{scanned:?} restricted={restricted} {name}");
            }
        }
    }
}

/// Ordinary and command-restricted receivers write only files they created,
/// alike: neither changes a linked file's metadata in place, both answer
/// that it must be replaced; an in-place request for an existing file
/// writes a stage that replaces it; and a symlink whose metadata changes is
/// created again.
#[test]
fn both_receivers_write_only_files_they_created() {
    use proto::TargetCondition::{Any, Matches};
    for restricted in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("linked"), b"same").unwrap();
        fs::hard_link(target.join("linked"), root.join("outside")).unwrap();
        fs::set_permissions(target.join("linked"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(target.join("existing"), b"old contents").unwrap();
        fs::hard_link(target.join("existing"), root.join("existing-outside")).unwrap();
        std::os::unix::fs::symlink("elsewhere", target.join("link")).unwrap();
        let mut receiver =
            ParityReceiver::new(&root, restricted, true, PublicationPolicy::InPlaceNew);
        if let Some(authority) = receiver.authority.as_mut() {
            authority.copy.options.preserve_times = true;
        }
        let case = format!("restricted={restricted}");

        // A metadata-only change to a file with another name.
        let linked = fs::metadata(target.join("linked")).unwrap();
        let mut request = Request::Apply {
            ops: vec![Op::SetFileMetaIfSame {
                path: path_bytes(&target.join("linked")),
                condition: Matches {
                    dev: linked.dev(),
                    ino: linked.ino(),
                },
                meta: proto::Meta {
                    mode: 0o600,
                    ..plain_meta()
                },
                flags: proto::flags::MODE,
            }],
        };
        let response = match &receiver.authority {
            Some(authority) => {
                let settlement = authority.authorize(&mut request, false).unwrap();
                let response = receiver.ops.handle(&request);
                authority.settle(settlement, &response);
                response
            }
            None => receiver.ops.handle(&request),
        };
        assert!(
            matches!(
                &response,
                proto::Response::Applied(errors)
                    if matches!(errors.as_slice(), [Some(error)]
                        if crate::fsops::vouch::is_replace_required_wire(error))
            ),
            "{case}: {response:?}"
        );
        assert_eq!(
            fs::metadata(root.join("outside")).unwrap().mode() & 0o7777,
            0o644,
            "{case}"
        );

        // An in-place request for an existing file.
        let path = path_bytes(&target.join("existing"));
        let data = b"new contents".to_vec();
        receiver.send(Request::Prepare {
            path: path.clone(),
            size: data.len() as u64,
            inplace: true,
            copy_id: [5; 16],
            mode: 0o644,
            flags: proto::flags::MODE,
            acl: false,
            scanned: proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
        });
        receiver.send(Request::WriteRange {
            path: path.clone(),
            inplace: true,
            copy_id: [5; 16],
            attempt: 0,
            off: 0,
            hash: crate::fsops::content_digest(&data),
            data: data.clone().into(),
        });
        assert_eq!(fs::read(target.join("existing")).unwrap(), b"old contents");
        receiver.send(Request::Finalize {
            expected_hash: None,
            path,
            inplace: true,
            copy_id: [5; 16],
            meta: proto::Meta {
                mode: 0o644,
                ..plain_meta()
            },
            flags: proto::flags::MODE,
            scanned: proto::ScannedDestination::Unknown,
            condition: Any,
        });
        assert_eq!(fs::read(target.join("existing")).unwrap(), data, "{case}");
        assert_eq!(
            fs::read(root.join("existing-outside")).unwrap(),
            b"old contents",
            "{case}"
        );

        // A symlink whose time changes is created again with it.
        let before = fs::symlink_metadata(target.join("link")).unwrap();
        receiver.send(Request::Apply {
            ops: vec![Op::Symlink {
                path: path_bytes(&target.join("link")),
                target: b"elsewhere".to_vec(),
                condition: Matches {
                    dev: before.dev(),
                    ino: before.ino(),
                },
                meta: proto::Meta {
                    mtime: 1_600_000_000,
                    ..plain_meta()
                },
                flags: proto::flags::TIMES,
            }],
        });
        let after = fs::symlink_metadata(target.join("link")).unwrap();
        assert_ne!(after.ino(), before.ino(), "{case}");
        assert_eq!(after.mtime(), 1_600_000_000, "{case}");
    }
}

/// Under `--in-place=update`, ordinary and command-restricted receivers
/// alike write a file of their own with one name where it is, and refuse to
/// write one with another name in place, so that the sender replaces it,
/// which it then does through a stage. The restricted receiver's receipt
/// records the replacement, and nothing of the refused preparation.
#[test]
fn both_receivers_update_in_place_only_files_they_vouch_for() {
    for restricted in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        for name in ["mine", "linked"] {
            fs::write(target.join(name), b"old contents").unwrap();
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        fs::hard_link(target.join("linked"), root.join("outside")).unwrap();
        let key = generate_results_key(EnrollmentId::random()).unwrap();
        let (secret, policy) = results_policy();
        let mut receiver =
            ParityReceiver::new(&root, restricted, true, PublicationPolicy::InPlaceUpdate);
        let mut reader = None;
        if restricted {
            let mut authority = test_authority_with_results(
                &root,
                DeletionPolicy::Forbid,
                1 << 20,
                0,
                FilterPolicy::default(),
                PublicationPolicy::InPlaceUpdate,
                ExistingDestinationPolicy::Replace,
                DestinationPlacement::ExactPath,
                RootExistence::Any,
                Some((key, policy)),
            )
            .unwrap();
            authority.copy.options.preserve_permissions = true;
            authority.copy.options.preserve_times = true;
            authority.copy.limits.max_entries = 1000;
            reader = Some(start_results(&authority, secret));
            receiver.authority = Some(authority);
        }
        let case = format!("restricted={restricted}");
        let meta = proto::Meta {
            mode: 0o644,
            mtime: 1_600_000_000,
            ..plain_meta()
        };
        let flags = proto::flags::MODE | proto::flags::TIMES;
        let data = b"new contents".to_vec();
        let path = |name: &str| path_bytes(&target.join(name));
        let prepare = |name: &str, update: bool| Request::Prepare {
            path: path(name),
            size: data.len() as u64,
            inplace: update,
            copy_id: [8; 16],
            mode: 0o644,
            flags,
            acl: false,
            scanned: proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: update.then(|| {
                Box::new(proto::InPlaceUpdate {
                    meta: meta.clone(),
                    flags,
                    only: None,
                })
            }),
        };
        let write = |name: &str, inplace: bool| Request::WriteRange {
            path: path(name),
            inplace,
            copy_id: [8; 16],
            attempt: 0,
            off: 0,
            hash: crate::fsops::content_digest(&data),
            data: data.clone().into(),
        };
        let finalize = |name: &str, inplace: bool| Request::Finalize {
            expected_hash: None,
            path: path(name),
            inplace,
            copy_id: [8; 16],
            meta: meta.clone(),
            flags,
            scanned: proto::ScannedDestination::Unknown,
            condition: proto::TargetCondition::Any,
        };

        let mine = fs::metadata(target.join("mine")).unwrap().ino();
        receiver.send(prepare("mine", true));
        receiver.send(write("mine", true));
        receiver.send(finalize("mine", true));
        let status = fs::metadata(target.join("mine")).unwrap();
        assert_eq!(fs::read(target.join("mine")).unwrap(), data, "{case}");
        assert_eq!(
            (status.ino(), status.mtime()),
            (mine, 1_600_000_000),
            "{case}"
        );

        let mut request = prepare("linked", true);
        let response = match &receiver.authority {
            Some(authority) => {
                let settlement = authority.authorize(&mut request, false).unwrap();
                let response = receiver.ops.handle(&request);
                authority.settle(settlement, &response);
                response
            }
            None => receiver.ops.handle(&request),
        };
        let proto::Response::EndpointError(error) = &response else {
            panic!("{case}: {response:?}");
        };
        assert_eq!(
            crate::fsops::vouch::replace_reason_wire(error),
            Some(proto::ReplaceReason::OtherNames),
            "{case}: {error:?}"
        );
        assert_eq!(
            fs::read(target.join("linked")).unwrap(),
            b"old contents",
            "{case}"
        );
        receiver.send(prepare("linked", false));
        receiver.send(write("linked", false));
        receiver.send(finalize("linked", false));
        assert_eq!(fs::read(target.join("linked")).unwrap(), data, "{case}");
        assert_eq!(
            fs::read(root.join("outside")).unwrap(),
            b"old contents",
            "{case}"
        );

        // The receiver's results report both files published, and nothing
        // of the refused preparation.
        if let (Some(authority), Some(reader)) = (&receiver.authority, reader.as_mut()) {
            let results = finish_results(authority, reader);
            let mut changes = results.changes();
            changes.sort();
            assert_eq!(
                changes,
                [
                    (
                        "transfer_file".to_owned(),
                        b"linked".to_vec(),
                        "succeeded".to_owned()
                    ),
                    (
                        "transfer_file".to_owned(),
                        b"mine".to_vec(),
                        "succeeded".to_owned()
                    ),
                ],
                "{case}: {:?}",
                results.records
            );
        }
    }
}

/// Under `--in-place=update`, ordinary and command-restricted receivers
/// settle each file of a patch batch alike: a file of their own is updated
/// in place, with only its new block written; one with another name is
/// replaced through a stage, and the reason returned; an unchanged one is
/// kept; and one changed since its comparison, in a block the patch
/// reuses, fails with nothing written. The rest of the batch is done
/// either way, and the restricted receiver's results list each.
#[test]
fn both_receivers_settle_each_file_of_an_in_place_batch_alike() {
    let block = proto::MIN_HASH_BLOCK_BYTES as usize;
    let old: Vec<u8> = (0..3 * block).map(|index| (index % 251) as u8).collect();
    let mut new = old.clone();
    new[block + 5] ^= 1;
    let names = ["mine", "linked", "unchanged", "changed"];
    for restricted in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        for name in names {
            fs::write(target.join(name), &old).unwrap();
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        fs::hard_link(target.join("linked"), root.join("outside")).unwrap();
        let inodes: Vec<u64> = names
            .iter()
            .map(|name| fs::metadata(target.join(name)).unwrap().ino())
            .collect();
        let key = generate_results_key(EnrollmentId::random()).unwrap();
        let (secret, policy) = results_policy();
        let mut receiver =
            ParityReceiver::new(&root, restricted, true, PublicationPolicy::InPlaceUpdate);
        let mut reader = None;
        if restricted {
            let mut authority = test_authority_with_results(
                &root,
                DeletionPolicy::Forbid,
                4 << 20,
                0,
                FilterPolicy::default(),
                PublicationPolicy::InPlaceUpdate,
                ExistingDestinationPolicy::Replace,
                DestinationPlacement::ExactPath,
                RootExistence::Any,
                Some((key, policy)),
            )
            .unwrap();
            authority.copy.options.preserve_permissions = true;
            authority.copy.options.preserve_times = true;
            authority.copy.limits.max_entries = 1000;
            reader = Some(start_results(&authority, secret));
            receiver.authority = Some(authority);
        }
        let case = format!("restricted={restricted}");
        let proto::Response::ExistingHashes(hashed) = receiver.send(Request::HashExistingBatch {
            block: block as u64,
            files: names
                .iter()
                .map(|name| existing_read(&target.join(name), new.len() as u64))
                .collect(),
        }) else {
            panic!("{case}: unexpected hash response");
        };
        // After its comparison, "changed" changes in a block the patch
        // reuses, and grows, so that its fingerprint shows the change
        // however coarse its change time.
        let planted = [&old[..10], b"planted", &old[17..], b"!"].concat();
        fs::write(target.join("changed"), &planted).unwrap();
        let flags = proto::flags::MODE | proto::flags::TIMES;
        let patches = names
            .iter()
            .zip(hashed)
            .map(|(name, hashed)| {
                let hashed = hashed.unwrap();
                let (reuse, data) = if *name == "unchanged" {
                    (hashed.hashes.iter().copied().map(Some).collect(), &[][..])
                } else {
                    (
                        vec![Some(hashed.hashes[0]), None, Some(hashed.hashes[2])],
                        &new[block..2 * block],
                    )
                };
                let mut patch = small_patch(
                    &target.join(name),
                    new.len() as u64,
                    block as u64,
                    reuse,
                    data,
                );
                patch.basis = hashed.fingerprint;
                patch.meta.mtime = 1_600_000_000;
                patch.flags = flags;
                patch.unchanged_flags = flags;
                patch.update_in_place = true;
                patch
            })
            .collect();
        let proto::Response::PatchedBatch(patched) =
            receiver.send(Request::PatchSmallBatch(patches))
        else {
            panic!("{case}: unexpected patch response");
        };
        let settled = |replaced, kept| {
            Ok(proto::SmallPatched {
                kept,
                identity: None,
                replaced,
            })
        };
        assert_eq!(
            patched[..3],
            [
                settled(None, false),
                settled(Some(proto::ReplaceReason::OtherNames), false),
                settled(None, true),
            ],
            "{case}"
        );
        let Err(failed) = &patched[3] else {
            panic!("{case}: {:?}", patched[3]);
        };
        assert!(
            !failed.written && !failed.matched && !failed.stale_condition,
            "{case}: {failed:?}"
        );
        for ((name, before), contents) in
            names.iter().zip(&inodes).zip([&new, &new, &old, &planted])
        {
            let status = fs::metadata(target.join(name)).unwrap();
            assert!(
                fs::read(target.join(name)).unwrap() == *contents,
                "{case}: {name}"
            );
            assert_eq!(status.ino() == *before, *name != "linked", "{case}: {name}");
            if *name != "changed" {
                assert_eq!(status.mtime(), 1_600_000_000, "{case}: {name}");
            }
        }
        assert!(fs::read(root.join("outside")).unwrap() == old, "{case}");

        if let (Some(authority), Some(reader)) = (&receiver.authority, reader.as_mut()) {
            let results = finish_results(authority, reader);
            // One whose patch failed with nothing written is held for the
            // sender to copy again; as no copy follows, it is listed failed.
            for (name, disposition) in [
                ("mine", "succeeded"),
                ("linked", "succeeded"),
                ("changed", "failed"),
            ] {
                assert!(
                    results.has("transfer_file", name.as_bytes(), disposition),
                    "{case}: {name}: {:?}",
                    results.records
                );
            }
            assert!(
                !results
                    .changes()
                    .iter()
                    .any(|(action, path, _)| action == "transfer_file" && path == b"unchanged"),
                "{case}: {:?}",
                results.records
            );
        }
    }
}

/// Only a grant for `--in-place=update` lets a receiver update an existing
/// file in place, and only with metadata the grant allows.
#[test]
fn in_place_updates_need_a_grant_for_them() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("existing"), b"old").unwrap();
    let prepare = |flags| Request::Prepare {
        path: path_bytes(&target.join("existing")),
        size: 3,
        inplace: true,
        copy_id: [9; 16],
        mode: 0o644,
        flags: proto::flags::RECEIVER_MODE,
        acl: false,
        scanned: proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: Some(Box::new(proto::InPlaceUpdate {
            meta: plain_meta(),
            flags,
            only: None,
        })),
    };
    for (publication, allowed) in [
        (PublicationPolicy::AtomicStaged, false),
        (PublicationPolicy::InPlace, false),
        (PublicationPolicy::InPlaceNew, false),
        (PublicationPolicy::InPlaceUpdate, true),
    ] {
        let authority = test_authority_with_policy(
            &root,
            DeletionPolicy::Forbid,
            1 << 20,
            0,
            FilterPolicy::default(),
            publication,
        );
        let result = authority.authorize(&mut prepare(proto::flags::RECEIVER_MODE), false);
        assert_eq!(result.is_ok(), allowed, "{publication:?}");
        if let Err(error) = result {
            assert!(
                error.to_string().contains("signed publication policy"),
                "{publication:?}: {error:#}"
            );
        }
        if allowed {
            let error = authority
                .authorize(&mut prepare(proto::flags::OWNER), false)
                .unwrap_err();
            assert!(error.to_string().contains("ownership"), "{error:#}");
        }
        // So too for a batch's patch, and never for a streamed one.
        let mut patch = small_patch(
            &target.join("existing"),
            3,
            proto::MIN_HASH_BLOCK_BYTES,
            vec![None],
            b"new",
        );
        patch.flags = proto::flags::RECEIVER_MODE;
        patch.unchanged_flags = patch.flags;
        patch.update_in_place = true;
        let result = authority.authorize(&mut Request::PatchSmallBatch(vec![patch.clone()]), false);
        assert_eq!(result.is_ok(), allowed, "{publication:?}");
        if let Err(error) = result {
            assert!(
                error.to_string().contains("signed publication policy"),
                "{publication:?}: {error:#}"
            );
        }
        patch.data.clear();
        let error = authority
            .authorize(
                &mut Request::PatchBegin {
                    patch: Box::new(patch),
                    data_len: 3,
                },
                false,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("not written in place"),
            "{publication:?}: {error:#}"
        );
    }
}

/// Both receivers put a new small file in place at its name, the restricted
/// one under its guard, and replace an existing one through a stage.
#[test]
fn both_receivers_put_small_files_in_place_only_when_new() {
    for restricted in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("existing"), b"old").unwrap();
        fs::hard_link(target.join("existing"), root.join("outside")).unwrap();
        let mut receiver =
            ParityReceiver::new(&root, restricted, true, PublicationPolicy::InPlaceNew);
        let put = |name: &str| {
            let Request::PutSmallBatch(mut puts) = small_put(&target.join(name)) else {
                unreachable!()
            };
            puts[0].inplace = true;
            puts[0].meta.mode = 0o644;
            puts[0].flags = proto::flags::MODE;
            puts.remove(0)
        };
        receiver.send(Request::PutSmallBatch(vec![put("new"), put("existing")]));
        let case = format!("restricted={restricted}");
        assert_eq!(fs::read(target.join("new")).unwrap(), b"new", "{case}");
        assert_eq!(fs::read(target.join("existing")).unwrap(), b"new", "{case}");
        assert_eq!(fs::read(root.join("outside")).unwrap(), b"old", "{case}");
    }
}

/// In place, the receiver creates a file whose name is free, and a name can
/// become free after any check: a grant that does not let the copy both
/// replace and create refuses in-place work, here one that changes only
/// existing files.
#[test]
fn in_place_work_needs_a_grant_that_replaces_and_creates() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("existing"), b"old").unwrap();
    let authority = test_authority_with_existence(
        &root,
        DeletionPolicy::Forbid,
        1 << 20,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlaceNew,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::ExactPath,
        RootExistence::Any,
    )
    .unwrap();
    let path = path_bytes(&target.join("existing"));
    let mut prepare = Request::Prepare {
        path: path.clone(),
        size: 3,
        inplace: true,
        copy_id: [6; 16],
        mode: 0o644,
        flags: 0,
        acl: false,
        scanned: proto::ScannedDestination::Unknown,
        attempt: 0,
        create_if_missing: true,
        group: None,
        update: None,
    };
    let error = authority.authorize(&mut prepare, false).unwrap_err();
    assert!(
        error.to_string().contains("not written in place"),
        "{error:#}"
    );
    let Request::PutSmallBatch(mut puts) = small_put(&target.join("existing")) else {
        unreachable!()
    };
    puts[0].inplace = true;
    let error = authority
        .authorize(&mut Request::PutSmallBatch(puts), false)
        .unwrap_err();
    assert!(
        error.to_string().contains("not written in place"),
        "{error:#}"
    );
}

#[test]
fn both_receivers_restore_set_id_bits_after_writing_in_place() {
    // Writes clear an existing file's set-ID bits. Without word from the
    // sender, each receiver restores the mode it found the file with.
    for restricted in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("program"), b"old program").unwrap();
        fs::set_permissions(target.join("program"), fs::Permissions::from_mode(0o4755)).unwrap();
        let mut receiver =
            ParityReceiver::new(&root, restricted, false, PublicationPolicy::InPlace);
        let path = path_bytes(&target.join("program"));
        let data = b"new program".to_vec();
        receiver.send(Request::Prepare {
            path: path.clone(),
            size: data.len() as u64,
            inplace: true,
            copy_id: [3; 16],
            mode: 0o755,
            flags: proto::flags::RECEIVER_MODE,
            acl: false,
            scanned: proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
        });
        receiver.send(Request::WriteRange {
            path: path.clone(),
            inplace: true,
            copy_id: [3; 16],
            attempt: 0,
            off: 0,
            hash: crate::fsops::content_digest(&data),
            data: data.clone().into(),
        });
        receiver.send(Request::Finalize {
            expected_hash: None,
            path,
            inplace: true,
            copy_id: [3; 16],
            meta: proto::Meta {
                mode: 0o755,
                ..plain_meta()
            },
            flags: proto::flags::RECEIVER_MODE,
            scanned: proto::ScannedDestination::Unknown,
            condition: proto::TargetCondition::Any,
        });
        assert_eq!(fs::read(target.join("program")).unwrap(), data);
        let mode = fs::metadata(target.join("program")).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o4755, "restricted={restricted}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn both_receivers_limit_a_new_in_place_file_by_a_narrower_default_acl() {
    use std::os::unix::ffi::OsStrExt;
    // The directory's default ACL grants only the owner. A new file gets the
    // proposal limited by it, as creating the file would, whether or not the
    // receiver takes its sender's word that the file is new.
    for restricted in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        // version 2; USER_OBJ rwx, GROUP_OBJ and OTHER nothing.
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permissions) in [(1u16, 7u16), (4, 0), (32, 0)] {
            acl.extend(tag.to_le_bytes());
            acl.extend(permissions.to_le_bytes());
            acl.extend(u32::MAX.to_le_bytes());
        }
        let directory = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        if unsafe {
            libc::setxattr(
                directory.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        } != 0
        {
            eprintln!(
                "skipped: this filesystem rejected a default ACL: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let mut receiver =
            ParityReceiver::new(&root, restricted, false, PublicationPolicy::InPlace);
        let path = path_bytes(&target.join("new"));
        let data = b"new contents".to_vec();
        let scanned = proto::ScannedDestination::Absent;
        receiver.send(Request::Prepare {
            path: path.clone(),
            size: data.len() as u64,
            inplace: true,
            copy_id: [4; 16],
            mode: 0o644,
            flags: proto::flags::RECEIVER_MODE,
            acl: false,
            scanned,
            attempt: 0,
            create_if_missing: true,
            group: None,
            update: None,
        });
        receiver.send(Request::WriteRange {
            path: path.clone(),
            inplace: true,
            copy_id: [4; 16],
            attempt: 0,
            off: 0,
            hash: crate::fsops::content_digest(&data),
            data: data.clone().into(),
        });
        receiver.send(Request::Finalize {
            expected_hash: None,
            path,
            inplace: true,
            copy_id: [4; 16],
            meta: proto::Meta {
                mode: 0o644,
                ..plain_meta()
            },
            flags: proto::flags::RECEIVER_MODE,
            scanned,
            condition: proto::TargetCondition::Any,
        });
        assert_eq!(fs::read(target.join("new")).unwrap(), data);
        let mode = fs::metadata(target.join("new")).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o600, "restricted={restricted}");
    }
}

/// A group this process belongs to other than its own, if any.
fn supplementary_group() -> Option<u32> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0; count.max(0) as usize];
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    groups.truncate(count.max(0) as usize);
    let own = unsafe { libc::getegid() };
    groups.into_iter().find(|&group| group != own)
}

#[test]
fn ordinary_and_restricted_receivers_give_directories_their_groups_first() {
    let Some(group) = supplementary_group() else {
        eprintln!("skipping: this process has no supplementary group");
        return;
    };
    let umask = crate::fsops::process_umask();
    let [ordinary, restricted] = [false, true].map(|restricted| {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(target.join("existing-dir")).unwrap();
        fs::set_permissions(
            target.join("existing-dir"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        let mut receiver =
            ParityReceiver::new(&root, restricted, false, PublicationPolicy::AtomicStaged);
        if let Some(authority) = receiver.authority.as_mut() {
            authority.copy.options.preserve_group = true;
        }
        let path = |name: &str| path_bytes(&target.join(name));
        let grouped = proto::Meta {
            mode: 0,
            gid: group,
            ..plain_meta()
        };
        let flags = proto::flags::GROUP | proto::flags::REQUIRE_GROUP;
        // As the planner sends them before filling either directory: an
        // existing one changes group first, and a new one takes its group in
        // the request that creates it.
        let existing = fs::metadata(target.join("existing-dir")).unwrap();
        receiver.send(Request::Apply {
            ops: vec![Op::SetMeta {
                path: path("existing-dir"),
                meta: grouped.clone(),
                flags,
                condition: proto::TargetCondition::Matches {
                    dev: existing.dev(),
                    ino: existing.ino(),
                },
                directory: false,
            }],
        });
        receiver.send(Request::Apply {
            ops: vec![
                Op::Mkdir {
                    path: path("new-dir"),
                    mode: 0o755,
                    condition: proto::TargetCondition::Any,
                },
                Op::SetMeta {
                    path: path("new-dir"),
                    meta: grouped.clone(),
                    flags,
                    condition: proto::TargetCondition::Any,
                    directory: false,
                },
            ],
        });
        ["existing-dir", "new-dir"].map(|name| {
            let metadata = fs::metadata(target.join(name)).unwrap();
            (metadata.mode() & 0o7777, metadata.gid())
        })
    });
    assert_eq!(ordinary, restricted);
    assert_eq!(ordinary, [(0o750, group), (0o755 & !umask, group)]);
}

/// Authorize `request` and carry it out as the restricted receiver does,
/// with the authority's record of the files it created.
fn execute(authority: &RestrictedAuthority, mut request: Request) -> Result<proto::Response> {
    let settlement = authority.authorize(&mut request, false)?;
    let mut ops = authority.test_ops();
    ops.set_owned_objects(authority.owned_objects());
    let response = ops.handle(&request);
    authority.settle(settlement, &response);
    Ok(response)
}

/// The result of each operation of an executed `Apply`.
fn applied(response: &proto::Response) -> &[Option<crate::proto::WireError>] {
    let proto::Response::Applied(results) = response else {
        panic!("{response:?}")
    };
    results
}

/// Whether every operation of an executed `Apply` succeeded.
fn all_applied(response: &proto::Response) -> bool {
    applied(response).iter().all(Option::is_none)
}

/// Whether `result` is the refusal of a hard link to a file this copy did
/// not create.
fn refused_link(result: &Option<crate::proto::WireError>) -> bool {
    result
        .as_ref()
        .is_some_and(|error| error.as_str().contains("a file this copy did not create"))
}

/// A grant under `existing` that copies hard links and permissions and may
/// delete, over a directory holding `kept`, a file that existed before the
/// copy with mode 0600.
fn link_authority(root: &Path, existing: ExistingDestinationPolicy) -> RestrictedAuthority {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("target/kept"), b"kept").unwrap();
    fs::set_permissions(root.join("target/kept"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut authority = test_authority_with_existence(
        root,
        DeletionPolicy::DeleteDestinationOnly,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        existing,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    authority.extra_options.hardlinks = true;
    authority.copy.options.preserve_permissions = true;
    authority.copy.options.receiver_managed_modes = false;
    authority.copy.limits.max_deletions = 10;
    authority
}

fn keeping_link_authority(root: &Path) -> RestrictedAuthority {
    link_authority(root, ExistingDestinationPolicy::Skip)
}

/// A hard link at `name` to the file at `source`, both in the target.
fn link_to(root: &Path, name: &str, source: &str) -> Op {
    use std::os::unix::fs::MetadataExt;
    let file = fs::metadata(root.join("target").join(source)).unwrap();
    Op::Hardlink {
        path: path_bytes(&root.join("target").join(name)),
        source: path_bytes(&root.join("target").join(source)),
        dev: file.dev(),
        ino: file.ino(),
        condition: proto::TargetCondition::Any,
    }
}

fn link_to_kept(root: &Path, name: &str) -> Op {
    link_to(root, name, "kept")
}

fn make_world_writable(root: &Path, name: &str) -> Op {
    Op::SetMeta {
        path: path_bytes(&root.join("target").join(name)),
        meta: proto::Meta {
            mode: 0o100666,
            ..plain_meta()
        },
        flags: proto::flags::MODE,
        condition: proto::TargetCondition::Any,
        directory: false,
    }
}

/// The kept file's mode and link count.
fn kept_state(root: &Path) -> (u32, u64) {
    use std::os::unix::fs::MetadataExt;
    let kept = fs::metadata(root.join("target/kept")).unwrap();
    (kept.mode() & 0o7777, kept.nlink())
}

/// A symlink at `name` that the grant creates.
fn create_symlink(authority: &RestrictedAuthority, root: &Path, name: &str) {
    let response = execute(
        authority,
        apply(Op::Symlink {
            path: path_bytes(&root.join("target").join(name)),
            target: b"kept".to_vec(),
            condition: proto::TargetCondition::Absent,
            meta: Default::default(),
            flags: 0,
        }),
    )
    .unwrap();
    assert!(all_applied(&response), "{response:?}");
}

/// Keeping existing files, a hard link gives a new name only to a file the
/// copy created: one to an existing file is refused as it is made, while a
/// group's new names can share a file the copy wrote.
#[test]
fn keeping_existing_files_links_only_to_files_the_copy_created() {
    use std::os::unix::fs::MetadataExt;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let authority = keeping_link_authority(&root);
    let response = execute(&authority, apply(link_to_kept(&root, "new"))).unwrap();
    assert!(refused_link(&applied(&response)[0]), "{response:?}");
    assert!(fs::symlink_metadata(root.join("target/new")).is_err());
    assert_eq!(kept_state(&root), (0o600, 1));

    let mine = root.join("target/mine");
    let mut ops = authority.test_ops();
    ops.set_owned_objects(authority.owned_objects());
    let mut put = small_put(&mine);
    let settlement = authority.authorize(&mut put, false).unwrap();
    let response = ops.handle(&put);
    authority.settle(settlement, &response);
    assert_eq!(fs::read(&mine).unwrap(), b"new", "{response:?}");
    let response = execute(&authority, apply(link_to(&root, "also", "mine"))).unwrap();
    assert!(all_applied(&response), "{response:?}");
    assert_eq!(
        fs::metadata(root.join("target/also")).unwrap().ino(),
        fs::metadata(&mine).unwrap().ino()
    );
}

/// Where inode numbers cannot tie a name to a file (SSHFS, rclone, unknown
/// filesystems), a grant that keeps existing files cannot check which file
/// a hard link names, so it refuses the link: a sender could supply a
/// created file's identity while naming an existing file.
#[test]
fn keeping_existing_files_refuses_links_it_cannot_tie_to_a_created_file() {
    use std::os::unix::fs::MetadataExt;
    let _untrusted = crate::fsops::override_profiles_for_test(|_, profile| crate::fsops::Profile {
        link_counts_trusted: false,
        ..profile
    });
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let authority = keeping_link_authority(&root);
    let mine = root.join("target/mine");
    let mut ops = authority.test_ops();
    ops.set_owned_objects(authority.owned_objects());
    let mut put = small_put(&mine);
    let settlement = authority.authorize(&mut put, false).unwrap();
    let response = ops.handle(&put);
    authority.settle(settlement, &response);
    assert_eq!(fs::read(&mine).unwrap(), b"new", "{response:?}");

    // The created file's identity, but the existing file's name.
    let created = fs::metadata(&mine).unwrap();
    let Op::Hardlink { path, source, .. } = link_to_kept(&root, "stolen") else {
        unreachable!()
    };
    let response = execute(
        &authority,
        apply(Op::Hardlink {
            path,
            source,
            dev: created.dev(),
            ino: created.ino(),
            condition: proto::TargetCondition::Any,
        }),
    )
    .unwrap();
    // Refused because the link cannot be tied to the file, not because a
    // trusted inode number showed another file.
    assert!(
        applied(&response)[0]
            .as_ref()
            .is_some_and(|error| error.as_str().contains("cannot be tied")),
        "{response:?}"
    );
    assert!(fs::symlink_metadata(root.join("target/stolen")).is_err());
    assert_eq!(kept_state(&root), (0o600, 1));
}

/// Only a grant that keeps existing files and copies hard links records the
/// files it creates: the record serves only to check links.
#[test]
fn only_keeping_grants_with_hard_links_record_created_files() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let mut keep = keeping_link_authority(&root);
    assert!(keep.owned_objects().is_some());
    keep.extra_options.hardlinks = false;
    assert!(keep.owned_objects().is_none());
    let mut replace = link_authority(&root, ExistingDestinationPolicy::Replace);
    assert!(replace.owned_objects().is_none());
    replace.extra_options.hardlinks = false;
    assert!(replace.owned_objects().is_none());
}

/// A link onto an existing file is an ordinary copy's step under a grant
/// that may replace existing files, and refused only under one that keeps
/// them.
#[test]
fn a_link_to_an_existing_file_is_refused_only_when_keeping_existing_files() {
    use std::os::unix::fs::MetadataExt;
    for existing in [
        ExistingDestinationPolicy::Skip,
        ExistingDestinationPolicy::Replace,
    ] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let authority = link_authority(&root, existing);
        let response = execute(&authority, apply(link_to_kept(&root, "new"))).unwrap();
        if existing == ExistingDestinationPolicy::Skip {
            assert!(refused_link(&applied(&response)[0]), "{response:?}");
            assert_eq!(kept_state(&root), (0o600, 1));
        } else {
            assert!(all_applied(&response), "{response:?}");
            assert_eq!(kept_state(&root), (0o600, 2));
            assert_eq!(
                fs::metadata(root.join("target/new")).unwrap().ino(),
                fs::metadata(root.join("target/kept")).unwrap().ino()
            );
        }
    }
}

/// Keeping existing files, a request on one connection approved to change a
/// name this grant created cannot be turned onto an existing file by another
/// connection linking the name to it, whether or not it deletes the name
/// first: the link is refused.
#[test]
fn another_connections_relink_does_not_redirect_an_approved_change() {
    for delete_first in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        let authority = keeping_link_authority(&root);
        create_symlink(&authority, &root, "mine");
        // Connection 2 is approved to change `mine` and has not run.
        let mut change = apply(make_world_writable(&root, "mine"));
        let pending = authority.authorize(&mut change, false).unwrap();
        // Connection 1 links `mine` to the kept file, deleting it first.
        if delete_first {
            let unlink = Op::Unlink {
                path: path_bytes(&root.join("target/mine")),
            };
            assert!(all_applied(&execute(&authority, apply(unlink)).unwrap()));
        }
        let response = execute(&authority, apply(link_to_kept(&root, "mine"))).unwrap();
        assert!(refused_link(&applied(&response)[0]), "{response:?}");
        // Connection 2's change then runs.
        let mut ops = authority.test_ops();
        ops.set_owned_objects(authority.owned_objects());
        let response = ops.handle(&change);
        authority.settle(pending, &response);
        assert_eq!(kept_state(&root), (0o600, 1), "delete_first={delete_first}");
    }
}

/// Keeping existing files, one request that creates a name, changes it, and
/// deletes and links it to an existing file does not change that file,
/// although the executor makes the link before the change: the link is
/// refused.
#[test]
fn a_relink_in_the_same_request_does_not_redirect_its_change() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let authority = keeping_link_authority(&root);
    let mine = path_bytes(&root.join("target/mine"));
    let response = execute(
        &authority,
        Request::Apply {
            ops: vec![
                Op::Symlink {
                    path: mine.clone(),
                    target: b"kept".to_vec(),
                    condition: proto::TargetCondition::Absent,
                    meta: Default::default(),
                    flags: 0,
                },
                make_world_writable(&root, "mine"),
                Op::Unlink { path: mine },
                link_to_kept(&root, "mine"),
            ],
        },
    )
    .unwrap();
    assert!(refused_link(&applied(&response)[3]), "{response:?}");
    assert_eq!(kept_state(&root), (0o600, 1));
}

/// Keeping existing files, no content reaches an existing file: a staged
/// file is published without replacing anything, even when the file
/// appears after the publication was approved.
#[test]
fn kept_files_take_no_content() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let authority = keeping_link_authority(&root);
    let late = root.join("target/late");
    let mut ops = authority.test_ops();
    ops.set_owned_objects(authority.owned_objects());
    let mut run = |mut request: Request| {
        let settlement = authority.authorize(&mut request, false);
        settlement.map(|settlement| {
            let response = ops.handle(&request);
            authority.settle(settlement, &response);
            response
        })
    };
    // Over a file there now, publication is refused, and the file kept.
    run(prepare_request(&root.join("target/kept"))).unwrap();
    let response = run(small_put(&root.join("target/kept"))).unwrap();
    assert!(
        matches!(&response, proto::Response::Applied(errors) if errors[0].as_ref().is_some_and(|error| error.condition_not_met)),
        "{response:?}"
    );
    // A file that appears after its approval keeps its contents.
    run(prepare_request(&late)).unwrap();
    let data = b"data".to_vec();
    run(Request::WriteRange {
        path: path_bytes(&late),
        inplace: false,
        copy_id: [1; 16],
        attempt: 0,
        off: 0,
        hash: crate::fsops::content_digest(&data),
        data: data.into(),
    })
    .unwrap();
    let mut publish = finalize_request(&late, proto::TargetCondition::Any);
    let settlement = authority.authorize(&mut publish, false).unwrap();
    fs::write(&late, b"theirs").unwrap();
    let response = ops.handle(&publish);
    authority.settle(settlement, &response);
    assert!(
        matches!(
            response,
            proto::Response::Err(_) | proto::Response::EndpointError(_)
        ),
        "{response:?}"
    );
    assert_eq!(fs::read(&late).unwrap(), b"theirs");
    assert_eq!(fs::read(root.join("target/kept")).unwrap(), b"kept");
}

/// Under a grant that publishes in place, a file that must be new (here an
/// `--as-new` root) is staged and published without replacing anything,
/// never written in place, so a retry after an interrupted attempt simply
/// stages it again.
#[test]
fn a_new_file_under_an_in_place_grant_is_staged_and_published_without_replacing() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let authority = test_authority_with_existence(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::New,
    )
    .unwrap();
    let target = root.join("target");
    let mut ops = authority.test_ops();
    let mut run = |mut request: Request| -> Result<(Request, proto::Response)> {
        let settlement = authority.authorize(&mut request, false)?;
        let response = ops.handle(&request);
        authority.settle(settlement, &response);
        Ok((request, response))
    };
    let prepare = |inplace, attempt| Request::Prepare {
        path: path_bytes(&target),
        size: 5,
        inplace,
        copy_id: [1; 16],
        mode: 0o644,
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        group: None,
        attempt,
        create_if_missing: true,
        update: None,
    };
    let write = |inplace, attempt| {
        let data = b"hello".to_vec();
        Request::WriteRange {
            path: path_bytes(&target),
            inplace,
            copy_id: [1; 16],
            attempt,
            off: 0,
            hash: crate::fsops::content_digest(&data),
            data: data.into(),
        }
    };
    let error = run(prepare(true, 0)).unwrap_err().to_string();
    assert!(error.contains("only creates"), "{error}");
    // Staged, an interrupted attempt is retried.
    for attempt in [0, 1] {
        let (_, response) = run(prepare(false, attempt)).unwrap();
        assert!(
            matches!(response, proto::Response::Prepared(_)),
            "{response:?}"
        );
        let (_, response) = run(write(false, attempt)).unwrap();
        assert!(
            !matches!(
                response,
                proto::Response::Err(_) | proto::Response::EndpointError(_)
            ),
            "{response:?}"
        );
        assert!(!target.exists());
    }
    let mut finalize = finalize_request(&target, Any);
    if let Request::Finalize { meta, .. } = &mut finalize {
        meta.mode = 0o100644;
    }
    let (finalize, response) = run(finalize).unwrap();
    assert!(
        matches!(
            finalize,
            Request::Finalize {
                condition: Absent,
                ..
            }
        ),
        "{finalize:?}"
    );
    assert!(
        !matches!(
            response,
            proto::Response::Err(_) | proto::Response::EndpointError(_)
        ),
        "{response:?}"
    );
    assert_eq!(fs::read(&target).unwrap(), b"hello");
}

/// A refused in-place preparation leaves a new file staged: under a grant
/// that only creates it (an `--as-new` root), a file that appears at its
/// name meanwhile takes no in-place write. (The reviewer's reproducer.)
#[test]
fn a_refused_in_place_preparation_keeps_a_new_file_staged() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let target = root.join("target");
    let authority = test_authority_with_existence(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::ExactPath,
        RootExistence::New,
    )
    .unwrap();
    let mut ops = authority.test_ops();
    let mut run = |mut request: Request| -> Result<proto::Response> {
        let settlement = authority.authorize(&mut request, false)?;
        let response = ops.handle(&request);
        authority.settle(settlement, &response);
        Ok(response)
    };
    let prepare = |inplace| Request::Prepare {
        path: path_bytes(&target),
        size: 5,
        inplace,
        copy_id: [1; 16],
        mode: 0o644,
        flags: 0,
        acl: false,
        scanned: proto::ScannedDestination::Unknown,
        group: None,
        attempt: 0,
        create_if_missing: true,
        update: None,
    };
    let response = run(prepare(false)).unwrap();
    assert!(
        matches!(response, proto::Response::Prepared(_)),
        "{response:?}"
    );
    // An unrelated file arrives before the new file is published.
    fs::write(&target, b"theirs").unwrap();
    let error = run(prepare(true)).unwrap_err();
    assert!(error.to_string().contains("only creates"), "{error}");
    // The receiver holds no in-place file to write.
    let data = b"HELLO".to_vec();
    let write = run(Request::WriteRange {
        path: path_bytes(&target),
        inplace: true,
        copy_id: [1; 16],
        attempt: 0,
        off: 0,
        hash: crate::fsops::content_digest(&data),
        data: data.into(),
    });
    assert!(
        write.as_ref().is_ok_and(|response| matches!(
            response,
            proto::Response::Err(_) | proto::Response::EndpointError(_)
        )),
        "{write:?}"
    );
    assert_eq!(fs::read(&target).unwrap(), b"theirs");
}

/// Under an in-place grant that may replace files, a new file inside the
/// destination (not its root), as `--inplace --if-exists=error` sends it, is
/// staged and published without replacing anything: one put at its name
/// before publication keeps its contents.
#[test]
fn a_new_file_inside_an_in_place_grant_is_staged_and_replaces_nothing() {
    use proto::TargetCondition::Absent;
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    let authority = test_authority_with_existence(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    let mut ops = authority.test_ops();
    let mut run = |mut request: Request| -> Result<(Request, proto::Response)> {
        let settlement = authority.authorize(&mut request, false)?;
        let response = ops.handle(&request);
        authority.settle(settlement, &response);
        Ok((request, response))
    };
    let failed = |response: &proto::Response| {
        matches!(
            response,
            proto::Response::Err(_) | proto::Response::EndpointError(_)
        )
    };
    let staged = |file: &Path, copy_id: proto::CopyId| {
        vec![
            Request::Prepare {
                path: path_bytes(file),
                size: 5,
                inplace: false,
                copy_id,
                mode: 0o644,
                flags: 0,
                acl: false,
                scanned: crate::proto::ScannedDestination::Unknown,
                group: None,
                attempt: 0,
                create_if_missing: true,
                update: None,
            },
            Request::WriteRange {
                path: path_bytes(file),
                inplace: false,
                copy_id,
                attempt: 0,
                off: 0,
                hash: crate::fsops::content_digest(b"hello"),
                data: b"hello".to_vec().into(),
            },
        ]
    };
    let finalize = |file: &Path, copy_id: proto::CopyId| {
        let mut request = finalize_request(file, Absent);
        if let Request::Finalize {
            copy_id: id, meta, ..
        } = &mut request
        {
            *id = copy_id;
            meta.mode = 0o100644;
        }
        request
    };
    // Staged, it is published at its name.
    let new = root.join("target/new");
    for request in staged(&new, [1; 16]) {
        let (_, response) = run(request).unwrap();
        assert!(!failed(&response), "{response:?}");
    }
    let (finalize_new, response) = run(finalize(&new, [1; 16])).unwrap();
    assert!(
        matches!(
            finalize_new,
            Request::Finalize {
                condition: Absent,
                ..
            }
        ),
        "{finalize_new:?}"
    );
    assert!(!failed(&response), "{response:?}");
    assert_eq!(fs::read(&new).unwrap(), b"hello");
    // A file put at the name before publication keeps its contents.
    let raced = root.join("target/raced");
    for request in staged(&raced, [2; 16]) {
        run(request).unwrap();
    }
    fs::write(&raced, b"theirs").unwrap();
    let (_, response) = run(finalize(&raced, [2; 16])).unwrap();
    assert!(failed(&response), "{response:?}");
    assert_eq!(fs::read(&raced).unwrap(), b"theirs");
}

/// `--in-place=new --as-new` on the command-restricted path never reaches
/// an existing file: a grant whose new root exists is refused when it is
/// redeemed, and a root that appears after that is neither staged over nor
/// written in place.
#[test]
fn an_in_place_as_new_root_that_exists_is_refused_and_unchanged() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let target = root.join("target");
    let grant = || {
        test_authority_with_existence(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::InPlace,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::ExactPath,
            RootExistence::New,
        )
    };
    fs::write(&target, b"theirs").unwrap();
    assert!(grant().is_err());
    fs::remove_file(&target).unwrap();
    let authority = grant().unwrap();
    fs::write(&target, b"theirs").unwrap();
    let mut ops = authority.test_ops();
    let mut run = |mut request: Request| -> Result<proto::Response> {
        let settlement = authority.authorize(&mut request, false)?;
        let response = ops.handle(&request);
        authority.settle(settlement, &response);
        Ok(response)
    };
    let prepare = |inplace| Request::Prepare {
        path: path_bytes(&target),
        size: 5,
        inplace,
        copy_id: [1; 16],
        mode: 0o644,
        flags: 0,
        acl: false,
        scanned: crate::proto::ScannedDestination::Unknown,
        group: None,
        attempt: 0,
        create_if_missing: true,
        update: None,
    };
    assert!(run(prepare(true)).is_err());
    // A stage, as without the option, is never published over it.
    run(prepare(false)).unwrap();
    run(Request::WriteRange {
        path: path_bytes(&target),
        inplace: false,
        copy_id: [1; 16],
        attempt: 0,
        off: 0,
        hash: crate::fsops::content_digest(b"hello"),
        data: b"hello".to_vec().into(),
    })
    .unwrap();
    let mut finalize = finalize_request(&target, proto::TargetCondition::Any);
    if let Request::Finalize { meta, .. } = &mut finalize {
        meta.mode = 0o100644;
    }
    if let Ok(response) = run(finalize) {
        assert!(
            matches!(
                response,
                proto::Response::Err(_) | proto::Response::EndpointError(_)
            ),
            "{response:?}"
        );
    }
    assert_eq!(fs::read(&target).unwrap(), b"theirs");
}

#[test]
fn a_refusal_racing_the_results_end_is_still_counted() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let (secret, policy) = results_policy();
    let authority = std::sync::Arc::new(existence_authority_with_results(&root, &policy, 30_000));
    let mut reader = start_results(&authority, secret);
    let mut ops = vec![Op::Mkdir {
        path: path_bytes(&root.join("outside")),
        mode: 0o755,
        condition: proto::TargetCondition::Any,
    }];
    // The first operation refuses the batch. Classifying its other requested
    // changes takes long enough for the control connection to end results.
    for _ in 0..20_000 {
        ops.push(Op::SetMeta {
            path: path_bytes(&target),
            meta: proto::Meta {
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: 0,
            condition: proto::TargetCondition::Any,
            directory: true,
        });
    }
    let other = authority.clone();
    let worker = std::thread::spawn(move || {
        let mut request = Request::Apply { ops };
        assert!(other.authorize(&mut request, false).is_err());
    });
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = authority.state.lock().unwrap();
        if state.recorded_any {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "refusal did not arrive; in_flight={}",
            state.in_flight
        );
        drop(state);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let results = finish_results(&authority, &mut reader);
    worker.join().unwrap();
    assert_eq!(
        results.totals.refused, 1,
        "authenticated end omitted a refused request"
    );
}

/// A restricted receiver reports its destination's filesystem as an
/// ordinary one does, about the directory it approved: the destination
/// itself, checked for emptiness, or, while it is missing, the directory it
/// goes into, never checked for emptiness. The sender cannot choose another.
#[test]
fn filesystem_information_describes_the_approved_destination() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir(root.join("other")).unwrap();
    fs::write(root.join("other/file"), b"x").unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut ops = authority.test_ops();
    let mut inspect = |check_empty: bool, target: Option<proto::DestinationFilesystemTarget>| {
        let mut request = Request::DestinationFilesystemInfo {
            check_empty,
            target,
        };
        let settlement = authority.authorize(&mut request, false).unwrap();
        let response = ops.handle(&request);
        authority.settle(settlement, &response);
        let proto::Response::DestinationFilesystemInfo(info) = response else {
            panic!("unexpected response {response:?}")
        };
        (request, info)
    };
    let other = fs::metadata(root.join("other")).unwrap();
    let elsewhere = proto::DestinationFilesystemTarget {
        relative_path: b"other".to_vec(),
        dev: other.dev(),
        ino: other.ino(),
    };
    let (request, info) = inspect(true, Some(elsewhere.clone()));
    let Request::DestinationFilesystemInfo {
        check_empty: true,
        target: Some(chosen),
    } = request
    else {
        panic!("the authority chose no target: {request:?}")
    };
    assert_eq!(chosen.relative_path, b"target");
    assert_eq!(info.empty, Some(true));
    assert_eq!(info.device, fs::metadata(&target).unwrap().dev());

    fs::remove_dir(&target).unwrap();
    let (request, info) = inspect(true, Some(elsewhere));
    assert!(
        matches!(
            request,
            Request::DestinationFilesystemInfo {
                check_empty: false,
                target: None,
            }
        ),
        "{request:?}"
    );
    assert_eq!(info.empty, None);
}

/// Without filters or a mapping, a metadata change is authorized without
/// looking up what it changes: the kind matters only to a failure's record,
/// which looks it up then.
#[test]
fn metadata_changes_need_no_lookup_without_filters() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let closed = root.join("target/closed");
    fs::create_dir_all(&closed).unwrap();
    fs::write(closed.join("file"), b"x").unwrap();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o000)).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut change = Request::Apply {
        ops: vec![Op::SetMeta {
            path: closed.join("file").as_os_str().as_bytes().to_vec(),
            meta: plain_meta(),
            flags: proto::flags::RECEIVER_MODE,
            condition: proto::TargetCondition::Any,
            directory: false,
        }],
    };
    let authorized = authority.authorize(&mut change, false);
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o755)).unwrap();
    authorized.unwrap();
}

/// What a signed mapping entry sets explicitly, the receiver applies
/// without the matching copy option, and only with exactly the entry's
/// values: other values, and other entries, still need the option.
#[test]
fn signed_mapping_metadata_is_applied_without_its_copy_options() {
    let root = crate::test_support::tempdir().unwrap();
    let target = root.path().join("target");
    fs::create_dir_all(&target).unwrap();
    let uid = unsafe { libc::getuid() };
    let manifest = format!(
        concat!(
            r#"{{"src":{{"encoding":"utf-8","value":"source"}},"dst":{{"encoding":"utf-8","value":"set"}},"metadata":{{"mode":416,"mtime":123,"mtime_nsec":456,"uid":{uid}}}}}"#,
            "\n",
            r#"{{"src":{{"encoding":"utf-8","value":"source"}},"dst":{{"encoding":"utf-8","value":"plain"}}}}"#,
            "\n"
        ),
        uid = uid
    )
    .into_bytes();
    let mut authority = test_authority(root.path(), DeletionPolicy::Forbid, 1024);
    authority.copy.limits.max_entries = 100;
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
    let meta = |mode, mtime, uid| proto::Meta {
        inode_metadata: None,
        mode,
        uid,
        gid: 0,
        mtime,
        mtime_nsec: 456,
    };
    let flags = proto::flags::MODE | proto::flags::TIMES | proto::flags::OWNER;
    let set = path_bytes(&target.join("set"));
    let plain = path_bytes(&target.join("plain"));
    authority
        .check_metadata(&set, &meta(0o100640, 123, uid), flags)
        .unwrap();
    for (path, meta) in [
        (&set, meta(0o100644, 123, uid)),
        (&set, meta(0o100640, 124, uid)),
        (&set, meta(0o100640, 123, uid.wrapping_add(1))),
        (&plain, meta(0o100640, 123, uid)),
    ] {
        assert!(
            authority.check_metadata(path, &meta, flags).is_err(),
            "{meta:?}"
        );
    }
    // A preparation names the entry's mode for the file to come.
    authority
        .check_preparation_flags(&set, 0o640, proto::flags::MODE | proto::flags::TIMES)
        .unwrap();
    assert!(authority
        .check_preparation_flags(&set, 0o644, proto::flags::MODE)
        .is_err());
}

/// A grant that keeps existing objects keeps a file another program puts
/// at a new file's name while the copy runs, whether the receiver finds it
/// when it authorizes the file or when it publishes it. That is no refusal
/// or failure: nothing changed, as the grant asks, and the results list
/// nothing for it.
#[test]
fn files_the_keep_policy_keeps_are_neither_refused_nor_failed() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
        Some((key, policy)),
    )
    .unwrap();
    let mut reader = start_results(&authority, secret);
    // There when the receiver authorizes it: the publication finds it.
    fs::write(target.join("early"), b"theirs").unwrap();
    let mut early = small_put(&target.join("early"));
    let settlement = authority.authorize(&mut early, false).unwrap();
    let response = authority.test_ops().handle(&early);
    authority.settle(settlement, &response);
    // Appears after the receiver authorizes it.
    let mut late = small_put(&target.join("late"));
    let settlement = authority.authorize(&mut late, false).unwrap();
    fs::write(target.join("late"), b"theirs").unwrap();
    let response = authority.test_ops().handle(&late);
    authority.settle(settlement, &response);
    assert!(
        matches!(&response, proto::Response::Applied(errors) if errors[0].is_some())
            || matches!(&response, proto::Response::PublishedBatch(results) if results[0].is_err()),
        "{response:?}"
    );
    for name in ["early", "late"] {
        assert_eq!(fs::read(target.join(name)).unwrap(), b"theirs", "{name}");
    }
    let results = finish_results(&authority, &mut reader);
    assert_eq!((results.totals.refused, results.totals.failed), (0, 0));
    assert!(results.changes().is_empty(), "{:?}", results.records);
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

/// The small-copy shortcut works on a restricted receiver: the receiver
/// opens the directory beneath the root its authority holds, each file
/// passes the grant's rules, payloads are held to what the preparation
/// asked for, and the results list what it published.
#[test]
fn small_copies_publish_through_a_restricted_receiver() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("old"), b"stale contents").unwrap();
    let key = generate_results_key(EnrollmentId::random()).unwrap();
    let (secret, policy) = results_policy();
    let authority = std::sync::Arc::new(
        test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
            Some((key, policy)),
        )
        .unwrap(),
    );
    let mut reader = start_results(&authority, secret);
    let mut ops = authority.test_ops();
    let mut gate = PatchStreamGate::new(authority.clone());
    let in_flight = || authority.state.lock().unwrap().in_flight;
    let names = ["one", "two", "old"];
    let contents: Vec<Vec<u8>> = names
        .iter()
        .map(|name| name.repeat(3).into_bytes())
        .collect();
    let offer = |directory: &Path| proto::SmallCopyRequest {
        reuse_block_size: None,
        if_exists: crate::cli::IfExists::Update,
        matching_flags: 0,
        hash_policy: authority.hash_policy(),
        copy_if: None,
        directory: path_bytes(directory),
        symlink_policy: proto::OperatorSymlinkPolicy::Refuse,
        request_prefix: path_bytes(directory),
        identity: proto::SmallCopyIdentity {
            copy_id: [8; 16],
            dst_leaf: None,
        },
        flags: 0,
        files: names
            .iter()
            .zip(&contents)
            .map(|(name, data)| proto::SmallCopyFile {
                path: path_bytes(&directory.join(name)),
                expression_source: None,
                size: data.len() as u64,
                meta: plain_meta(),
            })
            .collect(),
    };
    let payloads = |sizes_off_by: usize| -> Vec<proto::SmallCopyPayload> {
        contents
            .iter()
            .enumerate()
            .map(|(index, data)| {
                let data = data[..data.len() - sizes_off_by].to_vec();
                proto::SmallCopyPayload {
                    index: index as u32,
                    hash: crate::fsops::content_digest(&data),
                    data,
                }
            })
            .collect()
    };

    // Only into the signed destination.
    let error = execute_on_connection(
        &mut gate,
        &mut ops,
        Request::PrepareSmallFiles(offer(&root)),
    )
    .unwrap_err();
    assert!(
        error.contains("other than the signed destination"),
        "{error}"
    );

    // A preparation waits for its payloads, which must be the ones it
    // asked for; refused payloads end it with nothing changed.
    let prepare = || Request::PrepareSmallFiles(offer(&target));
    assert!(matches!(
        execute_on_connection(&mut gate, &mut ops, prepare()),
        Ok(proto::Response::SmallFilesPrepared(needed)) if needed == [true; 3]
    ));
    assert_eq!(in_flight(), 1);
    let error = execute_on_connection(&mut gate, &mut ops, Request::CopySmallFiles(payloads(1)))
        .unwrap_err();
    assert!(
        error.contains("differ from what its preparation asked"),
        "{error}"
    );
    assert_eq!(in_flight(), 0);
    assert!(!target.join("one").exists());

    // So does the connection's next request.
    assert!(matches!(
        execute_on_connection(&mut gate, &mut ops, prepare()),
        Ok(proto::Response::SmallFilesPrepared(_))
    ));
    execute_on_connection(
        &mut gate,
        &mut ops,
        Request::ConfigureHashing(authority.hash_policy()),
    )
    .unwrap();
    assert_eq!(in_flight(), 0);
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    // A telemetry sample in between does not.
    assert!(matches!(
        execute_on_connection(&mut gate, &mut ops, prepare()),
        Ok(proto::Response::SmallFilesPrepared(_))
    ));
    let sample = gate.authorize(&mut Request::TransportStats, false).unwrap();
    gate.settle(sample, &proto::Response::Ok, false);
    let response =
        execute_on_connection(&mut gate, &mut ops, Request::CopySmallFiles(payloads(0))).unwrap();
    assert!(
        matches!(
            &response,
            proto::Response::SmallFilesCopied(proto::SmallCopyResponse {
                outcome: proto::SmallCopyOutcome::Published(results),
                ..
            }) if results.iter().all(|result| result.error.is_none()
                && result.disposition == proto::SmallCopyDisposition::Copied)
        ),
        "{response:?}"
    );
    assert_eq!(in_flight(), 0);
    for (name, data) in names.iter().zip(&contents) {
        assert_eq!(&fs::read(target.join(name)).unwrap(), data, "{name}");
    }
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        3
    );
    let results = finish_results(&authority, &mut reader);
    assert_eq!(results.totals.files_transferred, 3);
    assert_eq!((results.totals.refused, results.totals.failed), (2, 0));
    for name in names {
        assert!(
            results.has("transfer_file", name.as_bytes(), "succeeded"),
            "{name}"
        );
    }
}

/// A destination named through a link to its directory, whose own link
/// names where it leads by an absolute path: the receiver compares that
/// path with where the directory really is, not the name the grant uses.
#[test]
fn follow_dst_compares_absolute_link_targets_with_the_real_directory() {
    let temporary = crate::test_support::tempdir().unwrap();
    let parent = temporary.path().join("parent");
    let real = parent.join("data/real");
    fs::create_dir_all(&real).unwrap();
    symlink(&parent, temporary.path().join("alias")).unwrap();
    symlink(&real, parent.join("target")).unwrap();
    let named = temporary.path().join("alias/target");
    let mut args =
        Args::try_parse_from(["syq rsync", "-r", "host-a:data/", "host-b:/unused"]).unwrap();
    args.normalize();
    let source = Location::parse("host-a:data/").unwrap();
    let grant = grant_for(
        &args,
        std::slice::from_ref(&source),
        (EnrollmentId::random(), 1),
        "receiver",
        named.as_os_str().as_bytes(),
    )
    .unwrap();
    let authority = RestrictedAuthority::new(
        ConfinedRoot::resolve(named.as_os_str().as_bytes(), &[]).unwrap(),
        grant,
        GrantConstraints {
            extra_options: crate::delegation::ExtraCopyOptions {
                follow_dst: true,
                ..Default::default()
            },
            ..GrantConstraints::default()
        },
        [0; 32],
        generate_results_key(EnrollmentId::random()).unwrap(),
        Instant::now() + std::time::Duration::from_secs(60),
        &[],
    )
    .unwrap();
    let mut put = small_put(&named.join("file"));
    let settlement = authority.authorize(&mut put, false).unwrap();
    let response = authority.test_ops().handle(&put);
    authority.settle(settlement, &response);
    assert_eq!(fs::read(real.join("file")).unwrap(), b"new", "{response:?}");
}

/// With `--follow-dst`, a destination reached through symlinks is the
/// directory they lead to inside the confinement root: the receiver works
/// beneath it, under the signed destination's name. A link that leads
/// outside the root, into the receiver's control plane, to nothing, or
/// round in a loop is refused when the grant is redeemed.
#[test]
fn follow_dst_copies_into_the_directory_a_destination_link_leads_to() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let real = root.join("data/real");
    fs::create_dir_all(&real).unwrap();
    fs::create_dir_all(temporary.path().join("outside")).unwrap();
    fs::create_dir_all(root.join(".ssh")).unwrap();
    let options = crate::delegation::ExtraCopyOptions {
        follow_dst: true,
        ..Default::default()
    };
    let protected = [ReceiverControlPath {
        path: path_bytes(&root.join(".ssh")),
        label: "protected SSH configuration directory",
    }];
    let authority = |target: &[u8], options| {
        let link = root.join("target");
        let _ = fs::remove_file(&link);
        symlink(OsStr::from_bytes(target), &link).unwrap();
        test_authority_with_options(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
            None,
            (options, &protected),
        )
    };
    for target in [
        b"data/real".to_vec(),
        b"./data/../data/real/".to_vec(),
        path_bytes(&real),
    ] {
        let authority = authority(&target, options).unwrap();
        let mut put = small_put(&root.join("target/file"));
        let settlement = authority.authorize(&mut put, false).unwrap();
        let response = authority.test_ops().handle(&put);
        authority.settle(settlement, &response);
        assert_eq!(
            fs::read(real.join("file")).unwrap(),
            b"new",
            "{target:?}: {response:?}"
        );
        fs::remove_file(real.join("file")).unwrap();
        assert!(fs::symlink_metadata(root.join("target"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
    // Without it, the link is the destination, and nothing follows it.
    let plain = authority(b"data/real", Default::default()).unwrap();
    let mut put = small_put(&root.join("target/file"));
    assert!(
        plain.authorize(&mut put, false).is_err()
            || {
                let response = plain.test_ops().handle(&put);
                !matches!(&response, proto::Response::Applied(errors) if errors[0].is_none())
                    && !matches!(&response, proto::Response::PublishedBatch(results) if results[0].is_ok())
            }
    );
    assert!(!real.join("file").exists());

    symlink("loop-b", root.join("loop-a")).unwrap();
    symlink("loop-a", root.join("loop-b")).unwrap();
    for (target, refusal) in [
        (
            b"../outside".to_vec(),
            "outside the directory the destination is in",
        ),
        (
            path_bytes(&temporary.path().join("outside")),
            "outside the directory the destination is in",
        ),
        (b".ssh".to_vec(), "protected SSH configuration"),
        (
            b"missing".to_vec(),
            "leads to missing, which does not exist",
        ),
        (b"loop-a".to_vec(), "too many symlinks"),
        (b".".to_vec(), "the directory it is in"),
    ] {
        let error = format!("{:#}", authority(&target, options).err().unwrap());
        assert!(error.contains(refusal), "{target:?}: {error}");
    }
}

/// `--follow-dst` (or `--follow`) with `--into` is signed for the receiver
/// to resolve; it cannot be combined with `--widen-dirs all`, whose
/// directories on the way to the destination a link would make ambiguous.
#[test]
fn follow_dst_is_signed_for_into_placements() {
    for (options, follow) in [
        (&["--into", "/backup"][..], false),
        (&["--into", "/backup", "--follow-dst"][..], true),
        (&["--into", "/backup", "--follow"][..], true),
        (&["--as", "/backup", "--follow-dst"][..], false),
    ] {
        let mut argv: Vec<_> = ["cp", "--from", "host-a", "source", "--to", "host-b"]
            .map(std::ffi::OsString::from)
            .into();
        argv.extend(options.iter().map(std::ffi::OsString::from));
        let args = Args::parse_args(&argv).unwrap();
        validate_restricted_args(&args).unwrap();
        let constraints = crate::restricted::grant::extra_copy_options(&args);
        assert_eq!(constraints.follow_dst, follow, "{options:?}");
    }
    let args = Args::parse_args(
        &[
            "cp",
            "--from",
            "host-a",
            "source",
            "--to",
            "host-b",
            "--into",
            "/backup",
            "--follow-dst",
            "--widen-dirs=all",
        ]
        .map(std::ffi::OsString::from),
    )
    .unwrap();
    let error = validate_restricted_args(&args).unwrap_err().to_string();
    assert!(error.contains("--widen-dirs all"), "{error}");
}

/// With `--follow-dst`, a destination that does not exist yet, with no
/// symlink on the way, is created as any destination is; one whose missing
/// part lies past a symlink is created inside the directory the link leads
/// to.
#[test]
fn follow_dst_creates_a_destination_that_does_not_exist_yet() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("real")).unwrap();
    let options = crate::delegation::ExtraCopyOptions {
        follow_dst: true,
        ..Default::default()
    };
    // No symlink: the destination is the confinement root's missing child.
    let authority = test_authority_with_options(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
        None,
        (options, &[]),
    )
    .unwrap();
    assert!(
        authority.root_path == path_bytes(&root),
        "{:?}",
        authority.root_path
    );
    // Missing components past a link resolve inside its target.
    let resolved = resolve_destination_links(
        &Root::open(&root).unwrap(),
        &path_bytes(&root),
        b"link/new/deeper",
    );
    symlink("real", root.join("link")).unwrap();
    assert!(
        resolved.unwrap().is_none(),
        "nothing to follow before the link exists"
    );
    let found = resolve_destination_links(
        &Root::open(&root).unwrap(),
        &path_bytes(&root),
        b"link/new/deeper",
    )
    .unwrap()
    .unwrap();
    assert_eq!(found.existing, vec![b"real".to_vec()]);
    assert_eq!(found.signed_components, 1);
}

/// An confinement root of `/` names everything beneath it, so restricted
/// lookups work there, and an absolute destination symlink resolves inside
/// it.
#[test]
fn an_enrolled_root_of_slash_names_paths_beneath_it() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("target/file"), b"there").unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.root = std::sync::Arc::new(Root::open(Path::new("/")).unwrap());
    authority.root_path = b"/".to_vec();
    assert!(authority
        .rooted_metadata(&path_bytes(&root.join("target/file")))
        .unwrap()
        .is_some_and(|metadata| metadata.is_file()));
    let mut ops = authority.test_ops();
    assert!(matches!(
        ops.handle(&Request::StatMany {
            paths: vec![path_bytes(&root.join("target/file"))],
            sources: None,
            follow: false,
        }),
        proto::Response::Stats(entries) if entries[0].is_some()
    ));
    symlink(root.join("target"), root.join("absolute-link")).unwrap();
    let relative = path_bytes(&root.join("absolute-link"));
    let found =
        resolve_destination_links(&Root::open(Path::new("/")).unwrap(), b"/", &relative[1..])
            .unwrap()
            .unwrap();
    assert_eq!(
        found.existing.join(&b'/'),
        path_bytes(&root.join("target"))[1..].to_vec()
    );
}

/// A followed destination that reaches the receiver's control files is
/// refused by identity, however the protected path or the destination is
/// spelled.
#[test]
fn followed_destinations_reaching_control_files_are_refused_by_identity() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("home/.ssh")).unwrap();
    symlink("home/.ssh", root.join("target")).unwrap();
    // The protected path, spelled through another name for the root.
    symlink(&root, temporary.path().join("alias")).unwrap();
    let protected = [ReceiverControlPath {
        path: path_bytes(&temporary.path().join("alias/home/.ssh")),
        label: "protected SSH configuration directory",
    }];
    let error = test_authority_with_options(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
        None,
        (
            crate::delegation::ExtraCopyOptions {
                follow_dst: true,
                ..Default::default()
            },
            &protected,
        ),
    )
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("protected SSH configuration"),
        "{error:#}"
    );
}

/// Under `keep_files` (rsync `--ignore-existing`) an existing file keeps
/// its metadata as well as its contents; an existing directory still takes
/// the copy's metadata.
#[test]
fn keep_files_leaves_existing_files_metadata_alone() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(target.join("dir")).unwrap();
    fs::write(target.join("file"), b"theirs").unwrap();
    fs::set_permissions(target.join("file"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    authority.extra_options.keep_files = true;
    authority.copy.options.preserve_permissions = true;
    authority.copy.options.receiver_managed_modes = false;
    let file = path_bytes(&target.join("file"));
    let mut mode = plain_meta();
    mode.mode = 0o644;
    for mut request in [
        Request::Apply {
            ops: vec![Op::SetFileMetaIfSame {
                path: file.clone(),
                meta: mode.clone(),
                flags: proto::flags::MODE,
                condition: proto::TargetCondition::Any,
            }],
        },
        Request::Apply {
            ops: vec![Op::SetMeta {
                path: file.clone(),
                meta: mode.clone(),
                flags: proto::flags::MODE,
                condition: proto::TargetCondition::Any,
                directory: false,
            }],
        },
        Request::FinishBasis {
            expected_hash: None,
            path: file.clone(),
            copy_id: [3; 16],
            meta: mode.clone(),
            flags: proto::flags::MODE,
            condition: proto::TargetCondition::Any,
        },
    ] {
        let error = authority.authorize(&mut request, false).unwrap_err();
        assert!(
            format!("{error:#}").contains("may not be modified"),
            "{error:#}"
        );
    }
    assert_eq!(
        fs::metadata(target.join("file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut directory = Request::Apply {
        ops: vec![Op::SetMeta {
            path: path_bytes(&target.join("dir")),
            meta: mode,
            flags: proto::flags::MODE,
            condition: proto::TargetCondition::Any,
            directory: true,
        }],
    };
    authority.authorize(&mut directory, false).unwrap();
}

/// A file counts against the entry limit before its first change: an
/// in-place preparation, or a stage, even an empty one. Its publication
/// then counts nothing more.
#[test]
fn files_count_against_the_entry_limit_from_their_first_change() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let changes = |authority: &RestrictedAuthority| {
        authority.changes.load(std::sync::atomic::Ordering::Relaxed)
    };
    for (inplace, size) in [(true, 4), (false, 0)] {
        let mut authority = test_authority_with_results(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            if inplace {
                PublicationPolicy::InPlace
            } else {
                PublicationPolicy::AtomicStaged
            },
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
            None,
        )
        .unwrap();
        authority.copy.limits.max_entries = 2;
        let prepare = |index: u8| {
            let mut request = prepare_request(&target.join(format!("file-{index}")));
            if let Request::Prepare {
                inplace: request_inplace,
                size: request_size,
                copy_id,
                ..
            } = &mut request
            {
                *request_inplace = inplace;
                *request_size = size;
                *copy_id = [index; 16];
            }
            request
        };
        // A retried preparation of the same file counts once.
        for index in [1, 1, 2] {
            authority.authorize(&mut prepare(index), false).unwrap();
        }
        assert_eq!(changes(&authority), 2, "in place: {inplace}");
        let error = authority.authorize(&mut prepare(3), false).unwrap_err();
        assert!(
            format!("{error:#}").contains("entry limit exceeded"),
            "{error:#}"
        );
        // Publishing a file counted at preparation counts nothing more.
        let mut finalize = finalize_request(&target.join("file-1"), proto::TargetCondition::Any);
        if let Request::Finalize {
            inplace: finalize_inplace,
            copy_id,
            ..
        } = &mut finalize
        {
            *finalize_inplace = inplace;
            *copy_id = [1; 16];
        }
        authority.authorize(&mut finalize, false).unwrap();
        assert_eq!(changes(&authority), 2, "in place: {inplace}");
    }
}

/// Only changes the receiver reports it did not make are given back: one
/// whose condition it found unmet, and one it skipped. One that failed
/// after it may have changed something stays counted.
#[test]
fn only_changes_that_made_nothing_are_given_back() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(target.join("taken")).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let unchanged = |message: &str| proto::WireError {
        unchanged: true,
        ..proto::WireError::from(message)
    };
    let mut request = Request::Apply {
        ops: ["taken", "partly", "fine"]
            .iter()
            .map(|name| Op::Mkdir {
                path: path_bytes(&target.join(name)),
                mode: 0o755,
                condition: proto::TargetCondition::Any,
            })
            .collect(),
    };
    let settlement = authority.authorize(&mut request, false).unwrap();
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        3
    );
    authority.settle(
        settlement,
        &proto::Response::Applied(vec![
            Some(unchanged("the name was taken")),
            Some(proto::WireError::from(
                "set metadata: failed after creating it",
            )),
            None,
        ]),
    );
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
}

/// Where inode numbers cannot show which file a name leads to, the
/// receiver holds a change to whatever it observes at the name, not to the
/// sender's numbers; elsewhere it refuses numbers that name another file.
#[test]
fn changes_check_existence_only_where_numbers_mislead() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("file"), b"there").unwrap();
    let observed = fs::metadata(target.join("file")).unwrap();
    for trusted in [true, false] {
        let authority = existence_authority(
            &root,
            ExistingDestinationPolicy::MustExist,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
        )
        .unwrap();
        if !trusted {
            let mut profile = authority.root.profile();
            profile.link_counts_trusted = false;
            authority.root.assume_profile_for_test(profile);
        }
        let mut request = Request::Apply {
            ops: vec![Op::SetMeta {
                path: path_bytes(&target.join("file")),
                meta: plain_meta(),
                flags: 0,
                // Numbers the file there does not have.
                condition: proto::TargetCondition::Matches { dev: 1, ino: 1 },
                directory: false,
            }],
        };
        let authorized = authority.authorize(&mut request, false);
        if trusted {
            let Err(error) = authorized else {
                panic!("other numbers are refused")
            };
            assert!(
                format!("{error:#}").contains("does not match the object"),
                "{error:#}"
            );
            continue;
        }
        authorized.unwrap();
        let Request::Apply { ops } = &request else {
            unreachable!()
        };
        let Op::SetMeta { condition, .. } = &ops[0] else {
            unreachable!()
        };
        assert_eq!(
            *condition,
            proto::TargetCondition::Matches {
                dev: observed.dev(),
                ino: observed.ino(),
            }
        );
    }
}

/// A small copy whose staging failed keeps the count of the files it may
/// have staged: their sidecars stay for the fallback engine to resume, so
/// they count against the entry limit as any file a change created. Here an
/// invalid time fails each file's metadata after its sidecar is created,
/// and a grant of one entry admits one such copy, not three; only Linux
/// refuses that time, so only there. A small copy that fails before staging
/// anything gives its count back.
#[test]
fn a_failed_small_copy_keeps_the_entries_its_staging_made() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let mut authority = test_authority_with_results(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
        None,
    )
    .unwrap();
    authority.copy.limits.max_entries = 1;
    authority.copy.options.preserve_times = true;
    let authority = std::sync::Arc::new(authority);
    let mut ops = authority.test_ops();
    let mut gate = PatchStreamGate::new(authority.clone());
    let changes = || authority.changes.load(std::sync::atomic::Ordering::Relaxed);
    let offer = |file: &Path, if_exists| proto::SmallCopyRequest {
        reuse_block_size: None,
        if_exists,
        matching_flags: 0,
        hash_policy: authority.hash_policy(),
        copy_if: None,
        directory: path_bytes(&target),
        symlink_policy: proto::OperatorSymlinkPolicy::Refuse,
        request_prefix: path_bytes(&target),
        identity: proto::SmallCopyIdentity {
            copy_id: [8; 16],
            dst_leaf: None,
        },
        flags: proto::flags::TIMES,
        files: vec![proto::SmallCopyFile {
            path: path_bytes(file),
            expression_source: None,
            size: 1,
            meta: proto::Meta {
                // Not a valid time: setting it fails once the file exists.
                mtime_nsec: 1_000_000_000,
                ..plain_meta()
            },
        }],
    };
    let payload = || {
        Request::CopySmallFiles(vec![proto::SmallCopyPayload {
            index: 0,
            data: b"x".to_vec(),
            hash: crate::fsops::content_digest(b"x"),
        }])
    };

    // Different contents under `error-if-different`: nothing is staged, and
    // the count comes back.
    fs::write(target.join("other"), b"y").unwrap();
    let response = execute_on_connection(
        &mut gate,
        &mut ops,
        Request::PrepareSmallFiles(offer(
            &target.join("other"),
            crate::cli::IfExists::ErrorIfDifferent,
        )),
    )
    .unwrap();
    assert!(
        matches!(response, proto::Response::SmallFilesPrepared(_)),
        "{response:?}"
    );
    let response = execute_on_connection(&mut gate, &mut ops, payload()).unwrap();
    assert!(
        matches!(
            response,
            proto::Response::SmallFilesCopied(proto::SmallCopyResponse {
                outcome: proto::SmallCopyOutcome::StagingFailed(_),
                ..
            })
        ),
        "{response:?}"
    );
    assert_eq!(changes(), 0);

    // macOS accepts a nanosecond count of a whole second.
    let tries = if cfg!(target_os = "linux") { 3 } else { 0 };
    for index in 0..tries {
        let file = target.join(format!("{index}-fail"));
        let prepared = execute_on_connection(
            &mut gate,
            &mut ops,
            Request::PrepareSmallFiles(offer(&file, crate::cli::IfExists::Update)),
        );
        if index > 0 {
            let error = prepared.unwrap_err();
            assert!(error.contains("entry limit"), "{error}");
            continue;
        }
        assert!(
            matches!(prepared, Ok(proto::Response::SmallFilesPrepared(_))),
            "{prepared:?}"
        );
        let response = execute_on_connection(&mut gate, &mut ops, payload()).unwrap();
        assert!(
            matches!(
                response,
                proto::Response::SmallFilesCopied(proto::SmallCopyResponse {
                    outcome: proto::SmallCopyOutcome::StagingFailed(_),
                    ..
                })
            ),
            "{response:?}"
        );
        assert!(crate::fsops::partial_path(&file, &[8; 16])
            .unwrap()
            .exists());
        assert_eq!(changes(), 1);
    }
}

/// A preparation that may neither create nor update its file only looks,
/// and so counts nothing against the entry limit: in place too, it creates
/// no file and resizes none this copy holds.
#[test]
fn an_in_place_preparation_that_only_looks_changes_nothing() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let authority = test_authority_with_policy(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlace,
    );
    let mut ops = authority.test_ops();
    let changes = || authority.changes.load(std::sync::atomic::Ordering::Relaxed);
    let look = |path: &Path, size: u64| {
        let mut request = prepare_request(path);
        if let Request::Prepare {
            inplace,
            create_if_missing,
            size: declared,
            ..
        } = &mut request
        {
            *inplace = true;
            *create_if_missing = false;
            *declared = size;
        }
        request
    };
    let mut carry_out = |request: &mut Request| {
        let settlement = authority.authorize(request, false).unwrap();
        let response = ops.handle(request);
        authority.settle(settlement, &response);
        response
    };

    let response = carry_out(&mut look(&target.join("new"), 512));
    assert!(
        fs::symlink_metadata(target.join("new")).is_err(),
        "a look created a file: {response:?}"
    );
    assert_eq!(changes(), 0);

    // A file this copy holds keeps the size its creation declared.
    let mut create = prepare_request(&target.join("held"));
    if let Request::Prepare { inplace, .. } = &mut create {
        *inplace = true;
    }
    carry_out(&mut create);
    assert_eq!(fs::metadata(target.join("held")).unwrap().len(), 4);
    assert_eq!(changes(), 1);
    carry_out(&mut look(&target.join("held"), 512));
    assert_eq!(fs::metadata(target.join("held")).unwrap().len(), 4);
    assert_eq!(changes(), 1);
}

/// Two requests that may create the same file share its count against the
/// entry limit: one that finds its condition unmet gives nothing back
/// while the other may still create the file.
#[test]
fn a_refused_preparation_keeps_the_count_another_still_shares() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let mut authority = test_authority_with_policy(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlaceUpdate,
    );
    authority.copy.limits.max_entries = 1;
    let mut ops = authority.test_ops();
    for index in 0..2 {
        let path = target.join(format!("file-{index}"));
        // In place, held to a file that is not there, and so refused.
        let mut stale = prepare_request(&path);
        if let Request::Prepare {
            inplace,
            size,
            update,
            ..
        } = &mut stale
        {
            *inplace = true;
            *size = 0;
            *update = Some(Box::new(proto::InPlaceUpdate {
                meta: plain_meta(),
                flags: 0,
                only: Some((0, 0)),
            }));
        }
        let mut create = stale.clone();
        if let Request::Prepare { update, .. } = &mut create {
            *update = None;
        }
        // The second file is past the limit.
        if index == 1 {
            let Err(error) = authority.authorize(&mut stale, false) else {
                panic!("a second file was authorized past the limit")
            };
            assert!(format!("{error:#}").contains("entry limit"), "{error:#}");
            continue;
        }
        let stale_settlement = authority.authorize(&mut stale, false).unwrap();
        let create_settlement = authority.authorize(&mut create, false);
        let stale_response = ops.handle(&stale);
        assert!(
            matches!(&stale_response, proto::Response::EndpointError(error) if error.condition_not_met),
            "{stale_response:?}"
        );
        authority.settle(stale_settlement, &stale_response);
        let create_settlement = create_settlement.unwrap();
        let create_response = ops.handle(&create);
        assert!(
            matches!(&create_response, proto::Response::Prepared(_)),
            "{create_response:?}"
        );
        authority.settle(create_settlement, &create_response);
        assert!(path.exists());
    }
    assert_eq!(
        authority.changes.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(!target.join("file-1").exists());
}

/// A destination reached through a symlink may not contain where a control
/// directory that does not exist yet would be: the copy would create it.
#[test]
fn followed_destinations_may_not_create_a_missing_control_directory() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("home")).unwrap();
    symlink("home", root.join("target")).unwrap();
    let protected = [ReceiverControlPath {
        path: path_bytes(&root.join("home/.ssh")),
        label: "protected SSH configuration directory",
    }];
    let error = test_authority_with_options(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::AtomicStaged,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
        None,
        (
            crate::delegation::ExtraCopyOptions {
                follow_dst: true,
                ..Default::default()
            },
            &protected,
        ),
    )
    .err()
    .expect("a destination that would hold the missing control directory");
    assert!(
        format!("{error:#}").contains("protected SSH configuration"),
        "{error:#}"
    );
}

/// A control path that is a symlink is protected where it really is: a
/// destination containing its target is refused, followed or not.
#[test]
fn a_symlinked_control_path_is_protected_where_it_leads() {
    for follow_dst in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir_all(root.join("target/keys")).unwrap();
        fs::create_dir_all(temporary.path().join("home")).unwrap();
        symlink(root.join("target/keys"), temporary.path().join("home/.ssh")).unwrap();
        let protected = [ReceiverControlPath {
            path: path_bytes(&temporary.path().join("home/.ssh")),
            label: "protected SSH configuration directory",
        }];
        let error = test_authority_with_options(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Replace,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
            None,
            (
                crate::delegation::ExtraCopyOptions {
                    follow_dst,
                    ..Default::default()
                },
                &protected,
            ),
        )
        .err()
        .expect("a destination containing the control directory's target");
        assert!(
            format!("{error:#}").contains("protected SSH configuration"),
            "follow {follow_dst}: {error:#}"
        );
    }
}

/// Look `paths` up for the planner on `ops`, a connection of `authority`,
/// as a receiver does for every name it plans (`Request::StatMany`).
fn look_up_for_planner(
    authority: &RestrictedAuthority,
    ops: &mut crate::fsops::FsOps,
    paths: &[PathBuf],
) {
    let mut request = Request::StatMany {
        paths: paths.iter().map(|path| path_bytes(path)).collect(),
        sources: None,
        follow: false,
    };
    authority.authorize(&mut request, false).unwrap();
    let response = ops.handle(&request);
    assert!(
        matches!(&response, proto::Response::Stats(stats) if stats.len() == paths.len()),
        "{response:?}"
    );
}

/// Make `authority`'s root look like a filesystem without a no-replace
/// rename (`no_replace_rename`) or an exchange (`exchange`), as NFS is.
fn assume_lacking(authority: &RestrictedAuthority, no_replace_rename: bool, exchange: bool) {
    let mut profile = authority.root.profile();
    profile.atomic_no_replace_rename &= !no_replace_rename;
    profile.exchange &= !exchange;
    profile.hard_links = true;
    authority.root.assume_profile_for_test(profile);
}

fn small_put_with(path: &Path, condition: proto::TargetCondition) -> Request {
    let mut request = small_put(path);
    if let Request::PutSmallBatch(puts) = &mut request {
        puts[0].condition = condition;
    }
    request
}

/// Under a grant that creates nothing (`MustExist`), on a filesystem
/// without an exchange, a file the receiver's own lookup for the planner
/// found is replaced with no look of its own; one it did not look up is
/// looked at, and refused unless it exists; one the grant deleted counts as
/// found no more.
#[test]
fn must_exist_takes_the_receivers_own_lookups_for_existence() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    for name in ["found", "unlooked"] {
        fs::write(target.join(name), b"old").unwrap();
    }
    let mut authority = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    authority.copy.limits.max_entries = 64;
    assume_lacking(&authority, false, true);
    let mut ops = authority.test_ops();
    look_up_for_planner(
        &authority,
        &mut ops,
        &[target.join("found"), target.join("missing")],
    );
    // Only the file it found: a name found absent is of no use here.
    assert_eq!(authority.lookups.as_ref().unwrap().len(), 1);
    // Gone since the lookup: no look tells the authority so.
    fs::remove_file(target.join("found")).unwrap();
    authority
        .authorize(&mut small_put(&target.join("found")), false)
        .unwrap();
    // Not looked up: looked at.
    authority
        .authorize(&mut small_put(&target.join("unlooked")), false)
        .unwrap();
    let Err(error) = authority.authorize(&mut small_put(&target.join("missing")), false) else {
        panic!("a file was created under a grant that creates nothing")
    };
    assert!(KeptExisting::is(&error), "{error:#}");
    // Deleted by the grant: found no more.
    authority
        .authorize(
            &mut apply(Op::Unlink {
                path: path_bytes(&target.join("found")),
            }),
            false,
        )
        .unwrap();
    let Err(error) = authority.authorize(&mut small_put(&target.join("found")), false) else {
        panic!("a deleted file was created again")
    };
    assert!(KeptExisting::is(&error), "{error:#}");
}

/// The receiver records its lookups only where a publication needs them:
/// on a filesystem with a no-replace rename, keeping files, or an
/// exchange, replacing only existing ones, it records nothing and holds
/// every publication as it always has.
#[test]
fn lookups_are_recorded_only_where_publication_needs_them() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("there"), b"old").unwrap();
    for policy in [
        ExistingDestinationPolicy::Skip,
        ExistingDestinationPolicy::MustExist,
    ] {
        let authority = existence_authority(
            &root,
            policy,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
        )
        .unwrap();
        let mut profile = authority.root.profile();
        profile.atomic_no_replace_rename = true;
        profile.exchange = true;
        authority.root.assume_profile_for_test(profile);
        let mut ops = authority.test_ops();
        look_up_for_planner(
            &authority,
            &mut ops,
            &[target.join("there"), target.join("new")],
        );
        assert_eq!(authority.lookups.as_ref().unwrap().len(), 0, "{policy:?}");
        if policy == ExistingDestinationPolicy::Skip {
            // Nor a directory this receiver creates.
            carry_out(
                &authority,
                &mut ops,
                &mut apply(mkdir(&target.join("made"))),
            )
            .unwrap();
            assert_eq!(authority.lookups.as_ref().unwrap().len(), 0);
            let mut request = small_put(&target.join("new"));
            authority.authorize(&mut request, false).unwrap();
            assert_eq!(
                small_put_condition(&request),
                proto::TargetCondition::Absent
            );
        }
    }
    // A grant that replaces records nothing anywhere.
    let authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Replace,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    assert!(authority.lookups.is_none());
}

/// Carry out `request` on `ops`, a connection of `authority`, as a receiver
/// does, and give what it did to the one request it carries.
fn carry_out(
    authority: &RestrictedAuthority,
    ops: &mut crate::fsops::FsOps,
    request: &mut Request,
) -> Result<()> {
    let settlement = authority.authorize(request, false)?;
    let response = ops.handle(request);
    authority.settle(settlement, &response);
    match response {
        proto::Response::Applied(results) if results.len() == 1 => match &results[0] {
            None => Ok(()),
            Some(error) => Err(anyhow::anyhow!("{error:?}")),
        },
        proto::Response::DestinationFilesystemInfo(_) => Ok(()),
        other => Err(anyhow::anyhow!("{other:?}")),
    }
}

/// Keeping existing files on a filesystem without a no-replace rename,
/// nothing was beneath a directory the receiver found empty, found missing
/// or created itself: a file published there is renamed into place
/// unchecked, once, as at a name its own lookup found absent. Beneath a
/// directory it found present, a name it never looked up is held to the
/// strict publication, which refuses one that exists.
///
/// Another program creating a name beneath such a directory, after the
/// receiver looked and before the rename, is the race every copy accepts:
/// that file is replaced, as an ordinary copy would replace it.
#[test]
fn keeping_files_renames_unchecked_beneath_directories_found_empty_or_made() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let mut authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    authority.copy.limits.max_entries = 64;
    assume_lacking(&authority, true, false);
    let mut ops = authority.test_ops();

    // The destination, found empty when the copy asked about it.
    carry_out(
        &authority,
        &mut ops,
        &mut Request::DestinationFilesystemInfo {
            check_empty: true,
            target: None,
        },
    )
    .unwrap();
    // Two publications of one name there: once only, so the second is
    // held to the strict publication, which refuses the name the first
    // took.
    let mut first = small_put_with(&target.join("new"), Absent);
    let mut second = small_put_with(&target.join("new"), Any);
    let first_settlement = authority.authorize(&mut first, false).unwrap();
    let second_settlement = authority.authorize(&mut second, false).unwrap();
    assert_eq!(small_put_condition(&first), Any);
    assert_eq!(small_put_condition(&second), Absent);
    let response = ops.handle(&first);
    authority.settle(first_settlement, &response);
    assert_eq!(fs::read(target.join("new")).unwrap(), b"new");
    let response = ops.handle(&second);
    assert!(
        matches!(&response, proto::Response::Applied(results)
            if matches!(&results[0], Some(error) if error.condition_not_met)),
        "{response:?}"
    );
    authority.settle(second_settlement, &response);

    // A directory this receiver created.
    carry_out(
        &authority,
        &mut ops,
        &mut apply(mkdir(&target.join("made"))),
    )
    .unwrap();
    let mut request = small_put_with(&target.join("made/file"), Absent);
    carry_out(&authority, &mut ops, &mut request).unwrap();
    assert_eq!(small_put_condition(&request), Any);

    // A directory found missing. Another program makes it, and a file in
    // it, after the lookup: the accepted race.
    look_up_for_planner(&authority, &mut ops, &[target.join("missing")]);
    fs::create_dir(target.join("missing")).unwrap();
    fs::write(target.join("missing/theirs"), b"theirs").unwrap();
    let mut request = small_put_with(&target.join("missing/theirs"), Absent);
    carry_out(&authority, &mut ops, &mut request).unwrap();
    assert_eq!(small_put_condition(&request), Any);
    assert_eq!(fs::read(target.join("missing/theirs")).unwrap(), b"new");

    // A directory found present says nothing of the names in it.
    fs::create_dir(target.join("old")).unwrap();
    fs::write(target.join("old/kept"), b"old").unwrap();
    look_up_for_planner(&authority, &mut ops, &[target.join("old")]);
    for name in ["kept", "unlooked"] {
        let mut request = small_put_with(&target.join("old").join(name), Any);
        let result = carry_out(&authority, &mut ops, &mut request);
        assert_eq!(small_put_condition(&request), Absent, "{name}");
        if name == "kept" {
            let error = result.unwrap_err();
            assert!(
                format!("{error:#}").contains("condition_not_met: true"),
                "{error:#}"
            );
        } else {
            result.unwrap();
        }
    }
    assert_eq!(fs::read(target.join("old/kept")).unwrap(), b"old");
}

/// A destination reached through links, which the receiver then holds as
/// its root, is known empty as one named directly is: keeping existing
/// files on a filesystem without a no-replace rename, a new file there is
/// renamed into place, not linked.
#[test]
fn an_empty_destination_reached_through_links_is_known_empty() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let real = root.join("data/real");
    fs::create_dir_all(&real).unwrap();
    let protected = [];
    for follow_dst in [false, true] {
        let link = root.join("target");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&link);
        let published = if follow_dst {
            symlink("data/real", &link).unwrap();
            real.join("new")
        } else {
            fs::create_dir(&link).unwrap();
            link.join("new")
        };
        let _ = fs::remove_file(real.join("new"));
        let mut authority = test_authority_with_options(
            &root,
            DeletionPolicy::Forbid,
            1024,
            0,
            FilterPolicy::default(),
            PublicationPolicy::AtomicStaged,
            ExistingDestinationPolicy::Skip,
            DestinationPlacement::DirectoryContents,
            RootExistence::Any,
            None,
            (
                crate::delegation::ExtraCopyOptions {
                    follow_dst,
                    ..Default::default()
                },
                &protected,
            ),
        )
        .unwrap();
        authority.copy.limits.max_entries = 64;
        assume_lacking(&authority, true, false);
        let mut ops = authority.test_ops();
        carry_out(
            &authority,
            &mut ops,
            &mut Request::DestinationFilesystemInfo {
                check_empty: true,
                target: None,
            },
        )
        .unwrap();
        let mut request = small_put_with(&root.join("target/new"), Absent);
        carry_out(&authority, &mut ops, &mut request).unwrap();
        assert_eq!(
            small_put_condition(&request),
            Any,
            "follow_dst {follow_dst}"
        );
        assert_eq!(fs::read(&published).unwrap(), b"new");
    }
}

/// The record holds a bounded number of names. Past it, a name is not
/// recorded and not given to a publication, which is then held to the
/// strict publication as if the receiver had not looked; names already
/// recorded keep being updated.
#[test]
fn a_full_record_holds_further_names_to_the_strict_publication() {
    use crate::fsops::lookups::{Claim, Looked, PlanningLookups, Recording};
    use proto::TargetCondition::Absent;
    let lookups = PlanningLookups::with_limit(Recording::Keep, 2);
    lookups.record(b"d", Looked::Empty);
    lookups.record(b"a", Looked::Absent);
    lookups.record(b"b", Looked::Absent);
    assert_eq!(lookups.len(), 2);
    assert_eq!(lookups.get(b"b"), None);
    lookups.record(b"a", Looked::Present { file_mode: None });
    assert_eq!(lookups.get(b"a"), Some(Looked::Present { file_mode: None }));
    // Beneath a directory found empty, but no room to remember the claim.
    assert_eq!(lookups.claim(b"d/x"), Claim::Unknown);
    assert_eq!(lookups.len(), 2);

    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let mut authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    authority.copy.limits.max_entries = 64;
    authority.lookups = Some(std::sync::Arc::new(PlanningLookups::with_limit(
        Recording::Keep,
        1,
    )));
    assume_lacking(&authority, true, false);
    let mut ops = authority.test_ops();
    look_up_for_planner(
        &authority,
        &mut ops,
        &[target.join("first"), target.join("second")],
    );
    assert_eq!(authority.lookups.as_ref().unwrap().len(), 1);
    let mut conditions = Vec::new();
    for name in ["first", "second"] {
        let mut request = small_put_with(&target.join(name), Absent);
        carry_out(&authority, &mut ops, &mut request).unwrap();
        conditions.push(small_put_condition(&request));
    }
    // One of the two was recorded and is renamed unchecked; the other is
    // held to the strict publication.
    conditions.sort_by_key(|condition| *condition == Absent);
    assert_eq!(conditions, [proto::TargetCondition::Any, Absent]);
}

/// Keeping existing files on a filesystem without a no-replace rename, the
/// receiver renames a file into place unchecked, with no link, only at a
/// name its own lookup for the planner found absent, and only once.
/// Whatever a sender asks: a name the receiver found present is kept; a
/// second publication of a name, and one at a name the receiver never
/// looked up, are held to the strict publication, which refuses a name
/// that exists.
///
/// Another program creating a name after the receiver found it absent, and
/// before the rename, is the race every copy accepts: that file is
/// replaced, as an ordinary copy would replace it.
#[test]
fn keeping_files_renames_unchecked_only_names_the_receiver_found_absent() {
    use proto::TargetCondition::{Absent, Any};
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    for name in ["present", "unlooked"] {
        fs::write(target.join(name), b"old").unwrap();
    }
    let mut authority = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    authority.copy.limits.max_entries = 64;
    assume_lacking(&authority, true, false);
    let mut ops = authority.test_ops();
    let names = ["present", "absent", "twice", "failed", "raced"];
    let paths: Vec<_> = names.iter().map(|name| target.join(name)).collect();
    look_up_for_planner(&authority, &mut ops, &paths);
    assert_eq!(authority.lookups.as_ref().unwrap().len(), names.len());
    let publish = |ops: &mut crate::fsops::FsOps, request: &mut Request| {
        let settlement = authority.authorize(request, false)?;
        let response = ops.handle(request);
        authority.settle(settlement, &response);
        match response {
            proto::Response::Applied(results) if results.len() == 1 => match &results[0] {
                None => Ok(()),
                Some(error) => Err(anyhow::anyhow!("{error:?}")),
            },
            other => Err(anyhow::anyhow!("{other:?}")),
        }
    };

    // Found present: kept, whatever the sender asks.
    for condition in [Any, Absent] {
        let Err(error) = publish(
            &mut ops,
            &mut small_put_with(&target.join("present"), condition),
        ) else {
            panic!("a file the receiver found was replaced")
        };
        assert!(KeptExisting::is(&error), "{error:#}");
    }
    assert_eq!(fs::read(target.join("present")).unwrap(), b"old");

    // Found absent: renamed into place unchecked.
    let mut request = small_put_with(&target.join("absent"), Absent);
    publish(&mut ops, &mut request).unwrap();
    assert_eq!(small_put_condition(&request), Any);
    let Request::PutSmallBatch(puts) = &request else {
        unreachable!()
    };
    assert_eq!(puts[0].scanned, proto::ScannedDestination::Absent);
    assert_eq!(fs::read(target.join("absent")).unwrap(), b"new");

    // Two publications of one name: the second is held to the strict
    // publication, which refuses the name the first has taken.
    let mut first = small_put_with(&target.join("twice"), Any);
    let mut second = small_put_with(&target.join("twice"), Any);
    let first_settlement = authority.authorize(&mut first, false).unwrap();
    let second_settlement = authority.authorize(&mut second, false).unwrap();
    assert_eq!(small_put_condition(&first), Any);
    assert_eq!(small_put_condition(&second), Absent);
    let response = ops.handle(&first);
    authority.settle(first_settlement, &response);
    let response = ops.handle(&second);
    assert!(
        matches!(&response, proto::Response::Applied(results)
            if matches!(&results[0], Some(error) if error.condition_not_met)),
        "{response:?}"
    );
    authority.settle(second_settlement, &response);

    // A publication that failed has used the name up: another program's
    // file there since is kept.
    let mut request = small_put_with(&target.join("failed"), Any);
    let settlement = authority.authorize(&mut request, false).unwrap();
    authority.settle(
        settlement,
        &proto::Response::Applied(vec![Some(proto::WireError::from("failed"))]),
    );
    fs::write(target.join("failed"), b"theirs").unwrap();
    let mut request = small_put_with(&target.join("failed"), Any);
    let Err(error) = publish(&mut ops, &mut request) else {
        panic!("a used-up lookup let a file be replaced")
    };
    assert!(
        format!("{error:#}").contains("condition_not_met: true"),
        "{error:#}"
    );
    assert_eq!(fs::read(target.join("failed")).unwrap(), b"theirs");

    // Never looked up: held to the strict publication, which refuses the
    // name that exists, whatever the sender asks.
    let mut request = small_put_with(&target.join("unlooked"), Any);
    let Err(error) = publish(&mut ops, &mut request) else {
        panic!("a name the receiver never looked up was replaced")
    };
    assert_eq!(small_put_condition(&request), Absent);
    assert!(
        format!("{error:#}").contains("condition_not_met: true"),
        "{error:#}"
    );
    assert_eq!(fs::read(target.join("unlooked")).unwrap(), b"old");

    // The accepted race: another program's file, created after the
    // lookup found the name absent, is replaced.
    fs::write(target.join("raced"), b"theirs").unwrap();
    publish(&mut ops, &mut small_put_with(&target.join("raced"), Absent)).unwrap();
    assert_eq!(fs::read(target.join("raced")).unwrap(), b"new");
}

/// A grant that creates nothing (`--only-existing`) lets a small file that
/// exists be updated in place, as one it replaces would be, but not a file
/// be created in place.
#[test]
fn must_exist_updates_existing_files_in_place_and_creates_none() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("there"), b"old contents").unwrap();
    let authority = test_authority_with_existence(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlaceUpdate,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    let block = authority.copy.limits.hash_block_bytes;
    let mut patch = small_patch(&target.join("there"), 3, block, vec![None], b"new");
    patch.update_in_place = true;
    authority
        .authorize(&mut Request::PatchSmallBatch(vec![patch]), false)
        .unwrap();
    let mut create = prepare_request(&target.join("new"));
    if let Request::Prepare { inplace, .. } = &mut create {
        *inplace = true;
    }
    assert!(authority.authorize(&mut create, false).is_err());
}

/// A request that shared a file's count settles against the reservation it
/// shared: once that one is published and gone, a newer reservation of the
/// same file and partial keeps its own count.
#[test]
fn a_late_settlement_leaves_a_newer_reservations_count_alone() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    let mut authority = test_authority_with_policy(
        &root,
        DeletionPolicy::Forbid,
        1024,
        0,
        FilterPolicy::default(),
        PublicationPolicy::InPlaceUpdate,
    );
    authority.copy.limits.max_entries = 8;
    let mut ops = authority.test_ops();
    let changes = |authority: &RestrictedAuthority| {
        authority.changes.load(std::sync::atomic::Ordering::Relaxed)
    };
    let path = target.join("file");
    let mut first = prepare_request(&path);
    if let Request::Prepare { size, .. } = &mut first {
        *size = 0;
    }
    let mut late = first.clone();
    let first_settlement = authority.authorize(&mut first, false).unwrap();
    let late_settlement = authority.authorize(&mut late, false).unwrap();
    let response = ops.handle(&first);
    authority.settle(first_settlement, &response);
    let mut publish = finalize_request(&path, proto::TargetCondition::Any);
    let settlement = authority.authorize(&mut publish, false).unwrap();
    let response = ops.handle(&publish);
    authority.settle(settlement, &response);
    assert!(path.exists());
    assert_eq!(changes(&authority), 1);
    // The same file and partial prepared again: a new change.
    let mut again = first.clone();
    let _again = authority.authorize(&mut again, false).unwrap();
    assert_eq!(changes(&authority), 2);
    // The late request found its condition unmet: its share was of the
    // published file's reservation, which is gone.
    authority.settle(
        late_settlement,
        &proto::Response::EndpointError(proto::WireError {
            condition_not_met: true,
            ..proto::WireError::from("gone")
        }),
    );
    assert_eq!(changes(&authority), 2);
}

/// What a publication replaces, the receiver tells itself without a look
/// where it knows: nothing, for a new name held to replace nothing, or what
/// its own lookup for the planner found. A sender's word is never taken.
#[test]
fn publications_tell_the_receiver_what_they_replace_where_the_authority_knows() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    let target = root.join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("scanned"), b"old").unwrap();
    fs::set_permissions(target.join("scanned"), fs::Permissions::from_mode(0o640)).unwrap();
    let scanned_of = |request: &Request| match request {
        Request::PutSmallBatch(puts) => puts[0].scanned,
        _ => unreachable!(),
    };
    let claimed = |path: &Path| {
        let mut request = small_put(path);
        if let Request::PutSmallBatch(puts) = &mut request {
            // What a sender might claim, which is never taken.
            puts[0].scanned = proto::ScannedDestination::File(0o4777);
        }
        request
    };
    let keep = existence_authority(
        &root,
        ExistingDestinationPolicy::Skip,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    let mut request = claimed(&target.join("new"));
    keep.authorize(&mut request, false).unwrap();
    assert_eq!(scanned_of(&request), proto::ScannedDestination::Absent);

    let update = existence_authority(
        &root,
        ExistingDestinationPolicy::MustExist,
        DestinationPlacement::DirectoryContents,
        RootExistence::Any,
    )
    .unwrap();
    assume_lacking(&update, false, true);
    look_up_for_planner(&update, &mut update.test_ops(), &[target.join("scanned")]);
    let mut request = claimed(&target.join("scanned"));
    update.authorize(&mut request, false).unwrap();
    assert_eq!(scanned_of(&request), proto::ScannedDestination::File(0o640));
}

/// A restricted receiver keeps existing files atomically: it refuses to be
/// told it may rename kept files into place unchecked.
#[test]
fn restricted_receivers_refuse_unchecked_keeps() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("target")).unwrap();
    let authority = test_authority(&root, DeletionPolicy::Forbid, 1024);
    let mut request = Request::ConfigurePreservation {
        selection: Default::default(),
        sparse: false,
        destination: true,
        narrow_new_directories: false,
        own_links: false,
        skips_unmet_conditions: true,
        unchecked_keep: true,
    };
    let Err(error) = authority.authorize(&mut request, false) else {
        panic!("an unchecked keep was authorized")
    };
    assert!(
        format!("{error:#}").contains("keeps existing files atomically"),
        "{error:#}"
    );
}
