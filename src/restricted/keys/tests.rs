//! Signing with the login key and verifying in Rust: key files, agent keys
//! (including encrypted ones), FIDO keys through an agent, and certificate
//! logins, with the probe that catches keys which cannot sign.
use super::*;
use crate::process::CommandExt as _;
use ssh_agent_lib::proto::{Identity, PublicCredential, Request, Response};
use ssh_agent_lib::ssh_encoding::{Decode as _, Encode as _};
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

const NAMESPACE: &str = delegation::SSHSIG_NAMESPACE;

fn now() -> i64 {
    super::super::now().unwrap()
}

/// The `ssh -vvv` lines that matter for a login with `name`, its key file
/// or an agent key's comment.
pub(crate) fn trace(name: &str, key: &PublicKey, certificate: bool) -> String {
    let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256);
    let algorithm = if certificate {
        format!("{}-cert-v01@openssh.com", key.algorithm().as_str())
    } else {
        key.algorithm().as_str().to_owned()
    };
    format!(
        "debug1: Remote protocol version 2.0, remote software version OpenSSH_9.2p1 Debian-2+deb12u3\n\
         debug1: Server accepts key: {name} KEY {fingerprint} explicit agent\n\
         debug3: sign_and_send_pubkey: signing using {algorithm} {fingerprint}\n\
         Authenticated to fixture ([127.0.0.1]:22) using \"publickey\".\n"
    )
}

fn run(command: &mut Command, action: &str) {
    let output = command
        .stdin(Stdio::null())
        .capture_output()
        .unwrap_or_else(|error| panic!("{action}: {error}"));
    assert!(
        output.status.success(),
        "{action}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `ssh-keygen` makes the key files: the files OpenSSH itself writes.
fn keygen(path: &Path, kind: &str, bits: Option<&str>, passphrase: &str) {
    let mut command = Command::new("ssh-keygen");
    command
        .args([
            "-q",
            "-t",
            kind,
            "-C",
            "syq-test-login",
            "-N",
            passphrase,
            "-f",
        ])
        .arg(path);
    if let Some(bits) = bits {
        command.args(["-b", bits]);
    }
    run(&mut command, "generate a test login key");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// A disposable `ssh-agent`, with an askpass program for passphrases.
struct Agent {
    directory: tempfile::TempDir,
    socket: PathBuf,
    group: crate::process_group::ProcessGroup,
}

impl Agent {
    fn start() -> Self {
        let directory = crate::test_support::short_tempdir().unwrap();
        let socket = directory.path().join("a");
        let mut command = Command::new("ssh-agent");
        command
            .args(["-D", "-a"])
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut group = crate::process_group::ProcessGroup::spawn(&mut command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(
                Instant::now() < deadline && group.poll().unwrap().is_none(),
                "test ssh-agent did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        crate::test_support::write_executable(
            &directory.path().join("askpass"),
            b"#!/bin/sh\nprintf '%s\\n' fixture-unlock\n",
            0o700,
        );
        Self {
            directory,
            socket,
            group,
        }
    }

    fn ssh_add(&self, arguments: &[&std::ffi::OsStr]) -> bool {
        Command::new("ssh-add")
            .args(arguments)
            .env("SSH_AUTH_SOCK", &self.socket)
            .env("SSH_ASKPASS", self.directory.path().join("askpass"))
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "fixture")
            .stdin(Stdio::null())
            .capture_output()
            .unwrap()
            .status
            .success()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.group.close();
    }
}

#[test]
fn key_files_sign_grants_that_only_the_trusted_key_verifies() {
    let mut rng = ssh_key::rand_core::OsRng;
    let other = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    for key in [
        PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap(),
        PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap(),
        PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
        )
        .unwrap(),
        PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP521,
            },
        )
        .unwrap(),
        ssh_key::private::RsaKeypair::random(&mut rng, 2048)
            .unwrap()
            .into(),
    ] {
        let algorithm = key.algorithm();
        let trusted = TrustedSigner::new(key.public_key(), None, None).unwrap();
        let signer = LoginSigner::File(Box::new(key));
        let signature = signer.sign(NAMESPACE, b"grant").unwrap();
        trusted
            .verify(NAMESPACE, b"grant", &signature, now())
            .unwrap_or_else(|error| panic!("{algorithm}: {error:#}"));
        assert!(trusted
            .verify(NAMESPACE, b"other grant", &signature, now())
            .is_err());
        // A signature in another namespace is never a grant's.
        let probe = signer.sign(PROBE_NAMESPACE, b"grant").unwrap();
        let error = trusted
            .verify(NAMESPACE, b"grant", &probe, now())
            .unwrap_err();
        assert!(error.to_string().contains("another purpose"), "{error:#}");
        let untrusted = TrustedSigner::new(other.public_key(), None, None).unwrap();
        assert!(untrusted
            .verify(NAMESPACE, b"grant", &signature, now())
            .is_err());
        if algorithm.is_rsa() {
            assert_eq!(
                ssh_key::SshSig::from_pem(&signature).unwrap().algorithm(),
                Algorithm::Rsa {
                    hash: Some(ssh_key::HashAlg::Sha512)
                }
            );
        }
    }
}

#[test]
fn rsa_login_keys_over_4096_bits_sign_and_verify_and_small_ones_are_refused() {
    let agent = Agent::start();
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let large = directory.path().join("large");
    keygen(&large, "rsa", Some("5120"), "");
    let public = PublicKey::read_openssh_file(&large.with_extension("pub")).unwrap();
    let name = large.to_str().unwrap();
    // From the key file.
    let login = discover(&trace(name, &public, false), b"", None, b"probe", "backup").unwrap();
    assert!(matches!(login.signer, LoginSigner::File(_)));
    let signature = login.signer.sign(NAMESPACE, b"grant").unwrap();
    login
        .trusted
        .verify(NAMESPACE, b"grant", &signature, now())
        .unwrap();
    assert!(login
        .trusted
        .verify(NAMESPACE, b"other grant", &signature, now())
        .is_err());
    // Through the agent.
    assert!(agent.ssh_add(&[large.as_os_str()]));
    let login = discover(
        &trace(name, &public, false),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .unwrap();
    assert!(matches!(login.signer, LoginSigner::Agent { .. }));
    let signature = login.signer.sign(NAMESPACE, b"grant").unwrap();
    login
        .trusted
        .verify(NAMESPACE, b"grant", &signature, now())
        .unwrap();
    // Under 2,048 bits, refused with a clear message before anything else.
    let small = directory.path().join("small");
    keygen(&small, "rsa", Some("1024"), "");
    let small_public = PublicKey::read_openssh_file(&small.with_extension("pub")).unwrap();
    let error = discover(
        &trace(small.to_str().unwrap(), &small_public, false),
        b"",
        None,
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(
        format!("{error:#}").contains("at least 2048 bits"),
        "{error:#}"
    );
}

#[test]
fn discovery_signs_with_an_unencrypted_key_file_and_records_it() {
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("id_ed25519");
    keygen(&path, "ed25519", None, "");
    let public = PublicKey::read_openssh_file(&path.with_extension("pub")).unwrap();
    for name in [path.clone(), path.with_extension("pub")] {
        let login = discover(
            &trace(name.to_str().unwrap(), &public, false),
            b"",
            None,
            b"probe",
            "backup",
        )
        .unwrap();
        assert!(matches!(login.signer, LoginSigner::File(_)));
        assert_eq!(login.identity_file.as_deref(), Some(path.as_path()));
        assert_eq!(login.trusted.key().unwrap().key_data(), public.key_data());
        assert_eq!(login.trusted.security_key_flags, None);
        assert_eq!(login.trusted.valid_before, None);
        // Later copies find the same signer through the recorded file.
        assert!(matches!(
            LoginSigner::find(&login.trusted, None, Some(&path), now()).unwrap(),
            Some(LoginSigner::File(_))
        ));
    }
    // A key file others can read is not used.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(discover(
        &trace(path.to_str().unwrap(), &public, false),
        b"",
        None,
        b"p",
        "backup"
    )
    .is_err());
    assert!(LoginSigner::find(
        &TrustedSigner::new(&public, None, None).unwrap(),
        None,
        Some(&path),
        now()
    )
    .unwrap()
    .is_none());
}

#[test]
fn encrypted_keys_sign_through_the_agent_and_fail_clearly_without_it() {
    let agent = Agent::start();
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for (kind, bits) in [
        ("ed25519", None),
        ("rsa", Some("2048")),
        ("ecdsa", Some("384")),
    ] {
        let path = directory.path().join(kind);
        keygen(&path, kind, bits, "fixture-unlock");
        let public = PublicKey::read_openssh_file(&path.with_extension("pub")).unwrap();
        let name = path.to_str().unwrap();
        // Not in the agent: the passphrase is not syq's to ask for.
        let error = discover(
            &trace(name, &public, false),
            b"",
            Some(&agent.socket),
            b"p",
            "backup",
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("ssh-add"), "{kind}: {error:#}");
        assert!(agent.ssh_add(&[path.as_os_str()]), "{kind}: ssh-add failed");
        let login = discover(
            &trace(name, &public, false),
            b"",
            Some(&agent.socket),
            b"p",
            "backup",
        )
        .unwrap();
        assert!(matches!(login.signer, LoginSigner::Agent { .. }), "{kind}");
        assert_eq!(login.identity_file, None, "{kind}");
        let signature = login.signer.sign(NAMESPACE, b"grant").unwrap();
        login
            .trusted
            .verify(NAMESPACE, b"grant", &signature, now())
            .unwrap_or_else(|error| panic!("{kind}: {error:#}"));
        // Later copies find it in the agent; once it leaves the agent, the
        // login key must be found again.
        assert!(matches!(
            LoginSigner::find(&login.trusted, Some(&agent.socket), None, now()).unwrap(),
            Some(LoginSigner::Agent { .. })
        ));
        assert!(agent.ssh_add(&["-d".as_ref(), path.with_extension("pub").as_os_str()]));
        assert!(
            LoginSigner::find(&login.trusted, Some(&agent.socket), None, now())
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn an_unreachable_agent_is_reported_rather_than_replaced() {
    let directory = crate::test_support::short_tempdir().unwrap();
    let missing = directory.path().join("no-agent");
    let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let trusted = TrustedSigner::new(key.public_key(), None, None).unwrap();
    let error = LoginSigner::find(&trusted, Some(&missing), None, now())
        .err()
        .expect("an unreachable agent must not look like a key that cannot sign");
    assert!(
        format!("{error:#}").contains("cannot use the SSH agent"),
        "{error:#}"
    );
    // The key's own file still signs.
    let path = directory.path().join("key");
    fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        LoginSigner::find(&trusted, Some(&missing), Some(&path), now()).unwrap(),
        Some(LoginSigner::File(_))
    ));
    // No agent configured at all: only that the key cannot sign.
    assert!(LoginSigner::find(&trusted, None, None, now())
        .unwrap()
        .is_none());
}

#[test]
fn agent_only_keys_sign_and_keys_limited_to_logins_are_refused() {
    let agent = Agent::start();
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("key");
    keygen(&path, "ed25519", None, "");
    let public = PublicKey::read_openssh_file(&path.with_extension("pub")).unwrap();
    assert!(agent.ssh_add(&[path.as_os_str()]));
    // The agent reports the key by its comment, and syq has no file for it:
    // a PIV or PKCS#11 key looks the same.
    fs::remove_file(&path).unwrap();
    let login = discover(
        &trace("syq-test-login", &public, false),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .unwrap();
    assert!(matches!(login.signer, LoginSigner::Agent { .. }));
    assert_eq!(login.identity_file, None);

    // `ssh-add -h` limits a key to logins at named hosts: the probe fails
    // before anything is installed.
    let limited = directory.path().join("limited");
    keygen(&limited, "ed25519", None, "");
    let limited_public = PublicKey::read_openssh_file(&limited.with_extension("pub")).unwrap();
    let host = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let known_hosts = directory.path().join("known_hosts");
    fs::write(
        &known_hosts,
        format!(
            "example.invalid {}\n",
            host.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    assert!(agent.ssh_add(&[
        "-H".as_ref(),
        known_hosts.as_os_str(),
        "-h".as_ref(),
        "nobody@example.invalid".as_ref(),
        limited.as_os_str()
    ]));
    fs::remove_file(&limited).unwrap();
    let error = discover(
        &trace("syq-test-login", &limited_public, false),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("ssh-add -h"), "{error:#}");

    // A key that is nowhere to be found.
    let missing = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let error = discover(
        &trace("/nonexistent/key", missing.public_key(), false),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("cannot find the key"),
        "{error:#}"
    );
}

#[test]
fn certificate_logins_trust_the_key_until_the_certificate_expires() {
    let agent = Agent::start();
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let ca = directory.path().join("ca");
    keygen(&ca, "ed25519", None, "");
    for (label, in_agent) in [("agent", true), ("file", false)] {
        let path = directory.path().join(label);
        keygen(&path, "ed25519", None, "");
        run(
            Command::new("ssh-keygen")
                .args(["-q", "-s"])
                .arg(&ca)
                .args(["-I", "syq-test", "-n", "backup", "-V", "-1m:+1h"])
                .arg(path.with_extension("pub")),
            "certify the test login key",
        );
        let certificate_path = PathBuf::from(format!("{}-cert.pub", path.display()));
        let certificate = ssh_key::Certificate::from_openssh(
            fs::read_to_string(&certificate_path).unwrap().trim(),
        )
        .unwrap();
        let public = PublicKey::new(certificate.public_key().clone(), "");
        if in_agent {
            // ssh-add loads the key and the certificate beside it.
            assert!(agent.ssh_add(&[path.as_os_str()]));
            fs::remove_file(&path).unwrap();
        }
        let login = discover(
            &trace(certificate_path.to_str().unwrap(), &public, true),
            b"",
            Some(&agent.socket),
            b"probe",
            "backup",
        )
        .unwrap_or_else(|error| panic!("{label}: {error:#}"));
        // The certificate's key signs, and the trusted key carries its expiry.
        assert_eq!(login.trusted.key().unwrap().key_data(), public.key_data());
        assert_eq!(login.trusted.valid_before, Some(certificate.valid_before()));
        let signature = login.signer.sign(NAMESPACE, b"grant").unwrap();
        login
            .trusted
            .verify(NAMESPACE, b"grant", &signature, now())
            .unwrap();
        let expired = certificate.valid_before() as i64;
        let error = login
            .trusted
            .verify(NAMESPACE, b"grant", &signature, expired)
            .unwrap_err();
        assert!(error.to_string().contains("expired"), "{error:#}");
        // An expired certificate means finding the login key again.
        assert!(LoginSigner::find(
            &login.trusted,
            Some(&agent.socket),
            login.identity_file.as_deref(),
            expired
        )
        .unwrap()
        .is_none());
        assert!(LoginSigner::find(
            &login.trusted,
            Some(&agent.socket),
            login.identity_file.as_deref(),
            now()
        )
        .unwrap()
        .is_some());
    }
    // A certificate login whose certificate syq cannot find is refused
    // rather than trusted without its expiry.
    let path = directory.path().join("lost");
    keygen(&path, "ed25519", None, "");
    let public = PublicKey::read_openssh_file(&path.with_extension("pub")).unwrap();
    let error = discover(
        &trace(path.to_str().unwrap(), &public, true),
        b"",
        None,
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("certificate"), "{error:#}");
}

/// Certify `public_key` as `principal` for `validity`, with extra
/// `ssh-keygen -O` options.
fn certify(ca: &Path, public_key: &Path, principal: &str, validity: &str, options: &[&str]) {
    let mut command = Command::new("ssh-keygen");
    command
        .args(["-q", "-s"])
        .arg(ca)
        .args(["-I", "fixture", "-n", principal, "-V", validity]);
    for option in options {
        command.args(["-O", option]);
    }
    run(command.arg(public_key), "certify the test key");
}

#[test]
fn certificate_expiry_comes_from_the_certificate_that_logged_in() {
    // Reviewer reproducer: a one-hour login must not record a one-year
    // expiry from another principal's certificate for the same key.
    let agent = Agent::start();
    let directory = crate::test_support::tempdir().unwrap();
    let ca = directory.path().join("ca");
    let path = directory.path().join("identity");
    keygen(&ca, "ed25519", None, "");
    keygen(&path, "ed25519", None, "");
    let public_path = path.with_extension("pub");
    certify(&ca, &public_path, "backup", "-1m:+1h", &[]);
    let certificate_path = directory.path().join("identity-cert.pub");
    let authenticated_path = directory.path().join("authenticated-cert.pub");
    fs::copy(&certificate_path, &authenticated_path).unwrap();
    let authenticated = read_certificate(&authenticated_path).unwrap();
    assert!(agent.ssh_add(&[path.as_os_str()]));
    certify(&ca, &public_path, "unrelated-account", "-1m:+52w", &[]);
    assert!(agent.ssh_add(&[path.as_os_str()]));
    let public = PublicKey::new(authenticated.public_key().clone(), "");
    let name = authenticated_path.to_str().unwrap();
    let login = discover(
        &trace(name, &public, true),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .unwrap();
    assert_eq!(
        login.trusted.valid_before,
        Some(authenticated.valid_before()),
        "an unrelated certificate in the agent must not extend this login's authority"
    );

    // An expired certificate, or one not valid yet, left in the agent is
    // never the one recorded.
    for validity in ["-2h:-1h", "+1h:+52w"] {
        certify(&ca, &public_path, "backup", validity, &[]);
        assert!(agent.ssh_add(&[path.as_os_str()]));
    }
    let login = discover(
        &trace(name, &public, true),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .unwrap();
    assert_eq!(
        login.trusted.valid_before,
        Some(authenticated.valid_before())
    );

    // Two valid certificates for the login account that disagree are
    // ambiguous: syq refuses rather than guess.
    certify(&ca, &public_path, "backup", "-1m:+2h", &[]);
    assert!(agent.ssh_add(&[path.as_os_str()]));
    let error = discover(
        &trace(name, &public, true),
        b"",
        Some(&agent.socket),
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("cannot tell which one"),
        "{error:#}"
    );

    // Only expired certificates: refused with a clear message.
    let lone = directory.path().join("lone");
    keygen(&lone, "ed25519", None, "");
    certify(&ca, &lone.with_extension("pub"), "backup", "-2h:-1h", &[]);
    let lone_certificate = directory.path().join("lone-cert.pub");
    let lone_public = PublicKey::read_openssh_file(&lone.with_extension("pub")).unwrap();
    let error = discover(
        &trace(lone_certificate.to_str().unwrap(), &lone_public, true),
        b"",
        None,
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("currently valid certificate"),
        "{error:#}"
    );
}

#[test]
fn fido_certificates_keep_their_touch_and_pin_requirements() {
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let ca = directory.path().join("ca");
    keygen(&ca, "ed25519", None, "");
    let ca_public = fs::read_to_string(ca.with_extension("pub")).unwrap();
    let handle = directory.path().join("identity");
    let key = security_key(SK_USER_PRESENCE);
    atomic_write(
        directory.path(),
        "identity",
        key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    let certificate_path = directory.path().join("identity-cert.pub");
    // (certificate options, the authority's line, flags the authenticator
    // signs with, the policy recorded)
    for (options, line, signing, expected) in [
        // Reviewer reproducer: the certificate's verify-required survives.
        (&["verify-required"][..], "", 5, 5),
        (&["verify-required"][..], "cert-authority", 5, 5),
        // A PIN on the authority's line alone applies too.
        (&[][..], "cert-authority,verify-required", 5, 5),
        // No touch needs both the certificate and the line to allow it.
        (&["no-touch-required"][..], "cert-authority", 1, 1),
        (&[][..], "cert-authority,no-touch-required", 1, 1),
        (
            &["no-touch-required"][..],
            "cert-authority,no-touch-required",
            1,
            1,
        ),
    ] {
        fs::write(
            handle.with_extension("pub"),
            key.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        let _ = fs::remove_file(&certificate_path);
        certify(
            &ca,
            &handle.with_extension("pub"),
            "backup",
            "-1m:+1h",
            options,
        );
        let certificate = read_certificate(&certificate_path).unwrap();
        let authorized = if line.is_empty() {
            String::new()
        } else {
            format!("{line} {ca_public}")
        };
        let (_agent, socket) = security_key_agent(key.public_key().clone(), signing);
        let login = discover(
            &trace(certificate_path.to_str().unwrap(), key.public_key(), true),
            authorized.as_bytes(),
            Some(&socket),
            b"probe",
            "backup",
        )
        .unwrap_or_else(|error| panic!("{options:?} {line:?}: {error:#}"));
        assert_eq!(
            login.trusted.security_key_flags,
            Some(expected),
            "{options:?} {line:?}"
        );
        assert_eq!(login.trusted.valid_before, Some(certificate.valid_before()));
    }
    // With the handle's own flags not requiring touch, the merged policy
    // decides: both must allow skipping it.
    let untouched = security_key(0);
    atomic_write(
        directory.path(),
        "identity",
        untouched.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        0o600,
    )
    .unwrap();
    for (options, line, expected) in [
        (&["no-touch-required"][..], "cert-authority", 1),
        (
            &["no-touch-required"][..],
            "cert-authority,no-touch-required",
            0,
        ),
    ] {
        let _ = fs::remove_file(&certificate_path);
        certify(
            &ca,
            &handle.with_extension("pub"),
            "backup",
            "-1m:+1h",
            options,
        );
        let (_agent, socket) = security_key_agent(untouched.public_key().clone(), expected);
        let login = discover(
            &trace(
                certificate_path.to_str().unwrap(),
                untouched.public_key(),
                true,
            ),
            format!("{line} {ca_public}").as_bytes(),
            Some(&socket),
            b"probe",
            "backup",
        )
        .unwrap_or_else(|error| panic!("{options:?} {line:?}: {error:#}"));
        assert_eq!(login.trusted.security_key_flags, Some(expected), "{line:?}");
    }
}

/// A FIDO key whose signatures carry `flags`, as an OpenSSH key handle.
fn security_key(flags: u8) -> PrivateKey {
    let pair = ssh_key::private::Ed25519Keypair::from_seed(&[73; 32]);
    let public = ssh_key::public::SkEd25519::new(pair.public, "ssh:");
    ssh_key::private::SkEd25519::new(public, flags, vec![1, 2, 3])
        .unwrap()
        .into()
}

/// A FIDO signature over `data` by `security_key`, with `flags`.
fn security_key_signature(flags: u8, data: &[u8]) -> ssh_key::Signature {
    use sha2::Digest as _;
    use signature::Signer as _;
    let pair = ssh_key::private::Ed25519Keypair::from_seed(&[73; 32]);
    let mut signed = sha2::Sha256::digest(b"ssh:").to_vec();
    signed.push(flags);
    signed.extend_from_slice(&1u32.to_be_bytes());
    signed.extend_from_slice(&sha2::Sha256::digest(data));
    let mut bytes = pair.try_sign(&signed).unwrap().as_bytes().to_vec();
    bytes.push(flags);
    bytes.extend_from_slice(&1u32.to_be_bytes());
    ssh_key::Signature::new(Algorithm::SkEd25519, bytes).unwrap()
}

/// An agent holding `key` that signs as an authenticator would, with the
/// touch and PIN flags `flags`; OpenSSH's own agent and the lab's FIDO
/// provider are covered by the real-SSH lab.
fn security_key_agent(key: PublicKey, flags: u8) -> (tempfile::TempDir, PathBuf) {
    let directory = crate::test_support::short_tempdir().unwrap();
    let socket = directory.path().join("a");
    let listener = UnixListener::bind(&socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            while let Ok(Some(frame)) = crate::agent_broker::read_frame(&mut stream) {
                let response = match Request::decode(&mut frame.as_slice()) {
                    Ok(Request::RequestIdentities) => Response::IdentitiesAnswer(vec![Identity {
                        credential: PublicCredential::Key(key.key_data().clone()),
                        comment: "fido".into(),
                    }]),
                    Ok(Request::SignRequest(request)) => {
                        Response::SignResponse(security_key_signature(flags, &request.data))
                    }
                    _ => Response::Failure,
                };
                let mut encoded = Vec::new();
                response.encode(&mut encoded).unwrap();
                if crate::agent_broker::write_frame(&mut stream, &encoded).is_err() {
                    break;
                }
            }
        }
    });
    (directory, socket)
}

#[test]
fn security_key_policy_comes_from_the_line_the_handle_or_the_probe() {
    let directory = crate::test_support::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let handle = directory.path().join("id_ed25519_sk");
    let public = security_key(0).public_key().clone();
    let line = |options: &str| {
        format!(
            "{options}{}{} user@laptop\n",
            if options.is_empty() { "" } else { " " },
            public.to_openssh().unwrap()
        )
    };
    // (handle flags if syq can read the handle, line options, the flags the
    // authenticator signs with, the policy recorded or None if refused)
    for (handle_flags, options, signing, expected) in [
        (Some(1), "", 1, Some(1)),
        (Some(5), "", 5, Some(5)),
        (Some(0), "no-touch-required", 0, Some(0)),
        (Some(4), "no-touch-required", 4, Some(4)),
        (Some(0), "no-touch-required,verify-required", 4, Some(4)),
        // Agent-only keys and encrypted handles: the probe's flags.
        (None, "", 1, Some(1)),
        (None, "", 5, Some(5)),
        (None, "no-touch-required", 0, Some(0)),
        (None, "verify-required", 5, Some(5)),
        // The probe lacks the PIN or touch the policy requires.
        (None, "verify-required", 1, None),
        (None, "", 0, None),
    ] {
        match handle_flags {
            Some(flags) => atomic_write(
                directory.path(),
                "id_ed25519_sk",
                security_key(flags)
                    .to_openssh(LineEnding::LF)
                    .unwrap()
                    .as_bytes(),
                0o600,
            )
            .unwrap(),
            None => {
                let _ = fs::remove_file(&handle);
            }
        }
        let (_agent, socket) = security_key_agent(public.clone(), signing);
        let label = format!("{handle_flags:?} {options:?} {signing}");
        let result = discover(
            &trace(handle.to_str().unwrap(), &public, false),
            line(options).as_bytes(),
            Some(&socket),
            b"probe",
            "backup",
        );
        match (result, expected) {
            (Ok(login), Some(expected)) => {
                assert_eq!(login.trusted.security_key_flags, Some(expected), "{label}");
                assert!(matches!(login.signer, LoginSigner::Agent { .. }), "{label}");
                // Grants carry the flags the authenticator gives them.
                let signature = login.signer.sign(NAMESPACE, b"grant").unwrap();
                login
                    .trusted
                    .verify(NAMESPACE, b"grant", &signature, now())
                    .unwrap_or_else(|error| panic!("{label}: {error:#}"));
            }
            (Err(error), None) => assert!(error.to_string().contains("FIDO"), "{label}: {error:#}"),
            (result, _) => panic!("{label}: {:?}", result.map(|login| login.trusted)),
        }
    }
    // A FIDO key works only through the agent.
    atomic_write(
        directory.path(),
        "id_ed25519_sk",
        security_key(1)
            .to_openssh(LineEnding::LF)
            .unwrap()
            .as_bytes(),
        0o600,
    )
    .unwrap();
    let error = discover(
        &trace(handle.to_str().unwrap(), &public, false),
        line("").as_bytes(),
        None,
        b"probe",
        "backup",
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("FIDO"), "{error:#}");
    // Two lines for the key leave its policy ambiguous.
    let (_agent, socket) = security_key_agent(public.clone(), 5);
    assert!(discover(
        &trace(handle.to_str().unwrap(), &public, false),
        format!("{}{}", line(""), line("verify-required")).as_bytes(),
        Some(&socket),
        b"probe",
        "backup"
    )
    .is_err());
}

#[test]
fn security_key_grants_without_the_recorded_touch_or_pin_are_refused() {
    let public = security_key(0).public_key().clone();
    for (required, signed, accepted) in [
        (1, 1, true),
        (1, 0, false),
        (5, 5, true),
        (5, 1, false),
        (5, 4, false),
        (4, 4, true),
        (0, 0, true),
    ] {
        let (_agent, socket) = security_key_agent(public.clone(), signed);
        let signer = LoginSigner::Agent {
            socket,
            key: public.clone(),
        };
        let signature = signer.sign(NAMESPACE, b"grant").unwrap();
        let trusted = TrustedSigner::new(&public, Some(required), None).unwrap();
        assert_eq!(
            trusted
                .verify(NAMESPACE, b"grant", &signature, now())
                .is_ok(),
            accepted,
            "{required} {signed}"
        );
    }
}

/// A FIDO ECDSA key, with the software key that stands in for its
/// authenticator.
fn security_ecdsa_key() -> (PrivateKey, PublicKey) {
    let software = PrivateKey::random(
        &mut ssh_key::rand_core::OsRng,
        Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let ssh_key::public::EcdsaPublicKey::NistP256(point) =
        *software.public_key().key_data().ecdsa().unwrap()
    else {
        unreachable!()
    };
    let key = PublicKey::new(
        ssh_key::public::SkEcdsaSha2NistP256::new(point, "ssh:").into(),
        "",
    );
    (software, key)
}

/// Regression: ssh-key 0.6.7 writes a FIDO ECDSA signature's flags and
/// counter inside its signature string (see `delegation::armored_sshsig`).
/// A grant signed through the agent with such a key must still verify.
#[test]
fn fido_ecdsa_grants_signed_through_the_agent_verify() {
    use sha2::Digest as _;
    use signature::Signer as _;
    use ssh_agent_lib::ssh_encoding::Encode as _;
    let (software, key) = security_ecdsa_key();
    let flags = SK_USER_PRESENCE | SK_USER_VERIFICATION;
    let directory = crate::test_support::short_tempdir().unwrap();
    let socket = directory.path().join("a");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let frame = crate::agent_broker::read_frame(&mut stream)
            .unwrap()
            .unwrap();
        let Ok(Request::SignRequest(request)) = Request::decode(&mut frame.as_slice()) else {
            panic!("expected a signing request");
        };
        let mut signed = sha2::Sha256::digest(b"ssh:").to_vec();
        signed.push(flags);
        signed.extend_from_slice(&9u32.to_be_bytes());
        signed.extend_from_slice(&sha2::Sha256::digest(&request.data));
        let ecdsa: ssh_key::Signature = software.try_sign(&signed).unwrap();
        // The authenticator's signature as OpenSSH's agent sends it: the
        // flags and counter follow the signature string.
        let mut blob = Vec::new();
        "sk-ecdsa-sha2-nistp256@openssh.com"
            .encode(&mut blob)
            .unwrap();
        ecdsa.as_bytes().encode(&mut blob).unwrap();
        blob.push(flags);
        blob.extend_from_slice(&9u32.to_be_bytes());
        let mut response = vec![14];
        blob.encode(&mut response).unwrap();
        crate::agent_broker::write_frame(&mut stream, &response).unwrap();
    });
    let signer = LoginSigner::Agent {
        socket,
        key: key.clone(),
    };
    let armored = signer.sign(NAMESPACE, b"grant").unwrap();
    worker.join().unwrap();
    let decoded = ssh_key::SshSig::from_pem(&armored).unwrap();
    assert_eq!(decoded.algorithm(), Algorithm::SkEcdsaSha2NistP256);
    assert_eq!(delegation::security_key_flags(&decoded).unwrap(), flags);
    TrustedSigner::new(&key, Some(flags), None)
        .unwrap()
        .verify(NAMESPACE, b"grant", &armored, now())
        .unwrap();
}

#[test]
fn only_key_logins_on_openssh_7_2_or_later_can_enroll() {
    let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    let login = trace("/tmp/key with spaces", key.public_key(), false);
    let found = login_from_trace(&login).unwrap();
    assert_eq!(found.name.as_deref(), Some("/tmp/key with spaces"));
    assert!(!found.certificate);
    assert!(login_from_trace(login.split("Authenticated to ").next().unwrap()).is_err());
    for method in [
        "password",
        "keyboard-interactive",
        "gssapi-with-mic",
        "hostbased",
    ] {
        let error =
            login_from_trace(&login.replace("using \"publickey\"", &format!("using \"{method}\"")))
                .unwrap_err();
        assert!(error.to_string().contains(method), "{error}");
        assert!(error.to_string().contains("--auth-from"), "{error}");
    }
    let error = login_from_trace(&format!(
        "Authenticated using publickey with partial success.\n{login}"
    ))
    .unwrap_err();
    assert!(error.to_string().contains("second factor"), "{error}");

    require_openssh_server(&login).unwrap();
    for (software, accepted) in [
        ("OpenSSH_7.2p2 Ubuntu-4ubuntu2.10", true),
        ("OpenSSH_7.1p1", false),
        ("OpenSSH_6.6.1p1 Ubuntu-2ubuntu2", false),
        ("OpenSSH_10.0", true),
        ("dropbear_2022.83", false),
    ] {
        let trace =
            format!("debug1: Remote protocol version 2.0, remote software version {software}\n");
        assert_eq!(
            require_openssh_server(&trace).is_ok(),
            accepted,
            "{software}"
        );
    }
    assert!(require_openssh_server("no version here\n").is_err());
}

#[test]
fn entry_keys_follow_the_login_algorithm_and_stay_software_keys() {
    let mut rng = ssh_key::rand_core::OsRng;
    let id = EnrollmentId::random();
    let ecdsa = |curve| {
        PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ecdsa { curve })
            .unwrap()
            .public_key()
            .clone()
    };
    for (login, expected) in [
        (
            PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .clone(),
            Algorithm::Ed25519,
        ),
        (security_key(1).public_key().clone(), Algorithm::Ed25519),
        (
            ecdsa(ssh_key::EcdsaCurve::NistP384),
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
        ),
    ] {
        let entry = generate_entry_key(&login, id).unwrap();
        assert_eq!(entry.algorithm(), expected);
        assert_ne!(entry.public_key().key_data(), login.key_data());
        validate_entry_public_key(entry.public_key()).unwrap();
        let encoded = entry.to_openssh(LineEnding::LF).unwrap();
        assert_eq!(
            parse_entry_key(encoded.as_bytes()).unwrap().public_key(),
            entry.public_key()
        );
    }
    // RSA keeps the login key's size and never goes below 3,072 bits.
    let rsa: PrivateKey = ssh_key::private::RsaKeypair::random(&mut rng, 2048)
        .unwrap()
        .into();
    let entry = generate_entry_key(rsa.public_key(), id).unwrap();
    let modulus = entry
        .public_key()
        .key_data()
        .rsa()
        .unwrap()
        .n
        .as_positive_bytes()
        .unwrap()
        .len();
    assert_eq!(modulus * 8, 3072);
    // An entry key is never a FIDO handle or encrypted.
    assert!(parse_entry_key(
        security_key(1)
            .to_openssh(LineEnding::LF)
            .unwrap()
            .as_bytes()
    )
    .is_err());
    let directory = crate::test_support::tempdir().unwrap();
    let encrypted = directory.path().join("encrypted");
    keygen(&encrypted, "ed25519", None, "passphrase");
    assert!(parse_entry_key(&fs::read(&encrypted).unwrap()).is_err());
}

#[test]
fn signing_and_verifying_start_no_program() {
    const CHILD: &str = "SYQ_TEST_NO_PROGRAM_CHILD";
    if let Some(marker) = std::env::var_os(CHILD) {
        let marker = PathBuf::from(marker);
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let trusted = TrustedSigner::new(key.public_key(), None, None).unwrap();
        let signature = LoginSigner::File(Box::new(key))
            .sign(NAMESPACE, b"grant")
            .unwrap();
        trusted
            .verify(NAMESPACE, b"grant", &signature, now())
            .unwrap();
        let (_agent, socket) = security_key_agent(security_key(5).public_key().clone(), 5);
        let signer = LoginSigner::Agent {
            socket,
            key: security_key(5).public_key().clone(),
        };
        let signature = signer.sign(NAMESPACE, b"grant").unwrap();
        TrustedSigner::new(signer.public_key(), Some(5), None)
            .unwrap()
            .verify(NAMESPACE, b"grant", &signature, now())
            .unwrap();
        assert!(!marker.exists(), "a program was started");
        return;
    }
    let directory = crate::test_support::tempdir().unwrap();
    let bin = directory.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let marker = directory.path().join("started");
    for program in ["ssh-keygen", "ssh-add", "ssh-agent", "ssh"] {
        crate::test_support::write_executable(
            &bin.join(program),
            format!("#!/bin/sh\necho \"$0\" >> '{}'\nexit 1\n", marker.display()),
            0o700,
        );
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "restricted::keys::tests::signing_and_verifying_start_no_program",
            "--nocapture",
        ])
        .env(CHILD, &marker)
        .env("PATH", &bin)
        .capture_output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists());
}
