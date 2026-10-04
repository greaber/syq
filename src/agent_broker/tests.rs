use super::*;
use signature::{Signer, Verifier};
use ssh_agent_lib::proto::{Extension, Request};
use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
use std::sync::mpsc;
use std::time::Instant;

const TEST_BROKER_CONNECTIONS: usize = 4;

fn key(seed: u8) -> (Ed25519Keypair, KeyData) {
    let keypair = Ed25519Keypair::from_seed(&[seed; 32]);
    let public = KeyData::Ed25519(keypair.public);
    (keypair, public)
}

fn host_policy(user: &str, name: &str, key: KeyData) -> HostPolicy {
    let algorithm = key.algorithm().as_str().to_string();
    HostPolicy {
        login_user: user.into(),
        connection_host: name.into(),
        port: 22,
        host_keys: vec![key],
        known_hosts_name: name.into(),
        host_key_algorithms: vec![algorithm],
        required_rsa_size: 1024,
    }
}

fn policy(coordinator: KeyData, peer: KeyData) -> BrokerPolicy {
    BrokerPolicy::new(
        host_policy("source-user", "source", coordinator),
        host_policy("backup", "destination", peer),
    )
}

fn binding(keypair: &Ed25519Keypair, key: KeyData, id: &[u8], forwarding: bool) -> SessionBind {
    SessionBind {
        host_key: key,
        session_id: id.to_vec(),
        signature: keypair.try_sign(id).unwrap(),
        is_forwarding: forwarding,
    }
}

fn encode_request(request: Request) -> Vec<u8> {
    let mut encoded = Vec::new();
    request.encode(&mut encoded).unwrap();
    encoded
}

fn bind_request(binding: SessionBind) -> Vec<u8> {
    encode_request(Request::Extension(Extension::new_message(binding).unwrap()))
}

fn ssh_string_len_at(bytes: &[u8], offset: usize) -> usize {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize
}

fn hostbound_data(
    session_id: &[u8],
    user: &[u8],
    method: &[u8],
    credential: &ssh_agent_lib::proto::PublicCredential,
    host_key: &KeyData,
) -> Vec<u8> {
    let mut credential_blob = Vec::new();
    credential.encode(&mut credential_blob).unwrap();
    let mut host_key_blob = Vec::new();
    host_key.encode(&mut host_key_blob).unwrap();
    let mut data = Vec::new();
    session_id.encode(&mut data).unwrap();
    data.push(50);
    for value in [user, b"ssh-connection", method] {
        value.encode(&mut data).unwrap();
    }
    data.push(1);
    let algorithm = match credential {
        PublicCredential::Key(key) => key.algorithm().as_str().to_string(),
        PublicCredential::Cert(certificate) => certificate.algorithm().to_certificate_type(),
    };
    algorithm.as_bytes().encode(&mut data).unwrap();
    credential_blob.as_slice().encode(&mut data).unwrap();
    host_key_blob.as_slice().encode(&mut data).unwrap();
    data
}

fn sign_request(
    session_id: &[u8],
    user: &[u8],
    method: &[u8],
    identity: KeyData,
    host_key: &KeyData,
) -> SignRequest {
    sign_request_for_credential(session_id, user, method, identity.into(), host_key)
}

fn sign_request_for_credential(
    session_id: &[u8],
    user: &[u8],
    method: &[u8],
    credential: PublicCredential,
    host_key: &KeyData,
) -> SignRequest {
    let data = hostbound_data(session_id, user, method, &credential, host_key);
    SignRequest {
        credential,
        data,
        flags: 0,
    }
}

fn read_response(stream: &mut UnixStream) -> Response {
    let frame = read_frame(stream).unwrap().unwrap();
    let mut input = frame.as_slice();
    let response = Response::decode(&mut input).unwrap();
    assert!(input.is_empty());
    response
}

fn assert_closed(stream: &mut UnixStream) {
    match crate::test_support::read_until_closed(stream, Duration::from_secs(1)) {
        Ok(bytes) if bytes.is_empty() => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("agent connection was not closed: {other:?}"),
    }
}

fn fake_ambient(
    socket: &Path,
    identity: Ed25519Keypair,
) -> (JoinHandle<()>, mpsc::Receiver<Vec<u8>>) {
    let listener = UnixListener::bind(socket).unwrap();
    let (sent, received) = mpsc::channel();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        while let Some(frame) = read_frame(&mut stream).unwrap() {
            sent.send(frame.clone()).unwrap();
            let response = match frame.first() {
                Some(27) => Response::ExtensionFailure,
                Some(11) => Response::IdentitiesAnswer(vec![Identity {
                    credential: KeyData::Ed25519(identity.public).into(),
                    comment: "ambient comment stays local".into(),
                }]),
                Some(13) => {
                    let request = parse_sign_request(&frame).unwrap();
                    Response::SignResponse(identity.try_sign(&request.data).unwrap())
                }
                other => panic!("unexpected upstream request {other:?}"),
            };
            let mut response_frame = Vec::new();
            response.encode(&mut response_frame).unwrap();
            write_frame(&mut stream, &response_frame).unwrap();
        }
    });
    (worker, received)
}

#[test]
fn parses_effective_host_lookup_and_files() {
    let output = b"host alias\nuser backup\nhostname vault.internal\nport 2222\nuserknownhostsfile /tmp/default-one /tmp/default-two\nglobalknownhostsfile none\nhostkeyalgorithms ssh-ed25519,rsa-sha2-512\nrequiredrsasize 3072\n";
    let defaults = KnownHostsDefaults {
        user: KnownHostsDefault {
            rendered: "/tmp/default-one /tmp/default-two".into(),
            files: vec!["/tmp/default-one".into(), "/tmp/default-two".into()],
        },
        global: KnownHostsDefault {
            rendered: "none".into(),
            files: Vec::new(),
        },
    };
    let config =
        parse_ssh_config_with_defaults(output, Some(&defaults), &KnownHostsConfigured::default())
            .unwrap();
    assert_eq!(config.user, "backup");
    assert_eq!(config.lookup, "[vault.internal]:2222");
    assert_eq!(config.required_rsa_size, 3072);
    assert_eq!(
        config.files,
        [
            PathBuf::from("/tmp/default-one"),
            PathBuf::from("/tmp/default-two")
        ]
    );
}

#[test]
fn ambiguous_or_relative_known_hosts_filenames_fail_closed() {
    for value in ["/tmp/known hosts", "/tmp/one /tmp/two", "relative-hosts"] {
        let output = format!(
                "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile {value}\nglobalknownhostsfile none\nhostkeyalgorithms ssh-ed25519\n"
            );
        let error = parse_ssh_config(output.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("known_hosts"),
            "unexpected error for {value:?}: {error:#}"
        );
    }
}

#[test]
fn configured_value_identical_to_flattened_defaults_fails_closed() {
    let rendered = "/home/grant/.ssh/known_hosts /home/grant/.ssh/known_hosts2";
    let output = format!(
            "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile {rendered}\nglobalknownhostsfile none\nhostkeyalgorithms ssh-ed25519\n"
        );
    let defaults = KnownHostsDefaults {
        user: KnownHostsDefault {
            rendered: rendered.into(),
            files: vec![
                "/home/grant/.ssh/known_hosts".into(),
                "/home/grant/.ssh/known_hosts2".into(),
            ],
        },
        global: KnownHostsDefault {
            rendered: "none".into(),
            files: Vec::new(),
        },
    };
    let error = parse_ssh_config_with_defaults(
        output.as_bytes(),
        Some(&defaults),
        &KnownHostsConfigured {
            user: true,
            global: false,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("ambiguous known_hosts"));
}

#[test]
fn configuration_failure_keeps_ssh_error_without_debug_trace() {
    let root = crate::test_support::tempdir().unwrap();
    let ssh = root.path().join("ssh");
    // Write in a child so parallel test forks cannot inherit an executable's
    // writable descriptor and cause ETXTBSY when this fixture is launched.
    let written = Command::new("sh")
        .args([
            "-c",
            "printf '%s' \"$1\" > \"$2\"",
            "write-ssh",
            "#!/bin/sh\nprintf '%s\n' 'OpenSSH_9.6p1, OpenSSL 3.0.13' 'debug1: Reading configuration data /private/config' 'debug2: checking match' '/private/config line 7: Bad configuration option: misspelled' 'debug3: final pass' >&2\nexit 255\n",
        ])
        .arg(&ssh)
        .capture_output()
        .unwrap();
    assert!(
        written.status.success(),
        "{}",
        String::from_utf8_lossy(&written.stderr)
    );
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = inspect_ssh_configuration(ssh.to_str().unwrap(), None, "host.invalid", false)
        .err()
        .expect("configuration failure");
    assert_eq!(
        error.to_string(),
        "could not inspect SSH configuration for host.invalid: /private/config line 7: Bad configuration option: misspelled"
    );
}

#[test]
fn configured_known_hosts_provenance_uses_files_openssh_read() {
    let temp = crate::test_support::tempdir().unwrap();
    let config = temp.path().join("ssh_config");
    std::fs::write(
            &config,
            b"# GlobalKnownHostsFile /ignored/comment\nHost *\n  UserKnownHostsFile=\"/tmp/known hosts\"\n",
        )
        .unwrap();
    let debug = format!(
        "OpenSSH test\ndebug1: Reading configuration data {}\n",
        config.display()
    );
    let paths = ssh_configuration_paths(debug.as_bytes()).unwrap();
    let configured = configured_known_hosts_directives(&paths).unwrap();
    assert!(configured.user);
    assert!(!configured.global);
}

#[test]
fn openssh_quoted_default_collision_is_rejected_end_to_end() {
    let defaults_output = inspect_ssh_configuration("ssh", None, "unused.example", true).unwrap();
    let defaults = KnownHostsDefaults::from_openssh(&defaults_output.output).unwrap();
    assert!(!defaults.user.rendered.contains(['"', '\\', '\n', '\r']));

    let temp = crate::test_support::tempdir().unwrap();
    let config = temp.path().join("ssh_config");
    std::fs::write(
        &config,
        format!(
            "Host *\n  UserKnownHostsFile \"{}\"\n",
            defaults.user.rendered
        ),
    )
    .unwrap();
    let output = Command::new("ssh")
        .args(["-G", "-vvv", "-F"])
        .arg(&config)
        .args(["--", "unused.example"])
        .env("LC_ALL", "C")
        .capture_output()
        .unwrap();
    assert!(
        output.status.success(),
        "ssh -G failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let paths = ssh_configuration_paths(&output.stderr).unwrap();
    let configured = configured_known_hosts_directives(&paths).unwrap();
    assert!(configured.user);
    let error =
        parse_ssh_config_with_defaults(&output.stdout, Some(&defaults), &configured).unwrap_err();
    assert!(error.to_string().contains("ambiguous known_hosts"));
}

#[test]
fn unrelated_literal_known_hosts_options_preserve_real_default_lists() {
    let defaults_output = inspect_ssh_configuration("ssh", None, "unused.example", true).unwrap();
    let defaults = KnownHostsDefaults::from_openssh(&defaults_output.output).unwrap();
    let temp = crate::test_support::tempdir().unwrap();
    let config = temp.path().join("ssh_config");
    std::fs::write(&config, b"Host unrelated.example\n  UserKnownHostsFile /tmp/private-known-hosts\n  GlobalKnownHostsFile=/dev/null\n").unwrap();
    let output = Command::new("ssh")
        .args(["-G", "-vvv", "-F"])
        .arg(&config)
        .args(["--", "unused.example"])
        .env("LC_ALL", "C")
        .capture_output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let paths = ssh_configuration_paths(&output.stderr).unwrap();
    let configured = configured_known_hosts_directives(&paths).unwrap();
    assert!(!configured.user && !configured.global);
    let parsed =
        parse_ssh_config_with_defaults(&output.stdout, Some(&defaults), &configured).unwrap();
    let mut expected = defaults.user.files;
    expected.extend(defaults.global.files);
    expected.sort();
    expected.dedup();
    assert_eq!(parsed.files, expected);
    for uncertain in [
        b"UserKnownHostsFile \"/tmp/a /tmp/b\"".as_slice(),
        b"UserKnownHostsFile /tmp/a\\ /tmp/b",
        b"UserKnownHostsFile ~/.ssh/known_hosts",
        b"UserKnownHostsFile ${HOME}/.ssh/known_hosts",
        b"UserKnownHostsFile /tmp/%h",
    ] {
        assert!(contains_ambiguous_known_hosts_directive(
            uncertain,
            b"userknownhostsfile"
        ));
    }
}

#[test]
fn pre_required_rsa_size_config_uses_historical_default() {
    let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\n",
        )
        .unwrap();
    assert_eq!(config.required_rsa_size, 1024);
}

#[test]
fn host_key_alias_is_used_verbatim() {
    let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 2222\nhostkeyalias stable-vault\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nrequiredrsasize 1024\n",
        )
        .unwrap();
    assert_eq!(config.lookup, "stable-vault");
}

#[test]
fn dynamic_and_external_revocation_host_policies_fail_closed() {
    for policy in [
        "knownhostscommand /usr/local/bin/known-host %h",
        "revokedhostkeys /etc/ssh/revoked.krl",
    ] {
        let config = format!(
                "user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-ed25519\nrequiredrsasize 1024\n{policy}\n"
            );
        let error = parse_ssh_config(config.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("constrained agent forwarding"));
    }
}

#[test]
fn host_key_algorithms_and_required_rsa_size_are_enforced() {
    use ssh_agent_lib::ssh_key::{public::RsaPublicKey, Mpint};

    let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms rsa-sha2-512\nrequiredrsasize 3072\n",
        )
        .unwrap();
    let rsa = KeyData::Rsa(RsaPublicKey {
        e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
        n: Mpint::from_positive_bytes(&[0x80; 256]).unwrap(),
    });
    assert!(!configured_host_key_allowed(&config, &rsa));
    let mut config = config;
    config.required_rsa_size = 2048;
    assert!(configured_host_key_allowed(&config, &rsa));
    let (_, ed25519) = key(50);
    assert!(!configured_host_key_allowed(&config, &ed25519));
}

#[test]
fn exported_host_algorithms_only_name_admitted_keys_and_preserve_rsa_policy() {
    use ssh_agent_lib::ssh_key::{public::RsaPublicKey, Mpint};

    let (_, ed25519) = key(80);
    let mut policy = host_policy("backup", "vault", ed25519);
    policy.host_key_algorithms = [
        "ssh-ed25519-cert-v01@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-512",
        "ssh-ed25519",
    ]
    .map(str::to_owned)
    .to_vec();
    assert_eq!(policy.host_key_algorithms(), "ssh-ed25519");
    policy.host_keys.push(KeyData::Rsa(RsaPublicKey {
        e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
        n: Mpint::from_positive_bytes(&[0x80; 256]).unwrap(),
    }));
    assert_eq!(policy.host_key_algorithms(), "rsa-sha2-512,ssh-ed25519");
    assert!(!policy.host_key_algorithms().contains("rsa-sha2-256"));
}

#[test]
fn pinned_host_fingerprints_are_sorted_unique_and_use_actual_keys() {
    let (_, first) = key(81);
    let (_, second) = key(82);
    let mut policy = host_policy("backup", "vault", first.clone());
    policy.host_keys.extend([second.clone(), first.clone()]);
    let fingerprints = policy.pinned_host_key_fingerprints();
    let mut expected = [first, second]
        .map(|key| {
            PublicKey::new(key, "")
                .fingerprint(ssh_agent_lib::ssh_key::HashAlg::Sha256)
                .to_string()
        })
        .to_vec();
    expected.sort_unstable();
    assert_eq!(fingerprints, expected);
    assert!(fingerprints
        .iter()
        .all(|value| value.starts_with("SHA256:")));
    policy.host_keys.reverse();
    assert_eq!(policy.pinned_host_key_fingerprints(), fingerprints);
}

#[test]
fn unsupported_opaque_algorithms_are_not_trusted() {
    use ssh_agent_lib::ssh_key::public::{OpaquePublicKey, SkEd25519};

    let unsupported = KeyData::Other(OpaquePublicKey::new(
        vec![1, 2, 3],
        Algorithm::new("ssh-mldsa44-ed25519@openssh.com").unwrap(),
    ));
    assert!(!key_is_cryptographically_verifiable(&unsupported));
    let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 22\nuserknownhostsfile /tmp/known\nhostkeyalgorithms ssh-mldsa44-ed25519@openssh.com\n",
        )
        .unwrap();
    assert!(!configured_host_key_allowed(&config, &unsupported));
    let (supported_private, supported) = key(60);
    assert!(key_is_cryptographically_verifiable(&supported));
    assert!(signature_algorithm_is_cryptographically_verifiable(
        &Algorithm::Ed25519
    ));
    assert!(!signature_algorithm_is_cryptographically_verifiable(
        &Algorithm::Rsa { hash: None }
    ));
    let fido = KeyData::SkEd25519(SkEd25519::new(supported_private.public, "ssh:".to_string()));
    assert!(key_is_cryptographically_verifiable(&fido));
}

#[test]
fn known_hosts_parser_keeps_plain_keys_and_tracks_ca_and_revocation() {
    let (_, plain) = key(51);
    let (_, revoked_key) = key(52);
    let plain_text = PublicKey::new(plain.clone(), "").to_openssh().unwrap();
    let revoked_text = PublicKey::new(revoked_key.clone(), "")
        .to_openssh()
        .unwrap();
    let text = format!(
        "host {plain_text}\n@cert-authority host {plain_text}\n@revoked host {revoked_text}\n"
    );
    let mut trusted = Vec::new();
    let mut revoked = Vec::new();
    let mut saw_ca = false;
    parse_known_host_output(
        &text,
        Path::new("known_hosts"),
        &mut trusted,
        &mut revoked,
        &mut saw_ca,
    )
    .unwrap();
    assert_eq!(trusted, [plain]);
    assert_eq!(revoked, [revoked_key]);
    assert!(saw_ca);
    assert!(parse_known_host_output(
        &format!("@unknown host {plain_text}\n"),
        Path::new("known_hosts"),
        &mut trusted,
        &mut revoked,
        &mut saw_ca,
    )
    .is_err());
}

#[test]
fn openssh_defaults_and_hashed_known_hosts_lookup_are_exercised() {
    let output = inspect_ssh_configuration("ssh", None, "unused.example", true).unwrap();
    let defaults = KnownHostsDefaults::from_openssh(&output.output).unwrap();
    assert_eq!(defaults.user.files.len(), 2);
    assert!(defaults.user.files.iter().all(|path| path.is_absolute()));
    assert!(defaults.global.files.iter().all(|path| path.is_absolute()));

    let temp = crate::test_support::tempdir().unwrap();
    let known_hosts = temp.path().join("known_hosts");
    let lookup = "[vault.internal]:2222";
    let (_, host_key) = key(53);
    let public = PublicKey::new(host_key.clone(), "").to_openssh().unwrap();
    std::fs::write(&known_hosts, format!("{lookup} {public}\n")).unwrap();
    let status = Command::new("ssh-keygen")
        .args(["-q", "-H", "-f"])
        .arg(&known_hosts)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status_guarded()
        .expect("hash test known_hosts entry");
    assert!(status.success(), "ssh-keygen known_hosts hashing failed");

    let (trusted, saw_ca) = read_known_host_keys(
        &ssh_keygen_for("ssh"),
        lookup,
        std::slice::from_ref(&known_hosts),
    )
    .unwrap();
    assert_eq!(trusted, [host_key]);
    assert!(!saw_ca);
}

#[test]
fn policy_deadline_interrupts_real_openssh_match_exec() {
    let temp = crate::test_support::tempdir().unwrap();
    let config = temp.path().join("ssh_config");
    let ssh = temp.path().join("ssh");
    let marker = temp.path().join("match-started");
    std::fs::write(
        &config,
        format!(
            "Match exec \"touch {}; sleep 30\"\n  User backup\n",
            shell_words::quote(marker.to_str().unwrap()),
        ),
    )
    .unwrap();
    std::fs::write(
        &ssh,
        format!(
            "#!/bin/sh\nexec ssh -F {} \"$@\"\n",
            shell_words::quote(config.to_str().unwrap()),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let error = resolve_host_policy_at_bounded(
        ssh.to_str().unwrap(),
        None,
        "unused.example",
        None,
        started + Duration::from_millis(300),
        &|| false,
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(marker.exists(), "OpenSSH did not reach Match exec");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn known_host_search_obeys_deadline_and_cancellation() {
    let temp = crate::test_support::tempdir().unwrap();
    let known_hosts = temp.path().join("known_hosts");
    let keygen = temp.path().join("ssh-keygen");
    std::fs::write(&known_hosts, "").unwrap();
    std::fs::write(&keygen, "#!/bin/sh\nexec sleep 30\n").unwrap();
    std::fs::set_permissions(&keygen, std::fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let error = read_known_host_keys_bounded(
        &keygen.clone().into_os_string(),
        "vault",
        std::slice::from_ref(&known_hosts),
        started + Duration::from_millis(100),
        &|| false,
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    let error = read_known_host_keys_bounded(
        &keygen.into_os_string(),
        "vault",
        &[known_hosts],
        Instant::now() + Duration::from_secs(5),
        &|| true,
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn resolved_host_policy_uses_real_openssh_and_ssh_keygen() {
    let temp = crate::test_support::tempdir().unwrap();
    let known_hosts = temp.path().join("known_hosts");
    let config = temp.path().join("ssh_config");
    let ssh = temp.path().join("ssh");
    let ssh_keygen = temp.path().join("ssh-keygen");
    let (_, host_key) = key(54);
    let public = PublicKey::new(host_key.clone(), "").to_openssh().unwrap();
    std::fs::write(
        &known_hosts,
        format!("stable-vault {public}\n[literal]:2200 {public}\n"),
    )
    .unwrap();
    std::fs::write(
            &config,
            format!(
                "Host vault\n  User backup\n  HostName vault.internal\n  Port 2222\n  HostKeyAlias stable-vault\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile none\n  HostKeyAlgorithms ssh-ed25519\n  IdentityFile none\nHost literal\n  User backup\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile none\n  HostKeyAlgorithms ssh-ed25519\n",
                known_hosts.display(), known_hosts.display()
            ),
        )
        .unwrap();
    let quoted_config = shell_words::quote(config.to_str().unwrap());
    std::fs::write(
            &ssh,
            format!(
                "#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = /dev/null ]; then exec ssh \"$@\"; fi\ndone\nexec ssh -F {quoted_config} \"$@\"\n"
            ),
        )
        .unwrap();
    std::fs::write(&ssh_keygen, "#!/bin/sh\nexec ssh-keygen \"$@\"\n").unwrap();
    for program in [&ssh, &ssh_keygen] {
        std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let resolved = resolve_host_policy(ssh.to_str().unwrap(), None, "vault").unwrap();
    assert_eq!(resolved.login_user, "backup");
    assert_eq!(resolved.connection_host(), "vault.internal");
    assert_eq!(resolved.port(), 2222);
    assert_eq!(resolved.known_hosts_name, "stable-vault");
    assert_eq!(resolved.host_keys, [host_key]);
    let overridden =
        resolve_host_policy_at(ssh.to_str().unwrap(), None, "vault", Some(2200)).unwrap();
    assert_eq!(overridden.port(), 2200);
    assert_eq!(overridden.known_hosts_name, "stable-vault");
    // The requester chooses a different login, while provider trust still
    // comes from its own alias and port rather than the requester route.
    let account = resolve_account_trust_bounded(
        ssh.to_str().unwrap(),
        "requester-user",
        "vault",
        None,
        Instant::now() + POLICY_TIMEOUT,
        &|| false,
    )
    .unwrap();
    assert_eq!(account.login_user, "requester-user");
    assert_eq!(account.connection_host(), "vault.internal");
    assert_eq!(account.port(), 2222);
    assert_eq!(account.known_hosts_name, "stable-vault");
    assert_eq!(account.host_keys, overridden.host_keys);
    let literal = resolve_account_trust_bounded(
        ssh.to_str().unwrap(),
        "requester-user",
        "literal",
        Some(2200),
        Instant::now() + POLICY_TIMEOUT,
        &|| false,
    )
    .unwrap();
    assert_eq!(literal.known_hosts_name, "[literal]:2200");
    assert_eq!(literal.login_user, "requester-user");
    assert_eq!(literal.host_keys, account.host_keys);
}

#[test]
fn resolved_policy_exports_only_keys_above_laptop_rsa_minimum() {
    use ssh_agent_lib::ssh_key::{public::RsaPublicKey, Mpint};
    let temp = crate::test_support::tempdir().unwrap();
    let known_hosts = temp.path().join("known_hosts");
    let config = temp.path().join("config");
    let ssh = temp.path().join("ssh");
    let rsa = |bytes| {
        KeyData::Rsa(RsaPublicKey {
            e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(),
            n: Mpint::from_positive_bytes(&vec![0x80; bytes]).unwrap(),
        })
    };
    let small = rsa(256);
    let large = rsa(512);
    let public = |key| PublicKey::new(key, "").to_openssh().unwrap();
    std::fs::write(
        &known_hosts,
        format!("vault {}\nvault {}\n", public(small), public(large.clone())),
    )
    .unwrap();
    std::fs::write(
        &config,
        format!("UserKnownHostsFile {}\n", known_hosts.display()),
    )
    .unwrap();
    // Supply the laptop's effective policy without making this regression
    // depend on the test machine supporting the newer OpenSSH directive.
    std::fs::write(&ssh, format!(
        "#!/bin/sh\nconfiguration={}\nfor arg in \"$@\"; do if [ \"$arg\" = /dev/null ]; then exec ssh \"$@\"; fi; done\necho \"debug1: Reading configuration data $configuration\" >&2\nprintf '%s\\n' 'user backup' 'hostname vault' 'port 22' {} 'globalknownhostsfile none' 'hostkeyalgorithms rsa-sha2-512' 'requiredrsasize 3072'\n",
        shell_words::quote(config.to_str().unwrap()),
        shell_words::quote(&format!("userknownhostsfile {}", known_hosts.display())),
    )).unwrap();
    let keygen = temp.path().join("ssh-keygen");
    std::fs::write(&keygen, "#!/bin/sh\nexec ssh-keygen \"$@\"\n").unwrap();
    for program in [&ssh, &keygen] {
        std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let policy = resolve_host_policy(ssh.to_str().unwrap(), None, "vault").unwrap();
    assert_eq!(policy.host_keys.as_slice(), std::slice::from_ref(&large));
    assert_eq!(
        policy.known_hosts("syq-copy-peer").unwrap(),
        format!("syq-copy-peer {}\n", public(large))
    );
}

#[test]
fn signature_algorithm_and_flags_must_match_key_blob() {
    let mut rsa = Vec::new();
    b"ssh-rsa".as_slice().encode(&mut rsa).unwrap();
    rsa.extend_from_slice(b"key fields are irrelevant here");
    validate_signature_algorithm(b"rsa-sha2-512", &rsa, 4).unwrap();
    assert!(validate_signature_algorithm(b"rsa-sha2-256", &rsa, 4).is_err());
    assert!(validate_signature_algorithm(b"ssh-rsa", &rsa, 0).is_err());
    assert!(validate_signature_algorithm(b"ssh-ed25519", &rsa, 0).is_err());
}

#[test]
fn hostbound_parser_rejects_trailing_or_obsolete_data() {
    let mut data = Vec::new();
    b"session".as_slice().encode(&mut data).unwrap();
    data.push(50);
    for value in [
        b"user".as_slice(),
        b"ssh-connection".as_slice(),
        b"publickey".as_slice(),
    ] {
        value.encode(&mut data).unwrap();
    }
    data.push(1);
    for value in [
        b"ssh-ed25519".as_slice(),
        b"key".as_slice(),
        b"host".as_slice(),
    ] {
        value.encode(&mut data).unwrap();
    }
    let parsed = HostboundUserauth::parse(&data).unwrap();
    assert_eq!(parsed.method, b"publickey");
    data.push(0);
    assert!(HostboundUserauth::parse(&data).is_err());
}

#[test]
fn bind_state_rejects_bad_signatures_wrong_hosts_and_extra_hops() {
    let (source_private, source) = key(1);
    let (destination_private, destination) = key(2);
    let (other_private, other) = key(3);
    let policy = policy(source.clone(), destination.clone());

    let mut disallowed_algorithm = policy.clone();
    disallowed_algorithm
        .coordinator
        .as_mut()
        .unwrap()
        .host_key_algorithms = vec!["rsa-sha2-512".into()];
    assert!(BindState::default()
        .add(
            &disallowed_algorithm,
            binding(
                &source_private,
                source.clone(),
                b"disallowed-algorithm",
                true,
            ),
        )
        .is_err());

    let mut state = BindState::default();
    assert!(state
        .add(
            &policy,
            binding(&other_private, source.clone(), b"bad-signature", true)
        )
        .is_err());
    assert!(state
        .add(
            &policy,
            binding(&other_private, other.clone(), b"wrong-source", true)
        )
        .is_err());
    state
        .add(
            &policy,
            binding(&source_private, source, b"source-session", true),
        )
        .unwrap();
    let error = state
        .add(
            &policy,
            binding(&other_private, other.clone(), b"wrong-destination", false),
        )
        .unwrap_err();
    assert!(error.to_string().contains("trusted peer"), "{error:#}");
    state
        .add(
            &policy,
            binding(
                &destination_private,
                destination,
                b"destination-session",
                false,
            ),
        )
        .unwrap();
    assert!(state
        .add(&policy, binding(&other_private, other, b"third-hop", true))
        .is_err());
}

#[test]
fn authorization_is_exact_for_user_session_host_and_method() {
    let (source_private, source) = key(11);
    let (destination_private, destination) = key(12);
    let (_, identity) = key(13);
    let (_, other_host) = key(14);
    let policy = policy(source.clone(), destination.clone());
    let mut state = BindState::default();
    state
        .add(
            &policy,
            binding(&source_private, source, b"source-session", true),
        )
        .unwrap();
    state
        .add(
            &policy,
            binding(
                &destination_private,
                destination.clone(),
                b"destination-session",
                false,
            ),
        )
        .unwrap();

    let allowed = sign_request(
        b"destination-session",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        identity.clone(),
        &destination,
    );
    state.authorize(&policy, &allowed, false).unwrap();
    for denied in [
        sign_request(
            b"other-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity.clone(),
            &destination,
        ),
        sign_request(
            b"destination-session",
            b"root",
            b"publickey-hostbound-v00@openssh.com",
            identity.clone(),
            &destination,
        ),
        sign_request(
            b"destination-session",
            b"backup",
            b"publickey",
            identity.clone(),
            &destination,
        ),
        sign_request(
            b"destination-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &other_host,
        ),
    ] {
        assert!(state.authorize(&policy, &denied, false).is_err());
    }
}

#[test]
fn direct_authorization_requires_the_exact_peer_and_login_without_forwarding() {
    let (peer_private, peer) = key(101);
    let (other_private, other) = key(102);
    let (_, identity) = key(103);
    let policy = BrokerPolicy::direct(host_policy("backup", "destination", peer.clone()));
    let allowed = sign_request(
        b"direct-session",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        identity.clone(),
        &peer,
    );
    assert!(BindState::default()
        .authorize(&policy, &allowed, false)
        .is_err());
    for denied in [
        binding(&peer_private, peer.clone(), b"direct-session", true),
        binding(&other_private, other.clone(), b"direct-session", false),
        binding(&other_private, peer.clone(), b"direct-session", false),
    ] {
        assert!(BindState::default().add(&policy, denied).is_err());
    }
    let mut state = BindState::default();
    state
        .add(
            &policy,
            binding(&peer_private, peer.clone(), b"direct-session", false),
        )
        .unwrap();
    state.authorize(&policy, &allowed, false).unwrap();
    for denied in [
        sign_request(
            b"other-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity.clone(),
            &peer,
        ),
        sign_request(
            b"direct-session",
            b"root",
            b"publickey-hostbound-v00@openssh.com",
            identity.clone(),
            &peer,
        ),
        sign_request(
            b"direct-session",
            b"backup",
            b"publickey",
            identity.clone(),
            &peer,
        ),
        sign_request(
            b"direct-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &other,
        ),
    ] {
        assert!(state.authorize(&policy, &denied, false).is_err());
    }
    assert!(state
        .add(
            &policy,
            binding(&peer_private, peer, b"extra-session", false)
        )
        .is_err());
}

fn user_certificate(key: KeyData) -> PublicCredential {
    let (ca, _) = self::key(199);
    let mut builder =
        ssh_agent_lib::ssh_key::certificate::Builder::new(vec![0; 16], key, 0, u32::MAX.into())
            .unwrap();
    builder.valid_principal("backup").unwrap();
    PublicCredential::Cert(Box::new(builder.sign(&PrivateKey::from(ca)).unwrap()))
}

#[test]
fn ambient_certificate_keeps_exact_account_host_and_key_binding() {
    let (peer_private, peer) = key(101);
    let (_, identity) = key(103);
    let (_, other) = key(104);
    let policy = BrokerPolicy::direct(host_policy("backup", "destination", peer.clone()));
    let mut state = BindState::default();
    state
        .add(
            &policy,
            binding(&peer_private, peer.clone(), b"certificate-session", false),
        )
        .unwrap();
    let certificate = user_certificate(identity.clone());
    let request = SignRequest {
        credential: identity.clone().into(),
        data: hostbound_data(
            b"certificate-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            &certificate,
            &peer,
        ),
        flags: 0,
    };
    state.authorize(&policy, &request, true).unwrap();
    assert!(state.authorize(&policy, &request, false).is_err());
    for (user, cert, host) in [
        (b"root".as_slice(), certificate.clone(), peer.clone()),
        (b"backup", user_certificate(other.clone()), peer.clone()),
        (b"backup", certificate.clone(), other),
    ] {
        let mut changed = request.clone();
        changed.data = hostbound_data(
            b"certificate-session",
            user,
            b"publickey-hostbound-v00@openssh.com",
            &cert,
            &host,
        );
        assert!(state.authorize(&policy, &changed, true).is_err());
    }
    let mut encoded = Vec::new();
    certificate.encode(&mut encoded).unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    assert!(!certificate_matches_signing_key(&encoded, &identity).unwrap());
    encoded[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(certificate_matches_signing_key(&encoded, &identity).is_err());
    let (ca, _) = key(199);
    let mut builder = ssh_agent_lib::ssh_key::certificate::Builder::new(
        vec![0; 16],
        identity.clone(),
        0,
        u32::MAX.into(),
    )
    .unwrap();
    builder.valid_principal("backup").unwrap();
    builder
        .cert_type(ssh_agent_lib::ssh_key::certificate::CertType::Host)
        .unwrap();
    let mut host_cert = Vec::new();
    PublicCredential::Cert(Box::new(builder.sign(&PrivateKey::from(ca)).unwrap()))
        .encode(&mut host_cert)
        .unwrap();
    assert!(!certificate_matches_signing_key(&host_cert, &identity).unwrap());
}

#[test]
fn certificate_signature_reaches_real_ambient_agent_but_never_private_enrollment_key() {
    use std::process::Stdio;
    let temp = crate::test_support::tempdir().unwrap();
    let ambient_socket = temp.path().join("a");
    let mut command = Command::new("ssh-agent");
    command
        .args(["-D", "-a"])
        .arg(&ambient_socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut agent = crate::process::group::ProcessGroup::spawn(&mut command).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut progress = Instant::now();
    while !ambient_socket.exists() {
        assert!(
            agent.poll().unwrap().is_none(),
            "test ssh-agent exited before readiness"
        );
        assert!(
            Instant::now() < deadline,
            "test ssh-agent did not create its socket"
        );
        if progress.elapsed() >= Duration::from_secs(1) {
            eprintln!("waiting for certificate test ssh-agent socket");
            progress = Instant::now();
        }
        thread::sleep(Duration::from_millis(10));
    }
    let (private, public) = key(195);
    let private = PrivateKey::from(private);
    let key_path = temp.path().join("identity");
    private
        .write_openssh_file(&key_path, ssh_agent_lib::ssh_key::LineEnding::LF)
        .unwrap();
    let added = Command::new("ssh-add")
        .env("SSH_AUTH_SOCK", &ambient_socket)
        .arg(&key_path)
        .capture_output()
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let (peer_private, peer) = key(196);
    let policy = BrokerPolicy::direct(host_policy("backup", "destination", peer.clone()));
    let certificate = user_certificate(public.clone());
    let request = SignRequest {
        credential: public.clone().into(),
        data: hostbound_data(
            b"real-agent-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            &certificate,
            &peer,
        ),
        flags: 0,
    };
    for ambient in [true, false] {
        let broker = if ambient {
            ConstrainedAgentBroker::start_with_ambient_socket(
                ambient_socket.clone(),
                policy.clone(),
                TEST_BROKER_CONNECTIONS,
            )
            .unwrap()
        } else {
            ConstrainedAgentBroker::start_with_private_key_and_socket(
                ambient_socket.clone(),
                policy.clone(),
                TEST_BROKER_CONNECTIONS,
                private.clone(),
            )
            .unwrap()
        };
        let mut client = UnixStream::connect(broker.socket_path()).unwrap();
        write_frame(
            &mut client,
            &bind_request(binding(
                &peer_private,
                peer.clone(),
                b"real-agent-session",
                false,
            )),
        )
        .unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));
        write_frame(&mut client, &[11]).unwrap();
        let Response::IdentitiesAnswer(identities) = read_response(&mut client) else {
            panic!("missing agent identity");
        };
        assert_eq!(identities.len(), 1);
        write_frame(
            &mut client,
            &encode_request(Request::SignRequest(request.clone())),
        )
        .unwrap();
        match read_response(&mut client) {
            Response::SignResponse(signature) if ambient => {
                public.verify(&request.data, &signature).unwrap()
            }
            Response::Failure if !ambient => assert_closed(&mut client),
            response => panic!("unexpected certificate signing response: {response:?}"),
        }
    }
    agent.close().unwrap();
}

#[test]
fn ambient_backend_forwards_only_advertised_fully_bound_signatures() {
    let temp = crate::test_support::tempdir().unwrap();
    let ambient_socket = temp.path().join("ambient.sock");
    let (identity_private, identity) = key(23);
    let (ambient, requests) = fake_ambient(&ambient_socket, identity_private.clone());
    let (source_private, source) = key(21);
    let (destination_private, destination) = key(22);
    let broker = ConstrainedAgentBroker::start_with_ambient_socket(
        ambient_socket,
        policy(source.clone(), destination.clone()),
        TEST_BROKER_CONNECTIONS,
    )
    .unwrap();
    let mut client = UnixStream::connect(broker.socket_path()).unwrap();

    let source_bind = bind_request(binding(&source_private, source, b"source-session", true));
    write_frame(&mut client, &source_bind).unwrap();
    assert!(matches!(read_response(&mut client), Response::Success));
    write_frame(&mut client, &[11]).unwrap();
    let Response::IdentitiesAnswer(identities) = read_response(&mut client) else {
        panic!("expected identities response")
    };
    assert_eq!(identities.len(), 1);
    assert!(identities[0].comment.is_empty());
    assert_eq!(requests.recv().unwrap(), source_bind);
    assert_eq!(requests.recv().unwrap(), vec![11]);

    let destination_bind = bind_request(binding(
        &destination_private,
        destination.clone(),
        b"destination-session",
        false,
    ));
    write_frame(&mut client, &destination_bind).unwrap();
    assert!(matches!(read_response(&mut client), Response::Success));
    assert_eq!(requests.recv().unwrap(), destination_bind);

    let request = sign_request(
        b"destination-session",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        identity,
        &destination,
    );
    let encoded = encode_request(Request::SignRequest(request.clone()));
    write_frame(&mut client, &encoded).unwrap();
    let Response::SignResponse(signature) = read_response(&mut client) else {
        panic!("expected signature response")
    };
    assert_eq!(signature, identity_private.try_sign(&request.data).unwrap());
    assert_eq!(requests.recv().unwrap(), encoded);

    let (_, unadvertised) = key(24);
    let request = sign_request(
        b"destination-session",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        unadvertised,
        &destination,
    );
    write_frame(&mut client, &encode_request(Request::SignRequest(request))).unwrap();
    assert!(matches!(read_response(&mut client), Response::Failure));
    assert_closed(&mut client);
    assert!(requests.try_recv().is_err());

    drop(client);
    drop(broker);
    ambient.join().unwrap();
}

#[test]
fn unbound_sign_mutation_unknown_extension_and_oversize_fail_closed() {
    let temp = crate::test_support::tempdir().unwrap();
    let ambient_socket = temp.path().join("ambient.sock");
    let _ambient = UnixListener::bind(&ambient_socket).unwrap();
    let (_, source) = key(31);
    let (_, destination) = key(32);
    let (_, identity) = key(33);
    let (transport, _) = key(34);
    let broker = ConstrainedAgentBroker::start_with_private_key_and_socket(
        ambient_socket,
        policy(source, destination.clone()),
        TEST_BROKER_CONNECTIONS,
        PrivateKey::from(transport),
    )
    .unwrap();

    let request = sign_request(
        b"unbound-session",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        identity,
        &destination,
    );
    let cases = [
        (encode_request(Request::SignRequest(request)), false),
        (vec![11], false),
        (vec![17], false),
        (
            encode_request(Request::Extension(Extension {
                name: "query".into(),
                details: Vec::new().into(),
            })),
            true,
        ),
    ];
    for (request, extension_failure) in cases {
        let mut client = UnixStream::connect(broker.socket_path()).unwrap();
        write_frame(&mut client, &request).unwrap();
        let response = read_response(&mut client);
        assert!(
            matches!(response, Response::ExtensionFailure) == extension_failure,
            "unexpected response: {response:?}"
        );
        assert!(read_frame(&mut client).unwrap().is_none());
    }

    let mut oversized = UnixStream::connect(broker.socket_path()).unwrap();
    oversized
        .write_all(&((MAX_AGENT_FRAME as u32) + 1).to_be_bytes())
        .unwrap();
    assert!(read_frame(&mut oversized).unwrap().is_none());
}

#[test]
fn malformed_nested_lengths_are_rejected_before_agent_decode_allocates() {
    let (host_private, host_key) = key(34);
    let valid_bind = bind_request(binding(
        &host_private,
        host_key.clone(),
        b"bounded-session",
        false,
    ));

    let mut extension_name = valid_bind.clone();
    extension_name[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_session_bind(&extension_name).is_err());

    let extension_name_len = ssh_string_len_at(&valid_bind, 1);
    let host_key_offset = 1 + 4 + extension_name_len;
    let session_id_offset = host_key_offset + 4 + ssh_string_len_at(&valid_bind, host_key_offset);
    let mut session_bind = valid_bind;
    session_bind[session_id_offset..session_id_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_session_bind(&session_bind).is_err());

    let (_, identity) = key(35);
    let sign_request = sign_request(
        b"bounded-sign",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        identity,
        &host_key,
    );
    let mut sign_frame = encode_request(Request::SignRequest(sign_request));
    let credential_len = ssh_string_len_at(&sign_frame, 1);
    let data_offset = 1 + 4 + credential_len;
    sign_frame[data_offset..data_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_sign_request(&sign_frame).is_err());
}

#[test]
fn broker_bounds_idle_clients_and_drop_closes_them() {
    let temp = crate::test_support::tempdir().unwrap();
    let ambient_socket = temp.path().join("ambient.sock");
    let _ambient = UnixListener::bind(&ambient_socket).unwrap();
    let (_, source) = key(41);
    let (_, destination) = key(42);
    let (transport, _) = key(43);
    let broker = ConstrainedAgentBroker::start_with_private_key_and_socket(
        ambient_socket,
        policy(source, destination),
        TEST_BROKER_CONNECTIONS,
        PrivateKey::from(transport),
    )
    .unwrap();
    let path = broker.socket_path().to_path_buf();
    let mut clients = Vec::new();
    for _ in 0..TEST_BROKER_CONNECTIONS {
        let mut client = UnixStream::connect(&path).unwrap();
        client.write_all(&[0]).unwrap(); // keep each worker waiting on its header
        clients.push(client);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while broker.broker.active_connections() < TEST_BROKER_CONNECTIONS && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(broker.broker.active_connections(), TEST_BROKER_CONNECTIONS);
    let mut excess = UnixStream::connect(&path).unwrap();
    // The broker rejects excess clients without reading a request. Writing
    // here would race that close and could fail with BrokenPipe.
    assert_closed(&mut excess);

    drop(broker);
    assert!(!path.exists());
    for mut client in clients {
        assert_closed(&mut client);
    }
}

#[test]
fn tracked_broker_connections_have_bounded_io() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let registry = Arc::new(ConnectionRegistry::new(BROKER_IO_TIMEOUT));
    let tracked = registry.track(stream).unwrap();
    assert_eq!(tracked.read_timeout().unwrap(), Some(BROKER_IO_TIMEOUT));
    assert_eq!(tracked.write_timeout().unwrap(), Some(BROKER_IO_TIMEOUT));
}

#[test]
fn broker_advertises_and_signs_only_the_enrollment_key() {
    let temp = crate::test_support::tempdir().unwrap();
    let ambient_socket = temp.path().join("ambient.sock");
    let _ambient = UnixListener::bind(&ambient_socket).unwrap();
    let (source_private, source) = key(51);
    let (destination_private, destination) = key(52);
    let (transport, transport_public) = key(53);
    let transport = PrivateKey::from(transport);
    let broker = ConstrainedAgentBroker::start_with_private_key_and_socket(
        ambient_socket,
        policy(source.clone(), destination.clone()),
        TEST_BROKER_CONNECTIONS,
        transport,
    )
    .unwrap();
    let mut client = UnixStream::connect(broker.socket_path()).unwrap();

    write_frame(
        &mut client,
        &bind_request(binding(
            &source_private,
            source.clone(),
            b"source-private-backend",
            true,
        )),
    )
    .unwrap();
    assert!(matches!(read_response(&mut client), Response::Success));
    write_frame(&mut client, &[11]).unwrap();
    let Response::IdentitiesAnswer(identities) = read_response(&mut client) else {
        panic!("expected transport identity")
    };
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].credential.key_data(), &transport_public);

    write_frame(
        &mut client,
        &bind_request(binding(
            &destination_private,
            destination.clone(),
            b"destination-private-backend",
            false,
        )),
    )
    .unwrap();
    assert!(matches!(read_response(&mut client), Response::Success));
    let request = sign_request(
        b"destination-private-backend",
        b"backup",
        b"publickey-hostbound-v00@openssh.com",
        transport_public.clone(),
        &destination,
    );
    let data = request.data.clone();
    write_frame(&mut client, &encode_request(Request::SignRequest(request))).unwrap();
    let Response::SignResponse(signature) = read_response(&mut client) else {
        panic!("expected transport signature")
    };
    transport_public.verify(&data, &signature).unwrap();

    // OpenSSH must not be able to extend the already-authorized path after
    // receiving a signature. A late bind is an extra forwarding hop.
    write_frame(
        &mut client,
        &bind_request(binding(
            &source_private,
            source,
            b"late-third-session",
            true,
        )),
    )
    .unwrap();
    assert!(matches!(
        read_response(&mut client),
        Response::ExtensionFailure
    ));
    assert_closed(&mut client);
}
