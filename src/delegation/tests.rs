
use super::*;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::process::Child;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

const NOW: i64 = 1_900_000_000;
const SIGNER: &str = "alice@example.test";
const MALLORY: &str = "mallory@example.test";
const TARGET: &str = "backup";

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        #[cfg(target_os = "macos")]
        let parent = std::env::var_os("TMPDIR")
            .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
            .or_else(|| std::env::var_os("HOME"));
        #[cfg(not(target_os = "macos"))]
        let parent = std::env::var_os("XDG_RUNTIME_DIR").or_else(|| std::env::var_os("HOME"));
        let parent = parent
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .expect("tests require an absolute private runtime or home directory");
        // Resolve symlinks (macOS `/var`) and keep the name short: an
        // ssh-agent socket beneath this directory must fit `sun_path`,
        // which is 104 bytes on macOS beneath an already long `TMPDIR`.
        let parent = fs::canonicalize(&parent).unwrap_or(parent);
        let label: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(6)
            .collect();
        for _ in 0..100 {
            let path = parent.join(format!(
                "syq-{label}-{}-{}",
                std::process::id(),
                hex(&random_array::<4>().expect("test randomness"))
            ));
            let result = fs::DirBuilder::new().mode(0o700).create(&path);
            match result {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory: {error}"),
            }
        }
        panic!("could not allocate a unique test directory");
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct AgentGuard {
    child: Child,
    socket: PathBuf,
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Fixture {
    directory: TestDir,
    key: PathBuf,
    allowed_signers: PathBuf,
}

impl Fixture {
    fn ordinary() -> Self {
        let directory = TestDir::new("ordinary");
        let key = directory.join("signer");
        generate_key(&key);
        let allowed_signers = directory.join("allowed-signers");
        write_allowed_signers(&allowed_signers, SIGNER, &key.with_extension("pub"), false);
        Self {
            directory,
            key,
            allowed_signers,
        }
    }

    fn replay(&self, name: &str) -> ReplayStore {
        let path = self.directory.join(name);
        provision_test_replay_directory(&path);
        ReplayStore::open(&path).expect("open replay store")
    }

    fn policy(&self) -> SshsigPolicy {
        SshsigPolicy {
            ssh_keygen: ssh_tool("ssh-keygen"),
            allowed_signers: self.allowed_signers.clone(),
            revocation_file: None,
        }
    }

    fn signed(&self, grant: Grant) -> Vec<u8> {
        signed_envelope(grant, &self.key, SSHSIG_NAMESPACE, None)
    }
}

fn ssh_tool(name: &str) -> PathBuf {
    for directory in ["/usr/bin", "/bin", "/usr/local/bin"] {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("required test tool {name} is not installed");
}

fn command_output(mut command: Command, action: &str) -> std::process::Output {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{action}: {error}"));
    assert!(
        output.status.success(),
        "{action} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn generate_key(path: &Path) {
    let mut command = Command::new(ssh_tool("ssh-keygen"));
    command
        .env_clear()
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .stdin(Stdio::null());
    command_output(command, "generate test signing key");
}

fn certify_key(ca: &Path, public_key: &Path, principals: &str) {
    let mut command = Command::new(ssh_tool("ssh-keygen"));
    command
        .env_clear()
        .args(["-q", "-s"])
        .arg(ca)
        .args(["-I", "syq-test", "-n", principals])
        .arg(public_key)
        .stdin(Stdio::null());
    command_output(command, "create test signing certificate");
}

fn write_private(path: &Path, contents: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create private test file");
    file.write_all(contents).expect("write private test file");
    file.sync_all().expect("sync private test file");
}

fn provision_test_replay_directory(path: &Path) {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("provision test replay directory");
}

fn write_allowed_signers(path: &Path, signer: &str, public_key: &Path, certificate: bool) {
    let public_key = fs::read_to_string(public_key).expect("read test public key");
    let authority = if certificate { "cert-authority," } else { "" };
    let line = format!(
        "{signer} {authority}namespaces=\"{SSHSIG_NAMESPACE}\" {}\n",
        public_key.trim()
    );
    write_private(path, line.as_bytes());
}

fn start_agent(directory: &TestDir) -> AgentGuard {
    let socket = directory.join("agent.sock");
    let mut child = Command::new(ssh_tool("ssh-agent"))
        .env_clear()
        .args(["-D", "-a"])
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start test ssh-agent");
    for _ in 0..200 {
        if fs::symlink_metadata(&socket)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
        {
            return AgentGuard { child, socket };
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("test ssh-agent did not create its socket");
}

fn add_to_agent(agent: &AgentGuard, key: &Path) {
    let mut command = Command::new(ssh_tool("ssh-add"));
    command
        .env_clear()
        .env("SSH_AUTH_SOCK", &agent.socket)
        .arg(key)
        .stdin(Stdio::null());
    command_output(command, "load test agent key");
}

fn sign(payload: &[u8], key: &Path, namespace: &str, agent: Option<&AgentGuard>) -> Vec<u8> {
    let mut command = Command::new(ssh_tool("ssh-keygen"));
    command
        .env_clear()
        .args(["-Y", "sign", "-f"])
        .arg(key)
        .args(["-n", namespace])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(agent) = agent {
        command.env("SSH_AUTH_SOCK", &agent.socket);
    }
    let mut child = command.spawn().expect("start test signer");
    child
        .stdin
        .take()
        .expect("signer stdin")
        .write_all(payload)
        .expect("write signing payload");
    let output = child.wait_with_output().expect("wait for test signer");
    assert!(
        output.status.success(),
        "sign test payload: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn fixture_grant(request_byte: u8) -> Grant {
    Grant {
        enrollment_id: EnrollmentId::test_v4(7),
        target_login: TARGET.to_owned(),
        signer: SIGNER.to_owned(),
        request_id: RequestId([request_byte; 32]),
        issued_at: NOW,
        not_before: NOW - 30,
        start_by: NOW + 600,
        finish_by: NOW + 900,
        operation: GrantOperation::Copy(CopyOperation {
            destination: b"/srv/archive/project".to_vec(),
            mutation_scopes: vec![MutationScope {
                path: b"/srv/archive/project".to_vec(),
                descendants: true,
            }],
            policy: CopyPolicy {
                placement: DestinationPlacement::ExactPath,
                existing: ExistingDestinationPolicy::Replace,
                deletion: DeletionPolicy::Forbid,
                publication: PublicationPolicy::AtomicStaged,
            },
            options: CopyOptions {
                recursive: true,
                preserve_symlinks: true,
                preserve_permissions: true,
                receiver_managed_modes: false,
                preserve_times: true,
                preserve_owner: false,
                preserve_group: false,
                preserve_devices: false,
                compare_existing_by_content: true,
                dry_run: false,
                verify_only: true,
                compressed_transport: false,
                tcp_port_lo: 47_600,
                tcp_port_hi: 47_699,
            },
            limits: CopyLimits {
                max_entries: 10_000,
                max_total_bytes: 1 << 30,
                max_file_bytes: 1 << 29,
                hash_block_bytes: 4 << 20,
                max_connections: 8,
                max_deletions: 0,
            },
        }),
    }
}

fn context<'a>(signer: &'a str, target: &'a str, now: i64, skew: i64) -> ReceiverContext<'a> {
    context_at(signer, target, now, skew, Instant::now())
}

fn context_at<'a>(
    signer: &'a str,
    target: &'a str,
    now: i64,
    skew: i64,
    observed_at: Instant,
) -> ReceiverContext<'a> {
    ReceiverContext {
        enrollment_id: EnrollmentId::test_v4(7),
        target_login: target,
        expected_signer: signer,
        clock: ClockObservation {
            unix_seconds: now,
            monotonic: observed_at,
        },
        clock_skew_seconds: skew,
    }
}

fn signed_envelope(
    grant: Grant,
    key: &Path,
    namespace: &str,
    agent: Option<&AgentGuard>,
) -> Vec<u8> {
    signed_envelope_with_rate(grant, 0, key, namespace, agent)
}

fn signed_envelope_with_rate(
    grant: Grant,
    max_file_data_bytes_per_second: u64,
    key: &Path,
    namespace: &str,
    agent: Option<&AgentGuard>,
) -> Vec<u8> {
    let payload = signing_payload_default(&grant, max_file_data_bytes_per_second)
        .expect("make signing payload");
    let signature = sign(&payload, key, namespace, agent);
    SignedGrantEnvelope::new(grant, max_file_data_bytes_per_second, signature)
        .encode()
        .expect("encode signed grant")
}

fn raw_envelope(grant: &Grant, signature: &[u8]) -> Vec<u8> {
    raw_envelope_with_rate(grant, 0, signature)
}

fn raw_envelope_with_rate(
    grant: &Grant,
    max_file_data_bytes_per_second: u64,
    signature: &[u8],
) -> Vec<u8> {
    let grant = canonical_body_bytes(
        grant,
        max_file_data_bytes_per_second,
        &FilterPolicy::default(),
        RootExistence::Any,
        &test_receipt_policy(),
        None,
        None,
        None,
    )
    .expect("encode test grant");
    let mut out = Vec::new();
    out.extend_from_slice(WIRE_MAGIC);
    out.extend_from_slice(&(grant.len() as u32).to_be_bytes());
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&grant);
    out.extend_from_slice(signature);
    out
}

#[test]
fn released_v041_grants_keep_their_bytes_signature_and_replay_identity() {
    // Produced by v0.4.1's unchanged sign_grant/fixture_grant(44), using
    // the deterministic test key below. Do not regenerate on protocol edits.
    let encoded = include_bytes!("../../tests/fixtures/restricted-grant-v0.4.1.bin");
    let decoded = SignedGrantEnvelope::decode(encoded).unwrap();
    let GrantOperation::Copy(copy) = &decoded.grant.operation;
    assert_eq!(copy.limits.max_connections, 8);
    assert_eq!(decoded.tcp_congestion, None);
    assert_eq!(decoded.encode().unwrap(), encoded);
    let private = PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "syq-test",
    )
    .unwrap();
    assert_eq!(
        sign_grant(fixture_grant(44), GrantConstraints::default(), &private).unwrap(),
        encoded
    );
    let fixture = Fixture::ordinary();
    fs::write(
        &fixture.allowed_signers,
        format!("{SIGNER} {}\n", private.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    let replay = fixture.replay("released-replay");
    verify_and_redeem(
        encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .unwrap();
    assert!(verify_and_redeem(
        encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay
    )
    .is_err());
}

#[test]
fn congestion_extension_is_signed_and_cannot_be_removed_or_changed() {
    let private = PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "syq-test",
    )
    .unwrap();
    let fixture = Fixture::ordinary();
    fs::write(
        &fixture.allowed_signers,
        format!("{SIGNER} {}\n", private.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    let encoded = sign_grant(
        fixture_grant(44),
        GrantConstraints {
            tcp_congestion: Some("cubic".into()),
            ..Default::default()
        },
        &private,
    )
    .unwrap();
    let decoded = SignedGrantEnvelope::decode(&encoded).unwrap();
    assert_eq!(decoded.tcp_congestion.as_deref(), Some("cubic"));
    let replay = fixture.replay("tcp-constraint-replay");
    for algorithm in [None, Some("bbr".into())] {
        let mut tampered = decoded.clone();
        tampered.tcp_congestion = algorithm;
        assert!(verify_and_redeem(
            &tampered.encode().unwrap(),
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay
        )
        .is_err());
    }
    let verified = verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .unwrap();
    assert_eq!(
        verified.into_parts().1.tcp_congestion.as_deref(),
        Some("cubic")
    );
}

#[test]
fn hashing_constraints_are_signed_and_preserve_legacy_encoding() {
    use crate::hashing::{CopyHashing, Digest, HashAlgorithm, HashPolicy};
    let private = PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "syq-test",
    )
    .unwrap();
    let fixture = Fixture::ordinary();
    fs::write(
        &fixture.allowed_signers,
        format!("{SIGNER} {}\n", private.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    let hashing = CopyHashing {
        policy: HashPolicy {
            algorithm: HashAlgorithm::Xxh3,
            transfer_integrity: false,
            transfer_hash_type: None,
        },
        expected_digest: Some(Digest::hash_bytes(HashAlgorithm::Sha256, b"expected file")),
    };
    let encoded = sign_grant(
        fixture_grant(45),
        GrantConstraints {
            hashing: Some(hashing.clone()),
            ..Default::default()
        },
        &private,
    )
    .unwrap();
    let decoded = SignedGrantEnvelope::decode(&encoded).unwrap();
    assert_eq!(decoded.hashing, Some(hashing.clone()));
    let replay = fixture.replay("hashing-replay");
    let mut changed = hashing.clone();
    changed.policy.transfer_integrity = true;
    let mut other_payload = hashing.clone();
    other_payload.policy.transfer_hash_type = Some(HashAlgorithm::Sha256);
    let mut omitted = hashing.clone();
    omitted.expected_digest = None;
    for policy in [None, Some(changed), Some(other_payload), Some(omitted)] {
        let mut tampered = decoded.clone();
        tampered.hashing = policy;
        assert!(verify_and_redeem(
            &tampered.encode().unwrap(),
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay
        )
        .is_err());
    }
    let verified = verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .unwrap();
    assert_eq!(verified.into_parts().1.hashing, Some(hashing));
    // The released body's encoding is unchanged; the new feature is an
    // extension an old reader rejects instead of silently dropping it.
    let legacy = fixture.signed(fixture_grant(46));
    let legacy_decoded = SignedGrantEnvelope::decode(&legacy).unwrap();
    assert!(legacy_decoded.hashing.is_none());
    assert_eq!(legacy_decoded.encode().unwrap(), legacy);
}

#[test]
fn mapping_extension_is_signed_and_preserves_non_mapping_encoding() {
    let private = PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]).into(),
        "syq-test",
    )
    .unwrap();
    let fixture = Fixture::ordinary();
    fs::write(
        &fixture.allowed_signers,
        format!("{SIGNER} {}\n", private.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    let mapping = crate::mapping::Authorization::from_contents(b"manifest bytes");
    for tcp in [None, Some("cubic".to_string())] {
        let encoded = sign_grant(
            fixture_grant(44),
            GrantConstraints {
                mapping: Some(mapping.clone()),
                tcp_congestion: tcp.clone(),
                ..Default::default()
            },
            &private,
        )
        .unwrap();
        let decoded = SignedGrantEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.mapping, Some(mapping.clone()));
        assert_eq!(decoded.tcp_congestion, tcp);
        // Released readers require byte-for-byte canonical re-encoding of
        // their GrantBody and cannot discard trailing signed constraints.
        let size = u32::from_be_bytes(encoded[8..12].try_into().unwrap()) as usize;
        let body = &encoded[WIRE_HEADER_LEN..WIRE_HEADER_LEN + size];
        let (old, _): (GrantBody, &[u8]) = postcard::take_from_bytes(body).unwrap();
        assert_ne!(postcard::to_stdvec(&old).unwrap(), body);
        let replay = fixture.replay(if tcp.is_some() {
            "mapping-tcp-replay"
        } else {
            "mapping-replay"
        });
        for changed in [
            None,
            Some(crate::mapping::Authorization {
                bytes: mapping.bytes + 1,
                ..mapping.clone()
            }),
            Some(crate::mapping::Authorization {
                digest: [0; 32],
                ..mapping.clone()
            }),
        ] {
            let mut tampered = decoded.clone();
            tampered.mapping = changed;
            assert!(verify_and_redeem(
                &tampered.encode().unwrap(),
                &context(SIGNER, TARGET, NOW, 0),
                &fixture.policy(),
                &replay
            )
            .is_err());
        }
        let verified = verify_and_redeem(
            &encoded,
            &context(SIGNER, TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .unwrap();
        assert_eq!(verified.into_parts().1.mapping, Some(mapping.clone()));
    }
}

#[test]
fn signed_worker_allowances_round_trip_without_widening() {
    let fixture = Fixture::ordinary();
    for workers in [1, 8, 32, 64, 128] {
        let mut grant = fixture_grant(1);
        let GrantOperation::Copy(copy) = &mut grant.operation;
        copy.limits.max_connections = workers;
        let encoded = fixture.signed(grant);
        let decoded = SignedGrantEnvelope::decode(&encoded).unwrap();
        let GrantOperation::Copy(copy) = decoded.grant.operation;
        assert_eq!(copy.limits.max_connections, workers);
    }
}

#[test]
fn canonical_typed_grant_round_trips_and_has_strict_bounds() {
    let fixture = Fixture::ordinary();
    let encoded = fixture.signed(fixture_grant(1));
    let decoded = SignedGrantEnvelope::decode(&encoded).expect("decode canonical grant");
    assert_eq!(decoded.grant, fixture_grant(1));
    assert_eq!(decoded.max_file_data_bytes_per_second, 0);
    let mut bad_magic = encoded.clone();
    bad_magic[3] ^= 1;
    assert!(SignedGrantEnvelope::decode(&bad_magic).is_err());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(SignedGrantEnvelope::decode(&trailing).is_err());

    let mut relative = fixture_grant(2);
    let GrantOperation::Copy(copy) = &mut relative.operation;
    copy.destination = b"relative/path".to_vec();
    assert!(signing_payload_default(&relative, 0).is_err());

    let mut unbounded = fixture_grant(3);
    unbounded.start_by = unbounded.not_before + MAX_GRANT_VALIDITY_SECS + 1;
    unbounded.finish_by = unbounded.start_by;
    assert!(signing_payload_default(&unbounded, 0).is_err());

    let mut endless = fixture_grant(3);
    endless.finish_by = endless.issued_at + MAX_FINISH_WINDOW_SECS + 1;
    assert!(signing_payload_default(&endless, 0).is_err());

    let mut reversed = fixture_grant(3);
    reversed.finish_by = reversed.start_by - 1;
    assert!(signing_payload_default(&reversed, 0).is_err());

    let mut excessive = fixture_grant(4);
    let GrantOperation::Copy(copy) = &mut excessive.operation;
    copy.limits.max_connections = MAX_CONNECTIONS + 1;
    assert!(signing_payload_default(&excessive, 0).is_err());

    let mut excessive = fixture_grant(4);
    let GrantOperation::Copy(copy) = &mut excessive.operation;
    copy.limits.max_total_bytes = u64::MAX;
    assert!(signing_payload_default(&excessive, 0).is_err());
}

#[test]
fn in_process_enrollment_key_signature_is_accepted_by_openssh() {
    let fixture = Fixture::ordinary();
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]);
    let private = PrivateKey::new(keypair.into(), "syq-test").unwrap();
    let public = private.public_key().to_openssh().unwrap();
    fs::write(&fixture.allowed_signers, format!("{SIGNER} {public}\n")).unwrap();
    let replay = fixture.replay("in-process-signature-replay");
    let encoded = sign_grant(fixture_grant(44), GrantConstraints::default(), &private).unwrap();
    SignedGrantEnvelope::decode(&encoded).unwrap();
    verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .expect("OpenSSH must accept the in-process SSHSIG");

    let rate_limited = sign_grant(
        fixture_grant(45),
        GrantConstraints {
            max_file_data_bytes_per_second: 4096,
            ..GrantConstraints::default()
        },
        &private,
    )
    .unwrap();
    let decoded = SignedGrantEnvelope::decode(&rate_limited).unwrap();
    assert_eq!(decoded.max_file_data_bytes_per_second, 4096);
    verify_and_redeem(
        &rate_limited,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("in-process-rate-signature-replay"),
    )
    .expect("OpenSSH must accept the signed rate extension");

    let filters = FilterPolicy {
        ignore: vec!["*.tmp".into(), "!keep.tmp".into()],
        destination_roots: vec![b"/srv/archive/project".to_vec()],
        delete_excluded: false,
    };
    let filtered = sign_grant(
        fixture_grant(46),
        GrantConstraints {
            filters: filters.clone(),
            ..GrantConstraints::default()
        },
        &private,
    )
    .unwrap();
    let decoded = SignedGrantEnvelope::decode(&filtered).unwrap();
    assert_eq!(decoded.filters, filters);
    assert_eq!(decoded.root_existence, RootExistence::Any);
    let verified = verify_and_redeem(
        &filtered,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("in-process-filter-signature-replay"),
    )
    .expect("OpenSSH must accept the signed filter extension");
    assert_eq!(verified.into_parts().1.filters, filters);

    let outside = FilterPolicy {
        ignore: vec!["*.tmp".into()],
        destination_roots: vec![b"/srv/outside".to_vec()],
        delete_excluded: false,
    };
    assert!(sign_grant(
        fixture_grant(47),
        GrantConstraints {
            filters: outside,
            ..GrantConstraints::default()
        },
        &private
    )
    .is_err());

    // A root-existence precondition survives verification unchanged.
    let rooted = sign_grant(
        fixture_grant(48),
        GrantConstraints {
            root_existence: RootExistence::New,
            ..GrantConstraints::default()
        },
        &private,
    )
    .unwrap();
    let decoded = SignedGrantEnvelope::decode(&rooted).unwrap();
    assert_eq!(decoded.root_existence, RootExistence::New);
    let verified = verify_and_redeem(
        &rooted,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("in-process-root-existence-signature-replay"),
    )
    .expect("OpenSSH must accept the signed root-existence extension");
    assert_eq!(verified.into_parts().1.root_existence, RootExistence::New);

    // The grant binds the complete receipt delivery policy, including the
    // per-transfer HPKE recipient key, into the signed grant transcript.
    let expected_receipt_policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: true,
        max_records: 32,
        max_plaintext_bytes: 64 * 1024,
        delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
            suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: [4; 32],
        },
    };
    let receipted = sign_grant(
        fixture_grant(53),
        GrantConstraints {
            receipt_policy: expected_receipt_policy.clone(),
            ..GrantConstraints::default()
        },
        &private,
    )
    .unwrap();
    let decoded = SignedGrantEnvelope::decode(&receipted).unwrap();
    assert_eq!(decoded.receipt_policy, expected_receipt_policy.clone());
    let expected_digest = signed_grant_digest(&receipted).unwrap();
    let verified = verify_and_redeem(
        &receipted,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("in-process-receipt-signature-replay"),
    )
    .expect("OpenSSH must accept the signed receipt policy");
    let (_, extensions, digest, _) = verified.into_parts();
    assert_eq!(extensions.receipt_policy, expected_receipt_policy);
    assert_eq!(digest, expected_digest);
}

#[test]
fn delete_excluded_filters_remain_valid_when_deletion_is_forbidden() {
    let grant = fixture_grant(50);
    let GrantOperation::Copy(copy) = &grant.operation;
    assert_eq!(copy.policy.deletion, DeletionPolicy::Forbid);
    let filters = FilterPolicy {
        ignore: vec!["*.tmp".into()],
        destination_roots: vec![b"/srv/archive/project".to_vec()],
        delete_excluded: true,
    };
    // The unfiltered-scan policy still matters for a dry run or a zero
    // deletion budget; the receiver's deletion policy refuses removals.
    filters.validate(&grant).unwrap();
}

#[test]
fn malformed_and_noncanonical_sshsig_are_rejected() {
    let fixture = Fixture::ordinary();
    let grant = fixture_grant(5);
    let payload = signing_payload_default(&grant, 0).expect("payload");
    let signature = sign(&payload, &fixture.key, SSHSIG_NAMESPACE, None);

    let mut malformed = signature.clone();
    let body_start = malformed
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("armor header newline")
        + 1;
    let position = malformed[body_start..]
        .iter()
        .position(|byte| byte.is_ascii_alphanumeric())
        .expect("base64 character")
        + body_start;
    malformed[position] = b'!';
    assert!(SignedGrantEnvelope::decode(&raw_envelope(&grant, &malformed)).is_err());

    let lines: Vec<&[u8]> = signature.split(|byte| *byte == b'\n').collect();
    let mut encoded = Vec::new();
    for line in &lines[1..lines.len() - 2] {
        encoded.extend_from_slice(line);
    }
    let mut rewrapped = b"-----BEGIN SSH SIGNATURE-----\n".to_vec();
    for chunk in encoded.chunks(64) {
        rewrapped.extend_from_slice(chunk);
        rewrapped.push(b'\n');
    }
    rewrapped.extend_from_slice(b"-----END SSH SIGNATURE-----\n");
    assert!(SignedGrantEnvelope::decode(&raw_envelope(&grant, &rewrapped)).is_err());
}

#[test]
fn verifies_ordinary_key_and_binds_every_typed_field() {
    let fixture = Fixture::ordinary();
    let replay = fixture.replay("replay");
    let encoded = fixture.signed(fixture_grant(6));
    verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .expect("verify signed request");

    let original = SignedGrantEnvelope::decode(&fixture.signed(fixture_grant(7)))
        .expect("decode signed request");
    let mut altered = original.grant;
    let GrantOperation::Copy(copy) = &mut altered.operation;
    copy.options.verify_only = false;
    let tampered = raw_envelope(&altered, &original.signature);
    assert!(verify_and_redeem(
        &tampered,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("tamper-replay"),
    )
    .is_err());

    let rate_grant = fixture_grant(29);
    let rate_limited = signed_envelope_with_rate(
        rate_grant.clone(),
        4096,
        &fixture.key,
        SSHSIG_NAMESPACE,
        None,
    );
    let decoded = SignedGrantEnvelope::decode(&rate_limited).expect("decode rate-limited grant");
    assert_eq!(decoded.max_file_data_bytes_per_second, 4096);
    let tampered_rate = raw_envelope_with_rate(&rate_grant, 8192, &decoded.signature);
    assert!(verify_and_redeem(
        &tampered_rate,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("rate-tamper-replay"),
    )
    .is_err());
}

#[test]
fn rejects_wrong_namespace_signer_target_and_enrollment_without_redeeming() {
    let fixture = Fixture::ordinary();
    let grant = fixture_grant(8);
    let wrong_namespace = signed_envelope(
        grant.clone(),
        &fixture.key,
        "other-protocol@example.test",
        None,
    );
    let replay = fixture.replay("binding-replay");
    assert!(verify_and_redeem(
        &wrong_namespace,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .is_err());

    let encoded = fixture.signed(grant.clone());
    assert!(verify_and_redeem(
        &encoded,
        &context("mallory@example.test", TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .is_err());
    let mut unlisted_signer = grant.clone();
    unlisted_signer.signer = "mallory@example.test".to_owned();
    let unlisted_signer = fixture.signed(unlisted_signer);
    assert!(verify_and_redeem(
        &unlisted_signer,
        &context("mallory@example.test", TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .is_err());
    assert!(verify_and_redeem(
        &encoded,
        &context(SIGNER, "root", NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .is_err());
    let mut wrong_enrollment = context(SIGNER, TARGET, NOW, 0);
    wrong_enrollment.enrollment_id = EnrollmentId::test_v4(9);
    assert!(verify_and_redeem(&encoded, &wrong_enrollment, &fixture.policy(), &replay).is_err());
    verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .expect("failed binding checks must not consume request");
}

#[test]
fn expiry_and_not_before_honor_only_bounded_clock_skew() {
    let fixture = Fixture::ordinary();
    let encoded = fixture.signed(fixture_grant(9));
    let replay = fixture.replay("expired-replay");
    assert!(verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW + 620, 10),
        &fixture.policy(),
        &replay,
    )
    .is_err());
    verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW + 590, 10),
        &fixture.policy(),
        &replay,
    )
    .expect("expiry inside clock-skew allowance");

    let mut future = fixture_grant(10);
    future.issued_at = NOW + 100;
    future.not_before = NOW + 100;
    future.start_by = NOW + 400;
    let encoded = fixture.signed(future);
    let replay = fixture.replay("future-replay");
    assert!(verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 90),
        &fixture.policy(),
        &replay,
    )
    .is_err());
    verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW + 50, 60),
        &fixture.policy(),
        &replay,
    )
    .expect("not-before inside clock-skew allowance");
    let invalid_skew = context(SIGNER, TARGET, NOW, MAX_CLOCK_SKEW_SECS + 1);
    assert!(invalid_skew
        .validate_at(&fixture_grant(11), invalid_skew.clock.monotonic)
        .is_err());
}

#[test]
fn execution_deadline_is_monotonic_and_bounded_by_finish_by() {
    let started = Instant::now();
    let verified = started + Duration::from_secs(3);

    let mut bounded = fixture_grant(17);
    bounded.finish_by = NOW + 20;
    assert_eq!(
        execution_deadline(&bounded, 5, NOW + 3, verified).expect("finish-by deadline"),
        verified + Duration::from_secs(22)
    );

    let partially_elapsed = started + Duration::from_millis(1100);
    let mut rounded = fixture_grant(19);
    rounded.finish_by = NOW + 5;
    assert_eq!(
        execution_deadline(&rounded, 0, NOW + 2, partially_elapsed)
            .expect("subsecond verification is rounded conservatively"),
        partially_elapsed + Duration::from_secs(3)
    );

    let mut finished = fixture_grant(20);
    finished.finish_by = NOW + 1;
    assert!(execution_deadline(&finished, 0, NOW + 2, started + Duration::from_secs(2),).is_err());
}

#[test]
fn queued_clock_observation_advances_validation_redeem_and_deadline() {
    let fixture = Fixture::ordinary();
    let replay = fixture.replay("paired-clock-replay");
    let observed_at = Instant::now()
        .checked_sub(Duration::from_secs(3))
        .expect("monotonic observation in the recent past");
    let context = context_at(SIGNER, TARGET, NOW, 0, observed_at);
    assert!(
        context
            .wall_time_at(Instant::now())
            .expect("adjust wall time")
            >= NOW + 3
    );

    let encoded = fixture.signed(fixture_grant(22));
    let verified = verify_and_redeem(&encoded, &context, &fixture.policy(), &replay)
        .expect("verify with a queued but still-valid clock observation");
    assert!(verified.execution_deadline() <= Instant::now() + Duration::from_secs(900));
    let redeem = fs::read(
        replay
            .path
            .join(format!("redeemed-{}", RequestId([22; 32]).file_component())),
    )
    .expect("read adjusted replay redeem");
    let redeemed_at = i64::from_be_bytes(redeem[8..16].try_into().expect("redeem timestamp"));
    assert!(redeemed_at >= NOW + 3);

    let mut expired = fixture_grant(23);
    expired.start_by = NOW + 2;
    expired.finish_by = NOW + 2;
    let encoded = fixture.signed(expired);
    let expired_replay = fixture.replay("queued-expired-replay");
    assert!(verify_and_redeem(&encoded, &context, &fixture.policy(), &expired_replay).is_err());
    assert!(!expired_replay
        .path
        .join(format!("redeemed-{}", RequestId([23; 32]).file_component()))
        .exists());
}

#[test]
fn duplicate_and_concurrent_redemption_allow_exactly_one_redeem() {
    let fixture = Fixture::ordinary();
    let encoded = Arc::new(fixture.signed(fixture_grant(12)));
    let replay = fixture.replay("concurrent-replay");
    let policy = fixture.policy();
    let barrier = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let encoded = Arc::clone(&encoded);
        let replay = replay.clone();
        let policy = policy.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            verify_and_redeem(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
        }));
    }
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("redemption thread"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let failures: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    assert_eq!(failures.len(), 7);
    assert!(
        failures.iter().all(|error| error
            .to_string()
            .contains("signed request has already been redeemed")),
        "{failures:?}"
    );
    let mut no_verifier = fixture.policy();
    no_verifier.ssh_keygen = PathBuf::from("/missing/verifier-must-not-run");
    let error = verify_and_redeem(
        &encoded,
        &context(SIGNER, TARGET, NOW, 0),
        &no_verifier,
        &replay,
    )
    .expect_err("duplicate request must fail");
    assert!(error
        .to_string()
        .contains("signed request has already been redeemed"));
}

#[test]
fn replay_redeem_survives_reopen_ignores_stale_temp_and_fails_closed_on_corruption() {
    let directory = TestDir::new("replay-disk");
    let state = directory.join("state");
    let first = RequestId([13; 32]);
    let first_digest = [0x31; 32];
    provision_test_replay_directory(&state);
    let store = ReplayStore::open(&state).expect("open replay store");
    store
        .redeem(first, first_digest, NOW)
        .expect("first redeem");
    drop(store);

    let record_path = state.join(format!("redeemed-{}", first.file_component()));
    let metadata = fs::metadata(&record_path).expect("redeem record metadata");
    assert_eq!(metadata.len() as usize, REDEMPTION_RECORD_LEN);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    write_private(&state.join(".redeem-crash-residue.tmp"), b"partial");
    let reopened = ReplayStore::open(&state).expect("reopen replay store");
    assert!(reopened.redeem(first, first_digest, NOW + 1).is_err());
    assert!(reopened.redeem(first, [0xff; 32], NOW + 1).is_err());
    reopened
        .redeem(RequestId([14; 32]), [0x32; 32], NOW + 1)
        .expect("stale unpublished temp cannot block another redeem");

    let corrupt = RequestId([15; 32]);
    write_private(
        &state.join(format!("redeemed-{}", corrupt.file_component())),
        b"partial",
    );
    assert!(reopened.redeem(corrupt, [0x33; 32], NOW + 2).is_err());
}

#[test]
fn verifier_snapshots_remain_pinned_when_the_state_path_is_replaced() {
    let directory = TestDir::new("pinned-snapshot");
    let state = directory.join("state");
    let relocated = directory.join("relocated-state");
    provision_test_replay_directory(&state);
    let store = ReplayStore::open(&state).expect("open replay store");
    fs::rename(&state, &relocated).expect("relocate open replay directory");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .expect("replace replay pathname");

    let temporary = store
        .temporary_file("policy", b"pinned policy contents")
        .expect("create pinned verifier snapshot");
    let name = temporary.name.clone();
    assert!(relocated.join(&name).is_file());
    assert!(!state.join(&name).exists());
    assert!(temporary
        .is_read_only()
        .expect("inspect snapshot access mode"));
    assert!(temporary
        .is_close_on_exec()
        .expect("inspect snapshot descriptor flags"));
    let byte = [0u8];
    assert_eq!(
        unsafe { libc::write(temporary.file.as_raw_fd(), byte.as_ptr().cast(), byte.len(),) },
        -1,
        "the verifier snapshot itself must not be writable"
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    let reserved = VerifierSnapshotFd::reserve(&temporary, 64)
        .expect("reserve child-only verifier descriptor");
    assert!(reserved
        .is_close_on_exec()
        .expect("inspect reserved descriptor flags"));
    assert!(
        descriptor_is_read_only(reserved.child.as_raw_fd()).expect("inspect reserved access mode")
    );
    assert_eq!(
        fs::read(format!("/dev/fd/{}", temporary.file.as_raw_fd()))
            .expect("read snapshot descriptor"),
        b"pinned policy contents"
    );

    drop(temporary);
    assert!(!relocated.join(name).exists());
}

#[test]
fn replay_store_checks_the_final_private_directory_not_its_ancestors() {
    let directory = TestDir::new("replay-security");
    let missing = directory.join("missing-state");
    assert!(ReplayStore::open(&missing).is_err());
    assert!(
        !missing.exists(),
        "request handling must not provision state"
    );

    let public = directory.join("public-state");
    fs::DirBuilder::new()
        .mode(0o755)
        .create(&public)
        .expect("create public state directory");
    assert!(ReplayStore::open(&public).is_err());

    let private = directory.join("private-state");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .expect("create private state directory");
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777))
        .expect("make the non-secret ancestor broadly writable");
    let dotted = PathBuf::from(format!("{}/./private-state", directory.0.display()));
    ReplayStore::open(&dotted).expect("ancestor permissions do not reject private state");
    let link = directory.join("state-link");
    std::os::unix::fs::symlink(&private, &link).expect("create state symlink");
    assert!(ReplayStore::open(&link).is_err());
}

#[test]
fn replay_store_accepts_a_setgid_private_directory() {
    let directory = TestDir::new("setgid-private");
    let state = directory.join("state");
    provision_test_replay_directory(&state);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o2700))
        .expect("set setgid on private state directory");
    assert_eq!(fs::metadata(&state).unwrap().mode() & 0o2000, 0o2000);

    ReplayStore::open(&state).expect("setgid does not grant another principal access");
}

#[test]
fn verifier_and_policy_checks_are_structural_not_ownership_walks() {
    let directory = TestDir::new("structural-policy");
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777)).unwrap();

    let verifier = directory.join("ssh-keygen");
    fs::write(&verifier, b"test executable").unwrap();
    fs::set_permissions(&verifier, fs::Permissions::from_mode(0o777)).unwrap();
    validate_regular_executable(&verifier, "test verifier")
        .expect("writable permissions do not reject a trusted receiver executable");
    fs::set_permissions(&verifier, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(validate_regular_executable(&verifier, "test verifier").is_err());

    let policy = directory.join("allowed-signers");
    fs::write(&policy, b"signer ssh-ed25519 test\n").unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_private_regular(&policy, "test policy", 1024).unwrap(),
        b"signer ssh-ed25519 test\n"
    );
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(read_private_regular(&policy, "test policy", 1024).is_err());
    assert!(read_private_regular(&directory.0, "test policy", 1024).is_err());
}

#[test]
fn request_ids_are_fresh_and_distinct_from_stable_copy_ids() {
    let first = RequestId::fresh(NOW).expect("fresh request ID");
    let second = RequestId::fresh(NOW).expect("fresh request ID");
    assert_ne!(first, second);
    assert_eq!(std::mem::size_of::<RequestId>(), 32);
    assert_eq!(std::mem::size_of::<crate::proto::CopyId>(), 16);
}

#[test]
fn timestamped_request_ids_sort_chronologically_and_stay_unique() {
    let earlier = RequestId::fresh(NOW).expect("fresh request ID");
    let later = RequestId::fresh(NOW + 1).expect("fresh request ID");
    assert_eq!(earlier.0[..8], u64::try_from(NOW).unwrap().to_be_bytes());
    // Hex filenames of big-endian timestamps sort lexicographically in
    // time order, so redeem listings are naturally chronological.
    assert!(earlier.file_component() < later.file_component());
    // Same second, distinct nonces: the 24 random bytes carry uniqueness.
    let sibling = RequestId::fresh(NOW).expect("fresh request ID");
    assert_ne!(earlier, sibling);
    assert_eq!(earlier.0[..8], sibling.0[..8]);
    earlier.validate().expect("timestamped IDs validate");
    // Pre-epoch issue times are refused rather than wrapped.
    assert!(RequestId::fresh(-1).is_err());
}

#[test]
fn verifier_timeout_kills_its_process_group() {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "sleep 30"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("start stalled verifier fixture");
    let started = Instant::now();
    let error = wait_for_verifier(child, b"test", Duration::from_millis(50))
        .expect_err("stalled verifier must time out");
    assert!(error.to_string().contains("timeout"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn rejects_a_key_authorized_only_for_another_principal() {
    let directory = TestDir::new("wrong-principal-key");
    let key = directory.join("mallory");
    generate_key(&key);
    let allowed_signers = directory.join("allowed-signers");
    write_allowed_signers(&allowed_signers, MALLORY, &key.with_extension("pub"), false);
    let encoded = signed_envelope(fixture_grant(24), &key, SSHSIG_NAMESPACE, None);
    let replay_path = directory.join("replay");
    provision_test_replay_directory(&replay_path);
    let replay = ReplayStore::open(&replay_path).expect("open replay store");
    let policy = SshsigPolicy {
        ssh_keygen: ssh_tool("ssh-keygen"),
        allowed_signers,
        revocation_file: None,
    };

    let error = verify_and_redeem(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
        .expect_err("a key listed only for another principal must fail");
    assert!(error.to_string().starts_with("SSHSIG verification failed"));
}

#[test]
fn revocation_survives_replay_path_replacement() {
    let fixture = Fixture::ordinary();
    let revocations = fixture.directory.join("revocations");
    let public_key =
        fs::read(fixture.key.with_extension("pub")).expect("read revoked test public key");
    write_private(&revocations, &public_key);
    let mut policy = fixture.policy();
    policy.revocation_file = Some(revocations);
    let replay = fixture.replay("replaced-replay");
    // Move the opened store aside and put a fresh, empty store at its
    // old path. The verifier must keep using the retained directory.
    let moved = fixture.directory.join("replaced-replay-moved");
    fs::rename(&replay.path, &moved).expect("move replay directory");
    provision_test_replay_directory(&replay.path);
    let error = verify_and_redeem(
        &fixture.signed(fixture_grant(26)),
        &context(SIGNER, TARGET, NOW, 0),
        &policy,
        &replay,
    )
    .expect_err("a revoked signer must fail after its store path is replaced");
    assert!(
        error.to_string().starts_with("SSHSIG verification failed"),
        "{error:#}"
    );
    assert!(fs::read_dir(&replay.path).unwrap().next().is_none());
}

#[test]
fn rejects_a_revoked_signing_key() {
    let fixture = Fixture::ordinary();
    let revocations = fixture.directory.join("revocations");
    let public_key =
        fs::read(fixture.key.with_extension("pub")).expect("read revoked test public key");
    write_private(&revocations, &public_key);
    let mut policy = fixture.policy();
    policy.revocation_file = Some(revocations);
    let replay = fixture.replay("revoked-replay");

    let error = verify_and_redeem(
        &fixture.signed(fixture_grant(25)),
        &context(SIGNER, TARGET, NOW, 0),
        &policy,
        &replay,
    )
    .expect_err("a revoked signer must fail");
    assert!(error.to_string().starts_with("SSHSIG verification failed"));
}

#[test]
fn verifies_certificate_signature_against_allowed_ca() {
    let directory = TestDir::new("certificate");
    let ca = directory.join("ca");
    let user = directory.join("user");
    generate_key(&ca);
    generate_key(&user);
    certify_key(&ca, &user.with_extension("pub"), SIGNER);

    let agent = start_agent(&directory);
    add_to_agent(&agent, &user);
    let allowed_signers = directory.join("allowed-signers");
    write_allowed_signers(&allowed_signers, SIGNER, &ca.with_extension("pub"), true);
    let grant = fixture_grant(16);
    let encoded = signed_envelope(
        grant,
        &directory.join("user-cert.pub"),
        SSHSIG_NAMESPACE,
        Some(&agent),
    );
    let replay_path = directory.join("replay");
    provision_test_replay_directory(&replay_path);
    let replay = ReplayStore::open(&replay_path).expect("open replay store");
    let policy = SshsigPolicy {
        ssh_keygen: ssh_tool("ssh-keygen"),
        allowed_signers,
        revocation_file: None,
    };
    verify_and_redeem(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
        .expect("verify SSH certificate signature through allowed CA");
}

#[test]
fn rejects_certificate_without_the_expected_principal() {
    let directory = TestDir::new("certificate-principal");
    let ca = directory.join("ca");
    let user = directory.join("user");
    generate_key(&ca);
    generate_key(&user);
    certify_key(&ca, &user.with_extension("pub"), MALLORY);

    let agent = start_agent(&directory);
    add_to_agent(&agent, &user);
    let allowed_signers = directory.join("allowed-signers");
    write_allowed_signers(&allowed_signers, SIGNER, &ca.with_extension("pub"), true);
    let encoded = signed_envelope(
        fixture_grant(26),
        &directory.join("user-cert.pub"),
        SSHSIG_NAMESPACE,
        Some(&agent),
    );
    let replay_path = directory.join("replay");
    provision_test_replay_directory(&replay_path);
    let replay = ReplayStore::open(&replay_path).expect("open replay store");
    let policy = SshsigPolicy {
        ssh_keygen: ssh_tool("ssh-keygen"),
        allowed_signers,
        revocation_file: None,
    };

    let error = verify_and_redeem(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
        .expect_err("a certificate without the expected principal must fail");
    assert!(error.to_string().starts_with("SSHSIG verification failed"));
}

#[test]
fn rejects_certificate_when_ca_is_not_marked_as_an_authority() {
    let directory = TestDir::new("certificate-not-ca");
    let ca = directory.join("ca");
    let user = directory.join("user");
    generate_key(&ca);
    generate_key(&user);
    certify_key(&ca, &user.with_extension("pub"), SIGNER);

    let agent = start_agent(&directory);
    add_to_agent(&agent, &user);
    let allowed_signers = directory.join("allowed-signers");
    write_allowed_signers(&allowed_signers, SIGNER, &ca.with_extension("pub"), false);
    let encoded = signed_envelope(
        fixture_grant(27),
        &directory.join("user-cert.pub"),
        SSHSIG_NAMESPACE,
        Some(&agent),
    );
    let replay_path = directory.join("replay");
    provision_test_replay_directory(&replay_path);
    let replay = ReplayStore::open(&replay_path).expect("open replay store");
    let policy = SshsigPolicy {
        ssh_keygen: ssh_tool("ssh-keygen"),
        allowed_signers,
        revocation_file: None,
    };

    let error = verify_and_redeem(&encoded, &context(SIGNER, TARGET, NOW, 0), &policy, &replay)
        .expect_err("a certificate signed by a non-authority entry must fail");
    assert!(error.to_string().starts_with("SSHSIG verification failed"));
}
