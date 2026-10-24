use super::*;
use crate::directive::{Binding, Inputs, Role, NAMESPACE};
use crate::process::CommandExt as _;
use ssh_key::{LineEnding, PrivateKey};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

const NOW: i64 = 1_900_000_000;
const TARGET: &str = "backup";
const BUILD: &str = "test-build";
const GENERATION: u64 = 3;

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

struct Fixture {
    directory: TestDir,
    key: PathBuf,
    trusted: std::cell::RefCell<TrustedSigner>,
}

impl Fixture {
    fn ordinary() -> Self {
        let directory = TestDir::new("ordinary");
        let key = directory.join("signer");
        generate_key(&key);
        let public = ssh_key::PublicKey::read_openssh_file(&key.with_extension("pub"))
            .expect("read test public key");
        Self {
            directory,
            key,
            trusted: std::cell::RefCell::new(TrustedSigner::new(&public, None, None).unwrap()),
        }
    }

    /// Trust another login key instead.
    fn trust(&self, key: &ssh_key::PublicKey) {
        *self.trusted.borrow_mut() = TrustedSigner::new(key, None, None).unwrap();
    }

    fn replay(&self, name: &str) -> ReplayStore {
        let path = self.directory.join(name);
        provision_test_replay_directory(&path);
        ReplayStore::open(&path).expect("open replay store")
    }

    fn policy(&self) -> TrustedSigner {
        self.trusted.borrow().clone()
    }

    fn signed(&self, directive: Directive) -> Vec<u8> {
        signed_directive(&directive, &self.key, crate::directive::NAMESPACE)
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
        .capture_output()
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

fn sign(payload: &[u8], key: &Path, namespace: &str) -> Vec<u8> {
    let mut command = Command::new(ssh_tool("ssh-keygen"));
    command
        .env_clear()
        .args(["-Y", "sign", "-f"])
        .arg(key)
        .args(["-n", namespace])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn_guarded().expect("start test signer");
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

fn fixture_directive(request_byte: u8) -> Directive {
    Directive {
        build: BUILD.to_owned(),
        request_id: RequestId([request_byte; 32]),
        issued_at: NOW,
        not_before: NOW - 30,
        start_by: NOW + 600,
        finish_by: NOW + 900,
        binding: Binding {
            enrollment: EnrollmentId::test_v4(7),
            generation: GENERATION,
            account: TARGET.to_owned(),
            role: Role::Destination,
        },
        command: [
            "cp", "--from", "source", "--src", "data", "--to", "backup", "--into", "/srv",
        ]
        .map(|arg| arg.as_bytes().to_vec())
        .to_vec(),
        cwd: "~/work".to_owned(),
        inputs: Inputs::default(),
        results_key: [4; 32],
    }
}

fn context(target: &str, now: i64, skew: i64) -> ReceiverContext<'_> {
    context_at(target, now, skew, Instant::now())
}

fn context_at(target: &str, now: i64, skew: i64, observed_at: Instant) -> ReceiverContext<'_> {
    ReceiverContext {
        enrollment_id: EnrollmentId::test_v4(7),
        generation: GENERATION,
        target_login: target,
        build: BUILD,
        clock: ClockObservation {
            unix_seconds: now,
            monotonic: observed_at,
        },
        clock_skew_seconds: skew,
    }
}

fn signed_directive(directive: &Directive, key: &Path, namespace: &str) -> Vec<u8> {
    crate::directive::sign(directive, |payload| Ok(sign(payload, key, namespace)))
        .expect("sign test directive")
}

/// The signed form of `directive` with `signature`, whatever made it.
fn raw_directive(directive: &Directive, signature: &[u8]) -> Vec<u8> {
    let body = postcard::to_stdvec(directive).expect("encode test directive");
    let mut out = b"SYQDIR1\0".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(signature);
    out
}

/// The payload a signature over `directive` covers.
fn payload_of(directive: &Directive) -> Vec<u8> {
    [
        b"SYQDIR1\0".as_slice(),
        &postcard::to_stdvec(directive).unwrap(),
    ]
    .concat()
}

fn verify(
    encoded: &[u8],
    context: &ReceiverContext<'_>,
    signer: &TrustedSigner,
    replay: &ReplayStore,
) -> Result<VerifiedDirective> {
    verify_and_redeem(encoded, context, signer, replay, |_| Ok(())).map(|(_, verified)| verified)
}

fn redeemed(replay: &ReplayStore, request_byte: u8) -> bool {
    replay
        .path
        .join(format!(
            "redeemed-{}",
            RequestId([request_byte; 32]).file_component()
        ))
        .exists()
}

#[test]
fn an_in_process_signature_verifies_with_every_field_bound() {
    let fixture = Fixture::ordinary();
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[42; 32]);
    let private = PrivateKey::new(keypair.into(), "syq-test").unwrap();
    fixture.trust(private.public_key());
    let mut directive = fixture_directive(44);
    directive.inputs = Inputs {
        ignore: vec!["*.tmp".into(), "!keep.tmp".into()],
        mapping: Some(crate::mapping::Authorization {
            bytes: 12,
            digest: [9; 32],
        }),
    };
    let sign_in_process = |payload: &[u8]| {
        Ok(private
            .sign(NAMESPACE, HashAlg::Sha256, payload)?
            .to_pem(LineEnding::LF)?
            .into_bytes())
    };
    let encoded = crate::directive::sign(&directive, sign_in_process).unwrap();
    let signed = crate::directive::Signed::decode(&encoded).unwrap();
    assert_eq!(signed.directive, directive);
    let (seen, verified) = verify_and_redeem(
        &encoded,
        &context(TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("in-process-replay"),
        |verified| Ok(verified.clone()),
    )
    .expect("an in-process SSHSIG verifies");
    assert_eq!(seen, directive);
    assert_eq!(verified.digest, signed.digest());

    // Changing any field after signing breaks the signature.
    let signature = signed.signature;
    let tampered: [fn(&mut Directive); 7] = [
        |d| d.command[7] = b"/etc".to_vec(),
        |d| d.inputs.ignore.pop().map(drop).unwrap_or(()),
        |d| d.inputs.mapping = None,
        |d| d.results_key = [5; 32],
        |d| d.cwd = "/".into(),
        |d| d.finish_by += 1,
        |d| d.binding.account = "root".into(),
    ];
    for (index, change) in tampered.into_iter().enumerate() {
        let mut altered = directive.clone();
        change(&mut altered);
        let replay = fixture.replay(&format!("tamper-{index}"));
        let result = verify(
            &raw_directive(&altered, &signature),
            &context(TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        );
        assert!(result.is_err(), "change {index} was accepted");
        assert!(!redeemed(&replay, 44));
    }
}

#[test]
fn delete_excluded_filters_remain_valid_when_deletion_is_forbidden() {
    let args = crate::approval_command::parse(&fixture_directive(50).command).unwrap();
    let copy = crate::directive::copy_operation(&args, &args.locations[..1], b"/srv").unwrap();
    assert_eq!(copy.policy.deletion, DeletionPolicy::Forbid);
    let filters = FilterPolicy {
        ignore: vec!["*.tmp".into()],
        destination_roots: vec![b"/srv/data".to_vec()],
        delete_excluded: true,
    };
    // The unfiltered-scan policy still matters for a dry run or a zero
    // deletion budget; the receiver's deletion policy refuses removals.
    filters.validate(&copy).unwrap();
}

#[test]
fn malformed_and_noncanonical_sshsig_are_rejected() {
    let fixture = Fixture::ordinary();
    let directive = fixture_directive(5);
    let signature = sign(&payload_of(&directive), &fixture.key, NAMESPACE);
    crate::directive::Signed::decode(&raw_directive(&directive, &signature)).unwrap();

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
    assert!(crate::directive::Signed::decode(&raw_directive(&directive, &malformed)).is_err());

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
    assert!(crate::directive::Signed::decode(&raw_directive(&directive, &rewrapped)).is_err());
}

#[test]
fn a_directive_for_another_receiver_is_refused_without_redeeming() {
    let fixture = Fixture::ordinary();
    let directive = fixture_directive(8);
    let replay = fixture.replay("binding-replay");
    let encoded = fixture.signed(directive.clone());
    let refused = |context: ReceiverContext<'_>, expected: &str| {
        let error = verify(&encoded, &context, &fixture.policy(), &replay).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert!(!redeemed(&replay, 8));
    };
    refused(context("root", NOW, 0), "different account");
    let mut other = context(TARGET, NOW, 0);
    other.enrollment_id = EnrollmentId::test_v4(9);
    refused(other, "different enrollment");
    let mut refreshed = context(TARGET, NOW, 0);
    refreshed.generation = GENERATION + 1;
    refused(refreshed, "now at generation");
    let mut rebuilt = context(TARGET, NOW, 0);
    rebuilt.build = "other-build";
    refused(rebuilt, "this receiver runs other-build");
    let wrong_namespace = signed_directive(&directive, &fixture.key, "other-protocol@example.test");
    let error = verify(
        &wrong_namespace,
        &context(TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .unwrap_err();
    assert!(error.to_string().contains("another purpose"), "{error:#}");
    assert!(!redeemed(&replay, 8));
    // A directive whose rules cannot be derived is not recorded either.
    let error = verify_and_redeem(
        &encoded,
        &context(TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
        |_| -> Result<()> { bail!("no rules") },
    )
    .unwrap_err();
    assert!(error.to_string().contains("no rules"), "{error:#}");
    assert!(!redeemed(&replay, 8));
    verify(
        &encoded,
        &context(TARGET, NOW, 0),
        &fixture.policy(),
        &replay,
    )
    .expect("failed checks must not consume the directive");
    assert!(redeemed(&replay, 8));
}

#[test]
fn expiry_and_not_before_honor_only_bounded_clock_skew() {
    let fixture = Fixture::ordinary();
    let encoded = fixture.signed(fixture_directive(9));
    let replay = fixture.replay("expired-replay");
    assert!(verify(
        &encoded,
        &context(TARGET, NOW + 620, 10),
        &fixture.policy(),
        &replay
    )
    .is_err());
    verify(
        &encoded,
        &context(TARGET, NOW + 590, 10),
        &fixture.policy(),
        &replay,
    )
    .expect("expiry inside clock-skew allowance");

    let mut future = fixture_directive(10);
    future.issued_at = NOW + 100;
    future.not_before = NOW + 100;
    future.start_by = NOW + 400;
    let encoded = fixture.signed(future);
    let replay = fixture.replay("future-replay");
    assert!(verify(
        &encoded,
        &context(TARGET, NOW, 90),
        &fixture.policy(),
        &replay
    )
    .is_err());
    verify(
        &encoded,
        &context(TARGET, NOW + 50, 60),
        &fixture.policy(),
        &replay,
    )
    .expect("not-before inside clock-skew allowance");
    let invalid_skew = context(TARGET, NOW, MAX_CLOCK_SKEW_SECS + 1);
    assert!(invalid_skew
        .validate_at(&fixture_directive(11), invalid_skew.clock.monotonic)
        .is_err());
}

#[test]
fn execution_deadline_is_monotonic_and_bounded_by_finish_by() {
    let started = Instant::now();
    let verified = started + Duration::from_secs(3);
    assert_eq!(
        execution_deadline(NOW + 20, 5, NOW + 3, verified).expect("finish-by deadline"),
        verified + Duration::from_secs(22)
    );
    let partially_elapsed = started + Duration::from_millis(1100);
    assert_eq!(
        execution_deadline(NOW + 5, 0, NOW + 2, partially_elapsed)
            .expect("subsecond verification is rounded conservatively"),
        partially_elapsed + Duration::from_secs(3)
    );
    assert!(execution_deadline(NOW + 1, 0, NOW + 2, started + Duration::from_secs(2)).is_err());
}

#[test]
fn queued_clock_observation_advances_validation_redeem_and_deadline() {
    let fixture = Fixture::ordinary();
    let replay = fixture.replay("paired-clock-replay");
    let observed_at = Instant::now()
        .checked_sub(Duration::from_secs(3))
        .expect("monotonic observation in the recent past");
    let context = context_at(TARGET, NOW, 0, observed_at);
    assert!(
        context
            .wall_time_at(Instant::now())
            .expect("adjust wall time")
            >= NOW + 3
    );

    let encoded = fixture.signed(fixture_directive(22));
    let verified = verify(&encoded, &context, &fixture.policy(), &replay)
        .expect("verify with a queued but still-valid clock observation");
    assert!(verified.execution_deadline <= Instant::now() + Duration::from_secs(900));
    let redeem = fs::read(
        replay
            .path
            .join(format!("redeemed-{}", RequestId([22; 32]).file_component())),
    )
    .expect("read adjusted replay redeem");
    let redeemed_at = i64::from_be_bytes(redeem[8..16].try_into().expect("redeem timestamp"));
    assert!(redeemed_at >= NOW + 3);

    let mut expired = fixture_directive(23);
    expired.start_by = NOW + 2;
    expired.finish_by = NOW + 2;
    let encoded = fixture.signed(expired);
    let expired_replay = fixture.replay("queued-expired-replay");
    assert!(verify(&encoded, &context, &fixture.policy(), &expired_replay).is_err());
    assert!(!redeemed(&expired_replay, 23));
}

#[test]
fn duplicate_and_concurrent_redemption_allow_exactly_one_redeem() {
    let fixture = Fixture::ordinary();
    let encoded = Arc::new(fixture.signed(fixture_directive(12)));
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
            verify(&encoded, &context(TARGET, NOW, 0), &policy, &replay)
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
    // The replay record is checked before the signature: a signer that
    // could not verify the directive still reports the redemption.
    let other = PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[43; 32]).into(),
        "other",
    )
    .unwrap();
    let no_signature = TrustedSigner::new(other.public_key(), None, None).unwrap();
    let error = verify(&encoded, &context(TARGET, NOW, 0), &no_signature, &replay)
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
fn private_state_checks_are_structural_not_ownership_walks() {
    let directory = TestDir::new("structural-policy");
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o777)).unwrap();

    let executable = directory.join("syq");
    fs::write(&executable, b"test executable").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o777)).unwrap();
    validate_regular_executable(&executable, "test receiver")
        .expect("writable permissions do not reject a trusted receiver executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(validate_regular_executable(&executable, "test receiver").is_err());

    let state = directory.join("config.json");
    fs::write(&state, b"{}\n").unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_private_regular(&state, "test state", 1024).unwrap(),
        b"{}\n"
    );
    fs::set_permissions(&state, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(read_private_regular(&state, "test state", 1024).is_err());
    assert!(read_private_regular(&directory.0, "test state", 1024).is_err());
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
fn rejects_a_signature_by_any_key_but_the_trusted_one() {
    let fixture = Fixture::ordinary();
    let directory = TestDir::new("other-key");
    let key = directory.join("other");
    generate_key(&key);
    let encoded = signed_directive(&fixture_directive(60), &key, NAMESPACE);
    let error = verify(
        &encoded,
        &context(TARGET, NOW, 0),
        &fixture.policy(),
        &fixture.replay("other-key-replay"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not trust"), "{error:#}");
}

#[test]
fn a_probe_grant_or_other_namespace_signature_never_verifies_as_a_directive() {
    let fixture = Fixture::ordinary();
    for namespace in [
        "syq-receiver-key-check-v1@greaber.github",
        "syq-receiver-key-wrap-v1@greaber.github",
        // The typed grants of earlier builds.
        "syq-grant@greaber.github",
        "git",
        "file",
    ] {
        let encoded = signed_directive(&fixture_directive(61), &fixture.key, namespace);
        let replay = fixture.replay(&format!("namespace-{}", namespace.len()));
        let error = verify(
            &encoded,
            &context(TARGET, NOW, 0),
            &fixture.policy(),
            &replay,
        )
        .unwrap_err();
        assert!(error.to_string().contains("another purpose"), "{error:#}");
        assert!(!redeemed(&replay, 61));
    }
}

/// A FIDO key's SSHSIG over `payload` in `namespace`, with `flags`.
/// A FIDO key's SSHSIG over `payload` in `namespace`, with `flags`.
fn security_key_signature(
    seed: u8,
    flags: u8,
    namespace: &str,
    payload: &[u8],
) -> (ssh_key::PublicKey, Vec<u8>) {
    use sha2::Digest as _;
    use signature::Signer as _;
    let pair = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
    let public = ssh_key::public::SkEd25519::new(pair.public, "ssh:");
    let key = ssh_key::PublicKey::new(public.into(), "");
    let hash = HashAlg::Sha512;
    let data = ssh_key::SshSig::signed_data(namespace, hash, payload).unwrap();
    let mut signed = Sha256::digest(b"ssh:").to_vec();
    signed.push(flags);
    signed.extend_from_slice(&7u32.to_be_bytes());
    signed.extend_from_slice(&Sha256::digest(&data));
    let mut bytes = pair.try_sign(&signed).unwrap().as_bytes().to_vec();
    bytes.push(flags);
    bytes.extend_from_slice(&7u32.to_be_bytes());
    let signature = ssh_key::SshSig::new(
        key.key_data().clone(),
        namespace,
        hash,
        ssh_key::Signature::new(ssh_key::Algorithm::SkEd25519, bytes).unwrap(),
    )
    .unwrap()
    .to_pem(LineEnding::LF)
    .unwrap()
    .into_bytes();
    (key, signature)
}

#[test]
fn fido_ecdsa_signatures_keep_their_flags_through_encoding() {
    use signature::Signer as _;
    let software = PrivateKey::random(
        &mut ssh_key::rand_core::OsRng,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let ssh_key::public::EcdsaPublicKey::NistP256(point) =
        *software.public_key().key_data().ecdsa().unwrap()
    else {
        unreachable!()
    };
    let key = ssh_key::PublicKey::new(
        ssh_key::public::SkEcdsaSha2NistP256::new(point, "ssh:").into(),
        "",
    );
    for flags in [0u8, 1, 5] {
        let data = ssh_key::SshSig::signed_data(NAMESPACE, HashAlg::Sha512, b"grant").unwrap();
        let mut signed = Sha256::digest(b"ssh:").to_vec();
        signed.push(flags);
        signed.extend_from_slice(&3u32.to_be_bytes());
        signed.extend_from_slice(&Sha256::digest(&data));
        let ecdsa: ssh_key::Signature = software.try_sign(&signed).unwrap();
        let mut bytes = ecdsa.as_bytes().to_vec();
        bytes.push(flags);
        bytes.extend_from_slice(&3u32.to_be_bytes());
        let signature =
            ssh_key::Signature::new(ssh_key::Algorithm::SkEcdsaSha2NistP256, bytes).unwrap();
        let armored =
            armored_sshsig(key.key_data(), NAMESPACE, HashAlg::Sha512, &signature).unwrap();
        validate_canonical_sshsig(&armored).unwrap();
        let decoded = ssh_key::SshSig::from_pem(&armored).unwrap();
        assert_eq!(security_key_flags(&decoded).unwrap(), flags);
        TrustedSigner::new(&key, Some(flags), None)
            .unwrap()
            .verify(NAMESPACE, b"grant", &armored, NOW)
            .unwrap();
        // A PIN the signature does not show is refused.
        assert_eq!(
            TrustedSigner::new(&key, Some(flags | SK_USER_VERIFICATION), None)
                .unwrap()
                .verify(NAMESPACE, b"grant", &armored, NOW)
                .is_ok(),
            flags & SK_USER_VERIFICATION != 0
        );
    }
}

#[test]
fn security_key_directives_need_the_touch_and_pin_the_enrollment_recorded() {
    let fixture = Fixture::ordinary();
    let mut request = 70;
    for flags in [0u8, 1, 4, 5] {
        for required in [0u8, 1, 4, 5] {
            request += 1;
            let directive = fixture_directive(request);
            let (key, signature) =
                security_key_signature(9, flags, NAMESPACE, &payload_of(&directive));
            let encoded = raw_directive(&directive, &signature);
            let signer = TrustedSigner::new(&key, Some(required), None).unwrap();
            let result = verify(
                &encoded,
                &context(TARGET, NOW, 0),
                &signer,
                &fixture.replay(&format!("sk-{flags}-{required}")),
            );
            assert_eq!(
                result.is_ok(),
                flags & required == required,
                "{flags} {required}: {result:?}"
            );
            if let Err(error) = result {
                assert!(error.to_string().contains("FIDO"), "{error:#}");
            }
        }
    }
    // A FIDO key needs a policy; a software key cannot have one.
    let (key, _) = security_key_signature(9, 1, NAMESPACE, b"");
    assert!(TrustedSigner::new(&key, None, None).is_err());
    assert!(TrustedSigner::new(&key, Some(2), None).is_err());
    let software =
        ssh_key::PublicKey::read_openssh_file(&fixture.key.with_extension("pub")).unwrap();
    assert!(TrustedSigner::new(&software, Some(1), None).is_err());
}

#[test]
fn a_certificate_login_key_is_trusted_until_the_certificate_expires() {
    let fixture = Fixture::ordinary();
    let public = ssh_key::PublicKey::read_openssh_file(&fixture.key.with_extension("pub")).unwrap();
    for (valid_before, skew, accepted) in [
        // The receiver's clock is read to the second, and its later bound
        // decides.
        (NOW as u64 + 2, 0, true),
        (NOW as u64 + 1, 0, false),
        (NOW as u64, 0, false),
        (NOW as u64 - 1, 0, false),
        // The clock skew allowance favours the signer, as for start-by.
        (NOW as u64 - 30, 60, true),
        (NOW as u64 - 61, 60, false),
    ] {
        let signer = TrustedSigner::new(&public, None, Some(valid_before)).unwrap();
        let directive = fixture_directive(90 + (valid_before % 100) as u8);
        let result = verify(
            &fixture.signed(directive),
            &context(TARGET, NOW, skew),
            &signer,
            &fixture.replay(&format!("certificate-{valid_before}-{skew}")),
        );
        assert_eq!(
            result.is_ok(),
            accepted,
            "{valid_before} {skew}: {result:?}"
        );
        if let Err(error) = result {
            assert!(error.to_string().contains("expired"), "{error:#}");
        }
    }
}
