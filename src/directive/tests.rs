use super::*;
use crate::delegation::RequestId;

const HOME: &str = "/home/backup";

fn command(args: &[&str]) -> Vec<Vec<u8>> {
    args.iter().map(|arg| arg.as_bytes().to_vec()).collect()
}

fn directive(args: &[&str]) -> Directive {
    let mut directive = issue(
        Binding {
            enrollment: EnrollmentId::test_v4(7),
            generation: 3,
            account: "backup".into(),
            role: Role::Destination,
        },
        command(args),
        "~/work".into(),
        Inputs::default(),
        [4; 32],
    )
    .unwrap();
    // Fixed, so derivations in different processes can be compared.
    directive.request_id = RequestId::test(9);
    directive.issued_at = 1_900_000_000;
    directive.not_before = directive.issued_at - CLOCK_SKEW_SECONDS;
    directive.start_by = directive.issued_at + VALIDITY_SECONDS - CLOCK_SKEW_SECONDS;
    directive.finish_by = directive.issued_at + FINISH_WINDOW_SECONDS;
    directive
}

const ROUTE_5: &[&str] = &[
    "cp", "--from", "host-a", "--src", "data", "--to", "host-b", "--into", "backup",
];

/// A placeholder signature: canonical armor, verified only by `delegation`.
fn armored(byte: u8) -> Vec<u8> {
    let mut raw = b"SSHSIG".to_vec();
    raw.extend_from_slice(&1u32.to_be_bytes());
    raw.extend_from_slice(&[byte; 40]);
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw);
    let mut out = b"-----BEGIN SSH SIGNATURE-----\n".to_vec();
    for chunk in encoded.as_bytes().chunks(70) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END SSH SIGNATURE-----\n");
    out
}

fn signed(directive: &Directive) -> Vec<u8> {
    sign(directive, |_| Ok(armored(1))).unwrap()
}

/// `body` and `signature` behind a directive header with their lengths.
fn framed(body: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(signature);
    out
}

#[test]
fn a_directive_has_one_canonical_encoding() {
    let original = directive(ROUTE_5);
    let encoded = signed(&original);
    let decoded = Signed::decode(&encoded).unwrap();
    assert_eq!(decoded.directive, original);
    assert_eq!(decoded.signature, armored(1));
    // The signature covers the magic and the body.
    let body = postcard::to_stdvec(&original).unwrap();
    assert_eq!(decoded.payload, [MAGIC.as_slice(), &body].concat());

    let refused = |bytes: &[u8]| Signed::decode(bytes).unwrap_err().to_string();
    // Another magic, or lengths that do not match the bytes.
    let mut magic = encoded.clone();
    magic[0] ^= 1;
    assert!(refused(&magic).contains("not a syq directive"));
    let mut longer = encoded.clone();
    longer.push(b'\n');
    assert!(refused(&longer).contains("noncanonical"));
    assert!(refused(&encoded[..encoded.len() - 1]).contains("noncanonical"));
    assert!(refused(&framed(&body, b"")).contains("noncanonical"));
    // Bytes after the body inside its length.
    let mut trailing = body.clone();
    trailing.push(0);
    assert!(refused(&framed(&trailing, &armored(1))).contains("noncanonical"));
    // The same value with its first length spelled in two bytes.
    assert_eq!(usize::from(body[0]), original.build.len());
    let mut spelled = vec![body[0] | 0x80, 0];
    spelled.extend_from_slice(&body[1..]);
    assert!(Signed::decode(&framed(&spelled, &armored(1))).is_err());
    // Larger than any receiver reads.
    assert!(refused(&vec![0; MAX_SIGNED_BYTES + 1]).contains("size limit"));
}

#[test]
fn unknown_variants_are_refused() {
    // The same layout as a directive, with a role no build defines.
    #[derive(Serialize)]
    struct Future {
        build: String,
        request_id: RequestId,
        issued_at: i64,
        not_before: i64,
        start_by: i64,
        finish_by: i64,
        enrollment: EnrollmentId,
        generation: u64,
        account: String,
        role: u32,
        command: Vec<Vec<u8>>,
        cwd: String,
        inputs: Inputs,
        results_key: [u8; 32],
    }
    let known = directive(ROUTE_5);
    let future = |role| Future {
        build: known.build.clone(),
        request_id: known.request_id,
        issued_at: known.issued_at,
        not_before: known.not_before,
        start_by: known.start_by,
        finish_by: known.finish_by,
        enrollment: known.binding.enrollment,
        generation: known.binding.generation,
        account: known.binding.account.clone(),
        role,
        command: known.command.clone(),
        cwd: known.cwd.clone(),
        inputs: known.inputs.clone(),
        results_key: known.results_key,
    };
    let body = |role| postcard::to_stdvec(&future(role)).unwrap();
    // The layout matches: role 0 is the destination.
    assert_eq!(body(0), postcard::to_stdvec(&known).unwrap());
    assert!(Signed::decode(&framed(&body(0), &armored(1))).is_ok());
    assert!(Signed::decode(&framed(&body(1), &armored(1))).is_err());
}

#[test]
fn directives_out_of_bounds_are_refused_before_they_are_signed_or_read() {
    type Change = Box<dyn Fn(&mut Directive)>;
    let mut cases: Vec<(&str, Change)> = vec![
        ("no build", Box::new(|d| d.build.clear())),
        (
            "issued before not-before",
            Box::new(|d| d.not_before = d.issued_at + 1),
        ),
        (
            "start-by after finish-by",
            Box::new(|d| d.finish_by = d.start_by - 1),
        ),
        (
            "usable for longer than a day",
            Box::new(|d| d.start_by = d.not_before + VALIDITY_SECONDS + 1),
        ),
        (
            "finishing more than 7 days after issue",
            Box::new(|d| d.finish_by = d.issued_at + FINISH_WINDOW_SECONDS + 1),
        ),
        ("no command", Box::new(|d| d.command.clear())),
        (
            "too long a command",
            Box::new(|d| {
                d.command
                    .push(vec![b'x'; crate::approval_command::MAX_COMMAND_BYTES])
            }),
        ),
        (
            "an account with a slash",
            Box::new(|d| d.binding.account = "a/b".into()),
        ),
        (
            "too long a working directory",
            Box::new(|d| d.cwd = "x".repeat(5000)),
        ),
        (
            "too many ignore rules",
            Box::new(|d| d.inputs.ignore = vec!["x".into(); MAX_IGNORE_RULES + 1]),
        ),
        (
            "an ignore rule with NUL",
            Box::new(|d| d.inputs.ignore = vec!["a\0b".into()]),
        ),
    ];
    for (label, change) in cases.drain(..) {
        let mut bad = directive(ROUTE_5);
        change(&mut bad);
        assert!(
            sign(&bad, |_| Ok(armored(1))).is_err(),
            "{label} was signed"
        );
        let body = postcard::to_stdvec(&bad).unwrap();
        assert!(
            Signed::decode(&framed(&body, &armored(1))).is_err(),
            "{label} was read"
        );
    }
}

#[test]
fn the_destination_rules_come_from_the_signed_command() {
    let home = Path::new(HOME);
    let (grant, constraints) = destination_rules(&directive(ROUTE_5), home).unwrap();
    assert_eq!(grant.enrollment_id, EnrollmentId::test_v4(7));
    assert_eq!(grant.copy.destination, b"/home/backup/backup");
    // Named sources: the directory itself, and each source's name in it.
    let scopes: Vec<_> = grant
        .copy
        .mutation_scopes
        .iter()
        .map(|scope| (scope.path.clone(), scope.descendants))
        .collect();
    assert_eq!(
        scopes,
        [
            (b"/home/backup/backup".to_vec(), false),
            (b"/home/backup/backup/data".to_vec(), true),
        ]
    );
    assert_eq!(
        constraints.receipt_policy,
        crate::destination_results::ReceiptPolicy::for_recipient([4; 32])
    );
    // A bandwidth limit is the sender's preference, not part of the rules.
    let mut limited = ROUTE_5.to_vec();
    limited.extend(["--resource-limits", "bandwidth=4M"]);
    let (_, limited) = destination_rules(&directive(&limited), home).unwrap();
    assert_eq!(limited.max_file_data_bytes_per_second, 0);
    // `~`, and an absolute destination, as on the server.
    for (destination, expected) in [
        ("~", HOME),
        ("~/archive", "/home/backup/archive"),
        ("/srv/archive", "/srv/archive"),
    ] {
        let mut args = ROUTE_5.to_vec();
        *args.last_mut().unwrap() = destination;
        let (grant, _) = destination_rules(&directive(&args), home).unwrap();
        assert_eq!(grant.copy.destination, expected.as_bytes(), "{destination}");
    }

    // What the command read from files comes beside it, and only narrows.
    let mut ignoring = directive(&[
        "cp",
        "--from",
        "host-a",
        "--src",
        "data",
        "--to",
        "host-b",
        "--into",
        "backup",
        "--ignore-from",
        "/unreadable/rules",
    ]);
    ignoring.inputs.ignore = vec!["*.tmp".into()];
    let (_, constraints) = destination_rules(&ignoring, home).unwrap();
    assert_eq!(constraints.filters.ignore, ["*.tmp"]);
    assert_eq!(
        constraints.filters.destination_roots,
        [b"/home/backup/backup/data".to_vec()]
    );
    // A mapping's digest comes with exactly the commands that name one.
    let mut mapped = directive(&[
        "cp",
        "--from",
        "host-a",
        "--mapping",
        "/unreadable/map",
        "--to",
        "host-b",
        "--into",
        "backup",
    ]);
    let error = destination_rules(&mapped, home).unwrap_err().to_string();
    assert!(error.contains("mapping"), "{error}");
    mapped.inputs.mapping = Some(crate::mapping::Authorization {
        bytes: 3,
        digest: [1; 32],
    });
    let (_, constraints) = destination_rules(&mapped, home).unwrap();
    assert_eq!(constraints.mapping, mapped.inputs.mapping);
    let mut unmapped = directive(ROUTE_5);
    unmapped.inputs.mapping = mapped.inputs.mapping.clone();
    assert!(destination_rules(&unmapped, home).is_err());
}

#[test]
fn commands_a_receiver_cannot_enforce_yield_no_rules() {
    let home = Path::new(HOME);
    for (args, expected) in [
        (
            &[
                "cp", "--from", "host-a", "--src", "data", "--into", "/local",
            ][..],
            "copies to this machine",
        ),
        (&["rsync", "-a", "a", "host-b:b"], "syq cp"),
        (
            &[
                "cp",
                "--from",
                "host-a",
                "--src",
                "data",
                "--to",
                "host-b",
                "--into",
                "b",
                "--no-tcp-encryption",
            ],
            "encrypted",
        ),
        (
            &[
                "cp",
                "--from",
                "host-a",
                "--src",
                "data",
                "--to",
                "host-b",
                "--into",
                "../escape",
            ],
            "..",
        ),
    ] {
        let error = destination_rules(&directive(args), home)
            .err()
            .unwrap_or_else(|| panic!("{args:?} has rules"));
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }
}

/// The rules a checker derives depend on the signed command alone, not on
/// its environment, its working directory, its locale or options from its
/// environment.
#[test]
fn derivation_does_not_depend_on_the_environment() {
    const CHILD: &str = "SYQ_TEST_DERIVATION_CHILD";
    let rules = || {
        let mut args = ROUTE_5.to_vec();
        args.extend(["--if-exists", "keep", "--ignore", "*.o"]);
        let (grant, constraints) = destination_rules(&directive(&args), Path::new(HOME)).unwrap();
        format!("{grant:?}\n{constraints:?}")
    };
    if std::env::var_os(CHILD).is_some() {
        println!("rules<<{}>>", rules());
        return;
    }
    let directory = crate::test_support::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "directive::tests::derivation_does_not_depend_on_the_environment",
            "--nocapture",
        ])
        .current_dir(directory.path())
        .env(CHILD, "1")
        .env("HOME", directory.path())
        .env("LC_ALL", "tr_TR.UTF-8")
        .env(
            "SYQ_CP_OPTIONS",
            "--dry-run --delete --max-delete 5 --inplace",
        )
        .env("SYQ_RECEIVER_MAX_ENTRIES", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    let child = stdout
        .split_once("rules<<")
        .and_then(|(_, rest)| rest.split_once(">>"))
        .map(|(rules, _)| rules)
        .unwrap_or_else(|| panic!("no rules in {stdout}"));
    assert_eq!(child, rules());
}
