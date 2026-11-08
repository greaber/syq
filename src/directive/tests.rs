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
        (Inputs::default(), None),
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
    assert_eq!(Framed::split(&encoded).unwrap().signature, armored(1));
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
        caps: Option<Caps>,
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
        caps: known.caps,
        results_key: known.results_key,
    };
    let body = |role| postcard::to_stdvec(&future(role)).unwrap();
    // The layout matches: role 0 is the destination, 1 a coordinating
    // source, with its peer, and 2 a source.
    assert_eq!(body(0), postcard::to_stdvec(&known).unwrap());
    assert!(Signed::decode(&framed(&body(0), &armored(1))).is_ok());
    assert_eq!(
        Signed::decode(&framed(&body(2), &armored(1)))
            .unwrap()
            .directive
            .binding
            .role,
        Role::Source
    );
    assert!(Signed::decode(&framed(&body(3), &armored(1))).is_err());
}

const ROUTE_6: &[&str] = &[
    "cp",
    "--from",
    "host-b",
    "--srcs-in",
    "data",
    "--to",
    "host-c",
    "--into",
    "archive",
    "--auth-from",
    "@laptop",
];

fn peer(destination: &Directive) -> Peer {
    Peer {
        enrollment: destination.binding.enrollment,
        generation: destination.binding.generation,
        account: destination.binding.account.clone(),
        request: destination.request_id,
        destination: b"/home/backup/archive".to_vec(),
        known_hosts: "host-c ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n".into(),
    }
}

/// The destination's directive and the source's, paired as the approving
/// machine signs them.
fn pair(args: &[&str]) -> (Directive, Directive) {
    let destination = directive(args);
    let mut source = directive(args);
    source.binding.enrollment = EnrollmentId::test_v4(8);
    source.binding.account = "reader".into();
    source.binding.role = Role::CoordinatingSource(peer(&destination));
    source.request_id = RequestId::test(10);
    (destination, source)
}

#[test]
fn a_coordinating_source_runs_only_the_destination_directive_approved_with_it() {
    let (destination, source) = pair(ROUTE_6);
    // It round-trips canonically with its peer.
    let encoded = signed(&source);
    assert_eq!(Signed::decode(&encoded).unwrap().directive, source);
    let args = coordination(&source, &destination).unwrap();
    assert_eq!(args.locations[0].host.as_deref(), Some("host-b"));
    assert_eq!(args.locations[1].host.as_deref(), Some("host-c"));

    type Change = Box<dyn Fn(&mut Directive)>;
    let cases: Vec<(&str, Change)> = vec![
        (
            "another enrollment",
            Box::new(|d| d.binding.enrollment = EnrollmentId::test_v4(9)),
        ),
        (
            "another generation",
            Box::new(|d| d.binding.generation += 1),
        ),
        (
            "another account",
            Box::new(|d| d.binding.account = "other".into()),
        ),
        (
            "another request",
            Box::new(|d| d.request_id = RequestId::test(11)),
        ),
        ("another build", Box::new(|d| d.build.push('x'))),
        (
            "another command",
            Box::new(|d| d.command = command(&[ROUTE_6, &["--prune"]].concat())),
        ),
        ("another directory", Box::new(|d| d.cwd = "/".into())),
        (
            "other ignore rules",
            Box::new(|d| d.inputs.ignore = vec!["*.tmp".into()]),
        ),
        (
            "other limits",
            Box::new(|d| {
                d.caps = Some(Caps {
                    max_bytes: 1,
                    max_entries: 1,
                    max_delete: 0,
                })
            }),
        ),
        (
            "a source's role",
            Box::new(|d| d.binding.role = Role::CoordinatingSource(peer(d))),
        ),
    ];
    for (case, change) in cases {
        let mut other = destination.clone();
        change(&mut other);
        assert!(coordination(&source, &other).is_err(), "{case}");
    }
    // A destination's directive does not coordinate, and a source's has no
    // destination rules: neither passes as the other.
    assert!(coordination(&destination, &destination)
        .unwrap_err()
        .to_string()
        .contains("not for a source"));
    assert!(destination_rules(&source, Path::new(HOME))
        .unwrap_err()
        .to_string()
        .contains("not for a copy's destination"));
}

#[test]
fn a_coordinating_source_needs_a_copy_between_two_servers() {
    let refused = |args: &[&str]| {
        let (destination, source) = pair(args);
        coordination(&source, &destination).unwrap_err().to_string()
    };
    // The same account at both ends, files on the requester, or a receiving
    // machine's name.
    assert!(refused(&[
        "cp",
        "--from",
        "host-b",
        "--srcs-in",
        "data",
        "--to",
        "host-b",
        "--into",
        "archive"
    ])
    .contains("different accounts"));
    assert!(refused(&[
        "cp",
        "--srcs-in",
        "data",
        "--to",
        "host-c",
        "--into",
        "archive"
    ])
    .contains("sources on one SSH server"));
    assert!(refused(&[
        "cp",
        "--from",
        "@laptop",
        "--srcs-in",
        "data",
        "--to",
        "host-c",
        "--into",
        "archive"
    ])
    .contains("sources on one SSH server"));
    // Options that choose another route or connection.
    for option in [
        &["--rsh", "ssh -i key"][..],
        &["--detach"],
        &["--coordinate-at", "dst"],
        &["--coordinate-at", "local"],
        &["--peer-auth", "broker"],
        &["--syq-path", "/tmp/syq"],
    ] {
        let message = refused(&[ROUTE_6, option].concat());
        assert!(
            message.contains("cannot be combined") || message.contains("--detach"),
            "{option:?}: {message}"
        );
    }
    assert!(refused(&[ROUTE_6, &["--no-tcp-encryption"]].concat())
        .contains("encrypted data connections"));
    // A mapping the command names must be the one approved with it.
    let mapped = &[
        "cp",
        "--from",
        "host-b",
        "--mapping",
        "map",
        "--to",
        "host-c",
        "--into",
        "archive",
    ];
    // The approving machine never sees a mapping, which would choose the
    // files read on the source.
    assert!(refused(mapped).contains("cannot use --mapping"));
    // Nor can a directive carry one for a command without it.
    let (destination, mut source) = pair(ROUTE_6);
    let digest = Some(crate::mapping::Authorization {
        bytes: 1,
        digest: [0; 32],
    });
    source.inputs.mapping = digest.clone();
    let mut destination = destination;
    destination.inputs.mapping = digest;
    assert!(coordination(&source, &destination)
        .unwrap_err()
        .to_string()
        .contains("mapping does not match"));
    // Coordinating at the source is what the route does anyway.
    let (destination, source) = pair(&[ROUTE_6, &["--coordinate-at", "src"]].concat());
    coordination(&source, &destination).unwrap();
}

#[test]
fn a_coordinating_sources_peer_is_bounded() {
    let (destination, source) = pair(ROUTE_6);
    let refused = |change: &dyn Fn(&mut Peer)| {
        let mut other = source.clone();
        let Role::CoordinatingSource(peer) = &mut other.binding.role else {
            unreachable!()
        };
        change(peer);
        sign(&other, |_| Ok(armored(1))).unwrap_err().to_string()
    };
    assert!(
        refused(&|peer| peer.enrollment = source.binding.enrollment).contains("another receiver's")
    );
    assert!(refused(&|peer| peer.request = source.request_id).contains("another receiver's"));
    assert!(refused(&|peer| peer.destination = b"archive".to_vec()).contains("destination"));
    assert!(refused(&|peer| peer.destination = b"/a\0b".to_vec()).contains("destination"));
    assert!(
        refused(&|peer| peer.known_hosts = "x".repeat(MAX_KNOWN_HOSTS_BYTES + 1))
            .contains("known hosts")
    );
    assert!(refused(&|peer| peer.account = String::new()).contains("account"));
    drop(destination);
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
    let (limited_grant, limited) = destination_rules(&directive(&limited), home).unwrap();
    assert_eq!(limited_grant.copy, grant.copy);
    assert_eq!(limited, constraints);
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

    // What the command read from files comes beside it.
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

#[test]
fn an_approval_lists_as_many_sources_as_a_copy_takes_with_their_destination() {
    let home = Path::new(HOME);
    let names: Vec<String> = (0..1025).map(|i| format!("data-{i:04}")).collect();
    let command = |count: usize| {
        let mut args = vec!["cp", "--from", "host-a"];
        args.extend(names[..count].iter().map(String::as_str));
        args.extend(["--to", "host-b", "--into", "backup"]);
        directive(&args)
    };
    let (grant, _) = destination_rules(&command(1024), home).unwrap();
    assert_eq!(grant.copy.mutation_scopes.len(), 1025);
    let error = destination_rules(&command(1025), home).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("this copy names 1025 sources, more than the 1024 its approval can list"),
        "{message}"
    );
    assert!(message.contains("--srcs-in"), "{message}");
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

/// A machine that approves a server's command signs its own limits beside
/// it, and the receiver holds the copy to the lower of the two.
#[test]
fn the_approving_machines_limits_lower_the_commands() {
    let home = Path::new(HOME);
    let mut args = ROUTE_5.to_vec();
    args.extend(["--prune", "--receiver-max-entries", "50"]);
    let capped = |caps: Caps| {
        let mut directive = directive(&args);
        directive.caps = Some(caps);
        destination_rules(&directive, home)
    };
    let (grant, _) = capped(Caps {
        max_bytes: 1 << 20,
        max_entries: 10,
        max_delete: 3,
    })
    .unwrap();
    assert_eq!(grant.copy.limits.max_total_bytes, 1 << 20);
    assert_eq!(grant.copy.limits.max_file_bytes, 1 << 20);
    assert_eq!(grant.copy.limits.max_entries, 10);
    assert_eq!(grant.copy.limits.max_deletions, 3);
    // Limits above the command's leave it as it is.
    let (grant, _) = capped(Caps {
        max_bytes: u64::MAX,
        max_entries: u64::MAX,
        max_delete: u64::MAX,
    })
    .unwrap();
    assert_eq!(grant.copy.limits.max_entries, 50);
    assert_eq!(grant.copy.limits.max_deletions, 50);
    // Pruning, or a dry run of it, needs the machine to allow deletions.
    for dry_run in [false, true] {
        let mut directive = directive(&args);
        if dry_run {
            directive.command.push(b"--dry-run".to_vec());
        }
        directive.caps = Some(Caps {
            max_bytes: u64::MAX,
            max_entries: u64::MAX,
            max_delete: 0,
        });
        let error = destination_rules(&directive, home).unwrap_err().to_string();
        assert!(error.contains("positive --max-delete"), "{error}");
    }
}

fn source_directive(args: &[&str]) -> Directive {
    let mut directive = directive(args);
    directive.binding.role = Role::Source;
    directive
}

const ROUTE_4: &[&str] = &[
    "cp", "--from", "host-b", "--src", "data", "--src", "~/notes", "--into", "copy",
];

/// A source's reads come from its signed command, as the command reads
/// them: within the approving machine's limits, deleting nothing, and with
/// relative paths in the account's home, where its own logins start. The
/// role is part of the binding, so neither end's directive passes as the
/// other's.
#[test]
fn a_sources_reads_come_from_the_signed_command() {
    let home = Path::new(HOME);
    let original = source_directive(ROUTE_4);
    assert_eq!(
        Signed::decode(&signed(&original)).unwrap().directive,
        original
    );
    let mut capped = original.clone();
    capped.caps = Some(Caps {
        max_bytes: 1 << 20,
        max_entries: 10,
        max_delete: 7,
    });
    let reads = source_rules(&capped, home).unwrap();
    assert_eq!(
        reads
            .selections
            .iter()
            .map(|selection| selection.path.as_slice())
            .collect::<Vec<_>>(),
        [&b"data"[..], b"~/notes"]
    );
    assert_eq!(reads.base.path, None);
    assert_eq!(reads.resolved_base.as_deref(), Some(HOME.as_bytes()));
    assert_eq!(reads.limits.max_total_bytes, 1 << 20);
    assert_eq!(reads.limits.max_file_bytes, 1 << 20);
    assert_eq!(reads.limits.max_entries, 10);
    assert_eq!(reads.limits.max_deletions, 0);
    // A base in the home or absolute is where the command names it; a
    // relative one is in the home.
    for (base, resolved) in [
        ("work", Some("/home/backup/work")),
        ("~/work", None),
        ("~", None),
        ("/srv/data", None),
    ] {
        let args = [&ROUTE_4[..3], &["-C", base], &ROUTE_4[3..]].concat();
        let reads = source_rules(&source_directive(&args), home).unwrap();
        assert_eq!(reads.base.path.as_deref(), Some(base.as_bytes()), "{base}");
        assert_eq!(
            reads.resolved_base.as_deref(),
            resolved.map(str::as_bytes),
            "{base}"
        );
    }
    // Neither end's directive passes as the other's.
    assert!(destination_rules(&original, home)
        .unwrap_err()
        .to_string()
        .contains("not for a copy's destination"));
    assert!(source_rules(&directive(ROUTE_4), home)
        .unwrap_err()
        .to_string()
        .contains("not for a copy's source"));
    // Only a copy from one server to the requester, without options that
    // choose another route, and with the mapping its command reads.
    for refused in [
        ROUTE_5.to_vec(),
        [ROUTE_4, &["--rsh", "ssh"]].concat(),
        [ROUTE_4, &["--no-tcp-encryption"]].concat(),
        [ROUTE_4, &["--coordinate-at", "src"]].concat(),
        [ROUTE_4, &["--receiver-max-entries", "0"]].concat(),
    ] {
        assert!(
            source_rules(&source_directive(&refused), home).is_err(),
            "{refused:?}"
        );
    }
    let mut mapped = original.clone();
    mapped.inputs.mapping = Some(crate::mapping::Authorization {
        bytes: 1,
        digest: [0; 32],
    });
    assert!(source_rules(&mapped, home)
        .unwrap_err()
        .to_string()
        .contains("mapping does not match"));
    // SSH data is not a reason to refuse it, and then the source starts no
    // TCP listener either.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    assert!(reads.policy(deadline).tcp.is_some());
    let ssh_only =
        source_rules(&source_directive(&[ROUTE_4, &["--no-tcp"]].concat()), home).unwrap();
    assert!(ssh_only.policy(deadline).tcp.is_none());
}
