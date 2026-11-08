use super::*;

#[test]
fn home_is_shortened_only_as_a_path_prefix() {
    let home = Some(OsStr::new("/home/me"));
    assert_eq!(abbreviate_home(b"/home/me", home), b"~");
    assert_eq!(abbreviate_home(b"/home/me/rt-bench", home), b"~/rt-bench");
    assert_eq!(abbreviate_home(b"/home/meow/x", home), b"/home/meow/x");
    assert_eq!(abbreviate_home(b"/tmp/x", home), b"/tmp/x");
    assert_eq!(abbreviate_home(b"/home/me/a b", home), b"~/a b");
    assert_eq!(abbreviate_home(b"/home/me/x", None), b"/home/me/x");
    assert_eq!(
        abbreviate_home(b"/home/me/x", Some(OsStr::new(""))),
        b"/home/me/x"
    );
}

fn command(args: &[&str]) -> Vec<Vec<u8>> {
    args.iter().map(|arg| arg.as_bytes().to_vec()).collect()
}
#[test]
fn receiving_authorizer_checks_the_command_without_local_preferences() {
    let omitted = command(&["cp", "results", "--to", "backup"]);
    check_authorizer(&omitted, "laptop").unwrap();
    for (mode, accepted) in [
        ("auto", true),
        ("@laptop", true),
        ("ssh", false),
        ("@other", false),
    ] {
        let selected = command(&["cp", "results", "--to", "backup", "--auth-from", mode]);
        assert_eq!(
            check_authorizer(&selected, "laptop").is_ok(),
            accepted,
            "{mode}"
        );
    }
}

/// The requesting server's arguments for `command`: it parses the command
/// as a command line, then reads its ignore and mapping files.
fn server_args(command: &[Vec<u8>]) -> crate::cli::Args {
    let argv: Vec<OsString> = command
        .iter()
        .map(|arg| OsString::from_vec(arg.clone()))
        .collect();
    let mut args = crate::cli::Args::parse_args(&argv).unwrap();
    args.normalize();
    crate::persistence::mark_explicit_scope(&mut args).unwrap();
    args.read_copy_inputs().unwrap();
    if args.native_mapping.is_some() {
        args.mapping_contents = Some(std::sync::Arc::new(
            std::sync::Arc::unwrap_or_clone(crate::mapping::load(&args).unwrap()).input,
        ));
    }
    args
}
/// What the requesting server sends beside `args`' command.
fn server_inputs(args: &crate::cli::Args) -> crate::directive::Inputs {
    crate::directive::Inputs {
        ignore: args.ignore_lines.clone(),
        mapping: crate::directive::mapping_authorization(args).unwrap(),
    }
}
/// The directive a receiving machine issues for `command` and `inputs`.
fn issued(command: &[Vec<u8>], inputs: crate::directive::Inputs) -> crate::directive::Directive {
    crate::directive::issue_here(
        crate::directive::Binding {
            enrollment: crate::enrollment::EnrollmentId::random(),
            generation: 0,
            account: "@laptop".into(),
            role: crate::directive::Role::Destination,
        },
        command.to_vec(),
        String::new(),
        (inputs, None),
        [1; 32],
        std::time::Duration::from_secs(60),
    )
    .unwrap()
}
const RECEIVED_AT: &[u8] = b"/home/me/runs";
fn storage_request(command: &[Vec<u8>]) -> crate::s3::authorization::Request {
    let args = parse(command).unwrap();
    crate::s3::authorization::request_for(&args, args.s3.as_ref().unwrap()).unwrap()
}

#[test]
fn a_receiving_machine_approves_only_copies_to_its_own_name() {
    let to_laptop = command(&[
        "cp", "--src", "results", "--to", "@laptop", "--into", "runs",
    ]);
    receiving_command(&to_laptop, "laptop").unwrap();
    assert!(receiving_command(&to_laptop, "other").is_err());
    for argv in [
        &["cp", "--src", "results", "--to", "backup", "--into", "runs"][..],
        &[
            "cp",
            "--src",
            "results",
            "--to",
            "s3://bucket",
            "--into",
            "runs",
        ],
    ] {
        assert!(
            receiving_command(&command(argv), "laptop").is_err(),
            "{argv:?}"
        );
    }
}

#[test]
fn server_files_supply_only_their_own_contents() {
    // Parsing on this machine must not read the server's files.
    for file_args in [
        &["--mapping", "/nonexistent/mapping"][..],
        &["--src", "results", "--ignore-from", "/nonexistent/ignore"],
    ] {
        let mut argv = vec!["cp"];
        argv.extend_from_slice(file_args);
        argv.extend(["--to", "@laptop", "--into", "runs"]);
        let with_file = command(&argv);
        let mapped = receiving_command(&with_file, "laptop")
            .unwrap()
            .native_mapping
            .is_some();
        let mapping = Some(crate::mapping::Authorization::from_contents(b"{}"));
        let inputs = crate::directive::Inputs {
            ignore: vec!["*.tmp".into()],
            mapping: if mapped { mapping.clone() } else { None },
        };
        let (_, constraints) =
            crate::directive::receiving_rules(&issued(&with_file, inputs.clone()), RECEIVED_AT)
                .unwrap();
        assert_eq!(constraints.filters.ignore, ["*.tmp"]);
        assert_eq!(constraints.mapping, inputs.mapping);
        // The server cannot leave out the mapping its command names, nor add
        // one it does not.
        let flipped = crate::directive::Inputs {
            mapping: if mapped { None } else { mapping },
            ..inputs
        };
        assert!(
            crate::directive::receiving_rules(&issued(&with_file, flipped), RECEIVED_AT).is_err()
        );
    }
}

#[test]
fn ignore_rules_come_from_the_server_and_only_narrow() {
    let command = command(&[
        "cp",
        "--src",
        "tree",
        "--ignore",
        "a",
        "--to",
        "@laptop",
        "--into",
        "runs",
        "--prune",
        "--max-delete",
        "5",
    ]);
    let rules = |ignore: &[&str]| {
        crate::directive::receiving_rules(
            &issued(
                &command,
                crate::directive::Inputs {
                    ignore: ignore.iter().map(|line| line.to_string()).collect(),
                    mapping: None,
                },
            ),
            RECEIVED_AT,
        )
        .unwrap()
    };
    let (stated, stated_constraints) = rules(&["a"]);
    assert_eq!(stated.copy.limits.max_deletions, 5);
    assert!(!stated_constraints.filters.delete_excluded);
    // Whatever rules the server read, what they restrict is the command's.
    for lines in [&[][..], &["b"], &["!a", "a"]] {
        let (grant, constraints) = rules(lines);
        assert_eq!(constraints.filters.ignore, lines);
        assert_eq!(grant.copy, stated.copy);
        assert!(!constraints.filters.delete_excluded);
    }
}

#[test]
fn derivation_ignores_this_machines_files() {
    // A source path that is a pipe here names an ordinary file on the server.
    let temp = crate::test_support::tempdir().unwrap();
    let fifo = temp.path().join("fifo");
    let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let fifo = fifo.to_str().unwrap();
    let copy = command(&["cp", "--src", fifo, "--to", "@laptop", "--into", "runs"]);
    receiving_command(&copy, "laptop").unwrap();
    let (grant, _) = crate::directive::receiving_rules(
        &issued(&copy, crate::directive::Inputs::default()),
        RECEIVED_AT,
    )
    .unwrap();
    assert_eq!(grant.copy.mutation_scopes[1].path, b"/home/me/runs/fifo");

    // A source that is a pipe on the server becomes a stream upload there.
    let upload = command(&[
        "cp",
        "--src",
        "/server/pipe",
        "--to",
        "s3://bucket",
        "--as",
        "log",
        "--auth-from",
        "@laptop",
    ]);
    let args = parse_with(&upload, crate::cli::SourceProbe::AssumePipes).unwrap();
    let plan = args.descriptor_copy.as_ref().unwrap();
    let stream = crate::s3::stream::authorization_request(
        &args,
        args.s3.as_ref().unwrap(),
        plan.key.as_deref().unwrap(),
        plan.placement.existence,
    );
    check_storage(&upload, &stream, "laptop").unwrap();
    check_storage(&upload, &storage_request(&upload), "laptop").unwrap();
    let mut changed = stream.clone();
    changed.scopes[0].key = "other".into();
    assert!(check_storage(&upload, &changed, "laptop").is_err());
}

#[test]
fn storage_requests_must_match_the_command_shown() {
    for options in [
        &["--src", "results", "--to", "s3://bucket", "--into", "runs"][..],
        &["--src", "runs", "--from", "s3://bucket", "--into", "local"],
        &[
            "--src",
            "runs",
            "--from",
            "s3://source",
            "--to",
            "s3://bucket",
            "--into",
            "copy",
        ],
        &[
            "--src",
            "file",
            "--to",
            "s3://bucket",
            "--as",
            "file",
            "--if-exists=keep",
        ],
    ] {
        let command = command(
            &["cp"]
                .iter()
                .chain(options)
                .chain(&["--auth-from", "@laptop", "--s3-profile", "storage"])
                .copied()
                .collect::<Vec<_>>(),
        );
        let request = storage_request(&command);
        check_storage(&command, &request, "laptop").unwrap();
        assert!(check_storage(&command, &request, "other").is_err());
        let mut changed = request.clone();
        changed.delete = true;
        assert!(check_storage(&command, &changed, "laptop").is_err());
        let mut changed = request.clone();
        changed.profile = Some("admin".into());
        assert!(check_storage(&command, &changed, "laptop").is_err());
        let mut changed = request.clone();
        changed.scopes[0].key = "elsewhere".into();
        assert!(check_storage(&command, &changed, "laptop").is_err());
    }
}

#[test]
fn storage_removal_and_streams_derive_the_same_request() {
    let removal = command(&[
        "rm",
        "--src",
        "old",
        "--on",
        "s3://bucket",
        "--auth-from",
        "@laptop",
    ]);
    check_storage(&removal, &storage_request(&removal), "laptop").unwrap();

    let stream = command(&[
        "cp",
        "--src-fd",
        "0",
        "--to",
        "s3://bucket",
        "--as",
        "log",
        "--auth-from",
        "@laptop",
    ]);
    let args = parse(&stream).unwrap();
    let plan = args.descriptor_copy.as_ref().unwrap();
    let mut request = crate::s3::stream::authorization_request(
        &args,
        args.s3.as_ref().unwrap(),
        plan.key.as_deref().unwrap(),
        plan.placement.existence,
    );
    check_storage(&stream, &request, "laptop").unwrap();
    request.upload = false;
    assert!(check_storage(&stream, &request, "laptop").is_err());
}

#[test]
fn a_server_endpoint_is_accepted_only_when_the_command_names_none() {
    let plain = command(&[
        "cp",
        "--src",
        "results",
        "--to",
        "s3://bucket",
        "--auth-from",
        "@laptop",
    ]);
    let mut request = storage_request(&plain);
    request.endpoint = Some("https://storage.example".into());
    check_storage(&plain, &request, "laptop").unwrap();

    let named = command(&[
        "cp",
        "--src",
        "results",
        "--to",
        "s3://bucket",
        "--auth-from",
        "@laptop",
        "--s3-endpoint",
        "https://storage.example",
    ]);
    let mut request = storage_request(&named);
    check_storage(&named, &request, "laptop").unwrap();
    request.endpoint = Some("https://other.example".into());
    assert!(check_storage(&named, &request, "laptop").is_err());
}

#[test]
fn only_copy_and_removal_commands_are_accepted() {
    for argv in [
        &["exec", "--on", "@laptop", "--", "true"][..],
        &["rsync", "-a", "src", "dst"],
        &["--help"],
        &["cp", "--help"],
        &[],
    ] {
        assert!(parse(&command(argv)).is_err(), "{argv:?}");
    }
    assert!(parse(&[vec![b'x'; MAX_COMMAND_BYTES]]).is_err());
}

#[test]
fn displayed_commands_escape_unusual_text_and_mark_server_files() {
    let shown = display(&[
        b"cp".to_vec(),
        b"--src".to_vec(),
        b"two words".to_vec(),
        b"bad\x1b[31m".to_vec(),
        b"\xff".to_vec(),
        "rtl\u{202e}txt".as_bytes().to_vec(),
        b"--mapping".to_vec(),
        b"map.json".to_vec(),
        b"--ignore-from=rules".to_vec(),
        b"--ignore".to_vec(),
        b"*.tmp".to_vec(),
        b"--ignore=*.log".to_vec(),
        b"--mapping=my files.ndjson".to_vec(),
        b"--to".to_vec(),
        b"@laptop".to_vec(),
    ]);
    assert_eq!(shown[..4], ["syq", "cp", "--src", "\"two words\""]);
    for word in &shown {
        assert!(
            !word.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{word}"
        );
    }
    let styled = std::cell::RefCell::new(Vec::new());
    render(&shown, None, str::to_owned, |word| {
        styled.borrow_mut().push(word.to_owned());
        word.to_owned()
    });
    assert_eq!(
        styled.into_inner(),
        [
            "map.json",
            "--ignore-from=rules",
            "\"*.tmp\"",
            "\"--ignore=*.log\"",
            "\"--mapping=my files.ndjson\"",
        ]
    );
    assert!(display(&[]).is_empty());
}

/// Replay the requesting server's steps between parsing and sending: reading
/// ignore and mapping files, then sending the command and what it read. The
/// rules this machine derives from them must be those of the copy the server
/// runs, its arguments after reading those files.
#[test]
fn server_side_preparation_matches_derivation_for_many_copy_options() {
    let temp = crate::test_support::tempdir().unwrap();
    let ignore = temp.path().join("ignore");
    std::fs::write(&ignore, "*.tmp\nbuild/\n").unwrap();
    let mapping = temp.path().join("mapping.ndjson");
    std::fs::write(
        &mapping,
        r#"{"src":{"encoding":"utf-8","value":"a"},"dst":{"encoding":"utf-8","value":"b/a"}}"#
            .to_owned()
            + "\n",
    )
    .unwrap();
    let ignore = ignore.to_str().unwrap();
    let mapping = mapping.to_str().unwrap();
    let root = temp.path().to_str().unwrap();
    let cases: &[&[&str]] = &[
        &["--src", "a", "--src", "b/c", "--to", "@laptop"],
        &["--srcs-in", "tree", "--to", "@laptop", "--into", "runs"],
        &["--src-dir", "tree", "--to", "@laptop", "--into-new", "runs"],
        &["--src", "file", "--to", "@laptop", "--as", "copy"],
        &["--src", "file", "--to", "@laptop", "--as-new", "copy"],
        &["--src", "tree", "--to", "@laptop", "--into", "/abs/path"],
        &[
            "--cwd", root, "--src", "tree", "--to", "@laptop", "--into", "runs",
        ],
        &["--root", root, "--src", "tree", "--to", "@laptop"],
        &[
            "--src",
            "tree",
            "--to",
            "@laptop",
            "--into",
            "runs",
            "--prune",
            "--max-delete",
            "3",
        ],
        &["--src", "tree", "--to", "@laptop", "--if-exists=keep"],
        &[
            "--src",
            "tree",
            "--to",
            "@laptop",
            "--if-exists=error-if-different",
        ],
        &[
            "--src",
            "tree",
            "--to",
            "@laptop",
            "--copy-metadata=permissions",
        ],
        &[
            "--src",
            "tree",
            "--to",
            "@laptop",
            "--ignore",
            "*.log",
            "--ignore-from",
            ignore,
        ],
        &["--src", "tree", "--to", "@laptop", "--ignore", "*.log"],
        &[
            "--src",
            "tree",
            "--ignore-from",
            ignore,
            "--ignore",
            "keep/",
            "--to",
            "@laptop",
        ],
        &["--mapping", mapping, "--to", "@laptop", "--into", "runs"],
        &["--src", "tree", "--to", "@laptop", "--dry-run"],
        &["--src", "tree", "--to", "@laptop", "--no-compress"],
        &[
            "--src",
            "tree",
            "--to",
            "@laptop",
            "--resource-limits",
            "workers=4",
        ],
    ];
    for case in cases {
        let command = command(&[&["cp"][..], case].concat());
        let args = server_args(&command);
        let directive = issued(&command, server_inputs(&args));
        let received = crate::directive::receiving_rules(&directive, RECEIVED_AT)
            .unwrap_or_else(|e| panic!("{case:?}: {e:#}"));
        let run = crate::directive::rules_for_args(&directive, &args, RECEIVED_AT)
            .unwrap_or_else(|e| panic!("{case:?}: {e:#}"));
        assert_eq!(received, run, "{case:?}");
    }
}

#[test]
fn displayed_commands_hide_customer_encryption_keys() {
    let shown = display(&command(&[
        "cp",
        "--s3-header",
        "x-amz-server-side-encryption-customer-key: c2VjcmV0",
        "--s3-write-header=X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key:c2VjcmV0",
        "--s3-header",
        "x-amz-server-side-encryption-customer-key-MD5: bWQ1",
        "--s3-write-header",
        "x-amz-storage-class: STANDARD",
    ]));
    let text = shown.join(" ");
    assert!(!text.contains("c2VjcmV0"), "{text}");
    assert!(
        text.contains("\"x-amz-server-side-encryption-customer-key: <redacted>\""),
        "{text}"
    );
    assert!(text.contains("<redacted>\" --s3-header"), "{text}");
    assert!(text.contains("bWQ1") && text.contains("STANDARD"), "{text}");
}

#[test]
fn long_commands_are_shortened_in_desktop_prompts() {
    let mut argv = vec!["cp".to_owned()];
    for index in 0..10_000 {
        argv.extend(["--src".to_owned(), format!("source-{index}")]);
    }
    argv.extend(["--to".into(), "@laptop".into()]);
    let shown = display(&command(
        &argv.iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    let short = render(&shown, Some(400), str::to_owned, str::to_owned);
    assert!(short.chars().count() < 450, "{}", short.len());
    assert!(short.ends_with("… (full command in syq persist receive pending)"));
    assert!(render(&shown, None, str::to_owned, str::to_owned).ends_with("--to @laptop"));
}

#[test]
fn a_command_too_long_for_an_approval_is_refused_with_advice() {
    let mut command = vec![b"cp".to_vec()];
    // 1,023 arguments of 255 bytes and their terminators, with "cp", fit.
    command.extend((0..1023).map(|i| format!("{i:0255}").into_bytes()));
    let room = MAX_COMMAND_BYTES - command_bytes(&command);
    command.push(vec![b'x'; room - 1]);
    assert!(ensure_command_fits(&command, 1024).is_ok());
    command.last_mut().unwrap().push(b'x');
    let error = ensure_command_fits(&command, 1024).unwrap_err();
    assert!(
        error.to_string().contains(
            "this copy names 1024 sources, which make its command 257 KiB, more than the 256 KiB its approval can carry"
        ),
        "{error:#}"
    );
    assert!(error.to_string().contains("--srcs-in"), "{error:#}");
}
