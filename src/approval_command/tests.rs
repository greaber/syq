use super::*;

fn command(args: &[&str]) -> Vec<Vec<u8>> {
    args.iter().map(|arg| arg.as_bytes().to_vec()).collect()
}
fn policy() -> crate::receipt::ReceiptPolicy {
    let (_, public) = crate::receipt::generate_recipient().unwrap();
    crate::receipt::ReceiptPolicy {
        required: true,
        hashed: false,
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
            suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: public,
        },
    }
}
/// What the requesting server sends for `command`: it parses the command as a
/// command line, reads its ignore and mapping files, then builds the request.
fn copy_request(command: &[Vec<u8>]) -> crate::destination::CopyRequest {
    let argv: Vec<OsString> = command
        .iter()
        .map(|arg| OsString::from_vec(arg.clone()))
        .collect();
    let mut args = crate::cli::Args::parse_args(&argv).unwrap();
    args.normalize();
    crate::persistence::mark_explicit_scope(&mut args);
    args.read_copy_inputs().unwrap();
    if args.native_mapping.is_some() {
        args.mapping_contents = Some(std::sync::Arc::new(
            std::sync::Arc::unwrap_or_clone(crate::mapping::load(&args).unwrap()).input,
        ));
    }
    crate::restricted::named_request(&args, policy()).unwrap()
}
fn storage_request(command: &[Vec<u8>]) -> crate::s3::authorization::Request {
    let args = parse(command).unwrap();
    crate::s3::authorization::request_for(&args, args.s3.as_ref().unwrap()).unwrap()
}

#[test]
fn copy_requests_must_match_the_command_shown() {
    for options in [
        &[][..],
        &["--prune", "--max-delete", "5"],
        &["--if-exists=keep"],
        &["--no-compress", "--performance-tuning", "workers=3"],
        &["--dry-run"],
    ] {
        let command = command(
            &[
                "cp", "--src", "results", "--to", "@laptop", "--into", "runs",
            ]
            .iter()
            .chain(options)
            .copied()
            .collect::<Vec<_>>(),
        );
        let request = copy_request(&command);
        check_copy(&command, &request, Some("laptop"), None).unwrap();
        assert!(check_copy(&command, &request, Some("other"), None).is_err());

        let mut changed = request.clone();
        changed.copy.limits.max_deletions += 1;
        assert!(check_copy(&command, &changed, Some("laptop"), None).is_err());
        let mut changed = request.clone();
        changed.destination = b"elsewhere".to_vec();
        assert!(check_copy(&command, &changed, Some("laptop"), None).is_err());
        let mut changed = request.clone();
        changed.copy.options.preserve_permissions ^= true;
        assert!(check_copy(&command, &changed, Some("laptop"), None).is_err());
    }
}

#[test]
fn server_files_supply_only_their_own_contents() {
    // Parsing on this machine must not read the server's files.
    let with_files = command(&[
        "cp",
        "--mapping",
        "/nonexistent/mapping",
        "--ignore-from",
        "/nonexistent/ignore",
        "--to",
        "@laptop",
        "--into",
        "runs",
    ]);
    let mut request =
        crate::restricted::named_request(&parse(&with_files).unwrap(), policy()).unwrap();
    request.constraints.filters.ignore = vec!["*.tmp".into()];
    request.constraints.mapping = Some(crate::mapping::Authorization::from_contents(b"{}"));
    check_copy(&with_files, &request, Some("laptop"), None).unwrap();
    request.copy.policy.deletion = crate::delegation::DeletionPolicy::DeleteDestinationOnly;
    assert!(check_copy(&with_files, &request, Some("laptop"), None).is_err());

    // Without a mapping file, the server cannot add a mapping.
    let inline = command(&[
        "cp", "--src", "results", "--ignore", "*.log", "--to", "@laptop",
    ]);
    let mut request = copy_request(&inline);
    assert_eq!(request.constraints.filters.ignore, ["*.log"]);
    check_copy(&inline, &request, Some("laptop"), None).unwrap();
    request.constraints.mapping = Some(crate::mapping::Authorization::from_contents(b"{}"));
    assert!(check_copy(&inline, &request, Some("laptop"), None).is_err());
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
    let request = copy_request(&command);
    assert_eq!(request.constraints.filters.ignore, ["a"]);
    for lines in [&[][..], &["b"], &["!a", "a"]] {
        let mut changed = request.clone();
        changed.constraints.filters.ignore = lines.iter().map(|line| line.to_string()).collect();
        check_copy(&command, &changed, Some("laptop"), None).unwrap();
    }
    // What the ignore rules restrict is still checked.
    let mut changed = request.clone();
    changed.copy.limits.max_deletions += 1;
    assert!(check_copy(&command, &changed, Some("laptop"), None).is_err());
    let mut changed = request;
    changed.constraints.filters.delete_excluded = true;
    assert!(check_copy(&command, &changed, Some("laptop"), None).is_err());
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
    let request = crate::restricted::named_request(
        &parse_with(&copy, crate::cli::SourceProbe::AssumeFiles).unwrap(),
        policy(),
    )
    .unwrap();
    check_copy(&copy, &request, Some("laptop"), None).unwrap();

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
fn forwarded_copies_name_their_ssh_destination() {
    let command = command(&[
        "cp", "--src", "results", "--to", "backup", "--into", "/archive",
    ]);
    let request = copy_request(&command);
    check_copy(&command, &request, None, Some("backup")).unwrap();
    assert!(check_copy(&command, &request, None, Some("other")).is_err());
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
/// ignore and mapping files, then building the request. Every combination must
/// match what this machine derives from the same command without those files.
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
        check_copy(&command, &copy_request(&command), Some("laptop"), None)
            .unwrap_or_else(|e| panic!("{case:?}: {e:#}"));
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
    assert!(short.ends_with("… (full command in Details)"));
    assert!(render(&shown, None, str::to_owned, str::to_owned).ends_with("--to @laptop"));
}
