use super::{
    native_engine_defaults, parse_native_copy, parse_native_endpoint, parse_native_rm, parse_size,
    read_files_from_reader, rsync_operator_symlink_policy, Args, EnvironmentOptions,
    NativeCopyCommand, Placement, SourceSelection,
};
use crate::proto::OperatorSymlinkPolicy;
use anyhow::{bail, Result};
use clap::Parser;
use std::ffi::OsString;

fn argv(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

#[test]
fn environment_options_follow_the_command_name_and_precede_argv() {
    let options = EnvironmentOptions(vec![
        (
            "cp",
            OsString::from("--performance-tuning workers=4 --quiet"),
        ),
        ("rm", OsString::from("")),
    ]);
    let mut cp = argv(&["syq", "cp", "src", "--into", "dst"]);
    options.insert(&mut cp).unwrap();
    assert_eq!(
        cp,
        argv(&[
            "syq",
            "cp",
            "--performance-tuning",
            "workers=4",
            "--quiet",
            "src",
            "--into",
            "dst"
        ])
    );
    for untouched in [
        argv(&["syq", "rm", "old"]),
        argv(&["syq", "rsync", "a", "b"]),
        argv(&["syq", "persist", "status"]),
        argv(&["syq", "--server"]),
        argv(&["syq"]),
    ] {
        let mut copy = untouched.clone();
        options.insert(&mut copy).unwrap();
        assert_eq!(copy, untouched);
    }
}

#[test]
fn environment_options_keep_quoting_and_reject_unbalanced_quotes() {
    let options = EnvironmentOptions(vec![("rm", OsString::from("--cwd 'my dir'"))]);
    let mut rm = argv(&["syq", "rm", "old"]);
    options.insert(&mut rm).unwrap();
    assert_eq!(rm, argv(&["syq", "rm", "--cwd", "my dir", "old"]));

    let options = EnvironmentOptions(vec![("rsync", OsString::from("--syq-no-tcp 'oops"))]);
    let error = options
        .insert(&mut argv(&["syq", "rsync", "a", "b"]))
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("SYQ_RSYNC_OPTIONS is not a valid shell word list"),
        "{error}"
    );
}

fn read_files_from_buffered_reference(raw: &[u8], nul: bool) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let items: Vec<&[u8]> = if nul {
        raw.split(|&byte| byte == 0).collect()
    } else {
        raw.split(|&byte| byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .collect()
    };
    for item in items {
        if item.is_empty() || matches!(item.first(), Some(b'#' | b';')) {
            continue;
        }
        if item.contains(&0) {
            bail!("entry contains a NUL byte");
        }
        if item.split(|&byte| byte == b'/').any(|part| part == b"..") {
            bail!("entry contains a `..` component");
        }
        let parts: Vec<&[u8]> = item
            .split(|&byte| byte == b'/')
            .filter(|part| *part != b"." && !part.is_empty())
            .collect();
        if parts.is_empty() {
            bail!("entry names the source root itself");
        }
        out.push(parts.join(&b'/'));
    }
    Ok(out)
}

#[test]
fn files_from_is_parsed_record_by_record() {
    let lines = b"a//b\r\ncomment\0inside\n./#literal\n; ignored\n";
    assert!(read_files_from_reader(&lines[..], false).is_err());
    assert_eq!(
        read_files_from_reader(&b"a//b\r\n./#literal\n; ignored\n"[..], false).unwrap(),
        [b"a/b".to_vec(), b"#literal".to_vec()]
    );
    assert_eq!(
        read_files_from_reader(&b"a/./b\0./;literal\0"[..], true).unwrap(),
        [b"a/b".to_vec(), b";literal".to_vec()]
    );
}

#[test]
fn insecure_links_is_the_rsync_operator_path_opt_out() {
    assert_eq!(
        rsync_operator_symlink_policy(false),
        OperatorSymlinkPolicy::TrustedOwner
    );
    assert_eq!(
        rsync_operator_symlink_policy(true),
        OperatorSymlinkPolicy::FollowAll
    );
}

#[test]
fn incremental_files_from_keeps_buffered_parser_validation() {
    const ALPHABET: &[u8] = b"a./\r\n\0#;";
    for nul in [false, true] {
        for length in 0usize..=5 {
            let cases = ALPHABET.len().pow(length as u32);
            for mut encoded in 0..cases {
                let mut raw = vec![0; length];
                for byte in &mut raw {
                    *byte = ALPHABET[encoded % ALPHABET.len()];
                    encoded /= ALPHABET.len();
                }
                let expected = read_files_from_buffered_reference(&raw, nul);
                let actual = read_files_from_reader(&raw[..], nul);
                assert_eq!(
                    actual.as_ref().ok(),
                    expected.as_ref().ok(),
                    "input {raw:?}, nul={nul}; actual={actual:?}, expected={expected:?}"
                );
                assert_eq!(
                    actual.is_err(),
                    expected.is_err(),
                    "input {raw:?}, nul={nul}; actual={actual:?}, expected={expected:?}"
                );
            }
        }
    }
}

fn args(options: &[&str]) -> Args {
    let mut argv = vec!["syq"];
    argv.extend_from_slice(options);
    argv.extend_from_slice(&["src", "dst"]);
    let mut args = Args::try_parse_from(argv).unwrap();
    args.normalize();
    args
}

#[test]
fn compression_defaults_on_and_can_be_disabled() {
    assert!(args(&[]).compress);
    assert!(args(&["-z"]).compress);
    assert!(!args(&["--no-compress"]).compress);

    // As with other clap overrides, the last spelling wins.
    assert!(!args(&["-z", "--no-compress"]).compress);
    assert!(args(&["--no-compress", "-z"]).compress);
}

#[test]
fn tcp_congestion_names_are_validated() {
    assert_eq!(
        args(&["--syq-tcp-congestion", "bbr"])
            .tcp_congestion
            .as_deref(),
        Some("bbr")
    );
    assert_eq!(
        args(&["--syq-tcp-congestion", "foo-bar"])
            .tcp_congestion
            .as_deref(),
        Some("foo-bar")
    );
    for value in ["", "1234567890123456"] {
        let parsed = Args::try_parse_from(["syq", "--syq-tcp-congestion", value, "src", "dst"]);
        assert!(parsed.is_err(), "accepted {value:?}");
    }
    assert!(Args::try_parse_from([
        "syq",
        "--syq-tcp-congestion",
        "bbr",
        "--syq-no-tcp",
        "src",
        "dst",
    ])
    .is_err());
}

#[test]
fn size_parser_checks_sign_and_range() {
    assert_eq!(parse_size("1.5K").unwrap(), 1536);
    assert_eq!(parse_size("18446744073709551615").unwrap(), u64::MAX);
    for value in ["-1", "18446744073709551616", "16777216T", "1e999"] {
        assert!(parse_size(value).is_err(), "accepted {value:?}");
    }
}

#[test]
fn native_copy_policy_is_rsync_rlt() {
    let args = native_engine_defaults();
    assert!(args.recursive);
    assert!(args.links);
    assert!(args.times);
    assert!(!args.perms);
    assert!(!args.owner);
    assert!(!args.group);
    assert!(!args.devices);
}

#[test]
fn comparison_block_size_is_a_native_advanced_control() {
    let args = parse_native_copy(
        &[
            "source",
            "--as",
            "destination",
            "--performance-tuning=comparison-block-size=64K,request-size=4M",
        ]
        .map(OsString::from),
    )
    .unwrap();
    assert_eq!(args.block_size, 64 << 10);
    assert_eq!(args.tuning_options.unwrap().request_size, Some(4 << 20));
    let error = parse_native_copy(
        &[
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "object",
            "--performance-tuning=comparison-block-size=64K",
        ]
        .map(OsString::from),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("filesystem performance tuning"),
        "{error}"
    );
    for spelling in ["-B", "--block-size"] {
        let args =
            Args::parse_rsync(&["source", "destination", spelling, "128K"].map(OsString::from))
                .unwrap();
        assert_eq!(args.block_size, 128 << 10);
        let error = Args::parse_rsync(
            &[
                "source",
                "destination",
                spelling,
                "128K",
                "--performance-tuning=comparison-block-size=64K",
            ]
            .map(OsString::from),
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts"), "{error}");
    }
    let args = Args::parse_rsync(
        &[
            "source",
            "destination",
            "--performance-tuning=comparison-block-size=128K",
        ]
        .map(OsString::from),
    )
    .unwrap();
    assert_eq!(args.block_size, 128 << 10);
}

#[test]
fn rsync_comparison_block_size_validates_during_argument_parsing() {
    for spelling in ["-B", "--block-size"] {
        for (raw, expected) in [("64K", 64 << 10), ("4M", 4 << 20), ("64M", 64 << 20)] {
            let args = Args::try_parse_from(["syq rsync", spelling, raw, "src", "dst"]).unwrap();
            assert_eq!(args.block_size, expected);
        }
        for raw in ["0", "32K", "65M", "invalid"] {
            let error =
                Args::try_parse_from(["syq rsync", spelling, raw, "src", "dst"]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
            let message = error.to_string();
            assert_eq!(message.matches("--block-size").count(), 1, "{message}");
            assert!(!message.contains("comparison-block-size"), "{message}");
            let reason = if raw == "invalid" {
                "bad size suffix"
            } else {
                "must be between 65536 and 67108864 bytes"
            };
            assert!(message.contains(reason), "{message}");
        }
    }
}

#[test]
fn automatic_workers_have_only_the_requested_ceiling() {
    for (extra, expected) in [
        (None, usize::MAX),
        (Some("--resource-limits=workers=1000"), 1000),
        (Some("--resource-limits=workers=65536"), 65536),
    ] {
        let mut argv: Vec<_> = ["source", "--as", "target"].map(OsString::from).into();
        argv.extend(extra.map(OsString::from));
        let args = parse_native_copy(&argv).unwrap();
        assert!(args.connections_default);
        assert_eq!(args.automatic_worker_limit(), expected);
    }
}

#[test]
fn automatic_workers_still_respect_restricted_receiver_authority() {
    let mut args = native_engine_defaults();
    args.restricted_grant = Some("signed grant".into());
    assert_eq!(args.automatic_worker_limit(), 128);
    args.resource_limits = Some(crate::advanced::ResourceLimits {
        workers: Some(3),
        ..Default::default()
    });
    assert_eq!(args.automatic_worker_limit(), 3);
}

#[test]
fn resource_limits_keep_automatic_workers_and_reject_conflicts() {
    let args = parse_native_copy(
        &["source", "--as", "target", "--resource-limits=workers=3"].map(OsString::from),
    )
    .unwrap();
    assert!(args.connections_default);
    assert_eq!(args.automatic_worker_limit(), 3);
    for extra in [
        "--performance-tuning=workers=3",
        "--resource-limits=workers=2",
        "--resource-limits=s3-objects=2",
    ] {
        assert!(parse_native_copy(
            &[
                "source",
                "--as",
                "target",
                "--resource-limits=workers=3",
                extra
            ]
            .map(OsString::from)
        )
        .is_err());
    }
    for key in ["s3-requests", "s3-objects", "s3-parts-per-object"] {
        let limit = format!("--resource-limits={key}=3");
        let fixed = format!("--performance-tuning={key}=3");
        let mut flags = vec!["source", "--to", "s3://bucket", "--as", "object", &limit];
        assert!(parse_native_copy(&flags.iter().map(OsString::from).collect::<Vec<_>>()).is_ok());
        flags.push(&fixed);
        assert!(parse_native_copy(&flags.iter().map(OsString::from).collect::<Vec<_>>()).is_err());
    }
    assert!(parse_native_copy(
        &[
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "object",
            "--resource-limits=workers=3"
        ]
        .map(OsString::from)
    )
    .is_err());
}

#[test]
fn advanced_groups_separate_limits_tuning_and_integrity() {
    let args = parse_native_copy(
        &[
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "object",
            "--resource-limits=bandwidth=1M",
            "--performance-tuning=s3-objects=3,s3-requests=4,s3-parts-per-object=2,s3-part-size=8M",
            "--integrity-checking=compare=blake3,transfer=sha256",
        ]
        .map(OsString::from),
    )
    .unwrap();
    let tuning = args.tuning_options.unwrap();
    assert_eq!(tuning.s3_requests, Some(4));
    assert_eq!(tuning.s3_object_workers, Some(3));
    assert_eq!(
        tuning
            .to_string()
            .parse::<crate::transfer_tuning::TransferTuning>()
            .unwrap(),
        tuning
    );
    assert_eq!(args.bwlimit_bytes, 1 << 20);
    assert!(args.checksum);
    assert!(args.transfer_integrity);
    assert_eq!(
        args.transfer_hash_type,
        Some(crate::hashing::HashAlgorithm::Sha256)
    );
    let options = args.s3.unwrap();
    assert_eq!(options.concurrency, 2);
    assert_eq!(options.part_size, 8 << 20);
    for flags in [
        vec!["--resource-limits=connections=2"],
        vec!["--hash", "--integrity-checking=compare=sha256"],
        vec![
            "--performance-tuning=workers=2",
            "--performance-tuning=workers=3",
        ],
    ] {
        let mut argv = vec!["source", "--as", "target"];
        argv.extend(flags);
        assert!(
            parse_native_copy(&argv.into_iter().map(OsString::from).collect::<Vec<_>>()).is_err()
        );
    }
    for old in [
        "--connections=2",
        "--bwlimit=1M",
        "--tuning-options=workers=2",
        "--s3-concurrency=2",
        "--s3-part-size=8",
        "--s3-integrity=none",
        "--hash-algorithm=sha256",
        "--transfer-integrity",
    ] {
        assert!(
            NativeCopyCommand::try_parse_from(["cp", "source", "--as", "target", old]).is_err()
        );
    }
}

#[test]
fn rsync_hash_controls_use_syq_prefix() {
    let mut parsed = Args::try_parse_from([
        "syq",
        "--integrity-checking",
        "compare=xxh3-128",
        "--integrity-checking=transfer=blake3",
        "source",
        "destination",
    ])
    .unwrap();
    parsed.apply_advanced().unwrap();
    assert_eq!(parsed.hash_algorithm, crate::hashing::HashAlgorithm::Xxh3);
    assert!(parsed.transfer_integrity);
    for option in [
        "--hash-algorithm=md5",
        "--transfer-integrity",
        "--expected-hash=md5:900150983cd24fb0d6963f7d28e17f72",
    ] {
        assert!(Args::try_parse_from(["syq", option, "source", "destination"]).is_err());
    }
}

#[test]
fn native_hash_selects_content_comparison() {
    let argv = ["--hash", "source", "--into", "destination"].map(std::ffi::OsString::from);
    let args = parse_native_copy(&argv).unwrap();
    assert!(args.checksum);
}

#[test]
fn payload_checks_and_encryption_are_independent() {
    for plain in [false, true] {
        for integrity in [false, true] {
            let mut argv = vec![
                "source",
                "--into",
                "destination",
                "--integrity-checking=compare=xxh3-128",
            ];
            if plain {
                argv.push("--tcp-plain");
            }
            if integrity {
                argv.push("--integrity-checking=transfer=blake3");
            }
            let args = parse_native_copy(
                &argv
                    .iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert_eq!(args.tcp_plain, plain);
            assert_eq!(args.transfer_integrity, integrity);
            assert_eq!(args.hash_algorithm, crate::hashing::HashAlgorithm::Xxh3);
            assert!(args.checksum);
        }
    }
}

#[test]
fn native_copy_policies_lower_to_the_shared_engine() {
    let argv = [
        "--follow",
        "--ignore",
        "*.tmp",
        "--ignore",
        "!keep.tmp",
        "--preserve=permissions,ownership,specials",
        "--inplace",
        "source",
        "--into",
        "destination",
    ]
    .map(std::ffi::OsString::from);
    let mut args = parse_native_copy(&argv).unwrap();
    args.read_copy_inputs().unwrap();
    assert!(args.native_follow);
    assert_eq!(args.ignore_lines, ["*.tmp", "!keep.tmp"]);
    assert!(args.perms);
    assert!(args.owner);
    assert!(args.group);
    assert!(args.devices);
    assert!(args.inplace);
    assert!(args.min_size.is_none());
    assert!(args.max_size.is_none());
}

#[test]
fn native_directional_follow_is_distinct_from_the_umbrella() {
    let argv = [
        "--follow-src",
        "source",
        "--follow-dst",
        "--into",
        "destination",
    ]
    .map(std::ffi::OsString::from);
    let args = parse_native_copy(&argv).unwrap();
    assert!(!args.native_follow);
    assert!(args.native_follow_src);
    assert!(args.native_follow_dst);
    assert!(args.follows_native_source_paths());
    assert!(args.follows_native_destination_paths());

    let argv = ["--follow", "source", "--into", "destination"].map(std::ffi::OsString::from);
    let args = parse_native_copy(&argv).unwrap();
    assert!(args.native_follow);
    assert!(!args.native_follow_src);
    assert!(!args.native_follow_dst);
    assert!(args.follows_native_source_paths());
    assert!(args.follows_native_destination_paths());
}

#[test]
fn native_prune_lowers_to_shared_deletion_policy() {
    let argv = [
        "--prune",
        "--max-delete=3",
        "source",
        "--into",
        "destination",
    ]
    .map(std::ffi::OsString::from);
    let args = parse_native_copy(&argv).unwrap();
    assert!(args.delete);
    assert_eq!(args.max_delete, Some(3));
}

#[test]
fn native_remote_controls_lower_to_the_shared_engine() {
    let argv = [
        "--coordinate-at=dst",
        "--rsh=ssh -J jump",
        "--syq-path=/opt/syq",
        "--no-tcp",
        "--tcp-ports=49000-49010",
        "--detach",
        "source",
        "--into",
        "destination",
    ]
    .map(std::ffi::OsString::from);
    let args = parse_native_copy(&argv).unwrap();
    assert_eq!(args.coordinate_at, super::CoordinateAt::Dst);
    assert_eq!(args.rsh.as_deref(), Some("ssh -J jump"));
    assert_eq!(args.syq_path.as_deref(), Some("/opt/syq"));
    assert!(!args.no_bootstrap);
    assert!(args.no_tcp);
    assert_eq!(args.tcp_ports, "49000-49010");
    assert!(args.detach);
}

#[test]
fn native_rm_named_paths_use_existing_file_selector_and_preserve_s3_marker_keys() {
    let argv = ["one", "--src=two", "--srcs", "three", "four"].map(std::ffi::OsString::from);
    let args = parse_native_rm(&argv).unwrap();
    assert_eq!(args.locations.len(), 4);
    assert!(args
        .locations
        .iter()
        .all(|l| l.selection == SourceSelection::File));
    let argv =
        ["--on=s3://bucket", "foo/", "--s3-version-id=version"].map(std::ffi::OsString::from);
    let args = parse_native_rm(&argv).unwrap();
    assert_eq!(args.locations[0].path, b"foo/");
}

#[test]
fn native_rm_lowers_remote_helper_selection() {
    let argv = ["--on=backup", "--syq-path=/opt/syq", "old"].map(std::ffi::OsString::from);
    let args = parse_native_rm(&argv).unwrap();
    assert_eq!(args.syq_path.as_deref(), Some("/opt/syq"));
    assert!(!args.no_bootstrap);

    let argv = ["--on=backup", "--no-bootstrap", "old"].map(std::ffi::OsString::from);
    let args = parse_native_rm(&argv).unwrap();
    assert!(args.syq_path.is_none());
    assert!(args.no_bootstrap);
}

#[test]
fn native_rm_rejects_remote_helper_selection_for_local_removal() {
    let argv = ["--syq-path=/opt/syq", "old"].map(std::ffi::OsString::from);
    let error = parse_native_rm(&argv).unwrap_err();
    assert!(error
        .to_string()
        .contains("apply only to a remote removal endpoint"));
}

#[test]
fn native_persistence_scope_rejects_an_explicit_remote_shell() {
    let argv = [
        "--pscope=/tmp/scope",
        "--rsh=ssh -J jump",
        "source",
        "--into",
        "destination",
    ]
    .map(std::ffi::OsString::from);
    let error = parse_native_copy(&argv).unwrap_err();
    assert!(error
        .to_string()
        .contains("--pscope cannot be used with --rsh"));
}

#[test]
fn native_endpoints_are_separate_from_paths() {
    assert_eq!(
        parse_native_endpoint(Some("alice@example.test")).unwrap(),
        Some(super::NativeEndpoint {
            user: Some("alice".into()),
            host: "example.test".into(),
            port: None,
        })
    );
    assert_eq!(
        parse_native_endpoint(Some("[2001:db8::1]")).unwrap(),
        Some(super::NativeEndpoint {
            user: None,
            host: "2001:db8::1".into(),
            port: None,
        })
    );
    assert_eq!(
        parse_native_endpoint(Some("alice@example.test:2222")).unwrap(),
        Some(super::NativeEndpoint {
            user: Some("alice".into()),
            host: "example.test".into(),
            port: Some(2222),
        })
    );
    assert_eq!(
        parse_native_endpoint(Some("alice@[2001:db8::1]:2200")).unwrap(),
        Some(super::NativeEndpoint {
            user: Some("alice".into()),
            host: "2001:db8::1".into(),
            port: Some(2200),
        })
    );
    for host in ["-oProxyCommand=evil", "user@-oProxyCommand=evil", "[-evil]"] {
        assert!(parse_native_endpoint(Some(host)).is_err(), "{host}");
        assert!(
            super::Location::parse(&format!("{host}:path")).is_err(),
            "{host}"
        );
    }
    assert!(parse_native_endpoint(Some("host:path")).is_err());
    assert!(parse_native_endpoint(Some("2001:db8::1")).is_err());
    assert!(parse_native_endpoint(Some("host:0")).is_err());
    assert!(parse_native_endpoint(Some("host]:2222")).is_err());
    assert!(parse_native_endpoint(Some("bad user@host")).is_err());
    assert!(parse_native_endpoint(Some("host/path")).is_err());
}

#[test]
fn native_source_arguments_must_precede_destination_arguments() {
    for (argv, source_argument) in [
        (
            vec![
                "source",
                "--to",
                "target.test",
                "--from",
                "source.test",
                "--into",
                "dest",
            ],
            "--from",
        ),
        (vec!["--into", "dest", "source"], "a positional source"),
        (vec!["source", "--into", "dest", "--src", "extra"], "--src"),
        (vec!["--into", "dest", "--mapping", "manifest"], "--mapping"),
        (
            vec!["source", "--to=target.test", "extra", "--into", "dest"],
            "a positional source",
        ),
        (
            vec![
                "source",
                "--to",
                "target.test",
                "--cwd",
                "base",
                "--into",
                "dest",
            ],
            "--cwd",
        ),
    ] {
        let argv = argv
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        let error = parse_native_copy(&argv).unwrap_err().to_string();
        assert!(error.contains(source_argument), "{error}");
        assert!(
            error.contains("must appear before destination arguments"),
            "{error}"
        );
    }
}

#[test]
fn native_remote_copy_default_placement_and_prune_guard() {
    use super::Existence;
    use std::ffi::OsString;
    for argv in [
        vec!["foo", "--to", "j5"],
        vec!["foo", "--from", "j5"],
        vec!["--from", "j5", "foo"],
        vec!["--from", "j5", "foo", "--to", "j6"],
        vec!["--from", "j5", "--mapping", "manifest"],
    ] {
        let argv = argv.into_iter().map(OsString::from).collect::<Vec<_>>();
        let args = parse_native_copy(&argv).unwrap();
        assert_eq!(args.placement, Placement::Into);
        assert_eq!(args.target_existence, Existence::Any);
        assert_eq!(args.locations.last().unwrap().path, b".");
        let mut pruning = argv;
        // Mapping has a separate clap-level conflict with --prune.
        if pruning.iter().any(|arg| arg == "--mapping") {
            continue;
        }
        pruning.push(OsString::from("--prune"));
        let error = parse_native_copy(&pruning).unwrap_err().to_string();
        assert!(
            error.contains("--prune requires an explicit placement"),
            "{error}"
        );
        pruning.extend(["--into", "."].map(OsString::from));
        assert!(parse_native_copy(&pruning).unwrap().delete);
    }
    assert!(parse_native_copy(&[OsString::from("foo")]).is_err());
}

#[test]
fn native_operational_options_may_follow_destination_arguments() {
    let argv = [
        "one",
        "--cwd",
        "base",
        "--from",
        "source.test",
        "--to",
        "target.test",
        "--into",
        "dest",
        "--dry-run",
        "--follow-src",
    ]
    .map(std::ffi::OsString::from);
    let args = parse_native_copy(&argv).unwrap();
    assert_eq!(args.placement, Placement::Into);
    assert_eq!(args.locations.len(), 2);
    assert_eq!(args.locations[0].host.as_deref(), Some("source.test"));
    assert_eq!(args.locations[0].path, b"one");
    assert_eq!(args.locations[0].selection, SourceSelection::NamedNoFollow);
    assert_eq!(args.native_source_cwd.as_deref(), Some(&b"base"[..]));
    assert!(args.native_source_root.is_none());
    assert_eq!(args.locations[1].host.as_deref(), Some("target.test"));
    assert_eq!(args.locations[1].path, b"dest");
    assert!(args.dry_run);
    assert!(args.native_follow_src);
}

#[test]
fn removed_native_options_fail_before_reading_sources() {
    for option in [
        "--via=@laptop",
        "--min-size=1",
        "--max-size=1",
        "--expected-hash=md5:900150983cd24fb0d6963f7d28e17f72",
    ] {
        let error =
            NativeCopyCommand::try_parse_from(["cp", option, "missing", "--into", "destination"])
                .unwrap_err()
                .to_string();
        assert!(error.contains("unexpected argument"), "{option}: {error}");
    }
    assert!(Args::try_parse_from([
        "syq",
        "--syq-expected-hash=md5:900150983cd24fb0d6963f7d28e17f72",
        "a",
        "b"
    ])
    .is_err());
    let args = Args::try_parse_from(["syq", "--min-size=1", "--max-size=2", "a", "b"]).unwrap();
    assert_eq!(args.min_size.as_deref(), Some("1"));
    assert_eq!(args.max_size.as_deref(), Some("2"));
}

#[test]
fn storage_authorization_is_explicit_and_preserves_provider_options() {
    for source in [vec!["source"], vec!["--src-fd", "0"]] {
        let mut command = source;
        command.extend([
            "--to",
            "s3://bucket",
            "--as",
            "key",
            "--auth-from",
            "@laptop",
            "--s3-profile",
            "storage",
        ]);
        let args = parse_native_copy(&argv(&command)).unwrap();
        assert!(matches!(args.auth_from, super::AuthFrom::Return(ref name) if name == "laptop"));
        assert_eq!(args.s3.unwrap().profile.as_deref(), Some("storage"));
    }
    for mode in ["auto", "ssh"] {
        let error = parse_native_copy(&argv(&[
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "key",
            "--auth-from",
            mode,
        ]))
        .unwrap_err();
        assert!(
            error.to_string().contains("requires --auth-from @NAME"),
            "{error}"
        );
    }
}

#[test]
fn storage_callbacks_preserve_an_explicit_authorizer() {
    let args = parse_native_copy(&argv(&[
        "--mapping",
        "manifest",
        "--stream-mapping-fd",
        "4",
        "--results-fd",
        "5",
        "--to",
        "s3://bucket",
        "--into",
        "keys",
        "--auth-from",
        "@laptop",
    ]))
    .unwrap();
    assert_eq!(args.stream_mapping_fd, Some(4));
    assert!(matches!(args.auth_from, super::AuthFrom::Return(ref name) if name == "laptop"));
}

#[test]
fn inode_preservation_is_explicit_and_rejects_nonfilesystem_routes() {
    let mut archive = Args::try_parse_from(["syq", "-a", "source", "destination"]).unwrap();
    archive.normalize();
    assert!(
        !archive.hardlinks
            && !archive.acls
            && !archive.xattrs
            && archive.atimes == 0
            && !archive.crtimes
            && !archive.open_noatime
            && !archive.sparse
    );
    let mut acls = Args::try_parse_from(["syq", "-A", "source", "destination"]).unwrap();
    acls.normalize();
    assert!(acls.acls && acls.perms);
    let native = parse_native_copy(&argv(&[
        "--preserve=hardlinks,acls,xattrs,atimes,crtimes",
        "--open-noatime",
        "--sparse",
        "source",
        "--into",
        "destination",
    ]))
    .unwrap();
    assert!(
        native.hardlinks
            && native.acls
            && native.xattrs
            && native.perms
            && native.atimes == 1
            && native.crtimes
            && native.open_noatime
            && native.sparse
    );
    for option in [
        "--preserve=acls",
        "--preserve=xattrs",
        "--preserve=atimes",
        "--preserve=crtimes",
        "--open-noatime",
        "--sparse",
    ] {
        for route in [
            vec![option, "--src-fd=0", "--as", "destination"],
            vec![option, "source", "--to", "s3://bucket", "--into", "prefix"],
        ] {
            let error = parse_native_copy(&argv(&route)).expect_err("route must be refused");
            let message = error.to_string();
            assert!(
                message.contains("named filesystem")
                    || (matches!(option, "--open-noatime" | "--sparse")
                        && message.contains("not supported")),
                "{error:#}"
            );
        }
    }
}
