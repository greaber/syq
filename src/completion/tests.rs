use super::*;

fn values(candidates: Vec<Candidate>) -> Vec<Vec<u8>> {
    candidates
        .into_iter()
        .map(|candidate| candidate.value)
        .collect()
}

#[test]
fn splits_local_and_rsync_remote_paths_without_confusing_colons_in_ipv6() {
    assert_eq!(
        split_path(b"a/b"),
        (b"a".to_vec(), b"a/".to_vec(), b"b".to_vec())
    );
    assert_eq!(
        split_rsync_remote(b"host:dir/f"),
        Some((&b"host"[..], &b"dir/f"[..]))
    );
    assert_eq!(
        split_rsync_remote(b"alice@[2001:db8::1]:dir"),
        Some((&b"alice@[2001:db8::1]"[..], &b"dir"[..]))
    );
    assert_eq!(split_rsync_remote(b"./a:b"), None);
    assert_eq!(split_rsync_remote(b"host::module"), None);
}

#[test]
fn bash_request_treats_every_replacement_as_literal_data() {
    for replacement in ["", "-", "--", "--co", "--help", "-h", "help", "--version"] {
        let line = format!("syq cp {replacement}");
        let argv = ["__complete-bash", replacement, "--", &line].map(OsString::from);
        let action = parse_action(&argv)
            .unwrap_or_else(|error| panic!("replacement {replacement:?}: {error}"));
        let CompletionAction::CompleteBash {
            replacement: parsed,
            line: parsed_line,
        } = action
        else {
            panic!("wrong action for {replacement:?}");
        };
        assert_eq!(parsed, replacement);
        assert_eq!(parsed_line, line.as_str());
    }
}

#[test]
fn completion_indices_allow_an_omitted_empty_word_but_reject_out_of_range() {
    let words = [OsString::from("syq")];
    assert!(values(candidates(1, &words).unwrap()).contains(&b"cp".to_vec()));
    assert!(candidates(2, &words).unwrap().is_empty());
    assert!(candidates(usize::MAX, &words).unwrap().is_empty());
}

#[test]
fn bash_request_mini_fuzzer_preserves_raw_bytes() {
    // All non-NUL bytes can occur in argv, including invalid UTF-8. Test
    // each byte next to syntax that clap and Bash would normally parse.
    for byte in 1..=255 {
        for prefix in [
            b"".as_slice(),
            b"-",
            b"--",
            b"'",
            b"\"",
            b"\\",
            b"a=",
            b"a:",
        ] {
            let mut fragment = prefix.to_vec();
            fragment.push(byte);
            let mut line = b"syq cp ".to_vec();
            line.extend_from_slice(&fragment);
            let argv = [
                OsString::from("__complete-bash"),
                OsString::from_vec(fragment.clone()),
                OsString::from("--"),
                OsString::from_vec(line.clone()),
            ];
            let CompletionAction::CompleteBash {
                replacement,
                line: parsed,
            } = parse_action(&argv).unwrap()
            else {
                panic!("wrong action for {fragment:?}");
            };
            assert_eq!(replacement.as_bytes(), fragment);
            assert_eq!(parsed.as_bytes(), line);
            let (index, words) = bash_command_words(parsed.as_bytes());
            assert!(index < words.len());
            assert!(words.iter().map(Vec::len).sum::<usize>() <= line.len());
        }
    }
}

#[test]
fn bash_line_parser_preserves_ssh_syntax_quotes_and_escapes() {
    let line = b"syq cp --cwd 'dir with spaces' user@host:some\\ path/fi";
    assert_eq!(
        bash_command_words(line),
        (
            4,
            vec![
                b"syq".to_vec(),
                b"cp".to_vec(),
                b"--cwd".to_vec(),
                b"dir with spaces".to_vec(),
                b"user@host:some path/fi".to_vec(),
            ]
        )
    );
    assert_eq!(
        bash_command_words(b"printf x | syq rsync host:di"),
        (
            2,
            vec![b"syq".to_vec(), b"rsync".to_vec(), b"host:di".to_vec()]
        )
    );
    assert_eq!(
        bash_command_words(b"syq cp "),
        (2, vec![b"syq".to_vec(), b"cp".to_vec(), Vec::new()])
    );
    assert_eq!(
        bash_command_words("syq cp éa".as_bytes()),
        (
            2,
            vec![b"syq".to_vec(), b"cp".to_vec(), "éa".as_bytes().to_vec()]
        )
    );
}

#[test]
fn bash_candidates_replace_only_the_fragment_after_a_word_break() {
    let candidates = vec![
        Candidate::text(b"host:dir/file".to_vec()),
        Candidate::prefix(b"host:dir/nested/".to_vec()),
    ];
    let candidates = bash_replacement_candidates(candidates, b"host:di", b"di");
    assert_eq!(candidates[0].value, b"dir/file");
    assert!(!candidates[0].no_space);
    assert_eq!(candidates[1].value, b"dir/nested/");
    assert!(candidates[1].no_space);

    assert_eq!(
        values(bash_replacement_candidates(
            vec![Candidate::text(b"--from=fake.example".to_vec())],
            b"--from=fake",
            b"fake",
        )),
        vec![b"fake.example".to_vec()]
    );
    assert_eq!(
        values(bash_replacement_candidates(
            vec![Candidate::text(b"alice@example".to_vec())],
            b"alice@ex",
            b"ex",
        )),
        vec![b"@example".to_vec()]
    );
}

#[test]
fn leading_shell_assignments_do_not_hide_the_syq_command() {
    let words = ["SYQ_COMPLETION_DEBUG=1", "FOO=x", "syq", "c"].map(OsString::from);
    let candidates = values(candidates(3, &words).unwrap());
    assert!(candidates.contains(&b"cp".to_vec()));
    assert!(candidates.contains(&b"completion".to_vec()));
    assert!(is_shell_assignment(b"_FOO_2=value"));
    assert!(!is_shell_assignment(b"2FOO=value"));
    assert!(!is_shell_assignment(b"--from=value"));
}

#[test]
fn root_bases_reject_paths_that_can_escape_the_root() {
    let root = Some(SourceBase::Root(b"/confined"));
    assert!(apply_path_base(root, b"../sibling").is_none());
    assert!(apply_path_base(root, b"/absolute").is_none());
    assert!(apply_path_base(root, b"~/home").is_none());
    assert_eq!(
        apply_path_base(root, b"inside/..").map(|directory| directory.path),
        Some(b"/confined/inside/..".to_vec())
    );
}

#[test]
fn attached_rsync_rsh_options_disable_remote_completion() {
    assert!(has_explicit_rsh("rsync", &[b"-efalse".to_vec()]));
    assert!(has_explicit_rsh("rsync", &[b"-avefalse".to_vec()]));
    assert!(has_explicit_rsh("rsync", &[b"--rsh=false".to_vec()]));
    assert!(!has_explicit_rsh("rsync", &[b"-Bsize".to_vec()]));
    assert!(!has_explicit_rsh("cp", &[b"-efalse".to_vec()]));
}

#[test]
fn option_policy_stops_at_the_double_dash_terminator() {
    let args = vec![
        b"--from".to_vec(),
        b"real.example".to_vec(),
        b"--".to_vec(),
        b"--from".to_vec(),
        b"fake.example".to_vec(),
        b"--rsh=false".to_vec(),
        b"--no-bootstrap".to_vec(),
    ];
    assert_eq!(
        find_option_bytes(&args, b"--from"),
        Some(&b"real.example"[..])
    );
    assert!(!has_explicit_rsh("cp", &args));
    assert!(!contains_option(&args, b"--no-bootstrap"));
    let terminated_value = vec![
        b"--from".to_vec(),
        b"--".to_vec(),
        b"--from".to_vec(),
        b"fake.example".to_vec(),
    ];
    assert_eq!(find_option_bytes(&terminated_value, b"--from"), None);
    assert!(!has_explicit_rsh(
        "rsync",
        &[b"--".to_vec(), b"-avefalse".to_vec()]
    ));
}

#[test]
fn completion_cache_lock_fails_immediately_when_already_held() {
    let temporary = crate::test_support::tempdir().unwrap();
    let directory = open_cache_directory(temporary.path(), true)
        .unwrap()
        .unwrap();
    let _first = lock_cache(temporary.path(), &directory).unwrap();
    let error = lock_cache(temporary.path(), &directory).err().unwrap();
    assert!(error.to_string().contains("completion cache is busy"));
}

#[test]
fn path_candidates_preserve_raw_names_and_mark_directories() {
    let candidates = path_candidates_from_entries(
        b"host:",
        b"dir/",
        b"n",
        vec![
            CompletionEntry {
                name: b"name\nwith-newline".to_vec(),
                directory: false,
            },
            CompletionEntry {
                name: b"nested".to_vec(),
                directory: true,
            },
        ],
    );
    assert_eq!(candidates[0].value, b"host:dir/name\nwith-newline");
    assert!(!candidates[0].no_space);
    assert_eq!(candidates[1].value, b"host:dir/nested/");
    assert!(candidates[1].no_space);
}

#[test]
fn root_and_option_candidates_come_from_public_command_metadata() {
    assert!(values(root_candidates(b"c")).contains(&b"cp".to_vec()));
    assert!(root_candidates(b"_l").is_empty());
    let listing = public_command("_ls").unwrap();
    assert_eq!(
        values(option_candidates(&listing, b"--conc")),
        vec![b"--concurrency".to_vec()]
    );
    let command = crate::cli::command_for_completion("cp").unwrap();
    let options = values(option_candidates(&command, b"--coor"));
    assert_eq!(options, vec![b"--coordinate-at".to_vec()]);
    assert_eq!(
        values(option_candidates(&command, b"--help-a")),
        vec![b"--help-all".to_vec()]
    );
    assert!(values(root_candidates(b"--help-a")).contains(&b"--help-all".to_vec()));
}

#[test]
fn native_option_looking_values_are_completed_as_options_unless_attached() {
    let options =
        values(filesystem_command_candidates("cp", &[b"--src-dir".to_vec()], b"--i").unwrap());
    assert!(options.contains(&b"--ignore".to_vec()));
    assert!(options.contains(&b"--into".to_vec()));
}

#[test]
fn native_copy_stops_completing_sources_after_the_destination_starts() {
    let args = [b"source".to_vec(), b"--into".to_vec(), b"target".to_vec()];
    assert!(filesystem_command_candidates("cp", &args, b"")
        .unwrap()
        .is_empty());

    let options = values(filesystem_command_candidates("cp", &args, b"--").unwrap());
    assert!(options.contains(&b"--dry-run".to_vec()));
    assert!(!options.contains(&b"--src".to_vec()));
    assert!(!options.contains(&b"--mapping".to_vec()));

    let mut invalid_source = args.to_vec();
    invalid_source.push(b"--src".to_vec());
    assert!(filesystem_command_candidates("cp", &invalid_source, b"s")
        .unwrap()
        .is_empty());
}

#[test]
fn remote_entries_are_strictly_validated() {
    assert!(validate_completion_entries(
        vec![CompletionEntry {
            name: b"../escape".to_vec(),
            directory: false,
        }],
        b""
    )
    .is_err());
    assert!(validate_completion_entries(
        vec![CompletionEntry {
            name: b"wrong".to_vec(),
            directory: false,
        }],
        b"prefix"
    )
    .is_err());
}

#[test]
fn rsync_endpoint_suggestions_never_treat_a_native_port_as_a_path() {
    let endpoint = NativeEndpoint {
        user: Some("alice".into()),
        host: "example".into(),
        port: Some(2222),
    };
    assert_eq!(endpoint_label(&endpoint), "alice@example:2222");
    assert!(endpoint_candidate_value(&endpoint, "alice", EndpointSyntax::Rsync).is_none());
    assert_eq!(
        endpoint_candidate_value(&endpoint, "alice", EndpointSyntax::Native).as_deref(),
        Some("alice@example:2222")
    );
}

#[test]
fn version_prefix_keeps_command_completion_and_never_completes_a_download() {
    for words in [
        vec!["syq", "--use-version", "0.7.1", "cp", "--int"],
        vec!["syq", "--use-version=0.7.1", "cp", "--int"],
        vec![
            "syq",
            "--version-is",
            ">=0.7.1, <1.0.0 | 2.0.0",
            "cp",
            "--int",
        ],
        vec!["syq", "--version-is=0.7.1", "cp", "--int"],
        vec![
            "syq",
            "--version-is=0.7.1",
            "--use-version",
            "0.7.0",
            "cp",
            "--int",
        ],
        vec![
            "syq",
            "--use-version=0.7.0",
            "--version-is",
            "0.7.1",
            "cp",
            "--int",
        ],
    ] {
        let words = words.into_iter().map(OsString::from).collect::<Vec<_>>();
        assert!(values(candidates(words.len() - 1, &words).unwrap()).contains(&b"--into".to_vec()));
    }
    for args in [
        vec!["syq", "--use-version", ""],
        vec!["syq", "--version-is", ""],
        vec!["syq", "--use-version=0.7.0", "--version-is", ""],
        vec!["syq", "--version-is=0.7.1", "--use-version", ""],
    ] {
        let words = args.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(candidates(words.len() - 1, &words).unwrap().is_empty());
    }
    let words = ["syq", "--version-is=0.7.1", "c"].map(OsString::from);
    assert!(values(candidates(2, &words).unwrap()).contains(&b"cp".to_vec()));
    let words = ["syq", "--vers"].map(OsString::from);
    assert!(values(candidates(1, &words).unwrap()).contains(&b"--version-is".to_vec()));
}

// Use the same framed socket transport as a ready pooled connection. The
// fake peer withholds every reply until it has read the complete query flight.
fn completion_transport() -> (RemoteConn, std::os::unix::net::UnixStream) {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let (client, server) = UnixStream::pair().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    crate::proto::FrameWriter::new(client.try_clone().unwrap(), false)
        .write_preamble()
        .unwrap();
    crate::proto::FrameWriter::new(server.try_clone().unwrap(), false)
        .write_msg(&Response::HelloOk {
            descriptors: None,
            identity: crate::identity::build().into(),
            platform: crate::identity::platform(),
            supports_confined_socket_nodes: false,
            ssh_worker_ticket: None,
        })
        .unwrap();
    let session = crate::session_pool::PooledSession {
        stdin: File::from(OwnedFd::from(client.try_clone().unwrap())),
        stdout: File::from(OwnedFd::from(client)),
        stderr: File::open("/dev/null").unwrap(),
    };
    let mut connection = RemoteConn::from_pooled(session, false, "completion test".into()).unwrap();
    assert!(matches!(
        connection.recv().unwrap(),
        Response::HelloOk { .. }
    ));
    (connection, server)
}

fn one_completion_entry() -> Vec<CompletionEntry> {
    vec![CompletionEntry {
        name: b"alpha".to_vec(),
        directory: false,
    }]
}

#[test]
fn remote_completion_pipelines_metadata_before_waiting_for_names() {
    for follow in [false, true] {
        for detailed in [false, true] {
            let (mut connection, server) = completion_transport();
            let policy = PathCompletionPolicy::new(OperatorSymlinkPolicy::TrustedOwner, follow);
            let peer = std::thread::spawn(move || {
                let mut reader = crate::proto::FrameReader::new(server.try_clone().unwrap());
                for expected_details in [false, true].into_iter().take(if detailed { 2 } else { 1 })
                {
                    let request: Request = reader.read_msg().unwrap();
                    let expected = remote_listing_request(
                        b"dir".to_vec(),
                        Some(b"root".to_vec()),
                        b"al".to_vec(),
                        policy,
                        expected_details,
                    );
                    assert_eq!(
                        serde_json::to_value(request).unwrap(),
                        serde_json::to_value(expected).unwrap()
                    );
                }
                let mut writer = crate::proto::FrameWriter::with_preamble_written(server, false);
                writer
                    .write_msg(&Response::DirectoryEntries {
                        entries: one_completion_entry(),
                        truncated: false,
                    })
                    .unwrap();
                if detailed {
                    writer
                        .write_msg(&Response::DetailedDirectoryEntries {
                            entries: one_completion_entry(),
                            details: vec!["file metadata".into()],
                            truncated: false,
                        })
                        .unwrap();
                }
                // A names-only query must not request optional metadata.
                assert!(matches!(
                    reader.read_msg::<Request>().unwrap(),
                    Request::Shutdown
                ));
            });
            let names = start_remote_listing(
                &mut connection,
                b"dir".to_vec(),
                Some(b"root".to_vec()),
                b"al".to_vec(),
                policy,
                detailed,
            );
            let details = if names.is_ok() && detailed {
                Some(receive_remote_entries(&mut connection, b"al"))
            } else {
                None
            };
            drop(connection);
            peer.join().unwrap();
            assert_eq!(names.unwrap().0[0].name, b"alpha");
            if let Some(details) = details {
                assert_eq!(details.unwrap().1, ["file metadata"]);
            }
        }
    }
}

#[test]
fn remote_completion_keeps_names_when_pipelined_metadata_is_slow() {
    let (mut connection, server) = completion_transport();
    let (release, gate) = std::sync::mpsc::sync_channel(1);
    let peer = std::thread::spawn(move || {
        let mut reader = crate::proto::FrameReader::new(server.try_clone().unwrap());
        assert!(matches!(
            reader.read_msg::<Request>().unwrap(),
            Request::ListDir { .. }
        ));
        assert!(matches!(
            reader.read_msg::<Request>().unwrap(),
            Request::ListDirDetails { .. }
        ));
        let mut writer = crate::proto::FrameWriter::with_preamble_written(server, false);
        writer
            .write_msg(&Response::DirectoryEntries {
                entries: one_completion_entry(),
                truncated: false,
            })
            .unwrap();
        gate.recv_timeout(Duration::from_secs(8)).unwrap();
        writer
            .write_msg(&Response::DetailedDirectoryEntries {
                entries: one_completion_entry(),
                details: vec!["late metadata".into()],
                truncated: false,
            })
            .unwrap();
    });
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = start_remote_listing(
            &mut connection,
            b"dir".to_vec(),
            None,
            b"al".to_vec(),
            PathCompletionPolicy::new(OperatorSymlinkPolicy::TrustedOwner, true),
            true,
        );
        let okay = result.is_ok();
        let _ = sender.send(result);
        if okay {
            let _ = sender.send(receive_remote_entries(&mut connection, b"al"));
        }
    });
    let started = std::time::Instant::now();
    let result = receive_remote_listing(receiver, true);
    let elapsed = started.elapsed();
    // Release blocked work before any assertion can unwind.
    let _ = release.send(());
    worker.join().unwrap();
    peer.join().unwrap();
    let (entries, details) = result.unwrap();
    assert_eq!(entries[0].name, b"alpha");
    assert_eq!(details, ["[metadata unavailable]"]);
    assert!(elapsed >= COMPLETION_DETAILS_DEADLINE);
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}
