use super::*;

/// Check meaning as well as framing, against explicit fixture expectations in
/// every backend format. The expected values never come from another adapter.
fn assert_completion_candidates(t: &Tmp, words: &[&str], expected: &[&str]) {
    for shell in ["bash", "zsh", "fish"] {
        let index = (words.len() - 1).to_string();
        let mut args = vec!["__complete", shell, &index, "--"];
        args.extend_from_slice(words);
        let output = completion_command(t, &args)
            .current_dir(t.path(""))
            .env("SYQ_COMPLETION_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(output.stderr.is_empty(), "{shell} {words:?}: {output:?}");
        let mut actual: Vec<Vec<u8>> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
            .map(|record| {
                if shell == "fish" {
                    record.to_vec()
                } else {
                    record[1..].to_vec()
                }
            })
            .collect();
        actual.sort();
        let mut expected: Vec<Vec<u8>> = expected
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        expected.sort();
        assert_eq!(actual, expected, "{shell} {words:?}");
    }
}

#[test]
fn completion_source_bases_types_and_symlink_policies_match_operations() {
    let t = Tmp::new();
    write(&t.path("base/inside.txt"), b"inside");
    write(&t.path("base/inner-dir/nested.txt"), b"nested");
    write(&t.path("outside.txt"), b"outside");
    std::os::unix::fs::symlink("base", t.path("link")).unwrap();
    std::os::unix::fs::symlink("../..", t.path("base/escape")).unwrap();
    for command in ["cp", "rm", "map"] {
        for base in [
            vec!["--cwd", "base"],
            vec!["-C", "base"],
            vec!["--root", "base"],
            vec!["--cwd=base"],
            vec!["--root=base"],
            vec!["-Cbase"],
            vec!["-C=base"],
        ] {
            let mut words = vec!["syq", command];
            words.extend(base);
            words.push("in");
            assert_completion_candidates(&t, &words, &["inner-dir/", "inside.txt"]);
        }
        assert_completion_candidates(&t, &["syq", command, "-Cba"], &["-Cbase/"]);
        assert_completion_candidates(&t, &["syq", command, "--cwd", ""], &["base/"]);
        for selector in ["--src-dir", "--src-dirs", "--srcs-in"] {
            assert_completion_candidates(
                &t,
                &["syq", command, "--cwd", "base", selector, "in"],
                &["inner-dir/"],
            );
        }
        assert_completion_candidates(
            &t,
            &["syq", command, "--root", "base", "inner-dir//"],
            &["inner-dir//nested.txt"],
        );
        assert_completion_candidates(&t, &["syq", command, "--root", "base", "../"], &[]);
        assert_completion_candidates(
            &t,
            &["syq", command, "--root", "base", "--follow-src", "escape/"],
            &[],
        );
        for follow in ["--follow", "--follow-src"] {
            for selector in ["--src-dir", "--src-dirs", "--srcs-in"] {
                assert_completion_candidates(
                    &t,
                    &["syq", command, follow, selector, "li"],
                    if command == "rm" { &[] } else { &["link/"] },
                );
            }
            assert_completion_candidates(
                &t,
                &["syq", command, follow, "li"],
                if command == "rm" {
                    &["link"]
                } else {
                    &["link/"]
                },
            );
            for base in ["--cwd", "--root"] {
                assert_completion_candidates(&t, &["syq", command, follow, base, "li"], &["link/"]);
            }
        }
        assert_completion_candidates(&t, &["syq", command, "link/"], &[]);
        assert_completion_candidates(
            &t,
            &["syq", command, "--follow-src", "link/in"],
            &["link/inner-dir/", "link/inside.txt"],
        );
    }
    assert_completion_candidates(
        &t,
        &["syq", "cp", "-nCbase", "in"],
        &["inner-dir/", "inside.txt"],
    );
    assert_completion_candidates(&t, &["syq", "cp", "--follow-dst", "link/"], &[]);
    assert_completion_candidates(
        &t,
        &["syq", "cp", "--cwd", "base", "inside.txt", "--into", ""],
        &["base/"],
    );
    assert_completion_candidates(&t, &["syq", "cp", "outside.txt", "--into", "link/"], &[]);
    assert_completion_candidates(
        &t,
        &[
            "syq",
            "cp",
            "outside.txt",
            "--follow-dst",
            "--into",
            "link/in",
        ],
        &["link/inner-dir/"],
    );
    assert_completion_candidates(
        &t,
        &[
            "syq",
            "cp",
            "outside.txt",
            "--into",
            "base",
            "--results",
            "ba",
        ],
        &["base/"],
    );
    assert_completion_candidates(
        &t,
        &["syq", "rm", "--cwd", "base", "--results", "ba"],
        &["base/"],
    );
}

#[test]
fn completion_covers_public_command_routes_and_parser_value_grammar() {
    let t = Tmp::new();
    fs::create_dir(t.path("scope")).unwrap();
    assert_completion_candidates(
        &t,
        &["syq", "receiver", ""],
        &["enroll", "list", "revoke", "help"],
    );
    assert_completion_candidates(&t, &["syq", "receiver", "enroll", "--v"], &["--via"]);
    assert_completion_candidates(
        &t,
        &["syq", "help", ""],
        &[
            "cp",
            "exec",
            "rm",
            "map",
            "rsync",
            "persist",
            "completion",
            "tuning-cache",
            "clean-partials",
            "receiver",
            "--self-update",
        ],
    );
    assert_completion_candidates(
        &t,
        &["syq", "tuning-cache", ""],
        &["list", "show", "export", "clear", "help"],
    );
    assert_completion_candidates(
        &t,
        &["syq", "tuning-cache", "show", "1", "--h"],
        &["--help", "--help-all", "--html"],
    );
    for args in [&[][..], &["--help"], &["-h"], &["help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("tuning-cache"));
    }
    for args in [
        &["--help-all"][..],
        &["help", "--help-all"],
        &["help", "tuning-cache"],
        &["tuning-cache", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("tuning-cache"));
    }
    assert_completion_candidates(&t, &["syq", "cp", "--as-f"], &["--as-fd"]);
    assert_completion_candidates(&t, &["syq", "cp", "--src-f"], &["--src-fd"]);
    assert_completion_candidates(&t, &["syq", "help", "receiver", "e"], &["enroll"]);
    assert_completion_candidates(
        &t,
        &["syq", "completion", "cache", ""],
        &["list", "forget", "clear", "help"],
    );
    assert_completion_candidates(&t, &["syq", "persist", "o"], &["on", "off"]);
    assert_completion_candidates(&t, &["syq", "persist", "con"], &["connect"]);
    write(
        &t.path("home/.ssh/config"),
        b"Host connect-server\n HostName localhost\n",
    );
    assert_completion_candidates(
        &t,
        &["syq", "persist", "connect", "connect-s"],
        &["connect-server"],
    );
    assert_completion_candidates(&t, &["syq", "persist", "r"], &["receive"]);
    assert_completion_candidates(&t, &["syq", "persist", "receive", "p"], &["pending"]);
    assert_completion_candidates(&t, &["syq", "persist", "destinations", "w"], &["wait"]);
    for action in ["off", "status", "connect"] {
        assert_completion_candidates(
            &t,
            &["syq", "persist", action, "--pscope", "sc"],
            &["scope/"],
        );
        assert_completion_candidates(
            &t,
            &["syq", "persist", action, "--pscope=sc"],
            &["--pscope=scope/"],
        );
    }
    assert_completion_candidates(
        &t,
        &["syq", "cp", "--preserve", "permissions,ow"],
        &["permissions,ownership"],
    );
    assert_completion_candidates(
        &t,
        &["syq", "cp", "--preserve=permissions,ow"],
        &["--preserve=permissions,ownership"],
    );
    assert_completion_candidates(
        &t,
        &["syq", "rsync", "--syq-ignore", "--", "--d"],
        &["--delete", "--delete-excluded", "--dry-run"],
    );
    assert_completion_candidates(
        &t,
        &["syq", "rsync", "--syq-ignore", "--files-from", "--d"],
        &["--delete", "--delete-excluded", "--dry-run"],
    );
    assert_completion_candidates(&t, &["syq", "rsync", "--", "--d"], &[]);
}

#[test]
fn completion_respects_conflicts_selection_modes_and_source_order() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    for destination in [
        "--to",
        "--into",
        "--into-new",
        "--into-existing",
        "--as",
        "--as-new",
        "--as-existing",
    ] {
        let attached = format!("{destination}=target");
        for arguments in [vec![destination, "target"], vec![attached.as_str()]] {
            let mut words = vec!["syq", "cp", "source"];
            words.extend(arguments);
            words.push("");
            assert_completion_candidates(&t, &["syq", "cp", "source", "--to", "--src"], &[]);
            assert_completion_candidates(&t, &words, &[]);
            for forbidden in ["--src", "--cwd", "--root", "--from", "--mapping", "-C"] {
                *words.last_mut().unwrap() = forbidden;
                assert_completion_candidates(&t, &words, &[]);
            }
            *words.last_mut().unwrap() = "--dry";
            assert_completion_candidates(&t, &words, &["--dry-run"]);
        }
    }
    assert_completion_candidates(
        &t,
        &["syq", "cp", "source", "--into", "target", "--as"],
        &[],
    );
    assert_completion_candidates(&t, &["syq", "cp", "--cwd", ".", "--root"], &[]);
    assert_completion_candidates(&t, &["syq", "cp", "--root", ".", "--cwd"], &[]);
    assert_completion_candidates(&t, &["syq", "cp", "--mapping", "manifest", "--src"], &[]);
    assert_completion_candidates(&t, &["syq", "cp", "--mapping", "manifest", "s"], &[]);
    assert_completion_candidates(&t, &["syq", "cp", "source", "--mapping"], &[]);
    assert_completion_candidates(&t, &["syq", "map", "--from", "s3://bucket", "s"], &[]);
    assert_completion_candidates(&t, &["syq", "map", "--include", "mt"], &["mtime"]);
    assert_completion_candidates(&t, &["syq", "map", "--srcs-in", ".", "s"], &[]);
    assert_completion_candidates(&t, &["syq", "map", "source", "--srcs-in"], &[]);
    assert_completion_candidates(&t, &["syq", "map", "--srcs-in", ".", "--src"], &[]);
}

#[test]
fn completion_bash_repeated_tabs_accept_option_fragments() {
    let t = Tmp::new();
    write(&t.path("--help"), b"literal filename");
    for (line, fragment, expected) in [
        ("syq --", "--", "--help"),
        ("syq --help", "--help", "--help"),
        ("syq -h", "-h", ""),
        ("syq help", "help", "help"),
        ("syq --version", "--version", "--version"),
        ("syq cp --", "--", "--coordinate-at"),
        ("syq cp --co", "--co", "--coordinate-at"),
        ("syq cp --coordinate-at=sr", "sr", "src"),
        ("syq cp -- --help", "--help", "--help"),
    ] {
        let backend = completion_command(&t, &["__complete-bash", fragment, "--", line])
            .current_dir(t.path(""))
            .env("SYQ_COMPLETION_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&backend);
        assert!(backend.stderr.is_empty(), "{line:?}: {backend:?}");
        let values = completion_values(&backend.stdout);
        if !expected.is_empty() {
            assert!(
                values.iter().any(|(_, value)| value == expected.as_bytes()),
                "{line:?}: {values:?}"
            );
        }
        let output = Command::new("bash")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                r#"
eval "$("$SYQ" completion bash)"
COMP_LINE=$1
COMP_POINT=${#COMP_LINE}
COMP_WORDS=(syq "$2")
COMP_CWORD=1
for ((tab=0; tab<3; tab++)); do
    _syq_complete
    for candidate in "${COMPREPLY[@]}"; do
        printf '%s\0' "$candidate"
    done
    printf '\0'
done
"#,
                "bash",
                line,
                fragment,
            ])
            .current_dir(t.path(""))
            .env("SYQ", env!("CARGO_BIN_EXE_syq"))
            .env("SYQ_COMPLETION_DEBUG", "1")
            .env("HOME", t.path("home"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_RUNTIME_DIR", t.runtime())
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    Path::new(env!("CARGO_BIN_EXE_syq"))
                        .parent()
                        .unwrap()
                        .display()
                ),
            )
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(output.stderr.is_empty(), "{line:?}: {output:?}");
        let mut frame = Vec::new();
        for (_, value) in values {
            frame.extend(value);
            frame.push(0);
        }
        frame.push(0);
        assert_eq!(output.stdout, frame.repeat(3), "{line:?}");
    }
}

#[test]
fn completion_adapters_and_local_filename_candidates_are_shell_safe() {
    let t = Tmp::new();
    write(&t.path("alpha file"), b"file");
    fs::create_dir(t.path("alpine")).unwrap();
    fs::create_dir(t.path("source-base")).unwrap();
    write(&t.path("source-base/beta"), b"based source");
    write(&t.path("éalpha"), b"unicode");
    write(&t.path("ébeta"), b"unicode");
    let raw_name = std::ffi::OsString::from_vec(b"raw-\xff".to_vec());
    let raw_names_supported = filesystem_accepts_non_utf8_names();
    if raw_names_supported {
        write(&t.path("").join(&raw_name), b"raw");
    }

    let bash = completion_command(&t, &["bash"]).run().unwrap();
    assert_output_ok(&bash);
    let mut syntax = Command::new("bash")
        .args(["-n"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    syntax
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&bash.stdout)
        .unwrap();
    let syntax = syntax.wait_with_output().unwrap();
    assert_output_ok(&syntax);

    let zsh = completion_command(&t, &["zsh"]).run().unwrap();
    assert_output_ok(&zsh);
    let zsh = String::from_utf8(zsh.stdout).unwrap();
    assert!(!zsh.contains("compadd -Q"), "{zsh}");
    assert!(zsh.contains("compadd -l -d descriptions --"), "{zsh}");
    assert!(
        zsh.contains("compadd -l -d prefix_descriptions -S '' --"),
        "{zsh}"
    );

    let registered = Command::new("bash")
        .arg("-c")
        .arg(
            r#"eval "$("$SYQ" completion bash)"
COMP_LINE='FOO=x syq c'
COMP_POINT=${#COMP_LINE}
COMP_WORDS=(FOO=x syq c)
COMP_CWORD=2
_syq_complete
printf '%s\n' "${COMPREPLY[@]}"
complete -p syq"#,
        )
        .env("SYQ", env!("CARGO_BIN_EXE_syq"))
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin",
                Path::new(env!("CARGO_BIN_EXE_syq"))
                    .parent()
                    .unwrap()
                    .display()
            ),
        )
        .run()
        .unwrap();
    assert_output_ok(&registered);
    let registered = String::from_utf8(registered.stdout).unwrap();
    assert!(registered.lines().any(|line| line == "cp"), "{registered}");
    assert!(
        registered.lines().any(|line| line == "completion"),
        "{registered}"
    );
    assert!(registered.contains("complete -F _syq_complete syq"));

    let unicode = Command::new("bash")
        .arg("-c")
        .arg(
            r#"eval "$("$SYQ" completion bash)"
COMP_LINE='syq cp éa'
COMP_POINT=${#COMP_LINE}
COMP_WORDS=(syq cp éa)
COMP_CWORD=2
_syq_complete
printf '%s\n' "${COMPREPLY[@]}""#,
        )
        .current_dir(t.path(""))
        .env("LC_ALL", "C.utf8")
        .env("SYQ", env!("CARGO_BIN_EXE_syq"))
        .env("HOME", t.path("home"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime())
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin",
                Path::new(env!("CARGO_BIN_EXE_syq"))
                    .parent()
                    .unwrap()
                    .display()
            ),
        )
        .run()
        .unwrap();
    assert_output_ok(&unicode);
    assert_eq!(unicode.stdout, "éalpha\n".as_bytes());

    let prefix = t.s("al");
    let output = completion_command(&t, &["__complete", "bash", "2", "--", "syq", "cp", &prefix])
        .run()
        .unwrap();
    assert_output_ok(&output);
    assert_eq!(
        completion_values(&output.stdout),
        vec![
            (
                b'f',
                t.path("alpha file").as_os_str().as_encoded_bytes().to_vec(),
            ),
            (
                b'p',
                t.path("alpine/").as_os_str().as_encoded_bytes().to_vec(),
            ),
        ]
    );

    let raw_prefix = t.path("raw-");
    let raw = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "2",
            "--",
            "syq",
            "cp",
            raw_prefix.to_str().unwrap(),
        ],
    )
    .run()
    .unwrap();
    assert_output_ok(&raw);
    assert_eq!(
        completion_values(&raw.stdout),
        if raw_names_supported {
            vec![(
                b'f',
                t.path("")
                    .join(raw_name)
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            )]
        } else {
            Vec::new()
        }
    );

    let based = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "4",
            "--",
            "syq",
            "cp",
            "--cwd",
            &t.s("source-base"),
            "b",
        ],
    )
    .run()
    .unwrap();
    assert_output_ok(&based);
    assert_eq!(
        completion_values(&based.stdout),
        vec![(b'f', b"beta".to_vec())]
    );

    let rooted = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "4",
            "--",
            "syq",
            "cp",
            "--root",
            &t.s("source-base"),
            "b",
        ],
    )
    .run()
    .unwrap();
    assert_output_ok(&rooted);
    assert_eq!(
        completion_values(&rooted.stdout),
        vec![(b'f', b"beta".to_vec())]
    );

    let escaped_root = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "4",
            "--",
            "syq",
            "cp",
            "--root",
            &t.s("source-base"),
            "../al",
        ],
    )
    .run()
    .unwrap();
    assert_output_ok(&escaped_root);
    assert!(completion_values(&escaped_root.stdout).is_empty());
}

#[test]
fn remote_completion_obeys_symlink_policy_types_and_literal_option_values() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    write(&t.path("remote-home/base/inside.txt"), b"inside");
    fs::create_dir(t.path("remote-home/base/inner-dir")).unwrap();
    std::os::unix::fs::symlink("base", t.path("remote-home/link")).unwrap();
    let ssh = fake_ssh(&t);
    let binary = env!("CARGO_BIN_EXE_syq");
    let base = t.s("remote-home/base");
    let link = format!("{}/in", t.s("remote-home/link"));
    let attached_base = format!("-C{base}");
    let remote_link = format!("fake.example:{link}");
    let link_prefix = t.s("remote-home/li");
    let link_path = t.s("remote-home/link");
    let mut cases = vec![
        (
            vec![
                "syq",
                "cp",
                "--syq-path",
                binary,
                "--from",
                "fake.example",
                &attached_base,
                "--src-dir",
                "in",
            ],
            vec!["inner-dir/".to_string()],
        ),
        (
            vec![
                "syq",
                "cp",
                "--syq-path",
                binary,
                "--from",
                "fake.example",
                &link,
            ],
            vec![],
        ),
        (
            vec![
                "syq",
                "cp",
                "--syq-path",
                binary,
                "--from",
                "fake.example",
                "--follow-src",
                &link,
            ],
            vec![format!("{}ner-dir/", link), format!("{}side.txt", link)],
        ),
        (
            vec![
                "syq",
                "cp",
                "--syq-path",
                binary,
                "--to",
                "fake.example",
                "--follow-dst",
                "--into",
                &link,
            ],
            vec![format!("{}ner-dir/", link)],
        ),
        // --rsh is the ignore pattern, so this must still perform the normal
        // remote completion through the test SSH transport.
        (
            vec![
                "syq",
                "rsync",
                "--rsync-path",
                binary,
                "--syq-ignore",
                "--rsh",
                &remote_link,
            ],
            vec![
                format!("{}ner-dir/", remote_link),
                format!("{}side.txt", remote_link),
            ],
        ),
    ];
    for command in ["cp", "rm", "map"] {
        for follow in ["--follow", "--follow-src"] {
            let endpoint = if command == "rm" { "--on" } else { "--from" };
            let common = vec![
                "syq",
                command,
                "--syq-path",
                binary,
                endpoint,
                "fake.example",
                follow,
            ];
            for selector in [
                "--src-dir",
                "--src-dirs",
                "--srcs-in",
                "--src",
                "--cwd",
                "--root",
            ] {
                let mut words = common.clone();
                words.extend([selector, &link_prefix]);
                let expected = if command != "rm" || ["--cwd", "--root"].contains(&selector) {
                    vec![format!("{link_path}/")]
                } else if selector == "--src" {
                    vec![link_path.clone()]
                } else {
                    vec![]
                };
                cases.push((words, expected));
            }
            let mut words = common;
            words.push(&link);
            cases.push((
                words,
                vec![format!("{link}ner-dir/"), format!("{link}side.txt")],
            ));
        }
    }
    for (words, expected) in cases {
        let index = (words.len() - 1).to_string();
        let mut args = vec!["__complete", "bash", &index, "--"];
        args.extend_from_slice(&words);
        let output = completion_command(&t, &args)
            .env_remove("SYQ_COMPLETION_DEBUG")
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(output.stderr.is_empty(), "{words:?}: {output:?}");
        let actual: Vec<Vec<u8>> = completion_values(&output.stdout)
            .into_iter()
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            actual,
            expected
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect::<Vec<_>>(),
            "{words:?}"
        );
    }
}

#[test]
fn remote_completion_uses_normal_ssh_and_learns_a_disposable_endpoint() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir_all(t.path("remote-home/data/nested")).unwrap();
    write(&t.path("remote-home/data/name with spaces"), b"remote");
    write(&t.path("from-local"), b"local");
    let ssh = fake_ssh(&t);
    // An SSH command starts in the remote account's home.
    let script = fs::read_to_string(&ssh)
        .unwrap()
        .replace("exec /bin/sh -c", "cd \"$HOME\" || exit 1\nexec /bin/sh -c");
    executable(&ssh, script.as_bytes());

    let path = format!("{}/n", t.s("remote-home/data"));
    let executable = env!("CARGO_BIN_EXE_syq");
    let output = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "6",
            "--",
            "syq",
            "cp",
            "--syq-path",
            executable,
            "--from",
            "fake.example",
            &path,
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&output);
    assert_eq!(
        completion_values(&output.stdout),
        vec![
            (
                b'f',
                t.path("remote-home/data/name with spaces")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ),
            (
                b'p',
                t.path("remote-home/data/nested/")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ),
        ]
    );
    let ssh_log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(ssh_log.contains("BatchMode=yes"), "{ssh_log}");
    assert!(ssh_log.contains("ConnectTimeout=3"), "{ssh_log}");

    let based = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "8",
            "--",
            "syq",
            "cp",
            "--syq-path",
            executable,
            "--from",
            "fake.example",
            "--cwd",
            &t.s("remote-home/data"),
            "n",
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&based);
    assert_eq!(
        completion_values(&based.stdout),
        vec![
            (b'f', b"name with spaces".to_vec()),
            (b'p', b"nested/".to_vec()),
        ]
    );

    let rooted = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "8",
            "--",
            "syq",
            "cp",
            "--syq-path",
            executable,
            "--from",
            "fake.example",
            "--root",
            &t.s("remote-home/data"),
            "n",
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&rooted);
    assert_eq!(
        completion_values(&rooted.stdout),
        vec![
            (b'f', b"name with spaces".to_vec()),
            (b'p', b"nested/".to_vec()),
        ]
    );

    fs::create_dir_all(t.path("go/local-only")).unwrap();
    fs::create_dir_all(t.path("remote-home/go/remote-only")).unwrap();
    for mode in ["__complete", "__complete-bash"] {
        let words = [
            "syq",
            "cp",
            "--syq-path",
            executable,
            "--src",
            "AGENTS.md",
            "--to",
            "fake.example",
            "--into",
            "go/",
        ];
        let line = shell_words::join(words);
        let args = if mode == "__complete-bash" {
            vec![mode, "go/", "--", &line]
        } else {
            let mut args = vec![mode, "bash", "9", "--"];
            args.extend(words);
            args
        };
        let output = completion_command(&t, &args)
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            )
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert_eq!(
            completion_values(&output.stdout),
            vec![(b'p', b"go/remote-only/".to_vec())],
            "{mode}"
        );
    }

    let destination = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "7",
            "--",
            "syq",
            "cp",
            "--syq-path",
            executable,
            "--to",
            "fake.example",
            "--into",
            &path,
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&destination);
    assert_eq!(
        completion_values(&destination.stdout),
        vec![(
            b'p',
            t.path("remote-home/data/nested/")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        ),]
    );

    let remote_operand = format!("fake.example:{path}");
    let rsync = completion_command(
        &t,
        &[
            "__complete",
            "fish",
            "4",
            "--",
            "syq",
            "rsync",
            "--rsync-path",
            executable,
            &remote_operand,
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&rsync);
    assert_eq!(
        rsync
            .stdout
            .split(|byte| *byte == 0)
            .filter(|candidate| !candidate.is_empty())
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>(),
        vec![
            format!("fake.example:{}/name with spaces", t.s("remote-home/data")).into_bytes(),
            format!("fake.example:{}/nested/", t.s("remote-home/data")).into_bytes(),
        ]
    );

    let bash_rsync_line = format!("syq rsync --rsync-path {executable} {remote_operand}");
    let bash_rsync = completion_command(&t, &["__complete-bash", &path, "--", &bash_rsync_line])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        )
        .run()
        .unwrap();
    assert_output_ok(&bash_rsync);
    assert_eq!(
        completion_values(&bash_rsync.stdout),
        vec![
            (
                b'f',
                t.path("remote-home/data/name with spaces")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ),
            (
                b'p',
                t.path("remote-home/data/nested/")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ),
        ]
    );

    let ssh_log_length = fs::metadata(t.path("rsh.log")).unwrap().len();
    let explicit_rsh = completion_command(
        &t,
        &[
            "__complete",
            "fish",
            "5",
            "--",
            "syq",
            "rsync",
            "--rsync-path",
            executable,
            "-avefalse",
            &remote_operand,
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&explicit_rsh);
    assert!(explicit_rsh.stdout.is_empty());
    assert_eq!(
        fs::metadata(t.path("rsh.log")).unwrap().len(),
        ssh_log_length
    );

    let after_terminator = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "5",
            "--",
            "syq",
            "rm",
            "--",
            "--on",
            "fake.example",
            &t.s("from-l"),
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&after_terminator);
    assert_eq!(
        completion_values(&after_terminator.stdout),
        vec![(
            b'f',
            t.path("from-local").as_os_str().as_encoded_bytes().to_vec(),
        )]
    );
    assert_eq!(
        fs::metadata(t.path("rsh.log")).unwrap().len(),
        ssh_log_length
    );

    let escaped_root = completion_command(
        &t,
        &[
            "__complete",
            "fish",
            "8",
            "--",
            "syq",
            "cp",
            "--syq-path",
            executable,
            "--from",
            "fake.example",
            "--root",
            &t.s("remote-home/data"),
            "../n",
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .run()
    .unwrap();
    assert_output_ok(&escaped_root);
    assert!(escaped_root.stdout.is_empty());
    assert_eq!(
        fs::metadata(t.path("rsh.log")).unwrap().len(),
        ssh_log_length
    );

    let listed = completion_command(&t, &["cache", "list"]).run().unwrap();
    assert_output_ok(&listed);
    assert_eq!(listed.stdout, b"fake.example\n");
    let metadata = fs::metadata(t.path("cache/syq/completion-endpoints.json")).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let suggested = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "3",
            "--",
            "syq",
            "cp",
            "--from",
            "fake",
        ],
    )
    .run()
    .unwrap();
    assert_output_ok(&suggested);
    assert!(completion_values(&suggested.stdout)
        .iter()
        .any(|candidate| candidate == &(b'f', b"fake.example".to_vec())));

    let inline = completion_command(&t, &["__complete-bash", "fake", "--", "syq cp --from=fake"])
        .run()
        .unwrap();
    assert_output_ok(&inline);
    assert!(completion_values(&inline.stdout)
        .iter()
        .any(|candidate| candidate == &(b'f', b"fake.example".to_vec())));

    let user_endpoint = completion_command(
        &t,
        &["__complete-bash", "fake", "--", "syq cp --from=alice@fake"],
    )
    .run()
    .unwrap();
    assert_output_ok(&user_endpoint);
    assert!(completion_values(&user_endpoint.stdout)
        .iter()
        .any(|candidate| candidate == &(b'f', b"@fake.example".to_vec())));

    let forgotten = completion_command(&t, &["cache", "forget", "fake.example"])
        .run()
        .unwrap();
    assert_output_ok(&forgotten);
    assert_eq!(forgotten.stdout, b"forgot fake.example\n");
    let listed = completion_command(&t, &["cache", "list"]).run().unwrap();
    assert_output_ok(&listed);
    assert_eq!(listed.stdout, b"completion endpoint cache is empty\n");

    let cleared = completion_command(&t, &["cache", "clear"]).run().unwrap();
    assert_output_ok(&cleared);
    assert!(!t.path("cache/syq/completion-endpoints.json").exists());
}

/// Candidates reach the shell as soon as the listing arrives. Closing the
/// remote connection waits for the helper's exit status, a whole network
/// round trip on a distant host, so the completion process must print and
/// exit while that connection is still open.
#[test]
fn remote_completion_replies_before_the_remote_connection_closes() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    fs::create_dir_all(t.path("remote-home/data/nested")).unwrap();
    write(&t.path("remote-home/data/name"), b"remote");
    let ssh = fake_ssh(&t);
    // A remote helper that serves normally and then stays alive until it is
    // released, like an ssh session whose exit status has not come back yet.
    // The wait is bounded so a regression fails instead of hanging.
    let helper = t.path("lingering-syq");
    executable(
        &helper,
        format!(
            r#"#!/bin/sh
'{syq}' "$@"
status=$?
n=0
until [ -e '{release}' ] || [ "$n" -ge 400 ]; do
    sleep 0.05
    n=$((n + 1))
done
printf 'helper-exit\n' >> "$FAKE_RSH_LOG"
exit "$status"
"#,
            syq = env!("CARGO_BIN_EXE_syq"),
            release = t.s("release-helper"),
        )
        .as_bytes(),
    );
    let path = format!("{}/n", t.s("remote-home/data"));
    let output = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "6",
            "--",
            "syq",
            "cp",
            "--syq-path",
            &t.s("lingering-syq"),
            "--from",
            "fake.example",
            &path,
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    // The lingering helper inherits stderr; a captured pipe would keep this
    // wait open until the helper exits.
    .stderr(Stdio::null())
    .start()
    .unwrap()
    .wait_with_output()
    .unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    assert_eq!(
        completion_values(&output.stdout),
        vec![
            (
                b'f',
                t.path("remote-home/data/name")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ),
            (
                b'p',
                t.path("remote-home/data/nested/")
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            ),
        ]
    );
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(
        !log.contains("helper-exit"),
        "completion waited for the remote helper to exit:\n{log}"
    );

    write(&t.path("release-helper"), b"");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let log = fs::read_to_string(t.path("rsh.log")).unwrap();
        if log.contains("helper-exit") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "released remote helper never exited:\n{log}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn named_destination_offline_failure_settles_results_and_completes_names_locally() {
    let t = Tmp::new();
    write(&t.path("source"), b"source");
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "source",
            "--to",
            "@laptop",
            "--results",
            "result.ndjson",
        ])
        .env("HOME", t.path(""))
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .current_dir(t.path(""))
        .capture_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", stderr_of(&output));
    let records: Vec<serde_json::Value> = fs::read_to_string(t.path("result.ndjson"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.last().unwrap()["status"], "failed");
    // The completion route uses private local registration names only, without
    // attempting SSH or contacting the receiving laptop.
    write(&t.path(".syq-destinations-v3/laptop.json"), b"{}");
    let completion = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "completion",
            "__complete",
            "fish",
            "4",
            "--",
            "syq",
            "cp",
            "source",
            "--to",
            "@lap",
        ])
        .env("HOME", t.path(""))
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .current_dir(t.path(""))
        .capture_output()
        .unwrap();
    assert_output_ok(&completion);
    assert_eq!(completion.stdout, b"@laptop\0");
}

#[test]
fn offline_receiver_ownership_keeps_names_but_allows_remote_completion() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("remote-home/data/nested")).unwrap();
    write(&t.path("home/.syq-destinations-v3/fake.owner"), b"{}");
    fs::set_permissions(
        t.path("home/.syq-destinations-v3"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let names = completion_command(
        &t,
        &[
            "__complete",
            "fish",
            "4",
            "--",
            "syq",
            "cp",
            "source",
            "--to",
            "@fake",
        ],
    )
    .capture_output()
    .unwrap();
    assert_output_ok(&names);
    assert_eq!(names.stdout, b"@fake\0");
    let ssh = fake_ssh(&t);
    let path = format!("{}/n", t.s("remote-home/data"));
    let output = completion_command(
        &t,
        &[
            "__complete",
            "bash",
            "9",
            "--",
            "syq",
            "cp",
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--src",
            "source",
            "--to",
            "fake",
            "--into",
            &path,
        ],
    )
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env(
        "PATH",
        format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
    )
    .capture_output()
    .unwrap();
    assert_output_ok(&output);
    assert_eq!(
        completion_values(&output.stdout),
        vec![(
            b'p',
            t.path("remote-home/data/nested/")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        )]
    );
}

#[test]
fn completion_details_keep_metadata_out_of_inserted_paths() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let t = Tmp::new();
    fs::write(t.path("alpha file"), vec![0; 2048]).unwrap();
    fs::set_permissions(t.path("alpha file"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::create_dir(t.path("alpine")).unwrap();
    symlink("missing-target", t.path("alias")).unwrap();
    let plain = completion_command(&t, &["__complete", "bash", "2", "--", "syq", "cp", "al"])
        .current_dir(t.path(""))
        .run()
        .unwrap();
    assert_output_ok(&plain);
    assert_eq!(
        completion_values(&plain.stdout),
        vec![
            (b'f', b"alias".to_vec()),
            (b'f', b"alpha file".to_vec()),
            (b'p', b"alpine/".to_vec())
        ]
    );
    let detailed = completion_command(&t, &["__complete", "zsh", "2", "--", "syq", "cp", "al"])
        .env("SYQ_COMPLETION_DETAILS", "1")
        .current_dir(t.path(""))
        .run()
        .unwrap();
    assert_output_ok(&detailed);
    let records: Vec<_> = detailed
        .stdout
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
        .collect();
    assert_eq!(records.len(), 6);
    assert_eq!(records[0], b"falias");
    assert!(String::from_utf8_lossy(records[1]).ends_with("alias -> missing-target"));
    assert_eq!(records[2], b"falpha file");
    let file = String::from_utf8_lossy(records[3]);
    assert!(file.starts_with("-rw-r----- "), "{file}");
    assert!(file.contains("2.0 KiB"), "{file}");
    assert!(file.contains(" UTC  alpha file"), "{file}");
    assert_eq!(records[4], b"palpine/");
    let directory = String::from_utf8_lossy(records[5]);
    assert!(
        directory.starts_with('d') && directory.contains('—'),
        "{directory}"
    );
    let bash = completion_command(&t, &["__complete-bash", "al", "--", "syq cp al"])
        .env("SYQ_COMPLETION_DETAILS", "1")
        .current_dir(t.path(""))
        .run()
        .unwrap();
    assert_output_ok(&bash);
    assert!(completion_values(&bash.stdout)
        .iter()
        .all(|(kind, _)| *kind == b'd'));
}

#[test]
fn return_via_completes_only_explicit_names_without_contacting_hosts() {
    let t = Tmp::new();
    write(&t.path(".syq-destinations-v3/laptop.json"), b"{}");
    fs::set_permissions(
        t.path(".syq-destinations-v3"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    write(
        &t.path("bin/ssh"),
        b"#!/bin/sh\n: > \"$HOME/ssh-used\"\nexit 99\n",
    );
    fs::set_permissions(t.path("bin/ssh"), fs::Permissions::from_mode(0o755)).unwrap();
    for option in ["--auth-from"] {
        for (prefix, expected) in [
            ("lap", b"".as_slice()),
            ("@lap", b"@laptop\0"),
            ("absent", b""),
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_syq"))
                .args([
                    "completion",
                    "__complete",
                    "fish",
                    "6",
                    "--",
                    "syq",
                    "cp",
                    "source",
                    "--to",
                    "backup",
                    option,
                    prefix,
                ])
                .env("HOME", t.path(""))
                .env("PATH", t.path("bin"))
                .env("SYQ_NO_UPDATE_CHECK", "1")
                .current_dir(t.path(""))
                .capture_output()
                .unwrap();
            assert_output_ok(&output);
            assert_eq!(output.stdout, expected, "{prefix}");
        }
    }
    assert!(!t.path("ssh-used").exists());
}

#[test]
fn automatic_authorization_completion_keeps_local_paths_and_never_prompts() {
    let t = Tmp::new();
    write(&t.path("local-folder/file"), b"payload");
    for name in ["laptop", "ssh"] {
        write(
            &t.path(&format!("home/.syq-destinations-v3/{name}.json")),
            b"{}",
        );
    }
    fs::set_permissions(
        t.path("home/.syq-destinations-v3"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_completion_candidates(&t, &["syq", "cp", "source", "--auth-f"], &["--auth-from"]);
    assert_completion_candidates(&t, &["syq", "cp", "source", "--auth-from", "ss"], &["ssh"]);
    assert_completion_candidates(
        &t,
        &["syq", "cp", "source", "--auth-from", "@ss"],
        &["@ssh"],
    );
    assert_completion_candidates(&t, &["syq", "cp", "source", "--auth-from", "au"], &["auto"]);
    assert_completion_candidates(
        &t,
        &["syq", "cp", "source", "--into", "local-f"],
        &["local-folder/"],
    );
    write(
        &t.path("bin/ssh"),
        b"#!/bin/sh\n: > \"$HOME/ssh-used\"\nexit 55\n",
    );
    fs::set_permissions(t.path("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
    for selector in [
        vec![],
        vec!["--auth-from", "@laptop"],
        vec!["--auth-from", "auto"],
    ] {
        let mut words = vec!["syq", "cp", "source", "--to", "backup"];
        words.extend(selector);
        words.extend(["--into", "anything"]);
        let index = (words.len() - 1).to_string();
        let mut args = vec!["__complete", "fish", &index, "--"];
        args.extend(words);
        let output = completion_command(&t, &args)
            .current_dir(t.path(""))
            .env("PATH", t.path("bin"))
            .capture_output()
            .unwrap();
        assert_output_ok(&output);
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(!t.path("home/ssh-used").exists());
    }
}

#[test]
fn return_exec_completion_and_offline_selection_never_contact_ssh() {
    let t = Tmp::new();
    write(&t.path("home/.syq-destinations-v3/laptop.json"), b"{}");
    fs::set_permissions(
        t.path("home/.syq-destinations-v3"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_completion_candidates(&t, &["syq", "ex"], &["exec"]);
    assert_completion_candidates(&t, &["syq", "exec", "--on", "lap"], &[]);
    assert_completion_candidates(&t, &["syq", "exec", "--on", "@lap"], &["@laptop"]);
    assert_completion_candidates(&t, &["syq", "exec", "--cw"], &["--cwd"]);
    assert_completion_candidates(&t, &["syq", "exec", "--on", "laptop", "--", "--he"], &[]);
    write(
        &t.path("bin/ssh"),
        b"#!/bin/sh\n: > \"$HOME/ssh-used\"\nexit 55\n",
    );
    fs::set_permissions(t.path("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["absent", "@absent", "user@host", "host:22"] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["exec", "--on", name, "--", "true"])
            .env("HOME", t.path("home"))
            .env("PATH", t.path("bin"))
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .capture_output()
            .unwrap();
        assert!(!output.status.success());
        if name == "@absent" {
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(
                error.contains("no receiving machine named @absent is registered"),
                "{error}"
            );
            assert!(error.contains("Registered names: @laptop"), "{error}");
            assert!(error.contains("syq persist destinations list"), "{error}");
            assert!(
                !error.contains(".syq-destinations") && !error.contains("os error"),
                "{error}"
            );
        }
        assert!(!t.path("home/ssh-used").exists());
    }
    // An empty registry gives setup instructions instead of suggesting a name.
    fs::remove_file(t.path("home/.syq-destinations-v3/laptop.json")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["exec", "--on", "@laptop", "--", "true"])
        .env("HOME", t.path("home"))
        .env("PATH", t.path("bin"))
        .capture_output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("On the receiving machine, run `syq persist connect SERVER`"),
        "{error}"
    );
    assert!(!error.contains("Registered names:"), "{error}");
    // Other read failures still explain their cause rather than claiming absence.
    write(&t.path("home/.syq-destinations-v3/laptop.json"), b"{}");
    fs::set_permissions(
        t.path("home/.syq-destinations-v3/laptop.json"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["exec", "--on", "@laptop", "--", "true"])
        .env("HOME", t.path("home"))
        .env("PATH", t.path("bin"))
        .capture_output()
        .unwrap();
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        error.contains("cannot read the registration for @laptop"),
        "{error}"
    );
    assert!(!error.contains("no receiving machine"), "{error}");
    let output = completion_command(
        &t,
        &[
            "__complete",
            "fish",
            "5",
            "--",
            "syq",
            "exec",
            "--on",
            "laptop",
            "--cwd",
            "anything",
        ],
    )
    .env("PATH", t.path("bin"))
    .capture_output()
    .unwrap();
    assert_output_ok(&output);
    assert!(output.stdout.is_empty());
    assert!(!t.path("home/ssh-used").exists());
}

#[cfg(debug_assertions)]
#[test]
fn concurrent_identical_and_different_copies_publish_complete_files() {
    // Exercise publication and retained-basis races through isolated receiver
    // processes, without spending seconds encrypting bulk data in debug builds.
    // Pipes preserve the same file operations and multi-block fixtures.
    for identical in [true, false] {
        for existing in [false, true] {
            let t = Tmp::new();
            let mut first_data = vec![b'a'; 8 << 20];
            first_data[..4 << 20].fill(b'o');
            let second_data = if identical {
                first_data.clone()
            } else {
                vec![b'b'; 8 << 20]
            };
            write(&t.path("first"), &first_data);
            write(&t.path("second"), &second_data);
            if existing {
                write(&t.path("out"), &vec![b'o'; 8 << 20]);
            }
            let ready = t.path("ready");
            let continuation = t.path("continue");
            let (ready_env, continue_env) = if existing {
                ("SYQ_TEST_BASIS_READY_FILE", "SYQ_TEST_BASIS_CONTINUE_FILE")
            } else {
                (
                    "SYQ_TEST_PARTIAL_READY_FILE",
                    "SYQ_TEST_PARTIAL_CONTINUE_FILE",
                )
            };
            let mut first = Command::new(env!("CARGO_BIN_EXE_syq"))
                .args([
                    "cp",
                    "--hash",
                    "--no-tcp",
                    "--resource-limits",
                    "bandwidth=1G",
                    "--performance-tuning",
                    "workers=2",
                    "--no-progress",
                    &t.s("first"),
                    "--as",
                    &t.s("out"),
                ])
                .env(ready_env, &ready)
                .env(continue_env, &continuation)
                // This barrier covers the second complete copy, including
                // hashing and publication on a loaded macOS CI runner.
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .start()
                .unwrap();
            wait_for_confinement_marker(
                &mut first,
                &ready,
                &format!(
                    "overlapping copy preparation (identical={identical}, existing={existing})"
                ),
            );
            let second_started = std::time::Instant::now();
            let second = Command::new(env!("CARGO_BIN_EXE_syq"))
                .args([
                    "cp",
                    "--hash",
                    "--no-tcp",
                    "--resource-limits",
                    "bandwidth=1G",
                    "--performance-tuning",
                    "workers=2",
                    "--no-progress",
                    &t.s("second"),
                    "--as",
                    &t.s("out"),
                ])
                .run()
                .unwrap();
            let second_published = fs::read(t.path("out"));
            release_confinement_barrier(&continuation);
            let first = first.wait_with_output().unwrap();
            assert_output_ok(&second);
            assert!(
                first.status.success(),
                "first copy failed: identical={identical}, existing={existing}, \
                 competitor elapsed={:?}, first={first:?}, second={second:?}",
                second_started.elapsed(),
            );
            assert_eq!(
                second_published.unwrap(),
                second_data,
                "competitor publication: identical={identical}, existing={existing}"
            );
            assert_eq!(
                read(&t.path("out")),
                first_data,
                "identical={identical}, existing={existing}"
            );
            assert!(partial_files(&t.0).is_empty());
        }
    }
}
