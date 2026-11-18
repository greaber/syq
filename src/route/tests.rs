use super::*;

fn parse(words: &[&str]) -> Args {
    let command: Vec<Vec<u8>> = std::iter::once("cp")
        .chain(words.iter().copied())
        .map(|word| word.as_bytes().to_vec())
        .collect();
    crate::approval_command::parse(&command).unwrap()
}

#[test]
fn routes_follow_the_endpoints() {
    for (words, route) in [
        (&["notes", "--into", "/out"][..], Route::Own),
        (
            &["--from", "@laptop", "notes", "--into", "/out"],
            Route::FromNamed,
        ),
        (&["notes", "--to", "@laptop"], Route::ToNamed),
        (&["notes", "--to", "server"], Route::Upload),
        (
            &["--from", "server", "notes", "--into", "/out"],
            Route::Download,
        ),
        (&["--from", "a", "notes", "--to", "b"], Route::Between),
        // A receiving machine names the route whatever the other end is.
        (
            &["--from", "server", "notes", "--to", "@laptop"],
            Route::ToNamed,
        ),
    ] {
        assert_eq!(classify(&parse(words)), route, "{words:?}");
    }
}

/// Each route's message names exactly the options it refuses, so the table
/// and what it tells the user cannot drift apart.
#[test]
fn each_refusal_names_the_options_it_refuses() {
    let flag = |option: Opt| match option {
        Opt::Rsh => Some("--rsh"),
        Opt::SyqPath => Some("--syq-path"),
        Opt::NoBootstrap => Some("--no-bootstrap"),
        Opt::Detach => Some("--detach"),
        Opt::PeerAuth => Some("--peer-auth"),
        Opt::CoordinateAt(_) => Some("--coordinate-at"),
        Opt::NoTcpEncryption => Some("--no-tcp-encryption"),
        Opt::Relay | Opt::RestrictedGrant => None,
    };
    let every = [
        "--rsh",
        "--syq-path",
        "--no-bootstrap",
        "--detach",
        "--peer-auth",
        "--coordinate-at",
        "--no-tcp-encryption",
    ];
    for route in [
        Route::ToNamed,
        Route::FromNamed,
        Route::Upload,
        Route::Download,
        Route::Between,
    ] {
        let refusal = refusal(route).unwrap();
        let named: Vec<_> = refusal.options.iter().filter_map(|&o| flag(o)).collect();
        for option in every {
            assert_eq!(
                refusal.message.contains(option),
                named.contains(&option),
                "{route:?} {option}"
            );
        }
    }
    assert!(refusal(Route::Own).is_none());
}

/// Today's refusals per route, option by option.
#[test]
fn routes_refuse_their_options() {
    let cases: [(&[&str], Route); 5] = [
        (&["notes", "--to", "@laptop"], Route::ToNamed),
        (
            &["--from", "@laptop", "notes", "--into", "/out"],
            Route::FromNamed,
        ),
        (&["notes", "--to", "server"], Route::Upload),
        (
            &["--from", "server", "notes", "--into", "/out"],
            Route::Download,
        ),
        (&["--from", "a", "notes", "--to", "b"], Route::Between),
    ];
    let options: [(&[&str], [bool; 5]); 9] = [
        // ToNamed, FromNamed, Upload, Download, Between
        (&["--rsh", "ssh"], [true; 5]),
        (&["--syq-path", "/bin/syq"], [true; 5]),
        (&["--no-bootstrap"], [false, false, true, true, true]),
        (&["--detach"], [true; 5]),
        (&["--peer-auth", "broker"], [true; 5]),
        (
            &["--coordinate-at", "src"],
            [false, true, true, true, false],
        ),
        (&["--coordinate-at", "dst"], [false, true, true, true, true]),
        (&["--no-tcp-encryption"], [true, true, false, false, false]),
        (&[], [false; 5]),
    ];
    for (base, route) in cases {
        assert_eq!(classify(&parse(base)), route);
        for (option, refused) in &options {
            let args = parse(&[base, option].concat());
            let index = cases.iter().position(|(_, r)| *r == route).unwrap();
            assert_eq!(
                refuse_options(route, &args).is_err(),
                refused[index],
                "{route:?} {option:?}"
            );
        }
    }
}
