//! Real HTTPS connections with an ephemeral CA selected through the system
//! certificate loader. Each syq child has its own trust store and caches.
#![cfg(any(target_os = "linux", target_os = "macos"))]

#[allow(dead_code)]
#[path = "../src/process.rs"]
mod process;
use process::CommandExt as _;
#[path = "support/temp.rs"]
mod test_support;

#[path = "support/https.rs"]
mod https;
use https::Server;
use std::{
    path::Path,
    process::{Command, Output},
};

impl Server {
    fn command(&self, directory: &Path, certificates: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .current_dir(directory)
            .env("SSL_CERT_FILE", certificates)
            .env_remove("SSL_CERT_DIR")
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env("XDG_CACHE_HOME", directory.join("cache"))
            .env("XDG_CONFIG_HOME", directory.join("config"));
        for variable in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env_remove(variable);
        }
        command
    }

    fn download(&self, directory: &Path, certificates: &Path) -> Output {
        self.command(directory, certificates)
            .env("SYQ_TEST_RELEASE_DOWNLOADS", self.url())
            .env_remove("SYQ_TEST_FIXTURES")
            .args(["--use-version", "9.9.9", "--version"])
            .capture_output()
            .unwrap()
    }
}

#[test]
fn release_download_uses_system_ca_file_and_directory() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("127.0.0.1");
    let certificates = temp.path().join("ca.pem");
    std::fs::write(&certificates, &server.ca).unwrap();
    let output = server.download(temp.path(), &certificates);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("parse signed release manifest"),
        "{output:?}"
    );
    let output = server
        .command(temp.path(), &certificates)
        .env_remove("SSL_CERT_FILE")
        .env("SSL_CERT_DIR", temp.path())
        .env("SYQ_TEST_RELEASE_DOWNLOADS", server.url())
        .env_remove("SYQ_TEST_FIXTURES")
        .args(["--use-version", "9.9.9", "--version"])
        .capture_output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("parse signed release manifest"),
        "{output:?}"
    );
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}

#[test]
fn release_download_rejects_untrusted_ca() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("127.0.0.1");
    let unrelated = Server::start("127.0.0.1");
    let certificates = temp.path().join("ca.pem");
    std::fs::write(&certificates, &unrelated.ca).unwrap();
    let output = server.download(temp.path(), &certificates);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid peer certificate"),
        "{output:?}"
    );
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn release_download_rejects_wrong_hostname() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("wrong.example");
    let certificates = temp.path().join("ca.pem");
    std::fs::write(&certificates, &server.ca).unwrap();
    let output = server.download(temp.path(), &certificates);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("not valid for name"), "{output:?}");
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn release_download_reports_empty_ca_overrides() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("127.0.0.1");
    let empty_bundle = temp.path().join("empty.pem");
    std::fs::write(&empty_bundle, b"").unwrap();
    for certificates in [Path::new(""), empty_bundle.as_path()] {
        let output = server.download(temp.path(), certificates);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("no trusted CA certificates were loaded"),
            "{output:?}"
        );
        assert!(error.contains("SSL_CERT_FILE"), "{output:?}");
    }
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn missing_ca_bundle_rejects_https_but_does_not_block_local_copy() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("127.0.0.1");
    let certificates = temp.path().join("missing.pem");
    let output = server.download(temp.path(), &certificates);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("no trusted CA certificates were loaded"),
        "{output:?}"
    );
    assert!(error.contains("missing.pem"), "{output:?}");
    assert!(server.requests.lock().unwrap().is_empty());
    std::fs::write(temp.path().join("source"), b"local data").unwrap();
    let output = server
        .command(temp.path(), &certificates)
        .args(["cp", "source", "--as", "copy"])
        .capture_output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(temp.path().join("copy")).unwrap(),
        b"local data"
    );
}

#[test]
fn s3_upload_and_download_share_system_trust() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("127.0.0.1");
    let certificates = temp.path().join("ca.pem");
    std::fs::write(&certificates, &server.ca).unwrap();
    let data = b"system certificates protect both upload and download";
    std::fs::write(temp.path().join("source"), data).unwrap();
    for args in [
        vec!["source", "--to", "s3://bucket", "--as", "object"],
        vec!["--from", "s3://bucket", "object", "--as", "copy"],
    ] {
        let output = server
            .command(temp.path(), &certificates)
            .env("AWS_ACCESS_KEY_ID", "test")
            .env("AWS_SECRET_ACCESS_KEY", "test")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_CONFIG_FILE", temp.path().join("no-config"))
            .env(
                "AWS_SHARED_CREDENTIALS_FILE",
                temp.path().join("no-credentials"),
            )
            .args([
                "cp",
                "--s3-endpoint",
                &server.url(),
                "--s3-region",
                "us-east-1",
                "--s3-retries",
                "0",
                "--no-progress",
            ])
            .args(args)
            .capture_output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    assert_eq!(std::fs::read(temp.path().join("copy")).unwrap(), data);
    let requests = server.requests.lock().unwrap();
    assert!(requests
        .iter()
        .any(|(request, body)| request.starts_with("PUT ") && body == data));
    assert!(requests
        .iter()
        .any(|(request, _)| request.starts_with("GET /bucket/object")));
}
