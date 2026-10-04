use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;
use std::sync::{Arc, Mutex};

type RecordedRequest = (String, String, String);

#[derive(Debug, Clone)]
struct Requests(Arc<Mutex<Vec<RecordedRequest>>>);
impl HttpConnector for Requests {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let method = request.method().to_owned();
        let uri = request.uri().to_string();
        let body = String::from_utf8(request.body().bytes().unwrap_or_default().to_vec()).unwrap();
        self.0
            .lock()
            .unwrap()
            .push((method.clone(), uri.clone(), body.clone()));
        HttpConnectorFuture::new(async move {
            let mut response = if method == "DELETE" {
                let mut response = HttpResponse::new(204.try_into().unwrap(), SdkBody::empty());
                let url = url::Url::parse(&uri).unwrap();
                if let Some((_, id)) = url.query_pairs().find(|(key, _)| key == "versionId") {
                    response
                        .headers_mut()
                        .insert("x-amz-version-id", id.into_owned());
                }
                response
            } else {
                assert_eq!(method, "POST");
                // Accept either a regular or versioned batch and echo its targets.
                let body = format!(
                    "<DeleteResult>{}</DeleteResult>",
                    body.split("<Object>")
                        .skip(1)
                        .map(|entry| format!(
                            "<Deleted>{}</Deleted>",
                            entry.split("</Object>").next().unwrap()
                        ))
                        .collect::<String>()
                );
                HttpResponse::new(200.try_into().unwrap(), SdkBody::from(body))
            };
            let length = response
                .body()
                .bytes()
                .unwrap_or_default()
                .len()
                .to_string();
            response.headers_mut().insert("content-length", length);
            Ok(response)
        })
    }
}

#[tokio::test]
async fn tigris_version_deletion_uses_individual_requests_and_other_deletion_stays_batched() {
    for (endpoint, tigris) in [
        ("https://t3.storage.dev", true),
        ("https://fly.storage.tigris.dev", true),
        ("https://region.tigris.dev:9443", true),
        ("https://T3.STORAGE.DEV", true),
        ("https://s3.us-east-1.amazonaws.com", false),
        ("https://storage.example", false),
        ("https://t3.storage.dev.example", false),
        ("https://nottigris.dev", false),
        ("https://storage.example/t3.storage.dev", false),
    ] {
        for flag in [None, Some("--s3-version-id=v1"), Some("--s3-all-versions")] {
            let mut argv = vec![
                "rm",
                "--on=s3://bucket",
                "object",
                "--s3-endpoint",
                endpoint,
            ];
            argv.extend(flag);
            let args = Args::parse_args(
                &argv
                    .iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            for authorized in [false, true] {
                let requests = Requests(Arc::new(Mutex::new(Vec::new())));
                let transport = requests.clone();
                let config = aws_sdk_s3::config::Builder::new()
                    .behavior_version_latest()
                    .region(aws_sdk_s3::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_s3::config::Credentials::new(
                        "test", "test", None, None, "fixture",
                    ))
                    .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                    .endpoint_url(endpoint)
                    .force_path_style(true)
                    .http_client(http_client_fn(move |_, _| {
                        SharedHttpConnector::new(transport.clone())
                    }))
                    .build();
                let client = Client::from_conf(config);
                let targets: Vec<_> = (1..=if flag == Some("--s3-version-id=v1") {
                    1
                } else {
                    2
                })
                    .map(|n| delete::Target {
                        key: format!("object{n}"),
                        version: flag.map(|_| format!("v{n}")),
                    })
                    .collect();
                let deleter = delete::Deleter {
                    client: &client,
                    bucket: "bucket",
                    retries: 2,
                    concurrency: crate::deletion::Concurrency::s3(&args),
                    individual: args
                        .s3_remove
                        .individual_deletes(args.s3.as_ref().unwrap(), authorized),
                };
                let mut completed = 0;
                deleter
                    .run(
                        &targets,
                        |target| target.clone(),
                        &|| Ok(()),
                        |_, result| {
                            assert!(result.is_ok(), "{endpoint}, {flag:?}: {result:?}");
                            completed += 1;
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(completed, targets.len());
                let calls = requests.0.lock().unwrap();
                if authorized || (tigris && flag.is_some()) {
                    assert_eq!(calls.len(), targets.len());
                    for (method, uri, _) in calls.iter() {
                        assert_eq!(method, "DELETE", "{endpoint}, {flag:?}");
                        let url = url::Url::parse(uri).unwrap();
                        let target = targets
                            .iter()
                            .find(|t| url.path().ends_with(&t.key))
                            .unwrap();
                        let version = url
                            .query_pairs()
                            .find(|(key, _)| key == "versionId")
                            .map(|(_, value)| value.into_owned());
                        assert_eq!(version, target.version);
                    }
                } else {
                    assert_eq!(calls.len(), 1);
                    assert_eq!(calls[0].0, "POST", "{endpoint}, {flag:?}");
                    assert!(calls[0].1.contains("?delete"));
                    for target in &targets {
                        assert!(calls[0].2.contains(&format!("<Key>{}</Key>", target.key)));
                        if let Some(version) = &target.version {
                            assert!(calls[0]
                                .2
                                .contains(&format!("<VersionId>{version}</VersionId>")));
                        }
                    }
                }
            }
        }
    }
}
