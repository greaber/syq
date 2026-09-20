//! Remove bearer query values only when an error actually contains them.
use aws_smithy_runtime_api::client::result::ConnectorError;

pub(super) fn connector_error(error: ConnectorError) -> ConnectorError {
    use std::fmt::Write;
    let mut details = format!("{error:?}");
    let mut cause = std::error::Error::source(&error);
    while let Some(error) = cause {
        write!(&mut details, "; {error}").unwrap();
        cause = error.source();
    }
    let redacted = redact(&details);
    if redacted == details {
        return error;
    }
    // The SDK classifies retries using the connector kind, including an
    // explicit retry kind on Other. Keep established-connection metadata too.
    // Debug includes the underlying causes, without keeping an unsafe source
    // that a caller could expose through Error::source or Debug.
    let source = anyhow::anyhow!(redacted).into();
    let sanitized = if error.is_io() {
        ConnectorError::io(source)
    } else if error.is_timeout() {
        ConnectorError::timeout(source)
    } else if error.is_user() {
        ConnectorError::user(source)
    } else {
        ConnectorError::other(source, error.as_other())
    };
    match error.connection_metadata() {
        Some(metadata) => sanitized.with_connection(metadata.clone()),
        None => sanitized,
    }
}

fn redact(message: &str) -> String {
    let mut result = message.to_owned();
    for field in ["x-amz-signature=", "x-amz-security-token="] {
        let mut offset = 0;
        while let Some(index) = result[offset..].to_ascii_lowercase().find(field) {
            let start = offset + index + field.len();
            let length = result[start..]
                .find(|c: char| c.is_whitespace() || "&\"'<>#\\)]}".contains(c))
                .unwrap_or(result.len() - start);
            result.replace_range(start..start + length, "[REDACTED]");
            offset = start + "[REDACTED]".len();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_types::retry::ErrorKind;
    use std::error::Error;

    #[test]
    fn removes_complete_bearer_values_and_preserves_other_details() {
        let signature = "abcdef".repeat(20);
        let token = "long%2Ftoken%2Bvalue%3D";
        let text = format!("reset for \"https://storage.example/b/key?X-Amz-Signature={signature}&partNumber=42&X-Amz-Security-Token={token}\"; timeout https://storage.example/key?x-amz-security-token={token}&X-Amz-Signature={signature}");
        let safe = redact(&text);
        assert!(!safe.contains(&signature));
        assert!(!safe.contains(token));
        assert_eq!(safe.matches("[REDACTED]").count(), 4);
        assert!(safe.contains("partNumber=42"));
        assert!(safe.contains("reset for"));
        assert!(safe.contains("timeout https://storage.example/key"));
    }

    #[test]
    fn redaction_keeps_every_connector_retry_class() {
        for kind in 0..6 {
            let source = anyhow::anyhow!("connection reset: https://storage.example/key?X-Amz-Signature=secret&X-Amz-Security-Token=token").into();
            let original = match kind {
                0 => ConnectorError::io(source),
                1 => ConnectorError::timeout(source),
                2 => ConnectorError::user(source),
                3 => ConnectorError::other(source, Some(ErrorKind::TransientError)),
                4 => ConnectorError::other(source, Some(ErrorKind::ThrottlingError)),
                _ => ConnectorError::other(source, None),
            };
            let expected = (
                original.is_io(),
                original.is_timeout(),
                original.is_user(),
                original.is_other(),
                original.as_other(),
            );
            let safe = connector_error(original);
            assert_eq!(
                (
                    safe.is_io(),
                    safe.is_timeout(),
                    safe.is_user(),
                    safe.is_other(),
                    safe.as_other()
                ),
                expected
            );
            let details = format!("{safe:?}");
            assert!(!details.contains("=secret"));
            assert!(!details.contains("=token"));
            assert!(details.contains("connection reset"));
            assert!(safe.source().unwrap().to_string().contains("[REDACTED]"));
        }
    }

    #[test]
    fn redaction_keeps_connection_metadata_and_poisoning() {
        use aws_smithy_runtime_api::client::connection::ConnectionMetadata;
        use std::sync::{
            atomic::{AtomicBool, Ordering::Relaxed},
            Arc,
        };
        let poisoned = Arc::new(AtomicBool::new(false));
        let flag = poisoned.clone();
        let address = "127.0.0.1:443".parse().unwrap();
        let metadata = ConnectionMetadata::builder()
            .proxied(false)
            .remote_addr(address)
            .poison_fn(move || {
                flag.store(true, Relaxed);
            })
            .build();
        let safe = connector_error(
            ConnectorError::io(
                anyhow::anyhow!("reset https://storage.example/key?X-Amz-Signature=secret").into(),
            )
            .with_connection(metadata),
        );
        assert!(safe.is_io());
        let connection = safe.connection_metadata().unwrap();
        assert_eq!(connection.remote_addr(), Some(address));
        connection.poison();
        assert!(poisoned.load(Relaxed));
    }

    #[test]
    fn redacts_urls_exposed_only_by_a_causes_display() {
        #[derive(Debug)]
        struct Cause;
        impl std::fmt::Display for Cause {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("reset https://storage.example/key?X-Amz-Signature=secret")
            }
        }
        impl std::error::Error for Cause {}
        let safe = connector_error(ConnectorError::io(Box::new(Cause)));
        assert!(!format!("{safe:?}").contains("=secret"));
        assert!(!safe.source().unwrap().to_string().contains("=secret"));
        assert!(safe.source().unwrap().to_string().contains("reset"));
    }

    #[test]
    fn errors_without_bearer_values_keep_the_original_source() {
        let safe = connector_error(
            ConnectorError::io(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
                .never_connected(),
        );
        assert!(safe.is_io());
        assert_eq!(
            safe.source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::ConnectionReset
        );
        assert!(format!("{safe:?}").contains("NeverConnected"));
    }
}
