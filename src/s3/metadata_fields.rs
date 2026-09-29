//! Explicitly selected S3 attributes. These remain process-local: filesystem
//! helpers and persisted mapping records do not carry S3 object properties.
use anyhow::Result;
use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::types::StorageClass;

#[derive(Clone, Debug, Default)]
pub(crate) struct Selection {
    pub content_type: bool,
    pub content_encoding: bool,
    pub content_language: bool,
    pub content_disposition: bool,
    pub cache_control: bool,
    pub expires: bool,
    pub website_redirect: bool,
    pub user_metadata: bool,
    pub tags: bool,
    pub storage_class: bool,
}

impl Selection {
    pub(crate) fn active(&self) -> bool {
        self.content_type
            || self.content_encoding
            || self.content_language
            || self.content_disposition
            || self.cache_control
            || self.expires
            || self.website_redirect
            || self.user_metadata
            || self.tags
            || self.storage_class
    }

    pub(super) fn apply(
        &self,
        source: &HeadObjectOutput,
        desired: &mut HeadObjectOutput,
    ) -> Result<()> {
        if self.user_metadata {
            anyhow::ensure!(source.missing_meta().unwrap_or(0) == 0,
                "cannot copy user metadata: the service omitted source metadata (x-amz-missing-meta)");
            let fields = desired.metadata.get_or_insert_with(Default::default);
            // Content identities and file attributes belong to the destination
            // bytes, or to their separate explicit metadata selections.
            fields.retain(|name, _| name.starts_with("syq-"));
            fields.extend(
                source
                    .metadata()
                    .into_iter()
                    .flat_map(|m| m.iter())
                    .filter(|(name, _)| !name.starts_with("syq-"))
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
        }
        if self.content_type {
            desired.content_type = source.content_type.clone();
        }
        if self.content_encoding {
            desired.content_encoding = source.content_encoding.clone();
        }
        if self.content_language {
            desired.content_language = source.content_language.clone();
        }
        if self.content_disposition {
            desired.content_disposition = source.content_disposition.clone();
        }
        if self.cache_control {
            desired.cache_control = source.cache_control.clone();
        }
        if self.expires {
            desired.expires_string = source.expires_string.clone();
        }
        if self.website_redirect {
            desired.website_redirect_location = source.website_redirect_location.clone();
        }
        if self.storage_class {
            desired.storage_class = Some(
                source
                    .storage_class
                    .clone()
                    .unwrap_or(StorageClass::Standard),
            );
        }
        Ok(())
    }
}

pub(super) fn storage_class(head: &HeadObjectOutput) -> &str {
    head.storage_class().map_or("STANDARD", |v| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_metadata_replaces_its_set_without_source_content_identity() {
        let source = HeadObjectOutput::builder()
            .metadata("syq-hash", "source-hash")
            .metadata("syq-mode", "384")
            .metadata("app", "source")
            .build();
        let mut desired = HeadObjectOutput::builder()
            .metadata("syq-hash", "destination-hash")
            .metadata("syq-mode", "416")
            .metadata("app", "destination")
            .metadata("destination-only", "remove")
            .build();
        Selection {
            user_metadata: true,
            ..Default::default()
        }
        .apply(&source, &mut desired)
        .unwrap();
        let metadata = desired.metadata().unwrap();
        assert_eq!(metadata["syq-hash"], "destination-hash");
        assert_eq!(metadata["syq-mode"], "416");
        assert_eq!(metadata["app"], "source");
        assert!(!metadata.contains_key("destination-only"));
    }
}
