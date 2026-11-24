//! ListObjectsV2 listings: `find` and `ls`, `map`, and copy, download and
//! removal planning.
pub(super) mod engine;
pub(super) mod pattern;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result};
use engine::{Entry, Page, Store};
#[cfg(test)]
use pattern::Pattern;

/// ListObjectsV2 pages for every S3 listing: `find` and `ls`, `map`, and
/// copy, download and removal planning.
pub(super) struct S3<'a> {
    pub(super) client: aws_sdk_s3::Client,
    pub(super) bucket: &'a str,
    /// Whether listings may be divided into parts: [`lists_in_byte_order`]
    /// for the endpoint the client uses and this bucket.
    pub(super) divides: bool,
}
/// Directory buckets do not promise lexicographic LIST order.
pub(super) fn lists_in_key_order(bucket: &str) -> bool {
    !bucket.ends_with("--x-s3")
}

/// Whether listings of `bucket` at `endpoint` may be divided into parts
/// (`engine::Store::divides`): the provider must document that ListObjectsV2
/// returns keys in UTF-8 byte order. `None` is the AWS endpoint the SDK
/// chooses.
///
/// Of the providers checked, only AWS documents it: "List results are always
/// returned in UTF-8 binary order" (https://docs.aws.amazon.com/AmazonS3/latest/userguide/ListingKeysUsingAPIs.html),
/// for general purpose buckets. Directory buckets are not in lexicographic
/// order (https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html),
/// and Object Lambda access points can return a LIST response of their own
/// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/olap-writing-lambda.html),
/// so only names of general purpose buckets divide.
///
/// Left out: Cloudflare R2, whose S3 API documentation states no order and
/// for which a different order was reported
/// (https://community.cloudflare.com/t/r2-listobjectsv2-returns-keys-in-non-standard-lexicographical-order/941399);
/// Google Cloud Storage, which says "lexicographically by name" without
/// saying by bytes (https://cloud.google.com/storage/docs/xml-api/get-bucket-list);
/// Backblaze B2, "sorted alphabetically by key"
/// (https://www.backblaze.com/apidocs/s3-list-objects-v2); Tigris, whose
/// S3 compatibility page states no order (https://www.tigrisdata.com/docs/api/s3/);
/// and every self-hosted or unrecognized endpoint.
pub(super) fn lists_in_byte_order(endpoint: Option<&str>, bucket: &str) -> bool {
    general_purpose_bucket(bucket)
        && endpoint
            .is_none_or(|endpoint| aws_endpoint(endpoint) || (test_divides() && loopback(endpoint)))
}

/// The test servers are not AWS. Debug builds let them divide listings: they
/// listen on a loopback address.
fn test_divides() -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_S3_DIVIDE_LISTINGS").is_some_and(|v| v == "1") {
        return true;
    }
    false
}

/// Whether a debug build reports that a listing was split by directory, so
/// that the S3 suite can confirm it against a real server.
#[cfg(debug_assertions)]
pub(super) fn test_reports_splits() -> bool {
    std::env::var_os("SYQ_TEST_S3_REPORT_SPLITS").is_some_and(|v| v == "1")
}

fn loopback(endpoint: &str) -> bool {
    url::Url::parse(endpoint).is_ok_and(|url| match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    })
}

/// Whether `bucket` names a general purpose bucket rather than an ARN or an
/// alias with a suffix AWS reserves: directory buckets (`--x-s3`) and their
/// access points (`--xa-s3`), Object Lambda (`--ol-s3`), Outposts (`--op-s3`),
/// access point and multi-Region access point aliases (`-s3alias`, `.mrap`),
/// and table buckets (`--table-s3`)
/// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html).
fn general_purpose_bucket(bucket: &str) -> bool {
    !bucket.contains(':')
        && ![
            "--x-s3",
            "--xa-s3",
            "--ol-s3",
            "--op-s3",
            "-s3alias",
            ".mrap",
            "--table-s3",
        ]
        .iter()
        .any(|suffix| bucket.ends_with(suffix))
}

/// Whether `endpoint` is the base URL of an AWS S3 endpoint for general
/// purpose buckets, which the client addresses path-style: global, regional,
/// legacy dash-regional, dual-stack and FIPS endpoints in the AWS and China
/// partitions (https://docs.aws.amazon.com/general/latest/gr/s3.html), and
/// the bucket role of a VPC interface endpoint
/// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/privatelink-interface-endpoints.html).
/// Hosts that already name a bucket, access points, Object Lambda, Outposts,
/// directory buckets (`s3express`) and multi-Region access points are not.
fn aws_endpoint(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    // A path would come before the bucket's: another bucket, and a key. The
    // SDK sends the path as given, so check it before any normalization.
    let Some((_, rest)) = endpoint.split_once("://") else {
        return false;
    };
    let path = rest.find(['/', '\\']).map_or("", |at| &rest[at..]);
    if !matches!(path, "" | "/") || url.path() != "/" {
        return false;
    }
    let Some(url::Host::Domain(host)) = url.host() else {
        return false;
    };
    let labels: Vec<&str> = host.split('.').collect();
    let rest = match labels.as_slice() {
        [rest @ .., "amazonaws", "com"] | [rest @ .., "amazonaws", "com", "cn"] => rest,
        _ => return false,
    };
    let region = |label: &str| {
        label
            .split('-')
            .next()
            .is_some_and(|area| area.len() == 2 && area.bytes().all(|b| b.is_ascii_lowercase()))
            && label.len() > 3
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && label.ends_with(|c: char| c.is_ascii_digit())
            && !label.contains("--")
    };
    match rest {
        ["s3"] | ["s3-external-1"] => true,
        ["s3" | "s3-fips", r] | ["s3" | "s3-fips", "dualstack", r] => region(r),
        ["bucket", endpoint, "s3", r, "vpce"] => endpoint.starts_with("vpce-") && region(r),
        [legacy] => legacy.strip_prefix("s3-").is_some_and(region),
        _ => false,
    }
}

/// The request [`S3::first_key`] sends, as storage signing names it.
pub(super) fn first_key_request(prefix: &str) -> super::authorization::Unsigned {
    super::authorization::Unsigned::new("GET", "")
        .query("list-type", "2")
        .query("prefix", prefix)
        .query("max-keys", "1")
        .query("encoding-type", "url")
}

/// The request [`S3::page`] sends for a page of `prefix` without a delimiter
/// or continuation token, as storage signing names it, so that a copy can have
/// it signed before sending it.
pub(super) fn first_page_request(
    prefix: &str,
    start_after: Option<&str>,
) -> super::authorization::Unsigned {
    let request = super::authorization::Unsigned::new("GET", "")
        .query("list-type", "2")
        .query("prefix", prefix)
        .query("max-keys", "1000")
        .query("encoding-type", "url");
    match start_after {
        Some(after) => request.query("start-after", after),
        None => request,
    }
}

impl Store for S3<'_> {
    fn ordered(&self) -> bool {
        lists_in_key_order(self.bucket)
    }

    fn slash_only(&self) -> bool {
        self.bucket.ends_with("--x-s3") || self.bucket.ends_with("--xa-s3")
    }

    fn divides(&self) -> bool {
        self.divides
    }

    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        self.request(prefix, delimiter, token, start_after, 1000)
            .await
    }
}

impl S3<'_> {
    /// The first key under `prefix`, if any, and whether more follow: the
    /// request [`first_key_request`] names.
    pub(super) async fn first_key(&self, prefix: &str) -> Result<Page> {
        self.request(prefix, false, None, None, 1).await
    }

    async fn request(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
        max_keys: i32,
    ) -> Result<Page> {
        // Tigris returns nothing for a delimiter listing that starts after a
        // key ending in '/'; syq never sends StartAfter with a delimiter.
        debug_assert!(!(delimiter && start_after.is_some()));
        let response = self
            .client
            .list_objects_v2()
            .bucket(self.bucket)
            .prefix(prefix)
            .max_keys(max_keys)
            .encoding_type(aws_sdk_s3::types::EncodingType::Url)
            .set_delimiter(delimiter.then(|| "/".into()))
            .set_continuation_token(token.map(str::to_owned))
            .set_start_after(start_after.map(str::to_owned))
            .send()
            .await
            .map_err(super::client::listing_failure)?;
        // URL encoding lets keys hold characters XML cannot carry. Decode only
        // when the response says it was applied: a provider that ignores the
        // request returns keys as stored, and those can contain '%' and '+'.
        let encoded = response.encoding_type() == Some(&aws_sdk_s3::types::EncodingType::Url);
        let decode = |value: &str| -> Result<String> {
            if !encoded {
                return Ok(value.to_owned());
            }
            Ok(
                percent_encoding::percent_decode_str(&value.replace('+', " "))
                    .decode_utf8()
                    .context("S3 listing returned a key that is not UTF-8")?
                    .into_owned(),
            )
        };
        let mut entries = Vec::new();
        for object in response.contents() {
            entries.push(Entry {
                key: decode(object.key().context("S3 listing omitted key")?)?,
                size: u64::try_from(object.size().context("S3 listing omitted size")?)
                    .context("S3 listing returned a negative size")?,
                last_modified: object
                    .last_modified()
                    .map(|time| (time.secs(), time.subsec_nanos())),
                etag: object.e_tag().map(str::to_owned),
            });
        }
        let prefixes = response
            .common_prefixes()
            .iter()
            .map(|p| decode(p.prefix().context("S3 listing omitted common prefix")?))
            .collect::<Result<_>>()?;
        let next = if response.is_truncated() == Some(true) {
            Some(
                response
                    .next_continuation_token()
                    .context("truncated S3 listing omitted continuation token")?
                    .to_owned(),
            )
        } else {
            None
        };
        // A response that leaves out IsTruncated, or that gives a
        // continuation token anyway, may have more to list.
        let complete =
            response.is_truncated() == Some(false) && response.next_continuation_token().is_none();
        Ok(Page {
            entries,
            prefixes,
            next,
            complete,
        })
    }
}
