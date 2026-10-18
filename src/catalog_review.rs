//! Maintainer review works with inert candidates and explicitly published metadata.

use gulikit_catalog::{Catalog, Entry, MAX_CATALOG_BYTES, VendorVerification, stable_source_url};
use gulikit_core::package::{CandidatePackageInspection, Component, Model};
use gulikit_platform::catalog::{
    CatalogFetchError, CatalogFetcher, HttpsCatalogFetcher, read_catalog_file,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path, str::FromStr};

use crate::{AppError, CatalogCommand};

const MAX_PAGE_BYTES: usize = 256 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CANDIDATE_BYTES: usize = 32 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    product: String,
    component: String,
    version: String,
    archive: String,
    member: String,
    source_url: String,
    observed_at: String,
    vendor_verification: VendorVerification,
    #[serde(default)]
    download_url: Option<String>,
    #[serde(default)]
    changelog_url: Option<String>,
    #[serde(default)]
    availability: gulikit_catalog::DownloadAvailability,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PageIdentity {
    size: usize,
    sha256: String,
}

#[derive(Serialize)]
struct Candidate {
    schema_version: u32,
    kind: &'static str,
    entry: Entry,
    observed_at: String,
    source_page: PageIdentity,
    vendor_verification: VendorVerification,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_page_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCandidate {
    schema_version: u32,
    kind: String,
    entry: Box<serde_json::value::RawValue>,
    observed_at: String,
    source_page: PageIdentity,
    vendor_verification: VendorVerification,
    #[serde(default)]
    previous_page_sha256: Option<String>,
}

fn rejected(message: impl Into<String>) -> AppError {
    AppError::new("catalog_review_rejected", 3, message.into())
}

fn file_error(error: impl std::fmt::Display) -> AppError {
    AppError::new("catalog_review_io", 4, error.to_string())
}

fn read(path: &Path, bound: usize) -> Result<Vec<u8>, AppError> {
    read_catalog_file(path, bound).map_err(file_error)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn page_identity(bytes: &[u8]) -> Result<PageIdentity, AppError> {
    if bytes.is_empty() || bytes.len() > MAX_PAGE_BYTES {
        return Err(rejected("Source page must contain 1..=262144 bytes."));
    }
    Ok(PageIdentity {
        size: bytes.len(),
        sha256: digest(bytes),
    })
}

fn valid_utc(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        b[start..end].iter().try_fold(0u32, |n, c| {
            c.is_ascii_digit().then(|| n * 10 + u32::from(*c - b'0'))
        })
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    year > 0 && day > 0 && day <= days && hour < 24 && minute < 60 && second < 60
}

fn require_verification_review(evidence: &VendorVerification) -> Result<(), AppError> {
    // Entry parsing already validates evidence bounds, official URLs and checksum equality.
    match evidence {
        VendorVerification::Unknown => Err(rejected(
            "Review the vendor's verification evidence before publication.",
        )),
        VendorVerification::Signature { .. } => Err(rejected(
            "This vendor signature format has no implemented verifier; preserve the candidate and add support before publication.",
        )),
        VendorVerification::NotPublished { .. } | VendorVerification::Sha256 { .. } => Ok(()),
    }
}

fn load_candidate(path: &Path) -> Result<Candidate, AppError> {
    let raw: RawCandidate = serde_json::from_slice(&read(path, MAX_CANDIDATE_BYTES)?)
        .map_err(|e| rejected(e.to_string()))?;
    if raw.schema_version != 1
        || raw.kind != "release_candidate"
        || !valid_utc(&raw.observed_at)
        || raw.source_page.size == 0
        || raw.source_page.size > MAX_PAGE_BYTES
        || !valid_digest(&raw.source_page.sha256)
        || raw
            .previous_page_sha256
            .as_deref()
            .is_some_and(|v| !valid_digest(v))
    {
        return Err(rejected(
            "Invalid candidate schema, timestamp or source-page identity.",
        ));
    }
    let entry = Entry::parse(raw.entry.get().as_bytes()).map_err(|e| rejected(e.to_string()))?;
    if entry.software_support() != gulikit_catalog::SoftwareSupport::MetadataOnly
        || entry.hardware_acceptance() != gulikit_catalog::HardwareAcceptance::Unqualified
        || entry.vendor_verification() != Some(&raw.vendor_verification)
    {
        return Err(rejected(
            "A candidate must remain metadata-only and hardware-unqualified.",
        ));
    }
    Ok(Candidate {
        schema_version: 1,
        kind: "release_candidate",
        entry,
        observed_at: raw.observed_at,
        source_page: raw.source_page,
        vendor_verification: raw.vendor_verification,
        previous_page_sha256: raw.previous_page_sha256,
    })
}

fn load_catalog(path: &Path) -> Result<Catalog, AppError> {
    Catalog::parse(&read(path, MAX_CATALOG_BYTES)?).map_err(|e| rejected(e.to_string()))
}

fn measure(
    archive: &Path,
    product: &str,
    component: &str,
    version: &str,
    member: &str,
) -> Result<CandidatePackageInspection, AppError> {
    let model = Model::from_str(product).map_err(|e| rejected(e.to_string()))?;
    let component = Component::from_str(component).map_err(|e| rejected(e.to_string()))?;
    gulikit_platform::inspect_candidate_package(archive, model, component, version, member).map_err(
        |error| match error {
            gulikit_platform::InspectError::Rejected(_) => rejected(error.to_string()),
            _ => file_error(error),
        },
    )
}

fn prepare(
    request: &Path,
    archive: &Path,
    page: &Path,
    previous: Option<&Path>,
) -> Result<Candidate, AppError> {
    let request: Request = serde_json::from_slice(&read(request, MAX_REQUEST_BYTES)?)
        .map_err(|e| rejected(e.to_string()))?;
    if request.schema_version != 1 || !valid_utc(&request.observed_at) {
        return Err(rejected(
            "Use request schema1 and a complete UTC timestamp YYYY-MM-DDTHH:MM:SSZ.",
        ));
    }
    let measured = measure(
        archive,
        &request.product,
        &request.component,
        &request.version,
        &request.member,
    )?;
    let info = measured.info();
    let entry = Entry::parse(&serde_json::to_vec(&json!({
        "product":request.product,"component":request.component,"version":request.version,
        "archive":request.archive,"member":request.member,"source_url":request.source_url,
        "archive_size":info.archive_size,"archive_sha256":info.archive_sha256,
        "member_size":info.member_size,"member_sha256":info.member_sha256,
        "payload_size":info.payload_size,"payload_sha256":info.payload_sha256,
        "parser_id":info.parser_id,"software_support":"metadata_only",
        "hardware_acceptance":"unqualified","hardware_evidence":null,
        "download_url":request.download_url,"changelog_url":request.changelog_url,"availability":request.availability,
        "vendor_verification":request.vendor_verification
    })).map_err(file_error)?).map_err(|e| rejected(e.to_string()))?;
    let source_page = page_identity(&read(page, MAX_PAGE_BYTES)?)?;
    let previous_page_sha256 = previous
        .map(load_candidate)
        .transpose()?
        .map(|old| {
            if old.entry.source_url() != entry.source_url() {
                return Err(rejected(
                    "Previous observation must refer to the same official page.",
                ));
            }
            Ok(old.source_page.sha256)
        })
        .transpose()?;
    Ok(Candidate {
        schema_version: 1,
        kind: "release_candidate",
        entry,
        observed_at: request.observed_at,
        source_page,
        vendor_verification: request.vendor_verification,
        previous_page_sha256,
    })
}

fn recheck(candidate: &Candidate, archive: &Path, page: &[u8]) -> Result<(), AppError> {
    let e = &candidate.entry;
    let measured = measure(archive, e.product(), e.component(), e.version(), e.member())?;
    let m = measured.info();
    if m.archive_size != usize::try_from(e.archive_size()).unwrap_or(usize::MAX)
        || m.archive_sha256 != e.archive_sha256().as_str()
        || m.member_size != usize::try_from(e.member_size()).unwrap_or(usize::MAX)
        || m.member_sha256 != e.member_sha256().as_str()
        || m.payload_size != usize::try_from(e.payload_size()).unwrap_or(usize::MAX)
        || m.payload_sha256 != e.payload_sha256().as_str()
        || m.parser_id != e.parser_id()
        || page_identity(page)? != candidate.source_page
    {
        return Err(rejected(
            "Original archive, selected member/payload or source page changed after preparation.",
        ));
    }
    require_verification_review(&candidate.vendor_verification)
}

fn publish_candidate(
    candidate: &Candidate,
    catalog: &Catalog,
    archive: &Path,
    page: &[u8],
) -> Result<Catalog, AppError> {
    recheck(candidate, archive, page)?;
    let mut entry = serde_json::to_value(&candidate.entry).map_err(file_error)?;
    entry["software_support"] = json!("supported");
    if let Some(prior) = catalog.entries().iter().find(|e| {
        e.product() == candidate.entry.product()
            && e.component() == candidate.entry.component()
            && e.version() == candidate.entry.version()
    }) {
        entry["hardware_acceptance"] =
            serde_json::to_value(prior.hardware_acceptance()).map_err(file_error)?;
        entry["hardware_evidence"] =
            serde_json::to_value(prior.hardware_evidence()).map_err(file_error)?;
    }
    let entry = Entry::parse(&serde_json::to_vec(&entry).map_err(file_error)?)
        .map_err(|e| rejected(e.to_string()))?;
    catalog.upsert(entry).map_err(|e| rejected(e.to_string()))
}

fn publish_file(path: &Path, bytes: &[u8]) -> Result<(), AppError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(file_error)?;
    temporary.write_all(bytes).map_err(file_error)?;
    temporary.as_file().sync_all().map_err(file_error)?;
    temporary
        .persist_noclobber(path)
        .map_err(|e| file_error(e.error))?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| AppError::new("catalog_review_durability_unknown", 8, e.to_string()))?;
    Ok(())
}

pub(super) fn report(command: CatalogCommand) -> Result<Value, AppError> {
    match command {
        CatalogCommand::Observe { url, output, .. } => {
            if !stable_source_url(&url) {
                return Err(rejected("Use a stable official GuliKit page URL."));
            }
            let bytes = HttpsCatalogFetcher
                .fetch(&url)
                .map_err(|error| match error {
                    CatalogFetchError::Request(_) => file_error(error),
                    _ => rejected(error.to_string()),
                })?;
            let source_page = page_identity(&bytes)?;
            publish_file(&output, &bytes)?;
            Ok(
                json!({"source_url":url,"source_page":source_page,"output":output.to_string_lossy(),"authorizes_firmware":false}),
            )
        }
        CatalogCommand::Prepare {
            request,
            archive,
            page,
            output,
            previous,
            ..
        } => {
            let candidate = prepare(&request, &archive, &page, previous.as_deref())?;
            let bytes = serde_json::to_vec_pretty(&candidate).map_err(file_error)?;
            if bytes.len() > MAX_CANDIDATE_BYTES {
                return Err(rejected("Candidate exceeds its byte limit."));
            }
            publish_file(&output, &bytes)?;
            let page_changed = candidate
                .previous_page_sha256
                .as_ref()
                .map(|old| old != &candidate.source_page.sha256);
            Ok(
                json!({"candidate":candidate,"page_changed":page_changed,"output":output.to_string_lossy(),"authorizes_firmware":false}),
            )
        }
        CatalogCommand::Diff {
            previous, proposed, ..
        } => {
            let previous = load_catalog(&previous)?;
            let proposed = load_catalog(&proposed)?;
            Ok(json!({"diff":previous.diff(&proposed),"authorizes_firmware":false}))
        }
        CatalogCommand::Publish {
            candidate,
            catalog,
            archive,
            page,
            output,
            ..
        } => {
            let candidate = load_candidate(&candidate)?;
            let catalog = load_catalog(&catalog)?;
            let proposed = publish_candidate(
                &candidate,
                &catalog,
                &archive,
                &read(&page, MAX_PAGE_BYTES)?,
            )?;
            let bytes = serde_json::to_vec_pretty(&proposed).map_err(file_error)?;
            if bytes.len() > MAX_CATALOG_BYTES {
                return Err(rejected("Published catalog exceeds its byte limit."));
            }
            publish_file(&output, &bytes)?;
            Ok(
                json!({"catalog":proposed,"diff":catalog.diff(&proposed),"output":output.to_string_lossy(),"authorizes_firmware":false}),
            )
        }
        _ => Err(rejected("Expected a catalog review command.")),
    }
}

#[cfg(test)]
mod tests {
    use super::valid_utc;

    #[test]
    fn observation_time_is_a_real_complete_utc_timestamp() {
        assert!(valid_utc("2024-02-29T23:59:59Z"));
        for invalid in [
            "2025-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-10-18",
            "2026-10-18T24:00:00Z",
            "0000-01-01T00:00:00Z",
            "é026-10-18T00:00:00Z",
        ] {
            assert!(!valid_utc(invalid), "{invalid}");
        }
    }
}
