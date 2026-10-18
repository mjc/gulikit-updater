//! Strict, bounded parsing for reviewed firmware catalog metadata.
//!
//! Catalog entries describe files, parser capability, software support and
//! hardware acceptance. [`Catalog::parse`] validates descriptive metadata only;
//! a digest match checks consistency with a catalog record. Catalog parsing
//! does not establish vendor authenticity or authorize installation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_CATALOG_BYTES: usize = 256 * 1024;
pub const MAX_ENTRIES: usize = 256;
pub const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;
const MAX_IDENTIFIER_LENGTH: usize = 64;
const MAX_ENTRY_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    schema_version: u32,
    entries: Vec<RawEntry>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    product: String,
    component: String,
    version: String,
    archive: String,
    archive_size: u64,
    archive_sha256: String,
    member: String,
    member_size: u64,
    member_sha256: String,
    payload_size: u64,
    payload_sha256: String,
    source_url: String,
    #[serde(default)]
    download_url: Option<String>,
    #[serde(default)]
    availability: DownloadAvailability,
    #[serde(default)]
    changelog_url: Option<String>,
    parser_id: String,
    software_support: String,
    hardware_acceptance: String,
    hardware_evidence: Option<RawHardwareEvidence>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RawHardwareEvidence {
    model_label: String,
    scope: String,
    evidence_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    schema_version: u32,
    entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    product: String,
    component: String,
    version: String,
    archive: String,
    archive_size: u64,
    archive_sha256: Sha256Digest,
    member: String,
    member_size: u64,
    member_sha256: Sha256Digest,
    payload_size: u64,
    payload_sha256: Sha256Digest,
    source_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_url: Option<String>,
    #[serde(default, skip_serializing_if = "DownloadAvailability::is_unknown")]
    availability: DownloadAvailability,
    #[serde(skip_serializing_if = "Option::is_none")]
    changelog_url: Option<String>,
    parser_id: ParserId,
    software_support: SoftwareSupport,
    hardware_acceptance: HardwareAcceptance,
    hardware_evidence: Option<HardwareEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserId {
    None,
    Kk3MainBinaryV1,
    Kk3BluetoothPeV1,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Metadata claim about software handling, not package authentication or write authorization.
pub enum SoftwareSupport {
    Supported,
    MetadataOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Metadata claim about device acceptance; it does not establish acceptance for another device or release.
pub enum HardwareAcceptance {
    Qualified,
    Unqualified,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Availability reported for a direct vendor ZIP link.
pub enum DownloadAvailability {
    #[default]
    Unknown,
    Available,
    Unavailable,
}

impl DownloadAvailability {
    // Serde skip_serializing_if predicates receive a reference.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_unknown(&self) -> bool {
        match self {
            Self::Unknown => true,
            Self::Available | Self::Unavailable => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareEvidence {
    model_label: String,
    scope: String,
    evidence_url: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("catalog exceeds the {MAX_CATALOG_BYTES}-byte input limit")]
    InputTooLarge,
    #[error("catalog entry exceeds the {MAX_ENTRY_BYTES}-byte input limit")]
    EntryInputTooLarge,
    #[error("invalid catalog JSON: {0}")]
    Json(String),
    #[error("unsupported catalog schema version {0}")]
    UnknownSchema(u32),
    #[error("catalog has more than {MAX_ENTRIES} entries")]
    TooManyEntries,
    #[error("invalid {field} in entry {index}: {reason}")]
    InvalidField {
        index: usize,
        field: &'static str,
        reason: &'static str,
    },
    #[error("duplicate product/component/version identity: {product}/{component}/{version}")]
    DuplicateIdentity {
        product: String,
        component: String,
        version: String,
    },
}

impl Catalog {
    /// Parse untrusted catalog JSON while enforcing the schema and metadata bounds.
    ///
    /// # Errors
    /// Returns an error for oversized input, malformed or unknown schema data,
    /// invalid metadata, and repeated product/component identities.
    pub fn parse(input: &[u8]) -> Result<Self, CatalogError> {
        if input.len() > MAX_CATALOG_BYTES {
            return Err(CatalogError::InputTooLarge);
        }
        let raw: RawCatalog =
            serde_json::from_slice(input).map_err(|error| CatalogError::Json(error.to_string()))?;
        if raw.schema_version != 1 {
            return Err(CatalogError::UnknownSchema(raw.schema_version));
        }
        if raw.entries.len() > MAX_ENTRIES {
            return Err(CatalogError::TooManyEntries);
        }
        let mut entries = Vec::with_capacity(raw.entries.len());
        for (index, raw_entry) in raw.entries.into_iter().enumerate() {
            let entry = Entry::try_from_raw(index, raw_entry)?;
            if entries.iter().any(|existing: &Entry| {
                existing.product == entry.product
                    && existing.component == entry.component
                    && existing.version == entry.version
            }) {
                return Err(CatalogError::DuplicateIdentity {
                    product: entry.product,
                    component: entry.component,
                    version: entry.version,
                });
            }
            entries.push(entry);
        }
        Ok(Self {
            schema_version: 1,
            entries,
        })
    }

    /// Build a catalog containing only one previously parsed record.
    #[must_use]
    pub fn from_entry(entry: Entry) -> Self {
        Self {
            schema_version: 1,
            entries: vec![entry],
        }
    }

    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

impl Entry {
    /// Parse one untrusted catalog record with the same validation as a catalog entry.
    ///
    /// # Errors
    /// Rejects oversized, malformed or invalid entry metadata.
    pub fn parse(input: &[u8]) -> Result<Self, CatalogError> {
        if input.len() > MAX_ENTRY_BYTES {
            return Err(CatalogError::EntryInputTooLarge);
        }
        let raw: RawEntry =
            serde_json::from_slice(input).map_err(|error| CatalogError::Json(error.to_string()))?;
        Self::try_from_raw(0, raw)
    }

    fn try_from_raw(index: usize, raw: RawEntry) -> Result<Self, CatalogError> {
        validate_identity(index, &raw)?;
        let hashes = validate_file_metadata(index, &raw)?;
        if !stable_source_url(&raw.source_url) {
            return Err(invalid(
                index,
                "source_url",
                "expected a stable HTTPS URL on gulikit.com",
            ));
        }
        if raw
            .download_url
            .as_deref()
            .is_some_and(|url| !stable_download_url(url))
        {
            return Err(invalid(
                index,
                "download_url",
                "expected a stable HTTPS GuliKit ZIP URL",
            ));
        }
        if raw
            .changelog_url
            .as_deref()
            .is_some_and(|url| !stable_source_url(url))
        {
            return Err(invalid(
                index,
                "changelog_url",
                "expected a stable HTTPS URL on gulikit.com",
            ));
        }
        let parser_id = parse_parser_id(index, &raw)?;
        let software_support = parse_software_support(index, &raw.software_support)?;
        let hardware_acceptance = parse_hardware_acceptance(index, &raw.hardware_acceptance)?;
        if software_support == SoftwareSupport::Supported && !parser_is_implemented(parser_id) {
            return Err(invalid(
                index,
                "software_support",
                "supported requires an implemented parser",
            ));
        }
        let hardware_evidence =
            parse_hardware_evidence(index, hardware_acceptance, raw.hardware_evidence)?;
        validate_status_coherence(
            index,
            hardware_acceptance,
            software_support,
            hardware_evidence.as_ref(),
        )?;
        let entry = Self {
            product: raw.product,
            component: raw.component,
            version: raw.version,
            archive: raw.archive,
            archive_size: raw.archive_size,
            archive_sha256: hashes.archive,
            member: raw.member,
            member_size: raw.member_size,
            member_sha256: hashes.member,
            payload_size: raw.payload_size,
            payload_sha256: hashes.payload,
            source_url: raw.source_url,
            download_url: raw.download_url,
            availability: raw.availability,
            changelog_url: raw.changelog_url,
            parser_id,
            software_support,
            hardware_acceptance,
            hardware_evidence,
        };
        if serde_json::to_vec(&entry)
            .map_err(|error| CatalogError::Json(error.to_string()))?
            .len()
            > MAX_ENTRY_BYTES
        {
            return Err(CatalogError::EntryInputTooLarge);
        }
        Ok(entry)
    }

    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
    #[must_use]
    pub fn archive(&self) -> &str {
        &self.archive
    }
    #[must_use]
    pub fn archive_size(&self) -> u64 {
        self.archive_size
    }
    #[must_use]
    pub fn archive_sha256(&self) -> &Sha256Digest {
        &self.archive_sha256
    }
    #[must_use]
    pub fn member(&self) -> &str {
        &self.member
    }
    #[must_use]
    pub fn member_size(&self) -> u64 {
        self.member_size
    }
    #[must_use]
    pub fn member_sha256(&self) -> &Sha256Digest {
        &self.member_sha256
    }
    #[must_use]
    pub fn payload_size(&self) -> u64 {
        self.payload_size
    }
    #[must_use]
    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }
    #[must_use]
    pub fn source_url(&self) -> &str {
        &self.source_url
    }
    #[must_use]
    pub fn download_url(&self) -> Option<&str> {
        self.download_url.as_deref()
    }
    #[must_use]
    pub fn availability(&self) -> DownloadAvailability {
        self.availability
    }
    #[must_use]
    pub fn changelog_url(&self) -> Option<&str> {
        self.changelog_url.as_deref()
    }
    #[must_use]
    pub fn parser_id(&self) -> ParserId {
        self.parser_id
    }
    #[must_use]
    pub fn software_support(&self) -> SoftwareSupport {
        self.software_support
    }
    #[must_use]
    pub fn hardware_acceptance(&self) -> HardwareAcceptance {
        self.hardware_acceptance
    }
    #[must_use]
    pub fn hardware_evidence(&self) -> Option<&HardwareEvidence> {
        self.hardware_evidence.as_ref()
    }
}

struct ValidatedHashes {
    archive: Sha256Digest,
    member: Sha256Digest,
    payload: Sha256Digest,
}

fn validate_identity(index: usize, raw: &RawEntry) -> Result<(), CatalogError> {
    for (field, value) in [
        ("product", raw.product.as_str()),
        ("component", raw.component.as_str()),
    ] {
        if !valid_identifier(value) {
            return Err(invalid(
                index,
                field,
                "expected a lowercase hyphenated identifier",
            ));
        }
    }
    validate_version(index, &raw.component, &raw.version)
}

fn validate_file_metadata(index: usize, raw: &RawEntry) -> Result<ValidatedHashes, CatalogError> {
    if !valid_filename(&raw.archive) {
        return Err(invalid(index, "archive", "expected a simple filename"));
    }
    if raw.archive_size == 0 || raw.archive_size > MAX_ARCHIVE_SIZE {
        return Err(invalid(index, "archive_size", "outside allowed bounds"));
    }
    if raw.payload_size == 0 || raw.payload_size > raw.member_size {
        return Err(invalid(
            index,
            "payload_size",
            "must be positive and no larger than the uncompressed member",
        ));
    }
    if !valid_relative_member(&raw.member) {
        return Err(invalid(
            index,
            "member",
            "expected a safe relative member path",
        ));
    }
    if raw.member_size == 0 || raw.member_size > MAX_ARCHIVE_SIZE {
        return Err(invalid(index, "member_size", "outside allowed bounds"));
    }
    Ok(ValidatedHashes {
        archive: parse_digest(index, "archive_sha256", raw.archive_sha256.clone())?,
        member: parse_digest(index, "member_sha256", raw.member_sha256.clone())?,
        payload: parse_digest(index, "payload_sha256", raw.payload_sha256.clone())?,
    })
}

fn parse_parser_id(index: usize, raw: &RawEntry) -> Result<ParserId, CatalogError> {
    match raw.parser_id.as_str() {
        "none" => Ok(ParserId::None),
        "kk3_main_binary_v1" if raw.product == "kk3-max" && raw.component == "main" => {
            Ok(ParserId::Kk3MainBinaryV1)
        }
        "kk3_bluetooth_pe_v1" if raw.product == "kk3-max" && raw.component == "bluetooth" => {
            Ok(ParserId::Kk3BluetoothPeV1)
        }
        _ => Err(invalid(
            index,
            "parser_id",
            "unknown or product/component-incompatible parser",
        )),
    }
}

fn parse_software_support(index: usize, value: &str) -> Result<SoftwareSupport, CatalogError> {
    match value {
        "supported" => Ok(SoftwareSupport::Supported),
        "metadata_only" => Ok(SoftwareSupport::MetadataOnly),
        _ => Err(invalid(
            index,
            "software_support",
            "unknown software support status",
        )),
    }
}

fn parse_hardware_acceptance(
    index: usize,
    value: &str,
) -> Result<HardwareAcceptance, CatalogError> {
    match value {
        "qualified" => Ok(HardwareAcceptance::Qualified),
        "unqualified" => Ok(HardwareAcceptance::Unqualified),
        _ => Err(invalid(
            index,
            "hardware_acceptance",
            "unknown hardware acceptance status",
        )),
    }
}

fn parse_hardware_evidence(
    index: usize,
    acceptance: HardwareAcceptance,
    raw: Option<RawHardwareEvidence>,
) -> Result<Option<HardwareEvidence>, CatalogError> {
    match (acceptance, raw) {
        (HardwareAcceptance::Unqualified, None) => Ok(None),
        (HardwareAcceptance::Qualified, Some(raw)) => {
            let valid_model = !raw.model_label.is_empty()
                && raw.model_label.len() <= 64
                && raw.model_label.trim() == raw.model_label
                && raw
                    .model_label
                    .bytes()
                    .any(|byte| byte.is_ascii_alphanumeric())
                && raw
                    .model_label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b' ' || byte == b'-');
            if !valid_model {
                return Err(invalid(
                    index,
                    "hardware_evidence.model_label",
                    "invalid bounded model label",
                ));
            }
            if raw.scope.is_empty()
                || raw.scope.len() > 512
                || raw.scope.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(invalid(
                    index,
                    "hardware_evidence.scope",
                    "expected bounded text without control characters",
                ));
            }
            if !stable_evidence_url(&raw.evidence_url) {
                return Err(invalid(
                    index,
                    "hardware_evidence.evidence_url",
                    "expected a stable HTTPS Lific document reference",
                ));
            }
            Ok(Some(HardwareEvidence {
                model_label: raw.model_label,
                scope: raw.scope,
                evidence_url: raw.evidence_url,
            }))
        }
        (HardwareAcceptance::Qualified, None) => Err(invalid(
            index,
            "hardware_evidence",
            "qualified acceptance requires scoped evidence",
        )),
        (HardwareAcceptance::Unqualified, Some(_)) => Err(invalid(
            index,
            "hardware_evidence",
            "unqualified acceptance must not carry qualification evidence",
        )),
    }
}

fn validate_status_coherence(
    index: usize,
    acceptance: HardwareAcceptance,
    support: SoftwareSupport,
    evidence: Option<&HardwareEvidence>,
) -> Result<(), CatalogError> {
    if acceptance == HardwareAcceptance::Qualified && support != SoftwareSupport::Supported {
        return Err(invalid(
            index,
            "hardware_acceptance",
            "qualified hardware acceptance requires supported software handling",
        ));
    }
    if acceptance == HardwareAcceptance::Qualified && evidence.is_none() {
        return Err(invalid(
            index,
            "hardware_evidence",
            "qualified acceptance requires scoped evidence",
        ));
    }
    Ok(())
}

impl HardwareEvidence {
    #[must_use]
    pub fn model_label(&self) -> &str {
        &self.model_label
    }
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    #[must_use]
    pub fn evidence_url(&self) -> &str {
        &self.evidence_url
    }
}

impl Sha256Digest {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn invalid(index: usize, field: &'static str, reason: &'static str) -> CatalogError {
    CatalogError::InvalidField {
        index,
        field,
        reason,
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value.ends_with(['.', ' '])
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || b"/\\:*?\"<>|".contains(&byte))
}

fn valid_relative_member(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.contains('\\')
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !part
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || b":*?\"<>|".contains(&byte))
        })
}

fn parser_is_implemented(parser: ParserId) -> bool {
    match parser {
        ParserId::None => false,
        ParserId::Kk3MainBinaryV1 | ParserId::Kk3BluetoothPeV1 => true,
    }
}

fn validate_version(index: usize, component: &str, version: &str) -> Result<(), CatalogError> {
    if version.is_empty() || version.len() > 32 {
        return Err(invalid(index, "version", "outside allowed length"));
    }
    let valid = match component {
        "main" => {
            version.matches('.').count() == 1
                && version.split_once('.').is_some_and(|(major, minor)| {
                    (1..=4).contains(&major.len())
                        && (1..=4).contains(&minor.len())
                        && canonical_decimal(major)
                        && canonical_decimal(minor)
                        && major.bytes().all(|byte| byte.is_ascii_digit())
                        && minor.bytes().all(|byte| byte.is_ascii_digit())
                        && major.parse::<u16>().is_ok()
                        && minor.parse::<u16>().is_ok()
                })
        }
        "bluetooth" => {
            version.matches('.').count() == 1
                && version.split_once('.').is_some_and(|(major, minor)| {
                    (1..=4).contains(&major.len())
                        && minor.len() == 2
                        && canonical_decimal(major)
                        && major.bytes().all(|byte| byte.is_ascii_digit())
                        && minor.bytes().all(|byte| byte.is_ascii_digit())
                        && major.parse::<u32>().is_ok_and(|value| {
                            value
                                .checked_mul(100)
                                .and_then(|hundreds| {
                                    hundreds.checked_add(minor.parse::<u32>().unwrap_or(u32::MAX))
                                })
                                .is_some_and(|hundreds| hundreds <= u16::MAX.into())
                        })
                })
        }
        _ => version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte)),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(index, "version", "invalid format for component"))
    }
}

fn canonical_decimal(value: &str) -> bool {
    value == "0" || !value.starts_with('0')
}

impl Catalog {
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

fn parse_digest(
    index: usize,
    field: &'static str,
    value: String,
) -> Result<Sha256Digest, CatalogError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            index,
            field,
            "expected 64 lowercase hexadecimal characters",
        ));
    }
    Ok(Sha256Digest(value))
}

fn stable_source_url(value: &str) -> bool {
    if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let Some((host, path)) = rest.split_once('/') else {
        return false;
    };
    (host == "gulikit.com" || host == "www.gulikit.com")
        && !path.is_empty()
        && !path.contains(['?', '#', '@', '\\', ' '])
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && valid_percent_escapes(segment)
        })
}

fn stable_download_url(value: &str) -> bool {
    stable_source_url(value)
        && value
            .rsplit('/')
            .next()
            .is_some_and(|filename| filename.to_ascii_lowercase().ends_with(".zip"))
}

fn stable_evidence_url(value: &str) -> bool {
    let Some(identifier) = value.strip_prefix("https://lific.mjc.lol/GULI/pages/") else {
        return false;
    };
    !identifier.is_empty()
        && identifier != "0"
        && !identifier.starts_with('0')
        && identifier.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_percent_escapes(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let Some(high) = bytes.next() else {
                return false;
            };
            let Some(low) = bytes.next() else {
                return false;
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }
            let decoded = (hex_value(high) << 4) | hex_value(low);
            if decoded.is_ascii_control() || decoded == b'/' || decoded == b'\\' || decoded == b'.'
            {
                return false;
            }
        }
    }
    true
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = include_str!("../../../catalog/official.json");

    fn one_entry() -> String {
        serde_json::json!({
            "schema_version": 1,
            "entries": [{
                "product": "kk3-max", "component": "main", "version": "5.9",
                "archive": "x.zip", "archive_size": 40,
                "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "member": "dir/x.bin", "member_size": 50,
                "member_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "payload_size": 50,
                "payload_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "source_url": "https://www.gulikit.com/newsinfo/887152.html",
                "parser_id": "kk3_main_binary_v1", "software_support": "supported",
                "hardware_acceptance": "unqualified",
                "hardware_evidence": null
            }]
        }).to_string()
    }

    fn mutate_first_entry(field: &str, value: serde_json::Value) -> String {
        let mut fixture: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        fixture["entries"][0][field] = value;
        fixture.to_string()
    }

    fn fixture_with_duplicate() -> String {
        let mut fixture: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        let duplicate = fixture["entries"][0].clone();
        fixture["entries"]
            .as_array_mut()
            .expect("entries array")
            .push(duplicate);
        fixture.to_string()
    }

    #[test]
    fn rejects_unknown_schema_fields_and_versions() {
        assert!(matches!(
            Catalog::parse(br#"{"schema_version":2,"entries":[]}"#),
            Err(CatalogError::UnknownSchema(2))
        ));
        let other_product = mutate_first_entry("product", serde_json::json!("future-controller"));
        assert!(Catalog::parse(other_product.as_bytes()).is_err());
        let future_metadata = {
            let mut fixture: serde_json::Value =
                serde_json::from_str(&one_entry()).expect("fixture JSON");
            fixture["entries"][0]["product"] = serde_json::json!("future-controller");
            fixture["entries"][0]["parser_id"] = serde_json::json!("none");
            fixture["entries"][0]["software_support"] = serde_json::json!("metadata_only");
            fixture.to_string()
        };
        assert!(Catalog::parse(future_metadata.as_bytes()).is_ok());
        assert!(matches!(
            Catalog::parse(br#"{"schema_version":1,"entries":[],"extra":true}"#),
            Err(CatalogError::Json(_))
        ));
        let bad_version = mutate_first_entry("version", serde_json::json!("5"));
        assert!(matches!(
            Catalog::parse(bad_version.as_bytes()),
            Err(CatalogError::InvalidField {
                field: "version",
                ..
            })
        ));
        let mut unknown_entry: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        unknown_entry["entries"][0]["surprise"] = serde_json::json!(true);
        let unknown_entry_field = unknown_entry.to_string();
        assert!(matches!(
            Catalog::parse(unknown_entry_field.as_bytes()),
            Err(CatalogError::Json(_))
        ));
        for noncanonical in [
            mutate_first_entry("version", serde_json::json!("05.9")),
            mutate_first_entry("version", serde_json::json!("5.09")),
        ] {
            assert!(Catalog::parse(noncanonical.as_bytes()).is_err());
        }
        let unknown_parser = mutate_first_entry("parser_id", serde_json::json!("future_parser_v9"));
        assert!(matches!(
            Catalog::parse(unknown_parser.as_bytes()),
            Err(CatalogError::InvalidField {
                field: "parser_id",
                ..
            })
        ));
        let inconsistent = mutate_first_entry("software_support", serde_json::json!("unknown"));
        assert!(Catalog::parse(inconsistent.as_bytes()).is_err());
        let mut incoherent: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        incoherent["entries"][0]["software_support"] = serde_json::json!("metadata_only");
        incoherent["entries"][0]["hardware_acceptance"] = serde_json::json!("qualified");
        incoherent["entries"][0]["hardware_evidence"] = serde_json::json!({
            "model_label":"NS39", "scope":"one device and tested pair",
            "evidence_url":"https://lific.mjc.lol/GULI/pages/252"
        });
        let incoherent = incoherent.to_string();
        assert!(matches!(
            Catalog::parse(incoherent.as_bytes()),
            Err(CatalogError::InvalidField {
                field: "hardware_acceptance",
                ..
            })
        ));
    }

    #[test]
    fn rejects_duplicate_identity_hash_size_and_url_failures() {
        let duplicate = fixture_with_duplicate();
        assert!(matches!(
            Catalog::parse(duplicate.as_bytes()),
            Err(CatalogError::DuplicateIdentity { .. })
        ));
        for bad in [
            mutate_first_entry("archive_sha256", serde_json::json!("z".repeat(64))),
            mutate_first_entry("archive_size", serde_json::json!(0)),
            mutate_first_entry(
                "source_url",
                serde_json::json!("http://gulikit.com/newsinfo/1"),
            ),
            mutate_first_entry("member", serde_json::json!("../x.bin")),
            mutate_first_entry("member", serde_json::json!("dir/./x.bin")),
            mutate_first_entry("member", serde_json::json!("dir/../x.bin")),
            mutate_first_entry(
                "source_url",
                serde_json::json!("https://gulikit.com/newsinfo/bad%2.html"),
            ),
            mutate_first_entry("archive", serde_json::json!("bad.")),
            mutate_first_entry("archive", serde_json::json!("bad ")),
            mutate_first_entry("archive", serde_json::json!("bad:device.zip")),
            mutate_first_entry("archive", serde_json::json!(".")),
            mutate_first_entry("archive", serde_json::json!("..")),
            mutate_first_entry("member", serde_json::json!("C:/firmware.bin")),
            mutate_first_entry("member", serde_json::json!("dir./firmware.bin")),
            mutate_first_entry("member", serde_json::json!("bad\u{0001}.bin")),
            mutate_first_entry("member", serde_json::json!("bad\u{0000}.bin")),
        ] {
            assert!(Catalog::parse(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn compressed_archives_may_be_smaller_than_payload_and_bt_version_is_bounded() {
        let compressed = one_entry();
        let parsed = Catalog::parse(compressed.as_bytes()).expect("compressed archive metadata");
        let entry = &parsed.entries()[0];
        assert!(entry.archive_size() < entry.payload_size());

        let mut bluetooth: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        bluetooth["entries"][0]["component"] = serde_json::json!("bluetooth");
        bluetooth["entries"][0]["parser_id"] = serde_json::json!("kk3_bluetooth_pe_v1");
        for (version, expected) in [("655.35", true), ("655.36", false), ("03.23", false)] {
            bluetooth["entries"][0]["version"] = serde_json::json!(version);
            let encoded = bluetooth.to_string();
            assert_eq!(
                Catalog::parse(encoded.as_bytes()).is_ok(),
                expected,
                "version {version}"
            );
        }
    }

    #[test]
    fn hardware_qualification_requires_scoped_canonical_evidence() {
        let qualification = serde_json::json!({
            "model_label": "NS39",
            "scope": "Single controller tested across the release pair",
            "evidence_url": "https://lific.mjc.lol/GULI/pages/252"
        });
        let qualified = mutate_first_entry("hardware_acceptance", serde_json::json!("qualified"));
        let mut qualified: serde_json::Value =
            serde_json::from_str(&qualified).expect("fixture JSON");
        qualified["entries"][0]["hardware_evidence"] = qualification.clone();
        assert!(Catalog::parse(qualified.to_string().as_bytes()).is_ok());

        for invalid_evidence in [
            serde_json::Value::Null,
            serde_json::json!({"model_label":"NS39", "scope":"test", "evidence_url":"https://example.com/252"}),
            serde_json::json!({"model_label":"NS39", "scope":"test", "evidence_url":"https://lific.mjc.lol/GULI/pages/0252"}),
        ] {
            let mut invalid: serde_json::Value =
                serde_json::from_str(&qualified.to_string()).expect("fixture JSON");
            invalid["entries"][0]["hardware_evidence"] = invalid_evidence;
            assert!(Catalog::parse(invalid.to_string().as_bytes()).is_err());
        }

        let mut unqualified: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        unqualified["entries"][0]["hardware_evidence"] = qualification;
        assert!(Catalog::parse(unqualified.to_string().as_bytes()).is_err());
    }

    #[test]
    fn parses_four_reviewed_seed_records() {
        let catalog = Catalog::parse(SEED.as_bytes()).expect("seed catalog is valid");
        assert_eq!(catalog.entries().len(), 4);
        let output = serde_json::to_vec(&catalog).expect("catalog serializes");
        assert_eq!(
            Catalog::parse(&output).expect("serialized catalog parses"),
            catalog
        );
        assert_eq!(catalog.schema_version(), 1);
        assert_eq!(catalog.entries().len(), 4);
    }

    #[test]
    fn seed_main_record_matches_reviewed_release() {
        let catalog = Catalog::parse(SEED.as_bytes()).expect("seed catalog is valid");
        let main = catalog
            .entries()
            .iter()
            .find(|entry| entry.component() == "main")
            .expect("main record");
        assert_eq!(main.version(), "5.9");
        assert_eq!(main.archive(), "KK3_NS38_NS39_V5.9.zip");
        assert_eq!(main.archive_size(), 107_606);
        assert_eq!(
            main.archive_sha256().as_str(),
            "b4d3c74bc2b0f6570523f121d7d8feb8842f239bdfc5e87bffd7af6aee520b67"
        );
        assert_eq!(main.member(), "NS39_KK3_MAX_V5.9.bin");
        assert_eq!(main.member_size(), 51_500);
        assert_eq!(
            main.member_sha256().as_str(),
            "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4"
        );
        assert_eq!(main.payload_size(), 51_500);
        assert_eq!(
            main.payload_sha256().as_str(),
            "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4"
        );
        assert_eq!(
            main.source_url(),
            "https://www.gulikit.com/newsinfo/887152.html"
        );
        assert_eq!(main.parser_id(), ParserId::Kk3MainBinaryV1);
        assert_eq!(main.hardware_acceptance(), HardwareAcceptance::Unqualified);
        assert!(main.hardware_evidence().is_none());
    }

    #[test]
    fn parses_one_entry_with_catalog_validation_and_bounds() {
        let input: serde_json::Value = serde_json::from_str(&one_entry()).unwrap();
        let entry = Entry::parse(&serde_json::to_vec(&input["entries"][0]).unwrap())
            .expect("one valid entry");
        assert_eq!(entry.product(), "kk3-max");
        assert_eq!(entry.component(), "main");
        assert_eq!(
            Entry::parse(&serde_json::to_vec(&entry).expect("entry serializes"))
                .expect("serialized entry parses"),
            entry
        );
        assert!(matches!(
            Entry::parse(&vec![b' '; MAX_ENTRY_BYTES + 1]),
            Err(CatalogError::EntryInputTooLarge)
        ));
        assert!(Entry::parse(br#"{"product":"kk3-max"}"#).is_err());
    }

    #[test]
    fn optional_download_metadata_is_backward_compatible_and_validated() {
        let legacy = Catalog::parse(SEED.as_bytes()).expect("legacy seed parses");
        let legacy_entry = &legacy.entries()[0];
        assert_eq!(legacy_entry.download_url(), None);
        assert_eq!(legacy_entry.availability(), DownloadAvailability::Unknown);
        assert_eq!(legacy_entry.changelog_url(), None);
        let serialized = serde_json::to_value(legacy_entry).unwrap();
        assert!(serialized.get("download_url").is_none());
        assert!(serialized.get("availability").is_none());
        assert!(serialized.get("changelog_url").is_none());

        let mut raw: serde_json::Value = serde_json::from_str(&one_entry()).unwrap();
        raw["entries"][0]["download_url"] = "https://www.gulikit.com/download/firmware.zip".into();
        raw["entries"][0]["availability"] = "available".into();
        raw["entries"][0]["changelog_url"] = "https://www.gulikit.com/newsinfo/887152.html".into();
        let catalog = Catalog::parse(raw.to_string().as_bytes()).unwrap();
        let entry = &catalog.entries()[0];
        assert_eq!(
            entry.download_url(),
            Some("https://www.gulikit.com/download/firmware.zip")
        );
        assert_eq!(entry.availability(), DownloadAvailability::Available);
        assert_eq!(
            entry.changelog_url(),
            Some("https://www.gulikit.com/newsinfo/887152.html")
        );
        let one_entry_catalog =
            Catalog::parse(&serde_json::to_vec(&Catalog::from_entry(entry.clone())).unwrap())
                .unwrap();
        assert_eq!(one_entry_catalog.entries(), std::slice::from_ref(entry));

        for (field, value) in [
            (
                "download_url",
                "http://www.gulikit.com/download/firmware.zip",
            ),
            (
                "download_url",
                "https://www.gulikit.com/download/firmware.exe",
            ),
            (
                "download_url",
                "https://www.gulikit.com/download/fw.zip?token=temporary",
            ),
            ("changelog_url", "https://example.com/release"),
        ] {
            let mut invalid = raw.clone();
            invalid["entries"][0][field] = value.into();
            assert!(Catalog::parse(invalid.to_string().as_bytes()).is_err());
        }
    }

    #[test]
    fn catalog_entries_round_trip_within_shared_serialized_entry_bound() {
        let mut raw: serde_json::Value = serde_json::from_str(&one_entry()).unwrap();
        let base_entry = Entry::parse(
            &serde_json::to_vec(&raw["entries"][0]).expect("fixture entry serializes"),
        )
        .expect("fixture entry parses");
        let base_size = serde_json::to_vec(&base_entry).unwrap().len();
        let base_url = raw["entries"][0]["source_url"].as_str().unwrap().to_owned();
        let url_padding = MAX_ENTRY_BYTES - base_size;
        raw["entries"][0]["source_url"] = format!("{base_url}{}", "a".repeat(url_padding)).into();
        let boundary_catalog = serde_json::to_vec(&raw).unwrap();
        let catalog = Catalog::parse(&boundary_catalog).expect("entry at limit parses");
        let serialized_entry = serde_json::to_vec(&catalog.entries()[0]).unwrap();
        assert_eq!(serialized_entry.len(), MAX_ENTRY_BYTES);
        assert_eq!(
            Entry::parse(&serialized_entry).expect("boundary entry reparses"),
            catalog.entries()[0]
        );

        raw["entries"][0]["source_url"] =
            format!("{base_url}{}", "a".repeat(url_padding + 1)).into();
        assert!(matches!(
            Catalog::parse(&serde_json::to_vec(&raw).unwrap()),
            Err(CatalogError::EntryInputTooLarge)
        ));
    }

    #[test]
    fn seed_bluetooth_records_mark_parser_and_hardware_acceptance() {
        let catalog = Catalog::parse(SEED.as_bytes()).expect("seed catalog is valid");
        let bluetooth_entries = catalog
            .entries()
            .iter()
            .filter(|entry| entry.component() == "bluetooth");
        assert_eq!(bluetooth_entries.clone().count(), 3);
        for entry in bluetooth_entries {
            assert_eq!(entry.parser_id(), ParserId::Kk3BluetoothPeV1);
            assert_eq!(entry.software_support(), SoftwareSupport::Supported);
        }
        assert_eq!(
            hardware_for(&catalog, "3.23"),
            HardwareAcceptance::Qualified
        );
        assert_eq!(
            hardware_for(&catalog, "3.24"),
            HardwareAcceptance::Qualified
        );
        assert_eq!(
            hardware_for(&catalog, "5.07"),
            HardwareAcceptance::Unqualified
        );
        let evidence = catalog
            .entries()
            .iter()
            .find(|entry| entry.version() == "3.23")
            .and_then(Entry::hardware_evidence)
            .expect("qualification scope evidence");
        assert_eq!(evidence.model_label(), "NS39");
        assert_eq!(
            evidence.scope(),
            "Single KK3 Max NS39; Bluetooth 3.23 -> 3.24 -> 3.23 with fresh version readbacks"
        );
        assert_eq!(
            evidence.evidence_url(),
            "https://lific.mjc.lol/GULI/pages/252"
        );
    }

    fn hardware_for(catalog: &Catalog, version: &str) -> HardwareAcceptance {
        catalog
            .entries()
            .iter()
            .find(|entry| entry.component() == "bluetooth" && entry.version() == version)
            .expect("Bluetooth seed version")
            .hardware_acceptance()
    }

    #[test]
    fn enforces_input_and_entry_count_bounds() {
        assert!(matches!(
            Catalog::parse(&vec![b' '; MAX_CATALOG_BYTES + 1]),
            Err(CatalogError::InputTooLarge)
        ));
        let mut fixture: serde_json::Value =
            serde_json::from_str(&one_entry()).expect("fixture JSON");
        let entry = fixture["entries"][0].clone();
        fixture["entries"] = serde_json::json!(vec![entry; MAX_ENTRIES + 1]);
        let input = fixture.to_string();
        assert!(matches!(
            Catalog::parse(input.as_bytes()),
            Err(CatalogError::TooManyEntries)
        ));
    }
}
