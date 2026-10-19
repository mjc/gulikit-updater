//! Typed, bounded manifest for original firmware archives.
//!
//! Manifest records describe locally measured bytes. They do not establish
//! vendor authenticity, prove firmware compatibility, or authorize installation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, str::FromStr};
use url::Url;

/// Maximum serialized manifest size.
pub const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of archive records in one manifest.
pub const MAX_RELEASES: usize = 512;
/// Maximum size of a complete original archive.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILENAME_BYTES: usize = 255;
const MAX_VERSION_BYTES: usize = 32;
const MAX_SOURCE_URL_BYTES: usize = 2 * 1024;
const MAX_RELEASED_AT_BYTES: usize = 128;
const MAX_CHANGELOG_BYTES: usize = 4 * 1024;
const MAX_MEMBER_BYTES: usize = 1024;
const MAX_HASH_CLAIMS: usize = 16;
const MAX_HASH_ALGORITHM_BYTES: usize = 64;
const MAX_HASH_VALUE_BYTES: usize = 256;
const HASH_HEX_BYTES: usize = 64;
const DEFAULT_PRODUCT_SLUG: &str = "kk3-max";
const MAX_PRODUCT_SLUG_BYTES: usize = 64;

/// Firmware component represented by this archive record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Component {
    Base,
    Bluetooth,
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Base => "base",
            Self::Bluetooth => "bluetooth",
        })
    }
}

impl FromStr for Component {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "base" => Ok(Self::Base),
            "bluetooth" => Ok(Self::Bluetooth),
            _ => Err(Error::InvalidMetadata("component")),
        }
    }
}

/// How the selected archive member maps to measurable firmware bytes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareMemberKind {
    /// Preserve the existing KK3 Max base BIN and Bluetooth updater PE handling.
    #[default]
    Kk3,
    /// A raw firmware BIN; the member bytes are the payload.
    RawBinary,
    /// An opaque firmware updater EXE; record member bytes without claiming a payload digest.
    OpaqueUpdaterExe,
}

impl FirmwareMemberKind {
    pub(crate) const fn has_measurable_payload(self) -> bool {
        match self {
            Self::OpaqueUpdaterExe => false,
            Self::Kk3 | Self::RawBinary => true,
        }
    }

    pub(crate) fn accepts_member(self, component: Component, member: &str) -> bool {
        let extension = member.rsplit('.').next().unwrap_or_default();
        match (self, component) {
            (Self::Kk3, Component::Base) | (Self::RawBinary, _) => {
                extension.eq_ignore_ascii_case("bin")
            }
            (Self::Kk3, Component::Bluetooth) | (Self::OpaqueUpdaterExe, _) => {
                extension.eq_ignore_ascii_case("exe")
            }
        }
    }
}

fn default_product_slug() -> String {
    DEFAULT_PRODUCT_SLUG.to_owned()
}

fn is_default_product_slug(value: &String) -> bool {
    value == DEFAULT_PRODUCT_SLUG
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde skip_serializing_if predicates receive a reference"
)]
fn is_default_member_kind(value: &FirmwareMemberKind) -> bool {
    *value == FirmwareMemberKind::Kk3
}

/// Reviewer-supplied release details stored with measured artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadata {
    /// Stable product namespace used in the archive path.
    #[serde(
        default = "default_product_slug",
        skip_serializing_if = "is_default_product_slug"
    )]
    pub product: String,
    /// Selected member interpretation; omitted records retain historical KK3 behavior.
    #[serde(default, skip_serializing_if = "is_default_member_kind")]
    pub member_kind: FirmwareMemberKind,
    pub component: Component,
    pub version: String,
    pub filename: String,
    pub source_url: String,
    #[serde(default)]
    pub released_at: Option<String>,
    #[serde(default)]
    pub retrieved_at: Option<String>,
    #[serde(default)]
    pub retrieved_from: Option<String>,
    #[serde(default)]
    pub changelog: Option<String>,
    #[serde(default)]
    pub changelog_source_url: Option<String>,
    /// Required archive member that contains the firmware file.
    pub firmware_member: String,
    /// Source-posted hashes; retained as assertions, not as authenticity proof.
    #[serde(default)]
    pub published_hashes: Vec<PublishedHash>,
}

impl ReleaseMetadata {
    fn validate(&self) -> Result<(), Error> {
        validate_product_slug(&self.product)?;
        let is_kk3_product = self.product == DEFAULT_PRODUCT_SLUG;
        if (self.member_kind == FirmwareMemberKind::Kk3) != is_kk3_product {
            return Err(Error::InvalidMetadata("member_kind"));
        }
        validate_version(&self.version)?;
        validate_filename(&self.filename)?;
        validate_https_url(&self.source_url, "source_url")?;
        if let Some(date) = &self.released_at
            && (date.len() > MAX_RELEASED_AT_BYTES || !valid_calendar_date(date))
        {
            return Err(Error::InvalidMetadata("released_at"));
        }
        if let Some(date) = &self.retrieved_at
            && (date.len() > MAX_RELEASED_AT_BYTES || !valid_utc_timestamp(date))
        {
            return Err(Error::InvalidMetadata("retrieved_at"));
        }
        if let Some(url) = &self.retrieved_from {
            validate_https_url(url, "retrieved_from")?;
        }
        if let Some(changelog) = &self.changelog
            && (changelog.is_empty()
                || changelog.len() > MAX_CHANGELOG_BYTES
                || changelog
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t'))
        {
            return Err(Error::InvalidMetadata("changelog"));
        }
        if let Some(url) = &self.changelog_source_url {
            validate_https_url(url, "changelog_source_url")?;
        }
        validate_member(&self.firmware_member)?;
        if !self
            .member_kind
            .accepts_member(self.component, &self.firmware_member)
        {
            return Err(Error::InvalidMetadata("firmware_member"));
        }
        if self.published_hashes.len() > MAX_HASH_CLAIMS {
            return Err(Error::InvalidMetadata("published_hashes"));
        }
        for claim in &self.published_hashes {
            claim.validate()?;
        }
        Ok(())
    }
}

/// Locally measured size and SHA-256 for one firmware artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDigest {
    pub size: u64,
    pub sha256: String,
}

/// Artifact a published checksum describes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashTarget {
    Zip,
    FirmwareFile,
    Payload,
}

/// Source-reported checksum, retained as descriptive provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedHash {
    pub target: HashTarget,
    pub algorithm: String,
    pub value: String,
    pub source_url: String,
}

impl PublishedHash {
    fn validate(&self) -> Result<(), Error> {
        validate_text(
            &self.algorithm,
            MAX_HASH_ALGORITHM_BYTES,
            "published_hashes.algorithm",
        )?;
        validate_text(&self.value, MAX_HASH_VALUE_BYTES, "published_hashes.value")?;
        validate_https_url(&self.source_url, "published_hashes.source_url")?;
        Ok(())
    }
}

/// Failure while parsing or validating a firmware manifest record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InputTooLarge,
    OutputTooLarge,
    Json(String),
    UnsupportedSchema(u32),
    TooManyReleases,
    ArchiveEmpty,
    ArchiveTooLarge,
    InvalidMetadata(&'static str),
    InvalidHash,
    PathMismatch,
    DuplicatePath,
    ArchiveSizeMismatch,
    ArchiveHashMismatch,
    FirmwareFileSizeMismatch,
    FirmwareFileHashMismatch,
    PayloadSizeMismatch,
    PayloadHashMismatch,
    PublishedHashMismatch,
    InvalidArchive,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("manifest exceeds the input size limit"),
            Self::OutputTooLarge => f.write_str("manifest exceeds the output size limit"),
            Self::Json(error) => write!(f, "invalid manifest JSON: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported manifest schema version {version}")
            }
            Self::TooManyReleases => f.write_str("manifest contains too many releases"),
            Self::ArchiveEmpty => f.write_str("firmware archive is empty"),
            Self::ArchiveTooLarge => f.write_str("firmware archive exceeds the size limit"),
            Self::InvalidMetadata(field) => write!(f, "invalid release metadata field {field}"),
            Self::InvalidHash => f.write_str("archive SHA-256 must be 64 lowercase hex digits"),
            Self::PathMismatch => f.write_str("archive path does not match release metadata"),
            Self::DuplicatePath => f.write_str("manifest contains a duplicate archive path"),
            Self::ArchiveSizeMismatch => f.write_str("archive size does not match manifest"),
            Self::ArchiveHashMismatch => f.write_str("archive SHA-256 does not match manifest"),
            Self::FirmwareFileSizeMismatch => {
                f.write_str("firmware-file size does not match manifest")
            }
            Self::FirmwareFileHashMismatch => {
                f.write_str("firmware-file SHA-256 does not match manifest")
            }
            Self::PayloadSizeMismatch => f.write_str("payload size does not match manifest"),
            Self::PayloadHashMismatch => f.write_str("payload SHA-256 does not match manifest"),
            Self::PublishedHashMismatch => {
                f.write_str("published SHA-256 does not match measured content")
            }
            Self::InvalidArchive => f.write_str("firmware ZIP is invalid or exceeds safety limits"),
        }
    }
}

impl std::error::Error for Error {}

/// One release entry with private, measured archive identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRecord {
    metadata: ReleaseMetadata,
    path: String,
    zip: ContentDigest,
    firmware_file: ContentDigest,
    payload: Option<ContentDigest>,
}

impl ReleaseRecord {
    /// Measure an original archive, extracted firmware file, and payload bytes.
    ///
    /// For base releases, pass the same firmware-file bytes as the payload bytes.
    /// For Bluetooth releases, pass the extracted PE file and its embedded payload
    /// separately.
    ///
    /// # Errors
    /// Rejects empty/oversized bytes, invalid metadata, and mismatched published SHA-256 claims.
    pub fn measure(
        metadata: ReleaseMetadata,
        archive_bytes: &[u8],
        firmware_file_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<Self, Error> {
        Self::measure_optional(
            metadata,
            archive_bytes,
            firmware_file_bytes,
            Some(payload_bytes),
        )
    }

    /// Measure an archive whose selected member may not expose a parsed payload.
    ///
    /// An absent payload is valid only for `OpaqueUpdaterExe`; other member kinds
    /// retain the same file-to-payload measurement contract as the legacy API.
    ///
    /// # Errors
    /// Rejects empty/oversized bytes, invalid metadata, missing or unexpected payloads,
    /// and mismatched published SHA-256 claims.
    pub fn measure_optional(
        metadata: ReleaseMetadata,
        archive_bytes: &[u8],
        firmware_file_bytes: &[u8],
        payload_bytes: Option<&[u8]>,
    ) -> Result<Self, Error> {
        metadata.validate()?;
        validate_archive_size(archive_bytes.len())?;
        validate_content_size(firmware_file_bytes.len())?;
        if metadata.member_kind.has_measurable_payload() != payload_bytes.is_some() {
            return Err(Error::InvalidMetadata("member_kind"));
        }
        if let Some(payload) = payload_bytes {
            validate_content_size(payload.len())?;
        }
        let path = canonical_path(&metadata);
        let zip = content_digest(archive_bytes)?;
        let firmware_file = content_digest(firmware_file_bytes)?;
        let payload = payload_bytes.map(content_digest).transpose()?;
        let record = Self {
            metadata,
            path,
            zip,
            firmware_file,
            payload,
        };
        record.validate_published_hashes()?;
        Ok(record)
    }

    /// Release component.
    #[must_use]
    pub const fn component(&self) -> Component {
        self.metadata.component
    }

    /// Vendor release version, preserved as written.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.metadata.version
    }

    /// Canonical orphan-branch path, including its leading slash.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Original archive filename.
    #[must_use]
    pub fn filename(&self) -> &str {
        &self.metadata.filename
    }

    /// Complete archive length in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.zip.size
    }

    /// Lowercase SHA-256 of the complete archive.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.zip.sha256
    }

    /// Measured firmware-file content.
    #[must_use]
    pub const fn firmware_file(&self) -> &ContentDigest {
        &self.firmware_file
    }

    /// Measured embedded payload content.
    #[must_use]
    pub const fn payload(&self) -> Option<&ContentDigest> {
        self.payload.as_ref()
    }

    /// Release details supplied by the maintainer.
    #[must_use]
    pub const fn metadata(&self) -> &ReleaseMetadata {
        &self.metadata
    }

    /// Verify the archive, extracted firmware file, and payload against measured digests.
    ///
    /// # Errors
    /// Returns the first size or digest mismatch.
    pub fn verify(
        &self,
        archive_bytes: &[u8],
        firmware_file_bytes: &[u8],
        payload_bytes: &[u8],
    ) -> Result<(), Error> {
        self.verify_optional(archive_bytes, firmware_file_bytes, Some(payload_bytes))
    }

    /// Verify the archive and selected member, plus an optional parsed payload.
    ///
    /// # Errors
    /// Returns the first size or digest mismatch.
    pub fn verify_optional(
        &self,
        archive_bytes: &[u8],
        firmware_file_bytes: &[u8],
        payload_bytes: Option<&[u8]>,
    ) -> Result<(), Error> {
        if u64::try_from(archive_bytes.len()).ok() != Some(self.zip.size) {
            return Err(Error::ArchiveSizeMismatch);
        }
        if hex::encode(Sha256::digest(archive_bytes)) != self.zip.sha256 {
            return Err(Error::ArchiveHashMismatch);
        }
        verify_content(
            &self.firmware_file,
            firmware_file_bytes,
            Error::FirmwareFileSizeMismatch,
            Error::FirmwareFileHashMismatch,
        )?;
        match (&self.payload, payload_bytes) {
            (Some(expected), Some(bytes)) => verify_content(
                expected,
                bytes,
                Error::PayloadSizeMismatch,
                Error::PayloadHashMismatch,
            )?,
            (None, None) => {}
            _ => return Err(Error::PayloadSizeMismatch),
        }
        Ok(())
    }

    /// Verify a complete ZIP archive, its selected firmware member, and measured payload.
    ///
    /// # Errors
    /// Returns an error if the ZIP is malformed, its selected member is unsafe,
    /// or any measured size or digest differs from this record.
    pub fn verify_archive_bytes(&self, archive_bytes: &[u8]) -> Result<(), Error> {
        if archive_bytes.is_empty() || archive_bytes.len() > MAX_ARCHIVE_BYTES {
            return Err(if archive_bytes.is_empty() {
                Error::ArchiveEmpty
            } else {
                Error::ArchiveTooLarge
            });
        }
        crate::git::validate_zip(archive_bytes).map_err(|_| Error::InvalidArchive)?;
        let (firmware_file, payload) =
            crate::content::firmware_bytes(&self.metadata, archive_bytes)
                .map_err(|_| Error::InvalidArchive)?;
        self.verify_optional(archive_bytes, &firmware_file, payload.as_deref())
    }

    fn validate_published_hashes(&self) -> Result<(), Error> {
        for claim in &self.metadata.published_hashes {
            if is_sha256_algorithm(&claim.algorithm)
                && !claim_matches(claim, &self.zip, &self.firmware_file, self.payload.as_ref())
            {
                return Err(Error::PublishedHashMismatch);
            }
        }
        Ok(())
    }
}

/// Ordered set of measured original firmware archives.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirmwareIndex {
    releases: Vec<ReleaseRecord>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawIndex {
    schema_version: u32,
    releases: Vec<RawRelease>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRelease {
    #[serde(
        default = "default_product_slug",
        skip_serializing_if = "is_default_product_slug"
    )]
    product: String,
    #[serde(default, skip_serializing_if = "is_default_member_kind")]
    member_kind: FirmwareMemberKind,
    component: Component,
    version: String,
    filename: String,
    source_url: String,
    #[serde(default)]
    released_at: Option<String>,
    #[serde(default)]
    retrieved_at: Option<String>,
    #[serde(default)]
    retrieved_from: Option<String>,
    #[serde(default)]
    changelog: Option<String>,
    #[serde(default)]
    changelog_source_url: Option<String>,
    firmware_member: String,
    #[serde(default)]
    published_hashes: Vec<PublishedHash>,
    path: String,
    size: u64,
    sha256: String,
    firmware_file: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payload: Option<ContentDigest>,
}

impl RawRelease {
    fn from_record(record: &ReleaseRecord) -> Self {
        Self {
            product: record.metadata.product.clone(),
            member_kind: record.metadata.member_kind,
            component: record.metadata.component,
            version: record.metadata.version.clone(),
            filename: record.metadata.filename.clone(),
            source_url: record.metadata.source_url.clone(),
            released_at: record.metadata.released_at.clone(),
            retrieved_at: record.metadata.retrieved_at.clone(),
            retrieved_from: record.metadata.retrieved_from.clone(),
            changelog: record.metadata.changelog.clone(),
            changelog_source_url: record.metadata.changelog_source_url.clone(),
            firmware_member: record.metadata.firmware_member.clone(),
            published_hashes: record.metadata.published_hashes.clone(),
            path: record.path.clone(),
            size: record.zip.size,
            sha256: record.zip.sha256.clone(),
            firmware_file: record.firmware_file.clone(),
            payload: record.payload.clone(),
        }
    }

    fn into_record(self) -> Result<ReleaseRecord, Error> {
        let metadata = ReleaseMetadata {
            product: self.product,
            member_kind: self.member_kind,
            component: self.component,
            version: self.version,
            filename: self.filename,
            source_url: self.source_url,
            released_at: self.released_at,
            retrieved_at: self.retrieved_at,
            retrieved_from: self.retrieved_from,
            changelog: self.changelog,
            changelog_source_url: self.changelog_source_url,
            firmware_member: self.firmware_member,
            published_hashes: self.published_hashes,
        };
        metadata.validate()?;
        let expected_path = canonical_path(&metadata);
        if self.path != expected_path {
            return Err(Error::PathMismatch);
        }
        validate_hash(&self.sha256)?;
        let zip = ContentDigest {
            size: self.size,
            sha256: self.sha256,
        };
        validate_content_digest(&zip)?;
        validate_content_digest(&self.firmware_file)?;
        if metadata.member_kind.has_measurable_payload() != self.payload.is_some() {
            return Err(Error::InvalidMetadata("member_kind"));
        }
        if let Some(payload) = &self.payload {
            validate_content_digest(payload)?;
        }
        let record = ReleaseRecord {
            metadata,
            path: expected_path,
            zip,
            firmware_file: self.firmware_file,
            payload: self.payload,
        };
        record.validate_published_hashes()?;
        Ok(record)
    }
}

impl FirmwareIndex {
    /// Create an empty manifest index.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            releases: Vec::new(),
        }
    }

    /// Parse and validate a bounded version-1 JSON manifest.
    ///
    /// # Errors
    /// Rejects oversized input, unsupported schema, unknown/duplicate JSON
    /// fields, invalid records, and duplicate identities or paths.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(Error::InputTooLarge);
        }
        let raw: RawIndex =
            serde_json::from_slice(bytes).map_err(|error| Error::Json(error.to_string()))?;
        if raw.schema_version != 1 {
            return Err(Error::UnsupportedSchema(raw.schema_version));
        }
        if raw.releases.len() > MAX_RELEASES {
            return Err(Error::TooManyReleases);
        }
        let mut index = Self::empty();
        let mut paths = HashSet::with_capacity(raw.releases.len());
        for raw_release in raw.releases {
            let release = raw_release.into_record()?;
            if !paths.insert(release.path().to_owned()) {
                return Err(Error::DuplicatePath);
            }
            index.releases.push(release);
        }
        if index.serialized_len()? > MAX_INDEX_BYTES {
            return Err(Error::OutputTooLarge);
        }
        Ok(index)
    }

    /// Add one measured archive while retaining insertion order.
    ///
    /// # Errors
    /// Rejects duplicate paths, count overflow, or serialized size overflow.
    pub fn add(&mut self, release: ReleaseRecord) -> Result<(), Error> {
        if self.releases.len() >= MAX_RELEASES {
            return Err(Error::TooManyReleases);
        }
        if self
            .releases
            .iter()
            .any(|existing| existing.path() == release.path())
        {
            return Err(Error::DuplicatePath);
        }
        self.releases.push(release);
        match self.serialized_len() {
            Ok(size) if size <= MAX_INDEX_BYTES => Ok(()),
            Ok(_) => {
                self.releases.pop();
                Err(Error::OutputTooLarge)
            }
            Err(error) => {
                self.releases.pop();
                Err(error)
            }
        }
    }

    /// Ordered release records.
    #[must_use]
    pub fn releases(&self) -> &[ReleaseRecord] {
        &self.releases
    }

    /// Find an archive by its canonical path, including the original filename.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<&ReleaseRecord> {
        self.releases.iter().find(|record| record.path() == path)
    }

    /// Serialize this index as bounded version-1 JSON.
    ///
    /// # Errors
    /// Returns an output size or JSON serialization failure.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        let raw = RawIndex {
            schema_version: 1,
            releases: self.releases.iter().map(RawRelease::from_record).collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&raw).map_err(|error| Error::Json(error.to_string()))?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(Error::OutputTooLarge);
        }
        Ok(bytes)
    }

    fn serialized_len(&self) -> Result<usize, Error> {
        let raw = RawIndex {
            schema_version: 1,
            releases: self.releases.iter().map(RawRelease::from_record).collect(),
        };
        serde_json::to_vec_pretty(&raw)
            .map(|bytes| bytes.len())
            .map_err(|error| Error::Json(error.to_string()))
    }
}

fn validate_archive_size(size: usize) -> Result<(), Error> {
    if size == 0 {
        return Err(Error::ArchiveEmpty);
    }
    if size > MAX_ARCHIVE_BYTES {
        return Err(Error::ArchiveTooLarge);
    }
    Ok(())
}

fn validate_content_size(size: usize) -> Result<(), Error> {
    if size == 0 {
        return Err(Error::ArchiveEmpty);
    }
    if size > MAX_ARCHIVE_BYTES {
        return Err(Error::ArchiveTooLarge);
    }
    Ok(())
}

fn content_digest(bytes: &[u8]) -> Result<ContentDigest, Error> {
    validate_content_size(bytes.len())?;
    let size = u64::try_from(bytes.len()).map_err(|_| Error::ArchiveTooLarge)?;
    Ok(ContentDigest {
        size,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn validate_content_digest(digest: &ContentDigest) -> Result<(), Error> {
    if digest.size == 0 {
        return Err(Error::ArchiveEmpty);
    }
    if digest.size > u64::try_from(MAX_ARCHIVE_BYTES).unwrap_or(u64::MAX) {
        return Err(Error::ArchiveTooLarge);
    }
    validate_hash(&digest.sha256)
}

fn verify_content(
    expected: &ContentDigest,
    bytes: &[u8],
    size_error: Error,
    hash_error: Error,
) -> Result<(), Error> {
    if u64::try_from(bytes.len()).ok() != Some(expected.size) {
        return Err(size_error);
    }
    if hex::encode(Sha256::digest(bytes)) != expected.sha256 {
        return Err(hash_error);
    }
    Ok(())
}

fn is_sha256_algorithm(algorithm: &str) -> bool {
    let algorithm = algorithm.trim();
    algorithm.eq_ignore_ascii_case("sha256") || algorithm.eq_ignore_ascii_case("sha-256")
}

fn claim_matches(
    claim: &PublishedHash,
    zip: &ContentDigest,
    firmware_file: &ContentDigest,
    payload: Option<&ContentDigest>,
) -> bool {
    let digest = match claim.target {
        HashTarget::Zip => Some(zip),
        HashTarget::FirmwareFile => Some(firmware_file),
        HashTarget::Payload => payload,
    };
    digest.is_some_and(|digest| claim.value.trim().eq_ignore_ascii_case(&digest.sha256))
}

fn valid_calendar_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let Some(year) = parse_decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = parse_decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = parse_decimal(&bytes[8..10]) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }
    let days_in_month = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days_in_month).contains(&day)
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || !bytes[..10].is_ascii()
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    if !valid_calendar_date(&value[..10]) {
        return false;
    }
    let Some(hour) = parse_decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = parse_decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = parse_decimal(&bytes[17..19]) else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    if bytes[19] == b'Z' {
        return bytes.len() == 20;
    }
    bytes[19] == b'.'
        && bytes.last() == Some(&b'Z')
        && bytes.len() > 21
        && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)
}

fn parse_decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u32::from(*byte - b'0'))
    })
}

fn validate_version(value: &str) -> Result<(), Error> {
    let valid = !value.is_empty()
        && value.len() <= MAX_VERSION_BYTES
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
                && part.bytes().any(|byte| byte.is_ascii_digit())
        });
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidMetadata("version"))
    }
}

fn validate_product_slug(value: &str) -> Result<(), Error> {
    let valid = !value.is_empty()
        && value.len() <= MAX_PRODUCT_SLUG_BYTES
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidMetadata("product"))
    }
}

fn validate_filename(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > MAX_FILENAME_BYTES
        || !value.to_ascii_lowercase().ends_with(".zip")
        || value.ends_with('.')
        || value.ends_with(' ')
        || value.chars().any(char::is_control)
        || value.chars().any(is_windows_reserved_filename_char)
        || is_windows_device_name(value)
    {
        return Err(Error::InvalidMetadata("filename"));
    }
    Ok(())
}

fn is_windows_device_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1
                    && suffix
                        .bytes()
                        .next()
                        .is_some_and(|digit| (b'1'..=b'9').contains(&digit))
            })
        })
}

fn is_windows_reserved_filename_char(character: char) -> bool {
    character == '<'
        || character == '>'
        || character == ':'
        || character == '"'
        || character == '/'
        || character == '\\'
        || character == '|'
        || character == '?'
        || character == '*'
}

fn validate_member(value: &str) -> Result<(), Error> {
    let safe = !value.is_empty()
        && value.len() <= MAX_MEMBER_BYTES
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.ends_with('/')
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with('.')
                && !is_windows_device_name(part)
                && !part.ends_with(' ')
                && !part.chars().any(char::is_control)
                && !part.chars().any(is_windows_reserved_filename_char)
        });
    if safe {
        Ok(())
    } else {
        Err(Error::InvalidMetadata("firmware_member"))
    }
}

fn validate_https_url(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty() || value.len() > MAX_SOURCE_URL_BYTES || value.chars().any(char::is_control)
    {
        return Err(Error::InvalidMetadata(field));
    }
    let Ok(url) = Url::parse(value) else {
        return Err(Error::InvalidMetadata(field));
    };
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidMetadata(field));
    }
    Ok(())
}

fn validate_text(value: &str, bound: usize, field: &'static str) -> Result<(), Error> {
    if value.is_empty() || value.len() > bound || value.chars().any(char::is_control) {
        return Err(Error::InvalidMetadata(field));
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), Error> {
    if value.len() == HASH_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(Error::InvalidHash)
    }
}

fn canonical_path(metadata: &ReleaseMetadata) -> String {
    format!(
        "/{}/{}/v{}/{}",
        metadata.product, metadata.component, metadata.version, metadata.filename
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> ReleaseMetadata {
        ReleaseMetadata {
            product: DEFAULT_PRODUCT_SLUG.to_owned(),
            member_kind: FirmwareMemberKind::Kk3,
            component: Component::Base,
            version: "5.9".to_owned(),
            filename: "firmware.zip".to_owned(),
            source_url: "https://example.com/release".to_owned(),
            released_at: None,
            retrieved_at: None,
            retrieved_from: None,
            changelog: None,
            changelog_source_url: None,
            firmware_member: "firmware.bin".to_owned(),
            published_hashes: Vec::new(),
        }
    }

    #[test]
    fn omitted_legacy_fields_keep_kk3_path_and_round_trip() {
        let record = ReleaseRecord::measure(
            metadata(),
            b"zip bytes",
            b"firmware bytes",
            b"firmware bytes",
        )
        .unwrap();
        assert_eq!(record.path(), "/kk3-max/base/v5.9/firmware.zip");

        let mut index = FirmwareIndex::empty();
        index.add(record).unwrap();
        let json = index.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let release = &value["releases"][0];
        assert!(release.get("product").is_none());
        assert!(release.get("member_kind").is_none());
        let parsed = FirmwareIndex::parse(&json).unwrap();
        assert_eq!(
            parsed.releases()[0].path(),
            "/kk3-max/base/v5.9/firmware.zip"
        );
        assert!(parsed.releases()[0].payload().is_some());
    }

    #[test]
    fn raw_member_supports_alphanumeric_version_and_product_namespace() {
        let metadata = ReleaseMetadata {
            product: "controller-x".to_owned(),
            member_kind: FirmwareMemberKind::RawBinary,
            version: "00.00.7E.10".to_owned(),
            firmware_member: "nested/board.BIN".to_owned(),
            ..metadata()
        };
        let record =
            ReleaseRecord::measure(metadata, b"zip bytes", b"raw firmware", b"raw firmware")
                .unwrap();
        assert_eq!(
            record.path(),
            "/controller-x/base/v00.00.7E.10/firmware.zip"
        );
    }

    #[test]
    fn opaque_updater_records_file_without_claiming_payload() {
        let metadata = ReleaseMetadata {
            product: "controller-x".to_owned(),
            member_kind: FirmwareMemberKind::OpaqueUpdaterExe,
            firmware_member: "update.exe".to_owned(),
            ..metadata()
        };
        let record =
            ReleaseRecord::measure_optional(metadata.clone(), b"zip bytes", b"updater bytes", None)
                .unwrap();
        assert!(record.payload().is_none());
        record
            .verify_optional(b"zip bytes", b"updater bytes", None)
            .unwrap();
        assert!(
            ReleaseRecord::measure(
                metadata,
                b"zip bytes",
                b"updater bytes",
                b"invented payload",
            )
            .is_err()
        );
    }

    #[test]
    fn opaque_updater_rejects_published_payload_hash_claim() {
        let mut metadata = ReleaseMetadata {
            product: "controller-x".to_owned(),
            member_kind: FirmwareMemberKind::OpaqueUpdaterExe,
            firmware_member: "update.exe".to_owned(),
            ..metadata()
        };
        metadata.published_hashes.push(PublishedHash {
            target: HashTarget::Payload,
            algorithm: "SHA-256".to_owned(),
            value: hex::encode(Sha256::digest(b"updater bytes")),
            source_url: "https://example.com/release".to_owned(),
        });
        assert_eq!(
            ReleaseRecord::measure_optional(metadata, b"zip bytes", b"updater bytes", None)
                .unwrap_err(),
            Error::PublishedHashMismatch
        );
    }
}
