//! Deterministic metadata comparison and historical-preserving publication helpers.
//!
//! These APIs compare descriptive catalog data and retain release history. They
//! do not authenticate a catalog, validate a publisher signature, or authorize
//! installation.

use crate::{Catalog, CatalogError, Entry, MAX_ENTRIES};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable product/component/version key for one catalog record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ReleaseIdentity {
    product: String,
    component: String,
    version: String,
}

impl ReleaseIdentity {
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

    fn for_entry(entry: &Entry) -> Self {
        Self {
            product: entry.product.clone(),
            component: entry.component.clone(),
            version: entry.version.clone(),
        }
    }
}

/// A catalog field whose value changed for an unchanged release identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryField {
    Archive,
    ArchiveSize,
    ArchiveSha256,
    Member,
    MemberSize,
    MemberSha256,
    PayloadSize,
    PayloadSha256,
    SourceUrl,
    DownloadUrl,
    Availability,
    ChangelogUrl,
    ParserId,
    SoftwareSupport,
    HardwareAcceptance,
    HardwareEvidence,
    VendorVerification,
}

/// A changed field with its previous and proposed JSON values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldChange {
    field: EntryField,
    previous: Value,
    proposed: Value,
}

impl FieldChange {
    #[must_use]
    pub fn field(&self) -> EntryField {
        self.field
    }

    #[must_use]
    pub fn previous(&self) -> &Value {
        &self.previous
    }

    #[must_use]
    pub fn proposed(&self) -> &Value {
        &self.proposed
    }
}

/// Field-level changes for one unchanged release identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReleaseChange {
    identity: ReleaseIdentity,
    fields: Vec<FieldChange>,
}

impl ReleaseChange {
    #[must_use]
    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }

    #[must_use]
    pub fn fields(&self) -> &[FieldChange] {
        &self.fields
    }
}

/// Added, changed, and removed identities, each sorted lexicographically.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CatalogDiff {
    added: Vec<ReleaseIdentity>,
    changed: Vec<ReleaseChange>,
    removed: Vec<ReleaseIdentity>,
}

impl CatalogDiff {
    #[must_use]
    pub fn added(&self) -> &[ReleaseIdentity] {
        &self.added
    }

    #[must_use]
    pub fn changed(&self) -> &[ReleaseChange] {
        &self.changed
    }

    #[must_use]
    pub fn removed(&self) -> &[ReleaseIdentity] {
        &self.removed
    }
}

impl Catalog {
    /// Compare catalogs independent of their entry storage order.
    #[must_use]
    pub fn diff(&self, proposed: &Self) -> CatalogDiff {
        let previous = entries_by_identity(self);
        let proposed_entries = entries_by_identity(proposed);
        let added = proposed_entries
            .keys()
            .filter(|identity| !previous.contains_key(*identity))
            .cloned()
            .collect();
        let removed = previous
            .keys()
            .filter(|identity| !proposed_entries.contains_key(*identity))
            .cloned()
            .collect();
        let changed = previous
            .iter()
            .filter_map(|(identity, previous_entry)| {
                let proposed_entry = proposed_entries.get(identity)?;
                let fields = changed_fields(previous_entry, proposed_entry);
                (!fields.is_empty()).then(|| ReleaseChange {
                    identity: identity.clone(),
                    fields,
                })
            })
            .collect();
        CatalogDiff {
            added,
            changed,
            removed,
        }
    }

    /// Insert or replace a validated entry while preserving all other history and order.
    ///
    /// Entries with the same identity may update descriptive and verification
    /// metadata, but their archive/member/payload identity and parser cannot change.
    /// The returned catalog is reparsed to enforce the serialized size and entry
    /// bounds. Metadata remains untrusted; this does not authenticate publication.
    ///
    /// # Errors
    /// Returns an error when immutable package metadata differs, the catalog
    /// bounds would be exceeded, or serialized metadata cannot be reparsed.
    pub fn upsert(&self, entry: Entry) -> Result<Self, CatalogError> {
        let identity = ReleaseIdentity::for_entry(&entry);
        let mut entries = self.entries.clone();
        if let Some(index) = entries
            .iter()
            .position(|existing| ReleaseIdentity::for_entry(existing) == identity)
        {
            let existing = &entries[index];
            if let Some(field) = immutable_metadata_difference(existing, &entry) {
                return Err(CatalogError::ImmutableMetadataChanged {
                    product: identity.product,
                    component: identity.component,
                    version: identity.version,
                    field,
                });
            }
            entries[index] = entry;
        } else {
            if entries.len() >= MAX_ENTRIES {
                return Err(CatalogError::TooManyEntries);
            }
            entries.push(entry);
        }
        let candidate = Self {
            schema_version: self.schema_version,
            entries,
        };
        let bytes = serde_json::to_vec(&candidate)
            .map_err(|error| CatalogError::Json(error.to_string()))?;
        Self::parse(&bytes)
    }
}

fn entries_by_identity(catalog: &Catalog) -> BTreeMap<ReleaseIdentity, &Entry> {
    catalog
        .entries
        .iter()
        .map(|entry| (ReleaseIdentity::for_entry(entry), entry))
        .collect()
}

fn changed_fields(previous: &Entry, proposed: &Entry) -> Vec<FieldChange> {
    [
        (EntryField::Archive, previous.archive != proposed.archive),
        (
            EntryField::ArchiveSize,
            previous.archive_size != proposed.archive_size,
        ),
        (
            EntryField::ArchiveSha256,
            previous.archive_sha256 != proposed.archive_sha256,
        ),
        (EntryField::Member, previous.member != proposed.member),
        (
            EntryField::MemberSize,
            previous.member_size != proposed.member_size,
        ),
        (
            EntryField::MemberSha256,
            previous.member_sha256 != proposed.member_sha256,
        ),
        (
            EntryField::PayloadSize,
            previous.payload_size != proposed.payload_size,
        ),
        (
            EntryField::PayloadSha256,
            previous.payload_sha256 != proposed.payload_sha256,
        ),
        (
            EntryField::SourceUrl,
            previous.source_url != proposed.source_url,
        ),
        (
            EntryField::DownloadUrl,
            previous.download_url != proposed.download_url,
        ),
        (
            EntryField::Availability,
            previous.availability != proposed.availability,
        ),
        (
            EntryField::ChangelogUrl,
            previous.changelog_url != proposed.changelog_url,
        ),
        (
            EntryField::ParserId,
            previous.parser_id != proposed.parser_id,
        ),
        (
            EntryField::SoftwareSupport,
            previous.software_support != proposed.software_support,
        ),
        (
            EntryField::HardwareAcceptance,
            previous.hardware_acceptance != proposed.hardware_acceptance,
        ),
        (
            EntryField::HardwareEvidence,
            previous.hardware_evidence != proposed.hardware_evidence,
        ),
        (
            EntryField::VendorVerification,
            previous.vendor_verification != proposed.vendor_verification,
        ),
    ]
    .into_iter()
    .filter(|(_, changed)| *changed)
    .map(|(field, _)| FieldChange {
        field,
        previous: field_value(previous, field),
        proposed: field_value(proposed, field),
    })
    .collect()
}

fn field_value(entry: &Entry, field: EntryField) -> Value {
    match field {
        EntryField::Archive => serde_json::json!(&entry.archive),
        EntryField::ArchiveSize => serde_json::json!(entry.archive_size),
        EntryField::ArchiveSha256 => serde_json::json!(entry.archive_sha256.as_str()),
        EntryField::Member => serde_json::json!(&entry.member),
        EntryField::MemberSize => serde_json::json!(entry.member_size),
        EntryField::MemberSha256 => serde_json::json!(entry.member_sha256.as_str()),
        EntryField::PayloadSize => serde_json::json!(entry.payload_size),
        EntryField::PayloadSha256 => serde_json::json!(entry.payload_sha256.as_str()),
        EntryField::SourceUrl => serde_json::json!(&entry.source_url),
        EntryField::DownloadUrl => serde_json::json!(&entry.download_url),
        EntryField::Availability => serde_json::json!(entry.availability),
        EntryField::ChangelogUrl => serde_json::json!(&entry.changelog_url),
        EntryField::ParserId => serde_json::json!(entry.parser_id),
        EntryField::SoftwareSupport => serde_json::json!(entry.software_support),
        EntryField::HardwareAcceptance => serde_json::json!(entry.hardware_acceptance),
        EntryField::HardwareEvidence => serde_json::json!(&entry.hardware_evidence),
        EntryField::VendorVerification => serde_json::json!(&entry.vendor_verification),
    }
}

fn immutable_metadata_difference(previous: &Entry, proposed: &Entry) -> Option<&'static str> {
    if previous.archive != proposed.archive {
        Some("archive")
    } else if previous.archive_size != proposed.archive_size {
        Some("archive_size")
    } else if previous.archive_sha256 != proposed.archive_sha256 {
        Some("archive_sha256")
    } else if previous.member != proposed.member {
        Some("member")
    } else if previous.member_size != proposed.member_size {
        Some("member_size")
    } else if previous.member_sha256 != proposed.member_sha256 {
        Some("member_sha256")
    } else if previous.payload_size != proposed.payload_size {
        Some("payload_size")
    } else if previous.payload_sha256 != proposed.payload_sha256 {
        Some("payload_sha256")
    } else if previous.parser_id != proposed.parser_id {
        Some("parser_id")
    } else {
        None
    }
}
