//! Bridge from measured archive records to the updater's existing compiled admission.
//!
//! Historical records may be inspected and downloaded, but this bridge never
//! turns them into write authorization.

use gulikit_archive::{FirmwareMemberKind, ReleaseRecord};
use gulikit_core::package::{Component, Model, PackageInfo, Release, VerifiedPackage};
use std::path::Path;

/// Result of inspecting a downloaded archive record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadInspection {
    /// The record exactly identifies an already admitted compiled release, and
    /// the existing package parser verified its member and payload.
    Supported(PackageInfo),
    /// The archive record and bytes are valid, but no compiled release admits it.
    ArchivedOnly,
}

/// Find an exact compiled release matching the descriptive archive record.
///
/// This only determines UI eligibility. The archive bytes still go through the
/// updater's compiled release verifier before becoming a `VerifiedPackage`.
#[must_use]
pub fn supported_release(record: &ReleaseRecord) -> Option<&'static Release> {
    let metadata = record.metadata();
    if metadata.product != "kk3-max" || metadata.member_kind != FirmwareMemberKind::Kk3 {
        return None;
    }

    let component = match record.component() {
        gulikit_archive::Component::Base => Component::Main,
        gulikit_archive::Component::Bluetooth => Component::Bluetooth,
    };

    gulikit_core::package::catalog().iter().find(|release| {
        release.model == Model::Kk3Max
            && release.component == component
            && release.version == record.version()
            && release.archive == record.filename()
            && u64::try_from(release.archive_size).ok() == Some(record.size())
            && release.archive_sha256 == record.sha256()
            && release.member == metadata.firmware_member
            && u64::try_from(release.member_size()).ok() == Some(record.firmware_file().size)
            && release.member_sha256() == record.firmware_file().sha256
            && record.payload().is_some_and(|payload| {
                u64::try_from(release.payload_size()).ok() == Some(payload.size)
                    && release.payload_sha256() == payload.sha256
            })
    })
}

/// Verify a downloaded archive record and, when it matches the compiled
/// catalog, run the existing KK3 parser and compiled archive admission again.
///
/// # Errors
/// Returns an error for unreadable files, archive/record mismatches, parser
/// failures, or disagreement between parsed package metadata and the selected
/// compiled record.
pub fn inspect_download(path: &Path, record: &ReleaseRecord) -> Result<DownloadInspection, String> {
    let bytes =
        gulikit_archive::read_verified_archive(path, record).map_err(|error| error.to_string())?;

    let Some(release) = supported_release(record) else {
        return Ok(DownloadInspection::ArchivedOnly);
    };

    let component = release.component;
    let package = VerifiedPackage::inspect(&bytes, Model::Kk3Max, component)
        .map_err(|error| error.to_string())?;
    let info = package.info();
    if info.model != release.model
        || info.component != release.component
        || info.version != release.version
        || info.archive_sha256 != release.archive_sha256
        || info.payload_size != release.payload_size()
        || info.payload_sha256 != release.payload_sha256()
        || info.member != release.member
        || info.source_url != release.source_url
    {
        return Err("parsed package does not match the selected compiled release".into());
    }
    Ok(DownloadInspection::Supported(info.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_record(component: &str) -> serde_json::Value {
        let (
            version,
            filename,
            archive_size,
            archive_hash,
            member,
            member_size,
            member_hash,
            payload_size,
            payload_hash,
        ) = match component {
            "base" => (
                "5.9",
                "KK3_NS38_NS39_V5.9.zip",
                107_606,
                "b4d3c74bc2b0f6570523f121d7d8feb8842f239bdfc5e87bffd7af6aee520b67",
                "NS39_KK3_MAX_V5.9.bin",
                51500,
                "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4",
                51500,
                "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4",
            ),
            "bluetooth" => (
                "3.23",
                "NS39_BT_V3.23.zip",
                1_163_454,
                "39d678170e8d86488d65eb815873c708ff31b096d69d93714a0177086d5db938",
                "NS39_BT_V3.23.exe",
                2_245_632,
                "825cca9b36fa9078d8198f31ab4bf0ecebb4a6a8bd100303801ba1d1363c4dd6",
                361_472,
                "783d206c08253c1e2291a8b0bc99b04f95fc4054c2215447a30933f623cf9dfe",
            ),
            _ => unreachable!(),
        };
        serde_json::json!({
            "schema_version": 1,
            "releases": [{
                "component": component,
                "version": version,
                "filename": filename,
                "source_url": "https://www.gulikit.com/newsinfo/887152.html",
                "firmware_member": member,
                "path": format!("/kk3-max/{component}/v{version}/{filename}"),
                "size": archive_size,
                "sha256": archive_hash,
                "firmware_file": {"size": member_size, "sha256": member_hash},
                "payload": {"size": payload_size, "sha256": payload_hash}
            }]
        })
    }

    fn parse_record(value: &serde_json::Value) -> ReleaseRecord {
        gulikit_archive::FirmwareIndex::parse(&serde_json::to_vec(value).unwrap())
            .unwrap()
            .releases()[0]
            .clone()
    }

    #[test]
    fn exact_compiled_base_and_bluetooth_records_are_eligible() {
        let base = parse_record(&known_record("base"));
        let bluetooth = parse_record(&known_record("bluetooth"));

        assert_eq!(
            supported_release(&base).map(|release| release.version),
            Some("5.9")
        );
        assert_eq!(
            supported_release(&bluetooth).map(|release| release.version),
            Some("3.23")
        );
    }

    #[test]
    fn wrong_product_component_kind_or_hash_does_not_gain_eligibility() {
        let mut wrong_product = known_record("base");
        wrong_product["releases"][0]["product"] = "other-product".into();
        wrong_product["releases"][0]["member_kind"] = "raw_binary".into();
        wrong_product["releases"][0]["path"] =
            "/other-product/base/v5.9/KK3_NS38_NS39_V5.9.zip".into();

        let mut wrong_component = known_record("base");
        wrong_component["releases"][0]["component"] = "bluetooth".into();
        wrong_component["releases"][0]["firmware_member"] = "NS39_BT_V5.9.exe".into();
        wrong_component["releases"][0]["path"] =
            "/kk3-max/bluetooth/v5.9/KK3_NS38_NS39_V5.9.zip".into();

        let mut wrong_kind = known_record("base");
        wrong_kind["releases"][0]["member_kind"] = "raw_binary".into();
        assert!(
            gulikit_archive::FirmwareIndex::parse(&serde_json::to_vec(&wrong_kind).unwrap())
                .is_err()
        );

        let mut wrong_hash = known_record("base");
        wrong_hash["releases"][0]["sha256"] = "0".repeat(64).into();

        for value in [wrong_product, wrong_component, wrong_hash] {
            assert!(supported_release(&parse_record(&value)).is_none());
        }
    }
}
