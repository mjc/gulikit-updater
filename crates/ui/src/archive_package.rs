//! Bridge from measured archive records to the bounded KK3 package parsers.

use gulikit_archive::{AuthorizedArchive, FirmwareMemberKind, ReleaseRecord};
use gulikit_core::package::{
    ArchiveParserKind, ArchiveSelection, ArchiveSelectionData, Component, PackageInfo,
    VerifiedPackage,
};

/// Result of inspecting a downloaded archive record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DownloadInspection {
    /// The exact selected record and archive bytes passed the KK3 format parser.
    Supported(PackageInfo),
    /// The record is valid and cached, but its product or format has no KK3 parser.
    ArchivedOnly,
}

/// Convert an eligible KK3 record from one immutable revision into a checked selection.
///
/// # Errors
/// Rejects malformed metadata that cannot form a safe, bounded parser selection.
pub fn selection_for_record(
    revision: &str,
    record: &ReleaseRecord,
) -> Result<Option<ArchiveSelection>, String> {
    let metadata = record.metadata();
    if metadata.product != "kk3-max" || metadata.member_kind != FirmwareMemberKind::Kk3 {
        return Ok(None);
    }
    let component = match record.component() {
        gulikit_archive::Component::Base => Component::Main,
        gulikit_archive::Component::Bluetooth => Component::Bluetooth,
    };
    let Some(payload) = record.payload() else {
        return Err("KK3 archive record has no measured payload metadata".into());
    };
    let parser = match component {
        Component::Main => ArchiveParserKind::MainBinV1,
        Component::Bluetooth => ArchiveParserKind::BluetoothPeV1,
    };
    ArchiveSelection::try_from(ArchiveSelectionData {
        archive_revision: revision.to_owned(),
        path: record.path().to_owned(),
        component,
        version: record.version().to_owned(),
        archive: record.filename().to_owned(),
        archive_size: record.size(),
        archive_sha256: record.sha256().to_owned(),
        firmware_member: metadata.firmware_member.clone(),
        member_size: record.firmware_file().size,
        member_sha256: record.firmware_file().sha256.clone(),
        payload_size: payload.size,
        payload_sha256: payload.sha256.clone(),
        source_url: metadata.source_url.clone(),
        parser,
    })
    .map(Some)
    .map_err(|error| error.to_string())
}

/// Verify a download admitted by the archive client, then parse supported KK3 formats.
///
/// # Errors
/// Returns an error for unreadable files, archive/record mismatches, parser failures,
/// or malformed KK3 selection metadata.
pub fn inspect_download(archive: &AuthorizedArchive) -> Result<DownloadInspection, String> {
    let bytes = gulikit_archive::read_verified_archive(archive.path(), archive.record())
        .map_err(|error| error.to_string())?;
    let Some(selection) = selection_for_record(archive.revision(), archive.record())? else {
        return Ok(DownloadInspection::ArchivedOnly);
    };
    inspect_selected(&bytes, &selection)
}

fn inspect_selected(
    bytes: &[u8],
    selection: &ArchiveSelection,
) -> Result<DownloadInspection, String> {
    let package =
        VerifiedPackage::inspect_selected(bytes, selection).map_err(|error| error.to_string())?;
    if !package.info().matches_archive_selection(selection) {
        return Err("parsed package does not match the selected archive record".into());
    }
    Ok(DownloadInspection::Supported(package.info().clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check format parsing against an externally supplied pinned firmware corpus.
    /// Catalog authentication is exercised separately by the archive client tests.
    #[test]
    #[ignore = "requires the pinned firmware index and all original archives in the ignored cache"]
    fn pinned_firmware_corpus_parses_only_supported_kk3_formats() {
        let directory = std::env::var_os("GULIKIT_ARCHIVE_TEST_DIR")
            .map(std::path::PathBuf::from)
            .expect("set GULIKIT_ARCHIVE_TEST_DIR");
        let index_path = std::env::var_os("GULIKIT_ARCHIVE_TEST_INDEX")
            .map(std::path::PathBuf::from)
            .expect("set GULIKIT_ARCHIVE_TEST_INDEX");
        let revision = std::env::var("GULIKIT_ARCHIVE_TEST_REVISION")
            .expect("set GULIKIT_ARCHIVE_TEST_REVISION to the pinned archive commit");
        let index = gulikit_archive::FirmwareIndex::parse(
            &std::fs::read(index_path).expect("read pinned firmware index"),
        )
        .expect("parse pinned firmware index");
        let mut kk3 = 0;
        let mut other_formats = 0;

        for record in index.releases() {
            let eligible = record.metadata().product == "kk3-max"
                && record.metadata().member_kind == FirmwareMemberKind::Kk3;
            if !eligible {
                other_formats += 1;
                assert!(
                    selection_for_record(&revision, record)
                        .expect("classify unsupported format")
                        .is_none(),
                    "unsupported record was admitted: {}",
                    record.path()
                );
                continue;
            }
            let filename = format!(
                "{}-{}-{}",
                record.component(),
                record.version(),
                record.filename()
            );
            let path = directory.join(filename);
            assert!(path.is_file(), "missing pinned archive {}", path.display());
            let bytes = gulikit_archive::read_verified_archive(&path, record)
                .unwrap_or_else(|error| panic!("{}: {error}", record.path()));
            let selection = selection_for_record(&revision, record)
                .unwrap_or_else(|error| panic!("{}: {error}", record.path()))
                .expect("eligible KK3 release has a parser selection");
            let inspected = inspect_selected(&bytes, &selection)
                .unwrap_or_else(|error| panic!("{}: {error}", record.path()));
            kk3 += 1;
            let DownloadInspection::Supported(info) = inspected else {
                panic!("KK3 record was not admitted: {}", record.path());
            };
            let selection = info.archive_selection.as_ref().expect("selection recipe");
            assert_eq!(selection.data().archive_revision, revision);
            assert_eq!(selection.data().path, record.path());
            assert!(info.matches_archive_selection(selection));
        }
        assert_eq!(kk3, 45, "expected every pinned KK3 release to be parsed");
        assert_eq!(
            other_formats, 29,
            "unsupported product records remain unadmitted"
        );
    }
}
