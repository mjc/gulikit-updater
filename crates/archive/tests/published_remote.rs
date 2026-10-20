use gulikit_archive::ArchiveClient;
use gulikit_core::package::{Model, VerifiedPackage, catalog};
use std::sync::atomic::AtomicBool;

#[test]
#[ignore = "Downloads the public firmware branch and original ZIPs from GitHub"]
fn published_firmware_branch_downloads_match_the_existing_updater_packages() {
    let cache = tempfile::tempdir().unwrap();
    let client = ArchiveClient::new(cache.path().to_owned());
    let cancelled = AtomicBool::new(false);
    let snapshot = client.refresh(&cancelled).unwrap();
    assert_ne!(snapshot.index().releases(), []);
    for release in catalog() {
        let record = snapshot
            .index()
            .releases()
            .iter()
            .find(|record| record.sha256() == release.archive_sha256)
            .expect("reviewed original ZIP is published");
        let archive = client
            .download(&snapshot, record.path(), &cancelled)
            .unwrap();
        assert_eq!(archive.path().file_name().unwrap(), record.filename());
        let bytes =
            gulikit_archive::read_verified_archive(archive.path(), archive.record()).unwrap();
        let package = VerifiedPackage::inspect(&bytes, Model::Kk3Max, release.component).unwrap();
        assert_eq!(package.info().version, release.version);
        assert_eq!(package.info().member, release.member);
        assert_eq!(package.info().archive_sha256, release.archive_sha256);
        assert_eq!(package.info().payload_sha256, release.payload_sha256());
    }
    assert_eq!(
        client.load_cached().unwrap().unwrap().revision(),
        snapshot.revision()
    );
}
