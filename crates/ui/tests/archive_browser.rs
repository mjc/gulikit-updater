use gulikit_archive::{
    ArchiveSnapshot, Component as ArchiveComponent, FirmwareIndex, FirmwareMemberKind,
    ReleaseMetadata, ReleaseRecord,
    manifest::{HashTarget, PublishedHash},
};
use gulikit_core::package::{Component, VerifiedPackage, catalog};
use gulikit_ui::{
    archive::{ArchiveBrowser, ArchiveEvent, Request},
    archive_package::{DownloadInspection, inspect_download},
};
use std::{sync::atomic::AtomicBool, sync::mpsc};

const REVISION_1: &str = "0123456789abcdef0123456789abcdef01234567";
const REVISION_2: &str = "1123456789abcdef0123456789abcdef01234567";

fn record(
    component: ArchiveComponent,
    version: &str,
    filename: &str,
    bytes: &[u8],
) -> ReleaseRecord {
    let member = match component {
        ArchiveComponent::Base => "NS39_KK3_MAX.bin",
        ArchiveComponent::Bluetooth => "NS39_BT.exe",
    };
    ReleaseRecord::measure(
        ReleaseMetadata {
            product: "kk3-max".into(),
            member_kind: FirmwareMemberKind::Kk3,
            component,
            version: version.into(),
            filename: filename.into(),
            source_url: "https://example.com/release".into(),
            released_at: None,
            retrieved_at: None,
            retrieved_from: None,
            changelog: None,
            changelog_source_url: None,
            firmware_member: member.into(),
            published_hashes: Vec::new(),
        },
        bytes,
        b"measured firmware member",
        b"measured firmware payload",
    )
    .unwrap()
}

fn snapshot(revision: &str, records: Vec<ReleaseRecord>) -> ArchiveSnapshot {
    let mut index = FirmwareIndex::empty();
    for record in records {
        index.add(record).unwrap();
    }
    ArchiveSnapshot::from_parts(revision, &index.to_json().unwrap()).unwrap()
}

fn browser(snapshot: ArchiveSnapshot) -> (ArchiveBrowser, mpsc::Receiver<Request>) {
    let (request_tx, request_rx) = mpsc::channel();
    (
        ArchiveBrowser::from_snapshot(snapshot, request_tx),
        request_rx,
    )
}

#[test]
fn offline_refresh_failure_preserves_cached_snapshot_and_selection() {
    let original = snapshot(
        REVISION_1,
        vec![record(ArchiveComponent::Base, "5.8", "old.zip", b"old")],
    );
    let (mut browser, requests) = browser(original);
    let selected = browser.selected_path().unwrap().to_owned();

    browser.refresh();
    assert!(matches!(requests.try_recv(), Ok(Request::Refresh)));
    let (event_tx, event_rx) = mpsc::channel();
    event_tx
        .send(ArchiveEvent::Refreshed(Err("offline".into())))
        .unwrap();
    browser.receive(&event_rx);

    let view = browser.view();
    assert_eq!(view.revision, REVISION_1);
    assert_eq!(browser.selected_path(), Some(selected.as_str()));
    assert_eq!(view.releases.len(), 1);
    assert!(view.status.contains("showing cached releases"));
    assert!(
        view.details
            .contains("Full changelog · No release notes supplied.")
    );
    assert!(
        view.details
            .contains("Published checksum claims · None supplied.")
    );
}

#[test]
fn component_filter_keeps_distinct_same_version_archives_selectable() {
    let base_a = record(ArchiveComponent::Base, "5.9", "base-a.zip", b"base-a");
    let base_b = record(ArchiveComponent::Base, "5.9", "base-b.zip", b"base-b");
    let bluetooth = record(ArchiveComponent::Bluetooth, "5.9", "bt.zip", b"bt");
    let (mut browser, requests) = browser(snapshot(REVISION_1, vec![base_a, base_b, bluetooth]));

    assert_eq!(
        browser.view().releases,
        ["5.9 · base-a.zip", "5.9 · base-b.zip"]
    );
    assert!(browser.set_component(Component::Bluetooth));
    assert_eq!(browser.view().releases, ["5.9 · bt.zip"]);
    assert!(browser.set_component(Component::Main));
    assert_eq!(
        browser.view().releases,
        ["5.9 · base-a.zip", "5.9 · base-b.zip"]
    );
    assert!(browser.select(1));
    browser.download();
    let request = requests.try_recv().unwrap();
    let Request::Download {
        snapshot: selected_snapshot,
        path,
    } = request
    else {
        panic!("download must capture selected snapshot and path");
    };
    assert_eq!(selected_snapshot.revision(), REVISION_1);
    assert_eq!(path, "/kk3-max/base/v5.9/base-b.zip");

    assert!(!browser.set_component(Component::Bluetooth)); // Download is in flight.
}

#[test]
fn version_sort_orders_numeric_prefix_and_alpha_suffix() {
    let versions = ["3.5", "3.6", "3.6a", "3.10"];
    let records = versions
        .iter()
        .rev()
        .map(|version| {
            record(
                ArchiveComponent::Base,
                version,
                &format!("v{version}.zip"),
                version.as_bytes(),
            )
        })
        .collect();
    let (browser, _requests) = browser(snapshot(REVISION_1, records));

    assert_eq!(
        browser.view().releases,
        [
            "3.10 · v3.10.zip",
            "3.6a · v3.6a.zip",
            "3.6 · v3.6.zip",
            "3.5 · v3.5.zip"
        ]
    );
}

#[test]
fn details_preserve_full_changelog_and_separate_published_claims_from_measured_hashes() {
    let changelog = "A detailed release note. ".repeat(12);
    let record = ReleaseRecord::measure(
        ReleaseMetadata {
            product: "kk3-max".into(),
            member_kind: FirmwareMemberKind::Kk3,
            component: ArchiveComponent::Base,
            version: "5.9".into(),
            filename: "release.zip".into(),
            source_url: "https://example.com/release".into(),
            released_at: None,
            retrieved_at: None,
            retrieved_from: None,
            changelog: Some(changelog.clone()),
            changelog_source_url: Some("https://example.com/notes".into()),
            firmware_member: "firmware.bin".into(),
            published_hashes: vec![PublishedHash {
                target: HashTarget::Zip,
                algorithm: "MD5".into(),
                value: "b343ae3b747c660f0606f82bf6e90b0a".into(),
                source_url: "https://example.com/checksums".into(),
            }],
        },
        b"measured archive bytes",
        b"measured member bytes",
        b"measured payload bytes",
    )
    .unwrap();
    let (browser, _requests) = browser(snapshot(REVISION_1, vec![record]));
    let view = browser.view();

    assert!(view.changelog.ends_with('…'));
    assert!(
        view.details
            .contains(&format!("Full changelog · {changelog}"))
    );
    assert!(view.details.contains("Measured ZIP SHA-256 · "));
    assert!(view.details.contains(
        "Published checksum claim · original ZIP · MD5 · b343ae3b747c660f0606f82bf6e90b0a · source https://example.com/checksums"
    ));
}

#[test]
fn selected_download_is_pinned_and_background_refresh_cannot_replace_it() {
    let first = record(ArchiveComponent::Base, "5.9", "same.zip", b"revision one");
    let second = record(ArchiveComponent::Base, "5.9", "same.zip", b"revision two");
    let (mut browser, requests) = browser(snapshot(REVISION_1, vec![first]));
    browser.download();
    let request = requests.try_recv().unwrap();
    let Request::Download {
        snapshot: captured,
        path,
    } = request
    else {
        panic!("download must carry its selected snapshot");
    };
    assert_eq!(captured.revision(), REVISION_1);
    assert_eq!(
        captured.index().find(&path).unwrap().sha256(),
        record(ArchiveComponent::Base, "5.9", "same.zip", b"revision one").sha256()
    );

    let (event_tx, event_rx) = mpsc::channel();
    event_tx
        .send(ArchiveEvent::Refreshed(Ok(snapshot(
            REVISION_2,
            vec![second],
        ))))
        .unwrap();
    browser.receive(&event_rx);

    assert_eq!(browser.view().revision, REVISION_1);
    assert_eq!(browser.view().releases, ["5.9 · same.zip"]);
    assert_eq!(
        browser.selected_record().unwrap().sha256(),
        captured.index().find(&path).unwrap().sha256()
    );
}

#[test]
fn event_channel_disconnect_ends_refreshing_state() {
    let (mut browser, _requests) = browser(snapshot(
        REVISION_1,
        vec![record(ArchiveComponent::Base, "5.8", "old.zip", b"old")],
    ));
    browser.refresh();
    assert!(browser.view().refreshing);
    let (event_tx, event_rx) = mpsc::channel();
    drop(event_tx);

    let (changed, _) = browser.receive(&event_rx);
    assert!(changed);
    assert!(!browser.view().refreshing);
    assert!(browser.view().status.contains("worker stopped"));
    assert_eq!(browser.view().revision, REVISION_1);
}

#[test]
#[ignore = "downloads the published firmware branch and four original vendor ZIPs"]
fn published_compiled_releases_download_and_inspect_through_ui_bridge() {
    struct Offline;
    impl gulikit_archive::ArchiveFetcher for Offline {
        fn fetch(
            &self,
            _url: &str,
            _limit: usize,
            _cancelled: &AtomicBool,
        ) -> Result<Vec<u8>, gulikit_archive::RemoteError> {
            Err(gulikit_archive::RemoteError::Request(
                "unexpected network access during offline cache reuse".into(),
            ))
        }
    }
    let cache = tempfile::tempdir().unwrap();
    let client = gulikit_archive::ArchiveClient::new(cache.path().to_owned());
    let cancelled = AtomicBool::new(false);
    let snapshot = client.refresh(&cancelled).unwrap();

    for release in catalog() {
        let record = snapshot
            .index()
            .releases()
            .iter()
            .find(|record| record.sha256() == release.archive_sha256)
            .expect("compiled release is present in published archive");
        let archive = client
            .download(&snapshot, record.path(), &cancelled)
            .unwrap();
        let DownloadInspection::Supported(info) = inspect_download(&archive).unwrap() else {
            panic!("compiled release should be supported");
        };
        let bytes =
            gulikit_archive::read_verified_archive(archive.path(), archive.record()).unwrap();
        let parsed = VerifiedPackage::inspect_selected(
            &bytes,
            info.archive_selection.as_ref().expect("archive recipe"),
        )
        .unwrap();
        assert_eq!(info, *parsed.info());
        assert_eq!(info.version, release.version);
        assert_eq!(info.archive_sha256, release.archive_sha256);
    }

    let offline =
        gulikit_archive::ArchiveClient::with_fetcher(cache.path().to_owned(), Box::new(Offline));
    let cached = offline.load_cached().unwrap().unwrap();
    assert_eq!(cached.revision(), snapshot.revision());
    for release in catalog() {
        let record = cached
            .index()
            .releases()
            .iter()
            .find(|record| record.sha256() == release.archive_sha256)
            .unwrap();
        let archive = offline
            .download(&cached, record.path(), &cancelled)
            .unwrap();
        let DownloadInspection::Supported(info) = inspect_download(&archive).unwrap() else {
            panic!("cached compiled release should remain supported offline");
        };
        assert_eq!(info.archive_sha256, release.archive_sha256);
    }
}
