use gulikit_archive::{
    ArchiveClient, ArchiveFetcher, ArchiveSnapshot, Component, FirmwareIndex, FirmwareMemberKind,
    ReleaseMetadata, ReleaseRecord, RemoteError,
};
use std::{
    collections::VecDeque,
    fs,
    io::{Cursor, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use zip::{ZipWriter, write::SimpleFileOptions};

const REV: &str = "0123456789abcdef0123456789abcdef01234567";

#[derive(Clone)]
struct Fake {
    responses: Arc<Mutex<VecDeque<Vec<u8>>>>,
    urls: Arc<Mutex<Vec<String>>>,
    cancel_after: Option<Arc<AtomicBool>>,
}
impl ArchiveFetcher for Fake {
    fn fetch(
        &self,
        url: &str,
        limit: usize,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, RemoteError> {
        if cancelled.load(Ordering::Relaxed) {
            return Err(RemoteError::Cancelled);
        }
        self.urls.lock().unwrap().push(url.to_owned());
        let bytes = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| RemoteError::Request("no fixture".into()))?;
        if bytes.len() > limit {
            return Err(RemoteError::TooLarge);
        }
        if let Some(flag) = &self.cancel_after {
            flag.store(true, Ordering::Relaxed);
        }
        Ok(bytes)
    }
}

fn fixture() -> (Vec<u8>, Vec<u8>, String) {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("firmware.bin", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"firmware bytes").unwrap();
    let zip = writer.finish().unwrap().into_inner();
    let record = ReleaseRecord::measure(
        ReleaseMetadata {
            product: "kk3-max".into(),
            member_kind: FirmwareMemberKind::Kk3,
            component: Component::Base,
            version: "5.9".into(),
            filename: "release 1%.zip".into(),
            source_url: "https://example.com/release".into(),
            released_at: None,
            retrieved_at: None,
            retrieved_from: None,
            changelog: None,
            changelog_source_url: None,
            firmware_member: "firmware.bin".into(),
            published_hashes: vec![],
        },
        &zip,
        b"firmware bytes",
        b"firmware bytes",
    )
    .unwrap();
    let path = record.path().to_owned();
    let mut index = FirmwareIndex::empty();
    index.add(record).unwrap();
    (zip, index.to_json().unwrap(), path)
}

fn client(
    dir: &std::path::Path,
    responses: Vec<Vec<u8>>,
) -> (ArchiveClient, Arc<Mutex<Vec<String>>>) {
    let urls = Arc::new(Mutex::new(Vec::new()));
    let fetcher = Fake {
        responses: Arc::new(Mutex::new(responses.into())),
        urls: urls.clone(),
        cancel_after: None,
    };
    (
        ArchiveClient::with_fetcher(dir.to_path_buf(), Box::new(fetcher)),
        urls,
    )
}

#[test]
fn refresh_pins_manifest_and_download_to_one_revision() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let (refresh_client, urls) = client(
        dir.path(),
        vec![
            format!(r#"{{"commit":{{"sha":"{REV}"}}}}"#).into_bytes(),
            index,
        ],
    );
    let snapshot = refresh_client.refresh(&AtomicBool::new(false)).unwrap();
    let seen = urls.lock().unwrap();
    assert!(seen[0].contains("api.github.com/repos/mjc/gulikit-updater/branches/firmware"));
    assert!(seen[1].contains(&format!("/{REV}/firmware.json")));
    assert_eq!(snapshot.revision(), REV);
    assert_eq!(
        refresh_client.load_cached().unwrap().unwrap().revision(),
        REV
    );
    let (download_client, urls) = client(dir.path(), vec![zip]);
    let saved = download_client
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(fs::read(saved).unwrap(), fixture().0);
    assert!(
        urls.lock().unwrap()[0].contains(&format!("/{REV}/kk3-max/base/v5.9/release%201%25.zip"))
    );
}

#[test]
fn validated_parts_reject_bad_revision_and_manifest() {
    assert!(ArchiveSnapshot::from_parts("abc", b"{}").is_err());
    assert!(ArchiveSnapshot::from_parts(REV, b"{}").is_err());
}

#[test]
fn cached_manifest_size_limit_is_enforced() {
    let oversized = vec![b' '; gulikit_archive::manifest::MAX_INDEX_BYTES + 1];
    assert!(matches!(
        ArchiveSnapshot::from_parts(REV, &oversized),
        Err(RemoteError::TooLarge)
    ));
}

#[test]
fn failed_refresh_preserves_cache_and_cached_zip_is_reverified() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let (first, _) = client(
        dir.path(),
        vec![
            format!(r#"{{"commit":{{"sha":"{REV}"}}}}"#).into_bytes(),
            index,
        ],
    );
    let snapshot = first.refresh(&AtomicBool::new(false)).unwrap();
    let snapshot_path = dir.path().join("snapshot");
    let old = fs::read(&snapshot_path).unwrap();
    let (bad_manifest, _) = client(
        dir.path(),
        vec![
            format!(r#"{{"commit":{{"sha":"{REV}"}}}}"#).into_bytes(),
            b"{}".to_vec(),
        ],
    );
    assert!(bad_manifest.refresh(&AtomicBool::new(false)).is_err());
    assert_eq!(fs::read(&snapshot_path).unwrap(), old);
    let (failed, _) = client(dir.path(), vec![b"bad branch".to_vec()]);
    assert!(failed.refresh(&AtomicBool::new(false)).is_err());
    assert_eq!(fs::read(snapshot_path).unwrap(), old);

    let (downloader, _) = client(dir.path(), vec![zip.clone()]);
    let path_on_disk = downloader
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    fs::write(&path_on_disk, b"corrupt").unwrap();
    let (repair, _) = client(dir.path(), vec![zip.clone()]);
    assert_eq!(
        fs::read(
            repair
                .download(&snapshot, &path, &AtomicBool::new(false))
                .unwrap()
        )
        .unwrap(),
        zip
    );
}

#[test]
fn valid_archive_cache_reuse_does_not_contact_transport() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let snapshot = ArchiveSnapshot::from_parts(REV, &index).unwrap();
    let (first, _) = client(dir.path(), vec![zip]);
    let downloaded = first
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(downloaded.file_name().unwrap(), "release 1%.zip");
    let no_network = ArchiveClient::with_fetcher(
        dir.path().to_path_buf(),
        Box::new(Fake {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            urls: Arc::new(Mutex::new(Vec::new())),
            cancel_after: None,
        }),
    );
    assert_eq!(
        no_network
            .download(&snapshot, &path, &AtomicBool::new(false))
            .unwrap(),
        downloaded
    );
}

#[test]
fn duplicate_zip_members_are_rejected_by_shared_zip_validation() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for name in ["firmware.bin", "not-used.bin"] {
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"firmware bytes").unwrap();
    }
    let mut duplicate_zip = writer.finish().unwrap().into_inner();
    let positions: Vec<_> = duplicate_zip
        .windows(b"not-used.bin".len())
        .enumerate()
        .filter_map(|(offset, name)| (name == b"not-used.bin").then_some(offset))
        .collect();
    assert_eq!(positions.len(), 2);
    for offset in positions {
        duplicate_zip[offset..offset + b"firmware.bin".len()].copy_from_slice(b"firmware.bin");
    }
    let (_, index, path) = fixture();
    let snapshot = ArchiveSnapshot::from_parts(REV, &index).unwrap();
    let record = ReleaseRecord::measure(
        snapshot.index().find(&path).unwrap().metadata().clone(),
        &duplicate_zip,
        b"firmware bytes",
        b"firmware bytes",
    )
    .unwrap();
    assert!(record.verify_archive_bytes(&duplicate_zip).is_err());
}

#[cfg(unix)]
#[test]
fn verified_archive_reader_rejects_symlinks_and_fifos_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let snapshot = ArchiveSnapshot::from_parts(REV, &index).unwrap();
    let record = snapshot.index().find(&path).unwrap();
    let target = dir.path().join("valid.zip");
    fs::write(&target, zip).unwrap();
    let link = dir.path().join("link.zip");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(gulikit_archive::read_verified_archive(&link, record).is_err());
    let fifo = dir.path().join("pipe.zip");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    assert!(gulikit_archive::read_verified_archive(&fifo, record).is_err());
    let oversized = dir.path().join("oversized.zip");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(u64::try_from(gulikit_archive::manifest::MAX_ARCHIVE_BYTES).unwrap() + 1)
        .unwrap();
    assert!(gulikit_archive::read_verified_archive(&oversized, record).is_err());
}

#[test]
fn cancellation_and_wrong_digest_preserve_existing_files() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let snapshot = ArchiveSnapshot::from_parts(REV, &index).unwrap();
    let (cancelled_client, _) = client(dir.path(), vec![zip]);
    let flag = AtomicBool::new(true);
    assert!(matches!(
        cancelled_client.download(&snapshot, &path, &flag),
        Err(RemoteError::Cancelled)
    ));

    let (client, _) = client(dir.path(), vec![b"not the zip".to_vec()]);
    assert!(matches!(
        client.download(&snapshot, &path, &AtomicBool::new(false)),
        Err(RemoteError::InvalidArchive)
    ));
    assert!(
        fs::read_dir(dir.path().join("archives"))
            .map_or(true, |mut entries| entries.next().is_none())
    );

    let cancel_on_return = Arc::new(AtomicBool::new(false));
    let fetcher = Fake {
        responses: Arc::new(Mutex::new(VecDeque::from([fixture().0]))),
        urls: Arc::new(Mutex::new(Vec::new())),
        cancel_after: Some(cancel_on_return.clone()),
    };
    let cancelled = ArchiveClient::with_fetcher(dir.path().to_path_buf(), Box::new(fetcher));
    assert!(matches!(
        cancelled.download(&snapshot, &path, &cancel_on_return),
        Err(RemoteError::Cancelled)
    ));
}
