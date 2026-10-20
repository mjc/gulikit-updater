use super::*;
use crate::FirmwareIndex;
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

const CATALOG: &str = include_str!("../../tests/fixtures/signed-test-catalog.json");
const REV: &str = "d05c2b88e912bed36f8bbed31553879119f78579";

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
    let catalog: serde_json::Value = serde_json::from_str(CATALOG).unwrap();
    let zip_hex = catalog["zip"].as_str().unwrap();
    let zip = hex::decode(zip_hex).unwrap();
    let index = catalog["index"].as_str().unwrap().as_bytes().to_vec();
    let parsed = FirmwareIndex::parse(&index).unwrap();
    let path = parsed.releases().first().unwrap().path().to_owned();
    (zip, index, path)
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
        ArchiveClient::with_test_fetcher(dir.to_path_buf(), Box::new(fetcher)),
        urls,
    )
}

fn catalog_value() -> serde_json::Value {
    serde_json::from_str(CATALOG).unwrap()
}

fn commit_response() -> Vec<u8> {
    serde_json::to_vec(&catalog_value()["commit"]).unwrap()
}

fn tree_response() -> Vec<u8> {
    serde_json::to_vec(&catalog_value()["tree"]).unwrap()
}

fn admission_responses(index: Vec<u8>) -> Vec<Vec<u8>> {
    vec![commit_response(), tree_response(), index]
}

fn branch_response() -> Vec<u8> {
    format!(r#"{{"commit":{{"sha":"{REV}"}}}}"#).into_bytes()
}

#[test]
fn refresh_verifies_commit_and_cached_index_before_download() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let (refresh_client, refresh_urls) = client(
        dir.path(),
        [
            vec![branch_response()],
            admission_responses(index),
            vec![zip.clone()],
        ]
        .concat(),
    );
    let snapshot = refresh_client.refresh(&AtomicBool::new(false)).unwrap();
    assert_eq!(snapshot.revision(), REV);
    let seen = refresh_urls.lock().unwrap();
    assert!(seen[0].contains("api.github.com/repos/mjc/gulikit-updater/branches/firmware"));
    assert!(seen[1].contains(&format!("/git/commits/{REV}")));
    assert!(seen[2].contains("/git/trees/"));
    assert!(seen[3].contains(&format!("/{REV}/firmware.json")));
    assert_eq!(seen.len(), 4);
    drop(seen);

    let fresh = refresh_client
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(fresh.revision(), REV);
    assert_eq!(fs::read(fresh.path()).unwrap(), zip);
    let seen = refresh_urls.lock().unwrap();
    assert_eq!(seen.len(), 5, "freshly admitted snapshots reuse provenance");
    assert!(seen[4].contains(&format!("/{REV}/kk3-max/base/v5.9/release%201%25.zip")));
    drop(seen);

    let cached = refresh_client.load_cached().unwrap().unwrap();
    let (download_client, download_urls) = client(dir.path(), vec![]);
    let authorized = download_client
        .download(&cached, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(fs::read(authorized.path()).unwrap(), zip);
    assert_eq!(authorized.revision(), REV);
    assert_eq!(authorized.record().path(), path);
    let seen = download_urls.lock().unwrap();
    assert!(
        seen.is_empty(),
        "verified snapshot and ZIP caches work offline"
    );
}

#[test]
fn refresh_rejects_unverified_commit_before_fetching_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (client, urls) = client(dir.path(), vec![branch_response(), b"{}".to_vec()]);
    assert!(client.refresh(&AtomicBool::new(false)).is_err());
    let seen = urls.lock().unwrap();
    assert_eq!(
        seen.len(),
        2,
        "unverified commits must not fetch the tree or index"
    );
    assert!(seen[1].contains(&format!("/git/commits/{REV}")));
    assert!(client.load_cached().unwrap().is_none());
}

#[test]
fn validated_parts_reject_bad_revision_and_manifest() {
    assert!(ArchiveSnapshot::from_parts("abc", b"{}").is_err());
    assert!(ArchiveSnapshot::from_parts(REV, b"{}").is_err());
}

#[test]
fn cached_manifest_size_limit_is_enforced() {
    let oversized = vec![b' '; crate::manifest::MAX_INDEX_BYTES + 1];
    assert!(matches!(
        ArchiveSnapshot::from_parts(REV, &oversized),
        Err(RemoteError::TooLarge)
    ));
}

#[test]
fn failed_refresh_preserves_the_cached_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot_path = dir.path().join("snapshot");
    let old = format!("{REV}\n{{}}\n").into_bytes();
    fs::write(&snapshot_path, &old).unwrap();
    let (failed, _) = client(dir.path(), vec![b"bad branch".to_vec()]);
    assert!(failed.refresh(&AtomicBool::new(false)).is_err());
    assert_eq!(fs::read(snapshot_path).unwrap(), old);
}

#[test]
fn untrusted_snapshot_must_be_admitted_before_a_zip_cache_hit() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let snapshot = ArchiveSnapshot::from_parts(REV, &index).unwrap();
    let record = snapshot.index().find(&path).unwrap();
    let cache_path = dir
        .path()
        .join("archives")
        .join(record.sha256())
        .join(record.filename());
    fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    fs::write(&cache_path, &zip).unwrap();
    let (client, urls) = client(dir.path(), admission_responses(index));
    let authorized = client
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(authorized.path(), cache_path);
    let seen = urls.lock().unwrap();
    assert_eq!(seen.len(), 3, "admission proof precedes ZIP cache reuse");
    assert!(seen[0].contains(&format!("/git/commits/{REV}")));
    assert!(seen[1].contains("/git/trees/"));
    assert!(seen[2].contains(&format!("/{REV}/firmware.json")));
    drop(seen);
    assert_eq!(fs::read(cache_path).unwrap(), zip);
}

#[test]
fn legacy_snapshot_requires_network_admission_then_becomes_offline_proof_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    fs::write(
        dir.path().join("snapshot"),
        [REV.as_bytes(), b"\n", index.as_slice()].concat(),
    )
    .unwrap();
    let snapshot = client(dir.path(), vec![]).0.load_cached().unwrap().unwrap();
    let record = snapshot.index().find(&path).unwrap();
    let cache_path = dir
        .path()
        .join("archives")
        .join(record.sha256())
        .join(record.filename());
    fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    fs::write(&cache_path, &zip).unwrap();

    let (admitting, urls) = client(dir.path(), admission_responses(index));
    admitting
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(urls.lock().unwrap().len(), 3);

    let (offline, offline_urls) = client(dir.path(), vec![]);
    let restored = offline.load_cached().unwrap().unwrap();
    offline
        .download(&restored, &path, &AtomicBool::new(false))
        .unwrap();
    assert!(offline_urls.lock().unwrap().is_empty());
}

#[test]
fn changed_cached_index_is_rejected_before_archive_cache_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, signed_index, path) = fixture();
    let mut changed: serde_json::Value = serde_json::from_slice(&signed_index).unwrap();
    changed["releases"][0]["changelog"] = serde_json::json!("changed after caching");
    let cached_index = serde_json::to_vec(&changed).unwrap();
    let snapshot = ArchiveSnapshot::from_parts(REV, &cached_index).unwrap();
    let record = snapshot.index().find(&path).unwrap();
    let cache_path = dir
        .path()
        .join("archives")
        .join(record.sha256())
        .join(record.filename());
    fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
    fs::write(&cache_path, &zip).unwrap();

    let (client, urls) = client(dir.path(), admission_responses(signed_index));
    assert!(matches!(
        client.download(&snapshot, &path, &AtomicBool::new(false)),
        Err(RemoteError::UntrustedSnapshot)
    ));
    assert_eq!(urls.lock().unwrap().len(), 3);
    assert_eq!(fs::read(cache_path).unwrap(), zip);
}

#[test]
fn authenticated_download_repairs_a_corrupted_zip_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let (refresh_client, _) = client(
        dir.path(),
        [vec![branch_response()], admission_responses(index)].concat(),
    );
    let snapshot = refresh_client.refresh(&AtomicBool::new(false)).unwrap();
    let (transport, _) = client(dir.path(), vec![zip.clone()]);
    let downloaded = transport
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    fs::write(downloaded.path(), b"corrupt").unwrap();

    let (repair, _) = client(dir.path(), vec![zip.clone()]);
    let repaired = repair
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(fs::read(repaired.path()).unwrap(), zip);
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
    assert!(crate::read_verified_archive(&link, record).is_err());
    let fifo = dir.path().join("pipe.zip");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
    assert!(crate::read_verified_archive(&fifo, record).is_err());
    let oversized = dir.path().join("oversized.zip");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(u64::try_from(crate::manifest::MAX_ARCHIVE_BYTES).unwrap() + 1)
        .unwrap();
    assert!(crate::read_verified_archive(&oversized, record).is_err());
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

    let (wrong_archive, _) = client(
        dir.path(),
        [admission_responses(index), vec![b"not the zip".to_vec()]].concat(),
    );
    assert!(matches!(
        wrong_archive.download(&snapshot, &path, &AtomicBool::new(false)),
        Err(RemoteError::InvalidArchive)
    ));
    assert!(
        fs::read_dir(dir.path().join("archives"))
            .map_or(true, |mut entries| entries.next().is_none())
    );

    let cancel_on_return = Arc::new(AtomicBool::new(false));
    let fetcher = Fake {
        responses: Arc::new(Mutex::new(VecDeque::from([b"{}".to_vec()]))),
        urls: Arc::new(Mutex::new(Vec::new())),
        cancel_after: Some(cancel_on_return.clone()),
    };
    let cancelled = ArchiveClient::with_test_fetcher(dir.path().to_path_buf(), Box::new(fetcher));
    assert!(matches!(
        cancelled.download(&snapshot, &path, &cancel_on_return),
        Err(RemoteError::Cancelled)
    ));
}

#[test]
fn cancellation_before_publication_preserves_the_previous_file() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("snapshot");
    fs::write(&destination, b"previous snapshot").unwrap();
    let cancelled = AtomicBool::new(true);

    assert!(matches!(
        atomic_write(&destination, b"new snapshot", &cancelled),
        Err(RemoteError::Cancelled)
    ));
    assert_eq!(fs::read(destination).unwrap(), b"previous snapshot");
}

#[test]
fn tampered_proof_cache_is_rejected_locally_before_any_network_or_zip_read() {
    let dir = tempfile::tempdir().unwrap();
    let (zip, index, path) = fixture();
    let (online, _) = client(
        dir.path(),
        [
            vec![branch_response()],
            admission_responses(index),
            vec![zip],
        ]
        .concat(),
    );
    let snapshot = online.refresh(&AtomicBool::new(false)).unwrap();
    online
        .download(&snapshot, &path, &AtomicBool::new(false))
        .unwrap();
    let cached_path = dir.path().join("snapshot");
    let mut cached: serde_json::Value =
        serde_json::from_slice(&fs::read(&cached_path).unwrap()).unwrap();
    let mut index: serde_json::Value =
        serde_json::from_str(cached["index"].as_str().unwrap()).unwrap();
    index["releases"][0]["changelog"] = serde_json::json!("tampered cached metadata");
    cached["index"] = serde_json::json!(serde_json::to_string(&index).unwrap());
    fs::write(&cached_path, serde_json::to_vec(&cached).unwrap()).unwrap();
    let (offline, urls) = client(dir.path(), vec![]);
    assert!(matches!(
        offline.load_cached(),
        Err(RemoteError::Admission(_))
    ));
    assert!(urls.lock().unwrap().is_empty());
}
