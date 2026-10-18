use ed25519_dalek::{Signer, SigningKey};
use gulikit_catalog::auth::TrustedKeys;
use gulikit_platform::catalog::{
    CatalogCache, CatalogCacheError, CatalogFetchError, CatalogFetcher, CatalogFreshness,
    read_catalog_file,
};
use serde_json::json;
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const DOMAIN: &[u8] = b"gulikit-catalog-v1\0";
const KEY_ID: &str = "cache-test-key";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[37; 32])
}

fn trusted_keys(key: &SigningKey) -> TrustedKeys {
    TrustedKeys::new([(KEY_ID.to_owned(), key.verifying_key().to_bytes())])
        .expect("test key is valid")
}

fn envelope(revision: u64, issued_at: u64, expires_at: u64) -> Vec<u8> {
    let key = signing_key();
    let payload = json!({
        "revision": revision,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "catalog": {"schema_version": 1, "entries": []},
    })
    .to_string();
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(payload.as_bytes());
    let mut signature = String::with_capacity(128);
    for byte in key.sign(&message).to_bytes() {
        write!(&mut signature, "{byte:02x}").expect("writing into string cannot fail");
    }
    json!({
        "schema_version": 1,
        "key_id": KEY_ID,
        "payload": payload,
        "signature": signature,
    })
    .to_string()
    .into_bytes()
}

fn setup() -> (TempDir, PathBuf, SigningKey, TrustedKeys) {
    let directory = tempfile::tempdir().expect("temporary cache directory");
    let path = directory.path().join("catalog.envelope.json");
    let key = signing_key();
    let keys = trusted_keys(&key);
    (directory, path, key, keys)
}

struct FixedFetcher(Vec<u8>);

impl CatalogFetcher for FixedFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, CatalogFetchError> {
        assert!(url.starts_with("https://"));
        Ok(self.0.clone())
    }
}

struct DelayedFetcher(Vec<u8>);

impl CatalogFetcher for DelayedFetcher {
    fn fetch(&self, _url: &str) -> Result<Vec<u8>, CatalogFetchError> {
        thread::sleep(Duration::from_millis(1_050));
        Ok(self.0.clone())
    }
}

fn cache(path: &Path) -> CatalogCache {
    CatalogCache::new(path)
}

#[test]
fn refresh_publishes_exact_signed_bytes_and_load_reauthenticates_them() {
    let (_directory, path, key, keys) = setup();
    let cache = cache(&path);
    let bytes = envelope(12, 100, 200);
    assert!(cache.load(&keys, 150, 1).expect("missing cache").is_none());

    let refreshed = cache
        .refresh_from_bytes(&bytes, &keys, 150, 1)
        .expect("fresh valid envelope");
    assert_eq!(refreshed.freshness(), CatalogFreshness::Fresh);
    assert_eq!(fs::read(&path).expect("published cache"), bytes);

    let loaded = cache
        .load(&keys, 150, 1)
        .expect("authenticated cache")
        .unwrap();
    assert_eq!(loaded.verified().revision(), 12);
    assert_eq!(loaded.verified().catalog().entries().len(), 0);
    assert_eq!(loaded.freshness(), CatalogFreshness::Fresh);
    assert_eq!(loaded.verified().key_id(), KEY_ID);
    assert_eq!(trusted_keys(&key).key_count(), 1);
}

#[test]
fn injected_https_fetch_is_bounded_and_http_url_is_refused_before_fetch() {
    let (_directory, path, _key, keys) = setup();
    let cache = cache(&path);
    let bytes = envelope(1, 100, 200);
    let fetcher = FixedFetcher(bytes.clone());
    let refreshed = cache
        .refresh_from_url_with(
            "https://catalog.example.test/signed.json",
            &keys,
            150,
            0,
            &fetcher,
        )
        .expect("injected response is verified and cached");
    assert_eq!(refreshed.verified().revision(), 1);
    assert_eq!(fs::read(path).expect("cached envelope"), bytes);
    assert!(matches!(
        cache.refresh_from_url_with("http://catalog.example.test", &keys, 150, 0, &fetcher),
        Err(CatalogCacheError::Fetch(CatalogFetchError::HttpsRequired))
    ));
}

#[test]
fn catalog_expiring_during_fetch_is_not_published() {
    let (_directory, path, _key, keys) = setup();
    let cache = cache(&path);
    let fetcher = DelayedFetcher(envelope(1, 100, 101));
    assert!(matches!(
        cache.refresh_from_url_with(
            "https://catalog.example.test/signed.json",
            &keys,
            100,
            0,
            &fetcher,
        ),
        Err(CatalogCacheError::Freshness(_))
    ));
    assert!(!path.exists());
}

#[test]
fn expired_signed_cache_remains_listable_with_explicit_freshness() {
    let (_directory, path, _key, keys) = setup();
    let cache = cache(&path);
    let bytes = envelope(12, 100, 200);
    cache
        .refresh_from_bytes(&bytes, &keys, 150, 1)
        .expect("initially fresh catalog");

    let loaded = cache
        .load(&keys, 200, 1)
        .expect("expired but signed")
        .unwrap();
    assert_eq!(loaded.freshness(), CatalogFreshness::Expired);
    assert_eq!(loaded.verified().revision(), 12);
}

#[test]
fn rejected_candidates_never_replace_the_valid_cache() {
    let (_directory, path, _key, keys) = setup();
    let cache = cache(&path);
    let current = envelope(20, 100, 200);
    cache
        .refresh_from_bytes(&current, &keys, 150, 1)
        .expect("initial cache");

    for (candidate, now, floor) in [
        (envelope(19, 100, 200), 150, 1),
        (envelope(21, 100, 200), 150, 22),
        (envelope(21, 100, 150), 150, 1),
        (envelope(21, 200, 300), 150, 1),
    ] {
        assert!(
            cache
                .refresh_from_bytes(&candidate, &keys, now, floor)
                .is_err()
        );
        assert_eq!(fs::read(&path).expect("original cache remains"), current);
    }

    let equivocation = envelope(20, 101, 201);
    assert!(matches!(
        cache.refresh_from_bytes(&equivocation, &keys, 150, 1),
        Err(CatalogCacheError::RevisionCollision(20))
    ));
    assert_eq!(fs::read(&path).expect("original cache remains"), current);
}

#[test]
fn corrupt_existing_cache_refuses_refresh_and_is_preserved_for_repair() {
    let (_directory, path, _key, keys) = setup();
    let corrupt = b"not an authenticated envelope";
    fs::write(&path, corrupt).expect("corrupt fixture");
    let candidate = envelope(1, 100, 200);
    assert!(
        cache(&path)
            .refresh_from_bytes(&candidate, &keys, 150, 0)
            .is_err()
    );
    assert_eq!(fs::read(path).expect("preserved corrupt cache"), corrupt);
}

#[test]
fn symlink_cache_is_refused_without_following_or_replacing_target() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let (directory, path, _key, keys) = setup();
        let target = directory.path().join("target");
        let original = b"keep target";
        fs::write(&target, original).expect("target fixture");
        symlink(&target, &path).expect("cache symlink");
        assert!(cache(&path).load(&keys, 150, 0).is_err());
        assert_eq!(fs::read(target).expect("target unchanged"), original);
    }
}

#[test]
fn shared_reader_bounds_local_files_and_refuses_special_files() {
    let (directory, path, _key, _keys) = setup();
    fs::write(&path, b"12345").expect("regular file");
    assert_eq!(read_catalog_file(&path, 5).expect("at limit"), b"12345");
    assert!(matches!(
        read_catalog_file(&path, 4),
        Err(CatalogCacheError::TooLarge)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = directory.path().join("target");
        fs::write(&target, b"secret").expect("target");
        let link = directory.path().join("link");
        symlink(target, &link).expect("symlink");
        assert!(matches!(
            read_catalog_file(&link, 32),
            Err(CatalogCacheError::UnsafeFile)
        ));

        let fifo = directory.path().join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("FIFO fixture");
        assert!(matches!(
            read_catalog_file(&fifo, 32),
            Err(CatalogCacheError::UnsafeFile)
        ));
    }
}

#[test]
fn concurrent_refreshes_cannot_regress_the_high_water_revision() {
    let (_directory, path, _key, keys) = setup();
    let cache = Arc::new(cache(&path));
    let low = envelope(2, 100, 500);
    let high = envelope(3, 100, 500);
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for candidate in [low, high] {
        let worker_cache = Arc::clone(&cache);
        let worker_keys = keys.clone();
        let worker_barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_cache.refresh_from_bytes(&candidate, &worker_keys, 150, 1)
        }));
    }
    barrier.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let final_revision = cache
        .load(&keys, 150, 1)
        .expect("final cache")
        .unwrap()
        .verified()
        .revision();
    assert!(matches!(final_revision, 2 | 3));
    assert!(results.iter().filter(|result| result.is_ok()).count() >= 1);
    let bytes = envelope(1, 100, 500);
    assert!(matches!(
        cache.refresh_from_bytes(&bytes, &keys, 150, 1),
        Err(CatalogCacheError::RevisionRollback { .. })
    ));
    assert_eq!(
        cache
            .load(&keys, 150, 1)
            .expect("high-water cache")
            .unwrap()
            .verified()
            .revision(),
        final_revision
    );
}
