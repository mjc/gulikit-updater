use gulikit_catalog::{Catalog, MAX_CATALOG_BYTES};
use gulikit_platform::catalog::{
    CatalogCache, CatalogCacheError, CatalogFetchError, CatalogFetcher, read_catalog_file,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
};
use tempfile::TempDir;

const CATALOG: &[u8] = br#"{"schema_version":1,"entries":[]}"#;
const CATALOG_WITH_WHITESPACE: &[u8] = br#"{
  "schema_version": 1,
  "entries": []
}
"#;

struct FixedFetcher(Vec<u8>);

impl CatalogFetcher for FixedFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, CatalogFetchError> {
        assert!(url.starts_with("https://"));
        Ok(self.0.clone())
    }
}

struct NeverFetcher;

impl CatalogFetcher for NeverFetcher {
    fn fetch(&self, _url: &str) -> Result<Vec<u8>, CatalogFetchError> {
        panic!("invalid URL must be rejected before fetch")
    }
}

fn setup() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary cache directory");
    let path = directory.path().join("catalog.json");
    (directory, path)
}

fn cache(path: &Path) -> CatalogCache {
    CatalogCache::new(path)
}

#[test]
fn refresh_caches_exact_raw_catalog_bytes_and_load_parses_metadata() {
    let (_directory, path) = setup();
    let cache = cache(&path);
    assert!(cache.load().expect("missing cache").is_none());

    let refreshed = cache
        .refresh_from_bytes(CATALOG)
        .expect("valid raw catalog");
    assert_eq!(refreshed, Catalog::parse(CATALOG).unwrap());
    assert_eq!(fs::read(&path).expect("published catalog"), CATALOG);

    let loaded = cache.load().expect("valid cached catalog").unwrap();
    assert_eq!(loaded, refreshed);
}

#[test]
fn injected_https_fetch_is_bounded_and_http_is_refused_before_fetch() {
    let (_directory, path) = setup();
    let cache = cache(&path);
    let refreshed = cache
        .refresh_from_url_with(
            "https://catalog.example.test/catalog.json",
            &FixedFetcher(CATALOG.to_vec()),
        )
        .expect("valid fetched catalog");
    assert_eq!(refreshed, Catalog::parse(CATALOG).unwrap());
    assert_eq!(fs::read(path).expect("cached catalog"), CATALOG);

    assert!(matches!(
        cache.refresh_from_url_with("http://catalog.example.test/catalog.json", &NeverFetcher),
        Err(CatalogCacheError::Fetch(CatalogFetchError::HttpsRequired))
    ));
    assert!(matches!(
        cache.refresh_from_url_with(
            "https://user@catalog.example.test/catalog.json",
            &NeverFetcher
        ),
        Err(CatalogCacheError::Fetch(CatalogFetchError::HttpsRequired))
    ));
}

#[test]
fn malformed_or_oversized_download_does_not_replace_existing_cache() {
    let (_directory, path) = setup();
    let cache = cache(&path);
    cache
        .refresh_from_bytes(CATALOG)
        .expect("initial valid cache");

    assert!(matches!(
        cache.refresh_from_bytes(b"not catalog JSON"),
        Err(CatalogCacheError::Catalog(_))
    ));
    assert_eq!(fs::read(&path).expect("original cache remains"), CATALOG);

    assert!(matches!(
        cache.refresh_from_url_with(
            "https://catalog.example.test/catalog.json",
            &FixedFetcher(vec![b' '; MAX_CATALOG_BYTES + 1]),
        ),
        Err(CatalogCacheError::TooLarge)
    ));
    assert_eq!(fs::read(&path).expect("original cache remains"), CATALOG);

    assert!(matches!(
        cache.refresh_from_url_with(
            "https://catalog.example.test/catalog.json",
            &FixedFetcher(b"invalid fetched catalog".to_vec()),
        ),
        Err(CatalogCacheError::Catalog(_))
    ));
    assert_eq!(fs::read(&path).expect("original cache remains"), CATALOG);
}

#[test]
fn a_valid_refresh_can_repair_malformed_existing_raw_cache() {
    let (_directory, path) = setup();
    fs::write(&path, b"corrupt prior metadata").expect("corrupt fixture");
    let cache = cache(&path);
    assert!(matches!(cache.load(), Err(CatalogCacheError::Catalog(_))));

    cache
        .refresh_from_bytes(CATALOG)
        .expect("valid replacement metadata");
    assert_eq!(
        cache.load().unwrap().unwrap(),
        Catalog::parse(CATALOG).unwrap()
    );
    assert_eq!(fs::read(path).expect("repaired raw catalog"), CATALOG);
}

#[test]
fn symlink_cache_is_refused_without_following_or_replacing_target() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let (directory, path) = setup();
        let target = directory.path().join("target");
        let original = b"keep target";
        fs::write(&target, original).expect("target fixture");
        symlink(&target, &path).expect("cache symlink");
        assert!(matches!(
            cache(&path).load(),
            Err(CatalogCacheError::UnsafeFile)
        ));
        assert_eq!(fs::read(target).expect("target unchanged"), original);
    }
}

#[test]
fn shared_reader_bounds_local_files_and_refuses_special_files() {
    let (_directory, path) = setup();
    fs::write(&path, b"12345").expect("regular file");
    assert_eq!(read_catalog_file(&path, 5).expect("at limit"), b"12345");
    assert!(matches!(
        read_catalog_file(&path, 4),
        Err(CatalogCacheError::TooLarge)
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let directory = path.parent().expect("fixture directory");
        let target = directory.join("target");
        fs::write(&target, b"data").expect("target");
        let link = directory.join("link");
        symlink(target, &link).expect("symlink");
        assert!(matches!(
            read_catalog_file(&link, 32),
            Err(CatalogCacheError::UnsafeFile)
        ));

        let fifo = directory.join("fifo");
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
fn concurrent_refreshes_leave_one_complete_parseable_catalog() {
    let (_directory, path) = setup();
    let cache = Arc::new(cache(&path));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for candidate in [CATALOG.to_vec(), CATALOG_WITH_WHITESPACE.to_vec()] {
        let worker_cache = Arc::clone(&cache);
        let worker_barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_cache.refresh_from_bytes(&candidate)
        }));
    }
    barrier.wait();
    let mut successes = 0;
    for worker in workers {
        match worker.join().unwrap() {
            Ok(_) => successes += 1,
            Err(CatalogCacheError::Lock(_)) => {}
            Err(error) => panic!("unexpected concurrent refresh failure: {error}"),
        }
    }
    assert!(successes >= 1, "at least one refresh must publish");

    let bytes = fs::read(&path).expect("published cache");
    assert!(bytes == CATALOG || bytes == CATALOG_WITH_WHITESPACE);
    assert_eq!(
        cache.load().expect("complete cached metadata").unwrap(),
        Catalog::parse(&bytes).unwrap()
    );
}

#[test]
fn readers_do_not_require_a_writable_lock_path_or_exclude_each_other() {
    let (_directory, path) = setup();
    fs::write(&path, include_bytes!("../../../catalog/official.json")).expect("cached metadata");
    // A directory cannot be opened as a lock file even by an elevated test user.
    // Reading an existing cache must never try to create or acquire this path.
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    fs::create_dir(std::path::PathBuf::from(lock_path)).expect("unusable lock path");
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                cache(&path)
                    .load()
                    .expect("read without writer lock")
                    .expect("cache exists")
                    .entries()
                    .len()
            })
        })
        .collect();
    for reader in readers {
        assert_eq!(reader.join().unwrap(), 4);
    }
}
