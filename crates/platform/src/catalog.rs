//! Verified, atomic caching for the signed firmware catalog.

use gulikit_catalog::auth::{
    AuthError, FreshnessError, TrustedKeys, VerifiedCatalog, verify_envelope,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use thiserror::Error;

/// Maximum signed catalog envelope accepted from disk or a refresh response.
const MAX_CATALOG_ENVELOPE_BYTES: usize = gulikit_catalog::auth::MAX_ENVELOPE_BYTES;

/// Freshness is reported separately so expired signed metadata can still be listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogFreshness {
    Fresh,
    NotYetValid,
    Expired,
    BelowMinimumRevision,
}

/// Authenticated catalog bytes and their current freshness assessment.
pub struct CachedCatalog {
    verified: VerifiedCatalog,
    freshness: CatalogFreshness,
}

impl CachedCatalog {
    #[must_use]
    pub fn verified(&self) -> &VerifiedCatalog {
        &self.verified
    }

    #[must_use]
    pub fn freshness(&self) -> CatalogFreshness {
        self.freshness
    }
}

#[derive(Debug, Error)]
pub enum CatalogCacheError {
    #[error("catalog cache I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog cache file is not a safe regular file")]
    UnsafeFile,
    #[error("catalog cache or input exceeds its configured byte limit")]
    TooLarge,
    #[error("catalog envelope authentication failed: {0}")]
    Authentication(#[from] AuthError),
    #[error("catalog candidate is not fresh enough: {0}")]
    Freshness(#[from] FreshnessError),
    #[error("catalog revision {candidate} is below cached revision {cached}")]
    RevisionRollback { cached: u64, candidate: u64 },
    #[error("catalog revision {0} already exists with different signed bytes")]
    RevisionCollision(u64),
    #[error("cache was published, but syncing its parent directory failed: {0}")]
    PublishedButDurabilityUnknown(#[source] std::io::Error),
    #[error("catalog cache lock failed: {0}")]
    Lock(String),
    #[error("catalog validation time overflowed while refreshing")]
    ClockOverflow,
    #[error(transparent)]
    Fetch(#[from] CatalogFetchError),
}

#[derive(Debug, Error)]
pub enum CatalogFetchError {
    #[error("catalog endpoint must be an HTTPS URL")]
    HttpsRequired,
    #[error("catalog request failed: {0}")]
    Request(String),
    #[error("catalog server returned HTTP status {0}, expected 200")]
    Status(u16),
    #[error("compressed catalog responses are unsupported")]
    CompressedResponse,
    #[error("invalid catalog Content-Length header")]
    InvalidContentLength,
    #[error("catalog response exceeds the {MAX_CATALOG_ENVELOPE_BYTES}-byte limit")]
    TooLarge,
}

/// Synchronous, bounded catalog transport. Implementations can be injected in tests.
pub trait CatalogFetcher {
    /// Fetch one HTTPS response, enforcing `MAX_CATALOG_ENVELOPE_BYTES` before returning.
    ///
    /// # Errors
    /// Returns a transport error or rejects non-success, compressed, and oversized bodies.
    fn fetch(&self, url: &str) -> Result<Vec<u8>, CatalogFetchError>;
}

/// HTTPS catalog transport with system roots, fixed timeouts, and no redirects or decompression.
pub struct HttpsCatalogFetcher;

impl CatalogFetcher for HttpsCatalogFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, CatalogFetchError> {
        if !url.starts_with("https://") {
            return Err(CatalogFetchError::HttpsRequired);
        }
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_response_header_size(16 * 1024)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_recv_body(Some(Duration::from_secs(15)))
            .tls_config(tls)
            .build()
            .new_agent();
        let response = agent
            .get(url)
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(|error| CatalogFetchError::Request(error.to_string()))?;
        let (parts, body) = response.into_parts();
        let encoding = parts
            .headers
            .get("content-encoding")
            .map(|value| value.to_str().unwrap_or("<invalid>"));
        let content_length = parts
            .headers
            .get("content-length")
            .map(|value| value.to_str().unwrap_or("<invalid>"));
        let mut reader = body
            .into_with_config()
            .limit((MAX_CATALOG_ENVELOPE_BYTES + 1) as u64)
            .reader();
        read_response(parts.status.as_u16(), encoding, content_length, &mut reader)
    }
}

/// Shared bounded reader for catalog-related local files. It rejects symlinks,
/// special files, and content larger than the caller's fixed application limit.
///
/// # Errors
/// Returns an error if the path is missing, unsafe, unreadable, or oversized.
pub fn read_catalog_file(path: &Path, limit: usize) -> Result<Vec<u8>, CatalogCacheError> {
    read_bounded_regular_file_with_limit(path, limit)?.ok_or_else(|| {
        CatalogCacheError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "catalog file does not exist",
        ))
    })
}

/// Cache using a caller-selected path and a sibling advisory lock file.
pub struct CatalogCache {
    path: PathBuf,
    lock_path: PathBuf,
}

impl CatalogCache {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        Self {
            path,
            lock_path: PathBuf::from(lock_name),
        }
    }

    /// Load and reauthenticate a cached envelope. A missing cache is `Ok(None)`;
    /// signed expired/future/stale metadata is returned with its freshness state.
    ///
    /// # Errors
    /// Returns an error for unsafe files, invalid signatures/schema, or I/O failure.
    pub fn load(
        &self,
        keys: &TrustedKeys,
        now: u64,
        minimum_revision: u64,
    ) -> Result<Option<CachedCatalog>, CatalogCacheError> {
        let _guard = CacheLock::acquire(&self.lock_path)?;
        self.read_verified(keys, now, minimum_revision)
    }

    /// Verify and publish a network or otherwise acquired signed envelope.
    ///
    /// The caller supplies the bootstrap minimum revision when no cache exists.
    /// Existing authenticated cache data is the high-water mark, even when expired.
    ///
    /// # Errors
    /// Returns an error without replacing the cache if verification, freshness,
    /// revision monotonicity, or I/O checks fail.
    pub fn refresh_from_bytes(
        &self,
        envelope: &[u8],
        keys: &TrustedKeys,
        now: u64,
        minimum_revision: u64,
    ) -> Result<CachedCatalog, CatalogCacheError> {
        self.refresh_from_bytes_started(envelope, keys, now, minimum_revision, Instant::now())
    }

    fn refresh_from_bytes_started(
        &self,
        envelope: &[u8],
        keys: &TrustedKeys,
        now: u64,
        minimum_revision: u64,
        started: Instant,
    ) -> Result<CachedCatalog, CatalogCacheError> {
        if envelope.len() > MAX_CATALOG_ENVELOPE_BYTES {
            return Err(CatalogCacheError::TooLarge);
        }
        let candidate = verify_envelope(envelope, keys)?;
        let validation_time = elapsed_validation_window_from(now, started)?;
        validate_candidate_window(&candidate, validation_time, minimum_revision)?;
        let _guard = CacheLock::acquire(&self.lock_path)?;
        let validation_time = elapsed_validation_window_from(now, started)?;
        validate_candidate_window(&candidate, validation_time, minimum_revision)?;
        if let Some(current) = self.read_verified(keys, validation_time.upper, minimum_revision)? {
            if candidate.revision() < current.verified.revision() {
                return Err(CatalogCacheError::RevisionRollback {
                    cached: current.verified.revision(),
                    candidate: candidate.revision(),
                });
            }
            if candidate.revision() == current.verified.revision()
                && candidate.payload_bytes() != current.verified.payload_bytes()
            {
                return Err(CatalogCacheError::RevisionCollision(candidate.revision()));
            }
        }
        // Recheck immediately before publication in case waiting for the lock
        // or validating an existing cache crossed the signed expiry boundary.
        let validation_time = elapsed_validation_window_from(now, started)?;
        validate_candidate_window(&candidate, validation_time, minimum_revision)?;
        self.publish(candidate.envelope_bytes())?;
        Ok(CachedCatalog {
            freshness: freshness(&candidate, validation_time.upper, minimum_revision),
            verified: candidate,
        })
    }

    /// Fetch, authenticate, and atomically cache an HTTPS catalog.
    ///
    /// # Errors
    /// Returns an error for HTTP/TLS failures, bad signatures, stale candidates,
    /// unsafe cache state, or persistence failures.
    pub fn refresh_from_url(
        &self,
        url: &str,
        keys: &TrustedKeys,
        now: u64,
        minimum_revision: u64,
    ) -> Result<CachedCatalog, CatalogCacheError> {
        self.refresh_from_url_with(url, keys, now, minimum_revision, &HttpsCatalogFetcher)
    }

    /// Fetch through an injected transport, enabling deterministic offline tests.
    ///
    /// # Errors
    /// Returns an error if fetching, authentication, freshness, revision checks,
    /// or cache persistence fails.
    pub fn refresh_from_url_with<F: CatalogFetcher + ?Sized>(
        &self,
        url: &str,
        keys: &TrustedKeys,
        now: u64,
        minimum_revision: u64,
        fetcher: &F,
    ) -> Result<CachedCatalog, CatalogCacheError> {
        let started = Instant::now();
        let uri = url
            .parse::<ureq::http::Uri>()
            .map_err(|_| CatalogFetchError::HttpsRequired)?;
        if url.len() > 4096
            || uri.scheme_str() != Some("https")
            || uri
                .authority()
                .is_none_or(|authority| authority.as_str().contains('@'))
        {
            return Err(CatalogFetchError::HttpsRequired.into());
        }
        let bytes = fetcher.fetch(url)?;
        if bytes.len() > MAX_CATALOG_ENVELOPE_BYTES {
            return Err(CatalogCacheError::TooLarge);
        }
        self.refresh_from_bytes_started(&bytes, keys, now, minimum_revision, started)
    }

    fn read_verified(
        &self,
        keys: &TrustedKeys,
        now: u64,
        minimum_revision: u64,
    ) -> Result<Option<CachedCatalog>, CatalogCacheError> {
        let Some(bytes) = read_bounded_regular_file(&self.path)? else {
            return Ok(None);
        };
        let verified = verify_envelope(&bytes, keys)?;
        let freshness = freshness(&verified, now, minimum_revision);
        Ok(Some(CachedCatalog {
            verified,
            freshness,
        }))
    }

    fn publish(&self, bytes: &[u8]) -> Result<(), CatalogCacheError> {
        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !parent.is_dir() {
            return Err(CatalogCacheError::UnsafeFile);
        }
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| CatalogCacheError::Io(error.error))?;
        #[cfg(unix)]
        {
            File::open(parent)
                .map_err(CatalogCacheError::PublishedButDurabilityUnknown)?
                .sync_all()
                .map_err(CatalogCacheError::PublishedButDurabilityUnknown)
        }
        #[cfg(not(unix))]
        {
            // Windows has no portable directory fsync. The temp file was synced
            // before its atomic replacement; directory-entry crash durability is
            // therefore best effort on this platform.
            let _ = parent;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidationWindow {
    lower: u64,
    upper: u64,
}

fn elapsed_validation_window(
    now: u64,
    elapsed: Duration,
) -> Result<ValidationWindow, CatalogCacheError> {
    let lower = now
        .checked_add(elapsed.as_secs())
        .ok_or(CatalogCacheError::ClockOverflow)?;
    let upper = lower
        .checked_add(u64::from(elapsed.subsec_nanos() != 0))
        .ok_or(CatalogCacheError::ClockOverflow)?;
    Ok(ValidationWindow { lower, upper })
}

fn elapsed_validation_window_from(
    now: u64,
    started: Instant,
) -> Result<ValidationWindow, CatalogCacheError> {
    elapsed_validation_window(now, started.elapsed())
}

fn validate_candidate_window(
    candidate: &VerifiedCatalog,
    window: ValidationWindow,
    minimum_revision: u64,
) -> Result<(), CatalogCacheError> {
    candidate.require_fresh_at(window.lower, minimum_revision)?;
    candidate.require_fresh_at(window.upper, minimum_revision)?;
    Ok(())
}

fn read_response(
    status: u16,
    encoding: Option<&str>,
    content_length: Option<&str>,
    reader: &mut impl Read,
) -> Result<Vec<u8>, CatalogFetchError> {
    if status != 200 {
        return Err(CatalogFetchError::Status(status));
    }
    if encoding.is_some_and(|value| !value.eq_ignore_ascii_case("identity")) {
        return Err(CatalogFetchError::CompressedResponse);
    }
    if let Some(length) = content_length {
        let length = length
            .parse::<usize>()
            .map_err(|_| CatalogFetchError::InvalidContentLength)?;
        if length > MAX_CATALOG_ENVELOPE_BYTES {
            return Err(CatalogFetchError::TooLarge);
        }
    }
    let mut bytes = Vec::new();
    reader
        .take((MAX_CATALOG_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| CatalogFetchError::Request(error.to_string()))?;
    if bytes.len() > MAX_CATALOG_ENVELOPE_BYTES {
        return Err(CatalogFetchError::TooLarge);
    }
    Ok(bytes)
}

fn freshness(catalog: &VerifiedCatalog, now: u64, minimum_revision: u64) -> CatalogFreshness {
    if catalog.revision() < minimum_revision {
        CatalogFreshness::BelowMinimumRevision
    } else if now < catalog.issued_at() {
        CatalogFreshness::NotYetValid
    } else if now >= catalog.expires_at() {
        CatalogFreshness::Expired
    } else {
        CatalogFreshness::Fresh
    }
}

fn read_bounded_regular_file(path: &Path) -> Result<Option<Vec<u8>>, CatalogCacheError> {
    read_bounded_regular_file_with_limit(path, MAX_CATALOG_ENVELOPE_BYTES)
}

fn read_bounded_regular_file_with_limit(
    path: &Path,
    limit: usize,
) -> Result<Option<Vec<u8>>, CatalogCacheError> {
    if limit == 0 || limit > MAX_CATALOG_ENVELOPE_BYTES {
        return Err(CatalogCacheError::TooLarge);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(CatalogCacheError::UnsafeFile);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|error| {
        if is_symlink_error(&error) {
            CatalogCacheError::UnsafeFile
        } else {
            CatalogCacheError::Io(error)
        }
    })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(CatalogCacheError::UnsafeFile);
    }
    if metadata.len() > limit as u64 {
        return Err(CatalogCacheError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(CatalogCacheError::TooLarge);
    }
    Ok(Some(bytes))
}

struct CacheLock {
    _file: File,
}

impl CacheLock {
    fn acquire(path: &Path) -> Result<Self, CatalogCacheError> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(path).map_err(|error| {
            if is_symlink_error(&error) {
                CatalogCacheError::UnsafeFile
            } else {
                CatalogCacheError::Io(error)
            }
        })?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 0 {
            return Err(CatalogCacheError::UnsafeFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(CatalogCacheError::UnsafeFile);
            }
        }
        file.try_lock()
            .map_err(|error| CatalogCacheError::Lock(error.to_string()))?;
        Ok(Self { _file: file })
    }
}

fn is_symlink_error(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(nix::libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        error.kind() == std::io::ErrorKind::InvalidInput
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::{fmt::Write as _, io::Cursor};

    const DOMAIN: &[u8] = b"gulikit-catalog-v1\0";

    fn verified(issued_at: u64, expires_at: u64) -> VerifiedCatalog {
        let key = SigningKey::from_bytes(&[19; 32]);
        let payload = serde_json::json!({
            "revision": 1,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "catalog": {"schema_version": 1, "entries": []},
        })
        .to_string();
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(payload.as_bytes());
        let mut signature = String::with_capacity(128);
        for byte in key.sign(&message).to_bytes() {
            write!(&mut signature, "{byte:02x}").expect("string write");
        }
        let envelope = serde_json::json!({
            "schema_version": 1,
            "key_id": "clock-test",
            "payload": payload,
            "signature": signature,
        })
        .to_string();
        let keys = TrustedKeys::new([("clock-test".to_owned(), key.verifying_key().to_bytes())])
            .expect("trusted key");
        verify_envelope(envelope.as_bytes(), &keys).expect("valid test envelope")
    }

    #[test]
    fn validation_window_checks_both_sides_of_fractional_seconds() {
        let window = elapsed_validation_window(100, Duration::from_nanos(1)).unwrap();
        assert_eq!(
            window,
            ValidationWindow {
                lower: 100,
                upper: 101
            }
        );
        assert!(matches!(
            validate_candidate_window(&verified(101, 200), window, 0),
            Err(CatalogCacheError::Freshness(FreshnessError::NotYetValid))
        ));
        assert!(matches!(
            validate_candidate_window(&verified(0, 101), window, 0),
            Err(CatalogCacheError::Freshness(FreshnessError::Expired))
        ));
        assert!(matches!(
            elapsed_validation_window(u64::MAX, Duration::from_secs(1)),
            Err(CatalogCacheError::ClockOverflow)
        ));
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("test read failure"))
        }
    }

    #[test]
    fn response_policy_rejects_status_encoding_lengths_and_bounded_body_failures() {
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            read_response(302, None, None, &mut empty),
            Err(CatalogFetchError::Status(302))
        ));
        assert!(matches!(
            read_response(404, None, None, &mut empty),
            Err(CatalogFetchError::Status(404))
        ));
        assert!(matches!(
            read_response(200, Some("gzip"), None, &mut empty),
            Err(CatalogFetchError::CompressedResponse)
        ));
        assert!(matches!(
            read_response(200, None, Some("nope"), &mut empty),
            Err(CatalogFetchError::InvalidContentLength)
        ));
        assert!(matches!(
            read_response(
                200,
                None,
                Some(&(MAX_CATALOG_ENVELOPE_BYTES + 1).to_string()),
                &mut empty
            ),
            Err(CatalogFetchError::TooLarge)
        ));
        let mut oversized = Cursor::new(vec![0; MAX_CATALOG_ENVELOPE_BYTES + 1]);
        assert!(matches!(
            read_response(200, None, None, &mut oversized),
            Err(CatalogFetchError::TooLarge)
        ));
        assert!(matches!(
            read_response(200, None, None, &mut FailingReader),
            Err(CatalogFetchError::Request(_))
        ));
    }
}
