//! Bounded, atomic caching for raw firmware catalog metadata.

use gulikit_catalog::{Catalog, CatalogError, MAX_CATALOG_BYTES};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

const MAX_LOCAL_CATALOG_FILE_BYTES: usize = MAX_CATALOG_BYTES;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum CatalogCacheError {
    #[error("catalog cache I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("catalog cache file is not a safe regular file")]
    UnsafeFile,
    #[error("catalog cache or input exceeds its configured byte limit")]
    TooLarge,
    #[error("invalid catalog metadata: {0}")]
    Catalog(#[from] CatalogError),
    #[error("cache was published, but syncing its parent directory failed: {0}")]
    PublishedButDurabilityUnknown(#[source] std::io::Error),
    #[error("catalog cache lock failed: {0}")]
    Lock(String),
    #[error(transparent)]
    Fetch(#[from] CatalogFetchError),
}

#[derive(Debug, Error)]
pub enum CatalogFetchError {
    #[error("catalog endpoint must be an HTTPS URL without user information")]
    HttpsRequired,
    #[error("catalog request failed: {0}")]
    Request(String),
    #[error("catalog server returned HTTP status {0}, expected 200")]
    Status(u16),
    #[error("compressed catalog responses are unsupported")]
    CompressedResponse,
    #[error("invalid catalog Content-Length header")]
    InvalidContentLength,
    #[error("catalog response exceeds the {MAX_CATALOG_BYTES}-byte limit")]
    TooLarge,
}

/// Synchronous bounded catalog transport, replaceable for deterministic tests.
pub trait CatalogFetcher {
    /// Fetch one HTTPS response, enforcing the raw catalog byte limit.
    ///
    /// # Errors
    /// Returns a transport error or rejects non-200, compressed, and oversized bodies.
    fn fetch(&self, url: &str) -> Result<Vec<u8>, CatalogFetchError>;
}

/// HTTPS catalog transport with platform certificate validation, fixed deadlines,
/// no redirects, and no response decompression.
pub struct HttpsCatalogFetcher;

impl CatalogFetcher for HttpsCatalogFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, CatalogFetchError> {
        validate_https_url(url)?;
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
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
            .limit((MAX_CATALOG_BYTES + 1) as u64)
            .reader();
        read_response(parts.status.as_u16(), encoding, content_length, &mut reader)
    }
}

/// Read a bounded local catalog file without following symlinks or opening
/// special files. The caller still validates its specific data format.
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

/// Cache raw catalog JSON at a caller-selected path and a sibling advisory lock.
/// Cached data is parsed metadata only; this cache does not authenticate it.
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

    /// Load and parse the cached raw catalog. A missing cache is `Ok(None)`.
    ///
    /// # Errors
    /// Returns an error for unsafe files, malformed catalog JSON, or I/O failure.
    pub fn load(&self) -> Result<Option<Catalog>, CatalogCacheError> {
        let _guard = CacheLock::acquire(&self.lock_path)?;
        let Some(bytes) = read_bounded_regular_file(&self.path)? else {
            return Ok(None);
        };
        Ok(Some(Catalog::parse(&bytes)?))
    }

    /// Validate and atomically cache raw catalog JSON.
    ///
    /// Validation completes before the prior cache can be replaced, so malformed
    /// input leaves the existing cache bytes untouched.
    ///
    /// # Errors
    /// Returns an error for oversized or malformed data, unsafe cache state, or I/O failure.
    pub fn refresh_from_bytes(&self, bytes: &[u8]) -> Result<Catalog, CatalogCacheError> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(CatalogCacheError::TooLarge);
        }
        let catalog = Catalog::parse(bytes)?;
        let _guard = CacheLock::acquire(&self.lock_path)?;
        self.publish(bytes)?;
        Ok(catalog)
    }

    /// Fetch, validate, and atomically cache raw catalog JSON over HTTPS.
    ///
    /// # Errors
    /// Returns an error for HTTP/TLS failures, malformed metadata, unsafe cache state, or I/O failure.
    pub fn refresh_from_url(&self, url: &str) -> Result<Catalog, CatalogCacheError> {
        self.refresh_from_url_with(url, &HttpsCatalogFetcher)
    }

    /// Fetch through an injected transport for deterministic offline tests.
    ///
    /// # Errors
    /// Returns an error if URL validation, fetching, parsing, or cache persistence fails.
    pub fn refresh_from_url_with<F: CatalogFetcher + ?Sized>(
        &self,
        url: &str,
        fetcher: &F,
    ) -> Result<Catalog, CatalogCacheError> {
        validate_https_url(url)?;
        let bytes = fetcher.fetch(url)?;
        self.refresh_from_bytes(&bytes)
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

fn validate_https_url(url: &str) -> Result<(), CatalogFetchError> {
    let uri = url
        .parse::<ureq::http::Uri>()
        .map_err(|_| CatalogFetchError::HttpsRequired)?;
    if url.len() > 4096
        || uri.scheme_str() != Some("https")
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err(CatalogFetchError::HttpsRequired);
    }
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
        if length > MAX_CATALOG_BYTES {
            return Err(CatalogFetchError::TooLarge);
        }
    }
    let mut bytes = Vec::new();
    reader
        .take((MAX_CATALOG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| CatalogFetchError::Request(error.to_string()))?;
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(CatalogFetchError::TooLarge);
    }
    Ok(bytes)
}

fn read_bounded_regular_file(path: &Path) -> Result<Option<Vec<u8>>, CatalogCacheError> {
    read_bounded_regular_file_with_limit(path, MAX_LOCAL_CATALOG_FILE_BYTES)
}

fn read_bounded_regular_file_with_limit(
    path: &Path,
    limit: usize,
) -> Result<Option<Vec<u8>>, CatalogCacheError> {
    if limit == 0 || limit > MAX_LOCAL_CATALOG_FILE_BYTES {
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
    use std::io::Cursor;

    #[test]
    fn response_reader_enforces_status_encoding_length_and_stream_bounds() {
        assert!(matches!(
            read_response(302, None, None, &mut Cursor::new(b"redirect")),
            Err(CatalogFetchError::Status(302))
        ));
        assert!(matches!(
            read_response(200, Some("gzip"), None, &mut Cursor::new(b"body")),
            Err(CatalogFetchError::CompressedResponse)
        ));
        assert!(matches!(
            read_response(200, None, Some("not-a-length"), &mut Cursor::new(b"body")),
            Err(CatalogFetchError::InvalidContentLength)
        ));
        assert!(matches!(
            read_response(
                200,
                None,
                Some(&(MAX_CATALOG_BYTES + 1).to_string()),
                &mut Cursor::new(b"body")
            ),
            Err(CatalogFetchError::TooLarge)
        ));
        assert!(matches!(
            read_response(
                200,
                None,
                None,
                &mut Cursor::new(vec![0; MAX_CATALOG_BYTES + 1])
            ),
            Err(CatalogFetchError::TooLarge)
        ));
        assert_eq!(
            read_response(200, Some("identity"), Some("4"), &mut Cursor::new(b"{}  "))
                .expect("bounded response"),
            b"{}  "
        );
    }
}
