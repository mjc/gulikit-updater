//! Bounded access to the public firmware orphan branch. Remote bytes remain
//! descriptive archive data and do not authorize a controller write.

use crate::{
    FirmwareIndex, ReleaseRecord,
    manifest::{Error as ManifestError, MAX_ARCHIVE_BYTES, MAX_INDEX_BYTES},
};
use serde::Deserialize;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use thiserror::Error;
use url::Url;

const OWNER: &str = "mjc";
const REPOSITORY: &str = "gulikit-updater";
const BRANCH: &str = "firmware";
const HEADER_LIMIT: usize = 16 * 1024;
const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Deserialize)]
struct BranchResponse {
    commit: BranchCommit,
}

#[derive(Deserialize)]
struct BranchCommit {
    sha: String,
}

#[derive(Debug, Error)]
pub enum RemoteError {
    #[error("remote archive request failed: {0}")]
    Request(String),
    #[error("archive server returned HTTP status {0}")]
    Status(u16),
    #[error("remote archive response exceeded its byte limit")]
    TooLarge,
    #[error("remote archive response has an invalid content length")]
    InvalidLength,
    #[error("remote archive response uses unsupported content encoding")]
    Compressed,
    #[error("remote firmware branch returned an invalid revision")]
    InvalidRevision,
    #[error("requested archive path is not present in the selected snapshot")]
    ReleaseNotFound,
    #[error("remote operation was cancelled")]
    Cancelled,
    #[error("archive manifest is invalid: {0}")]
    Manifest(#[from] ManifestError),
    #[error("remote archive cache I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive ZIP did not match its measured record")]
    InvalidArchive,
}

/// Immutable branch revision and its validated index.
#[derive(Clone, Debug)]
pub struct ArchiveSnapshot {
    revision: String,
    index: FirmwareIndex,
    index_bytes: Vec<u8>,
}

impl ArchiveSnapshot {
    /// Construct a snapshot from a full immutable Git commit and manifest bytes.
    ///
    /// # Errors
    /// Rejects abbreviated or malformed revisions and invalid manifest data.
    pub fn from_parts(revision: &str, index_bytes: &[u8]) -> Result<Self, RemoteError> {
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RemoteError::InvalidRevision);
        }
        if index_bytes.len() > MAX_INDEX_BYTES {
            return Err(RemoteError::TooLarge);
        }
        let index = FirmwareIndex::parse(index_bytes)?;
        Ok(Self {
            revision: revision.to_ascii_lowercase(),
            index,
            index_bytes: index_bytes.to_vec(),
        })
    }

    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    #[must_use]
    pub fn index(&self) -> &FirmwareIndex {
        &self.index
    }
}

/// Client for the fixed public firmware branch, with an offline cache.
pub struct ArchiveClient {
    cache_dir: PathBuf,
    fetcher: Box<dyn ArchiveFetcher>,
}

impl std::fmt::Debug for ArchiveClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveClient")
            .field("cache_dir", &self.cache_dir)
            .finish_non_exhaustive()
    }
}

#[doc(hidden)]
pub trait ArchiveFetcher: Send + Sync {
    /// Fetch one bounded response, observing cancellation before and between reads.
    fn fetch(
        &self,
        url: &str,
        limit: usize,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, RemoteError>;
}

impl ArchiveClient {
    /// Create a client using the fixed public `GuliKit` firmware branch.
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            fetcher: Box::new(HttpsFetcher),
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn with_fetcher(cache_dir: PathBuf, fetcher: Box<dyn ArchiveFetcher>) -> Self {
        Self { cache_dir, fetcher }
    }

    /// Load the last successfully validated cached firmware index, if present.
    ///
    /// # Errors
    /// Returns an error for unreadable, oversized, or invalid cached data.
    pub fn load_cached(&self) -> Result<Option<ArchiveSnapshot>, RemoteError> {
        let bytes = match read_bounded(&self.cache_dir.join("snapshot"), MAX_INDEX_BYTES + 41) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let separator = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| RemoteError::Request("invalid cached snapshot".into()))?;
        let (revision, rest) = bytes.split_at(separator);
        let index = &rest[1..];
        let revision =
            std::str::from_utf8(revision).map_err(|e| RemoteError::Request(e.to_string()))?;
        Ok(Some(ArchiveSnapshot::from_parts(revision, index)?))
    }

    /// Resolve the current branch commit and fetch its manifest at that commit.
    /// The cache changes only after both responses and manifest validation succeed.
    ///
    /// # Errors
    /// Returns an error for cancellation, network failures, invalid revisions or
    /// manifests, and cache I/O failures.
    pub fn refresh(&self, cancelled: &AtomicBool) -> Result<ArchiveSnapshot, RemoteError> {
        check_cancelled(cancelled)?;
        let api = Url::parse(&format!(
            "https://api.github.com/repos/{OWNER}/{REPOSITORY}/branches/{BRANCH}"
        ))
        .map_err(|error| RemoteError::Request(error.to_string()))?;
        let branch_bytes = self.fetcher.fetch(api.as_str(), 64 * 1024, cancelled)?;
        let branch: BranchResponse = serde_json::from_slice(&branch_bytes)
            .map_err(|e| RemoteError::Request(e.to_string()))?;
        let revision = branch.commit.sha;
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RemoteError::InvalidRevision);
        }
        let index_url = raw_url(&revision, "firmware.json")?;
        let index_bytes = self
            .fetcher
            .fetch(index_url.as_str(), MAX_INDEX_BYTES, cancelled)?;
        let snapshot = ArchiveSnapshot::from_parts(&revision, &index_bytes)?;
        check_cancelled(cancelled)?;
        fs::create_dir_all(&self.cache_dir)?;
        let mut cache_bytes = snapshot.revision.as_bytes().to_vec();
        cache_bytes.push(b'\n');
        cache_bytes.extend_from_slice(&snapshot.index_bytes);
        atomic_write(&self.cache_dir.join("snapshot"), &cache_bytes, cancelled)?;
        Ok(snapshot)
    }

    /// Fetch and verify an archive from the same immutable commit as `snapshot`.
    /// A verified ZIP is kept in a digest-keyed local cache and its path returned.
    ///
    /// # Errors
    /// Returns an error for cancellation, absent paths, transport or cache errors,
    /// or any ZIP, member, size, or digest mismatch.
    pub fn download(
        &self,
        snapshot: &ArchiveSnapshot,
        archive_path: &str,
        cancelled: &AtomicBool,
    ) -> Result<PathBuf, RemoteError> {
        check_cancelled(cancelled)?;
        let record = snapshot
            .index
            .find(archive_path)
            .ok_or(RemoteError::ReleaseNotFound)?;
        let cache_path = self
            .cache_dir
            .join("archives")
            .join(record.sha256())
            .join(record.filename());
        match read_verified_archive(&cache_path, record) {
            Ok(_) => {
                check_cancelled(cancelled)?;
                return Ok(cache_path);
            }
            Err(RemoteError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                let _ = fs::remove_file(&cache_path);
            }
        }
        let relative = record
            .path()
            .strip_prefix('/')
            .ok_or(RemoteError::ReleaseNotFound)?;
        let url = raw_url(&snapshot.revision, relative)?;
        let bytes = self.fetcher.fetch(
            url.as_str(),
            usize::try_from(record.size()).unwrap_or(MAX_ARCHIVE_BYTES),
            cancelled,
        )?;
        check_cancelled(cancelled)?;
        record
            .verify_archive_bytes(&bytes)
            .map_err(|_| RemoteError::InvalidArchive)?;
        check_cancelled(cancelled)?;
        let cache_parent = cache_path
            .parent()
            .ok_or_else(|| std::io::Error::other("archive cache path has no parent"))?;
        fs::create_dir_all(cache_parent)?;
        check_cancelled(cancelled)?;
        atomic_write(&cache_path, &bytes, cancelled)?;
        Ok(cache_path)
    }
}

/// Read and verify a complete archive from a bounded regular file.
///
/// # Errors
/// Rejects symlinks, special files, oversized or unreadable files, and any ZIP,
/// selected-member, payload, size, or digest mismatch.
pub fn read_verified_archive(path: &Path, record: &ReleaseRecord) -> Result<Vec<u8>, RemoteError> {
    let bytes = read_bounded(path, MAX_ARCHIVE_BYTES)?;
    record
        .verify_archive_bytes(&bytes)
        .map_err(|_| RemoteError::InvalidArchive)?;
    Ok(bytes)
}

fn raw_url(revision: &str, path: &str) -> Result<Url, RemoteError> {
    let mut url = Url::parse(&format!(
        "https://raw.githubusercontent.com/{OWNER}/{REPOSITORY}/{revision}/"
    ))
    .map_err(|e| RemoteError::Request(e.to_string()))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| RemoteError::Request("invalid raw URL".into()))?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(RemoteError::ReleaseNotFound);
            }
            segments.push(segment);
        }
    }
    Ok(url)
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), RemoteError> {
    if cancelled.load(Ordering::Relaxed) {
        Err(RemoteError::Cancelled)
    } else {
        Ok(())
    }
}

fn atomic_write(path: &Path, bytes: &[u8], cancelled: &AtomicBool) -> Result<(), RemoteError> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing parent"))?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    check_cancelled(cancelled)?;
    temp.persist(path)
        .map_err(|error| RemoteError::Io(error.error))?;
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    let file = open_cache_file(path)?;
    if file.metadata()?.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(std::io::Error::other(
            "cached file exceeds configured limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::other(
            "cached file exceeds configured limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_cache_file(path: &Path) -> Result<fs::File, std::io::Error> {
    use nix::{
        fcntl::{OFlag, open},
        sys::stat::Mode,
    };
    let descriptor = open(
        path,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
    let file = fs::File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("cached path is not a regular file"));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_cache_file(path: &Path) -> Result<fs::File, std::io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::Error::other("cached path is not a regular file"));
    }
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("cached path is not a regular file"));
    }
    Ok(file)
}

struct HttpsFetcher;
impl ArchiveFetcher for HttpsFetcher {
    fn fetch(
        &self,
        url: &str,
        limit: usize,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, RemoteError> {
        check_cancelled(cancelled)?;
        let parsed = Url::parse(url).map_err(|e| RemoteError::Request(e.to_string()))?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(RemoteError::Request("HTTPS URL required".into()));
        }
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .max_redirects(0)
            .max_response_header_size(HEADER_LIMIT)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_recv_body(Some(Duration::from_secs(15)))
            .tls_config(tls)
            .build()
            .new_agent();
        let response = agent
            .get(url)
            .header("Accept-Encoding", "identity")
            .header("User-Agent", "gulikit-updater")
            .call()
            .map_err(|error| RemoteError::Request(error.to_string()))?;
        let (parts, body) = response.into_parts();
        if parts.status.as_u16() != 200 {
            return Err(RemoteError::Status(parts.status.as_u16()));
        }
        if parts
            .headers
            .get("content-encoding")
            .is_some_and(|v| !v.to_str().unwrap_or("").eq_ignore_ascii_case("identity"))
        {
            return Err(RemoteError::Compressed);
        }
        if let Some(length) = parts.headers.get("content-length") {
            let length = length
                .to_str()
                .map_err(|_| RemoteError::InvalidLength)?
                .parse::<usize>()
                .map_err(|_| RemoteError::InvalidLength)?;
            if length > limit {
                return Err(RemoteError::TooLarge);
            }
        }
        let mut reader = body
            .into_with_config()
            .limit(limit.saturating_add(1) as u64)
            .reader();
        let mut bytes = Vec::new();
        let mut chunk = vec![0; CHUNK_SIZE];
        loop {
            check_cancelled(cancelled)?;
            let count = reader
                .read(&mut chunk)
                .map_err(|e| RemoteError::Request(e.to_string()))?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > limit {
                return Err(RemoteError::TooLarge);
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
