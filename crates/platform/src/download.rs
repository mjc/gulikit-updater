//! Bounded acquisition of original `GuliKit` ZIP archives and vendor source pages.

use gulikit_catalog::{DownloadAvailability, Entry, MAX_ARCHIVE_SIZE};
use sha2::Digest;
#[cfg(unix)]
use std::fs::File;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use thiserror::Error;

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("download is marked unavailable by the selected catalog entry")]
    Unavailable,
    #[error("download destination must name a file in an existing directory")]
    UnsafeDestination,
    #[error("download I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("download request failed: {0}")]
    Request(String),
    #[error("download server returned HTTP status {0}, expected 200")]
    Status(u16),
    #[error("compressed download responses are unsupported")]
    CompressedResponse,
    #[error("invalid download Content-Length header")]
    InvalidContentLength,
    #[error("download Content-Length did not match the reviewed archive size")]
    LengthHeaderMismatch,
    #[error("download body did not match the reviewed archive size")]
    LengthMismatch,
    #[error("download response exceeded the reviewed archive size")]
    TooLarge,
    #[error("download SHA-256 did not match the selected catalog entry")]
    HashMismatch,
    #[error("download was cancelled before publication")]
    Cancelled,
    #[error("opening the vendor source page failed: {0}")]
    Browser(String),
    #[error("archive was published, but syncing its parent directory failed: {0}")]
    PublishedButDurabilityUnknown(#[source] std::io::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DownloadResult {
    Downloaded { path: PathBuf },
    ManualRequired { source_url: String },
}

/// Response stream from an injected or platform HTTPS transport.
pub struct DownloadResponse {
    pub status: u16,
    pub content_encoding: Option<String>,
    pub content_length: Option<String>,
    pub body: Box<dyn Read>,
}

/// Fetcher seam for deterministic offline tests.
pub trait DownloadFetcher {
    /// Fetch a response for a previously validated official ZIP URL.
    ///
    /// # Errors
    /// Returns transport failures without publishing a destination file.
    fn fetch(&self, url: &str, limit: u64) -> Result<DownloadResponse, DownloadError>;
}

/// Platform TLS transport with no redirects, decompression, or unbounded reads.
pub struct HttpsDownloadFetcher;

impl DownloadFetcher for HttpsDownloadFetcher {
    fn fetch(&self, url: &str, limit: u64) -> Result<DownloadResponse, DownloadError> {
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
            .map_err(|error| DownloadError::Request(error.to_string()))?;
        let (parts, body) = response.into_parts();
        let content_encoding = parts
            .headers
            .get("content-encoding")
            .map(|value| value.to_str().unwrap_or("<invalid>").to_owned());
        let content_length = parts
            .headers
            .get("content-length")
            .map(|value| value.to_str().unwrap_or("<invalid>").to_owned());
        let body = body
            .into_with_config()
            .limit(limit.saturating_add(1))
            .reader();
        Ok(DownloadResponse {
            status: parts.status.as_u16(),
            content_encoding,
            content_length,
            body: Box::new(body),
        })
    }
}

/// Download the exact original archive described by an explicitly selected entry.
///
/// Missing direct links return a manual source-page action without contacting a
/// server or touching the destination. The archive is published only after its
/// byte count and SHA-256 match the entry.
///
/// # Errors
/// Rejects unavailable releases, invalid responses, cancellation, mismatched
/// bytes, unsafe destinations, and filesystem or transport failures.
pub fn download_release(
    entry: &Entry,
    destination: &Path,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<DownloadResult, DownloadError> {
    download_release_with(entry, destination, cancelled, &HttpsDownloadFetcher)
}

/// Download through an injected transport for deterministic offline tests.
///
/// # Errors
/// Has the same refusal behavior as [`download_release`].
pub fn download_release_with<F: DownloadFetcher + ?Sized>(
    entry: &Entry,
    destination: &Path,
    cancelled: &mut dyn FnMut() -> bool,
    fetcher: &F,
) -> Result<DownloadResult, DownloadError> {
    if entry.availability() == DownloadAvailability::Unavailable {
        return Err(DownloadError::Unavailable);
    }
    let Some(url) = entry.download_url() else {
        return Ok(DownloadResult::ManualRequired {
            source_url: entry.source_url().to_owned(),
        });
    };
    if cancelled() {
        return Err(DownloadError::Cancelled);
    }
    let archive_size = entry.archive_size();
    if archive_size == 0 || archive_size > MAX_ARCHIVE_SIZE {
        return Err(DownloadError::TooLarge);
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if destination.file_name().is_none() || !parent.is_dir() {
        return Err(DownloadError::UnsafeDestination);
    }
    let mut response = fetcher.fetch(url, archive_size)?;
    validate_response_headers(&response, archive_size)?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut hasher = sha2::Sha256::new();
    let mut bytes_written = 0u64;
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        if cancelled() {
            return Err(DownloadError::Cancelled);
        }
        let count = response
            .body
            .read(&mut buffer)
            .map_err(|error| DownloadError::Request(error.to_string()))?;
        if count == 0 {
            break;
        }
        let count = u64::try_from(count).map_err(|_| DownloadError::TooLarge)?;
        bytes_written = bytes_written
            .checked_add(count)
            .ok_or(DownloadError::TooLarge)?;
        if bytes_written > archive_size {
            return Err(DownloadError::TooLarge);
        }
        let count = usize::try_from(count).map_err(|_| DownloadError::TooLarge)?;
        hasher.update(&buffer[..count]);
        temporary.write_all(&buffer[..count])?;
    }
    if bytes_written != archive_size {
        return Err(DownloadError::LengthMismatch);
    }
    let digest = hex::encode(hasher.finalize());
    if digest != entry.archive_sha256().as_str() {
        return Err(DownloadError::HashMismatch);
    }
    if cancelled() {
        return Err(DownloadError::Cancelled);
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(destination)
        .map_err(|error| DownloadError::Io(error.error))?;
    #[cfg(unix)]
    File::open(parent)
        .map_err(DownloadError::PublishedButDurabilityUnknown)?
        .sync_all()
        .map_err(DownloadError::PublishedButDurabilityUnknown)?;
    Ok(DownloadResult::Downloaded {
        path: destination.to_owned(),
    })
}

fn validate_response_headers(
    response: &DownloadResponse,
    archive_size: u64,
) -> Result<(), DownloadError> {
    if response.status != 200 {
        return Err(DownloadError::Status(response.status));
    }
    if response
        .content_encoding
        .as_deref()
        .is_some_and(|encoding| !encoding.eq_ignore_ascii_case("identity"))
    {
        return Err(DownloadError::CompressedResponse);
    }
    if let Some(length) = response.content_length.as_deref() {
        let length = length
            .parse::<u64>()
            .map_err(|_| DownloadError::InvalidContentLength)?;
        if length != archive_size {
            return Err(DownloadError::LengthHeaderMismatch);
        }
    }
    Ok(())
}

/// Opener seam for the default operating-system browser action.
pub trait OfficialSourceOpener {
    /// Request that the operating system open the selected official source page.
    ///
    /// # Errors
    /// Returns an error if the OS browser launcher cannot be started.
    fn open(&self, url: &str) -> Result<(), DownloadError>;
}

/// Request the default OS browser to open the entry's stable vendor information page.
///
/// # Errors
/// Returns an error if launching the browser fails.
pub fn open_official_source(entry: &Entry) -> Result<(), DownloadError> {
    open_official_source_with(entry, &SystemBrowserOpener)
}

/// Request the official page through an injected opener for deterministic tests.
///
/// # Errors
/// Returns an error if the injected opener fails.
pub fn open_official_source_with<O: OfficialSourceOpener + ?Sized>(
    entry: &Entry,
    opener: &O,
) -> Result<(), DownloadError> {
    opener.open(entry.source_url())
}

/// Request the default OS browser to open the optional official changelog page.
///
/// Does nothing when the selected record has no changelog URL.
///
/// # Errors
/// Returns an error if launching the browser fails.
pub fn open_official_changelog(entry: &Entry) -> Result<(), DownloadError> {
    open_official_changelog_with(entry, &SystemBrowserOpener)
}

/// Request the optional changelog through an injected opener for tests.
///
/// # Errors
/// Returns an error if the injected opener fails.
pub fn open_official_changelog_with<O: OfficialSourceOpener + ?Sized>(
    entry: &Entry,
    opener: &O,
) -> Result<(), DownloadError> {
    if let Some(url) = entry.changelog_url() {
        opener.open(url)?;
    }
    Ok(())
}

struct SystemBrowserOpener;

impl OfficialSourceOpener for SystemBrowserOpener {
    fn open(&self, url: &str) -> Result<(), DownloadError> {
        #[cfg(target_os = "macos")]
        let mut command = Command::new("open");
        #[cfg(target_os = "linux")]
        let mut command = Command::new("xdg-open");
        #[cfg(target_os = "windows")]
        let mut command = {
            let mut command = Command::new("rundll32.exe");
            command.arg("url.dll,FileProtocolHandler");
            command
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        return Err(DownloadError::Browser(
            "no default-browser launcher is configured for this platform".into(),
        ));
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            let child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .arg(url)
                .spawn()
                .map_err(|error| DownloadError::Browser(error.to_string()))?;
            std::thread::spawn(move || {
                let mut child = child;
                let _ = child.wait();
            });
            Ok(())
        }
    }
}
