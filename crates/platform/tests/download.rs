use gulikit_catalog::{DownloadAvailability, Entry};
use gulikit_platform::download::{
    DownloadError, DownloadFetcher, DownloadResponse, DownloadResult, OfficialSourceOpener,
    download_release_with, open_official_source_with,
};
use sha2::Digest;
use std::{
    io::Cursor,
    sync::atomic::{AtomicUsize, Ordering},
};

const SEED: &str = include_str!("../../../catalog/official.json");

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}

fn synthetic_zip() -> Vec<u8> {
    let name = b"firmware.bin";
    let payload = b"test firmware payload";
    let checksum = crc32(payload);
    let size = u32::try_from(payload.len()).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&checksum.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(payload);
    let central_offset = u32::try_from(bytes.len()).unwrap();
    bytes.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&checksum.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&size.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(name);
    let central_size = u32::try_from(bytes.len()).unwrap() - central_offset;
    bytes.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&central_size.to_le_bytes());
    bytes.extend_from_slice(&central_offset.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn entry_for(bytes: &[u8], direct_url: bool, availability: DownloadAvailability) -> Entry {
    entry_with_hash(bytes, bytes, direct_url, availability)
}

fn entry_with_hash(
    archive_bytes: &[u8],
    hash_bytes: &[u8],
    direct_url: bool,
    availability: DownloadAvailability,
) -> Entry {
    let mut raw: serde_json::Value = serde_json::from_str(SEED).unwrap();
    raw["entries"][0]["archive_size"] = serde_json::json!(archive_bytes.len());
    raw["entries"][0]["archive_sha256"] = digest_hex(hash_bytes).into();
    raw["entries"][0]["availability"] = match availability {
        DownloadAvailability::Unknown => serde_json::Value::Null,
        DownloadAvailability::Available => "available".into(),
        DownloadAvailability::Unavailable => "unavailable".into(),
    };
    if direct_url {
        raw["entries"][0]["download_url"] = "https://www.gulikit.com/download/firmware.zip".into();
    }
    if availability == DownloadAvailability::Unknown {
        raw["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("availability");
    }
    Entry::parse(&serde_json::to_vec(&raw["entries"][0]).unwrap()).unwrap()
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    sha2::Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| [HEX[usize::from(*byte >> 4)], HEX[usize::from(*byte & 0x0f)]])
        .map(char::from)
        .collect()
}

type FakeResponse = (u16, Option<String>, Option<String>, Vec<u8>);

struct FakeFetcher {
    response: Option<FakeResponse>,
    calls: AtomicUsize,
}

struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("synthetic body read failure"))
    }
}

struct FailingBodyFetcher;

impl DownloadFetcher for FailingBodyFetcher {
    fn fetch(&self, _url: &str, _limit: u64) -> Result<DownloadResponse, DownloadError> {
        Ok(DownloadResponse {
            status: 200,
            content_encoding: None,
            content_length: None,
            body: Box::new(FailingReader),
        })
    }
}

impl FakeFetcher {
    fn successful(bytes: Vec<u8>) -> Self {
        Self {
            response: Some((
                200,
                Some("identity".into()),
                Some(bytes.len().to_string()),
                bytes,
            )),
            calls: AtomicUsize::new(0),
        }
    }

    fn configured(
        status: u16,
        encoding: Option<&str>,
        content_length: Option<&str>,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            response: Some((
                status,
                encoding.map(str::to_owned),
                content_length.map(str::to_owned),
                bytes,
            )),
            calls: AtomicUsize::new(0),
        }
    }
}

impl DownloadFetcher for FakeFetcher {
    fn fetch(&self, url: &str, limit: u64) -> Result<DownloadResponse, DownloadError> {
        assert_eq!(url, "https://www.gulikit.com/download/firmware.zip");
        assert!(limit <= gulikit_catalog::MAX_ARCHIVE_SIZE);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (status, content_encoding, content_length, body) = self.response.clone().unwrap();
        Ok(DownloadResponse {
            status,
            content_encoding,
            content_length,
            body: Box::new(Cursor::new(body)),
        })
    }
}

#[test]
fn downloads_exact_archive_and_never_overwrites_existing_destination() {
    let bytes = synthetic_zip();
    let entry = entry_for(&bytes, true, DownloadAvailability::Available);
    let fetcher = FakeFetcher::successful(bytes.clone());
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("firmware.zip");
    let result = download_release_with(&entry, &destination, &mut || false, &fetcher).unwrap();
    assert_eq!(
        result,
        DownloadResult::Downloaded {
            path: destination.clone()
        }
    );
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

    let replacement = FakeFetcher::successful(synthetic_zip());
    assert!(matches!(
        download_release_with(&entry, &destination, &mut || false, &replacement),
        Err(DownloadError::Io(_))
    ));
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
}

#[test]
fn missing_direct_url_returns_manual_source_without_network_or_filesystem_effects() {
    let entry = entry_for(b"archive", false, DownloadAvailability::Unknown);
    let fetcher = FakeFetcher::successful(b"archive".to_vec());
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("missing.zip");
    assert_eq!(
        download_release_with(&entry, &destination, &mut || false, &fetcher).unwrap(),
        DownloadResult::ManualRequired {
            source_url: entry.source_url().to_owned()
        }
    );
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    assert!(!destination.exists());
}

#[test]
fn availability_is_independent_of_direct_link_presence() {
    let bytes = synthetic_zip();
    let available_without_link = entry_for(&bytes, false, DownloadAvailability::Available);
    let fetcher = FakeFetcher::successful(bytes.clone());
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("manual.zip");
    assert!(matches!(
        download_release_with(
            &available_without_link,
            &destination,
            &mut || false,
            &fetcher
        )
        .unwrap(),
        DownloadResult::ManualRequired { .. }
    ));
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    assert!(!destination.exists());

    let unavailable_with_link = entry_for(&bytes, true, DownloadAvailability::Unavailable);
    let fetcher = FakeFetcher::successful(bytes);
    assert!(matches!(
        download_release_with(
            &unavailable_with_link,
            &destination,
            &mut || false,
            &fetcher
        ),
        Err(DownloadError::Unavailable)
    ));
    assert_eq!(fetcher.calls.load(Ordering::SeqCst), 0);
    assert!(!destination.exists());
}

#[test]
fn invalid_responses_hash_length_and_cancellation_leave_no_destination() {
    let bytes = synthetic_zip();
    let entry = entry_for(&bytes, true, DownloadAvailability::Available);
    let directory = tempfile::tempdir().unwrap();
    let cases = [
        (
            FakeFetcher::configured(302, None, None, bytes.clone()),
            DownloadError::Status(302),
        ),
        (
            FakeFetcher::configured(404, None, None, bytes.clone()),
            DownloadError::Status(404),
        ),
        (
            FakeFetcher::configured(200, Some("gzip"), None, bytes.clone()),
            DownloadError::CompressedResponse,
        ),
        (
            FakeFetcher::configured(200, None, Some("unknown"), bytes.clone()),
            DownloadError::InvalidContentLength,
        ),
        (
            FakeFetcher::configured(200, None, Some("1"), bytes.clone()),
            DownloadError::LengthHeaderMismatch,
        ),
        (
            FakeFetcher::configured(200, None, None, bytes[..bytes.len() - 1].to_vec()),
            DownloadError::LengthMismatch,
        ),
        (
            FakeFetcher::configured(200, None, None, [bytes.clone(), vec![0]].concat()),
            DownloadError::TooLarge,
        ),
    ];
    for (index, (fetcher, expected)) in cases.into_iter().enumerate() {
        let destination = directory.path().join(format!("case-{index}.zip"));
        let result = download_release_with(&entry, &destination, &mut || false, &fetcher);
        assert!(
            matches_error(result, &expected),
            "unexpected error for case {index}"
        );
        assert!(!destination.exists());
    }

    let wrong_hash = entry_with_hash(&bytes, b"different", true, DownloadAvailability::Available);
    let fetcher = FakeFetcher::successful(bytes);
    let destination = directory.path().join("bad-hash.zip");
    assert!(matches!(
        download_release_with(&wrong_hash, &destination, &mut || false, &fetcher),
        Err(DownloadError::HashMismatch)
    ));
    assert!(!destination.exists());

    let destination = directory.path().join("read-error.zip");
    assert!(matches!(
        download_release_with(&entry, &destination, &mut || false, &FailingBodyFetcher),
        Err(DownloadError::Request(_))
    ));
    assert!(!destination.exists());

    let fetcher = FakeFetcher::successful(synthetic_zip());
    let destination = directory.path().join("cancelled.zip");
    let mut cancellation_checks = 0;
    let result = download_release_with(
        &entry,
        &destination,
        &mut || {
            cancellation_checks += 1;
            cancellation_checks >= 3
        },
        &fetcher,
    );
    assert!(matches!(result, Err(DownloadError::Cancelled)));
    assert!(!destination.exists());
}

fn matches_error<T>(result: Result<T, DownloadError>, expected: &DownloadError) -> bool {
    match (result, expected) {
        (Err(DownloadError::Status(actual)), DownloadError::Status(expected)) => {
            actual == *expected
        }
        (Err(DownloadError::CompressedResponse), DownloadError::CompressedResponse)
        | (Err(DownloadError::InvalidContentLength), DownloadError::InvalidContentLength)
        | (Err(DownloadError::LengthHeaderMismatch), DownloadError::LengthHeaderMismatch)
        | (Err(DownloadError::LengthMismatch), DownloadError::LengthMismatch)
        | (Err(DownloadError::TooLarge), DownloadError::TooLarge) => true,
        _ => false,
    }
}

struct RecordingOpener {
    opened: std::cell::RefCell<Option<String>>,
}

impl OfficialSourceOpener for RecordingOpener {
    fn open(&self, url: &str) -> Result<(), DownloadError> {
        *self.opened.borrow_mut() = Some(url.to_owned());
        Ok(())
    }
}

#[test]
fn official_source_opens_vendor_information_page_not_direct_download() {
    let entry = entry_for(b"archive", true, DownloadAvailability::Available);
    let opener = RecordingOpener {
        opened: std::cell::RefCell::new(None),
    };
    open_official_source_with(&entry, &opener).unwrap();
    assert_eq!(
        opener.opened.borrow().as_deref(),
        Some("https://www.gulikit.com/newsinfo/887152.html")
    );
}

#[test]
fn absent_optional_changelog_does_not_invoke_browser_opener() {
    let entry = entry_for(b"archive", false, DownloadAvailability::Unknown);
    let opener = RecordingOpener {
        opened: std::cell::RefCell::new(None),
    };
    gulikit_platform::download::open_official_changelog_with(&entry, &opener).unwrap();
    assert_eq!(*opener.opened.borrow(), None);
}

struct FailingOpener;

impl OfficialSourceOpener for FailingOpener {
    fn open(&self, _url: &str) -> Result<(), DownloadError> {
        Err(DownloadError::Browser("synthetic launcher failure".into()))
    }
}

#[test]
fn source_page_launcher_errors_are_returned_without_claiming_success() {
    let entry = entry_for(b"archive", false, DownloadAvailability::Unknown);
    assert!(matches!(
        open_official_source_with(&entry, &FailingOpener),
        Err(DownloadError::Browser(_))
    ));
}
