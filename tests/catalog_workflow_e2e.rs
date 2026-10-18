use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::{ZipWriter, write::SimpleFileOptions};

const SOURCE_URL: &str = "https://www.gulikit.com/newsinfo/123456.html";
const PAYLOAD_SIZE: usize = 51_500;

struct WorkflowFixture {
    binary: PathBuf,
    directory: TempDir,
    archive: PathBuf,
    page: PathBuf,
    request: PathBuf,
    payload: Vec<u8>,
}

impl WorkflowFixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let binary = assert_cmd::cargo::cargo_bin!("gulikit-updater").to_path_buf();
        let payload = vec![0x5a; PAYLOAD_SIZE];
        let archive = directory.path().join("official.zip");
        std::fs::write(&archive, zip_bytes(&payload)).unwrap();
        let page = directory.path().join("release-page.html");
        std::fs::write(
            &page,
            b"Official release page snapshot: KK3 Max main firmware 6.1",
        )
        .unwrap();
        let request = directory.path().join("request.json");
        std::fs::write(
            &request,
            serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "product": "kk3-max",
                "component": "main",
                "version": "6.1",
                "archive": "official.zip",
                "member": "firmware.bin",
                "source_url": SOURCE_URL,
                "observed_at": "2026-10-18T00:00:00Z",
                "vendor_verification": {
                    "status": "not_published",
                    "source_url": SOURCE_URL,
                    "note": "No signature/checksum on reviewed page."
                }
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            binary,
            directory,
            archive,
            page,
            request,
            payload,
        }
    }

    fn command(&self) -> Command {
        Command::new(&self.binary)
    }
}

fn zip_bytes(payload: &[u8]) -> Vec<u8> {
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file("firmware.bin", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(payload).unwrap();
    writer.finish().unwrap().into_inner()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_stdout(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn source_catalog() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/catalog/official.json"
    ))
}

#[test]
fn public_cli_catalog_review_to_offline_manual_acquisition_lifecycle() {
    let fixture = WorkflowFixture::new();
    let catalog = prepare_and_publish_catalog(&fixture);
    let cache = refresh_cache_and_check_offline_reads(&fixture, &catalog);
    check_manual_download_and_cached_package_inspection(&fixture, &cache);
    check_changed_archive_and_component_rejections(&fixture, &cache);
}

fn prepare_and_publish_catalog(fixture: &WorkflowFixture) -> PathBuf {
    // The exact same compiled executable cannot admit this release through its
    // built-in catalog before the operator explicitly publishes reviewed metadata.
    let without_catalog = fixture
        .command()
        .args(["package", "inspect"])
        .arg(&fixture.archive)
        .args(["--model", "kk3-max", "--component", "main", "--json"])
        .assert()
        .code(3);
    assert!(without_catalog.get_output().stdout.is_empty());
    assert_eq!(
        parse_stdout(without_catalog.get_output().stderr.as_slice())
            .get("error")
            .and_then(|error| error.get("kind"))
            .and_then(Value::as_str),
        Some("package_rejected")
    );

    let candidate = fixture.directory.path().join("candidate.json");
    let prepared = fixture
        .command()
        .args(["catalog", "prepare", "--request"])
        .arg(&fixture.request)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&candidate)
        .arg("--json")
        .assert()
        .success();
    let prepared_report = parse_stdout(&prepared.get_output().stdout);
    let candidate_json: Value =
        serde_json::from_slice(&std::fs::read(&candidate).unwrap()).unwrap();
    assert_eq!(prepared_report["candidate"], candidate_json);
    assert_eq!(prepared_report["authorizes_firmware"], false);
    assert_eq!(candidate_json["entry"]["software_support"], "metadata_only");
    assert_eq!(
        candidate_json["entry"]["hardware_acceptance"],
        "unqualified"
    );
    assert_eq!(
        candidate_json["vendor_verification"]["status"],
        "not_published"
    );
    assert_eq!(candidate_json["entry"]["payload_size"], PAYLOAD_SIZE);
    assert_eq!(
        candidate_json["entry"]["payload_sha256"],
        sha256(&fixture.payload)
    );

    let catalog = fixture.directory.path().join("reviewed-catalog.json");
    let original_seed = std::fs::read(source_catalog()).unwrap();
    let published = fixture
        .command()
        .args(["catalog", "publish", "--candidate"])
        .arg(&candidate)
        .args(["--catalog"])
        .arg(source_catalog())
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&catalog)
        .arg("--json")
        .assert()
        .success();
    let published_report = parse_stdout(&published.get_output().stdout);
    let published_catalog: Value =
        serde_json::from_slice(&std::fs::read(&catalog).unwrap()).unwrap();
    assert_eq!(published_report["catalog"], published_catalog);
    assert_eq!(published_report["authorizes_firmware"], false);
    assert_eq!(published_catalog["entries"].as_array().unwrap().len(), 5);
    assert!(
        published_catalog["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["product"] == "kk3-max"
                    && entry["component"] == "main"
                    && entry["version"] == "6.1"
                    && entry["software_support"] == "supported"
                    && entry["hardware_acceptance"] == "unqualified"
                    && entry["vendor_verification"]["status"] == "not_published"
            })
    );
    assert_eq!(std::fs::read(source_catalog()).unwrap(), original_seed);

    catalog
}

fn refresh_cache_and_check_offline_reads(fixture: &WorkflowFixture, catalog: &Path) -> PathBuf {
    let cache = fixture.directory.path().join("catalog-cache.json");
    let refresh = fixture
        .command()
        .args(["catalog", "refresh", "--file"])
        .arg(catalog)
        .args(["--cache"])
        .arg(&cache)
        .arg("--json")
        .assert()
        .success();
    let refresh_report = parse_stdout(&refresh.get_output().stdout);
    assert_eq!(refresh_report["authorizes_firmware"], false);
    assert_eq!(refresh_report["trust"], "unverified");
    assert_eq!(
        refresh_report["catalog"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    let valid_cache = std::fs::read(&cache).unwrap();

    let invalid = fixture.directory.path().join("invalid-catalog.json");
    std::fs::write(&invalid, b"not a catalog").unwrap();
    let rejected_refresh = fixture
        .command()
        .args(["catalog", "refresh", "--file"])
        .arg(&invalid)
        .args(["--cache"])
        .arg(&cache)
        .arg("--json")
        .assert()
        .code(3);
    assert!(rejected_refresh.get_output().stdout.is_empty());
    assert_eq!(std::fs::read(&cache).unwrap(), valid_cache);

    let cached = fixture
        .command()
        .args(["catalog", "cached", "--cache"])
        .arg(&cache)
        .arg("--json")
        .assert()
        .success();
    let cached_report = parse_stdout(&cached.get_output().stdout);
    assert_eq!(cached_report["authorizes_firmware"], false);
    assert_eq!(cached_report, refresh_report);

    let releases = fixture
        .command()
        .args(["catalog", "releases", "--catalog"])
        .arg(&cache)
        .args(["--product", "kk3-max", "--component", "main", "--json"])
        .assert()
        .success();
    let release_report = parse_stdout(&releases.get_output().stdout);
    assert_eq!(release_report["authorizes_firmware"], false);
    assert!(
        release_report["releases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["version"] == "6.1" && entry["component"] == "main" })
    );

    cache
}

fn check_manual_download_and_cached_package_inspection(fixture: &WorkflowFixture, cache: &Path) {
    let download_path = fixture.directory.path().join("manual-download.zip");
    let download = fixture
        .command()
        .args(["catalog", "download"])
        .args(["--catalog"])
        .arg(cache)
        .args([
            "--product",
            "kk3-max",
            "--component",
            "main",
            "--version",
            "6.1",
            "--output",
        ])
        .arg(&download_path)
        .arg("--json")
        .assert()
        .success();
    let download_report = parse_stdout(&download.get_output().stdout);
    assert_eq!(download_report["release"]["version"], "6.1");
    assert_eq!(download_report["download"]["status"], "manual_required");
    assert_eq!(download_report["authorizes_firmware"], false);
    assert!(!download_path.exists());

    let inspected = fixture
        .command()
        .args(["package", "inspect"])
        .arg(&fixture.archive)
        .args(["--catalog"])
        .arg(cache)
        .args(["--model", "kk3-max", "--component", "main", "--json"])
        .assert()
        .success();
    let inspection = parse_stdout(&inspected.get_output().stdout);
    assert_eq!(inspection["package"]["version"], "6.1");
    assert_eq!(inspection["catalog_authenticity"], "not_established");
    assert_eq!(inspection["authorizes_firmware"], false);
}

fn check_changed_archive_and_component_rejections(fixture: &WorkflowFixture, cache: &Path) {
    // A different, well-formed ZIP is rebuilt so its internal CRC is valid; the
    // selected catalog hashes must still reject it as the wrong archive bytes.
    let changed_archive = fixture.directory.path().join("valid-crc-changed.zip");
    let changed_payload = vec![0x5b; PAYLOAD_SIZE];
    std::fs::write(&changed_archive, zip_bytes(&changed_payload)).unwrap();
    let wrong_archive = fixture
        .command()
        .args(["package", "inspect"])
        .arg(&changed_archive)
        .args(["--catalog"])
        .arg(cache)
        .args(["--model", "kk3-max", "--component", "main", "--json"])
        .assert()
        .code(3);
    assert!(wrong_archive.get_output().stdout.is_empty());

    let wrong_component = fixture
        .command()
        .args(["package", "inspect"])
        .arg(&fixture.archive)
        .args(["--catalog"])
        .arg(cache)
        .args(["--model", "kk3-max", "--component", "bluetooth", "--json"])
        .assert()
        .code(3);
    assert!(wrong_component.get_output().stdout.is_empty());
}
