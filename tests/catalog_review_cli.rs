use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::{ZipWriter, write::SimpleFileOptions};

const SOURCE_URL: &str = "https://www.gulikit.com/newsinfo/123456.html";
const PAYLOAD_SIZE: usize = 51_500;

struct Fixture {
    directory: TempDir,
    archive: PathBuf,
    page: PathBuf,
    request: PathBuf,
    payload: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let payload = vec![0x5a; PAYLOAD_SIZE];
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file("firmware.bin", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&payload).unwrap();
        let archive_bytes = writer.finish().unwrap().into_inner();
        let archive = directory.path().join("official.zip");
        std::fs::write(&archive, archive_bytes).unwrap();

        let page = directory.path().join("release-page.html");
        std::fs::write(
            &page,
            b"Official release page snapshot: KK3 Max main firmware 6.1",
        )
        .unwrap();

        let request = directory.path().join("request.json");
        write_request(&request, SOURCE_URL, "not_published", None);
        Self {
            directory,
            archive,
            page,
            request,
            payload,
        }
    }

    fn prepare(&self, output: &Path) -> Value {
        let result = updater()
            .args(["catalog", "prepare", "--request"])
            .arg(&self.request)
            .args(["--archive"])
            .arg(&self.archive)
            .args(["--page"])
            .arg(&self.page)
            .args(["--output"])
            .arg(output)
            .arg("--json")
            .assert()
            .success();
        serde_json::from_slice(&result.get_output().stdout).unwrap()
    }

    fn prepare_with_previous(&self, output: &Path, previous: &Path) -> Value {
        let result = updater()
            .args(["catalog", "prepare", "--request"])
            .arg(&self.request)
            .args(["--archive"])
            .arg(&self.archive)
            .args(["--page"])
            .arg(&self.page)
            .args(["--previous"])
            .arg(previous)
            .args(["--output"])
            .arg(output)
            .arg("--json")
            .assert()
            .success();
        serde_json::from_slice(&result.get_output().stdout).unwrap()
    }

    fn update_archive_payload(&self, payload: &[u8]) {
        std::fs::write(&self.archive, zip_bytes(payload)).unwrap();
    }

    fn publish(&self, candidate: &Path, catalog: &Path, output: &Path) -> Value {
        let result = updater()
            .args(["catalog", "publish", "--candidate"])
            .arg(candidate)
            .args(["--catalog"])
            .arg(catalog)
            .args(["--archive"])
            .arg(&self.archive)
            .args(["--page"])
            .arg(&self.page)
            .args(["--output"])
            .arg(output)
            .arg("--json")
            .assert()
            .success();
        serde_json::from_slice(&result.get_output().stdout).unwrap()
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

fn updater() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_request(path: &Path, source_url: &str, verification: &str, extra: Option<Value>) {
    let mut request = json!({
        "schema_version": 1,
        "product": "kk3-max",
        "component": "main",
        "version": "6.1",
        "archive": "official.zip",
        "member": "firmware.bin",
        "source_url": source_url,
        "observed_at": "2026-10-18T00:00:00Z",
        "vendor_verification": if verification == "signature" {
            json!({"status": verification, "source_url": source_url, "format": "vendor-detached-signature"})
        } else if verification == "sha256" {
            json!({"status": verification, "source_url": source_url, "sha256": "0".repeat(64)})
        } else if verification == "unknown" {
            json!({"status": verification})
        } else {
            json!({
                "status": verification,
                "source_url": source_url,
                "note": "No signature/checksum on reviewed page."
            })
        }
    });
    if let Some(extra) = extra {
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
    }
    std::fs::write(path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();
}

fn seed_catalog(path: &Path) -> Vec<u8> {
    let bytes = include_bytes!("../catalog/official.json").to_vec();
    std::fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn prepare_records_page_and_archive_evidence_without_authorizing_firmware() {
    let fixture = Fixture::new();
    let candidate_path = fixture.directory.path().join("candidate.json");
    let report = fixture.prepare(&candidate_path);
    let candidate: Value =
        serde_json::from_slice(&std::fs::read(&candidate_path).unwrap()).unwrap();

    assert_eq!(report["candidate"], candidate);
    assert_eq!(report["candidate"]["kind"], "release_candidate");
    assert_eq!(
        report["output"].as_str(),
        Some(candidate_path.to_string_lossy().as_ref())
    );
    assert_eq!(report["authorizes_firmware"], false);
    assert_eq!(candidate["schema_version"], 1);
    assert_eq!(candidate["kind"], "release_candidate");
    assert_eq!(candidate["entry"]["product"], "kk3-max");
    assert_eq!(candidate["entry"]["component"], "main");
    assert_eq!(candidate["entry"]["version"], "6.1");
    assert_eq!(candidate["entry"]["software_support"], "metadata_only");
    assert_eq!(candidate["entry"]["hardware_acceptance"], "unqualified");
    assert_eq!(
        candidate["source_page"]["size"],
        std::fs::metadata(&fixture.page).unwrap().len()
    );
    assert_eq!(
        candidate["source_page"]["sha256"],
        sha256(&std::fs::read(&fixture.page).unwrap())
    );
    assert_eq!(candidate["observed_at"], "2026-10-18T00:00:00Z");
    assert_eq!(candidate["vendor_verification"]["status"], "not_published");
    assert_eq!(candidate["vendor_verification"]["source_url"], SOURCE_URL);
    assert_eq!(candidate["entry"]["payload_size"], fixture.payload.len());
    assert_eq!(
        candidate["entry"]["payload_sha256"],
        sha256(&fixture.payload)
    );

    let inspect = updater()
        .args(["catalog", "inspect"])
        .arg(&candidate_path)
        .arg("--json")
        .assert()
        .code(3);
    assert!(inspect.get_output().stdout.is_empty());
    let error: Value = serde_json::from_slice(&inspect.get_output().stderr).unwrap();
    assert_eq!(error["error"]["kind"], "catalog_rejected");
}

#[test]
fn publish_rechecks_candidate_and_archive_then_preserves_catalog_history() {
    let fixture = Fixture::new();
    let candidate_path = fixture.directory.path().join("candidate.json");
    let candidate_report = fixture.prepare(&candidate_path);
    assert_eq!(candidate_report["authorizes_firmware"], false);
    let input_catalog = fixture.directory.path().join("input-catalog.json");
    let original_catalog = seed_catalog(&input_catalog);
    let output_catalog = fixture.directory.path().join("published.json");

    let report = fixture.publish(&candidate_path, &input_catalog, &output_catalog);
    assert_eq!(report["catalog"]["schema_version"], 1);
    assert_eq!(
        report["output"].as_str(),
        Some(output_catalog.to_string_lossy().as_ref())
    );
    assert_eq!(report["authorizes_firmware"], false);
    assert_eq!(std::fs::read(&input_catalog).unwrap(), original_catalog);
    let published: Value =
        serde_json::from_slice(&std::fs::read(&output_catalog).unwrap()).unwrap();
    assert_eq!(report["catalog"], published);
    let original: Value = serde_json::from_slice(&original_catalog).unwrap();
    assert_eq!(published["schema_version"], 1);
    assert_eq!(
        published["entries"].as_array().unwrap().len(),
        original["entries"].as_array().unwrap().len() + 1
    );
    for historical in original["entries"].as_array().unwrap() {
        assert!(
            published["entries"]
                .as_array()
                .unwrap()
                .contains(historical)
        );
    }
    let entry = published["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            entry["version"] == "6.1"
                && entry["product"] == "kk3-max"
                && entry["component"] == "main"
        })
        .unwrap();
    assert_eq!(entry["software_support"], "supported");
    assert_eq!(entry["hardware_acceptance"], "unqualified");
    assert_eq!(
        entry["archive_size"],
        std::fs::metadata(&fixture.archive).unwrap().len()
    );
    assert_eq!(
        entry["archive_sha256"],
        sha256(&std::fs::read(&fixture.archive).unwrap())
    );
    assert_eq!(entry["member"], "firmware.bin");
    assert_eq!(entry["payload_size"], PAYLOAD_SIZE);
    assert_eq!(entry["payload_sha256"], sha256(&fixture.payload));
    assert_eq!(entry["source_url"], SOURCE_URL);

    let second_output = fixture.directory.path().join("must-not-clobber.json");
    std::fs::write(&second_output, b"preserve existing output").unwrap();
    let refused = updater()
        .args(["catalog", "publish", "--candidate"])
        .arg(&candidate_path)
        .args(["--catalog"])
        .arg(&output_catalog)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&second_output)
        .arg("--json")
        .assert()
        .code(4);
    assert!(refused.get_output().stdout.is_empty());
    assert_eq!(
        std::fs::read(&second_output).unwrap(),
        b"preserve existing output"
    );

    let same_input_output = fixture.directory.path().join("same-input-output.json");
    let original = seed_catalog(&same_input_output);
    let rejected = updater()
        .args(["catalog", "publish", "--candidate"])
        .arg(&candidate_path)
        .args(["--catalog"])
        .arg(&same_input_output)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&same_input_output)
        .arg("--json")
        .assert()
        .code(4);
    assert!(rejected.get_output().stdout.is_empty());
    assert_eq!(std::fs::read(&same_input_output).unwrap(), original);
}

#[test]
fn publish_rejects_changed_archive_or_page_without_creating_output() {
    for changed in ["archive", "page"] {
        let fixture = Fixture::new();
        let candidate_path = fixture.directory.path().join("candidate.json");
        fixture.prepare(&candidate_path);
        if changed == "archive" {
            let mut changed_payload = fixture.payload.clone();
            changed_payload[0] ^= 1;
            fixture.update_archive_payload(&changed_payload);
        } else {
            std::fs::write(&fixture.page, b"changed official page snapshot").unwrap();
        }
        let input_catalog = fixture.directory.path().join("catalog.json");
        seed_catalog(&input_catalog);
        let output_catalog = fixture.directory.path().join("must-not-exist.json");
        let result = updater()
            .args(["catalog", "publish", "--candidate"])
            .arg(&candidate_path)
            .args(["--catalog"])
            .arg(&input_catalog)
            .args(["--archive"])
            .arg(&fixture.archive)
            .args(["--page"])
            .arg(&fixture.page)
            .args(["--output"])
            .arg(&output_catalog)
            .arg("--json")
            .assert()
            .code(3);
        assert!(result.get_output().stdout.is_empty());
        assert!(!output_catalog.exists());
    }
}

#[test]
fn prepare_links_previous_candidate_page_evidence() {
    let fixture = Fixture::new();
    let old_page = fixture.directory.path().join("old-page.html");
    std::fs::write(&old_page, b"previous observed page snapshot").unwrap();
    let old_candidate_path = fixture.directory.path().join("previous.json");
    let old_report = updater()
        .args(["catalog", "prepare", "--request"])
        .arg(&fixture.request)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&old_page)
        .args(["--output"])
        .arg(&old_candidate_path)
        .arg("--json")
        .assert()
        .success();
    assert_eq!(
        serde_json::from_slice::<Value>(&old_report.get_output().stdout).unwrap()["authorizes_firmware"],
        false
    );
    let old_candidate: Value =
        serde_json::from_slice(&std::fs::read(&old_candidate_path).unwrap()).unwrap();

    let current_candidate_path = fixture.directory.path().join("current.json");
    fixture.prepare_with_previous(&current_candidate_path, &old_candidate_path);
    let current_candidate: Value =
        serde_json::from_slice(&std::fs::read(&current_candidate_path).unwrap()).unwrap();
    assert_eq!(
        current_candidate["previous_page_sha256"],
        old_candidate["source_page"]["sha256"]
    );
    assert_ne!(
        current_candidate["source_page"]["sha256"],
        old_candidate["source_page"]["sha256"]
    );
}

#[test]
fn prepare_rejects_untrusted_request_shapes_and_urls() {
    let fixture = Fixture::new();
    for (source, verification, extra) in [
        ("file:///tmp/page.html", "not_published", None),
        ("https://example.com/release.html", "not_published", None),
        (
            SOURCE_URL,
            "not_published",
            Some(json!({"unexpected": true})),
        ),
    ] {
        write_request(&fixture.request, source, verification, extra);
        let output = fixture.directory.path().join("rejected.json");
        let result = updater()
            .args(["catalog", "prepare", "--request"])
            .arg(&fixture.request)
            .args(["--archive"])
            .arg(&fixture.archive)
            .args(["--page"])
            .arg(&fixture.page)
            .args(["--output"])
            .arg(&output)
            .arg("--json")
            .assert()
            .code(3);
        assert!(result.get_output().stdout.is_empty());
        assert!(!output.exists());
    }

    std::fs::write(&fixture.request, b"{").unwrap();
    let output = fixture.directory.path().join("malformed.json");
    let result = updater()
        .args(["catalog", "prepare", "--request"])
        .arg(&fixture.request)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&output)
        .arg("--json")
        .assert()
        .code(3);
    assert!(result.get_output().stdout.is_empty());
    assert!(!output.exists());

    let missing = fixture.directory.path().join("absent-request.json");
    let io_error = updater()
        .args(["catalog", "prepare", "--request"])
        .arg(missing)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&output)
        .arg("--json")
        .assert()
        .code(4);
    assert!(io_error.get_output().stdout.is_empty());
    let error: Value = serde_json::from_slice(&io_error.get_output().stderr).unwrap();
    assert_eq!(error["error"]["kind"], "catalog_review_io");
    assert!(!output.exists());
}

#[test]
fn publish_rejects_unknown_vendor_verification_and_checksum_mismatch() {
    for verification in ["unknown", "signature"] {
        let fixture = Fixture::new();
        write_request(&fixture.request, SOURCE_URL, verification, None);
        let candidate_path = fixture.directory.path().join("candidate.json");
        fixture.prepare(&candidate_path);
        let input_catalog = fixture.directory.path().join("catalog.json");
        seed_catalog(&input_catalog);
        let output = fixture.directory.path().join("published.json");
        let rejected = updater()
            .args(["catalog", "publish", "--candidate"])
            .arg(&candidate_path)
            .args(["--catalog"])
            .arg(&input_catalog)
            .args(["--archive"])
            .arg(&fixture.archive)
            .args(["--page"])
            .arg(&fixture.page)
            .args(["--output"])
            .arg(&output)
            .arg("--json")
            .assert()
            .code(3);
        assert!(rejected.get_output().stdout.is_empty());
        assert!(!output.exists());
    }

    let fixture = Fixture::new();
    write_request(&fixture.request, SOURCE_URL, "sha256", None);
    let output = fixture.directory.path().join("sha-mismatch.json");
    let rejected = updater()
        .args(["catalog", "prepare", "--request"])
        .arg(&fixture.request)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&output)
        .arg("--json")
        .assert()
        .code(3);
    assert!(rejected.get_output().stdout.is_empty());
    assert!(!output.exists());

    let fixture = Fixture::new();
    let candidate_path = fixture.directory.path().join("candidate.json");
    fixture.prepare(&candidate_path);
    let mut candidate: Value =
        serde_json::from_slice(&std::fs::read(&candidate_path).unwrap()).unwrap();
    candidate["entry"]["payload_sha256"] = json!("0".repeat(64));
    std::fs::write(
        &candidate_path,
        serde_json::to_vec_pretty(&candidate).unwrap(),
    )
    .unwrap();
    let input_catalog = fixture.directory.path().join("catalog.json");
    seed_catalog(&input_catalog);
    let output = fixture.directory.path().join("published.json");
    let rejected = updater()
        .args(["catalog", "publish", "--candidate"])
        .arg(&candidate_path)
        .args(["--catalog"])
        .arg(&input_catalog)
        .args(["--archive"])
        .arg(&fixture.archive)
        .args(["--page"])
        .arg(&fixture.page)
        .args(["--output"])
        .arg(&output)
        .arg("--json")
        .assert()
        .code(3);
    assert!(rejected.get_output().stdout.is_empty());
    assert!(!output.exists());
}

#[test]
fn matching_vendor_checksum_is_a_consistency_claim_not_authenticity() {
    let fixture = Fixture::new();
    write_request(&fixture.request, SOURCE_URL, "sha256", None);
    let mut request: Value =
        serde_json::from_slice(&std::fs::read(&fixture.request).unwrap()).unwrap();
    request["vendor_verification"]["sha256"] =
        json!(sha256(&std::fs::read(&fixture.archive).unwrap()));
    std::fs::write(
        &fixture.request,
        serde_json::to_vec_pretty(&request).unwrap(),
    )
    .unwrap();

    let candidate_path = fixture.directory.path().join("candidate.json");
    let prepared = fixture.prepare(&candidate_path);
    assert_eq!(prepared["authorizes_firmware"], false);
    let catalog = fixture.directory.path().join("catalog.json");
    seed_catalog(&catalog);
    let output = fixture.directory.path().join("published.json");
    let published = fixture.publish(&candidate_path, &catalog, &output);
    assert_eq!(published["authorizes_firmware"], false);
    let released = published["catalog"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["version"] == "6.1" && entry["component"] == "main")
        .unwrap();
    assert_eq!(released["vendor_verification"]["status"], "sha256");
    assert_eq!(released["vendor_verification"]["source_url"], SOURCE_URL);
    assert_eq!(
        released["vendor_verification"]["sha256"],
        released["archive_sha256"]
    );
    assert_eq!(
        published["catalog"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["version"] == "6.1" && entry["component"] == "main")
            .unwrap()["archive_sha256"],
        sha256(&std::fs::read(&fixture.archive).unwrap())
    );
}

#[test]
fn catalog_diff_is_deterministic_and_reports_metadata_changes_without_authority() {
    let fixture = Fixture::new();
    let candidate_path = fixture.directory.path().join("candidate.json");
    fixture.prepare(&candidate_path);
    let old_catalog = fixture.directory.path().join("old.json");
    seed_catalog(&old_catalog);
    let new_catalog = fixture.directory.path().join("new.json");
    fixture.publish(&candidate_path, &old_catalog, &new_catalog);

    let run_diff = || {
        let result = updater()
            .args(["catalog", "diff", "--previous"])
            .arg(&old_catalog)
            .args(["--proposed"])
            .arg(&new_catalog)
            .arg("--json")
            .assert()
            .success();
        result.get_output().stdout.clone()
    };
    let first = run_diff();
    assert_eq!(first, run_diff());
    let report: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(report["authorizes_firmware"], false);
    assert!(report["diff"].to_string().contains("6.1"));
    assert!(!report["diff"].is_null());
}
