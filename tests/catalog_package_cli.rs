use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use tempfile::TempDir;
use zip::{ZipWriter, write::SimpleFileOptions};

fn updater() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fixture(directory: &TempDir) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let payload = vec![0x5a; 51_500];
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file("firmware/kk3.bin", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(&payload).unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let archive_path = directory.path().join("main.zip");
    std::fs::write(&archive_path, &archive).unwrap();
    let catalog_path = directory.path().join("catalog.json");
    let entry = json!({
        "product": "kk3-max",
        "component": "main",
        "version": "6.1",
        "archive": "main.zip",
        "archive_size": archive.len(),
        "archive_sha256": sha256(&archive),
        "member": "firmware/kk3.bin",
        "member_size": payload.len(),
        "member_sha256": sha256(&payload),
        "payload_size": payload.len(),
        "payload_sha256": sha256(&payload),
        "source_url": "https://www.gulikit.com/newsinfo/123456.html",
        "parser_id": "kk3_main_binary_v1",
        "software_support": "supported",
        "hardware_acceptance": "unqualified",
        "hardware_evidence": null
    });
    let catalog = json!({"schema_version": 1, "entries": [entry]});
    let catalog_bytes = serde_json::to_vec(&catalog).unwrap();
    std::fs::write(&catalog_path, &catalog_bytes).unwrap();
    (archive_path, catalog_path, catalog_bytes)
}

#[test]
fn package_inspection_uses_explicit_catalog_without_claiming_vendor_authenticity() {
    let directory = TempDir::new().unwrap();
    let (archive, catalog, _) = fixture(&directory);
    let output = updater()
        .args(["package", "inspect"])
        .arg(archive)
        .args(["--catalog"])
        .arg(catalog)
        .args(["--model", "kk3-max", "--component", "main", "--json"])
        .assert()
        .success();
    let value: Value = serde_json::from_slice(&output.get_output().stdout).unwrap();
    assert_eq!(value["package"]["version"], "6.1");
    assert_eq!(value["catalog_authenticity"], "not_established");
}

#[test]
fn catalog_hash_or_model_rejection_precedes_native_device_attempt_and_record_creation() {
    let directory = TempDir::new().unwrap();
    let (archive, catalog_path, catalog_bytes) = fixture(&directory);
    let mut wrong_hash: Value = serde_json::from_slice(&catalog_bytes).unwrap();
    wrong_hash["entries"][0]["archive_sha256"] = json!("0".repeat(64));
    std::fs::write(&catalog_path, serde_json::to_vec(&wrong_hash).unwrap()).unwrap();
    let record = directory.path().join("attempt.jsonl");

    let output = updater()
        .args(["update"])
        .arg(&archive)
        .args(["--catalog"])
        .arg(&catalog_path)
        .args([
            "--model",
            "kk3-max",
            "--component",
            "main",
            "--confirm-ns39",
            "--record",
        ])
        .arg(&record)
        .arg("--json")
        .assert()
        .code(3);
    assert!(!record.exists());
    assert!(output.get_output().stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.get_output().stderr).unwrap();
    assert_eq!(error["error"]["kind"], "package_rejected");

    let mut wrong_model: Value = serde_json::from_slice(&catalog_bytes).unwrap();
    wrong_model["entries"][0]["product"] = json!("other-controller");
    wrong_model["entries"][0]["parser_id"] = json!("none");
    wrong_model["entries"][0]["software_support"] = json!("metadata_only");
    std::fs::write(&catalog_path, serde_json::to_vec(&wrong_model).unwrap()).unwrap();
    let output = updater()
        .args(["update"])
        .arg(&archive)
        .args(["--catalog"])
        .arg(&catalog_path)
        .args([
            "--model",
            "kk3-max",
            "--component",
            "main",
            "--confirm-ns39",
            "--record",
        ])
        .arg(&record)
        .arg("--json")
        .assert()
        .code(3);
    assert!(!record.exists());
    assert!(output.get_output().stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.get_output().stderr).unwrap();
    assert_eq!(error["error"]["kind"], "package_rejected");
}
