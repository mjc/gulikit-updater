use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;

fn updater() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
}

fn refresh(file: &Path, cache: &Path) -> assert_cmd::assert::Assert {
    updater()
        .args(["catalog", "refresh", "--file"])
        .arg(file)
        .arg("--cache")
        .arg(cache)
        .arg("--json")
        .assert()
}

#[test]
fn caches_metadata_without_keys_and_reads_it_offline_without_authenticity_claims() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("catalog.json");
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/catalog/official.json"
    ));
    let result = refresh(source, &cache).success();
    let report: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(report["trust"], "unverified");
    assert_eq!(report["authorizes_firmware"], false);
    assert_eq!(report["catalog"]["entries"].as_array().unwrap().len(), 4);
    let cached = updater()
        .args(["catalog", "cached", "--cache"])
        .arg(&cache)
        .arg("--json")
        .assert()
        .success();
    let offline: Value = serde_json::from_slice(&cached.get_output().stdout).unwrap();
    assert_eq!(offline, report);
    assert_eq!(
        std::fs::read(&cache).unwrap(),
        std::fs::read(source).unwrap()
    );
}

#[test]
fn rejected_refresh_preserves_cache_and_has_no_success_output() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory.path().join("catalog.json");
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/catalog/official.json"
    ));
    refresh(source, &cache).success();
    let original = std::fs::read(&cache).unwrap();
    let invalid = directory.path().join("invalid.json");
    for bytes in [
        b"{}".to_vec(),
        vec![b' '; gulikit_catalog::MAX_CATALOG_BYTES + 1],
    ] {
        std::fs::write(&invalid, bytes).unwrap();
        let result = refresh(&invalid, &cache).code(3);
        assert!(result.get_output().stdout.is_empty());
        assert_eq!(std::fs::read(&cache).unwrap(), original);
    }
    let result = updater()
        .args([
            "catalog",
            "refresh",
            "--url",
            "http://gulikit.com/catalog.json",
            "--cache",
        ])
        .arg(&cache)
        .arg("--json")
        .assert()
        .code(3);
    assert!(result.get_output().stdout.is_empty());
    assert_eq!(std::fs::read(&cache).unwrap(), original);
}

#[test]
fn refuses_old_custom_signing_commands_and_missing_cache() {
    updater()
        .args([
            "catalog",
            "verify",
            "unused.json",
            "--trusted-keys",
            "unused-keys.json",
        ])
        .assert()
        .code(2);
    let directory = tempfile::tempdir().unwrap();
    let result = updater()
        .args(["catalog", "cached", "--cache"])
        .arg(directory.path().join("absent.json"))
        .arg("--json")
        .assert()
        .code(4);
    assert!(result.get_output().stdout.is_empty());
}
