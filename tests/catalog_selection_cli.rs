use assert_cmd::Command;
use serde_json::Value;

fn updater() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
}

fn selection<'a>(command: &'a mut Command, version: &str) -> &'a mut Command {
    command.args([
        "--product",
        "kk3-max",
        "--component",
        "bluetooth",
        "--version",
        version,
    ])
}

#[test]
fn lists_each_component_and_historical_version_without_device_access() {
    let result = updater()
        .args(["catalog", "releases", "--json"])
        .assert()
        .success();
    let report: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(report["releases"].as_array().unwrap().len(), 4);
    assert_eq!(report["authorizes_firmware"], false);
    assert_eq!(report["trust"], "unverified");
    let filtered = updater()
        .args([
            "catalog",
            "releases",
            "--product",
            "kk3-max",
            "--component",
            "bluetooth",
            "--json",
        ])
        .assert()
        .success();
    let report: Value = serde_json::from_slice(&filtered.get_output().stdout).unwrap();
    let entries = report["releases"].as_array().unwrap();
    let versions: Vec<_> = entries
        .iter()
        .map(|entry| entry["version"].as_str().unwrap())
        .collect();
    assert_eq!(versions, ["5.07", "3.24", "3.23"]);
    assert_eq!(entries[0]["software_support"], "supported");
    assert_eq!(entries[0]["hardware_acceptance"], "unqualified");
    assert_eq!(entries[1]["hardware_acceptance"], "qualified");
    assert!(entries.iter().all(|entry| {
        entry["source_url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    }));
}

#[test]
fn manual_download_keeps_exact_selection_and_leaves_destination_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("archive.zip");
    std::fs::write(&destination, b"existing file").unwrap();
    let result = selection(updater().args(["catalog", "download"]), "3.23")
        .arg("--output")
        .arg(&destination)
        .arg("--json")
        .assert()
        .success();
    let report: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(report["release"]["version"], "3.23");
    assert_eq!(report["download"]["status"], "manual_required");
    assert_eq!(
        report["download"]["source_url"],
        report["release"]["source_url"]
    );
    assert_eq!(report["authorizes_firmware"], false);
    assert_eq!(std::fs::read(&destination).unwrap(), b"existing file");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn missing_selection_and_unavailable_release_fail_before_output_or_io() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("archive.zip");
    let missing = selection(updater().args(["catalog", "download"]), "0.00")
        .arg("--output")
        .arg(&destination)
        .arg("--json")
        .assert()
        .code(3);
    assert!(missing.get_output().stdout.is_empty());
    let report: Value = serde_json::from_slice(&missing.get_output().stderr).unwrap();
    assert_eq!(report["error"]["kind"], "catalog_release_missing");
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../catalog/official.json")).unwrap();
    for entry in catalog["entries"].as_array_mut().unwrap() {
        entry["availability"] = "unavailable".into();
    }
    let path = directory.path().join("catalog.json");
    std::fs::write(&path, serde_json::to_vec(&catalog).unwrap()).unwrap();
    let refused = selection(updater().args(["catalog", "download"]), "3.23")
        .arg("--catalog")
        .arg(&path)
        .arg("--output")
        .arg(&destination)
        .arg("--json")
        .assert()
        .code(3);
    assert!(refused.get_output().stdout.is_empty());
    assert!(!destination.exists());
}

#[test]
fn missing_changelog_does_not_launch_a_browser() {
    let result = selection(updater().args(["catalog", "source"]), "3.24")
        .args(["--changelog", "--json"])
        .assert()
        .code(3);
    let report: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
    assert_eq!(report["error"]["kind"], "catalog_changelog_missing");
    assert!(result.get_output().stdout.is_empty());
}
