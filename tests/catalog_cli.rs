use assert_cmd::Command;
use serde_json::Value;

fn updater() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
}

#[test]
fn inspects_seed_as_unverified_metadata_without_authorizing_firmware() {
    let result = updater()
        .args(["catalog", "inspect"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/catalog/official.json"
        ))
        .arg("--json")
        .assert()
        .success();
    let output: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(output["schema_version"], 1);
    assert_eq!(output["trust"], "unverified");
    assert_eq!(output["authorizes_firmware"], false);
    assert_eq!(output["catalog"]["entries"].as_array().unwrap().len(), 4);
    assert!(result.get_output().stderr.is_empty());
}

#[test]
fn malformed_and_oversized_catalogs_fail_with_empty_stdout() {
    let file = tempfile::NamedTempFile::new().unwrap();
    for bytes in [
        b"invalid".to_vec(),
        vec![b' '; gulikit_catalog::MAX_CATALOG_BYTES + 1],
    ] {
        std::fs::write(file.path(), bytes).unwrap();
        let result = updater()
            .args(["catalog", "inspect"])
            .arg(file.path())
            .arg("--json")
            .assert()
            .code(3);
        assert!(result.get_output().stdout.is_empty());
        let error: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
        assert_eq!(error["error"]["kind"], "catalog_rejected");
    }
}

#[test]
fn missing_catalog_and_directory_are_io_errors() {
    let directory = tempfile::tempdir().unwrap();
    for path in [
        directory.path().to_owned(),
        directory.path().join("absent.json"),
    ] {
        let result = updater()
            .args(["catalog", "inspect"])
            .arg(path)
            .arg("--json")
            .assert()
            .code(4);
        assert!(result.get_output().stdout.is_empty());
        let error: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
        assert_eq!(error["error"]["kind"], "catalog_io");
    }
}

#[cfg(unix)]
#[test]
fn catalog_inspection_rejects_symlinks_and_fifos_without_blocking() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("catalog.json");
    std::fs::write(&original, b"{}").unwrap();
    let symlink = directory.path().join("link.json");
    std::os::unix::fs::symlink(&original, &symlink).unwrap();
    let fifo = directory.path().join("fifo.json");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    for path in [symlink, fifo] {
        updater()
            .timeout(std::time::Duration::from_secs(2))
            .args(["catalog", "inspect"])
            .arg(path)
            .arg("--json")
            .assert()
            .code(4);
    }
}
