use assert_cmd::Command;
use serde_json::Value;

#[test]
fn lists_reviewed_firmware_without_touching_devices() {
    let result = Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
        .args(["packages", "--json"])
        .assert()
        .success();
    let output: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(output["schema_version"], 1);
    assert_eq!(output["packages"][0]["model"], "kk3-max");
    assert_eq!(output["packages"][0]["component"], "main");
    assert_eq!(output["packages"][1]["version"], "5.07");
}

#[test]
fn rejects_an_unknown_model_instead_of_accepting_a_filename() {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
        .args([
            "package",
            "inspect",
            "anything.zip",
            "--model",
            "kk3-pro",
            "--component",
            "main",
        ])
        .assert()
        .code(2);
}

#[test]
fn malformed_package_is_a_structured_error_with_empty_stdout() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"not firmware").unwrap();
    let result = Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
        .args(["package", "inspect"])
        .arg(file.path())
        .args(["--model", "kk3-max", "--component", "main", "--json"])
        .assert()
        .code(3);
    assert!(result.get_output().stdout.is_empty());
    let error: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
    assert_eq!(error["schema_version"], 1);
    assert_eq!(error["error"]["kind"], "package_rejected");
}

#[test]
fn update_is_unavailable_in_the_offline_slice() {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
        .arg("update")
        .assert()
        .code(2);
}

#[test]
fn missing_file_and_directory_have_io_exit_codes_and_no_stdout() {
    let directory = tempfile::tempdir().unwrap();
    for path in [
        directory.path().to_owned(),
        directory.path().join("missing.zip"),
    ] {
        let result = Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
            .args(["package", "inspect"])
            .arg(path)
            .args(["--model", "kk3-max", "--component", "main", "--json"])
            .assert()
            .code(4);
        assert!(result.get_output().stdout.is_empty());
        let error: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
        assert_eq!(error["error"]["kind"], "package_io");
    }
}

#[test]
fn supports_human_catalog_and_rejects_an_unknown_component() {
    let result = Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
        .arg("packages")
        .assert()
        .success();
    let text = std::str::from_utf8(&result.get_output().stdout).unwrap();
    assert!(text.contains("kk3-max main 5.9"));
    assert!(text.contains("kk3-max bluetooth 5.07"));
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
        .args([
            "package",
            "inspect",
            "anything.zip",
            "--model",
            "kk3-max",
            "--component",
            "receiver",
        ])
        .assert()
        .code(2);
}
