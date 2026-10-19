use assert_cmd::Command;
use serde_json::Value;
use std::fs;

#[test]
fn initializes_and_lists_an_empty_archive_without_replacing_an_existing_path() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("firmware.git");
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("init")
        .arg(&repo)
        .assert()
        .success();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("list")
        .arg(&repo)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let index: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(index["schema_version"], 1);
    assert_eq!(index["releases"], serde_json::json!([]));
    fs::write(repo.join("preserve"), "owned data").unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("init")
        .arg(&repo)
        .assert()
        .code(2);
    assert_eq!(fs::read(repo.join("preserve")).unwrap(), b"owned data");
}

#[test]
fn missing_release_cannot_replace_an_output_or_create_a_new_one() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("firmware.git");
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("init")
        .arg(&repo)
        .assert()
        .success();
    let output = temp.path().join("original.zip");
    fs::write(&output, "preserve").unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("read")
        .arg(&repo)
        .args(["--path", "/kk3-max/bluetooth/v3.23/missing.zip", "--output"])
        .arg(&output)
        .assert()
        .code(2);
    assert_eq!(fs::read(&output).unwrap(), b"preserve");
    let missing = temp.path().join("missing.zip");
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-archive"))
        .arg("read")
        .arg(&repo)
        .args(["--path", "/kk3-max/base/v5.9/missing.zip", "--output"])
        .arg(&missing)
        .assert()
        .code(2);
    assert!(!missing.exists());
}
