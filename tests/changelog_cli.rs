use assert_cmd::Command;
use serde_json::Value;

fn command() -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"));
    command.args(["changelog", "--component", "bluetooth"]);
    command
}

#[test]
fn json_contains_every_crossed_release_and_provenance() {
    let result = command()
        .args(["--from", "3.23", "--to", "5.07", "--json"])
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&result.get_output().stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["changelog"]["direction"], "upgrade");
    assert_eq!(json["changelog"]["coverage"], "partial_historical_record");
    let versions: Vec<_> = json["changelog"]["releases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|release| release["version"].as_str().unwrap())
        .collect();
    assert_eq!(
        versions,
        ["3.24", "3.26", "3.27", "3.30", "3.31", "5.03", "5.07"]
    );
    assert!(
        json["changelog"]["releases"][0]["source_url"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );
}

#[test]
fn human_downgrade_explains_removed_changes_and_coverage() {
    let result = command()
        .args(["--from", "3.27", "--to", "3.23"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&result.get_output().stdout);
    assert!(text.contains("Changes removed"));
    assert!(text.find("Version 3.27").unwrap() < text.find("Version 3.24").unwrap());
    assert!(text.contains("may be incomplete"));
    assert!(!text.contains("Version 3.23"));
}

#[test]
fn invalid_bounds_produce_structured_error_without_stdout() {
    let result = command()
        .args(["--from", "latest", "--to", "5.07", "--json"])
        .assert()
        .code(2);
    assert_eq!(result.get_output().stdout, [] as [u8; 0]);
    let json: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
    assert_eq!(json["error"]["kind"], "invalid_version");
}

#[test]
fn equal_versions_are_an_explicit_empty_comparison() {
    let result = command()
        .args(["--from", "3.23", "--to", "3.23"])
        .assert()
        .success();
    assert!(String::from_utf8_lossy(&result.get_output().stdout).contains("No version change"));
}
