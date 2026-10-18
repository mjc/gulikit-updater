use gulikit_core::{
    changelog::{Direction, compare},
    package::{Component, Model},
};

fn versions(component: Component, from: &str, to: &str) -> Vec<&'static str> {
    compare(Model::Kk3Max, component, from, to)
        .unwrap()
        .releases()
        .iter()
        .map(|release| release.version)
        .collect()
}

#[test]
fn upgrade_includes_every_recorded_intermediate_release() {
    assert_eq!(
        versions(Component::Bluetooth, "3.23", "5.07"),
        ["3.24", "3.26", "3.27", "3.30", "3.31", "5.03", "5.07"]
    );
}

#[test]
fn upgrade_excludes_baseline_and_includes_destination() {
    assert_eq!(
        versions(Component::Bluetooth, "3.24", "3.30"),
        ["3.26", "3.27", "3.30"]
    );
}

#[test]
fn downgrade_shows_changes_removed_in_reverse_order() {
    let comparison = compare(Model::Kk3Max, Component::Bluetooth, "5.07", "3.23").unwrap();
    assert_eq!(comparison.direction(), Direction::Downgrade);
    assert_eq!(
        versions(Component::Bluetooth, "5.07", "3.23"),
        ["5.07", "5.03", "3.31", "3.30", "3.27", "3.26", "3.24"]
    );
    assert!(comparison.render_text().contains("Changes removed"));
}

#[test]
fn equal_versions_have_no_version_change() {
    let comparison = compare(Model::Kk3Max, Component::Bluetooth, "3.23", "3.23").unwrap();
    assert_eq!(comparison.direction(), Direction::Unchanged);
    assert_eq!(comparison.releases().len(), 0);
    assert!(comparison.render_text().contains("No version change"));
}

#[test]
fn unknown_bounds_still_select_known_intermediate_notes() {
    assert_eq!(
        versions(Component::Bluetooth, "3.25", "3.30"),
        ["3.26", "3.27", "3.30"]
    );
}

#[test]
fn numeric_main_versions_do_not_use_lexical_or_decimal_order() {
    assert_eq!(versions(Component::Main, "5.8", "5.10"), ["5.9"]);
}

#[test]
fn component_histories_are_independent() {
    assert_eq!(
        versions(Component::Main, "3.2", "5.9"),
        ["4.4", "5.8", "5.9"]
    );
    assert_eq!(versions(Component::Bluetooth, "5.03", "5.07"), ["5.07"]);
}

#[test]
fn absent_notes_do_not_claim_absent_changes() {
    let comparison = compare(Model::Kk3Max, Component::Bluetooth, "3.24", "3.25").unwrap();
    assert_eq!(comparison.releases().len(), 0);
    let text = comparison.render_text();
    assert!(text.contains("No recorded release notes"));
    assert!(text.contains("may be incomplete"));
}

#[test]
fn malformed_versions_are_rejected_at_both_bounds() {
    for value in [
        "", "latest", "3", "3..23", "-3.23", "65536.23", "3.230", "3.2",
    ] {
        assert!(
            compare(Model::Kk3Max, Component::Bluetooth, value, "5.07").is_err(),
            "from={value}"
        );
        assert!(
            compare(Model::Kk3Max, Component::Bluetooth, "3.23", value).is_err(),
            "to={value}"
        );
    }
}

#[test]
fn notes_keep_provenance_and_coverage_in_json() {
    let comparison = compare(Model::Kk3Max, Component::Bluetooth, "3.23", "3.24").unwrap();
    let json = serde_json::to_value(&comparison).unwrap();
    assert_eq!(json["coverage"], "partial_historical_record");
    assert_eq!(json["releases"][0]["version"], "3.24");
    assert!(
        json["releases"][0]["source_url"]
            .as_str()
            .unwrap()
            .contains("web.archive.org")
    );
    assert!(comparison.render_text().contains("wired PC"));
}
