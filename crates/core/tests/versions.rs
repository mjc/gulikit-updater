use gulikit_core::version::{MainVersion, VersionDecision, bluetooth_info};

#[test]
fn observed_text_and_integer_version_policy() {
    let current = MainVersion::parse(b"www.gulikit.com \r\nversion 5.9").unwrap();
    assert_eq!(current.to_string(), "5.9");
    assert_eq!(current.decision(), VersionDecision::AlreadyCurrent);
    assert_eq!(
        MainVersion::parse(b"\twww.gulikit.com\n version 5.10 \n")
            .unwrap()
            .decision(),
        VersionDecision::NewerThanSupported
    );
    assert_eq!(
        MainVersion::parse(b"www.gulikit.com\nversion 5.8")
            .unwrap()
            .decision(),
        VersionDecision::Eligible
    );
}

#[test]
fn main_line_endings_preserve_evidence_and_reject_unpaired_carriage_returns() {
    let text = "\r\nwww.gulikit.com\r\n\r\nversion 5.9\r\n";
    let version = MainVersion::parse(text.as_bytes()).unwrap();
    assert_eq!(version.to_string(), "5.9");
    assert_eq!(serde_json::to_value(version).unwrap()["original"], text);
    for text in [
        "www.gulikit.com\r\r\nversion 5.9",
        "www.gulikit.com\r\nversion 5.9\r",
        "www.gulikit.com\rversion 5.9\n",
    ] {
        assert!(MainVersion::parse(text.as_bytes()).is_err());
    }
}

#[test]
fn ambiguous_or_unbounded_main_text_is_unknown() {
    for bytes in [
        b"version 5.8".as_slice(),
        b"www.gulikit.com\nversion 5.8\nversion 5.9",
        b"www.gulikit.com\nversion  5.8",
        b"www.gulikit.com\nversion +5.8",
        b"www.gulikit.com\nversion 5.8\0",
        b"www.gulikit.com\rversion 5.8",
        b"www.gulikit.com\nversion 5.8\r",
        b"www.gulikit.com\nversion 5.8\nextra",
        b"www.gulikit.com\nversion 10000.8",
    ] {
        assert!(MainVersion::parse(bytes).is_err(), "{bytes:?}");
    }
    assert!(MainVersion::parse(&vec![b' '; 4097]).is_err());
}

#[test]
fn bluetooth_requires_complete_compatible_fresh_data() {
    let mut bytes = hex::decode("a1ca51da724cb6103658c05d7d4e1596fb010000").unwrap();
    let info = bluetooth_info(&bytes).unwrap();
    assert_eq!(info.to_string(), "5.07");
    assert_eq!(info.decision(), VersionDecision::AlreadyCurrent);
    bytes[16] = 0xfa;
    assert_eq!(
        bluetooth_info(&bytes).unwrap().decision(),
        VersionDecision::Eligible
    );
    bytes[16] = 0xfc;
    assert_eq!(
        bluetooth_info(&bytes).unwrap().decision(),
        VersionDecision::NewerThanSupported
    );
    assert!(bluetooth_info(&bytes[..19]).is_err());
    bytes[0] ^= 1;
    assert!(bluetooth_info(&bytes).is_err());
}

#[test]
fn explicit_downgrade_changes_only_direction_and_never_reinstalls_equal_versions() {
    use gulikit_core::version::{BT_SIGNATURE, VersionPolicy};
    let newer = MainVersion::parse(b"www.gulikit.com\nversion 5.10").unwrap();
    assert_eq!(newer.decision(), VersionDecision::NewerThanSupported);
    assert_eq!(
        newer.decision_with_policy(VersionPolicy::AllowDowngrade),
        VersionDecision::Eligible
    );
    let equal = MainVersion::parse(b"www.gulikit.com\nversion 5.9").unwrap();
    assert_eq!(
        equal.decision_with_policy(VersionPolicy::AllowDowngrade),
        VersionDecision::AlreadyCurrent
    );
    let mut raw = [0; 20];
    raw[..16].copy_from_slice(&BT_SIGNATURE);
    raw[16..18].copy_from_slice(&508u16.to_le_bytes());
    let newer = bluetooth_info(&raw).unwrap();
    assert_eq!(newer.decision(), VersionDecision::NewerThanSupported);
    assert_eq!(
        newer.decision_with_policy(VersionPolicy::AllowDowngrade),
        VersionDecision::Eligible
    );
    raw[16..18].copy_from_slice(&507u16.to_le_bytes());
    assert_eq!(
        bluetooth_info(&raw)
            .unwrap()
            .decision_with_policy(VersionPolicy::AllowDowngrade),
        VersionDecision::AlreadyCurrent
    );
    raw[0] ^= 1;
    assert!(bluetooth_info(&raw).is_err());
}

#[test]
fn selected_reviewed_release_controls_direction_for_all_supported_versions() {
    use gulikit_core::package::{Component, catalog};
    use gulikit_core::version::{VersionDecision, VersionPolicy};
    for (target, current, expected) in [
        ("3.24", "3.23", VersionDecision::Eligible),
        ("3.24", "3.24", VersionDecision::AlreadyCurrent),
        ("3.24", "5.06", VersionDecision::NewerThanSupported),
        ("5.07", "3.24", VersionDecision::Eligible),
        ("5.07", "5.07", VersionDecision::AlreadyCurrent),
        ("5.07", "6.00", VersionDecision::NewerThanSupported),
    ] {
        let release = catalog()
            .iter()
            .find(|r| r.component == Component::Bluetooth && r.version == target)
            .unwrap();
        assert_eq!(
            release
                .decision_for_installed(current, VersionPolicy::UpgradeOnly)
                .unwrap(),
            expected
        );
        let allowed = release
            .decision_for_installed(current, VersionPolicy::AllowDowngrade)
            .unwrap();
        assert_eq!(
            allowed,
            if current == target {
                VersionDecision::AlreadyCurrent
            } else {
                VersionDecision::Eligible
            }
        );
        for invalid in [
            "unknown", "3.2", "+3.24", "3.024", "655.36", "65536.00", "3.24.0",
        ] {
            assert!(
                release
                    .decision_for_installed(invalid, VersionPolicy::UpgradeOnly)
                    .is_err(),
                "{invalid}"
            );
        }
    }
    let main = catalog()
        .iter()
        .find(|r| r.component == Component::Main)
        .unwrap();
    assert_eq!(
        main.decision_for_installed("5.8", VersionPolicy::UpgradeOnly)
            .unwrap(),
        VersionDecision::Eligible
    );
    assert_eq!(
        main.decision_for_installed("5.9", VersionPolicy::UpgradeOnly)
            .unwrap(),
        VersionDecision::AlreadyCurrent
    );
    assert_eq!(
        main.decision_for_installed("5.10", VersionPolicy::UpgradeOnly)
            .unwrap(),
        VersionDecision::NewerThanSupported
    );
}
