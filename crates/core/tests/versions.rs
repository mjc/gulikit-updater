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
