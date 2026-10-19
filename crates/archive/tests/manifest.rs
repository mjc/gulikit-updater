use gulikit_archive::manifest::{
    Component, Error, FirmwareIndex, HashTarget, MAX_ARCHIVE_BYTES, MAX_INDEX_BYTES, MAX_RELEASES,
    PublishedHash, ReleaseMetadata, ReleaseRecord,
};
use serde_json::{Value, json};

fn metadata(component: Component, version: &str, filename: &str) -> ReleaseMetadata {
    ReleaseMetadata {
        product: "kk3-max".to_owned(),
        member_kind: gulikit_archive::manifest::FirmwareMemberKind::Kk3,
        component,
        version: version.to_owned(),
        filename: filename.to_owned(),
        source_url: "https://www.gulikit.com/newsinfo/887152.html".to_owned(),
        released_at: None,
        retrieved_at: None,
        retrieved_from: None,
        changelog: None,
        changelog_source_url: None,
        firmware_member: if component == Component::Base {
            "NS39/firmware.bin"
        } else {
            "NS39/updater.exe"
        }
        .to_owned(),
        published_hashes: Vec::new(),
    }
}

fn record(component: Component, version: &str, filename: &str, bytes: &[u8]) -> ReleaseRecord {
    ReleaseRecord::measure(metadata(component, version, filename), bytes, bytes, bytes).unwrap()
}

#[test]
fn records_measure_verify_and_roundtrip_canonical_index_json() {
    let mut base_metadata = metadata(Component::Base, "5.9", "KK3_Max_5.9.zip");
    base_metadata.released_at = Some("2024-05-03".to_owned());
    base_metadata.retrieved_at = Some("2026-10-18T20:00:00Z".to_owned());
    base_metadata.retrieved_from = Some("https://cdn.example.net/firmware/5.9.zip".to_owned());
    base_metadata.changelog = Some("- First correction\r\n- Second correction".to_owned());
    base_metadata.published_hashes.push(PublishedHash {
        target: HashTarget::Payload,
        algorithm: "CRC32".to_owned(),
        value: "A1B2C3D4".to_owned(),
        source_url: "https://community.example/release/checksums".to_owned(),
    });
    let base = ReleaseRecord::measure(
        base_metadata,
        b"original zip bytes",
        b"NS39 firmware file",
        b"extracted firmware payload",
    )
    .unwrap();
    assert_eq!(base.path(), "/kk3-max/base/v5.9/KK3_Max_5.9.zip");
    assert_eq!(base.filename(), "KK3_Max_5.9.zip");
    assert_eq!(base.size(), 18);
    assert_eq!(base.sha256().len(), 64);
    assert_eq!(base.metadata().firmware_member, "NS39/firmware.bin");
    assert_eq!(base.firmware_file().size, 18);
    assert_eq!(base.payload().unwrap().size, 26);
    assert_ne!(base.sha256(), base.firmware_file().sha256);
    assert_ne!(base.firmware_file().sha256, base.payload().unwrap().sha256);
    base.verify(
        b"original zip bytes",
        b"NS39 firmware file",
        b"extracted firmware payload",
    )
    .unwrap();
    assert_eq!(
        base.verify(
            b"original zip byteS",
            b"NS39 firmware file",
            b"extracted firmware payload",
        ),
        Err(Error::ArchiveHashMismatch)
    );
    assert_eq!(
        base.verify(
            b"original zip bytes",
            b"NS39 firmware filE",
            b"extracted firmware payload",
        ),
        Err(Error::FirmwareFileHashMismatch)
    );
    assert_eq!(
        base.verify(
            b"original zip bytes",
            b"NS39 firmware file",
            b"extracted firmware payloAd",
        ),
        Err(Error::PayloadHashMismatch)
    );

    let bluetooth = record(
        Component::Bluetooth,
        "3.24",
        "NS39_BT_3.24.zip",
        b"bt archive",
    );
    assert_eq!(
        bluetooth.path(),
        "/kk3-max/bluetooth/v3.24/NS39_BT_3.24.zip"
    );

    let mut index = FirmwareIndex::empty();
    index.add(base.clone()).unwrap();
    index.add(bluetooth.clone()).unwrap();
    assert_eq!(index.find(base.path()), Some(&base));
    assert_eq!(index.find("/kk3-max/bluetooth/v5.9/missing.zip"), None);

    let json = index.to_json().unwrap();
    let value: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["releases"][0]["released_at"], "2024-05-03");
    assert_eq!(value["releases"][0]["retrieved_at"], "2026-10-18T20:00:00Z");
    assert_eq!(
        value["releases"][0]["retrieved_from"],
        "https://cdn.example.net/firmware/5.9.zip"
    );
    assert_eq!(value["releases"][0]["path"], base.path());
    assert_eq!(value["releases"][0]["firmware_file"]["size"], 18);
    assert_eq!(value["releases"][0]["payload"]["size"], 26);
    assert_eq!(
        value["releases"][0]["published_hashes"][0]["value"],
        "A1B2C3D4"
    );
    let parsed = FirmwareIndex::parse(&json).unwrap();
    assert_eq!(parsed.releases(), &[base, bluetooth]);
}

#[test]
fn parser_rejects_unknown_fields_and_invalid_metadata() {
    let mut index = FirmwareIndex::empty();
    index
        .add(record(Component::Base, "5.9", "KK3_Max_5.9.zip", b"zip"))
        .unwrap();
    let mut value: Value = serde_json::from_slice(&index.to_json().unwrap()).unwrap();
    value["releases"][0]["unexpected"] = true.into();
    assert!(matches!(
        FirmwareIndex::parse(&serde_json::to_vec(&value).unwrap()),
        Err(Error::Json(_))
    ));

    for (version, filename, source) in [
        (
            "../5.9",
            "firmware.zip",
            "https://www.gulikit.com/newsinfo/1.html",
        ),
        (
            "5.9",
            "../firmware.zip",
            "https://www.gulikit.com/newsinfo/1.html",
        ),
        (
            "5.9",
            "firmware.zip",
            "http://www.gulikit.com/newsinfo/1.html",
        ),
        ("5.9", "firmware.zip", "https://"),
        (
            "5.9",
            "firmware.zip",
            "https://user@community.example/archive",
        ),
        (
            "5.9",
            "firmware.zip",
            "https://community.example/archive#fragment",
        ),
        (
            "5.9",
            "firmware.zip",
            "https://community.example/archive\npage",
        ),
        (
            "5.9",
            "bad:name.zip",
            "https://www.gulikit.com/newsinfo/1.html",
        ),
        (
            "5.9",
            "firmware.zip ",
            "https://www.gulikit.com/newsinfo/1.html",
        ),
        ("5.9", "CON.zip", "https://www.gulikit.com/newsinfo/1.html"),
    ] {
        let mut metadata = metadata(Component::Base, version, filename);
        metadata.source_url = source.to_owned();
        assert!(ReleaseRecord::measure(metadata, b"zip", b"member", b"payload").is_err());
    }

    let mut regional = metadata(Component::Base, "5.9", "firmware.zip");
    regional.source_url = "https://www.gulikit.es/newsinfo/firmware.html".to_owned();
    regional.changelog_source_url = Some(
        "https://web.archive.org/web/20261018id_/https://community.example/releases/kk3".to_owned(),
    );
    regional.retrieved_from = Some("https://community.example/archive/firmware.zip".to_owned());
    assert!(ReleaseRecord::measure(regional, b"zip", b"member", b"payload").is_ok());

    let mut original_filename = metadata(Component::Base, "5.9", "firmware.zip");
    original_filename.filename = "KK3 Max (欧洲版) 5.9.zip".to_owned();
    assert!(ReleaseRecord::measure(original_filename, b"zip", b"member", b"payload").is_ok());

    let mut missing_member: Value = serde_json::from_slice(&index.to_json().unwrap()).unwrap();
    missing_member["releases"][0]
        .as_object_mut()
        .unwrap()
        .remove("firmware_member");
    assert!(matches!(
        FirmwareIndex::parse(&serde_json::to_vec(&missing_member).unwrap()),
        Err(Error::Json(_))
    ));
}

#[test]
fn published_sha256_claims_must_match_the_measured_target() {
    let sample = record(Component::Base, "5.9", "firmware.zip", b"archive bytes");
    let mut metadata = metadata(Component::Base, "5.9", "firmware.zip");
    metadata.published_hashes.push(PublishedHash {
        target: HashTarget::FirmwareFile,
        algorithm: " sHa-256 ".to_owned(),
        value: format!(" {} ", sample.firmware_file().sha256.to_ascii_uppercase()),
        source_url: "https://community.example/checksums".to_owned(),
    });
    let measured = ReleaseRecord::measure(
        metadata.clone(),
        b"archive bytes",
        b"archive bytes",
        b"archive bytes",
    )
    .unwrap();
    assert_eq!(
        measured.metadata().published_hashes[0].value,
        format!(" {} ", sample.firmware_file().sha256.to_ascii_uppercase())
    );
    let mut measured_index = FirmwareIndex::empty();
    measured_index.add(measured).unwrap();
    let measured_json: Value = serde_json::from_slice(&measured_index.to_json().unwrap()).unwrap();
    assert_eq!(
        measured_json["releases"][0]["published_hashes"][0]["algorithm"],
        " sHa-256 "
    );
    assert_eq!(
        measured_json["releases"][0]["published_hashes"][0]["value"],
        format!(" {} ", sample.firmware_file().sha256.to_ascii_uppercase())
    );

    metadata.published_hashes[0].algorithm = " SHA-256 ".to_owned();
    metadata.published_hashes[0].value = format!(" {} ", "0".repeat(64));
    assert_eq!(
        ReleaseRecord::measure(
            metadata,
            b"archive bytes",
            b"archive bytes",
            b"archive bytes",
        ),
        Err(Error::PublishedHashMismatch)
    );
}

#[test]
fn dates_require_real_calendar_days_and_strict_utc_timestamps() {
    let mut valid = metadata(Component::Base, "5.9", "firmware.zip");
    valid.released_at = Some("2024-02-29".to_owned());
    valid.retrieved_at = Some("2024-02-29T23:59:59.123456Z".to_owned());
    assert!(ReleaseRecord::measure(valid, b"zip", b"member", b"payload").is_ok());

    for date in ["2023-02-29", "2024-02-30", "2024-2-09", "0000-01-01"] {
        let mut invalid = metadata(Component::Base, "5.9", "firmware.zip");
        invalid.released_at = Some(date.to_owned());
        assert_eq!(
            ReleaseRecord::measure(invalid, b"zip", b"member", b"payload"),
            Err(Error::InvalidMetadata("released_at"))
        );
    }

    for timestamp in [
        "2026-02-30T12:00:00Z",
        "2026-10-18 12:00:00Z",
        "2026-10-18T12:00:00+00:00",
        "2026-10-18T12:00:00",
        "2026-10-18T12:00:00.Z",
    ] {
        let mut invalid = metadata(Component::Base, "5.9", "firmware.zip");
        invalid.retrieved_at = Some(timestamp.to_owned());
        assert_eq!(
            ReleaseRecord::measure(invalid, b"zip", b"member", b"payload"),
            Err(Error::InvalidMetadata("retrieved_at"))
        );
    }
}

#[test]
fn index_rejects_duplicate_identity_and_tampered_record_fields() {
    let mut index = FirmwareIndex::empty();
    let first = record(Component::Base, "5.9", "KK3_Max_5.9.zip", b"zip one");
    index.add(first.clone()).unwrap();
    assert_eq!(
        index.add(record(
            Component::Base,
            "5.9",
            "KK3_Max_5.9.zip",
            b"zip two"
        )),
        Err(Error::DuplicatePath)
    );

    let mut value: Value = serde_json::from_slice(&index.to_json().unwrap()).unwrap();
    value["releases"][0]["path"] = "/kk3-max/bluetooth/v5.9/KK3_Max_5.9.zip".into();
    assert_eq!(
        FirmwareIndex::parse(&serde_json::to_vec(&value).unwrap()),
        Err(Error::PathMismatch)
    );

    value["releases"][0]["path"] = first.path().into();
    value["releases"][0]["sha256"] = "A".repeat(64).into();
    assert_eq!(
        FirmwareIndex::parse(&serde_json::to_vec(&value).unwrap()),
        Err(Error::InvalidHash)
    );
}

#[test]
fn same_version_fix_preserves_both_original_filenames_in_the_version_directory() {
    let mut index = FirmwareIndex::empty();
    let original = record(
        Component::Base,
        "5.1",
        "KK3_NS38_NS39_V5.1.zip",
        b"original",
    );
    let fixed = record(
        Component::Base,
        "5.1",
        "KK3_NS38_NS39_V5.1FIX.zip",
        b"fixed",
    );
    index.add(original.clone()).unwrap();
    index.add(fixed.clone()).unwrap();
    assert_eq!(fixed.path(), "/kk3-max/base/v5.1/KK3_NS38_NS39_V5.1FIX.zip");
    let parsed = FirmwareIndex::parse(&index.to_json().unwrap()).unwrap();
    assert_eq!(parsed.find(original.path()), Some(&original));
    assert_eq!(parsed.find(fixed.path()), Some(&fixed));
}

#[test]
fn index_and_archive_input_bounds_are_enforced() {
    let oversized_index = vec![b' '; MAX_INDEX_BYTES + 1];
    assert_eq!(
        FirmwareIndex::parse(&oversized_index),
        Err(Error::InputTooLarge)
    );
    assert_eq!(
        ReleaseRecord::measure(
            metadata(Component::Base, "5.9", "firmware.zip"),
            b"",
            b"member",
            b"payload"
        ),
        Err(Error::ArchiveEmpty)
    );

    let mut one = FirmwareIndex::empty();
    one.add(record(Component::Base, "5.9", "firmware.zip", b"zip"))
        .unwrap();
    let one_json: Value = serde_json::from_slice(&one.to_json().unwrap()).unwrap();
    let oversized_release = json!({
        "schema_version": 1,
        "releases": [{
            "component": "base",
            "version": "5.9",
            "filename": "firmware.zip",
            "source_url": "https://www.gulikit.com/newsinfo/1.html",
            "released_at": null,
            "retrieved_at": null,
            "retrieved_from": null,
            "changelog": null,
            "changelog_source_url": null,
            "firmware_member": "NS39/firmware.bin",
            "published_hashes": [],
            "path": "/kk3-max/base/v5.9/firmware.zip",
            "size": u64::try_from(MAX_ARCHIVE_BYTES).unwrap() + 1,
            "sha256": one_json["releases"][0]["sha256"],
            "firmware_file": one_json["releases"][0]["firmware_file"],
            "payload": one_json["releases"][0]["payload"]
        }]
    });
    assert_eq!(
        FirmwareIndex::parse(&serde_json::to_vec(&oversized_release).unwrap()),
        Err(Error::ArchiveTooLarge)
    );

    let entry = one_json["releases"][0].clone();
    let too_many = json!({
        "schema_version": 1,
        "releases": vec![entry; MAX_RELEASES + 1]
    });
    assert_eq!(
        FirmwareIndex::parse(&serde_json::to_vec(&too_many).unwrap()),
        Err(Error::TooManyReleases)
    );

    let unsupported = json!({"schema_version": 2, "releases": []});
    assert_eq!(
        FirmwareIndex::parse(&serde_json::to_vec(&unsupported).unwrap()),
        Err(Error::UnsupportedSchema(2))
    );
}
