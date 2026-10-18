use gulikit_catalog::{Catalog, Entry};
use gulikit_core::package::{
    CatalogPackageInspection, Component, Model, PackageError, VerifiedPackage, catalog_package_info,
};
use gulikit_core::version::{VersionDecision, VersionPolicy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use zip::{ZipWriter, write::SimpleFileOptions};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fixture() -> (Vec<u8>, Value) {
    let payload = vec![0x5a; 51_500];
    let mut archive = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    archive
        .start_file("firmware/kk3.bin", SimpleFileOptions::default())
        .unwrap();
    archive.write_all(&payload).unwrap();
    let archive = archive.finish().unwrap().into_inner();
    let entry = json!({
        "product": "kk3-max",
        "component": "main",
        "version": "6.1",
        "archive": "kk3-main.zip",
        "archive_size": archive.len(),
        "archive_sha256": sha(&archive),
        "member": "firmware/kk3.bin",
        "member_size": payload.len(),
        "member_sha256": sha(&payload),
        "payload_size": payload.len(),
        "payload_sha256": sha(&payload),
        "source_url": "https://www.gulikit.com/newsinfo/123456.html",
        "parser_id": "kk3_main_binary_v1",
        "software_support": "supported",
        "hardware_acceptance": "unqualified",
        "hardware_evidence": null
    });
    (archive, entry)
}

fn parsed_catalog(entries: &[Value]) -> Result<Catalog, gulikit_catalog::CatalogError> {
    Catalog::parse(
        json!({"schema_version": 1, "entries": entries})
            .to_string()
            .as_bytes(),
    )
}

fn inspect(archive: &[u8], entries: &[Value]) -> Result<CatalogPackageInspection, PackageError> {
    let catalog = parsed_catalog(entries).expect("synthetic catalog is schema-valid");
    CatalogPackageInspection::inspect(archive, &catalog, Model::Kk3Max, Component::Main)
}

fn minimal_bluetooth_pe(version: u16, payload: &[u8]) -> Vec<u8> {
    const BT_SIGNATURE: [u8; 16] = [
        0xa1, 0xca, 0x51, 0xda, 0x72, 0x4c, 0xb6, 0x10, 0x36, 0x58, 0xc0, 0x5d, 0x7d, 0x4e, 0x15,
        0x96,
    ];

    let pe_offset = 0x80;
    let optional_offset = pe_offset + 4 + 20;
    let section_offset = optional_offset + 0xe0;
    let raw_offset = 0x200;
    let raw_size = 0x180_000;
    let pe_offset_u32 = u32::try_from(pe_offset).unwrap();
    let raw_offset_u32 = u32::try_from(raw_offset).unwrap();
    let raw_size_u32 = u32::try_from(raw_size).unwrap();
    let payload_len_u32 = u32::try_from(payload.len()).unwrap();
    let mut image = vec![0; raw_offset + raw_size];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&pe_offset_u32.to_le_bytes());
    image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    let coff = pe_offset + 4;
    image[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&0xe0u16.to_le_bytes());
    image[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
    image[optional_offset..optional_offset + 2].copy_from_slice(&0x010bu16.to_le_bytes());
    image[optional_offset + 32..optional_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[optional_offset + 36..optional_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[optional_offset + 56..optional_offset + 60]
        .copy_from_slice(&0x0018_1000_u32.to_le_bytes());
    image[optional_offset + 60..optional_offset + 64]
        .copy_from_slice(&raw_offset_u32.to_le_bytes());
    image[optional_offset + 68..optional_offset + 70].copy_from_slice(&3u16.to_le_bytes());
    image[optional_offset + 92..optional_offset + 96].copy_from_slice(&16u32.to_le_bytes());
    image[section_offset..section_offset + 5].copy_from_slice(b".text");
    image[section_offset + 8..section_offset + 12].copy_from_slice(&raw_size_u32.to_le_bytes());
    image[section_offset + 12..section_offset + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section_offset + 16..section_offset + 20].copy_from_slice(&raw_size_u32.to_le_bytes());
    image[section_offset + 20..section_offset + 24].copy_from_slice(&raw_offset_u32.to_le_bytes());
    let at_rva = |rva: u32| raw_offset + usize::try_from(rva - 0x1000).unwrap();
    let identity = at_rva(0x17_32d0);
    image[identity..identity + 16].copy_from_slice(&BT_SIGNATURE);
    let version_offset = at_rva(0x17_32e0);
    image[version_offset..version_offset + 2].copy_from_slice(&version.to_le_bytes());
    let length_offset = at_rva(0x17_32e4);
    image[length_offset..length_offset + 4].copy_from_slice(&payload_len_u32.to_le_bytes());
    let payload_offset = at_rva(0x17_32f0);
    image[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    image
}

#[test]
fn catalog_metadata_selects_hash_checked_archive_and_preserves_package_provenance() {
    let (archive, entry) = fixture();
    let catalog = parsed_catalog(std::slice::from_ref(&entry)).unwrap();
    let package =
        VerifiedPackage::inspect_catalog(&archive, &catalog, Model::Kk3Max, Component::Main)
            .unwrap();
    assert_eq!(package.info().version, "6.1");
    assert_eq!(
        package.info().source_url,
        "https://www.gulikit.com/newsinfo/123456.html"
    );
    assert_eq!(package.info().member, "firmware/kk3.bin");
    assert_eq!(package.info().payload_size, 51_500);
    assert_eq!(package.catalog_entry().unwrap().version(), "6.1");

    let raw_entry = serde_json::to_vec(&entry).unwrap();
    let parsed_entry = Entry::parse(&raw_entry).unwrap();
    assert_eq!(
        catalog_package_info(&parsed_entry).unwrap(),
        *package.info()
    );
    assert_eq!(
        package
            .info()
            .decision_for_installed("6.0", VersionPolicy::UpgradeOnly)
            .unwrap(),
        VersionDecision::Eligible
    );
    assert_eq!(
        package
            .info()
            .decision_for_installed("6.2", VersionPolicy::UpgradeOnly)
            .unwrap(),
        VersionDecision::NewerThanSupported
    );
    assert_eq!(
        package
            .info()
            .decision_for_installed("6.2", VersionPolicy::AllowDowngrade)
            .unwrap(),
        VersionDecision::Eligible
    );
}

#[test]
fn catalog_hash_mismatches_and_invalid_member_paths_are_rejected() {
    let (archive, entry) = fixture();
    let mut wrong_archive_hash = entry.clone();
    wrong_archive_hash["archive_sha256"] = json!("0".repeat(64));
    assert!(matches!(
        inspect(&archive, &[wrong_archive_hash]),
        Err(PackageError::Digest { kind: "archive" })
    ));

    let mut wrong_member_hash = entry.clone();
    wrong_member_hash["member_sha256"] = json!("0".repeat(64));
    assert!(matches!(
        inspect(&archive, &[wrong_member_hash]),
        Err(PackageError::Digest { kind: "member" })
    ));

    let mut wrong_payload_hash = entry.clone();
    wrong_payload_hash["payload_sha256"] = json!("0".repeat(64));
    assert!(matches!(
        inspect(&archive, &[wrong_payload_hash]),
        Err(PackageError::Digest { kind: "payload" })
    ));

    let mut traversal = entry;
    traversal["member"] = json!("../kk3.bin");
    assert!(parsed_catalog(&[traversal]).is_err());
}

#[test]
fn ambiguous_or_unsupported_entries_and_invalid_main_lengths_do_not_select_payloads() {
    let (archive, entry) = fixture();
    let mut another = entry.clone();
    another["version"] = json!("6.2");
    assert!(matches!(
        inspect(&archive, &[entry.clone(), another]),
        Err(PackageError::UnsupportedCatalogEntry)
    ));

    let mut metadata_only = entry.clone();
    metadata_only["software_support"] = json!("metadata_only");
    assert!(matches!(
        inspect(&archive, &[metadata_only]),
        Err(PackageError::UnsupportedCatalogEntry)
    ));

    let mut unsupported_parser = entry.clone();
    unsupported_parser["parser_id"] = json!("none");
    unsupported_parser["software_support"] = json!("metadata_only");
    assert!(matches!(
        inspect(&archive, &[unsupported_parser]),
        Err(PackageError::UnsupportedCatalogEntry)
    ));

    let mut invalid_main_size = entry;
    invalid_main_size["member_size"] = json!(51_501);
    invalid_main_size["payload_size"] = json!(51_501);
    assert!(matches!(
        inspect(&archive, &[invalid_main_size]),
        Err(PackageError::UnsupportedCatalogEntry)
    ));
}

#[test]
fn three_version_catalog_selects_the_exact_bluetooth_archive_record() {
    let payload = vec![0x3c; 512];
    let member_bytes = minimal_bluetooth_pe(324, &payload);
    let mut archive_writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    archive_writer
        .start_file("controller.exe", SimpleFileOptions::default())
        .unwrap();
    archive_writer.write_all(&member_bytes).unwrap();
    let archive = archive_writer.finish().unwrap().into_inner();
    let mut entries = Vec::new();
    for version in ["3.23", "3.24", "5.07"] {
        entries.push(json!({
            "product": "kk3-max",
            "component": "bluetooth",
            "version": version,
            "archive": format!("bt-{version}.zip"),
            "archive_size": archive.len(),
            "archive_sha256": if version == "3.24" { sha(&archive) } else { "0".repeat(64) },
            "member": "controller.exe",
            "member_size": member_bytes.len(),
            "member_sha256": sha(&member_bytes),
            "payload_size": 512,
            "payload_sha256": if version == "3.24" { sha(&payload) } else { "1".repeat(64) },
            "source_url": "https://www.gulikit.com/newsinfo/123456.html",
            "parser_id": "kk3_bluetooth_pe_v1",
            "software_support": "supported",
            "hardware_acceptance": "unqualified",
            "hardware_evidence": null
        }));
    }
    let catalog = parsed_catalog(&entries).unwrap();
    let inspection =
        CatalogPackageInspection::inspect(&archive, &catalog, Model::Kk3Max, Component::Bluetooth)
            .unwrap();
    assert_eq!(inspection.info().version, "3.24");
    assert_eq!(inspection.info().member, "controller.exe");
    let package =
        VerifiedPackage::inspect_catalog(&archive, &catalog, Model::Kk3Max, Component::Bluetooth)
            .unwrap();
    assert_eq!(package.info().version, "3.24");
    assert_eq!(package.catalog_entry().unwrap().version(), "3.24");
    assert_eq!(package.payload().len(), payload.len());
    assert_eq!(
        catalog_package_info(package.catalog_entry().unwrap()).unwrap(),
        *package.info()
    );
}

#[test]
fn unsupported_model_record_does_not_match_kk3_selection() {
    let (archive, mut entry) = fixture();
    entry["product"] = json!("other-controller");
    entry["parser_id"] = json!("none");
    entry["software_support"] = json!("metadata_only");
    assert!(matches!(
        inspect(&archive, &[entry]),
        Err(PackageError::UnsupportedCatalogEntry)
    ));
}
