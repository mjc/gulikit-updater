use gulikit_catalog::ParserId;
use gulikit_core::package::{CandidatePackageInspection, Component, Model, PackageError};
use sha2::{Digest, Sha256};
use std::io::Write;
use zip::{ZipWriter, write::SimpleFileOptions};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn zip_member(name: &str, contents: &[u8], options: SimpleFileOptions) -> Vec<u8> {
    let mut archive = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    archive.start_file(name, options).unwrap();
    archive.write_all(contents).unwrap();
    archive.finish().unwrap().into_inner()
}

fn duplicate_name_archive(contents: &[u8]) -> Vec<u8> {
    let mut archive = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for name in ["fw.bin", "xx.bin"] {
        archive
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        archive.write_all(contents).unwrap();
    }
    let mut archive = archive.finish().unwrap().into_inner();
    let mut renamed_local = false;
    let mut renamed_central = false;
    for index in 0..archive.len().saturating_sub(5) {
        if &archive[index..index + 6] == b"xx.bin" {
            let is_local_name =
                index >= 30 && archive.get(index - 30..index - 26) == Some(&b"PK\x03\x04"[..]);
            let is_central_name =
                index >= 46 && archive.get(index - 46..index - 42) == Some(&b"PK\x01\x02"[..]);
            if is_local_name {
                archive[index..index + 6].copy_from_slice(b"fw.bin");
                renamed_local = true;
            } else if is_central_name {
                archive[index..index + 6].copy_from_slice(b"fw.bin");
                renamed_central = true;
            }
        }
    }
    assert!(renamed_local && renamed_central);
    archive
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
    let mut image = vec![0; raw_offset + raw_size];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&u32::try_from(pe_offset).unwrap().to_le_bytes());
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
        .copy_from_slice(&0x0018_1000u32.to_le_bytes());
    image[optional_offset + 60..optional_offset + 64]
        .copy_from_slice(&u32::try_from(raw_offset).unwrap().to_le_bytes());
    image[optional_offset + 68..optional_offset + 70].copy_from_slice(&3u16.to_le_bytes());
    image[optional_offset + 92..optional_offset + 96].copy_from_slice(&16u32.to_le_bytes());
    image[section_offset..section_offset + 5].copy_from_slice(b".text");
    image[section_offset + 8..section_offset + 12]
        .copy_from_slice(&u32::try_from(raw_size).unwrap().to_le_bytes());
    image[section_offset + 12..section_offset + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    image[section_offset + 16..section_offset + 20]
        .copy_from_slice(&u32::try_from(raw_size).unwrap().to_le_bytes());
    image[section_offset + 20..section_offset + 24]
        .copy_from_slice(&u32::try_from(raw_offset).unwrap().to_le_bytes());
    let at_rva = |rva: u32| raw_offset + usize::try_from(rva - 0x1000).unwrap();
    let identity = at_rva(0x17_32d0);
    image[identity..identity + 16].copy_from_slice(&BT_SIGNATURE);
    let version_offset = at_rva(0x17_32e0);
    image[version_offset..version_offset + 2].copy_from_slice(&version.to_le_bytes());
    let length_offset = at_rva(0x17_32e4);
    image[length_offset..length_offset + 4]
        .copy_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    let payload_offset = at_rva(0x17_32f0);
    image[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    image
}

#[test]
fn main_candidate_reports_archive_and_payload_measurements() {
    let payload = vec![0x5a; 51_500];
    let archive = zip_member("firmware/kk3.bin", &payload, SimpleFileOptions::default());
    let candidate = CandidatePackageInspection::inspect(
        &archive,
        Model::Kk3Max,
        Component::Main,
        "6.1",
        "firmware/kk3.bin",
    )
    .unwrap();
    let info = candidate.info();
    assert_eq!(info.version, "6.1");
    assert_eq!(info.parser_id, ParserId::Kk3MainBinaryV1);
    assert_eq!(info.archive_size, archive.len());
    assert_eq!(info.archive_sha256, sha(&archive));
    assert_eq!(info.member, "firmware/kk3.bin");
    assert_eq!(info.member_size, payload.len());
    assert_eq!(info.member_sha256, sha(&payload));
    assert_eq!(info.payload_size, payload.len());
    assert_eq!(info.payload_sha256, sha(&payload));
}

#[test]
fn bluetooth_candidate_uses_the_shared_fixed_pe_recipe_and_embedded_version() {
    let payload = vec![0x73; 512 * 4];
    let executable = minimal_bluetooth_pe(324, &payload);
    let archive = zip_member(
        "fw/controller.exe",
        &executable,
        SimpleFileOptions::default(),
    );
    let candidate = CandidatePackageInspection::inspect(
        &archive,
        Model::Kk3Max,
        Component::Bluetooth,
        "3.24",
        "fw/controller.exe",
    )
    .unwrap();
    assert_eq!(candidate.info().parser_id, ParserId::Kk3BluetoothPeV1);
    assert_eq!(candidate.info().member_size, executable.len());
    assert_eq!(candidate.info().member_sha256, sha(&executable));
    assert_eq!(candidate.info().payload_size, payload.len());
    assert_eq!(candidate.info().payload_sha256, sha(&payload));
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &archive,
            Model::Kk3Max,
            Component::Bluetooth,
            "3.23",
            "fw/controller.exe"
        ),
        Err(PackageError::EmbeddedMetadata)
    ));
}

#[test]
fn candidate_rejects_duplicate_unsafe_oversized_and_crc_corrupt_members() {
    let payload = vec![1; 51_500];
    let duplicate = duplicate_name_archive(&payload);
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &duplicate,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        ),
        Err(PackageError::Archive(_))
    ));

    let unsafe_archive = zip_member("../fw.bin", &payload, SimpleFileOptions::default());
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &unsafe_archive,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "../fw.bin"
        ),
        Err(PackageError::InvalidCandidateMetadata)
    ));

    let mut symlink_writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    symlink_writer
        .add_symlink("fw.bin", "target", SimpleFileOptions::default())
        .unwrap();
    let symlink_archive = symlink_writer.finish().unwrap().into_inner();
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &symlink_archive,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        ),
        Err(PackageError::InvalidMember)
    ));

    let mut encrypted = zip_member(
        "fw.bin",
        &payload,
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    );
    let central = encrypted
        .windows(4)
        .rposition(|window| window == b"PK\x01\x02")
        .unwrap();
    let local_flags = u16::from_le_bytes([encrypted[6], encrypted[7]]) | 1;
    encrypted[6..8].copy_from_slice(&local_flags.to_le_bytes());
    let central_flags = u16::from_le_bytes([encrypted[central + 8], encrypted[central + 9]]) | 1;
    encrypted[central + 8..central + 10].copy_from_slice(&central_flags.to_le_bytes());
    assert!(
        CandidatePackageInspection::inspect(
            &encrypted,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        )
        .is_err()
    );

    let oversized = vec![0; 16 * 1024 * 1024 + 1];
    let oversized_archive = zip_member("fw.bin", &oversized, SimpleFileOptions::default());
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &oversized_archive,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        ),
        Err(PackageError::CandidateMemberTooLarge)
    ));

    let mut corrupt = zip_member(
        "fw.bin",
        &payload,
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    );
    let name_length = usize::from(u16::from_le_bytes([corrupt[26], corrupt[27]]));
    let extra_length = usize::from(u16::from_le_bytes([corrupt[28], corrupt[29]]));
    corrupt[30 + name_length + extra_length] ^= 0xff;
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &corrupt,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        ),
        Err(PackageError::Archive(_) | PackageError::Read(_))
    ));
}

#[test]
fn candidate_rejects_bad_main_size_and_unsupported_selection() {
    let archive = zip_member("fw.bin", b"short", SimpleFileOptions::default());
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &archive,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        ),
        Err(PackageError::Size {
            kind: "main member",
            ..
        })
    ));
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &archive,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "../fw.bin"
        ),
        Err(PackageError::InvalidCandidateMetadata)
    ));
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &archive,
            Model::Kk3Max,
            Component::Main,
            "nonsense",
            "fw.bin"
        ),
        Err(PackageError::InvalidCandidateMetadata)
    ));
}

#[test]
fn candidate_enforces_archive_bound_before_zip_parsing() {
    let oversized = vec![0; 64 * 1024 * 1024 + 1];
    assert!(matches!(
        CandidatePackageInspection::inspect(
            &oversized,
            Model::Kk3Max,
            Component::Main,
            "6.1",
            "fw.bin"
        ),
        Err(PackageError::CandidateArchiveTooLarge)
    ));
}
