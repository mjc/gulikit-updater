//! Offline measurements; none of these bytes can authorize a controller write.

use crate::{Component, FirmwareMemberKind, ReleaseMetadata, git::GitArchiveError};
use gulikit_core::version::BT_SIGNATURE;
use object::read::pe::PeFile32;
use std::io::{Cursor, Read};

const MAX_MEMBER_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn firmware_bytes(
    metadata: &ReleaseMetadata,
    zip: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>), GitArchiveError> {
    if !metadata
        .member_kind
        .accepts_member(metadata.component, &metadata.firmware_member)
    {
        return Err(invalid(
            "selected member extension does not match its firmware kind",
        ));
    }

    let mut archive = zip::ZipArchive::new(Cursor::new(zip)).map_err(invalid)?;
    let member = archive
        .by_name(&metadata.firmware_member)
        .map_err(invalid)?;
    if !member.is_file() || member.encrypted() || member.size() > MAX_MEMBER_BYTES {
        return Err(invalid(
            "selected firmware file is not a bounded regular member",
        ));
    }
    let mut file = Vec::new();
    member.take(MAX_MEMBER_BYTES + 1).read_to_end(&mut file)?;
    if file.is_empty() || file.len() as u64 > MAX_MEMBER_BYTES {
        return Err(invalid("selected firmware file is empty or too large"));
    }
    let payload = match (metadata.member_kind, metadata.component) {
        (FirmwareMemberKind::Kk3, Component::Base) | (FirmwareMemberKind::RawBinary, _) => {
            Some(file.clone())
        }
        (FirmwareMemberKind::Kk3, Component::Bluetooth) => {
            Some(bluetooth_payload(&file, &metadata.version)?.to_vec())
        }
        (FirmwareMemberKind::OpaqueUpdaterExe, _) => None,
    };
    Ok((file, payload))
}

fn bluetooth_payload<'a>(exe: &'a [u8], version: &str) -> Result<&'a [u8], GitArchiveError> {
    // This is the same PE32 layout used by the reviewed Windows updater parser.
    // Version and length come from the image; no executable is launched.
    let image = PeFile32::parse(exe).map_err(invalid)?;
    if pe_bytes(&image, exe, 0x17_32d0, 16)? != BT_SIGNATURE {
        return Err(invalid("unrecognized Bluetooth firmware signature"));
    }
    let version_bytes = pe_bytes(&image, exe, 0x17_32e0, 2)?;
    let encoded = u16::from_le_bytes(version_bytes.try_into().map_err(invalid)?);
    if format!("{}.{:02}", encoded / 100, encoded % 100) != version {
        return Err(invalid(
            "Bluetooth image version does not match release metadata",
        ));
    }
    let size_bytes = pe_bytes(&image, exe, 0x17_32e4, 4)?;
    let size = u32::from_le_bytes(size_bytes.try_into().map_err(invalid)?);
    if size == 0 || size > 1024 * 1024 || !size.is_multiple_of(512) {
        return Err(invalid("invalid embedded Bluetooth firmware size"));
    }
    pe_bytes(&image, exe, 0x17_32f0, size as usize)
}

fn pe_bytes<'a>(
    image: &PeFile32<'a>,
    exe: &'a [u8],
    rva: u32,
    size: usize,
) -> Result<&'a [u8], GitArchiveError> {
    let (offset, remaining) = image
        .section_table()
        .pe_file_range_at(rva)
        .ok_or_else(|| invalid("embedded Bluetooth data is outside PE sections"))?;
    if size > remaining as usize {
        return Err(invalid("embedded Bluetooth data exceeds its PE section"));
    }
    let start = offset as usize;
    let end = start
        .checked_add(size)
        .ok_or_else(|| invalid("embedded range overflow"))?;
    exe.get(start..end)
        .ok_or_else(|| invalid("embedded Bluetooth data is truncated"))
}

fn invalid(error: impl std::fmt::Display) -> GitArchiveError {
    GitArchiveError::Zip(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn metadata(firmware_member: &str) -> ReleaseMetadata {
        ReleaseMetadata {
            product: "kk3-max".to_owned(),
            member_kind: FirmwareMemberKind::Kk3,
            component: Component::Base,
            version: "5.9".to_owned(),
            filename: "firmware.zip".to_owned(),
            source_url: "https://example.com/release".to_owned(),
            released_at: None,
            retrieved_at: None,
            retrieved_from: None,
            changelog: None,
            changelog_source_url: None,
            firmware_member: firmware_member.to_owned(),
            published_hashes: Vec::new(),
        }
    }

    fn zip_with_member(name: &str, content: &[u8]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(content).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn image() -> Vec<u8> {
        let mut bytes = vec![0; 0x800];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x14c_u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&224_u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x10b_u16.to_le_bytes());
        let section = 0x178;
        bytes[section..section + 5].copy_from_slice(b".data");
        bytes[section + 8..section + 12].copy_from_slice(&0x600_u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x17_3000_u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x600_u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[0x4d0..0x4e0].copy_from_slice(&BT_SIGNATURE);
        bytes[0x4e0..0x4e2].copy_from_slice(&324_u16.to_le_bytes());
        bytes[0x4e4..0x4e8].copy_from_slice(&512_u32.to_le_bytes());
        bytes[0x4f0..0x6f0].fill(0xa5);
        bytes
    }

    #[test]
    fn measures_exact_pe_payload_without_executing_the_program() {
        let exe = image();
        assert_eq!(bluetooth_payload(&exe, "3.24").unwrap(), &[0xa5; 512]);
        assert!(bluetooth_payload(&exe, "3.23").is_err());
        assert!(bluetooth_payload(&exe[..0x600], "3.24").is_err());
        let mut wrong_signature = exe.clone();
        wrong_signature[0x4d0] ^= 1;
        assert!(bluetooth_payload(&wrong_signature, "3.24").is_err());
        let mut oversized = exe;
        oversized[0x4e4..0x4e8].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        assert!(bluetooth_payload(&oversized, "3.24").is_err());
    }

    #[test]
    fn base_firmware_member_must_be_a_bin_file() {
        let readme_zip = zip_with_member("readme.txt", b"not firmware");
        assert!(firmware_bytes(&metadata("readme.txt"), &readme_zip).is_err());

        let firmware_zip = zip_with_member("firmware.BIN", b"firmware bytes");
        let (file, payload) = firmware_bytes(&metadata("firmware.BIN"), &firmware_zip).unwrap();
        assert_eq!(file, b"firmware bytes");
        assert_eq!(payload.as_deref(), Some(&b"firmware bytes"[..]));
    }

    #[test]
    fn explicit_member_kinds_measure_raw_and_opaque_files() {
        let raw_zip = zip_with_member("board.bin", b"raw image");
        let raw_metadata = ReleaseMetadata {
            product: "other-controller".to_owned(),
            member_kind: FirmwareMemberKind::RawBinary,
            firmware_member: "board.bin".to_owned(),
            ..metadata("board.bin")
        };
        let (raw_file, raw_payload) = firmware_bytes(&raw_metadata, &raw_zip).unwrap();
        assert_eq!(raw_file, b"raw image");
        assert_eq!(raw_payload.as_deref(), Some(&b"raw image"[..]));

        let updater_zip = zip_with_member("update.exe", b"opaque updater bytes");
        let updater_metadata = ReleaseMetadata {
            product: "other-controller".to_owned(),
            member_kind: FirmwareMemberKind::OpaqueUpdaterExe,
            firmware_member: "update.exe".to_owned(),
            ..metadata("update.exe")
        };
        let (updater_file, updater_payload) =
            firmware_bytes(&updater_metadata, &updater_zip).unwrap();
        assert_eq!(updater_file, b"opaque updater bytes");
        assert_eq!(updater_payload, None);

        let invalid_member = ReleaseMetadata {
            firmware_member: "readme.txt".to_owned(),
            ..updater_metadata
        };
        assert!(firmware_bytes(&invalid_member, &updater_zip).is_err());
    }
}
