//! Offline inspection of reviewed official firmware packages.

use object::read::pe::PeFile32;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::{fmt, str::FromStr};

/// Upper bound checked before reading a package from an untrusted file.
pub const MAX_ARCHIVE_SIZE: usize = 1_148_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Main,
    Bluetooth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Model {
    Kk3Max,
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported {kind}: {value}")]
pub struct SelectionError {
    kind: &'static str,
    value: String,
}

impl FromStr for Model {
    type Err = SelectionError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "kk3-max" => Ok(Self::Kk3Max),
            _ => Err(SelectionError {
                kind: "model",
                value: value.into(),
            }),
        }
    }
}

impl FromStr for Component {
    type Err = SelectionError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "main" => Ok(Self::Main),
            "bluetooth" => Ok(Self::Bluetooth),
            _ => Err(SelectionError {
                kind: "component",
                value: value.into(),
            }),
        }
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kk3Max => f.write_str("kk3-max"),
        }
    }
}

impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Main => "main",
            Self::Bluetooth => "bluetooth",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("{kind} size mismatch: expected {expected}, received {actual}")]
    Size {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{kind} SHA-256 does not match the reviewed release")]
    Digest { kind: &'static str },
    #[error("invalid ZIP package: {0}")]
    Archive(#[from] zip::result::ZipError),
    #[error("cannot read firmware member: {0}")]
    Read(#[from] std::io::Error),
    #[error("firmware member is not a regular, unencrypted file")]
    InvalidMember,
    #[error("invalid PE executable: {0}")]
    Executable(#[from] object::Error),
    #[error("embedded firmware address or length is outside the executable")]
    EmbeddedRange,
    #[error("embedded firmware metadata does not match the reviewed release")]
    EmbeddedMetadata,
}

#[derive(Debug, Serialize)]
pub struct PackageInfo {
    pub model: Model,
    pub component: Component,
    pub version: String,
    pub payload_size: usize,
    pub payload_sha256: String,
    pub archive_sha256: String,
    pub source_url: &'static str,
    pub member: &'static str,
}

#[derive(Debug)]
pub struct VerifiedPackage {
    info: PackageInfo,
    payload: Vec<u8>,
}

impl VerifiedPackage {
    pub fn inspect(bytes: &[u8], model: Model, component: Component) -> Result<Self, PackageError> {
        let release = release(model, component);
        verify_bytes(
            bytes,
            release.archive_size,
            release.archive_sha256,
            "archive",
        )?;
        let member = read_member(bytes, release.member, release.member_size)?;
        verify_bytes(
            &member,
            release.member_size,
            release.member_sha256,
            "member",
        )?;
        let payload = match component {
            Component::Main => member,
            Component::Bluetooth => extract_bluetooth_payload(&member)?,
        };
        verify_bytes(
            &payload,
            release.payload_size,
            release.payload_sha256,
            "payload",
        )?;
        Ok(Self {
            info: PackageInfo {
                model,
                component,
                version: release.version.into(),
                payload_size: payload.len(),
                payload_sha256: release.payload_sha256.into(),
                archive_sha256: release.archive_sha256.into(),
                source_url: release.source_url,
                member: release.member,
            },
            payload,
        })
    }

    pub fn info(&self) -> &PackageInfo {
        &self.info
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Reviewed source data is compiled into the application, never loaded from a
/// user-editable inventory. An unknown archive cannot authorize a new payload.
#[derive(Debug, Serialize)]
pub struct Release {
    pub model: Model,
    pub component: Component,
    pub version: &'static str,
    pub archive: &'static str,
    pub archive_size: usize,
    pub archive_sha256: &'static str,
    pub source_url: &'static str,
    pub member: &'static str,
    member_size: usize,
    member_sha256: &'static str,
    payload_size: usize,
    payload_sha256: &'static str,
}

const MAIN_HASH: &str = "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4";

static RELEASES: [Release; 2] = [
    Release {
        model: Model::Kk3Max,
        component: Component::Main,
        version: "5.9",
        archive: "KK3_NS38_NS39_V5.9.zip",
        archive_size: 107_606,
        archive_sha256: "b4d3c74bc2b0f6570523f121d7d8feb8842f239bdfc5e87bffd7af6aee520b67",
        source_url: "https://www.gulikit.com/newsinfo/887152.html",
        member: "NS39_KK3_MAX_V5.9.bin",
        member_size: 51_500,
        member_sha256: MAIN_HASH,
        payload_size: 51_500,
        payload_sha256: MAIN_HASH,
    },
    Release {
        model: Model::Kk3Max,
        component: Component::Bluetooth,
        version: "5.07",
        archive: "GuliKit_NS38_NS39_NS59_BT_V5.07.zip",
        archive_size: 1_148_144,
        archive_sha256: "6ce3db166031d30ff9f61e83387c6f8cb0475eef57321c2347ee32afe9152dad",
        source_url: "https://www.gulikit.com/newsinfo/915900.html",
        member: "GuliKit_NS38_NS39_NS59_BT_V5.07.exe",
        member_size: 2_245_632,
        member_sha256: "3dc8fd352597de4b619efcf139933fbbccc5c1c335aa580455bf5f64f4b9c97a",
        payload_size: 345_088,
        payload_sha256: "2e0e89d458eb39f30eaa1ba9f4038039ad95c2eeed0e392ecfb0d5ece3441826",
    },
];

pub fn catalog() -> &'static [Release] {
    &RELEASES
}

fn release(model: Model, component: Component) -> &'static Release {
    match (model, component) {
        (Model::Kk3Max, Component::Main) => &RELEASES[0],
        (Model::Kk3Max, Component::Bluetooth) => &RELEASES[1],
    }
}

fn verify_bytes(
    bytes: &[u8],
    size: usize,
    digest: &str,
    kind: &'static str,
) -> Result<(), PackageError> {
    if bytes.len() != size {
        return Err(PackageError::Size {
            kind,
            expected: size,
            actual: bytes.len(),
        });
    }
    if hex::encode(Sha256::digest(bytes)) != digest {
        return Err(PackageError::Digest { kind });
    }
    Ok(())
}

fn read_member(bytes: &[u8], name: &str, size: usize) -> Result<Vec<u8>, PackageError> {
    // The complete original ZIP was checked against the reviewed digest
    // before parsing. Read one exact member into memory; never extract paths.
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
    let member = archive.by_name(name)?;
    if !member.is_file() || member.encrypted() {
        return Err(PackageError::InvalidMember);
    }
    if member.size() != size as u64 {
        return Err(PackageError::Size {
            kind: "member",
            expected: size,
            actual: usize::try_from(member.size()).unwrap_or(usize::MAX),
        });
    }
    let mut result = Vec::with_capacity(size);
    member.take(size as u64 + 1).read_to_end(&mut result)?;
    if result.len() != size {
        return Err(PackageError::Size {
            kind: "member",
            expected: size,
            actual: result.len(),
        });
    }
    Ok(result)
}

fn pe_bytes<'a>(
    image: &PeFile32<'a>,
    exe: &'a [u8],
    rva: u32,
    size: usize,
) -> Result<&'a [u8], PackageError> {
    let (offset, remaining) = image
        .section_table()
        .pe_file_range_at(rva)
        .ok_or(PackageError::EmbeddedRange)?;
    if size > remaining as usize {
        return Err(PackageError::EmbeddedRange);
    }
    let start = offset as usize;
    let end = start.checked_add(size).ok_or(PackageError::EmbeddedRange)?;
    exe.get(start..end).ok_or(PackageError::EmbeddedRange)
}

fn extract_bluetooth_payload(exe: &[u8]) -> Result<Vec<u8>, PackageError> {
    let image = PeFile32::parse(exe)?;
    let identity = pe_bytes(&image, exe, 0x1732d0, 16)?;
    let version = pe_bytes(&image, exe, 0x1732e0, 2)?;
    let length = pe_bytes(&image, exe, 0x1732e4, 4)?;
    // These constants describe the hash-pinned 5.07 executable only. The F1
    // signature is also used by older devices; it does not identify NS39.
    if identity
        != [
            0xa1, 0xca, 0x51, 0xda, 0x72, 0x4c, 0xb6, 0x10, 0x36, 0x58, 0xc0, 0x5d, 0x7d, 0x4e,
            0x15, 0x96,
        ]
        || version != 507_u16.to_le_bytes()
        || length != 345_088_u32.to_le_bytes()
    {
        return Err(PackageError::EmbeddedMetadata);
    }
    Ok(pe_bytes(&image, exe, 0x1732f0, 345_088)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[test]
    fn rejects_an_unreviewed_archive_before_zip_parsing() {
        let bytes = vec![0; 107_606];
        assert!(matches!(
            VerifiedPackage::inspect(&bytes, Model::Kk3Max, Component::Main),
            Err(PackageError::Digest { kind: "archive" })
        ));
    }

    #[test]
    fn rejects_truncated_oversized_and_raw_payload_inputs() {
        for size in [0, 51_500, 107_605, MAX_ARCHIVE_SIZE + 1] {
            assert!(matches!(
                VerifiedPackage::inspect(&vec![0; size], Model::Kk3Max, Component::Main),
                Err(PackageError::Size {
                    kind: "archive",
                    ..
                })
            ));
        }
    }

    fn synthetic_zip() -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in [("NS38.bin", &b"wrong"[..]), ("NS39.bin", &b"abc"[..])] {
            zip.start_file(name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn reads_only_the_exact_member_and_checks_its_size() {
        let bytes = synthetic_zip();
        assert_eq!(read_member(&bytes, "NS39.bin", 3).unwrap(), b"abc");
        assert!(matches!(
            read_member(&bytes, "NS39.bin", 4),
            Err(PackageError::Size { kind: "member", .. })
        ));
        assert!(matches!(
            read_member(&bytes, "missing.bin", 3),
            Err(PackageError::Archive(_))
        ));
    }

    #[test]
    fn checks_member_and_payload_digests_independently() {
        const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_bytes(b"abc", 3, ABC, "payload").is_ok());
        assert!(matches!(
            verify_bytes(b"abd", 3, ABC, "payload"),
            Err(PackageError::Digest { kind: "payload" })
        ));
        assert!(matches!(
            verify_bytes(b"ab", 3, ABC, "member"),
            Err(PackageError::Size { kind: "member", .. })
        ));
    }

    #[test]
    fn malformed_executables_are_rejected_by_the_pe_parser() {
        assert!(matches!(
            extract_bluetooth_payload(b"not a PE executable"),
            Err(PackageError::Executable(_))
        ));
    }
}
