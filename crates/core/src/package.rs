//! Offline inspection of reviewed official firmware packages.

use object::read::pe::PeFile32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::{fmt, str::FromStr};

/// Upper bound checked before reading a package from an untrusted file.
pub const MAX_ARCHIVE_SIZE: usize = 1_163_538;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
    bluetooth_version: Option<u16>,
}

impl VerifiedPackage {
    /// Authenticate an original reviewed archive and extract its selected payload offline.
    ///
    /// # Errors
    ///
    /// Rejects unreviewed archive lengths/digests, invalid or encrypted ZIP members,
    /// read failures, mismatched member/payload digests and incompatible embedded
    /// executable metadata or address ranges. No embedded executable is run.
    pub fn inspect(bytes: &[u8], model: Model, component: Component) -> Result<Self, PackageError> {
        let release = release_from_archive(bytes, model, component)?;
        let member = read_member(bytes, release.member, release.member_size)?;
        verify_bytes(
            &member,
            release.member_size,
            release.member_sha256,
            "member",
        )?;
        let payload = match component {
            Component::Main => member,
            Component::Bluetooth => extract_bluetooth_payload(&member, release)?,
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
            bluetooth_version: release.bluetooth_version,
        })
    }

    #[must_use]
    pub fn info(&self) -> &PackageInfo {
        &self.info
    }

    pub(crate) fn bluetooth_version(&self) -> Option<u16> {
        self.bluetooth_version
    }
    #[must_use]
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
    #[serde(skip)]
    bluetooth_version: Option<u16>,
}

impl Release {
    /// Apply version direction policy to the selected reviewed release.
    ///
    /// # Errors
    ///
    /// Rejects malformed version text, including Bluetooth versions that cannot be
    /// represented by the protocol's unsigned 16-bit hundredths value.
    pub fn decision_for_installed(
        &self,
        installed: &str,
        policy: crate::version::VersionPolicy,
    ) -> Result<crate::version::VersionDecision, crate::version::UnknownVersion> {
        crate::version::release_decision(self.component, installed, self.version, policy)
    }

    /// Exact payload length pinned to this reviewed release.
    #[must_use]
    pub fn payload_size(&self) -> usize {
        self.payload_size
    }

    /// Exact selected member length pinned to this reviewed release.
    #[must_use]
    pub fn member_size(&self) -> usize {
        self.member_size
    }

    /// SHA-256 of the selected archive member pinned to this reviewed release.
    #[must_use]
    pub fn member_sha256(&self) -> &'static str {
        self.member_sha256
    }

    /// SHA-256 of the payload pinned to this reviewed release.
    #[must_use]
    pub fn payload_sha256(&self) -> &'static str {
        self.payload_sha256
    }
}

const MAIN_HASH: &str = "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4";

static RELEASES: [Release; 4] = [
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
        bluetooth_version: None,
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
        bluetooth_version: Some(507),
    },
    Release {
        model: Model::Kk3Max,
        component: Component::Bluetooth,
        version: "3.24",
        archive: "NS38_NS39_BT_V3.24.zip",
        archive_size: 1_163_538,
        archive_sha256: "1bcccf02448b9c92b5b69d82b168b951c883ea6d71ec6463127523d0b275ab30",
        source_url: "https://gulikit.com/filedownload/133023",
        member: "GuliKit_NS38_NS39_BT_V3.24.exe",
        member_size: 2_245_632,
        member_sha256: "38e24c9e49952fbba14764f688a020fb22a49786321382bc5a2ea76822addc2c",
        payload_size: 361_472,
        payload_sha256: "e540b990cd07df2deb91ac90d20428ddf7788a15f55d84aaaf88cdd99ea71606",
        bluetooth_version: Some(324),
    },
    Release {
        model: Model::Kk3Max,
        component: Component::Bluetooth,
        version: "3.23",
        archive: "NS39_BT_V3.23.zip",
        archive_size: 1_163_454,
        archive_sha256: "39d678170e8d86488d65eb815873c708ff31b096d69d93714a0177086d5db938",
        source_url: "https://gulikit.com/filedownload/123020",
        member: "NS39_BT_V3.23.exe",
        member_size: 2_245_632,
        member_sha256: "825cca9b36fa9078d8198f31ab4bf0ecebb4a6a8bd100303801ba1d1363c4dd6",
        payload_size: 361_472,
        payload_sha256: "783d206c08253c1e2291a8b0bc99b04f95fc4054c2215447a30933f623cf9dfe",
        bluetooth_version: Some(323),
    },
];

#[must_use]
pub fn catalog() -> &'static [Release] {
    &RELEASES
}

fn release_from_archive(
    bytes: &[u8],
    model: Model,
    component: Component,
) -> Result<&'static Release, PackageError> {
    let mut candidates = RELEASES
        .iter()
        .filter(|release| release.model == model && release.component == component);
    if !candidates
        .clone()
        .any(|release| bytes.len() == release.archive_size)
    {
        return Err(PackageError::Size {
            kind: "archive",
            expected: candidates.clone().next().unwrap().archive_size,
            actual: bytes.len(),
        });
    }
    let digest = Sha256::digest(bytes);
    candidates
        .find(|release| {
            bytes.len() == release.archive_size && digest_matches(&digest, release.archive_sha256)
        })
        .ok_or(PackageError::Digest { kind: "archive" })
}

fn digest_matches(actual: &[u8], expected_hex: &str) -> bool {
    let mut expected = [0; 32];
    hex::decode_to_slice(expected_hex, &mut expected).is_ok() && actual == expected
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
    if !digest_matches(&Sha256::digest(bytes), digest) {
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

fn extract_bluetooth_payload(exe: &[u8], release: &Release) -> Result<Vec<u8>, PackageError> {
    let image = PeFile32::parse(exe)?;
    let identity = pe_bytes(&image, exe, 0x17_32d0, 16)?;
    let version = pe_bytes(&image, exe, 0x17_32e0, 2)?;
    let length = pe_bytes(&image, exe, 0x17_32e4, 4)?;
    // The reviewed 3.23, 3.24 and 5.07 programs share this layout and identical
    // transport code. Version and payload size belong to the selected archive.
    let target = release
        .bluetooth_version
        .ok_or(PackageError::EmbeddedMetadata)?;
    let size: u32 = release
        .payload_size
        .try_into()
        .map_err(|_| PackageError::EmbeddedRange)?;
    if identity != crate::version::BT_SIGNATURE
        || version != target.to_le_bytes()
        || length != size.to_le_bytes()
    {
        return Err(PackageError::EmbeddedMetadata);
    }
    Ok(pe_bytes(&image, exe, 0x17_32f0, release.payload_size)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[test]
    fn catalog_bounds_and_target_versions_match_the_reviewed_release_metadata() {
        let mut archives = std::collections::BTreeSet::new();
        for release in catalog() {
            assert!(release.archive_size <= MAX_ARCHIVE_SIZE);
            assert!(archives.insert(release.archive_sha256));
            if let Some(version) = release.bluetooth_version {
                assert_eq!(
                    format!("{}.{:02}", version / 100, version % 100),
                    release.version
                );
                assert!(release.payload_size > 0 && release.payload_size.is_multiple_of(512));
            }
        }
    }
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
            extract_bluetooth_payload(b"not a PE executable", &RELEASES[1]),
            Err(PackageError::Executable(_))
        ));
    }
}
