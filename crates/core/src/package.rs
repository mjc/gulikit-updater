//! Offline inspection of reviewed official firmware packages.

use object::read::pe::PeFile32;
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::{fmt, str::FromStr};

/// Upper bound checked before reading a package from an untrusted file.
pub const MAX_ARCHIVE_SIZE: usize = 64 * 1024 * 1024;
const MAX_ARCHIVE_MEMBER_SIZE: usize = 4 * 1024 * 1024;
const MAX_BLUETOOTH_PAYLOAD_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Main,
    Bluetooth,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Model {
    Kk3Max,
}

/// Fixed byte format understood by the KK3 Max package inspector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveParserKind {
    /// A bounded raw NS39 Main firmware BIN; the selected member is the payload.
    MainBinV1,
    /// The reviewed KK3 Bluetooth PE32 layout with embedded signature/version/length.
    BluetoothPeV1,
}

/// Descriptive snapshot supplied by the pinned archive-record loader.
///
/// Construct this from the exact record resolved at `archive_revision` and `path`.
/// Core validates its format and byte claims, but does not establish Git membership
/// or vendor authenticity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSelectionData {
    pub archive_revision: String,
    pub path: String,
    pub component: Component,
    pub version: String,
    pub archive: String,
    pub archive_size: u64,
    pub archive_sha256: String,
    pub firmware_member: String,
    pub member_size: u64,
    pub member_sha256: String,
    pub payload_size: u64,
    pub payload_sha256: String,
    pub source_url: String,
    pub parser: ArchiveParserKind,
}

/// Structurally validated snapshot of one selected archive record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ArchiveSelection {
    data: Box<ArchiveSelectionData>,
}

impl ArchiveSelection {
    /// The checked, immutable record snapshot.
    #[must_use]
    pub fn data(&self) -> &ArchiveSelectionData {
        &self.data
    }
}

impl<'de> Deserialize<'de> for ArchiveSelection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = ArchiveSelectionData::deserialize(deserializer)?;
        Self::try_from(data).map_err(de::Error::custom)
    }
}

impl TryFrom<ArchiveSelectionData> for ArchiveSelection {
    type Error = PackageError;

    fn try_from(data: ArchiveSelectionData) -> Result<Self, Self::Error> {
        validate_archive_selection(&data)?;
        Ok(Self {
            data: Box::new(data),
        })
    }
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
    #[error("archive selection is unsupported or malformed: {0}")]
    InvalidArchiveSelection(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub model: Model,
    pub component: Component,
    pub version: String,
    pub payload_size: usize,
    pub payload_sha256: String,
    pub archive_sha256: String,
    pub source_url: String,
    pub member: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_selection: Option<ArchiveSelection>,
}

impl PackageInfo {
    /// Apply version-direction policy using this package's selected target.
    ///
    /// # Errors
    /// Rejects malformed component-specific version text.
    pub fn decision_for_installed(
        &self,
        installed: &str,
        policy: crate::version::VersionPolicy,
    ) -> Result<crate::version::VersionDecision, crate::version::UnknownVersion> {
        crate::version::release_decision(self.component, installed, &self.version, policy)
    }

    /// Check that display/receipt metadata still describes this selected record.
    #[must_use]
    pub fn matches_archive_selection(&self, selection: &ArchiveSelection) -> bool {
        let data = selection.data();
        self.model == Model::Kk3Max
            && self.component == data.component
            && self.version == data.version
            && self.payload_size == usize::try_from(data.payload_size).unwrap_or(usize::MAX)
            && self.payload_sha256 == data.payload_sha256
            && self.archive_sha256 == data.archive_sha256
            && self.source_url == data.source_url
            && self.member == data.firmware_member
            && self.archive_selection.as_ref() == Some(selection)
    }
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
                source_url: release.source_url.into(),
                member: release.member.into(),
                archive_selection: None,
            },
            payload,
            bluetooth_version: release.bluetooth_version,
        })
    }

    /// Inspect an archive using a structurally validated KK3 format selection.
    ///
    /// The caller must obtain the selection from the exact archive record resolved
    /// at its immutable revision. This verifies the selected archive/member/payload
    /// bytes and parser identity; it does not establish repository membership.
    ///
    /// # Errors
    /// Rejects mismatched archive/member/payload size or digest, unsupported PE
    /// metadata, and malformed selected package contents.
    pub fn inspect_selected(
        bytes: &[u8],
        selection: &ArchiveSelection,
    ) -> Result<Self, PackageError> {
        let data = selection.data();
        let archive_size = usize::try_from(data.archive_size)
            .map_err(|_| PackageError::InvalidArchiveSelection("archive_size"))?;
        verify_bytes(bytes, archive_size, &data.archive_sha256, "archive")?;
        let member_size = usize::try_from(data.member_size)
            .map_err(|_| PackageError::InvalidArchiveSelection("member_size"))?;
        let member = read_member(bytes, &data.firmware_member, member_size)?;
        verify_bytes(&member, member_size, &data.member_sha256, "member")?;
        let (payload, bluetooth_version) = match data.parser {
            ArchiveParserKind::MainBinV1 => (member, None),
            ArchiveParserKind::BluetoothPeV1 => {
                let expected_payload_size = usize::try_from(data.payload_size)
                    .map_err(|_| PackageError::InvalidArchiveSelection("payload_size"))?;
                let version = parse_bluetooth_version(&data.version)?;
                let payload =
                    extract_bluetooth_payload_for(&member, version, expected_payload_size)?;
                (payload, Some(version))
            }
        };
        let payload_size = usize::try_from(data.payload_size)
            .map_err(|_| PackageError::InvalidArchiveSelection("payload_size"))?;
        verify_bytes(&payload, payload_size, &data.payload_sha256, "payload")?;
        Ok(Self {
            info: PackageInfo {
                model: Model::Kk3Max,
                component: data.component,
                version: data.version.clone(),
                payload_size: payload.len(),
                payload_sha256: data.payload_sha256.clone(),
                archive_sha256: data.archive_sha256.clone(),
                source_url: data.source_url.clone(),
                member: data.firmware_member.clone(),
                archive_selection: Some(selection.clone()),
            },
            payload,
            bluetooth_version,
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

/// Built-in release admitted by the compiled package catalog.
///
/// Archive-backed releases use [`ArchiveSelection`] with the same fixed parsers
/// and byte checks, supplied from an immutable archive-record snapshot.
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

fn validate_archive_selection(data: &ArchiveSelectionData) -> Result<(), PackageError> {
    let invalid = PackageError::InvalidArchiveSelection;
    if data.archive_revision.len() != 40
        || !data
            .archive_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("archive_revision"));
    }
    parse_canonical_version(data.component, &data.version)?;
    let component_path = match data.component {
        Component::Main => "base",
        Component::Bluetooth => "bluetooth",
    };
    let expected_path = format!(
        "/kk3-max/{component_path}/v{}/{}",
        data.version, data.archive
    );
    if data.archive_size == 0
        || data.archive_size > MAX_ARCHIVE_SIZE as u64
        || data.member_size == 0
        || data.member_size > MAX_ARCHIVE_MEMBER_SIZE as u64
        || data.payload_size == 0
        || data.payload_size > MAX_ARCHIVE_MEMBER_SIZE as u64
        || !valid_sha256(&data.archive_sha256)
        || !valid_sha256(&data.member_sha256)
        || !valid_sha256(&data.payload_sha256)
        || data.source_url.len() > 2048
        || !data.source_url.starts_with("https://")
        || data.source_url.bytes().any(|byte| byte.is_ascii_control())
        || !is_archive_filename(data.component, &data.version, &data.archive)
        || !is_firmware_member(data.component, &data.version, &data.firmware_member)
        || data.path != expected_path
    {
        return Err(invalid("record fields"));
    }
    match (data.component, data.parser) {
        (Component::Main, ArchiveParserKind::MainBinV1)
            if data.member_size == data.payload_size
                && data.member_sha256 == data.payload_sha256 => {}
        (Component::Bluetooth, ArchiveParserKind::BluetoothPeV1)
            if data.payload_size <= MAX_BLUETOOTH_PAYLOAD_SIZE as u64
                && data.payload_size.is_multiple_of(512) => {}
        _ => return Err(invalid("component/parser or payload bounds")),
    }
    Ok(())
}

fn parse_canonical_version(
    component: Component,
    version: &str,
) -> Result<(u16, u16), PackageError> {
    let invalid = || PackageError::InvalidArchiveSelection("version");
    let (major, minor) = version.split_once('.').ok_or_else(invalid)?;
    if version.bytes().filter(|byte| *byte == b'.').count() != 1
        || !canonical_integer(major)
        || match component {
            Component::Main => !canonical_integer(minor),
            Component::Bluetooth => {
                minor.len() != 2 || !minor.bytes().all(|byte| byte.is_ascii_digit())
            }
        }
    {
        return Err(invalid());
    }
    let major = major.parse::<u16>().map_err(|_| invalid())?;
    let minor = minor.parse::<u16>().map_err(|_| invalid())?;
    if component == Component::Bluetooth
        && (minor > 99
            || major
                .checked_mul(100)
                .and_then(|v| v.checked_add(minor))
                .is_none())
    {
        return Err(invalid());
    }
    Ok((major, minor))
}

fn canonical_integer(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_archive_filename(component: Component, version: &str, value: &str) -> bool {
    let stem = value.strip_suffix(".zip").unwrap_or_default();
    let accepted = match component {
        Component::Main => [
            format!("GuliKit_NS39_V{version}"),
            format!("GuliKit_NS39_V{version}a"),
            format!("KK3_NS38_NS39_V{version}"),
            format!("KK3_NS38_NS39_V{version}FIX"),
        ]
        .iter()
        .any(|candidate| stem == candidate),
        Component::Bluetooth => [
            format!("NS39_BT_V{version}"),
            format!("NS38_NS39_BT_V{version}"),
            format!("GuliKit_NS38_NS39_BT_V{version}"),
            format!("GuliKit_NS38_NS39_NS59_BT_V{version}"),
        ]
        .iter()
        .any(|candidate| stem == candidate),
    };
    accepted
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn is_firmware_member(component: Component, version: &str, value: &str) -> bool {
    let name = match component {
        Component::Main => {
            value == format!("GuliKit_NS39_V{version}.bin")
                || value == format!("NS39_KK3_MAX_V{version}.bin")
        }
        Component::Bluetooth => [
            format!("NS39_BT_V{version}.exe"),
            format!("GuliKit_NS38_NS39_BT_V{version}.exe"),
            format!("GuliKit_NS38_NS39_NS59_BT_V{version}.exe"),
        ]
        .iter()
        .any(|candidate| value == candidate),
    };
    name && value.len() <= 255 && !value.contains('/') && !value.contains('\\')
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
    let target = release
        .bluetooth_version
        .ok_or(PackageError::EmbeddedMetadata)?;
    extract_bluetooth_payload_for(exe, target, release.payload_size)
}

fn extract_bluetooth_payload_for(
    exe: &[u8],
    target: u16,
    payload_size: usize,
) -> Result<Vec<u8>, PackageError> {
    if payload_size == 0
        || payload_size > MAX_BLUETOOTH_PAYLOAD_SIZE
        || !payload_size.is_multiple_of(512)
    {
        return Err(PackageError::EmbeddedMetadata);
    }
    let image = PeFile32::parse(exe)?;
    let identity = pe_bytes(&image, exe, 0x17_32d0, 16)?;
    let version = pe_bytes(&image, exe, 0x17_32e0, 2)?;
    let length = pe_bytes(&image, exe, 0x17_32e4, 4)?;
    // The reviewed 3.23, 3.24 and 5.07 programs share this layout and identical
    // transport code. Version and payload size belong to the selected archive.
    let size: u32 = payload_size
        .try_into()
        .map_err(|_| PackageError::EmbeddedRange)?;
    if identity != crate::version::BT_SIGNATURE
        || version != target.to_le_bytes()
        || length != size.to_le_bytes()
    {
        return Err(PackageError::EmbeddedMetadata);
    }
    Ok(pe_bytes(&image, exe, 0x17_32f0, payload_size)?.to_vec())
}

fn parse_bluetooth_version(version: &str) -> Result<u16, PackageError> {
    let (major, minor) = parse_canonical_version(Component::Bluetooth, version)?;
    major
        .checked_mul(100)
        .and_then(|value| value.checked_add(minor))
        .ok_or(PackageError::InvalidArchiveSelection("version"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn main_selection(archive: &[u8], member: &[u8]) -> ArchiveSelection {
        ArchiveSelection::try_from(ArchiveSelectionData {
            archive_revision: "0123456789012345678901234567890123456789".into(),
            path: "/kk3-max/base/v3.1/GuliKit_NS39_V3.1.zip".into(),
            component: Component::Main,
            version: "3.1".into(),
            archive: "GuliKit_NS39_V3.1.zip".into(),
            archive_size: archive.len() as u64,
            archive_sha256: hex::encode(Sha256::digest(archive)),
            firmware_member: "GuliKit_NS39_V3.1.bin".into(),
            member_size: member.len() as u64,
            member_sha256: hex::encode(Sha256::digest(member)),
            payload_size: member.len() as u64,
            payload_sha256: hex::encode(Sha256::digest(member)),
            source_url: "https://www.gulikit.com/newsinfo/887152.html".into(),
            parser: ArchiveParserKind::MainBinV1,
        })
        .unwrap()
    }

    fn bluetooth_selection(archive: &[u8], member: &[u8], payload: &[u8]) -> ArchiveSelection {
        ArchiveSelection::try_from(ArchiveSelectionData {
            archive_revision: "0123456789012345678901234567890123456789".into(),
            path: "/kk3-max/bluetooth/v3.24/NS38_NS39_BT_V3.24.zip".into(),
            component: Component::Bluetooth,
            version: "3.24".into(),
            archive: "NS38_NS39_BT_V3.24.zip".into(),
            archive_size: archive.len() as u64,
            archive_sha256: hex::encode(Sha256::digest(archive)),
            firmware_member: "GuliKit_NS38_NS39_BT_V3.24.exe".into(),
            member_size: member.len() as u64,
            member_sha256: hex::encode(Sha256::digest(member)),
            payload_size: payload.len() as u64,
            payload_sha256: hex::encode(Sha256::digest(payload)),
            source_url: "https://www.gulikit.com/newsinfo/887152.html".into(),
            parser: ArchiveParserKind::BluetoothPeV1,
        })
        .unwrap()
    }

    fn zip_member(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(bytes).unwrap();
        zip.finish().unwrap().into_inner()
    }

    fn synthetic_bt_pe(version: u16, size: usize) -> Vec<u8> {
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
        bytes[0x4d0..0x4e0].copy_from_slice(&crate::version::BT_SIGNATURE);
        bytes[0x4e0..0x4e2].copy_from_slice(&version.to_le_bytes());
        bytes[0x4e4..0x4e8].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        bytes[0x4f0..0x4f0 + size].fill(0xa5);
        bytes
    }

    #[test]
    fn archive_selection_rejects_unbounded_or_noncanonical_metadata() {
        let member = b"arbitrary reviewed raw BIN";
        let archive = zip_member("GuliKit_NS39_V3.1.bin", member);
        let valid = main_selection(&archive, member).data().clone();

        let mut malformed = valid.clone();
        malformed.archive_revision = "bad".into();
        assert!(ArchiveSelection::try_from(malformed).is_err());
        let mut malformed = valid.clone();
        malformed.path = "/kk3-max/base/v03.1/GuliKit_NS39_V3.1.zip".into();
        assert!(ArchiveSelection::try_from(malformed).is_err());
        let mut malformed = valid.clone();
        malformed.component = Component::Bluetooth;
        assert!(ArchiveSelection::try_from(malformed).is_err());
        let mut malformed = valid.clone();
        malformed.parser = ArchiveParserKind::BluetoothPeV1;
        assert!(ArchiveSelection::try_from(malformed).is_err());
        let mut malformed = valid.clone();
        malformed.firmware_member = "NS38.bin".into();
        assert!(ArchiveSelection::try_from(malformed).is_err());
        let mut malformed = valid.clone();
        malformed.archive_sha256 = "A".repeat(64);
        assert!(ArchiveSelection::try_from(malformed).is_err());
        let mut malformed = valid;
        malformed.payload_size += 1;
        assert!(ArchiveSelection::try_from(malformed).is_err());
    }

    #[test]
    fn archive_selection_accepts_reviewed_ns39_member_name_families() {
        let archive = b"zip";
        let digest = hex::encode(Sha256::digest(archive));
        for (component, version, filename, member, parser, member_size, payload_size) in [
            (
                Component::Main,
                "3.6",
                "GuliKit_NS39_V3.6a.zip",
                "GuliKit_NS39_V3.6.bin",
                ArchiveParserKind::MainBinV1,
                3,
                3,
            ),
            (
                Component::Main,
                "5.9",
                "KK3_NS38_NS39_V5.9.zip",
                "NS39_KK3_MAX_V5.9.bin",
                ArchiveParserKind::MainBinV1,
                3,
                3,
            ),
            (
                Component::Bluetooth,
                "3.23",
                "NS39_BT_V3.23.zip",
                "NS39_BT_V3.23.exe",
                ArchiveParserKind::BluetoothPeV1,
                3,
                512,
            ),
            (
                Component::Bluetooth,
                "3.24",
                "NS38_NS39_BT_V3.24.zip",
                "GuliKit_NS38_NS39_BT_V3.24.exe",
                ArchiveParserKind::BluetoothPeV1,
                3,
                512,
            ),
            (
                Component::Bluetooth,
                "5.07",
                "GuliKit_NS38_NS39_NS59_BT_V5.07.zip",
                "GuliKit_NS38_NS39_NS59_BT_V5.07.exe",
                ArchiveParserKind::BluetoothPeV1,
                3,
                512,
            ),
        ] {
            let component_path = if component == Component::Main {
                "base"
            } else {
                "bluetooth"
            };
            let data = ArchiveSelectionData {
                archive_revision: "0123456789012345678901234567890123456789".into(),
                path: format!("/kk3-max/{component_path}/v{version}/{filename}"),
                component,
                version: version.into(),
                archive: filename.into(),
                archive_size: archive.len() as u64,
                archive_sha256: digest.clone(),
                firmware_member: member.into(),
                member_size,
                member_sha256: "11".repeat(32),
                payload_size,
                payload_sha256: if component == Component::Main {
                    "11".repeat(32)
                } else {
                    "22".repeat(32)
                },
                source_url: "https://www.gulikit.com/newsinfo/887152.html".into(),
                parser,
            };
            assert!(
                ArchiveSelection::try_from(data.clone()).is_ok(),
                "rejected {component:?} {version} {filename} {member}: {:?}",
                ArchiveSelection::try_from(data).err()
            );
        }
    }

    #[test]
    fn selected_main_bin_is_verified_as_bounded_raw_payload_with_selected_target() {
        let member = b"raw main bytes without an embedded version header";
        let archive = zip_member("GuliKit_NS39_V3.1.bin", member);
        let selection = main_selection(&archive, member);
        let package = VerifiedPackage::inspect_selected(&archive, &selection).unwrap();

        assert_eq!(package.payload(), member);
        assert_eq!(package.info().version, "3.1");
        assert!(package.info().matches_archive_selection(&selection));
        assert_eq!(
            package
                .info()
                .decision_for_installed("5.8", crate::version::VersionPolicy::AllowDowngrade)
                .unwrap(),
            crate::version::VersionDecision::Eligible
        );
        assert!(VerifiedPackage::inspect_selected(b"changed archive", &selection).is_err());
        let mut serialized = serde_json::to_value(&selection).unwrap();
        serialized["path"] = "/kk3-max/base/v9.9/forged.zip".into();
        assert!(serde_json::from_value::<ArchiveSelection>(serialized).is_err());
    }

    #[test]
    fn selected_bluetooth_pe_checks_actual_version_length_and_payload() {
        let firmware = synthetic_bt_pe(324, 512);
        let payload = &firmware[0x4f0..0x4f0 + 512];
        let archive = zip_member("GuliKit_NS38_NS39_BT_V3.24.exe", &firmware);
        let selection = bluetooth_selection(&archive, &firmware, payload);
        let package = VerifiedPackage::inspect_selected(&archive, &selection).unwrap();

        assert_eq!(package.payload(), payload);
        assert!(package.info().matches_archive_selection(&selection));

        let wrong_version = synthetic_bt_pe(323, 512);
        let wrong_archive = zip_member("GuliKit_NS38_NS39_BT_V3.24.exe", &wrong_version);
        assert!(VerifiedPackage::inspect_selected(&wrong_archive, &selection).is_err());
    }

    #[test]
    fn legacy_package_info_omits_optional_archive_selection() {
        let info = PackageInfo {
            model: Model::Kk3Max,
            component: Component::Main,
            version: "5.9".into(),
            payload_size: 1,
            payload_sha256: "00".repeat(32),
            archive_sha256: "00".repeat(32),
            source_url: "https://www.gulikit.com/".into(),
            member: "NS39_KK3_MAX_V5.9.bin".into(),
            archive_selection: None,
        };
        let value = serde_json::to_value(info).unwrap();
        assert!(value.get("archive_selection").is_none());
    }

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
