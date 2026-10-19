//! Component-specific installed-version policy. Unknown versions never authorize writes.
use serde::{Deserialize, Serialize};
use std::fmt;

pub const BT_SIGNATURE: [u8; 16] = [
    0xa1, 0xca, 0x51, 0xda, 0x72, 0x4c, 0xb6, 0x10, 0x36, 0x58, 0xc0, 0x5d, 0x7d, 0x4e, 0x15, 0x96,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionDecision {
    Eligible,
    AlreadyCurrent,
    NewerThanSupported,
}

/// Explicit version-direction permission; it never authorizes an unverified device or package.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionPolicy {
    #[default]
    UpgradeOnly,
    AllowDowngrade,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Unknown or incompatible installed firmware version; writing refused.")]
pub struct UnknownVersion;

fn decision<T: Ord + Copy>(current: T, target: T, policy: VersionPolicy) -> VersionDecision {
    match current.cmp(&target) {
        std::cmp::Ordering::Less => VersionDecision::Eligible,
        std::cmp::Ordering::Equal => VersionDecision::AlreadyCurrent,
        std::cmp::Ordering::Greater if policy == VersionPolicy::AllowDowngrade => {
            VersionDecision::Eligible
        }
        std::cmp::Ordering::Greater => VersionDecision::NewerThanSupported,
    }
}

/// Compare canonical version text already obtained from a validated device read.
pub(crate) fn release_decision(
    component: crate::package::Component,
    installed: &str,
    target: &str,
    policy: VersionPolicy,
) -> Result<VersionDecision, UnknownVersion> {
    let parts = |text: &str| -> Result<(u16, u16), UnknownVersion> {
        let (major, minor) = text.split_once('.').ok_or(UnknownVersion)?;
        let part = |value: &str| -> Result<u16, UnknownVersion> {
            if !(1..=4).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(UnknownVersion);
            }
            value.parse().map_err(|_| UnknownVersion)
        };
        let value = (part(major)?, part(minor)?);
        if component == crate::package::Component::Bluetooth
            && (minor.len() != 2
                || value
                    .0
                    .checked_mul(100)
                    .and_then(|major| major.checked_add(value.1))
                    .is_none())
        {
            return Err(UnknownVersion);
        }
        Ok(value)
    };
    Ok(decision(parts(installed)?, parts(target)?, policy))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MainVersion {
    major: u16,
    minor: u16,
    original: String,
}

impl MainVersion {
    /// Parse the bounded controller version file while retaining its original bytes as text.
    ///
    /// # Errors
    ///
    /// Rejects non-ASCII, NUL-containing or oversized input, unpaired carriage
    /// returns, missing/duplicate identity or version lines and malformed numbers.
    pub fn parse(bytes: &[u8]) -> Result<Self, UnknownVersion> {
        if bytes.len() > 4096 || !bytes.is_ascii() || bytes.contains(&0) {
            return Err(UnknownVersion);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| UnknownVersion)?;
        if text
            .split('\r')
            .skip(1)
            .any(|suffix| !suffix.starts_with('\n'))
        {
            return Err(UnknownVersion);
        }
        let mut website = false;
        let mut version = None;
        for line in text.split('\n') {
            let line = line
                .strip_suffix('\r')
                .unwrap_or(line)
                .trim_matches([' ', '\t']);
            if line.is_empty() {
                continue;
            }
            if line == "www.gulikit.com" && !website {
                website = true;
                continue;
            }
            if version.is_some() {
                return Err(UnknownVersion);
            }
            let value = line.strip_prefix("version ").ok_or(UnknownVersion)?;
            let (major, minor) = value.split_once('.').ok_or(UnknownVersion)?;
            let part = |s: &str| -> Result<u16, UnknownVersion> {
                if !(1..=4).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UnknownVersion);
                }
                s.parse().map_err(|_| UnknownVersion)
            };
            version = Some((part(major)?, part(minor)?));
        }
        let (major, minor) = version.filter(|_| website).ok_or(UnknownVersion)?;
        Ok(Self {
            major,
            minor,
            original: text.to_owned(),
        })
    }
    #[must_use]
    pub fn decision(&self) -> VersionDecision {
        self.decision_with_policy(VersionPolicy::UpgradeOnly)
    }
    #[must_use]
    pub fn decision_with_policy(&self, policy: VersionPolicy) -> VersionDecision {
        decision((self.major, self.minor), (5, 9), policy)
    }
}
impl fmt::Display for MainVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BluetoothVersion(u16);
impl BluetoothVersion {
    #[must_use]
    pub fn decision(self) -> VersionDecision {
        self.decision_with_policy(VersionPolicy::UpgradeOnly)
    }
    #[must_use]
    pub fn decision_with_policy(self, policy: VersionPolicy) -> VersionDecision {
        self.decision_for(507, policy)
    }
    pub(crate) fn decision_for(self, target: u16, policy: VersionPolicy) -> VersionDecision {
        decision(self.0, target, policy)
    }
}
impl fmt::Display for BluetoothVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.0 / 100, self.0 % 100)
    }
}
/// Call only with the bytes from a successful fresh F1 command.
///
/// # Errors
///
/// Rejects any response that is not exactly 20 bytes or lacks the reviewed
/// Bluetooth identity signature; missing response bytes are never inferred.
pub fn bluetooth_info(bytes: &[u8]) -> Result<BluetoothVersion, UnknownVersion> {
    if bytes.len() != 20 || bytes[..16] != BT_SIGNATURE {
        return Err(UnknownVersion);
    }
    Ok(BluetoothVersion(u16::from_le_bytes([bytes[16], bytes[17]])))
}
