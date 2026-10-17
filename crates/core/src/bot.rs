//! USB mass-storage command-status validation.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// One serialized bulk stage. An error must retain OS status, actual count and raw bytes.
pub trait BulkIo {
    fn max_lun(&mut self) -> Result<u8, String>;
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn transfer(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, String>;
}

/// A BOT command session is never resumed after a failed stage. Keep ownership of
/// this object through cleanup so the pre-CBW F0 latch cannot be lost on errors.
pub struct Session<T> {
    io: T,
    tag: u32,
    failed: bool,
    firmware_submitted: bool,
    qualified_lun: Option<u8>,
}
impl<T: BulkIo> Session<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            tag: 0,
            failed: false,
            firmware_submitted: false,
            qualified_lun: None,
        }
    }
    /// This implementation supports only an attachment advertising exactly LUN0.
    pub fn qualify_addressing(&mut self) -> Result<u8, String> {
        if self.failed {
            return Err("BOT session already failed".into());
        }
        if let Some(lun) = self.qualified_lun {
            return Ok(lun);
        }
        let result = self.io.max_lun().and_then(|maximum| {
            if maximum == 0 { Ok(0) } else { Err(format!("Unsupported advertised maximum LUN {maximum}; only the qualified single-LUN profile is supported")) }
        });
        match result {
            Ok(lun) => {
                self.qualified_lun = Some(lun);
                Ok(lun)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    pub fn qualified_lun(&self) -> Option<u8> {
        self.qualified_lun
    }
    pub fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }
    pub fn into_inner(self) -> T {
        self.io
    }
    pub fn firmware_may_have_been_submitted(&self) -> bool {
        self.firmware_submitted
    }
    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn tag(&self) -> u32 {
        self.tag
    }
    fn transfer_before(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, String> {
        let remaining = deadline
            .checked_duration_since(self.io.now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("BOT command deadline expired before next stage")?;
        let actual = self.io.transfer(direction, bytes, remaining)?;
        if self.io.now() >= deadline {
            return Err(format!(
                "BOT command deadline expired; actual={actual} requested={} raw={:02x?}",
                bytes.len(),
                &bytes[..actual.min(bytes.len())]
            ));
        }
        Ok(actual)
    }
    pub fn command(
        &mut self,
        cdb: &[u8],
        direction: Direction,
        data: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, String> {
        if self.failed {
            return Err("BOT session failed; no new command, reset or replay is authorized".into());
        }
        if direction == Direction::Out && data.len() != length {
            return Err("OUT buffer length differs from the command".into());
        }
        self.qualify_addressing()?;
        let expected = u32::try_from(length).map_err(|_| "BOT length exceeds u32")?;
        let tag = self.tag.checked_add(1).ok_or("BOT tag exhausted")?;
        let mut cbw = command_block(tag, direction, expected, cdb).map_err(|e| e.to_string())?;
        self.tag = tag;
        if cdb[0] == 0xf0 {
            self.firmware_submitted = true;
        }
        let deadline = self.io.now() + Duration::from_secs(5);
        let result = (|| -> Result<Vec<u8>, String> {
            if self.transfer_before(Direction::Out, &mut cbw, deadline)? != 31 {
                return Err("Short CBW; command is uncertain".into());
            }
            let mut bytes = if direction == Direction::In {
                vec![0; length]
            } else {
                data.to_vec()
            };
            let actual = self.transfer_before(direction, &mut bytes, deadline)?;
            if actual > length {
                return Err("Invalid bulk data length".into());
            }
            bytes.truncate(actual);
            if direction == Direction::In {
                let stage = data_stage(&bytes, tag, expected)
                    .map_err(|e| format!("{e}; raw={bytes:02x?}"))?;
                if stage == DataStage::EarlyStatus {
                    return Err(format!("Early CSW instead of vendor data: {bytes:02x?}"));
                }
            }
            let mut status = [0; 13];
            let status_actual = self.transfer_before(Direction::In, &mut status, deadline)?;
            if status_actual > status.len() {
                return Err("Invalid CSW transfer length".into());
            }
            validate_status(&status[..status_actual], tag, expected, actual as u32).map_err(
                |e| {
                    format!(
                        "{e}; CSW={:02x?}; data={bytes:02x?}",
                        &status[..status_actual]
                    )
                },
            )?;
            if actual != length {
                return Err(format!("Short vendor data {actual}/{length}: {bytes:02x?}"));
            }
            Ok(if direction == Direction::In {
                bytes
            } else {
                Vec::new()
            })
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    #[error("SCSI CDB must contain 1 to 16 bytes")]
    CdbLength,
}

pub fn command_block(
    tag: u32,
    direction: Direction,
    length: u32,
    cdb: &[u8],
) -> Result<[u8; 31], CommandError> {
    if cdb.is_empty() || cdb.len() > 16 {
        return Err(CommandError::CdbLength);
    }
    let mut bytes = [0; 31];
    bytes[..4].copy_from_slice(b"USBC");
    bytes[4..8].copy_from_slice(&tag.to_le_bytes());
    bytes[8..12].copy_from_slice(&length.to_le_bytes());
    bytes[12] = match direction {
        Direction::In => 0x80,
        Direction::Out => 0,
    };
    bytes[14] = cdb.len() as u8;
    bytes[15..15 + cdb.len()].copy_from_slice(cdb);
    Ok(bytes)
}

#[derive(Debug, PartialEq, Eq)]
pub enum DataStage<'a> {
    Data(&'a [u8]),
    EarlyStatus,
}

pub fn data_stage(bytes: &[u8], tag: u32, expected: u32) -> Result<DataStage<'_>, StatusError> {
    if bytes.len() == 13 && bytes.starts_with(b"USBS") {
        validate_status(bytes, tag, expected, 0)?;
        return Ok(DataStage::EarlyStatus);
    }
    if bytes.len() as u64 > u64::from(expected) {
        return Err(StatusError::Residue);
    }
    Ok(DataStage::Data(bytes))
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    #[error("BOT status must contain exactly 13 bytes")]
    Length,
    #[error("BOT status signature is invalid")]
    Signature,
    #[error("BOT status tag does not match the command")]
    Tag,
    #[error("BOT residue does not match the actual transfer length")]
    Residue,
    #[error("device rejected the command")]
    CommandFailed,
    #[error("BOT phase error")]
    PhaseError,
    #[error("invalid BOT command status {0}")]
    UnknownStatus(u8),
}

pub fn validate_status(
    bytes: &[u8],
    tag: u32,
    expected: u32,
    actual: u32,
) -> Result<(), StatusError> {
    let bytes: &[u8; 13] = bytes.try_into().map_err(|_| StatusError::Length)?;
    if &bytes[..4] != b"USBS" {
        return Err(StatusError::Signature);
    }
    if u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != tag {
        return Err(StatusError::Tag);
    }
    let residue = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if expected.checked_sub(actual) != Some(residue) {
        return Err(StatusError::Residue);
    }
    match bytes[12] {
        0 => Ok(()),
        1 => Err(StatusError::CommandFailed),
        2 => Err(StatusError::PhaseError),
        other => Err(StatusError::UnknownStatus(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_real_inquiry_status() {
        let status = [
            0x55, 0x53, 0x42, 0x53, 0x47, 0x55, 0x4c, 0x49, 0, 0, 0, 0, 0,
        ];
        assert_eq!(validate_status(&status, 0x494c5547, 36, 36), Ok(()));
    }

    #[test]
    fn rejects_bad_signature_tag_residue_and_device_errors() {
        let original = [
            0x55, 0x53, 0x42, 0x53, 0x47, 0x55, 0x4c, 0x49, 0, 0, 0, 0, 0,
        ];
        for (offset, error) in [
            (0, StatusError::Signature),
            (4, StatusError::Tag),
            (8, StatusError::Residue),
            (12, StatusError::CommandFailed),
        ] {
            let mut bytes = original;
            bytes[offset] ^= 1;
            assert_eq!(validate_status(&bytes, 0x494c5547, 36, 36), Err(error));
        }
        assert_eq!(
            validate_status(&original[..12], 0x494c5547, 36, 36),
            Err(StatusError::Length)
        );
        assert_eq!(
            validate_status(&original, 0x494c5547, 20, 21),
            Err(StatusError::Residue)
        );
    }

    #[test]
    fn accepts_a_short_data_stage_only_with_matching_residue() {
        let mut bytes = [
            0x55, 0x53, 0x42, 0x53, 0x47, 0x55, 0x4c, 0x49, 0, 0, 0, 0, 0,
        ];
        bytes[8] = 20;
        assert_eq!(validate_status(&bytes, 0x494c5547, 20, 0), Ok(()));
        assert_eq!(
            validate_status(&bytes, 0x494c5547, 20, 7),
            Err(StatusError::Residue)
        );
    }

    #[test]
    fn encodes_the_observed_inquiry_cbw() {
        assert_eq!(
            command_block(0x494c5547, Direction::In, 36, &[0x12, 0, 0, 0, 36, 0]).unwrap(),
            [
                0x55, 0x53, 0x42, 0x43, 0x47, 0x55, 0x4c, 0x49, 0x24, 0, 0, 0, 0x80, 0, 6, 0x12, 0,
                0, 0, 0x24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn an_early_csw_is_not_identity_data() {
        let bytes = [
            0x55, 0x53, 0x42, 0x53, 0x47, 0x55, 0x4c, 0x49, 20, 0, 0, 0, 0,
        ];
        assert_eq!(
            data_stage(&bytes, 0x494c5547, 20),
            Ok(DataStage::EarlyStatus)
        );
        assert_eq!(data_stage(&bytes, 1, 20), Err(StatusError::Tag));
    }
}
