//! USB mass-storage command-status validation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
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
