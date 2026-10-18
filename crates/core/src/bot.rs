//! USB mass-storage command-status validation.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Direction {
    In,
    Out,
}

/// Evidence obtained by the standard `GET_MAX_LUN` request on this attachment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "maximum", rename_all = "snake_case")]
pub enum MaxLun {
    Reported(u8),
    /// BOT 1.0 section 3.2 permits a single-LUN device to STALL this request.
    SingleLunStall,
}
impl MaxLun {
    fn maximum(self) -> u8 {
        match self {
            Self::Reported(value) => value,
            Self::SingleLunStall => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferFailureKind {
    Stall,
    Timeout,
    Other,
}

#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
#[error("{message}; kind={kind:?} actual={actual} raw={raw:02x?}")]
pub struct TransferError {
    pub kind: TransferFailureKind,
    pub actual: usize,
    pub raw: Vec<u8>,
    pub message: String,
}
impl From<String> for TransferError {
    fn from(message: String) -> Self {
        Self {
            kind: TransferFailureKind::Other,
            actual: 0,
            raw: Vec::new(),
            message,
        }
    }
}
impl From<&str> for TransferError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl From<TransferError> for String {
    fn from(error: TransferError) -> Self {
        error.to_string()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "outcome", content = "error", rename_all = "snake_case")]
pub enum StallClear {
    Passed,
    Failed(TransferError),
}

/// Bounded evidence for the latest command. OUT payload bytes are already hash-pinned.
#[derive(Clone, Debug, serde::Serialize)]
pub struct CommandEvidence {
    pub tag: u32,
    pub opcode: u8,
    pub requested: usize,
    pub cbw_actual: Option<usize>,
    pub cbw_error: Option<TransferError>,
    pub data_actual: Option<usize>,
    pub data_in: Option<Vec<u8>>,
    pub csw_reads: u8,
    pub csw_raw: Vec<u8>,
    pub csw_actual: Option<usize>,
    pub csw_errors: Vec<TransferError>,
    pub stall_clear: Option<StallClear>,
    pub stall_clear_elapsed: Option<Duration>,
    /// Observed NS39 F2: one success byte with a passed zero-residue CSW.
    /// Actual DATA and raw CSW fields remain unchanged when this is accepted.
    pub f2_zero_residue_quirk: bool,
}

/// One serialized bulk stage. An error must retain OS status, actual count and raw bytes.
pub trait BulkIo {
    /// Read the attachment's advertised LUN addressing evidence.
    ///
    /// # Errors
    ///
    /// Returns the adapter's failure when `GET_MAX_LUN` cannot establish a maximum
    /// or the permitted single-LUN stall response.
    fn max_lun(&mut self) -> Result<MaxLun, String>;
    /// Clear only the Bulk-IN halt for the original CSW. Never reset or resubmit a CBW.
    /// Keep ownership until this operation has finished, including any OS deadline overrun.
    ///
    /// # Errors
    ///
    /// Fails when halt clearance is unsupported or the host operation fails;
    /// the error must retain its actual count and native status evidence.
    fn clear_stall(&mut self, _budget: Duration) -> Result<(), TransferError> {
        Err("Bulk-IN stall clearance is unsupported by this adapter".into())
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    /// Complete one bulk stage within the supplied remaining request budget.
    ///
    /// # Errors
    ///
    /// Reports stalls, timeouts and other host failures with actual transferred
    /// bytes and raw evidence. An error never authorizes replay of the command.
    fn transfer(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, TransferError>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DataPolicy {
    Exact,
    F2Status,
    DiagnosticSense,
}

/// A BOT command session is never resumed after a failed stage. Keep ownership of
/// this object through cleanup so the pre-CBW F0 latch cannot be lost on errors.
pub struct Session<T> {
    io: T,
    tag: u32,
    failed: bool,
    firmware_submitted: bool,
    qualified_lun: Option<u8>,
    lun_evidence: Option<MaxLun>,
    failed_f1_status: Option<[u8; 13]>,
    sense_used: bool,
    evidence: Option<CommandEvidence>,
}
impl<T: BulkIo> Session<T> {
    pub fn new(io: T) -> Self {
        Self {
            io,
            tag: 0,
            failed: false,
            firmware_submitted: false,
            qualified_lun: None,
            lun_evidence: None,
            failed_f1_status: None,
            sense_used: false,
            evidence: None,
        }
    }
    /// This implementation supports only an attachment advertising exactly LUN0.
    ///
    /// # Errors
    ///
    /// Refuses failed sessions, failed addressing queries or a maximum LUN above
    /// zero. A failed query or unsupported addressing latches session failure.
    pub fn qualify_addressing(&mut self) -> Result<u8, String> {
        if self.failed {
            return Err("BOT session already failed".into());
        }
        if let Some(lun) = self.qualified_lun {
            return Ok(lun);
        }
        let result = self.io.max_lun().and_then(|evidence| {
            let maximum = evidence.maximum();
            if maximum == 0 { Ok(evidence) } else { Err(format!("Unsupported advertised maximum LUN {maximum}; only the qualified single-LUN profile is supported")) }
        });
        match result {
            Ok(evidence) => {
                self.qualified_lun = Some(0);
                self.lun_evidence = Some(evidence);
                Ok(0)
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    pub fn lun_evidence(&self) -> Option<MaxLun> {
        self.lun_evidence
    }
    pub fn qualified_lun(&self) -> Option<u8> {
        self.qualified_lun
    }
    /// A failed exact F0 whose successful DATA stage was followed by no CSW bytes.
    /// CSW reads are scheduled only after DATA succeeds. Keep the BOT session
    /// failed: this observation never authorizes another command or replay.
    pub fn data_sent_status_missing(&self) -> bool {
        self.failed
            && self.evidence.as_ref().is_some_and(|evidence| {
                evidence.opcode == 0xf0
                    && evidence.requested == 512
                    && evidence.cbw_actual == Some(31)
                    && evidence.cbw_error.is_none()
                    && evidence.data_actual == Some(512)
                    && evidence.data_in.is_none()
                    && evidence.csw_reads > 0
                    && evidence.csw_actual == Some(0)
                    && evidence.csw_raw.is_empty()
                    && !evidence.csw_errors.is_empty()
            })
    }
    pub fn take_evidence(&mut self) -> Option<CommandEvidence> {
        self.evidence.take()
    }
    pub fn clear_evidence(&mut self) {
        self.evidence = None;
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
    pub fn failed_f1_status(&self) -> Option<[u8; 13]> {
        self.failed_f1_status
    }
    pub fn request_sense_eligible(&self) -> bool {
        self.failed
            && !self.firmware_submitted
            && self.qualified_lun == Some(0)
            && !self.sense_used
            && self
                .failed_f1_status
                .is_some_and(|raw| u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) == self.tag)
    }
    /// One standard error read after the exact completed failed F1 status.
    /// This never clears failure or permits normal commands/firmware afterward.
    ///
    /// # Errors
    ///
    /// Refuses ineligible/repeated diagnostics and propagates bulk-stage, deadline
    /// or command-status validation failures from the one permitted sense request.
    pub fn diagnostic_request_sense(&mut self) -> Result<Vec<u8>, String> {
        if !self.request_sense_eligible() {
            return Err("No diagnostic sense allowance".into());
        }
        self.sense_used = true;
        self.exchange(
            &[3, 0, 0, 0, 18, 0],
            Direction::In,
            &[],
            18,
            DataPolicy::DiagnosticSense,
        )
    }
    pub fn tag(&self) -> u32 {
        self.tag
    }
    fn remaining(&self, deadline: Instant) -> Result<Duration, TransferError> {
        deadline
            .checked_duration_since(self.io.now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| TransferError {
                kind: TransferFailureKind::Timeout,
                actual: 0,
                raw: Vec::new(),
                message: "BOT request budget expired before next stage".into(),
            })
    }
    fn transfer_before(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, TransferError> {
        let remaining = self.remaining(deadline)?;
        let actual = self.io.transfer(direction, bytes, remaining)?;
        if self.io.now() >= deadline {
            return Err(TransferError {
                kind: TransferFailureKind::Timeout,
                actual,
                raw: bytes[..actual.min(bytes.len())].to_vec(),
                message: format!("BOT request budget expired; requested={}", bytes.len()),
            });
        }
        Ok(actual)
    }
    /// Execute one qualified command without retrying a submitted command block.
    ///
    /// # Errors
    ///
    /// Refuses failed sessions, mismatched OUT lengths, unsupported addressing,
    /// oversized lengths, invalid CDBs or exhausted tags. Transfer, deadline,
    /// data/status or residue failures latch failure after the exchange starts.
    pub fn command(
        &mut self,
        cdb: &[u8],
        direction: Direction,
        data: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, String> {
        self.clear_evidence();
        if self.failed {
            return Err("BOT session failed; no new command, reset or replay is authorized".into());
        }
        if direction == Direction::Out && data.len() != length {
            return Err("OUT buffer length differs from the command".into());
        }
        self.qualify_addressing()?;
        let policy = if cdb == [0xf2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            && direction == Direction::In
            && length == 20
            && data.is_empty()
        {
            DataPolicy::F2Status
        } else {
            DataPolicy::Exact
        };
        self.exchange(cdb, direction, data, length, policy)
    }
    fn exchange(
        &mut self,
        cdb: &[u8],
        direction: Direction,
        data: &[u8],
        length: usize,
        policy: DataPolicy,
    ) -> Result<Vec<u8>, String> {
        let expected = u32::try_from(length).map_err(|_| "BOT length exceeds u32")?;
        let tag = self.tag.checked_add(1).ok_or("BOT tag exhausted")?;
        let mut cbw = command_block(tag, direction, expected, cdb).map_err(|e| e.to_string())?;
        self.tag = tag;
        self.evidence = Some(CommandEvidence {
            tag,
            opcode: cdb[0],
            requested: length,
            cbw_actual: None,
            cbw_error: None,
            data_actual: None,
            data_in: None,
            csw_reads: 0,
            csw_raw: Vec::new(),
            csw_actual: None,
            csw_errors: Vec::new(),
            stall_clear: None,
            stall_clear_elapsed: None,
            f2_zero_residue_quirk: false,
        });
        if cdb[0] == 0xf0 {
            self.firmware_submitted = true;
        }
        let deadline = self.io.now() + Duration::from_secs(5);
        let result = (|| -> Result<Vec<u8>, String> {
            self.submit_command_block(&mut cbw, deadline)?;
            // Firmware OUT stages are 512 bytes. Give the mutable transport a
            // private copy without allocating a heap buffer for every block.
            // Larger public commands retain their existing owned-buffer path.
            let mut short_out = [0; 512];
            let mut owned = if direction == Direction::In {
                vec![0; length]
            } else if length > short_out.len() {
                data.to_vec()
            } else {
                Vec::new()
            };
            let bytes = if direction == Direction::Out && length <= short_out.len() {
                short_out[..length].copy_from_slice(data);
                &mut short_out[..length]
            } else {
                owned.as_mut_slice()
            };
            let actual = self.transfer_data_stage(direction, bytes, deadline)?;
            let bytes = &bytes[..actual];
            if direction == Direction::In {
                self.reject_early_status(cdb, tag, expected, bytes)?;
            }
            let mut status = [0; 13];
            let status_actual = self.read_status_with_halt_clear(&mut status, bytes, deadline)?;
            self.validate_command_response(tag, expected, bytes, &status[..status_actual], policy)?;
            Ok(if direction == Direction::In {
                owned.truncate(actual);
                owned
            } else {
                Vec::new()
            })
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn submit_command_block(
        &mut self,
        cbw: &mut [u8; 31],
        deadline: Instant,
    ) -> Result<(), String> {
        let cbw_result = self.transfer_before(Direction::Out, cbw, deadline);
        if let Some(evidence) = self.evidence.as_mut() {
            evidence.cbw_actual = Some(
                cbw_result
                    .as_ref()
                    .map_or_else(|error| error.actual, |count| *count),
            );
            evidence.cbw_error = cbw_result.as_ref().err().cloned();
        }
        let cbw_actual = cbw_result.map_err(|error| format!("CBW failed: {error}"))?;
        if cbw_actual != 31 {
            let error = TransferError {
                kind: TransferFailureKind::Other,
                actual: cbw_actual,
                raw: cbw[..cbw_actual.min(cbw.len())].to_vec(),
                message: "Short CBW; command is uncertain".into(),
            };
            if let Some(evidence) = self.evidence.as_mut() {
                evidence.cbw_error = Some(error.clone());
            }
            return Err(error.to_string());
        }
        Ok(())
    }

    fn transfer_data_stage(
        &mut self,
        direction: Direction,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, String> {
        let length = bytes.len();
        let actual = match self.transfer_before(direction, bytes, deadline) {
            Ok(actual) => actual,
            Err(error) => {
                if let Some(evidence) = self.evidence.as_mut() {
                    evidence.data_actual = Some(error.actual);
                    if direction == Direction::In {
                        evidence.data_in = Some(error.raw.clone());
                    }
                }
                return Err(format!("Data stage failed: {error}"));
            }
        };
        if actual > length {
            return Err("Invalid bulk data length".into());
        }
        if let Some(evidence) = self.evidence.as_mut() {
            evidence.data_actual = Some(actual);
            if direction == Direction::In {
                evidence.data_in = Some(bytes[..actual].to_vec());
            }
        }
        Ok(actual)
    }

    fn reject_early_status(
        &mut self,
        cdb: &[u8],
        tag: u32,
        expected: u32,
        bytes: &[u8],
    ) -> Result<(), String> {
        // Retain a normally completed early status, never timeout/error bytes.
        // This is the exact observed F1 quirk, not arbitrary failed BOT recovery.
        if cdb == [0xf1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            && expected == 20
            && bytes.len() == 13
            && bytes.starts_with(b"USBS")
            && bytes[4..8] == tag.to_le_bytes()
            && bytes[8..12] == [0; 4]
            && bytes[12] == 1
        {
            self.failed_f1_status = bytes.try_into().ok();
        }
        let stage = data_stage(bytes, tag, expected).map_err(|e| {
            format!(
                "{e}; early_command_failed={}; raw={bytes:02x?}",
                self.failed_f1_status.is_some() && cdb[0] == 0xf1
            )
        })?;
        if stage == DataStage::EarlyStatus {
            return Err(format!("Early CSW instead of vendor data: {bytes:02x?}"));
        }
        Ok(())
    }

    fn read_status_with_halt_clear(
        &mut self,
        status: &mut [u8; 13],
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<usize, String> {
        let actual = bytes.len();
        if let Some(evidence) = self.evidence.as_mut() {
            evidence.csw_reads = 1;
        }
        let first = self.transfer_before(Direction::In, status, deadline);
        if let Err(error) = &first
            && let Some(evidence) = self.evidence.as_mut()
        {
            evidence.csw_actual = Some(error.actual);
            evidence.csw_raw.clone_from(&error.raw);
            evidence.csw_errors.push(error.clone());
        }
        let status_actual = match first {
            Ok(count) => count,
            Err(first) if first.kind == TransferFailureKind::Stall && first.actual == 0 => {
                let remaining = self.remaining(deadline).map_err(|error|format!("{error}; original_csw_error={first}; data_actual={actual} data={bytes:02x?}"))?;
                let clear_started = self.io.now();
                let cleared = self.io.clear_stall(remaining);
                let clear_elapsed = self.io.now().saturating_duration_since(clear_started);
                if let Some(evidence) = self.evidence.as_mut() {
                    evidence.stall_clear_elapsed = Some(clear_elapsed);
                    evidence.stall_clear = Some(match &cleared {
                        Ok(()) => StallClear::Passed,
                        Err(error) => StallClear::Failed(error.clone()),
                    });
                }
                cleared.map_err(|error|format!("CSW halt clearance failed: {error}; original_csw_error={first}; data_actual={actual} data={bytes:02x?}"))?;
                self.remaining(deadline).map_err(|error| {
                    format!(
                        "{error}; after CSW halt clearance; data_actual={actual} data={bytes:02x?}"
                    )
                })?;
                if let Some(evidence) = self.evidence.as_mut() {
                    evidence.csw_reads = 2;
                }
                match self.transfer_before(Direction::In, status, deadline) {
                    Ok(count) => count,
                    Err(error) => {
                        if let Some(evidence) = self.evidence.as_mut() {
                            evidence.csw_actual = Some(error.actual);
                            evidence.csw_raw.clone_from(&error.raw);
                            evidence.csw_errors.push(error.clone());
                        }
                        return Err(format!(
                            "Second CSW read failed: {error}; original_csw_error={first}; data_actual={actual} data={bytes:02x?}"
                        ));
                    }
                }
            }
            Err(error) => {
                return Err(format!(
                    "CSW read failed: {error}; data_actual={actual} data={bytes:02x?}"
                ));
            }
        };
        if let Some(evidence) = self.evidence.as_mut() {
            evidence.csw_actual = Some(status_actual);
            evidence.csw_raw = status[..status_actual.min(status.len())].to_vec();
        }
        if status_actual > status.len() {
            return Err("Invalid CSW transfer length".into());
        }
        Ok(status_actual)
    }

    fn validate_command_response(
        &mut self,
        tag: u32,
        expected: u32,
        bytes: &[u8],
        status: &[u8],
        policy: DataPolicy,
    ) -> Result<(), String> {
        let actual = bytes.len();
        let length = expected as usize;
        // This exact NS39 F2 response was observed on hardware after the
        // original CSW halt was cleared. Its data count is one, despite the
        // passed wrapper reporting zero residue. Keep both facts in the
        // record; do not relax residue checks for other lengths/commands.
        let f2_zero_residue_quirk = policy == DataPolicy::F2Status
            && bytes == [0]
            && status.len() == 13
            && status[..4] == *b"USBS"
            && status[4..8] == tag.to_le_bytes()
            && status[8..13] == [0; 5];
        if let Some(evidence) = self.evidence.as_mut() {
            evidence.f2_zero_residue_quirk = f2_zero_residue_quirk;
        }
        if !f2_zero_residue_quirk {
            let actual = u32::try_from(actual).map_err(|_| "BOT length exceeds u32")?;
            validate_status(status, tag, expected, actual).map_err(|e| {
                format!("{e}; CSW={status:02x?}; data_actual={actual} data={bytes:02x?}")
            })?;
        }
        let accepted = match policy {
            DataPolicy::Exact => bytes.len() == expected as usize,
            DataPolicy::F2Status => (1..=20).contains(&bytes.len()),
            DataPolicy::DiagnosticSense => true,
        };
        if !accepted {
            return Err(format!(
                "Invalid vendor data length {actual}/{length}; data={bytes:02x?}; CSW={status:02x?}"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    #[error("SCSI CDB must contain 1 to 16 bytes")]
    CdbLength,
}

/// Encode one LUN0 command block with zero-filled unused CDB bytes.
///
/// # Errors
///
/// Rejects an empty CDB or one longer than the 16-byte BOT command field.
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
    bytes[14] = u8::try_from(cdb.len()).map_err(|_| CommandError::CdbLength)?;
    bytes[15..15 + cdb.len()].copy_from_slice(cdb);
    Ok(bytes)
}

#[derive(Debug, PartialEq, Eq)]
pub enum DataStage<'a> {
    Data(&'a [u8]),
    EarlyStatus,
}

/// Classify received data, recognizing a complete early command-status wrapper.
///
/// # Errors
///
/// Rejects invalid early status (including tag, residue and command failure) or
/// data longer than the advertised command length.
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

/// Validate the complete BOT wrapper against the original tag and actual DATA count.
///
/// # Errors
///
/// Rejects incomplete wrappers, wrong signatures/tags, inconsistent residue,
/// command failure, phase errors and unknown status values.
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
        assert_eq!(validate_status(&status, 0x494c_5547, 36, 36), Ok(()));
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
            assert_eq!(validate_status(&bytes, 0x494c_5547, 36, 36), Err(error));
        }
        assert_eq!(
            validate_status(&original[..12], 0x494c_5547, 36, 36),
            Err(StatusError::Length)
        );
        assert_eq!(
            validate_status(&original, 0x494c_5547, 20, 21),
            Err(StatusError::Residue)
        );
    }

    #[test]
    fn accepts_a_short_data_stage_only_with_matching_residue() {
        let mut bytes = [
            0x55, 0x53, 0x42, 0x53, 0x47, 0x55, 0x4c, 0x49, 0, 0, 0, 0, 0,
        ];
        bytes[8] = 20;
        assert_eq!(validate_status(&bytes, 0x494c_5547, 20, 0), Ok(()));
        assert_eq!(
            validate_status(&bytes, 0x494c_5547, 20, 7),
            Err(StatusError::Residue)
        );
    }

    #[test]
    fn encodes_the_observed_inquiry_cbw() {
        assert_eq!(
            command_block(0x494c_5547, Direction::In, 36, &[0x12, 0, 0, 0, 36, 0]).unwrap(),
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
            data_stage(&bytes, 0x494c_5547, 20),
            Ok(DataStage::EarlyStatus)
        );
        assert_eq!(data_stage(&bytes, 1, 20), Err(StatusError::Tag));
    }
}
