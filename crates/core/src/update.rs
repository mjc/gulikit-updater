//! Serialized component transactions, shared by every host and presentation layer.

use crate::{
    package::{Component, VerifiedPackage},
    version::{VersionDecision, bluetooth_info},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Refused,
    AlreadyCurrent,
    NewerThanSupported,
    CancelledBeforeWrite,
    OutcomeUnknown,
    TransferCompletedAwaitingVerification,
    TransferSubmittedPendingCompletion,
    InstalledVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionDecision {
    Pending,
    ExpectedDetach,
    Invalidated,
}
pub struct CompletionObservation {
    pub selected_present: bool,
    pub other_candidate_present: bool,
    pub discovery_complete: bool,
    pub usb_events: u64,
    pub usb_arrivals: u64,
}
impl CompletionObservation {
    pub fn decision(&self) -> CompletionDecision {
        if !self.discovery_complete || self.other_candidate_present || self.usb_arrivals != 0 {
            return CompletionDecision::Invalidated;
        }
        match (self.selected_present, self.usb_events) {
            (true, 0) => CompletionDecision::Pending,
            (false, 1) => CompletionDecision::ExpectedDetach,
            _ => CompletionDecision::Invalidated,
        }
    }
}

/// A fresh machine readback and separately recorded assisted association.
#[derive(Debug, Serialize)]
pub struct Verification {
    pub component: Component,
    pub previous_generation: u64,
    pub generation: u64,
    pub same_unit_confirmed: bool,
    pub model_confirmed: bool,
    /// Canonical component-specific text from a successful fresh version parser.
    pub version: String,
}
pub fn verify_restart(previous: Outcome, observation: &Verification) -> Outcome {
    let expected = match observation.component {
        Component::Main => "5.9",
        Component::Bluetooth => "5.07",
    };
    if matches!(
        previous,
        Outcome::TransferCompletedAwaitingVerification
            | Outcome::TransferSubmittedPendingCompletion
    ) && observation.generation != observation.previous_generation
        && observation.same_unit_confirmed
        && observation.model_confirmed
        && observation.version == expected
    {
        Outcome::InstalledVerified
    } else {
        previous
    }
}

#[derive(Debug, Serialize)]
pub struct CommandRecord {
    pub index: usize,
    pub opcode: u8,
    pub requested: usize,
    pub confirmed: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TransferRecord {
    pub outcome: Outcome,
    pub prewrite_version: Option<String>,
    pub bytes_submitted: usize,
    pub bytes_confirmed: usize,
    pub commands: Vec<CommandRecord>,
    pub error: Option<String>,
    pub cleanup_errors: Vec<String>,
}
impl Default for TransferRecord {
    fn default() -> Self {
        Self {
            outcome: Outcome::Refused,
            prewrite_version: None,
            bytes_submitted: 0,
            bytes_confirmed: 0,
            commands: Vec::new(),
            error: None,
            cleanup_errors: Vec::new(),
        }
    }
}

/// An exclusive, quiesced transport bound to one attachment and a live topology watcher.
/// Each command must validate OS success, exact data length and passed transport status.
/// Implementations must never retry a submitted vendor command or reset after failure.
pub trait BluetoothPort {
    /// Refuse unsupported/unqualified writes before any submission is recorded.
    fn prepare_write(&mut self) -> Result<(), String>;
    fn check_session(&mut self) -> Result<(), String>;
    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, String>;
    /// Release all claims and restore storage access on every exit.
    fn finish(&mut self) -> Result<(), String>;
}

pub fn update_bluetooth(
    port: &mut impl BluetoothPort,
    package: &VerifiedPackage,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    if package.info().component != Component::Bluetooth {
        let mut record = TransferRecord {
            error: Some("Bluetooth update requires a verified Bluetooth package".into()),
            ..TransferRecord::default()
        };
        if let Err(error) = port.finish() {
            record.cleanup_errors.push(error);
        }
        return record;
    }
    bluetooth(port, package.payload(), cancelled)
}

fn bluetooth(
    port: &mut impl BluetoothPort,
    payload: &[u8],
    mut cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    let mut record = TransferRecord::default();
    let mut submitted = false;
    let result = (|| -> Result<(), String> {
        if cancelled() {
            record.outcome = Outcome::CancelledBeforeWrite;
            return Ok(());
        }
        port.check_session()?;
        let response = command(port, &mut record, 0xf1, &[])?;
        let version = bluetooth_info(&response).map_err(|e| e.to_string())?;
        record.prewrite_version = Some(version.to_string());
        match version.decision() {
            VersionDecision::AlreadyCurrent => {
                record.outcome = Outcome::AlreadyCurrent;
                return Ok(());
            }
            VersionDecision::NewerThanSupported => {
                record.outcome = Outcome::NewerThanSupported;
                return Ok(());
            }
            VersionDecision::Eligible => {}
        }
        if payload.len() != 345088 {
            return Err("Incorrect Bluetooth payload size".into());
        }
        port.prepare_write()?;
        for (index, block) in payload.as_chunks::<512>().0.iter().enumerate() {
            if cancelled() {
                if !submitted {
                    record.outcome = Outcome::CancelledBeforeWrite;
                    return Ok(());
                }
                return Err(
                    "Cancelled after firmware submission; no rollback or resume is available"
                        .into(),
                );
            }
            port.check_session()?;
            submitted = true;
            record.bytes_submitted += block.len();
            command(port, &mut record, 0xf0, block)?;
            record.bytes_confirmed += block.len();
            if index == 0 || index == 673 {
                if cancelled() {
                    return Err("Cancelled after firmware submission".into());
                }
                port.check_session()?;
                let status = command(port, &mut record, 0xf2, &[])?;
                if status[0] != 0 {
                    return Err(format!("DeviceStatusError({})", status[0]));
                }
            }
        }
        port.check_session()?;
        record.outcome = Outcome::TransferCompletedAwaitingVerification;
        Ok(())
    })();
    if let Err(error) = result {
        record.error = Some(error);
        record.outcome = if submitted {
            Outcome::OutcomeUnknown
        } else {
            Outcome::Refused
        };
    }
    if let Err(error) = port.finish() {
        record.cleanup_errors.push(error);
    }
    record
}

fn command(
    port: &mut impl BluetoothPort,
    record: &mut TransferRecord,
    opcode: u8,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let requested = if opcode == 0xf0 { 512 } else { 20 };
    let result = port.command(opcode, data).and_then(|response| {
        if response.len() != if opcode == 0xf0 { 0 } else { 20 } {
            return Err(format!(
                "Short/invalid vendor response: {} bytes",
                response.len()
            ));
        }
        Ok(response)
    });
    record.commands.push(CommandRecord {
        index: record.commands.len(),
        opcode,
        requested,
        confirmed: if result.is_ok() { requested } else { 0 },
        error: result.as_ref().err().cloned(),
    });
    result
}

/// A mounted, writable, verified root held open throughout the operation.
/// Creation is exclusive and does not follow symlinks; cleanup never deletes firmware.
pub trait MainPort {
    fn prepare_write(&mut self) -> Result<(), String>;
    fn read_version(&mut self) -> Result<Vec<u8>, String>;
    fn check_session(&mut self) -> Result<(), String>;
    fn create_destination(&mut self) -> Result<(), String>;
    fn write(&mut self, bytes: &[u8]) -> Result<usize, String>;
    fn flush(&mut self) -> Result<(), String>;
    fn close(&mut self) -> Result<(), String>;
    fn volume_flush(&mut self) -> Result<(), String>;
    /// Bounded host wait for automatic controller detach, never an eject/reset.
    fn wait_for_completion(&mut self, cancelled: &mut dyn FnMut() -> bool) -> Result<bool, String>;
    fn finish(&mut self) -> Result<(), String>;
}

pub fn update_main(
    port: &mut impl MainPort,
    package: &VerifiedPackage,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    if package.info().component != Component::Main {
        let mut record = TransferRecord {
            error: Some("Main update requires a verified Main package".into()),
            ..TransferRecord::default()
        };
        if let Err(error) = port.finish() {
            record.cleanup_errors.push(error);
        }
        return record;
    }
    main_transfer(port, package.payload(), cancelled)
}

fn main_transfer(
    port: &mut impl MainPort,
    payload: &[u8],
    mut cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    let mut record = TransferRecord::default();
    let result = (|| -> Result<(), String> {
        if cancelled() {
            record.outcome = Outcome::CancelledBeforeWrite;
            return Ok(());
        }
        port.check_session()?;
        let raw = port.read_version()?;
        let version = crate::version::MainVersion::parse(&raw).map_err(|e| e.to_string())?;
        record.prewrite_version = Some(version.to_string());
        match version.decision() {
            VersionDecision::AlreadyCurrent => {
                record.outcome = Outcome::AlreadyCurrent;
                return Ok(());
            }
            VersionDecision::NewerThanSupported => {
                record.outcome = Outcome::NewerThanSupported;
                return Ok(());
            }
            VersionDecision::Eligible => {}
        }
        if payload.len() != 51500 {
            return Err("Incorrect Main payload size".into());
        }
        port.prepare_write()?;
        port.check_session()?;
        if cancelled() {
            record.outcome = Outcome::CancelledBeforeWrite;
            return Ok(());
        }
        port.create_destination()?;
        let mut offset = 0;
        while offset < payload.len() {
            if cancelled() {
                if offset == 0 {
                    record.outcome = Outcome::CancelledBeforeWrite;
                    return Ok(());
                }
                return Err("Cancelled after firmware submission".into());
            }
            port.check_session()?;
            let bytes = &payload[offset..(offset + 4096).min(payload.len())];
            record.bytes_submitted += bytes.len();
            let count = port.write(bytes)?;
            if count == 0 || count > bytes.len() {
                return Err("Invalid or zero-progress filesystem write".into());
            }
            offset += count;
            record.bytes_confirmed += count;
        }
        port.flush()?;
        port.close()?;
        port.volume_flush()?;
        record.outcome = if port.wait_for_completion(&mut cancelled)? {
            Outcome::TransferCompletedAwaitingVerification
        } else {
            Outcome::TransferSubmittedPendingCompletion
        };
        Ok(())
    })();
    if let Err(error) = result {
        record.error = Some(error);
        record.outcome = if record.bytes_submitted > 0 {
            Outcome::OutcomeUnknown
        } else {
            Outcome::Refused
        };
    }
    if let Err(error) = port.finish() {
        record.cleanup_errors.push(error);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::BT_SIGNATURE;

    struct MainFake {
        events: Vec<&'static str>,
        written: Vec<u8>,
        version: &'static [u8],
        fail: Option<&'static str>,
    }
    impl MainPort for MainFake {
        fn prepare_write(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn read_version(&mut self) -> Result<Vec<u8>, String> {
            Ok(self.version.to_vec())
        }
        fn check_session(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn create_destination(&mut self) -> Result<(), String> {
            self.event("create")
        }
        fn write(&mut self, bytes: &[u8]) -> Result<usize, String> {
            self.event("write")?;
            let n = bytes.len().min(79);
            self.written.extend_from_slice(&bytes[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> Result<(), String> {
            self.event("flush")
        }
        fn close(&mut self) -> Result<(), String> {
            self.event("close")
        }
        fn volume_flush(&mut self) -> Result<(), String> {
            self.event("volume_flush")
        }
        fn wait_for_completion(&mut self, _: &mut dyn FnMut() -> bool) -> Result<bool, String> {
            self.event("detach")?;
            Ok(true)
        }
        fn finish(&mut self) -> Result<(), String> {
            self.event("finish")
        }
    }
    impl MainFake {
        fn event(&mut self, name: &'static str) -> Result<(), String> {
            self.events.push(name);
            if self.fail == Some(name) {
                Err(name.into())
            } else {
                Ok(())
            }
        }
    }
    fn main_port() -> MainFake {
        MainFake {
            events: vec![],
            written: vec![],
            version: b"www.gulikit.com\nversion 5.8",
            fail: None,
        }
    }
    #[test]
    fn main_handles_short_writes_flushes_open_file_and_waits_for_detach() {
        let mut port = main_port();
        let payload = vec![0x83; 51500];
        let record = main_transfer(&mut port, &payload, || false);
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(port.written, payload);
        let tail = &port.events[port.events.len() - 5..];
        assert_eq!(tail, ["flush", "close", "volume_flush", "detach", "finish"]);
    }
    #[test]
    fn main_equal_newer_unknown_and_existing_destination_write_nothing() {
        for text in [
            b"www.gulikit.com\nversion 5.9".as_slice(),
            b"www.gulikit.com\nversion 5.10",
            b"garbage",
        ] {
            let mut port = main_port();
            port.version = text;
            let result = main_transfer(&mut port, &vec![0; 51500], || false);
            assert!(matches!(
                result.outcome,
                Outcome::AlreadyCurrent | Outcome::NewerThanSupported | Outcome::Refused
            ));
            assert!(port.written.is_empty());
            assert_eq!(port.events, ["finish"]);
        }
        let mut port = main_port();
        port.fail = Some("create");
        assert_eq!(
            main_transfer(&mut port, &vec![0; 51500], || false).outcome,
            Outcome::Refused
        );
        assert!(port.written.is_empty());
    }
    #[test]
    fn main_failure_never_turns_later_detach_into_success() {
        for failure in ["write", "flush", "close", "volume_flush"] {
            let mut port = main_port();
            port.fail = Some(failure);
            assert_eq!(
                main_transfer(&mut port, &vec![0; 51500], || false).outcome,
                Outcome::OutcomeUnknown
            );
            assert!(!port.events.contains(&"detach"));
            assert_eq!(port.events.last(), Some(&"finish"));
        }
    }

    #[derive(Default)]
    struct Fake {
        calls: Vec<u8>,
        bytes: Vec<u8>,
        fail: Option<usize>,
        invalidate: Option<usize>,
        version: u16,
        cleanup: bool,
        refuse_write: bool,
    }
    impl BluetoothPort for Fake {
        fn prepare_write(&mut self) -> Result<(), String> {
            if self.refuse_write {
                Err("unqualified adapter".into())
            } else {
                Ok(())
            }
        }
        fn check_session(&mut self) -> Result<(), String> {
            if self.invalidate == Some(self.calls.len()) {
                Err("extra device arrived".into())
            } else {
                Ok(())
            }
        }
        fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, String> {
            self.calls.push(opcode);
            if self.fail == Some(self.calls.len()) {
                return Err("timeout after submission".into());
            }
            match opcode {
                0xf1 => {
                    let mut bytes = vec![0; 20];
                    bytes[..16].copy_from_slice(&BT_SIGNATURE);
                    bytes[16..18].copy_from_slice(&self.version.to_le_bytes());
                    Ok(bytes)
                }
                0xf0 => {
                    self.bytes.extend_from_slice(data);
                    Ok(Vec::new())
                }
                0xf2 => Ok(vec![0; 20]),
                _ => unreachable!(),
            }
        }
        fn finish(&mut self) -> Result<(), String> {
            self.cleanup = true;
            Ok(())
        }
    }
    #[test]
    fn exact_bluetooth_transcript_and_payload_no_installed_success() {
        let payload: Vec<_> = (0..345088).map(|n| (n % 251) as u8).collect();
        let mut port = Fake {
            version: 506,
            ..Fake::default()
        };
        let record = bluetooth(&mut port, &payload, || false);
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(port.calls.len(), 677);
        assert_eq!(&port.calls[..3], &[0xf1, 0xf0, 0xf2]);
        assert!(port.calls[3..676].iter().all(|b| *b == 0xf0));
        assert_eq!(port.calls[676], 0xf2);
        assert_eq!(port.bytes, payload);
        assert_eq!(record.bytes_confirmed, 345088);
        assert!(port.cleanup);
    }
    #[test]
    fn equal_newer_and_failed_f1_write_nothing() {
        for (version, fail, outcome) in [
            (507, None, Outcome::AlreadyCurrent),
            (508, None, Outcome::NewerThanSupported),
            (506, Some(1), Outcome::Refused),
        ] {
            let mut port = Fake {
                version,
                fail,
                ..Fake::default()
            };
            assert_eq!(
                bluetooth(&mut port, &vec![0; 345088], || false).outcome,
                outcome
            );
            assert!(port.bytes.is_empty());
            assert_eq!(port.calls, [0xf1]);
            assert!(port.cleanup);
        }
    }
    #[test]
    fn unqualified_adapter_refuses_before_firmware_submission() {
        let mut port = Fake {
            version: 506,
            refuse_write: true,
            ..Fake::default()
        };
        let record = bluetooth(&mut port, &vec![0; 345088], || false);
        assert_eq!(record.outcome, Outcome::Refused);
        assert_eq!(record.bytes_submitted, 0);
        assert_eq!(port.calls, [0xf1]);
        assert!(port.cleanup);
    }
    #[test]
    fn every_failed_command_stops_without_retry_and_releases() {
        for index in 2..=677 {
            let mut port = Fake {
                version: 506,
                fail: Some(index),
                ..Fake::default()
            };
            let record = bluetooth(&mut port, &vec![0; 345088], || false);
            assert_eq!(record.outcome, Outcome::OutcomeUnknown, "command {index}");
            assert_eq!(port.calls.len(), index);
            assert!(port.cleanup);
        }
    }
    #[test]
    fn topology_change_and_cancellation_stop_next_submission() {
        let mut port = Fake {
            version: 506,
            invalidate: Some(3),
            ..Fake::default()
        };
        let record = bluetooth(&mut port, &vec![0; 345088], || false);
        assert_eq!(record.outcome, Outcome::OutcomeUnknown);
        assert_eq!(port.calls, [0xf1, 0xf0, 0xf2]);
        let mut port = Fake {
            version: 506,
            ..Fake::default()
        };
        assert_eq!(
            bluetooth(&mut port, &vec![0; 345088], || true).outcome,
            Outcome::CancelledBeforeWrite
        );
        assert!(port.calls.is_empty());
        assert!(port.cleanup);
    }
}
