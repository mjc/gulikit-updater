//! Serialized component transactions, shared by every host and presentation layer.

use crate::{
    package::{Component, VerifiedPackage},
    version::{VersionDecision, VersionPolicy, bluetooth_info},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Refused,
    AlreadyCurrent,
    NewerThanSupported,
    CancelledBeforeWrite,
    DestinationCreatedWithoutPayload,
    OutcomeUnknown,
    TransferCompletedAwaitingVerification,
    TransferSubmittedPendingCompletion,
    InstalledVerified,
}

impl Outcome {
    #[must_use]
    pub fn awaits_restart_verification(self) -> bool {
        match self {
            Self::TransferCompletedAwaitingVerification
            | Self::TransferSubmittedPendingCompletion => true,
            Self::Refused
            | Self::AlreadyCurrent
            | Self::NewerThanSupported
            | Self::CancelledBeforeWrite
            | Self::DestinationCreatedWithoutPayload
            | Self::OutcomeUnknown
            | Self::InstalledVerified => false,
        }
    }
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
    #[must_use]
    pub fn decision(&self) -> CompletionDecision {
        if !self.discovery_complete || self.other_candidate_present || self.usb_arrivals != 0 {
            return CompletionDecision::Invalidated;
        }
        match (self.selected_present, self.usb_events) {
            (false, 1) => CompletionDecision::ExpectedDetach,
            // Registry enumeration and dispatch-queue notification can observe
            // the same removal in either order. Wait for both within the caller's
            // existing deadline; arrivals and extra events still invalidate it.
            (_, 0) | (true, 1) => CompletionDecision::Pending,
            _ => CompletionDecision::Invalidated,
        }
    }
    /// At the deadline, one-sided removal evidence is an invalidated session,
    /// not an ordinary wait for a controller that has not restarted yet.
    ///
    /// # Errors
    ///
    /// Rejects incomplete/ambiguous discovery, intervening arrivals or inconsistent
    /// removal notifications instead of treating them as expected completion.
    pub fn at_deadline(&self) -> Result<bool, &'static str> {
        match self.decision() {
            CompletionDecision::ExpectedDetach => Ok(true),
            CompletionDecision::Pending if self.selected_present && self.usb_events == 0 => {
                Ok(false)
            }
            CompletionDecision::Pending | CompletionDecision::Invalidated => {
                Err("Unexpected topology change while awaiting completion")
            }
        }
    }
}

/// A fresh machine readback and separately recorded assisted association.
#[derive(Debug, Serialize, Deserialize)]
pub struct Verification {
    pub component: Component,
    pub previous_generation: u64,
    pub generation: u64,
    pub same_unit_confirmed: bool,
    pub model_confirmed: bool,
    /// Canonical component-specific text from a successful fresh version parser.
    pub version: String,
    /// Target version from the validated package metadata in the original attempt.
    pub expected_version: String,
}
#[must_use]
pub fn verify_restart(previous: Outcome, observation: &Verification) -> Outcome {
    if previous.awaits_restart_verification()
        && observation.generation != observation.previous_generation
        && observation.same_unit_confirmed
        && observation.model_confirmed
        && !observation.expected_version.is_empty()
        && observation.version == observation.expected_version
    {
        Outcome::InstalledVerified
    } else {
        previous
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandRecord {
    pub index: usize,
    pub opcode: u8,
    pub requested: usize,
    pub confirmed: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferRecord {
    pub outcome: Outcome,
    pub version_policy: VersionPolicy,
    pub prewrite_version: Option<String>,
    pub main_destination_created: bool,
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
            version_policy: VersionPolicy::UpgradeOnly,
            prewrite_version: None,
            main_destination_created: false,
            bytes_submitted: 0,
            bytes_confirmed: 0,
            commands: Vec::new(),
            error: None,
            cleanup_errors: Vec::new(),
        }
    }
}

/// What the transport established before returning a command error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionCompletion {
    #[default]
    Uncertain,
    /// Exact firmware DATA OUT succeeded, but no command-status bytes arrived.
    /// This is not a passed command or proof that the firmware was installed.
    DataSentStatusMissing,
}

/// A refusal before I/O is distinct from a failure after submission may have begun.
/// Adapters may return `before` only when no part of this operation was submitted.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct SubmissionError {
    pub message: String,
    pub may_have_been_submitted: bool,
    pub audit_failure: bool,
    pub completion: SubmissionCompletion,
    /// Successful Main write count retained when only its audit result failed.
    pub known_write_count: Option<usize>,
}
impl SubmissionError {
    pub fn before(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            may_have_been_submitted: false,
            audit_failure: false,
            completion: SubmissionCompletion::Uncertain,
            known_write_count: None,
        }
    }
    pub fn audit_before(message: impl Into<String>) -> Self {
        Self {
            audit_failure: true,
            ..Self::before(message)
        }
    }
}
impl From<String> for SubmissionError {
    fn from(message: String) -> Self {
        Self {
            message,
            may_have_been_submitted: true,
            audit_failure: false,
            completion: SubmissionCompletion::Uncertain,
            known_write_count: None,
        }
    }
}
impl From<&str> for SubmissionError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

/// An exclusive, quiesced transport bound to one attachment and a live topology watcher.
///
/// Each command must validate OS success and passed transport status. F0 requires
/// exact OUT512; F1 exact IN20; F2 requests IN20 and consumes a nonempty 1..20-byte
/// status reply with exact residue, except the observed NS39 one-byte `00` reply
/// with a matching passed zero-residue CSW. Preserve its actual count and raw
/// status, and record that exception. No missing byte may be padded.
/// Implementations must never retry a submitted vendor command or automatically reset
/// once firmware may have been submitted. Read-only cleanup effects must be explicit.
pub trait BluetoothPort {
    fn take_transport_evidence(&mut self) -> Option<crate::bot::CommandEvidence> {
        None
    }
    fn lun_evidence(&self) -> Option<crate::bot::MaxLun> {
        None
    }
    /// Freshly qualified BOT LUN, when the adapter uses raw BOT.
    fn qualified_lun(&self) -> Option<u8> {
        None
    }
    /// Refuse unsupported/unqualified writes before any submission is recorded.
    ///
    /// # Errors
    ///
    /// Refuses unqualified addressing, stale attachment/identity evidence or an
    /// adapter that cannot safely submit this firmware transaction.
    fn prepare_write(&mut self) -> Result<(), String>;
    /// Revalidate attachment ownership before the next transaction operation.
    ///
    /// # Errors
    ///
    /// Fails when ownership, topology or attachment-bound evidence has changed.
    fn check_session(&mut self) -> Result<(), String>;
    /// Submit one authorized vendor command and retain its submission disposition.
    ///
    /// # Errors
    ///
    /// Refuses unauthorized commands before submission or reports transport/status
    /// and audit failures, distinguishing known non-submission from uncertainty.
    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, SubmissionError>;
    /// Observe only the selected device's removal, with complete discovery and
    /// no intervening USB arrival or additional recognized update candidate.
    /// Allow bounded host-notification delay after the controller's normal
    /// final-block reboot. This observation must not send device commands.
    ///
    /// # Errors
    ///
    /// Fails if the host cannot establish a complete, attachment-bound observation.
    fn completion_detached(&mut self) -> Result<bool, String> {
        Ok(false)
    }
    /// Release claims on every exit; report restoration or preservation pending.
    /// No-reset surrender after F0 may deliberately leave storage drivers detached.
    ///
    /// # Errors
    ///
    /// Reports cleanup failure or pending driver restoration without resetting a
    /// controller after firmware may have been submitted.
    fn finish(&mut self) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub submitted: usize,
    pub confirmed: usize,
    pub total: usize,
}
fn publish_progress(record: &TransferRecord, total: usize, progress: &mut impl FnMut(Progress)) {
    progress(Progress {
        submitted: record.bytes_submitted,
        confirmed: record.bytes_confirmed,
        total,
    });
}

pub fn update_bluetooth(
    port: &mut impl BluetoothPort,
    package: &VerifiedPackage,
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    update_bluetooth_with_progress(port, package, policy, cancelled, |_| {})
}

pub fn update_bluetooth_with_progress(
    port: &mut impl BluetoothPort,
    package: &VerifiedPackage,
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
    progress: impl FnMut(Progress),
) -> TransferRecord {
    let Some(target) = package
        .bluetooth_version()
        .filter(|_| package.info().component == Component::Bluetooth)
    else {
        let mut record = TransferRecord {
            version_policy: policy,
            error: Some("Bluetooth update requires a verified Bluetooth package".into()),
            ..TransferRecord::default()
        };
        if let Err(error) = port.finish() {
            record.cleanup_errors.push(error);
        }
        return record;
    };
    run_bluetooth_transaction(port, package.payload(), target, policy, cancelled, progress)
}

#[cfg(test)]
fn bluetooth(
    port: &mut impl BluetoothPort,
    payload: &[u8],
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    bluetooth_release(port, payload, 507, policy, cancelled)
}
#[cfg(test)]
fn bluetooth_release(
    port: &mut impl BluetoothPort,
    payload: &[u8],
    target: u16,
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    run_bluetooth_transaction(port, payload, target, policy, cancelled, |_| {})
}
fn run_bluetooth_transaction(
    port: &mut impl BluetoothPort,
    payload: &[u8],
    target: u16,
    policy: VersionPolicy,
    mut cancelled: impl FnMut() -> bool,
    mut progress: impl FnMut(Progress),
) -> TransferRecord {
    let mut record = TransferRecord {
        version_policy: policy,
        ..TransferRecord::default()
    };
    let result = (|| -> Result<(), String> {
        if cancelled() {
            record.outcome = Outcome::CancelledBeforeWrite;
            return Ok(());
        }
        port.check_session()?;
        let response = record_bluetooth_command(port, &mut record, 0xf1, &[])
            .map_err(|error| error.message)?;
        let version = bluetooth_info(&response).map_err(|e| e.to_string())?;
        record.prewrite_version = Some(version.to_string());
        match version.decision_for(target, policy) {
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
        if payload.is_empty() || !payload.len().is_multiple_of(512) {
            return Err("Bluetooth payload must contain complete 512-byte blocks".into());
        }
        port.prepare_write()?;
        stream_bluetooth_payload(port, payload, &mut record, &mut cancelled, &mut progress)
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

fn stream_bluetooth_payload(
    port: &mut impl BluetoothPort,
    payload: &[u8],
    record: &mut TransferRecord,
    cancelled: &mut impl FnMut() -> bool,
    progress: &mut impl FnMut(Progress),
) -> Result<(), String> {
    let block_count = payload.len() / 512;
    for (index, block) in payload.as_chunks::<512>().0.iter().enumerate() {
        if cancelled() {
            if record.bytes_submitted == 0 {
                record.outcome = Outcome::CancelledBeforeWrite;
                return Ok(());
            }
            return Err(
                "Cancelled after firmware submission; no rollback or resume is available".into(),
            );
        }
        port.check_session()?;
        let result = record_bluetooth_command(port, record, 0xf0, block);
        publish_progress(record, payload.len(), progress);
        if let Err(error) = result {
            if index > 0
                && index + 1 == block_count
                && record.bytes_submitted == payload.len()
                && record.bytes_confirmed + block.len() == payload.len()
                && error.completion == SubmissionCompletion::DataSentStatusMissing
                && !error.audit_failure
            {
                // A KK3 normally reboots after accepting the last DATA OUT,
                // before returning its CSW. This is the expected completion
                // path, not a reason to retry the block or send another F2.
                // The adapter waits for host removal notifications to converge.
                // Preserve the missing CSW; fresh F1 still proves installation.
                if port.completion_detached()? {
                    record.outcome = Outcome::TransferSubmittedPendingCompletion;
                    return Ok(());
                }
            }
            return Err(error.message);
        }
        record.bytes_confirmed += block.len();
        publish_progress(record, payload.len(), progress);
        if index == 0 || index + 1 == block_count {
            if cancelled() {
                return Err("Cancelled after firmware submission".into());
            }
            if let Err(error) = port.check_session() {
                if index + 1 == block_count && port.completion_detached()? {
                    record.outcome = Outcome::TransferSubmittedPendingCompletion;
                    return Ok(());
                }
                return Err(error);
            }
            let status =
                record_bluetooth_command(port, record, 0xf2, &[]).map_err(|error| error.message)?;
            if status[0] != 0 {
                return Err(format!("DeviceStatusError({})", status[0]));
            }
        }
    }
    if let Err(error) = port.check_session()
        && !port.completion_detached()?
    {
        return Err(error);
    }
    record.outcome = Outcome::TransferCompletedAwaitingVerification;
    Ok(())
}

fn record_bluetooth_command(
    port: &mut impl BluetoothPort,
    record: &mut TransferRecord,
    opcode: u8,
    data: &[u8],
) -> Result<Vec<u8>, SubmissionError> {
    let requested = if opcode == 0xf0 { 512 } else { 20 };
    let result = port.command(opcode, data).and_then(|response| {
        let accepted = match opcode {
            0xf0 => response.is_empty(),
            0xf2 => (1..=20).contains(&response.len()),
            _ => response.len() == 20,
        };
        if !accepted {
            return Err(format!("Invalid vendor response length: {} bytes", response.len()).into());
        }
        Ok(response)
    });
    if opcode == 0xf0
        && result
            .as_ref()
            .map_or_else(|error| error.may_have_been_submitted, |_| true)
    {
        record.bytes_submitted += data.len();
    }
    if let Err(error) = &result
        && error.audit_failure
    {
        record
            .cleanup_errors
            .push(format!("Host audit failure: {}", error.message));
    }
    record.commands.push(CommandRecord {
        index: record.commands.len(),
        opcode,
        requested,
        confirmed: result.as_ref().map_or(0, |response| {
            if opcode == 0xf0 {
                requested
            } else {
                response.len()
            }
        }),
        error: result.as_ref().err().map(|error| error.message.clone()),
    });
    result
}

/// A mounted, writable, verified root held open throughout the operation.
/// Creation is exclusive and does not follow symlinks; cleanup never deletes firmware.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct DestinationCreationError {
    pub error: String,
    /// Preserve actual creation even if recording its successful result failed.
    pub created: bool,
}
impl From<String> for DestinationCreationError {
    fn from(error: String) -> Self {
        Self {
            error,
            created: false,
        }
    }
}

pub trait MainPort {
    /// Check that the selected filesystem path supports a safe update.
    ///
    /// # Errors
    ///
    /// Refuses unsupported write handling or invalidated attachment evidence.
    fn prepare_write(&mut self) -> Result<(), String>;
    /// Read the actual controller version file without synthesizing missing bytes.
    ///
    /// # Errors
    ///
    /// Reports file access, bounded-read or attachment validation failures.
    fn read_version(&mut self) -> Result<Vec<u8>, String>;
    /// Revalidate ownership and the mounted destination's physical attachment.
    ///
    /// # Errors
    ///
    /// Refuses stale ownership, changed topology or a replaced device/volume.
    fn check_session(&mut self) -> Result<(), String>;
    /// Exclusively create the selected package member's firmware destination.
    ///
    /// # Errors
    ///
    /// Reports creation or audit failure while retaining whether the destination
    /// was actually created, even when no payload bytes were written.
    fn create_destination(&mut self, member: &str) -> Result<(), DestinationCreationError>;
    /// Write a payload slice and report the actual accepted byte count.
    ///
    /// # Errors
    ///
    /// Reports write/audit errors with known successful counts or possible
    /// submission, preserving uncertainty rather than replaying bytes.
    fn write(&mut self, bytes: &[u8]) -> Result<usize, SubmissionError>;
    /// Sync the open firmware file after all payload bytes were accepted.
    ///
    /// # Errors
    ///
    /// Reports file synchronization or attachment validation failure.
    fn flush(&mut self) -> Result<(), String>;
    /// Close the destination while retaining any host close error.
    ///
    /// # Errors
    ///
    /// Reports close or attachment validation failure; successful writes remain recorded.
    fn close(&mut self) -> Result<(), String>;
    /// Perform the adapter's qualified volume durability step.
    ///
    /// # Errors
    ///
    /// Reports volume synchronization or required durability-evidence failure.
    fn volume_flush(&mut self) -> Result<(), String>;
    /// Bounded host wait for automatic controller detach, never an eject/reset.
    ///
    /// # Errors
    ///
    /// Reports cancellation, observation failure or unexpected topology changes;
    /// ordinary expiry without completion returns `Ok(false)`.
    fn wait_for_completion(&mut self, cancelled: &mut dyn FnMut() -> bool) -> Result<bool, String>;
    /// Release host filesystem resources and report remaining cleanup work.
    ///
    /// # Errors
    ///
    /// Reports checked close, restoration or host-audit failures during cleanup.
    fn finish(&mut self) -> Result<(), String>;
}

pub fn update_main(
    port: &mut impl MainPort,
    package: &VerifiedPackage,
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    update_main_with_progress(port, package, policy, cancelled, |_| {})
}

pub fn update_main_with_progress(
    port: &mut impl MainPort,
    package: &VerifiedPackage,
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
    progress: impl FnMut(Progress),
) -> TransferRecord {
    if package.info().component != Component::Main {
        let mut record = TransferRecord {
            version_policy: policy,
            error: Some("Main update requires a verified Main package".into()),
            ..TransferRecord::default()
        };
        if let Err(error) = port.finish() {
            record.cleanup_errors.push(error);
        }
        return record;
    }
    run_main_transaction(
        port,
        package.payload(),
        MainTarget {
            version: &package.info().version,
            payload_size: package.info().payload_size,
            member: &package.info().member,
        },
        policy,
        cancelled,
        progress,
    )
}

#[cfg(test)]
fn main_transfer(
    port: &mut impl MainPort,
    payload: &[u8],
    policy: VersionPolicy,
    cancelled: impl FnMut() -> bool,
) -> TransferRecord {
    run_main_transaction(
        port,
        payload,
        MainTarget {
            version: "5.9",
            payload_size: 51_500,
            member: "NS39_KK3_MAX_V5.9.bin",
        },
        policy,
        cancelled,
        |_| {},
    )
}

#[derive(Clone, Copy)]
struct MainTarget<'a> {
    version: &'a str,
    payload_size: usize,
    member: &'a str,
}

fn run_main_transaction(
    port: &mut impl MainPort,
    payload: &[u8],
    target: MainTarget<'_>,
    policy: VersionPolicy,
    mut cancelled: impl FnMut() -> bool,
    mut progress: impl FnMut(Progress),
) -> TransferRecord {
    let mut record = TransferRecord {
        version_policy: policy,
        ..TransferRecord::default()
    };
    let result = (|| -> Result<(), String> {
        if cancelled() {
            record.outcome = Outcome::CancelledBeforeWrite;
            return Ok(());
        }
        port.check_session()?;
        let raw = port.read_version()?;
        let version = crate::version::MainVersion::parse(&raw).map_err(|e| e.to_string())?;
        record.prewrite_version = Some(version.to_string());
        match crate::version::release_decision(
            Component::Main,
            &version.to_string(),
            target.version,
            policy,
        )
        .map_err(|error| error.to_string())?
        {
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
        if payload.len() != target.payload_size {
            return Err("Incorrect Main payload size".into());
        }
        port.prepare_write()?;
        port.check_session()?;
        if cancelled() {
            record.outcome = Outcome::CancelledBeforeWrite;
            return Ok(());
        }
        if let Err(error) = port.create_destination(target.member) {
            record.main_destination_created = error.created;
            return Err(error.error);
        }
        record.main_destination_created = true;
        write_main_payload(port, payload, &mut record, &mut cancelled, &mut progress)?;
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
        } else if record.main_destination_created {
            Outcome::DestinationCreatedWithoutPayload
        } else {
            Outcome::Refused
        };
    }
    if let Err(error) = port.finish() {
        record.cleanup_errors.push(error);
    }
    record
}

fn write_main_payload(
    port: &mut impl MainPort,
    payload: &[u8],
    record: &mut TransferRecord,
    cancelled: &mut impl FnMut() -> bool,
    progress: &mut impl FnMut(Progress),
) -> Result<(), String> {
    let mut offset = 0;
    while offset < payload.len() {
        if cancelled() {
            if offset == 0 {
                return Err("Cancelled after destination creation; the empty firmware file remains and requires inspection before another attempt".into());
            }
            return Err("Cancelled after firmware submission".into());
        }
        port.check_session()?;
        let bytes = &payload[offset..(offset + 4096).min(payload.len())];
        let count = match port.write(bytes) {
            Ok(count) if count <= bytes.len() => {
                record.bytes_submitted += count;
                count
            }
            Ok(_) => {
                record.bytes_submitted += bytes.len();
                publish_progress(record, payload.len(), progress);
                return Err("Invalid filesystem write count".into());
            }
            Err(error) => {
                if let Some(count) = error
                    .known_write_count
                    .filter(|count| *count <= bytes.len())
                {
                    record.bytes_submitted += count;
                    record.bytes_confirmed += count;
                } else if error.may_have_been_submitted {
                    record.bytes_submitted += bytes.len();
                }
                if error.audit_failure {
                    record
                        .cleanup_errors
                        .push(format!("Host audit failure: {}", error.message));
                }
                publish_progress(record, payload.len(), progress);
                return Err(error.message);
            }
        };
        publish_progress(record, payload.len(), progress);
        if count == 0 {
            return Err("Zero-progress filesystem write".into());
        }
        offset += count;
        record.bytes_confirmed += count;
        publish_progress(record, payload.len(), progress);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::BT_SIGNATURE;

    struct MainFake {
        events: Vec<&'static str>,
        written: Vec<u8>,
        destination_name: Option<String>,
        version: &'static [u8],
        refuse_write: bool,
        fail: Option<&'static str>,
    }
    impl MainPort for MainFake {
        fn prepare_write(&mut self) -> Result<(), String> {
            if self.refuse_write {
                Err("unqualified adapter".into())
            } else {
                Ok(())
            }
        }
        fn read_version(&mut self) -> Result<Vec<u8>, String> {
            Ok(self.version.to_vec())
        }
        fn check_session(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn create_destination(&mut self, name: &str) -> Result<(), DestinationCreationError> {
            self.destination_name = Some(name.to_owned());
            if self.fail == Some("creation_audit") {
                self.events.push("create");
                return Err(DestinationCreationError {
                    error: "creation audit failed".into(),
                    created: true,
                });
            }
            self.event("create").map_err(Into::into)
        }
        fn write(&mut self, bytes: &[u8]) -> Result<usize, SubmissionError> {
            if self.fail == Some("write_audit") {
                return Err(SubmissionError::audit_before(
                    "host audit failed before Main write",
                ));
            }
            self.event("write")?;
            let n = if self.fail == Some("write_result_audit_zero") {
                0
            } else {
                bytes.len().min(79)
            };
            self.written.extend_from_slice(&bytes[..n]);
            if matches!(
                self.fail,
                Some("write_result_audit" | "write_result_audit_zero")
            ) {
                return Err(SubmissionError {
                    message: "write succeeded but audit failed".into(),
                    may_have_been_submitted: true,
                    audit_failure: true,
                    completion: SubmissionCompletion::Uncertain,
                    known_write_count: Some(n),
                });
            }
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
            destination_name: None,
            version: b"www.gulikit.com\nversion 5.8",
            refuse_write: false,
            fail: None,
        }
    }
    #[test]
    fn main_result_audit_failure_retains_the_successful_write_count() {
        for (failure, count, outcome) in [
            ("write_result_audit", 79, Outcome::OutcomeUnknown),
            (
                "write_result_audit_zero",
                0,
                Outcome::DestinationCreatedWithoutPayload,
            ),
        ] {
            let mut port = main_port();
            port.fail = Some(failure);
            let record = main_transfer(
                &mut port,
                &vec![0xa5; 51500],
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert_eq!(record.bytes_submitted, count);
            assert_eq!(record.bytes_confirmed, count);
            assert_eq!(port.written.len(), count);
            assert_eq!(record.outcome, outcome);
            assert_eq!(port.events, ["create", "write", "finish"]);
            assert_ne!(record.cleanup_errors, [] as [std::string::String; 0]);
        }
    }

    #[test]
    fn selected_main_target_drives_downgrade_policy_and_expected_transfer_size() {
        let mut port = main_port();
        let payload = vec![0x6d; 1536];
        let record = run_main_transaction(
            &mut port,
            &payload,
            MainTarget {
                version: "3.1",
                payload_size: payload.len(),
                member: "NS39_KK3_MAX_V3.1.bin",
            },
            VersionPolicy::AllowDowngrade,
            || false,
            |_| {},
        );

        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(port.written, payload);
        assert_eq!(
            port.destination_name.as_deref(),
            Some("NS39_KK3_MAX_V3.1.bin")
        );
    }

    #[test]
    fn selected_main_target_rejects_a_payload_length_mismatch_before_creation() {
        let mut port = main_port();
        let record = run_main_transaction(
            &mut port,
            &[0x6d; 512],
            MainTarget {
                version: "3.1",
                payload_size: 1024,
                member: "NS39_KK3_MAX_V3.1.bin",
            },
            VersionPolicy::AllowDowngrade,
            || false,
            |_| {},
        );

        assert_eq!(record.outcome, Outcome::Refused);
        assert_eq!(port.events, ["finish"]);
        assert_eq!(record.bytes_submitted, 0);
    }

    #[test]
    fn progress_reports_confirmed_short_writes_and_never_guesses_completion() {
        let mut port = main_port();
        let mut progress = Vec::new();
        let result = run_main_transaction(
            &mut port,
            &vec![0; 51500],
            MainTarget {
                version: "5.9",
                payload_size: 51_500,
                member: "NS39_KK3_MAX_V5.9.bin",
            },
            VersionPolicy::UpgradeOnly,
            || false,
            |p| progress.push(p),
        );
        assert_eq!(
            result.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert!(
            !progress.is_empty(),
            "real transfers must publish byte progress"
        );
        assert_eq!(progress.last().unwrap().confirmed, 51500);
        assert!(
            progress
                .iter()
                .all(|p| p.confirmed <= p.submitted && p.confirmed <= p.total)
        );
        assert_eq!(
            progress.iter().find(|p| p.confirmed > 0).unwrap().confirmed,
            79
        );
    }
    #[test]
    fn failed_bluetooth_command_reports_submission_without_confirmation() {
        let mut port = Fake {
            version: 506,
            fail: Some(4),
            ..Fake::default()
        };
        let mut progress = Vec::new();
        let record = run_bluetooth_transaction(
            &mut port,
            &vec![0; 345_088],
            507,
            VersionPolicy::UpgradeOnly,
            || false,
            |p| progress.push(p),
        );
        assert_eq!(record.outcome, Outcome::OutcomeUnknown);
        assert_eq!(record.bytes_submitted, 1024);
        assert_eq!(record.bytes_confirmed, 512);
        assert_eq!(
            progress.last().unwrap(),
            &Progress {
                submitted: 1024,
                confirmed: 512,
                total: 345_088
            }
        );
        assert!(port.cleanup);
    }
    #[test]
    fn main_handles_short_writes_flushes_open_file_and_waits_for_detach() {
        let mut port = main_port();
        let payload = vec![0x83; 51500];
        let record = main_transfer(&mut port, &payload, VersionPolicy::UpgradeOnly, || false);
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(port.written, payload);
        assert_eq!(record.bytes_submitted, payload.len());
        let tail = &port.events[port.events.len() - 5..];
        assert_eq!(tail, ["flush", "close", "volume_flush", "detach", "finish"]);
    }
    #[test]
    fn cancellation_after_main_creation_requires_attention_without_claiming_payload_submission() {
        let mut port = main_port();
        let mut checks = 0;
        let record = main_transfer(
            &mut port,
            &vec![0; 51500],
            VersionPolicy::UpgradeOnly,
            || {
                checks += 1;
                checks == 3
            },
        );
        assert_eq!(record.outcome, Outcome::DestinationCreatedWithoutPayload);
        assert!(record.main_destination_created);
        assert_eq!(record.bytes_submitted, 0);
        assert_eq!(record.bytes_confirmed, 0);
        assert_eq!(port.written, [] as [u8; 0]);
        assert_eq!(port.events, ["create", "finish"]);
        assert!(record.error.as_deref().unwrap().contains("destination"));
    }
    #[test]
    fn created_destination_survives_a_failure_recording_its_creation() {
        let mut port = main_port();
        port.fail = Some("creation_audit");
        let record = main_transfer(
            &mut port,
            &vec![0; 51500],
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(record.outcome, Outcome::DestinationCreatedWithoutPayload);
        assert!(record.main_destination_created);
        assert_eq!(record.bytes_submitted, 0);
        assert_eq!(port.events, ["create", "finish"]);
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
            let result = main_transfer(
                &mut port,
                &vec![0; 51500],
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert!(matches!(
                result.outcome,
                Outcome::AlreadyCurrent | Outcome::NewerThanSupported | Outcome::Refused
            ));
            assert_eq!(port.written, [] as [u8; 0]);
            assert_eq!(port.events, ["finish"]);
        }
        let mut port = main_port();
        port.fail = Some("create");
        assert_eq!(
            main_transfer(
                &mut port,
                &vec![0; 51500],
                VersionPolicy::UpgradeOnly,
                || false
            )
            .outcome,
            Outcome::Refused
        );
        assert_eq!(port.written, [] as [u8; 0]);
    }
    #[test]
    fn main_failure_never_turns_later_detach_into_success() {
        for failure in ["write", "flush", "close", "volume_flush"] {
            let mut port = main_port();
            port.fail = Some(failure);
            assert_eq!(
                main_transfer(
                    &mut port,
                    &vec![0; 51500],
                    VersionPolicy::UpgradeOnly,
                    || false
                )
                .outcome,
                Outcome::OutcomeUnknown
            );
            assert!(!port.events.contains(&"detach"));
            assert_eq!(port.events.last(), Some(&"finish"));
        }
    }

    #[derive(Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "Independent fake transport, audit, cleanup and detach failures are tested in combination."
    )]
    struct Fake {
        calls: Vec<u8>,
        bytes: Vec<u8>,
        fail: Option<usize>,
        invalidate: Option<usize>,
        version: u16,
        cleanup: bool,
        refuse_write: bool,
        audit_before_firmware: bool,
        f2_response: Option<Vec<u8>>,
        missing_status: Option<usize>,
        audit_at_missing_status: bool,
        selected_still_present: bool,
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
        fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, SubmissionError> {
            if opcode == 0xf0 && self.audit_before_firmware {
                return Err(SubmissionError::audit_before("host audit failed before F0"));
            }
            self.calls.push(opcode);
            if self.missing_status == Some(self.calls.len()) {
                self.bytes.extend_from_slice(data);
                return Err(SubmissionError {
                    completion: SubmissionCompletion::DataSentStatusMissing,
                    audit_failure: self.audit_at_missing_status,
                    ..SubmissionError::from("status unavailable after exact DATA OUT")
                });
            }
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
                0xf2 => Ok(self.f2_response.clone().unwrap_or_else(|| vec![0; 20])),
                _ => unreachable!(),
            }
        }
        fn completion_detached(&mut self) -> Result<bool, String> {
            Ok(!self.selected_still_present)
        }
        fn finish(&mut self) -> Result<(), String> {
            self.cleanup = true;
            Ok(())
        }
    }
    #[test]
    #[expect(
        clippy::naive_bytecount,
        reason = "Counting a bounded fake command log does not warrant an additional dependency."
    )]
    fn only_a_fully_sent_last_block_can_await_restart_without_its_status() {
        for (at, audit, expected) in [
            (2, false, Outcome::OutcomeUnknown),
            (4, false, Outcome::OutcomeUnknown),
            (708, true, Outcome::OutcomeUnknown),
            (708, false, Outcome::TransferSubmittedPendingCompletion),
        ] {
            let mut port = Fake {
                version: 323,
                missing_status: Some(at),
                audit_at_missing_status: audit,
                ..Fake::default()
            };
            let record = bluetooth_release(
                &mut port,
                &vec![0x5a; 361_472],
                324,
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert_eq!(record.outcome, expected, "at={at} audit={audit}");
            assert_eq!(record.bytes_confirmed, at.saturating_sub(3) * 512);
            assert!(record.commands.last().unwrap().error.is_some());
            assert_eq!(record.commands.last().unwrap().confirmed, 0);
            assert_eq!(port.calls.last(), Some(&0xf0));
            assert!(port.cleanup);
            if at == 708 && !audit {
                assert_eq!(record.bytes_submitted, 361_472);
                assert_eq!(record.bytes_confirmed, 360_960);
                assert!(record.error.is_none());
                assert_eq!(port.calls.iter().filter(|&&op| op == 0xf2).count(), 1);
            }
        }
    }

    #[test]
    fn final_data_without_status_or_observed_detach_remains_unknown() {
        let mut port = Fake {
            version: 323,
            missing_status: Some(708),
            selected_still_present: true,
            ..Fake::default()
        };
        let record = bluetooth_release(
            &mut port,
            &vec![0; 361_472],
            324,
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(record.outcome, Outcome::OutcomeUnknown);
        assert_eq!(record.bytes_submitted, 361_472);
        assert_eq!(record.bytes_confirmed, 360_960);
    }

    #[test]
    fn kk3_normal_last_block_reboot_waits_for_readback_without_retrying_firmware() {
        let mut port = Fake {
            version: 323,
            missing_status: Some(708),
            ..Fake::default()
        };
        let record = bluetooth_release(
            &mut port,
            &vec![0x5a; 361_472],
            324,
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(record.outcome, Outcome::TransferSubmittedPendingCompletion);
        assert_eq!(record.bytes_submitted, 361_472);
        assert_eq!(record.bytes_confirmed, 360_960);
        assert_eq!(port.calls.len(), 708);
        assert_eq!(port.calls.last(), Some(&0xf0));
        assert_eq!(port.calls[2], 0xf2);
        assert!(record.commands.last().unwrap().error.is_some());
        assert!(record.error.is_none());
        assert!(port.cleanup);
    }

    #[test]
    fn completed_final_commands_retain_confirmation_across_expected_detach() {
        for (after_command, still_present, expected) in [
            (708, false, Outcome::TransferSubmittedPendingCompletion),
            (709, false, Outcome::TransferCompletedAwaitingVerification),
            (708, true, Outcome::OutcomeUnknown),
            (709, true, Outcome::OutcomeUnknown),
            (4, false, Outcome::OutcomeUnknown),
        ] {
            let mut port = Fake {
                version: 323,
                invalidate: Some(after_command),
                selected_still_present: still_present,
                ..Fake::default()
            };
            let record = bluetooth_release(
                &mut port,
                &vec![0; 361_472],
                324,
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert_eq!(
                record.outcome, expected,
                "after={after_command} present={still_present}"
            );
            let confirmed = if after_command >= 708 { 361_472 } else { 1024 };
            assert_eq!(record.bytes_confirmed, confirmed);
            assert_eq!(record.bytes_submitted, confirmed);
            assert_eq!(port.calls.len(), after_command);
            assert!(port.cleanup);
        }
    }

    #[test]
    fn upgrade_and_explicit_downgrade_pending_receipts_require_fresh_target_readback() {
        for (current, target, policy) in [
            (323, 324, VersionPolicy::UpgradeOnly),
            (324, 323, VersionPolicy::AllowDowngrade),
        ] {
            let mut port = Fake {
                version: current,
                missing_status: Some(708),
                ..Fake::default()
            };
            let record = bluetooth_release(&mut port, &vec![0; 361_472], target, policy, || false);
            assert_eq!(record.outcome, Outcome::TransferSubmittedPendingCompletion);
            let mut observation = Verification {
                component: Component::Bluetooth,
                previous_generation: 10,
                generation: 11,
                same_unit_confirmed: true,
                model_confirmed: true,
                version: record.prewrite_version.clone().unwrap(),
                expected_version: format!("{}.{:02}", target / 100, target % 100),
            };
            assert_eq!(verify_restart(record.outcome, &observation), record.outcome);
            observation.version = observation.expected_version.clone();
            observation.generation = 10;
            assert_eq!(verify_restart(record.outcome, &observation), record.outcome);
            observation.generation = 11;
            observation.same_unit_confirmed = false;
            assert_eq!(verify_restart(record.outcome, &observation), record.outcome);
            observation.same_unit_confirmed = true;
            assert_eq!(
                verify_restart(record.outcome, &observation),
                Outcome::InstalledVerified
            );
        }
    }

    #[test]
    fn first_and_final_f2_use_only_received_nonempty_status() {
        let mut port = Fake {
            version: 323,
            f2_response: Some(vec![0]),
            ..Fake::default()
        };
        let record = bluetooth_release(
            &mut port,
            &vec![0; 361_472],
            324,
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        let statuses: Vec<_> = record
            .commands
            .iter()
            .filter(|command| command.opcode == 0xf2)
            .collect();
        assert_eq!(statuses.len(), 2);
        assert!(
            statuses
                .iter()
                .all(|status| status.requested == 20 && status.confirmed == 1)
        );
        for response in [vec![], vec![1], vec![0; 21]] {
            let mut port = Fake {
                version: 323,
                f2_response: Some(response),
                ..Fake::default()
            };
            let record = bluetooth_release(
                &mut port,
                &vec![0; 361_472],
                324,
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert_eq!(record.outcome, Outcome::OutcomeUnknown);
            assert_eq!(record.bytes_confirmed, 512);
            assert_eq!(port.calls, [0xf1, 0xf0, 0xf2]);
        }
    }
    #[test]
    fn first_f0_audit_refusal_is_known_zero_submission_and_requires_host_attention() {
        let mut port = Fake {
            version: 323,
            audit_before_firmware: true,
            ..Fake::default()
        };
        let record = bluetooth_release(
            &mut port,
            &vec![0; 361_472],
            324,
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(record.outcome, Outcome::Refused);
        assert_eq!(record.bytes_submitted, 0);
        assert_eq!(record.bytes_confirmed, 0);
        assert_ne!(record.cleanup_errors, [] as [std::string::String; 0]);
        assert_eq!(port.calls, [0xf1]);
        assert_eq!(port.bytes, [] as [u8; 0]);
        assert!(port.cleanup);
    }
    #[test]
    fn first_main_write_audit_refusal_retains_the_created_file_with_zero_submission() {
        let mut port = main_port();
        port.fail = Some("write_audit");
        let record = main_transfer(
            &mut port,
            &vec![0; 51500],
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(record.outcome, Outcome::DestinationCreatedWithoutPayload);
        assert!(record.main_destination_created);
        assert_eq!(record.bytes_submitted, 0);
        assert_ne!(record.cleanup_errors, [] as [std::string::String; 0]);
        assert_eq!(port.events, ["create", "finish"]);
        assert_eq!(port.written, [] as [u8; 0]);
    }
    #[test]
    fn selected_324_release_uses_its_target_and_all_706_blocks() {
        let payload: Vec<u8> = (0..361_472)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let mut port = Fake {
            version: 323,
            ..Fake::default()
        };
        let record =
            bluetooth_release(&mut port, &payload, 324, VersionPolicy::UpgradeOnly, || {
                false
            });
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(record.bytes_confirmed, 361_472);
        assert_eq!(port.bytes, payload);
        let mut expected = vec![0xf1, 0xf0, 0xf2];
        expected.extend(std::iter::repeat_n(0xf0, 705));
        expected.push(0xf2);
        assert_eq!(port.calls, expected);
        for (version, policy, outcome) in [
            (324, VersionPolicy::UpgradeOnly, Outcome::AlreadyCurrent),
            (324, VersionPolicy::AllowDowngrade, Outcome::AlreadyCurrent),
            (325, VersionPolicy::UpgradeOnly, Outcome::NewerThanSupported),
        ] {
            let mut port = Fake {
                version,
                ..Fake::default()
            };
            let record = bluetooth_release(&mut port, &payload, 324, policy, || false);
            assert_eq!(record.outcome, outcome);
            assert_eq!(port.bytes, [] as [u8; 0]);
            assert_eq!(port.calls, [0xf1]);
        }
    }
    #[test]
    fn selected_323_release_downgrade_keeps_the_full_transfer_and_version_guards() {
        let payload = vec![0xa5; 361_472];
        for (version, policy, expected) in [
            (324, VersionPolicy::UpgradeOnly, Outcome::NewerThanSupported),
            (
                324,
                VersionPolicy::AllowDowngrade,
                Outcome::TransferCompletedAwaitingVerification,
            ),
            (323, VersionPolicy::AllowDowngrade, Outcome::AlreadyCurrent),
        ] {
            let mut port = Fake {
                version,
                ..Fake::default()
            };
            let record = bluetooth_release(&mut port, &payload, 323, policy, || false);
            assert_eq!(record.outcome, expected);
            if expected == Outcome::TransferCompletedAwaitingVerification {
                assert_eq!(record.bytes_confirmed, 361_472);
                assert_eq!(port.bytes, payload);
                let mut commands = vec![0xf1, 0xf0, 0xf2];
                commands.extend(std::iter::repeat_n(0xf0, 705));
                commands.push(0xf2);
                assert_eq!(port.calls, commands);
            } else {
                assert_eq!(port.bytes, [] as [u8; 0]);
                assert_eq!(port.calls, [0xf1]);
            }
        }
    }
    #[test]
    fn every_324_command_failure_stops_without_replay_or_losing_submission_uncertainty() {
        for failure in 1..=709 {
            let mut port = Fake {
                version: 323,
                fail: Some(failure),
                ..Fake::default()
            };
            let record = bluetooth_release(
                &mut port,
                &vec![0; 361_472],
                324,
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert_eq!(
                record.outcome,
                if failure == 1 {
                    Outcome::Refused
                } else {
                    Outcome::OutcomeUnknown
                }
            );
            assert_eq!(port.calls.len(), failure);
            assert!(port.cleanup);
        }
        for length in [0, 511, 513, 361_471, 361_473] {
            let mut port = Fake {
                version: 323,
                ..Fake::default()
            };
            let record = bluetooth_release(
                &mut port,
                &vec![0; length],
                324,
                VersionPolicy::UpgradeOnly,
                || false,
            );
            assert_eq!(record.outcome, Outcome::Refused);
            assert_eq!(port.bytes, [] as [u8; 0]);
            assert_eq!(port.calls, [0xf1]);
        }
        let mut port = Fake {
            version: 325,
            ..Fake::default()
        };
        let record = bluetooth_release(
            &mut port,
            &vec![0; 361_472],
            324,
            VersionPolicy::AllowDowngrade,
            || false,
        );
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(record.bytes_confirmed, 361_472);
    }
    #[test]
    fn exact_bluetooth_transcript_and_payload_no_installed_success() {
        let payload: Vec<_> = (0..345_088)
            .map(|n| u8::try_from(n % 251).unwrap())
            .collect();
        let mut port = Fake {
            version: 506,
            ..Fake::default()
        };
        let record = bluetooth(&mut port, &payload, VersionPolicy::UpgradeOnly, || false);
        assert_eq!(
            record.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(port.calls.len(), 677);
        assert_eq!(&port.calls[..3], &[0xf1, 0xf0, 0xf2]);
        assert!(port.calls[3..676].iter().all(|b| *b == 0xf0));
        assert_eq!(port.calls[676], 0xf2);
        assert_eq!(port.bytes, payload);
        assert_eq!(record.bytes_confirmed, 345_088);
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
                fail,
                version,
                ..Fake::default()
            };
            assert_eq!(
                bluetooth(
                    &mut port,
                    &vec![0; 345_088],
                    VersionPolicy::UpgradeOnly,
                    || false
                )
                .outcome,
                outcome
            );
            assert_eq!(port.bytes, [] as [u8; 0]);
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
        let record = bluetooth(
            &mut port,
            &vec![0; 345_088],
            VersionPolicy::UpgradeOnly,
            || false,
        );
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
            let record = bluetooth(
                &mut port,
                &vec![0; 345_088],
                VersionPolicy::UpgradeOnly,
                || false,
            );
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
        let record = bluetooth(
            &mut port,
            &vec![0; 345_088],
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(record.outcome, Outcome::OutcomeUnknown);
        assert_eq!(port.calls, [0xf1, 0xf0, 0xf2]);
        let mut port = Fake {
            version: 506,
            ..Fake::default()
        };
        assert_eq!(
            bluetooth(
                &mut port,
                &vec![0; 345_088],
                VersionPolicy::UpgradeOnly,
                || true
            )
            .outcome,
            Outcome::CancelledBeforeWrite
        );
        assert_eq!(port.calls, [] as [u8; 0]);
        assert!(port.cleanup);
    }
    #[test]
    fn main_downgrade_permission_never_bypasses_version_or_adapter_preflight() {
        let mut main = main_port();
        main.version = b"www.gulikit.com\nversion 5.10";
        let default = main_transfer(
            &mut main,
            &vec![0; 51500],
            VersionPolicy::UpgradeOnly,
            || false,
        );
        assert_eq!(default.outcome, Outcome::NewerThanSupported);
        assert_eq!(main.written, [] as [u8; 0]);
        let mut main = main_port();
        main.version = b"www.gulikit.com\nversion 5.10";
        let allowed = main_transfer(
            &mut main,
            &vec![0; 51500],
            VersionPolicy::AllowDowngrade,
            || false,
        );
        assert_eq!(
            allowed.outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        assert_eq!(allowed.version_policy, VersionPolicy::AllowDowngrade);
        for version in [b"www.gulikit.com\nversion 5.9".as_slice(), b"unknown"] {
            let mut main = main_port();
            main.version = version;
            let result = main_transfer(
                &mut main,
                &vec![0; 51500],
                VersionPolicy::AllowDowngrade,
                || false,
            );
            assert!(matches!(
                result.outcome,
                Outcome::AlreadyCurrent | Outcome::Refused
            ));
            assert_eq!(main.written, [] as [u8; 0]);
        }
        let mut main = main_port();
        main.version = b"www.gulikit.com\nversion 5.10";
        main.refuse_write = true;
        assert_eq!(
            main_transfer(
                &mut main,
                &vec![0; 51500],
                VersionPolicy::AllowDowngrade,
                || false
            )
            .outcome,
            Outcome::Refused
        );
        assert!(!main.events.contains(&"create"));
    }

    #[test]
    fn bluetooth_downgrade_permission_never_bypasses_version_or_adapter_preflight() {
        let mut bt = Fake {
            version: 508,
            ..Fake::default()
        };
        assert_eq!(
            bluetooth(
                &mut bt,
                &vec![0; 345_088],
                VersionPolicy::UpgradeOnly,
                || false
            )
            .outcome,
            Outcome::NewerThanSupported
        );
        assert_eq!(bt.bytes, [] as [u8; 0]);
        let mut bt = Fake {
            version: 508,
            ..Fake::default()
        };
        assert_eq!(
            bluetooth(
                &mut bt,
                &vec![0; 345_088],
                VersionPolicy::AllowDowngrade,
                || false
            )
            .outcome,
            Outcome::TransferCompletedAwaitingVerification
        );
        for (version, fail, refuse_write, outcome) in [
            (507, None, false, Outcome::AlreadyCurrent),
            (508, Some(1), false, Outcome::Refused),
            (508, None, true, Outcome::Refused),
        ] {
            let mut bt = Fake {
                fail,
                version,
                refuse_write,
                ..Fake::default()
            };
            let result = bluetooth(
                &mut bt,
                &vec![0; 345_088],
                VersionPolicy::AllowDowngrade,
                || false,
            );
            assert_eq!(result.outcome, outcome);
            assert_eq!(bt.bytes, [] as [u8; 0]);
            assert_eq!(result.bytes_submitted, 0);
        }
    }
}
