//! Synchronous application API. Frontends run these operations off their event loop.

use gulikit_core::{
    package::{Component, PackageInfo, VerifiedPackage},
    update::{Outcome, Progress, TransferRecord, Verification},
    version::VersionPolicy,
};
use gulikit_platform::discovery::{NativeCandidate, Snapshot};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Request {
    Devices,
    Probe {
        component: Component,
        confirm_ns39: bool,
    },
    Update {
        package: VerifiedPackage,
        confirm_ns39: bool,
        record: PathBuf,
        expected_attachment: Option<Attachment>,
        policy: VersionPolicy,
    },
    Verify {
        attempt: PathBuf,
        record: PathBuf,
        confirm_ns39: bool,
        confirm_same_controller: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub ancestor: u64,
    pub generation: u64,
}
impl From<&NativeCandidate> for Attachment {
    fn from(target: &NativeCandidate) -> Self {
        Self {
            ancestor: target.ancestor,
            generation: target.generation,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Devices {
    pub discovery: Snapshot,
    pub coverage: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub component: Component,
    pub installed_version: String,
    pub decision: gulikit_core::version::VersionDecision,
    pub raw_version_bytes: Vec<u8>,
    pub qualified_bot_lun: Option<u8>,
    pub cleanup_errors: Vec<String>,
    pub target: NativeCandidate,
    pub identity_provenance: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Attempt {
    pub event: &'static str,
    pub schema_version: u8,
    pub target: NativeCandidate,
    pub package: PackageInfo,
    pub transfer: TransferRecord,
    pub operator_action: &'static str,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct VerificationTransfer {
    pub outcome: Outcome,
    pub error: Option<String>,
    pub cleanup_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Readback {
    pub event: &'static str,
    pub schema_version: u8,
    #[serde(serialize_with = "serialize_record_path")]
    pub source_attempt: PathBuf,
    pub verification: Option<Verification>,
    pub raw_version_bytes: Option<Vec<u8>>,
    pub qualified_bot_lun: Option<u8>,
    pub target: NativeCandidate,
    pub same_unit_association: &'static str,
    pub transfer: VerificationTransfer,
}

fn serialize_record_path<S: serde::Serializer>(
    path: &std::path::Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    native::record_path(path).serialize(serializer)
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Reply {
    Devices(Devices),
    Inspection(Inspection),
    Attempt(Attempt),
    Readback(Readback),
}

/// A receipt can only request a fresh observation; it cannot authorize a transfer.
#[derive(Debug)]
pub struct PriorAttempt {
    pub component: Component,
    pub outcome: Outcome,
    pub generation: u64,
    pub record: serde_json::Value,
    pub expected_version: String,
}

impl PriorAttempt {
    /// Check the receipt before acquiring a new controller session.
    pub fn require_verifiable(&self) -> Result<(), String> {
        if self.outcome.awaits_restart_verification() {
            Ok(())
        } else {
            Err("This receipt does not safely await restart verification. Keep a partial or unknown controller connected and unchanged; no new device session or reset is permitted by this receipt.".into())
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        let prior = records
            .into_iter()
            .last()
            .filter(|v| v["event"] == "attempt_result")
            .ok_or(
                "Attempt has no complete result. Keep the controller connected and unchanged; a missing final receipt does not establish that no firmware was submitted. Do not probe or reset until recovery is separately qualified.",
            )?;
        let (component, expected_version) = native::attempt_target(&prior)?;
        let outcome = serde_json::from_value(prior["transfer"]["outcome"].clone())
            .map_err(|e| e.to_string())?;
        let generation = prior["target"]["generation"]
            .as_u64()
            .ok_or("Missing attachment generation")?;
        Ok(Self {
            component,
            outcome,
            generation,
            record: prior,
            expected_version,
        })
    }
}

#[derive(Debug)]
pub struct ApplicationError {
    pub kind: &'static str,
    pub code: u8,
    pub message: String,
    pub cleanup_errors: Vec<String>,
}
impl ApplicationError {
    pub fn new(kind: &'static str, code: u8, message: String) -> Self {
        Self {
            kind,
            code,
            message,
            cleanup_errors: Vec::new(),
        }
    }
    pub fn host_io(message: String) -> Self {
        Self::new("host_record_io", 4, message)
    }
    pub fn with_cleanup(mut self, cleanup_errors: Vec<String>) -> Self {
        if !cleanup_errors.is_empty() {
            self.code = 8;
        }
        self.cleanup_errors = cleanup_errors;
        self
    }
}
impl From<String> for ApplicationError {
    fn from(message: String) -> Self {
        Self::new("device_refused", 5, message)
    }
}
impl From<&str> for ApplicationError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl From<gulikit_platform::acquisition::AcquisitionError> for ApplicationError {
    fn from(error: gulikit_platform::acquisition::AcquisitionError) -> Self {
        Self::from(error.error).with_cleanup(error.cleanup_errors)
    }
}
mod native;

/// Execute a desktop operation through the shared component transaction and
/// native ownership boundary. Firmware installation requires fresh readback.
pub fn execute(
    request: Request,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(Progress),
) -> Result<Reply, String> {
    if let Request::Update { .. } = &request {
        return Err("Desktop firmware writes are not available until a verified rollback path and desktop update supervision are ready.".into());
    }
    let context = match &request {
        Request::Verify {
            attempt,
            confirm_same_controller,
            ..
        } => Some((attempt.clone(), *confirm_same_controller)),
        _ => None,
    };
    let component = match &request {
        Request::Probe { component, .. } => Some(*component),
        _ => None,
    };
    let mut value = execute_raw(request, cancelled, progress)
        .map_err(|error| format!("{}; cleanup={:?}", error.message, error.cleanup_errors))?;
    if value.get("discovery").is_some() {
        return Ok(Reply::Devices(Devices {
            discovery: field(&mut value, "discovery")?,
            coverage: "Observed GuliKit update profiles and correlated GuliKit volumes. Put only one device in update mode; future unknown identities may not be recognized.",
        }));
    }
    if let Some(component) = component {
        let raw: Vec<u8> = field(&mut value, "raw_version_bytes")?;
        let decision = match component {
            Component::Main => gulikit_core::version::MainVersion::parse(&raw)
                .map_err(|error| error.to_string())?
                .decision(),
            Component::Bluetooth => gulikit_core::version::bluetooth_info(&raw)
                .map_err(|error| error.to_string())?
                .decision(),
        };
        return Ok(Reply::Inspection(Inspection {
            component,
            installed_version: field(&mut value, "installed_version")?,
            decision,
            raw_version_bytes: raw,
            qualified_bot_lun: field(&mut value, "qualified_bot_lun")?,
            cleanup_errors: field(&mut value, "cleanup_errors")?,
            target: field(&mut value, "target")?,
            identity_provenance: "user-confirmed NS39; observed update profile",
        }));
    }
    let (source_attempt, confirmed) = context.ok_or("Unexpected application operation result")?;
    Ok(Reply::Readback(Readback {
        event: "verification_result",
        schema_version: 1,
        source_attempt,
        verification: field(&mut value, "verification")?,
        raw_version_bytes: field(&mut value, "raw_version_bytes")?,
        qualified_bot_lun: field(&mut value, "qualified_bot_lun")?,
        target: field(&mut value, "target")?,
        same_unit_association: same_unit_association(confirmed),
        transfer: field(&mut value, "transfer")?,
    }))
}
fn field<T: serde::de::DeserializeOwned>(
    value: &mut serde_json::Value,
    name: &str,
) -> Result<T, String> {
    serde_json::from_value(value[name].take())
        .map_err(|error| format!("Invalid operation result {name}: {error}"))
}

/// CLI operation boundary. Main transfers are dispatched through its guardian first.
pub fn execute_raw(
    request: Request,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(Progress),
) -> Result<serde_json::Value, ApplicationError> {
    #[cfg(target_os = "macos")]
    {
        native::execute(request, None, cancelled, progress)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (request, cancelled, progress);
        Err("Native device access currently supports macOS only; package inspection works on this OS".into())
    }
}
#[cfg(target_os = "macos")]
pub fn execute_main_worker(
    request: Request,
    lease: gulikit_platform::lock::ProcessLock,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(Progress),
) -> Result<serde_json::Value, ApplicationError> {
    match &request {
        Request::Update { package, .. } if package.info().component == Component::Main => native::execute(request, Some(lease), cancelled, progress),
        _ => Err("Filesystem supervision is restricted to Main updates; never terminate a Bluetooth capture worker".into()),
    }
}

pub fn check_attachment(
    expected: Option<Attachment>,
    target: &NativeCandidate,
) -> Result<(), String> {
    if expected.is_some_and(|expected| expected != Attachment::from(target)) {
        Err("Controller attachment changed since inspection. Inspect and confirm it again.".into())
    } else {
        Ok(())
    }
}

fn same_unit_association(confirmed: bool) -> &'static str {
    if confirmed {
        "user-confirmed; attachment generation bound; no machine-proven unique serial identity"
    } else {
        "not confirmed; independent observation only; no machine-proven unique serial identity"
    }
}

pub fn operator_action(component: Component, outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::TransferCompletedAwaitingVerification
        | Outcome::TransferSubmittedPendingCompletion => match component {
            Component::Main => {
                "The controller completes Main installation and restarts automatically. Once it has restarted, re-enter update mode if needed and use verify with this attempt plus a new host record. Confirm the same physical controller; transfer completion alone does not verify installation."
            }
            Component::Bluetooth => {
                "After the controller completes the transfer and restarts, turn it on normally once, turn it off, then hold Gear first and press the rightmost A to re-enter Bluetooth update mode. Use verify with this attempt plus a new host record and confirm the same physical controller. Only a fresh version read matching the selected target verifies installation."
            }
        },
        Outcome::OutcomeUnknown => {
            "Keep the cable connected and leave the controller unchanged. Do not restart, reset, retry or resume a partial update. Preserve this record and wait for a recovery procedure qualified for this interrupted state."
        }
        Outcome::DestinationCreatedWithoutPayload => {
            "No firmware payload bytes were submitted, but the destination file was created. It remains on the controller and requires inspection before another attempt; the updater does not delete or overwrite it."
        }
        Outcome::AlreadyCurrent => {
            "This component is already current. No firmware bytes were sent."
        }
        _ => {
            "No firmware transfer was completed. Address the recorded refusal before starting a new session."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_readback_serializes_native_source_path_units_losslessly() {
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(b"attempt-\xff.jsonl".to_vec()))
        };
        #[cfg(windows)]
        let path = {
            use std::os::windows::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_wide(&[0x61, 0xd800, 0x62]))
        };
        #[cfg(not(any(unix, windows)))]
        let path = PathBuf::from("attempt.jsonl");
        let target = serde_json::from_value(serde_json::json!({
            "ancestor": 1, "generation": 1, "main_volume_candidate": false,
            "bluetooth_transport_candidate": true, "observed_profile": true,
            "conflicting_model": false, "storage_identities": [], "disks": [], "mount": null
        }))
        .unwrap();
        let reply = Reply::Readback(Readback {
            event: "verification_result",
            schema_version: 1,
            source_attempt: path.clone(),
            verification: None,
            raw_version_bytes: None,
            qualified_bot_lun: None,
            target,
            same_unit_association: "user-confirmed",
            transfer: VerificationTransfer {
                outcome: Outcome::OutcomeUnknown,
                error: None,
                cleanup_errors: vec![],
            },
        });
        let value = serde_json::to_value(reply).unwrap();
        assert_eq!(
            value["source_attempt"]["display"],
            path.to_string_lossy().as_ref()
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let units: Vec<u8> =
                serde_json::from_value(value["source_attempt"]["unix_bytes"].clone()).unwrap();
            assert_eq!(units, path.as_os_str().as_bytes());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let units: Vec<u16> =
                serde_json::from_value(value["source_attempt"]["windows_wide"].clone()).unwrap();
            assert_eq!(units, path.as_os_str().encode_wide().collect::<Vec<_>>());
        }
    }

    #[test]
    fn same_controller_provenance_matches_the_explicit_attestation() {
        for confirmed in [false, true] {
            let observation = Verification {
                component: Component::Bluetooth,
                previous_generation: 1,
                generation: 2,
                same_unit_confirmed: confirmed,
                model_confirmed: true,
                version: "3.24".into(),
                expected_version: "3.24".into(),
            };
            let outcome = gulikit_core::update::verify_restart(
                Outcome::TransferCompletedAwaitingVerification,
                &observation,
            );
            assert_eq!(outcome == Outcome::InstalledVerified, confirmed);
            let provenance = same_unit_association(confirmed);
            assert_eq!(provenance.starts_with("user-confirmed;"), confirmed);
            if !confirmed {
                assert!(provenance.starts_with("not confirmed;"));
            }
        }
    }

    #[test]
    fn receipts_preserve_the_original_reviewed_release_and_reject_changed_metadata() {
        for release in gulikit_core::package::catalog() {
            let mut record = serde_json::json!({
                "event": "attempt_result", "package": release,
                "transfer": {"outcome": "outcome_unknown"},
                "target": {"generation": 12}
            });
            let prior = PriorAttempt::parse(&serde_json::to_vec(&record).unwrap()).unwrap();
            assert_eq!(prior.component, release.component);
            assert_eq!(prior.expected_version, release.version);
            assert_eq!(prior.outcome, Outcome::OutcomeUnknown);
            assert_eq!(prior.generation, 12);
            record["package"]["payload_sha256"] = "changed".into();
            assert!(PriorAttempt::parse(&serde_json::to_vec(&record).unwrap()).is_err());
        }
    }

    #[test]
    fn only_completed_or_pending_completion_receipts_allow_a_verification_session() {
        for outcome in [
            Outcome::Refused,
            Outcome::AlreadyCurrent,
            Outcome::NewerThanSupported,
            Outcome::CancelledBeforeWrite,
            Outcome::DestinationCreatedWithoutPayload,
            Outcome::OutcomeUnknown,
            Outcome::InstalledVerified,
            Outcome::TransferCompletedAwaitingVerification,
            Outcome::TransferSubmittedPendingCompletion,
        ] {
            let record = serde_json::json!({
                "event":"attempt_result", "package":gulikit_core::package::catalog()[2],
                "transfer":{"outcome":outcome,"bytes_submitted":512,"bytes_confirmed":512},
                "target":{"generation":42}
            });
            let prior = PriorAttempt::parse(&serde_json::to_vec(&record).unwrap()).unwrap();
            let expected = matches!(
                outcome,
                Outcome::TransferCompletedAwaitingVerification
                    | Outcome::TransferSubmittedPendingCompletion
            );
            assert_eq!(prior.require_verifiable().is_ok(), expected, "{outcome:?}");
        }
    }

    #[test]
    fn incomplete_receipts_cannot_request_verification() {
        assert!(PriorAttempt::parse(br#"{"event":"attempt_started"}"#).is_err());
        assert!(
            PriorAttempt::parse(br#"{"event":"attempt_result","package":{"component":"main"}}"#)
                .is_err()
        );
    }

    #[test]
    fn acquisition_failures_keep_the_primary_refusal_and_cleanup_attention() {
        let error = ApplicationError::from(
            gulikit_platform::acquisition::AcquisitionError::after_cleanup(
                "interface open failed".into(),
                Err("remount failed".into()),
            ),
        );
        assert_eq!(error.kind, "device_refused");
        assert_eq!(error.code, 8);
        assert_eq!(error.message, "interface open failed");
        assert_eq!(error.cleanup_errors, ["remount failed"]);
    }
    #[test]
    fn partial_bluetooth_failure_never_recommends_restart_from_surrender() {
        let partial = TransferRecord {
            outcome: Outcome::OutcomeUnknown,
            bytes_submitted: 512,
            bytes_confirmed: 512,
            error: Some("F2 status transport failed".into()),
            cleanup_errors: vec![gulikit_platform::acquisition::SURRENDER_PENDING_NOTICE.into()],
            ..TransferRecord::default()
        };
        let advice = operator_action(Component::Bluetooth, partial.outcome);
        assert!(advice.contains("Do not restart"), "{advice}");
        assert!(
            advice.contains("leave the controller unchanged"),
            "{advice}"
        );
        assert!(!partial.cleanup_errors[0].contains("Restart normally"));
        assert!(!advice.contains("Power off and on normally"));
    }
}
