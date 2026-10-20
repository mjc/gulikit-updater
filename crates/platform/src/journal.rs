//! Durable host-side operation records around the same ports used by the updater.

use gulikit_core::update::{BluetoothPort, DestinationCreationError, MainPort, SubmissionError};
use serde::Serialize;
use serde_json::json;
use std::{fs::File, io::Write};

#[cfg(unix)]
const ATTEMPT_SIZE_LIMIT: u64 = 16 * 1024 * 1024;

/// Open the attempt itself without following a symlink or waiting for a FIFO writer.
#[cfg(unix)]
///
/// # Errors
///
/// Returns an error for a symlink, nonregular or unreadable file, an oversized record, or a read failure.
pub fn read_attempt(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use nix::{
        fcntl::{OFlag, open},
        sys::stat::Mode,
    };
    use std::io::Read;
    let file = File::from(
        open(
            path,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| format!("Attempt record must be a readable regular file: {error}"))?,
    );
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("Attempt record must be a regular file".into());
    }
    // The largest curated Bluetooth release has 706 blocks. Recording a
    // recovered CSW stall on all 709 commands, with a full native error buffer
    // expanded by JSON escaping, needs about 4.9 MB including its final receipt.
    // Main can report up to 51,500 positive one-byte writes; allow its larger
    // submission/result journal too, while keeping reads explicitly bounded.
    if metadata.len() > ATTEMPT_SIZE_LIMIT {
        return Err("Attempt record exceeds its size bound".into());
    }
    let mut bytes = Vec::new();
    file.take(ATTEMPT_SIZE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > ATTEMPT_SIZE_LIMIT {
        return Err("Attempt record exceeds its size bound".into());
    }
    Ok(bytes)
}

#[derive(Serialize)]
#[serde(tag = "event")]
enum SubmissionEvent {
    #[serde(rename = "command_submitted")]
    Command {
        index: usize,
        opcode: u8,
        qualified_lun: Option<u8>,
        lun_evidence: Option<gulikit_core::bot::MaxLun>,
        requested: usize,
    },
    #[serde(rename = "main_create_submitted")]
    MainDestination { index: usize },
    #[serde(rename = "main_write_submitted")]
    MainWrite { index: usize, requested: usize },
}

#[derive(Serialize)]
struct ResultEvent<'a> {
    event: &'a str,
    index: usize,
    actual: Option<serde_json::Value>,
    error: Option<&'a str>,
}

#[derive(Serialize)]
struct SubmissionResultEvent<'a> {
    event: &'a str,
    index: usize,
    actual: Option<serde_json::Value>,
    error: Option<&'a str>,
    may_have_been_submitted: bool,
    error_completion: Option<gulikit_core::update::SubmissionCompletion>,
    transport: Option<&'a gulikit_core::bot::CommandEvidence>,
}

pub struct Recorded<'a, P> {
    inner: P,
    journal: &'a mut File,
    index: usize,
    audit_failures: Vec<String>,
}
impl<'a, P> Recorded<'a, P> {
    pub fn new(inner: P, journal: &'a mut File) -> Self {
        Self {
            inner,
            journal,
            index: 0,
            audit_failures: Vec::new(),
        }
    }
    fn persist_event(&mut self, name: &str, value: &impl Serialize) -> Result<(), String> {
        let result = (|| {
            serde_json::to_writer(&mut *self.journal, value).map_err(|e| e.to_string())?;
            writeln!(self.journal).map_err(|e| e.to_string())?;
            self.journal.sync_all().map_err(|e| e.to_string())
        })();
        if let Err(error) = &result {
            self.audit_failures.push(format!(
                "Host audit failure while recording {name}: {error}"
            ));
        }
        result
    }
    fn record_cleanup(&mut self, result: Result<(), String>) -> Result<(), String> {
        let logged = self.record_result("cleanup_result", result, |()| json!(null));
        let mut failure = logged.err();
        for audit_error in &self.audit_failures {
            match &mut failure {
                Some(message) => {
                    message.push_str("; ");
                    message.push_str(audit_error);
                }
                None => failure = Some(audit_error.clone()),
            }
        }
        failure.map_or(Ok(()), Err)
    }
    fn record_submission_result<T>(
        &mut self,
        name: &str,
        result: Result<T, SubmissionError>,
        transport: Option<&gulikit_core::bot::CommandEvidence>,
        known_write_count: Option<usize>,
        actual: impl FnOnce(&T) -> serde_json::Value,
    ) -> Result<T, SubmissionError> {
        let logged = self.persist_event(
            name,
            &SubmissionResultEvent {
                event: name,
                index: self.index,
                actual: result.as_ref().ok().map(actual),
                error: result.as_ref().err().map(|error| error.message.as_str()),
                may_have_been_submitted: result
                    .as_ref()
                    .map_or_else(|error| error.may_have_been_submitted, |_| true),
                error_completion: result.as_ref().err().map(|error| error.completion),
                transport,
            },
        );
        self.index += 1;
        match (result, logged) {
            (Err(mut error), Err(log)) => {
                error.message.push_str("; audit failure: ");
                error.message.push_str(&log);
                error.audit_failure = true;
                Err(error)
            }
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(log)) => Err(SubmissionError {
                message: format!("Operation completed but audit failed: {log}"),
                may_have_been_submitted: true,
                audit_failure: true,
                completion: gulikit_core::update::SubmissionCompletion::Uncertain,
                known_write_count,
            }),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
    fn record_result<T>(
        &mut self,
        name: &str,
        result: Result<T, String>,
        actual: impl FnOnce(&T) -> serde_json::Value,
    ) -> Result<T, String> {
        let logged = self.persist_event(
            name,
            &ResultEvent {
                event: name,
                index: self.index,
                actual: result.as_ref().ok().map(actual),
                error: result.as_ref().err().map(String::as_str),
            },
        );
        self.index += 1;
        match (result, logged) {
            (Err(mut first), Err(log)) => {
                first.push_str("; audit failure: ");
                first.push_str(&log);
                Err(first)
            }
            (Err(first), _) => Err(first),
            (Ok(_), Err(log)) => Err(format!("Operation completed but audit failed: {log}")),
            (Ok(value), Ok(())) => Ok(value),
        }
    }
}
impl<P: BluetoothPort> BluetoothPort for Recorded<'_, P> {
    fn lun_evidence(&self) -> Option<gulikit_core::bot::MaxLun> {
        self.inner.lun_evidence()
    }
    fn qualified_lun(&self) -> Option<u8> {
        self.inner.qualified_lun()
    }
    fn prepare_write(&mut self) -> Result<(), String> {
        self.inner.prepare_write()
    }
    fn check_session(&mut self) -> Result<(), String> {
        self.inner.check_session()
    }
    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, SubmissionError> {
        self.persist_event(
            "command_submitted",
            &SubmissionEvent::Command {
                index: self.index,
                opcode,
                qualified_lun: self.inner.qualified_lun(),
                lun_evidence: self.inner.lun_evidence(),
                requested: if opcode == 0xf0 { data.len() } else { 20 },
            },
        )
        .map_err(SubmissionError::audit_before)?;
        let result = self.inner.command(opcode, data);
        let transport = self.inner.take_transport_evidence();
        self.record_submission_result("command_result",result,transport.as_ref(),None,|bytes|json!({"response":bytes,"firmware_bytes_confirmed":if opcode==0xf0{data.len()}else{0}}))
    }
    fn completion_detached(&mut self) -> Result<bool, String> {
        let result = self.inner.completion_detached();
        self.record_result("bluetooth_completion_detach", result, |value| json!(value))
    }
    fn finish(&mut self) -> Result<(), String> {
        let result = self.inner.finish();
        self.record_cleanup(result)
    }
}
impl<P: MainPort> MainPort for Recorded<'_, P> {
    fn prepare_write(&mut self) -> Result<(), String> {
        self.inner.prepare_write()
    }
    fn check_session(&mut self) -> Result<(), String> {
        self.inner.check_session()
    }
    fn read_version(&mut self) -> Result<Vec<u8>, String> {
        let result = self.inner.read_version();
        self.record_result("main_version", result, |bytes| json!(bytes))
    }
    fn create_destination(&mut self, member: &str) -> Result<(), DestinationCreationError> {
        self.persist_event(
            "main_create_submitted",
            &SubmissionEvent::MainDestination { index: self.index },
        )?;
        let result = self.inner.create_destination(member);
        let created = result
            .as_ref()
            .map_or_else(|error| error.created, |()| true);
        self.record_result(
            "main_create_result",
            result.map_err(|error| error.error),
            |()| json!({"created":true}),
        )
        .map_err(|error| DestinationCreationError { error, created })
    }
    fn write(&mut self, bytes: &[u8]) -> Result<usize, SubmissionError> {
        self.persist_event(
            "main_write_submitted",
            &SubmissionEvent::MainWrite {
                index: self.index,
                requested: bytes.len(),
            },
        )
        .map_err(SubmissionError::audit_before)?;
        let result = self.inner.write(bytes);
        let known_count = result.as_ref().ok().copied();
        self.record_submission_result("main_write_result", result, None, known_count, |count| {
            json!(count)
        })
    }
    fn flush(&mut self) -> Result<(), String> {
        let result = self.inner.flush();
        self.record_result("main_flush_result", result, |()| json!(null))
    }
    fn close(&mut self) -> Result<(), String> {
        let result = self.inner.close();
        self.record_result("main_close_result", result, |()| json!(null))
    }
    fn volume_flush(&mut self) -> Result<(), String> {
        let result = self.inner.volume_flush();
        self.record_result("volume_durability",result,|()|json!("No separate qualified volume-flush API; sync_all on open file and checked close are recorded separately"))
    }
    fn wait_for_completion(&mut self, cancelled: &mut dyn FnMut() -> bool) -> Result<bool, String> {
        let result = self.inner.wait_for_completion(cancelled);
        self.record_result("main_completion_indication", result, |value| json!(value))
    }
    fn finish(&mut self) -> Result<(), String> {
        let result = self.inner.finish();
        self.record_cleanup(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gulikit_core::update::BluetoothPort;
    struct Fake {
        path: std::path::PathBuf,
        finished: bool,
        called: bool,
    }
    impl BluetoothPort for Fake {
        fn prepare_write(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn check_session(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn command(&mut self, opcode: u8, _: &[u8]) -> Result<Vec<u8>, SubmissionError> {
            self.called = true;
            let log = std::fs::read_to_string(&self.path).unwrap();
            let event: serde_json::Value =
                serde_json::from_str(log.lines().last().unwrap()).unwrap();
            assert_eq!(event["event"], "command_submitted");
            assert_eq!(event["opcode"], opcode);
            Err("transport failure with raw bytes".into())
        }
        fn finish(&mut self) -> Result<(), String> {
            self.finished = true;
            Ok(())
        }
    }
    #[test]
    fn failed_submission_audit_never_calls_transport_and_retains_known_zero_submission() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut readonly = File::open(file.path()).unwrap();
        let mut port = Recorded::new(
            Fake {
                path: file.path().into(),
                finished: false,
                called: false,
            },
            &mut readonly,
        );
        let error = port.command(0xf0, &[0; 512]).unwrap_err();
        assert!(!error.may_have_been_submitted);
        assert!(error.audit_failure);
        assert!(!port.inner.called);
        assert!(port.finish().is_err());
        assert!(port.inner.finished);
    }
    #[test]
    fn result_audit_failure_preserves_the_underlying_submission_disposition() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut readonly = File::open(file.path()).unwrap();
        let mut port = Recorded::new((), &mut readonly);
        for (result, expected) in [
            (Err(SubmissionError::before("refused")), false),
            (Err(SubmissionError::from("uncertain")), true),
            (Ok(7usize), true),
        ] {
            let known_count = result.as_ref().ok().copied();
            let error = port
                .record_submission_result("result", result, None, known_count, |count| json!(count))
                .unwrap_err();
            assert_eq!(error.may_have_been_submitted, expected);
            assert_eq!(error.known_write_count, known_count);
            assert!(error.audit_failure);
        }
    }
    #[test]
    fn missing_status_disposition_survives_recording_but_an_audit_error_stays_visible() {
        use gulikit_core::update::SubmissionCompletion;
        let file = tempfile::NamedTempFile::new().unwrap();
        for writable in [true, false] {
            let mut journal = if writable {
                file.reopen().unwrap()
            } else {
                File::open(file.path()).unwrap()
            };
            let mut port = Recorded::new((), &mut journal);
            let failure = SubmissionError {
                completion: SubmissionCompletion::DataSentStatusMissing,
                ..SubmissionError::from("last F0 status lost")
            };
            let error = port
                .record_submission_result::<Vec<u8>>(
                    "command_result",
                    Err(failure),
                    None,
                    None,
                    |_| json!(null),
                )
                .unwrap_err();
            assert_eq!(
                error.completion,
                SubmissionCompletion::DataSentStatusMissing
            );
            assert_eq!(error.audit_failure, !writable);
            if writable {
                let saved: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
                assert_eq!(saved["error_completion"], "data_sent_status_missing");
            }
        }
    }

    struct MainReadFake {
        finished: bool,
        member: Option<String>,
    }
    impl MainPort for MainReadFake {
        fn prepare_write(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn check_session(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn read_version(&mut self) -> Result<Vec<u8>, String> {
            Ok(b"version 5.8".to_vec())
        }
        fn create_destination(&mut self, member: &str) -> Result<(), DestinationCreationError> {
            self.member = Some(member.to_owned());
            Ok(())
        }
        fn write(&mut self, _: &[u8]) -> Result<usize, SubmissionError> {
            Ok(7)
        }
        fn flush(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn volume_flush(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn wait_for_completion(&mut self, _: &mut dyn FnMut() -> bool) -> Result<bool, String> {
            Ok(true)
        }
        fn finish(&mut self) -> Result<(), String> {
            self.finished = true;
            Ok(())
        }
    }
    #[test]
    fn main_submission_records_preserve_creation_and_actual_short_write_fields() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = file.reopen().unwrap();
        let mut port = Recorded::new(
            MainReadFake {
                finished: false,
                member: None,
            },
            &mut journal,
        );
        port.create_destination("GuliKit_NS39_V3.1.bin").unwrap();
        assert_eq!(port.inner.member.as_deref(), Some("GuliKit_NS39_V3.1.bin"));
        assert_eq!(port.write(&[0; 8]).unwrap(), 7);
        let events: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            events,
            vec![
                json!({"event":"main_create_submitted", "index":0}),
                json!({"event":"main_create_result", "index":0, "actual":{"created":true}, "error":null}),
                json!({"event":"main_write_submitted", "index":1, "requested":8}),
                json!({"event":"main_write_result", "index":1, "actual":7, "error":null,
                "error_completion":null, "may_have_been_submitted":true, "transport":null}),
            ]
        );
    }

    #[test]
    fn a_transient_read_result_audit_failure_remains_cleanup_attention() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut readonly = File::open(file.path()).unwrap();
        let mut writable = file.reopen().unwrap();
        let mut port = Recorded::new(
            MainReadFake {
                finished: false,
                member: None,
            },
            &mut readonly,
        );
        assert!(port.read_version().unwrap_err().contains("audit failed"));
        port.journal = &mut writable;
        let error = MainPort::finish(&mut port).unwrap_err();
        assert!(error.contains("Host audit failure"), "{error}");
        assert!(port.inner.finished);
    }

    #[test]
    fn submission_record_retains_raw_transport_evidence_and_nullable_fields() {
        use gulikit_core::bot::{CommandEvidence, StallClear, TransferError, TransferFailureKind};
        use gulikit_core::update::SubmissionCompletion;
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = file.reopen().unwrap();
        let mut port = Recorded::new((), &mut journal);
        let transport = CommandEvidence {
            tag: 3,
            opcode: 0xf2,
            requested: 20,
            cbw_actual: Some(31),
            cbw_error: None,
            data_actual: Some(1),
            data_in: Some(vec![0]),
            csw_reads: 2,
            csw_raw: vec![85, 83, 66, 83, 3, 0, 0, 0, 0, 0, 0, 0, 0],
            csw_actual: Some(13),
            csw_errors: vec![TransferError {
                kind: TransferFailureKind::Stall,
                actual: 0,
                raw: vec![0, 255],
                message: "native \"stall\"\n".into(),
            }],
            stall_clear: Some(StallClear::Passed),
            stall_clear_elapsed: Some(std::time::Duration::from_millis(7)),
            f2_zero_residue_quirk: true,
        };
        let expected_transport = serde_json::to_value(&transport).unwrap();
        assert_eq!(
            port.record_submission_result(
                "command_result",
                Ok(20usize),
                Some(&transport),
                None,
                |count| json!(count),
            )
            .unwrap(),
            20,
        );
        let failure = SubmissionError {
            completion: SubmissionCompletion::DataSentStatusMissing,
            ..SubmissionError::from("status \"missing\"\n")
        };
        assert!(
            port.record_submission_result::<usize>(
                "command_result",
                Err(failure),
                None,
                None,
                |count| json!(count),
            )
            .is_err()
        );
        let saved: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            saved,
            vec![
                json!({
                    "event":"command_result", "index":0, "actual":20,
                    "error":null, "may_have_been_submitted":true,
                    "error_completion":null, "transport":expected_transport,
                }),
                json!({
                    "event":"command_result", "index":1, "actual":null,
                    "error":"status \"missing\"\n", "may_have_been_submitted":true,
                    "error_completion":"data_sent_status_missing", "transport":null,
                }),
            ]
        );
    }

    #[test]
    fn command_submission_is_persisted_before_transport_and_error_is_retained() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_owned();
        let mut journal = file.reopen().unwrap();
        let mut port = Recorded::new(
            Fake {
                path: path.clone(),
                finished: false,
                called: false,
            },
            &mut journal,
        );
        assert!(
            port.command(0xf1, &[])
                .unwrap_err()
                .message
                .contains("transport failure")
        );
        port.finish().unwrap();
        assert!(port.inner.finished);
        let events: Vec<serde_json::Value> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            events[0],
            json!({
                "event":"command_submitted", "index":0, "opcode":0xf1,
                "qualified_lun":null, "lun_evidence":null, "requested":20,
            })
        );
        assert_eq!(events[1]["event"], "command_result");
        assert_eq!(events[1]["error"], "transport failure with raw bytes");
        assert_eq!(events[2]["event"], "cleanup_result");
    }
}

/// Write and sync one JSON-line event, returning any serialization, write or sync error.
///
/// # Errors
///
/// Returns an error if JSON encoding, writing the complete line, or syncing the journal fails.
pub fn write_event(journal: &mut File, value: &serde_json::Value) -> Result<(), String> {
    serde_json::to_writer(&mut *journal, value).map_err(|e| e.to_string())?;
    writeln!(journal).map_err(|e| e.to_string())?;
    journal.sync_all().map_err(|e| e.to_string())
}

/// The authenticated desktop user's UID that may read a finalized host record.
///
/// Instances are created from the UID argument appended by the administrator-
/// authenticated desktop launcher. A zero UID is never a receipt owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptOwner(u32);

impl ReceiptOwner {
    /// Validate a UID supplied by the administrator-authenticated launcher.
    ///
    /// # Errors
    /// Rejects reserved UID values that cannot identify a receipt owner.
    pub fn from_authenticated_launcher_uid(uid: u32) -> Result<Self, String> {
        if uid == 0 || uid == u32::MAX {
            return Err("Receipt owner UID must be a valid non-root user".into());
        }
        Ok(Self(uid))
    }

    /// Return the validated Unix user ID.
    #[must_use]
    pub const fn uid(self) -> u32 {
        self.0
    }

    /// Resolve the invoking user's home directory for desktop file pickers.
    ///
    /// # Errors
    /// Returns an error if the account is unavailable or its home is not absolute.
    #[cfg(unix)]
    pub fn home_directory(self) -> Result<std::path::PathBuf, String> {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(self.uid()))
            .map_err(|error| {
                format!("Could not resolve the desktop user's home directory: {error}")
            })?
            .ok_or("Could not resolve the desktop user's home directory")?;
        if !user.dir.is_absolute() {
            return Err("The desktop user's home directory is not absolute".into());
        }
        if !user.dir.is_dir() {
            return Err("The desktop user's home directory is unavailable".into());
        }
        Ok(user.dir)
    }
}

pub fn finalize_record(journal: &mut File, value: serde_json::Value) -> serde_json::Value {
    finalize_record_with_sync(journal, value, File::sync_all)
}
fn finalize_record_with_sync(
    journal: &mut File,
    mut value: serde_json::Value,
    mut sync: impl FnMut(&File) -> std::io::Result<()>,
) -> serde_json::Value {
    value["record_finalized"] = false.into();
    let persisted = (|| -> Result<(), String> {
        serde_json::to_writer(&mut *journal, &value).map_err(|error| error.to_string())?;
        writeln!(journal).map_err(|error| error.to_string())?;
        sync(journal).map_err(|error| error.to_string())?;
        // Write the acknowledgement only after syncing the result. Writing it
        // earlier could make an unsynced result appear complete. If it is lost,
        // verification must refuse the unacknowledged result.
        let acknowledgement = json!({
            "event":"record_finalized", "schema_version":1,
            "result_event":value["event"],
        });
        serde_json::to_writer(&mut *journal, &acknowledgement)
            .map_err(|error| error.to_string())?;
        writeln!(journal).map_err(|error| error.to_string())?;
        sync(journal).map_err(|error| error.to_string())
    })();
    if let Err(error) = persisted {
        // Outcome remains a statement about the device observation. Persistence
        // failure separately makes this result require attention (CLI exit8).
        let transfer = value["transfer"]
            .as_object_mut()
            .expect("typed transfer object");
        transfer
            .entry("cleanup_errors")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("typed cleanup array")
            .push(json!(format!(
                "Host record could not be finalized: {error}"
            )));
    } else {
        value["record_finalized"] = true.into();
    }
    value
}

/// Finalize a host record, then make the completed receipt readable by its
/// authenticated desktop user without granting write access.
///
/// The result and finalization acknowledgement are synced while the record is
/// still root-owned. Ownership changes are applied to the already-open record
/// descriptor, never to a pathname.
///
/// # Panics
/// Panics if `value` is not a shared updater transfer result with a
/// `transfer.cleanup_errors` array.
#[cfg(unix)]
pub fn finalize_record_for_owner(
    journal: &mut File,
    value: serde_json::Value,
    owner: ReceiptOwner,
) -> serde_json::Value {
    let mut result = finalize_record(journal, value);
    if !result["record_finalized"].as_bool().unwrap_or(false) {
        return result;
    }

    if let Err(error) = handoff_finalized_record(journal, owner) {
        result["transfer"]["cleanup_errors"]
            .as_array_mut()
            .expect("typed cleanup array")
            .push(json!(format!(
                "Finalized host record could not be handed to the desktop user: {error}"
            )));
    }
    result
}

#[cfg(unix)]
fn handoff_finalized_record(journal: &File, owner: ReceiptOwner) -> Result<(), String> {
    use nix::{
        sys::stat::{Mode, fchmod},
        unistd::{Uid, fchown},
    };

    if nix::unistd::geteuid().as_raw() != 0 {
        return Err("record ownership transfer requires an elevated process".into());
    }

    handoff_finalized_record_with(journal, owner, |journal, action| match action {
        HandoffAction::SetMode(mode) => {
            fchmod(journal, Mode::from_bits_truncate(mode)).map_err(|error| error.to_string())
        }
        HandoffAction::SetOwner(uid) => {
            fchown(journal, Some(Uid::from_raw(uid)), None).map_err(|error| error.to_string())
        }
        HandoffAction::Sync => journal.sync_all().map_err(|error| error.to_string()),
    })
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandoffAction {
    SetMode(nix::libc::mode_t),
    SetOwner(u32),
    Sync,
}

#[cfg(unix)]
fn handoff_finalized_record_with(
    journal: &File,
    owner: ReceiptOwner,
    mut apply: impl FnMut(&File, HandoffAction) -> Result<(), String>,
) -> Result<(), String> {
    // Keep the file inaccessible while its owner changes, then expose a
    // read-only completed receipt. The open root descriptor remains usable.
    apply(journal, HandoffAction::SetMode(0))?;
    if let Err(error) = apply(journal, HandoffAction::SetOwner(owner.uid())) {
        return match apply(journal, HandoffAction::SetMode(0o600)) {
            Ok(()) => Err(error),
            Err(restore_error) => Err(format!(
                "ownership change failed ({error}); restoring root-private permissions failed ({restore_error})"
            )),
        };
    }
    if let Err(error) = apply(journal, HandoffAction::SetMode(0o400)) {
        // The recipient has no permission bits yet. Restore root ownership and
        // private access if possible, but retain the original failure even
        // when rollback succeeds.
        if let Err(owner_error) = apply(journal, HandoffAction::SetOwner(0)) {
            return Err(format!(
                "read-only permission change failed ({error}); restoring root ownership failed ({owner_error}); the record remains inaccessible"
            ));
        }
        return match apply(journal, HandoffAction::SetMode(0o600)) {
            Ok(()) => Err(format!(
                "read-only permission change failed ({error}); root-private permissions were restored"
            )),
            Err(restore_error) => Err(format!(
                "read-only permission change failed ({error}); restoring root-private permissions failed ({restore_error})"
            )),
        };
    }
    apply(journal, HandoffAction::Sync)
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    #[test]
    fn failed_result_sync_never_leaves_a_finalized_record_on_reopen() {
        let input = json!({
            "event":"attempt_result", "schema_version":1,
            "transfer":{"outcome":"transfer_completed_awaiting_verification", "cleanup_errors":[]}
        });
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = file.reopen().unwrap();
        let result = finalize_record_with_sync(&mut journal, input, |_| {
            Err(std::io::Error::other("injected result sync failure"))
        });
        assert_eq!(result["record_finalized"], false);
        assert_eq!(
            result["transfer"]["outcome"],
            "transfer_completed_awaiting_verification"
        );
        assert!(
            result["transfer"]["cleanup_errors"][0]
                .as_str()
                .unwrap()
                .contains("injected result sync failure")
        );
        let reopened: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0]["record_finalized"], false);
        assert_eq!(reopened[0]["event"], "attempt_result");
    }

    #[test]
    fn finalization_acknowledgement_follows_the_result_sync() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut journal = file.reopen().unwrap();
        let input = json!({
            "event":"attempt_result", "schema_version":1,
            "transfer":{"outcome":"outcome_unknown", "cleanup_errors":[]}
        });
        let mut sync_count = 0;
        let result = finalize_record_with_sync(&mut journal, input, |journal| {
            sync_count += 1;
            let saved: Vec<serde_json::Value> = std::fs::read_to_string(file.path())?
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            match sync_count {
                1 => {
                    assert_eq!(saved.len(), 1);
                    assert_eq!(saved[0]["record_finalized"], false);
                    assert_eq!(saved[0]["event"], "attempt_result");
                }
                2 => assert_eq!(saved.len(), 2),
                _ => panic!("unexpected extra sync"),
            }
            journal.sync_all()
        });
        assert_eq!(sync_count, 2);
        assert_eq!(result["record_finalized"], true);
        assert_eq!(result["transfer"]["outcome"], "outcome_unknown");
        let saved = std::fs::read_to_string(file.path()).unwrap();
        assert!(saved.ends_with('\n'));
        let events: Vec<serde_json::Value> = saved
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["record_finalized"], false);
        assert_eq!(
            events[1],
            json!({
                "event":"record_finalized", "schema_version":1,
                "result_event":"attempt_result",
            })
        );
    }

    #[test]
    fn receipt_owner_rejects_root_and_retains_validated_uid() {
        assert!(ReceiptOwner::from_authenticated_launcher_uid(0).is_err());
        assert!(ReceiptOwner::from_authenticated_launcher_uid(u32::MAX).is_err());
        assert_eq!(
            ReceiptOwner::from_authenticated_launcher_uid(501)
                .unwrap()
                .uid(),
            501
        );
    }

    #[test]
    fn fresh_verification_is_durable_and_failed_persistence_requires_attention() {
        let input = json!({
            "event":"verification_result", "schema_version":1,
            "record_finalized":true,
            "source_attempt":"attempt.jsonl",
            "raw_version_bytes":[118,53,57],
            "verification":{"generation":12,"previous_generation":11,"same_unit_confirmed":true,"model_confirmed":true,"version":"5.9"},
            "transfer":{"outcome":"installed_verified","cleanup_errors":[]}
        });
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let mut journal = temporary.reopen().unwrap();
        let result = finalize_record(&mut journal, input.clone());
        assert_eq!(result, input);
        let saved = std::fs::read_to_string(temporary.path()).unwrap();
        assert!(saved.ends_with('\n'));
        let saved: Vec<serde_json::Value> = saved
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let mut pending = input.clone();
        pending["record_finalized"] = false.into();
        assert_eq!(
            saved,
            vec![
                pending,
                json!({
                    "event":"record_finalized", "schema_version":1,
                    "result_event":"verification_result",
                })
            ]
        );
        let mut readonly = File::open(temporary.path()).unwrap();
        let failed = finalize_record(&mut readonly, input);
        assert_eq!(failed["record_finalized"], false);
        assert_eq!(failed["transfer"]["outcome"], "installed_verified");
        assert_ne!(
            failed["transfer"]["cleanup_errors"]
                .as_array()
                .unwrap()
                .as_slice(),
            [] as [serde_json::Value; 0]
        );
        let reopened: Vec<serde_json::Value> = std::fs::read_to_string(temporary.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(reopened, saved);
    }
}

/// Create one exclusive host record and durably publish its directory entry.
#[cfg(unix)]
///
/// # Errors
///
/// Returns an error if the host directory cannot be opened safely, resides on excluded device storage, or record creation and directory syncing fail.
pub fn create_host_record(
    path: &std::path::Path,
    excluded_devices: &[u64],
) -> Result<File, String> {
    use nix::{
        fcntl::{OFlag, open},
        sys::stat::Mode,
    };
    use std::os::unix::fs::MetadataExt;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let name = path
        .file_name()
        .ok_or("Attempt record requires a filename")?;
    let directory = File::from(
        open(
            parent,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    if excluded_devices.contains(&directory.metadata().map_err(|e| e.to_string())?.dev()) {
        return Err(
            "Attempt records must be stored on the host, outside the controller volume".into(),
        );
    }
    create_in_directory(&directory, name, File::sync_all)
}
#[cfg(unix)]
fn create_in_directory(
    directory: &File,
    name: &std::ffi::OsStr,
    sync_parent: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<File, String> {
    use nix::{
        fcntl::{OFlag, openat},
        sys::stat::Mode,
    };
    let file = File::from(
        openat(
            directory,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| e.to_string())?,
    );
    sync_parent(directory)
        .map_err(|error| format!("Host record directory entry could not be persisted: {error}"))?;
    Ok(file)
}
#[cfg(all(test, unix))]
mod creation_tests {
    use super::*;
    #[test]
    fn parent_entry_is_synced_before_record_is_returned_and_sync_failure_refuses_it() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let name = std::ffi::OsStr::new("attempt.jsonl");
        let mut synced = false;
        let file = create_in_directory(&directory, name, |parent| {
            assert!(temporary.path().join(name).is_file());
            synced = true;
            parent.sync_all()
        })
        .unwrap();
        assert!(synced);
        drop(file);
        let failed = create_in_directory(&directory, std::ffi::OsStr::new("failed.jsonl"), |_| {
            Err(std::io::Error::other("directory sync failed"))
        });
        assert!(failed.unwrap_err().contains("directory sync failed"));
        assert!(temporary.path().join("failed.jsonl").is_file());
        assert!(create_host_record(&temporary.path().join(name), &[]).is_err());
    }
}

#[cfg(all(test, unix))]
mod ownership_tests {
    use super::*;

    fn result() -> serde_json::Value {
        json!({
            "event":"attempt_result", "schema_version":1,
            "transfer":{"outcome":"outcome_unknown", "cleanup_errors":[]}
        })
    }

    #[test]
    #[ignore = "requires an elevated host-file-only test process"]
    fn owner_handoff_changes_only_the_open_record_after_its_ack_is_synced() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        assert_eq!(nix::unistd::geteuid().as_raw(), 0);
        let owner_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|uid| uid.parse::<u32>().ok())
            .filter(|uid| *uid != 0 && *uid != u32::MAX)
            .unwrap_or_else(|| nix::unistd::getuid().as_raw());
        assert_ne!(owner_uid, 0);

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("attempt.jsonl");
        let mut record = create_host_record(&path, &[]).unwrap();
        let record_inode = record.metadata().unwrap().ino();
        let replacement = temporary.path().join("replacement.jsonl");
        std::fs::write(&replacement, b"replacement\n").unwrap();
        std::fs::rename(&path, temporary.path().join("moved.jsonl")).unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let finalized = finalize_record_for_owner(
            &mut record,
            result(),
            ReceiptOwner::from_authenticated_launcher_uid(owner_uid).unwrap(),
        );

        assert_eq!(finalized["record_finalized"], true);
        assert_eq!(
            finalized["transfer"]["cleanup_errors"],
            serde_json::json!([])
        );
        let moved = std::fs::metadata(temporary.path().join("moved.jsonl")).unwrap();
        assert_eq!(moved.ino(), record_inode);
        assert_eq!(moved.uid(), owner_uid);
        assert_eq!(moved.permissions().mode() & 0o777, 0o400);
        let replacement = std::fs::metadata(&path).unwrap();
        assert_ne!(replacement.ino(), record_inode);
        assert_eq!(replacement.uid(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement\n");
        let events = std::fs::read_to_string(temporary.path().join("moved.jsonl")).unwrap();
        assert_eq!(events.lines().count(), 2);
        assert!(events.contains("\"event\":\"record_finalized\""));
    }

    #[test]
    fn owner_handoff_failure_preserves_the_durable_root_owned_record() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        assert_ne!(nix::unistd::geteuid().as_raw(), 0);
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("attempt.jsonl");
        let mut record = create_host_record(&path, &[]).unwrap();
        let uid = nix::unistd::getuid().as_raw().saturating_add(1);
        let finalized = finalize_record_for_owner(
            &mut record,
            result(),
            ReceiptOwner::from_authenticated_launcher_uid(uid).unwrap(),
        );

        assert_eq!(finalized["record_finalized"], true);
        assert_eq!(
            finalized["transfer"]["cleanup_errors"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.uid(), nix::unistd::getuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(temporary.path().join("attempt.jsonl"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[test]
    fn ordinary_finalization_keeps_the_existing_owner_and_private_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("attempt.jsonl");
        let mut record = create_host_record(&path, &[]).unwrap();
        let original_owner = record.metadata().unwrap().uid();

        let finalized = finalize_record(&mut record, result());

        assert_eq!(finalized["record_finalized"], true);
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(metadata.uid(), original_owner);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn successful_permission_rollback_still_reports_handoff_failure() {
        let file = tempfile::tempfile().unwrap();
        let owner = ReceiptOwner::from_authenticated_launcher_uid(501).unwrap();
        let mut actions = Vec::new();

        let error = handoff_finalized_record_with(&file, owner, |_, action| {
            actions.push(action);
            match action {
                HandoffAction::SetMode(0o400) => Err("injected read-only mode failure".into()),
                _ => Ok(()),
            }
        })
        .unwrap_err();

        assert!(error.contains("injected read-only mode failure"));
        assert!(error.contains("root-private permissions were restored"));
        assert_eq!(
            actions,
            [
                HandoffAction::SetMode(0),
                HandoffAction::SetOwner(501),
                HandoffAction::SetMode(0o400),
                HandoffAction::SetOwner(0),
                HandoffAction::SetMode(0o600),
            ]
        );
    }
}
