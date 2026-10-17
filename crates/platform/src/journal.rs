//! Durable host-side operation records around the same ports used by the updater.

use gulikit_core::update::{BluetoothPort, DestinationCreationError, MainPort};
use serde_json::json;
use std::{fs::File, io::Write};

/// Open the attempt itself without following a symlink or waiting for a FIFO writer.
#[cfg(unix)]
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
    const LIMIT: u64 = 1_048_576;
    if metadata.len() > LIMIT {
        return Err("Attempt record exceeds its size bound".into());
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("Attempt record exceeds its size bound".into());
    }
    Ok(bytes)
}

pub struct Recorded<'a, P> {
    inner: P,
    journal: &'a mut File,
    index: usize,
}
impl<'a, P> Recorded<'a, P> {
    pub fn new(inner: P, journal: &'a mut File) -> Self {
        Self {
            inner,
            journal,
            index: 0,
        }
    }
    fn event(&mut self, value: serde_json::Value) -> Result<(), String> {
        serde_json::to_writer(&mut *self.journal, &value).map_err(|e| e.to_string())?;
        writeln!(self.journal).map_err(|e| e.to_string())?;
        self.journal.sync_all().map_err(|e| e.to_string())
    }
    fn result<T>(
        &mut self,
        name: &str,
        result: Result<T, String>,
        actual: impl FnOnce(&T) -> serde_json::Value,
    ) -> Result<T, String> {
        let logged=self.event(json!({"event":name,"index":self.index,"actual":result.as_ref().ok().map(actual),"error":result.as_ref().err()}));
        self.index += 1;
        match (result, logged) {
            (Err(first), Err(log)) => Err(format!("{first}; audit failure: {log}")),
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
    fn command(&mut self, opcode: u8, data: &[u8]) -> Result<Vec<u8>, String> {
        self.event(json!({"event":"command_submitted","index":self.index,"opcode":opcode,"qualified_lun":self.inner.qualified_lun(),"lun_evidence":self.inner.lun_evidence(),"requested":if opcode==0xf0{data.len()}else{20}}))?;
        let result = self.inner.command(opcode, data);
        self.result("command_result",result,|bytes|json!({"response":bytes,"firmware_bytes_confirmed":if opcode==0xf0{data.len()}else{0}}))
    }
    fn finish(&mut self) -> Result<(), String> {
        let result = self.inner.finish();
        self.result("cleanup_result", result, |_| json!(null))
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
        self.result("main_version", result, |bytes| json!(bytes))
    }
    fn create_destination(&mut self) -> Result<(), DestinationCreationError> {
        self.event(json!({"event":"main_create_submitted","index":self.index}))?;
        let result = self.inner.create_destination();
        let created = result.as_ref().map_or_else(|error| error.created, |_| true);
        self.result(
            "main_create_result",
            result.map_err(|error| error.error),
            |_| json!({"created":true}),
        )
        .map_err(|error| DestinationCreationError { error, created })
    }
    fn write(&mut self, bytes: &[u8]) -> Result<usize, String> {
        self.event(
            json!({"event":"main_write_submitted","index":self.index,"requested":bytes.len()}),
        )?;
        let result = self.inner.write(bytes);
        self.result("main_write_result", result, |count| json!(count))
    }
    fn flush(&mut self) -> Result<(), String> {
        let result = self.inner.flush();
        self.result("main_flush_result", result, |_| json!(null))
    }
    fn close(&mut self) -> Result<(), String> {
        let result = self.inner.close();
        self.result("main_close_result", result, |_| json!(null))
    }
    fn volume_flush(&mut self) -> Result<(), String> {
        let result = self.inner.volume_flush();
        self.result("volume_durability",result,|_|json!("No separate qualified volume-flush API; sync_all on open file and checked close are recorded separately"))
    }
    fn wait_for_completion(&mut self, cancelled: &mut dyn FnMut() -> bool) -> Result<bool, String> {
        let result = self.inner.wait_for_completion(cancelled);
        self.result("main_completion_indication", result, |value| json!(value))
    }
    fn finish(&mut self) -> Result<(), String> {
        let result = self.inner.finish();
        self.result("cleanup_result", result, |_| json!(null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gulikit_core::update::BluetoothPort;
    struct Fake {
        path: std::path::PathBuf,
        finished: bool,
    }
    impl BluetoothPort for Fake {
        fn prepare_write(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn check_session(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn command(&mut self, opcode: u8, _: &[u8]) -> Result<Vec<u8>, String> {
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
    fn command_submission_is_persisted_before_transport_and_error_is_retained() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let path = file.path().to_owned();
        let mut journal = file.reopen().unwrap();
        let mut port = Recorded::new(
            Fake {
                path: path.clone(),
                finished: false,
            },
            &mut journal,
        );
        assert!(
            port.command(0xf1, &[])
                .unwrap_err()
                .contains("transport failure")
        );
        port.finish().unwrap();
        assert!(port.inner.finished);
        let events: Vec<serde_json::Value> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events[1]["event"], "command_result");
        assert_eq!(events[1]["error"], "transport failure with raw bytes");
        assert_eq!(events[2]["event"], "cleanup_result");
    }
}

/// Complete an outcome record without hiding persistence failure from its caller.
pub fn write_event(journal: &mut File, value: &serde_json::Value) -> Result<(), String> {
    serde_json::to_writer(&mut *journal, value).map_err(|e| e.to_string())?;
    writeln!(journal).map_err(|e| e.to_string())?;
    journal.sync_all().map_err(|e| e.to_string())
}
pub fn finalize_record(journal: &mut File, mut value: serde_json::Value) -> serde_json::Value {
    if let Err(error) = write_event(journal, &value) {
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
    }
    value
}

#[cfg(test)]
mod verification_tests {
    use super::*;
    #[test]
    fn fresh_verification_is_durable_and_failed_persistence_requires_attention() {
        let input = json!({
            "event":"verification_result", "schema_version":1,
            "source_attempt":"attempt.jsonl",
            "raw_version_bytes":[118,53,57],
            "verification":{"generation":12,"previous_generation":11,"same_unit_confirmed":true,"model_confirmed":true,"version":"5.9"},
            "transfer":{"outcome":"installed_verified","cleanup_errors":[]}
        });
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let mut journal = temporary.reopen().unwrap();
        let result = finalize_record(&mut journal, input.clone());
        assert_eq!(result, input);
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temporary.path()).unwrap()).unwrap();
        assert_eq!(saved, input);
        let mut readonly = File::open(temporary.path()).unwrap();
        let failed = finalize_record(&mut readonly, input.clone());
        assert_eq!(failed["transfer"]["outcome"], "installed_verified");
        assert!(
            !failed["transfer"]["cleanup_errors"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(temporary.path()).unwrap())
                .unwrap(),
            input
        );
    }
}

/// Create one exclusive host record and durably publish its directory entry.
#[cfg(unix)]
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
        .unwrap_or(std::path::Path::new("."));
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
