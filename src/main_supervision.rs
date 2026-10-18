//! The Main worker owns synchronous volume/journal calls; the guardian owns its lease.
use super::{AppError, Command};
use gulikit_catalog::Catalog;
use gulikit_core::package::Component;
use gulikit_platform::{
    lock::ProcessLock,
    main_worker::{Channel, Message},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    os::unix::ffi::{OsStrExt, OsStringExt},
    process::{Command as ProcessCommand, ExitCode},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct Request {
    archive: Vec<u8>,
    record: Vec<u8>,
    catalog: Option<Vec<u8>>,
    model: String,
    allow_downgrade: bool,
    confirm_ns39: bool,
}
fn subprocess(argument: &str) -> Result<ProcessCommand, AppError> {
    let mut command =
        ProcessCommand::new(std::env::current_exe().map_err(|error| error.to_string())?);
    command.arg(argument);
    Ok(command)
}
pub fn update(command: Command, catalog: Option<Vec<u8>>) -> Result<Value, AppError> {
    let Command::Update {
        path,
        record,
        model,
        allow_downgrade,
        confirm_ns39,
        ..
    } = command
    else {
        return Err("Main update request required".into());
    };
    let request = Request {
        archive: path.as_os_str().as_bytes().to_vec(),
        record: record.as_os_str().as_bytes().to_vec(),
        catalog,
        model: model.to_string(),
        allow_downgrade,
        confirm_ns39,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
        .map_err(|error| error.to_string())?;
    let response = gulikit_platform::main_worker::run(
        subprocess("__main-guardian")?,
        serde_json::to_value(request).map_err(|error| error.to_string())?,
        Duration::from_secs(185),
        || cancelled.load(Ordering::SeqCst),
    )?;
    match response {
        Message::Result(value) => Ok(value),
        Message::Failed {
            kind,
            code,
            message,
        } => Err(AppError {
            kind: child_error_kind(&kind),
            code,
            message,
            cleanup_errors: Vec::new(),
        }),
        Message::Unknown {
            reason,
            worker_stopped,
        } => Ok(
            json!({"event":"attempt_supervision_result","schema_version":1,"component":"main","transfer":{"outcome":"outcome_unknown","error":reason,"cleanup_errors":["Consult the worker's durable host record. No retry, deletion or recovery was attempted."]},"supervision":{"worker_stopped":worker_stopped,"guardian_retains_lease_until_worker_reaped":true},"operator_action":"The outcome is uncertain. Do not retry; retain the record and obtain an independent version observation after the controller is safely available."}),
        ),
        _ => Err("Main worker returned an unexpected response".into()),
    }
}

fn child_error_kind(kind: &str) -> &'static str {
    match kind {
        "package_rejected" => "package_rejected",
        "package_io" => "package_io",
        "catalog_rejected" => "catalog_rejected",
        "catalog_io" => "catalog_io",
        "host_record_io" => "host_record_io",
        _ => "device_refused",
    }
}
fn worker(channel: &mut Channel) -> Result<(), AppError> {
    let Message::Request(request) = channel.wait(Duration::from_secs(10))? else {
        return Err("Expected Main worker request".into());
    };
    let request: Request = serde_json::from_value(request).map_err(|error| error.to_string())?;
    let (archive, model, package) = inspect_worker_package(&request)?;
    let record = std::path::PathBuf::from(std::ffi::OsString::from_vec(request.record));
    channel.send(&Message::PackageReady)?;
    let lease = ProcessLock::adopt_worker_stderr()?;
    channel.send(&Message::Ready)?;
    let Message::Go = channel.wait(Duration::from_secs(10))? else {
        return Err("Main worker was not authorized to start".into());
    };
    let command = Command::Update {
        path: archive,
        catalog: None,
        model,
        component: Component::Main,
        allow_downgrade: request.allow_downgrade,
        confirm_ns39: request.confirm_ns39,
        record,
        json: true,
    };
    let value = super::native::execute_main_worker(command, package, lease)?;
    channel.send(&Message::Result(value))?;
    Ok(())
}

fn inspect_worker_package(
    request: &Request,
) -> Result<
    (
        std::path::PathBuf,
        gulikit_core::package::Model,
        gulikit_core::package::VerifiedPackage,
    ),
    AppError,
> {
    let archive = std::path::PathBuf::from(std::ffi::OsString::from_vec(request.archive.clone()));
    let model = request
        .model
        .parse()
        .map_err(|error: gulikit_core::package::SelectionError| error.to_string())?;
    let package = if let Some(bytes) = request.catalog.as_deref() {
        let catalog = Catalog::parse(bytes)
            .map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))?;
        gulikit_platform::inspect_catalog_package(&archive, &catalog, model, Component::Main)
    } else {
        gulikit_platform::inspect_package(&archive, model, Component::Main)
    }
    .map_err(|error| package_error(&error))?;
    Ok((archive, model, package))
}

fn package_error(error: &gulikit_platform::InspectError) -> AppError {
    let (kind, code) = match &error {
        gulikit_platform::InspectError::Rejected(_) => ("package_rejected", 3),
        gulikit_platform::InspectError::Io(_) | gulikit_platform::InspectError::NotFile => {
            ("package_io", 4)
        }
    };
    AppError::new(kind, code, error.to_string())
}

pub fn internal(command: &Command) -> ExitCode {
    let result = match command {
        Command::MainGuardian => {
            Channel::from_stdin()
                .map_err(AppError::from)
                .and_then(|channel| {
                    gulikit_platform::main_worker::guardian(
                        channel,
                        subprocess("__main-worker")?,
                        Duration::from_secs(180),
                    )
                    .map_err(AppError::from)
                })
        }
        Command::MainWorker => {
            Channel::from_stdin()
                .map_err(AppError::from)
                .and_then(|mut channel| {
                    let result = worker(&mut channel);
                    if let Err(error) = &result {
                        let _ = channel.send(&Message::Failed {
                            kind: error.kind.into(),
                            code: error.code,
                            message: error.message.clone(),
                        });
                    }
                    result
                })
        }
        _ => return ExitCode::from(2),
    };
    if let Err(error) = result {
        if let Ok(mut channel) = Channel::from_stdin() {
            let _ = channel.send(&Message::Unknown {
                reason: error.message,
                worker_stopped: true,
            });
        }
        ExitCode::from(5)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    const PAYLOAD: &[u8] = &[0x5a; 51_500];

    fn archive_bytes() -> Vec<u8> {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file("NS39.bin", SimpleFileOptions::default())
            .expect("ZIP member starts");
        writer.write_all(PAYLOAD).expect("payload writes");
        writer.finish().expect("ZIP finishes").into_inner()
    }

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn catalog_bytes(archive: &[u8]) -> Vec<u8> {
        let entry = serde_json::json!({
            "product": "kk3-max",
            "component": "main",
            "version": "6.1",
            "archive": "original.zip",
            "archive_size": archive.len(),
            "archive_sha256": digest(archive),
            "member": "NS39.bin",
            "member_size": PAYLOAD.len(),
            "member_sha256": digest(PAYLOAD),
            "payload_size": PAYLOAD.len(),
            "payload_sha256": digest(PAYLOAD),
            "source_url": "https://www.gulikit.com/newsinfo/887152.html",
            "parser_id": "kk3_main_binary_v1",
            "software_support": "supported",
            "hardware_acceptance": "unqualified",
            "hardware_evidence": null
        });
        serde_json::to_vec(&serde_json::json!({"schema_version": 1, "entries": [entry]}))
            .expect("catalog serializes")
    }

    fn request(archive_path: &std::path::Path, catalog: Vec<u8>) -> Request {
        Request {
            archive: archive_path.as_os_str().as_bytes().to_vec(),
            record: b"/tmp/operation.jsonl".to_vec(),
            catalog: Some(catalog),
            model: "kk3-max".into(),
            allow_downgrade: false,
            confirm_ns39: true,
        }
    }

    #[test]
    fn request_ipc_preserves_catalog_snapshot_when_source_changes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive_bytes();
        let catalog = catalog_bytes(&archive);
        let source = directory.path().join("catalog.json");
        let archive_path = directory.path().join("firmware.zip");
        std::fs::write(&source, &catalog).expect("catalog saved");
        std::fs::write(&archive_path, &archive).expect("archive saved");
        let outgoing = request(&archive_path, catalog.clone());

        let encoded = serde_json::to_vec(&outgoing).expect("request serializes");
        std::fs::write(&source, b"replaced source file").expect("source changes");
        let received: Request = serde_json::from_slice(&encoded).expect("request deserializes");

        assert_eq!(received.catalog.as_deref(), Some(catalog.as_slice()));
        let (_archive, _model, package) =
            inspect_worker_package(&received).expect("worker uses request snapshot");
        assert_eq!(package.info().version, "6.1");
    }

    #[test]
    fn worker_package_inspection_uses_snapshot_and_rejects_replaced_archive() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = archive_bytes();
        let archive_path = directory.path().join("firmware.zip");
        std::fs::write(&archive_path, &archive).expect("archive saved");
        let request = request(&archive_path, catalog_bytes(&archive));

        let (_archive, _model, package) =
            inspect_worker_package(&request).expect("snapshot validates package");
        assert_eq!(package.info().version, "6.1");
        assert_eq!(package.info().component, Component::Main);

        std::fs::write(&archive_path, b"replaced archive").expect("archive changes");
        let error = inspect_worker_package(&request).expect_err("changed archive is rejected");
        assert_eq!(error.kind, "package_rejected");
        assert_eq!(error.code, 3);
    }

    #[test]
    fn malformed_catalog_retains_catalog_rejected_classification() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let request = request(&directory.path().join("firmware.zip"), b"{}".to_vec());

        let error = inspect_worker_package(&request).expect_err("unsupported schema is rejected");

        assert_eq!(error.kind, "catalog_rejected");
        assert_eq!(error.code, 3);
        assert_eq!(child_error_kind(error.kind), "catalog_rejected");
    }
}
