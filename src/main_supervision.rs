//! The Main worker owns synchronous volume/journal calls; the guardian owns its lease.
use super::{AppError, Command};
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
pub fn update(command: Command) -> Result<Value, AppError> {
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
            kind: match kind.as_str() {
                "package_rejected" => "package_rejected",
                "package_io" => "package_io",
                "host_record_io" => "host_record_io",
                _ => "device_refused",
            },
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
fn worker(channel: &mut Channel) -> Result<(), AppError> {
    let Message::Request(request) = channel.wait(Duration::from_secs(10))? else {
        return Err("Expected Main worker request".into());
    };
    let request: Request = serde_json::from_value(request).map_err(|error| error.to_string())?;
    let archive = std::path::PathBuf::from(std::ffi::OsString::from_vec(request.archive));
    let record = std::path::PathBuf::from(std::ffi::OsString::from_vec(request.record));
    let model = request
        .model
        .parse()
        .map_err(|error: gulikit_core::package::SelectionError| error.to_string())?;
    let package =
        gulikit_platform::inspect_package(&archive, model, Component::Main).map_err(|error| {
            let (kind, code) = if matches!(error, gulikit_platform::InspectError::Rejected(_)) {
                ("package_rejected", 3)
            } else {
                ("package_io", 4)
            };
            AppError::new(kind, code, error.to_string())
        })?;
    let lease = ProcessLock::adopt_worker_stderr()?;
    channel.send(&Message::Ready)?;
    if !matches!(channel.wait(Duration::from_secs(10))?, Message::Go) {
        return Err("Main worker was not authorized to start".into());
    }
    let command = Command::Update {
        path: archive,
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
pub fn internal(command: Command) -> ExitCode {
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
