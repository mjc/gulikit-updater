//! Main filesystem workers shared by the CLI and desktop executable.
use crate::updater::{self, ApplicationError, Attachment};
use gulikit_core::{
    package::{Component, Model},
    update::Progress,
    version::VersionPolicy,
};
use gulikit_platform::{
    lock::ProcessLock,
    main_worker::{Channel, Message},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
pub struct MainUpdate {
    pub archive: PathBuf,
    pub record: PathBuf,
    pub model: Model,
    pub policy: VersionPolicy,
    pub confirm_ns39: bool,
    pub expected_attachment: Option<Attachment>,
    pub expected_archive_sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct WorkerRequest {
    archive: Vec<u8>,
    record: Vec<u8>,
    model: String,
    allow_downgrade: bool,
    confirm_ns39: bool,
    expected_attachment: Option<Attachment>,
    expected_archive_sha256: Option<String>,
}

fn subprocess(argument: &str) -> Result<Command, ApplicationError> {
    let mut command = Command::new(std::env::current_exe().map_err(|error| error.to_string())?);
    command.arg(argument);
    Ok(command)
}

/// Run a Main transaction under a guardian that retains its lease until I/O stops.
///
/// # Errors
/// Reports startup, package and preflight failures. A lost response after GO is
/// returned as an uncertain result, never as proof that nothing was written.
pub fn update(
    request: MainUpdate,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(Progress),
) -> Result<Value, ApplicationError> {
    let wire = WorkerRequest {
        archive: request.archive.as_os_str().as_bytes().to_vec(),
        record: request.record.as_os_str().as_bytes().to_vec(),
        model: request.model.to_string(),
        allow_downgrade: request.policy == VersionPolicy::AllowDowngrade,
        confirm_ns39: request.confirm_ns39,
        expected_attachment: request.expected_attachment,
        expected_archive_sha256: request.expected_archive_sha256,
    };
    let response = gulikit_platform::main_worker::run_with_progress(
        subprocess("__main-guardian")?,
        serde_json::to_value(wire).map_err(|error| error.to_string())?,
        Duration::from_secs(185),
        cancelled,
        progress,
    )?;
    match response {
        Message::Result(value) => Ok(value),
        Message::Failed {
            kind,
            code,
            message,
        } => Err(ApplicationError {
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
        } => Ok(json!({
            "event":"attempt_supervision_result", "schema_version":1, "component":"main",
            "transfer":{"outcome":"outcome_unknown","error":reason,"cleanup_errors":["Consult the worker's durable host record. No retry, deletion or recovery was attempted."]},
            "supervision":{"worker_stopped":worker_stopped,"guardian_retains_lease_until_worker_reaped":true},
            "operator_action":"Keep USB connected and leave the controller unchanged. Do not retry or inspect until recovery is qualified for this interrupted state."
        })),
        _ => Err("Main worker returned an unexpected response".into()),
    }
}

fn worker(channel: &mut Channel) -> Result<(), ApplicationError> {
    let Message::Request(request) = channel.wait(Duration::from_secs(10))? else {
        return Err("Expected Main worker request".into());
    };
    let request: WorkerRequest =
        serde_json::from_value(request).map_err(|error| error.to_string())?;
    let archive = PathBuf::from(std::ffi::OsString::from_vec(request.archive));
    let record = PathBuf::from(std::ffi::OsString::from_vec(request.record));
    let model = request
        .model
        .parse()
        .map_err(|error: gulikit_core::package::SelectionError| error.to_string())?;
    let package = gulikit_platform::inspect_package(&archive, model, Component::Main)?;
    if request
        .expected_archive_sha256
        .as_ref()
        .is_some_and(|hash| hash != &package.info().archive_sha256)
    {
        return Err("Firmware package changed since selection. Select and review it again.".into());
    }
    channel.send(&Message::PackageReady)?;
    let lease = ProcessLock::adopt_worker_stderr()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    ctrlc::set_handler(move || flag.store(true, Ordering::Release))
        .map_err(|error| error.to_string())?;
    channel.send(&Message::Ready)?;
    let Message::Go = channel.wait(Duration::from_secs(10))? else {
        return Err("Main worker was not authorized to start".into());
    };
    let command = updater::Request::Update {
        archive,
        package,
        confirm_ns39: request.confirm_ns39,
        record,
        expected_attachment: request.expected_attachment,
        policy: if request.allow_downgrade {
            VersionPolicy::AllowDowngrade
        } else {
            VersionPolicy::UpgradeOnly
        },
    };
    let value = updater::execute_main_worker(
        command,
        lease,
        &mut || cancelled.load(Ordering::Acquire),
        &mut |value| {
            if channel.send(&Message::Progress(value)).is_err() {
                cancelled.store(true, Ordering::Release);
            }
        },
    )?;
    channel.send(&Message::Result(value))?;
    Ok(())
}

/// Handle a private worker invocation before either frontend initializes.
/// Returns `None` for ordinary frontend arguments.
#[must_use]
pub fn dispatch_internal(argument: &OsStr) -> Option<u8> {
    let result = match argument.to_str()? {
        "__main-guardian" => Channel::from_stdin()
            .map_err(ApplicationError::from)
            .and_then(|channel| {
                gulikit_platform::main_worker::guardian(
                    channel,
                    subprocess("__main-worker")?,
                    Duration::from_secs(180),
                )
                .map_err(ApplicationError::from)
            }),
        "__main-worker" => Channel::from_stdin()
            .map_err(ApplicationError::from)
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
            }),
        _ => return None,
    };
    Some(if let Err(error) = result {
        if let Ok(mut channel) = Channel::from_stdin() {
            let _ = channel.send(&Message::Unknown {
                reason: error.message,
                worker_stopped: true,
            });
        }
        5
    } else {
        0
    })
}
