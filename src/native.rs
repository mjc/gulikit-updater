//! CLI argument and interruption adapter for the shared application operations.
use super::{AppError, Command};
use gulikit_core::{package::VerifiedPackage, version::VersionPolicy};
use gulikit_updater::updater::{self, Request};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn request(command: Command, package: Option<VerifiedPackage>) -> Result<Request, AppError> {
    match command {
        Command::Devices { .. } => Ok(Request::Devices),
        Command::Probe {
            component,
            confirm_ns39,
            ..
        } => Ok(Request::Probe {
            component,
            confirm_ns39,
        }),
        Command::Update {
            allow_downgrade,
            confirm_ns39,
            record,
            ..
        } => Ok(Request::Update {
            package: package.ok_or("Missing verified package")?,
            confirm_ns39,
            record,
            expected_attachment: None,
            policy: if allow_downgrade {
                VersionPolicy::AllowDowngrade
            } else {
                VersionPolicy::UpgradeOnly
            },
        }),
        Command::Verify {
            attempt,
            record,
            confirm_ns39,
            confirm_same_controller,
            ..
        } => Ok(Request::Verify {
            attempt,
            record,
            confirm_ns39,
            confirm_same_controller,
        }),
        _ => Err("Not a native command".into()),
    }
}
fn cancellation(request: &Request) -> Result<Arc<AtomicBool>, AppError> {
    let cancelled = Arc::new(AtomicBool::new(false));
    #[cfg(target_os = "macos")]
    {
        if let Request::Devices = request {
            return Ok(cancelled);
        }
        let flag = Arc::clone(&cancelled);
        ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
            .map_err(|error| error.to_string())?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = request;
    Ok(cancelled)
}
pub fn execute(command: Command, package: Option<VerifiedPackage>) -> Result<Value, AppError> {
    let request = request(command, package)?;
    let cancelled = cancellation(&request)?;
    updater::execute_raw(
        request,
        &mut || cancelled.load(Ordering::SeqCst),
        &mut |_| {},
    )
}
#[cfg(target_os = "macos")]
pub fn execute_main_worker(
    command: Command,
    package: VerifiedPackage,
    lease: gulikit_platform::lock::ProcessLock,
) -> Result<Value, AppError> {
    let request = request(command, Some(package))?;
    let cancelled = cancellation(&request)?;
    updater::execute_main_worker(
        request,
        lease,
        &mut || cancelled.load(Ordering::SeqCst),
        &mut |_| {},
    )
}
