//! CLI confirmation and interruption handling for shared Main supervision.
use super::{AppError, Command};
use gulikit_core::version::VersionPolicy;
use gulikit_updater::supervision::{self, MainUpdate};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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
    let cancelled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancelled);
    ctrlc::set_handler(move || flag.store(true, Ordering::Release))
        .map_err(|error| error.to_string())?;
    supervision::update(
        MainUpdate {
            archive: path,
            record,
            model,
            confirm_ns39,
            policy: if allow_downgrade {
                VersionPolicy::AllowDowngrade
            } else {
                VersionPolicy::UpgradeOnly
            },
            expected_attachment: None,
            expected_archive_sha256: None,
        },
        &mut || cancelled.load(Ordering::Acquire),
        &mut |_| {},
    )
}
