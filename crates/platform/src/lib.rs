//! Host I/O adapters. Firmware compatibility decisions belong to the core.
#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
pub mod macos;

pub mod acquisition;
pub mod discovery;
pub mod journal;
#[cfg(unix)]
pub mod lock;
#[cfg(unix)]
pub mod main_worker;
#[cfg(unix)]
pub mod volume;

use gulikit_core::package::{Component, MAX_ARCHIVE_SIZE, Model, PackageError, VerifiedPackage};
use std::{fs::File, io::Read, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("cannot read package: {0}")]
    Io(#[from] std::io::Error),
    #[error("package input must be a regular file")]
    NotFile,
    #[error(transparent)]
    Rejected(#[from] PackageError),
}

/// Read a bounded local package without opening a controller or running an EXE.
///
/// # Errors
///
/// Returns an error if the input is not a readable regular file, exceeds the archive bound, or fails reviewed package validation.
pub fn inspect_package(
    path: &Path,
    model: Model,
    component: Component,
) -> Result<VerifiedPackage, InspectError> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(InspectError::NotFile);
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(InspectError::NotFile);
    }
    let mut bytes = Vec::new();
    file.take(MAX_ARCHIVE_SIZE as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(VerifiedPackage::inspect(&bytes, model, component)?)
}
