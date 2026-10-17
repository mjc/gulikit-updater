//! Host I/O adapters. Firmware compatibility decisions belong to the core.
#![forbid(unsafe_code)]

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
