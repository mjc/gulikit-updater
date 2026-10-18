//! Host I/O adapters. Firmware compatibility decisions belong to the core.
#![deny(unsafe_code)]

#[cfg(target_os = "macos")]
pub mod macos;

pub mod acquisition;
pub mod catalog;
pub mod discovery;
pub mod download;
pub mod journal;
#[cfg(unix)]
pub mod lock;
#[cfg(unix)]
pub mod main_worker;
#[cfg(unix)]
pub mod volume;

use gulikit_core::package::{Component, MAX_ARCHIVE_SIZE, Model, PackageError, VerifiedPackage};
use std::{fs::OpenOptions, io::Read, path::Path};

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
    let bytes = read_archive(path, MAX_ARCHIVE_SIZE as u64)?;
    Ok(VerifiedPackage::inspect(&bytes, model, component)?)
}

/// Check a selected archive against an explicitly selected metadata catalog.
///
/// Hashes check consistency with that catalog, not vendor authenticity. This
/// function never opens a controller or executes the embedded updater.
///
/// # Errors
/// Rejects unsafe files, excessive sizes and incompatible package metadata.
pub fn inspect_catalog_package(
    path: &Path,
    catalog: &gulikit_catalog::Catalog,
    model: Model,
    component: Component,
) -> Result<VerifiedPackage, InspectError> {
    let bytes = read_archive(path, gulikit_catalog::MAX_ARCHIVE_SIZE)?;
    Ok(VerifiedPackage::inspect_catalog(
        &bytes, catalog, model, component,
    )?)
}

fn read_archive(path: &Path, limit: u64) -> Result<Vec<u8>, InspectError> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(InspectError::NotFile);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(InspectError::NotFile);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}
