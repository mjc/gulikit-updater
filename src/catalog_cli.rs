//! Metadata inspection stays separate from firmware authorization.

use gulikit_catalog::{Catalog, MAX_CATALOG_BYTES};
use std::{fs::File, io, io::Read, io::Write, path::Path, process::ExitCode};

use crate::{AppError, write_json};

fn load(path: &Path) -> Result<Catalog, AppError> {
    let read_error = |error: io::Error| AppError::new("catalog_io", 4, error.to_string());
    let regular_file_error = || {
        AppError::new(
            "catalog_io",
            4,
            "catalog input must be a regular file".into(),
        )
    };
    if !std::fs::symlink_metadata(path)
        .map_err(read_error)?
        .is_file()
    {
        return Err(regular_file_error());
    }
    let file = File::open(path).map_err(read_error)?;
    if !file.metadata().map_err(read_error)?.is_file() {
        return Err(regular_file_error());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CATALOG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    Catalog::parse(&bytes).map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))
}

pub(super) fn inspect(
    path: &Path,
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<ExitCode> {
    match load(path) {
        Ok(catalog) => {
            if json {
                write_json(
                    out,
                    serde_json::json!({"catalog": catalog, "trust": "unverified", "authorizes_firmware": false}),
                )?;
            } else {
                writeln!(
                    out,
                    "Catalog metadata valid; signature unverified. No firmware authorized."
                )?;
                for entry in catalog.entries() {
                    writeln!(
                        out,
                        "{} {} {} — {}",
                        entry.product(),
                        entry.component(),
                        entry.version(),
                        entry.source_url()
                    )?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            if json {
                write_json(
                    err,
                    serde_json::json!({"error": {"kind": error.kind, "message": error.message}}),
                )?;
            } else {
                writeln!(err, "{}", error.message)?;
            }
            Ok(ExitCode::from(error.code))
        }
    }
}
