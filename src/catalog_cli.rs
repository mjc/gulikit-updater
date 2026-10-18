//! Catalog metadata does not assert vendor authenticity or authorize a write.

use gulikit_catalog::{Catalog, MAX_CATALOG_BYTES};
use gulikit_platform::catalog::{CatalogCache, CatalogCacheError, read_catalog_file};
use std::{io, io::Write, path::Path, process::ExitCode};

use crate::{AppError, CatalogCommand, write_json};

fn cache_error(error: &CatalogCacheError) -> AppError {
    let (kind, code) = match error {
        CatalogCacheError::Io(_) | CatalogCacheError::UnsafeFile | CatalogCacheError::Lock(_) => {
            ("catalog_io", 4)
        }
        CatalogCacheError::PublishedButDurabilityUnknown(_) => ("catalog_durability_unknown", 8),
        _ => ("catalog_rejected", 3),
    };
    AppError::new(kind, code, error.to_string())
}

fn load(path: &Path) -> Result<Catalog, AppError> {
    let bytes = read_catalog_file(path, MAX_CATALOG_BYTES).map_err(|error| cache_error(&error))?;
    Catalog::parse(&bytes).map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))
}

fn metadata(command: CatalogCommand) -> Result<Catalog, AppError> {
    match command {
        CatalogCommand::Inspect { path, .. } => load(&path),
        CatalogCommand::Cached { cache, .. } => CatalogCache::new(cache)
            .load()
            .map_err(|error| cache_error(&error))?
            .ok_or_else(|| AppError::new("catalog_io", 4, "no catalog is cached".into())),
        CatalogCommand::Refresh {
            url, file, cache, ..
        } => {
            let cache = CatalogCache::new(cache);
            match (url, file) {
                (Some(url), None) => cache
                    .refresh_from_url(&url)
                    .map_err(|error| cache_error(&error)),
                (None, Some(path)) => {
                    let bytes = read_catalog_file(&path, MAX_CATALOG_BYTES)
                        .map_err(|error| cache_error(&error))?;
                    cache
                        .refresh_from_bytes(&bytes)
                        .map_err(|error| cache_error(&error))
                }
                _ => Err(AppError::new(
                    "catalog_usage",
                    2,
                    "select exactly one catalog source: --url or --file".into(),
                )),
            }
        }
    }
}

pub(super) fn run(
    command: CatalogCommand,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<ExitCode> {
    let json = match &command {
        CatalogCommand::Inspect { json, .. }
        | CatalogCommand::Cached { json, .. }
        | CatalogCommand::Refresh { json, .. } => *json,
    };
    match metadata(command) {
        Ok(catalog) => {
            if json {
                write_json(
                    out,
                    serde_json::json!({"catalog":catalog,"trust":"unverified","authorizes_firmware":false}),
                )?;
            } else {
                writeln!(
                    out,
                    "Catalog metadata valid; vendor authenticity not established. No firmware authorized."
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
                    serde_json::json!({"error":{"kind":error.kind,"message":error.message}}),
                )?;
            } else {
                writeln!(err, "{}", error.message)?;
            }
            Ok(ExitCode::from(error.code))
        }
    }
}
