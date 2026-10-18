//! Metadata inspection stays separate from firmware authorization.

use gulikit_catalog::auth::{MAX_ENVELOPE_BYTES, TrustedKeys, VerifiedCatalog, verify_envelope};
use gulikit_catalog::{Catalog, MAX_CATALOG_BYTES};
use gulikit_platform::catalog::{
    CatalogCache, CatalogCacheError, CatalogFreshness, read_catalog_file,
};
use serde::Deserialize;
use std::{
    io,
    io::Write,
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{AppError, CatalogCommand, write_json};

const MAX_TRUST_FILE_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    schema_version: u32,
    keys: Vec<TrustKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustKey {
    id: String,
    public_key: String,
}

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

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, AppError> {
    read_catalog_file(path, limit).map_err(|error| cache_error(&error))
}

fn load_keys(path: &Path) -> Result<TrustedKeys, AppError> {
    let invalid = |message: String| AppError::new("catalog_keys_rejected", 3, message);
    let bytes = read(path, MAX_TRUST_FILE_BYTES)?;
    let file: TrustFile =
        serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
    if file.schema_version != 1 {
        return Err(invalid("unsupported trusted-keys schema".into()));
    }
    let keys = file
        .keys
        .into_iter()
        .map(|key| {
            let mut public = [0; 32];
            if key.public_key.len() != 64
                || !key
                    .public_key
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(invalid(
                    "trusted public keys require 64 lowercase hex characters".into(),
                ));
            }
            hex::decode_to_slice(key.public_key, &mut public)
                .map_err(|error| invalid(error.to_string()))?;
            Ok((key.id, public))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    TrustedKeys::new(keys).map_err(|error| invalid(error.to_string()))
}

fn now() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| AppError::new("catalog_clock", 4, error.to_string()))
}

fn freshness_name(freshness: CatalogFreshness) -> &'static str {
    match freshness {
        CatalogFreshness::Fresh => "fresh",
        CatalogFreshness::NotYetValid => "not_yet_valid",
        CatalogFreshness::Expired => "expired",
        CatalogFreshness::BelowMinimumRevision => "below_minimum_revision",
    }
}

fn authenticated_report(
    catalog: &VerifiedCatalog,
    freshness: CatalogFreshness,
) -> serde_json::Value {
    serde_json::json!({
        "catalog": catalog.catalog(), "trust": "authenticated", "trust_source": "explicit_key_file", "freshness": freshness_name(freshness),
        "revision": catalog.revision(), "key_id": catalog.key_id(), "issued_at": catalog.issued_at(),
        "expires_at": catalog.expires_at(), "authorizes_firmware": false
    })
}

fn signed(command: CatalogCommand) -> Result<serde_json::Value, AppError> {
    match command {
        CatalogCommand::Verify {
            path,
            trusted_keys,
            minimum_revision,
            ..
        } => {
            let keys = load_keys(&trusted_keys)?;
            let catalog = verify_envelope(&read(&path, MAX_ENVELOPE_BYTES)?, &keys)
                .map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))?;
            catalog
                .require_fresh_at(now()?, minimum_revision)
                .map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))?;
            Ok(authenticated_report(&catalog, CatalogFreshness::Fresh))
        }
        CatalogCommand::Cached {
            cache,
            trusted_keys,
            minimum_revision,
            ..
        } => {
            let keys = load_keys(&trusted_keys)?;
            let cached = CatalogCache::new(cache)
                .load(&keys, now()?, minimum_revision)
                .map_err(|error| cache_error(&error))?
                .ok_or_else(|| {
                    AppError::new("catalog_io", 4, "no authenticated catalog is cached".into())
                })?;
            Ok(authenticated_report(cached.verified(), cached.freshness()))
        }
        CatalogCommand::Refresh {
            url,
            envelope,
            cache,
            trusted_keys,
            minimum_revision,
            ..
        } => {
            let keys = load_keys(&trusted_keys)?;
            let cache = CatalogCache::new(cache);
            let cached = match (url, envelope) {
                (Some(url), None) => cache
                    .refresh_from_url(&url, &keys, now()?, minimum_revision)
                    .map_err(|error| cache_error(&error))?,
                (None, Some(path)) => cache
                    .refresh_from_bytes(
                        &read(&path, MAX_ENVELOPE_BYTES)?,
                        &keys,
                        now()?,
                        minimum_revision,
                    )
                    .map_err(|error| cache_error(&error))?,
                _ => {
                    return Err(AppError::new(
                        "catalog_usage",
                        2,
                        "select exactly one catalog source: --url or --envelope".into(),
                    ));
                }
            };
            Ok(authenticated_report(cached.verified(), cached.freshness()))
        }
        CatalogCommand::Inspect { .. } => unreachable!("raw metadata uses the inspection path"),
    }
}

pub(super) fn run(
    command: CatalogCommand,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<ExitCode> {
    if let CatalogCommand::Inspect { path, json } = command {
        return inspect(&path, json, out, err);
    }
    let json = match &command {
        CatalogCommand::Verify { json, .. }
        | CatalogCommand::Cached { json, .. }
        | CatalogCommand::Refresh { json, .. }
        | CatalogCommand::Inspect { json, .. } => *json,
    };
    match signed(command) {
        Ok(report) => {
            if json {
                write_json(out, report)?;
            } else {
                writeln!(
                    out,
                    "Authenticated catalog; freshness: {}. No firmware authorized.",
                    report["freshness"].as_str().unwrap_or("unknown")
                )?;
                serde_json::to_writer_pretty(&mut *out, &report)?;
                writeln!(out)?;
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

fn load(path: &Path) -> Result<Catalog, AppError> {
    let bytes = read(path, MAX_CATALOG_BYTES)?;
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
