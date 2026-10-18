//! Catalog metadata and acquisition never authorize a device write.

use gulikit_catalog::{Catalog, Entry, MAX_CATALOG_BYTES};
use gulikit_platform::{
    catalog::{CatalogCache, CatalogCacheError, CatalogFetchError, read_catalog_file},
    download::{
        DownloadError, DownloadResult, download_release, open_official_changelog,
        open_official_source,
    },
};
use std::{
    io,
    io::Write,
    path::Path,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{AppError, CatalogCommand, ReleaseSelection, write_json};

enum Report {
    Review(serde_json::Value),
    Metadata(Catalog),
    Releases(Vec<Entry>),
    Source(String),
    Download {
        entry: Box<Entry>,
        result: DownloadResult,
    },
}

fn cache_error(error: &CatalogCacheError) -> AppError {
    let (kind, code) = match error {
        CatalogCacheError::Io(_)
        | CatalogCacheError::UnsafeFile
        | CatalogCacheError::Lock(_)
        | CatalogCacheError::Fetch(CatalogFetchError::Request(_)) => ("catalog_io", 4),
        CatalogCacheError::PublishedButDurabilityUnknown(_) => ("catalog_durability_unknown", 8),
        _ => ("catalog_rejected", 3),
    };
    AppError::new(kind, code, error.to_string())
}

fn download_error(error: &DownloadError) -> AppError {
    let (kind, code) = match error {
        DownloadError::Io(_) | DownloadError::UnsafeDestination => ("download_io", 4),
        DownloadError::PublishedButDurabilityUnknown(_) => ("download_durability_unknown", 8),
        DownloadError::Cancelled => ("download_cancelled", 5),
        _ => ("download_refused", 3),
    };
    AppError::new(kind, code, error.to_string())
}

fn load(path: &Path) -> Result<Catalog, AppError> {
    let bytes = read_catalog_file(path, MAX_CATALOG_BYTES).map_err(|error| cache_error(&error))?;
    Catalog::parse(&bytes).map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))
}

fn selected_catalog(path: Option<&Path>) -> Result<Catalog, AppError> {
    path.map_or_else(
        || {
            Catalog::parse(include_bytes!("../catalog/official.json"))
                .map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))
        },
        load,
    )
}

fn selected_entry(selection: &ReleaseSelection) -> Result<Entry, AppError> {
    selected_catalog(selection.catalog.as_deref())?
        .entries()
        .iter()
        .find(|entry| {
            entry.product() == selection.product
                && entry.component() == selection.component
                && entry.version() == selection.version
        })
        .cloned()
        .ok_or_else(|| {
            AppError::new(
                "catalog_release_missing",
                3,
                "No release matches the selected product, component and version.".into(),
            )
        })
}

fn refresh_catalog(
    cache: &Path,
    url: Option<&str>,
    file: Option<&Path>,
) -> Result<Catalog, AppError> {
    let cache = CatalogCache::new(cache);
    match (url, file) {
        (Some(url), None) => cache
            .refresh_from_url(url)
            .map_err(|error| cache_error(&error)),
        (None, Some(path)) => {
            let bytes =
                read_catalog_file(path, MAX_CATALOG_BYTES).map_err(|error| cache_error(&error))?;
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

fn report(command: CatalogCommand) -> Result<Report, AppError> {
    match command {
        command @ (CatalogCommand::Observe { .. }
        | CatalogCommand::Prepare { .. }
        | CatalogCommand::Diff { .. }
        | CatalogCommand::Publish { .. }) => {
            crate::catalog_review::report(command).map(Report::Review)
        }
        CatalogCommand::Inspect { path, .. } => load(&path).map(Report::Metadata),
        CatalogCommand::Cached { cache, .. } => CatalogCache::new(cache)
            .load()
            .map_err(|error| cache_error(&error))?
            .map(Report::Metadata)
            .ok_or_else(|| AppError::new("catalog_io", 4, "no catalog is cached".into())),
        CatalogCommand::Refresh {
            url, file, cache, ..
        } => refresh_catalog(&cache, url.as_deref(), file.as_deref()).map(Report::Metadata),
        CatalogCommand::Releases {
            catalog,
            product,
            component,
            ..
        } => {
            let catalog = selected_catalog(catalog.as_deref())?;
            Ok(Report::Releases(
                catalog
                    .entries()
                    .iter()
                    .filter(|entry| {
                        product
                            .as_ref()
                            .is_none_or(|product| entry.product() == product)
                            && component
                                .as_ref()
                                .is_none_or(|component| entry.component() == component)
                    })
                    .cloned()
                    .collect(),
            ))
        }
        CatalogCommand::Source {
            selection,
            changelog,
            ..
        } => {
            let entry = selected_entry(&selection)?;
            let url = if changelog {
                let url = entry.changelog_url().ok_or_else(|| {
                    AppError::new(
                        "catalog_changelog_missing",
                        3,
                        "No separate changelog is recorded; use the official release page.".into(),
                    )
                })?;
                open_official_changelog(&entry).map_err(|error| download_error(&error))?;
                url
            } else {
                open_official_source(&entry).map_err(|error| download_error(&error))?;
                entry.source_url()
            };
            Ok(Report::Source(url.to_owned()))
        }
        CatalogCommand::Download {
            selection,
            output,
            open,
            ..
        } => {
            let entry = selected_entry(&selection)?;
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancelled);
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))
                .map_err(|error| AppError::new("download_cancel_handler", 4, error.to_string()))?;
            let result =
                download_release(&entry, &output, &mut || cancelled.load(Ordering::Relaxed))
                    .map_err(|error| download_error(&error))?;
            if open && let DownloadResult::ManualRequired { .. } = &result {
                open_official_source(&entry).map_err(|error| download_error(&error))?;
            }
            Ok(Report::Download {
                entry: Box::new(entry),
                result,
            })
        }
    }
}

impl Report {
    fn json(&self) -> serde_json::Value {
        match self {
            Self::Review(value) => value.clone(),
            Self::Metadata(catalog) => {
                serde_json::json!({"schema_version":catalog.schema_version(),"catalog":catalog,"trust":"unverified","authorizes_firmware":false})
            }
            Self::Releases(entries) => {
                serde_json::json!({"releases":entries,"trust":"unverified","authorizes_firmware":false})
            }
            Self::Source(url) => {
                serde_json::json!({"requested_source":url,"authorizes_firmware":false})
            }
            Self::Download { entry, result } => {
                let download = match result {
                    DownloadResult::Downloaded { path } => {
                        serde_json::json!({"status":"downloaded","path":path.to_string_lossy()})
                    }
                    DownloadResult::ManualRequired { source_url } => {
                        serde_json::json!({"status":"manual_required","source_url":source_url,"instruction":"Download the complete original ZIP in your browser, then import it for the selected release."})
                    }
                };
                serde_json::json!({"release":entry,"download":download,"authorizes_firmware":false})
            }
        }
    }

    fn text(&self, out: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Review(value) => {
                serde_json::to_writer_pretty(&mut *out, value)?;
                writeln!(out)?;
            }
            Self::Metadata(catalog) => {
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
            Self::Releases(entries) => {
                for entry in entries {
                    writeln!(
                        out,
                        "{} {} {} — availability: {:?}; software: {:?}; hardware: {:?}\n  {}",
                        entry.product(),
                        entry.component(),
                        entry.version(),
                        entry.availability(),
                        entry.software_support(),
                        entry.hardware_acceptance(),
                        entry.source_url()
                    )?;
                }
                if entries.is_empty() {
                    writeln!(out, "No matching releases.")?;
                }
            }
            Self::Source(url) => writeln!(
                out,
                "Requested the official source in the default browser: {url}"
            )?,
            Self::Download { entry, result } => match result {
                DownloadResult::Downloaded { path } => writeln!(
                    out,
                    "Downloaded and hash-checked {} {} {} to {}",
                    entry.product(),
                    entry.component(),
                    entry.version(),
                    path.display()
                )?,
                DownloadResult::ManualRequired { source_url } => writeln!(
                    out,
                    "This release requires a browser download: {source_url}\nDownload the complete original ZIP ({}) and import it for the selected release.",
                    entry.archive()
                )?,
            },
        }
        Ok(())
    }
}

pub(super) fn run(
    command: CatalogCommand,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<ExitCode> {
    let json = match &command {
        CatalogCommand::Observe { json, .. }
        | CatalogCommand::Prepare { json, .. }
        | CatalogCommand::Diff { json, .. }
        | CatalogCommand::Publish { json, .. }
        | CatalogCommand::Inspect { json, .. }
        | CatalogCommand::Cached { json, .. }
        | CatalogCommand::Refresh { json, .. }
        | CatalogCommand::Releases { json, .. }
        | CatalogCommand::Source { json, .. }
        | CatalogCommand::Download { json, .. } => *json,
    };
    match report(command) {
        Ok(report) => {
            if json {
                write_json(out, report.json())?;
            } else {
                report.text(out)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_failures_are_io_errors_and_response_refusals_are_rejections() {
        let transport = cache_error(&CatalogCacheError::Fetch(CatalogFetchError::Request(
            "offline".into(),
        )));
        assert_eq!(transport.kind, "catalog_io");
        assert_eq!(transport.code, 4);
        for rejection in [
            CatalogFetchError::HttpsRequired,
            CatalogFetchError::Status(404),
            CatalogFetchError::CompressedResponse,
            CatalogFetchError::InvalidContentLength,
            CatalogFetchError::TooLarge,
        ] {
            let error = cache_error(&CatalogCacheError::Fetch(rejection));
            assert_eq!(error.kind, "catalog_rejected");
            assert_eq!(error.code, 3);
        }
    }
}
