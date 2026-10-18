use clap::{Parser, Subcommand};
use gulikit_catalog::{Catalog, MAX_CATALOG_BYTES};
use gulikit_core::package::{Component, Model, VerifiedPackage, catalog};
use gulikit_platform::{
    InspectError, catalog::CatalogCacheError, inspect_catalog_package, inspect_package,
};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Inspect and update a user-confirmed KK3 Max NS39 controller"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[cfg(target_os = "macos")]
    #[command(hide = true, name = "__main-guardian")]
    MainGuardian,
    #[cfg(target_os = "macos")]
    #[command(hide = true, name = "__main-worker")]
    MainWorker,
    /// Enumerate all recognized update candidates. Put only one device in update mode.
    Devices {
        #[arg(long)]
        json: bool,
    },
    /// Read a version in the selected mode: Main APS+A, Bluetooth Gear/Set+A.
    Probe {
        #[arg(long)]
        component: Component,
        #[arg(long, required = true)]
        confirm_ns39: bool,
        #[arg(long)]
        json: bool,
    },
    /// Update one component in its separate mode (Main APS+A; Bluetooth Gear/Set+A).
    Update {
        path: PathBuf,
        /// Use this explicitly selected metadata catalog for package matching.
        #[arg(long)]
        catalog: Option<PathBuf>,
        /// Permit the selected package version to replace a newer installed version.
        #[arg(long)]
        allow_downgrade: bool,
        #[arg(long)]
        model: Model,
        #[arg(long)]
        component: Component,
        #[arg(long, required = true)]
        confirm_ns39: bool,
        #[arg(long)]
        record: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// After off/on restart and update-mode re-entry, verify the same physical controller.
    Verify {
        attempt: PathBuf,
        /// New host record linking this fresh readback to the original attempt.
        #[arg(long)]
        record: PathBuf,
        #[arg(long, required = true)]
        confirm_ns39: bool,
        #[arg(long, required = true)]
        confirm_same_controller: bool,
        #[arg(long)]
        json: bool,
    },
    /// List the reviewed firmware releases supported by this build.
    Packages {
        #[arg(long)]
        json: bool,
    },
    /// Validate a package without accessing a controller.
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Inspect catalog metadata without accessing a device or claiming vendor authenticity.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// Validate local catalog metadata without claiming vendor authentication.
    Inspect {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Inspect saved catalog metadata offline.
    Cached {
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate and atomically cache catalog metadata from a file or HTTPS URL.
    Refresh {
        #[arg(long, required_unless_present = "file", conflicts_with = "file")]
        url: Option<String>,
        #[arg(long, required_unless_present = "url", conflicts_with = "url")]
        file: Option<PathBuf>,
        #[arg(long)]
        cache: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List catalog releases, including official source and support status.
    Releases {
        #[arg(long)]
        catalog: Option<PathBuf>,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        component: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Open the selected release's official page in the default browser.
    Source {
        #[command(flatten)]
        selection: ReleaseSelection,
        #[arg(long)]
        changelog: bool,
        #[arg(long)]
        json: bool,
    },
    /// Obtain a reviewed direct download, or show the official manual-download page.
    Download {
        #[command(flatten)]
        selection: ReleaseSelection,
        #[arg(long)]
        output: PathBuf,
        /// Open the default browser when the download requires a manual step.
        #[arg(long)]
        open: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Args)]
struct ReleaseSelection {
    #[arg(long)]
    catalog: Option<PathBuf>,
    #[arg(long)]
    product: String,
    #[arg(long)]
    component: String,
    #[arg(long)]
    version: String,
}

#[derive(Subcommand)]
enum PackageCommand {
    /// Inspect an original ZIP against compiled releases or explicitly selected catalog metadata.
    Inspect {
        path: PathBuf,
        /// Use this explicitly selected metadata catalog for package matching.
        #[arg(long)]
        catalog: Option<PathBuf>,
        #[arg(long)]
        model: Model,
        #[arg(long)]
        component: Component,
        #[arg(long)]
        json: bool,
    },
}

fn write_json(writer: impl Write, mut body: serde_json::Value) -> io::Result<()> {
    let mut writer = writer;
    body.as_object_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "JSON output body must be an object",
            )
        })?
        .insert("schema_version".into(), serde_json::json!(1));
    serde_json::to_writer_pretty(&mut writer, &body)?;
    writeln!(writer)
}

fn write_native_result(
    result: Result<serde_json::Value, AppError>,
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> io::Result<ExitCode> {
    match result {
        Ok(value) => {
            let code = outcome_code(&value);
            if json {
                write_json(out, value)?;
            } else {
                serde_json::to_writer_pretty(&mut *out, &value)?;
                writeln!(out)?;
            }
            Ok(ExitCode::from(code))
        }
        Err(error) => {
            if json {
                write_json(
                    err,
                    serde_json::json!({"error":{"kind":error.kind,"message":error.message,"cleanup_errors":error.cleanup_errors}}),
                )?;
            } else {
                writeln!(err, "{}; cleanup={:?}", error.message, error.cleanup_errors)?;
            }
            Ok(ExitCode::from(error.code))
        }
    }
}

fn run(cli: Cli, out: &mut impl Write, err: &mut impl Write) -> io::Result<ExitCode> {
    match cli.command {
        #[cfg(target_os = "macos")]
        Command::MainGuardian | Command::MainWorker => unreachable!("internal process entrypoint"),
        command @ (Command::Devices { .. }
        | Command::Probe { .. }
        | Command::Update { .. }
        | Command::Verify { .. }) => {
            let json = match &command {
                Command::Devices { json }
                | Command::Probe { json, .. }
                | Command::Update { json, .. }
                | Command::Verify { json, .. } => *json,
                _ => unreachable!(),
            };
            write_native_result(native_command(command), json, out, err)
        }
        Command::Packages { json } => {
            if json {
                write_json(out, serde_json::json!({"packages": catalog()}))?;
            } else {
                for release in catalog() {
                    writeln!(
                        out,
                        "{} {} {} — {}",
                        release.model, release.component, release.version, release.archive
                    )?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Catalog { command } => catalog_cli::run(command, out, err),
        Command::Package {
            command:
                PackageCommand::Inspect {
                    path,
                    catalog,
                    model,
                    component,
                    json,
                },
        } => match inspect_selected_package(&path, model, component, catalog.as_deref()) {
            Ok(package) => {
                if json {
                    write_json(
                        out,
                        serde_json::json!({
                            "package": package.info(),
                            "catalog_authenticity": if catalog.is_some() { "not_established" } else { "not_applicable" }
                        }),
                    )?;
                } else {
                    let info = package.info();
                    writeln!(
                        out,
                        "{}: {} {} {}",
                        if catalog.is_some() {
                            "Catalog-matched package (catalog authenticity not established)"
                        } else {
                            "Reviewed package"
                        },
                        info.model,
                        info.component,
                        info.version
                    )?;
                    writeln!(out, "Member: {}", info.member)?;
                    writeln!(
                        out,
                        "Payload: {} bytes\nSHA-256: {}",
                        info.payload_size, info.payload_sha256
                    )?;
                    writeln!(out, "Source: {}", info.source_url)?;
                    writeln!(
                        out,
                        "Package inspection only; installed firmware has not been checked."
                    )?;
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
        },
    }
}

use gulikit_updater::updater::ApplicationError as AppError;

fn native_command(command: Command) -> Result<serde_json::Value, AppError> {
    let catalog_bytes = if let Command::Update {
        catalog: Some(path),
        ..
    } = &command
    {
        Some(read_catalog_snapshot(path)?)
    } else {
        None
    };
    if let Some(bytes) = catalog_bytes.as_deref() {
        let _ = parse_catalog(bytes)?;
    }
    #[cfg(target_os = "macos")]
    if let Command::Update {
        component: Component::Main,
        ..
    } = &command
    {
        let catalog_selected = catalog_bytes.is_some();
        let result = main_supervision::update(command, catalog_bytes)?;
        return Ok(mark_catalog_authenticity(result, catalog_selected));
    }
    // Package rejection precedes device access and attempt-file creation on every OS.
    let package = if let Command::Update {
        path,
        catalog: _,
        model,
        component,
        ..
    } = &command
    {
        Some(inspect_package_with_catalog_bytes(
            path,
            *model,
            *component,
            catalog_bytes.as_deref(),
        )?)
    } else {
        None
    };
    let catalog_selected = catalog_bytes.is_some();
    let result = native::execute(command, package)?;
    Ok(mark_catalog_authenticity(result, catalog_selected))
}

fn mark_catalog_authenticity(
    mut result: serde_json::Value,
    catalog_selected: bool,
) -> serde_json::Value {
    if catalog_selected && let Some(object) = result.as_object_mut() {
        object.insert(
            "catalog_authenticity".into(),
            serde_json::json!("not_established"),
        );
    }
    result
}

fn inspect_selected_package(
    path: &std::path::Path,
    model: Model,
    component: Component,
    catalog_path: Option<&std::path::Path>,
) -> Result<VerifiedPackage, AppError> {
    let catalog_bytes = if let Some(catalog_path) = catalog_path {
        Some(read_catalog_snapshot(catalog_path)?)
    } else {
        None
    };
    inspect_package_with_catalog_bytes(path, model, component, catalog_bytes.as_deref())
}

fn inspect_package_with_catalog_bytes(
    path: &std::path::Path,
    model: Model,
    component: Component,
    catalog_bytes: Option<&[u8]>,
) -> Result<VerifiedPackage, AppError> {
    let package = if let Some(bytes) = catalog_bytes {
        let catalog = parse_catalog(bytes)?;
        inspect_catalog_package(path, &catalog, model, component)
    } else {
        inspect_package(path, model, component)
    };
    package.map_err(|error| package_error(&error))
}

fn read_catalog_snapshot(path: &std::path::Path) -> Result<Vec<u8>, AppError> {
    gulikit_platform::catalog::read_catalog_file(path, MAX_CATALOG_BYTES)
        .map_err(|error| catalog_read_error(&error))
}

fn parse_catalog(bytes: &[u8]) -> Result<Catalog, AppError> {
    Catalog::parse(bytes).map_err(|error| AppError::new("catalog_rejected", 3, error.to_string()))
}

fn catalog_read_error(error: &CatalogCacheError) -> AppError {
    let message = error.to_string();
    let (kind, code) = match &error {
        CatalogCacheError::TooLarge | CatalogCacheError::Catalog(_) => ("catalog_rejected", 3),
        CatalogCacheError::Io(_)
        | CatalogCacheError::UnsafeFile
        | CatalogCacheError::Lock(_)
        | CatalogCacheError::PublishedButDurabilityUnknown(_)
        | CatalogCacheError::Fetch(_) => ("catalog_io", 4),
    };
    AppError::new(kind, code, message)
}

fn package_error(error: &InspectError) -> AppError {
    let (kind, code) = match &error {
        InspectError::Rejected(_) => ("package_rejected", 3),
        InspectError::Io(_) | InspectError::NotFile => ("package_io", 4),
    };
    AppError::new(kind, code, error.to_string())
}
fn outcome_code(value: &serde_json::Value) -> u8 {
    if value.pointer("/transfer/outcome").and_then(|v| v.as_str()) == Some("outcome_unknown") {
        return 9;
    }
    if value.pointer("/transfer/outcome").and_then(|v| v.as_str())
        == Some("destination_created_without_payload")
    {
        return 8;
    }
    if ["/transfer/cleanup_errors", "/cleanup_errors"]
        .iter()
        .any(|path| {
            value
                .pointer(path)
                .and_then(|v| v.as_array())
                .is_some_and(|errors| !errors.is_empty())
        })
    {
        return 8;
    }
    if value
        .pointer("/transfer/error")
        .and_then(|value| value.as_str())
        .is_some()
    {
        return 5;
    }
    match value.pointer("/transfer/outcome").and_then(|v| v.as_str()) {
        Some("already_current" | "installed_verified") | None => 0,
        Some(
            "transfer_completed_awaiting_verification" | "transfer_submitted_pending_completion",
        ) => 7,
        Some("outcome_unknown") => 9,
        _ => 5,
    }
}

mod catalog_cli;
#[cfg(target_os = "macos")]
mod main_supervision;
mod native;

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(target_os = "macos")]
    if let Command::MainGuardian | Command::MainWorker = &cli.command {
        return main_supervision::internal(&cli.command);
    }
    match run(cli, &mut io::stdout().lock(), &mut io::stderr().lock()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("output failed: {error}");
            ExitCode::from(4)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_failure_codes_distinguish_host_io_and_restoration_attention() {
        let io = AppError::host_io("cannot create record".into());
        assert_eq!(io.kind, "host_record_io");
        assert_eq!(io.code, 4);
        let acquisition = gulikit_platform::acquisition::AcquisitionError::after_cleanup(
            "USB open failed".into(),
            Err("remount failed".into()),
        );
        let failure = AppError::from(acquisition);
        assert_eq!(failure.code, 8);
        assert_eq!(failure.message, "USB open failed");
        assert_eq!(failure.cleanup_errors, ["remount failed"]);
    }
    #[test]
    fn cleanup_failure_cannot_have_a_success_exit_status() {
        let value = serde_json::json!({"transfer":{"outcome":"already_current","cleanup_errors":["remount failed"]}});
        assert_eq!(outcome_code(&value), 8);
        let unknown = serde_json::json!({"transfer":{"outcome":"outcome_unknown","cleanup_errors":["remount failed"]}});
        assert_eq!(outcome_code(&unknown), 9);
    }
    #[test]
    fn created_main_file_without_payload_requires_attention() {
        let value = serde_json::json!({"transfer":{"outcome":"destination_created_without_payload","main_destination_created":true,"bytes_submitted":0,"error":"cancelled","cleanup_errors":[]}});
        assert_eq!(outcome_code(&value), 8);
    }
    #[test]
    fn probe_cleanup_failure_preserves_readback_but_requires_attention() {
        let value = serde_json::json!({"installed_version":"5.07","raw_version_bytes":[1,2],"cleanup_errors":["driver restoration pending"]});
        assert_eq!(outcome_code(&value), 8);
    }
    #[test]
    fn verification_read_error_cannot_reuse_a_previous_success_exit_status() {
        let value = serde_json::json!({"transfer":{"outcome":"already_current","error":"fresh read failed","cleanup_errors":[]}});
        assert_eq!(outcome_code(&value), 5);
    }
    #[test]
    fn json_envelope_replaces_existing_schema_marker() {
        let mut out = Vec::new();
        write_json(
            &mut out,
            serde_json::json!({"schema_version":1,"event":"attempt_result"}),
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches("\"schema_version\"").count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap()["schema_version"],
            1
        );
    }
    #[test]
    fn json_envelope_preserves_nested_evidence_and_rejects_nonobjects() {
        let body = serde_json::json!({
            "schema_version":0,
            "evidence":{"raw":[0,255,13,10], "error":"quoted \"message\"\nUSB — failed", "nullable":null}
        });
        let mut expected = body.clone();
        expected["schema_version"] = 1.into();
        let mut out = Vec::new();
        write_json(&mut out, body).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
            expected
        );
        assert_eq!(out.last(), Some(&b'\n'));
        for body in [
            serde_json::json!(null),
            serde_json::json!([1]),
            serde_json::json!("text"),
        ] {
            let mut out = Vec::new();
            let error = write_json(&mut out, body).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(out.is_empty());
        }
    }
}
