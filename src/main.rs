use clap::{Parser, Subcommand};
use gulikit_core::package::{Component, Model, catalog};
use gulikit_platform::{InspectError, inspect_package};
use serde::Serialize;
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
        /// Permit the reviewed selected release to replace a newer installed version.
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
}

#[derive(Subcommand)]
enum PackageCommand {
    /// Validate an original official ZIP and inspect its selected payload.
    Inspect {
        path: PathBuf,
        #[arg(long)]
        model: Model,
        #[arg(long)]
        component: Component,
        #[arg(long)]
        json: bool,
    },
}

fn write_json(writer: impl Write, body: impl Serialize) -> io::Result<()> {
    let mut writer = writer;
    let mut body = serde_json::to_value(body)?;
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
            match native_command(command) {
                Ok(value) => {
                    let code = outcome_code(&value);
                    if json {
                        write_json(out, value)?;
                    } else {
                        writeln!(out, "{}", serde_json::to_string_pretty(&value)?)?;
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
        Command::Package {
            command:
                PackageCommand::Inspect {
                    path,
                    model,
                    component,
                    json,
                },
        } => match inspect_package(&path, model, component) {
            Ok(package) => {
                if json {
                    write_json(out, serde_json::json!({"package": package.info()}))?;
                } else {
                    let info = package.info();
                    writeln!(
                        out,
                        "Reviewed package: {} {} {}",
                        info.model, info.component, info.version
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
                let (kind, code) = match &error {
                    InspectError::Rejected(_) => ("package_rejected", 3),
                    InspectError::Io(_) | InspectError::NotFile => ("package_io", 4),
                };
                if json {
                    write_json(
                        err,
                        serde_json::json!({"error": {"kind": kind, "message": error.to_string()}}),
                    )?;
                } else {
                    writeln!(err, "{error}")?;
                }
                Ok(ExitCode::from(code))
            }
        },
    }
}

#[derive(Debug)]
struct AppError {
    kind: &'static str,
    code: u8,
    message: String,
    cleanup_errors: Vec<String>,
}
impl AppError {
    fn new(kind: &'static str, code: u8, message: String) -> Self {
        Self {
            kind,
            code,
            message,
            cleanup_errors: Vec::new(),
        }
    }
    #[cfg(any(target_os = "macos", test))]
    fn host_io(message: String) -> Self {
        Self::new("host_record_io", 4, message)
    }
    #[cfg(any(target_os = "macos", test))]
    fn with_cleanup(mut self, cleanup_errors: Vec<String>) -> Self {
        if !cleanup_errors.is_empty() {
            self.code = 8;
        }
        self.cleanup_errors = cleanup_errors;
        self
    }
}
impl From<String> for AppError {
    fn from(message: String) -> Self {
        Self::new("device_refused", 5, message)
    }
}
impl From<&str> for AppError {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
#[cfg(any(target_os = "macos", test))]
impl From<gulikit_platform::acquisition::AcquisitionError> for AppError {
    fn from(error: gulikit_platform::acquisition::AcquisitionError) -> Self {
        Self::from(error.error).with_cleanup(error.cleanup_errors)
    }
}
fn native_command(command: Command) -> Result<serde_json::Value, AppError> {
    // Package rejection precedes device access and attempt-file creation on every OS.
    let package = if let Command::Update {
        path,
        model,
        component,
        ..
    } = &command
    {
        Some(inspect_package(path, *model, *component).map_err(|e| {
            let (kind, code) = if matches!(e, InspectError::Rejected(_)) {
                ("package_rejected", 3)
            } else {
                ("package_io", 4)
            };
            AppError::new(kind, code, e.to_string())
        })?)
    } else {
        None
    };
    #[cfg(target_os = "macos")]
    if matches!(
        &command,
        Command::Update {
            component: Component::Main,
            ..
        }
    ) {
        return main_supervision::update(command);
    }
    native::execute(command, package)
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

#[cfg(target_os = "macos")]
mod main_supervision;
mod native;

fn main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(target_os = "macos")]
    if matches!(&cli.command, Command::MainGuardian | Command::MainWorker) {
        return main_supervision::internal(cli.command);
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
}
