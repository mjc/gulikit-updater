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
    /// Enumerate all recognized update candidates. Put only one device in update mode.
    Devices {
        #[arg(long)]
        json: bool,
    },
    /// Read an installed version; confirm the physical NS39 label and Max controls.
    Probe {
        #[arg(long)]
        component: Component,
        #[arg(long, required = true)]
        confirm_ns39: bool,
        #[arg(long)]
        json: bool,
    },
    /// Update one component using a reviewed original ZIP and record the attempt.
    Update {
        path: PathBuf,
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
                Err((kind, code, message)) => {
                    if json {
                        write_json(
                            err,
                            serde_json::json!({"error":{"kind":kind,"message":message}}),
                        )?;
                    } else {
                        writeln!(err, "{message}")?;
                    }
                    Ok(ExitCode::from(code))
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

type AppError = (&'static str, u8, String);
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
            (kind, code, e.to_string())
        })?)
    } else {
        None
    };
    native::execute(command, package).map_err(|e| ("device_refused", 5, e))
}
fn outcome_code(value: &serde_json::Value) -> u8 {
    match value.pointer("/transfer/outcome").and_then(|v| v.as_str()) {
        Some("already_current" | "installed_verified") | None => 0,
        Some(
            "transfer_completed_awaiting_verification" | "transfer_submitted_pending_completion",
        ) => 7,
        Some("outcome_unknown") => 9,
        _ => 5,
    }
}

mod native;

fn main() -> ExitCode {
    let cli = Cli::parse();
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
