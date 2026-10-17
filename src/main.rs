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
#[command(version, about = "Inspect reviewed GuliKit firmware packages offline")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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

#[derive(Serialize)]
struct Envelope<T> {
    schema_version: u8,
    #[serde(flatten)]
    body: T,
}

fn write_json(writer: impl Write, body: impl Serialize) -> io::Result<()> {
    let mut writer = writer;
    serde_json::to_writer_pretty(
        &mut writer,
        &Envelope {
            schema_version: 1,
            body,
        },
    )?;
    writeln!(writer)
}

fn run(cli: Cli, out: &mut impl Write, err: &mut impl Write) -> io::Result<ExitCode> {
    match cli.command {
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
