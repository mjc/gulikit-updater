use clap::{Parser, ValueEnum};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const APP_NAME: &str = "GuliKit Updater.app";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Smoke,
    Release,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Architecture {
    Arm64,
    #[value(name = "x86_64")]
    X86_64,
}

impl Architecture {
    fn name(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X86_64 => "x86_64",
        }
    }
}

/// Package native macOS executables; release mode requires notarization.
#[derive(Debug, Parser)]
pub(super) struct Options {
    mode: Mode,
    #[arg(long)]
    binaries: PathBuf,
    #[arg(long, default_value = "artifacts/distribution")]
    output: PathBuf,
    #[arg(long, value_enum)]
    arch: Architecture,
    #[arg(long, env = "MACOS_SIGNING_IDENTITY", hide_env_values = true)]
    identity: Option<String>,
    #[arg(
        long,
        env = "APPLE_NOTARY_PROFILE",
        hide_env_values = true,
        conflicts_with = "notary_key"
    )]
    notary_profile: Option<String>,
    #[arg(long, env = "APPLE_NOTARY_KEY_PATH", hide_env_values = true)]
    notary_key: Option<PathBuf>,
    #[arg(long, env = "APPLE_NOTARY_KEY_ID", hide_env_values = true)]
    notary_key_id: Option<String>,
    #[arg(long, env = "APPLE_NOTARY_ISSUER_ID", hide_env_values = true)]
    notary_issuer: Option<String>,
    #[arg(long, env = "MACOS_SIGNING_KEYCHAIN", hide_env_values = true)]
    keychain: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    // Do not print command arguments: notarization arguments identify credentials.
    #[error("{program} failed ({status}): {stderr}")]
    Tool {
        program: String,
        status: std::process::ExitStatus,
        stderr: String,
    },
}

type Result<T> = std::result::Result<T, Error>;

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

trait Runner {
    fn execute(&self, program: &str, args: &[OsString]) -> std::io::Result<Output>;
}

struct Native;

impl Runner for Native {
    fn execute(&self, program: &str, args: &[OsString]) -> std::io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

fn tool_error(program: &str, output: &Output) -> Error {
    Error::Tool {
        program: program.into(),
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run(runner: &impl Runner, program: &str, args: &[OsString]) -> Result<String> {
    let output = runner.execute(program, args)?;
    if !output.status.success() {
        return Err(tool_error(program, &output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn check_binary(runner: &impl Runner, binary: &Path, arch: Architecture) -> Result<()> {
    let architectures = run(runner, "/usr/bin/lipo", &["-archs".into(), binary.into()])?;
    if architectures.trim() != arch.name() {
        return Err(invalid(format!(
            "Wrong architecture: {}; expected {}",
            binary.display(),
            arch.name()
        )));
    }
    let dependencies = run(runner, "/usr/bin/otool", &["-L".into(), binary.into()])?;
    for line in dependencies.lines().skip(1) {
        let dependency = line.trim().split(" (").next().unwrap_or_default();
        if !dependency.starts_with("/System/Library/") && !dependency.starts_with("/usr/lib/") {
            return Err(invalid(format!(
                "Non-system dependency in {}: {dependency}",
                binary.display()
            )));
        }
    }
    Ok(())
}

fn stage(
    runner: &impl Runner,
    binaries: &Path,
    destination: &Path,
    version: &str,
    arch: Architecture,
) -> Result<PathBuf> {
    let components: Vec<_> = version.split('.').collect();
    if components.len() != 3
        || components
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid(
            "macOS bundle version must have three numeric components",
        ));
    }
    let app = destination.join(APP_NAME);
    for (name, directory) in [("gulikit-ui", "MacOS"), ("gulikit-updater", "Helpers")] {
        let binary = binaries.join(name);
        check_binary(runner, &binary, arch)?;
        let directory = app.join("Contents").join(directory);
        fs::create_dir_all(&directory)?;
        let installed = directory.join(name);
        fs::copy(binary, &installed)?;
        fs::set_permissions(installed, fs::Permissions::from_mode(0o755))?;
    }
    fs::write(
        app.join("Contents/Info.plist"),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>gulikit-ui</string>
<key>CFBundleIdentifier</key><string>lol.mjc.gulikit-updater</string>
<key>CFBundleName</key><string>GuliKit Updater</string>
<key>CFBundleDisplayName</key><string>GuliKit Updater</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundleVersion</key><string>{version}</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
"#
        ),
    )?;
    Ok(app)
}

fn verify(runner: &impl Runner, app: &Path) -> Result<()> {
    let mut arguments = args(&["--verify", "--deep", "--strict"]);
    arguments.push(app.into());
    run(runner, "/usr/bin/codesign", &arguments)?;
    Ok(())
}

fn sign(runner: &impl Runner, app: &Path, identity: &str, keychain: Option<&Path>) -> Result<()> {
    let mut options = args(&["--force", "--options", "runtime", "--sign", identity]);
    options.push(
        if identity == "-" {
            "--timestamp=none"
        } else {
            "--timestamp"
        }
        .into(),
    );
    if let Some(keychain) = keychain {
        options.extend(["--keychain".into(), keychain.into()]);
    }
    // Sign inside out. --deep is reserved for verification.
    for target in [app.join("Contents/Helpers/gulikit-updater"), app.to_owned()] {
        let mut arguments = options.clone();
        arguments.push(target.into());
        run(runner, "/usr/bin/codesign", &arguments)?;
    }
    verify(runner, app)
}

fn smoke(runner: &impl Runner, app: &Path) -> Result<()> {
    for (name, expected) in [
        ("Contents/MacOS/gulikit-ui", "Usage: gulikit-ui"),
        ("Contents/Helpers/gulikit-updater", "Usage:"),
    ] {
        let binary = app.join(name);
        // Apple platforms use UTF-8 executable paths. Command arguments remain OsString.
        let program = binary
            .to_str()
            .ok_or_else(|| invalid("Executable path is not UTF-8"))?;
        if !run(runner, program, &args(&["--help"]))?.contains(expected) {
            return Err(invalid(format!(
                "Packaged executable did not print help: {}",
                binary.display()
            )));
        }
    }
    Ok(())
}

fn archive(runner: &impl Runner, app: &Path, path: &Path) -> Result<()> {
    let mut arguments = args(&["-c", "-k", "--sequesterRsrc", "--keepParent"]);
    arguments.extend([app.into(), path.into()]);
    run(runner, "/usr/bin/ditto", &arguments)?;
    Ok(())
}

enum NotaryAuth<'a> {
    Profile {
        name: &'a str,
        keychain: Option<&'a Path>,
    },
    ApiKey {
        path: &'a Path,
        id: &'a str,
        issuer: Option<&'a str>,
    },
}

impl NotaryAuth<'_> {
    fn arguments(&self) -> Vec<OsString> {
        match self {
            Self::Profile { name, keychain } => {
                let mut arguments = args(&["--keychain-profile", name]);
                if let Some(keychain) = keychain {
                    arguments.extend(["--keychain".into(), keychain.as_os_str().to_owned()]);
                }
                arguments
            }
            Self::ApiKey { path, id, issuer } => {
                let mut arguments = vec![
                    "--key".into(),
                    path.as_os_str().to_owned(),
                    "--key-id".into(),
                    id.into(),
                ];
                if let Some(issuer) = issuer {
                    arguments.extend(args(&["--issuer", issuer]));
                }
                arguments
            }
        }
    }
}

fn notarize(
    runner: &impl Runner,
    submission: &Path,
    output: &Path,
    name: &str,
    auth: &NotaryAuth<'_>,
) -> Result<()> {
    let mut arguments = args(&["notarytool", "submit"]);
    arguments.push(submission.into());
    arguments.extend(auth.arguments());
    arguments.extend(args(&[
        "--wait",
        "--timeout",
        "30m",
        "--output-format",
        "json",
    ]));
    let response = runner.execute("/usr/bin/xcrun", &arguments)?;
    // Preserve diagnostics even when a rejected submission exits nonzero.
    if !response.status.success() && response.stdout.is_empty() {
        return Err(tool_error("notarytool", &response));
    }
    let json: Value = serde_json::from_slice(&response.stdout)?;
    fs::write(
        output.join(format!("{name}-notary.json")),
        serde_json::to_vec_pretty(&json)?,
    )?;
    let id = json["id"]
        .as_str()
        .ok_or_else(|| invalid("Notarization response has no submission ID"))?;
    let mut arguments = args(&["notarytool", "log", id]);
    arguments.extend(auth.arguments());
    let log = run(runner, "/usr/bin/xcrun", &arguments)?;
    fs::write(output.join(format!("{name}-notary-log.json")), log)?;
    if !response.status.success() || json["status"] != "Accepted" {
        return Err(invalid(format!(
            "Notarization was not accepted: {}",
            json["status"]
        )));
    }
    Ok(())
}

fn assess(runner: &impl Runner, app: &Path) -> Result<()> {
    run(
        runner,
        "/usr/bin/xcrun",
        &["stapler".into(), "validate".into(), app.into()],
    )?;
    verify(runner, app)?;
    let mut arguments = args(&["--assess", "--type", "execute", "--verbose=2"]);
    arguments.push(app.into());
    run(runner, "/usr/sbin/spctl", &arguments)?;
    Ok(())
}

fn release(
    runner: &impl Runner,
    app: &Path,
    output: &Path,
    name: &str,
    identity: &str,
    keychain: Option<&Path>,
    auth: &NotaryAuth<'_>,
) -> Result<()> {
    let final_zip = output.join(format!("{name}.zip"));
    let checksum = output.join(format!("{name}.zip.sha256"));
    if final_zip.exists() || checksum.exists() {
        return Err(invalid("Release artifact already exists"));
    }
    if !identity.starts_with("Developer ID Application:") {
        return Err(invalid("A Developer ID Application identity is required"));
    }
    let mut arguments = args(&["find-identity", "-v", "-p", "codesigning"]);
    if let Some(keychain) = keychain {
        arguments.push(keychain.into());
    }
    if !run(runner, "/usr/bin/security", &arguments)?.contains(&format!("\"{identity}\"")) {
        return Err(invalid(
            "Developer ID Application identity/private key is unavailable",
        ));
    }
    sign(runner, app, identity, keychain)?;
    smoke(runner, app)?;
    let parent = app
        .parent()
        .ok_or_else(|| invalid("App has no parent directory"))?;
    let submission = parent.join("notary-submission.zip");
    archive(runner, app, &submission)?;
    notarize(runner, &submission, output, name, auth)?;
    run(
        runner,
        "/usr/bin/xcrun",
        &["stapler".into(), "staple".into(), app.into()],
    )?;
    assess(runner, app)?;
    let candidate = parent.join(format!("{name}.zip"));
    archive(runner, app, &candidate)?;
    let extracted = parent.join("extracted");
    run(
        runner,
        "/usr/bin/ditto",
        &[
            "-x".into(),
            "-k".into(),
            candidate.clone().into(),
            extracted.clone().into(),
        ],
    )?;
    let packaged = extracted.join(APP_NAME);
    assess(runner, &packaged)?;
    smoke(runner, &packaged)?;
    // Publication happens only after the consumer copy passes every check.
    let digest = hex::encode(Sha256::digest(fs::read(&candidate)?));
    // Both paths are on the output filesystem. Linking atomically refuses an
    // existing destination, including a file created since the initial check.
    fs::hard_link(candidate, &final_zip)?;
    fs::write(checksum, format!("{digest}  {name}.zip\n"))?;
    println!("Signed, notarized and verified: {}", final_zip.display());
    Ok(())
}

pub(super) fn package(options: &Options) -> Result<()> {
    let auth = match (
        options.notary_profile.as_deref(),
        options.notary_key.as_deref(),
        options.notary_key_id.as_deref(),
    ) {
        (Some(name), None, _) => Some(NotaryAuth::Profile {
            name,
            keychain: options.keychain.as_deref(),
        }),
        (None, Some(path), Some(id)) => Some(NotaryAuth::ApiKey {
            path,
            id,
            issuer: options.notary_issuer.as_deref(),
        }),
        (None, None, _) => None,
        _ => {
            return Err(invalid(
                "Choose a notary profile or an API key with its key ID",
            ));
        }
    };
    if matches!(options.mode, Mode::Release) && (options.identity.is_none() || auth.is_none()) {
        return Err(invalid(
            "release requires --identity and a notary profile or API key",
        ));
    }
    fs::create_dir_all(&options.output)?;
    let temporary = tempfile::tempdir_in(&options.output)?;
    let version = env!("CARGO_PKG_VERSION");
    let app = stage(
        &Native,
        &options.binaries.canonicalize()?,
        temporary.path(),
        version,
        options.arch,
    )?;
    match options.mode {
        Mode::Smoke => {
            sign(&Native, &app, "-", None)?;
            smoke(&Native, &app)?;
            println!("Local ad-hoc packaging smoke passed; no release artifact produced");
        }
        Mode::Release => {
            let name = format!("gulikit-updater-{version}-macos-{}", options.arch.name());
            release(
                &Native,
                &app,
                &options.output,
                &name,
                options
                    .identity
                    .as_deref()
                    .ok_or_else(|| invalid("Missing signing identity"))?,
                options.keychain.as_deref(),
                &auth.ok_or_else(|| invalid("Missing notarization credentials"))?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
