use super::Command;
use gulikit_core::package::VerifiedPackage;
use serde_json::Value;

#[cfg(not(target_os = "macos"))]
pub fn execute(_command: Command, _package: Option<VerifiedPackage>) -> Result<Value, String> {
    Err(
        "Native device access currently supports macOS only; package inspection works on this OS"
            .into(),
    )
}

#[cfg(target_os = "macos")]
pub fn execute(command: Command, package: Option<VerifiedPackage>) -> Result<Value, String> {
    use gulikit_core::{
        package::Component,
        update::{
            BluetoothPort, MainPort, Outcome, TransferRecord, Verification, update_bluetooth,
            update_main, verify_restart,
        },
        version::{MainVersion, VersionPolicy, bluetooth_info},
    };
    use gulikit_platform::journal::{Recorded, finalize_record, write_event};
    use gulikit_platform::macos::{Session, discover, read_main};
    use serde_json::json;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    match command {
        Command::Devices { .. } => Ok(
            json!({"discovery":discover()?,"coverage":"Observed GuliKit update profiles and correlated GuliKit volumes. Put only one device in update mode; future unknown identities may not be recognized."}),
        ),
        Command::Probe {
            component,
            confirm_ns39,
            ..
        } => {
            let (target, raw, version, qualified_lun, cleanup_errors) = match component {
                Component::Main => {
                    let (target, raw, version) = read_main(confirm_ns39)?;
                    (target, raw, version.to_string(), None, Vec::<String>::new())
                }
                Component::Bluetooth => {
                    let mut port =
                        Session::open(confirm_ns39, Component::Bluetooth)?.bluetooth()?;
                    let target = port.target().clone();
                    let qualified_lun = port.qualified_lun();
                    let raw = port.read_info();
                    let cleanup_errors: Vec<_> = port.finish().err().into_iter().collect();
                    let raw = raw.map_err(|e| format!("{e}; cleanup={cleanup_errors:?}"))?;
                    let version = bluetooth_info(&raw)
                        .map_err(|e| format!("{e}; raw={raw:02x?}; cleanup={cleanup_errors:?}"))?
                        .to_string();
                    (target, raw, version, qualified_lun, cleanup_errors)
                }
            };
            Ok(
                json!({"component":component,"installed_version":version,"raw_version_bytes":raw,"qualified_bot_lun":qualified_lun,"cleanup_errors":cleanup_errors,"target":target,"identity_provenance":"user-confirmed NS39; observed update profile"}),
            )
        }
        Command::Update {
            component,
            allow_downgrade,
            confirm_ns39,
            record,
            ..
        } => {
            let package = package.ok_or("Missing verified package")?;
            let policy = if allow_downgrade {
                VersionPolicy::AllowDowngrade
            } else {
                VersionPolicy::UpgradeOnly
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&cancelled);
            ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))
                .map_err(|e| e.to_string())?;
            let mut session = Session::open(confirm_ns39, component)?;
            let target = session.target.clone();
            let mut journal = session.create_record(&record)?;
            let header = json!({"event":"attempt_started","schema_version":1,"version_policy":policy,"target":target,"package":package.info(),"identity_provenance":"user-confirmed NS39; observed update profile","post_restart_association":"pending; no USB serial is available"});
            write_event(&mut journal, &header)?;
            let result = match component {
                Component::Main => match session.main() {
                    Ok(port) => update_main(
                        &mut Recorded::new(port, &mut journal),
                        &package,
                        policy,
                        || cancelled.load(Ordering::SeqCst),
                    ),
                    Err(error) => TransferRecord {
                        version_policy: policy,
                        error: Some(error),
                        ..TransferRecord::default()
                    },
                },
                Component::Bluetooth => match session.bluetooth() {
                    Ok(port) => update_bluetooth(
                        &mut Recorded::new(port, &mut journal),
                        &package,
                        policy,
                        || cancelled.load(Ordering::SeqCst),
                    ),
                    Err(error) => TransferRecord {
                        version_policy: policy,
                        error: Some(error),
                        ..TransferRecord::default()
                    },
                },
            };
            let action = match result.outcome {
                Outcome::TransferCompletedAwaitingVerification
                | Outcome::TransferSubmittedPendingCompletion => {
                    if component == Component::Main {
                        "The controller completes Main installation and restarts automatically. Once it has restarted, re-enter update mode if needed and use verify with this attempt plus a new host record. Confirm the same physical controller; transfer completion alone does not verify installation."
                    } else {
                        "Power off and on normally, re-enter update mode, then use verify with this attempt plus a new host record and confirm the same physical controller. Transfer completion does not verify installation."
                    }
                }
                Outcome::OutcomeUnknown => {
                    "Keep the cable connected. No retry or resume will be attempted. Use the documented recovery procedure if needed, then obtain a fresh independent version observation."
                }
                Outcome::DestinationCreatedWithoutPayload => {
                    "No firmware payload bytes were submitted, but the destination file was created. It remains on the controller and requires inspection before another attempt; the updater does not delete or overwrite it."
                }
                Outcome::AlreadyCurrent => {
                    "This component is already current. No firmware bytes were sent."
                }
                _ => {
                    "No firmware transfer was completed. Address the recorded refusal before starting a new session."
                }
            };
            let value = json!({"event":"attempt_result","schema_version":1,"target":target,"package":package.info(),"transfer":result,"operator_action":action});
            Ok(finalize_record(&mut journal, value))
        }
        Command::Verify {
            attempt,
            record,
            confirm_ns39,
            confirm_same_controller,
            ..
        } => {
            let bytes = gulikit_platform::journal::read_attempt(&attempt)?;
            let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            let records: Vec<Value> = text
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            let prior=records.last().filter(|v|v["event"]=="attempt_result").ok_or("Attempt has no complete result; use probe for an independent version observation")?;
            let (component, expected_version) = attempt_target(prior)?;
            let previous: Outcome = serde_json::from_value(prior["transfer"]["outcome"].clone())
                .map_err(|e| e.to_string())?;
            let generation = prior["target"]["generation"]
                .as_u64()
                .ok_or("Missing attachment generation")?;
            let mut session = Session::open(confirm_ns39, component)?;
            let target = session.target.clone();
            let mut journal = session.create_record(&record)?;
            write_event(
                &mut journal,
                &json!({"event":"verification_started","schema_version":1,"source_attempt":record_path(&attempt),"prior_result":prior,"target":target,"same_unit_association":"user-confirmed; attachment generation bound; no machine-proven unique serial identity"}),
            )?;
            let (readback, cleanup, qualified_lun) = match component {
                Component::Main => match session.main() {
                    Ok(mut port) => {
                        let raw = port.read_version();
                        let cleanup = port.finish();
                        (raw, cleanup, None)
                    }
                    Err(error) => (Err(error), Ok(()), None),
                },
                Component::Bluetooth => match session.bluetooth() {
                    Ok(mut port) => {
                        let qualified_lun = port.qualified_lun();
                        let raw = port.read_info();
                        let cleanup = port.finish();
                        (raw, cleanup, qualified_lun)
                    }
                    Err(error) => (Err(error), Ok(()), None),
                },
            };
            let version = readback
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|raw| match component {
                    Component::Main => MainVersion::parse(raw)
                        .map(|version| version.to_string())
                        .map_err(|e| e.to_string()),
                    Component::Bluetooth => bluetooth_info(raw)
                        .map(|version| version.to_string())
                        .map_err(|e| e.to_string()),
                });
            let error = version.as_ref().err().cloned();
            let observation = version.ok().map(|version| Verification {
                component,
                previous_generation: generation,
                generation: target.generation,
                same_unit_confirmed: confirm_same_controller,
                model_confirmed: confirm_ns39,
                version,
                expected_version,
            });
            let outcome = observation.as_ref().map_or(previous, |observation| {
                verify_restart(previous, observation)
            });
            let cleanup_errors: Vec<_> = cleanup.err().into_iter().collect();
            Ok(finalize_record(
                &mut journal,
                json!({
                    "event":"verification_result", "schema_version":1,
                    "source_attempt":record_path(&attempt), "verification":observation,
                    "raw_version_bytes":readback.ok(), "qualified_bot_lun":qualified_lun, "target":target,
                    "same_unit_association":"user-confirmed; attachment generation bound; no machine-proven unique serial identity",
                    "transfer":{"outcome":outcome,"error":error,"cleanup_errors":cleanup_errors}
                }),
            ))
        }
        _ => Err("Not a native command".into()),
    }
}

#[cfg(any(target_os = "macos", test))]
fn attempt_target(prior: &Value) -> Result<(gulikit_core::package::Component, String), String> {
    let component = prior["package"]["component"]
        .as_str()
        .ok_or("Missing component")?
        .parse::<gulikit_core::package::Component>()
        .map_err(|e| e.to_string())?;
    let version = prior["package"]["version"]
        .as_str()
        .ok_or("Missing package version")?;
    let package = &prior["package"];
    let recognized = gulikit_core::package::catalog().iter().any(|release| {
        let metadata = serde_json::to_value(release).expect("catalog metadata serializes");
        [
            "model",
            "component",
            "version",
            "payload_size",
            "payload_sha256",
            "archive_sha256",
            "member",
            "source_url",
        ]
        .iter()
        .all(|field| package[*field] == metadata[*field])
    });
    if !recognized {
        return Err(
            "Original attempt package metadata is not a recognized reviewed release".into(),
        );
    }
    Ok((component, version.into()))
}

#[cfg(any(target_os = "macos", test))]
fn record_path(path: &std::path::Path) -> Value {
    let mut value = serde_json::json!({"display": path.to_string_lossy()});
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value["unix_bytes"] = serde_json::json!(path.as_os_str().as_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value["windows_wide"] =
            serde_json::json!(path.as_os_str().encode_wide().collect::<Vec<_>>());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verification_refuses_unrecognized_or_inconsistent_original_package_metadata() {
        let release = &gulikit_core::package::catalog()[0];
        let mut package = serde_json::to_value(release).unwrap();
        // Attempt records use PackageInfo rather than the whole catalog entry.
        package
            .as_object_mut()
            .unwrap()
            .insert("payload_size".into(), serde_json::json!(51500));
        package.as_object_mut().unwrap().insert(
            "payload_sha256".into(),
            serde_json::json!("d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4"),
        );
        let prior = serde_json::json!({"package":package});
        assert_eq!(
            attempt_target(&prior).unwrap(),
            (gulikit_core::package::Component::Main, "5.9".into())
        );
        for (field, value) in [
            ("version", serde_json::json!("6.0")),
            ("payload_sha256", serde_json::json!("wrong")),
            ("archive_sha256", serde_json::json!("wrong")),
            ("payload_size", serde_json::json!(0)),
            ("model", serde_json::json!("kk3-pro")),
            ("component", serde_json::json!("bluetooth")),
        ] {
            let mut invalid = prior.clone();
            invalid["package"][field] = value;
            assert!(
                attempt_target(&invalid).is_err(),
                "accepted changed {field}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn verification_path_preserves_non_utf8_bytes_without_panicking() {
        use std::os::unix::ffi::OsStrExt;
        let bytes = b"/tmp/attempt-\xff.jsonl";
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(bytes));
        let value = record_path(path);
        let roundtrip: Vec<u8> = serde_json::from_value(value["unix_bytes"].clone()).unwrap();
        assert_eq!(roundtrip, bytes);
        assert!(value["display"].as_str().unwrap().contains("attempt-"));
    }
}
