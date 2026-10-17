#[cfg(target_os = "macos")]
use super::{ApplicationError as AppError, Request, check_attachment};
use serde_json::Value;
#[cfg(target_os = "macos")]
pub(super) fn execute(
    request: Request,
    mut main_lease: Option<gulikit_platform::lock::ProcessLock>,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(gulikit_core::update::Progress),
) -> Result<Value, AppError> {
    use gulikit_core::{
        package::Component,
        update::{
            BluetoothPort, MainPort, Outcome, TransferRecord, Verification,
            update_bluetooth_with_progress, update_main_with_progress, verify_restart,
        },
        version::{MainVersion, bluetooth_info},
    };
    use gulikit_platform::journal::{Recorded, finalize_record, write_event};
    use gulikit_platform::macos::{Session, discover};
    use serde_json::json;
    match request {
        Request::Devices => Ok(
            json!({"discovery":discover()?,"coverage":"Observed GuliKit update profiles and correlated GuliKit volumes. Put only one device in update mode; future unknown identities may not be recognized."}),
        ),
        Request::Probe {
            component,
            confirm_ns39,
            ..
        } => {
            let (target, raw, version, qualified_lun, cleanup_errors) = match component {
                Component::Main => {
                    let mut port = Session::open(confirm_ns39, Component::Main)?.main()?;
                    let target = port.target().clone();
                    let (raw, cleanup) = read_with_cleanup(
                        &mut port,
                        MainPort::read_version,
                        MainPort::finish,
                        &mut *cancelled,
                    );
                    let cleanup_errors: Vec<_> = cleanup.err().into_iter().collect();
                    let raw = raw.map_err(|error| {
                        AppError::from(error).with_cleanup(cleanup_errors.clone())
                    })?;
                    let version = MainVersion::parse(&raw).map_err(|error| {
                        AppError::from(error.to_string()).with_cleanup(cleanup_errors.clone())
                    })?;
                    (target, raw, version.to_string(), None, cleanup_errors)
                }
                Component::Bluetooth => {
                    let mut port =
                        Session::open(confirm_ns39, Component::Bluetooth)?.bluetooth()?;
                    let target = port.target().clone();
                    let qualified_lun = port.qualified_lun();
                    let (raw, cleanup) = read_with_cleanup(
                        &mut port,
                        |port| port.read_info(),
                        BluetoothPort::finish,
                        &mut *cancelled,
                    );
                    let cleanup_errors: Vec<_> = cleanup.err().into_iter().collect();
                    let raw = raw.map_err(|error| {
                        AppError::from(error).with_cleanup(cleanup_errors.clone())
                    })?;
                    let version = bluetooth_info(&raw)
                        .map_err(|e| {
                            AppError::from(format!("{e}; raw={raw:02x?}"))
                                .with_cleanup(cleanup_errors.clone())
                        })?
                        .to_string();
                    (target, raw, version, qualified_lun, cleanup_errors)
                }
            };
            Ok(
                json!({"component":component,"installed_version":version,"raw_version_bytes":raw,"qualified_bot_lun":qualified_lun,"cleanup_errors":cleanup_errors,"target":target,"identity_provenance":"user-confirmed NS39; observed update profile"}),
            )
        }
        Request::Update {
            package,
            confirm_ns39,
            record,
            expected_attachment,
            policy,
        } => {
            let component = package.info().component;
            if component == Component::Main && main_lease.is_none() {
                return Err("Main update requires the supervised filesystem worker".into());
            }
            let mut session = if let Some(lease) = main_lease.take() {
                Session::open_main_worker(confirm_ns39, lease)?
            } else {
                Session::open(confirm_ns39, component)?
            };
            let target = session.target.clone();
            check_attachment(expected_attachment, &target)?;
            let mut journal = session.create_record(&record).map_err(AppError::host_io)?;
            let header = json!({"event":"attempt_started","schema_version":1,"version_policy":policy,"target":target,"package":package.info(),"identity_provenance":"user-confirmed NS39; observed update profile","post_restart_association":"pending; no USB serial is available"});
            write_event(&mut journal, &header).map_err(AppError::host_io)?;
            let result = match component {
                Component::Main => match session.main() {
                    Ok(port) => update_main_with_progress(
                        &mut Recorded::new(port, &mut journal),
                        &package,
                        policy,
                        &mut *cancelled,
                        &mut *progress,
                    ),
                    Err(error) => TransferRecord {
                        version_policy: policy,
                        error: Some(error),
                        ..TransferRecord::default()
                    },
                },
                Component::Bluetooth => match session.bluetooth() {
                    Ok(port) => update_bluetooth_with_progress(
                        &mut Recorded::new(port, &mut journal),
                        &package,
                        policy,
                        &mut *cancelled,
                        &mut *progress,
                    ),
                    Err(error) => TransferRecord {
                        version_policy: policy,
                        error: Some(error.error),
                        cleanup_errors: error.cleanup_errors,
                        ..TransferRecord::default()
                    },
                },
            };
            let action = super::operator_action(component, result.outcome);
            let value = json!({"event":"attempt_result","schema_version":1,"target":target,"package":package.info(),"transfer":result,"operator_action":action});
            Ok(finalize_record(&mut journal, value))
        }
        Request::Verify {
            attempt,
            record,
            confirm_ns39,
            confirm_same_controller,
            ..
        } => {
            let bytes =
                gulikit_platform::journal::read_attempt(&attempt).map_err(AppError::host_io)?;
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
            let mut journal = session.create_record(&record).map_err(AppError::host_io)?;
            write_event(
                &mut journal,
                &json!({"event":"verification_started","schema_version":1,"source_attempt":record_path(&attempt),"prior_result":prior,"target":target,"same_unit_association":super::same_unit_association(confirm_same_controller)}),
            ).map_err(AppError::host_io)?;
            let (readback, cleanup, qualified_lun) = match component {
                Component::Main => match session.main() {
                    Ok(mut port) => {
                        let (raw, cleanup) = read_with_cleanup(
                            &mut port,
                            MainPort::read_version,
                            MainPort::finish,
                            &mut *cancelled,
                        );
                        (raw, cleanup, None)
                    }
                    Err(error) => (Err(error), Ok(()), None),
                },
                Component::Bluetooth => match session.bluetooth() {
                    Ok(mut port) => {
                        let qualified_lun = port.qualified_lun();
                        let (raw, cleanup) = read_with_cleanup(
                            &mut port,
                            |port| port.read_info(),
                            BluetoothPort::finish,
                            &mut *cancelled,
                        );
                        (raw, cleanup, qualified_lun)
                    }
                    Err(error) => (
                        Err(error.error),
                        if error.cleanup_errors.is_empty() {
                            Ok(())
                        } else {
                            Err(error.cleanup_errors.join("; "))
                        },
                        None,
                    ),
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
                    "same_unit_association":super::same_unit_association(confirm_same_controller),
                    "transfer":{"outcome":outcome,"error":error,"cleanup_errors":cleanup_errors}
                }),
            ))
        }
    }
}

pub(super) fn attempt_target(
    prior: &Value,
) -> Result<(gulikit_core::package::Component, String), String> {
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

pub(super) fn record_path(path: &std::path::Path) -> Value {
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

#[cfg(any(target_os = "macos", test))]
fn read_with_cleanup<P>(
    port: &mut P,
    read: impl FnOnce(&mut P) -> Result<Vec<u8>, String>,
    finish: impl FnOnce(&mut P) -> Result<(), String>,
    mut cancelled: impl FnMut() -> bool,
) -> (Result<Vec<u8>, String>, Result<(), String>) {
    let result = if cancelled() {
        Err("Cancelled before version read".into())
    } else {
        let result = read(port);
        if cancelled() {
            Err(match result {
                Ok(_) => "Cancelled during version read".into(),
                Err(error) => format!("Cancelled during version read; {error}"),
            })
        } else {
            result
        }
    };
    let cleanup = finish(port);
    (result, cleanup)
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
    #[cfg(windows)]
    #[test]
    fn verification_path_preserves_non_unicode_windows_units_without_panicking() {
        use std::os::windows::ffi::OsStringExt;
        let units = [0x61, 0xd800, 0x62];
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&units));
        let value = record_path(&path);
        let roundtrip: Vec<u16> = serde_json::from_value(value["windows_wide"].clone()).unwrap();
        assert_eq!(roundtrip, units);
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
    #[test]
    fn read_cancellation_preserves_cleanup_before_and_after_device_io() {
        for already_cancelled in [false, true] {
            let mut events = Vec::new();
            let flag = std::cell::Cell::new(already_cancelled);
            let (result, cleanup) = read_with_cleanup(
                &mut events,
                |events| {
                    events.push("read");
                    flag.set(true);
                    Ok(vec![1, 2, 3])
                },
                |events| {
                    events.push("finish");
                    Err("restore failed".into())
                },
                || flag.get(),
            );
            assert!(result.unwrap_err().contains("Cancelled"));
            assert_eq!(cleanup.unwrap_err(), "restore failed");
            assert_eq!(
                events,
                if already_cancelled {
                    vec!["finish"]
                } else {
                    vec!["read", "finish"]
                }
            );
        }
    }
}
