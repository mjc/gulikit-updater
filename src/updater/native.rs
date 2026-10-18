#[cfg(target_os = "macos")]
use super::{ApplicationError as AppError, Request, check_attachment};
#[cfg(target_os = "macos")]
use gulikit_core::{
    package::Component,
    update::{
        BluetoothPort, MainPort, TransferRecord, Verification, update_bluetooth_with_progress,
        update_main_with_progress, verify_restart,
    },
    version::{MainVersion, bluetooth_info},
};
#[cfg(target_os = "macos")]
use gulikit_platform::journal::{Recorded, finalize_record, write_event};
#[cfg(target_os = "macos")]
use gulikit_platform::macos::{Session, discover};
use serde_json::Value;
#[cfg(target_os = "macos")]
use serde_json::json;

#[cfg(target_os = "macos")]
pub(super) fn execute(
    request: Request,
    mut main_lease: Option<gulikit_platform::lock::ProcessLock>,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(gulikit_core::update::Progress),
) -> Result<Value, AppError> {
    match request {
        Request::Devices => Ok(
            json!({"discovery":discover()?,"coverage":"Observed GuliKit update profiles and correlated GuliKit volumes. Put only one device in update mode; future unknown identities may not be recognized."}),
        ),
        Request::Probe {
            component,
            confirm_ns39,
        } => probe(component, confirm_ns39, cancelled),
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
            let header = json!({"event":"attempt_started","schema_version":1,"version_policy":policy,"target":target,"package":package.info(),"catalog_entry":package.catalog_entry(),"identity_provenance":"user-confirmed NS39; observed update profile","post_restart_association":"pending; no USB serial is available"});
            write_event(&mut journal, &header).map_err(AppError::host_io)?;
            let result =
                transfer_package(session, &package, policy, &mut journal, cancelled, progress);
            let action = super::operator_action(component, result.outcome);
            let value = json!({"event":"attempt_result","schema_version":1,"target":target,"package":package.info(),"catalog_entry":package.catalog_entry(),"transfer":result,"operator_action":action});
            Ok(finalize_record(&mut journal, value))
        }
        Request::Verify {
            attempt,
            record,
            confirm_ns39,
            confirm_same_controller,
            expected_receipt,
        } => verify_attempt(
            &attempt,
            &record,
            confirm_ns39,
            confirm_same_controller,
            expected_receipt.as_ref(),
            cancelled,
        ),
    }
}

#[cfg(target_os = "macos")]
fn transfer_package(
    session: Session,
    package: &gulikit_core::package::VerifiedPackage,
    policy: gulikit_core::version::VersionPolicy,
    journal: &mut std::fs::File,
    cancelled: &mut dyn FnMut() -> bool,
    progress: &mut dyn FnMut(gulikit_core::update::Progress),
) -> TransferRecord {
    match package.info().component {
        Component::Main => match session.main() {
            Ok(port) => update_main_with_progress(
                &mut Recorded::new(port, &mut *journal),
                package,
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
                &mut Recorded::new(port, &mut *journal),
                package,
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
    }
}

#[cfg(target_os = "macos")]
fn probe(
    component: gulikit_core::package::Component,
    confirm_ns39: bool,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Value, AppError> {
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
            let raw = match raw {
                Ok(raw) => raw,
                Err(error) => return Err(AppError::from(error).with_cleanup(cleanup_errors)),
            };
            let version = match MainVersion::parse(&raw) {
                Ok(version) => version,
                Err(error) => {
                    return Err(AppError::from(error.to_string()).with_cleanup(cleanup_errors));
                }
            };
            (target, raw, version.to_string(), None, cleanup_errors)
        }
        Component::Bluetooth => {
            let mut port = Session::open(confirm_ns39, Component::Bluetooth)?.bluetooth()?;
            let target = port.target().clone();
            let qualified_lun = port.qualified_lun();
            let (raw, cleanup) = read_with_cleanup(
                &mut port,
                gulikit_platform::macos::BluetoothSession::read_info,
                BluetoothPort::finish,
                &mut *cancelled,
            );
            let mut cleanup_errors: Vec<_> = cleanup.err().into_iter().collect();
            let raw = match raw {
                Ok(raw) => raw,
                Err(error) => return Err(AppError::from(error).with_cleanup(cleanup_errors)),
            };
            let version = match bluetooth_info(&raw) {
                Ok(version) => version.to_string(),
                Err(error) => {
                    return Err(AppError::from(format!("{error}; raw={raw:02x?}"))
                        .with_cleanup(cleanup_errors));
                }
            };
            // Read-only cleanup may reset USB and restart driver matching.
            // Discover again before returning an attachment for later operations.
            let target = match discover()
                .and_then(|snapshot| post_cleanup_target(&target, &snapshot, confirm_ns39))
            {
                Ok(current) => current,
                Err(error) => {
                    cleanup_errors
                        .push(format!("Attachment after cleanup is unconfirmed: {error}"));
                    target
                }
            };
            (target, raw, version, qualified_lun, cleanup_errors)
        }
    };
    Ok(
        json!({"component":component,"installed_version":version,"raw_version_bytes":raw,"qualified_bot_lun":qualified_lun,"cleanup_errors":cleanup_errors,"target":target,"identity_provenance":"user-confirmed NS39; observed update profile"}),
    )
}

#[cfg(target_os = "macos")]
fn verify_attempt(
    attempt: &std::path::Path,
    record: &std::path::Path,
    confirm_ns39: bool,
    confirm_same_controller: bool,
    expected_receipt: Option<&super::ReceiptIdentity>,
    cancelled: &mut dyn FnMut() -> bool,
) -> Result<Value, AppError> {
    let prior = read_verification_receipt(attempt, expected_receipt)?;
    let component = prior.component;
    let expected_version = prior.expected_version;
    let previous = prior.outcome;
    let generation = prior.generation;
    let prior = prior.record;
    let mut session = Session::open(confirm_ns39, component)?;
    let target = session.target.clone();
    let mut journal = session.create_record(record).map_err(AppError::host_io)?;
    write_event(
        &mut journal,
        &json!({
            "event": "verification_started", "schema_version": 1,
            "source_attempt": record_path(attempt), "prior_result": prior, "target": target,
            "same_unit_association": super::same_unit_association(confirm_same_controller)
        }),
    )
    .map_err(AppError::host_io)?;
    let VersionReadback {
        raw: readback,
        cleanup,
        qualified_lun,
    } = read_verification_version(session, component, cancelled);
    let (version, raw_version_bytes) = match readback {
        Ok(raw) => {
            let version = match component {
                Component::Main => MainVersion::parse(&raw)
                    .map(|version| version.to_string())
                    .map_err(|error| error.to_string()),
                Component::Bluetooth => bluetooth_info(&raw)
                    .map(|version| version.to_string())
                    .map_err(|error| error.to_string()),
            };
            (version, Some(raw))
        }
        Err(error) => (Err(error), None),
    };
    let (observation, error) = match version {
        Ok(version) => (
            Some(Verification {
                component,
                previous_generation: generation,
                generation: target.generation,
                same_unit_confirmed: confirm_same_controller,
                model_confirmed: confirm_ns39,
                version,
                expected_version,
            }),
            None,
        ),
        Err(error) => (None, Some(error)),
    };
    let outcome = observation.as_ref().map_or(previous, |observation| {
        verify_restart(previous, observation)
    });
    let cleanup_errors: Vec<_> = cleanup.err().into_iter().collect();
    Ok(finalize_record(
        &mut journal,
        json!({
            "event":"verification_result", "schema_version":1,
            "source_attempt":record_path(attempt), "verification":observation,
            "raw_version_bytes":raw_version_bytes, "qualified_bot_lun":qualified_lun, "target":target,
            "same_unit_association":super::same_unit_association(confirm_same_controller),
            "transfer":{"outcome":outcome,"error":error,"cleanup_errors":cleanup_errors}
        }),
    ))
}

#[cfg(target_os = "macos")]
fn read_verification_receipt(
    attempt: &std::path::Path,
    expected: Option<&super::ReceiptIdentity>,
) -> Result<super::PriorAttempt, AppError> {
    let bytes = gulikit_platform::journal::read_attempt(attempt).map_err(AppError::host_io)?;
    let prior = super::PriorAttempt::parse(&bytes)?;
    prior.require_verifiable()?;
    if let Some(expected) = expected {
        prior.require_identity(expected)?;
    }
    Ok(prior)
}

#[cfg(target_os = "macos")]
struct VersionReadback {
    raw: Result<Vec<u8>, String>,
    cleanup: Result<(), String>,
    qualified_lun: Option<u8>,
}

#[cfg(target_os = "macos")]
fn read_verification_version(
    session: Session,
    component: Component,
    cancelled: &mut dyn FnMut() -> bool,
) -> VersionReadback {
    match component {
        Component::Main => match session.main() {
            Ok(mut port) => {
                let (raw, cleanup) = read_with_cleanup(
                    &mut port,
                    MainPort::read_version,
                    MainPort::finish,
                    &mut *cancelled,
                );
                VersionReadback {
                    raw,
                    cleanup,
                    qualified_lun: None,
                }
            }
            Err(error) => VersionReadback {
                raw: Err(error),
                cleanup: Ok(()),
                qualified_lun: None,
            },
        },
        Component::Bluetooth => match session.bluetooth() {
            Ok(mut port) => {
                let qualified_lun = port.qualified_lun();
                let (raw, cleanup) = read_with_cleanup(
                    &mut port,
                    gulikit_platform::macos::BluetoothSession::read_info,
                    BluetoothPort::finish,
                    &mut *cancelled,
                );
                VersionReadback {
                    raw,
                    cleanup,
                    qualified_lun,
                }
            }
            Err(error) => VersionReadback {
                raw: Err(error.error),
                cleanup: if error.cleanup_errors.is_empty() {
                    Ok(())
                } else {
                    Err(error.cleanup_errors.join("; "))
                },
                qualified_lun: None,
            },
        },
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
        let model = match release.model {
            gulikit_core::package::Model::Kk3Max => "kk3-max",
        };
        package["model"].as_str() == Some(model)
            && release.component == component
            && release.version == version
            && package["payload_size"].as_u64() == Some(release.payload_size() as u64)
            && package["payload_sha256"].as_str() == Some(release.payload_sha256())
            && package["archive_sha256"].as_str() == Some(release.archive_sha256)
            && package["member"].as_str() == Some(release.member)
            && package["source_url"].as_str() == Some(release.source_url)
    });
    match prior.get("catalog_entry") {
        Some(Value::Null) | None if recognized => {}
        Some(Value::Null) | None => {
            return Err(
                "Original attempt package metadata is not a recognized reviewed release".into(),
            );
        }
        Some(snapshot) => {
            let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
            let entry = gulikit_catalog::Entry::parse(&bytes).map_err(|error| error.to_string())?;
            let info = gulikit_core::package::catalog_package_info(&entry)
                .map_err(|error| error.to_string())?;
            let expected = serde_json::to_value(info).map_err(|error| error.to_string())?;
            if package != &expected {
                return Err(
                    "Original attempt catalog snapshot does not match package metadata".into(),
                );
            }
        }
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
fn post_cleanup_target(
    original: &gulikit_platform::discovery::NativeCandidate,
    snapshot: &gulikit_platform::discovery::Snapshot,
    confirmed: bool,
) -> Result<gulikit_platform::discovery::NativeCandidate, String> {
    let current = snapshot.select(confirmed, gulikit_core::package::Component::Bluetooth)?;
    if current.ancestor != original.ancestor {
        return Err(
            "The physical attachment changed during cleanup. Confirm and inspect it again.".into(),
        );
    }
    Ok(current)
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
    #[cfg(target_os = "macos")]
    #[test]
    fn replaced_receipt_is_rejected_at_the_pre_session_read_boundary() {
        let mut record = serde_json::json!({
            "event":"attempt_result", "schema_version":1,
            "package":gulikit_core::package::catalog()[2],
            "transfer":{"outcome":"transfer_completed_awaiting_verification", "cleanup_errors":[]},
            "target":{"generation":7}
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.jsonl");
        let persist = |record| {
            let mut file = std::fs::File::create(&path).unwrap();
            gulikit_platform::journal::finalize_record(&mut file, record)
        };
        persist(record.clone());
        let opened = read_verification_receipt(&path, None).unwrap().identity();
        record["package"] = serde_json::to_value(&gulikit_core::package::catalog()[0]).unwrap();
        persist(record);
        let error = read_verification_receipt(&path, Some(&opened)).unwrap_err();
        assert_eq!(
            error.message,
            "Attempt record changed since selection. Keep the controller unchanged; verification requires the original record."
        );
        // This production boundary returns before Session::open; the test never
        // creates a controller session or verification output record.
    }

    #[test]
    fn probe_attachment_is_refreshed_after_cleanup_without_adopting_a_new_physical_unit() {
        use gulikit_platform::discovery::{NativeCandidate, Snapshot};
        let original:NativeCandidate=serde_json::from_value(serde_json::json!({"ancestor":42,"generation":7,"main_volume_candidate":false,"bluetooth_transport_candidate":true,"observed_profile":true,"conflicting_model":false,"storage_identities":[],"disks":[],"mount":null})).unwrap();
        let mut current = original.clone();
        current.generation = 8;
        assert_eq!(
            post_cleanup_target(
                &original,
                &Snapshot {
                    candidates: vec![current.clone()],
                    incomplete: vec![]
                },
                true
            )
            .unwrap(),
            current
        );
        let mut replaced = current.clone();
        replaced.ancestor = 43;
        for snapshot in [
            Snapshot {
                candidates: vec![replaced.clone()],
                incomplete: vec![],
            },
            Snapshot {
                candidates: vec![current.clone(), replaced],
                incomplete: vec![],
            },
            Snapshot {
                candidates: vec![],
                incomplete: vec![],
            },
            Snapshot {
                candidates: vec![current.clone()],
                incomplete: vec!["discovery pending".into()],
            },
        ] {
            assert!(post_cleanup_target(&original, &snapshot, true).is_err());
        }
        assert!(
            post_cleanup_target(
                &original,
                &Snapshot {
                    candidates: vec![current],
                    incomplete: vec![]
                },
                false
            )
            .is_err()
        );
    }

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
            ("member", serde_json::json!("other.bin")),
            (
                "source_url",
                serde_json::json!("https://example.invalid/other.zip"),
            ),
            ("payload_size", serde_json::json!(-1)),
            ("payload_size", serde_json::json!("51500")),
            ("payload_size", serde_json::json!(51500.0)),
        ] {
            let mut invalid = prior.clone();
            invalid["package"][field] = value;
            assert!(
                attempt_target(&invalid).is_err(),
                "accepted changed {field}"
            );
        }
        for field in [
            "model",
            "component",
            "version",
            "payload_size",
            "payload_sha256",
            "archive_sha256",
            "member",
            "source_url",
        ] {
            let mut invalid = prior.clone();
            invalid["package"].as_object_mut().unwrap().remove(field);
            assert!(
                attempt_target(&invalid).is_err(),
                "accepted missing {field}"
            );
            invalid["package"][field] = serde_json::json!(["wrong type"]);
            assert!(
                attempt_target(&invalid).is_err(),
                "accepted mistyped {field}"
            );
        }
    }

    #[test]
    fn catalog_snapshot_supports_historical_metadata_but_never_falls_back_when_present() {
        let mut raw: Value =
            serde_json::from_slice(include_bytes!("../../catalog/official.json")).unwrap();
        let entry_value = &mut raw["entries"][2];
        entry_value["version"] = "3.25".into();
        let entry_bytes = serde_json::to_vec(entry_value).unwrap();
        let entry = gulikit_catalog::Entry::parse(&entry_bytes).unwrap();
        let package = gulikit_core::package::catalog_package_info(&entry).unwrap();
        assert_eq!(package.version, "3.25");
        assert!(!gulikit_core::package::catalog().iter().any(|release| {
            release.component == package.component && release.version == package.version
        }));

        let mut prior = serde_json::json!({
            "event":"attempt_result",
            "package":package,
            "catalog_entry":entry,
            "transfer":{"outcome":"transfer_completed_awaiting_verification"},
            "target":{"generation":7}
        });
        assert_eq!(
            attempt_target(&prior).unwrap(),
            (gulikit_core::package::Component::Bluetooth, "3.25".into())
        );

        prior["package"]["archive_sha256"] = "0".repeat(64).into();
        assert!(
            attempt_target(&prior).is_err(),
            "package metadata tampering"
        );

        prior["package"] =
            serde_json::to_value(gulikit_core::package::catalog_package_info(&entry).unwrap())
                .unwrap();
        prior["catalog_entry"]["version"] = "3.26".into();
        assert!(attempt_target(&prior).is_err(), "snapshot tampering");

        prior["package"] =
            serde_json::to_value(gulikit_core::package::catalog_package_info(&entry).unwrap())
                .unwrap();
        prior["catalog_entry"] = serde_json::json!({"component":"bluetooth"});
        assert!(attempt_target(&prior).is_err(), "incomplete snapshot");

        prior["package"] = serde_json::to_value(&gulikit_core::package::catalog()[2]).unwrap();
        prior["catalog_entry"] = serde_json::json!({"malformed":true});
        assert!(
            attempt_target(&prior).is_err(),
            "malformed present snapshot cannot fall back"
        );
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
