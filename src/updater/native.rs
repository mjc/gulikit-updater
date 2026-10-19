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
#[derive(Default)]
pub(super) struct Interactive {
    inspected: Option<gulikit_platform::macos::BluetoothSession>,
}

#[cfg(target_os = "macos")]
impl Drop for Interactive {
    fn drop(&mut self) {
        if let Some(port) = self.inspected.take() {
            port.surrender();
        }
    }
}

#[cfg(target_os = "macos")]
impl Interactive {
    pub(super) fn execute(
        &mut self,
        request: Request,
        cancelled: &mut dyn FnMut() -> bool,
        progress: &mut dyn FnMut(gulikit_core::update::Progress),
    ) -> Result<Value, AppError> {
        match request {
            Request::Probe {
                component: Component::Bluetooth,
                confirm_ns39,
            } => {
                let (port, raw) = inspect_retaining_port(
                    &mut self.inspected,
                    || Ok(Session::open(confirm_ns39, Component::Bluetooth)?.bluetooth()?),
                    |port| {
                        let raw = port.read_info()?;
                        bluetooth_info(&raw).map_err(|error| error.to_string())?;
                        Ok(raw)
                    },
                    BluetoothPort::finish,
                    cancelled,
                )?;
                let version = bluetooth_info(&raw).map_err(|error| error.to_string())?;
                let value = json!({"component":Component::Bluetooth,"installed_version":version.to_string(),"raw_version_bytes":raw,"qualified_bot_lun":port.qualified_lun(),"cleanup_errors":[],"target":port.target(),"identity_provenance":super::IDENTITY_PROVENANCE});
                Ok(value)
            }
            Request::Update {
                package,
                confirm_ns39: _,
                record,
                expected_attachment,
                policy,
                ..
            } if package.info().component == Component::Bluetooth => {
                let (port, (target, mut journal)) =
                    prepare_retained_port(&mut self.inspected, |port| {
                        let target = port.target().clone();
                        check_attachment(expected_attachment, &target)?;
                        port.check_session()?;
                        let mut journal = port.create_record(&record).map_err(AppError::host_io)?;
                        start_attempt(&mut journal, &target, package.info(), policy)?;
                        Ok((target, journal))
                    })?;
                let result = update_bluetooth_with_progress(
                    &mut Recorded::new(port, &mut journal),
                    &package,
                    policy,
                    cancelled,
                    progress,
                );
                Ok(finish_attempt(
                    &mut journal,
                    &target,
                    package.info(),
                    &result,
                ))
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
                &mut self.inspected,
            ),
            request => {
                self.inspected = None;
                super::execute_frontend(request, cancelled, progress)
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn start_attempt(
    journal: &mut std::fs::File,
    target: &gulikit_platform::discovery::NativeCandidate,
    package: &gulikit_core::package::PackageInfo,
    policy: gulikit_core::version::VersionPolicy,
) -> Result<(), AppError> {
    write_event(journal, &json!({"event":"attempt_started","schema_version":1,"version_policy":policy,"target":target,"package":package,"identity_provenance":super::IDENTITY_PROVENANCE,"post_restart_association":"pending; no USB serial is available"})).map_err(AppError::host_io)
}

#[cfg(target_os = "macos")]
fn finish_attempt(
    journal: &mut std::fs::File,
    target: &gulikit_platform::discovery::NativeCandidate,
    package: &gulikit_core::package::PackageInfo,
    result: &TransferRecord,
) -> Value {
    let action = super::operator_action(package.component, result.outcome);
    finalize_record(
        journal,
        json!({"event":"attempt_result","schema_version":1,"target":target,"package":package,"transfer":result,"operator_action":action}),
    )
}

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
            ..
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
            start_attempt(&mut journal, &target, package.info(), policy)?;
            let result =
                transfer_package(session, &package, policy, &mut journal, cancelled, progress);
            Ok(finish_attempt(
                &mut journal,
                &target,
                package.info(),
                &result,
            ))
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
            &mut None,
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
            let port = Session::open(confirm_ns39, Component::Bluetooth)?.bluetooth()?;
            let target = port.target().clone();
            let VersionReadback {
                raw,
                cleanup,
                qualified_lun,
            } = read_bluetooth_version(port, cancelled);
            let cleanup_errors: Vec<_> = cleanup.err().into_iter().collect();
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
            (target, raw, version, qualified_lun, cleanup_errors)
        }
    };
    Ok(
        json!({"component":component,"installed_version":version,"raw_version_bytes":raw,"qualified_bot_lun":qualified_lun,"cleanup_errors":cleanup_errors,"target":target,"identity_provenance":super::IDENTITY_PROVENANCE}),
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
    retained: &mut Option<gulikit_platform::macos::BluetoothSession>,
) -> Result<Value, AppError> {
    let prior = read_verification_receipt(attempt, expected_receipt)?;
    let component = prior.component;
    let expected_version = prior.expected_version;
    let previous = prior.outcome;
    let generation = prior.generation;
    let prior = prior.record;
    let retained = prepare_retained_verification(
        retained,
        component,
        BluetoothPort::check_session,
        |port| {
            let target = port.target().clone();
            let mut journal = port.create_record(record).map_err(AppError::host_io)?;
            start_verification(
                &mut journal,
                attempt,
                &prior,
                &target,
                confirm_same_controller,
            )?;
            Ok((target, journal))
        },
        gulikit_platform::macos::BluetoothSession::surrender,
    )?;
    let (target, mut journal, readback) = if let Some((port, (target, journal))) = retained {
        (target, journal, read_bluetooth_version(port, cancelled))
    } else {
        let mut session = Session::open(confirm_ns39, component)?;
        let target = session.target.clone();
        let mut journal = session.create_record(record).map_err(AppError::host_io)?;
        start_verification(
            &mut journal,
            attempt,
            &prior,
            &target,
            confirm_same_controller,
        )?;
        (
            target,
            journal,
            read_verification_version(session, component, cancelled),
        )
    };
    let VersionReadback {
        raw: readback,
        cleanup,
        qualified_lun,
    } = readback;
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
                model_confirmed: confirm_ns39 || target.has_known_usb_ids(component),
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

#[cfg(any(target_os = "macos", test))]
fn prepare_retained_verification<P, T>(
    retained: &mut Option<P>,
    component: gulikit_core::package::Component,
    mut check_session: impl FnMut(&mut P) -> Result<(), String>,
    prepare: impl FnOnce(&mut P) -> Result<T, super::ApplicationError>,
    surrender: impl FnOnce(P),
) -> Result<Option<(P, T)>, super::ApplicationError> {
    if component != gulikit_core::package::Component::Bluetooth {
        if let Some(port) = retained.take() {
            surrender(port);
        }
        return Ok(None);
    }

    let Some(port) = retained.as_mut() else {
        return Ok(None);
    };
    if check_session(port).is_err() {
        if let Some(port) = retained.take() {
            surrender(port);
        }
        return Ok(None);
    }

    prepare_retained_port(retained, prepare).map(Some)
}

#[cfg(target_os = "macos")]
fn start_verification(
    journal: &mut std::fs::File,
    attempt: &std::path::Path,
    prior: &Value,
    target: &gulikit_platform::discovery::NativeCandidate,
    same_controller: bool,
) -> Result<(), AppError> {
    write_event(
        journal,
        &json!({
            "event": "verification_started", "schema_version": 1,
            "source_attempt": record_path(attempt), "prior_result": prior, "target": target,
            "same_unit_association": super::same_unit_association(same_controller)
        }),
    )
    .map_err(AppError::host_io)
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
            Ok(port) => read_bluetooth_version(port, cancelled),
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

#[cfg(target_os = "macos")]
fn read_bluetooth_version(
    mut port: gulikit_platform::macos::BluetoothSession,
    cancelled: &mut dyn FnMut() -> bool,
) -> VersionReadback {
    let qualified_lun = port.qualified_lun();
    let (raw, cleanup) = read_with_cleanup(
        &mut port,
        gulikit_platform::macos::BluetoothSession::read_info,
        BluetoothPort::finish,
        cancelled,
    );
    VersionReadback {
        raw,
        cleanup,
        qualified_lun,
    }
}

pub(super) fn attempt_target(
    prior: &Value,
) -> Result<(gulikit_core::package::Component, String), String> {
    let package = &prior["package"];
    // A receipt may request observation of its original target, never a transfer.
    // A malformed snapshot must not fall back to legacy compiled admission.
    if package.get("archive_selection").is_some() {
        let info: gulikit_core::package::PackageInfo = serde_json::from_value(package.clone())
            .map_err(|error| format!("Invalid original archive package: {error}"))?;
        let selection = info
            .archive_selection
            .as_ref()
            .ok_or("Missing original archive selection")?;
        if !info.matches_archive_selection(selection) {
            return Err("Original attempt package disagrees with its archive selection".into());
        }
        return Ok((info.component, info.version));
    }
    let component = prior["package"]["component"]
        .as_str()
        .ok_or("Missing component")?
        .parse::<gulikit_core::package::Component>()
        .map_err(|e| e.to_string())?;
    let version = prior["package"]["version"]
        .as_str()
        .ok_or("Missing package version")?;
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
fn prepare_retained_port<P, T>(
    retained: &mut Option<P>,
    prepare: impl FnOnce(&mut P) -> Result<T, super::ApplicationError>,
) -> Result<(P, T), super::ApplicationError> {
    let prepared = prepare(
        retained
            .as_mut()
            .ok_or("Inspect Bluetooth before continuing.")?,
    )?;
    let port = retained
        .take()
        .ok_or("Inspected USB session is unavailable.")?;
    Ok((port, prepared))
}

#[cfg(any(target_os = "macos", test))]
fn inspect_retaining_port<P>(
    retained: &mut Option<P>,
    open: impl FnOnce() -> Result<P, super::ApplicationError>,
    read: impl FnOnce(&mut P) -> Result<Vec<u8>, String>,
    finish: impl FnOnce(&mut P) -> Result<(), String>,
    cancelled: impl FnMut() -> bool,
) -> Result<(&mut P, Vec<u8>), super::ApplicationError> {
    let port = match retained.take() {
        Some(port) => port,
        None => open()?,
    };
    let (port, raw) = read_for_interactive_inspection(port, read, finish, cancelled)?;
    Ok((retained.insert(port), raw))
}

#[cfg(any(target_os = "macos", test))]
fn read_for_interactive_inspection<P>(
    mut port: P,
    read: impl FnOnce(&mut P) -> Result<Vec<u8>, String>,
    finish: impl FnOnce(&mut P) -> Result<(), String>,
    mut cancelled: impl FnMut() -> bool,
) -> Result<(P, Vec<u8>), super::ApplicationError> {
    let raw = read_version(&mut port, read, &mut cancelled);
    match raw {
        Ok(raw) => Ok((port, raw)),
        Err(error) => {
            let errors = finish(&mut port).err().into_iter().collect();
            Err(super::ApplicationError::from(error).with_cleanup(errors))
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn read_with_cleanup<P>(
    port: &mut P,
    read: impl FnOnce(&mut P) -> Result<Vec<u8>, String>,
    finish: impl FnOnce(&mut P) -> Result<(), String>,
    mut cancelled: impl FnMut() -> bool,
) -> (Result<Vec<u8>, String>, Result<(), String>) {
    let result = read_version(port, read, &mut cancelled);
    let cleanup = finish(port);
    (result, cleanup)
}

#[cfg(any(target_os = "macos", test))]
fn read_version<P>(
    port: &mut P,
    read: impl FnOnce(&mut P) -> Result<Vec<u8>, String>,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, String> {
    if cancelled() {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct RetainedSession {
        live: bool,
    }

    fn check_fake_session(session: &mut RetainedSession) -> Result<(), String> {
        if session.live {
            Ok(())
        } else {
            Err("USB topology changed".into())
        }
    }

    #[test]
    fn main_verification_releases_unrelated_bluetooth_session_for_fresh_open() {
        let mut retained = Some(RetainedSession { live: true });
        let mut released = false;
        let prepared = prepare_retained_verification::<_, ()>(
            &mut retained,
            gulikit_core::package::Component::Main,
            |_| panic!("Main verification must not validate a retained Bluetooth session"),
            |_| panic!("Main verification must use a fresh Main session"),
            |_| released = true,
        )
        .unwrap();

        assert!(prepared.is_none(), "None selects the fresh session path");
        assert!(retained.is_none());
        assert!(released, "the retained claim is surrendered without reset");
    }

    #[test]
    fn stale_bluetooth_session_is_released_for_fresh_verification() {
        let mut retained = Some(RetainedSession { live: false });
        let mut released = false;
        let prepared = prepare_retained_verification::<_, ()>(
            &mut retained,
            gulikit_core::package::Component::Bluetooth,
            check_fake_session,
            |_| panic!("stale session must not create a verification record"),
            |_| released = true,
        )
        .unwrap();

        assert!(prepared.is_none(), "None selects fresh discovery/session");
        assert!(retained.is_none());
        assert!(released, "stale capture must be surrendered");
    }

    #[test]
    fn session_invalidated_during_record_preparation_preserves_original_error() {
        let mut retained = Some(RetainedSession { live: true });
        let mut released = false;
        let error = prepare_retained_verification::<_, ()>(
            &mut retained,
            gulikit_core::package::Component::Bluetooth,
            check_fake_session,
            |session| {
                session.live = false;
                Err(super::super::ApplicationError::host_io(
                    "USB topology changed while creating the record".into(),
                ))
            },
            |_| released = true,
        )
        .unwrap_err();

        assert_eq!(
            error.message,
            "USB topology changed while creating the record"
        );
        assert!(retained.as_ref().is_some_and(|session| !session.live));
        assert!(!released, "do not hide the failed record preparation");

        let prepared = prepare_retained_verification::<_, ()>(
            &mut retained,
            gulikit_core::package::Component::Bluetooth,
            check_fake_session,
            |_| panic!("stale session must be released before another record is created"),
            |_| released = true,
        )
        .unwrap();

        assert!(prepared.is_none(), "retry selects a fresh session");
        assert!(retained.is_none());
        assert!(released);
    }

    #[test]
    fn live_bluetooth_session_survives_host_record_failure_for_retry() {
        let mut retained = Some(RetainedSession { live: true });
        let mut released = false;
        let error = prepare_retained_verification::<_, ()>(
            &mut retained,
            gulikit_core::package::Component::Bluetooth,
            check_fake_session,
            |_| {
                Err(super::super::ApplicationError::host_io(
                    "record path unavailable".into(),
                ))
            },
            |_| released = true,
        )
        .unwrap_err();

        assert_eq!(error.message, "record path unavailable");
        assert!(retained.as_ref().is_some_and(|session| session.live));
        assert!(!released, "a healthy inspected session remains retryable");
    }

    #[test]
    fn failed_host_preparation_keeps_the_inspected_port_for_a_corrected_record_path() {
        let mut retained = Some(vec!["inspected"]);
        let error = prepare_retained_port(&mut retained, |events| {
            events.push("host record refused");
            Err::<(), _>(super::super::ApplicationError::host_io(
                "record exists".into(),
            ))
        })
        .unwrap_err();
        assert_eq!(error.message, "record exists");
        assert_eq!(
            retained.as_ref().unwrap(),
            &["inspected", "host record refused"]
        );
        let (port, record) = prepare_retained_port(&mut retained, |events| {
            events.push("host record created");
            Ok("new record")
        })
        .unwrap();
        assert_eq!(record, "new record");
        assert_eq!(
            port,
            ["inspected", "host record refused", "host record created"]
        );
        assert!(retained.is_none());
    }
    #[test]
    fn inspecting_again_reads_the_owned_port_without_reopening_or_resetting() {
        let mut retained = None;
        inspect_retaining_port(
            &mut retained,
            || Ok(vec!["open"]),
            |events| {
                events.push("read");
                Ok(vec![1])
            },
            |_| panic!("successful inspection must retain its claim"),
            || false,
        )
        .unwrap();
        let (port, _) = inspect_retaining_port(
            &mut retained,
            || panic!("Inspect again must not reacquire the USB device"),
            |events| {
                events.push("read");
                Ok(vec![1])
            },
            |_| panic!("successful reinspection must not reset"),
            || false,
        )
        .unwrap();
        assert_eq!(port, &["open", "read", "read"]);
    }
    #[test]
    fn interactive_inspection_retains_the_live_port_without_resetting_it() {
        let (port, raw) = read_for_interactive_inspection(
            Vec::new(),
            |events| {
                events.push("read");
                Ok(vec![1, 2, 3])
            },
            |events| {
                events.push("reset");
                Ok(())
            },
            || false,
        )
        .unwrap();
        assert_eq!(raw, [1, 2, 3]);
        assert_eq!(port, ["read"]);
    }

    #[test]
    fn failed_or_cancelled_interactive_inspection_releases_its_claim() {
        for (cancel_before, cancel_during, fail_read) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            let mut events = Vec::new();
            let cancelled = std::cell::Cell::new(cancel_before);
            let error = read_for_interactive_inspection(
                &mut events,
                |events| {
                    events.push("read");
                    cancelled.set(cancel_during);
                    if fail_read {
                        Err("F1 failed".into())
                    } else {
                        Ok(vec![1])
                    }
                },
                |events| {
                    events.push("finish");
                    Err("restoration failed".into())
                },
                || cancelled.get(),
            )
            .unwrap_err();
            assert_eq!(error.cleanup_errors, ["restoration failed"]);
            assert_eq!(
                events,
                if cancel_before {
                    vec!["finish"]
                } else {
                    vec!["read", "finish"]
                }
            );
            assert!(
                error
                    .message
                    .contains(if fail_read { "F1 failed" } else { "Cancelled" })
            );
        }
    }
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
    fn archive_receipts_use_the_original_snapshot_and_reject_inconsistent_metadata() {
        use gulikit_core::package::{
            ArchiveParserKind, ArchiveSelection, ArchiveSelectionData, Component, Model,
            PackageInfo,
        };
        let selection = ArchiveSelection::try_from(ArchiveSelectionData {
            archive_revision: "a".repeat(40),
            path: "/kk3-max/base/v3.1/GuliKit_NS39_V3.1.zip".into(),
            component: Component::Main,
            version: "3.1".into(),
            archive: "GuliKit_NS39_V3.1.zip".into(),
            archive_size: 100_000,
            archive_sha256: "b".repeat(64),
            firmware_member: "GuliKit_NS39_V3.1.bin".into(),
            member_size: 43_140,
            member_sha256: "c".repeat(64),
            payload_size: 43_140,
            payload_sha256: "c".repeat(64),
            source_url: "https://www.gulikit.com/newsinfo/887152.html".into(),
            parser: ArchiveParserKind::MainBinV1,
        })
        .unwrap();
        let data = selection.data();
        let package = PackageInfo {
            model: Model::Kk3Max,
            component: data.component,
            version: data.version.clone(),
            payload_size: 43_140,
            payload_sha256: data.payload_sha256.clone(),
            archive_sha256: data.archive_sha256.clone(),
            source_url: data.source_url.clone(),
            member: data.firmware_member.clone(),
            archive_selection: Some(selection),
        };
        let prior = serde_json::json!({"package":package});
        assert_eq!(
            attempt_target(&prior).unwrap(),
            (Component::Main, "3.1".into())
        );
        for (field, value) in [
            ("version", serde_json::json!("3.2")),
            ("payload_size", serde_json::json!(1)),
            ("payload_sha256", serde_json::json!("d".repeat(64))),
            ("archive_sha256", serde_json::json!("d".repeat(64))),
            ("member", serde_json::json!("other.bin")),
            (
                "source_url",
                serde_json::json!("https://example.com/changed"),
            ),
            ("archive_selection", Value::Null),
            ("archive_selection", serde_json::json!({})),
        ] {
            let mut changed = prior.clone();
            changed["package"][field] = value;
            assert!(
                attempt_target(&changed).is_err(),
                "accepted changed {field}"
            );
        }
        let mut malformed = prior;
        malformed["package"]["archive_selection"]["path"] = "/other.zip".into();
        assert!(attempt_target(&malformed).is_err());
    }

    #[test]
    fn malformed_archive_snapshot_never_falls_back_to_a_compiled_release() {
        let prior = serde_json::json!({"package":gulikit_core::package::catalog()[0]});
        assert!(attempt_target(&prior).is_ok());
        for snapshot in [Value::Null, serde_json::json!({}), serde_json::json!(false)] {
            let mut changed = prior.clone();
            changed["package"]["archive_selection"] = snapshot;
            assert!(attempt_target(&changed).is_err());
        }
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
