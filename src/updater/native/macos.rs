use super::super::{ApplicationError as AppError, Request, check_attachment};
use super::{
    inspect_retaining_port, prepare_retained_port, prepare_retained_verification,
    read_verification_receipt, read_with_cleanup, record_path,
};
use gulikit_core::{
    package::Component,
    update::{
        BluetoothPort, MainPort, TransferRecord, Verification, update_bluetooth_with_progress,
        update_main_with_progress, verify_restart,
    },
    version::{MainVersion, bluetooth_info},
};
use gulikit_platform::journal::{
    ReceiptOwner, Recorded, finalize_record, finalize_record_for_owner, write_event,
};
use gulikit_platform::macos::{Session, discover};
use serde_json::Value;
use serde_json::json;

#[derive(Default)]
pub(in crate::updater) struct Interactive {
    inspected: Option<gulikit_platform::macos::BluetoothSession>,
    receipt_owner: Option<ReceiptOwner>,
}

impl Interactive {
    pub(in crate::updater) fn with_receipt_owner(receipt_owner: Option<ReceiptOwner>) -> Self {
        Self {
            inspected: None,
            receipt_owner,
        }
    }
}

impl Drop for Interactive {
    fn drop(&mut self) {
        if let Some(port) = self.inspected.take() {
            port.surrender();
        }
    }
}

impl Interactive {
    pub(in crate::updater) fn execute(
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
                let value = json!({"component":Component::Bluetooth,"installed_version":version.to_string(),"raw_version_bytes":raw,"qualified_bot_lun":port.qualified_lun(),"cleanup_errors":[],"target":port.target(),"identity_provenance":super::super::IDENTITY_PROVENANCE});
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
                    self.receipt_owner,
                ))
            }
            Request::Verify {
                attempt,
                record,
                confirm_ns39,
                confirm_same_controller,
                expected_receipt,
            } => verify_attempt(
                VerifyAttempt {
                    attempt: &attempt,
                    record: &record,
                    confirm_ns39,
                    confirm_same_controller,
                    expected_receipt: expected_receipt.as_ref(),
                },
                cancelled,
                &mut self.inspected,
                self.receipt_owner,
            ),
            request => {
                self.inspected = None;
                super::super::execute_frontend(request, self.receipt_owner, cancelled, progress)
            }
        }
    }
}

fn start_attempt(
    journal: &mut std::fs::File,
    target: &gulikit_platform::discovery::NativeCandidate,
    package: &gulikit_core::package::PackageInfo,
    policy: gulikit_core::version::VersionPolicy,
) -> Result<(), AppError> {
    write_event(journal, &json!({"event":"attempt_started","schema_version":1,"version_policy":policy,"target":target,"package":package,"identity_provenance":super::super::IDENTITY_PROVENANCE,"post_restart_association":"pending; no USB serial is available"})).map_err(AppError::host_io)
}

fn finish_attempt(
    journal: &mut std::fs::File,
    target: &gulikit_platform::discovery::NativeCandidate,
    package: &gulikit_core::package::PackageInfo,
    result: &TransferRecord,
    receipt_owner: Option<ReceiptOwner>,
) -> Value {
    let action = super::super::operator_action(package.component, result.outcome);
    let record = json!({"event":"attempt_result","schema_version":1,"target":target,"package":package,"transfer":result,"operator_action":action});
    match receipt_owner {
        Some(owner) => finalize_record_for_owner(journal, record, owner),
        None => finalize_record(journal, record),
    }
}

pub(in crate::updater) fn execute(
    request: Request,
    mut main_lease: Option<gulikit_platform::lock::ProcessLock>,
    receipt_owner: Option<ReceiptOwner>,
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
                receipt_owner,
            ))
        }
        Request::Verify {
            attempt,
            record,
            confirm_ns39,
            confirm_same_controller,
            expected_receipt,
        } => verify_attempt(
            VerifyAttempt {
                attempt: &attempt,
                record: &record,
                confirm_ns39,
                confirm_same_controller,
                expected_receipt: expected_receipt.as_ref(),
            },
            cancelled,
            &mut None,
            receipt_owner,
        ),
    }
}

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
        json!({"component":component,"installed_version":version,"raw_version_bytes":raw,"qualified_bot_lun":qualified_lun,"cleanup_errors":cleanup_errors,"target":target,"identity_provenance":super::super::IDENTITY_PROVENANCE}),
    )
}

#[derive(Clone, Copy)]
struct VerifyAttempt<'a> {
    attempt: &'a std::path::Path,
    record: &'a std::path::Path,
    confirm_ns39: bool,
    confirm_same_controller: bool,
    expected_receipt: Option<&'a super::super::ReceiptIdentity>,
}

fn verify_attempt(
    request: VerifyAttempt<'_>,
    cancelled: &mut dyn FnMut() -> bool,
    retained: &mut Option<gulikit_platform::macos::BluetoothSession>,
    receipt_owner: Option<ReceiptOwner>,
) -> Result<Value, AppError> {
    let prior = read_verification_receipt(request.attempt, request.expected_receipt)?;
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
            let mut journal = port
                .create_record(request.record)
                .map_err(AppError::host_io)?;
            start_verification(
                &mut journal,
                request.attempt,
                &prior,
                &target,
                request.confirm_same_controller,
            )?;
            Ok((target, journal))
        },
        gulikit_platform::macos::BluetoothSession::surrender,
    )?;
    let (target, mut journal, readback) = if let Some((port, (target, journal))) = retained {
        (target, journal, read_bluetooth_version(port, cancelled))
    } else {
        let mut session = Session::open(request.confirm_ns39, component)?;
        let target = session.target.clone();
        let mut journal = session
            .create_record(request.record)
            .map_err(AppError::host_io)?;
        start_verification(
            &mut journal,
            request.attempt,
            &prior,
            &target,
            request.confirm_same_controller,
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
                same_unit_confirmed: request.confirm_same_controller,
                model_confirmed: request.confirm_ns39 || target.has_known_usb_ids(component),
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
    let record = json!({
        "event":"verification_result", "schema_version":1,
        "source_attempt":record_path(request.attempt), "verification":observation,
        "raw_version_bytes":raw_version_bytes, "qualified_bot_lun":qualified_lun, "target":target,
        "same_unit_association":super::super::same_unit_association(request.confirm_same_controller),
        "transfer":{"outcome":outcome,"error":error,"cleanup_errors":cleanup_errors}
    });
    Ok(match receipt_owner {
        Some(owner) => finalize_record_for_owner(&mut journal, record, owner),
        None => finalize_record(&mut journal, record),
    })
}

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
            "same_unit_association": super::super::same_unit_association(same_controller)
        }),
    )
    .map_err(AppError::host_io)
}

struct VersionReadback {
    raw: Result<Vec<u8>, String>,
    cleanup: Result<(), String>,
    qualified_lun: Option<u8>,
}

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
