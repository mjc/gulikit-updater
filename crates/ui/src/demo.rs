//! An in-memory device. The shared UI controller owns selection, transfer and verification states.
use crate::{
    backend::Device,
    live::{Event, Work},
};
use gulikit_core::{
    package::{Component, Model, PackageInfo, catalog},
    update::{Outcome, Progress, TransferRecord, Verification, verify_restart},
    version::{BT_SIGNATURE, MainVersion, VersionDecision, VersionPolicy, bluetooth_info},
};
use gulikit_platform::discovery::NativeCandidate;
use gulikit_updater::updater::{
    self, Attachment, Attempt, Inspection, PriorAttempt, Readback, ReceiptIdentity,
    VerificationTransfer,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Default)]
pub enum Profile {
    #[default]
    Normal,
    Current,
    Newer,
    IdentityFailure,
    TransferFailure,
    VerificationFailure,
    UnknownVersion,
}
#[derive(Clone, Copy, Debug)]
pub enum SamplePackage {
    Matching,
    WrongModel,
    WrongComponent,
    LongFilename,
}

pub struct DemoDevice {
    profile: Profile,
    generation: u64,
    versions: [&'static str; 2],
    selected: Option<(PathBuf, PackageInfo)>,
    attempt: Option<(PathBuf, PriorAttempt)>,
    wait: Box<dyn FnMut(Duration) + Send>,
}
impl Default for DemoDevice {
    fn default() -> Self {
        Self::with_transfer_wait(std::thread::sleep)
    }
}
impl DemoDevice {
    /// Supply a controlled wait for deterministic tests of transfer and cancellation.
    pub fn with_transfer_wait(wait: impl FnMut(Duration) + Send + 'static) -> Self {
        Self {
            profile: Profile::Normal,
            generation: 7,
            versions: ["5.8", "5.06"],
            selected: None,
            attempt: None,
            wait: Box::new(wait),
        }
    }
}
fn index(component: Component) -> usize {
    match component {
        Component::Main => 0,
        Component::Bluetooth => 1,
    }
}
fn release(component: Component) -> &'static gulikit_core::package::Release {
    catalog()
        .iter()
        .find(|r| r.model == Model::Kk3Max && r.component == component)
        .expect("supported demo component")
}
impl DemoDevice {
    fn target(&self) -> NativeCandidate {
        NativeCandidate {
            ancestor: 42,
            generation: self.generation,
            main_volume_candidate: true,
            bluetooth_transport_candidate: true,
            observed_profile: true,
            conflicting_model: false,
            storage_identities: vec![],
            disks: vec![],
            mount: None,
        }
    }
    fn observe(&self, component: Component, confirmed: bool) -> Result<Inspection, String> {
        if !confirmed {
            return Err("NS39 identity not confirmed. Writing refused.".into());
        }
        match self.profile {
            Profile::IdentityFailure => {
                return Err("NS39 identity not confirmed. Writing refused.".into());
            }
            Profile::UnknownVersion => {
                return Err("Unknown installed version. Writing refused.".into());
            }
            _ => {}
        }
        let version = self.versions[index(component)];
        let (raw, decision) = match component {
            Component::Main => {
                let raw = format!("www.gulikit.com\nversion {version}\n").into_bytes();
                let decision = MainVersion::parse(&raw)
                    .map_err(|e| e.to_string())?
                    .decision();
                (raw, decision)
            }
            Component::Bluetooth => {
                let mut raw = BT_SIGNATURE.to_vec();
                let number: u16 = version
                    .replace('.', "")
                    .parse()
                    .map_err(|_| "Invalid simulated version")?;
                raw.extend(number.to_le_bytes());
                raw.extend([0, 0]);
                let decision = bluetooth_info(&raw).map_err(|e| e.to_string())?.decision();
                (raw, decision)
            }
        };
        Ok(Inspection {
            component,
            installed_version: version.into(),
            decision,
            raw_version_bytes: raw,
            qualified_bot_lun: (component == Component::Bluetooth).then_some(0),
            cleanup_errors: vec![],
            target: self.target(),
            identity_provenance: "simulated NS39",
        })
    }
    fn select(&mut self, component: Component, sample: SamplePackage) -> Result<Event, String> {
        let release = release(component);
        let name = match sample {
            SamplePackage::WrongModel | SamplePackage::WrongComponent => {
                self.selected = None;
                return Err("Package does not match this controller component.".into());
            }
            SamplePackage::LongFilename => format!(
                "GuliKit_KK3_MAX_NS39_official_firmware_backup_downloaded_2026-10-17_{}",
                release.archive
            ),
            SamplePackage::Matching => release.archive.into(),
        };
        let path = PathBuf::from(name);
        let info = PackageInfo {
            model: Model::Kk3Max,
            component,
            version: release.version.into(),
            payload_size: if component == Component::Main {
                51_500
            } else {
                345_088
            },
            payload_sha256: "simulated payload; no firmware bytes".into(),
            archive_sha256: release.archive_sha256.into(),
            source_url: release.source_url.to_owned(),
            member: release.member.to_owned(),
        };
        self.selected = Some((path.clone(), info.clone()));
        Ok(Event::Package { path, info })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "The demo checks each typed Update request field before simulating I/O."
    )]
    fn transfer(
        &mut self,
        path: &Path,
        component: Component,
        attachment: Attachment,
        confirmed: bool,
        policy: VersionPolicy,
        cancelled: &AtomicBool,
        emit: &mut dyn FnMut(Event),
    ) -> Result<Event, String> {
        updater::check_attachment(Some(attachment), &self.target())?;
        let observed = self.observe(component, confirmed)?;
        let (_, package) = self
            .selected
            .as_ref()
            .filter(|(selected, info)| selected.as_path() == path && info.component == component)
            .ok_or("Select a simulated package first")?;
        if package
            .decision_for_installed(&observed.installed_version, policy)
            .map_err(|error| error.to_string())?
            != VersionDecision::Eligible
        {
            return Err(
                "Installed version does not permit an update under the selected policy.".into(),
            );
        }
        let mut transfer = simulate_transfer(
            package.payload_size,
            self.profile,
            &mut self.wait,
            cancelled,
            emit,
        );
        transfer.version_policy = policy;
        if transfer.outcome == Outcome::TransferCompletedAwaitingVerification {
            self.versions[index(component)] = match self.profile {
                Profile::VerificationFailure => self.versions[index(component)],
                _ => release(component).version,
            };
        }
        let result = Attempt {
            event: "attempt_result",
            schema_version: 1,
            record_finalized: true,
            target: self.target(),
            package: package.clone(),
            catalog_entry: None,
            operator_action: updater::operator_action(component, transfer.outcome),
            transfer,
        };
        self.record_attempt(result)
    }
    fn record_attempt(&mut self, result: Attempt) -> Result<Event, String> {
        let record = PathBuf::from(format!("demo-attempt-{}.jsonl", self.generation));
        self.attempt = Some((
            record.clone(),
            PriorAttempt {
                component: result.package.component,
                outcome: result.transfer.outcome,
                generation: self.generation,
                record: serde_json::to_value(&result).map_err(|e| e.to_string())?,
                expected_version: result.package.version.clone(),
            },
        ));
        Ok(Event::Transferred { record, result })
    }
    fn verify(
        &mut self,
        path: PathBuf,
        confirmed: bool,
        same_controller: bool,
        expected_receipt: &ReceiptIdentity,
    ) -> Result<Event, String> {
        let (_, attempt) = self
            .attempt
            .as_ref()
            .filter(|(record, _)| *record == path)
            .ok_or("No matching simulated attempt")?;
        attempt.require_verifiable()?;
        attempt.require_identity(expected_receipt)?;
        // A new simulated attachment models the user's explicit reconnect in demo mode.
        self.generation += 1;
        let read = self.observe(attempt.component, confirmed)?;
        let observation = Verification {
            component: attempt.component,
            previous_generation: attempt.generation,
            generation: self.generation,
            same_unit_confirmed: same_controller,
            model_confirmed: confirmed,
            version: read.installed_version,
            expected_version: attempt.expected_version.clone(),
        };
        let outcome = verify_restart(attempt.outcome, &observation);
        Ok(Event::Verified(Readback {
            event: "verification_result",
            schema_version: 1,
            source_attempt: path,
            verification: Some(observation),
            raw_version_bytes: Some(read.raw_version_bytes),
            qualified_bot_lun: read.qualified_bot_lun,
            target: read.target,
            same_unit_association: "simulated same controller",
            transfer: VerificationTransfer {
                outcome,
                error: None,
                cleanup_errors: vec![],
            },
        }))
    }
}
fn simulate_transfer(
    total: usize,
    profile: Profile,
    wait: &mut dyn FnMut(Duration),
    cancelled: &AtomicBool,
    emit: &mut dyn FnMut(Event),
) -> TransferRecord {
    let mut transfer = TransferRecord::default();
    let step = total.div_ceil(32);
    for confirmed in (0..total)
        .step_by(step)
        .map(|offset| (offset + step).min(total))
    {
        let connection_lost = match profile {
            Profile::TransferFailure => transfer.bytes_submitted > 0,
            _ => false,
        };
        if cancelled.load(Ordering::Acquire) || connection_lost {
            transfer.outcome = Outcome::OutcomeUnknown;
            transfer.error = Some("Simulated connection loss after possible submission.".into());
            break;
        }
        transfer.bytes_submitted = confirmed;
        transfer.bytes_confirmed = confirmed;
        emit(Event::Progress(Progress {
            submitted: confirmed,
            confirmed,
            total,
        }));
        wait(Duration::from_millis(80));
    }
    if transfer.bytes_confirmed == total {
        transfer.outcome = Outcome::TransferCompletedAwaitingVerification;
    }
    transfer
}

impl Device for DemoDevice {
    fn run(
        &mut self,
        work: Work,
        cancelled: &AtomicBool,
        emit: &mut dyn FnMut(Event),
    ) -> Result<Event, String> {
        if cancelled.load(Ordering::Acquire) {
            return Ok(Event::Cancelled);
        }
        match work {
            Work::Inspect {
                component,
                confirmed,
            } => self.observe(component, confirmed).map(Event::Inspected),
            Work::ChoosePackage(component) => self.select(component, SamplePackage::Matching),
            Work::ChooseSample { component, sample } => self.select(component, sample),
            Work::ImportRelease(_)
            | Work::OpenSource(_)
            | Work::OpenChangelog(_)
            | Work::DownloadRelease(_) => {
                Err("Catalog actions are unavailable in simulated mode.".into())
            }
            Work::ConfigureDemo(profile) => {
                self.profile = profile;
                self.selected = None;
                self.attempt = None;
                self.generation += 1;
                self.versions = match profile {
                    Profile::Current => ["5.9", "5.07"],
                    Profile::Newer => ["6.0", "6.00"],
                    _ => ["5.8", "5.06"],
                };
                self.observe(Component::Main, true).map(Event::Inspected)
            }
            Work::Update {
                path,
                component,
                attachment,
                confirmed,
                policy,
            } => self.transfer(
                &path, component, attachment, confirmed, policy, cancelled, emit,
            ),
            Work::Verify {
                attempt,
                confirmed,
                same_controller,
                expected_receipt,
            } => self.verify(attempt, confirmed, same_controller, &expected_receipt),
            Work::OpenAttempt => {
                let (path, result) = self
                    .attempt
                    .as_ref()
                    .ok_or("No simulated attempt recorded")?;
                Ok(Event::Prior {
                    path: path.clone(),
                    prior: PriorAttempt {
                        component: result.component,
                        outcome: result.outcome,
                        generation: result.generation,
                        record: result.record.clone(),
                        expected_version: result.expected_version.clone(),
                    },
                })
            }
            Work::Shutdown => Ok(Event::Cancelled),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::LiveApp;

    #[test]
    fn changed_receipt_is_rejected_before_simulated_reconnection() {
        for changed_field in ["component", "outcome", "generation", "version"] {
            let mut device = DemoDevice::with_transfer_wait(|_| {});
            let mut app = LiveApp::default();
            let cancelled = AtomicBool::new(false);
            app.confirm_model(true);
            let work = app.connect().unwrap();
            app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
            let work = app.choose_package().unwrap();
            app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
            let work = app.start().unwrap();
            let event = device
                .run(work, &cancelled, &mut |event| app.accept(event))
                .unwrap();
            app.accept(event);
            app.confirm_same_controller(true);
            let verification = app.primary().unwrap();
            let (_, prior) = device.attempt.as_mut().unwrap();
            match changed_field {
                "component" => prior.component = Component::Bluetooth,
                "outcome" => prior.outcome = Outcome::TransferSubmittedPendingCompletion,
                "generation" => prior.generation += 10,
                "version" => prior.expected_version = "5.8".into(),
                _ => unreachable!(),
            }
            let generation = device.generation;
            assert!(
                device.run(verification, &cancelled, &mut |_| {}).is_err(),
                "{changed_field}"
            );
            assert_eq!(device.generation, generation, "{changed_field}");
        }
    }
}
