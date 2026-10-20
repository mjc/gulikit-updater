//! UI intents and backend observations; no native I/O runs in this model.
use crate::Page;
use gulikit_core::{
    package::{Component, Model, PackageInfo},
    update::{Outcome, Progress, verify_restart},
    version::{VersionDecision, VersionPolicy},
};
use gulikit_updater::updater::{
    Attachment, Attempt, Inspection, PriorAttempt, Readback, ReceiptIdentity,
};
use std::{borrow::Cow, path::PathBuf};

#[derive(Debug)]
pub enum Work {
    Inspect {
        component: Component,
        confirmed: bool,
    },
    ChoosePackage(Component),
    Update {
        expected_package: PackageInfo,
        policy: VersionPolicy,
        path: PathBuf,
        component: Component,
        attachment: Attachment,
        confirmed: bool,
    },
    Verify {
        attempt: PathBuf,
        confirmed: bool,
        same_controller: bool,
        expected_receipt: ReceiptIdentity,
    },
    OpenAttempt,
    ConfigureDemo(crate::demo::Profile),
    ChooseSample {
        component: Component,
        sample: crate::demo::SamplePackage,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum Event {
    Inspected(Inspection),
    Package { path: PathBuf, info: PackageInfo },
    Transferred { record: PathBuf, result: Attempt },
    Verified(Readback),
    Prior { path: PathBuf, prior: PriorAttempt },
    Progress(Progress),
    Cancelled,
    Error(String),
    WorkerFailed(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Job {
    Inspect,
    Package,
    Transfer,
    Verify,
    Receipt,
}

struct Selected {
    path: PathBuf,
    info: PackageInfo,
    payload_label: String,
}
#[derive(Clone, Copy)]
enum RetryBlock {
    UncertainOutcome,
    MainDestinationCreated,
    RecordNotFinalized,
}

struct Receipt {
    path: PathBuf,
    identity: ReceiptIdentity,
    lifecycle: ReceiptLifecycle,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReceiptLifecycle {
    Pending,
    Verified,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "This borrowed Slint projection exposes independent control states; the model owns the lifecycle invariants."
)]
pub struct View<'a> {
    pub page: Page,
    pub component: Component,
    pub confirmed: bool,
    pub same_controller: bool,
    pub allow_downgrade: bool,
    pub is_downgrade: bool,
    pub can_allow_downgrade: bool,
    pub busy: bool,
    pub connected: bool,
    pub main_version: &'a str,
    pub bt_version: &'a str,
    pub installed: &'a str,
    pub target: &'a str,
    pub filename: Cow<'a, str>,
    pub payload: &'a str,
    pub digest: &'a str,
    pub progress: Progress,
    pub can_update: bool,
    pub can_choose_package: bool,
    pub can_open_attempt: bool,
    pub can_switch_component: bool,
    pub can_troubleshoot: bool,
    pub can_primary: bool,
    pub primary_label: Cow<'a, str>,
    pub notice: &'a str,
    pub log: &'a [String],
}

pub struct LiveApp {
    component: Component,
    confirmed: bool,
    same_controller: bool,
    policy: VersionPolicy,
    page: Page,
    pending: Option<Job>,
    attachment: Option<Attachment>,
    versions: [Option<Inspection>; 2],
    package: Option<Selected>,
    receipt: Option<Receipt>,
    progress: Progress,
    retry_block: Option<RetryBlock>,
    connected: bool,
    notice: String,
    log: Vec<String>,
}
impl Default for LiveApp {
    fn default() -> Self {
        Self {
            component: Component::Main,
            confirmed: false,
            same_controller: false,
            policy: VersionPolicy::UpgradeOnly,
            page: Page::Connect,
            pending: None,
            attachment: None,
            versions: [None, None],
            package: None,
            receipt: None,
            progress: Progress {
                submitted: 0,
                confirmed: 0,
                total: 0,
            },
            retry_block: None,
            connected: false,
            notice: String::new(),
            log: vec![],
        }
    }
}

fn index(component: Component) -> usize {
    match component {
        Component::Main => 0,
        Component::Bluetooth => 1,
    }
}

impl LiveApp {
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.pending.is_some()
    }

    pub fn confirm_model(&mut self, confirmed: bool) {
        if self.pending.is_some() {
            return;
        }
        self.confirmed = confirmed;
        if !confirmed {
            self.policy = VersionPolicy::UpgradeOnly;
            self.attachment = None;
            self.versions = [None, None];
            self.connected = false;
            self.page = if self.retry_block.is_some() {
                Page::Failed
            } else if self.has_unverified_receipt() {
                Page::Restart
            } else {
                Page::Connect
            };
        }
    }
    pub fn confirm_same_controller(&mut self, confirmed: bool) {
        if self.pending.is_none() {
            self.same_controller = confirmed;
        }
    }
    pub fn connect(&mut self) -> Option<Work> {
        if self.pending.is_some() || self.retry_block.is_some() || self.has_unverified_receipt() {
            return None;
        }
        self.receipt = None;
        self.policy = VersionPolicy::UpgradeOnly;
        self.pending = Some(Job::Inspect);
        self.notice = "Reading installed version…".into();
        Some(Work::Inspect {
            component: self.component,
            confirmed: false,
        })
    }
    pub fn select_component(&mut self, component: Component) -> Option<Work> {
        if !self.can_switch_component() || component == self.component {
            return None;
        }
        self.component = component;
        self.policy = VersionPolicy::UpgradeOnly;
        self.confirmed = false;
        self.package = None;
        self.receipt = None;
        self.same_controller = false;
        self.attachment = None;
        self.versions = [None, None];
        self.connected = false;
        self.progress = Progress {
            submitted: 0,
            confirmed: 0,
            total: 0,
        };
        self.page = Page::Connect;
        self.notice = "Main and Bluetooth use different procedures. Exit the current mode before entering the other mode and inspecting again.".into();
        None
    }
    pub fn choose_package(&mut self) -> Option<Work> {
        if !self.can_choose_package() {
            return None;
        }
        self.pending = Some(Job::Package);
        Some(Work::ChoosePackage(self.component))
    }

    /// Select an inspected archive download without opening another file dialog.
    /// Protected transfers and pending restart verification retain their package.
    pub fn use_downloaded_package(&mut self, path: PathBuf, info: PackageInfo) -> bool {
        if !self.can_choose_package()
            || info.model != Model::Kk3Max
            || info.component != self.component
        {
            return false;
        }
        self.policy = VersionPolicy::UpgradeOnly;
        self.selected(path, info);
        true
    }

    /// Change the current, one-attempt permission for an inspected downgrade.
    pub fn set_allow_downgrade(&mut self, allow: bool) {
        if self.pending.is_some() {
            return;
        }
        if !allow {
            self.policy = VersionPolicy::UpgradeOnly;
        } else if self.can_allow_downgrade() {
            self.policy = VersionPolicy::AllowDowngrade;
        }
    }

    /// Remove the previous write candidate when the archive selection changes.
    /// Returns false while a transfer or unresolved receipt protects that candidate.
    pub fn clear_selected_package(&mut self) -> bool {
        if !self.can_choose_package() {
            return false;
        }
        self.policy = VersionPolicy::UpgradeOnly;
        self.package = None;
        if !self.connected {
            self.page = Page::Connect;
        }
        true
    }

    fn can_choose_package(&self) -> bool {
        self.pending.is_none()
            && self.retry_block.is_none()
            && !self.has_unverified_receipt()
            && [Page::Connect, Page::Ready, Page::Failed].contains(&self.page)
    }
    pub fn configure_demo(&mut self, profile: crate::demo::Profile) -> Option<Work> {
        if self.pending.is_some() {
            return None;
        }
        *self = Self::default();
        self.confirmed = true;
        self.pending = Some(Job::Inspect);
        Some(Work::ConfigureDemo(profile))
    }
    pub fn choose_sample(&mut self, sample: crate::demo::SamplePackage) -> Option<Work> {
        self.choose_package()?;
        Some(Work::ChooseSample {
            component: self.component,
            sample,
        })
    }
    pub fn open_attempt(&mut self) -> Option<Work> {
        if !self.can_open_attempt() {
            return None;
        }
        self.pending = Some(Job::Receipt);
        Some(Work::OpenAttempt)
    }
    fn has_unverified_receipt(&self) -> bool {
        self.receipt
            .as_ref()
            .is_some_and(|receipt| receipt.lifecycle == ReceiptLifecycle::Pending)
    }
    fn can_open_attempt(&self) -> bool {
        self.pending.is_none() && !self.has_unverified_receipt() && self.retry_block.is_none()
    }
    fn can_switch_component(&self) -> bool {
        self.pending.is_none() && self.retry_block.is_none() && !self.has_unverified_receipt()
    }
    #[must_use]
    pub fn can_update(&self) -> bool {
        self.page == Page::Ready
            && self.pending.is_none()
            && self.confirmed
            && self.connected
            && self.retry_block.is_none()
            && self.attachment.is_some()
            && self.versions[index(self.component)]
                .as_ref()
                .is_some_and(|v| v.cleanup_errors.is_empty())
            && self.package.as_ref().is_some_and(|p| {
                p.info.model == Model::Kk3Max && p.info.component == self.component
            })
            && self.selected_decision(self.policy) == Some(VersionDecision::Eligible)
    }
    fn selected_decision(&self, policy: VersionPolicy) -> Option<VersionDecision> {
        let installed = &self.versions[index(self.component)]
            .as_ref()?
            .installed_version;
        let package = &self.package.as_ref()?.info;
        package.decision_for_installed(installed, policy).ok()
    }
    fn is_downgrade(&self) -> bool {
        self.selected_decision(VersionPolicy::UpgradeOnly)
            == Some(VersionDecision::NewerThanSupported)
    }
    fn can_allow_downgrade(&self) -> bool {
        self.can_choose_package()
            && self.confirmed
            && self.connected
            && self.attachment.is_some()
            && self.versions[index(self.component)]
                .as_ref()
                .is_some_and(|inspection| inspection.cleanup_errors.is_empty())
            && self.package.as_ref().is_some_and(|package| {
                package.info.model == Model::Kk3Max && package.info.component == self.component
            })
            && self.is_downgrade()
    }
    pub fn start(&mut self) -> Option<Work> {
        if !self.can_update() {
            return None;
        }
        let package = self.package.as_ref()?;
        let work = Work::Update {
            expected_package: package.info.clone(),
            policy: self.policy,
            path: package.path.clone(),
            component: self.component,
            attachment: self.attachment?,
            confirmed: self.confirmed,
        };
        self.policy = VersionPolicy::UpgradeOnly;
        self.progress = Progress {
            submitted: 0,
            confirmed: 0,
            total: package.info.payload_size,
        };
        self.pending = Some(Job::Transfer);
        self.page = Page::Writing;
        self.notice = "Keep USB connected.".into();
        Some(work)
    }
    pub fn primary(&mut self) -> Option<Work> {
        if self.pending.is_some() || self.retry_block.is_some() {
            return None;
        }
        match self.page {
            Page::Ready => self.start(),
            Page::Restart if self.same_controller && self.has_unverified_receipt() => {
                let receipt = self.receipt.as_ref()?;
                self.pending = Some(Job::Verify);
                self.notice = "Reading the restarted controller…".into();
                Some(Work::Verify {
                    attempt: receipt.path.clone(),
                    confirmed: self.confirmed,
                    same_controller: self.same_controller,
                    expected_receipt: receipt.identity.clone(),
                })
            }
            Page::Writing | Page::Restart => None,
            Page::Verified => self.select_component(if self.component == Component::Main {
                Component::Bluetooth
            } else {
                Component::Main
            }),
            Page::Failed if self.has_unverified_receipt() && self.retry_block.is_none() => {
                self.page = Page::Restart;
                self.same_controller = false;
                None
            }
            Page::Connect | Page::Failed => self.connect(),
        }
    }
    fn fail(&mut self, error: String) {
        if self.progress.submitted > 0 && self.pending == Some(Job::Transfer) {
            self.retry_block = Some(RetryBlock::UncertainOutcome);
        }
        if self.pending == Some(Job::Package) {
            self.package = None;
        }
        self.connected = false;
        self.pending = None;
        self.page = Page::Failed;
        self.notice.clone_from(&error);
        self.log.push(error);
    }
    pub fn accept(&mut self, event: Event) {
        match event {
            Event::Progress(progress) if self.pending == Some(Job::Transfer) => {
                if progress.total != self.progress.total
                    || progress.submitted > progress.total
                    || progress.submitted < self.progress.submitted
                    || progress.confirmed > progress.total
                    || progress.confirmed > progress.submitted
                    || progress.confirmed < self.progress.confirmed
                {
                    self.notice =
                        "Invalid transfer progress; waiting for the worker to finish cleanup."
                            .into();
                    self.retry_block = Some(RetryBlock::UncertainOutcome);
                } else {
                    self.progress = progress;
                }
                return;
            }
            Event::Progress(_) => return,
            Event::WorkerFailed(error) if self.pending.is_some() => {
                if self.pending == Some(Job::Transfer) {
                    self.retry_block = Some(RetryBlock::UncertainOutcome);
                }
                self.fail(error);
            }
            Event::Error(error) if self.pending.is_some() => self.fail(error),
            Event::Cancelled
                if self.pending == Some(Job::Transfer) && self.progress.submitted > 0 =>
            {
                self.fail(
                    "Cancelled after possible submission. Inspect the operation record.".into(),
                );
            }
            Event::Cancelled => {
                if self.pending == Some(Job::Transfer) {
                    self.page = Page::Ready;
                }
                self.pending = None;
                self.notice = "Selection cancelled. No new operation started.".into();
            }
            Event::Inspected(inspection)
                if self.pending == Some(Job::Inspect) && inspection.component == self.component =>
            {
                self.inspected(inspection);
            }
            Event::Package { path, info } if self.pending == Some(Job::Package) => {
                self.selected(path, info);
            }
            Event::Transferred { record, result } if self.pending == Some(Job::Transfer) => {
                self.transferred(record, result);
            }
            Event::Verified(result) if self.pending == Some(Job::Verify) => self.verified(result),
            Event::Prior { path, prior } if self.pending == Some(Job::Receipt) => {
                self.loaded(path, prior);
            }
            _ => {
                if self.pending.is_some() {
                    self.fail("Unexpected updater response. Inspect the operation record.".into());
                }
            }
        }
        if self.log.len() > 200 {
            self.log.drain(..self.log.len() - 200);
        }
    }
    fn inspected(&mut self, inspection: Inspection) {
        self.policy = VersionPolicy::UpgradeOnly;
        self.confirmed = inspection.target.has_known_usb_ids(inspection.component);
        if !self.confirmed {
            self.fail("Unrecognized controller USB IDs.".into());
            return;
        }
        let attachment = Attachment::from(&inspection.target);
        if self.attachment != Some(attachment) {
            self.versions = [None, None];
        }
        self.attachment = Some(attachment);
        self.notice = inspection.cleanup_errors.join("\n");
        self.log.push(format!(
            "{}: {}\n{}",
            inspection.component, inspection.installed_version, self.notice
        ));
        let component = inspection.component;
        let cleanup_failed = !inspection.cleanup_errors.is_empty();
        self.versions[index(component)] = Some(inspection);
        self.connected = true;
        self.pending = None;
        self.page = if cleanup_failed {
            Page::Failed
        } else {
            Page::Ready
        };
    }
    fn selected(&mut self, path: PathBuf, info: PackageInfo) {
        self.policy = VersionPolicy::UpgradeOnly;
        if info.model != Model::Kk3Max || info.component != self.component {
            self.package = None;
            self.pending = None;
            self.notice = "Package does not match this controller component.".into();
        } else {
            self.receipt = None;
            self.package = Some(Selected {
                path,
                payload_label: format!("{} bytes", info.payload_size),
                info,
            });
            self.pending = None;
            self.page = Page::Ready;
            self.notice = self.versions[index(self.component)]
                .as_ref()
                .map_or_else(String::new, |v| v.cleanup_errors.join("\n"));
            self.log.push("Reviewed firmware package selected.".into());
        }
    }
    fn transfer_matches_request(&self, result: &Attempt) -> bool {
        result.package.component == self.component
            && self.attachment == Some(Attachment::from(&result.target))
            && self
                .package
                .as_ref()
                .is_some_and(|p| p.info == result.package)
            && result.transfer.bytes_confirmed <= self.progress.total
            && result.transfer.bytes_submitted <= self.progress.total
            && result.transfer.bytes_submitted >= self.progress.submitted
            && result.transfer.bytes_confirmed <= result.transfer.bytes_submitted
            && result.transfer.bytes_confirmed >= self.progress.confirmed
            && match result.transfer.outcome {
                Outcome::TransferCompletedAwaitingVerification => {
                    result.transfer.bytes_submitted == self.progress.total
                        && result.transfer.bytes_confirmed == self.progress.total
                }
                Outcome::TransferSubmittedPendingCompletion => {
                    result.transfer.bytes_submitted == self.progress.total
                }
                Outcome::Refused
                | Outcome::AlreadyCurrent
                | Outcome::NewerThanSupported
                | Outcome::CancelledBeforeWrite => {
                    result.transfer.bytes_submitted == 0
                        && result.transfer.bytes_confirmed == 0
                        && !result.transfer.main_destination_created
                }
                Outcome::DestinationCreatedWithoutPayload => {
                    result.transfer.bytes_submitted == 0
                        && result.transfer.bytes_confirmed == 0
                        && result.transfer.main_destination_created
                }
                Outcome::OutcomeUnknown => true,
                Outcome::InstalledVerified => false,
            }
    }
    fn transferred(&mut self, record: PathBuf, result: Attempt) {
        if !self.transfer_matches_request(&result) {
            self.retry_block = Some(RetryBlock::UncertainOutcome);
            self.fail(
                "Inconsistent transfer result. Inspect the operation record before continuing."
                    .into(),
            );
            return;
        }
        self.pending = None;
        self.connected = false;
        self.same_controller = false;
        self.progress.confirmed = result.transfer.bytes_confirmed;
        self.progress.submitted = result.transfer.bytes_submitted;
        self.notice = operation_notice(result.transfer.error, &result.transfer.cleanup_errors);
        self.log.push(format!(
            "{:?}: {} confirmed bytes\nRecord: {}\n{}",
            result.transfer.outcome,
            result.transfer.bytes_confirmed,
            record.display(),
            self.notice
        ));
        if !result.record_finalized {
            self.receipt = None;
            self.retry_block = Some(RetryBlock::RecordNotFinalized);
            self.page = Page::Failed;
            return;
        }
        match result.transfer.outcome {
            Outcome::TransferCompletedAwaitingVerification
            | Outcome::TransferSubmittedPendingCompletion => {
                self.receipt = Some(Receipt {
                    path: record,
                    lifecycle: ReceiptLifecycle::Pending,
                    identity: ReceiptIdentity {
                        component: result.package.component,
                        outcome: result.transfer.outcome,
                        generation: result.target.generation,
                        expected_version: result.package.version.clone(),
                        package: serde_json::to_value(&result.package)
                            .expect("package metadata serializes"),
                    },
                });
                self.page = Page::Restart;
            }
            Outcome::AlreadyCurrent | Outcome::NewerThanSupported => {
                self.page = Page::Ready;
                if let Some(v) = &mut self.versions[index(self.component)] {
                    v.decision = if result.transfer.outcome == Outcome::AlreadyCurrent {
                        VersionDecision::AlreadyCurrent
                    } else {
                        VersionDecision::NewerThanSupported
                    };
                    if let Some(version) = result.transfer.prewrite_version {
                        v.installed_version = version;
                    }
                }
            }
            outcome => {
                if outcome == Outcome::OutcomeUnknown || result.transfer.bytes_submitted > 0 {
                    self.retry_block = Some(RetryBlock::UncertainOutcome);
                } else if outcome == Outcome::DestinationCreatedWithoutPayload {
                    self.retry_block = Some(RetryBlock::MainDestinationCreated);
                }
                self.page = Page::Failed;
                if self.notice.is_empty() {
                    self.notice = format!("Update stopped: {outcome:?}. No automatic retry.");
                }
            }
        }
    }
    fn readback_verifies_receipt(&self, result: &Readback) -> bool {
        self.receipt.as_ref().is_some_and(|receipt| {
            receipt.lifecycle == ReceiptLifecycle::Pending
                && result.target.has_known_usb_ids(receipt.identity.component)
                && self.same_controller
                && result.source_attempt == receipt.path
                && result.transfer.outcome == Outcome::InstalledVerified
                && result.transfer.error.is_none()
                && result.transfer.cleanup_errors.is_empty()
                && result.verification.as_ref().is_some_and(|v| {
                    v.generation == result.target.generation
                        && v.component == receipt.identity.component
                        && v.previous_generation == receipt.identity.generation
                        && v.expected_version == receipt.identity.expected_version
                        && verify_restart(receipt.identity.outcome, v) == Outcome::InstalledVerified
                })
        })
    }
    fn verified(&mut self, result: Readback) {
        self.pending = None;
        let verified = self.readback_verifies_receipt(&result);
        self.notice = operation_notice(result.transfer.error, &result.transfer.cleanup_errors);
        if verified {
            if let Some(receipt) = &mut self.receipt {
                receipt.lifecycle = ReceiptLifecycle::Verified;
            }
            if let Some(observation) = result.verification {
                self.attachment = Some(Attachment::from(&result.target));
                self.versions = [None, None];
                self.versions[index(observation.component)] = Some(Inspection {
                    component: observation.component,
                    installed_version: observation.version,
                    decision: VersionDecision::AlreadyCurrent,
                    target: result.target,
                    raw_version_bytes: result.raw_version_bytes.unwrap_or_default(),
                    qualified_bot_lun: result.qualified_bot_lun,
                    cleanup_errors: vec![],
                    identity_provenance: result.same_unit_association,
                });
                self.connected = true;
                self.confirmed = true;
                self.retry_block = None;
            }
            self.page = Page::Verified;
            self.notice = "Confirmed by a fresh version read after restart.".into();
        } else {
            self.page = Page::Failed;
            if self.notice.is_empty() {
                self.notice =
                    "Version not verified. Check the restart and read the operation record.".into();
            }
        }
        self.log.push(self.notice.clone());
    }
    fn loaded(&mut self, path: PathBuf, prior: PriorAttempt) {
        self.pending = None;
        if self.has_unverified_receipt() || self.retry_block.is_some() {
            return;
        }
        self.component = prior.component;
        let verifiable = prior.require_verifiable().is_ok();
        self.retry_block = if prior
            .record
            .get("record_finalized")
            .is_some_and(|value| value.as_bool() != Some(true))
        {
            Some(RetryBlock::RecordNotFinalized)
        } else {
            match prior.outcome {
                Outcome::OutcomeUnknown => Some(RetryBlock::UncertainOutcome),
                Outcome::DestinationCreatedWithoutPayload => {
                    Some(RetryBlock::MainDestinationCreated)
                }
                _ => None,
            }
        };
        self.receipt = verifiable.then_some(Receipt {
            path,
            lifecycle: ReceiptLifecycle::Pending,
            identity: ReceiptIdentity {
                component: prior.component,
                outcome: prior.outcome,
                generation: prior.generation,
                expected_version: prior.expected_version,
                package: prior.record["package"].clone(),
            },
        });
        self.package = None;
        self.same_controller = false;
        self.page = if verifiable {
            Page::Restart
        } else {
            Page::Failed
        };
        self.notice = if verifiable {
            "Confirm the same physical NS39 before fresh readback. This record cannot resume a transfer."
        } else {
            "This record does not establish a transfer that can be verified. Inspect its outcome and recovery guidance."
        }.into();
    }
    fn installed_version(&self, component: Component) -> &str {
        self.versions[index(component)]
            .as_ref()
            .map_or("Version unknown", |v| v.installed_version.as_str())
    }
    fn target_version(&self) -> &str {
        self.package
            .as_ref()
            .map(|package| package.info.version.as_str())
            .or_else(|| {
                self.receipt
                    .as_ref()
                    .map(|receipt| receipt.identity.expected_version.as_str())
            })
            .unwrap_or("No firmware selected")
    }
    fn display_notice(&self) -> &str {
        if let Some(block) = self.retry_block {
            match block {
                RetryBlock::UncertainOutcome => {
                    "Transfer outcome unknown. No retry or resume. Keep the cable connected and follow recovery guidance."
                }
                RetryBlock::MainDestinationCreated => {
                    "No firmware payload bytes were submitted, but a file was created on the controller. No retry; inspect the retained file before another attempt."
                }
                RetryBlock::RecordNotFinalized => {
                    "The host record could not be finalized. Keep the controller connected and unchanged. Verification and further device access are unavailable; inspect the host record and recovery guidance."
                }
            }
        } else if !self.notice.is_empty() {
            &self.notice
        } else if self.page == Page::Restart {
            "Verification pending. Follow this component's restart procedure, then check the installed version."
        } else if !self.confirmed {
            "Connect the controller in update mode."
        } else if self.package.is_none() {
            "Choose an original reviewed firmware ZIP."
        } else if self.is_downgrade() && self.policy == VersionPolicy::UpgradeOnly {
            "Selected firmware is older than the installed version. Allow a one-time downgrade to continue."
        } else if self.selected_decision(self.policy) != Some(VersionDecision::Eligible) {
            "Installed version is unknown, already current, or newer. Update unavailable."
        } else {
            ""
        }
    }
    fn can_primary(&self) -> bool {
        self.pending.is_none()
            && self.retry_block.is_none()
            && match self.page {
                Page::Ready => self.can_update(),
                Page::Restart => self.same_controller && self.has_unverified_receipt(),
                Page::Writing => false,
                _ => true,
            }
    }
    fn primary_label(&self) -> Cow<'_, str> {
        match self.page {
            Page::Failed if self.has_unverified_receipt() && self.retry_block.is_none() => {
                "Back to verification".into()
            }
            Page::Connect | Page::Failed => "Inspect controller".into(),
            Page::Ready => format!("Update to {}  →", self.target_version()).into(),
            Page::Writing => "Updating…".into(),
            Page::Restart => "Check version  →".into(),
            Page::Verified => "Other firmware  →".into(),
        }
    }
    #[must_use]
    pub fn view(&self) -> View<'_> {
        View {
            page: self.page,
            component: self.component,
            confirmed: self.confirmed,
            same_controller: self.same_controller,
            allow_downgrade: self.policy == VersionPolicy::AllowDowngrade,
            is_downgrade: self.is_downgrade(),
            can_allow_downgrade: self.can_allow_downgrade(),
            busy: self.is_busy(),
            connected: self.connected,
            main_version: self.installed_version(Component::Main),
            bt_version: self.installed_version(Component::Bluetooth),
            installed: self.installed_version(self.component),
            target: self.target_version(),
            filename: self.package.as_ref().map_or_else(
                || "No firmware selected".into(),
                |p| p.path.file_name().unwrap_or_default().to_string_lossy(),
            ),
            payload: self
                .package
                .as_ref()
                .map_or("", |p| p.payload_label.as_str()),
            digest: self
                .package
                .as_ref()
                .map_or("", |p| p.info.payload_sha256.as_str()),
            progress: self.progress,
            can_update: self.can_update(),
            can_choose_package: self.can_choose_package(),
            can_open_attempt: self.can_open_attempt(),
            can_switch_component: self.can_switch_component(),
            can_troubleshoot: self.pending.is_none()
                && self.retry_block.is_none()
                && !self.has_unverified_receipt(),
            can_primary: self.can_primary(),
            primary_label: self.primary_label(),
            notice: self.display_notice(),
            log: &self.log,
        }
    }
}

fn operation_notice(error: Option<String>, cleanup_errors: &[String]) -> String {
    let mut notice = error.unwrap_or_default();
    for error in cleanup_errors {
        notice.push('\n');
        notice.push_str(error);
    }
    notice
}
