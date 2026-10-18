//! UI intents and backend observations; no native I/O runs in this model.
use crate::Page;
use gulikit_catalog::{
    Catalog, DownloadAvailability, Entry, HardwareAcceptance, ParserId, SoftwareSupport,
};
use gulikit_core::{
    package::{Component, Model, PackageInfo, catalog},
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
    ImportRelease(Box<Entry>),
    OpenSource(Box<Entry>),
    OpenChangelog(Box<Entry>),
    DownloadRelease(Box<Entry>),
    Update {
        path: PathBuf,
        component: Component,
        attachment: Attachment,
        confirmed: bool,
        policy: VersionPolicy,
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
    CatalogAction(String),
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
    CatalogAction,
    Download,
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
    pub catalog_products: Vec<String>,
    pub catalog_product_index: i32,
    pub catalog_components: Vec<String>,
    pub catalog_component_index: i32,
    pub catalog_versions: Vec<String>,
    pub catalog_version_index: i32,
    pub catalog_source_url: &'a str,
    pub catalog_changelog_url: &'a str,
    pub catalog_archive: &'a str,
    pub catalog_software_support: &'a str,
    pub catalog_parser_id: &'a str,
    pub catalog_hardware_acceptance: &'a str,
    pub catalog_hardware_scope: &'a str,
    pub catalog_availability: &'a str,
    pub catalog_available: bool,
    pub catalog_can_import: bool,
    pub catalog_can_open_source: bool,
    pub catalog_can_open_changelog: bool,
    pub catalog_can_download: bool,
    pub allow_rollback: bool,
    pub can_allow_rollback: bool,
    pub can_troubleshoot: bool,
    pub can_primary: bool,
    pub primary_label: Cow<'a, str>,
    pub notice: &'a str,
    pub log: &'a [String],
}

// Independent operator attestations and connection/rollback state.
#[allow(clippy::struct_excessive_bools)]
pub struct LiveApp {
    component: Component,
    confirmed: bool,
    same_controller: bool,
    page: Page,
    pending: Option<Job>,
    attachment: Option<Attachment>,
    versions: [Option<Inspection>; 2],
    package: Option<Selected>,
    receipt: Option<Receipt>,
    progress: Progress,
    retry_block: Option<RetryBlock>,
    catalog: Option<Catalog>,
    catalog_product_index: Option<usize>,
    catalog_component_index: Option<usize>,
    catalog_version_index: Option<usize>,
    allow_rollback: bool,
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
            catalog: None,
            catalog_product_index: None,
            catalog_component_index: None,
            catalog_version_index: None,
            allow_rollback: false,
            connected: false,
            notice: "Check the physical NS39 label and Max controls.".into(),
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

fn parse_component(value: &str) -> Option<Component> {
    match value {
        "main" => Some(Component::Main),
        "bluetooth" => Some(Component::Bluetooth),
        _ => None,
    }
}

fn version_key(value: &str) -> (u16, u16) {
    let (major, minor) = value.split_once('.').unwrap_or(("0", "0"));
    let parse = |value: &str| value.parse::<u16>().unwrap_or(0);
    (parse(major), parse(minor))
}

impl LiveApp {
    /// Configure an optional descriptive catalog before the UI starts.
    ///
    /// Calls made while an operation, pending receipt or uncertain outcome is
    /// active are ignored so catalog changes cannot disturb recovery state.
    pub fn set_catalog(&mut self, catalog: Catalog) {
        if !self.can_select_catalog() {
            return;
        }
        self.catalog = Some(catalog);
        self.catalog_product_index = (!self.catalog_products().is_empty()).then_some(0);
        let components = self.catalog_components();
        self.catalog_component_index = components
            .iter()
            .position(|value| parse_component(value) == Some(self.component))
            .or_else(|| (!components.is_empty()).then_some(0));
        self.catalog_version_index = (!self.catalog_versions().is_empty()).then_some(0);
        self.clear_selected_package();
    }

    #[must_use]
    pub fn catalog_products(&self) -> Vec<String> {
        let Some(catalog) = &self.catalog else {
            return Vec::new();
        };
        let mut products: Vec<_> = catalog
            .entries()
            .iter()
            .map(|entry| entry.product().to_owned())
            .collect();
        products.sort();
        products.dedup();
        products
    }

    #[must_use]
    pub fn catalog_components(&self) -> Vec<String> {
        let Some(product) = self.selected_product() else {
            return Vec::new();
        };
        let Some(catalog) = &self.catalog else {
            return Vec::new();
        };
        let mut components: Vec<_> = catalog
            .entries()
            .iter()
            .filter(|entry| entry.product() == product)
            .map(|entry| entry.component().to_owned())
            .collect();
        components.sort();
        components.dedup();
        components
    }

    #[must_use]
    pub fn catalog_versions(&self) -> Vec<String> {
        let (Some(product), Some(component), Some(catalog)) = (
            self.selected_product(),
            self.selected_component(),
            self.catalog.as_ref(),
        ) else {
            return Vec::new();
        };
        let mut versions: Vec<_> = catalog
            .entries()
            .iter()
            .filter(|entry| entry.product() == product && entry.component() == component)
            .map(|entry| entry.version().to_owned())
            .collect();
        versions.sort_by_key(|value| std::cmp::Reverse(version_key(value)));
        versions.dedup();
        versions
    }

    #[must_use]
    pub fn selected_release(&self) -> Option<&Entry> {
        let product = self.selected_product()?;
        let component = self.selected_component()?;
        let version = self
            .catalog_versions()
            .get(self.catalog_version_index?)?
            .clone();
        self.catalog.as_ref()?.entries().iter().find(|entry| {
            entry.product() == product
                && entry.component() == component
                && entry.version() == version
        })
    }

    #[must_use]
    pub fn catalog_product_index(&self) -> i32 {
        self.catalog_product_index
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(-1)
    }

    #[must_use]
    pub fn catalog_component_index(&self) -> i32 {
        self.catalog_component_index
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(-1)
    }

    #[must_use]
    pub fn catalog_version_index(&self) -> i32 {
        self.catalog_version_index
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(-1)
    }

    pub fn select_catalog_product(&mut self, index: usize) {
        if !self.can_select_catalog() || index >= self.catalog_products().len() {
            return;
        }
        self.catalog_product_index = Some(index);
        let components = self.catalog_components();
        self.catalog_component_index = components
            .iter()
            .position(|value| parse_component(value) == Some(self.component))
            .or_else(|| (!components.is_empty()).then_some(0));
        self.catalog_version_index = (!self.catalog_versions().is_empty()).then_some(0);
        if let Some(component) = self
            .selected_component()
            .as_deref()
            .and_then(parse_component)
        {
            let _ = self.select_component(component);
        }
        self.clear_selected_package();
    }

    pub fn select_catalog_component(&mut self, index: usize) {
        if !self.can_select_catalog() || index >= self.catalog_components().len() {
            return;
        }
        self.catalog_component_index = Some(index);
        self.catalog_version_index = (!self.catalog_versions().is_empty()).then_some(0);
        if let Some(component) = self
            .selected_component()
            .as_deref()
            .and_then(parse_component)
        {
            let _ = self.select_component(component);
        }
        self.clear_selected_package();
    }

    pub fn select_catalog_version(&mut self, index: usize) {
        if !self.can_select_catalog() || index >= self.catalog_versions().len() {
            return;
        }
        self.catalog_version_index = Some(index);
        self.clear_selected_package();
    }

    fn selected_product(&self) -> Option<String> {
        self.catalog_products()
            .get(self.catalog_product_index?)
            .cloned()
    }

    fn selected_component(&self) -> Option<String> {
        self.catalog_components()
            .get(self.catalog_component_index?)
            .cloned()
    }

    fn can_select_catalog(&self) -> bool {
        self.pending.is_none() && self.retry_block.is_none() && !self.has_unverified_receipt()
    }

    fn clear_selected_package(&mut self) {
        self.package = None;
        self.allow_rollback = false;
        self.notice =
            "Selected release changed. Import that exact archive before considering an update."
                .into();
    }

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
        if self.pending.is_some()
            || !self.confirmed
            || self.retry_block.is_some()
            || self.has_unverified_receipt()
        {
            return None;
        }
        self.receipt = None;
        self.pending = Some(Job::Inspect);
        self.notice = "Reading installed version…".into();
        Some(Work::Inspect {
            component: self.component,
            confirmed: self.confirmed,
        })
    }
    pub fn select_component(&mut self, component: Component) -> Option<Work> {
        if !self.can_switch_component() || component == self.component {
            return None;
        }
        self.component = component;
        self.sync_catalog_component();
        self.package = None;
        self.allow_rollback = false;
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

    fn sync_catalog_component(&mut self) {
        if self.catalog.is_none() {
            return;
        }
        self.catalog_component_index = self
            .catalog_components()
            .iter()
            .position(|value| parse_component(value) == Some(self.component));
        self.catalog_version_index = (!self.catalog_versions().is_empty()).then_some(0);
    }
    pub fn choose_package(&mut self) -> Option<Work> {
        if !self.can_choose_package() {
            return None;
        }
        if let Some(entry) = self.selected_release().cloned() {
            return self.import_release_for(entry);
        }
        if self.catalog.is_some() {
            return None;
        }
        self.pending = Some(Job::Package);
        Some(Work::ChoosePackage(self.component))
    }

    fn import_release_for(&mut self, entry: Entry) -> Option<Work> {
        if !self.can_choose_package() || !self.catalog_can_import_entry(&entry) {
            return None;
        }
        self.allow_rollback = false;
        self.pending = Some(Job::Package);
        Some(Work::ImportRelease(Box::new(entry)))
    }

    pub fn import_release(&mut self) -> Option<Work> {
        self.import_release_for(self.selected_release()?.clone())
    }

    pub fn open_source(&mut self) -> Option<Work> {
        if !self.can_catalog_action() {
            return None;
        }
        let entry = self.selected_release()?.clone();
        self.pending = Some(Job::CatalogAction);
        Some(Work::OpenSource(Box::new(entry)))
    }

    pub fn open_changelog(&mut self) -> Option<Work> {
        if !self.can_catalog_action() {
            return None;
        }
        let entry = self.selected_release()?.clone();
        entry.changelog_url()?;
        self.pending = Some(Job::CatalogAction);
        Some(Work::OpenChangelog(Box::new(entry)))
    }

    pub fn download_release(&mut self) -> Option<Work> {
        if !self.can_catalog_action() {
            return None;
        }
        let entry = self.selected_release()?.clone();
        if entry.availability() == DownloadAvailability::Unavailable {
            return None;
        }
        self.pending = Some(Job::Download);
        Some(Work::DownloadRelease(Box::new(entry)))
    }

    fn can_catalog_action(&self) -> bool {
        self.pending.is_none() && self.retry_block.is_none() && !self.has_unverified_receipt()
    }

    fn catalog_can_import_entry(&self, entry: &Entry) -> bool {
        entry.product() == "kk3-max"
            && parse_component(entry.component()) == Some(self.component)
            && entry.software_support() == SoftwareSupport::Supported
            && self.can_choose_package()
    }

    pub fn set_allow_rollback(&mut self, allow: bool) {
        if !self.can_catalog_action() {
            return;
        }
        if !allow {
            self.allow_rollback = false;
        } else if self.can_allow_rollback() {
            self.allow_rollback = true;
        }
    }

    fn can_allow_rollback(&self) -> bool {
        self.page == Page::Ready
            && self.pending.is_none()
            && self.retry_block.is_none()
            && !self.has_unverified_receipt()
            && self.package.is_some()
            && self.selected_decision_with_policy(gulikit_core::version::VersionPolicy::UpgradeOnly)
                == Some(VersionDecision::NewerThanSupported)
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
            && self.selected_decision() == Some(VersionDecision::Eligible)
    }
    fn selected_decision(&self) -> Option<VersionDecision> {
        self.selected_decision_with_policy(self.selected_policy())
    }
    fn selected_policy(&self) -> VersionPolicy {
        if self.allow_rollback {
            VersionPolicy::AllowDowngrade
        } else {
            VersionPolicy::UpgradeOnly
        }
    }
    fn selected_decision_with_policy(
        &self,
        policy: gulikit_core::version::VersionPolicy,
    ) -> Option<VersionDecision> {
        let installed = &self.versions[index(self.component)]
            .as_ref()?
            .installed_version;
        let package = &self.package.as_ref()?.info;
        package.decision_for_installed(installed, policy).ok()
    }
    pub fn start(&mut self) -> Option<Work> {
        if !self.can_update() {
            return None;
        }
        let package = self.package.as_ref()?;
        let work = Work::Update {
            path: package.path.clone(),
            component: self.component,
            attachment: self.attachment?,
            confirmed: self.confirmed,
            policy: self.selected_policy(),
        };
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
            Page::Restart
                if self.confirmed && self.same_controller && self.has_unverified_receipt() =>
            {
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
    fn catalog_action_failed(&mut self, error: String) {
        self.pending = None;
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
                if matches!(self.pending, Some(Job::CatalogAction | Job::Download)) {
                    self.catalog_action_failed(error);
                    return;
                }
                if self.pending == Some(Job::Transfer) {
                    self.retry_block = Some(RetryBlock::UncertainOutcome);
                }
                self.fail(error);
            }
            Event::Error(error)
                if self.pending == Some(Job::CatalogAction)
                    || self.pending == Some(Job::Download) =>
            {
                self.catalog_action_failed(error);
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
            Event::Package { path, info }
                if matches!(self.pending, Some(Job::Package | Job::Download)) =>
            {
                let matches_catalog = self.selected_release().is_none_or(|entry| {
                    gulikit_core::package::catalog_package_info(entry)
                        .is_ok_and(|expected| expected == info)
                });
                if matches_catalog {
                    self.selected(path, info);
                } else {
                    self.pending = None;
                    self.package = None;
                    self.fail(
                        "Imported archive does not match the selected catalog version.".into(),
                    );
                }
            }
            Event::Transferred { record, result } if self.pending == Some(Job::Transfer) => {
                self.transferred(record, result);
            }
            Event::Verified(result) if self.pending == Some(Job::Verify) => self.verified(result),
            Event::Prior { path, prior } if self.pending == Some(Job::Receipt) => {
                self.loaded(path, &prior);
            }
            Event::CatalogAction(message) if self.pending == Some(Job::CatalogAction) => {
                self.pending = None;
                self.notice.clone_from(&message);
                self.log.push(message);
            }
            Event::CatalogAction(message)
                if matches!(self.pending, Some(Job::Package | Job::Download)) =>
            {
                self.pending = None;
                self.notice.clone_from(&message);
                self.log.push(message);
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
        if info.model != Model::Kk3Max || info.component != self.component {
            self.package = None;
            self.pending = None;
            self.notice = "Package does not match this controller component.".into();
        } else {
            self.receipt = None;
            self.allow_rollback = false;
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
        result.transfer.version_policy == self.selected_policy()
            && result.package.component == self.component
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
                    identity: ReceiptIdentity::for_package(
                        result.transfer.outcome,
                        result.target.generation,
                        &result.package,
                        result.catalog_entry.as_deref(),
                    ),
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
                && self.confirmed
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
    fn loaded(&mut self, path: PathBuf, prior: &PriorAttempt) {
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
            identity: prior.identity(),
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
            .unwrap_or_else(|| {
                catalog()
                    .iter()
                    .find(|r| r.model == Model::Kk3Max && r.component == self.component)
                    .expect("supported component has a catalog entry")
                    .version
            })
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
            "Check the physical NS39 label and Max controls."
        } else if self.package.is_none() {
            "Choose an original reviewed firmware ZIP."
        } else if self.selected_decision() != Some(VersionDecision::Eligible) {
            "Installed version is unknown, already current, or newer. Update unavailable."
        } else {
            "Ready. Updating requires an explicit action."
        }
    }
    fn can_primary(&self) -> bool {
        self.pending.is_none()
            && self.retry_block.is_none()
            && match self.page {
                Page::Ready => self.can_update(),
                Page::Restart => {
                    self.confirmed && self.same_controller && self.has_unverified_receipt()
                }
                Page::Writing => false,
                _ => self.confirmed,
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
        let entry = self.selected_release();
        let hardware_evidence = entry.and_then(Entry::hardware_evidence);
        let parser_id = entry.map_or("", |entry| match entry.parser_id() {
            ParserId::None => "none",
            ParserId::Kk3MainBinaryV1 => "kk3_main_binary_v1",
            ParserId::Kk3BluetoothPeV1 => "kk3_bluetooth_pe_v1",
        });
        let hardware_acceptance = entry.map_or("", |entry| match entry.hardware_acceptance() {
            HardwareAcceptance::Qualified => "qualified",
            HardwareAcceptance::Unqualified => "unqualified",
        });
        let software_support = entry.map_or("", |entry| match entry.software_support() {
            SoftwareSupport::Supported => "supported",
            SoftwareSupport::MetadataOnly => "metadata only",
        });
        let availability = entry.map_or("", |entry| match entry.availability() {
            DownloadAvailability::Unknown => "unknown",
            DownloadAvailability::Available => "available",
            DownloadAvailability::Unavailable => "unavailable",
        });
        View {
            page: self.page,
            component: self.component,
            confirmed: self.confirmed,
            same_controller: self.same_controller,
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
            catalog_products: self.catalog_products(),
            catalog_product_index: self.catalog_product_index(),
            catalog_components: self.catalog_components(),
            catalog_component_index: self.catalog_component_index(),
            catalog_versions: self.catalog_versions(),
            catalog_version_index: self.catalog_version_index(),
            catalog_source_url: entry.map_or("", Entry::source_url),
            catalog_changelog_url: entry.and_then(Entry::changelog_url).unwrap_or(""),
            catalog_archive: entry.map_or("", Entry::archive),
            catalog_software_support: software_support,
            catalog_parser_id: parser_id,
            catalog_hardware_acceptance: hardware_acceptance,
            catalog_hardware_scope: hardware_evidence.map_or("", |evidence| evidence.scope()),
            catalog_availability: availability,
            catalog_available: entry
                .is_some_and(|entry| entry.availability() == DownloadAvailability::Available),
            catalog_can_import: entry.is_some_and(|entry| self.catalog_can_import_entry(entry)),
            catalog_can_open_source: self.can_catalog_action()
                && entry.is_some_and(|entry| !entry.source_url().is_empty()),
            catalog_can_open_changelog: self.can_catalog_action()
                && entry.is_some_and(|entry| entry.changelog_url().is_some()),
            catalog_can_download: self.can_catalog_action()
                && entry
                    .is_some_and(|entry| entry.availability() != DownloadAvailability::Unavailable),
            allow_rollback: self.allow_rollback,
            can_allow_rollback: self.can_allow_rollback(),
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
