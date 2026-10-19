//! Controller independent browser for the public firmware archive.

use gulikit_archive::{
    ArchiveClient, ArchiveSnapshot, Component as ArchiveComponent, ReleaseRecord,
};
use gulikit_core::package::Component;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread::{self, JoinHandle},
};

#[derive(Clone, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "direct Slint view projection"
)]
pub struct ArchiveView {
    pub status: String,
    pub revision: String,
    pub releases: Vec<String>,
    pub selected: i32,
    pub version: String,
    pub filename: String,
    pub details: String,
    pub changelog: String,
    pub can_refresh: bool,
    pub can_download: bool,
    pub busy: bool,
    pub refreshing: bool,
}

#[derive(Debug)]
pub enum ArchiveEvent {
    Snapshot(Result<Option<ArchiveSnapshot>, String>),
    Refreshed(Result<ArchiveSnapshot, String>),
    Downloaded {
        path: PathBuf,
        record: Box<ReleaseRecord>,
        inspection: Result<crate::archive_package::DownloadInspection, String>,
    },
    Failed(String),
}

#[doc(hidden)]
#[derive(Debug)]
pub enum Request {
    Refresh,
    Download {
        snapshot: ArchiveSnapshot,
        path: String,
    },
    Shutdown,
}

pub struct ArchiveBrowser {
    component: Component,
    snapshot: Option<ArchiveSnapshot>,
    records: Vec<ReleaseRecord>,
    selected_path: Option<String>,
    status: String,
    busy: bool,
    refreshing: bool,
    requests: Sender<Request>,
    worker_cancelled: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    worker_stopped: bool,
}

impl ArchiveBrowser {
    #[must_use]
    pub fn spawn(
        cache_dir: Result<PathBuf, String>,
        enabled: bool,
    ) -> (Self, Receiver<ArchiveEvent>) {
        let (requests, request_rx) = mpsc::channel();
        let (events_tx, events_rx) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let handle = thread::spawn(move || {
            archive_worker(
                cache_dir,
                request_rx,
                &events_tx,
                &worker_cancelled,
                enabled,
            );
        });
        (
            Self {
                component: Component::Main,
                snapshot: None,
                records: Vec::new(),
                selected_path: None,
                status: if enabled {
                    "Loading firmware archive…"
                } else {
                    "Firmware archive is disabled in demo mode."
                }
                .into(),
                busy: false,
                refreshing: enabled,
                requests,
                worker_cancelled: cancelled,
                handle: Some(handle),
                worker_stopped: false,
            },
            events_rx,
        )
    }

    /// Build an offline browser around a supplied validated snapshot.
    ///
    /// This constructor is exposed for deterministic UI previews and tests.
    #[doc(hidden)]
    #[must_use]
    pub fn from_snapshot(snapshot: ArchiveSnapshot, requests: Sender<Request>) -> Self {
        let mut browser = Self {
            component: Component::Main,
            snapshot: Some(snapshot),
            records: Vec::new(),
            selected_path: None,
            status: "Cached archive snapshot loaded.".into(),
            busy: false,
            refreshing: false,
            requests,
            worker_cancelled: Arc::new(AtomicBool::new(false)),
            handle: None,
            worker_stopped: false,
        };
        browser.rebuild_records();
        browser
    }

    pub fn receive(&mut self, events: &Receiver<ArchiveEvent>) -> (bool, Vec<ArchiveEvent>) {
        let mut downloaded = Vec::new();
        let mut changed = false;
        loop {
            match events.try_recv() {
                Ok(ArchiveEvent::Snapshot(result)) => {
                    self.apply_snapshot(result, "Cached archive loaded.");
                    changed = true;
                }
                Ok(ArchiveEvent::Refreshed(result)) => {
                    self.refreshing = false;
                    if self.busy {
                        // Keep the displayed selection pinned to the snapshot
                        // used by the in-flight download. The user can refresh
                        // again after it completes.
                        self.status =
                            "Download in progress; refresh again when it completes.".into();
                    } else {
                        self.apply_snapshot(result.map(Some), "Firmware archive is current.");
                    }
                    changed = true;
                }
                Ok(event @ ArchiveEvent::Downloaded { .. }) => {
                    self.busy = false;
                    downloaded.push(event);
                    changed = true;
                }
                Ok(ArchiveEvent::Failed(error)) => {
                    self.busy = false;
                    self.refreshing = false;
                    self.status = format!("Archive operation failed. {error}");
                    changed = true;
                }
                Err(TryRecvError::Empty) => return (changed, downloaded),
                Err(TryRecvError::Disconnected) => {
                    if (self.busy || self.refreshing) && !self.worker_stopped {
                        self.worker_stopped = true;
                        self.busy = false;
                        self.refreshing = false;
                        self.status =
                            "Archive worker stopped. Restart the application to continue.".into();
                        changed = true;
                    }
                    return (changed, downloaded);
                }
            }
        }
    }

    fn apply_snapshot(&mut self, result: Result<Option<ArchiveSnapshot>, String>, success: &str) {
        match result {
            Ok(snapshot) => {
                if let Some(snapshot) = snapshot {
                    self.snapshot = Some(snapshot);
                    self.status = success.into();
                } else {
                    self.status = "No cached firmware archive. Refresh to load releases.".into();
                }
                self.rebuild_records();
            }
            Err(error) => {
                self.status = if self.snapshot.is_some() {
                    format!("Could not refresh archive; showing cached releases. {error}")
                } else {
                    format!("Firmware archive unavailable. {error}")
                };
            }
        }
    }

    fn rebuild_records(&mut self) {
        let previous = self.selected_path.clone();
        self.records = self.snapshot.as_ref().map_or_else(Vec::new, |snapshot| {
            snapshot
                .index()
                .releases()
                .iter()
                .filter(|record| record.metadata().product == "kk3-max")
                .filter(|record| match (self.component, record.component()) {
                    (Component::Main, ArchiveComponent::Base)
                    | (Component::Bluetooth, ArchiveComponent::Bluetooth) => true,
                    (Component::Main, ArchiveComponent::Bluetooth)
                    | (Component::Bluetooth, ArchiveComponent::Base) => false,
                })
                .cloned()
                .collect()
        });
        self.records.sort_by(|left, right| {
            compare_versions(right.version(), left.version())
                .then_with(|| left.filename().cmp(right.filename()))
                .then_with(|| left.path().cmp(right.path()))
        });
        self.selected_path = previous
            .filter(|path| self.records.iter().any(|record| record.path() == path))
            .or_else(|| self.records.first().map(|record| record.path().to_owned()));
        if self.records.is_empty() && self.snapshot.is_some() {
            self.status = "No releases are archived for this component.".into();
        }
    }

    pub fn set_component(&mut self, component: Component) -> bool {
        if self.busy || self.component == component {
            return false;
        }
        self.component = component;
        self.rebuild_records();
        true
    }

    pub fn select(&mut self, index: i32) -> bool {
        if self.busy {
            return false;
        }
        let Ok(index) = usize::try_from(index) else {
            return false;
        };
        let Some(record) = self.records.get(index) else {
            return false;
        };
        let changed = self.selected_path.as_deref() != Some(record.path());
        self.selected_path = Some(record.path().to_owned());
        changed
    }

    pub fn select_label(&mut self, label: &str) -> bool {
        let Some(index) = self
            .records
            .iter()
            .position(|record| release_label(record) == label)
        else {
            return false;
        };
        self.select(i32::try_from(index).unwrap_or(-1))
    }

    pub fn refresh(&mut self) {
        if self.busy || self.refreshing {
            return;
        }
        self.refreshing = true;
        self.status = "Refreshing archive index…".into();
        if self.requests.send(Request::Refresh).is_err() {
            self.refreshing = false;
            self.status = "Archive worker stopped. Restart the application to refresh.".into();
        }
    }

    pub fn download(&mut self) {
        if self.busy {
            return;
        }
        let Some(path) = self.selected_path.clone() else {
            return;
        };
        let Some(snapshot) = self.snapshot.clone() else {
            self.status = "No archive snapshot is available. Refresh first.".into();
            return;
        };
        self.busy = true;
        self.status = "Downloading and verifying original ZIP…".into();
        if self
            .requests
            .send(Request::Download { snapshot, path })
            .is_err()
        {
            self.busy = false;
            self.status = "Archive worker stopped. Restart the application to download.".into();
        }
    }

    #[must_use]
    pub fn selected_path(&self) -> Option<&str> {
        self.selected_path.as_deref()
    }

    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.busy
    }

    #[must_use]
    pub fn selected_record(&self) -> Option<&ReleaseRecord> {
        let path = self.selected_path.as_deref()?;
        self.records.iter().find(|record| record.path() == path)
    }

    #[must_use]
    pub fn view(&self) -> ArchiveView {
        let selected = self.selected_record();
        let revision = self
            .snapshot
            .as_ref()
            .map_or("", |snapshot| snapshot.revision());
        let selected_index = selected
            .and_then(|record| self.records.iter().position(|r| r.path() == record.path()))
            .unwrap_or(0);
        let details = selected.map_or_else(String::new, details);
        let changelog = selected
            .and_then(|record| record.metadata().changelog.as_deref())
            .map_or_else(|| "No changelog supplied for this release.".into(), summary);
        ArchiveView {
            status: self.status.clone(),
            revision: revision.into(),
            releases: self.records.iter().map(release_label).collect(),
            selected: i32::try_from(selected_index).unwrap_or(0),
            version: selected.map_or_else(
                || "No release selected".into(),
                |record| record.version().into(),
            ),
            filename: selected.map_or_else(String::new, |record| record.filename().into()),
            details,
            changelog,
            can_refresh: !self.busy && !self.refreshing,
            can_download: !self.busy && selected.is_some(),
            busy: self.busy,
            refreshing: self.refreshing,
        }
    }
}

impl Drop for ArchiveBrowser {
    fn drop(&mut self) {
        self.worker_cancelled.store(true, Ordering::Release);
        let _ = self.requests.send(Request::Shutdown);
        drop(self.handle.take());
    }
}

fn archive_worker(
    cache_dir: Result<PathBuf, String>,
    requests: Receiver<Request>,
    events: &Sender<ArchiveEvent>,
    cancelled: &AtomicBool,
    enabled: bool,
) {
    if !enabled {
        for request in requests {
            if let Request::Shutdown = request {
                break;
            }
        }
        return;
    }
    let cache_dir = match cache_dir {
        Ok(path) => path,
        Err(error) => {
            let _ = events.send(ArchiveEvent::Failed(error));
            return;
        }
    };
    let client = ArchiveClient::new(cache_dir);
    let cached = client.load_cached().map_err(|error| error.to_string());
    let _ = events.send(ArchiveEvent::Snapshot(cached));
    if !cancelled.load(Ordering::Acquire) {
        let result = client.refresh(cancelled).map_err(|error| error.to_string());
        let _ = events.send(ArchiveEvent::Refreshed(result));
    }
    for request in requests {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        match request {
            Request::Refresh => {
                let result = client.refresh(cancelled).map_err(|error| error.to_string());
                if events.send(ArchiveEvent::Refreshed(result)).is_err() {
                    break;
                }
            }
            Request::Download { snapshot, path } => {
                let result = (|| {
                    let record = snapshot.index().find(&path).cloned().ok_or_else(|| {
                        "Selected release is not in the selected archive snapshot.".to_owned()
                    })?;
                    let cache_path = client
                        .download(&snapshot, &path, cancelled)
                        .map_err(|error| error.to_string())?;
                    let inspection = crate::archive_package::inspect_download(&cache_path, &record);
                    Ok((cache_path, record, inspection))
                })();
                match result {
                    Ok((path, record, inspection)) => {
                        if events
                            .send(ArchiveEvent::Downloaded {
                                path,
                                record: Box::new(record),
                                inspection,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        if events.send(ArchiveEvent::Failed(error)).is_err() {
                            break;
                        }
                    }
                }
            }
            Request::Shutdown => break,
        }
    }
}

fn release_label(record: &ReleaseRecord) -> String {
    format!("{} · {}", record.version(), record.filename())
}

fn summary(changelog: &str) -> String {
    const SUMMARY_LIMIT: usize = 180;
    if changelog.chars().count() <= SUMMARY_LIMIT {
        return changelog.to_owned();
    }
    let mut result: String = changelog.chars().take(SUMMARY_LIMIT).collect();
    result.push('…');
    result
}

fn details(record: &ReleaseRecord) -> String {
    let metadata = record.metadata();
    let mut lines = vec![
        format!("Original ZIP · {} bytes", record.size()),
        format!("ZIP SHA-256 · {}", record.sha256()),
    ];
    lines.push(format!(
        "Firmware member · {} · {} bytes · SHA-256 {}",
        metadata.firmware_member,
        record.firmware_file().size,
        record.firmware_file().sha256
    ));
    if let Some(payload) = record.payload() {
        lines.push(format!(
            "Firmware payload · {} bytes · SHA-256 {}",
            payload.size, payload.sha256
        ));
    }
    if let Some(url) = &metadata.changelog_source_url {
        lines.push(format!("Changelog source · {url}"));
    }
    lines.push(format!("Release source · {}", metadata.source_url));
    if let Some(source) = &metadata.retrieved_from {
        lines.push(format!("Retrieved from · {source}"));
    }
    if let Some(date) = &metadata.retrieved_at {
        lines.push(format!("Retrieved · {date}"));
    }
    if let Some(date) = &metadata.released_at {
        lines.push(format!("Released · {date}"));
    }
    lines.join("\n")
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    fn parts(value: &str) -> Vec<(u64, &str)> {
        value
            .split('.')
            .map(|part| {
                let suffix_start = part
                    .find(|character: char| !character.is_ascii_digit())
                    .unwrap_or(part.len());
                let (numeric, suffix) = part.split_at(suffix_start);
                (numeric.parse().unwrap_or(0), suffix)
            })
            .collect()
    }
    parts(left).cmp(&parts(right))
}

/// Resolve the operating-system cache directory used for verified archive ZIPs.
///
/// # Errors
///
/// Returns an error when the platform does not provide a suitable cache root.
pub fn cache_directory() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        let path = PathBuf::from(path);
        return if path.is_absolute() {
            Ok(path.join("gulikit-updater"))
        } else {
            Err("XDG_CACHE_HOME must be an absolute path.".into())
        };
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home);
        return if path.is_absolute() {
            Ok(path.join("Library/Caches/gulikit-updater"))
        } else {
            Err("HOME must be an absolute path to use the firmware cache.".into())
        };
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        let path = PathBuf::from(path);
        return if path.is_absolute() {
            Ok(path.join("GuliKit/updater"))
        } else {
            Err("LOCALAPPDATA must be an absolute path to use the firmware cache.".into())
        };
    }
    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home);
        return if path.is_absolute() {
            Ok(path.join(".cache/gulikit-updater"))
        } else {
            Err("HOME must be an absolute path to use the firmware cache.".into())
        };
    }
    Err("No absolute OS cache directory is available for the firmware archive.".into())
}
