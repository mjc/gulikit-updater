//! One serialized worker for native dialogs, bounded package I/O and updater operations.
use crate::live::{Event, Work};
use gulikit_core::package::{Component, Model, PackageInfo, VerifiedPackage};
use gulikit_updater::updater::{self, ReceiptIdentity, Reply, Request};
use std::{
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread::{self, JoinHandle},
};

/// Native and demo devices execute requests on the same serialized worker.
pub trait Device: Send {
    /// Execute one request and emit observations before its terminal event.
    ///
    /// # Errors
    /// Returns an error when the request is unsupported, its inputs are invalid,
    /// or the requested record, package, or device operation fails.
    fn run(
        &mut self,
        work: Work,
        cancelled: &AtomicBool,
        emit: &mut dyn FnMut(Event),
    ) -> Result<Event, String>;
}

pub struct NativeDevice;
pub const NATIVE_UPDATE_SUPPORTED: bool = cfg!(target_os = "macos");
pub const NATIVE_UPDATE_UNAVAILABLE: &str = "Native device updates currently support macOS only.";
impl Device for NativeDevice {
    fn run(
        &mut self,
        work: Work,
        cancelled: &AtomicBool,
        emit: &mut dyn FnMut(Event),
    ) -> Result<Event, String> {
        run_native(work, cancelled, emit)
    }
}

pub struct Worker {
    pub requests: Sender<Work>,
    pub cancelled: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}
impl Worker {
    pub fn spawn(device: impl Device + 'static) -> (Self, Receiver<Event>) {
        let (requests, work) = mpsc::channel();
        let (events, replies) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let handle = thread::spawn(move || serve_requests(device, work, &events, &flag));
        (
            Self {
                requests,
                cancelled,
                handle: Some(handle),
            },
            replies,
        )
    }
}

fn serve_requests(
    mut device: impl Device,
    work: Receiver<Work>,
    events: &Sender<Event>,
    cancelled: &AtomicBool,
) {
    let mut emit = |event| {
        if events.send(event).is_err() {
            cancelled.store(true, Ordering::Release);
        }
    };
    let _ = work.into_iter().try_for_each(|request| {
        if let Work::Shutdown = request {
            return ControlFlow::Break(());
        }
        let event = run_catching_failure(&mut device, request, cancelled, &mut emit);
        emit(event);
        ControlFlow::Continue(())
    });
}

fn run_catching_failure(
    device: &mut impl Device,
    work: Work,
    cancelled: &AtomicBool,
    emit: &mut dyn FnMut(Event),
) -> Event {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        device.run(work, cancelled, emit)
    })) {
        Ok(Ok(event)) => event,
        Ok(Err(error)) => Event::Error(error),
        Err(_) => Event::WorkerFailed(
            "Updater worker failed. Inspect the operation record before continuing.".into(),
        ),
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.requests.send(Work::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Reading a selected archive never opens a device or runs the embedded executable.
///
/// # Errors
/// Returns an error if the path cannot be read within the package size limit or
/// the archive does not match a reviewed KK3 Max release for the requested component.
pub fn inspect_selected_package(path: &Path, component: Component) -> Result<Event, String> {
    let package = gulikit_platform::inspect_package(path, Model::Kk3Max, component)
        .map_err(|e| e.to_string())?;
    Ok(Event::Package {
        path: path.to_owned(),
        info: package.info().clone(),
    })
}

fn record_path() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Save a new host operation record")
        .add_filter("Operation record", &["jsonl"])
        .set_file_name("gulikit-attempt.jsonl")
        .save_file()
}

fn run_native(
    work: Work,
    cancelled: &AtomicBool,
    emit: &mut dyn FnMut(Event),
) -> Result<Event, String> {
    if cancelled.load(Ordering::Acquire) {
        return Ok(Event::Cancelled);
    }
    match work {
        Work::ChoosePackage(component) => choose_package(component, cancelled),
        Work::OpenAttempt => open_attempt(),
        Work::Inspect {
            component,
            confirmed: _,
        } => match execute(
            Request::Probe {
                component,
                confirm_ns39: false,
            },
            cancelled,
            emit,
        )? {
            Reply::Inspection(inspection) => Ok(Event::Inspected(inspection)),
            _ => Err("Unexpected inspection result".into()),
        },
        Work::Update {
            path,
            component,
            attachment,
            confirmed,
            expected_package,
        } => {
            if !NATIVE_UPDATE_SUPPORTED {
                return Err(NATIVE_UPDATE_UNAVAILABLE.into());
            }
            if expected_package.component != component {
                return Err("Package component changed since selection.".into());
            }
            update_selected(
                SelectedUpdate {
                    path,
                    expected: expected_package,
                    attachment,
                    confirmed,
                },
                cancelled,
                emit,
                record_path,
                execute,
            )
        }
        Work::Verify {
            attempt,
            confirmed: _,
            same_controller,
            expected_receipt,
        } => verify(attempt, same_controller, expected_receipt, cancelled, emit),
        Work::ConfigureDemo(_) | Work::ChooseSample { .. } => {
            Err("Simulated device operations are unavailable in native mode.".into())
        }
        Work::Shutdown => Ok(Event::Cancelled),
    }
}

struct SelectedUpdate {
    path: PathBuf,
    expected: PackageInfo,
    attachment: updater::Attachment,
    confirmed: bool,
}

fn prepare_selected_update(selection: &SelectedUpdate) -> Result<VerifiedPackage, String> {
    if !selection.confirmed {
        return Err("Inspect the controller before updating.".into());
    }
    let package = gulikit_platform::inspect_package(
        &selection.path,
        Model::Kk3Max,
        selection.expected.component,
    )
    .map_err(|error| error.to_string())?;
    if package.info() != &selection.expected {
        return Err("Firmware package changed since selection. Select and review it again.".into());
    }
    Ok(package)
}

fn update_selected(
    selection: SelectedUpdate,
    cancelled: &AtomicBool,
    emit: &mut dyn FnMut(Event),
    choose_record: impl FnOnce() -> Option<PathBuf>,
    perform: impl FnOnce(Request, &AtomicBool, &mut dyn FnMut(Event)) -> Result<Reply, String>,
) -> Result<Event, String> {
    if cancelled.load(Ordering::Acquire) {
        return Ok(Event::Cancelled);
    }
    let package = prepare_selected_update(&selection)?;
    let Some(record) = choose_record() else {
        return Ok(Event::Cancelled);
    };
    if cancelled.load(Ordering::Acquire) {
        return Ok(Event::Cancelled);
    }
    let reply = perform(
        Request::Update {
            archive: selection.path,
            package,
            confirm_ns39: false,
            record: record.clone(),
            expected_attachment: Some(selection.attachment),
            policy: gulikit_core::version::VersionPolicy::UpgradeOnly,
        },
        cancelled,
        emit,
    )?;
    match reply {
        Reply::Attempt(result) => Ok(Event::Transferred { record, result }),
        Reply::Uncertain { record, reason } => Ok(Event::WorkerFailed(format!(
            "{reason}\nRecord: {}\nKeep USB connected and leave the controller unchanged.",
            record.display()
        ))),
        _ => Ok(Event::WorkerFailed(format!(
            "Unexpected update result. Inspect the record: {}",
            record.display()
        ))),
    }
}

fn choose_package(component: Component, cancelled: &AtomicBool) -> Result<Event, String> {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Choose original firmware ZIP")
        .add_filter("Firmware ZIP", &["zip"])
        .pick_file()
    else {
        return Ok(Event::Cancelled);
    };
    if cancelled.load(Ordering::Acquire) {
        return Ok(Event::Cancelled);
    }
    inspect_selected_package(&path, component)
}

fn open_attempt() -> Result<Event, String> {
    if !cfg!(target_os = "macos") {
        return Err("Native verification currently supports macOS only.".into());
    }
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open an update record for fresh verification")
        .add_filter("Operation record", &["jsonl"])
        .pick_file()
    else {
        return Ok(Event::Cancelled);
    };
    #[cfg(unix)]
    {
        let prior = updater::PriorAttempt::parse(&gulikit_platform::journal::read_attempt(&path)?)?;
        Ok(Event::Prior { path, prior })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("Native verification currently supports macOS only.".into())
    }
}

fn verify(
    attempt: PathBuf,
    same_controller: bool,
    expected_receipt: ReceiptIdentity,
    cancelled: &AtomicBool,
    emit: &mut dyn FnMut(Event),
) -> Result<Event, String> {
    let Some(record) = record_path() else {
        return Ok(Event::Cancelled);
    };
    if cancelled.load(Ordering::Acquire) {
        return Ok(Event::Cancelled);
    }
    match execute(
        Request::Verify {
            attempt,
            record,
            confirm_ns39: false,
            confirm_same_controller: same_controller,
            expected_receipt: Some(expected_receipt),
        },
        cancelled,
        emit,
    )? {
        Reply::Readback(result) => Ok(Event::Verified(result)),
        _ => Err("Unexpected verification result".into()),
    }
}

fn execute(
    request: Request,
    cancelled: &AtomicBool,
    emit: &mut dyn FnMut(Event),
) -> Result<Reply, String> {
    updater::execute(
        request,
        &mut || cancelled.load(Ordering::Acquire),
        &mut |progress| emit(Event::Progress(progress)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection() -> SelectedUpdate {
        let release = gulikit_core::package::catalog()
            .iter()
            .find(|release| release.component == Component::Main)
            .unwrap();
        SelectedUpdate {
            path: "missing.zip".into(),
            expected: PackageInfo {
                model: Model::Kk3Max,
                component: Component::Main,
                version: release.version.into(),
                payload_size: release.payload_size(),
                payload_sha256: release.payload_sha256().into(),
                archive_sha256: release.archive_sha256.into(),
                source_url: release.source_url,
                member: release.member,
            },
            attachment: updater::Attachment {
                ancestor: 42,
                generation: 7,
            },
            confirmed: true,
        }
    }

    #[test]
    fn cancelled_or_unconfirmed_native_updates_never_open_the_picker_or_device() {
        let mut selected = selection();
        let event = update_selected(
            selected,
            &AtomicBool::new(true),
            &mut |_| panic!("no progress"),
            || panic!("no picker"),
            |_, _, _| panic!("no device"),
        )
        .unwrap();
        assert!(matches!(event, Event::Cancelled));
        selected = selection();
        selected.confirmed = false;
        let error = update_selected(
            selected,
            &AtomicBool::new(false),
            &mut |_| panic!("no progress"),
            || panic!("no picker"),
            |_, _, _| panic!("no device"),
        )
        .unwrap_err();
        assert!(error.contains("Inspect the controller"), "{error}");
    }

    fn original(component: Component) -> SelectedUpdate {
        let directory = std::env::var_os("GULIKIT_VENDOR_DIR").map_or_else(
            || {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/vendor/kk3/packages")
            },
            PathBuf::from,
        );
        let archive = match component {
            Component::Main => "KK3_NS38_NS39_V5.9.zip",
            Component::Bluetooth => "NS38_NS39_BT_V3.24.zip",
        };
        let path = directory.join(archive);
        let package = gulikit_platform::inspect_package(&path, Model::Kk3Max, component)
            .expect("supply original archives with GULIKIT_VENDOR_DIR");
        SelectedUpdate {
            path,
            expected: package.info().clone(),
            ..selection()
        }
    }

    #[test]
    #[ignore = "requires original vendor archives in ignored cache"]
    fn native_selection_dispatches_both_components_with_bound_package_and_attachment() {
        for component in [Component::Main, Component::Bluetooth] {
            let selected = original(component);
            let expected = selected.expected.clone();
            let archive = selected.path.clone();
            let host = tempfile::tempdir().unwrap();
            let record = host.path().join("attempt.jsonl");
            let mut observed = Vec::new();
            let event = update_selected(
                selected,
                &AtomicBool::new(false),
                &mut |value| observed.push(value),
                || Some(record.clone()),
                |request, _, emit| {
                    let Request::Update {
                        archive: actual_archive,
                        package,
                        record: actual_record,
                        expected_attachment,
                        confirm_ns39,
                        policy,
                    } = request
                    else {
                        panic!("update request");
                    };
                    assert_eq!(actual_archive, archive);
                    assert_eq!(package.info(), &expected);
                    assert_eq!(actual_record, record);
                    assert_eq!(
                        expected_attachment,
                        Some(updater::Attachment {
                            ancestor: 42,
                            generation: 7
                        })
                    );
                    assert!(!confirm_ns39, "native requests require USB identification");
                    assert_eq!(policy, gulikit_core::version::VersionPolicy::UpgradeOnly);
                    emit(Event::Progress(gulikit_core::update::Progress {
                        submitted: 512,
                        confirmed: 512,
                        total: expected.payload_size,
                    }));
                    Ok(Reply::Uncertain {
                        record: actual_record,
                        reason: "injected reporting failure".into(),
                    })
                },
            )
            .unwrap();
            assert!(
                matches!(observed.as_slice(), [Event::Progress(value)] if value.confirmed == 512)
            );
            assert!(
                matches!(event, Event::WorkerFailed(error) if error.contains("injected reporting failure") && error.contains("attempt.jsonl"))
            );
            assert!(
                !record.exists(),
                "the fake executor must never create a device record"
            );
        }
    }

    #[test]
    #[ignore = "requires original vendor archives in ignored cache"]
    fn changed_selection_and_picker_cancellation_never_dispatch_a_native_update() {
        let mut selected = original(Component::Bluetooth);
        selected.expected.version = "3.23".into();
        let error = update_selected(
            selected,
            &AtomicBool::new(false),
            &mut |_| panic!("no progress"),
            || panic!("changed package must not open picker"),
            |_, _, _| panic!("no device"),
        )
        .unwrap_err();
        assert!(error.contains("changed since selection"));
        let event = update_selected(
            original(Component::Main),
            &AtomicBool::new(false),
            &mut |_| panic!("no progress"),
            || None,
            |_, _, _| panic!("no device"),
        )
        .unwrap();
        assert!(matches!(event, Event::Cancelled));
        let cancelled = AtomicBool::new(false);
        let event = update_selected(
            original(Component::Main),
            &cancelled,
            &mut |_| panic!("no progress"),
            || {
                cancelled.store(true, Ordering::Release);
                Some("unused.jsonl".into())
            },
            |_, _, _| panic!("no device"),
        )
        .unwrap();
        assert!(matches!(event, Event::Cancelled));
    }
}
