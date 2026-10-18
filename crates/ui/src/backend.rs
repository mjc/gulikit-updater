//! One serialized worker for native dialogs, bounded package I/O and updater operations.
use crate::live::{Event, Work};
use gulikit_core::package::{Component, Model};
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
    fn run(
        &mut self,
        work: Work,
        cancelled: &AtomicBool,
        emit: &mut dyn FnMut(Event),
    ) -> Result<Event, String>;
}

pub struct NativeDevice;
pub const NATIVE_UPDATE_UNAVAILABLE: &str =
    "Desktop updates are not available yet. You can still inspect firmware packages.";
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
        let handle = thread::spawn(move || serve_requests(device, work, events, &flag));
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
    events: Sender<Event>,
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
            confirmed,
        } => match execute(
            Request::Probe {
                component,
                confirm_ns39: confirmed,
            },
            cancelled,
            emit,
        )? {
            Reply::Inspection(inspection) => Ok(Event::Inspected(inspection)),
            _ => Err("Unexpected inspection result".into()),
        },
        Work::Update { .. } => Err(NATIVE_UPDATE_UNAVAILABLE.into()),
        Work::Verify {
            attempt,
            confirmed,
            same_controller,
            expected_receipt,
        } => verify(
            attempt,
            confirmed,
            same_controller,
            expected_receipt,
            cancelled,
            emit,
        ),
        Work::ConfigureDemo(_) | Work::ChooseSample { .. } => {
            Err("Simulated device operations are unavailable in native mode.".into())
        }
        Work::Shutdown => Ok(Event::Cancelled),
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
    confirmed: bool,
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
            confirm_ns39: confirmed,
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
