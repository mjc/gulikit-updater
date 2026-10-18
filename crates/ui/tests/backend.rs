use gulikit_core::package::Component;
use gulikit_ui::{
    backend::{Device, NativeDevice, Worker, inspect_selected_package},
    demo::{Profile, SamplePackage},
    live::{Event, Work},
};
use gulikit_updater::updater::Attachment;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[test]
fn native_cancellation_and_simulator_requests_never_enter_device_access() {
    let mut device = NativeDevice;
    assert!(matches!(
        device
            .run(
                Work::Inspect {
                    component: Component::Main,
                    confirmed: true
                },
                &AtomicBool::new(true),
                &mut |_| {}
            )
            .unwrap(),
        Event::Cancelled
    ));
    for work in [
        Work::ConfigureDemo(Profile::Normal),
        Work::ChooseSample {
            component: Component::Main,
            sample: SamplePackage::Matching,
        },
    ] {
        assert!(
            device
                .run(work, &AtomicBool::new(false), &mut |_| {})
                .unwrap_err()
                .contains("unavailable in native mode")
        );
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_native_record_access_is_refused_before_any_dialog() {
    let result = NativeDevice.run(Work::OpenAttempt, &AtomicBool::new(false), &mut |_| {
        panic!("unsupported record access cannot publish events")
    });
    assert!(result.unwrap_err().contains("macOS only"));
}

#[test]
fn native_update_is_unavailable_before_package_io_or_dialogs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("changed-package.zip");
    std::fs::write(&path, b"not a reviewed firmware archive").unwrap();
    assert!(inspect_selected_package(&path, Component::Main).is_err());
    let mut device = NativeDevice;
    let work = Work::Update {
        policy: gulikit_core::version::VersionPolicy::UpgradeOnly,
        path: path.clone(),
        component: Component::Main,
        attachment: Attachment {
            ancestor: 42,
            generation: 7,
        },
        confirmed: true,
    };
    assert!(
        device
            .run(work, &AtomicBool::new(false), &mut |_| panic!(
                "rejected packages cannot publish progress"
            ))
            .unwrap_err()
            .contains(gulikit_ui::backend::NATIVE_UPDATE_UNAVAILABLE)
    );
    std::fs::remove_file(&path).unwrap();
    assert!(inspect_selected_package(&path, Component::Main).is_err());
}

struct ScriptedDevice(Arc<AtomicUsize>);
impl Device for ScriptedDevice {
    fn run(
        &mut self,
        work: Work,
        _: &AtomicBool,
        emit: &mut dyn FnMut(Event),
    ) -> Result<Event, String> {
        let index = self.0.fetch_add(1, Ordering::AcqRel);
        assert!(index != 0, "simulated device worker panic");
        assert!(matches!(work, Work::ChoosePackage(Component::Main)));
        emit(Event::Error("progress event before result".into()));
        Err("second operation completed".into())
    }
}
#[test]
fn one_worker_serializes_device_operations_and_reports_panics_before_next_result() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (worker, events) = Worker::spawn(ScriptedDevice(calls.clone()));
    worker
        .requests
        .send(Work::Inspect {
            component: Component::Main,
            confirmed: true,
        })
        .unwrap();
    worker
        .requests
        .send(Work::ChoosePackage(Component::Main))
        .unwrap();
    assert!(
        matches!(events.recv_timeout(Duration::from_secs(5)).unwrap(), Event::WorkerFailed(e) if e.contains("worker failed"))
    );
    assert!(
        matches!(events.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Error(e) if e == "progress event before result")
    );
    assert!(
        matches!(events.recv_timeout(Duration::from_secs(5)).unwrap(), Event::Error(e) if e == "second operation completed")
    );
    drop(worker);
    assert_eq!(calls.load(Ordering::Acquire), 2);
}

#[test]
#[ignore = "requires original vendor archives in ignored cache"]
fn selected_vendor_archives_are_inspectable_and_changed_archives_are_rejected() {
    let vendor = std::env::var_os("GULIKIT_VENDOR_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/vendor/kk3/packages")
        },
        std::path::PathBuf::from,
    );
    for (component, archive, version, size) in [
        (Component::Main, "KK3_NS38_NS39_V5.9.zip", "5.9", 51_500),
        (
            Component::Bluetooth,
            "NS38_NS39_BT_V3.24.zip",
            "3.24",
            361_472,
        ),
        (
            Component::Bluetooth,
            "GuliKit_NS38_NS39_NS59_BT_V5.07.zip",
            "5.07",
            345_088,
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let selected = directory.path().join(archive);
        std::fs::copy(vendor.join(archive), &selected)
            .expect("supply original archives with GULIKIT_VENDOR_DIR");
        let Event::Package { path, info } = inspect_selected_package(&selected, component).unwrap()
        else {
            panic!("expected selected package metadata");
        };
        assert_eq!(path, selected);
        assert_eq!(info.component, component);
        assert_eq!(info.version, version);
        assert_eq!(info.payload_size, size);
        let mut bytes = std::fs::read(&selected).unwrap();
        bytes[100] ^= 1;
        std::fs::write(&selected, bytes).unwrap();
        assert!(inspect_selected_package(&selected, component).is_err());
        let work = Work::Update {
            policy: gulikit_core::version::VersionPolicy::UpgradeOnly,
            path: selected,
            component,
            attachment: Attachment {
                ancestor: 42,
                generation: 7,
            },
            confirmed: true,
        };
        assert!(
            NativeDevice
                .run(work, &AtomicBool::new(false), &mut |_| panic!(
                    "changed archive cannot publish progress"
                ))
                .is_err()
        );
    }
}

#[test]
fn replaced_or_reenumerated_desktop_attachment_requires_new_inspection() {
    let target = gulikit_platform::discovery::NativeCandidate {
        ancestor: 42,
        generation: 7,
        main_volume_candidate: true,
        bluetooth_transport_candidate: true,
        observed_profile: true,
        conflicting_model: false,
        storage_identities: vec![],
        disks: vec![],
        mount: None,
    };
    assert!(
        gulikit_updater::updater::check_attachment(
            Some(Attachment {
                ancestor: 42,
                generation: 7
            }),
            &target
        )
        .is_ok()
    );
    for expected in [
        Attachment {
            ancestor: 43,
            generation: 7,
        },
        Attachment {
            ancestor: 42,
            generation: 8,
        },
    ] {
        assert!(gulikit_updater::updater::check_attachment(Some(expected), &target).is_err());
    }
}

#[path = "common/mod.rs"]
#[allow(dead_code)]
mod common;

struct PanicDevice;
impl Device for PanicDevice {
    fn run(&mut self, _: Work, _: &AtomicBool, _: &mut dyn FnMut(Event)) -> Result<Event, String> {
        panic!("transport panicked after possible submission, before progress");
    }
}
#[test]
fn update_panic_before_progress_holds_retry_and_shutdown_stops_iteration() {
    use gulikit_ui::{Page, live::LiveApp};
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect().unwrap();
    app.accept(Event::Inspected(common::inspection()));
    app.choose_package().unwrap();
    app.accept(Event::Package {
        path: "official.zip".into(),
        info: common::package(),
    });
    let (worker, events) = Worker::spawn(PanicDevice);
    worker.requests.send(app.start().unwrap()).unwrap();
    app.accept(events.recv_timeout(Duration::from_secs(5)).unwrap());
    assert_eq!(app.view().progress.submitted, 0);
    assert_eq!(app.view().page, Page::Failed);
    assert!(!app.view().can_primary);
    assert!(app.connect().is_none());
    worker.requests.send(Work::Shutdown).unwrap();
    assert!(matches!(
        events.recv_timeout(Duration::from_secs(5)),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    drop(worker);
}

#[test]
fn paced_demo_exposes_progress_and_accepts_cancellation_before_completion() {
    use gulikit_ui::{Page, demo::DemoDevice, live::LiveApp};
    let (ticks, waiting) = std::sync::mpsc::channel();
    let (advance, gate) = std::sync::mpsc::channel();
    let device = DemoDevice::with_transfer_wait(move |duration| {
        ticks.send(duration).unwrap();
        gate.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let (worker, events) = Worker::spawn(device);
    let mut app = LiveApp::default();
    app.confirm_model(true);
    worker.requests.send(app.connect().unwrap()).unwrap();
    app.accept(events.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.requests.send(app.choose_package().unwrap()).unwrap();
    app.accept(events.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.requests.send(app.start().unwrap()).unwrap();
    app.accept(events.recv_timeout(Duration::from_secs(5)).unwrap());
    assert_eq!(
        waiting.recv_timeout(Duration::from_secs(5)).unwrap(),
        Duration::from_millis(80)
    );
    assert_eq!(app.view().page, Page::Writing);
    assert!(
        app.view().progress.confirmed > 0
            && app.view().progress.confirmed < app.view().progress.total
    );
    assert!(
        events.try_recv().is_err(),
        "terminal result must wait for the next clock step"
    );
    worker.cancelled.store(true, Ordering::Release);
    advance.send(()).unwrap();
    app.accept(events.recv_timeout(Duration::from_secs(5)).unwrap());
    assert_eq!(app.view().page, Page::Failed);
    assert!(!app.view().can_primary);
    drop(worker);
}

#[test]
fn unavailable_download_is_refused_before_browser_or_file_dialog() {
    let mut raw: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../catalog/official.json")).unwrap();
    raw["entries"][0]["availability"] = "unavailable".into();
    let catalog = gulikit_catalog::Catalog::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    let result = NativeDevice.run(
        Work::DownloadRelease(Box::new(catalog.entries()[0].clone())),
        &AtomicBool::new(false),
        &mut |_| panic!("no device events"),
    );
    assert!(result.unwrap_err().contains("unavailable"));
}
