use super::*;
use gulikit_core::package::Component;
use i_slint_backend_testing::{ElementHandle, TestingBackend, TestingBackendOptions};
use slint::platform::{PointerEventButton, WindowEvent};
use std::time::Duration;

fn init_backend() {
    // Each test thread owns its backend, clock, clipboard and windows. No desktop access.
    thread_local! {
        static INITIALIZED: () = slint::platform::set_platform(Box::new(TestingBackend::new(
            TestingBackendOptions {
                mock_time: true,
                renderer_name: Some("software".into()),
                ..Default::default()
            },
        )))
        .unwrap();
    }
    INITIALIZED.with(|()| {});
}

fn layout(ui: &AppWindow) {
    i_slint_backend_testing::mock_elapsed_time(Duration::ZERO);
    ui.window().take_snapshot().unwrap();
}

fn element(ui: &AppWindow, label: &str) -> ElementHandle {
    ElementHandle::find_by_accessible_label(ui, label)
        .next()
        .unwrap_or_else(|| panic!("missing UI element: {label}"))
}

fn click(ui: &AppWindow, label: &str) {
    element(ui, label).mock_single_click(PointerEventButton::Left);
    layout(ui);
}

fn key(ui: &AppWindow, text: impl Into<slint::SharedString>) {
    let text = text.into();
    ui.window()
        .dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    ui.window()
        .dispatch_event(WindowEvent::KeyReleased { text });
    layout(ui);
}

fn inside_window(ui: &AppWindow, item: &ElementHandle) {
    let position = item.absolute_position();
    let size = item.size();
    let window = ui.window().size();
    assert!(size.width > 0. && size.height > 0.);
    assert!(position.x >= 0. && position.y >= 0.);
    assert!(f64::from(position.x + size.width) <= f64::from(window.width) + 1.);
    assert!(
        f64::from(position.y + size.height) <= f64::from(window.height) + 1.,
        "element y={} + height={} exceeds window height={}",
        position.y,
        size.height,
        window.height
    );
}

#[test]
fn normal_startup_never_presents_a_simulated_controller() {
    let app = LiveHarness::new();
    assert!(
        ElementHandle::find_by_accessible_label(
            &app.ui,
            "I checked the NS39 label and Max controls"
        )
        .next()
        .is_none()
    );
    assert!(
        ElementHandle::find_by_accessible_label(&app.ui, "DEMO")
            .next()
            .is_none(),
        "normal startup must use the real updater"
    );
    assert!(
        app.work.try_recv().is_err(),
        "startup must not open devices or start an update"
    );
    assert_eq!(
        element(&app.ui, "Inspect controller").accessible_enabled(),
        Some(true)
    );
    app.ui.invoke_inspect_controller();
    assert!(matches!(
        app.work.try_recv().unwrap(),
        gulikit_ui::live::Work::Inspect {
            confirmed: false,
            ..
        }
    ));
    app.ui.invoke_primary_action();
    assert!(app.work.try_recv().is_err());
}

#[test]
fn desktop_renders_both_components_and_routes_confirmed_inspection() {
    use gulikit_ui::live::Work;

    let app = LiveHarness::new();
    assert!(app.work.try_recv().is_err());
    for size in [(760., 600.), (1000., 660.)] {
        app.ui
            .window()
            .set_size(slint::LogicalSize::new(size.0, size.1));
        app.ui.invoke_select_component(false);
        layout(&app.ui);
        let main = app.ui.window().take_snapshot().unwrap();
        assert!(!app.ui.get_state().bluetooth);
        assert!(
            main.as_slice()
                .iter()
                .filter(|pixel| pixel.r < 100 && pixel.g < 130 && pixel.b < 100)
                .count()
                > 1000,
            "the desktop must render content at each supported window size"
        );
        app.ui.invoke_select_component(true);
        layout(&app.ui);
        let bluetooth = app.ui.window().take_snapshot().unwrap();
        assert!(app.ui.get_state().bluetooth);
        assert_eq!(main.width(), bluetooth.width());
        assert_eq!(main.height(), bluetooth.height());
        assert_ne!(main.as_bytes(), bluetooth.as_bytes());
    }
    assert!(app.work.try_recv().is_err());
    app.ui.invoke_inspect_controller();
    assert!(matches!(
        app.work.try_recv().unwrap(),
        Work::Inspect {
            component: Component::Bluetooth,
            confirmed: false
        }
    ));
}

#[test]
fn controller_and_button_guidance_survive_display_scale_changes() {
    let app = LiveHarness::new();
    for scale in [1., 2., 3.] {
        app.ui
            .window()
            .dispatch_event(WindowEvent::ScaleFactorChanged {
                scale_factor: scale,
            });
        let logical_size = slint::LogicalSize::new(760., 600.);
        // The testing adapter assumes 1× in set_size; provide its backing size
        // and the logical resize event separately when simulating another scale.
        app.ui.window().set_size(logical_size.to_physical(scale));
        app.ui
            .window()
            .dispatch_event(WindowEvent::Resized { size: logical_size });
        layout(&app.ui);
        let controller = element(&app.ui, "KK3 Max controller illustration");
        inside_window(&app.ui, &controller);
        inside_window(
            &app.ui,
            &element(&app.ui, "A button (rightmost in default Switch layout)"),
        );
        let position = controller.absolute_position();
        let size = controller.size();
        let horizontal =
            f64::from(position.x * scale)..f64::from((position.x + size.width) * scale);
        let vertical = f64::from(position.y * scale)..f64::from((position.y + size.height) * scale);
        let snapshot = app.ui.window().take_snapshot().unwrap();
        let width = usize::try_from(snapshot.width()).unwrap();
        let ink = snapshot
            .as_slice()
            .chunks_exact(width)
            .enumerate()
            .filter(|(y, _)| vertical.contains(&f64::from(u32::try_from(*y).unwrap())))
            .flat_map(|(_, row)| row.iter().enumerate())
            .filter(|(x, pixel)| {
                horizontal.contains(&f64::from(u32::try_from(*x).unwrap()))
                    && pixel.r < 200
                    && pixel.g < 210
                    && pixel.b < 200
            })
            .count();
        assert!(
            ink > 100,
            "the controller illustration must remain visible at {scale}×"
        );
    }
}

#[test]
fn native_record_control_matches_platform_verification_support() {
    let app = LiveHarness::new();
    let record = element(&app.ui, "Open record…");
    assert_eq!(record.accessible_enabled(), Some(cfg!(target_os = "macos")));
    if !cfg!(target_os = "macos") {
        click(&app.ui, "Open record…");
        assert!(app.work.try_recv().is_err());
    }
}

#[test]
fn native_ready_enables_updates_only_on_supported_platforms() {
    let app = LiveHarness::new();
    app.prepare_main();
    assert_eq!(app.ui.get_state().page, Page::Ready);
    assert_eq!(app.ui.get_state().can_update, cfg!(target_os = "macos"));
    assert_eq!(app.ui.get_primary_enabled(), cfg!(target_os = "macos"));
    click(&app.ui, "Update to 5.9  →");
    if cfg!(target_os = "macos") {
        assert!(matches!(
            app.work.try_recv().unwrap(),
            gulikit_ui::live::Work::Update { .. }
        ));
        assert_eq!(app.ui.get_state().page, Page::Writing);
    } else {
        assert!(app.work.try_recv().is_err());
    }
}

#[test]
fn native_primary_callback_dispatches_only_on_supported_platforms() {
    let app = LiveHarness::new();
    app.prepare_main();
    app.ui.invoke_primary_action();
    if cfg!(target_os = "macos") {
        assert!(matches!(
            app.work.try_recv().unwrap(),
            gulikit_ui::live::Work::Update { .. }
        ));
        assert_eq!(app.ui.get_state().page, Page::Writing);
        assert!(app.ui.get_state().busy);
    } else {
        assert!(app.work.try_recv().is_err());
        assert_eq!(app.ui.get_state().page, Page::Ready);
        assert!(!app.ui.get_state().busy);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn loaded_pending_receipt_disables_record_replacement_in_native_controls() {
    use gulikit_core::update::Outcome;
    let app = LiveHarness::new();
    app.open_record(live_fixtures::attempt(
        Outcome::TransferSubmittedPendingCompletion,
    ));
    assert_eq!(app.ui.get_state().page, Page::Restart);
    assert!(
        app.ui
            .get_state()
            .notice
            .contains("Confirm the same physical NS39")
    );
    assert_eq!(
        element(&app.ui, "Open record…").accessible_enabled(),
        Some(false)
    );
    click(&app.ui, "Open record…");
    assert!(app.work.try_recv().is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn recovery_hold_hides_connection_troubleshooting_advice() {
    use gulikit_core::update::Outcome;
    for outcome in [
        Outcome::OutcomeUnknown,
        Outcome::DestinationCreatedWithoutPayload,
    ] {
        let app = LiveHarness::new();
        let mut result = live_fixtures::attempt(outcome);
        if outcome == Outcome::DestinationCreatedWithoutPayload {
            result.transfer.bytes_submitted = 0;
            result.transfer.bytes_confirmed = 0;
            result.transfer.main_destination_created = true;
        }
        app.open_record(result);
        assert_eq!(app.ui.get_state().page, Page::Failed);
        let expected_notice = match outcome {
            Outcome::OutcomeUnknown => "Transfer outcome unknown. No retry or resume.",
            Outcome::DestinationCreatedWithoutPayload => {
                "No firmware payload bytes were submitted, but a file was created on the controller."
            }
            _ => unreachable!(),
        };
        assert!(app.ui.get_state().notice.starts_with(expected_notice));
        assert!(
            ElementHandle::find_by_accessible_label(
                &app.ui,
                "Check the connection before continuing."
            )
            .next()
            .is_none()
        );
        element(&app.ui, "Keep the controller connected and unchanged.");
        assert_eq!(
            element(&app.ui, "Open record…").accessible_enabled(),
            Some(false)
        );
        assert_eq!(
            element(&app.ui, "Connection help").accessible_enabled(),
            Some(false)
        );
        assert_eq!(app.ui.get_state().page, Page::Failed);
        assert!(
            ElementHandle::find_by_accessible_label(
                &app.ui,
                "Start with the controller off and connect USB."
            )
            .next()
            .is_none()
        );
    }
}

#[test]
fn an_open_help_popup_replaces_mode_instructions_when_a_recovery_hold_arrives() {
    use gulikit_ui::live::{Event, Work};
    let app = LiveHarness::new_mode(true);
    app.prepare_main();
    click(&app.ui, "Connection help");
    element(
        &app.ui,
        "Switch modes: Mode off → normal on, then off again.",
    );
    // Invoke the bound action while help is open, then deliver the worker's result.
    app.ui.invoke_primary_action();
    assert!(matches!(app.work.try_recv().unwrap(), Work::Update { .. }));
    app.send(Event::WorkerFailed("worker ended before progress".into()));
    assert!(
        ElementHandle::find_by_accessible_label(
            &app.ui,
            "Switch modes: Mode off → normal on, then off again."
        )
        .next()
        .is_none()
    );
    element(&app.ui, "Keep the controller connected and unchanged.");
    element(&app.ui, "Done");
}

#[path = "../tests/common/mod.rs"]
mod live_fixtures;

struct LiveHarness {
    ui: AppWindow,
    _timer: slint::Timer,
    work: std::sync::mpsc::Receiver<gulikit_ui::live::Work>,
    events: std::sync::mpsc::Sender<gulikit_ui::live::Event>,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl LiveHarness {
    fn new() -> Self {
        Self::new_mode(false)
    }
    fn new_mode(demo: bool) -> Self {
        init_backend();
        let (requests, work) = std::sync::mpsc::channel();
        let (events, replies) = std::sync::mpsc::channel();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (ui, timer) = live_ui::create_mode(requests, replies, cancelled.clone(), demo).unwrap();
        ui.show().unwrap();
        ui.window().set_size(slint::LogicalSize::new(760., 600.));
        layout(&ui);
        Self {
            ui,
            _timer: timer,
            work,
            events,
            cancelled,
        }
    }
    fn send(&self, event: gulikit_ui::live::Event) {
        self.events.send(event).unwrap();
        i_slint_backend_testing::mock_elapsed_time(Duration::from_millis(30));
        layout(&self.ui);
    }
    fn prepare_main(&self) {
        use gulikit_ui::live::{Event, Work};
        click(&self.ui, "Inspect controller");
        assert!(matches!(
            self.work.try_recv().unwrap(),
            Work::Inspect {
                component: Component::Main,
                confirmed: false
            }
        ));
        self.send(Event::Inspected(live_fixtures::inspection()));
        click(&self.ui, "Choose file…");
        if self.ui.get_demo_mode() {
            click(&self.ui, "NS39 · Main 5.9");
            assert!(matches!(
                self.work.try_recv().unwrap(),
                Work::ChooseSample {
                    component: Component::Main,
                    sample: gulikit_ui::demo::SamplePackage::Matching,
                }
            ));
        } else {
            assert!(matches!(
                self.work.try_recv().unwrap(),
                Work::ChoosePackage(Component::Main)
            ));
        }
        self.send(Event::Package {
            path: "original-reviewed-package.zip".into(),
            info: live_fixtures::package(),
        });
    }
    #[cfg(target_os = "macos")]
    fn open_record(&self, result: gulikit_updater::updater::Attempt) {
        use gulikit_ui::live::{Event, Work};
        click(&self.ui, "Open record…");
        assert!(matches!(self.work.try_recv().unwrap(), Work::OpenAttempt));
        let file = tempfile::NamedTempFile::new().unwrap();
        let finalized = gulikit_platform::journal::finalize_record(
            &mut file.reopen().unwrap(),
            serde_json::to_value(result).unwrap(),
        );
        assert_eq!(finalized["record_finalized"], true);
        let prior =
            gulikit_updater::updater::PriorAttempt::parse(&std::fs::read(file.path()).unwrap())
                .unwrap();
        assert_eq!(prior.record["record_finalized"], true);
        self.send(Event::Prior {
            path: "attempt.jsonl".into(),
            prior,
        });
    }
}

#[test]
fn shared_controls_only_transfer_on_click_and_only_verify_after_fresh_readback() {
    use gulikit_core::update::{Outcome, Progress};
    use gulikit_ui::live::{Event, Work};
    let app = LiveHarness::new_mode(true);
    assert_eq!(
        element(&app.ui, "Inspect controller").accessible_enabled(),
        Some(true)
    );
    assert!(app.work.try_recv().is_err());
    app.prepare_main();
    click(&app.ui, "Update to 5.9  →");
    assert!(matches!(
        app.work.try_recv().unwrap(),
        Work::Update {
            component: Component::Main,
            confirmed: true,
            ..
        }
    ));
    assert_eq!(
        element(&app.ui, "Bluetooth firmware, Version unknown").accessible_enabled(),
        Some(false)
    );
    i_slint_backend_testing::mock_elapsed_time(Duration::from_secs(10));
    layout(&app.ui);
    assert_eq!(
        app.ui.get_state().progress.to_bits(),
        0_f32.to_bits(),
        "wall time cannot invent transfer progress"
    );
    app.send(Event::Progress(Progress {
        submitted: 4096,
        confirmed: 79,
        total: 51500,
    }));
    assert_eq!(
        app.ui.get_state().transfer_label,
        "79 / 51500 bytes confirmed"
    );
    app.send(Event::Transferred {
        record: "attempt.jsonl".into(),
        result: live_fixtures::attempt(Outcome::TransferCompletedAwaitingVerification),
    });
    assert_eq!(app.ui.get_state().page, Page::Restart);
    assert_eq!(app.ui.get_state().main_version, "5.8");
    click(&app.ui, "Check version  →");
    assert!(app.work.try_recv().is_err());
    click(&app.ui, "Confirm same controller");
    click(&app.ui, "Check version  →");
    assert!(matches!(
        app.work.try_recv().unwrap(),
        Work::Verify {
            confirmed: true,
            same_controller: true,
            ..
        }
    ));
    app.send(Event::Verified(live_fixtures::readback(8, "5.9")));
    assert_eq!(app.ui.get_state().page, Page::Verified);
    assert_eq!(app.ui.get_state().main_version, "5.9");
    assert_eq!(app.ui.get_state().bt_version, "Version unknown");
}

#[test]
fn shared_cancel_requests_backend_cancellation_without_inventing_a_result() {
    use gulikit_core::update::Progress;
    use gulikit_ui::live::Event;
    let app = LiveHarness::new_mode(true);
    app.prepare_main();
    click(&app.ui, "Update to 5.9  →");
    app.work.try_recv().unwrap();
    app.send(Event::Progress(Progress {
        submitted: 4096,
        confirmed: 79,
        total: 51500,
    }));
    click(&app.ui, "Cancel");
    assert!(app.cancelled.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(app.ui.get_state().page, Page::Writing);
    assert!(app.work.try_recv().is_err());
    app.send(Event::Error("Cancelled after possible submission".into()));
    assert_eq!(app.ui.get_state().page, Page::Failed);
    assert!(app.ui.get_state().notice.contains("No retry"));
}

#[test]
fn progress_updates_reuse_unchanged_text_and_still_present_recovery_holds() {
    use gulikit_core::update::Progress;
    use gulikit_ui::live::Event;
    let app = LiveHarness::new_mode(true);
    app.prepare_main();
    click(&app.ui, "Update to 5.9  →");
    app.work.try_recv().unwrap();
    let before = app.ui.get_state();
    for confirmed in [79, 158, 237] {
        app.send(Event::Progress(Progress {
            submitted: 4096,
            confirmed,
            total: 51500,
        }));
        let after = app.ui.get_state();
        assert_eq!(
            after.transfer_label,
            format!("{confirmed} / 51500 bytes confirmed")
        );
        for (before, after) in [
            (&before.main_version, &after.main_version),
            (&before.filename, &after.filename),
            (&before.payload, &after.payload),
            (&before.digest, &after.digest),
            (&before.notice, &after.notice),
            (&before.log, &after.log),
        ] {
            assert_eq!(before, after);
            assert_eq!(before.as_str().as_ptr(), after.as_str().as_ptr());
        }
        assert_eq!(
            after.notice.as_str().as_ptr(),
            after.error.as_str().as_ptr()
        );
    }
    app.send(Event::Progress(Progress {
        submitted: 4096,
        confirmed: 0,
        total: 51500,
    }));
    let held = app.ui.get_state();
    assert_eq!(held.progress.to_bits(), (237_f32 / 51_500.).to_bits());
    assert!(held.notice.contains("No retry or resume"));
    assert_eq!(held.notice, held.error);
    assert!(!app.ui.get_primary_enabled());
    assert_eq!(held.log.as_str().as_ptr(), before.log.as_str().as_ptr());
}

struct DemoHarness {
    app: LiveHarness,
    device: gulikit_ui::demo::DemoDevice,
}
impl DemoHarness {
    fn new() -> Self {
        let app = LiveHarness::new_mode(true);
        Self {
            app,
            device: gulikit_ui::demo::DemoDevice::with_transfer_wait(|_| {}),
        }
    }
    fn pump(&mut self) {
        use gulikit_ui::backend::Device;
        while let Ok(work) = self.app.work.try_recv() {
            let event = self
                .device
                .run(work, &self.app.cancelled, &mut |event| self.app.send(event))
                .unwrap_or_else(gulikit_ui::live::Event::Error);
            self.app.send(event);
        }
    }
    fn click(&mut self, label: &str) {
        click(&self.app.ui, label);
        self.pump();
    }
    fn prepare(&mut self) {
        self.click("Inspect controller");
        self.click("Choose file…");
        self.click("NS39 · Main 5.9");
    }
}
#[test]
fn demo_controls_use_the_same_inspection_transfer_and_verification_callbacks() {
    let mut demo = DemoHarness::new();
    element(&demo.app.ui, "DEMO");
    demo.prepare();
    assert!(demo.app.ui.get_state().can_update);
    demo.click("Update to 5.9  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Restart);
    assert_eq!(demo.app.ui.get_state().main_version, "5.8");
    demo.click("Check version  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Restart);
    demo.click("Confirm same controller");
    demo.click("Check version  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Verified);
    assert_eq!(demo.app.ui.get_state().main_version, "5.9");
}
#[test]
fn simulator_profiles_are_device_conditions_and_never_skip_to_ui_success() {
    for (label, failed) in [
        ("Normal device", false),
        ("Already current", false),
        ("Newer version", false),
        ("Identity failure", true),
        ("Transfer failure", false),
        ("Verification failure", false),
        ("Unknown version", true),
    ] {
        let mut demo = DemoHarness::new();
        demo.click("Demo…");
        inside_window(&demo.app.ui, &element(&demo.app.ui, label));
        demo.click(label);
        assert_eq!(
            demo.app.ui.get_state().page,
            if failed { Page::Failed } else { Page::Ready },
            "{label}"
        );
        assert!(
            !demo.app.ui.get_state().can_update,
            "profiles never select a package or start a transfer"
        );
    }
}
#[test]
fn simulator_menu_supports_keyboard_selection_and_escape() {
    let mut demo = DemoHarness::new();
    demo.click("Demo…");
    key(&demo.app.ui, slint::platform::Key::Escape);
    assert!(
        ElementHandle::find_by_accessible_label(&demo.app.ui, "Demo scenario")
            .next()
            .is_none()
    );
    demo.click("Demo…");
    key(&demo.app.ui, slint::platform::Key::Tab);
    key(&demo.app.ui, slint::platform::Key::Return);
    demo.pump();
    assert_eq!(demo.app.ui.get_state().page, Page::Ready);
}
#[test]
fn package_picker_rejects_mismatch_and_wraps_long_filename() {
    let mut demo = DemoHarness::new();
    demo.prepare();
    demo.click("Choose file…");
    demo.click("Wrong component");
    assert!(!demo.app.ui.get_state().can_update);
    // A rejected archive can be corrected after a fresh inspection.
    demo.click("Inspect controller");
    demo.click("Choose file…");
    demo.click("Long filename");
    let filename = demo.app.ui.get_state().filename;
    let item = element(&demo.app.ui, &filename);
    inside_window(&demo.app.ui, &item);
    assert!(
        item.size().height > 20.,
        "filename should wrap at minimum width"
    );
    assert!(demo.app.ui.get_state().can_update);
}
#[test]
fn simulated_connection_loss_preserves_observed_version_and_blocks_retry() {
    let mut demo = DemoHarness::new();
    demo.click("Demo…");
    demo.click("Transfer failure");
    demo.click("Choose file…");
    demo.click("NS39 · Main 5.9");
    demo.click("Update to 5.9  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Failed);
    element(&demo.app.ui, "Not connected");
    element(&demo.app.ui, "Main firmware, 5.8");
    assert!(demo.app.ui.get_state().notice.contains("No retry"));
}

#[test]
fn log_is_read_only_copyable_and_has_visible_text() {
    let mut demo = DemoHarness::new();
    demo.prepare();
    let ui = &demo.app.ui;
    ui.global::<Palette>()
        .set_color_scheme(slint::language::ColorScheme::Dark);
    click(ui, "Log");
    let log = ElementHandle::find_by_element_id(ui, "AppWindow::log-text")
        .next()
        .unwrap();
    assert_eq!(log.accessible_read_only(), Some(true));
    let snapshot = ui.window().take_snapshot().unwrap();
    let position = log.absolute_position();
    let size = log.size();
    let horizontal_inset =
        f64::from(position.x.ceil()) + 4. ..f64::from((position.x + size.width).floor()) - 4.;
    let vertical_inset =
        f64::from(position.y.ceil()) + 4. ..f64::from((position.y + size.height).floor()) - 4.;
    let width = usize::try_from(snapshot.width()).unwrap();
    let mut ink_pixels = 0;
    for (y, row) in snapshot.as_slice().chunks_exact(width).enumerate() {
        if !vertical_inset.contains(&f64::from(u32::try_from(y).unwrap())) {
            continue;
        }
        for (x, pixel) in row.iter().enumerate() {
            if horizontal_inset.contains(&f64::from(u32::try_from(x).unwrap()))
                && pixel.r < 128
                && pixel.g < 150
                && pixel.b < 128
            {
                ink_pixels += 1;
            }
        }
    }
    assert!(
        ink_pixels > 20,
        "log text must have dark ink on its light surface"
    );

    log.mock_single_click(PointerEventButton::Left);
    key(ui, "x");
    assert_eq!(log.accessible_value().unwrap(), ui.get_state().log);
    click(ui, "Copy");
    slint::slint! {
        export component ClipboardProbe inherits Window {
            public function read-clipboard() -> string { input.paste(); return input.text; }
            input := TextInput { single-line: false; }
        }
    }
    let probe = ClipboardProbe::new().unwrap();
    assert_eq!(probe.invoke_read_clipboard(), ui.get_state().log);
}

#[test]
fn procedure_reminder_is_prominent_and_mode_switch_waits_for_inspection() {
    use gulikit_ui::live::Work;
    let app = LiveHarness::new();
    let reminder = element(
        &app.ui,
        "Main and Bluetooth use different update and restart procedures.",
    );
    inside_window(&app.ui, &reminder);
    assert!(
        reminder.absolute_position().y < 200.,
        "procedure reminder must stay above the task content"
    );
    app.prepare_main();
    click(&app.ui, "Bluetooth firmware, Version unknown");
    assert_eq!(app.ui.get_state().page, Page::Connect);
    assert!(
        app.work.try_recv().is_err(),
        "show mode instructions before asking for fresh discovery"
    );
    element(&app.ui, "Gear / Set button");
    element(
        &app.ui,
        "To switch modes: Mode off → normal on, then off again.",
    );
    click(&app.ui, "Inspect controller");
    assert!(matches!(
        app.work.try_recv().unwrap(),
        Work::Inspect {
            component: Component::Bluetooth,
            confirmed: false
        }
    ));
}

#[test]
fn both_component_flows_show_their_own_restart_procedure() {
    let mut demo = DemoHarness::new();
    demo.prepare();
    demo.click("Update to 5.9  →");
    element(
        &demo.app.ui,
        "Wait for automatic power-off and for the GuliKit drive to disappear. Then turn on normally.",
    );
    demo.click("Confirm same controller");
    demo.click("Check version  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Verified);
    demo.click("Other firmware  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Connect);
    element(&demo.app.ui, "Gear / Set button");
    demo.click("Inspect controller");
    demo.click("Choose file…");
    demo.click("NS39 · Bluetooth 5.07");
    demo.click("Update to 5.07  →");
    assert_eq!(demo.app.ui.get_state().page, Page::Restart);
    element(&demo.app.ui, "After completion, power off and on normally.");
    element(&demo.app.ui, "Gear / Set button");
}

#[test]
fn mode_instructions_show_accessible_button_icons_for_the_selected_component() {
    let app = LiveHarness::new();
    inside_window(&app.ui, &element(&app.ui, "Use the rightmost"));
    inside_window(&app.ui, &element(&app.ui, "A"));
    let aps = element(&app.ui, "APS button (overlapping squares)");
    assert_eq!(
        ElementHandle::find_by_accessible_label(&app.ui, "APS button (overlapping squares)")
            .count(),
        2,
        "Main entry and keep-held reminder both identify APS"
    );
    let a = element(&app.ui, "A button (rightmost in default Switch layout)");
    inside_window(&app.ui, &aps);
    save_preview(&app.ui, "main-button-instructions");
    inside_window(&app.ui, &element(&app.ui, "Inspect controller"));
    inside_window(&app.ui, &element(&app.ui, "Open record…"));
    inside_window(&app.ui, &a);
    assert!(
        aps.absolute_position().x < a.absolute_position().x,
        "hold APS before pressing A"
    );
    click(&app.ui, "Bluetooth firmware, Version unknown");
    inside_window(&app.ui, &element(&app.ui, "Use the rightmost"));
    inside_window(&app.ui, &element(&app.ui, "A"));
    let gear = element(&app.ui, "Gear / Set button");
    assert_eq!(
        ElementHandle::find_by_accessible_label(&app.ui, "Gear / Set button").count(),
        2,
        "Bluetooth entry and keep-held reminder both identify Gear"
    );
    let a = element(&app.ui, "A button (rightmost in default Switch layout)");
    inside_window(&app.ui, &gear);
    save_preview(&app.ui, "bluetooth-button-instructions");
    inside_window(&app.ui, &element(&app.ui, "Inspect controller"));
    inside_window(&app.ui, &element(&app.ui, "Open record…"));
    inside_window(&app.ui, &a);
    assert!(
        gear.absolute_position().x < a.absolute_position().x,
        "hold Gear before pressing A"
    );
    assert!(
        ElementHandle::find_by_accessible_label(&app.ui, "APS button (overlapping squares)")
            .next()
            .is_none()
    );
}

fn save_preview(ui: &AppWindow, name: &str) {
    let Some(directory) = std::env::var_os("GULIKIT_UI_PREVIEW_DIR") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    std::fs::create_dir_all(&directory).unwrap();
    let snapshot = ui.window().take_snapshot().unwrap();
    let path = directory.join(format!(
        "{name}-{}x{}.rgba",
        snapshot.width(),
        snapshot.height()
    ));
    std::fs::write(path, snapshot.as_bytes()).unwrap();
}

#[test]
fn offline_package_controls_show_metadata_without_claiming_a_controller() {
    use gulikit_ui::live::{Event, Work};
    let app = LiveHarness::new();
    app.ui
        .window()
        .set_size(slint::LogicalSize::new(760., 900.));
    layout(&app.ui);
    click(&app.ui, "Choose file…");
    assert!(matches!(
        app.work.try_recv().unwrap(),
        Work::ChoosePackage(Component::Main)
    ));
    app.send(Event::Package {
        path: "offline.zip".into(),
        info: live_fixtures::package(),
    });
    assert_eq!(app.ui.get_state().page, Page::Ready);
    assert_eq!(app.ui.get_state().filename, "offline.zip");
    assert!(!app.ui.get_state().connected);
    assert!(!app.ui.get_primary_enabled());
    assert!(app.work.try_recv().is_err());
    click(&app.ui, "Inspect again");
    assert!(matches!(
        app.work.try_recv().unwrap(),
        Work::Inspect {
            component: Component::Main,
            confirmed: false
        }
    ));
    app.send(Event::Error(
        "Native device access is unavailable on this platform".into(),
    ));
    assert_eq!(app.ui.get_state().page, Page::Failed);
    assert!(app.ui.get_state().can_choose_package);
}

#[test]
fn transfer_worker_failure_before_progress_disables_all_device_actions() {
    use gulikit_ui::live::{Event, Work};
    let app = LiveHarness::new_mode(true);
    app.prepare_main();
    click(&app.ui, "Update to 5.9  →");
    assert!(matches!(app.work.try_recv().unwrap(), Work::Update { .. }));
    app.send(Event::WorkerFailed("worker ended before progress".into()));
    assert_eq!(app.ui.get_state().page, Page::Failed);
    assert!(!app.ui.get_primary_enabled());
    assert!(!app.ui.get_state().can_choose_package);
    click(&app.ui, "Inspect controller");
    assert!(app.work.try_recv().is_err());
}
