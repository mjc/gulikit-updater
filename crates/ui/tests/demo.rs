use gulikit_core::package::Component;
use gulikit_ui::{
    Page,
    backend::Device,
    demo::DemoDevice,
    live::{Event, LiveApp, Work},
};
use std::sync::atomic::AtomicBool;
#[test]
fn demo_uses_the_shared_controller_and_device_operations() {
    let mut device = DemoDevice::with_transfer_wait(|_| {});
    let mut app = LiveApp::default();
    let cancelled = AtomicBool::new(false);
    assert!(app.connect().is_none());
    app.confirm_model(true);
    let work = app.connect().unwrap();
    let event = device.run(work, &cancelled, &mut |_| {}).unwrap();
    assert!(
        matches!(event, Event::Inspected(_)),
        "the demo must return a device observation through the shared boundary"
    );
    app.accept(event);
    assert_eq!(app.view().page, Page::Ready);
    let work = app.choose_package().unwrap();
    app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
    assert!(app.can_update());
    let work = app.start().unwrap();
    assert!(matches!(
        work,
        Work::Update {
            component: Component::Main,
            ..
        }
    ));
    let event = device
        .run(work, &cancelled, &mut |e| app.accept(e))
        .unwrap();
    app.accept(event);
    assert_eq!(app.view().page, Page::Restart);
    assert_eq!(app.view().installed, "5.8");
    assert!(app.primary().is_none());
    app.confirm_same_controller(true);
    let work = app.primary().unwrap();
    app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
    assert_eq!(app.view().page, Page::Verified);
    assert_eq!(app.view().installed, "5.9");
}

#[test]
fn simulated_conditions_obey_the_same_refusal_and_verification_policy() {
    use gulikit_ui::demo::Profile;
    for profile in [
        Profile::Current,
        Profile::Newer,
        Profile::IdentityFailure,
        Profile::UnknownVersion,
    ] {
        let mut device = DemoDevice::with_transfer_wait(|_| {});
        let mut app = LiveApp::default();
        let work = app.configure_demo(profile).unwrap();
        let event = device
            .run(work, &AtomicBool::new(false), &mut |_| {})
            .unwrap_or_else(Event::Error);
        app.accept(event);
        if let Some(work) = app.choose_package() {
            app.accept(
                device
                    .run(work, &AtomicBool::new(false), &mut |_| {})
                    .unwrap(),
            );
        }
        assert!(!app.can_update());
        assert!(app.start().is_none());
    }
    for profile in [Profile::TransferFailure, Profile::VerificationFailure] {
        let mut device = DemoDevice::with_transfer_wait(|_| {});
        let mut app = LiveApp::default();
        let cancelled = AtomicBool::new(false);
        let work = app.configure_demo(profile).unwrap();
        app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
        let work = app.choose_package().unwrap();
        app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
        let work = app.start().unwrap();
        let event = device
            .run(work, &cancelled, &mut |e| app.accept(e))
            .unwrap();
        app.accept(event);
        if app.view().page == Page::Restart {
            app.confirm_same_controller(true);
            let work = app.primary().unwrap();
            app.accept(device.run(work, &cancelled, &mut |_| {}).unwrap());
        }
        assert_eq!(app.view().page, Page::Failed);
        assert_eq!(app.view().installed, "5.8");
        assert!(!app.can_update());
    }
}
#[test]
fn simulated_cancellation_after_submission_keeps_the_outcome_uncertain() {
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
        .run(work, &cancelled, &mut |e| {
            app.accept(e);
            cancelled.store(true, std::sync::atomic::Ordering::Release);
        })
        .unwrap();
    app.accept(event);
    assert_eq!(app.view().page, Page::Failed);
    assert!(app.view().notice.contains("No retry"));
    assert!(app.view().progress.confirmed < app.view().progress.total);
}
