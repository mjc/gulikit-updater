// Slint’s generated bindings contain their own unsafe FFI; application code may not.
#![deny(unsafe_code)]
use slint::ComponentHandle;
slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    use gulikit_ui::{
        backend::{NativeDevice, Worker},
        demo::DemoDevice,
    };
    let started = std::time::Instant::now();
    let mut args = std::env::args_os().skip(1);
    let argument = args.next();
    let extra = args.next().is_some();
    if !extra
        && argument
            .as_ref()
            .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        println!(
            "GuliKit updater\n\nUsage: gulikit-ui [--demo]\n\nNormal mode uses the native updater. --demo uses a simulated device."
        );
        return Ok(());
    }
    let demo = !extra && argument.as_ref().is_some_and(|arg| arg == "--demo");
    if argument.is_some() && !demo {
        return Err(slint::PlatformError::Other(
            "Usage: gulikit-ui [--demo]".into(),
        ));
    }
    let profile = lifecycle_profile::LifecycleProfile::from_environment(demo, started)?;
    let (worker, events) = if demo {
        Worker::spawn(DemoDevice::default())
    } else {
        Worker::spawn(NativeDevice)
    };
    let (ui, timer) = live_ui::create_mode(
        worker.requests.clone(),
        events,
        worker.cancelled.clone(),
        demo,
    )?;
    let result = if let Some(profile) = &profile {
        ui.show()?;
        profile.close_after_idle(&ui);
        let result = slint::run_event_loop();
        let hidden = ui.hide();
        result.and(hidden)
    } else {
        ui.run()
    };
    drop(timer);
    drop(ui);
    drop(worker);
    if let Some(profile) = profile {
        profile.report();
    }
    result
}

mod lifecycle_profile;
mod live_ui;
#[cfg(test)]
mod ui_tests;
