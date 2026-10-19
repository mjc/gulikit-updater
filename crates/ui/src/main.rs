// Slint’s generated bindings contain their own unsafe FFI; application code may not.
#![deny(unsafe_code)]
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]
use gulikit_ui::{
    backend::{NativeDevice, Worker},
    demo::DemoDevice,
};
use slint::ComponentHandle;
slint::include_modules!();

fn main() -> Result<(), slint::PlatformError> {
    #[cfg(target_os = "macos")]
    if let Some(code) = std::env::args_os()
        .nth(1)
        .as_deref()
        .and_then(gulikit_updater::supervision::dispatch_internal)
    {
        std::process::exit(i32::from(code));
    }
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
    #[cfg(target_os = "macos")]
    if !demo {
        match elevation::ensure_administrator() {
            Ok(elevation::StartupDisposition::Continue) => {}
            Ok(elevation::StartupDisposition::Exit) => return Ok(()),
            Err(error) => {
                rfd::MessageDialog::new()
                    .set_title("GuliKit Updater could not start")
                    .set_description(&error)
                    .set_level(rfd::MessageLevel::Error)
                    .show();
                return Err(slint::PlatformError::Other(error));
            }
        }
    }
    let (worker, events) = if demo {
        Worker::spawn(DemoDevice::default())
    } else {
        Worker::spawn_with(NativeDevice::default)
    };
    let (ui, timer) = live_ui::create_mode(
        worker.requests.clone(),
        events,
        worker.cancelled.clone(),
        demo,
    )?;
    let result = ui.run();
    drop(timer);
    drop(ui);
    drop(worker);
    result
}

#[cfg(target_os = "macos")]
mod elevation;
mod live_ui;
#[cfg(test)]
mod ui_tests;
