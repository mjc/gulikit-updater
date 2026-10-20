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
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(target_os = "macos")]
    if let Some(code) = arguments
        .first()
        .map(std::ffi::OsString::as_os_str)
        .and_then(gulikit_updater::supervision::dispatch_internal)
    {
        std::process::exit(i32::from(code));
    }

    #[cfg(target_os = "macos")]
    let (arguments, launcher_receipt_owner) = {
        let mut arguments = arguments;
        let owner =
            elevation::take_launcher_receipt_owner(&mut arguments, nix::unistd::geteuid().as_raw())
                .map_err(slint::PlatformError::Other)?;
        (arguments, owner)
    };

    let mut args = arguments.into_iter();
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
    let receipt_owner = if demo {
        None
    } else {
        match elevation::ensure_administrator(launcher_receipt_owner) {
            Ok(elevation::StartupDisposition::Continue { receipt_owner }) => receipt_owner,
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
    };
    #[cfg(target_os = "macos")]
    let record_directory = receipt_owner
        .map(gulikit_platform::journal::ReceiptOwner::home_directory)
        .transpose()
        .map_err(|error| {
            rfd::MessageDialog::new()
                .set_title("GuliKit Updater could not start")
                .set_description(&error)
                .set_level(rfd::MessageLevel::Error)
                .show();
            slint::PlatformError::Other(error)
        })?;

    #[cfg(target_os = "macos")]
    initialize_desktop_backend()?;
    let (worker, events) = if demo {
        Worker::spawn(DemoDevice::default())
    } else {
        #[cfg(target_os = "macos")]
        {
            Worker::spawn_with(move || {
                NativeDevice::with_receipt_owner(receipt_owner, record_directory)
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Worker::spawn_with(NativeDevice::default)
        }
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
fn initialize_desktop_backend() -> Result<(), slint::PlatformError> {
    use slint::winit_030::winit::{
        event_loop::EventLoop,
        platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS},
    };
    // The bundle starts as an agent so the authorization launcher has no icon.
    // Only the actual GUI (elevated or demo) becomes a regular application.
    let mut builder = EventLoop::with_user_event();
    builder.with_activation_policy(ActivationPolicy::Regular);
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .with_winit_event_loop_builder(builder)
        .select()
}

#[cfg(target_os = "macos")]
mod elevation;
mod live_ui;
#[cfg(test)]
mod ui_tests;
