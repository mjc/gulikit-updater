// Slint’s generated bindings contain their own unsafe FFI; application code may not.
#![deny(unsafe_code)]
use slint::ComponentHandle;
slint::include_modules!();

const USAGE: &str = "Usage: gulikit-ui [--demo | --catalog PATH]";

#[derive(Debug, PartialEq, Eq)]
enum Launch {
    Native(Option<std::path::PathBuf>),
    Demo,
    Help,
}

fn launch(args: &[std::ffi::OsString]) -> Result<Launch, slint::PlatformError> {
    match args {
        [] => Ok(Launch::Native(None)),
        [arg] if arg == "--demo" => Ok(Launch::Demo),
        [arg] if arg == "--help" || arg == "-h" => Ok(Launch::Help),
        [arg, path] if arg == "--catalog" && !path.is_empty() => {
            Ok(Launch::Native(Some(path.into())))
        }
        _ => Err(slint::PlatformError::Other(USAGE.into())),
    }
}

fn main() -> Result<(), slint::PlatformError> {
    use gulikit_ui::{
        backend::{CatalogDevice, NativeDevice, Worker},
        demo::DemoDevice,
    };
    let launch = launch(&std::env::args_os().skip(1).collect::<Vec<_>>())?;
    let demo = launch == Launch::Demo;
    let (worker, events) = match launch {
        Launch::Help => {
            println!(
                "GuliKit updater\n\n{USAGE}\n\n--demo uses a simulated device. --catalog selects release metadata for local ZIP inspection."
            );
            return Ok(());
        }
        Launch::Demo => Worker::spawn(DemoDevice::default()),
        Launch::Native(None) => Worker::spawn(NativeDevice),
        Launch::Native(Some(path)) => {
            let rejected = |error: String| slint::PlatformError::Other(error);
            let bytes = gulikit_platform::catalog::read_catalog_file(
                &path,
                gulikit_catalog::MAX_CATALOG_BYTES,
            )
            .map_err(|error| rejected(error.to_string()))?;
            let catalog = gulikit_catalog::Catalog::parse(&bytes)
                .map_err(|error| rejected(error.to_string()))?;
            Worker::spawn(CatalogDevice::new(catalog))
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

#[cfg(test)]
mod launch_tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }
    #[test]
    fn explicit_catalog_is_independent_of_demo_and_requires_a_path() {
        assert_eq!(launch(&args(&[])).unwrap(), Launch::Native(None));
        assert_eq!(
            launch(&args(&["--catalog", "metadata.json"])).unwrap(),
            Launch::Native(Some("metadata.json".into()))
        );
        assert_eq!(launch(&args(&["--demo"])).unwrap(), Launch::Demo);
        for invalid in [
            vec!["--catalog"],
            vec!["--demo", "--catalog", "metadata.json"],
            vec!["metadata.json"],
        ] {
            assert!(launch(&args(&invalid)).is_err());
        }
    }
}

mod live_ui;
#[cfg(test)]
mod ui_tests;
