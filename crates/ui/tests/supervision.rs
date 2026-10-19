#![cfg(target_os = "macos")]

use gulikit_platform::main_worker::{self, Message};
use std::{os::unix::ffi::OsStrExt, process::Command, time::Duration};

#[test]
fn gui_executable_runs_the_shared_main_guardian_without_opening_a_window_or_device() {
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("invalid.zip");
    std::fs::write(&archive, b"not a reviewed firmware package").unwrap();
    let response = run_guardian(&archive, None);
    let Message::Failed { kind, code, .. } = response else {
        panic!("{response:?}");
    };
    assert_eq!(kind, "package_rejected");
    assert_eq!(code, 3);
}

#[test]
#[ignore = "requires original vendor archive in ignored cache"]
fn replaced_main_archive_is_rejected_by_the_gui_helper_before_claiming_a_device() {
    let directory = std::env::var_os("GULIKIT_VENDOR_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../artifacts/vendor/kk3/packages")
        },
        std::path::PathBuf::from,
    );
    let archive = directory.join("KK3_NS38_NS39_V5.9.zip");
    gulikit_platform::inspect_package(
        &archive,
        gulikit_core::package::Model::Kk3Max,
        gulikit_core::package::Component::Main,
    )
    .expect("supply original archive with GULIKIT_VENDOR_DIR");
    let mut expected = gulikit_platform::inspect_package(
        &archive,
        gulikit_core::package::Model::Kk3Max,
        gulikit_core::package::Component::Main,
    )
    .unwrap()
    .info()
    .clone();
    expected.archive_sha256 = "0".repeat(64);
    let response = run_guardian(&archive, Some(&expected));
    let Message::Failed { message, .. } = response else {
        panic!("{response:?}");
    };
    assert!(message.contains("changed since selection"), "{message}");
}

fn run_guardian(
    archive: &std::path::Path,
    expected_package: Option<&gulikit_core::package::PackageInfo>,
) -> Message {
    let directory = tempfile::tempdir().unwrap();
    let record = directory.path().join("must-not-exist.jsonl");
    let mut command = Command::new(env!("CARGO_BIN_EXE_gulikit-ui"));
    command.arg("__main-guardian");
    let response = main_worker::run(
        command,
        serde_json::json!({
            "archive": archive.as_os_str().as_bytes(),
            "record": record.as_os_str().as_bytes(),
            "model": "kk3-max", "allow_downgrade": false, "confirm_ns39": true,
            "expected_attachment": {"ancestor":42,"generation":7},
            "expected_package": expected_package
        }),
        Duration::from_secs(5),
        || false,
    )
    .unwrap();
    assert!(!record.exists());
    response
}
