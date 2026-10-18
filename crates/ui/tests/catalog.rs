use gulikit_catalog::Catalog;
use gulikit_core::{
    package::Component,
    version::{VersionDecision, VersionPolicy},
};
use gulikit_ui::{
    backend::{inspect_selected_package, inspect_selected_package_from_catalog},
    live::{Event, LiveApp},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use zip::{ZipWriter, write::SimpleFileOptions};

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Catalog) {
    let payload = vec![0x5a; 51_500];
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file("NS39.bin", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(&payload).unwrap();
    let archive = writer.finish().unwrap().into_inner();
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let entry = json!({"product":"kk3-max","component":"main","version":"6.1","archive":"original.zip","archive_size":archive.len(),"archive_sha256":digest(&archive),"member":"NS39.bin","member_size":payload.len(),"member_sha256":digest(&payload),"payload_size":payload.len(),"payload_sha256":digest(&payload),"source_url":"https://www.gulikit.com/newsinfo/887152.html","parser_id":"kk3_main_binary_v1","software_support":"supported","hardware_acceptance":"unqualified","hardware_evidence":null});
    let catalog = Catalog::parse(
        json!({"schema_version":1,"entries":[entry]})
            .to_string()
            .as_bytes(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original.zip");
    std::fs::write(&path, archive).unwrap();
    (directory, path, catalog)
}

#[test]
fn selected_catalog_inspects_a_new_compatible_release_without_device_access() {
    let (_directory, path, catalog) = fixture();
    assert!(inspect_selected_package(&path, Component::Main).is_err());
    let Event::Package { info, .. } =
        inspect_selected_package_from_catalog(&path, Component::Main, Some(&catalog)).unwrap()
    else {
        panic!("expected inspected package")
    };
    assert_eq!(info.version, "6.1");
    assert_eq!(
        info.decision_for_installed("5.9", VersionPolicy::UpgradeOnly)
            .unwrap(),
        VersionDecision::Eligible
    );
    assert!(
        inspect_selected_package_from_catalog(&path, Component::Bluetooth, Some(&catalog)).is_err()
    );
    std::fs::write(&path, b"changed archive").unwrap();
    assert!(inspect_selected_package_from_catalog(&path, Component::Main, Some(&catalog)).is_err());
}

#[test]
fn controller_uses_selected_catalog_target_instead_of_compiled_target() {
    let (_directory, path, catalog) = fixture();
    let event =
        inspect_selected_package_from_catalog(&path, Component::Main, Some(&catalog)).unwrap();
    let target = gulikit_platform::discovery::NativeCandidate {
        ancestor: 42,
        generation: 7,
        main_volume_candidate: true,
        bluetooth_transport_candidate: false,
        observed_profile: true,
        conflicting_model: false,
        storage_identities: vec![],
        disks: vec![],
        mount: None,
    };
    let mut app = LiveApp::default();
    app.confirm_model(true);
    app.connect().unwrap();
    app.accept(Event::Inspected(gulikit_updater::updater::Inspection {
        component: Component::Main,
        installed_version: "5.9".into(),
        decision: VersionDecision::AlreadyCurrent,
        raw_version_bytes: b"www.gulikit.com\nversion 5.9".to_vec(),
        qualified_bot_lun: None,
        cleanup_errors: vec![],
        target,
        identity_provenance: "synthetic NS39 observation",
    }));
    app.choose_package().unwrap();
    app.accept(event);
    assert_eq!(app.view().target, "6.1");
    assert!(app.can_update());
}

#[test]
fn catalog_receipt_reopens_with_original_target_and_confirmation_identity() {
    use gulikit_core::update::{Outcome, TransferRecord};
    use gulikit_updater::updater::{Attempt, PriorAttempt, ReceiptIdentity};
    let (_directory, path, catalog) = fixture();
    let Event::Package { info, .. } =
        inspect_selected_package_from_catalog(&path, Component::Main, Some(&catalog)).unwrap()
    else {
        panic!("expected package")
    };
    let entry = catalog.entries()[0].clone();
    let identity = ReceiptIdentity::for_package(
        Outcome::TransferCompletedAwaitingVerification,
        7,
        &info,
        Some(&entry),
    );
    let target = serde_json::from_value(json!({"ancestor":42,"generation":7,"main_volume_candidate":true,"bluetooth_transport_candidate":false,"observed_profile":true,"conflicting_model":false,"storage_identities":[],"disks":[],"mount":null})).unwrap();
    let result = Attempt {
        event: "attempt_result",
        schema_version: 1,
        record_finalized: true,
        target,
        package: info,
        catalog_entry: Some(Box::new(entry)),
        transfer: TransferRecord {
            outcome: Outcome::TransferCompletedAwaitingVerification,
            ..TransferRecord::default()
        },
        operator_action: "Restart and verify",
    };
    let record = tempfile::NamedTempFile::new().unwrap();
    let finalized = gulikit_platform::journal::finalize_record(
        &mut record.reopen().unwrap(),
        serde_json::to_value(result).unwrap(),
    );
    assert_eq!(finalized["record_finalized"], true);
    drop(catalog);
    let prior = PriorAttempt::parse(&std::fs::read(record.path()).unwrap()).unwrap();
    prior.require_verifiable().unwrap();
    assert_eq!(prior.identity(), identity);
    let mut app = LiveApp::default();
    app.open_attempt().unwrap();
    app.accept(Event::Prior {
        path: record.path().to_owned(),
        prior,
    });
    assert_eq!(app.view().target, "6.1");
    app.confirm_model(true);
    app.confirm_same_controller(true);
    let Some(gulikit_ui::live::Work::Verify {
        expected_receipt, ..
    }) = app.primary()
    else {
        panic!("expected fresh verification request")
    };
    assert_eq!(expected_receipt, identity);
}
