use gulikit_core::{
    package::{Component, Model, PackageInfo, catalog},
    update::{Outcome, TransferRecord, Verification},
    version::VersionDecision,
};
use gulikit_platform::discovery::NativeCandidate;
use gulikit_updater::updater::{Attempt, Inspection, Readback, VerificationTransfer};

pub fn inspection() -> Inspection {
    Inspection {
        component: Component::Main,
        installed_version: "5.8".into(),
        decision: VersionDecision::Eligible,
        raw_version_bytes: b"www.gulikit.com\nversion 5.8".to_vec(),
        qualified_bot_lun: None,
        cleanup_errors: vec![],
        identity_provenance: "test-confirmed NS39",
        target: NativeCandidate {
            ancestor: 42,
            generation: 7,
            main_volume_candidate: true,
            storage_identities: vec![],
            bluetooth_transport_candidate: true,
            observed_profile: true,
            conflicting_model: false,
            usb: Some(gulikit_platform::discovery::UsbIdentity {
                vendor: 0x34d3,
                product: 0x1100,
            }),
            disks: vec![],
            mount: None,
        },
    }
}
pub fn package() -> PackageInfo {
    let release = catalog()
        .iter()
        .find(|r| r.model == Model::Kk3Max && r.component == Component::Main)
        .unwrap();
    PackageInfo {
        model: Model::Kk3Max,
        component: Component::Main,
        version: release.version.into(),
        payload_size: 51500,
        payload_sha256: "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4".into(),
        archive_sha256: release.archive_sha256.into(),
        source_url: release.source_url.into(),
        member: release.member.into(),
        archive_selection: None,
    }
}
pub fn attempt(outcome: Outcome) -> Attempt {
    Attempt {
        event: "attempt_result",
        schema_version: 1,
        record_finalized: true,
        target: inspection().target,
        package: package(),
        operator_action: "Restart and verify",
        transfer: TransferRecord {
            outcome,
            bytes_confirmed: 51500,
            bytes_submitted: 51500,
            ..TransferRecord::default()
        },
    }
}
pub fn readback(generation: u64, version: &str) -> Readback {
    let mut target = inspection().target;
    target.generation = generation;
    Readback {
        event: "verification_result",
        schema_version: 1,
        source_attempt: "attempt.jsonl".into(),
        target,
        verification: Some(Verification {
            component: Component::Main,
            previous_generation: 7,
            generation,
            same_unit_confirmed: true,
            model_confirmed: true,
            version: version.into(),
            expected_version: "5.9".into(),
        }),
        raw_version_bytes: Some(format!("www.gulikit.com\nversion {version}").into_bytes()),
        qualified_bot_lun: None,
        same_unit_association: "test-confirmed same controller",
        transfer: VerificationTransfer {
            outcome: Outcome::InstalledVerified,
            error: None,
            cleanup_errors: vec![],
        },
    }
}
