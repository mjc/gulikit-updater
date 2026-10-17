use gulikit_core::{
    package::Component,
    update::{Outcome, Verification, verify_restart},
};

#[test]
fn fresh_version_requires_new_attachment_and_same_unit_attestation() {
    let mut observation = Verification {
        component: Component::Main,
        previous_generation: 10,
        generation: 11,
        same_unit_confirmed: false,
        model_confirmed: true,
        version: "5.9".into(),
        expected_version: "5.9".into(),
    };
    assert_ne!(
        verify_restart(Outcome::TransferCompletedAwaitingVerification, &observation),
        Outcome::InstalledVerified
    );
    observation.same_unit_confirmed = true;
    assert_eq!(
        verify_restart(Outcome::TransferCompletedAwaitingVerification, &observation),
        Outcome::InstalledVerified
    );
    observation.generation = 10;
    assert_ne!(
        verify_restart(Outcome::TransferCompletedAwaitingVerification, &observation),
        Outcome::InstalledVerified
    );
    observation.generation = 11;
    assert_ne!(
        verify_restart(Outcome::OutcomeUnknown, &observation),
        Outcome::InstalledVerified
    );
    observation.component = Component::Bluetooth;
    observation.expected_version = "5.07".into();
    assert_ne!(
        verify_restart(Outcome::TransferCompletedAwaitingVerification, &observation),
        Outcome::InstalledVerified
    );
    observation.version = "5.07".into();
    assert_eq!(
        verify_restart(Outcome::TransferCompletedAwaitingVerification, &observation),
        Outcome::InstalledVerified
    );
}

#[test]
fn verification_compares_the_original_target_instead_of_the_running_catalog_version() {
    let mut observation = Verification {
        component: Component::Main,
        previous_generation: 10,
        generation: 11,
        same_unit_confirmed: true,
        model_confirmed: true,
        version: "5.9".into(),
        expected_version: "6.0".into(),
    };
    let pending = Outcome::TransferCompletedAwaitingVerification;
    assert_eq!(verify_restart(pending, &observation), pending);
    observation.version = "6.0".into();
    assert_eq!(
        verify_restart(pending, &observation),
        Outcome::InstalledVerified
    );
}
