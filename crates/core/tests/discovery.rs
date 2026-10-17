use gulikit_core::device::{Candidate, Discovery, DiscoveryError};

fn candidate(id: u64) -> Candidate {
    Candidate {
        ancestor: id,
        generation: id,
        main_access: true,
        bluetooth_access: true,
        observed_profile: true,
        conflicting_model: false,
    }
}

#[test]
fn counts_all_ancestors_before_compatibility_and_incomplete_errors() {
    let mut second = candidate(2);
    second.observed_profile = false;
    let snapshot = Discovery {
        candidates: vec![candidate(1), second],
        incomplete: vec!["uncorrelated volume".into()],
    };
    assert_eq!(
        snapshot.select(true).unwrap_err(),
        DiscoveryError::MultipleDevices
    );
    assert_eq!(
        Discovery {
            candidates: vec![candidate(1)],
            incomplete: snapshot.incomplete
        }
        .select(true)
        .unwrap_err(),
        DiscoveryError::DiscoveryIncomplete
    );
}

#[test]
fn assisted_identity_requires_confirmation_and_joint_generation() {
    let snapshot = Discovery {
        candidates: vec![candidate(1), candidate(1)],
        incomplete: vec![],
    };
    assert_eq!(
        snapshot.select(false).unwrap_err(),
        DiscoveryError::WrongOrConflictingModel
    );
    assert_eq!(snapshot.select(true).unwrap().generation, 1);
    let mut changed = candidate(1);
    changed.generation = 2;
    assert_eq!(
        Discovery {
            candidates: vec![candidate(1), changed],
            incomplete: vec![]
        }
        .select(true)
        .unwrap_err(),
        DiscoveryError::DiscoveryIncomplete
    );
}
