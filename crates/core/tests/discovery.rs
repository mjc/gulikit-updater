use gulikit_core::{
    device::{Candidate, Discovery, DiscoveryError},
    package::Component,
};

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
        snapshot.select(true, Component::Main).unwrap_err(),
        DiscoveryError::MultipleDevices
    );
    assert_eq!(
        Discovery {
            candidates: vec![candidate(1)],
            incomplete: snapshot.incomplete
        }
        .select(true, Component::Main)
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
        snapshot.select(false, Component::Main).unwrap_err(),
        DiscoveryError::WrongOrConflictingModel
    );
    assert_eq!(
        snapshot.select(true, Component::Main).unwrap().generation,
        1
    );
    let mut changed = candidate(1);
    changed.generation = 2;
    assert_eq!(
        Discovery {
            candidates: vec![candidate(1), changed],
            incomplete: vec![]
        }
        .select(true, Component::Main)
        .unwrap_err(),
        DiscoveryError::DiscoveryIncomplete
    );
}

#[test]
fn each_component_selects_its_own_path_without_the_other_view() {
    for component in [Component::Main, Component::Bluetooth] {
        let mut unit = candidate(1);
        unit.main_access = component == Component::Main;
        unit.bluetooth_access = component == Component::Bluetooth;
        // Recognized candidate inputs need not have the historical joint profile.
        unit.observed_profile = false;
        let snapshot = Discovery {
            candidates: vec![unit],
            incomplete: vec![],
        };
        assert_eq!(snapshot.select(true, component).unwrap().ancestor, 1);
        let other = if component == Component::Main {
            Component::Bluetooth
        } else {
            Component::Main
        };
        assert_eq!(
            snapshot.select(true, other).unwrap_err(),
            DiscoveryError::MissingAccess
        );
        let mut second = candidate(2);
        second.main_access = !snapshot.candidates[0].main_access;
        second.bluetooth_access = !snapshot.candidates[0].bluetooth_access;
        assert_eq!(
            Discovery {
                candidates: vec![snapshot.candidates[0].clone(), second],
                incomplete: vec![]
            }
            .select(true, component)
            .unwrap_err(),
            DiscoveryError::MultipleDevices
        );
    }
}

#[test]
fn legacy_selector_also_allows_independent_components_without_cross_unit_pairing() {
    use gulikit_core::{
        device::{ControllerId, Identity, Observation, select_ns39_update_target},
        package::Model,
    };
    for component in [Component::Main, Component::Bluetooth] {
        let observation = Observation {
            controller: ControllerId::new("one").unwrap(),
            component,
            identity: Identity::Exact {
                model: Model::Kk3Max,
            },
        };
        let target = select_ns39_update_target([observation], component).unwrap();
        assert_eq!(target.controller().components, [component]);
    }
}
