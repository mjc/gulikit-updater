//! Physical-controller identity and component access, independent of the OS.

use crate::package::{Component, Model};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Current attachment evidence. These keys are session identities, never serial numbers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub ancestor: u64,
    pub generation: u64,
    pub main_access: bool,
    pub bluetooth_access: bool,
    pub observed_profile: bool,
    pub conflicting_model: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Discovery {
    pub candidates: Vec<Candidate>,
    pub incomplete: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("More than one device is in update mode. Disconnect the others and try again.")]
    MultipleDevices,
    #[error("Discovery is incomplete; all update candidates must be correlated before continuing.")]
    DiscoveryIncomplete,
    #[error("No device is in update mode. Connect the controller and try again.")]
    NoDevice,
    #[error(
        "Confirm the physical NS39 label and Max controls; unknown or conflicting model evidence refuses writing."
    )]
    WrongOrConflictingModel,
    #[error("Main and Bluetooth update access must belong to the same attachment.")]
    MissingAccess,
}

impl Discovery {
    pub fn select(&self, user_confirmed_ns39: bool) -> Result<Candidate, DiscoveryError> {
        let ids: BTreeSet<_> = self.candidates.iter().map(|c| c.ancestor).collect();
        if ids.len() > 1 {
            return Err(DiscoveryError::MultipleDevices);
        }
        if !self.incomplete.is_empty()
            || self
                .candidates
                .windows(2)
                .any(|p| p[0].generation != p[1].generation)
        {
            return Err(DiscoveryError::DiscoveryIncomplete);
        }
        let first = self.candidates.first().ok_or(DiscoveryError::NoDevice)?;
        if !user_confirmed_ns39
            || self
                .candidates
                .iter()
                .any(|c| c.conflicting_model || !c.observed_profile)
        {
            return Err(DiscoveryError::WrongOrConflictingModel);
        }
        let mut candidate = first.clone();
        candidate.main_access = self.candidates.iter().any(|c| c.main_access);
        candidate.bluetooth_access = self.candidates.iter().any(|c| c.bluetooth_access);
        if !candidate.main_access || !candidate.bluetooth_access {
            return Err(DiscoveryError::MissingAccess);
        }
        Ok(candidate)
    }
}

/// The platform's opaque correlation key for one physical controller.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ControllerId(String);

impl ControllerId {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        (!value.trim().is_empty()).then_some(Self(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Identity {
    Exact { model: Model },
    ProtocolSignature { bytes: [u8; 16] },
    Unknown,
    Conflicting,
}

/// Evidence from an adapter; a volume label by itself cannot establish a model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Observation {
    pub controller: ControllerId,
    pub component: Component,
    pub identity: Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Controller {
    pub id: ControllerId,
    pub identity: Identity,
    pub components: Vec<Component>,
    pub evidence: Vec<Observation>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SelectionError {
    #[error("No device is in update mode. Connect the controller and try again.")]
    NoDevice,
    #[error("More than one device is in update mode. Disconnect the others and try again.")]
    MultipleDevices,
    #[error("Main and Bluetooth update access must belong to the same controller.")]
    MissingComponent,
    #[error("Controller model identity is unknown or conflicting.")]
    Unidentified,
}

/// A selection proof for the current observation, not authorization to write.
/// A native adapter must refresh discovery before a future write operation.
#[derive(Debug)]
pub struct UpdateTarget {
    controller: Controller,
}

impl UpdateTarget {
    pub fn controller(&self) -> &Controller {
        &self.controller
    }
}

pub fn select_ns39_update_target(
    observations: impl IntoIterator<Item = Observation>,
) -> Result<UpdateTarget, SelectionError> {
    let controllers = group_observations(observations);
    let mut controllers = controllers.into_iter();
    let controller = controllers.next().ok_or(SelectionError::NoDevice)?;
    if controllers.next().is_some() {
        return Err(SelectionError::MultipleDevices);
    }
    if ![Component::Main, Component::Bluetooth]
        .iter()
        .all(|component| controller.components.contains(component))
    {
        return Err(SelectionError::MissingComponent);
    }
    if controller.identity
        != (Identity::Exact {
            model: Model::Kk3Max,
        })
    {
        return Err(SelectionError::Unidentified);
    }
    Ok(UpdateTarget { controller })
}

pub fn group_observations(observations: impl IntoIterator<Item = Observation>) -> Vec<Controller> {
    let mut groups: BTreeMap<ControllerId, Vec<Observation>> = BTreeMap::new();
    for observation in observations {
        groups
            .entry(observation.controller.clone())
            .or_default()
            .push(observation);
    }
    groups
        .into_iter()
        .map(|(id, evidence)| Controller {
            id,
            identity: summarize_identity(&evidence),
            components: evidence
                .iter()
                .map(|item| item.component)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            evidence,
        })
        .collect()
}

fn summarize_identity(evidence: &[Observation]) -> Identity {
    let mut models = BTreeSet::new();
    let mut signatures: BTreeMap<Component, BTreeSet<[u8; 16]>> = BTreeMap::new();
    for item in evidence {
        match item.identity {
            Identity::Exact { model } => {
                models.insert(model);
            }
            Identity::ProtocolSignature { bytes } => {
                signatures.entry(item.component).or_default().insert(bytes);
            }
            Identity::Conflicting => return Identity::Conflicting,
            Identity::Unknown => {}
        }
    }
    if models.len() > 1 || signatures.values().any(|values| values.len() > 1) {
        return Identity::Conflicting;
    }
    models
        .into_iter()
        .next()
        .map_or(Identity::Unknown, |model| Identity::Exact { model })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(id: &str, component: Component, identity: Identity) -> Observation {
        Observation {
            controller: ControllerId::new(id).unwrap(),
            component,
            identity,
        }
    }

    #[test]
    fn groups_main_and_bluetooth_on_the_same_physical_ns39() {
        let controllers = group_observations([
            observation(
                "usb:one",
                Component::Main,
                Identity::Exact {
                    model: Model::Kk3Max,
                },
            ),
            observation(
                "usb:one",
                Component::Bluetooth,
                Identity::ProtocolSignature { bytes: [0xa1; 16] },
            ),
        ]);
        assert_eq!(controllers.len(), 1);
        assert_eq!(
            controllers[0].identity,
            Identity::Exact {
                model: Model::Kk3Max
            }
        );
        assert_eq!(
            controllers[0].components,
            vec![Component::Main, Component::Bluetooth]
        );
    }

    #[test]
    fn never_combines_main_evidence_from_another_controller() {
        let controllers = group_observations([
            observation(
                "usb:one",
                Component::Main,
                Identity::Exact {
                    model: Model::Kk3Max,
                },
            ),
            observation("usb:two", Component::Bluetooth, Identity::Unknown),
        ]);
        assert_eq!(controllers.len(), 2);
        assert_eq!(controllers[1].identity, Identity::Unknown);
    }

    #[test]
    fn conflicting_identity_is_preserved_and_duplicate_components_are_removed() {
        let controllers = group_observations([
            observation(
                "one",
                Component::Main,
                Identity::Exact {
                    model: Model::Kk3Max,
                },
            ),
            observation("one", Component::Main, Identity::Conflicting),
        ]);
        assert_eq!(controllers[0].identity, Identity::Conflicting);
        assert_eq!(controllers[0].components.len(), 1);
    }

    fn dual_access(id: &str) -> [Observation; 2] {
        [
            observation(
                id,
                Component::Main,
                Identity::Exact {
                    model: Model::Kk3Max,
                },
            ),
            observation(
                id,
                Component::Bluetooth,
                Identity::ProtocolSignature { bytes: [0xa1; 16] },
            ),
        ]
    }

    #[test]
    fn selects_one_controller_with_both_component_accesses() {
        let target = select_ns39_update_target(dual_access("one")).unwrap();
        assert_eq!(target.controller().components.len(), 2);
    }

    #[test]
    fn refuses_multiple_physical_devices_even_when_one_is_identified() {
        let observations = dual_access("one").into_iter().chain([observation(
            "two",
            Component::Main,
            Identity::Unknown,
        )]);
        assert_eq!(
            select_ns39_update_target(observations).unwrap_err(),
            SelectionError::MultipleDevices
        );
    }

    #[test]
    fn refuses_missing_or_cross_device_component_access() {
        assert_eq!(
            select_ns39_update_target([dual_access("one")[0].clone()]).unwrap_err(),
            SelectionError::MissingComponent
        );
        let observations = [dual_access("one")[0].clone(), dual_access("two")[1].clone()];
        assert_eq!(
            select_ns39_update_target(observations).unwrap_err(),
            SelectionError::MultipleDevices
        );
    }

    #[test]
    fn protocol_signature_alone_does_not_establish_ns39() {
        let observations = [
            observation("one", Component::Main, Identity::Unknown),
            dual_access("one")[1].clone(),
        ];
        assert_eq!(
            select_ns39_update_target(observations).unwrap_err(),
            SelectionError::Unidentified
        );
    }

    #[test]
    fn conflicting_signatures_refuse_every_observation_order() {
        let exact = dual_access("one")[0].clone();
        let first = dual_access("one")[1].clone();
        let second = observation(
            "one",
            Component::Bluetooth,
            Identity::ProtocolSignature { bytes: [0xb2; 16] },
        );
        for observations in [
            [exact.clone(), first.clone(), second.clone()],
            [exact.clone(), second.clone(), first.clone()],
            [first.clone(), exact.clone(), second.clone()],
            [second.clone(), exact.clone(), first.clone()],
            [first.clone(), second.clone(), exact.clone()],
            [second.clone(), first.clone(), exact.clone()],
        ] {
            assert_eq!(
                select_ns39_update_target(observations).unwrap_err(),
                SelectionError::Unidentified
            );
        }
    }
}
