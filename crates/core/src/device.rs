//! Physical-controller identity and component access, independent of the OS.

use crate::package::Component;
use serde::Serialize;
use std::collections::BTreeSet;

/// Current attachment evidence. These keys are session identities, never serial numbers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Candidate {
    pub ancestor: u64,
    pub generation: u64,
    pub main_access: bool,
    /// A candidate command path, not proof that F1 or firmware writes succeed.
    pub bluetooth_access: bool,
    pub observed_profile: bool,
    pub conflicting_model: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Discovery {
    /// All recognized update candidates, before model or component filtering.
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
    #[error("The requested component has no correlated access path on this attachment.")]
    MissingAccess,
}

impl Discovery {
    pub fn select(
        &self,
        user_confirmed_ns39: bool,
        component: Component,
    ) -> Result<Candidate, DiscoveryError> {
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
        if !user_confirmed_ns39 || self.candidates.iter().any(|c| c.conflicting_model) {
            return Err(DiscoveryError::WrongOrConflictingModel);
        }
        let mut candidate = first.clone();
        candidate.main_access = self.candidates.iter().any(|c| c.main_access);
        candidate.bluetooth_access = self.candidates.iter().any(|c| c.bluetooth_access);
        let available = match component {
            Component::Main => candidate.main_access,
            Component::Bluetooth => candidate.bluetooth_access,
        };
        if !available {
            return Err(DiscoveryError::MissingAccess);
        }
        Ok(candidate)
    }
}
