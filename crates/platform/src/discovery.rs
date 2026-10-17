//! Portable discovery records produced by native host adapters.
use gulikit_core::{
    device::{Candidate, Discovery},
    package::Component,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Disk {
    pub bsd: String,
    pub mount: PathBuf,
    pub writable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct StorageIdentity {
    pub entry: u64,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct NativeCandidate {
    pub ancestor: u64,
    pub generation: u64,
    /// A mounted volume to inspect, not proof of valid GULI.TXT or writable media.
    pub main_volume_candidate: bool,
    /// A correlated command path; successful F1 is separate protocol evidence.
    pub bluetooth_transport_candidate: bool,
    pub observed_profile: bool,
    pub conflicting_model: bool,
    pub storage_identities: Vec<StorageIdentity>,
    pub disks: Vec<Disk>,
    pub mount: Option<PathBuf>,
}
impl NativeCandidate {
    pub(crate) fn core(&self) -> Candidate {
        Candidate {
            ancestor: self.ancestor,
            generation: self.generation,
            main_access: self.main_volume_candidate,
            bluetooth_access: self.bluetooth_transport_candidate,
            observed_profile: self.observed_profile,
            conflicting_model: self.conflicting_model,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub candidates: Vec<NativeCandidate>,
    pub incomplete: Vec<String>,
}
impl Snapshot {
    pub fn select(&self, confirmed: bool, component: Component) -> Result<NativeCandidate, String> {
        let selected = Discovery {
            candidates: self.candidates.iter().map(NativeCandidate::core).collect(),
            incomplete: self.incomplete.clone(),
        }
        .select(confirmed, component)
        .map_err(|e| e.to_string())?;
        self.candidates
            .iter()
            .find(|c| c.ancestor == selected.ancestor)
            .cloned()
            .ok_or_else(|| "Selected attachment vanished".into())
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn validate_transport(
        &self,
        target: &NativeCandidate,
        component: Component,
    ) -> Result<(), String> {
        let selected = Discovery {
            candidates: self.candidates.iter().map(NativeCandidate::core).collect(),
            incomplete: self.incomplete.clone(),
        }
        .select(true, component)
        .map_err(|e| e.to_string())?;
        if selected.ancestor != target.ancestor || selected.generation != target.generation {
            return Err("Transport attachment changed".into());
        }
        Ok(())
    }
}
