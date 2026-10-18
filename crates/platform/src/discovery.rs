//! Portable discovery records produced by native host adapters.
use gulikit_core::{
    device::{Candidate, Discovery},
    package::Component,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct Disk {
    pub bsd: String,
    pub mount: PathBuf,
    pub writable: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
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
            .map(|mut candidate| {
                // Native iterator order is not attachment identity. Preserve all
                // entries and fields while making exact session checks stable.
                candidate.disks.sort();
                candidate.storage_identities.sort();
                candidate
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_ignores_enumeration_order_but_retains_changed_device_evidence() {
        let candidate: NativeCandidate = serde_json::from_value(serde_json::json!({
            "ancestor": 1, "generation": 1, "main_volume_candidate": true,
            "bluetooth_transport_candidate": false, "observed_profile": true,
            "conflicting_model": false, "mount": "/Volumes/GuliKit",
            "disks": [
                {"bsd":"disk2", "mount":"/Volumes/GuliKit", "writable":true},
                {"bsd":"disk1", "mount":"", "writable":false}
            ],
            "storage_identities": [
                {"entry":2, "vendor":"GuliKit", "product":"Updater", "revision":"1.00"},
                {"entry":1, "vendor":null, "product":null, "revision":null}
            ]
        }))
        .unwrap();
        let mut snapshot = Snapshot {
            candidates: vec![candidate],
            incomplete: vec![],
        };
        let original = snapshot.select(true, Component::Main).unwrap();
        snapshot.candidates[0].disks.reverse();
        snapshot.candidates[0].storage_identities.reverse();
        assert_eq!(snapshot.select(true, Component::Main).unwrap(), original);
        snapshot.candidates[0].disks[0].writable = true;
        assert_ne!(snapshot.select(true, Component::Main).unwrap(), original);
        snapshot.candidates[0].disks[0].writable = false;
        snapshot.candidates[0].storage_identities[0].entry = 3;
        assert_ne!(snapshot.select(true, Component::Main).unwrap(), original);
    }
}
