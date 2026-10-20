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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
}
impl UsbIdentity {
    #[must_use]
    pub const fn for_update_mode(component: Component) -> Self {
        let (vendor, product) = match component {
            Component::Main => (0x34d3, 0x1100),
            Component::Bluetooth => (0x8087, 0x1024),
        };
        Self { vendor, product }
    }
    #[must_use]
    pub fn matches_update_mode(self, component: Component) -> bool {
        self == Self::for_update_mode(component)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "Native snapshot fields are independent observations, not mutually exclusive states"
)]
pub struct NativeCandidate {
    pub ancestor: u64,
    pub generation: u64,
    /// A mounted volume to inspect, not proof of valid GULI.TXT or writable media.
    pub main_volume_candidate: bool,
    /// A correlated command path; successful F1 is separate protocol evidence.
    pub bluetooth_transport_candidate: bool,
    pub observed_profile: bool,
    pub conflicting_model: bool,
    #[serde(default)]
    pub usb: Option<UsbIdentity>,
    pub storage_identities: Vec<StorageIdentity>,
    pub disks: Vec<Disk>,
    pub mount: Option<PathBuf>,
}
impl NativeCandidate {
    #[must_use]
    pub fn has_known_usb_ids(&self, component: Component) -> bool {
        !self.conflicting_model
            && self
                .usb
                .is_some_and(|usb| usb.matches_update_mode(component))
    }
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
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete or ambiguous discovery, unknown USB IDs
    /// without an explicit model choice, conflicting identity, or absent component access.
    pub fn select(&self, confirmed: bool, component: Component) -> Result<NativeCandidate, String> {
        let recognized = !self.candidates.is_empty()
            && self
                .candidates
                .iter()
                .all(|candidate| candidate.has_known_usb_ids(component));
        let selected = Discovery::select_from(
            self.candidates.iter().map(NativeCandidate::core),
            !self.incomplete.is_empty(),
            confirmed || recognized,
            component,
        )
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
        let selected = Discovery::select_from(
            self.candidates.iter().map(NativeCandidate::core),
            !self.incomplete.is_empty(),
            true,
            component,
        )
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
    fn recognized_usb_ids_select_without_a_manual_confirmation() {
        for (component, vendor, product) in [
            (Component::Main, 0x34d3, 0x1100),
            (Component::Bluetooth, 0x8087, 0x1024),
        ] {
            let snapshot: Snapshot = serde_json::from_value(serde_json::json!({
                "candidates":[{
                    "ancestor":1,"generation":1,"main_volume_candidate":true,
                    "bluetooth_transport_candidate":true,"observed_profile":true,
                    "conflicting_model":false,"storage_identities":[],"disks":[],"mount":null,
                    "usb":{"vendor":vendor,"product":product}
                }], "incomplete":[]
            }))
            .unwrap();
            assert_eq!(snapshot.select(false, component).unwrap().ancestor, 1);
        }
    }

    #[test]
    fn automatic_identification_refuses_missing_unknown_and_wrong_mode_ids() {
        let mut snapshot: Snapshot = serde_json::from_value(serde_json::json!({
            "candidates":[{
                "ancestor":1,"generation":1,"main_volume_candidate":true,
                "bluetooth_transport_candidate":true,"observed_profile":true,
                "conflicting_model":false,"storage_identities":[
                    {"entry":2,"vendor":"Gamepad","product":"Updater","revision":"1.00"}
                ],"disks":[],"mount":null
            }], "incomplete":[]
        }))
        .unwrap();
        for (component, wrong_mode) in [
            (
                Component::Main,
                UsbIdentity {
                    vendor: 0x8087,
                    product: 0x1024,
                },
            ),
            (
                Component::Bluetooth,
                UsbIdentity {
                    vendor: 0x34d3,
                    product: 0x1100,
                },
            ),
        ] {
            for usb in [
                None,
                Some(wrong_mode),
                Some(UsbIdentity {
                    vendor: 0x1234,
                    product: 0x5678,
                }),
            ] {
                snapshot.candidates[0].usb = usb;
                assert!(snapshot.select(false, component).is_err());
            }
        }
        snapshot.candidates[0].usb = Some(UsbIdentity {
            vendor: 0x34d3,
            product: 0x1100,
        });
        snapshot.candidates[0].conflicting_model = true;
        assert!(snapshot.select(false, Component::Main).is_err());
        snapshot.candidates[0].conflicting_model = false;
        snapshot
            .incomplete
            .push("USB properties unavailable".into());
        assert!(snapshot.select(false, Component::Main).is_err());
        snapshot.incomplete.clear();
        let mut other = snapshot.candidates[0].clone();
        other.ancestor = 2;
        snapshot.candidates.push(other);
        assert!(snapshot.select(false, Component::Main).is_err());
    }

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
