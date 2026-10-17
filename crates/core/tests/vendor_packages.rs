//! These explicit acceptance tests use original archives from the ignored cache.
//! They never open a controller or execute the bundled Windows updater.

use gulikit_core::package::{Component, Model, VerifiedPackage};
use std::path::PathBuf;

fn archive(name: &str) -> Vec<u8> {
    let directory = std::env::var_os("GULIKIT_VENDOR_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts/vendor/kk3/packages")
        });
    std::fs::read(directory.join(name))
        .expect("supply intact official archives via GULIKIT_VENDOR_DIR")
}

#[test]
#[ignore = "requires original vendor archive in ignored cache"]
fn selects_ns39_main_instead_of_ns38_sibling() {
    let bytes = archive("KK3_NS38_NS39_V5.9.zip");
    let package = VerifiedPackage::inspect(&bytes, Model::Kk3Max, Component::Main).unwrap();
    assert_eq!(package.info().version, "5.9");
    assert_eq!(package.payload().len(), 51_500);
    assert_eq!(
        package.info().payload_sha256,
        "d1c7d485e1a29fd518d2a77c824c46a883bdd6c73c8126cca15bf5a1ec6d6ae4"
    );
    assert!(VerifiedPackage::inspect(&bytes, Model::Kk3Max, Component::Bluetooth).is_err());
}

#[test]
#[ignore = "requires original vendor archive in ignored cache"]
fn extracts_the_official_bt_payload_without_executing_the_updater() {
    let bytes = archive("GuliKit_NS38_NS39_NS59_BT_V5.07.zip");
    let package = VerifiedPackage::inspect(&bytes, Model::Kk3Max, Component::Bluetooth).unwrap();
    assert_eq!(package.info().version, "5.07");
    assert_eq!(package.payload().len(), 345_088);
    assert_eq!(
        &package.payload()[..8],
        &[0x46, 0x4f, 0x54, 0, 0xf8, 0x43, 5, 0]
    );
    assert_eq!(
        package.info().payload_sha256,
        "2e0e89d458eb39f30eaa1ba9f4038039ad95c2eeed0e392ecfb0d5ece3441826"
    );
    assert!(VerifiedPackage::inspect(&bytes, Model::Kk3Max, Component::Main).is_err());
}

#[test]
#[ignore = "requires original vendor archive in ignored cache"]
fn rejects_modified_archive_before_using_its_payload() {
    let mut bytes = archive("KK3_NS38_NS39_V5.9.zip");
    bytes[100] ^= 1;
    assert!(VerifiedPackage::inspect(&bytes, Model::Kk3Max, Component::Main).is_err());
}
