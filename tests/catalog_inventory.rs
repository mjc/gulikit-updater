use gulikit_catalog::Catalog;

#[test]
fn seed_preserves_compiled_release_identity_without_replacing_its_authority() {
    let catalog = Catalog::parse(include_bytes!("../catalog/official.json")).unwrap();
    let compiled = gulikit_core::package::catalog();
    assert_eq!(catalog.entries().len(), compiled.len());
    for release in compiled {
        let entry = catalog
            .entries()
            .iter()
            .find(|entry| {
                entry.product() == release.model.to_string()
                    && entry.component() == release.component.to_string()
                    && entry.version() == release.version
            })
            .expect("compiled release must have a matching seed record");
        assert_eq!(entry.archive(), release.archive);
        assert_eq!(entry.archive_size(), release.archive_size as u64);
        assert_eq!(entry.archive_sha256().as_str(), release.archive_sha256);
        assert_eq!(entry.member(), release.member);
        let compiled_metadata = serde_json::to_value(release).unwrap();
        assert_eq!(
            entry.member_size(),
            compiled_metadata["member_size"].as_u64().unwrap()
        );
        assert_eq!(
            entry.member_sha256().as_str(),
            compiled_metadata["member_sha256"].as_str().unwrap()
        );
        assert_eq!(entry.payload_size(), release.payload_size() as u64);
        assert_eq!(entry.payload_sha256().as_str(), release.payload_sha256());
        assert_eq!(entry.source_url(), release.source_url);
    }
}
