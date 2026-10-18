use gulikit_catalog::{
    Catalog, CatalogError, Entry, EntryField, MAX_CATALOG_BYTES, MAX_ENTRIES, VendorVerification,
};
use serde_json::{Value, json};

fn raw_entry(product: &str, version: &str) -> Value {
    json!({
        "product": product,
        "component": "main",
        "version": version,
        "archive": "firmware.zip",
        "archive_size": 10,
        "archive_sha256": "a".repeat(64),
        "member": "firmware.bin",
        "member_size": 10,
        "member_sha256": "b".repeat(64),
        "payload_size": 10,
        "payload_sha256": "c".repeat(64),
        "source_url": "https://www.gulikit.com/newsinfo/123.html",
        "parser_id": "none",
        "software_support": "metadata_only",
        "hardware_acceptance": "unqualified",
        "hardware_evidence": null
    })
}

fn catalog_with(entries: &[Value]) -> Catalog {
    Catalog::parse(&serde_json::to_vec(&json!({"schema_version": 1, "entries": entries})).unwrap())
        .unwrap()
}

fn entry_from(value: &Value) -> Entry {
    Entry::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn assert_immutable_change_rejected(original: &Catalog, changed: &Value, field: &'static str) {
    assert_eq!(
        original.upsert(entry_from(changed)).unwrap_err(),
        CatalogError::ImmutableMetadataChanged {
            product: "future-a".to_owned(),
            component: "main".to_owned(),
            version: "1.0".to_owned(),
            field,
        }
    );
}

#[test]
fn diff_reports_sorted_added_changed_and_removed_fields_independent_of_input_order() {
    let mut previous_values = vec![raw_entry("future-b", "1.0"), raw_entry("future-a", "1.0")];
    let previous = catalog_with(&previous_values);

    let mut changed = raw_entry("future-b", "1.0");
    changed["source_url"] = json!("https://www.gulikit.com/newsinfo/456.html");
    let mut proposed_values = vec![changed, raw_entry("future-c", "1.0")];
    let proposed = catalog_with(&proposed_values);
    let diff = previous.diff(&proposed);

    assert_eq!(diff.added().len(), 1);
    assert_eq!(diff.added()[0].product(), "future-c");
    assert_eq!(diff.removed().len(), 1);
    assert_eq!(diff.removed()[0].product(), "future-a");
    assert_eq!(diff.changed().len(), 1);
    assert_eq!(diff.changed()[0].identity().product(), "future-b");
    assert_eq!(diff.changed()[0].fields().len(), 1);
    assert_eq!(diff.changed()[0].fields()[0].field(), EntryField::SourceUrl);
    assert_eq!(
        diff.changed()[0].fields()[0].previous(),
        &json!("https://www.gulikit.com/newsinfo/123.html")
    );
    assert_eq!(
        diff.changed()[0].fields()[0].proposed(),
        &json!("https://www.gulikit.com/newsinfo/456.html")
    );

    previous_values.reverse();
    proposed_values.reverse();
    let reversed_previous = catalog_with(&previous_values);
    let reversed_proposed = catalog_with(&proposed_values);
    assert_eq!(diff, reversed_previous.diff(&reversed_proposed));
}

#[test]
fn upsert_replaces_in_place_and_appends_without_dropping_history() {
    let original_values = vec![raw_entry("future-b", "1.0"), raw_entry("future-a", "1.0")];
    let original = catalog_with(&original_values);
    let original_identities = original
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.product().to_owned(),
                entry.component().to_owned(),
                entry.version().to_owned(),
            )
        })
        .collect::<Vec<_>>();

    let mut updated = raw_entry("future-b", "1.0");
    updated["source_url"] = json!("https://www.gulikit.com/newsinfo/456.html");
    updated["vendor_verification"] = json!({
        "status": "not_published",
        "source_url": "https://www.gulikit.com/newsinfo/456.html",
        "note": "No archive checksum is published on this page."
    });
    let updated = entry_from(&updated);
    let replaced = original.upsert(updated).unwrap();

    assert_eq!(replaced.entries().len(), 2);
    assert_eq!(replaced.entries()[0].product(), "future-b");
    assert_eq!(
        replaced.entries()[0].source_url(),
        "https://www.gulikit.com/newsinfo/456.html"
    );
    assert_eq!(
        replaced.entries()[0].vendor_verification(),
        Some(&VendorVerification::NotPublished {
            source_url: "https://www.gulikit.com/newsinfo/456.html".to_owned(),
            note: "No archive checksum is published on this page.".to_owned(),
        })
    );
    let metadata_diff = original.diff(&replaced);
    assert_eq!(metadata_diff.changed()[0].fields().len(), 2);
    assert_eq!(
        metadata_diff.changed()[0]
            .fields()
            .iter()
            .map(gulikit_catalog::FieldChange::field)
            .collect::<Vec<_>>(),
        vec![EntryField::SourceUrl, EntryField::VendorVerification]
    );
    assert_eq!(replaced.entries()[1].product(), "future-a");
    let replaced_identities = replaced
        .entries()
        .iter()
        .map(|entry| {
            (
                entry.product().to_owned(),
                entry.component().to_owned(),
                entry.version().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(replaced_identities, original_identities);

    let appended = replaced
        .upsert(entry_from(&raw_entry("future-c", "1.0")))
        .unwrap();
    assert_eq!(appended.entries()[2].product(), "future-c");
    assert_eq!(appended.entries()[0].product(), "future-b");
    assert_eq!(appended.entries()[1].product(), "future-a");
}

#[test]
fn upsert_rejects_changes_to_archive_member_payload_or_parser_identity() {
    let original_values = vec![raw_entry("future-a", "1.0")];
    let original = catalog_with(&original_values);
    for (key, value, field) in [
        ("archive", json!("replacement.zip"), "archive"),
        ("member", json!("replacement.bin"), "member"),
        ("payload_sha256", json!("d".repeat(64)), "payload_sha256"),
    ] {
        let mut changed = raw_entry("future-a", "1.0");
        changed[key] = value;
        assert_immutable_change_rejected(&original, &changed, field);
    }

    let parser_values = vec![raw_entry("kk3-max", "1.0")];
    let parser_original = catalog_with(&parser_values);
    let mut changed_parser = raw_entry("kk3-max", "1.0");
    changed_parser["parser_id"] = json!("kk3_main_binary_v1");
    changed_parser["software_support"] = json!("supported");
    assert_eq!(
        parser_original
            .upsert(entry_from(&changed_parser))
            .unwrap_err(),
        CatalogError::ImmutableMetadataChanged {
            product: "kk3-max".to_owned(),
            component: "main".to_owned(),
            version: "1.0".to_owned(),
            field: "parser_id",
        }
    );
}

#[test]
fn upsert_enforces_entry_count_and_serialized_catalog_limits() {
    let full_count: Vec<_> = (0..MAX_ENTRIES)
        .map(|index| raw_entry(&format!("future-{index:03}"), "1.0"))
        .collect();
    let full_count = catalog_with(&full_count);
    assert_eq!(
        full_count
            .upsert(entry_from(&raw_entry("future-overflow", "1.0")))
            .unwrap_err(),
        CatalogError::TooManyEntries
    );

    let large_values: Vec<_> = (0..16)
        .map(|index| {
            let mut value = raw_entry(&format!("future-{index:03}"), "1.0");
            value["source_url"] = format!("https://www.gulikit.com/{}", "z".repeat(15_000)).into();
            value
        })
        .collect();
    let large_catalog = catalog_with(&large_values);
    let mut oversized_entry = raw_entry("future-016", "1.0");
    oversized_entry["source_url"] =
        format!("https://www.gulikit.com/{}", "z".repeat(15_000)).into();
    assert!(serde_json::to_vec(&large_catalog).unwrap().len() <= MAX_CATALOG_BYTES);
    assert_eq!(
        large_catalog
            .upsert(entry_from(&oversized_entry))
            .unwrap_err(),
        CatalogError::InputTooLarge
    );
}

#[test]
fn vendor_verification_is_bounded_typed_and_omitted_for_legacy_entries() {
    let legacy = entry_from(&raw_entry("future-a", "1.0"));
    assert_eq!(legacy.vendor_verification(), None);
    assert!(
        !serde_json::to_value(&legacy)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("vendor_verification")
    );

    let mut source_record = raw_entry("future-a", "1.0");
    source_record["vendor_verification"] = json!({
        "status": "sha256",
        "source_url": "https://www.gulikit.com/newsinfo/123.html",
        "sha256": "d".repeat(64)
    });
    source_record["archive_sha256"] = json!("d".repeat(64));
    let entry = entry_from(&source_record);
    assert!(matches!(
        entry.vendor_verification(),
        Some(VendorVerification::Sha256 { sha256, .. }) if sha256 == &"d".repeat(64)
    ));
    let round_trip = Entry::parse(&serde_json::to_vec(&entry).unwrap()).unwrap();
    assert_eq!(
        round_trip.vendor_verification(),
        entry.vendor_verification()
    );

    source_record["vendor_verification"]["source_url"] = json!("https://example.invalid/checksum");
    assert!(Entry::parse(&serde_json::to_vec(&source_record).unwrap()).is_err());
    source_record["vendor_verification"]["source_url"] =
        json!("https://www.gulikit.com/newsinfo/123.html");
    source_record["vendor_verification"]["sha256"] = json!("D".repeat(64));
    assert!(Entry::parse(&serde_json::to_vec(&source_record).unwrap()).is_err());

    source_record["vendor_verification"]["sha256"] = json!("c".repeat(64));
    assert!(Entry::parse(&serde_json::to_vec(&source_record).unwrap()).is_err());
}
