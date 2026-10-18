use ed25519_dalek::{Signer, SigningKey};
use gulikit_catalog::CatalogError;
use gulikit_catalog::auth::{
    AuthError, FreshnessError, MAX_ENVELOPE_BYTES, MAX_SIGNED_PAYLOAD_BYTES, MAX_TRUSTED_KEYS,
    TrustedKeys, verify_envelope,
};
use serde_json::{Value, json};

const DOMAIN: &[u8] = b"gulikit-catalog-v1\0";
const KEY_ID: &str = "release-key-2026";

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trusted(key: &SigningKey) -> TrustedKeys {
    TrustedKeys::new([(KEY_ID.to_owned(), key.verifying_key().to_bytes())])
        .expect("valid test trust key")
}

fn catalog_json() -> Value {
    json!({
        "schema_version": 1,
        "entries": [{
            "product": "kk3-max",
            "component": "main",
            "version": "5.9",
            "archive": "firmware.zip",
            "archive_size": 40,
            "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "member": "firmware.bin",
            "member_size": 50,
            "member_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "payload_size": 50,
            "payload_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "source_url": "https://www.gulikit.com/newsinfo/887152.html",
            "parser_id": "kk3_main_binary_v1",
            "software_support": "supported",
            "hardware_acceptance": "unqualified",
            "hardware_evidence": null
        }]
    })
}

fn payload_json(revision: u64, issued_at: u64, expires_at: u64) -> String {
    json!({
        "revision": revision,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "catalog": catalog_json()
    })
    .to_string()
}

fn signed_envelope(payload: &str, key_id: &str, key: &SigningKey) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(payload.as_bytes());
    let signature = hex::encode(key.sign(&message).to_bytes());
    json!({
        "schema_version": 1,
        "key_id": key_id,
        "payload": payload,
        "signature": signature
    })
    .to_string()
    .into_bytes()
}

fn unsigned_envelope(payload: &str, key_id: &str, signature: &str) -> Vec<u8> {
    json!({
        "schema_version": 1,
        "key_id": key_id,
        "payload": payload,
        "signature": signature
    })
    .to_string()
    .into_bytes()
}

#[test]
fn verifies_exact_signed_payload_and_keeps_freshness_explicit() {
    let key = signing_key(7);
    let envelope = signed_envelope(&payload_json(12, 100, 200), KEY_ID, &key);
    let keys = trusted(&key);
    assert_eq!(keys.key_count(), 1);
    let verified = verify_envelope(&envelope, &keys).expect("valid signed envelope");

    assert_eq!(verified.revision(), 12);
    assert_eq!(verified.issued_at(), 100);
    assert_eq!(verified.expires_at(), 200);
    assert_eq!(verified.key_id(), KEY_ID);
    assert_eq!(verified.envelope_bytes(), envelope);
    assert_eq!(
        verified.payload_bytes(),
        payload_json(12, 100, 200).as_bytes()
    );
    assert_eq!(verified.catalog().entries().len(), 1);
    assert_eq!(verified.require_fresh_at(100, 12), Ok(()));
    assert_eq!(verified.require_fresh_at(199, 12), Ok(()));
    assert_eq!(
        verified.require_fresh_at(99, 12),
        Err(FreshnessError::NotYetValid)
    );
    assert_eq!(
        verified.require_fresh_at(200, 12),
        Err(FreshnessError::Expired)
    );
    assert_eq!(
        verified.require_fresh_at(100, 13),
        Err(FreshnessError::StaleRevision)
    );
}

#[test]
fn authentic_expired_catalog_remains_inspectable_but_fails_freshness() {
    let key = signing_key(9);
    let envelope = signed_envelope(&payload_json(4, 10, 20), KEY_ID, &key);
    let verified = verify_envelope(&envelope, &trusted(&key)).expect("signature authenticates");

    assert_eq!(verified.revision(), 4);
    assert_eq!(verified.catalog().entries().len(), 1);
    assert_eq!(
        verified.require_fresh_at(20, 0),
        Err(FreshnessError::Expired)
    );
}

#[test]
fn rejects_tampering_wrong_keys_and_unknown_key_ids() {
    let key = signing_key(3);
    let envelope = signed_envelope(&payload_json(1, 10, 20), KEY_ID, &key);
    let keys = trusted(&key);

    let mut tampered: Value = serde_json::from_slice(&envelope).expect("envelope JSON");
    tampered["payload"] = json!(payload_json(2, 10, 20));
    assert_eq!(
        verify_envelope(tampered.to_string().as_bytes(), &keys),
        Err(AuthError::InvalidSignature)
    );
    assert!(matches!(
        verify_envelope(&envelope, &trusted(&signing_key(4))),
        Err(AuthError::InvalidSignature)
    ));

    let unknown_key = signed_envelope(&payload_json(1, 10, 20), "other-key", &key);
    assert!(matches!(
        verify_envelope(&unknown_key, &keys),
        Err(AuthError::UnknownKey(id)) if id == "other-key"
    ));
}

#[test]
fn rejects_bad_envelope_payload_schema_and_duplicate_fields() {
    let key = signing_key(11);
    let keys = trusted(&key);
    let payload = payload_json(1, 10, 20);

    assert!(matches!(
        verify_envelope(br#"{"schema_version":1,"schema_version":1,"key_id":"release-key-2026","payload":"{}","signature":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#, &keys),
        Err(AuthError::EnvelopeJson(_))
    ));
    let mut unknown_envelope: Value =
        serde_json::from_slice(&signed_envelope(&payload, KEY_ID, &key)).expect("envelope JSON");
    unknown_envelope["unexpected"] = json!(true);
    assert!(matches!(
        verify_envelope(unknown_envelope.to_string().as_bytes(), &keys),
        Err(AuthError::EnvelopeJson(_))
    ));
    let mut unsupported_envelope: Value =
        serde_json::from_slice(&signed_envelope(&payload, KEY_ID, &key)).expect("envelope JSON");
    unsupported_envelope["schema_version"] = json!(2);
    assert!(matches!(
        verify_envelope(unsupported_envelope.to_string().as_bytes(), &keys),
        Err(AuthError::UnknownEnvelopeSchema(2))
    ));
    assert!(matches!(
        verify_envelope(
            &unsigned_envelope(&payload, KEY_ID, &"A".repeat(128)),
            &keys
        ),
        Err(AuthError::InvalidSignatureEncoding)
    ));
    assert!(matches!(
        verify_envelope(&unsigned_envelope(&payload, KEY_ID, "bad"), &keys),
        Err(AuthError::InvalidSignatureEncoding)
    ));
    assert!(matches!(
        verify_envelope(
            &unsigned_envelope(&payload, KEY_ID, &"z".repeat(128)),
            &keys
        ),
        Err(AuthError::InvalidSignatureEncoding)
    ));

    let duplicate_payload = r#"{"revision":1,"revision":1,"issued_at":10,"expires_at":20,"catalog":{"schema_version":1,"entries":[]}}"#;
    let signed = signed_envelope(duplicate_payload, KEY_ID, &key);
    assert!(matches!(
        verify_envelope(&signed, &keys),
        Err(AuthError::PayloadJson(_))
    ));

    let duplicate_catalog = r#"{"revision":1,"issued_at":10,"expires_at":20,"catalog":{"schema_version":1,"schema_version":1,"entries":[]}}"#;
    let signed = signed_envelope(duplicate_catalog, KEY_ID, &key);
    assert!(matches!(
        verify_envelope(&signed, &keys),
        Err(AuthError::Catalog(_))
    ));

    let unsupported_payload = json!({
        "revision": 1, "issued_at": 10, "expires_at": 20,
        "catalog": catalog_json(), "extra": true
    })
    .to_string();
    let signed = signed_envelope(&unsupported_payload, KEY_ID, &key);
    assert!(matches!(
        verify_envelope(&signed, &keys),
        Err(AuthError::PayloadJson(_))
    ));

    let unknown_schema = signed_envelope(
        "{\"revision\":1,\"issued_at\":10,\"expires_at\":20,\"catalog\":{\"schema_version\":2,\"entries\":[]}}",
        KEY_ID,
        &key,
    );
    assert!(matches!(
        verify_envelope(&unknown_schema, &keys),
        Err(AuthError::Catalog(CatalogError::UnknownSchema(2)))
    ));
}

#[test]
fn verifies_signature_before_interpreting_signed_payload() {
    let key = signing_key(13);
    let bad_payload = "not-json";
    let invalid_signature = unsigned_envelope(bad_payload, KEY_ID, &"00".repeat(64));
    assert_eq!(
        verify_envelope(&invalid_signature, &trusted(&key)),
        Err(AuthError::InvalidSignature)
    );
    let authenticated_bad_payload = signed_envelope(bad_payload, KEY_ID, &key);
    assert!(matches!(
        verify_envelope(&authenticated_bad_payload, &trusted(&key)),
        Err(AuthError::PayloadJson(_))
    ));
}

#[test]
fn enforces_size_and_time_bounds() {
    let key = signing_key(17);
    let keys = trusted(&key);
    assert_eq!(
        verify_envelope(&vec![b' '; MAX_ENVELOPE_BYTES + 1], &keys),
        Err(AuthError::EnvelopeTooLarge)
    );

    let oversized_payload = " ".repeat(MAX_SIGNED_PAYLOAD_BYTES + 1);
    let envelope = signed_envelope(&oversized_payload, KEY_ID, &key);
    assert_eq!(
        verify_envelope(&envelope, &keys),
        Err(AuthError::PayloadTooLarge)
    );

    let invalid_times = signed_envelope(&payload_json(1, 20, 20), KEY_ID, &key);
    assert_eq!(
        verify_envelope(&invalid_times, &keys),
        Err(AuthError::InvalidTimeRange)
    );
}

#[test]
fn validates_caller_pinned_key_sets() {
    let key = signing_key(21);
    assert!(matches!(
        TrustedKeys::new(std::iter::empty::<(String, [u8; 32])>()),
        Err(AuthError::EmptyKeySet)
    ));
    assert!(matches!(
        TrustedKeys::new([(String::from("Bad Key"), key.verifying_key().to_bytes())]),
        Err(AuthError::InvalidKeyId)
    ));
    assert!(matches!(
        TrustedKeys::new([
            (String::from(KEY_ID), key.verifying_key().to_bytes()),
            (String::from(KEY_ID), key.verifying_key().to_bytes()),
        ]),
        Err(AuthError::DuplicateKeyId(id)) if id == KEY_ID
    ));
    assert!(matches!(
        TrustedKeys::new([(String::from(KEY_ID), [0; 32])]),
        Err(AuthError::InvalidPublicKey)
    ));
    let too_many = (0..=MAX_TRUSTED_KEYS).map(|index| {
        (
            format!("key-{index}"),
            signing_key(u8::try_from(index).expect("bounded test index"))
                .verifying_key()
                .to_bytes(),
        )
    });
    assert!(matches!(
        TrustedKeys::new(too_many),
        Err(AuthError::TooManyKeys)
    ));
}
