use assert_cmd::Command;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const KEY_ID: &str = "test-catalog-key";

fn updater() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("gulikit-updater"))
}

struct Fixture {
    directory: tempfile::TempDir,
    key: SigningKey,
    keys: PathBuf,
    cache: PathBuf,
    now: u64,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[42; 32]);
        let keys = directory.path().join("keys.json");
        let cache = directory.path().join("catalog.json");
        std::fs::write(&keys, json!({"schema_version":1,"keys":[{"id":KEY_ID,"public_key":hex::encode(key.verifying_key().to_bytes())}]}).to_string()).unwrap();
        Self {
            directory,
            key,
            keys,
            cache,
            now: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn envelope(&self, revision: u64, expires_at: u64) -> Vec<u8> {
        let catalog: Value =
            serde_json::from_str(include_str!("../catalog/official.json")).unwrap();
        let payload = json!({"revision":revision,"issued_at":self.now-3600,"expires_at":expires_at,"catalog":catalog}).to_string();
        let mut message = b"gulikit-catalog-v1\0".to_vec();
        message.extend_from_slice(payload.as_bytes());
        json!({"schema_version":1,"key_id":KEY_ID,"payload":payload,"signature":hex::encode(self.key.sign(&message).to_bytes())}).to_string().into_bytes()
    }

    fn write_envelope(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn refresh(&self, envelope: &Path) -> Command {
        let mut command = updater();
        command
            .args(["catalog", "refresh", "--envelope"])
            .arg(envelope)
            .arg("--cache")
            .arg(&self.cache)
            .arg("--trusted-keys")
            .arg(&self.keys)
            .arg("--json");
        command
    }

    fn cached(&self) -> Command {
        let mut command = updater();
        command
            .args(["catalog", "cached", "--cache"])
            .arg(&self.cache)
            .arg("--trusted-keys")
            .arg(&self.keys)
            .arg("--json");
        command
    }
}

#[test]
fn verifies_explicit_keys_and_persists_a_reauthenticated_offline_cache() {
    let fixture = Fixture::new();
    let bytes = fixture.envelope(7, fixture.now + 3600);
    let envelope = fixture.write_envelope("envelope.json", &bytes);
    let verified = updater()
        .args(["catalog", "verify"])
        .arg(&envelope)
        .arg("--trusted-keys")
        .arg(&fixture.keys)
        .arg("--json")
        .assert()
        .success();
    let output: Value = serde_json::from_slice(&verified.get_output().stdout).unwrap();
    assert_eq!(output["trust"], "authenticated");
    assert_eq!(output["trust_source"], "explicit_key_file");
    assert_eq!(output["freshness"], "fresh");
    assert_eq!(output["authorizes_firmware"], false);
    fixture.refresh(&envelope).assert().success();
    assert_eq!(std::fs::read(&fixture.cache).unwrap(), bytes);
    let cached = fixture.cached().assert().success();
    let output: Value = serde_json::from_slice(&cached.get_output().stdout).unwrap();
    assert_eq!(output["revision"], 7);
    assert_eq!(output["key_id"], KEY_ID);
    assert_eq!(output["catalog"]["entries"].as_array().unwrap().len(), 4);
}

#[test]
fn older_or_tampered_refresh_never_replaces_the_verified_cache() {
    let fixture = Fixture::new();
    let original = fixture.envelope(7, fixture.now + 3600);
    let initial = fixture.write_envelope("initial.json", &original);
    fixture.refresh(&initial).assert().success();
    let older = fixture.write_envelope("older.json", &fixture.envelope(6, fixture.now + 3600));
    let mut tampered = fixture.envelope(8, fixture.now + 3600);
    let index = tampered.iter().position(|byte| *byte == b'8').unwrap();
    tampered[index] = b'9';
    let tampered = fixture.write_envelope("tampered.json", &tampered);
    for path in [older, tampered] {
        let result = fixture.refresh(&path).assert().code(3);
        assert!(result.get_output().stdout.is_empty());
        let error: Value = serde_json::from_slice(&result.get_output().stderr).unwrap();
        assert_eq!(error["error"]["kind"], "catalog_rejected");
        assert_eq!(std::fs::read(&fixture.cache).unwrap(), original);
    }
}

#[test]
fn expired_cache_stays_inspectable_and_retains_its_revision_floor() {
    let fixture = Fixture::new();
    let expired = fixture.envelope(9, fixture.now - 60);
    std::fs::write(&fixture.cache, &expired).unwrap();
    let cached = fixture.cached().assert().success();
    let output: Value = serde_json::from_slice(&cached.get_output().stdout).unwrap();
    assert_eq!(output["freshness"], "expired");
    assert_eq!(output["authorizes_firmware"], false);
    updater()
        .args(["catalog", "verify"])
        .arg(&fixture.cache)
        .arg("--trusted-keys")
        .arg(&fixture.keys)
        .arg("--json")
        .assert()
        .code(3);
    let older = fixture.write_envelope("older.json", &fixture.envelope(8, fixture.now + 3600));
    fixture.refresh(&older).assert().code(3);
    assert_eq!(std::fs::read(&fixture.cache).unwrap(), expired);
}

#[test]
fn explicit_trust_configuration_rejects_unknown_fields_and_wrong_keys() {
    let fixture = Fixture::new();
    let envelope =
        fixture.write_envelope("envelope.json", &fixture.envelope(1, fixture.now + 3600));
    for keys in [
        json!({"schema_version":1,"keys":[],"trust_everything":true}),
        json!({"schema_version":1,"keys":[{"id":KEY_ID,"public_key":hex::encode(SigningKey::from_bytes(&[43;32]).verifying_key().to_bytes())}]}),
    ] {
        std::fs::write(&fixture.keys, keys.to_string()).unwrap();
        fixture.refresh(&envelope).assert().code(3);
        assert!(!fixture.cache.exists());
    }
}

#[test]
fn refresh_requires_one_source_and_refuses_plain_http_without_network_io() {
    let fixture = Fixture::new();
    updater().args(["catalog", "refresh"]).assert().code(2);
    updater()
        .args([
            "catalog",
            "refresh",
            "--url",
            "https://example.test/catalog",
            "--envelope",
            "anything.json",
            "--cache",
        ])
        .arg(&fixture.cache)
        .arg("--trusted-keys")
        .arg(&fixture.keys)
        .assert()
        .code(2);
    updater()
        .args([
            "catalog",
            "refresh",
            "--url",
            "http://127.0.0.1:1/catalog",
            "--cache",
        ])
        .arg(&fixture.cache)
        .arg("--trusted-keys")
        .arg(&fixture.keys)
        .arg("--json")
        .assert()
        .code(3);
    assert!(!fixture.cache.exists());
}
