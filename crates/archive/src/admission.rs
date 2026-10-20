//! Authenticate cached catalogs through their signed Git object chain.
//! Manufacturer firmware files and their original signatures remain unchanged.

use pgp::{
    composed::{Deserializable, DetachedSignature, SignedPublicKey},
    types::KeyDetails,
};
use serde::{Deserialize, Serialize};
use sha1_checked::{Digest as _, Sha1};
use std::collections::HashSet;
use thiserror::Error;

pub(crate) const MAX_PROOF_BYTES: usize = 1024 * 1024;
const MAX_COMMIT_BYTES: usize = 128 * 1024;
// Ship replacement signing subkeys in the application before rotating the archive.
const MAINTAINER_FINGERPRINTS: &[&str] = &["53e071b497f9f6ef73f6c356d7415e8b2e80d893"];
const PUBLIC_KEY: &str = include_str!("keys/maintainer.asc");

/// Trust roots are constructed by the application, never deserialized from a cache.
#[derive(Clone, Debug)]
pub(crate) struct CatalogKey {
    public_key: String,
    fingerprints: Vec<String>,
}
impl CatalogKey {
    pub(crate) fn maintainer() -> Self {
        Self {
            public_key: PUBLIC_KEY.to_owned(),
            fingerprints: MAINTAINER_FINGERPRINTS
                .iter()
                .map(|fingerprint| (*fingerprint).to_owned())
                .collect(),
        }
    }
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/signed-test-catalog.json"))
                .unwrap();
        Self {
            public_key: fixture["public_key"].as_str().unwrap().to_owned(),
            fingerprints: vec![fixture["fingerprint"].as_str().unwrap().to_owned()],
        }
    }
}

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("invalid commit-verification response: {0}")]
    Response(#[from] serde_json::Error),
    #[error("commit-verification response identifies a different revision")]
    Revision,
    #[error(
        "GitHub did not verify the archive commit signature; a newer app version may be required"
    )]
    Unverified,
    #[error(
        "archive commit signature does not verify against a trusted archive key; a newer app version may be required"
    )]
    Signature,
    #[error("catalog Git-object proof does not match its signed commit")]
    Object,
}

#[derive(Deserialize)]
struct CommitResponse {
    sha: String,
    verification: Verification,
}
#[derive(Deserialize)]
struct Verification {
    verified: bool,
    reason: String,
    signature: Option<String>,
    payload: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SignedCommit {
    sha: String,
    signature: String,
    payload: String,
}
impl SignedCommit {
    pub(crate) fn from_response(
        revision: &str,
        response: &[u8],
        key: &CatalogKey,
    ) -> Result<Self, AdmissionError> {
        if response.len() > MAX_COMMIT_BYTES {
            return Err(AdmissionError::Object);
        }
        let response: CommitResponse = serde_json::from_slice(response)?;
        if !response.verification.verified || response.verification.reason != "valid" {
            return Err(AdmissionError::Unverified);
        }
        let commit = Self {
            sha: response.sha,
            signature: response
                .verification
                .signature
                .ok_or(AdmissionError::Signature)?,
            payload: response
                .verification
                .payload
                .ok_or(AdmissionError::Signature)?,
        };
        commit.verify(revision, key)?;
        Ok(commit)
    }
    pub(crate) fn root_tree(&self) -> Result<&str, AdmissionError> {
        self.payload
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("tree "))
            .filter(|oid| valid_oid(oid))
            .ok_or(AdmissionError::Object)
    }
    fn verify(&self, revision: &str, key: &CatalogKey) -> Result<(), AdmissionError> {
        if self.sha != revision || !valid_oid(revision) {
            return Err(AdmissionError::Revision);
        }
        if self.signature.len() > 16 * 1024 || self.payload.len() > MAX_COMMIT_BYTES {
            return Err(AdmissionError::Object);
        }
        let (signature, _) = DetachedSignature::from_string(&self.signature)
            .map_err(|_| AdmissionError::Signature)?;
        let (public, _) =
            SignedPublicKey::from_string(&key.public_key).map_err(|_| AdmissionError::Signature)?;
        let verified = (key
            .fingerprints
            .contains(&hex::encode(public.primary_key.fingerprint().as_bytes()))
            && signature
                .verify(&public.primary_key, self.payload.as_bytes())
                .is_ok())
            || public.public_subkeys.iter().any(|subkey| {
                key.fingerprints
                    .contains(&hex::encode(subkey.key.fingerprint().as_bytes()))
                    && signature
                        .verify(&subkey.key, self.payload.as_bytes())
                        .is_ok()
            });
        if !verified {
            return Err(AdmissionError::Signature);
        }
        // Git stores the detached signature as a folded header before the separator.
        let split = self.payload.find("\n\n").ok_or(AdmissionError::Object)? + 1;
        let signed = format!(
            "{}gpgsig {}\n{}",
            &self.payload[..split],
            self.signature.trim_end_matches('\n').replace('\n', "\n "),
            &self.payload[split..]
        );
        if git_oid("commit", signed.as_bytes())? != revision {
            return Err(AdmissionError::Revision);
        }
        self.root_tree()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TreeEntry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}
#[derive(Deserialize)]
struct TreeResponse {
    sha: String,
    tree: Vec<TreeEntry>,
    truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AdmissionProof {
    commit: SignedCommit,
    tree: Vec<TreeEntry>,
}
impl AdmissionProof {
    pub(crate) fn from_tree_response(
        commit: SignedCommit,
        response: &[u8],
    ) -> Result<Self, AdmissionError> {
        if response.len() > MAX_PROOF_BYTES {
            return Err(AdmissionError::Object);
        }
        let tree: TreeResponse = serde_json::from_slice(response)?;
        if tree.truncated || tree.sha != commit.root_tree()? {
            return Err(AdmissionError::Object);
        }
        let proof = Self {
            commit,
            tree: tree.tree,
        };
        proof.manifest_blob()?;
        Ok(proof)
    }
    pub(crate) fn verify(
        &self,
        revision: &str,
        index: &[u8],
        key: &CatalogKey,
    ) -> Result<(), AdmissionError> {
        if index.len() > crate::manifest::MAX_INDEX_BYTES {
            return Err(AdmissionError::Object);
        }
        self.commit.verify(revision, key)?;
        if git_oid("blob", index)? != self.manifest_blob()? {
            return Err(AdmissionError::Object);
        }
        Ok(())
    }
    fn manifest_blob(&self) -> Result<&str, AdmissionError> {
        if self.tree.len() > 1024 {
            return Err(AdmissionError::Object);
        }
        let mut names = HashSet::new();
        let mut entries = Vec::new();
        let mut manifest = None;
        for entry in &self.tree {
            if entry.path.is_empty()
                || entry.path.len() > 255
                || entry.path == "."
                || entry.path == ".."
                || entry.path.bytes().any(|byte| byte == 0 || byte == b'/')
                || !valid_oid(&entry.sha)
                || !names.insert(&entry.path)
            {
                return Err(AdmissionError::Object);
            }
            let mode = match (entry.mode.as_str(), entry.kind.as_str()) {
                ("040000", "tree") => "40000",
                ("100644", "blob") => "100644",
                ("100755", "blob") => "100755",
                ("120000", "blob") => "120000",
                ("160000", "commit") => "160000",
                _ => return Err(AdmissionError::Object),
            };
            if entry.path == "firmware.json" {
                if mode != "100644" {
                    return Err(AdmissionError::Object);
                }
                manifest = Some(entry.sha.as_str());
            }
            let mut sort_key = entry.path.as_bytes().to_vec();
            if entry.kind == "tree" {
                sort_key.push(b'/');
            }
            entries.push((sort_key, mode, entry));
        }
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let mut bytes = Vec::new();
        for (_, mode, entry) in entries {
            bytes.extend_from_slice(mode.as_bytes());
            bytes.push(b' ');
            bytes.extend_from_slice(entry.path.as_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&hex::decode(&entry.sha).map_err(|_| AdmissionError::Object)?);
        }
        if git_oid("tree", &bytes)? != self.commit.root_tree()? {
            return Err(AdmissionError::Object);
        }
        manifest.ok_or(AdmissionError::Object)
    }
}

fn valid_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn git_oid(kind: &str, bytes: &[u8]) -> Result<String, AdmissionError> {
    let mut hash = Sha1::new();
    hash.update(format!("{kind} {}\0", bytes.len()).as_bytes());
    hash.update(bytes);
    let result = hash.try_finalize();
    if result.has_collision() {
        return Err(AdmissionError::Object);
    }
    Ok(hex::encode(result.hash()))
}

#[cfg(test)]
fn verify_commit(revision: &str, response: &[u8]) -> Result<(), AdmissionError> {
    SignedCommit::from_response(revision, response, &CatalogKey::maintainer()).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    const REVISION: &str = "9e23e8fba1d3597953d7d44072092f8ac5a4d373";
    const VERIFIED: &[u8] = include_bytes!("../tests/fixtures/verified-commit.json");

    #[test]
    fn accepts_existing_archive_commit_signed_by_pinned_key() {
        verify_commit(REVISION, VERIFIED).unwrap();
    }

    #[test]
    fn accepts_only_explicitly_allowed_signing_keys_during_rotation() {
        let mut key = CatalogKey::maintainer();
        key.fingerprints
            .insert(0, "ef8586ebfb8cbf8c8f53651e0de33d9681fafad9".into());
        SignedCommit::from_response(REVISION, VERIFIED, &key).unwrap();
        // Trusting a primary key must not implicitly trust every signing subkey.
        key.fingerprints.pop();
        assert!(SignedCommit::from_response(REVISION, VERIFIED, &key).is_err());
    }

    #[test]
    fn rejects_wrong_revision_verdict_payload_and_signature() {
        assert!(verify_commit("different", VERIFIED).is_err());
        for (field, value) in [
            ("verified", serde_json::json!(false)),
            ("reason", serde_json::json!("invalid")),
            ("payload", serde_json::json!("altered signed payload")),
            ("signature", serde_json::Value::Null),
            ("signature", serde_json::json!("malformed signature")),
        ] {
            let mut invalid: serde_json::Value = serde_json::from_slice(VERIFIED).unwrap();
            invalid["verification"][field] = value;
            assert!(
                verify_commit(REVISION, &serde_json::to_vec(&invalid).unwrap()).is_err(),
                "accepted altered {field}"
            );
        }
    }

    #[test]
    fn rejects_valid_signature_from_foreign_key() {
        const FOREIGN_KEY: &str = include_str!("../tests/fixtures/foreign-key.asc");
        const FOREIGN_SIGNATURE: &str = include_str!("../tests/fixtures/foreign-signature.asc");
        // Keep signed binary data independent of Git checkout line endings.
        const FOREIGN_PAYLOAD: &str =
            "Foreign signer regression payload for Gulikit archive admission.\n";

        let (signature, _) = DetachedSignature::from_string(FOREIGN_SIGNATURE).unwrap();
        let (key, _) = SignedPublicKey::from_string(FOREIGN_KEY).unwrap();
        signature
            .verify(&key.primary_key, FOREIGN_PAYLOAD.as_bytes())
            .unwrap();

        let response = serde_json::json!({
            "sha": REVISION,
            "verification": {
                "verified": true,
                "reason": "valid",
                "signature": FOREIGN_SIGNATURE,
                "payload": FOREIGN_PAYLOAD,
            }
        });
        assert!(
            verify_commit(REVISION, &serde_json::to_vec(&response).unwrap()).is_err(),
            "GitHub's generic valid verdict must not admit a different signer"
        );
    }
    fn catalog_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/signed-test-catalog.json")).unwrap()
    }

    #[test]
    fn cached_proof_authenticates_exact_git_objects_without_network() {
        let fixture = catalog_fixture();
        let revision = fixture["revision"].as_str().unwrap();
        let index = fixture["index"].as_str().unwrap().as_bytes();
        let key = CatalogKey::fixture();
        let commit = SignedCommit::from_response(
            revision,
            &serde_json::to_vec(&fixture["commit"]).unwrap(),
            &key,
        )
        .unwrap();
        let proof = AdmissionProof::from_tree_response(
            commit,
            &serde_json::to_vec(&fixture["tree"]).unwrap(),
        )
        .unwrap();
        let invented_revision = "0123456789abcdef0123456789abcdef01234567";
        let mut false_commit = fixture["commit"].clone();
        false_commit["sha"] = serde_json::json!(invented_revision);
        assert!(
            SignedCommit::from_response(
                invented_revision,
                &serde_json::to_vec(&false_commit).unwrap(),
                &key
            )
            .is_err(),
            "a valid signature must not authenticate an invented commit object ID"
        );
        let cached: AdmissionProof =
            serde_json::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap();
        cached.verify(revision, index, &key).unwrap();
        assert!(
            cached
                .verify(revision, index, &CatalogKey::maintainer())
                .is_err(),
            "test catalog must never pass the production trust root"
        );
        let changed = [index, b" "].concat();
        assert!(cached.verify(revision, &changed, &key).is_err());
        assert!(
            cached
                .verify("0123456789abcdef0123456789abcdef01234567", index, &key)
                .is_err()
        );
        for path in ["sha", "payload", "signature"] {
            let mut changed = serde_json::to_value(&cached).unwrap();
            changed["commit"][path] = serde_json::json!("changed");
            let changed: AdmissionProof = serde_json::from_value(changed).unwrap();
            assert!(
                changed.verify(revision, index, &key).is_err(),
                "accepted changed commit {path}"
            );
        }
    }

    #[test]
    fn root_tree_proof_rejects_tampering_truncation_and_duplicate_names() {
        let fixture = catalog_fixture();
        let revision = fixture["revision"].as_str().unwrap();
        let key = CatalogKey::fixture();
        let commit = SignedCommit::from_response(
            revision,
            &serde_json::to_vec(&fixture["commit"]).unwrap(),
            &key,
        )
        .unwrap();
        let mut reordered = fixture["tree"].clone();
        reordered["tree"].as_array_mut().unwrap().reverse();
        AdmissionProof::from_tree_response(
            commit.clone(),
            &serde_json::to_vec(&reordered).unwrap(),
        )
        .unwrap();
        for field in ["path", "mode", "type", "sha"] {
            let mut changed = fixture["tree"].clone();
            changed["tree"][0][field] = serde_json::json!("changed");
            assert!(
                AdmissionProof::from_tree_response(
                    commit.clone(),
                    &serde_json::to_vec(&changed).unwrap()
                )
                .is_err(),
                "accepted changed tree {field}"
            );
        }
        let mut false_blob = fixture["tree"].clone();
        false_blob["tree"][0]["sha"] =
            serde_json::json!("0123456789abcdef0123456789abcdef01234567");
        assert!(
            AdmissionProof::from_tree_response(
                commit.clone(),
                &serde_json::to_vec(&false_blob).unwrap()
            )
            .is_err(),
            "a different well-formed blob ID must break the signed tree proof"
        );
        let mut duplicate = fixture["tree"].clone();
        let entry = duplicate["tree"][0].clone();
        duplicate["tree"].as_array_mut().unwrap().push(entry);
        assert!(
            AdmissionProof::from_tree_response(
                commit.clone(),
                &serde_json::to_vec(&duplicate).unwrap()
            )
            .is_err()
        );
        let mut truncated = fixture["tree"].clone();
        truncated["truncated"] = serde_json::json!(true);
        assert!(
            AdmissionProof::from_tree_response(commit, &serde_json::to_vec(&truncated).unwrap())
                .is_err()
        );
    }
}
