//! Authenticate catalog Git commits against the existing archive signing key.
//!
//! GitHub's fixed HTTPS endpoint binds the response to the requested revision;
//! local `OpenPGP` verification binds its signed payload to the embedded public key.
//! Manufacturer firmware files and their original signatures remain unchanged.

use pgp::{
    composed::{Deserializable, DetachedSignature, SignedPublicKey},
    types::KeyDetails,
};
use serde::Deserialize;
use thiserror::Error;

const MAINTAINER_FINGERPRINT: &str = "53e071b497f9f6ef73f6c356d7415e8b2e80d893";
const PUBLIC_KEY: &str = include_str!("keys/maintainer.asc");

#[derive(Debug, Error)]
pub enum AdmissionError {
    #[error("invalid commit-verification response: {0}")]
    Response(#[from] serde_json::Error),
    #[error("commit-verification response identifies a different revision")]
    Revision,
    #[error("GitHub did not verify the archive commit signature")]
    Unverified,
    #[error("archive commit signature does not verify against the trusted archive key")]
    Signature,
}

#[derive(Deserialize)]
struct Commit {
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

pub(crate) fn verify_commit(revision: &str, response: &[u8]) -> Result<(), AdmissionError> {
    let commit: Commit = serde_json::from_slice(response)?;
    if commit.sha != revision {
        return Err(AdmissionError::Revision);
    }
    if !commit.verification.verified || commit.verification.reason != "valid" {
        return Err(AdmissionError::Unverified);
    }
    let signature = commit
        .verification
        .signature
        .ok_or(AdmissionError::Signature)?;
    let payload = commit
        .verification
        .payload
        .ok_or(AdmissionError::Signature)?;
    let (signature, _) =
        DetachedSignature::from_string(&signature).map_err(|_| AdmissionError::Signature)?;
    let (key, _) =
        SignedPublicKey::from_string(PUBLIC_KEY).map_err(|_| AdmissionError::Signature)?;
    let signing_key = key
        .public_subkeys
        .iter()
        .find(|subkey| hex::encode(subkey.key.fingerprint().as_bytes()) == MAINTAINER_FINGERPRINT)
        .ok_or(AdmissionError::Signature)?;
    signature
        .verify(&signing_key.key, payload.as_bytes())
        .map_err(|_| AdmissionError::Signature)
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
}
