//! Signature verification and freshness policy for catalog envelopes.
//!
//! Trust roots come only from the caller's explicit [`TrustedKeys`]. An envelope
//! cannot add, replace, or rotate keys. A [`VerifiedCatalog`] means its exact
//! payload bytes verified under one of those pinned keys and its catalog schema
//! parsed successfully. Its timestamps are claims until checked with
//! [`VerifiedCatalog::require_fresh_at`]; verification alone does not prove
//! freshness, authorize firmware installation, or construct a `VerifiedPackage`.

use crate::{Catalog, CatalogError};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
pub const MAX_SIGNED_PAYLOAD_BYTES: usize = crate::MAX_CATALOG_BYTES + 4 * 1024;
pub const MAX_TRUSTED_KEYS: usize = 32;
const MAX_KEY_ID_LENGTH: usize = 64;
const SIGNATURE_DOMAIN: &[u8] = b"gulikit-catalog-v1\0";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    schema_version: u32,
    key_id: String,
    payload: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPayload {
    revision: u64,
    issued_at: u64,
    expires_at: u64,
    catalog: Box<RawValue>,
}

/// Public verification keys supplied by the application as an explicit trust root.
#[derive(Clone, Debug)]
pub struct TrustedKeys {
    keys: BTreeMap<String, VerifyingKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCatalog {
    catalog: Catalog,
    payload_bytes: Vec<u8>,
    revision: u64,
    issued_at: u64,
    expires_at: u64,
    key_id: String,
    envelope_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FreshnessError {
    #[error("catalog is not valid until its issued-at time")]
    NotYetValid,
    #[error("catalog has expired")]
    Expired,
    #[error("catalog revision is below the caller's minimum")]
    StaleRevision,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("catalog envelope exceeds the {MAX_ENVELOPE_BYTES}-byte limit")]
    EnvelopeTooLarge,
    #[error("signed payload exceeds the {MAX_SIGNED_PAYLOAD_BYTES}-byte limit")]
    PayloadTooLarge,
    #[error("invalid envelope JSON: {0}")]
    EnvelopeJson(String),
    #[error("unsupported envelope schema version {0}")]
    UnknownEnvelopeSchema(u32),
    #[error("invalid trusted key identifier")]
    InvalidKeyId,
    #[error("trusted key set is empty")]
    EmptyKeySet,
    #[error("trusted key set exceeds {MAX_TRUSTED_KEYS} keys")]
    TooManyKeys,
    #[error("duplicate trusted key identifier: {0}")]
    DuplicateKeyId(String),
    #[error("trusted public key is malformed or weak")]
    InvalidPublicKey,
    #[error("envelope references an unknown pinned key: {0}")]
    UnknownKey(String),
    #[error("signature must be exactly 128 lowercase hexadecimal characters")]
    InvalidSignatureEncoding,
    #[error("catalog envelope signature verification failed")]
    InvalidSignature,
    #[error("invalid signed payload JSON: {0}")]
    PayloadJson(String),
    #[error("payload expiry must be later than its issued-at time")]
    InvalidTimeRange,
    #[error(transparent)]
    Catalog(#[from] CatalogError),
}

impl TrustedKeys {
    /// Build a pinned key set from caller-owned key IDs and raw Ed25519 public keys.
    ///
    /// Key identifiers are never read from trusted key material; the caller
    /// decides which key IDs and public keys are trusted. Envelopes cannot modify
    /// this set.
    ///
    /// # Errors
    /// Rejects an empty or oversized key set, invalid or duplicate IDs, malformed
    /// public keys, and weak Ed25519 public keys.
    pub fn new<I>(keys: I) -> Result<Self, AuthError>
    where
        I: IntoIterator<Item = (String, [u8; 32])>,
    {
        let mut trusted = BTreeMap::new();
        for (key_id, bytes) in keys {
            if !valid_key_id(&key_id) {
                return Err(AuthError::InvalidKeyId);
            }
            if trusted.contains_key(&key_id) {
                return Err(AuthError::DuplicateKeyId(key_id));
            }
            if trusted.len() >= MAX_TRUSTED_KEYS {
                return Err(AuthError::TooManyKeys);
            }
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| AuthError::InvalidPublicKey)?;
            if key.is_weak() {
                return Err(AuthError::InvalidPublicKey);
            }
            trusted.insert(key_id, key);
        }
        if trusted.is_empty() {
            return Err(AuthError::EmptyKeySet);
        }
        Ok(Self { keys: trusted })
    }

    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Authenticate and parse a bounded envelope using only caller-pinned keys.
///
/// The signature is checked over the domain separator followed by the exact
/// UTF-8 bytes in the envelope's payload string. Only after signature success
/// does this function parse payload timestamps and catalog metadata. Successful
/// verification does not perform a freshness decision.
///
/// # Errors
/// Rejects oversized input, malformed or unknown schemas, duplicate/unknown
/// fields, unknown keys, invalid signatures, invalid time ranges, and invalid
/// catalog metadata.
pub fn verify_envelope(
    bytes: &[u8],
    trusted_keys: &TrustedKeys,
) -> Result<VerifiedCatalog, AuthError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(AuthError::EnvelopeTooLarge);
    }
    let envelope: RawEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| AuthError::EnvelopeJson(error.to_string()))?;
    if envelope.schema_version != 1 {
        return Err(AuthError::UnknownEnvelopeSchema(envelope.schema_version));
    }
    if !valid_key_id(&envelope.key_id) {
        return Err(AuthError::InvalidKeyId);
    }
    if envelope.payload.len() > MAX_SIGNED_PAYLOAD_BYTES {
        return Err(AuthError::PayloadTooLarge);
    }
    let key = trusted_keys
        .keys
        .get(&envelope.key_id)
        .ok_or_else(|| AuthError::UnknownKey(envelope.key_id.clone()))?;
    let signature_bytes = decode_signature(&envelope.signature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| AuthError::InvalidSignatureEncoding)?;
    let message = signed_message(envelope.payload.as_bytes());
    key.verify_strict(&message, &signature)
        .map_err(|_| AuthError::InvalidSignature)?;

    let payload: RawPayload = serde_json::from_str(&envelope.payload)
        .map_err(|error| AuthError::PayloadJson(error.to_string()))?;
    if payload.expires_at <= payload.issued_at {
        return Err(AuthError::InvalidTimeRange);
    }
    let catalog = Catalog::parse(payload.catalog.get().as_bytes())?;
    Ok(VerifiedCatalog {
        catalog,
        payload_bytes: envelope.payload.into_bytes(),
        revision: payload.revision,
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        key_id: envelope.key_id,
        envelope_bytes: bytes.to_vec(),
    })
}

impl VerifiedCatalog {
    #[must_use]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Exact authenticated payload bytes, suitable for revision equivocation checks.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Exact source envelope bytes, retained for offline inspection and provenance.
    #[must_use]
    pub fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    /// Apply caller-supplied wall-clock and rollback policy to signed timestamps.
    ///
    /// Authentication is separate: an expired but correctly signed catalog can
    /// still be represented for offline inspection, but it fails this check.
    /// Passing this freshness check alone is not firmware installation authority.
    ///
    /// # Errors
    /// Returns whether the catalog is not yet valid, expired, or below the
    /// caller's minimum acceptable revision.
    pub fn require_fresh_at(&self, now: u64, minimum_revision: u64) -> Result<(), FreshnessError> {
        if now < self.issued_at {
            return Err(FreshnessError::NotYetValid);
        }
        if now >= self.expires_at {
            return Err(FreshnessError::Expired);
        }
        if self.revision < minimum_revision {
            return Err(FreshnessError::StaleRevision);
        }
        Ok(())
    }
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_ID_LENGTH
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn decode_signature(value: &str) -> Result<Vec<u8>, AuthError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AuthError::InvalidSignatureEncoding);
    }
    hex::decode(value).map_err(|_| AuthError::InvalidSignatureEncoding)
}

fn signed_message(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + payload.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(payload);
    message
}
