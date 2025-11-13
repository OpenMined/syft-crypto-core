use crate::result::Result;
use rand::rng;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use urlencoding::decode;

use syft_crypto_protocol::{
    SyftPrivateKeys, SyftPublicKeyBundle, SyftRecoveryKey, decrypt_message,
    did_utils::generate_did_web_id_default,
    encrypt_message,
    encryption::EncryptionRecipient,
    envelope::{ParsedEnvelope, has_syc_magic},
    serialization::{
        deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
        serialize_to_did_document,
    },
};

// Helper to ensure `syft-crypto-protocol` stays linked even when no symbols are referenced.
pub(crate) fn ensure_protocol_dependency() {
    let _ = core::mem::size_of::<SyftPublicKeyBundle>();
}

/// Output of the identity generation flow.
pub(crate) struct GeneratedIdentity {
    pub(crate) fingerprint: String,
    pub(crate) did: String,
    pub(crate) recovery_key_hex: String,
    pub(crate) recovery_key_mnemonic: String,
    pub(crate) key_file: Vec<u8>,
    pub(crate) public_bundle: Value,
}

/// Information extracted during ciphertext inspection.
pub(crate) struct CipherInspection {
    pub(crate) envelope: CipherEnvelope,
    pub(crate) length: usize,
}

/// Indicates whether bytes were wrapped using an SYC envelope or left as plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherEnvelope {
    Wrapped,
    Plaintext,
}

impl CipherEnvelope {
    pub(crate) fn is_wrapped(self) -> bool {
        matches!(self, CipherEnvelope::Wrapped)
    }
}

pub(crate) fn generate_identity_material(identity: &str) -> Result<GeneratedIdentity> {
    let recovery_key = SyftRecoveryKey::generate();
    let recovery_key_hex = recovery_key.to_hex_string();
    let recovery_key_mnemonic = recovery_key.to_mnemonic();

    let private_keys = recovery_key.derive_keys()?;
    let jwks = serialize_private_keys(&private_keys)?;

    // Build public bundle + DID document
    let mut rng = rng();
    let public_bundle = private_keys.to_public_bundle(&mut rng)?;
    let fingerprint = public_bundle.identity_fingerprint();
    let did = generate_did_web_id_default(identity);
    let mut did_document = serialize_to_did_document(&public_bundle, &did)?;
    if let Some(map) = did_document.as_object_mut() {
        map.insert("identity".into(), Value::String(identity.to_string()));
        map.insert(
            "identity_fingerprint".into(),
            Value::String(fingerprint.clone()),
        );
    }

    // Private key file with identity metadata + JWKS
    let key_doc = json!({
        "format": "syft-private-keys-v1",
        "identity": identity,
        "identity_fingerprint": fingerprint,
        "did": did,
        "private_keys": jwks,
    });
    let mut key_file = serde_json::to_vec_pretty(&key_doc)?;
    key_file.push(b'\n');

    Ok(GeneratedIdentity {
        fingerprint,
        did,
        recovery_key_hex,
        recovery_key_mnemonic,
        key_file,
        public_bundle: did_document,
    })
}

pub(crate) fn load_identity_label(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path)?;
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&contents)
        && let Some(identity) = map.get("identity").and_then(|v| v.as_str())
    {
        return Ok(identity.to_string());
    }
    Err(format!("unable to parse identity from {}", path.display()).into())
}

pub(crate) fn inspect_ciphertext(ciphertext: &[u8]) -> CipherInspection {
    let envelope = if has_syc_magic(ciphertext) {
        CipherEnvelope::Wrapped
    } else {
        CipherEnvelope::Plaintext
    };

    CipherInspection {
        envelope,
        length: ciphertext.len(),
    }
}

/// Parsed representation of a cached public bundle.
pub(crate) struct PublicBundleInfo {
    pub(crate) identity: String,
    pub(crate) fingerprint: String,
    pub(crate) did: Option<String>,
    pub(crate) bundle: SyftPublicKeyBundle,
    pub(crate) value: Value,
}

pub(crate) fn parse_public_bundle(body: &str) -> Result<PublicBundleInfo> {
    let value: Value = serde_json::from_str(body)?;
    let bundle =
        deserialize_from_did_document(&value).map_err(|e| format!("invalid DID document: {e}"))?;
    let fingerprint = bundle.identity_fingerprint();
    let identity = extract_identity(&value).ok_or("bundle missing identity metadata or DID id")?;
    let did = value
        .get("id")
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    Ok(PublicBundleInfo {
        identity,
        fingerprint,
        did,
        bundle,
        value,
    })
}

fn extract_identity(value: &Value) -> Option<String> {
    if let Some(identity) = value.get("identity").and_then(Value::as_str) {
        return Some(identity.to_string());
    }
    value
        .get("id")
        .and_then(Value::as_str)
        .and_then(identity_from_did_id)
}

fn identity_from_did_id(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    let mut segments = rest.split(':');
    segments.next()?; // domain component
    let encoded = segments.next_back()?;
    decode(encoded).ok().map(|cow| cow.into_owned())
}

pub(crate) fn load_private_keys_from_file(path: &Path) -> Result<SyftPrivateKeys> {
    let body = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&body)?;
    let jwks = value
        .get("private_keys")
        .ok_or("key file missing private_keys section")?;
    deserialize_private_keys(jwks).map_err(|e| format!("failed to parse private keys: {e}").into())
}

pub(crate) fn encrypt_envelope_for_recipient(
    sender_identity: &str,
    sender_keys: &SyftPrivateKeys,
    recipient_identity: &str,
    recipient_bundle: &SyftPublicKeyBundle,
    plaintext: &[u8],
    filename_hint: Option<&str>,
) -> Result<Vec<u8>> {
    encrypt_message(
        sender_identity,
        sender_keys,
        &[EncryptionRecipient {
            identity: recipient_identity,
            bundle: recipient_bundle,
        }],
        plaintext,
        filename_hint,
        &mut rng(),
    )
    .map_err(|e| e.into())
}

pub(crate) fn decrypt_envelope_for_recipient(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    parsed: &ParsedEnvelope,
) -> Result<Vec<u8>> {
    decrypt_message(recipient_identity, recipient_keys, sender_bundle, parsed).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_ciphertext_marks_plaintext() {
        let inspection = inspect_ciphertext(b"no envelope");
        assert_eq!(inspection.envelope, CipherEnvelope::Plaintext);
        assert_eq!(inspection.length, 11);
    }

    #[test]
    fn parse_public_bundle_extracts_identity_and_fingerprint() {
        let generated = generate_identity_material("alice@example.org").unwrap();
        let body = serde_json::to_string(&generated.public_bundle).unwrap();
        let parsed = parse_public_bundle(&body).unwrap();
        assert_eq!(parsed.identity, "alice@example.org");
        assert_eq!(parsed.fingerprint.len(), 64);
        assert!(
            parsed
                .did
                .as_deref()
                .unwrap_or_default()
                .starts_with("did:web:")
        );
    }
}
