use crate::result::Result;
use rand::rng;
use serde_json::{Value, json};
use syft_crypto_protocol::{
    SyftRecoveryKey,
    did_utils::generate_did_web_id_default,
    envelope::has_syc_magic,
    serialization::{serialize_private_keys, serialize_to_did_document},
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use syft_crypto_protocol::datasite::crypto::parse_public_bundle;

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
