use crate::result::Result;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

use syft_crypto_protocol::PublicKeyBundle;

// Temporary stub to ensure protocol dependency is linked
pub(crate) fn ensure_protocol_dependency() {
    let _ = core::mem::size_of::<PublicKeyBundle>();
}

/// Output of the stubbed identity generation flow.
pub(crate) struct GeneratedIdentity {
    pub(crate) key_file: Vec<u8>,
    pub(crate) public_bundle: Value,
}

/// Result of decrypting ciphertext bytes via the stubbed protocol.
pub(crate) struct DecryptionResult {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) envelope: CipherEnvelope,
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
    pub(crate) fn is_stubbed(self) -> bool {
        matches!(self, CipherEnvelope::Wrapped)
    }
}

pub(crate) fn generate_identity_material(identity: &str) -> Result<GeneratedIdentity> {
    // TODO: Replace stub with libsignal identity + pre-key derivation.
    let key_doc = json!({
        "identity": identity,
        "note": "Placeholder key material – replace with real libsignal export",
    });
    let mut key_file = serde_json::to_vec_pretty(&key_doc)?;
    key_file.push(b'\n');

    let public_bundle = json!({
        "identity": identity,
        "stub": true,
        "note": "Placeholder bundle – replace once libsignal export is wired",
        "keys": {
            "identity": "placeholder",
            "signed_prekey": "placeholder",
            "pq_prekey": "placeholder",
        }
    });

    Ok(GeneratedIdentity {
        key_file,
        public_bundle,
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

pub(crate) fn encrypt_bytes(
    _sender: &str,
    _recipient: Option<&str>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    // TODO: Replace with libsignal sealing (PQXDH + payload encryption).
    Ok(plaintext.to_vec())
}

pub(crate) fn decrypt_bytes(
    _identity: &str,
    ciphertext: &[u8],
    skip_checks: bool,
) -> Result<DecryptionResult> {
    // TODO: Replace with libsignal decryption + signature verification.
    let plaintext = ciphertext.to_vec();
    let envelope = CipherEnvelope::Wrapped;
    let _ = skip_checks; // placeholder until real validation is wired
    Ok(DecryptionResult {
        plaintext,
        envelope,
    })
}

pub(crate) fn decrypt_allow_plaintext(
    _identity: &str,
    ciphertext: &[u8],
) -> Result<DecryptionResult> {
    // TODO: Replace with libsignal decryption + signature verification.
    Ok(DecryptionResult {
        plaintext: ciphertext.to_vec(),
        envelope: CipherEnvelope::Plaintext,
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

pub use crate::envelope::{
    CURRENT_VERSION, MAGIC, build_stub_envelope, has_syc_magic, parse_envelope,
    verify_stub_signature,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_ciphertext_marks_plaintext() {
        let inspection = inspect_ciphertext(b"no envelope");
        assert_eq!(inspection.envelope, CipherEnvelope::Plaintext);
        assert_eq!(inspection.length, 11);
    }
}
