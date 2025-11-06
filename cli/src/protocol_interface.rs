use crate::result::Result;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

use syft_crypto_protocol::PublicKeyBundle;

const STUB_KEY_PREFIX: &str = "SYC-STUB-KEY";
const STUB_ENVELOPE_HEADER: &[u8] = b"SYC-STUB-CIPHERTEXT\n";

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

/// Indicates whether bytes were wrapped using the stub envelope or left as plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherEnvelope {
    Stubbed,
    Plaintext,
}

impl CipherEnvelope {
    pub(crate) fn is_stubbed(self) -> bool {
        matches!(self, CipherEnvelope::Stubbed)
    }
}

pub(crate) fn generate_identity_material(identity: &str) -> Result<GeneratedIdentity> {
    // TODO: Replace stub with libsignal identity + pre-key derivation.
    let key_file = format!("{STUB_KEY_PREFIX}:{identity}\n").into_bytes();

    let public_bundle = json!({
        "identity": identity,
        "stub": true,
        "note": "Placeholder bundle – replace once libsignal export is wired",
        "keys": {
            "identity": format!("{STUB_KEY_PREFIX}/identity"),
            "signed_prekey": format!("{STUB_KEY_PREFIX}/signed_prekey"),
            "pq_prekey": format!("{STUB_KEY_PREFIX}/pq_prekey"),
        }
    });

    Ok(GeneratedIdentity {
        key_file,
        public_bundle,
    })
}

pub(crate) fn load_identity_label(path: &Path) -> Result<String> {
    // TODO: Parse actual key material format once wired.
    let contents = fs::read_to_string(path)?;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{STUB_KEY_PREFIX}:")) {
            return Ok(rest.trim().to_string());
        }
    }
    Err(format!("unable to parse identity from {}", path.display()).into())
}

pub(crate) fn encrypt_bytes(
    _sender: &str,
    _recipient: Option<&str>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    // TODO: Replace with libsignal sealing (PQXDH + payload encryption).
    let mut ciphertext = STUB_ENVELOPE_HEADER.to_vec();
    ciphertext.extend_from_slice(plaintext);
    Ok(ciphertext)
}

pub(crate) fn decrypt_bytes(
    _identity: &str,
    ciphertext: &[u8],
    skip_checks: bool,
) -> Result<DecryptionResult> {
    // TODO: Replace with libsignal decryption + signature verification.
    if ciphertext.starts_with(STUB_ENVELOPE_HEADER) {
        let plaintext = ciphertext[STUB_ENVELOPE_HEADER.len()..].to_vec();
        Ok(DecryptionResult {
            plaintext,
            envelope: CipherEnvelope::Stubbed,
        })
    } else if skip_checks {
        Ok(DecryptionResult {
            plaintext: ciphertext.to_vec(),
            envelope: CipherEnvelope::Plaintext,
        })
    } else {
        Err("ciphertext does not contain expected stub envelope".into())
    }
}

pub(crate) fn decrypt_allow_plaintext(
    _identity: &str,
    ciphertext: &[u8],
) -> Result<DecryptionResult> {
    // TODO: Replace with libsignal decryption + signature verification.
    if ciphertext.starts_with(STUB_ENVELOPE_HEADER) {
        Ok(DecryptionResult {
            plaintext: ciphertext[STUB_ENVELOPE_HEADER.len()..].to_vec(),
            envelope: CipherEnvelope::Stubbed,
        })
    } else {
        Ok(DecryptionResult {
            plaintext: ciphertext.to_vec(),
            envelope: CipherEnvelope::Plaintext,
        })
    }
}

pub(crate) fn inspect_ciphertext(ciphertext: &[u8]) -> CipherInspection {
    // TODO: Extract envelope metadata once protocol integration lands.
    let envelope = if ciphertext.starts_with(STUB_ENVELOPE_HEADER) {
        CipherEnvelope::Stubbed
    } else {
        CipherEnvelope::Plaintext
    };

    CipherInspection {
        envelope,
        length: ciphertext.len(),
    }
}
