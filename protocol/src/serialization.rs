//! Serialization for cryptographic keys
//!
//! This module handles serialization and deserialization of keys in two formats:
//! - **DID Document**: W3C-compliant JSON format for public keys (published to network)
//! - **JWKS**: JSON Web Key Set format for private keys (stored locally)
//!
//! # DID Document Format
//! Public keys are serialized according to W3C DID specification with JWK encoding:
//! - Identity key in `verificationMethod` (Ed25519)
//! - Encryption keys in `keyAgreement` (X25519, Kyber1024)
//! - Base64url encoding (RFC 7515, no padding)
//!
//! # JWKS Format
//! Private keys are stored in a flat JSON structure:
//! - `identity_key`: Ed25519 keypair
//! - `signed_prekey`: X25519 keypair with signature
//! - `pq_prekey`: Kyber1024 keypair with signature

use crate::error::{SerializationError, SerializationResult};
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PublicKey, kem};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

/// Serialize public key bundle to W3C DID document format.
///
/// Creates a DID document with:
/// - `@context`: W3C DID and security suite contexts
/// - `verificationMethod`: Identity key (Ed25519) for signing
/// - `keyAgreement`: Encryption keys (X25519, Kyber1024)
///
/// # Arguments
/// * `bundle` - Public key bundle to serialize
/// * `did_id` - DID identifier (e.g., "did:web:syftbox.net:alice%40example.com")
///
/// # Example
/// ```
/// use syft_crypto_protocol::SyftRecoveryKey;
/// use syft_crypto_protocol::serialization::serialize_to_did_document;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();
/// let did_doc = serialize_to_did_document(&bundle, "did:web:example.com:alice").unwrap();
/// ```
pub fn serialize_to_did_document(
    bundle: &SyftPublicKeyBundle,
    did_id: &str,
) -> SerializationResult<Value> {
    let controller = did_id;

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
        ],
        "id": did_id,
        "verificationMethod": [{
            "id": format!("{}#identity-key", did_id),
            "type": "Ed25519VerificationKey2020",
            "controller": controller,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(bundle.signal_identity_public_key.serialize()),
                "kid": "identity-key",
                "use": "sig"
            }
        }],
        "keyAgreement": [
            {
                "id": format!("{}#signed-prekey", did_id),
                "type": "X25519KeyAgreementKey2020",
                "controller": controller,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": URL_SAFE_NO_PAD.encode(bundle.signal_signed_public_pre_key.serialize()),
                    "kid": "signed-prekey",
                    "use": "enc",
                    "signature": URL_SAFE_NO_PAD.encode(&bundle.signal_signed_pre_key_signature)
                }
            },
            {
                "id": format!("{}#pq-prekey", did_id),
                "type": "JsonWebKey2020",  //
                "controller": controller,
                "publicKeyJwk": {
                    "kty": "PQ",
                    "crv": "Kyber1024",
                    "x": URL_SAFE_NO_PAD.encode(bundle.signal_pq_public_pre_key.serialize()),
                    "kid": "pq-prekey",
                    "use": "enc",
                    "signature": URL_SAFE_NO_PAD.encode(&bundle.signal_pq_pre_key_signature)
                }
            }
        ]
    }))
}

/// Deserialize public key bundle from DID document.
///
/// Parses a W3C DID document and extracts:
/// - Identity key from `verificationMethod`
/// - Signed prekey from `keyAgreement` (X25519)
/// - PQ prekey from `keyAgreement` (Kyber1024)
///
/// # Arguments
/// * `json` - DID document as JSON value
///
/// # Returns
/// * `Ok(SyftPublicKeyBundle)` if parsing succeeds and signatures are valid
/// * `Err(SerializationError)` if format is invalid or signatures don't verify
pub fn deserialize_from_did_document(json: &Value) -> SerializationResult<SyftPublicKeyBundle> {
    // Helper to decode base64url
    fn decode_base64url(s: &str) -> SerializationResult<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| SerializationError::InvalidBase64(e.to_string()))
    }

    // Extract identity key from verificationMethod
    let verification_methods = json["verificationMethod"]
        .as_array()
        .ok_or(SerializationError::InvalidFormat)?;

    let identity_method = verification_methods
        .iter()
        .find(|m| m["type"] == "Ed25519VerificationKey2020")
        .ok_or(SerializationError::MissingIdentityKey)?;

    let identity_key_bytes = decode_base64url(
        identity_method["publicKeyJwk"]["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;
    let identity_key =
        IdentityKey::decode(&identity_key_bytes).map_err(|_| SerializationError::InvalidFormat)?;

    // Extract encryption keys from keyAgreement
    let key_agreement = json["keyAgreement"]
        .as_array()
        .ok_or(SerializationError::InvalidFormat)?;

    // Find X25519 signed prekey
    let spk_method = key_agreement
        .iter()
        .find(|m| m["type"] == "X25519KeyAgreementKey2020")
        .ok_or(SerializationError::MissingSignedPrekey)?;

    let spk_bytes = decode_base64url(
        spk_method["publicKeyJwk"]["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;
    let spk_signature = decode_base64url(
        spk_method["publicKeyJwk"]["signature"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?
    .into_boxed_slice();

    let signed_pre_key =
        PublicKey::deserialize(&spk_bytes).map_err(|_| SerializationError::InvalidFormat)?;

    // Find Kyber1024 PQ prekey (JsonWebKey2020 with kty="PQ")
    let pqspk_method = key_agreement
        .iter()
        .find(|m| m["type"] == "JsonWebKey2020" && m["publicKeyJwk"]["kty"] == "PQ")
        .ok_or(SerializationError::MissingPQPrekey)?;

    let pqspk_bytes = decode_base64url(
        pqspk_method["publicKeyJwk"]["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;
    let pqspk_signature = decode_base64url(
        pqspk_method["publicKeyJwk"]["signature"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?
    .into_boxed_slice();

    let pq_pre_key =
        kem::PublicKey::deserialize(&pqspk_bytes).map_err(|_| SerializationError::InvalidFormat)?;

    // Create PublicKeyBundle
    let bundle = SyftPublicKeyBundle {
        signal_identity_public_key: identity_key,
        signal_signed_public_pre_key: signed_pre_key,
        signal_signed_pre_key_signature: spk_signature,
        signal_pq_public_pre_key: pq_pre_key,
        signal_pq_pre_key_signature: pqspk_signature,
    };

    // Verify signatures
    if !bundle.verify_signatures() {
        return Err(SerializationError::InvalidSignature);
    }

    Ok(bundle)
}

/// Serialize private keys to JWKS format.
///
/// Creates a flat JSON structure with three keys:
/// - `identity_key`: Ed25519 keypair (public + private)
/// - `signed_prekey`: X25519 keypair with signature
/// - `pq_prekey`: Kyber1024 keypair with signature
///
/// All keys use base64url encoding (RFC 7515, no padding).
///
/// # Example
/// ```
/// use syft_crypto_protocol::SyftRecoveryKey;
/// use syft_crypto_protocol::serialization::serialize_private_keys;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let jwks = serialize_private_keys(&private_keys).unwrap();
/// ```
pub fn serialize_private_keys(keys: &SyftPrivateKeys) -> SerializationResult<Value> {
    Ok(json!({
        "identity_key": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(keys.identity().identity_key().serialize()),
            "d": URL_SAFE_NO_PAD.encode(keys.identity().serialize()),
            "kid": "identity-key",
            "use": "sig"
        },
        "signed_prekey": {
            "kty": "OKP",
            "crv": "X25519",
            "x": URL_SAFE_NO_PAD.encode(keys.signed_pre_key().public_key.serialize()),
            "d": URL_SAFE_NO_PAD.encode(keys.signed_pre_key().private_key.serialize()),
            "kid": "signed-prekey",
            "use": "enc"
        },
        "pq_prekey": {
            "kty": "PQ",
            "crv": "Kyber1024",
            "x": URL_SAFE_NO_PAD.encode(keys.pq_signed_pre_key().public_key.serialize()),
            "d": URL_SAFE_NO_PAD.encode(keys.pq_signed_pre_key().secret_key.serialize()),
            "kid": "pq-prekey",
            "use": "enc"
        }
    }))
}

/// Deserialize private keys from JWKS format.
///
/// Parses a JWKS JSON structure and reconstructs:
/// - Identity keypair (Ed25519)
/// - Signed prekey pair (X25519)
/// - PQ prekey pair (Kyber1024)
///
/// # Arguments
/// * `json` - JWKS document as JSON value
///
/// # Returns
/// * `Ok(SyftPrivateKeys)` if parsing succeeds
/// * `Err(SerializationError)` if format is invalid or keys cannot be reconstructed
pub fn deserialize_private_keys(json: &Value) -> SerializationResult<SyftPrivateKeys> {
    // Helper to decode base64url
    fn decode_base64url(s: &str) -> SerializationResult<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| SerializationError::InvalidBase64(e.to_string()))
    }

    // Extract identity key
    let identity_obj = json
        .get("identity_key")
        .ok_or(SerializationError::MissingIdentityKey)?;

    let identity_private_bytes = Zeroizing::new(decode_base64url(
        identity_obj["d"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?);

    let identity_keypair = IdentityKeyPair::try_from(&identity_private_bytes[..])
        .map_err(|_| SerializationError::InvalidFormat)?;

    // Extract signed prekey
    let spk_obj = json
        .get("signed_prekey")
        .ok_or(SerializationError::MissingSignedPrekey)?;

    let spk_private_bytes = Zeroizing::new(decode_base64url(
        spk_obj["d"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?);

    // Need to get public key bytes from JSON as well
    let spk_public_bytes = decode_base64url(
        spk_obj["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;

    let spk_keypair = KeyPair::from_public_and_private(&spk_public_bytes, &spk_private_bytes)
        .map_err(|_| SerializationError::InvalidFormat)?;

    // Extract PQ prekey
    let pqspk_obj = json
        .get("pq_prekey")
        .ok_or(SerializationError::MissingPQPrekey)?;

    let pqspk_secret_bytes = Zeroizing::new(decode_base64url(
        pqspk_obj["d"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?);

    // Need to get public key bytes from JSON as well
    let pqspk_public_bytes = decode_base64url(
        pqspk_obj["x"]
            .as_str()
            .ok_or(SerializationError::InvalidFormat)?,
    )?;

    let pqspk_keypair =
        kem::KeyPair::from_public_and_private(&pqspk_public_bytes, &pqspk_secret_bytes)
            .map_err(|_| SerializationError::InvalidFormat)?;

    // Reconstruct SyftPrivateKeys
    Ok(SyftPrivateKeys::new(
        identity_keypair,
        spk_keypair,
        pqspk_keypair,
    ))
}

/// Recursively zeroize all string data contained within a JSON value.
pub(crate) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
        Value::String(s) => {
            // String implements Zeroize, which uses volatile writes internally
            s.zeroize();
        }
        Value::Array(items) => {
            for item in items {
                zeroize_json_value(item);
            }
        }
        Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                zeroize_json_value(val);
            }
        }
    }
}
