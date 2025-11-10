//! Storage for cryptographic keys and DID documents
//!
//! This module handles secure file I/O for:
//! - **Private keys**: Stored in JWKS format with restricted permissions (0o600)
//! - **DID documents**: Public key bundles in W3C DID format
//!
//! # Security
//! Private key files are created with Unix permissions 0o600 (owner read/write only)
//! to prevent unauthorized access.
//!
//! # Example
//! ```no_run
//! use syft_crypto_protocol::SyftRecoveryKey;
//! use syft_crypto_protocol::storage::{save_private_keys, load_private_keys};
//! use std::path::Path;
//!
//! let recovery_key = SyftRecoveryKey::generate();
//! let private_keys = recovery_key.derive_keys().unwrap();
//!
//! // Save with secure permissions
//! save_private_keys(&private_keys, Path::new("keys.json")).unwrap();
//!
//! // Load back
//! let loaded_keys = load_private_keys(Path::new("keys.json")).unwrap();
//! ```

use crate::error::KeyError;
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::serialization::{
    deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
    serialize_to_did_document,
};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Save private keys to disk with secure permissions (0o600 on Unix).
///
/// The keys are serialized to JWKS format and written to the specified path.
/// On Unix systems, file permissions are set to 0o600 (read/write for owner only).
///
/// # Arguments
/// * `keys` - The private keys to save
/// * `path` - Destination file path
///
/// # Errors
/// * `KeyError::JsonError` if serialization fails
/// * `KeyError::StorageError` if file I/O fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::SyftRecoveryKey;
/// use syft_crypto_protocol::storage::save_private_keys;
/// use std::path::Path;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let keys = recovery_key.derive_keys().unwrap();
/// save_private_keys(&keys, Path::new("my_keys.json")).unwrap();
/// ```
pub fn save_private_keys(keys: &SyftPrivateKeys, path: &Path) -> Result<(), KeyError> {
    // Serialize to JWKS format
    let jwks = serialize_private_keys(keys).map_err(|e| {
        KeyError::SerializationError(format!("Failed to serialize private keys: {}", e))
    })?;

    // Convert to pretty-printed JSON string
    let json_string = serde_json::to_string_pretty(&jwks)?;

    // Write to file
    let mut file = File::create(path)?;
    file.write_all(json_string.as_bytes())?;

    // Set secure permissions on Unix (0o600 = owner read/write only)
    #[cfg(unix)]
    {
        let metadata = file.metadata()?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

/// Load private keys from disk.
///
/// Reads a JWKS file and deserializes the private keys.
///
/// # Arguments
/// * `path` - Path to the JWKS file
///
/// # Returns
/// * `Ok(SyftPrivateKeys)` if successful
/// * `Err(KeyError)` if file reading or deserialization fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::storage::load_private_keys;
/// use std::path::Path;
///
/// let keys = load_private_keys(Path::new("my_keys.json")).unwrap();
/// ```
pub fn load_private_keys(path: &Path) -> Result<SyftPrivateKeys, KeyError> {
    // Read file contents
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse JSON
    let jwks: serde_json::Value = serde_json::from_str(&contents)?;

    // Deserialize keys
    let keys = deserialize_private_keys(&jwks).map_err(|e| {
        KeyError::SerializationError(format!("Failed to deserialize private keys: {}", e))
    })?;

    Ok(keys)
}

/// Save DID document to disk.
///
/// Serializes a public key bundle to W3C DID document format and writes to file.
/// This is public data, so no special permissions are set.
///
/// # Arguments
/// * `bundle` - The public key bundle to save
/// * `did_id` - The DID identifier (e.g., "did:web:syftbox.net:alice%40example.com")
/// * `path` - Destination file path
///
/// # Errors
/// * `KeyError::JsonError` if serialization fails
/// * `KeyError::StorageError` if file I/O fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::SyftRecoveryKey;
/// use syft_crypto_protocol::storage::save_did_document;
/// use std::path::Path;
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();
/// save_did_document(&bundle, "did:web:example.com:alice", Path::new("did.json")).unwrap();
/// ```
pub fn save_did_document(
    bundle: &SyftPublicKeyBundle,
    did_id: &str,
    path: &Path,
) -> Result<(), KeyError> {
    // Serialize to DID document format
    let did_doc = serialize_to_did_document(bundle, did_id).map_err(|e| {
        KeyError::SerializationError(format!("Failed to serialize DID document: {}", e))
    })?;

    // Convert to pretty-printed JSON string
    let json_string = serde_json::to_string_pretty(&did_doc)?;

    // Write to file
    let mut file = File::create(path)?;
    file.write_all(json_string.as_bytes())?;

    Ok(())
}

/// Load DID document from disk.
///
/// Reads a W3C DID document file and deserializes the public key bundle.
/// Verifies signatures during deserialization.
///
/// # Arguments
/// * `path` - Path to the DID document file
///
/// # Returns
/// * `Ok(SyftPublicKeyBundle)` if successful and signatures are valid
/// * `Err(KeyError)` if file reading, deserialization, or signature verification fails
///
/// # Example
/// ```no_run
/// use syft_crypto_protocol::storage::load_did_document;
/// use std::path::Path;
///
/// let bundle = load_did_document(Path::new("did.json")).unwrap();
/// ```
pub fn load_did_document(path: &Path) -> Result<SyftPublicKeyBundle, KeyError> {
    // Read file contents
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse JSON
    let did_doc: serde_json::Value = serde_json::from_str(&contents)?;

    // Deserialize and verify signatures
    let bundle = deserialize_from_did_document(&did_doc).map_err(|e| {
        KeyError::SerializationError(format!("Failed to deserialize DID document: {}", e))
    })?;

    Ok(bundle)
}
