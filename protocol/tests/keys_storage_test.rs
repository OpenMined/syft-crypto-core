use std::fs;
use syft_crypto_protocol::SyftRecoveryKey;
use syft_crypto_protocol::did_utils::generate_did_web_id;
use syft_crypto_protocol::storage::{
    load_did_document, load_private_keys, save_did_document, save_private_keys,
};
use tempfile::TempDir;

#[test]
fn test_private_keys_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("test_keys.json");

    // Generate keys
    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key.derive_keys().unwrap();

    // Save to disk
    save_private_keys(&original_keys, &key_path).expect("Should save keys");

    // Verify file exists
    assert!(key_path.exists(), "Key file should exist");

    // Check Unix permissions (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(&key_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            0o600,
            "Private keys should have 0o600 permissions"
        );
    }

    // Load from disk
    let loaded_keys = load_private_keys(&key_path).expect("Should load keys");

    // Verify keys match (both public AND private)

    // Identity key (contains both public and private)
    assert_eq!(
        original_keys.identity().serialize(),
        loaded_keys.identity().serialize(),
        "Identity keypairs should match"
    );

    // Signed prekey - verify both public and private keys
    assert_eq!(
        original_keys.signed_pre_key().public_key.serialize(),
        loaded_keys.signed_pre_key().public_key.serialize(),
        "Signed prekey public keys should match"
    );
    assert_eq!(
        original_keys.signed_pre_key().private_key.serialize(),
        loaded_keys.signed_pre_key().private_key.serialize(),
        "Signed prekey private keys should match"
    );

    // PQ prekey - verify both public and secret keys
    assert_eq!(
        original_keys.pq_signed_pre_key().public_key.serialize(),
        loaded_keys.pq_signed_pre_key().public_key.serialize(),
        "PQ prekey public keys should match"
    );
    assert_eq!(
        original_keys.pq_signed_pre_key().secret_key.serialize(),
        loaded_keys.pq_signed_pre_key().secret_key.serialize(),
        "PQ prekey secret keys should match"
    );
}

#[test]
fn test_did_document_storage_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let did_path = temp_dir.path().join("test_did.json");

    // Generate keys and bundle
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let original_bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate DID using utility function
    let did_id = generate_did_web_id("alice@example.com", "example.com");

    // Save to disk
    save_did_document(&original_bundle, &did_id, &did_path).expect("Should save DID document");

    // Verify file exists
    assert!(did_path.exists(), "DID document file should exist");

    // Load from disk
    let loaded_bundle = load_did_document(&did_path).expect("Should load DID document");

    // Verify keys match
    assert_eq!(
        original_bundle.signal_identity_public_key.serialize(),
        loaded_bundle.signal_identity_public_key.serialize(),
        "Identity keys should match"
    );
    assert_eq!(
        original_bundle.signal_signed_public_pre_key.serialize(),
        loaded_bundle.signal_signed_public_pre_key.serialize(),
        "Signed prekeys should match"
    );
    assert_eq!(
        original_bundle.signal_pq_public_pre_key.serialize(),
        loaded_bundle.signal_pq_public_pre_key.serialize(),
        "PQ prekeys should match"
    );
}

#[test]
fn test_load_nonexistent_file() {
    let result = load_private_keys(std::path::Path::new("/nonexistent/path/keys.json"));
    assert!(result.is_err(), "Should fail to load nonexistent file");
}

#[test]
fn test_load_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let invalid_path = temp_dir.path().join("invalid.json");

    // Write invalid JSON
    fs::write(&invalid_path, "not valid json").unwrap();

    let result = load_private_keys(&invalid_path);
    assert!(result.is_err(), "Should fail to load invalid JSON");
}

#[test]
fn test_did_document_file_format() {
    let temp_dir = TempDir::new().unwrap();
    let did_path = temp_dir.path().join("test_did_format.json");

    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate DID using utility function
    let did_id = generate_did_web_id("alice@example.com", "syftbox.net");

    save_did_document(&bundle, &did_id, &did_path).unwrap();

    // Read and parse the file
    let contents = fs::read_to_string(&did_path).unwrap();
    let did_doc: serde_json::Value = serde_json::from_str(&contents).unwrap();

    // Verify structure
    assert_eq!(did_doc["@context"].as_array().unwrap().len(), 3);
    assert_eq!(did_doc["id"], did_id);
    assert!(did_doc["verificationMethod"].is_array());
    assert!(did_doc["keyAgreement"].is_array());

    // Verify keyAgreement has PQ key with JsonWebKey2020 type
    let ka = did_doc["keyAgreement"].as_array().unwrap();
    let pq_key = ka
        .iter()
        .find(|k| k["publicKeyJwk"]["kty"] == "PQ")
        .unwrap();
    assert_eq!(pq_key["type"], "JsonWebKey2020");
    assert_eq!(pq_key["publicKeyJwk"]["crv"], "Kyber1024");
}
