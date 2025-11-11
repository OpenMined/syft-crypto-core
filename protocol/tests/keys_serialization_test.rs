use syft_crypto_protocol::SyftRecoveryKey;
use syft_crypto_protocol::did_utils::generate_did_web_id;
use syft_crypto_protocol::serialization::{
    deserialize_from_did_document, deserialize_private_keys, serialize_private_keys,
    serialize_to_did_document,
};

#[test]
fn test_did_document_roundtrip() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let original_bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate DID using utility function
    let did_id = generate_did_web_id("alice@example.com", "example.com");

    // Serialize
    let did_doc = serialize_to_did_document(&original_bundle, &did_id).expect("Should serialize");

    // Deserialize
    let restored_bundle = deserialize_from_did_document(&did_doc).expect("Should deserialize");

    // Verify keys match
    assert_eq!(
        original_bundle.signal_identity_public_key.serialize(),
        restored_bundle.signal_identity_public_key.serialize(),
        "Identity keys should match"
    );
    assert_eq!(
        original_bundle.signal_signed_public_pre_key.serialize(),
        restored_bundle.signal_signed_public_pre_key.serialize(),
        "Signed prekeys should match"
    );
    assert_eq!(
        original_bundle.signal_pq_public_pre_key.serialize(),
        restored_bundle.signal_pq_public_pre_key.serialize(),
        "PQ prekeys should match"
    );
}

#[test]
fn test_private_keys_roundtrip() {
    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key.derive_keys().unwrap();

    // Serialize
    let jwks = serialize_private_keys(&original_keys).expect("Should serialize");

    // Deserialize
    let restored_keys = deserialize_private_keys(&jwks).expect("Should deserialize");

    // print out original and restored keys for debugging
    println!(
        "Original Keys Identity : {:?}",
        original_keys.identity().serialize()
    );
    println!(
        "Restored Keys Identity: {:?}",
        restored_keys.identity().serialize()
    );

    // Verify keys match
    assert_eq!(
        original_keys.identity().serialize(),
        restored_keys.identity().serialize(),
        "Identity keys should match"
    );
    assert_eq!(
        original_keys.signed_pre_key().public_key.serialize(),
        restored_keys.signed_pre_key().public_key.serialize(),
        "Signed prekeys should match"
    );
    assert_eq!(
        original_keys.pq_signed_pre_key().public_key.serialize(),
        restored_keys.pq_signed_pre_key().public_key.serialize(),
        "PQ prekeys should match"
    );
}

#[test]
fn test_did_document_format() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key.derive_keys().unwrap();
    let bundle = private_keys.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate DID using utility function
    let did_id = generate_did_web_id("alice@example.com", "example.com");

    let did_doc = serialize_to_did_document(&bundle, &did_id).unwrap();

    // Verify structure
    assert!(did_doc["@context"].is_array());
    assert_eq!(did_doc["id"], did_id);
    assert!(did_doc["verificationMethod"].is_array());
    assert!(did_doc["keyAgreement"].is_array());

    // Verify identity key
    let vm = &did_doc["verificationMethod"][0];
    assert_eq!(vm["type"], "Ed25519VerificationKey2020");
    assert_eq!(vm["publicKeyJwk"]["kty"], "OKP");
    assert_eq!(vm["publicKeyJwk"]["crv"], "Ed25519");

    // Verify encryption keys
    let ka = did_doc["keyAgreement"].as_array().unwrap();
    assert_eq!(ka.len(), 2);
}
