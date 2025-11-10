use syft_crypto_protocol::SyftRecoveryKey;

#[test]
fn test_derive_keys_from_recovery_key() {
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key
        .derive_keys()
        .expect("Key derivation should succeed");

    // Verify all keys are generated
    assert!(
        !private_keys.identity().serialize().is_empty(),
        "Identity key should exist"
    );
    assert!(
        !private_keys
            .signed_pre_key()
            .public_key
            .serialize()
            .is_empty(),
        "Signed prekey should exist"
    );
    assert!(
        !private_keys
            .pq_signed_pre_key()
            .public_key
            .serialize()
            .is_empty(),
        "PQ prekey should exist"
    );
}

#[test]
fn test_deterministic_key_derivation() {
    // Same recovery key should produce same keys
    let recovery_key = SyftRecoveryKey::generate();

    let keys1 = recovery_key
        .derive_keys()
        .expect("First derivation should succeed");
    let keys2 = recovery_key
        .derive_keys()
        .expect("Second derivation should succeed");

    // Compare identity keys
    assert_eq!(
        keys1.identity().serialize(),
        keys2.identity().serialize(),
        "Identity keys should match"
    );

    // Compare signed prekeys
    assert_eq!(
        keys1.signed_pre_key().public_key.serialize(),
        keys2.signed_pre_key().public_key.serialize(),
        "Signed prekeys should match"
    );
    assert_eq!(
        keys1.signed_pre_key().private_key.serialize(),
        keys2.signed_pre_key().private_key.serialize(),
        "Signed prekey private keys should match"
    );

    // Compare PQ prekeys
    assert_eq!(
        keys1.pq_signed_pre_key().public_key.serialize(),
        keys2.pq_signed_pre_key().public_key.serialize(),
        "PQ prekeys should match"
    );
    assert_eq!(
        keys1.pq_signed_pre_key().secret_key.serialize(),
        keys2.pq_signed_pre_key().secret_key.serialize(),
        "PQ prekey secret keys should match"
    );
}

#[test]
fn test_different_recovery_keys_produce_different_keys() {
    // Different recovery keys should produce different keys
    let recovery_key1 = SyftRecoveryKey::generate();
    let recovery_key2 = SyftRecoveryKey::generate();

    let keys1 = recovery_key1
        .derive_keys()
        .expect("First derivation should succeed");
    let keys2 = recovery_key2
        .derive_keys()
        .expect("Second derivation should succeed");

    // Identity keys should be different
    assert_ne!(
        keys1.identity().serialize(),
        keys2.identity().serialize(),
        "Identity keys should be different"
    );

    // Signed prekeys should be different
    assert_ne!(
        keys1.signed_pre_key().public_key.serialize(),
        keys2.signed_pre_key().public_key.serialize(),
        "Signed prekeys should be different"
    );

    // PQ prekeys should be different
    assert_ne!(
        keys1.pq_signed_pre_key().public_key.serialize(),
        keys2.pq_signed_pre_key().public_key.serialize(),
        "PQ prekeys should be different"
    );
}

#[test]
fn test_recovery_key_hex_roundtrip_with_derived_keys() {
    // Verify that hex serialization + deserialization produces same keys
    let recovery_key = SyftRecoveryKey::generate();
    let original_keys = recovery_key
        .derive_keys()
        .expect("Original derivation should succeed");

    // Serialize to hex and back
    let hex = recovery_key.to_hex_string();
    let recovered_key = SyftRecoveryKey::from_hex_string(&hex).expect("Should parse hex");
    let recovered_keys = recovered_key
        .derive_keys()
        .expect("Recovered derivation should succeed");

    // Keys should match
    assert_eq!(
        original_keys.identity().serialize(),
        recovered_keys.identity().serialize(),
        "Identity keys should match after hex roundtrip"
    );
    assert_eq!(
        original_keys.signed_pre_key().public_key.serialize(),
        recovered_keys.signed_pre_key().public_key.serialize(),
        "Signed prekeys should match after hex roundtrip"
    );
    assert_eq!(
        original_keys.pq_signed_pre_key().public_key.serialize(),
        recovered_keys.pq_signed_pre_key().public_key.serialize(),
        "PQ prekeys should match after hex roundtrip"
    );
}

#[test]
fn test_derived_keys_can_create_public_bundle() {
    // Verify derived keys can be used to create a public key bundle
    let recovery_key = SyftRecoveryKey::generate();
    let private_keys = recovery_key
        .derive_keys()
        .expect("Key derivation should succeed");

    // Create public bundle
    let public_bundle = private_keys
        .to_public_bundle(&mut rand::rng())
        .expect("Should create public bundle");

    // Verify signatures are valid
    assert!(
        public_bundle.verify_signatures(),
        "Public bundle signatures should be valid"
    );

    // Verify public keys match private keys
    assert_eq!(
        public_bundle.signal_identity_public_key.serialize(),
        private_keys.identity().identity_key().serialize(),
        "Public identity key should match private key"
    );
    assert_eq!(
        public_bundle.signal_signed_public_pre_key.serialize(),
        private_keys.signed_pre_key().public_key.serialize(),
        "Public signed prekey should match private key"
    );
    assert_eq!(
        public_bundle.signal_pq_public_pre_key.serialize(),
        private_keys.pq_signed_pre_key().public_key.serialize(),
        "Public PQ prekey should match private key"
    );
}
