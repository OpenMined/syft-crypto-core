//! Tests for SyftPrivateKeys and SyftPublicKeyBundle
//!
//! Note: SyftRecoveryKey tests are in syft_recovery_key_test.rs

use libsignal_protocol::{IdentityKeyPair, KeyPair, kem};
use syft_crypto_protocol::{SyftPrivateKeys, SyftPublicKeyBundle};

// ============================================================================
// SyftPrivateKeys Tests
// ============================================================================

#[test]
fn test_private_keys_to_public_bundle() {
    let mut rng = rand::rng();

    let signal_identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signal_signed_pre_key_pair = KeyPair::generate(&mut rng);
    let signal_pq_signed_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let private_keys = SyftPrivateKeys::new(
        signal_identity_key_pair,
        signal_signed_pre_key_pair,
        signal_pq_signed_pre_key_pair.clone(),
    );

    let public_bundle = private_keys
        .to_public_bundle(&mut rng)
        .expect("Bundle creation should succeed");

    // Verify the public bundle has correct keys
    assert_eq!(
        public_bundle.signal_identity_public_key.serialize(),
        signal_identity_key_pair.identity_key().serialize(),
        "Identity key should match"
    );

    assert_eq!(
        public_bundle.signal_signed_public_pre_key.serialize(),
        signal_signed_pre_key_pair.public_key.serialize(),
        "Signed pre key should match"
    );

    assert_eq!(
        public_bundle.signal_pq_public_pre_key.serialize(),
        signal_pq_signed_pre_key_pair.public_key.serialize(),
        "PQ pre key should match"
    );

    // Verify signatures are valid
    assert!(
        public_bundle.verify_signatures(),
        "Public bundle signatures should be valid"
    );
}

#[test]
fn test_private_keys_multiple_bundles_same_keys() {
    let mut rng = rand::rng();

    let private_keys = SyftPrivateKeys::new(
        IdentityKeyPair::generate(&mut rng),
        KeyPair::generate(&mut rng),
        kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng),
    );

    let bundle1 = private_keys
        .to_public_bundle(&mut rng)
        .expect("Bundle 1 creation should succeed");
    let bundle2 = private_keys
        .to_public_bundle(&mut rng)
        .expect("Bundle 2 creation should succeed");

    // Same keys should produce bundles with same public keys
    assert_eq!(
        bundle1.signal_identity_public_key.serialize(),
        bundle2.signal_identity_public_key.serialize(),
        "Identity keys should match"
    );

    assert_eq!(
        bundle1.signal_signed_public_pre_key.serialize(),
        bundle2.signal_signed_public_pre_key.serialize(),
        "Signed pre keys should match"
    );

    assert_eq!(
        bundle1.signal_pq_public_pre_key.serialize(),
        bundle2.signal_pq_public_pre_key.serialize(),
        "PQ pre keys should match"
    );

    // Both bundles should have valid signatures
    assert!(bundle1.verify_signatures(), "Bundle 1 should be valid");
    assert!(bundle2.verify_signatures(), "Bundle 2 should be valid");
}

// ============================================================================
// SyftPublicKeyBundle Tests
// ============================================================================

#[test]
fn test_public_key_bundle_creation() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    assert_eq!(
        bundle.signal_identity_public_key.serialize(),
        identity_pair.identity_key().serialize()
    );
    assert_eq!(
        bundle.signal_signed_public_pre_key.serialize(),
        signed_pre_key_pair.public_key.serialize()
    );
    assert_eq!(
        bundle.signal_pq_public_pre_key.serialize(),
        pq_pre_key_pair.public_key.serialize()
    );
}

#[test]
fn test_public_key_bundle_signature_verification() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    assert!(
        bundle.verify_signatures(),
        "Valid bundle signatures should verify"
    );
}

#[test]
fn test_public_key_bundle_detects_tampered_ec_key() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let mut bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    // Tamper with EC key by replacing it
    let different_key_pair = KeyPair::generate(&mut rng);
    bundle.signal_signed_public_pre_key = different_key_pair.public_key;

    assert!(
        !bundle.verify_signatures(),
        "Tampered EC key should fail verification"
    );
}

#[test]
fn test_public_key_bundle_detects_tampered_pq_key() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let mut bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    // Tamper with PQ key by replacing it
    let different_pq_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    bundle.signal_pq_public_pre_key = different_pq_pair.public_key;

    assert!(
        !bundle.verify_signatures(),
        "Tampered PQ key should fail verification"
    );
}

#[test]
fn test_public_key_bundle_detects_tampered_ec_signature() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let mut bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    // Tamper with EC signature
    let mut tampered_sig = bundle.signal_signed_pre_key_signature.to_vec();
    tampered_sig[0] ^= 0xFF; // Flip bits in first byte
    bundle.signal_signed_pre_key_signature = tampered_sig.into_boxed_slice();

    assert!(
        !bundle.verify_signatures(),
        "Tampered EC signature should fail verification"
    );
}

#[test]
fn test_public_key_bundle_detects_tampered_pq_signature() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let mut bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    // Tamper with PQ signature
    let mut tampered_sig = bundle.signal_pq_pre_key_signature.to_vec();
    tampered_sig[0] ^= 0xFF; // Flip bits in first byte
    bundle.signal_pq_pre_key_signature = tampered_sig.into_boxed_slice();

    assert!(
        !bundle.verify_signatures(),
        "Tampered PQ signature should fail verification"
    );
}

#[test]
fn test_public_key_bundle_total_size() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    let total = bundle.total_size();

    // Calculate expected size manually
    let expected = bundle.signal_identity_public_key.serialize().len()
        + bundle.signal_signed_public_pre_key.serialize().len()
        + bundle.signal_signed_pre_key_signature.len()
        + bundle.signal_pq_public_pre_key.serialize().len()
        + bundle.signal_pq_pre_key_signature.len();

    assert_eq!(total, expected, "Total size should match sum of parts");

    // Verify size is reasonable (identity ~32, signed_pre ~32, sigs ~64 each, pq ~1568)
    // Total should be around 1760 bytes
    assert!(
        total > 1500,
        "Bundle should be at least 1500 bytes (Kyber public key is large)"
    );
    assert!(
        total < 2000,
        "Bundle should be less than 2000 bytes for reasonable sizes"
    );
}

#[test]
fn test_public_key_bundle_clone() {
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle1 = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle creation should succeed");

    let bundle2 = bundle1.clone();

    // Verify all fields are identical
    assert_eq!(
        bundle1.signal_identity_public_key.serialize(),
        bundle2.signal_identity_public_key.serialize()
    );
    assert_eq!(
        bundle1.signal_signed_public_pre_key.serialize(),
        bundle2.signal_signed_public_pre_key.serialize()
    );
    assert_eq!(
        bundle1.signal_signed_pre_key_signature,
        bundle2.signal_signed_pre_key_signature
    );
    assert_eq!(
        bundle1.signal_pq_public_pre_key.serialize(),
        bundle2.signal_pq_public_pre_key.serialize()
    );
    assert_eq!(
        bundle1.signal_pq_pre_key_signature,
        bundle2.signal_pq_pre_key_signature
    );

    // Both should verify
    assert!(bundle1.verify_signatures());
    assert!(bundle2.verify_signatures());
}

#[test]
fn test_public_key_bundle_cross_contamination() {
    // Ensure signatures from one bundle don't validate keys from another
    let mut rng = rand::rng();

    let identity_pair_1 = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair_1 = KeyPair::generate(&mut rng);
    let pq_pre_key_pair_1 = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let identity_pair_2 = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair_2 = KeyPair::generate(&mut rng);
    let pq_pre_key_pair_2 = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle1 = SyftPublicKeyBundle::new(
        &identity_pair_1,
        &signed_pre_key_pair_1,
        &pq_pre_key_pair_1,
        &mut rng,
    )
    .expect("Bundle 1 creation should succeed");

    let bundle2 = SyftPublicKeyBundle::new(
        &identity_pair_2,
        &signed_pre_key_pair_2,
        &pq_pre_key_pair_2,
        &mut rng,
    )
    .expect("Bundle 2 creation should succeed");

    // Create a mixed bundle: identity from bundle1, but keys and sigs from bundle2
    let mixed_bundle = SyftPublicKeyBundle {
        signal_identity_public_key: bundle1.signal_identity_public_key,
        signal_signed_public_pre_key: bundle2.signal_signed_public_pre_key,
        signal_signed_pre_key_signature: bundle2.signal_signed_pre_key_signature.clone(),
        signal_pq_public_pre_key: bundle2.signal_pq_public_pre_key.clone(),
        signal_pq_pre_key_signature: bundle2.signal_pq_pre_key_signature.clone(),
    };

    assert!(
        !mixed_bundle.verify_signatures(),
        "Mixed bundle with mismatched identity should fail verification"
    );
}

#[test]
fn test_public_key_bundle_deterministic_within_session() {
    // Verify that creating multiple bundles from the same keys produces valid bundles
    // (Note: signatures may differ due to randomness, but all should verify)
    let mut rng = rand::rng();

    let identity_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle1 = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle 1 should be created");

    let bundle2 = SyftPublicKeyBundle::new(
        &identity_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Bundle 2 should be created");

    // Both should verify independently
    assert!(bundle1.verify_signatures(), "Bundle 1 should verify");
    assert!(bundle2.verify_signatures(), "Bundle 2 should verify");

    // Public keys should be identical
    assert_eq!(
        bundle1.signal_identity_public_key.serialize(),
        bundle2.signal_identity_public_key.serialize()
    );
    assert_eq!(
        bundle1.signal_signed_public_pre_key.serialize(),
        bundle2.signal_signed_public_pre_key.serialize()
    );
    assert_eq!(
        bundle1.signal_pq_public_pre_key.serialize(),
        bundle2.signal_pq_public_pre_key.serialize()
    );
}
