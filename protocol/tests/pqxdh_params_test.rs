//! Tests for PQXDH Parameter Structs
//!
//! Tests the AlicePqxdhParameters, BobPqxdhParameters, and PublicKeyBundle
//! following libsignal's testing patterns.

use libsignal_protocol::*;
use rand::SeedableRng;
use syft_crypto_protocol::{AlicePqxdhParameters, BobPqxdhParameters, SyftPublicKeyBundle};

#[test]
fn test_public_key_bundle_creation() {
    println!("🔐 Test: PublicKeyBundle Creation");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);

    // Generate all key pairs
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    println!("\n📝 Creating PublicKeyBundle...");
    let bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Failed to create bundle");

    println!("   ✅ Bundle created");

    // Verify signatures
    println!("\n🔍 Verifying signatures...");
    assert!(bundle.verify_signatures(), "Signatures should be valid");
    println!("   ✅ Both signatures verified");

    // Check bundle size is reasonable
    let size = bundle.total_size();
    println!(
        "\n📊 Bundle size: {} bytes ({:.2} KB)",
        size,
        size as f64 / 1024.0
    );
    assert!(size > 1600, "Bundle should be at least 1600 bytes");
    assert!(size < 2000, "Bundle should be less than 2000 bytes");
    println!("   ✅ Size is within expected range");

    println!("\n{}", "=".repeat(60));
    println!("🎯 PublicKeyBundle Creation: PASSED");
    println!("{}", "=".repeat(60));
}

#[test]
fn test_alice_parameters_creation() {
    println!("🔐 Test: AlicePqxdhParameters Creation");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([2u8; 32]);

    // Generate Alice's keys
    println!("\n📝 Generating Alice's keys...");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let alice_base = KeyPair::generate(&mut rng);
    println!("   ✅ Alice's identity and base keys generated");

    // Generate Bob's keys and bundle
    println!("\n📝 Generating Bob's key bundle...");
    let bob_identity = IdentityKeyPair::generate(&mut rng);
    let bob_signed_prekey = KeyPair::generate(&mut rng);
    let bob_pq_prekey = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bob_spk_sig = bob_identity
        .private_key()
        .calculate_signature(&bob_signed_prekey.public_key.serialize(), &mut rng)
        .unwrap();

    let bob_pq_sig = bob_identity
        .private_key()
        .calculate_signature(&bob_pq_prekey.public_key.serialize(), &mut rng)
        .unwrap();

    println!("   ✅ Bob's bundle with signatures generated");

    // Create Alice's parameters
    println!("\n📝 Creating AlicePqxdhParameters...");
    let params = AlicePqxdhParameters::new(
        alice_identity,
        alice_base,
        *bob_identity.identity_key(),
        bob_signed_prekey.public_key,
        bob_spk_sig,
        bob_pq_prekey.public_key.clone(),
        bob_pq_sig,
    );

    // Test getters
    println!("\n🔍 Verifying parameter access...");
    assert_eq!(
        params
            .our_identity_key_pair()
            .identity_key()
            .serialize()
            .len(),
        33,
        "Identity key should be 33 bytes"
    );
    assert_eq!(
        params.our_base_key_pair().public_key.serialize().len(),
        33,
        "Base key should be 33 bytes"
    );
    assert_eq!(
        params.their_identity_key().serialize().len(),
        33,
        "Their identity key should be 33 bytes"
    );
    assert_eq!(
        params.their_signed_pre_key().serialize().len(),
        33,
        "Their signed prekey should be 33 bytes"
    );
    assert_eq!(
        params.their_pq_pre_key().serialize().len(),
        1569,
        "Their PQ prekey should be 1569 bytes"
    );
    assert_eq!(
        params.their_signed_pre_key_signature().len(),
        64,
        "EC signature should be 64 bytes"
    );
    assert_eq!(
        params.their_pq_pre_key_signature().len(),
        64,
        "PQ signature should be 64 bytes"
    );
    println!("   ✅ All parameters accessible and correct size");

    println!("\n{}", "=".repeat(60));
    println!("🎯 AlicePqxdhParameters Creation: PASSED");
    println!("{}", "=".repeat(60));
}

#[test]
fn test_bob_parameters_creation() {
    println!("🔐 Test: BobPqxdhParameters Creation");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([3u8; 32]);

    // Generate Alice's keys
    println!("\n📝 Generating Alice's keys...");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let alice_base = KeyPair::generate(&mut rng);
    println!("   ✅ Alice's keys generated");

    // Generate Bob's keys
    println!("\n📝 Generating Bob's keys...");
    let bob_identity = IdentityKeyPair::generate(&mut rng);
    let bob_signed_prekey = KeyPair::generate(&mut rng);
    let bob_pq_prekey = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    println!("   ✅ Bob's keys generated");

    // Simulate Alice encapsulating to Bob's PQ key
    println!("\n📝 Simulating Alice's KEM encapsulation...");
    let (_, kyber_ciphertext) = bob_pq_prekey.public_key.encapsulate(&mut rng).unwrap();
    println!(
        "   ✅ Kyber ciphertext created: {} bytes",
        kyber_ciphertext.len()
    );

    // Create Bob's parameters
    println!("\n📝 Creating BobPqxdhParameters...");
    let params = BobPqxdhParameters::new(
        bob_identity,
        bob_signed_prekey,
        bob_pq_prekey,
        *alice_identity.identity_key(),
        alice_base.public_key,
        &kyber_ciphertext,
    );

    // Test getters
    println!("\n🔍 Verifying parameter access...");
    assert_eq!(
        params
            .our_identity_key_pair()
            .identity_key()
            .serialize()
            .len(),
        33,
        "Identity key should be 33 bytes"
    );
    assert_eq!(
        params
            .our_signed_pre_key_pair()
            .public_key
            .serialize()
            .len(),
        33,
        "Signed prekey should be 33 bytes"
    );
    assert_eq!(
        params.our_pq_pre_key_pair().public_key.serialize().len(),
        1569,
        "PQ prekey should be 1569 bytes"
    );
    assert_eq!(
        params.their_identity_key().serialize().len(),
        33,
        "Their identity key should be 33 bytes"
    );
    assert_eq!(
        params.their_base_key().serialize().len(),
        33,
        "Their base key should be 33 bytes"
    );
    assert!(
        !params.their_kyber_ciphertext().is_empty(),
        "Kyber ciphertext should not be empty"
    );
    println!("   ✅ All parameters accessible and correct size");

    println!("\n{}", "=".repeat(60));
    println!("🎯 BobPqxdhParameters Creation: PASSED");
    println!("{}", "=".repeat(60));
}

#[test]
fn test_bundle_signature_verification() {
    println!("🔐 Test: Bundle Signature Verification");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([4u8; 32]);

    // Create a valid bundle
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Failed to create bundle");

    println!("\n🔍 Verifying valid bundle...");
    assert!(bundle.verify_signatures(), "Valid bundle should verify");
    println!("   ✅ Valid signatures verified");

    // Test: Manually verify EC signature
    println!("\n🔍 Manually verifying EC signature...");
    let ec_sig_ok = identity_key_pair.public_key().verify_signature(
        &bundle.signal_signed_public_pre_key.serialize(),
        &bundle.signal_signed_pre_key_signature,
    );
    assert!(ec_sig_ok, "EC signature should be valid");
    println!("   ✅ EC signature manually verified");

    // Test: Manually verify PQ signature
    println!("\n🔍 Manually verifying PQ signature...");
    let pq_sig_ok = identity_key_pair.public_key().verify_signature(
        &bundle.signal_pq_public_pre_key.serialize(),
        &bundle.signal_pq_pre_key_signature,
    );
    assert!(pq_sig_ok, "PQ signature should be valid");
    println!("   ✅ PQ signature manually verified");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Bundle Signature Verification: PASSED");
    println!("{}", "=".repeat(60));
}

#[test]
fn test_bundle_with_wrong_signature() {
    println!("🔐 Test: Bundle with Wrong Signature");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([5u8; 32]);

    // Create bundle with valid signatures
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let mut bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .expect("Failed to create bundle");

    println!("\n✅ Valid bundle created");

    // Corrupt the EC signature
    println!("\n🔧 Corrupting EC signature...");
    bundle.signal_signed_pre_key_signature[0] ^= 0xFF;

    println!("🔍 Verifying corrupted bundle...");
    assert!(
        !bundle.verify_signatures(),
        "Corrupted bundle should fail verification"
    );
    println!("   ✅ Corrupted signature correctly rejected");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Wrong Signature Detection: PASSED");
    println!("{}", "=".repeat(60));
}
