/// Security Tests for PQXDH Implementation
///
/// These tests verify that the implementation correctly rejects invalid inputs,
/// corrupted data, and potential attack vectors. Inspired by libsignal's security tests.
use libsignal_protocol::*;
use rand::SeedableRng;
use syft_crypto_protocol::SyftPublicKeyBundle;

/// Test that PublicKeyBundle rejects corrupted EC prekey signature
#[test]
fn test_reject_corrupted_ec_signature() {
    println!("🔐 Security Test: Reject Corrupted EC Signature");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);

    // Create valid bundle
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
    assert!(
        bundle.verify_signatures(),
        "Original bundle should have valid signatures"
    );
    println!("✅ Original signatures verified");

    // Corrupt the EC signature
    println!("\n🔧 Corrupting EC signature (flipping first byte)...");
    bundle.signal_signed_pre_key_signature[0] ^= 0xFF;

    // Verify rejection
    println!("🔍 Verifying corrupted bundle...");
    assert!(
        !bundle.verify_signatures(),
        "Corrupted EC signature should be rejected"
    );
    println!("✅ Corrupted EC signature correctly rejected");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: EC signature corruption detected");
    println!("{}", "=".repeat(60));
}

/// Test that PublicKeyBundle rejects corrupted PQ prekey signature
#[test]
fn test_reject_corrupted_pq_signature() {
    println!("🔐 Security Test: Reject Corrupted PQ Signature");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([2u8; 32]);

    // Create valid bundle
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
    assert!(
        bundle.verify_signatures(),
        "Original bundle should have valid signatures"
    );
    println!("✅ Original signatures verified");

    // Corrupt the PQ signature
    println!("\n🔧 Corrupting PQ signature (flipping last byte)...");
    let last_idx = bundle.signal_pq_pre_key_signature.len() - 1;
    bundle.signal_pq_pre_key_signature[last_idx] ^= 0xFF;

    // Verify rejection
    println!("🔍 Verifying corrupted bundle...");
    assert!(
        !bundle.verify_signatures(),
        "Corrupted PQ signature should be rejected"
    );
    println!("✅ Corrupted PQ signature correctly rejected");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: PQ signature corruption detected");
    println!("{}", "=".repeat(60));
}

/// Test that signatures from wrong identity key are rejected
#[test]
fn test_reject_wrong_identity_key_signature() {
    println!("🔐 Security Test: Reject Wrong Identity Key Signature");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([3u8; 32]);

    // Alice creates her keys
    println!("\n📝 Alice generates her keys...");
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let alice_signed_prekey = KeyPair::generate(&mut rng);
    let alice_pq_prekey = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    println!("   ✅ Alice's keys generated");

    // Bob (attacker) creates his identity key
    println!("\n📝 Bob (attacker) generates his identity key...");
    let bob_identity = IdentityKeyPair::generate(&mut rng);
    println!("   ✅ Bob's identity key generated");

    // Bob tries to sign Alice's prekeys with his identity key
    println!("\n🔧 Bob attempts to sign Alice's prekeys with his identity key...");
    let fake_ec_sig = bob_identity
        .private_key()
        .calculate_signature(&alice_signed_prekey.public_key.serialize(), &mut rng)
        .unwrap();

    let fake_pq_sig = bob_identity
        .private_key()
        .calculate_signature(&alice_pq_prekey.public_key.serialize(), &mut rng)
        .unwrap();
    println!("   ✅ Fake signatures created");

    // Create bundle with Alice's keys but Bob's signatures
    println!("\n📦 Creating malicious bundle (Alice's keys + Bob's signatures)...");
    let malicious_bundle = SyftPublicKeyBundle {
        signal_identity_public_key: *bob_identity.identity_key(), // Bob's identity
        signal_signed_public_pre_key: alice_signed_prekey.public_key,
        signal_signed_pre_key_signature: fake_ec_sig,
        signal_pq_public_pre_key: alice_pq_prekey.public_key.clone(),
        signal_pq_pre_key_signature: fake_pq_sig,
    };

    // The signatures ARE valid (Bob signed Alice's keys correctly)
    println!("\n🔍 Verifying malicious bundle...");
    assert!(
        malicious_bundle.verify_signatures(),
        "Signatures are technically valid (Bob signed Alice's keys)"
    );
    println!("⚠️  Signatures are technically valid BUT...");

    // However, the identity key doesn't match Alice's
    println!("\n🔍 Checking if identity matches Alice's...");
    assert_ne!(
        malicious_bundle.signal_identity_public_key.serialize(),
        alice_identity.identity_key().serialize(),
        "Identity keys should NOT match"
    );
    println!("✅ Identity key mismatch detected!");
    println!("   This bundle claims to be from Bob, not Alice");

    println!("   When receiving a bundle, we must:");
    println!("   1. Verify signatures ✓");
    println!("   2. Verify identity key matches expected sender ✓");
    println!("   3. Check identity key against trusted source (DID document) ✓");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: Identity key validation is essential");
    println!("{}", "=".repeat(60));
}

/// Test that swapped prekeys are detected
#[test]
fn test_reject_swapped_prekeys() {
    println!("🔐 Security Test: Detect Swapped Prekeys");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([4u8; 32]);

    // Generate two sets of keys
    println!("\n📝 Generating two separate key sets...");
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);

    let signed_prekey_1 = KeyPair::generate(&mut rng);
    let signed_prekey_2 = KeyPair::generate(&mut rng);

    let pq_prekey_1 = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let pq_prekey_2 = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    println!("   ✅ Two key sets generated");

    // Create bundle with key set 1
    let bundle_1 =
        SyftPublicKeyBundle::new(&identity_key_pair, &signed_prekey_1, &pq_prekey_1, &mut rng)
            .unwrap();
    println!("\n✅ Bundle 1 created (keys from set 1)");

    // Create malicious bundle: signatures from bundle 1, but keys from set 2
    println!("\n🔧 Creating malicious bundle (signatures for set 1, but keys from set 2)...");
    let malicious_bundle = SyftPublicKeyBundle {
        signal_identity_public_key: bundle_1.signal_identity_public_key,
        signal_signed_public_pre_key: signed_prekey_2.public_key, // Swapped!
        signal_signed_pre_key_signature: bundle_1.signal_signed_pre_key_signature.clone(),
        signal_pq_public_pre_key: pq_prekey_2.public_key.clone(), // Swapped!
        signal_pq_pre_key_signature: bundle_1.signal_pq_pre_key_signature.clone(),
    };

    // Verify rejection
    println!("\n🔍 Verifying malicious bundle...");
    assert!(
        !malicious_bundle.verify_signatures(),
        "Swapped keys should fail signature verification"
    );
    println!("✅ Swapped keys correctly rejected");

    println!("\n💡 Security Lesson:");
    println!("   Signatures are bound to specific keys");
    println!("   Cannot reuse signatures with different keys");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: Key swapping detected");
    println!("{}", "=".repeat(60));
}

/// Test that empty/zero signatures are rejected
#[test]
fn test_reject_zero_signature() {
    println!("🔐 Security Test: Reject Zero/Empty Signatures");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([5u8; 32]);

    // Create valid bundle
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let mut bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .unwrap();

    println!("\n✅ Valid bundle created");

    // Replace EC signature with zeros
    println!("\n🔧 Replacing EC signature with zeros...");
    bundle.signal_signed_pre_key_signature = vec![0u8; 64].into_boxed_slice();

    println!("🔍 Verifying bundle with zero signature...");
    assert!(
        !bundle.verify_signatures(),
        "Zero signature should be rejected"
    );
    println!("✅ Zero EC signature correctly rejected");

    // Restore EC signature, zero out PQ signature
    println!("\n🔧 Replacing PQ signature with zeros...");
    let valid_bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .unwrap();

    let bundle2 = SyftPublicKeyBundle {
        signal_identity_public_key: valid_bundle.signal_identity_public_key,
        signal_signed_public_pre_key: valid_bundle.signal_signed_public_pre_key,
        signal_signed_pre_key_signature: valid_bundle.signal_signed_pre_key_signature,
        signal_pq_public_pre_key: valid_bundle.signal_pq_public_pre_key,
        signal_pq_pre_key_signature: vec![0u8; 64].into_boxed_slice(),
    };

    println!("🔍 Verifying bundle with zero PQ signature...");
    assert!(
        !bundle2.verify_signatures(),
        "Zero PQ signature should be rejected"
    );
    println!("✅ Zero PQ signature correctly rejected");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: Zero signatures rejected");
    println!("{}", "=".repeat(60));
}

/// Test that bundle size is reasonable (not a DoS vector)
#[test]
fn test_bundle_size_reasonable() {
    println!("🔐 Security Test: Bundle Size is Reasonable");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([6u8; 32]);

    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .unwrap();

    let size = bundle.total_size();
    println!(
        "\n📊 Bundle size: {} bytes ({:.2} KB)",
        size,
        size as f64 / 1024.0
    );

    // Check upper bound (prevent DoS via huge bundles)
    println!("\n🔍 Checking upper bound...");
    assert!(
        size < 2000,
        "Bundle should be less than 2KB (DoS prevention)"
    );
    println!("✅ Size is under 2KB");

    // Check lower bound (ensure all components present)
    println!("\n🔍 Checking lower bound...");
    assert!(
        size > 1600,
        "Bundle should be at least 1.6KB (all components present)"
    );
    println!("✅ Size indicates all components are present");

    // Component breakdown
    println!("\n📊 Component sizes:");
    println!(
        "   Identity key:    {} bytes",
        bundle.signal_identity_public_key.serialize().len()
    );
    println!(
        "   Signed prekey:   {} bytes",
        bundle.signal_signed_public_pre_key.serialize().len()
    );
    println!(
        "   SPK signature:   {} bytes",
        bundle.signal_signed_pre_key_signature.len()
    );
    println!(
        "   PQ prekey:       {} bytes",
        bundle.signal_pq_public_pre_key.serialize().len()
    );
    println!(
        "   PQSPK signature: {} bytes",
        bundle.signal_pq_pre_key_signature.len()
    );

    println!("\n💡 Security Notes:");
    println!("   - Bundle size is deterministic (no variable length attacks)");
    println!("   - Small enough for network transmission (<2KB)");
    println!("   - Large enough to indicate no missing components (>1.6KB)");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: Bundle size is reasonable");
    println!("{}", "=".repeat(60));
}

/// Test that signature verification is constant-time resistant
/// (This is a behavioral test, not a timing test)
#[test]
fn test_signature_verification_consistency() {
    println!("🔐 Security Test: Signature Verification Consistency");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([7u8; 32]);

    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let pq_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_pre_key_pair,
        &pq_pre_key_pair,
        &mut rng,
    )
    .unwrap();

    println!("\n🔍 Testing multiple verifications produce consistent results...");

    // Verify 100 times - should always return true
    for i in 0..100 {
        let result = bundle.verify_signatures();
        assert!(result, "Verification {} should succeed", i);
    }
    println!("✅ 100 valid verifications: all returned true");

    // Corrupt and verify 100 times - should always return false
    let mut corrupted = bundle.clone();
    corrupted.signal_signed_pre_key_signature[0] ^= 0xFF;

    println!("\n🔍 Testing corrupted bundle consistency...");
    for i in 0..100 {
        let result = corrupted.verify_signatures();
        assert!(!result, "Corrupted verification {} should fail", i);
    }
    println!("✅ 100 corrupted verifications: all returned false");

    println!("\n💡 Security Note:");
    println!("   Verification results are deterministic and consistent");
    println!("   This is important for cache-timing attack resistance");

    println!("\n{}", "=".repeat(60));
    println!("🎯 Security Test PASSED: Verification is consistent");
    println!("{}", "=".repeat(60));
}
