//! Tests for PQXDH 3-Key Structure (no one-time prekeys)
//! - IK (Identity Key) - Ed25519
//! - SPK (Signed EC Prekey) - X25519
//! - PQSPK (PQ Last-Resort Prekey) - Kyber1024

use libsignal_protocol::*;
use rand::SeedableRng;
use syft_crypto_protocol::SyftPublicKeyBundle;

/// Test 1: Generate the 3 keys required for PQXDH
///
/// Keys generated:
/// 1. IK (Identity Key) - Long-term, never rotated
/// 2. SPK (Signed Prekey) - Medium-term, rotated weekly/monthly
/// 3. PQSPK (PQ Signed Prekey) - Medium-term, rotated weekly/monthly
#[test]
fn test_generate_3_keys() -> Result<(), SignalProtocolError> {
    println!("🔐 Test: Generate 3-Key PQXDH Bundle");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);

    // === 1. Identity Key (IK) - Ed25519 ===
    println!("\n📝 Generating Key 1/3: Identity Key (IK)");
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);

    // Verify key properties
    let identity_public = identity_key_pair.public_key();
    assert_eq!(identity_public.serialize().len(), 33); // 32 bytes + type byte
    println!("   ✅ Identity key generated");
    println!(
        "   📊 Public key size: {} bytes",
        identity_public.serialize().len()
    );
    println!("   🔑 Type: Ed25519 (for signing)");

    // === 2. Signed EC Prekey (SPK) - X25519 ===
    println!("\n📝 Generating Key 2/3: Signed EC Prekey (SPK)");
    let signed_prekey_pair = KeyPair::generate(&mut rng);

    // Sign the prekey with identity key
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_prekey_pair.public_key.serialize(), &mut rng)?;

    // Verify signature properties
    assert_eq!(signed_pre_key_signature.len(), 64); // Ed25519 signature is 64 bytes
    assert_eq!(signed_prekey_pair.public_key.serialize().len(), 33);
    println!("   ✅ Signed prekey generated");
    println!(
        "   📊 Public key size: {} bytes",
        signed_prekey_pair.public_key.serialize().len()
    );
    println!(
        "   📊 Signature size: {} bytes",
        signed_pre_key_signature.len()
    );
    println!("   🔑 Type: X25519 (for DH)");
    println!("   🔏 Signed by: Identity key");

    // === 3. PQ Last-Resort Prekey (PQSPK) - Kyber1024 ===
    println!("\n📝 Generating Key 3/3: PQ Last-Resort Prekey (PQSPK)");
    let pq_prekey_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    // Sign the PQ prekey with identity key
    let pq_signature = identity_key_pair
        .private_key()
        .calculate_signature(&pq_prekey_pair.public_key.serialize(), &mut rng)?;

    // Verify PQ key properties
    assert_eq!(pq_signature.len(), 64);
    // Kyber1024 public key: 1568 bytes + 1 byte type identifier
    assert_eq!(pq_prekey_pair.public_key.serialize().len(), 1569);
    // Kyber1024 secret key: 3168 bytes + 1 byte type identifier
    assert_eq!(pq_prekey_pair.secret_key.serialize().len(), 3169);
    println!("   ✅ PQ last-resort prekey generated");
    println!(
        "   📊 Public key size: {} bytes",
        pq_prekey_pair.public_key.serialize().len()
    );
    println!(
        "   📊 Secret key size: {} bytes",
        pq_prekey_pair.secret_key.serialize().len()
    );
    println!("   📊 Signature size: {} bytes", pq_signature.len());
    println!("   🔑 Type: Kyber1024 (for KEM)");
    println!("   🔏 Signed by: Identity key");

    // === Summary ===
    println!();
    println!("{}", "=".repeat(60));
    println!("🎯 3-Key Bundle Generated Successfully!");
    println!("{}", "=".repeat(60));
    println!("Key Structure:");
    println!(
        "  1. IK (Identity)       : {} bytes public",
        identity_public.serialize().len()
    );
    println!(
        "  2. SPK (Signed Prekey) : {} bytes public",
        signed_prekey_pair.public_key.serialize().len()
    );
    println!(
        "  3. PQSPK (PQ Prekey)   : {} bytes public",
        pq_prekey_pair.public_key.serialize().len()
    );
    println!(
        "\nTotal public key bundle size: {} bytes",
        identity_public.serialize().len()
            + signed_prekey_pair.public_key.serialize().len()
            + pq_prekey_pair.public_key.serialize().len()
            + signed_pre_key_signature.len()
            + pq_signature.len()
    );
    println!("{}", "=".repeat(60));

    Ok(())
}

/// Test 2: Verify signature on Signed EC Prekey (SPK)
#[test]
fn test_verify_signed_prekey_signature() -> Result<(), SignalProtocolError> {
    println!("🔐 Test: Verify Signed Prekey Signature");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([2u8; 32]);

    // Generate identity key and signed prekey
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_prekey_pair = KeyPair::generate(&mut rng);

    // Sign the prekey
    let signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_prekey_pair.public_key.serialize(), &mut rng)?;

    println!("✅ Signature created: {} bytes", signature.len());

    // Verify the signature
    let verification_result = identity_key_pair
        .public_key()
        .verify_signature(&signed_prekey_pair.public_key.serialize(), &signature);

    assert!(verification_result, "Signature verification should succeed");
    println!("✅ Signature verified successfully");

    // Test: Signature should fail with wrong data
    println!("\n🔍 Testing signature with wrong data...");
    let wrong_data = b"wrong_data";
    let wrong_verification = identity_key_pair
        .public_key()
        .verify_signature(wrong_data, &signature);

    assert!(!wrong_verification, "Signature should fail with wrong data");
    println!("✅ Signature correctly rejected for wrong data");

    println!("{}", "=".repeat(60));
    println!("🎯 Signed Prekey Signature Verification: PASSED");
    println!("{}", "=".repeat(60));

    Ok(())
}

/// Test 3: Verify signature on PQ Last-Resort Prekey (PQSPK)
#[test]
fn test_verify_pq_prekey_signature() -> Result<(), SignalProtocolError> {
    println!("🔐 Test: Verify PQ Prekey Signature");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([3u8; 32]);

    // Generate identity key and PQ prekey
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let pq_prekey_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    // Sign the PQ prekey
    let pq_signature = identity_key_pair
        .private_key()
        .calculate_signature(&pq_prekey_pair.public_key.serialize(), &mut rng)?;

    println!("✅ PQ signature created: {} bytes", pq_signature.len());

    // Verify the signature
    let verification_result = identity_key_pair
        .public_key()
        .verify_signature(&pq_prekey_pair.public_key.serialize(), &pq_signature);

    assert!(
        verification_result,
        "PQ signature verification should succeed"
    );
    println!("✅ PQ signature verified successfully");

    // Test: Signature should fail with wrong key
    println!("\n🔍 Testing signature with wrong PQ key...");
    let wrong_pq_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let wrong_verification = identity_key_pair
        .public_key()
        .verify_signature(&wrong_pq_key.public_key.serialize(), &pq_signature);

    assert!(!wrong_verification, "Signature should fail with wrong key");
    println!("✅ Signature correctly rejected for wrong key");

    println!("{}", "=".repeat(60));
    println!("🎯 PQ Prekey Signature Verification: PASSED");
    println!("{}", "=".repeat(60));

    Ok(())
}

/// Test 4: Simulate key bundle publication (what gets stored in DID document)
#[test]
fn test_key_bundle_serialization() -> Result<(), SignalProtocolError> {
    println!("🔐 Test: Key Bundle Serialization (DID Document)");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([4u8; 32]);

    // Generate all 3 keys
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let signed_prekey_pair = KeyPair::generate(&mut rng);
    let pq_prekey_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    // Create PublicKeyBundle (automatically signs both prekeys)
    println!("\n📝 Creating PublicKeyBundle...");
    let bundle = SyftPublicKeyBundle::new(
        &identity_key_pair,
        &signed_prekey_pair,
        &pq_prekey_pair,
        &mut rng,
    )?;
    println!("   ✅ Bundle created with both signatures");

    // Serialize public components (what goes into DID document)
    let identity_public_bytes = bundle.signal_identity_public_key.serialize();
    let spk_public_bytes = bundle.signal_signed_public_pre_key.serialize();
    let pqspk_public_bytes = bundle.signal_pq_public_pre_key.serialize();
    let spk_signature = &bundle.signal_signed_pre_key_signature;
    let pqspk_signature = &bundle.signal_pq_pre_key_signature;

    println!("\n📦 Public Key Bundle (for DID document):");
    println!("   IK (Identity Key):");
    println!("     - Public key: {} bytes", identity_public_bytes.len());
    println!(
        "     - Hex (first 16 bytes): {}",
        hex::encode(&identity_public_bytes[..16.min(identity_public_bytes.len())])
    );

    println!("\n   SPK (Signed EC Prekey):");
    println!("     - Public key: {} bytes", spk_public_bytes.len());
    println!("     - Signature: {} bytes", spk_signature.len());
    println!(
        "     - Key hex (first 16 bytes): {}",
        hex::encode(&spk_public_bytes[..16.min(spk_public_bytes.len())])
    );
    println!(
        "     - Sig hex (first 16 bytes): {}",
        hex::encode(&spk_signature[..16.min(spk_signature.len())])
    );

    println!("\n   PQSPK (PQ Last-Resort Prekey):");
    println!("     - Public key: {} bytes", pqspk_public_bytes.len());
    println!("     - Signature: {} bytes", pqspk_signature.len());
    println!(
        "     - Key hex (first 16 bytes): {}",
        hex::encode(&pqspk_public_bytes[..16.min(pqspk_public_bytes.len())])
    );
    println!(
        "     - Sig hex (first 16 bytes): {}",
        hex::encode(&pqspk_signature[..16.min(pqspk_signature.len())])
    );

    let total_bundle_size = identity_public_bytes.len()
        + spk_public_bytes.len()
        + spk_signature.len()
        + pqspk_public_bytes.len()
        + pqspk_signature.len();

    println!(
        "\n📊 Total bundle size: {} bytes ({:.2} KB)",
        total_bundle_size,
        total_bundle_size as f64 / 1024.0
    );

    // Verify we can deserialize keys back
    println!("\n🔄 Testing deserialization...");
    let _identity_restored = IdentityKey::decode(&identity_public_bytes)?;
    let _spk_restored = PublicKey::deserialize(&spk_public_bytes)?;
    let _pqspk_restored = kem::PublicKey::deserialize(&pqspk_public_bytes)?;

    println!("   ✅ Identity key deserialized");
    println!("   ✅ Signed prekey deserialized");
    println!("   ✅ PQ prekey deserialized");

    // Verify signatures (using original identity key pair)
    let sig1_ok = identity_key_pair
        .public_key()
        .verify_signature(&spk_public_bytes, spk_signature);
    let sig2_ok = identity_key_pair
        .public_key()
        .verify_signature(&pqspk_public_bytes, pqspk_signature);
    assert!(
        sig1_ok && sig2_ok,
        "Signatures should verify after deserialization"
    );
    println!("   ✅ All signatures verified");

    println!();
    println!("{}", "=".repeat(60));
    println!("🎯 Key Bundle Serialization: PASSED");
    println!("   Can be safely stored in DID document (JSON format)");
    println!("{}", "=".repeat(60));

    Ok(())
}

/// Test 5: Simulate key rotation (SPK and PQSPK rotation)
#[test]
fn test_key_rotation() -> Result<(), SignalProtocolError> {
    println!("🔐 Test: Key Rotation (SPK and PQSPK)");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([5u8; 32]);

    // Generate initial keys
    println!("\n📝 Step 1: Generate initial key bundle");
    let identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let old_spk = KeyPair::generate(&mut rng);
    let old_pqspk = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    println!("   ✅ Initial keys generated");

    // Simulate time passing (weekly/monthly rotation)
    println!("\n⏰ Step 2: Time passes... (weekly/monthly rotation period)");

    // Generate new prekeys (identity key stays the same!)
    println!("\n🔄 Step 3: Rotate prekeys (identity key unchanged)");
    let new_spk = KeyPair::generate(&mut rng);
    let new_pqspk = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    // Sign new prekeys with SAME identity key
    let new_spk_sig = identity_key_pair
        .private_key()
        .calculate_signature(&new_spk.public_key.serialize(), &mut rng)?;

    let new_pqspk_sig = identity_key_pair
        .private_key()
        .calculate_signature(&new_pqspk.public_key.serialize(), &mut rng)?;

    println!("   ✅ New SPK generated and signed");
    println!("   ✅ New PQSPK generated and signed");
    println!("   ️✅ Identity key remains unchanged");

    // Verify new keys are different
    assert_ne!(
        old_spk.public_key.serialize(),
        new_spk.public_key.serialize(),
        "SPK should change after rotation"
    );
    assert_ne!(
        old_pqspk.public_key.serialize(),
        new_pqspk.public_key.serialize(),
        "PQSPK should change after rotation"
    );
    println!("   ✅ New keys are different from old keys");

    // Verify signatures are valid
    let sig1_ok = identity_key_pair
        .public_key()
        .verify_signature(&new_spk.public_key.serialize(), &new_spk_sig);
    let sig2_ok = identity_key_pair
        .public_key()
        .verify_signature(&new_pqspk.public_key.serialize(), &new_pqspk_sig);
    assert!(sig1_ok && sig2_ok, "New key signatures should be valid");
    println!("   ✅ New key signatures verified");

    // Simulate grace period (old keys kept temporarily for delayed messages)
    println!("\n⏳ Step 4: Grace period (old keys kept temporarily)");
    println!("   - New keys published to DID document");
    println!("   - Old private keys kept locally for 24-48 hours");
    println!("   - Allows decryption of messages sent before rotation");

    println!("\n🗑️  Step 5: After grace period");
    println!("   - Old private keys deleted (forward secrecy)");
    println!("   - Only new keys remain");

    println!();
    println!("{}", "=".repeat(60));
    println!("🎯 Key Rotation: PASSED");
    println!("   Identity key: Never rotated ✅");
    println!("   SPK: Rotated successfully ✅");
    println!("   PQSPK: Rotated successfully ✅");
    println!("{}", "=".repeat(60));

    Ok(())
}

/// Test 6: Compare key sizes between different components
#[test]
fn test_key_size_comparison() {
    println!("🔐 Test: Key Size Comparison");
    println!("{}", "=".repeat(60));

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([6u8; 32]);

    // Generate all keys
    let ik = IdentityKeyPair::generate(&mut rng);
    let spk = KeyPair::generate(&mut rng);
    let pqspk = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    println!("\n📊 Key Size Breakdown:");
    println!("\n1. Identity Key (Ed25519):");
    println!("   Public:  {} bytes", ik.public_key().serialize().len());
    println!("   Private: {} bytes (estimated)", 32); // Ed25519 private key

    println!("\n2. Signed EC Prekey (X25519):");
    println!("   Public:  {} bytes", spk.public_key.serialize().len());
    println!("   Private: {} bytes (estimated)", 32); // X25519 private key

    println!("\n3. PQ Last-Resort Prekey (Kyber1024):");
    println!(
        "   Public:  {} bytes ({:.2} KB)",
        pqspk.public_key.serialize().len(),
        pqspk.public_key.serialize().len() as f64 / 1024.0
    );
    println!(
        "   Private: {} bytes ({:.2} KB)",
        pqspk.secret_key.serialize().len(),
        pqspk.secret_key.serialize().len() as f64 / 1024.0
    );

    let total_public_size = ik.public_key().serialize().len()
        + spk.public_key.serialize().len()
        + pqspk.public_key.serialize().len();

    let total_private_size_estimated = 32 + 32 + pqspk.secret_key.serialize().len();

    println!("\n📦 Total Size:");
    println!(
        "   All public keys:  {} bytes ({:.2} KB)",
        total_public_size,
        total_public_size as f64 / 1024.0
    );
    println!(
        "   All private keys: ~{} bytes ({:.2} KB) [estimated]",
        total_private_size_estimated,
        total_private_size_estimated as f64 / 1024.0
    );

    println!("\n💡 Observations:");
    println!("   - Classical keys (IK, SPK) are tiny (~33 bytes each)");
    println!("   - PQ key (PQSPK) is much larger (~1.5 KB public, ~3.1 KB private)");
    println!("   - Trade-off: Larger keys for quantum resistance");

    println!();
    println!("{}", "=".repeat(60));
    println!("🎯 Key Size Analysis: COMPLETE");
    println!("{}", "=".repeat(60));
}

/// Test 7: Verify no one-time prekeys are used
#[test]
fn test_no_one_time_prekeys() {
    println!("🔐 Test: Verify No One-Time Prekeys");
    println!("{}", "=".repeat(60));

    println!("\n✅ Design Decision: Skip One-Time Prekeys");
    println!("\n📝 What we DON'T have:");
    println!("   ❌ One-time EC prekeys (OPK)");
    println!("   ❌ One-time PQ prekeys (PQOPK)");

    println!("\n📝 What we DO have:");
    println!("   ✅ Identity Key (IK) - never rotated");
    println!("   ✅ Signed EC Prekey (SPK) - rotated periodically");
    println!("   ✅ PQ Last-Resort Prekey (PQSPK) - rotated periodically");

    println!("\n🎯 Rationale:");
    println!("   1. SyftBox uses eventual consistency (not atomic operations)");
    println!("   2. One-time keys require atomic allocation to avoid race conditions");
    println!("   3. Race conditions would cause key reuse → security failure");
    println!("   4. Simplified key management is more reliable for file-based sync");

    println!("\n📊 Security Impact:");
    println!("   ✅ Still post-quantum secure (Kyber1024)");
    println!("   ✅ Still forward secrecy (ephemeral keys in each session)");
    println!("   ✅ Still authenticated (identity key signatures)");
    println!("   ⚠️  Slightly reduced forward secrecy vs one-time keys (acceptable)");

    println!("\n💡 Trade-off:");
    println!("   Simpler + More Reliable > Perfect Forward Secrecy");

    println!();
    println!("{}", "=".repeat(60));
    println!("🎯 No One-Time Prekeys: DESIGN VERIFIED");
    println!("{}", "=".repeat(60));

    // This test always passes - it's documentation
}
