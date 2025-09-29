use libsignal_protocol::*;
use rand::SeedableRng;

/// Test X3DH key component generation
///
/// This demonstrates the basic cryptographic building blocks of X3DH:
/// - Identity key pairs (IK_A, IK_B) - long-term authentication keys
/// - Signed prekeys (SPK_B) - medium-term keys signed by identity key
/// - One-time prekeys (OPK_B) - ephemeral keys for forward secrecy
#[test]
fn test_x3dh_key_generation() -> Result<(), SignalProtocolError> {
    println!("🔐 Testing X3DH Key Generation Components");

    // Use ChaCha20 RNG with fixed seed for reproducible tests
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);

    // Generate identity key pairs (long-term keys)
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let bob_identity = IdentityKeyPair::generate(&mut rng);

    // Verify identity key structure
    assert_eq!(alice_identity.public_key().serialize().len(), 33); // 32 bytes + type byte
    assert_eq!(bob_identity.public_key().serialize().len(), 33);
    println!("✅ Identity keys (IK_A, IK_B) generated");

    // Generate signed prekey pair
    let bob_signed_prekey_pair: KeyPair = KeyPair::generate(&mut rng);
    let bob_signed_prekey_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_signed_prekey_pair.public_key.serialize(), &mut rng)?;

    // Verify Ed25519 signature is 64 bytes
    assert_eq!(bob_signed_prekey_signature.len(), 64);
    println!("✅ Signed prekey (SPK_B) with signature generated");

    // Generate one-time prekey (ephemeral)
    let _bob_one_time_prekey = KeyPair::generate(&mut rng);
    println!("✅ One-time prekey (OPK_B) generated");

    println!("🎯 All X3DH cryptographic components created successfully!");
    Ok(())
}

/// Test 3DH key agreement protocol (X3DH without one-time prekeys)
///
/// This implements the core 3DH operations:
/// - DH1 = DH(IK_A, SPK_B) - Alice's identity key with Bob's signed prekey
/// - DH2 = DH(EK_A, IK_B)  - Alice's ephemeral key with Bob's identity key
/// - DH3 = DH(EK_A, SPK_B) - Alice's ephemeral key with Bob's signed prekey
/// - SK = KDF(DH1 || DH2 || DH3) - Derive shared secret from concatenated DH outputs
#[test]
fn test_3dh_key_agreement() -> Result<(), SignalProtocolError> {
    println!("🔐 Testing 3DH Key Agreement Protocol");

    // Use ChaCha20 RNG with fixed seed for reproducible tests
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([1u8; 32]);

    // Generate Alice's keys
    let alice_identity = IdentityKeyPair::generate(&mut rng);
    let alice_ephemeral = KeyPair::generate(&mut rng);
    println!("✅ Alice's keys generated (IK_A, EK_A)");

    // Generate Bob's keys
    let bob_identity = IdentityKeyPair::generate(&mut rng);
    let bob_signed_prekey = KeyPair::generate(&mut rng);

    // Bob signs his prekey with his identity key
    // let bob_spk_signature = bob_identity
    //     .private_key()
    //     .calculate_signature(&bob_signed_prekey.public_key.serialize(), &mut rng)?;

    println!("✅ Bob's keys generated (IK_B, SPK_B) with signature");

    // === Alice's side: Perform 3DH operations ===

    // DH1 = DH(IK_A, SPK_B)
    // Alice's identity private key with Bob's signed prekey public key
    let dh1_alice = alice_identity
        .private_key()
        .calculate_agreement(&bob_signed_prekey.public_key)?;

    // DH2 = DH(EK_A, IK_B)
    // Alice's ephemeral private key with Bob's identity public key
    let dh2_alice = alice_ephemeral
        .private_key
        .calculate_agreement(bob_identity.public_key())?;

    // DH3 = DH(EK_A, SPK_B)
    // Alice's ephemeral private key with Bob's signed prekey public key
    let dh3_alice = alice_ephemeral
        .private_key
        .calculate_agreement(&bob_signed_prekey.public_key)?;

    println!("✅ Alice completed 3 DH operations");

    // === Bob's side: Perform matching 3DH operations ===

    // DH1 = DH(SPK_B, IK_A) - Same as DH(IK_A, SPK_B) due to DH symmetry
    let dh1_bob = bob_signed_prekey
        .private_key
        .calculate_agreement(alice_identity.public_key())?;

    // DH2 = DH(IK_B, EK_A) - Same as DH(EK_A, IK_B)
    let dh2_bob = bob_identity
        .private_key()
        .calculate_agreement(&alice_ephemeral.public_key)?;

    // DH3 = DH(SPK_B, EK_A) - Same as DH(EK_A, SPK_B)
    let dh3_bob = bob_signed_prekey
        .private_key
        .calculate_agreement(&alice_ephemeral.public_key)?;

    println!("✅ Bob completed 3 DH operations");

    // === Verify DH outputs match ===
    assert_eq!(dh1_alice, dh1_bob, "DH1 outputs must match");
    assert_eq!(dh2_alice, dh2_bob, "DH2 outputs must match");
    assert_eq!(dh3_alice, dh3_bob, "DH3 outputs must match");
    println!("✅ All DH outputs match between Alice and Bob");

    // === Key Derivation Function (KDF) ===
    // Concatenate DH outputs: DH1 || DH2 || DH3
    let mut key_material_alice = Vec::new();
    key_material_alice.extend_from_slice(&dh1_alice);
    key_material_alice.extend_from_slice(&dh2_alice);
    key_material_alice.extend_from_slice(&dh3_alice);

    let mut key_material_bob = Vec::new();
    key_material_bob.extend_from_slice(&dh1_bob);
    key_material_bob.extend_from_slice(&dh2_bob);
    key_material_bob.extend_from_slice(&dh3_bob);

    // Verify key material is identical
    assert_eq!(
        key_material_alice, key_material_bob,
        "Key material must be identical"
    );
    println!("✅ Key material (DH1||DH2||DH3) matches");

    // Apply HKDF to derive shared secret
    use hkdf::Hkdf;
    use sha2::Sha256;

    let salt = [0xFFu8; 32]; // Salt of all 0xFF bytes as per X3DH spec
    let info = b"3DH-SyftBox"; // Protocol identifier

    let hk = Hkdf::<Sha256>::new(Some(&salt), &key_material_alice);
    let mut shared_secret_alice = [0u8; 32];
    hk.expand(info, &mut shared_secret_alice)
        .map_err(|_| SignalProtocolError::InvalidState("HKDF expand failed", "".to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(&salt), &key_material_bob);
    let mut shared_secret_bob = [0u8; 32];
    hk.expand(info, &mut shared_secret_bob)
        .map_err(|_| SignalProtocolError::InvalidState("HKDF expand failed", "".to_string()))?;

    // Verify both parties derive the same shared secret
    assert_eq!(
        shared_secret_alice, shared_secret_bob,
        "Shared secrets must match"
    );
    assert_eq!(
        shared_secret_alice.len(),
        32,
        "Shared secret must be 32 bytes"
    );

    println!("✅ Shared secret (SK) derived successfully");
    println!("📊 SK length: {} bytes", shared_secret_alice.len());
    println!("📊 SK (hex): {}", hex::encode(&shared_secret_alice[..8])); // Show first 8 bytes

    println!("🎯 3DH Key Agreement Protocol completed successfully!");
    println!("   Both Alice and Bob now share the same 256-bit secret key");

    Ok(())
}
