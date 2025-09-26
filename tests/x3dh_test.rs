use libsignal_protocol::*;
use rand::SeedableRng;

/// Test X3DH key component generation
///
/// This demonstrates the basic cryptographic building blocks of X3DH:
/// - Identity key pairs (IK_A, IK_B) - long-term authentication keys
/// - Signed prekeys (SPK_B) - medium-term keys signed by identity key
/// - One-time prekeys (OPK_B) - ephemeral keys for forward secrecy
/// - Kyber keys for post-quantum security
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

    // Generate Kyber post-quantum keys
    let bob_kyber_prekey_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let bob_kyber_signature = bob_identity
        .private_key()
        .calculate_signature(&bob_kyber_prekey_pair.public_key.serialize(), &mut rng)?;

    assert!(!bob_kyber_prekey_pair.public_key.serialize().is_empty());
    assert_eq!(bob_kyber_signature.len(), 64);
    println!("✅ Kyber post-quantum keys generated");

    println!("🎯 All X3DH cryptographic components created successfully!");
    Ok(())
}
