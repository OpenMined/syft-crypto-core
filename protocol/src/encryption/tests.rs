use crate::{SyftRecoveryKey, error::KeyError};
use rand::{rng, RngCore};
use super::{key_wrap, pqxdh};

#[test]
fn test_pqxdh_round_trip() {
    // Alice and Bob generate their keys
    let mut rng = rng();
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");
    let bob_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("bob key derivation");

    let alice_bundle = alice_keys.to_public_bundle(&mut rng).expect("alice bundle");
    let bob_bundle = bob_keys.to_public_bundle(&mut rng).expect("bob bundle");

    // Alice performs sender-side PQXDH to Bob
    let (alice_material, wrapping_info) = pqxdh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bob_bundle,
        &mut rng,
    )
    .expect("alice PQXDH");

    // Bob performs recipient-side PQXDH from Alice
    let bob_material = pqxdh::derive_recipient_shared_material(
        &bob_keys,
        &alice_bundle,
        &wrapping_info,
    )
    .expect("bob PQXDH");

    // Both should derive the same shared material
    assert_eq!(
        &alice_material[..],
        &bob_material[..],
        "PQXDH materials must match"
    );

    // Material should be ~196 bytes (4×32 DH + 32 Kyber)
    assert!(
        alice_material.len() >= 160 && alice_material.len() <= 200,
        "Expected ~196 bytes, got {}",
        alice_material.len()
    );
}

#[test]
fn test_pqxdh_rejects_invalid_bundle() {
    let mut rng = rng();
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");

    // Create a bundle from different keys (Charlie)
    let charlie_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("charlie key derivation");
    let mut bad_bundle = charlie_keys.to_public_bundle(&mut rng).expect("charlie bundle");

    // Replace identity key with Alice's, but keep Charlie's signatures
    // This creates an invalid bundle (signatures won't match the identity key)
    bad_bundle.signal_identity_public_key = (*alice_keys.identity().public_key()).into();

    // Attempting PQXDH with invalid bundle should fail
    let result = pqxdh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bad_bundle,
        &mut rng,
    );

    assert!(
        result.is_err(),
        "PQXDH should reject bundle with invalid signature"
    );

    if let Err(e) = result {
        assert!(
            matches!(e, KeyError::InvalidSignature),
            "Expected InvalidSignature error, got: {:?}",
            e
        );
    }
}

#[test]
fn test_key_wrapping_round_trip() {
    let mut rng = rng();

    // Generate PQXDH material (simulate successful key agreement)
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");
    let bob_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("bob key derivation");
    let bob_bundle = bob_keys.to_public_bundle(&mut rng).expect("bob bundle");

    let (pqxdh_material, _) = pqxdh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bob_bundle,
        &mut rng,
    )
    .expect("PQXDH");

    // Create a random file key
    let file_key = {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    };

    // Wrap the file key
    let wrapped = key_wrap::wrap_file_key(pqxdh_material.as_ref(), &file_key, &mut rng)
        .expect("wrap file key");

    // Verify wrapped size is exactly 72 bytes (24 nonce + 48 ciphertext+tag)
    assert_eq!(
        wrapped.len(),
        key_wrap::WRAPPED_KEY_SIZE,
        "Wrapped key must be exactly 72 bytes"
    );

    // Unwrap the file key
    let unwrapped = key_wrap::unwrap_file_key(pqxdh_material.as_ref(), &wrapped)
        .expect("unwrap file key");

    // Verify we got the original key back
    assert_eq!(
        &file_key[..],
        &unwrapped[..],
        "Unwrapped key must match original"
    );
}

#[test]
fn test_unwrap_rejects_tampered_data() {
    let mut rng = rng();

    // Generate PQXDH material
    let alice_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("alice key derivation");
    let bob_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("bob key derivation");
    let bob_bundle = bob_keys.to_public_bundle(&mut rng).expect("bob bundle");

    let (pqxdh_material, _) = pqxdh::derive_sender_shared_material(
        &alice_keys,
        "bob@example.org",
        &bob_bundle,
        &mut rng,
    )
    .expect("PQXDH");

    // Wrap a file key
    let file_key = {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    };
    let mut wrapped = key_wrap::wrap_file_key(pqxdh_material.as_ref(), &file_key, &mut rng)
        .expect("wrap file key");

    // Tamper with the ciphertext (flip a bit in the middle)
    wrapped[40] ^= 0x01;

    // Unwrap should fail due to authentication tag mismatch
    let result = key_wrap::unwrap_file_key(pqxdh_material.as_ref(), &wrapped);

    assert!(
        result.is_err(),
        "Unwrap should reject tampered ciphertext"
    );

    if let Err(e) = result {
        assert!(
            matches!(e, KeyError::InvalidSignature),
            "Expected InvalidSignature error for tampered data, got: {:?}",
            e
        );
    }

    // Also test: wrong PQXDH material should fail
    let wrong_material = vec![0u8; pqxdh_material.len()]; // All zeros
    let result = key_wrap::unwrap_file_key(&wrong_material, &wrapped);

    assert!(
        result.is_err(),
        "Unwrap should reject wrong PQXDH material"
    );
}
