use libsignal_protocol::{IdentityKeyPair, KeyPair, kem};
use rand::{SeedableRng, rngs::StdRng};
use syft_crypto_protocol::SyftPrivateKeys;

#[test]
fn test_private_keys_getters_expose_expected_material() {
    let mut rng = StdRng::from_seed([42u8; 32]);
    let identity = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key = KeyPair::generate(&mut rng);
    let pq_signed_pre_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    // Keep copies for comparison before moving into SyftPrivateKeys
    let identity_pub_bytes = identity.identity_key().serialize();
    let signed_pre_key_bytes = signed_pre_key.public_key.serialize();
    let pq_pre_key_bytes = pq_signed_pre_key.public_key.serialize();

    let keys = SyftPrivateKeys::new(identity, signed_pre_key, pq_signed_pre_key);

    assert_eq!(
        keys.identity().identity_key().serialize(),
        identity_pub_bytes
    );
    assert_eq!(
        keys.signed_pre_key().public_key.serialize(),
        signed_pre_key_bytes
    );
    assert_eq!(
        keys.pq_signed_pre_key().public_key.serialize(),
        pq_pre_key_bytes
    );
}

#[test]
fn test_to_public_bundle_respects_supplied_rng() {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let identity = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key = KeyPair::generate(&mut rng);
    let pq_signed_pre_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    let keys = SyftPrivateKeys::new(identity, signed_pre_key, pq_signed_pre_key);

    let mut rng1 = StdRng::from_seed([1u8; 32]);
    let mut rng2 = StdRng::from_seed([1u8; 32]);

    let bundle1 = keys
        .to_public_bundle(&mut rng1)
        .expect("bundle creation succeeds");
    let bundle2 = keys
        .to_public_bundle(&mut rng2)
        .expect("bundle creation succeeds");

    assert!(bundle1.verify_signatures());
    assert!(bundle2.verify_signatures());
    // Identical RNG seeds should produce identical deterministic signatures
    assert_eq!(
        bundle1.signal_signed_pre_key_signature.as_ref(),
        bundle2.signal_signed_pre_key_signature.as_ref()
    );
    assert_eq!(
        bundle1.signal_pq_pre_key_signature,
        bundle2.signal_pq_pre_key_signature
    );

    // Different RNG seeds must produce different signatures
    let mut rng3 = StdRng::from_seed([9u8; 32]);
    let bundle3 = keys
        .to_public_bundle(&mut rng3)
        .expect("bundle creation succeeds");
    assert_ne!(
        bundle1.signal_signed_pre_key_signature.as_ref(),
        bundle3.signal_signed_pre_key_signature.as_ref()
    );
    assert_ne!(
        bundle1.signal_pq_pre_key_signature.as_ref(),
        bundle3.signal_pq_pre_key_signature.as_ref()
    );
}

/// Verifies that `SyftPrivateKeys` zeroizes its memory when dropped.
///
/// # Why Unsafe Is Required In This Test
///
/// There is no safe way to verify zeroization because we need to:
/// 1. Control where the value lives in memory (MaybeUninit gives stable address)
/// 2. Drop the value manually (drop_in_place)
/// 3. Read the memory AFTER the value is dropped (normally prevented by Rust)
///
/// This is a security test that verifies implementation details - the unsafe
/// is confined to the test, not the production code being tested.
#[test]
fn test_syft_private_keys_memory_zeroized_on_drop() {
    use std::mem::{MaybeUninit, size_of};

    let mut rng = StdRng::from_seed([99u8; 32]);
    let identity = IdentityKeyPair::generate(&mut rng);
    let signed_pre_key = KeyPair::generate(&mut rng);
    let pq_signed_pre_key = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);

    // Use MaybeUninit to get a stable memory location we can inspect after drop
    let mut slot = MaybeUninit::<SyftPrivateKeys>::uninit();

    // SAFETY: This test intentionally reads memory after drop to verify zeroization.
    // - We write a valid value to the slot
    // - We drop it in place (triggering Sensitive<T>'s zeroization)
    // - We read the raw bytes to verify they are all zero
    // This would be UB in normal code, but is acceptable for security testing.
    unsafe {
        let ptr = slot.as_mut_ptr();
        ptr.write(SyftPrivateKeys::new(
            identity,
            signed_pre_key,
            pq_signed_pre_key,
        ));
        ptr.drop_in_place();

        let raw = std::slice::from_raw_parts(ptr as *const u8, size_of::<SyftPrivateKeys>());
        assert!(
            raw.iter().all(|&b| b == 0),
            "SyftPrivateKeys memory not zeroized: first bytes = {:?}",
            &raw[..raw.len().min(16)]
        );
    }
}
