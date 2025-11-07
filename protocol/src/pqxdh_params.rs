//! Simplified 3-Key PQXDH Parameters for SyftBox
//!
//! This module defines parameter structs for a simplified PQXDH protocol that uses:
//! - Identity Key (IK) - Ed25519, never rotated
//! - Signed EC Prekey (SPK) - X25519, rotated periodically
//! - PQ Last-Resort Prekey (PQSPK) - Kyber1024, rotated periodically
//!
//! Unlike the full Signal protocol, this implementation skips one-time prekeys
//! to avoid race conditions in SyftBox's eventual consistency model.

use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PublicKey, kem};

/// Parameters for Alice (initiator) in simplified 3-key PQXDH
///
/// Alice needs:
/// - Her own identity key pair and ephemeral base key
/// - Bob's public keys: identity, signed prekey, and PQ prekey
pub struct AlicePqxdhParameters {
    // Alice's keys
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,

    // Bob's public keys
    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_signed_pre_key_signature: Box<[u8]>,
    their_pq_pre_key: kem::PublicKey,
    their_pq_pre_key_signature: Box<[u8]>,
}

impl AlicePqxdhParameters {
    /// Create new parameters for Alice (initiator)
    ///
    /// # Arguments
    /// * `our_identity_key_pair` - Alice's long-term identity key pair
    /// * `our_base_key_pair` - Alice's ephemeral key for this session
    /// * `their_identity_key` - Bob's identity key (from DID document)
    /// * `their_signed_pre_key` - Bob's signed EC prekey (from DID document)
    /// * `their_signed_pre_key_signature` - Signature on Bob's EC prekey
    /// * `their_pq_pre_key` - Bob's PQ last-resort prekey (from DID document)
    /// * `their_pq_pre_key_signature` - Signature on Bob's PQ prekey
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_signed_pre_key_signature: Box<[u8]>,
        their_pq_pre_key: kem::PublicKey,
        their_pq_pre_key_signature: Box<[u8]>,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_signed_pre_key_signature,
            their_pq_pre_key,
            their_pq_pre_key_signature,
        }
    }

    // Getters for Alice's keys
    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_base_key_pair(&self) -> &KeyPair {
        &self.our_base_key_pair
    }

    // Getters for Bob's public keys
    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_signed_pre_key(&self) -> &PublicKey {
        &self.their_signed_pre_key
    }

    #[inline]
    pub fn their_signed_pre_key_signature(&self) -> &[u8] {
        &self.their_signed_pre_key_signature
    }

    #[inline]
    pub fn their_pq_pre_key(&self) -> &kem::PublicKey {
        &self.their_pq_pre_key
    }

    #[inline]
    pub fn their_pq_pre_key_signature(&self) -> &[u8] {
        &self.their_pq_pre_key_signature
    }
}

/// Parameters for Bob (responder) in simplified 3-key PQXDH
///
/// Bob needs:
/// - His own identity key pair and prekey pairs
/// - Alice's public keys: identity and ephemeral base key
/// - The Kyber ciphertext that Alice generated
pub struct BobPqxdhParameters<'a> {
    // Bob's keys
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: KeyPair,
    our_pq_pre_key_pair: kem::KeyPair,

    // Alice's public keys
    their_identity_key: IdentityKey,
    their_base_key: PublicKey,

    // Kyber ciphertext from Alice
    their_kyber_ciphertext: &'a kem::SerializedCiphertext,
}

impl<'a> BobPqxdhParameters<'a> {
    /// Create new parameters for Bob (responder)
    ///
    /// # Arguments
    /// * `our_identity_key_pair` - Bob's long-term identity key pair
    /// * `our_signed_pre_key_pair` - Bob's signed EC prekey pair
    /// * `our_pq_pre_key_pair` - Bob's PQ last-resort prekey pair
    /// * `their_identity_key` - Alice's identity key (from PreKey message)
    /// * `their_base_key` - Alice's ephemeral key (from PreKey message)
    /// * `their_kyber_ciphertext` - Kyber ciphertext from Alice
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_pq_pre_key_pair: kem::KeyPair,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: &'a kem::SerializedCiphertext,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_pq_pre_key_pair,
            their_identity_key,
            their_base_key,
            their_kyber_ciphertext,
        }
    }

    // Getters for Bob's keys
    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_signed_pre_key_pair(&self) -> &KeyPair {
        &self.our_signed_pre_key_pair
    }

    #[inline]
    pub fn our_pq_pre_key_pair(&self) -> &kem::KeyPair {
        &self.our_pq_pre_key_pair
    }

    // Getters for Alice's public keys
    #[inline]
    pub fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }

    #[inline]
    pub fn their_base_key(&self) -> &PublicKey {
        &self.their_base_key
    }

    #[inline]
    pub fn their_kyber_ciphertext(&self) -> &kem::SerializedCiphertext {
        self.their_kyber_ciphertext
    }
}
