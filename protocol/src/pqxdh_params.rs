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

/// Parameters for Sender (initiator) in simplified 3-key PQXDH
///
/// The sender needs:
/// - Their own identity key pair and ephemeral base key
/// - Recipient's public keys: identity, signed prekey, and PQ prekey
pub struct SenderPqxdhParameters {
    // Sender's keys
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,

    // Recipient's public keys
    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_signed_pre_key_signature: Box<[u8]>,
    their_pq_pre_key: kem::PublicKey,
    their_pq_pre_key_signature: Box<[u8]>,
}

impl SenderPqxdhParameters {
    /// Create new parameters for Sender (initiator)
    ///
    /// # Arguments
    /// * `our_identity_key_pair` - Sender's long-term identity key pair
    /// * `our_base_key_pair` - Sender's ephemeral key for this session
    /// * `their_identity_key` - Recipient's identity key (from DID document)
    /// * `their_signed_pre_key` - Recipient's signed EC prekey (from DID document)
    /// * `their_signed_pre_key_signature` - Signature on recipient's EC prekey
    /// * `their_pq_pre_key` - Recipient's PQ last-resort prekey (from DID document)
    /// * `their_pq_pre_key_signature` - Signature on recipient's PQ prekey
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

    // Getters for Sender's keys
    #[inline]
    pub fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    pub fn our_base_key_pair(&self) -> &KeyPair {
        &self.our_base_key_pair
    }

    // Getters for Recipient's public keys
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

/// Parameters for Recipient (responder) in simplified 3-key PQXDH
///
/// The recipient needs:
/// - Their own identity key pair and prekey pairs
/// - Sender's public keys: identity and ephemeral base key
/// - The Kyber ciphertext that the sender generated
pub struct RecipientPqxdhParameters<'a> {
    // Recipient's keys
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: KeyPair,
    our_pq_pre_key_pair: kem::KeyPair,

    // Sender's public keys
    their_identity_key: IdentityKey,
    their_base_key: PublicKey,

    // Kyber ciphertext from Sender
    their_kyber_ciphertext: &'a kem::SerializedCiphertext,
}

impl<'a> RecipientPqxdhParameters<'a> {
    /// Create new parameters for Recipient (responder)
    ///
    /// # Arguments
    /// * `our_identity_key_pair` - Recipient's long-term identity key pair
    /// * `our_signed_pre_key_pair` - Recipient's signed EC prekey pair
    /// * `our_pq_pre_key_pair` - Recipient's PQ last-resort prekey pair
    /// * `their_identity_key` - Sender's identity key (from PreKey message)
    /// * `their_base_key` - Sender's ephemeral key (from PreKey message)
    /// * `their_kyber_ciphertext` - Kyber ciphertext from Sender
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

    // Getters for Recipient's keys
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

    // Getters for Sender's public keys
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
