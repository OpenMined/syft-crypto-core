//! Key structures for PQXDH protocol
//!
//! This module defines the key types used in the PQXDH protocol:
//! - RecoveryKey: 32-byte master secret for deterministic key derivation
//! - IdentityKeyPair: Ed25519 keypair for signing (wraps libsignal)
//! - SignedPreKey: X25519 keypair for ECDH (wraps libsignal)
//! - PQSignedPreKey: Kyber1024 keypair for post-quantum KEM (wraps libsignal)
//! - PrivateKeys: Container for all private key material

use crate::error::{RecoveryError, RecoveryResult};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PublicKey, kem};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte recovery key that deterministically derives all private keys.
///
/// This is the MASTER secret that can regenerate all private keys.
/// Users must write down the 64-character hex representation for backup.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SyftRecoveryKey([u8; 32]);

impl SyftRecoveryKey {
    /// Generate a new random recovery key with 256 bits of entropy.
    pub fn generate() -> Self {
        loop {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            if Self::has_min_entropy(&key) {
                return Self(key);
            }
        }
    }

    /// Format: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
    /// (16 groups of 4 chars)
    pub fn to_hex_string(&self) -> String {
        let hex = hex::encode(self.0);
        hex.as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).expect("hex encoding is ASCII"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse from hex string (with or without dashes).
    ///
    /// Accepts 64 hex characters in any format (dashes and spaces are ignored).
    pub fn from_hex_string(s: &str) -> RecoveryResult<Self> {
        // Remove readability separators while rejecting unexpected characters.
        let mut cleaned = String::with_capacity(64);
        for ch in s.chars() {
            if ch.is_ascii_hexdigit() {
                cleaned.push(ch);
            } else if matches!(ch, '-' | ' ' | '\n' | '\r' | '\t') {
                continue;
            } else {
                return Err(RecoveryError::InvalidHex(format!(
                    "unexpected character '{ch}' in recovery key"
                )));
            }
        }

        if cleaned.len() != 64 {
            return Err(RecoveryError::InvalidLength {
                expected: 64,
                actual: cleaned.len(),
            });
        }

        let bytes = hex::decode(&cleaned).map_err(|e| RecoveryError::InvalidHex(e.to_string()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);

        if !Self::has_min_entropy(&key) {
            return Err(RecoveryError::InsufficientEntropy);
        }

        Ok(Self(key))
    }

    fn has_min_entropy(bytes: &[u8; 32]) -> bool {
        if bytes.iter().all(|&b| b == 0) {
            return false;
        }

        if bytes.windows(2).all(|w| w[0] == w[1]) {
            return false;
        }

        true
    }

    /// Get raw bytes (for internal use only)
    ///
    /// # Security
    /// This should only be used internally for key derivation.
    /// Never expose these bytes to external APIs.
    #[allow(dead_code)] // Used in upcoming key-derivation logic
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Container for all private key material needed for PQXDH.
///
/// Bundles identity key pair (Ed25519), signed prekey pair (X25519), and PQ prekey pair (Kyber1024).
pub struct SyftPrivateKeys {
    /// Ed25519 identity key pair for signing
    pub identity: IdentityKeyPair,
    /// X25519 signed prekey pair for ECDH
    pub signed_pre_key: KeyPair,
    /// Kyber1024 PQ signed prekey for KEM
    pub pq_signed_pre_key: kem::KeyPair,
}

impl SyftPrivateKeys {
    // pub fn from_recovery_key(recovery_key: &SyftRecoveryKey) -> Result<Self> {
    //     // Derive seed material with HKDF
    //     // Create KeyPair and kem::KeyPair from seeds
    //     unimplemented!()
    // }

    /// Create public key bundle with all public keys and signatures.
    pub fn to_public_bundle(&self) -> SyftPublicKeyBundle {
        SyftPublicKeyBundle::new(
            &self.identity,
            &self.signed_pre_key,
            &self.pq_signed_pre_key,
            &mut rand::rng(),
        )
        .expect("signing should never fail with valid keys")
    }
}

/// Bundle of public keys for publishing in DID documents.
///
/// Contains identity key and signed prekeys that can be fetched by message senders.
#[derive(Clone)]
pub struct SyftPublicKeyBundle {
    pub identity_key: IdentityKey,
    pub signed_pre_key: PublicKey,
    pub signed_pre_key_signature: Box<[u8]>,
    pub pq_pre_key: kem::PublicKey,
    pub pq_pre_key_signature: Box<[u8]>,
}

impl SyftPublicKeyBundle {
    /// Create a new public key bundle from an identity key pair and prekey pairs.
    ///
    /// This will sign both prekeys with the identity private key.
    pub fn new<R: rand::CryptoRng + rand::Rng>(
        identity_key_pair: &IdentityKeyPair,
        signed_pre_key_pair: &KeyPair,
        pq_pre_key_pair: &kem::KeyPair,
        rng: &mut R,
    ) -> Result<Self, libsignal_protocol::SignalProtocolError> {
        // Sign the EC prekey
        let signed_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&signed_pre_key_pair.public_key.serialize(), rng)?;

        // Sign the PQ prekey
        let pq_pre_key_signature = identity_key_pair
            .private_key()
            .calculate_signature(&pq_pre_key_pair.public_key.serialize(), rng)?;

        Ok(Self {
            identity_key: *identity_key_pair.identity_key(),
            signed_pre_key: signed_pre_key_pair.public_key,
            signed_pre_key_signature,
            pq_pre_key: pq_pre_key_pair.public_key.clone(),
            pq_pre_key_signature,
        })
    }

    /// Verify both signatures in the bundle.
    pub fn verify_signatures(&self) -> bool {
        let ec_sig_valid = self.identity_key.public_key().verify_signature(
            &self.signed_pre_key.serialize(),
            &self.signed_pre_key_signature,
        );

        let pq_sig_valid = self
            .identity_key
            .public_key()
            .verify_signature(&self.pq_pre_key.serialize(), &self.pq_pre_key_signature);

        ec_sig_valid && pq_sig_valid
    }

    /// Get the total size of the bundle in bytes.
    pub fn total_size(&self) -> usize {
        self.identity_key.serialize().len()
            + self.signed_pre_key.serialize().len()
            + self.signed_pre_key_signature.len()
            + self.pq_pre_key.serialize().len()
            + self.pq_pre_key_signature.len()
    }
}
