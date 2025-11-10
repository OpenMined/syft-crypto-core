//! Key structures for SyftBox PQXDH protocol
//!
//! This module defines the key types used in the SyftBox PQXDH protocol:
//! - SyftRecoveryKey: 32-byte master secret for deterministic key derivation
//! - SyftPrivateKeys: Container for all private key material
//! - SyftPublicKeyBundle: Container for all public keys and signatures
//!
//! The Syft keys wrap libsignal_protocol keys:
//! - IdentityKeyPair: Ed25519 keypair for signing
//! - SignedPreKey: X25519 keypair for ECDH
//! - PQSignedPreKey: Kyber1024 keypair for post-quantum KEM

use crate::error::{RecoveryError, RecoveryResult};
use libsignal_protocol::{IdentityKey, IdentityKeyPair, KeyPair, PublicKey, kem};
use rand::RngCore;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte recovery key that deterministically derives all private keys.
///
/// This is the MASTER secret that can regenerate all private keys.
/// Users must write down the 64-character hex representation for backup.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SyftRecoveryKey([u8; 32]);

impl std::fmt::Debug for SyftRecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyftRecoveryKey")
            .field(
                "first_4_bytes",
                &format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    self.0[0], self.0[1], self.0[2], self.0[3]
                ),
            )
            .field("remaining", &"<redacted 28 bytes>")
            .finish()
    }
}

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
#[allow(private_interfaces)]
pub struct SyftPrivateKeys {
    /// Ed25519 identity key pair for signing (wrapped to ensure zeroization).
    pub signal_identity_key_pair: Sensitive<IdentityKeyPair>,
    /// X25519 signed prekey pair for ECDH (wrapped to ensure zeroization).
    pub signal_signed_pre_key_pair: Sensitive<KeyPair>,
    /// Kyber1024 PQ signed prekey for KEM (wrapped to ensure zeroization).
    pub signal_pq_signed_pre_key_pair: Sensitive<kem::KeyPair>,
}

impl SyftPrivateKeys {
    /// Create a new container for private key material.
    pub fn new(
        identity: IdentityKeyPair,
        signed_pre_key: KeyPair,
        pq_signed_pre_key: kem::KeyPair,
    ) -> Self {
        Self {
            signal_identity_key_pair: Sensitive::new(identity),
            signal_signed_pre_key_pair: Sensitive::new(signed_pre_key),
            signal_pq_signed_pre_key_pair: Sensitive::new(pq_signed_pre_key),
        }
    }

    /// Borrow the identity key pair.
    pub fn identity(&self) -> &IdentityKeyPair {
        &self.signal_identity_key_pair
    }

    /// Borrow the signed prekey pair.
    pub fn signed_pre_key(&self) -> &KeyPair {
        &self.signal_signed_pre_key_pair
    }

    /// Borrow the PQ signed prekey pair.
    pub fn pq_signed_pre_key(&self) -> &kem::KeyPair {
        &self.signal_pq_signed_pre_key_pair
    }

    /// Create public key bundle with all public keys and signatures.
    pub fn to_public_bundle<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: &mut R,
    ) -> Result<SyftPublicKeyBundle, libsignal_protocol::SignalProtocolError> {
        SyftPublicKeyBundle::new(
            self.identity(),
            self.signed_pre_key(),
            self.pq_signed_pre_key(),
            rng,
        )
    }
}

/// Wrapper that zeroizes contained data immediately after it has been dropped.
struct Sensitive<T>(ManuallyDrop<T>);

impl<T> Sensitive<T> {
    fn new(value: T) -> Self {
        Self(ManuallyDrop::new(value))
    }
}

impl<T> Deref for Sensitive<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Sensitive<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Drop for Sensitive<T> {
    fn drop(&mut self) {
        unsafe {
            // Drop the inner value first so any heap allocations are freed.
            ManuallyDrop::drop(&mut self.0);
            // Then zeroize the now-dropped memory to clear residual key material.
            let ptr = (&mut self.0 as *mut ManuallyDrop<T>).cast::<u8>();
            std::ptr::write_bytes(ptr, 0, std::mem::size_of::<T>());
        }
    }
}

/// Bundle of public keys and signatures for publishing in DID documents.
#[derive(Clone)]
pub struct SyftPublicKeyBundle {
    pub identity_public_key: IdentityKey,
    pub signed_public_pre_key: PublicKey,
    pub signed_pre_key_signature: Box<[u8]>,
    pub pq_public_pre_key: kem::PublicKey,
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
            identity_public_key: *identity_key_pair.identity_key(),
            signed_public_pre_key: signed_pre_key_pair.public_key,
            signed_pre_key_signature,
            pq_public_pre_key: pq_pre_key_pair.public_key.clone(),
            pq_pre_key_signature,
        })
    }

    /// Verify both signatures in the bundle.
    pub fn verify_signatures(&self) -> bool {
        let ec_sig_valid = self.identity_public_key.public_key().verify_signature(
            &self.signed_public_pre_key.serialize(),
            &self.signed_pre_key_signature,
        );

        let pq_sig_valid = self.identity_public_key.public_key().verify_signature(
            &self.pq_public_pre_key.serialize(),
            &self.pq_pre_key_signature,
        );

        ec_sig_valid && pq_sig_valid
    }

    /// Get the total size of the bundle in bytes.
    pub fn total_size(&self) -> usize {
        self.identity_public_key.serialize().len()
            + self.signed_public_pre_key.serialize().len()
            + self.signed_pre_key_signature.len()
            + self.pq_public_pre_key.serialize().len()
            + self.pq_pre_key_signature.len()
    }
}
