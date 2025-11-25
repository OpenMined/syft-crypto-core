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
use sha2::{Digest, Sha256};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compute SHA-256 fingerprint of any public key bytes.
pub fn compute_key_fingerprint(key_bytes: &[u8]) -> String {
    let hash = Sha256::digest(key_bytes);
    hex::encode(hash)
}

/// Compute SHA-256 fingerprint of an identity public key.
///
/// Convenience wrapper around `compute_key_fingerprint` for identity keys specifically.
///
/// # Arguments
/// * `identity_key` - The identity public key
///
/// # Returns
/// A 64-character hex string representing the SHA-256 hash of the public key bytes
///
/// # Example
/// ```
/// use syft_crypto_protocol::{SyftRecoveryKey, compute_identity_fingerprint};
///
/// let recovery_key = SyftRecoveryKey::generate();
/// let private_keys = recovery_key.derive_keys().unwrap();
/// let fingerprint = compute_identity_fingerprint(private_keys.identity().identity_key());
/// assert_eq!(fingerprint.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
/// ```
pub fn compute_identity_fingerprint(identity_key: &IdentityKey) -> String {
    compute_key_fingerprint(&identity_key.serialize())
}

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

    /// Convert recovery key to a BIP39 mnemonic phrase (24 words).
    pub fn to_mnemonic(&self) -> String {
        use bip39::{Language, Mnemonic};

        // BIP39 with 32 bytes = 24 words (256 bits entropy)
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &self.0)
            .expect("32 bytes should always create valid mnemonic");

        mnemonic.to_string()
    }

    /// Parse a BIP39 mnemonic phrase back into a recovery key.
    pub fn from_mnemonic(phrase: &str) -> RecoveryResult<Self> {
        use bip39::{Language, Mnemonic};

        // Normalize to lowercase and clean whitespace for BIP39 library
        let normalized = phrase
            .split_whitespace()
            .map(|word| word.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        // Parse mnemonic
        let mnemonic = Mnemonic::parse_in(Language::English, &normalized)
            .map_err(|e| RecoveryError::MnemonicError(e.to_string()))?;

        // Get the entropy (should be 32 bytes for 24-word mnemonic)
        let entropy = mnemonic.to_entropy();

        if entropy.len() != 32 {
            return Err(RecoveryError::InvalidLength {
                expected: 32,
                actual: entropy.len(),
            });
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&entropy);

        // Verify minimum entropy
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

        let mut seen = [false; 256];
        for &byte in bytes {
            seen[byte as usize] = true;
        }
        seen.iter().filter(|&&present| present).count() >= 8
    }

    /// Get raw bytes (for internal use only)
    ///
    /// # Security
    /// This should only be used internally for key derivation.
    /// Never expose these bytes to external APIs.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive all private keys from this recovery key using HKDF-SHA256.
    ///
    /// This is deterministic - the same recovery key will always produce the same keys.
    ///
    /// # Example
    /// ```
    /// use syft_crypto_protocol::SyftRecoveryKey;
    /// let recovery_key = SyftRecoveryKey::generate();
    /// let private_keys = recovery_key.derive_keys().expect("derivation should succeed");
    /// ```
    pub fn derive_keys(&self) -> RecoveryResult<SyftPrivateKeys> {
        use hkdf::Hkdf;
        use rand::SeedableRng;
        use sha2::Sha256;

        let recovery_key_bytes = self.as_bytes();

        // HKDF instance for all key derivations
        let hk = Hkdf::<Sha256>::new(None, recovery_key_bytes);

        // 1. Derive identity key pair (Ed25519)
        let mut identity_seed = [0u8; 32];
        hk.expand(b"SyftBox_Identity_Key_v1", &mut identity_seed)
            .map_err(|_| RecoveryError::DerivationFailed)?;

        let mut identity_rng = rand::rngs::StdRng::from_seed(identity_seed);
        let signal_identity_key_pair = IdentityKeyPair::generate(&mut identity_rng);

        // 2. Derive signed prekey (X25519)
        let mut spk_seed = [0u8; 32];
        hk.expand(b"SyftBox_Signed_Prekey_v1", &mut spk_seed)
            .map_err(|_| RecoveryError::DerivationFailed)?;

        let mut spk_rng = rand::rngs::StdRng::from_seed(spk_seed);
        let signal_signed_pre_key_pair = KeyPair::generate(&mut spk_rng);

        // 3. Derive PQ prekey (Kyber1024)
        let mut pqspk_seed = [0u8; 32];
        hk.expand(b"SyftBox_PQ_Prekey_v1", &mut pqspk_seed)
            .map_err(|_| RecoveryError::DerivationFailed)?;

        let mut pqspk_rng = rand::rngs::StdRng::from_seed(pqspk_seed);
        let signal_pq_signed_pre_key_pair =
            kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut pqspk_rng);

        Ok(SyftPrivateKeys {
            signal_identity_key_pair: Sensitive::new(signal_identity_key_pair),
            signal_signed_pre_key_pair: Sensitive::new(signal_signed_pre_key_pair),
            signal_pq_signed_pre_key_pair: Sensitive::new(signal_pq_signed_pre_key_pair),
        })
    }
}

/// Container for all private key material needed for PQXDH.
///
/// Bundles identity key pair (Ed25519), signed prekey pair (X25519), and PQ prekey pair (Kyber1024).
pub struct SyftPrivateKeys {
    /// Ed25519 identity key pair for signing (wrapped to ensure zeroization).
    signal_identity_key_pair: Sensitive<IdentityKeyPair>,
    /// X25519 signed prekey pair for ECDH (wrapped to ensure zeroization).
    signal_signed_pre_key_pair: Sensitive<KeyPair>,
    /// Kyber1024 PQ signed prekey for KEM (wrapped to ensure zeroization).
    signal_pq_signed_pre_key_pair: Sensitive<kem::KeyPair>,
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
///
/// # Why This Exists
///
/// Ideally we would use `zeroize::Zeroizing<T>` which provides safe, guaranteed
/// zeroization. However, the libsignal-protocol types (`IdentityKeyPair`, `KeyPair`,
/// `kem::KeyPair`) do not implement the `Zeroize` trait, so we cannot use the safe API.
///
/// If libsignal-protocol-syft added `Zeroize` implementations for its key types,
/// this wrapper could be removed entirely in favor of `Zeroizing<T>`.
///
/// # Why Unsafe Is Required
///
/// 1. **Volatile writes** (`std::ptr::write_volatile`): Required to prevent the
///    compiler from optimizing away the zeroization as a "dead store". There is
///    no safe API for volatile memory writes in Rust.
///
/// 2. **ManuallyDrop::drop**: Required to drop the inner value in-place without
///    creating a copy. This is unsafe because calling it twice would cause UB.
///
/// # Implementation
///
/// - The inner value is dropped first (in place, no copy created)
/// - Memory is then zeroed using volatile writes
/// - A guard struct ensures zeroization runs even if the inner Drop panics
/// - A compiler fence prevents reordering of the volatile writes
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
        // Guard struct ensures zeroization runs even if dropping `T` panics.
        // When this guard is dropped (either normally or during unwinding),
        // it will zero the memory.
        struct ZeroizeGuard {
            ptr: *mut u8,
            size: usize,
        }

        impl Drop for ZeroizeGuard {
            fn drop(&mut self) {
                // SAFETY: We have exclusive access to this memory (we're in Drop),
                // and the pointer was derived from a valid ManuallyDrop<T>.
                // Volatile writes prevent dead-store elimination.
                unsafe {
                    for i in 0..self.size {
                        std::ptr::write_volatile(self.ptr.add(i), 0);
                    }
                    // Ensure writes are not reordered past this point
                    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        let guard = ZeroizeGuard {
            ptr: (&mut self.0 as *mut ManuallyDrop<T>).cast::<u8>(),
            size: std::mem::size_of::<T>(),
        };

        // SAFETY: We only call this once, and self.0 is valid.
        // We use ManuallyDrop specifically to control drop timing.
        unsafe { ManuallyDrop::drop(&mut self.0) };

        // Guard drops here (or on unwind), zeroing the memory
        drop(guard);
    }
}

/// Bundle of public keys and signatures for publishing in DID documents.
#[derive(Clone)]
pub struct SyftPublicKeyBundle {
    pub signal_identity_public_key: IdentityKey,
    pub signal_signed_public_pre_key: PublicKey,
    pub signal_signed_pre_key_signature: Box<[u8]>,
    pub signal_pq_public_pre_key: kem::PublicKey,
    pub signal_pq_pre_key_signature: Box<[u8]>,
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
            signal_identity_public_key: *identity_key_pair.identity_key(),
            signal_signed_public_pre_key: signed_pre_key_pair.public_key,
            signal_signed_pre_key_signature: signed_pre_key_signature,
            signal_pq_public_pre_key: pq_pre_key_pair.public_key.clone(),
            signal_pq_pre_key_signature: pq_pre_key_signature,
        })
    }

    /// Verify both signatures in the bundle.
    pub fn verify_signatures(&self) -> bool {
        let ec_sig_valid = self
            .signal_identity_public_key
            .public_key()
            .verify_signature(
                &self.signal_signed_public_pre_key.serialize(),
                &self.signal_signed_pre_key_signature,
            );

        let pq_sig_valid = self
            .signal_identity_public_key
            .public_key()
            .verify_signature(
                &self.signal_pq_public_pre_key.serialize(),
                &self.signal_pq_pre_key_signature,
            );

        ec_sig_valid && pq_sig_valid
    }

    /// Compute and return the identity public key fingerprint.
    pub fn identity_fingerprint(&self) -> String {
        compute_identity_fingerprint(&self.signal_identity_public_key)
    }

    /// Get the total size of the bundle in bytes.
    pub fn total_size(&self) -> usize {
        self.signal_identity_public_key.serialize().len()
            + self.signal_signed_public_pre_key.serialize().len()
            + self.signal_signed_pre_key_signature.len()
            + self.signal_pq_public_pre_key.serialize().len()
            + self.signal_pq_pre_key_signature.len()
    }
}
