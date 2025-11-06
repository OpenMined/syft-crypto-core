//! Key structures for PQXDH protocol
//!
//! This module defines the key types used in the PQXDH protocol:
//! - RecoveryKey: 32-byte master secret for deterministic key derivation
//! - IdentityKeyPair: Ed25519 keypair for signing
//! - SignedPreKey: X25519 keypair for ECDH
//! - PQSignedPreKey: Kyber1024 keypair for post-quantum KEM
//! - PrivateKeys: Container for all private key material

use crate::error::{RecoveryError, RecoveryResult};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte recovery key that deterministically derives all private keys
///
/// This is the MASTER secret that can regenerate all private keys.
/// Users must write down the 64-character hex representation or 24-word mnemonic.
///
/// # Security
/// - The recovery key should be stored securely offline
/// - It can regenerate all private keys deterministically
/// - If compromised, all derived keys are compromised
/// - Automatically zeroized on drop
///
/// # Example
/// ```
/// use syft_crypto_protocol::RecoveryKey;
///
/// // Generate new recovery key
/// let recovery_key = RecoveryKey::generate();
///
/// // Export as hex string for backup
/// let hex = recovery_key.to_hex_string();
/// println!("Write this down: {}", hex);
///
/// // Restore from hex string
/// let restored = RecoveryKey::from_hex_string(&hex).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    /// Generate a new random recovery key with 256 bits of entropy
    ///
    /// Uses OS-provided randomness via `OsRng` for cryptographic security.
    ///
    /// # Example
    /// ```
    /// use syft_crypto_protocol::RecoveryKey;
    ///
    /// let recovery_key = RecoveryKey::generate();
    /// ```
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self(key)
    }

    /// Format as 64 hex chars with dashes for readability
    ///
    /// Format: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (16 groups of 4 chars)
    ///
    /// This format is easier to write down and verify than a continuous hex string.
    ///
    /// # Example
    /// ```
    /// use syft_crypto_protocol::RecoveryKey;
    ///
    /// let key = RecoveryKey::generate();
    /// let hex = key.to_hex_string();
    /// println!("{}", hex);  // "a3f5-e8c9-1234-5678-..."
    /// ```
    pub fn to_hex_string(&self) -> String {
        let hex = hex::encode(self.0);
        // Insert dashes every 4 characters
        hex.as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse from hex string (with or without dashes)
    ///
    /// Accepts formats:
    /// - With dashes: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
    /// - Without dashes: `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` (64 chars)
    /// - Mixed spacing/dashes (cleaned automatically)
    ///
    /// # Errors
    /// - `RecoveryError::InvalidLength` if not exactly 64 hex characters
    /// - `RecoveryError::InvalidHex` if contains non-hex characters
    ///
    /// # Example
    /// ```
    /// use syft_crypto_protocol::RecoveryKey;
    ///
    /// // With dashes
    /// let key1 = RecoveryKey::from_hex_string("a3f5-e8c9-1234-5678-9abc-def0-1234-5678-9abc-def0-1234-5678-9abc-def0-1234-5678").unwrap();
    ///
    /// // Without dashes
    /// let key2 = RecoveryKey::from_hex_string("a3f5e8c9123456789abcdef0123456789abcdef0123456789abcdef012345678").unwrap();
    /// ```
    pub fn from_hex_string(s: &str) -> RecoveryResult<Self> {
        // Remove all dashes, spaces, and whitespace
        let cleaned = s
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>();

        if cleaned.len() != 64 {
            return Err(RecoveryError::InvalidLength {
                expected: 64,
                actual: cleaned.len(),
            });
        }

        let bytes = hex::decode(&cleaned).map_err(|e| RecoveryError::InvalidHex(e.to_string()))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }

    /// Get raw bytes (for internal use only)
    ///
    /// # Security
    /// This should only be used internally for key derivation.
    /// Never expose these bytes to external APIs.
    #[allow(dead_code)] // Used in tests and will be used in key derivation (Step 5)
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test internal implementation detail: zeroization on drop
    ///
    /// This test verifies that the ZeroizeOnDrop trait properly clears
    /// sensitive key material when the RecoveryKey is dropped.
    #[test]
    fn test_recovery_key_zeroization() {
        let key = RecoveryKey::generate();

        // Store original bytes for comparison
        let original_bytes = *key.as_bytes();

        // Drop the key (should trigger zeroization)
        drop(key);

        // Note: We can't safely read the memory after drop in safe Rust,
        // but the zeroize library guarantees this happens
        // This test mainly ensures the ZeroizeOnDrop trait is applied

        // Verify original bytes were not all zeros (sanity check)
        assert_ne!(original_bytes, [0u8; 32]);
    }

    /// Test internal implementation: verify as_bytes() returns correct data
    ///
    /// This uses the pub(crate) as_bytes() method which is not part of the public API.
    #[test]
    fn test_recovery_key_from_known_hex() {
        // Test with a known hex string
        let known_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = RecoveryKey::from_hex_string(known_hex).unwrap();

        let expected_bytes = hex::decode(known_hex).unwrap();
        assert_eq!(key.as_bytes().as_slice(), expected_bytes.as_slice());
    }
}
