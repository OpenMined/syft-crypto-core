//! File encryption using XChaCha20-Poly1305 AEAD cipher.
//!
//! Two cipher suites share the same key material and envelope:
//!
//! - `xchacha20poly1305-v1` seals the whole payload with one AEAD call. It is the original
//!   suite and stays the default for the in-memory API.
//! - `xchacha20poly1305-stream-v1` seals the payload as a sequence of fixed-size segments so
//!   arbitrarily large files can be encrypted and decrypted with a bounded amount of memory.
//!   Every segment gets its own nonce derived from a per-envelope prefix, the segment index, and
//!   a "last segment" flag, and the same index and flag are bound into the AEAD associated data.
//!   Reordering, dropping, duplicating, or truncating segments therefore fails authentication
//!   without any bookkeeping on the caller's side (the STREAM construction, as used by `age`).

use crate::Result;
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

/// Additional authenticated data for whole-payload file encryption.
const FILE_AAD: &[u8] = b"syc-file-v1";

/// Additional authenticated data prefix for segmented (streaming) encryption.
const STREAM_AAD: &[u8] = b"syc-stream-v1";

/// File cipher suite advertised in envelope metadata.
pub const FILE_CIPHER_SUITE: &str = "xchacha20poly1305-v1";

/// Segmented (streaming) cipher suite advertised in envelope metadata.
pub const STREAM_CIPHER_SUITE: &str = "xchacha20poly1305-stream-v1";

/// Poly1305 authentication tag size appended to every sealed segment.
pub const TAG_LEN: usize = 16;

/// Random per-envelope nonce prefix for the streaming suite. The remaining 5 bytes of the
/// 24-byte XChaCha20 nonce carry the segment index and the last-segment flag.
pub const STREAM_NONCE_PREFIX_LEN: usize = 19;

/// Default plaintext bytes per segment for the streaming suite.
pub const DEFAULT_SEGMENT_SIZE: usize = 1024 * 1024;

/// Largest plaintext segment accepted, so a malicious prelude cannot request a huge buffer.
pub const MAX_SEGMENT_SIZE: usize = 256 * 1024 * 1024;

/// Encrypts plaintext with XChaCha20-Poly1305.
///
/// Uses the recommended attachment cipher with 192-bit nonces (XChaCha20)
/// and Poly1305 authentication tags.
///
/// # Arguments
/// - `key`: 32-byte encryption key
/// - `nonce`: 24-byte nonce (must be unique per encryption)
/// - `plaintext`: Data to encrypt
///
/// # Returns
/// Ciphertext with appended 16-byte authentication tag
pub(super) fn encrypt_payload(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    // We locally reuse the XChaCha20-Poly1305 construction used for attachments so
    // callers can seal bytes without additional dependencies.
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: FILE_AAD,
            },
        )
        .map_err(|_| "file encryption failed".into())
}

/// Segment geometry of a streamed payload, as recorded in (and recovered from) the prelude's
/// `cipher` section: `segment_count`, `last_segment_bytes`, and `ciphertext_len`.
///
/// No extra prelude field is needed: the plaintext segment size is implied by the three
/// existing values, which keeps streamed envelopes parseable by older tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentLayout {
    /// Plaintext bytes in every segment except possibly the last.
    pub segment_size: usize,
    /// Number of sealed segments (always at least 1; an empty payload is one empty segment).
    pub segment_count: u32,
    /// Ciphertext bytes (plaintext + tag) of the final segment.
    pub last_segment_bytes: u64,
    /// Total ciphertext bytes across all segments.
    pub ciphertext_len: u64,
}

impl SegmentLayout {
    /// Compute the layout for `plaintext_len` bytes split into `segment_size`-byte segments.
    pub fn for_plaintext(plaintext_len: u64, segment_size: usize) -> Result<Self> {
        if segment_size == 0 {
            return Err("segment size must be non-zero".into());
        }
        if segment_size > MAX_SEGMENT_SIZE {
            return Err(format!(
                "segment size {} exceeds maximum {}",
                segment_size, MAX_SEGMENT_SIZE
            )
            .into());
        }
        let seg = segment_size as u64;
        let full_segments = plaintext_len / seg;
        let remainder = plaintext_len % seg;
        // A payload that is an exact multiple ends with a full segment; an empty payload is a
        // single empty segment so the last-segment flag is always emitted.
        let (count, last_plaintext) = if remainder == 0 && full_segments > 0 {
            (full_segments, seg)
        } else {
            (full_segments + 1, remainder)
        };
        let segment_count =
            u32::try_from(count).map_err(|_| "plaintext too large for the segment count field")?;
        let tag = TAG_LEN as u64;
        let last_segment_bytes = last_plaintext + tag;
        let ciphertext_len = (count - 1)
            .checked_mul(seg + tag)
            .and_then(|full| full.checked_add(last_segment_bytes))
            .ok_or("ciphertext length overflowed")?;
        Ok(Self {
            segment_size,
            segment_count,
            last_segment_bytes,
            ciphertext_len,
        })
    }

    /// Recover the layout from the prelude's cipher metadata, validating that the three values
    /// describe a consistent sequence of segments.
    pub fn from_cipher_info(
        segment_count: u32,
        last_segment_bytes: u64,
        ciphertext_len: u64,
    ) -> Result<Self> {
        let tag = TAG_LEN as u64;
        if segment_count == 0 {
            return Err("segment count must be at least 1".into());
        }
        if last_segment_bytes < tag {
            return Err("last segment is smaller than an authentication tag".into());
        }
        let full_ciphertext = ciphertext_len
            .checked_sub(last_segment_bytes)
            .ok_or("ciphertext length is smaller than the last segment")?;
        let segment_ciphertext = if segment_count == 1 {
            if full_ciphertext != 0 {
                return Err("single-segment payload has trailing ciphertext".into());
            }
            last_segment_bytes
        } else {
            let full_count = u64::from(segment_count - 1);
            if full_ciphertext % full_count != 0 {
                return Err("ciphertext length is not a whole number of segments".into());
            }
            let seg_ct = full_ciphertext / full_count;
            if seg_ct <= tag {
                return Err("segment size is too small".into());
            }
            if last_segment_bytes > seg_ct {
                return Err("last segment is larger than a full segment".into());
            }
            seg_ct
        };
        let segment_size = usize::try_from(segment_ciphertext - tag)
            .map_err(|_| "segment size does not fit in memory")?;
        if segment_size > MAX_SEGMENT_SIZE {
            return Err(format!(
                "segment size {} exceeds maximum {}",
                segment_size, MAX_SEGMENT_SIZE
            )
            .into());
        }
        Ok(Self {
            segment_size,
            segment_count,
            last_segment_bytes,
            ciphertext_len,
        })
    }

    /// Ciphertext bytes of segment `index` (plaintext + tag).
    pub fn segment_ciphertext_len(&self, index: u32) -> u64 {
        if self.is_last(index) {
            self.last_segment_bytes
        } else {
            self.segment_size as u64 + TAG_LEN as u64
        }
    }

    /// Plaintext bytes of segment `index`.
    pub fn segment_plaintext_len(&self, index: u32) -> u64 {
        self.segment_ciphertext_len(index) - TAG_LEN as u64
    }

    /// Whether `index` is the final segment.
    pub fn is_last(&self, index: u32) -> bool {
        index + 1 == self.segment_count
    }
}

/// Derive the 24-byte nonce for one segment: prefix || index (big-endian u32) || last flag.
fn segment_nonce(prefix: &[u8; STREAM_NONCE_PREFIX_LEN], index: u32, last: bool) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..STREAM_NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[STREAM_NONCE_PREFIX_LEN..STREAM_NONCE_PREFIX_LEN + 4]
        .copy_from_slice(&index.to_be_bytes());
    nonce[23] = u8::from(last);
    nonce
}

/// Associated data for one segment: label || index (big-endian u32) || last flag.
fn segment_aad(index: u32, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STREAM_AAD.len() + 5);
    aad.extend_from_slice(STREAM_AAD);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

/// Seal one segment of a streamed payload.
pub(super) fn encrypt_segment(
    key: &[u8; 32],
    nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    index: u32,
    last: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = segment_nonce(nonce_prefix, index, last);
    let aad = segment_aad(index, last);
    cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "segment encryption failed".into())
}

/// Open one segment of a streamed payload. Fails if the segment was moved, altered, or is not
/// the segment the caller expects at this position.
pub(super) fn decrypt_segment(
    key: &[u8; 32],
    nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    index: u32,
    last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = segment_nonce(nonce_prefix, index, last);
    let aad = segment_aad(index, last);
    cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| crate::error::KeyError::DecryptionFailed)
}
