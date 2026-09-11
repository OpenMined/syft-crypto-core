use crate::Result;
use crate::keys::{SyftPublicKeyBundle, compute_key_fingerprint};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;

#[cfg(test)]
use serde_json::json;
use std::convert::TryFrom;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: &[u8; 4] = b"SYC2";
pub const CURRENT_VERSION: u8 = 1;
pub const PRELUDE_PAD: usize = 4096;
const ED25519_SIGNATURE_LEN: usize = 64;
const MAX_PRELUDE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB
const MAX_RECIPIENTS: usize = 1000;
const SIGNING_CONTEXT: &[u8] = b"SYC2-PRELUDE";

/// Payload data for envelope construction.
pub struct EnvelopePayload<'a> {
    pub ciphertext: &'a [u8],
    pub filename_hint: Option<&'a str>,
    pub cipher_suite: &'a str,
    pub cipher_nonce_b64: &'a str,
}

/// Cipher metadata for envelope construction when the ciphertext is not in memory.
///
/// Describes what the prelude's `cipher` section will say about a payload that is written
/// separately (for example, streamed segment by segment after the header).
pub struct CipherMeta<'a> {
    pub cipher_suite: &'a str,
    pub cipher_nonce_b64: &'a str,
    pub segment_count: u32,
    pub last_segment_bytes: u64,
    pub ciphertext_len: u64,
    pub filename_hint: Option<&'a str>,
}

impl<'a> CipherMeta<'a> {
    /// Metadata for a whole-payload (single segment) envelope built from in-memory ciphertext.
    pub fn for_payload(payload: &EnvelopePayload<'a>) -> Result<Self> {
        let ciphertext_len = u64::try_from(payload.ciphertext.len())
            .map_err(|_| "ciphertext too large to fit in 64-bit length")?;
        Ok(Self {
            cipher_suite: payload.cipher_suite,
            cipher_nonce_b64: payload.cipher_nonce_b64,
            segment_count: 1,
            last_segment_bytes: ciphertext_len,
            ciphertext_len,
            filename_hint: payload.filename_hint,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnvelopePrelude {
    pub version: u32,
    pub canon: String,
    pub created_at: u64,
    pub sender: SenderInfo,
    pub recipients: Vec<RecipientInfo>,
    pub recipient_set_fpr: String,
    pub wrappings: Vec<WrappingInfo>,
    pub cipher: CipherInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_meta: Option<PublicMeta>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SenderInfo {
    pub identity: String,
    pub ik_fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RecipientInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spk_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_prekey_id: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WrappingInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    pub wrap_ephemeral_public: String,
    pub wrap_ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherInfo {
    pub suite: String,
    pub segment_count: u32,
    pub last_segment_bytes: u64,
    pub ciphertext_len: u64,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedEnvelope {
    pub prelude: EnvelopePrelude,
    pub prelude_bytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The parsed header of an envelope: everything before the ciphertext.
///
/// Produced by [`parse_envelope_header`], which reads only the header from a stream so the
/// (possibly very large) ciphertext can be consumed afterwards without loading it into memory.
#[derive(Debug, Clone)]
pub struct ParsedEnvelopeHeader {
    pub prelude: EnvelopePrelude,
    pub prelude_bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ParsedEnvelopeHeader {
    /// Number of bytes the header occupies on disk (magic through signature).
    pub fn header_len(&self) -> Result<usize> {
        let padded_len = align_to_block(self.prelude_bytes.len(), PRELUDE_PAD)?;
        Ok(MAGIC.len() + 1 + 4 + padded_len + 2 + self.signature.len())
    }
}

impl From<ParsedEnvelope> for ParsedEnvelopeHeader {
    fn from(parsed: ParsedEnvelope) -> Self {
        Self {
            prelude: parsed.prelude,
            prelude_bytes: parsed.prelude_bytes,
            signature: parsed.signature,
        }
    }
}

pub fn has_syc_magic(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

// ============================================================================
// Cryptographic Functions
// ============================================================================

/// Validate envelope header: minimum size, magic bytes, and version.
fn validate_envelope_header(bytes: &[u8]) -> Result<()> {
    // Check minimum size for header
    const HEADER_MIN_SIZE: usize = 4 + 1 + 4; // magic + version + prelude_len
    if bytes.len() < HEADER_MIN_SIZE {
        return Err("file is too small to contain SYC envelope header".into());
    }

    // Verify magic bytes
    if !has_syc_magic(bytes) {
        return Err("file does not begin with SYC envelope magic".into());
    }

    // Check version
    let version = bytes[MAGIC.len()];
    if version != CURRENT_VERSION {
        return Err(format!("unsupported SYC envelope version {}", version).into());
    }

    Ok(())
}

/// Parse the prelude section: length field, prelude data, and padding.
///
/// Returns the prelude bytes (without padding) and the new cursor position.
fn parse_prelude_section(bytes: &[u8], mut cursor: usize) -> Result<(Vec<u8>, usize)> {
    if bytes.len() < cursor + 4 {
        return Err("file truncated while reading SYC prelude length".into());
    }
    // Read prelude length (4 bytes, little-endian)
    let prelude_len_bytes = &bytes[cursor..cursor + 4];
    let prelude_len = u32::from_le_bytes(prelude_len_bytes.try_into().unwrap()) as usize;
    cursor += 4;

    if prelude_len > MAX_PRELUDE_SIZE {
        return Err("prelude too large".into());
    }

    // Calculate padded length (aligned to 4096-byte blocks)
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD)?;

    // Validate sufficient bytes available
    let padded_end = cursor
        .checked_add(padded_len)
        .ok_or("file truncated while reading SYC prelude")?;
    if bytes.len() < padded_end {
        return Err("file truncated while reading SYC prelude".into());
    }

    // Extract prelude data (excluding padding)
    let prelude_end = cursor
        .checked_add(prelude_len)
        .ok_or("file truncated while reading SYC prelude")?;
    let prelude_bytes = bytes[cursor..prelude_end].to_vec();
    cursor = padded_end; // Skip to end of padded section

    Ok((prelude_bytes, cursor))
}

/// Read exactly `len` bytes from `reader`, mapping a short read to a truncation error.
fn read_exact_or_truncated<R: Read>(reader: &mut R, len: usize, what: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|_| format!("file truncated while reading SYC {}", what))?;
    Ok(buf)
}

/// Parse an envelope header (magic, version, prelude, signature) from a stream.
///
/// Reads only the header; the reader is left positioned at the first ciphertext byte, so the
/// caller can stream the ciphertext with bounded memory (see `encryption::decrypt_stream`).
/// The same checks as [`parse_envelope`] apply to the header. The ciphertext length recorded in
/// the prelude is **not** validated here because the ciphertext has not been read.
///
/// After parsing, call [`verify_header_signature`] to authenticate the sender before trusting
/// anything in the prelude.
pub fn parse_envelope_header<R: Read>(reader: &mut R) -> Result<ParsedEnvelopeHeader> {
    let mut magic_version = [0u8; 5];
    reader
        .read_exact(&mut magic_version)
        .map_err(|_| "file is too small to contain SYC envelope header")?;
    if &magic_version[..MAGIC.len()] != MAGIC {
        return Err("file does not begin with SYC envelope magic".into());
    }
    let version = magic_version[MAGIC.len()];
    if version != CURRENT_VERSION {
        return Err(format!("unsupported SYC envelope version {}", version).into());
    }

    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|_| "file truncated while reading SYC prelude length")?;
    let prelude_len = u32::from_le_bytes(len_bytes) as usize;
    if prelude_len > MAX_PRELUDE_SIZE {
        return Err("prelude too large".into());
    }
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD)?;
    let mut padded = read_exact_or_truncated(reader, padded_len, "prelude")?;
    padded.truncate(prelude_len);
    let prelude_bytes = padded;

    let mut sig_len_bytes = [0u8; 2];
    reader
        .read_exact(&mut sig_len_bytes)
        .map_err(|_| "file truncated while reading SYC signature length")?;
    let signature_len = u16::from_le_bytes(sig_len_bytes) as usize;
    if signature_len != ED25519_SIGNATURE_LEN {
        return Err(format!(
            "invalid signature length: {} (expected {})",
            signature_len, ED25519_SIGNATURE_LEN
        )
        .into());
    }
    let signature = read_exact_or_truncated(reader, signature_len, "signature")?;

    let prelude: EnvelopePrelude = from_jcs_bytes(&prelude_bytes)?;
    Ok(ParsedEnvelopeHeader {
        prelude,
        prelude_bytes,
        signature,
    })
}

/// Parse the signature section: length field and signature data.
///
/// Returns the signature bytes and the new cursor position.
fn parse_signature_section(bytes: &[u8], cursor: usize) -> Result<(Vec<u8>, usize)> {
    // Check space for signature length field
    if bytes.len() < cursor + 2 {
        return Err("file truncated while reading SYC signature length".into());
    }

    // Read signature length (2 bytes, little-endian)
    let signature_len = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    if signature_len != ED25519_SIGNATURE_LEN {
        return Err(format!(
            "invalid signature length: {} (expected {})",
            signature_len, ED25519_SIGNATURE_LEN
        )
        .into());
    }
    let mut cursor = cursor + 2;

    // Validate sufficient bytes for signature
    let signature_end = cursor
        .checked_add(signature_len)
        .ok_or("file truncated while reading SYC signature")?;
    if bytes.len() < signature_end {
        return Err("file truncated while reading SYC signature".into());
    }

    // Extract signature data
    let signature = bytes[cursor..signature_end].to_vec();
    cursor = signature_end;

    Ok((signature, cursor))
}

/// Parse a Syft Crypto (SYC) envelope from raw bytes into its structured components.
///
/// This function parses the binary SYC envelope format and extracts all components:
/// the prelude metadata, signature, and ciphertext. The envelope format is designed
/// for hybrid encryption.
///
/// # SYC Envelope Binary Format
///
/// The envelope has the following structure:
/// ```text
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Magic (4 bytes): b"SYC2"                                     │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Version (1 byte): 1                                          │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Prelude Length (4 bytes, little-endian u32)                 │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Prelude (variable length, RFC 8785 canonical JSON)          │
/// │ - Contains: sender info, recipients, cipher info, metadata  │
/// │ - Padding: aligned to 4096-byte blocks with zero bytes      │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Signature Length (2 bytes, little-endian u16)               │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Signature (variable length, Ed25519 signature ~64 bytes)    │
/// │ - Signs the prelude bytes (before padding)                  │
/// ├─────────────────────────────────────────────────────────────┤
/// │ Ciphertext (remainder of file)                              │
/// │ - Encrypted with XChaCha20-Poly1305                        │
/// │ - Key wrapped using X3DH X25519                      │
/// └─────────────────────────────────────────────────────────────┘
/// ```
///
/// # Arguments
///
/// * `bytes` - Raw envelope bytes to parse (typically read from a `.syc` file)
///
/// # Returns
///
/// Returns a `ParsedEnvelope` containing:
/// - `prelude`: Deserialized metadata structure with sender/recipient info
/// - `prelude_bytes`: Raw prelude bytes (for signature verification)
/// - `signature`: Ed25519 signature of the prelude
/// - `ciphertext`: Encrypted payload data
///
/// # Errors
///
/// Returns an error if:
/// - File is too small to contain a valid envelope header
/// - Missing SYC magic bytes (not a valid envelope file)
/// - Unsupported version (only version 1 is currently supported)
/// - File is truncated (incomplete prelude, signature, or ciphertext)
/// - Prelude JSON is not RFC 8785 canonical
///
/// # Example
///
/// ```
/// use syft_crypto_protocol::envelope::{parse_envelope, verify_signature};
///
/// # fn example() -> syft_crypto_protocol::Result<()> {
/// // Read envelope from file
/// let envelope_bytes = std::fs::read("message.syc")?;
///
/// // Parse the envelope structure
/// let parsed = parse_envelope(&envelope_bytes)?;
///
/// // Access components
/// println!("Sender: {}", parsed.prelude.sender.identity);
/// println!("Recipients: {}", parsed.prelude.recipients.len());
/// println!("Ciphertext size: {} bytes", parsed.ciphertext.len());
///
/// // Verify signature (requires sender's identity public key)
/// // verify_signature(&parsed, &sender_identity_key)?;
/// # Ok(())
/// # }
/// ```
///
/// # Security Notes
///
/// - This function only **parses** the envelope structure - it does NOT verify the signature
/// - After parsing, you MUST call `verify_signature()` to authenticate the sender
/// - The prelude is validated for RFC 8785 canonical JSON format
/// - Signature verification requires the sender's identity public key
///
/// # See Also
///
/// - `build_envelope_with_wrappings()` - Creates envelopes with real signatures and X3DH wrappings
/// - `verify_signature()` - Verifies the envelope signature after parsing
pub fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope> {
    // Validate envelope header (magic bytes + version)
    validate_envelope_header(bytes)?;

    // Parse prelude section (includes length, data, and padding)
    let mut cursor = MAGIC.len() + 1; // Skip magic + version byte
    let (prelude_bytes, new_cursor) = parse_prelude_section(bytes, cursor)?;
    cursor = new_cursor;

    // Parse signature section (length + data)
    let (signature, new_cursor) = parse_signature_section(bytes, cursor)?;
    cursor = new_cursor;

    // Extract ciphertext (all remaining bytes)
    let ciphertext = bytes[cursor..].to_vec();

    // Deserialize and validate prelude JSON
    let prelude: EnvelopePrelude = from_jcs_bytes(&prelude_bytes)?;
    let ciphertext_len = u64::try_from(ciphertext.len())
        .map_err(|_| "ciphertext too large to fit in 64-bit length")?;
    if ciphertext_len != prelude.cipher.ciphertext_len {
        return Err(format!(
            "ciphertext length mismatch: expected {}, got {}",
            prelude.cipher.ciphertext_len, ciphertext_len
        )
        .into());
    }

    Ok(ParsedEnvelope {
        prelude,
        prelude_bytes,
        signature,
        ciphertext,
    })
}

/// Sign envelope prelude with sender's identity private key.
fn sign_prelude<R: rand::CryptoRng + rand::Rng>(
    prelude_bytes: &[u8],
    identity_key_pair: &SigningKey,
    _rng: &mut R,
) -> Result<Box<[u8]>> {
    let message = signing_message(prelude_bytes);
    let signature = identity_key_pair.sign(&message);
    Ok(signature.to_bytes().to_vec().into_boxed_slice())
}

/// Verify envelope signature using sender's identity public key.
pub fn verify_signature(
    parsed_envelope: &ParsedEnvelope,
    sender_identity_key: &VerifyingKey,
) -> Result<()> {
    verify_prelude_signature(
        &parsed_envelope.prelude,
        &parsed_envelope.prelude_bytes,
        &parsed_envelope.signature,
        sender_identity_key,
    )
}

/// Verify the signature of a header parsed with [`parse_envelope_header`].
///
/// Identical to [`verify_signature`] but does not require the ciphertext to be in memory.
pub fn verify_header_signature(
    header: &ParsedEnvelopeHeader,
    sender_identity_key: &VerifyingKey,
) -> Result<()> {
    verify_prelude_signature(
        &header.prelude,
        &header.prelude_bytes,
        &header.signature,
        sender_identity_key,
    )
}

fn verify_prelude_signature(
    prelude: &EnvelopePrelude,
    prelude_bytes: &[u8],
    signature: &[u8],
    sender_identity_key: &VerifyingKey,
) -> Result<()> {
    let expected_fingerprint = compute_key_fingerprint(sender_identity_key.as_bytes());
    if !fingerprints_match(&expected_fingerprint, &prelude.sender.ik_fingerprint) {
        return Err("sender fingerprint mismatch".into());
    }

    let message = signing_message(prelude_bytes);
    let signature = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| "SYC envelope signature verification failed")?;
    if sender_identity_key
        .verify_strict(&message, &signature)
        .is_err()
    {
        return Err("SYC envelope signature verification failed".into());
    }
    Ok(())
}

/// Build envelope prelude with real fingerprints from public key bundles.
///
/// This creates an EnvelopePrelude using cryptographic fingerprints
/// computed from the sender's identity key and recipients' public key bundles.
fn build_prelude(
    sender_identity: &str,
    sender_public_bundle: &SyftPublicKeyBundle,
    recipients: &[(String, SyftPublicKeyBundle)],
    wrappings: Vec<WrappingInfo>,
    meta: &CipherMeta,
) -> Result<EnvelopePrelude> {
    if recipients.len() > MAX_RECIPIENTS {
        return Err(format!(
            "too many recipients: {} (max {})",
            recipients.len(),
            MAX_RECIPIENTS
        )
        .into());
    }

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Compute real fingerprint for sender's identity key
    let sender_ik_fingerprint =
        compute_key_fingerprint(sender_public_bundle.identity_signing_public_key.as_bytes());

    let sender_info = SenderInfo {
        identity: sender_identity.to_owned(),
        ik_fingerprint: sender_ik_fingerprint,
    };

    // Build recipient infos with real fingerprints
    let mut recipients_infos: Vec<RecipientInfo> = Vec::with_capacity(recipients.len());
    for (recipient_identity, recipient_bundle) in recipients {
        if !recipient_bundle.verify_signatures() {
            return Err(format!(
                "recipient bundle for {} failed signature verification",
                recipient_identity
            )
            .into());
        }
        let spk_fingerprint =
            compute_key_fingerprint(recipient_bundle.signed_prekey_public_key.as_bytes());
        recipients_infos.push(RecipientInfo {
            identity: Some(recipient_identity.clone()),
            device_label: Some("default".into()), // set to "default" as a placeholder because the current implementation doesn't have a multi-device system yet
            spk_fingerprint: Some(spk_fingerprint),
            signed_prekey_id: Some(1), // Key rotation not yet supported => Always using ID 1
        });
    }

    if !recipients.is_empty() && wrappings.len() != recipients.len() {
        return Err("wrappings length does not match recipient count".into());
    }

    // Compute recipient set fingerprint from all recipient identity fingerprints using length-prefixing
    let mut recipient_fps: Vec<String> = recipients
        .iter()
        .map(|(_, bundle)| compute_key_fingerprint(bundle.identity_signing_public_key.as_bytes()))
        .collect();
    recipient_fps.sort();
    let mut combined = Vec::with_capacity(recipient_fps.len() * (std::mem::size_of::<u32>() + 64));
    for fp in &recipient_fps {
        let len_u32 = u32::try_from(fp.len())
            .map_err(|_| "recipient fingerprint exceeds supported length")?;
        combined.extend_from_slice(&len_u32.to_le_bytes());
        combined.extend_from_slice(fp.as_bytes());
    }
    let recipient_set_fpr = compute_key_fingerprint(&combined);

    // Build cipher info metadata
    let cipher = CipherInfo {
        suite: meta.cipher_suite.into(),
        segment_count: meta.segment_count,
        last_segment_bytes: meta.last_segment_bytes,
        ciphertext_len: meta.ciphertext_len,
        nonce: meta.cipher_nonce_b64.to_string(),
    };

    let public_meta = meta.filename_hint.map(|hint| PublicMeta {
        filename_hint: Some(hint.to_owned()),
    });

    Ok(EnvelopePrelude {
        version: 1,
        canon: JCS_CANON_LABEL.to_string(),
        created_at,
        sender: sender_info,
        recipients: recipients_infos,
        recipient_set_fpr,
        wrappings,
        cipher,
        integrity: None,
        public_meta,
    })
}

/// Build a complete SYC envelope with real cryptographic signatures and X3DH wrappings.
///
/// This creates an envelope with:
/// - Real fingerprints from actual public keys
/// - Real Ed25519 signature of the prelude
/// - Real X3DH wrappings for key encapsulation
/// - Proper envelope structure with magic, version, padding, etc.
///
/// # Arguments
/// * `sender_identity` - Sender's identity string (e.g., email)
/// * `sender_identity_key_pair` - Sender's identity key pair for signing
/// * `sender_public_bundle` - Sender's public key bundle
/// * `recipients` - Vector of (identity, public_bundle) tuples for each recipient
/// * `wrappings` - X3DH key wrappings (ephemeral keys + wrapped file key)
/// * `payload` - Envelope payload with ciphertext and metadata
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// The complete envelope bytes ready for storage/transmission
///
/// # Note
/// This is typically called from `encrypt_message()` which handles X3DH wrapping.
/// Do not use this directly unless you're implementing custom encryption logic.
pub fn build_envelope_with_wrappings<R: rand::CryptoRng + rand::Rng>(
    sender_identity: &str,
    sender_identity_key_pair: &SigningKey,
    sender_public_bundle: &SyftPublicKeyBundle,
    recipients: &[(String, SyftPublicKeyBundle)],
    wrappings: &[WrappingInfo],
    payload: &EnvelopePayload,
    rng: &mut R,
) -> Result<Vec<u8>> {
    if payload.ciphertext.is_empty() {
        return Err("ciphertext cannot be empty".into());
    }
    let meta = CipherMeta::for_payload(payload)?;
    let mut envelope = build_envelope_header_with_wrappings(
        sender_identity,
        sender_identity_key_pair,
        sender_public_bundle,
        recipients,
        wrappings,
        &meta,
        rng,
    )?;
    envelope.reserve_exact(payload.ciphertext.len());
    envelope.extend_from_slice(payload.ciphertext);
    Ok(envelope)
}

/// Build the header of a SYC envelope (magic, version, signed prelude, signature) **without**
/// the ciphertext, which the caller appends or streams afterwards.
///
/// This is the building block for streaming encryption: the prelude describes the ciphertext
/// that will follow (`meta`), is signed, and can be written before any payload byte exists in
/// memory. [`build_envelope_with_wrappings`] is this function plus the in-memory ciphertext.
pub fn build_envelope_header_with_wrappings<R: rand::CryptoRng + rand::Rng>(
    sender_identity: &str,
    sender_identity_key_pair: &SigningKey,
    sender_public_bundle: &SyftPublicKeyBundle,
    recipients: &[(String, SyftPublicKeyBundle)],
    wrappings: &[WrappingInfo],
    meta: &CipherMeta,
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Validate inputs
    if sender_identity.is_empty() {
        return Err("sender_identity cannot be empty".into());
    }
    if meta.ciphertext_len == 0 {
        return Err("ciphertext cannot be empty".into());
    }

    // Verify that the identity key pair matches the public bundle
    if sender_identity_key_pair.verifying_key() != sender_public_bundle.identity_signing_public_key
    {
        return Err("identity key pair does not match public bundle".into());
    }
    if !sender_public_bundle.verify_signatures() {
        return Err("sender public bundle signatures are invalid".into());
    }

    // Build the prelude with fingerprints and supplied wrappings
    let prelude = build_prelude(
        sender_identity,
        sender_public_bundle,
        recipients,
        wrappings.to_vec(),
        meta,
    )?;

    // Serialize prelude to canonical JSON
    let prelude_bytes = to_jcs_bytes(&prelude)?;
    let prelude_len = prelude_bytes.len();
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD)?;

    // Sign the prelude with sender's identity private key
    let signature = sign_prelude(&prelude_bytes, sender_identity_key_pair, rng)?;

    // Assemble the header
    let mut envelope = Vec::with_capacity(
        MAGIC.len()
            + 1  // version byte
            + std::mem::size_of::<u32>()  // prelude length
            + padded_len
            + std::mem::size_of::<u16>()  // signature length
            + signature.len(),
    );

    envelope.extend_from_slice(MAGIC);
    envelope.push(CURRENT_VERSION);
    envelope.extend_from_slice(&u32::try_from(prelude_len)?.to_le_bytes());
    envelope.extend_from_slice(&prelude_bytes);
    if padded_len > prelude_len {
        envelope.resize(envelope.len() + (padded_len - prelude_len), 0u8);
    }
    envelope.extend_from_slice(&u16::try_from(signature.len())?.to_le_bytes());
    envelope.extend_from_slice(&signature);

    Ok(envelope)
}

/// Round up a length to the nearest multiple of a block size.
///
/// This is used to align the prelude to 4096-byte boundaries for metadata privacy
/// and format stability. Padding hides the exact size of the prelude JSON.
///
/// # Examples
///
/// ```text
/// align_to_block(1, 4096)?    → 4096    // Rounds up to 1 block
/// align_to_block(4096, 4096)? → 4096    // Already aligned
/// align_to_block(4097, 4096)? → 8192    // Rounds up to 2 blocks
/// align_to_block(0, 4096)?    → 4096    // Zero becomes 1 block
/// ```
fn align_to_block(len: usize, block: usize) -> Result<usize> {
    if block == 0 {
        return Err("block size must be non-zero".into());
    }
    if len == 0 {
        return Ok(block);
    }
    let blocks = len
        .checked_add(block - 1)
        .ok_or("alignment calculation overflowed")?
        / block;
    blocks
        .checked_mul(block)
        .ok_or("alignment calculation overflowed".into())
}

/// Canonical label for RFC 8785 JSON Canonicalization Scheme.
pub const JCS_CANON_LABEL: &str = "jcs-rfc8785";

/// Serialize a value to RFC 8785 canonical JSON bytes.
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_jcs::to_vec(value)?)
}

/// Deserialize a value from RFC 8785 canonical JSON bytes.
pub fn from_jcs_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: Value = serde_json::from_slice(bytes)?;
    let canonical = serde_jcs::to_vec(&value)?;
    if canonical != bytes {
        return Err("prelude JSON is not RFC 8785 canonical".into());
    }
    Ok(serde_json::from_value(value)?)
}

fn signing_message(prelude_bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNING_CONTEXT.len() + 1 + prelude_bytes.len());
    message.extend_from_slice(SIGNING_CONTEXT);
    message.push(CURRENT_VERSION);
    message.extend_from_slice(prelude_bytes);
    message
}

fn fingerprints_match(expected: &str, actual: &str) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    expected.as_bytes().ct_eq(actual.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/envelope_tests.rs"
    ));
}
