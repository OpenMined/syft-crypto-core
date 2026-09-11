//! Multi-recipient file encryption using X3DH key agreement and XChaCha20-Poly1305.
//!
//! This module provides end-to-end encrypted file sharing with:
//! - **X3DH key agreement**: X25519-based key agreement with fresh ephemerals
//! - **Multi-recipient support**: Encrypt once, wrap the key N times for N recipients
//! - **XChaCha20-Poly1305 AEAD**: recommended attachment cipher
//! - **Forward secrecy**: Fresh ephemeral keys for each encryption
//!
//! Two entry points share the same key agreement, wrapping, and envelope:
//! - [`encrypt_message`] / [`decrypt_message`] work on in-memory bytes.
//! - [`encrypt_stream`] / [`decrypt_stream`] work on `Read` / `Write` and hold at most one
//!   segment in memory, for payloads larger than RAM.
//!
//! [`decrypt_message`] understands both cipher suites, so any envelope can be opened from
//! memory; [`decrypt_stream`] likewise opens both, but only the streaming suite with bounded
//! memory.

mod constant_time;
mod file_cipher;
mod key_wrap;
mod x3dh;

use crate::envelope::{
    CipherMeta, EnvelopePayload, EnvelopePrelude, ParsedEnvelope, ParsedEnvelopeHeader,
    WrappingInfo, build_envelope_header_with_wrappings, build_envelope_with_wrappings,
    parse_envelope_header, verify_header_signature, verify_signature,
};
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::{Result, error::KeyError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::{CryptoRng, RngCore};
use std::io::{Read, Write};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

// Re-export public constants and types
pub use file_cipher::{
    DEFAULT_SEGMENT_SIZE, FILE_CIPHER_SUITE, MAX_SEGMENT_SIZE, STREAM_CIPHER_SUITE,
    STREAM_NONCE_PREFIX_LEN, SegmentLayout, TAG_LEN,
};

// Import private functions from submodules
use constant_time::ct_identity_match;
use file_cipher::{decrypt_segment_in_place, encrypt_payload, encrypt_segment_in_place};
use key_wrap::{WRAPPED_KEY_SIZE, unwrap_file_key, wrap_file_key};
use x3dh::{derive_recipient_shared_material, derive_sender_shared_material};

/// Additional authenticated data for file decryption
const FILE_AAD: &[u8] = b"syc-file-v1";

/// Recipient metadata required to encrypt a payload.
pub struct EncryptionRecipient<'a> {
    pub identity: &'a str,
    pub bundle: &'a SyftPublicKeyBundle,
}

/// A freshly generated file key together with the `(identity, bundle)` list and wrapping
/// metadata the envelope builder expects.
type WrappedFileKey = (
    Zeroizing<[u8; 32]>,
    Vec<(String, SyftPublicKeyBundle)>,
    Vec<WrappingInfo>,
);

/// Generate a random file key and wrap it for every recipient.
///
/// Shared by the in-memory and streaming encryptors.
fn generate_and_wrap_file_key<R: CryptoRng + RngCore>(
    sender_keys: &SyftPrivateKeys,
    recipients: &[EncryptionRecipient<'_>],
    rng: &mut R,
) -> Result<WrappedFileKey> {
    if recipients.is_empty() {
        return Err("at least one recipient is required".into());
    }

    let file_key = Zeroizing::new({
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    });

    // Wrap file key for each recipient (Key Encapsulation Mechanism)
    let mut recipient_vec = Vec::with_capacity(recipients.len());
    let mut wrappings = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let (x3dh_material, mut wrapping_info) =
            derive_sender_shared_material(sender_keys, recipient.identity, recipient.bundle, rng)?;

        // Wrap the file key using X3DH material
        let wrapped_key = wrap_file_key(x3dh_material.as_ref(), &file_key, rng)?;

        // Store wrapped key bytes as the wrapping ciphertext
        wrapping_info.wrap_ciphertext = URL_SAFE_NO_PAD.encode(&wrapped_key);

        recipient_vec.push((recipient.identity.to_string(), recipient.bundle.clone()));
        wrappings.push(wrapping_info);
    }

    Ok((file_key, recipient_vec, wrappings))
}

/// Encrypt plaintext bytes for the provided recipients, returning a fully formed SYC envelope.
///
/// Supports multiple recipients - the file is encrypted once with a random key, then that key
/// is wrapped separately for each recipient using X3DH-derived material.
///
/// The payload is sealed in one piece (`xchacha20poly1305-v1`); for payloads that should not be
/// held in memory at once use [`encrypt_stream`].
pub fn encrypt_message<R: CryptoRng + RngCore>(
    sender_identity: &str,
    sender_keys: &SyftPrivateKeys,
    recipients: &[EncryptionRecipient<'_>],
    plaintext: &[u8],
    filename_hint: Option<&str>,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let sender_public_bundle = sender_keys.to_public_bundle(rng)?;
    let (file_key, recipient_vec, wrappings) =
        generate_and_wrap_file_key(sender_keys, recipients, rng)?;

    // Encrypt the file / the payload once with the generated random key
    let mut file_nonce = Zeroizing::new([0u8; 24]);
    rng.fill_bytes(file_nonce.as_mut());
    let nonce_b64 = URL_SAFE_NO_PAD.encode(file_nonce.as_ref());
    let ciphertext = encrypt_payload(&file_key, &file_nonce, plaintext)?;

    let payload = EnvelopePayload {
        ciphertext: &ciphertext,
        filename_hint,
        cipher_suite: FILE_CIPHER_SUITE,
        cipher_nonce_b64: &nonce_b64,
    };

    build_envelope_with_wrappings(
        sender_identity,
        sender_keys.identity(),
        &sender_public_bundle,
        &recipient_vec,
        &wrappings,
        &payload,
        rng,
    )
}

/// Options for [`encrypt_stream`].
#[derive(Debug, Clone)]
pub struct StreamOptions<'a> {
    /// Plaintext bytes per segment. Default [`DEFAULT_SEGMENT_SIZE`].
    pub segment_size: usize,
    /// Segments sealed concurrently. `0` means one per available CPU (capped at
    /// [`MAX_PARALLELISM`]); `1` runs on the calling thread only. Default `0`.
    pub parallelism: usize,
    /// Optional public filename hint recorded in the prelude.
    pub filename_hint: Option<&'a str>,
}

impl Default for StreamOptions<'_> {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            parallelism: 0,
            filename_hint: None,
        }
    }
}

/// Upper bound on worker threads, so a machine with many cores does not turn a bounded-memory
/// stream into `cores × batch` buffers.
pub const MAX_PARALLELISM: usize = 32;

/// Segments read (and held in memory) per worker before they are sealed or opened in parallel.
/// Buffers are allocated once and reused, and the AEAD works in place, so peak memory of a
/// stream is about `parallelism × BATCH_PER_WORKER × segment`.
const BATCH_PER_WORKER: usize = 2;

/// Resolve the requested parallelism to a concrete worker count.
fn resolve_parallelism(requested: usize) -> usize {
    let n = if requested == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        requested
    };
    n.clamp(1, MAX_PARALLELISM)
}

/// Apply `f` to every buffer concurrently on up to `workers` scoped threads. Segments are
/// independent (each has its own nonce and tag), so this is what lets a streamed payload use
/// every core without changing the wire format. `f` receives the segment's offset within the
/// batch and works on the buffer in place.
fn process_batch_in_place<F>(buffers: &mut [Zeroizing<Vec<u8>>], workers: usize, f: F) -> Result<()>
where
    F: Fn(usize, &mut Vec<u8>) -> Result<()> + Sync,
{
    let n = buffers.len();
    let workers = workers.clamp(1, n.max(1));
    if workers == 1 {
        for (i, buf) in buffers.iter_mut().enumerate() {
            f(i, buf)?;
        }
        return Ok(());
    }
    let per_worker = n.div_ceil(workers);
    let results: Vec<Result<()>> = std::thread::scope(|scope| {
        let handles: Vec<_> = buffers
            .chunks_mut(per_worker)
            .enumerate()
            .map(|(w, chunk)| {
                let f = &f;
                scope.spawn(move || {
                    for (k, buf) in chunk.iter_mut().enumerate() {
                        f(w * per_worker + k, buf)?;
                    }
                    Ok(())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("worker thread panicked".into()))
            })
            .collect()
    });
    results.into_iter().collect()
}

/// A fixed set of reusable segment buffers, one per batch slot, sized for a full segment plus
/// its tag so neither sealing nor opening ever reallocates.
fn segment_buffers(slots: usize, segment_size: usize) -> Vec<Zeroizing<Vec<u8>>> {
    (0..slots)
        .map(|_| Zeroizing::new(Vec::with_capacity(segment_size + TAG_LEN)))
        .collect()
}

/// Encrypt `plaintext_len` bytes read from `reader` for the provided recipients, writing a fully
/// formed SYC envelope to `writer`, with memory bounded by the segment size, not the payload.
///
/// The payload is sealed with the streaming suite (`xchacha20poly1305-stream-v1`): the header
/// is written first, then the plaintext is read, sealed, and written in batches of segments.
/// Segments in a batch are sealed concurrently on `options.parallelism` threads and written in
/// order, so throughput scales with cores while the envelope is byte-for-byte the same format a
/// single thread would produce.
///
/// The plaintext length must be known up front because the signed prelude records the segment
/// geometry. The reader must yield exactly `plaintext_len` bytes: fewer is an error, and any
/// extra byte is an error too, so a declared length can never silently mismatch the payload.
///
/// Returns the number of envelope bytes written.
#[allow(clippy::too_many_arguments)] // mirrors encrypt_message's positional style plus the two stream inputs
pub fn encrypt_stream<R: CryptoRng + RngCore, I: Read, O: Write>(
    sender_identity: &str,
    sender_keys: &SyftPrivateKeys,
    recipients: &[EncryptionRecipient<'_>],
    plaintext_len: u64,
    reader: &mut I,
    writer: &mut O,
    options: &StreamOptions<'_>,
    rng: &mut R,
) -> Result<u64> {
    let sender_public_bundle = sender_keys.to_public_bundle(rng)?;
    let (file_key, recipient_vec, wrappings) =
        generate_and_wrap_file_key(sender_keys, recipients, rng)?;

    let layout = SegmentLayout::for_plaintext(plaintext_len, options.segment_size)?;

    let mut nonce_prefix = Zeroizing::new([0u8; STREAM_NONCE_PREFIX_LEN]);
    rng.fill_bytes(nonce_prefix.as_mut());
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce_prefix.as_ref());

    let meta = CipherMeta {
        cipher_suite: STREAM_CIPHER_SUITE,
        cipher_nonce_b64: &nonce_b64,
        segment_count: layout.segment_count,
        last_segment_bytes: layout.last_segment_bytes,
        ciphertext_len: layout.ciphertext_len,
        filename_hint: options.filename_hint,
    };

    let header = build_envelope_header_with_wrappings(
        sender_identity,
        sender_keys.identity(),
        &sender_public_bundle,
        &recipient_vec,
        &wrappings,
        &meta,
        rng,
    )?;
    writer.write_all(&header)?;
    let mut written = u64::try_from(header.len()).map_err(|_| "header too large")?;

    let workers = resolve_parallelism(options.parallelism);
    let batch_len = workers * BATCH_PER_WORKER;
    let file_key: &[u8; 32] = &file_key;
    let nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN] = &nonce_prefix;
    let mut buffers = segment_buffers(batch_len, layout.segment_size);

    let mut index = 0u32;
    while index < layout.segment_count {
        // Fill a batch of buffers with plaintext segments.
        let first = index;
        let mut filled = 0usize;
        while index < layout.segment_count && filled < batch_len {
            let len = usize::try_from(layout.segment_plaintext_len(index))
                .map_err(|_| "segment does not fit in memory")?;
            let buf = &mut buffers[filled];
            buf.resize(len, 0);
            reader
                .read_exact(buf)
                .map_err(|_| "plaintext ended before the declared length")?;
            filled += 1;
            index += 1;
        }
        // Seal them in place concurrently, then write in order.
        process_batch_in_place(&mut buffers[..filled], workers, |k, buf| {
            let i = first + u32::try_from(k).map_err(|_| "segment index overflow")?;
            encrypt_segment_in_place(file_key, nonce_prefix, i, layout.is_last(i), buf)
        })?;
        for buf in &buffers[..filled] {
            writer.write_all(buf)?;
            written += u64::try_from(buf.len()).map_err(|_| "segment too large")?;
        }
    }

    // The declared length is signed into the prelude: refuse to silently drop trailing input.
    let mut probe = [0u8; 1];
    if reader.read(&mut probe)? != 0 {
        return Err("plaintext is longer than the declared length".into());
    }

    writer.flush()?;
    Ok(written)
}

/// Authenticate the envelope header for `recipient_identity` and unwrap the file key.
///
/// Performs the sender signature/fingerprint checks, the constant-time recipient lookup, the
/// X3DH derivation, and the key unwrap. Shared by [`decrypt_message`] and [`decrypt_stream`].
fn authenticate_and_unwrap_file_key(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    prelude: &EnvelopePrelude,
    envelope_signature_valid: bool,
) -> Result<Zeroizing<[u8; 32]>> {
    let signature_valid = sender_bundle.verify_signatures();
    let expected_fp = sender_bundle.identity_fingerprint();
    let fingerprint_match = expected_fp
        .as_bytes()
        .ct_eq(prelude.sender.ik_fingerprint.as_bytes())
        .unwrap_u8();
    let combined = Choice::from(signature_valid as u8)
        & Choice::from(envelope_signature_valid as u8)
        & Choice::from(fingerprint_match);
    if combined.ct_eq(&Choice::from(1)).unwrap_u8() != 1 {
        return Err(KeyError::InvalidSignature);
    }

    if prelude.cipher.suite != FILE_CIPHER_SUITE && prelude.cipher.suite != STREAM_CIPHER_SUITE {
        return Err(KeyError::InvalidFormat);
    }

    let mut recipient_index = 0usize;
    let mut match_choice = Choice::from(0);
    for (idx, info) in prelude.recipients.iter().enumerate() {
        let eq = ct_identity_match(info.identity.as_deref(), recipient_identity);
        let eq_mask = usize::from(eq.unwrap_u8());
        recipient_index = eq_mask * idx + (1 - eq_mask) * recipient_index;
        match_choice |= eq;
    }
    if match_choice.unwrap_u8() == 0 {
        return Err(KeyError::RecipientNotFound);
    }

    let wrapping = prelude
        .wrappings
        .get(recipient_index)
        .ok_or(KeyError::InvalidSignature)?;

    // Decode wrapping ciphertext: wrapped_key (72 bytes)
    let wrapped_file_key = URL_SAFE_NO_PAD
        .decode(&wrapping.wrap_ciphertext)
        .map_err(|_| KeyError::InvalidFormat)?;

    if wrapped_file_key.len() != WRAPPED_KEY_SIZE {
        return Err(KeyError::InvalidFormat);
    }

    // Derive X3DH shared material
    let x3dh_material = derive_recipient_shared_material(recipient_keys, sender_bundle, wrapping)?;

    // Unwrap file key using X3DH material
    unwrap_file_key(x3dh_material.as_ref(), &wrapped_file_key)
}

/// Decode the prelude nonce for the whole-payload suite (24 bytes).
fn file_nonce(prelude: &EnvelopePrelude) -> Result<Zeroizing<[u8; 24]>> {
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&prelude.cipher.nonce)
        .map_err(|_| KeyError::InvalidFormat)?;
    if nonce_bytes.len() != 24 {
        return Err(KeyError::InvalidFormat);
    }
    let mut nonce = Zeroizing::new([0u8; 24]);
    nonce.copy_from_slice(&nonce_bytes);
    Ok(nonce)
}

/// Decode the prelude nonce prefix for the streaming suite (19 bytes) and the segment layout.
fn stream_geometry(
    prelude: &EnvelopePrelude,
) -> Result<(Zeroizing<[u8; STREAM_NONCE_PREFIX_LEN]>, SegmentLayout)> {
    let prefix_bytes = URL_SAFE_NO_PAD
        .decode(&prelude.cipher.nonce)
        .map_err(|_| KeyError::InvalidFormat)?;
    if prefix_bytes.len() != STREAM_NONCE_PREFIX_LEN {
        return Err(KeyError::InvalidFormat);
    }
    let mut prefix = Zeroizing::new([0u8; STREAM_NONCE_PREFIX_LEN]);
    prefix.copy_from_slice(&prefix_bytes);
    let layout = SegmentLayout::from_cipher_info(
        prelude.cipher.segment_count,
        prelude.cipher.last_segment_bytes,
        prelude.cipher.ciphertext_len,
    )?;
    Ok((prefix, layout))
}

/// Decrypt an envelope for the active recipient.
///
/// Opens envelopes sealed with either cipher suite. For the streaming suite the whole ciphertext
/// is still expected in `parsed`; use [`decrypt_stream`] to open large envelopes without
/// loading them.
pub fn decrypt_message(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    parsed: &ParsedEnvelope,
) -> Result<Vec<u8>> {
    let envelope_signature_valid =
        verify_signature(parsed, &sender_bundle.identity_signing_public_key).is_ok();
    let file_key = authenticate_and_unwrap_file_key(
        recipient_identity,
        recipient_keys,
        sender_bundle,
        &parsed.prelude,
        envelope_signature_valid,
    )?;

    if parsed.prelude.cipher.suite == STREAM_CIPHER_SUITE {
        let (prefix, layout) = stream_geometry(&parsed.prelude)?;
        let mut plaintext = Vec::with_capacity(usize::try_from(layout.ciphertext_len).unwrap_or(0));
        let mut reader = parsed.ciphertext.as_slice();
        decrypt_segments(&file_key, &prefix, &layout, &mut reader, &mut plaintext, 1)?;
        return Ok(plaintext);
    }

    let nonce = file_nonce(&parsed.prelude)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*file_key));
    cipher
        .decrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: &parsed.ciphertext,
                aad: FILE_AAD,
            },
        )
        .map_err(|_| KeyError::DecryptionFailed)
}

/// Read, open, and write every segment described by `layout`, then require end of input.
///
/// Segments are opened in place, concurrently on `workers` threads in batches, and written in
/// order. Every segment authenticates its own index and last-flag, so concurrency cannot weaken
/// the ordering or truncation checks: a segment that does not belong at its position simply
/// fails to open. Buffers are zeroized after each batch is written.
fn decrypt_segments<I: Read, O: Write>(
    file_key: &[u8; 32],
    nonce_prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    layout: &SegmentLayout,
    reader: &mut I,
    writer: &mut O,
    workers: usize,
) -> Result<u64> {
    let batch_len = workers * BATCH_PER_WORKER;
    let mut buffers = segment_buffers(batch_len, layout.segment_size);
    let mut written = 0u64;
    let mut index = 0u32;
    while index < layout.segment_count {
        let first = index;
        let mut filled = 0usize;
        while index < layout.segment_count && filled < batch_len {
            let len = usize::try_from(layout.segment_ciphertext_len(index))
                .map_err(|_| "segment does not fit in memory")?;
            let buf = &mut buffers[filled];
            buf.resize(len, 0);
            reader
                .read_exact(buf)
                .map_err(|_| KeyError::DecryptionFailed)?;
            filled += 1;
            index += 1;
        }
        process_batch_in_place(&mut buffers[..filled], workers, |k, buf| {
            let i = first + u32::try_from(k).map_err(|_| "segment index overflow")?;
            decrypt_segment_in_place(file_key, nonce_prefix, i, layout.is_last(i), buf)
        })?;
        for buf in &mut buffers[..filled] {
            writer.write_all(buf)?;
            written += u64::try_from(buf.len()).map_err(|_| "segment too large")?;
            buf.zeroize();
        }
    }

    // The last segment carries the terminal flag, so anything after it is an appended forgery.
    let mut probe = [0u8; 1];
    if reader.read(&mut probe)? != 0 {
        return Err(KeyError::DecryptionFailed);
    }
    Ok(written)
}

/// Decrypt an envelope read from `reader` for the active recipient, writing the plaintext to
/// `writer`, while holding at most one segment in memory.
///
/// The header is parsed and its signature verified before any ciphertext is read. Envelopes
/// sealed with the streaming suite are opened segment by segment; envelopes sealed with the
/// whole-payload suite are also accepted, but their ciphertext is necessarily buffered.
///
/// `parallelism` is the number of segments opened concurrently (`0` = one per CPU, capped at
/// [`MAX_PARALLELISM`]; `1` = calling thread only).
///
/// Returns the number of plaintext bytes written.
pub fn decrypt_stream<I: Read, O: Write>(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    reader: &mut I,
    writer: &mut O,
    parallelism: usize,
) -> Result<u64> {
    let header: ParsedEnvelopeHeader = parse_envelope_header(reader)?;
    let envelope_signature_valid =
        verify_header_signature(&header, &sender_bundle.identity_signing_public_key).is_ok();
    let file_key = authenticate_and_unwrap_file_key(
        recipient_identity,
        recipient_keys,
        sender_bundle,
        &header.prelude,
        envelope_signature_valid,
    )?;

    if header.prelude.cipher.suite == STREAM_CIPHER_SUITE {
        let (prefix, layout) = stream_geometry(&header.prelude)?;
        let workers = resolve_parallelism(parallelism);
        let written = decrypt_segments(&file_key, &prefix, &layout, reader, writer, workers)?;
        writer.flush()?;
        return Ok(written);
    }

    // Whole-payload suite: the AEAD needs the full ciphertext, so buffer exactly what the
    // signed prelude declares and refuse anything beyond it.
    let ciphertext_len = usize::try_from(header.prelude.cipher.ciphertext_len)
        .map_err(|_| "ciphertext does not fit in memory")?;
    let mut ciphertext = vec![0u8; ciphertext_len];
    reader
        .read_exact(&mut ciphertext)
        .map_err(|_| KeyError::DecryptionFailed)?;
    let mut probe = [0u8; 1];
    if reader.read(&mut probe)? != 0 {
        return Err(KeyError::DecryptionFailed);
    }
    let nonce = file_nonce(&header.prelude)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*file_key));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&*nonce),
                Payload {
                    msg: &ciphertext,
                    aad: FILE_AAD,
                },
            )
            .map_err(|_| KeyError::DecryptionFailed)?,
    );
    writer.write_all(&plaintext)?;
    writer.flush()?;
    u64::try_from(plaintext.len()).map_err(|_| "plaintext too large".into())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
