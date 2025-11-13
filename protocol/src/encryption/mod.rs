use crate::envelope::{
    EnvelopePayload, ParsedEnvelope, WrappingInfo, build_envelope_with_wrappings, verify_signature,
};
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::{Result, error::KeyError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use libsignal_protocol::{KeyPair, PublicKey};
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

const FILE_HKDF_SALT: &[u8] = b"syc-crypto-core:pqxdh:file";
const FILE_AAD: &[u8] = b"syc-file-v1";
// Serialized libsignal X25519 public keys include a 1-byte key-type tag.
const X25519_PUBLIC_KEY_LEN: usize = 33;
// Wrapped key format: nonce (24) + encrypted_key (32) + auth_tag (16)
const WRAPPED_KEY_SIZE: usize = 72;

/// File cipher suite advertised in envelope metadata.
pub const FILE_CIPHER_SUITE: &str = "xchacha20poly1305-v1";

/// Recipient metadata required to encrypt a payload.
pub struct EncryptionRecipient<'a> {
    pub identity: &'a str,
    pub bundle: &'a SyftPublicKeyBundle,
}

/// Encrypt plaintext bytes for the provided recipients, returning a fully formed SYC envelope.
///
/// Supports multiple recipients - the file is encrypted once with a random key, then that key
/// is wrapped separately for each recipient using PQXDH.
pub fn encrypt_message<R: CryptoRng + Rng>(
    sender_identity: &str,
    sender_keys: &SyftPrivateKeys,
    recipients: &[EncryptionRecipient<'_>],
    plaintext: &[u8],
    filename_hint: Option<&str>,
    rng: &mut R,
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err("at least one recipient is required".into());
    }

    let sender_public_bundle = sender_keys.to_public_bundle(rng)?;

    // Generate a random file encryption key
    let file_key = Zeroizing::new({
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        key
    });

    // Encrypt the file / the payload once with the generated random key
    let mut file_nonce = Zeroizing::new([0u8; 24]);
    rng.fill_bytes(file_nonce.as_mut());
    let nonce_b64 = URL_SAFE_NO_PAD.encode(file_nonce.as_ref());
    let ciphertext = encrypt_payload(&file_key, &file_nonce, plaintext)?;

    // Wrap file key for each recipient (Key Encapsulation Mechanism)
    let mut recipient_vec = Vec::with_capacity(recipients.len());
    let mut wrappings = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let (pqxdh_material, mut wrapping_info) =
            derive_sender_shared_material(sender_keys, recipient.identity, recipient.bundle, rng)?;

        // Wrap the file key using PQXDH material
        let wrapped_key = wrap_file_key(pqxdh_material.as_ref(), &file_key, rng)?;

        // Decode the existing kyber ciphertext from the wrapping
        let kyber_ct = URL_SAFE_NO_PAD
            .decode(&wrapping_info.wrap_ciphertext)
            .map_err(|_| KeyError::InvalidFormat)?;

        // Combine: wrapped_key (72 bytes) || kyber_ct (~1568 bytes)
        let mut combined = wrapped_key;
        combined.extend_from_slice(&kyber_ct);

        // Update wrapping with combined data
        wrapping_info.wrap_ciphertext = URL_SAFE_NO_PAD.encode(&combined);

        recipient_vec.push((recipient.identity.to_string(), recipient.bundle.clone()));
        wrappings.push(wrapping_info);
    }

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

/// Decrypt an envelope for the active recipient.
pub fn decrypt_message(
    recipient_identity: &str,
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    parsed: &ParsedEnvelope,
) -> Result<Vec<u8>> {
    let signature_valid = sender_bundle.verify_signatures();
    let envelope_signature_valid =
        verify_signature(parsed, &sender_bundle.signal_identity_public_key).is_ok();
    let expected_fp = sender_bundle.identity_fingerprint();
    let fingerprint_match = expected_fp
        .as_bytes()
        .ct_eq(parsed.prelude.sender.ik_fingerprint.as_bytes())
        .unwrap_u8();
    let combined = Choice::from(signature_valid as u8)
        & Choice::from(envelope_signature_valid as u8)
        & Choice::from(fingerprint_match);
    if combined.ct_eq(&Choice::from(1)).unwrap_u8() != 1 {
        return Err(KeyError::InvalidSignature);
    }

    if parsed.prelude.cipher.suite != FILE_CIPHER_SUITE {
        return Err(KeyError::InvalidFormat);
    }

    let mut recipient_index = 0usize;
    let mut match_choice = Choice::from(0);
    for (idx, info) in parsed.prelude.recipients.iter().enumerate() {
        let eq = ct_identity_match(info.identity.as_deref(), recipient_identity);
        let eq_mask = usize::from(eq.unwrap_u8());
        recipient_index = eq_mask * idx + (1 - eq_mask) * recipient_index;
        match_choice |= eq;
    }
    if match_choice.unwrap_u8() == 0 {
        return Err(KeyError::InvalidSignature);
    }

    let wrapping = parsed
        .prelude
        .wrappings
        .get(recipient_index)
        .ok_or(KeyError::InvalidSignature)?;

    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&parsed.prelude.cipher.nonce)
        .map_err(|_| KeyError::InvalidFormat)?;
    if nonce_bytes.len() != 24 {
        return Err(KeyError::InvalidFormat);
    }
    let mut nonce = Zeroizing::new([0u8; 24]);
    nonce.copy_from_slice(&nonce_bytes);

    // Decode wrapping ciphertext: wrapped_key (72 bytes) || kyber_ct
    let wrap_ciphertext_combined = URL_SAFE_NO_PAD
        .decode(&wrapping.wrap_ciphertext)
        .map_err(|_| KeyError::InvalidFormat)?;

    if wrap_ciphertext_combined.len() < WRAPPED_KEY_SIZE {
        return Err(KeyError::InvalidFormat);
    }

    // Split wrapped file key and kyber ciphertext
    let (wrapped_file_key, kyber_ct) = wrap_ciphertext_combined.split_at(WRAPPED_KEY_SIZE);

    // Create modified wrapping with only kyber_ct for PQXDH derivation
    let pqxdh_wrapping = WrappingInfo {
        recipient_identity: wrapping.recipient_identity.clone(),
        device_label: wrapping.device_label.clone(),
        wrap_ephemeral_public: wrapping.wrap_ephemeral_public.clone(),
        wrap_ciphertext: URL_SAFE_NO_PAD.encode(kyber_ct),
    };

    // Derive PQXDH shared material
    let pqxdh_material =
        derive_recipient_shared_material(recipient_keys, sender_bundle, &pqxdh_wrapping)?;

    // Unwrap file key using PQXDH material
    let file_key = unwrap_file_key(pqxdh_material.as_ref(), wrapped_file_key)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*file_key));
    cipher
        .decrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: &parsed.ciphertext,
                aad: FILE_AAD,
            },
        )
        .map_err(|_| KeyError::InvalidSignature)
}

fn derive_sender_shared_material<R: CryptoRng + Rng>(
    sender_keys: &SyftPrivateKeys,
    recipient_identity: &str,
    recipient_bundle: &SyftPublicKeyBundle,
    rng: &mut R,
) -> Result<(Zeroizing<Vec<u8>>, WrappingInfo)> {
    if !recipient_bundle.verify_signatures() {
        return Err(KeyError::InvalidSignature);
    }

    let ephemeral = KeyPair::generate(rng);

    let dh1 = Zeroizing::new(
        sender_keys
            .identity()
            .private_key()
            .calculate_agreement(&recipient_bundle.signal_signed_public_pre_key)
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );
    let dh2 = Zeroizing::new(
        sender_keys
            .signed_pre_key()
            .private_key
            .calculate_agreement(recipient_bundle.signal_identity_public_key.public_key())
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );
    let dh3 = Zeroizing::new(
        ephemeral
            .private_key
            .calculate_agreement(recipient_bundle.signal_identity_public_key.public_key())
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );
    let dh4 = Zeroizing::new(
        ephemeral
            .private_key
            .calculate_agreement(&recipient_bundle.signal_signed_public_pre_key)
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );

    let (pq_secret_raw, pq_ciphertext) = recipient_bundle
        .signal_pq_public_pre_key
        .encapsulate(rng)
        .map_err(KeyError::SignalError)?;
    let pq_secret = Zeroizing::new(pq_secret_raw);

    let mut material = Zeroizing::new(Vec::with_capacity(
        dh1.len() + dh2.len() + dh3.len() + dh4.len() + pq_secret.len(),
    ));
    material.extend_from_slice(dh1.as_ref());
    material.extend_from_slice(dh2.as_ref());
    material.extend_from_slice(dh3.as_ref());
    material.extend_from_slice(dh4.as_ref());
    material.extend_from_slice(pq_secret.as_ref());

    let wrapping = WrappingInfo {
        recipient_identity: Some(recipient_identity.to_owned()),
        device_label: Some("default".into()),
        wrap_ephemeral_public: URL_SAFE_NO_PAD.encode(ephemeral.public_key.serialize()),
        wrap_ciphertext: URL_SAFE_NO_PAD.encode(&pq_ciphertext),
    };

    Ok((material, wrapping))
}

fn derive_recipient_shared_material(
    recipient_keys: &SyftPrivateKeys,
    sender_bundle: &SyftPublicKeyBundle,
    wrapping: &WrappingInfo,
) -> Result<Zeroizing<Vec<u8>>> {
    let ephemeral_bytes = URL_SAFE_NO_PAD
        .decode(&wrapping.wrap_ephemeral_public)
        .map_err(|_| KeyError::InvalidFormat)?;
    if ephemeral_bytes.len() != X25519_PUBLIC_KEY_LEN {
        return Err(KeyError::InvalidFormat);
    }
    let pq_ciphertext_bytes = URL_SAFE_NO_PAD
        .decode(&wrapping.wrap_ciphertext)
        .map_err(|_| KeyError::InvalidFormat)?;
    validate_pq_ciphertext(recipient_keys, &pq_ciphertext_bytes)?;

    let ephemeral_public = PublicKey::try_from(ephemeral_bytes.as_slice())
        .map_err(|e| KeyError::SignalError(e.into()))?;

    let dh1 = Zeroizing::new(
        recipient_keys
            .signed_pre_key()
            .private_key
            .calculate_agreement(sender_bundle.signal_identity_public_key.public_key())
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );
    let dh2 = Zeroizing::new(
        recipient_keys
            .identity()
            .private_key()
            .calculate_agreement(&sender_bundle.signal_signed_public_pre_key)
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );
    let dh3 = Zeroizing::new(
        recipient_keys
            .identity()
            .private_key()
            .calculate_agreement(&ephemeral_public)
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );
    let dh4 = Zeroizing::new(
        recipient_keys
            .signed_pre_key()
            .private_key
            .calculate_agreement(&ephemeral_public)
            .map_err(|e| KeyError::SignalError(e.into()))?,
    );

    let pq_shared = Zeroizing::new(
        recipient_keys
            .pq_signed_pre_key()
            .secret_key
            .decapsulate(&pq_ciphertext_bytes.into_boxed_slice())
            .map_err(KeyError::SignalError)?,
    );

    let mut material = Zeroizing::new(Vec::with_capacity(
        dh1.len() + dh2.len() + dh3.len() + dh4.len() + pq_shared.len(),
    ));
    material.extend_from_slice(dh1.as_ref());
    material.extend_from_slice(dh2.as_ref());
    material.extend_from_slice(dh3.as_ref());
    material.extend_from_slice(dh4.as_ref());
    material.extend_from_slice(pq_shared.as_ref());
    Ok(material)
}

fn validate_pq_ciphertext(recipient_keys: &SyftPrivateKeys, ciphertext: &[u8]) -> Result<()> {
    let public_key_bytes = recipient_keys.pq_signed_pre_key().public_key.serialize();
    if ciphertext.len() != public_key_bytes.len() {
        return Err(KeyError::InvalidFormat);
    }
    let expected_tag = public_key_bytes
        .first()
        .copied()
        .ok_or(KeyError::InvalidFormat)?;
    if ciphertext.first().copied() != Some(expected_tag) {
        return Err(KeyError::InvalidFormat);
    }

    Ok(())
}

fn encrypt_payload(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Result<Vec<u8>> {
    // libsignal's Rust bindings currently expose PQXDH/session layers but do not provide
    // an attachment/file cipher helper. Until that API exists upstream we locally reuse the
    // XChaCha20-Poly1305 construction Signal uses elsewhere so callers can seal bytes today.
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

const KEY_WRAP_AAD: &[u8] = b"syc-key-wrap-v1";
const KEY_WRAP_INFO: &[u8] = b"syc-wrap-key";

/// Derives a wrapping key from PQXDH shared material and wraps the file key.
/// Returns: nonce (24 bytes) || wrapped_key (32 bytes plaintext + 16 bytes auth tag) = 72 bytes total
fn wrap_file_key<R: CryptoRng + Rng>(
    pqxdh_material: &[u8],
    file_key: &[u8; 32],
    rng: &mut R,
) -> Result<Vec<u8>> {
    // Derive wrapping key from PQXDH material using HKDF
    let hkdf = Hkdf::<Sha256>::new(Some(FILE_HKDF_SALT), pqxdh_material);
    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(KEY_WRAP_INFO, wrapping_key.as_mut())
        .map_err(|_| KeyError::HkdfError)?;

    // Generate random nonce
    let mut nonce = Zeroizing::new([0u8; 24]);
    rng.fill_bytes(nonce.as_mut());

    // Encrypt file key with wrapping key
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*wrapping_key));
    let mut ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: file_key,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| "key wrapping failed")?;

    // Return nonce || ciphertext+tag
    let mut result = nonce.to_vec();
    result.append(&mut ciphertext);
    Ok(result) // WRAPPED_KEY_SIZE bytes
}

/// Unwraps file encryption key using PQXDH shared material.
/// Input: nonce (24 bytes) || wrapped_key (48 bytes with tag)
fn unwrap_file_key(pqxdh_material: &[u8], wrapped_data: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped_data.len() != WRAPPED_KEY_SIZE {
        return Err(KeyError::InvalidFormat);
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = wrapped_data.split_at(24);
    let mut nonce = Zeroizing::new([0u8; 24]);
    nonce.copy_from_slice(nonce_bytes);

    // Derive wrapping key from PQXDH material
    let hkdf = Hkdf::<Sha256>::new(Some(FILE_HKDF_SALT), pqxdh_material);
    let mut wrapping_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(KEY_WRAP_INFO, wrapping_key.as_mut())
        .map_err(|_| KeyError::HkdfError)?;

    // Decrypt file key
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*wrapping_key));
    let file_key_bytes = cipher
        .decrypt(
            XNonce::from_slice(&*nonce),
            Payload {
                msg: ciphertext,
                aad: KEY_WRAP_AAD,
            },
        )
        .map_err(|_| KeyError::InvalidSignature)?;

    let mut file_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&file_key_bytes);
    Ok(file_key)
}

fn ct_identity_match(candidate: Option<&str>, target: &str) -> Choice {
    match candidate {
        Some(identity) => {
            let lhs = identity.as_bytes();
            let rhs = target.as_bytes();
            let max_len = lhs.len().max(rhs.len());
            let mut diff = 0u8;
            for i in 0..max_len {
                let l = *lhs.get(i).unwrap_or(&0);
                let r = *rhs.get(i).unwrap_or(&0);
                diff |= l ^ r;
            }
            let len_match = (lhs.len() as u64).ct_eq(&(rhs.len() as u64));
            let bytes_match = diff.ct_eq(&0);
            len_match & bytes_match
        }
        None => Choice::from(0),
    }
}
