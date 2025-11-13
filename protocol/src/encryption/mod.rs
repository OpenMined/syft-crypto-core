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
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const FILE_HKDF_SALT: &[u8] = b"syc-crypto-core:pqxdh:file";
const FILE_KEY_INFO: &[u8] = b"syc-file-key";
const FILE_AAD: &[u8] = b"syc-file-v1";
// Serialized libsignal X25519 public keys include a 1-byte key-type tag.
const X25519_PUBLIC_KEY_LEN: usize = 33;

/// File cipher suite advertised in envelope metadata.
pub const FILE_CIPHER_SUITE: &str = "xchacha20poly1305-v1";

/// Recipient metadata required to encrypt a payload.
pub struct EncryptionRecipient<'a> {
    pub identity: &'a str,
    pub bundle: &'a SyftPublicKeyBundle,
}

/// Encrypt plaintext bytes for the provided recipients, returning a fully formed SYC envelope.
///
/// Currently, multi-recipient envelopes are not supported – the function will return an
/// error if more than one recipient is supplied.
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
    if recipients.len() > 1 {
        return Err("multi-recipient envelopes are not yet supported".into());
    }

    let sender_public_bundle = sender_keys.to_public_bundle(rng)?;
    let EncryptionRecipient { identity, bundle } = &recipients[0];

    let (shared_material, wrapping) =
        derive_sender_shared_material(sender_keys, identity, bundle, rng)?;
    let file_key = Zeroizing::new(derive_file_key(shared_material.as_ref())?);
    let mut file_nonce = Zeroizing::new([0u8; 24]);
    rng.fill_bytes(file_nonce.as_mut());
    let nonce_b64 = URL_SAFE_NO_PAD.encode(file_nonce.as_ref());
    let ciphertext = encrypt_payload(&file_key, &file_nonce, plaintext)?;

    let recipient_vec = vec![(identity.to_string(), (*bundle).clone())];
    let wrappings = vec![wrapping];

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

    let combined = (signature_valid as u8) & (envelope_signature_valid as u8) & fingerprint_match;
    if combined != 1 {
        return Err(KeyError::InvalidSignature);
    }

    if parsed.prelude.cipher.suite != FILE_CIPHER_SUITE {
        return Err(KeyError::InvalidFormat);
    }

    let recipient_index = parsed
        .prelude
        .recipients
        .iter()
        .position(|info| info.identity.as_deref() == Some(recipient_identity))
        .ok_or(KeyError::InvalidSignature)?;

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

    let shared_material =
        derive_recipient_shared_material(recipient_keys, sender_bundle, wrapping)?;
    let file_key = Zeroizing::new(derive_file_key(shared_material.as_ref())?);

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
    if ciphertext.len() <= 1 {
        return Err(KeyError::InvalidFormat);
    }

    // Serialized Kyber ciphertexts include a one-byte key-type tag. Ensure the tag matches the
    // recipient's published PQ pre-key; libsignal will enforce the remaining structure as part of
    // decapsulation.
    let public_key_bytes = recipient_keys.pq_signed_pre_key().public_key.serialize();
    let expected_tag = public_key_bytes
        .first()
        .copied()
        .ok_or(KeyError::InvalidFormat)?;
    if ciphertext[0] != expected_tag {
        return Err(KeyError::InvalidFormat);
    }

    Ok(())
}

fn derive_file_key(material: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(FILE_HKDF_SALT), material);
    let mut key = [0u8; 32];
    hkdf.expand(FILE_KEY_INFO, &mut key)
        .map_err(|_| KeyError::HkdfError)?;
    Ok(key)
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
