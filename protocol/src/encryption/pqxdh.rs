//! PQXDH (Post-Quantum Extended Diffie-Hellman) key agreement protocol.

use crate::envelope::WrappingInfo;
use crate::keys::{SyftPrivateKeys, SyftPublicKeyBundle};
use crate::{Result, error::KeyError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libsignal_protocol::{KeyPair, PublicKey};
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

/// Serialized libsignal X25519 public keys include a 1-byte key-type tag.
const X25519_PUBLIC_KEY_LEN: usize = 33;

/// Performs sender-side PQXDH key agreement.
///
/// Establishes shared secret material by combining X25519 DH operations with Kyber1024
/// key encapsulation. The sender (Alice) computes:
///
/// - DH1 = DH(IKA_priv, SPKB_pub)
/// - DH2 = DH(SPKA_priv, IKB_pub)
/// - DH3 = DH(EKA_priv, IKB_pub)  [fresh ephemeral key for forward secrecy]
/// - DH4 = DH(EKA_priv, SPKB_pub)
/// - (SS, CT) = Kyber1024.Encapsulate(PQPKB_pub)
/// - PQXDH_material = DH1 || DH2 || DH3 || DH4 || SS
///
/// Where:
/// - IK = Identity Key, SPK = Signed PreKey, EK = Ephemeral Key, PQPK = Post-Quantum PreKey
/// - A = sender (Alice), B = recipient (Bob)
/// - SS = Kyber shared secret, CT = Kyber ciphertext
///
/// Returns PQXDH material (~196 bytes) and wrapping metadata (EKA_pub, CT) for the recipient.
///
/// # Errors
/// - `KeyError::InvalidSignature` if recipient bundle signature verification fails
/// - `KeyError::SignalError` if DH operations or Kyber encapsulation fail
pub(super) fn derive_sender_shared_material<R: CryptoRng + Rng>(
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

/// Performs recipient-side PQXDH key agreement.
///
/// Derives the same shared secret material as the sender by performing the same DH operations
/// from the recipient's perspective and decapsulating the Kyber ciphertext. The recipient (Bob) computes:
///
/// - DH1 = DH(SPKB_priv, IKA_pub)
/// - DH2 = DH(IKB_priv, SPKA_pub)
/// - DH3 = DH(IKB_priv, EKA_pub)  [EKA_pub received from sender]
/// - DH4 = DH(SPKB_priv, EKA_pub)
/// - SS = Kyber1024.Decapsulate(CT, PQPKB_priv)  [CT received from sender]
/// - PQXDH_material = DH1 || DH2 || DH3 || DH4 || SS
///
/// Where:
/// - IK = Identity Key, SPK = Signed PreKey, EK = Ephemeral Key, PQPK = Post-Quantum PreKey
/// - A = sender (Alice), B = recipient (Bob)
/// - SS = Kyber shared secret, CT = Kyber ciphertext (from wrapping metadata)
///
/// Returns the same PQXDH material (~196 bytes) computed by the sender.
///
/// # Errors
/// - `KeyError::InvalidFormat` if ephemeral key or Kyber ciphertext is malformed
/// - `KeyError::SignalError` if DH operations or Kyber decapsulation fail
pub(super) fn derive_recipient_shared_material(
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

/// Validates Kyber ciphertext format before decapsulation.
///
/// Checks that:
/// - Ciphertext length matches public key serialized length
/// - First byte (key type tag) matches expected value
///
/// This prevents crashes from malformed input to Kyber decapsulation.
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
