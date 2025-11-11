use crate::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: &[u8; 4] = b"SYC1";
pub const CURRENT_VERSION: u8 = 1;
const PRELUDE_PAD: usize = 4096;
const STUB_SIGNATURE: &[u8] = b"syc-stub-signature-v1";

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
    pub pqspk_fingerprint: Option<String>,
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
    pub last_segment_bytes: u32,
    pub ciphertext_len: u64,
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

pub fn has_syc_magic(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

pub fn build_stub_envelope(
    sender_identity: &str,
    recipients: &[String],
    ciphertext: &[u8],
    filename_hint: Option<&str>,
) -> Result<Vec<u8>> {
    let prelude = build_stub_prelude(sender_identity, recipients, ciphertext.len(), filename_hint);
    let prelude_bytes = to_jcs_bytes(&prelude)?;
    let prelude_len = prelude_bytes.len();
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD);

    let signature = stub_signature(&prelude_bytes);

    let mut out = Vec::with_capacity(
        MAGIC.len()
            + 1
            + std::mem::size_of::<u32>()
            + padded_len
            + std::mem::size_of::<u16>()
            + signature.len()
            + ciphertext.len(),
    );

    out.extend_from_slice(MAGIC);
    out.push(CURRENT_VERSION);
    out.extend_from_slice(&u32::try_from(prelude_len)?.to_le_bytes());
    out.extend_from_slice(&prelude_bytes);
    if padded_len > prelude_len {
        out.resize(out.len() + (padded_len - prelude_len), 0u8);
    }
    out.extend_from_slice(&u16::try_from(signature.len())?.to_le_bytes());
    out.extend_from_slice(&signature);
    out.extend_from_slice(ciphertext);

    Ok(out)
}

pub fn parse_envelope(bytes: &[u8]) -> Result<ParsedEnvelope> {
    if bytes.len() < MAGIC.len() + 1 + std::mem::size_of::<u32>() {
        return Err("file is too small to contain SYC envelope header".into());
    }
    if !has_syc_magic(bytes) {
        return Err("file does not begin with SYC envelope magic".into());
    }
    let mut cursor = MAGIC.len();
    let version = bytes[cursor];
    cursor += 1;
    if version != CURRENT_VERSION {
        return Err(format!("unsupported SYC envelope version {}", version).into());
    }
    let prelude_len_bytes = &bytes[cursor..cursor + 4];
    let prelude_len = u32::from_le_bytes(prelude_len_bytes.try_into().unwrap()) as usize;
    cursor += 4;
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD);

    if bytes.len() < cursor + padded_len {
        return Err("file truncated while reading SYC prelude".into());
    }
    let prelude_slice = &bytes[cursor..cursor + prelude_len];
    let prelude_bytes = prelude_slice.to_vec();
    cursor += padded_len;

    if bytes.len() < cursor + 2 {
        return Err("file truncated while reading SYC signature length".into());
    }
    let signature_len = u16::from_le_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
    cursor += 2;

    if bytes.len() < cursor + signature_len {
        return Err("file truncated while reading SYC signature".into());
    }
    let signature = bytes[cursor..cursor + signature_len].to_vec();
    cursor += signature_len;

    let ciphertext = bytes[cursor..].to_vec();

    let prelude: EnvelopePrelude = from_jcs_bytes(&prelude_bytes)?;

    Ok(ParsedEnvelope {
        prelude,
        prelude_bytes,
        signature,
        ciphertext,
    })
}

pub fn verify_stub_signature(parsed: &ParsedEnvelope, skip_checks: bool) -> Result<()> {
    if skip_checks {
        return Ok(());
    }
    let expected = stub_signature(&parsed.prelude_bytes);
    if parsed.signature != expected {
        return Err("SYCe signature verification failed (stub placeholder mismatch)".into());
    }
    Ok(())
}

fn build_stub_prelude(
    sender_identity: &str,
    recipients: &[String],
    ciphertext_len: usize,
    filename_hint: Option<&str>,
) -> EnvelopePrelude {
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sender = SenderInfo {
        identity: sender_identity.to_owned(),
        ik_fingerprint: stub_fingerprint(sender_identity),
    };

    let recipients_infos = if recipients.is_empty() {
        vec![RecipientInfo {
            identity: None,
            device_label: None,
            spk_fingerprint: None,
            pqspk_fingerprint: None,
            signed_prekey_id: None,
        }]
    } else {
        recipients
            .iter()
            .map(|recipient| RecipientInfo {
                identity: Some(recipient.clone()),
                device_label: Some("stub-device".into()),
                spk_fingerprint: Some(stub_fingerprint(&(recipient.clone() + ":spk"))),
                pqspk_fingerprint: Some(stub_fingerprint(&(recipient.clone() + ":pqspk"))),
                signed_prekey_id: Some(1),
            })
            .collect()
    };

    let wrappings = recipients
        .iter()
        .map(|recipient| WrappingInfo {
            recipient_identity: Some(recipient.clone()),
            device_label: Some("stub-device".into()),
            wrap_ephemeral_public: "stub-epk".into(),
            wrap_ciphertext: "stub-kem-ciphertext".into(),
        })
        .collect::<Vec<_>>();

    let cipher = CipherInfo {
        suite: "libsignal-file-v1".into(),
        segment_count: 1,
        last_segment_bytes: u32::try_from(ciphertext_len).unwrap_or(u32::MAX),
        ciphertext_len: ciphertext_len as u64,
    };

    let public_meta = filename_hint.map(|hint| PublicMeta {
        filename_hint: Some(hint.to_owned()),
    });

    EnvelopePrelude {
        version: 1,
        canon: JCS_CANON_LABEL.to_string(),
        created_at,
        sender,
        recipients: recipients_infos,
        recipient_set_fpr: format!("stub-fpr-{}", recipients.len()),
        wrappings,
        cipher,
        integrity: None,
        public_meta,
    }
}

fn stub_fingerprint(input: &str) -> String {
    format!("stub-{}", input.replace('@', "_at_"))
}

fn stub_signature(prelude_bytes: &[u8]) -> Vec<u8> {
    let mut sig = Vec::with_capacity(STUB_SIGNATURE.len() + prelude_bytes.len().min(8));
    sig.extend_from_slice(STUB_SIGNATURE);
    sig.extend_from_slice(&prelude_bytes[..prelude_bytes.len().min(8)]);
    sig
}

fn align_to_block(len: usize, block: usize) -> usize {
    if len == 0 {
        return block;
    }
    len.div_ceil(block) * block
}

/// Canonical label for RFC 8785 JSON Canonicalization Scheme.
pub const JCS_CANON_LABEL: &str = "jcs-rfc8785";

pub fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_jcs::to_vec(value)?)
}

pub fn from_jcs_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: Value = serde_json::from_slice(bytes)?;
    let canonical = serde_jcs::to_vec(&value)?;
    if canonical != bytes {
        return Err("prelude JSON is not RFC 8785 canonical".into());
    }
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/envelope_tests.rs"
    ));
}
