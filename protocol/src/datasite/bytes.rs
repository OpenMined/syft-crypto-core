use crate::datasite::context::{AppContext, atomic_write, resolve_data_path, resolve_identity};
use crate::datasite::crypto::{
    decrypt_envelope_for_recipient, encrypt_envelope_for_recipient, load_private_keys_for_identity,
    parse_optional_envelope, resolve_recipient_bundle, resolve_sender_bundle_for_decrypt,
};
use anyhow::{Result, bail};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BytesWriteOpts {
    pub relative: PathBuf,
    pub recipients: Vec<String>,
    pub plaintext: bool,
    pub overwrite: bool,
    pub hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BytesReadOpts {
    pub relative: PathBuf,
    pub identity: Option<String>,
    pub require_envelope: bool,
}

#[derive(Debug, Clone)]
pub struct BytesWriteOutcome {
    pub destination: PathBuf,
    pub bytes_written: usize,
    pub encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct BytesReadOutput {
    pub source: PathBuf,
    pub plaintext: Vec<u8>,
    pub envelope_used: bool,
}

pub fn write_bytes(
    context: &AppContext,
    opts: &BytesWriteOpts,
    data: &[u8],
) -> Result<BytesWriteOutcome> {
    let encrypted = !opts.recipients.is_empty() && !opts.plaintext;
    let data_path = resolve_data_path(context, &opts.relative);
    if data_path.exists() && !opts.overwrite {
        bail!(
            "path {} already exists (use --overwrite to replace)",
            data_path.display()
        );
    }

    let payload = if encrypted {
        if opts.recipients.len() != 1 {
            bail!("exactly one recipient is supported for encryption");
        }
        let sender_identity = resolve_identity(None, &context.vault_path)?;
        let recipient_identity = opts.recipients[0].clone();
        let sender_keys = load_private_keys_for_identity(context, &sender_identity)?;
        let recipient_bundle =
            resolve_recipient_bundle(context, &sender_keys, &sender_identity, &recipient_identity)?;
        let hint = opts.hint.clone().or_else(|| {
            opts.relative
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        });
        encrypt_envelope_for_recipient(
            &sender_identity,
            &sender_keys,
            &recipient_identity,
            &recipient_bundle,
            data,
            hint.as_deref(),
        )?
    } else {
        data.to_vec()
    };

    atomic_write(&data_path, &payload)?;
    Ok(BytesWriteOutcome {
        destination: data_path,
        bytes_written: payload.len(),
        encrypted,
    })
}

pub fn read_bytes(context: &AppContext, opts: &BytesReadOpts) -> Result<BytesReadOutput> {
    let data_path = resolve_data_path(context, &opts.relative);
    if !data_path.exists() {
        bail!("{} does not exist", data_path.display());
    }
    let bytes = fs::read(&data_path)?;

    let identity = resolve_identity(opts.identity.as_deref(), &context.vault_path)?;

    let (plaintext, envelope_used) = match parse_optional_envelope(&bytes)? {
        Some(envelope) => {
            let recipient_keys = load_private_keys_for_identity(context, &identity)?;
            let sender_bundle = resolve_sender_bundle_for_decrypt(context, &envelope)?;
            let plaintext = decrypt_envelope_for_recipient(
                &identity,
                &recipient_keys,
                &sender_bundle,
                &envelope,
            )?;
            (plaintext, true)
        }
        None => {
            if opts.require_envelope {
                bail!("{} does not contain an SYC envelope", data_path.display());
            }
            (bytes, false)
        }
    };

    Ok(BytesReadOutput {
        source: data_path,
        plaintext,
        envelope_used,
    })
}
