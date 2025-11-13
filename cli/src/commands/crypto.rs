use crate::app::{AppContext, Result, bundle_path_for_identity, key_path_for_identity};
use crate::protocol_interface::{
    PublicBundleInfo, load_private_keys_from_file, parse_public_bundle,
};
use rand::rng;
use std::fs;
use syft_crypto_protocol::{SyftPrivateKeys, SyftPublicKeyBundle, envelope::ParsedEnvelope};

pub(crate) fn load_private_keys_for_identity(
    context: &AppContext,
    identity: &str,
) -> Result<SyftPrivateKeys> {
    let key_path = key_path_for_identity(&context.vault_path, identity);
    if !key_path.exists() {
        return Err("key material not found in vault (run `syc key generate`)".into());
    }
    load_private_keys_from_file(&key_path)
}

pub(crate) fn load_cached_bundle(
    context: &AppContext,
    identity: &str,
) -> Result<Option<PublicBundleInfo>> {
    let path = bundle_path_for_identity(&context.vault_path, identity);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path)?;
    let info = parse_public_bundle(&body)?;
    Ok(Some(info))
}

pub(crate) fn resolve_recipient_bundle(
    context: &AppContext,
    sender_keys: &SyftPrivateKeys,
    sender_identity: &str,
    recipient_identity: &str,
) -> Result<SyftPublicKeyBundle> {
    if let Some(info) = load_cached_bundle(context, recipient_identity)? {
        Ok(info.bundle)
    } else if sender_identity == recipient_identity {
        // Self-addressed encryption can safely fall back to deriving the bundle from the
        // locally stored private keys because the result is deterministic – it matches the
        // bundle that would have been cached via `syc key import`. This keeps the UX simple
        // without weakening TOFU guarantees for third-party recipients, who must be cached.
        sender_keys
            .to_public_bundle(&mut rng())
            .map_err(|e| format!("failed to derive sender public bundle: {e}").into())
    } else {
        Err("recipient bundle not cached (run `syc key import --bundle ...`)".into())
    }
}

pub(crate) fn resolve_sender_bundle_for_decrypt(
    context: &AppContext,
    parsed: &ParsedEnvelope,
) -> Result<SyftPublicKeyBundle> {
    let sender_identity = &parsed.prelude.sender.identity;
    if let Some(info) = load_cached_bundle(context, sender_identity)? {
        Ok(info.bundle)
    } else {
        Err("sender bundle not cached (run `syc key import`)".into())
    }
}
