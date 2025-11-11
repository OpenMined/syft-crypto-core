use crate::error::KeyError;
use serde_json::Value;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Writes JWKS data directly to the destination file.
///
/// Windows currently relies on inherited per-user ACLs for confidentiality.
/// A follow-up will add explicit DACL hardening plus atomic temp-file writes.
pub(crate) fn save_private_keys_platform(jwks: &Value, path: &Path) -> Result<(), KeyError> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, jwks)?;
    writer.flush()?;
    Ok(())
}
