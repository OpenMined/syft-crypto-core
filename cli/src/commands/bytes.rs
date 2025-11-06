use crate::app::{
    AppContext, Result, atomic_write, detect_single_identity, resolve_data_path, yes_no,
};
use crate::envelope::ParsedEnvelope;
use crate::protocol_interface::{
    build_stub_envelope, decrypt_allow_plaintext, decrypt_bytes, encrypt_bytes, has_syc_magic,
    parse_envelope, verify_stub_signature,
};
use clap::{Args, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub(crate) enum BytesCommand {
    /// Write plaintext or encrypted bytes to the datasite tree
    Write(BytesWriteArgs),
    /// Read plaintext from a datasite path, automatically decrypting when needed
    Read(BytesReadArgs),
}

#[derive(Args, Debug)]
pub(crate) struct BytesWriteArgs {
    /// Relative path within the datasite tree
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: PathBuf,

    /// Recipient identities to encrypt for; omit to store plaintext
    #[arg(long = "recipient", value_name = "IDENTITY")]
    pub(crate) recipients: Vec<String>,

    /// Source file to read from (defaults to stdin)
    #[arg(long, value_name = "FILE")]
    pub(crate) input: Option<PathBuf>,

    /// Force plaintext storage even if recipients are supplied
    #[arg(long)]
    pub(crate) plaintext: bool,

    /// Allow replacing an existing file
    #[arg(long)]
    pub(crate) overwrite: bool,

    /// Optional filename hint stored in the envelope metadata
    #[arg(long, value_name = "TEXT")]
    pub(crate) hint: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct BytesReadArgs {
    /// Relative path within the datasite tree
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: PathBuf,

    /// Identity used to decrypt (auto-detect when omitted)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Fail if the target is plaintext (defaults to lenient mode)
    #[arg(long)]
    pub(crate) require_envelope: bool,

    /// Destination file for the plaintext (defaults to stdout)
    #[arg(long, value_name = "FILE")]
    pub(crate) output: Option<PathBuf>,
}

pub(crate) fn handle_bytes_command(context: &AppContext, command: BytesCommand) -> Result<()> {
    match command {
        BytesCommand::Write(args) => handle_bytes_write(context, args),
        BytesCommand::Read(args) => handle_bytes_read(context, args),
    }
}

fn handle_bytes_write(context: &AppContext, args: BytesWriteArgs) -> Result<()> {
    eprintln!("[plan] bytes write");
    eprintln!("  relative path: {}", args.relative.display());
    eprintln!(
        "  mode: {}",
        if !args.recipients.is_empty() && !args.plaintext {
            "encrypted"
        } else {
            "plaintext"
        }
    );
    eprintln!("  overwrite existing: {}", yes_no(args.overwrite));

    let data_path = resolve_data_path(context, &args.relative);
    if data_path.exists() && !args.overwrite {
        return Err(format!(
            "path {} already exists (use --overwrite to replace)",
            data_path.display()
        )
        .into());
    }

    let mut data = Vec::new();
    match &args.input {
        Some(path) => {
            data = fs::read(path)?;
        }
        None => {
            eprintln!("  reading from stdin");
            io::stdin().read_to_end(&mut data)?;
        }
    }

    if data.is_empty() {
        eprintln!("  warning: zero-byte payload");
    }

    let payload = if !args.recipients.is_empty() && !args.plaintext {
        let sender_identity = detect_single_identity(&context.vault_path)?;
        eprintln!("  sender identity: {}", sender_identity);
        eprintln!(
            "  recipients: {}",
            args.recipients
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );

        let ciphertext = encrypt_bytes(
            &sender_identity,
            args.recipients.first().map(|s| s.as_str()),
            &data,
        )?;
        build_stub_envelope(
            &sender_identity,
            &args.recipients,
            &ciphertext,
            args.hint.as_deref(),
        )?
    } else {
        if args.plaintext && !args.recipients.is_empty() {
            eprintln!("  note: --plaintext provided – recipients will be ignored");
        }
        data
    };

    atomic_write(&data_path, &payload)?;
    eprintln!("  wrote {} bytes to {}", payload.len(), data_path.display());
    Ok(())
}

fn handle_bytes_read(context: &AppContext, args: BytesReadArgs) -> Result<()> {
    eprintln!("[plan] bytes read");
    eprintln!("  relative path: {}", args.relative.display());
    let data_path = resolve_data_path(context, &args.relative);
    eprintln!("  datasite source: {}", data_path.display());

    let identity = match &args.identity {
        Some(id) => id.clone(),
        None => detect_single_identity(&context.vault_path)?,
    };
    eprintln!("  using identity: {}", identity);

    let bytes = fs::read(&data_path)?;
    let (plaintext, envelope_used) = match parse_optional_envelope(&bytes, false)? {
        Some(parsed) => {
            let result = decrypt_bytes(&identity, &parsed.ciphertext, false)?;
            (result.plaintext, true)
        }
        None => {
            if args.require_envelope {
                return Err(
                    format!("{} does not contain an SYC envelope", data_path.display()).into(),
                );
            }
            let result = decrypt_allow_plaintext(&identity, &bytes)?;
            (result.plaintext, false)
        }
    };

    if envelope_used {
        eprintln!("  detected SYC envelope – returning decrypted plaintext");
    } else {
        eprintln!("  returning plaintext without envelope");
    }

    match &args.output {
        Some(path) => {
            atomic_write(path, &plaintext)?;
            eprintln!("  wrote output to {}", path.display());
        }
        None => {
            io::stdout().write_all(&plaintext)?;
        }
    }

    Ok(())
}

fn parse_optional_envelope(bytes: &[u8], skip_checks: bool) -> Result<Option<ParsedEnvelope>> {
    if has_syc_magic(bytes) {
        let parsed = parse_envelope(bytes)?;
        verify_stub_signature(&parsed, skip_checks)?;
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/bytes_command_tests.rs"
    ));
}
