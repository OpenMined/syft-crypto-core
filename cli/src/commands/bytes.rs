use crate::app::{AppContext, Result, atomic_write, resolve_data_path};
use crate::commands::{PlanPrinter, parse_optional_envelope, resolve_identity};
use crate::protocol_interface::{
    build_stub_envelope, decrypt_allow_plaintext, decrypt_bytes, encrypt_bytes,
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
    let plan = PlanPrinter::stderr("bytes write");
    let encrypted = !args.recipients.is_empty() && !args.plaintext;
    plan.field("relative path", args.relative.display())
        .field("mode", if encrypted { "encrypted" } else { "plaintext" })
        .bool("overwrite existing", args.overwrite);

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
            plan.field("input", path.display());
            data = fs::read(path)?;
        }
        None => {
            plan.info("reading from stdin");
            io::stdin().read_to_end(&mut data)?;
        }
    }

    if data.is_empty() {
        plan.info("warning: zero-byte payload");
    }

    let payload = if !args.recipients.is_empty() && !args.plaintext {
        let sender_identity = resolve_identity(None, &context.vault_path)?;
        plan.field("sender identity", &sender_identity);
        if !args.recipients.is_empty() {
            plan.field(
                "recipients",
                args.recipients
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }

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
            plan.info("note: --plaintext provided – recipients will be ignored");
        }
        data
    };

    atomic_write(&data_path, &payload)?;
    plan.field("bytes written", payload.len())
        .field("destination", data_path.display());
    Ok(())
}

fn handle_bytes_read(context: &AppContext, args: BytesReadArgs) -> Result<()> {
    let plan = PlanPrinter::stderr("bytes read");
    plan.field("relative path", args.relative.display());
    let data_path = resolve_data_path(context, &args.relative);
    plan.field("datasite source", data_path.display());

    let identity = resolve_identity(args.identity.as_deref(), &context.vault_path)?;
    plan.field("using identity", &identity);

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
        plan.info("detected SYC envelope – returning decrypted plaintext");
    } else {
        plan.info("returning plaintext without envelope");
    }

    match &args.output {
        Some(path) => {
            atomic_write(path, &plaintext)?;
            plan.field("wrote output to", path.display());
        }
        None => {
            plan.info("writing plaintext to stdout");
            io::stdout().write_all(&plaintext)?;
        }
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/bytes_command_tests.rs"
    ));
}
