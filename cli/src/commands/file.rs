use crate::app::{
    AppContext, Result, atomic_write, detect_single_identity, ensure_vault_layout,
    resolve_data_path, resolve_shadow_path, yes_no,
};
use crate::protocol_interface::{
    decrypt_allow_plaintext, decrypt_bytes, encrypt_bytes, inspect_ciphertext,
};
use clap::{Args, Subcommand};
use std::fs;
use std::path::PathBuf;

/// File and path subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum FileCommand {
    /// Encrypt a source file into a destination file without touching datasite roots
    Encrypt(FileEncryptArgs),

    /// Decrypt a ciphertext file into a destination file without touching datasite roots
    Decrypt(FileDecryptArgs),

    /// Inspect an encrypted blob without modifying it
    Inspect(FileInspectArgs),
}

pub(crate) fn handle_file_command(context: &AppContext, command: FileCommand) -> Result<()> {
    match command {
        FileCommand::Encrypt(args) => handle_file_encrypt(context, args),
        FileCommand::Decrypt(args) => handle_file_decrypt(context, args),
        FileCommand::Inspect(args) => handle_file_inspect(context, args),
    }
}

/// Arguments for `syc file encrypt`.
#[derive(Args, Debug)]
pub(crate) struct FileEncryptArgs {
    /// Relative path within datasite/shadow trees (mirrors encrypt/decrypt automatically)
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: Option<PathBuf>,

    /// Path to the plaintext file to encrypt (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) src: Option<PathBuf>,

    /// Destination path for the encrypted output (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) dest: Option<PathBuf>,

    /// Identity to tag as sender (metadata only in placeholder mode)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) sender: Option<String>,

    /// Identity to tag as recipient (metadata only in placeholder mode)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) recipient: Option<String>,

    /// Simulate the encryption without writing output
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `syc file decrypt`.
#[derive(Args, Debug)]
pub(crate) struct FileDecryptArgs {
    /// Relative path within datasite/shadow trees (mirrors encrypt/decrypt automatically)
    #[arg(short = 'p', long, value_name = "RELATIVE")]
    pub(crate) relative: Option<PathBuf>,

    /// Encrypted input file (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) src: Option<PathBuf>,

    /// Destination for decrypted plaintext (direct mode)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) dest: Option<PathBuf>,

    /// Identity expected to own the decryption keys (auto-detect if omitted)
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Bypass schema validation before attempting to decrypt
    #[arg(long)]
    pub(crate) skip_checks: bool,

    /// Simulate the operation without writing output
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `syc file inspect`.
#[derive(Args, Debug)]
pub(crate) struct FileInspectArgs {
    /// Encrypted file to inspect (relative paths resolve under data root)
    #[arg(short, long, value_name = "FILE")]
    pub(crate) input: PathBuf,

    /// Identity to resolve in the vault when checking key availability
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Print extended debugging info about headers and schema
    #[arg(long)]
    pub(crate) verbose: bool,
}

fn handle_file_encrypt(context: &AppContext, args: FileEncryptArgs) -> Result<()> {
    println!("[plan] file encrypt");
    println!("  dry-run: {}", yes_no(args.dry_run));

    if let Some(relative) = &args.relative {
        println!("  mode: datasite/shadow (relative)");
        println!("  vault: {}", context.vault_path.display());
        println!("  data root: {}", context.data_root.display());
        println!("  shadow root: {}", context.shadow_root.display());
        println!("  relative path: {}", relative.display());
        if let Some(recipient) = &args.recipient {
            println!("  recipient: {}", recipient);
        }
        if let Some(sender) = &args.sender {
            println!("  sender identity: {}", sender);
        }
        println!("  TODO: fetch recipient bundle, establish PQXDH session, and seal file");

        if args.dry_run {
            println!("  dry-run complete: no ciphertext produced");
            return Ok(());
        }

        ensure_vault_layout(&context.vault_path)?;
        let shadow_path = resolve_shadow_path(context, relative);
        let data_path = resolve_data_path(context, relative);
        println!("  shadow source: {}", shadow_path.display());
        println!("  datasite destination: {}", data_path.display());

        let sender_identity = match &args.sender {
            Some(identity) => identity.clone(),
            None => detect_single_identity(&context.vault_path)?,
        };
        println!("  using sender identity: {}", sender_identity);

        let plaintext = fs::read(&shadow_path)?;
        let ciphertext = encrypt_bytes(&sender_identity, args.recipient.as_deref(), &plaintext)?;

        atomic_write(&data_path, &ciphertext)?;
        println!(
            "  wrote placeholder ciphertext atomically to {}",
            data_path.display()
        );
    } else {
        let src = args
            .src
            .as_ref()
            .ok_or_else(|| "--src or --relative is required".to_string())?;
        let dest = args
            .dest
            .as_ref()
            .ok_or_else(|| "--dest or --relative is required".to_string())?;

        let sender_identity = match &args.sender {
            Some(identity) => identity.clone(),
            None => detect_single_identity(&context.vault_path)?,
        };

        println!("  mode: direct file");
        println!("  source: {}", src.display());
        println!("  destination: {}", dest.display());
        println!("  sender identity: {}", sender_identity);
        if let Some(recipient) = &args.recipient {
            println!("  recipient identity: {}", recipient);
        }
        println!("  TODO: fetch recipient bundle, establish PQXDH session, and seal file");

        if args.dry_run {
            println!("  dry-run complete: no ciphertext produced");
            return Ok(());
        }

        let plaintext = fs::read(src)?;
        let ciphertext = encrypt_bytes(&sender_identity, args.recipient.as_deref(), &plaintext)?;
        atomic_write(dest, &ciphertext)?;
        println!("  wrote placeholder ciphertext to {}", dest.display());
    }

    Ok(())
}

fn handle_file_decrypt(context: &AppContext, args: FileDecryptArgs) -> Result<()> {
    println!("[plan] file decrypt");
    println!("  dry-run: {}", yes_no(args.dry_run));
    println!("  skip schema checks: {}", yes_no(args.skip_checks));

    if let Some(relative) = &args.relative {
        println!("  mode: datasite/shadow (relative)");
        println!("  vault: {}", context.vault_path.display());
        println!("  data root: {}", context.data_root.display());
        println!("  shadow root: {}", context.shadow_root.display());
        println!("  relative path: {}", relative.display());
        if let Some(identity) = &args.identity {
            println!("  preferred identity: {}", identity);
        } else {
            println!("  preferred identity: auto-detect");
        }
        println!("  TODO: verify sender authenticity and check key availability prior to decrypt");

        if args.dry_run {
            println!("  dry-run complete: no plaintext extracted");
            return Ok(());
        }

        ensure_vault_layout(&context.vault_path)?;
        let data_path = resolve_data_path(context, relative);
        let shadow_path = resolve_shadow_path(context, relative);
        println!("  datasite source: {}", data_path.display());
        println!("  shadow destination: {}", shadow_path.display());

        let active_identity = match &args.identity {
            Some(identity) => identity.clone(),
            None => detect_single_identity(&context.vault_path)?,
        };
        println!("  using identity: {}", active_identity);

        let ciphertext = fs::read(&data_path)?;
        let result = decrypt_allow_plaintext(&active_identity, &ciphertext)?;
        if !args.skip_checks && !result.envelope.is_stubbed() {
            println!("  stub envelope missing – treating payload as plaintext (relative mode)");
        }
        let plaintext = result.plaintext;

        atomic_write(&shadow_path, &plaintext)?;
        println!(
            "  wrote decrypted placeholder output atomically to {}",
            shadow_path.display()
        );
    } else {
        let src = args
            .src
            .as_ref()
            .ok_or_else(|| "--src or --relative is required".to_string())?;
        let dest = args
            .dest
            .as_ref()
            .ok_or_else(|| "--dest or --relative is required".to_string())?;

        let active_identity = match &args.identity {
            Some(identity) => identity.clone(),
            None => detect_single_identity(&context.vault_path)?,
        };

        println!("  mode: direct file");
        println!("  source: {}", src.display());
        println!("  destination: {}", dest.display());
        println!("  preferred identity: {}", active_identity);

        if args.dry_run {
            println!("  dry-run complete: no plaintext extracted");
            return Ok(());
        }

        let ciphertext = fs::read(src)?;
        let result = decrypt_bytes(&active_identity, &ciphertext, args.skip_checks)?;
        if !result.envelope.is_stubbed() {
            println!("  stub envelope missing – returning plaintext as-is");
        }
        let plaintext = result.plaintext;

        atomic_write(dest, &plaintext)?;
        println!("  wrote decrypted placeholder output to {}", dest.display());
    }

    Ok(())
}

fn handle_file_inspect(context: &AppContext, args: FileInspectArgs) -> Result<()> {
    println!("[plan] inspect encrypted blob");
    println!("  vault: {}", context.vault_path.display());
    let ciphertext_path = resolve_data_path(context, &args.input);
    println!("  input (encrypted): {}", ciphertext_path.display());
    if let Some(identity) = &args.identity {
        println!("  identity: {}", identity);
    }
    println!("  verbose: {}", yes_no(args.verbose));
    println!("  TODO: read envelope header and report recipient, sender, and schema version");
    println!("  TODO: look up local key availability before attempting decrypt");

    let ciphertext = fs::read(&ciphertext_path)?;
    let info = inspect_ciphertext(&ciphertext);
    println!(
        "  stub envelope present: {}",
        yes_no(info.envelope.is_stubbed())
    );
    println!("  file size: {} bytes", info.length);

    Ok(())
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/file_command_tests.rs"
    ));
}
