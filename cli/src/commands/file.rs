use crate::app::{
    AppContext, Result, atomic_write, bundle_path_for_identity, detect_single_identity,
    ensure_vault_layout, resolve_data_path, resolve_shadow_path, yes_no,
};
use crate::envelope::ParsedEnvelope;
use crate::protocol_interface::{
    CURRENT_VERSION, MAGIC, build_stub_envelope, decrypt_allow_plaintext, decrypt_bytes,
    encrypt_bytes, has_syc_magic, inspect_ciphertext, parse_envelope, verify_stub_signature,
};
use clap::{Args, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

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

    let operation = if let Some(relative) = &args.relative {
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

        EncryptPlan::Relative {
            plaintext: shadow_path,
            ciphertext: data_path,
        }
    } else {
        let src = args
            .src
            .as_ref()
            .ok_or_else(|| "--src or --relative is required".to_string())?;
        let dest = args
            .dest
            .as_ref()
            .ok_or_else(|| "--dest or --relative is required".to_string())?;

        println!("  mode: direct file");
        println!("  source: {}", src.display());
        println!("  destination: {}", dest.display());
        if let Some(sender) = &args.sender {
            println!("  sender identity: {}", sender);
        }
        if let Some(recipient) = &args.recipient {
            println!("  recipient identity: {}", recipient);
        }
        println!("  TODO: fetch recipient bundle, establish PQXDH session, and seal file");

        if args.dry_run {
            println!("  dry-run complete: no ciphertext produced");
            return Ok(());
        }

        EncryptPlan::Direct {
            plaintext: src.to_path_buf(),
            ciphertext: dest.to_path_buf(),
        }
    };

    let sender_identity = match &args.sender {
        Some(identity) => identity.clone(),
        None => detect_single_identity(&context.vault_path)?,
    };
    println!("  using sender identity: {}", sender_identity);

    let plaintext = fs::read(operation.plaintext_path())?;
    let ciphertext = encrypt_bytes(&sender_identity, args.recipient.as_deref(), &plaintext)?;
    let recipients: Vec<String> = args.recipient.iter().cloned().collect();
    let envelope = build_stub_envelope(&sender_identity, &recipients, &ciphertext, None)?;

    atomic_write(operation.ciphertext_path(), &envelope)?;
    operation.print_completion();

    Ok(())
}

fn handle_file_decrypt(context: &AppContext, args: FileDecryptArgs) -> Result<()> {
    println!("[plan] file decrypt");
    println!("  dry-run: {}", yes_no(args.dry_run));
    println!("  skip schema checks: {}", yes_no(args.skip_checks));

    let operation = if let Some(relative) = &args.relative {
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

        DecryptPlan::Relative {
            encrypted: data_path,
            plaintext: shadow_path,
        }
    } else {
        let src = args
            .src
            .as_ref()
            .ok_or_else(|| "--src or --relative is required".to_string())?;
        let dest = args
            .dest
            .as_ref()
            .ok_or_else(|| "--dest or --relative is required".to_string())?;

        println!("  mode: direct file");
        println!("  source: {}", src.display());
        println!("  destination: {}", dest.display());
        if let Some(identity) = &args.identity {
            println!("  preferred identity: {}", identity);
        } else {
            println!("  preferred identity: auto-detect");
        }

        if args.dry_run {
            println!("  dry-run complete: no plaintext extracted");
            return Ok(());
        }

        DecryptPlan::Direct {
            encrypted: src.to_path_buf(),
            plaintext: dest.to_path_buf(),
        }
    };

    let active_identity = match &args.identity {
        Some(identity) => identity.clone(),
        None => detect_single_identity(&context.vault_path)?,
    };
    println!("  using identity: {}", active_identity);

    let encrypted_path = operation.encrypted_path();
    let file_bytes = fs::read(encrypted_path)?;
    let parsed_envelope = parse_optional_envelope(&file_bytes, args.skip_checks)?;
    let parsed_envelope = match parsed_envelope {
        Some(parsed) => Some(parsed),
        None => {
            operation.handle_missing_envelope(encrypted_path, args.skip_checks)?;
            None
        }
    };

    let result = if let Some(parsed) = parsed_envelope.as_ref() {
        decrypt_bytes(&active_identity, &parsed.ciphertext, args.skip_checks)?
    } else {
        decrypt_allow_plaintext(&active_identity, &file_bytes)?
    };

    if let Some(parsed) = parsed_envelope.as_ref() {
        debug_assert!(
            result.envelope.is_stubbed(),
            "expected stubbed envelope for {:?}",
            parsed.prelude.sender.identity
        );
    } else if matches!(operation, DecryptPlan::Direct { .. }) && result.envelope.is_stubbed() {
        println!(
            "  warning: ciphertext envelope detected despite plain input ({}); continuing",
            encrypted_path.display()
        );
    }

    atomic_write(operation.plaintext_path(), &result.plaintext)?;
    operation.print_completion();

    Ok(())
}

enum EncryptPlan {
    Relative {
        plaintext: PathBuf,
        ciphertext: PathBuf,
    },
    Direct {
        plaintext: PathBuf,
        ciphertext: PathBuf,
    },
}

impl EncryptPlan {
    fn plaintext_path(&self) -> &Path {
        match self {
            EncryptPlan::Relative { plaintext, .. } | EncryptPlan::Direct { plaintext, .. } => {
                plaintext
            }
        }
    }

    fn ciphertext_path(&self) -> &Path {
        match self {
            EncryptPlan::Relative { ciphertext, .. } | EncryptPlan::Direct { ciphertext, .. } => {
                ciphertext
            }
        }
    }

    fn print_completion(&self) {
        match self {
            EncryptPlan::Relative { ciphertext, .. } => {
                println!(
                    "  wrote SYC envelope atomically to {}",
                    ciphertext.display()
                );
            }
            EncryptPlan::Direct { ciphertext, .. } => {
                println!("  wrote SYC envelope to {}", ciphertext.display());
            }
        }
    }
}

enum DecryptPlan {
    Relative {
        encrypted: PathBuf,
        plaintext: PathBuf,
    },
    Direct {
        encrypted: PathBuf,
        plaintext: PathBuf,
    },
}

impl DecryptPlan {
    fn encrypted_path(&self) -> &Path {
        match self {
            DecryptPlan::Relative { encrypted, .. } | DecryptPlan::Direct { encrypted, .. } => {
                encrypted
            }
        }
    }

    fn plaintext_path(&self) -> &Path {
        match self {
            DecryptPlan::Relative { plaintext, .. } | DecryptPlan::Direct { plaintext, .. } => {
                plaintext
            }
        }
    }

    fn handle_missing_envelope(&self, path: &Path, skip_checks: bool) -> Result<()> {
        match self {
            DecryptPlan::Relative { .. } => {
                if !skip_checks {
                    println!(
                        "  SYC envelope missing – treating payload as plaintext (relative mode)"
                    );
                }
                Ok(())
            }
            DecryptPlan::Direct { .. } => {
                if skip_checks {
                    Ok(())
                } else {
                    Err(format!(
                        "input {} is not an SYC envelope (magic missing)",
                        path.display()
                    )
                    .into())
                }
            }
        }
    }

    fn print_completion(&self) {
        match self {
            DecryptPlan::Relative { plaintext, .. } => {
                println!(
                    "  wrote decrypted output atomically to {}",
                    plaintext.display()
                );
            }
            DecryptPlan::Direct { plaintext, .. } => {
                println!("  wrote decrypted output to {}", plaintext.display());
            }
        }
    }
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

fn handle_file_inspect(context: &AppContext, args: FileInspectArgs) -> Result<()> {
    println!("[plan] inspect encrypted blob");
    println!("  vault: {}", context.vault_path.display());
    let ciphertext_path = resolve_data_path(context, &args.input);
    println!("  input (encrypted): {}", ciphertext_path.display());
    if let Some(identity) = &args.identity {
        println!("  identity: {}", identity);
    }
    println!("  verbose: {}", yes_no(args.verbose));
    let bytes = fs::read(&ciphertext_path)?;
    if let Some(parsed) = parse_optional_envelope(&bytes, false)? {
        println!(
            "  envelope magic: {} (version {})",
            std::str::from_utf8(MAGIC).unwrap_or("SYC1"),
            CURRENT_VERSION
        );
        println!("  created_at: {}", parsed.prelude.created_at);
        println!(
            "  sender: {} (ik_fingerprint: {})",
            parsed.prelude.sender.identity, parsed.prelude.sender.ik_fingerprint
        );
        report_sender_consistency(context, &parsed)?;
        println!("  recipients ({}):", parsed.prelude.recipients.len());
        for recipient in &parsed.prelude.recipients {
            let identity = recipient
                .identity
                .as_deref()
                .unwrap_or("<unspecified-identity>");
            let device = recipient
                .device_label
                .as_deref()
                .unwrap_or("<unspecified-device>");
            println!(
                "    - {} [{}] spk={} pqspk={}",
                identity,
                device,
                recipient.spk_fingerprint.as_deref().unwrap_or("<none>"),
                recipient.pqspk_fingerprint.as_deref().unwrap_or("<none>")
            );
        }
        println!(
            "  cipher: suite={} segments={} last_segment_bytes={} ciphertext_len={}",
            parsed.prelude.cipher.suite,
            parsed.prelude.cipher.segment_count,
            parsed.prelude.cipher.last_segment_bytes,
            parsed.prelude.cipher.ciphertext_len
        );
        if let Some(meta) = &parsed.prelude.public_meta
            && let Some(filename_hint) = &meta.filename_hint
        {
            println!("  filename hint: {}", filename_hint);
        }
        println!("  prelude size: {} bytes", parsed.prelude_bytes.len());
        println!("  signature size: {} bytes", parsed.signature.len());
        println!("  payload bytes: {}", parsed.ciphertext.len());
    } else {
        let info = inspect_ciphertext(&bytes);
        println!("  not an SYC envelope – fallback stub header check");
        println!(
            "  stub ciphertext marker present: {}",
            yes_no(info.envelope.is_stubbed())
        );
        println!("  file size: {} bytes", info.length);
    }

    Ok(())
}

fn report_sender_consistency(context: &AppContext, parsed: &ParsedEnvelope) -> Result<()> {
    let sender_identity = &parsed.prelude.sender.identity;
    if sender_identity.is_empty() {
        return Ok(());
    }

    match load_cached_bundle(context, sender_identity)? {
        Some(info) => {
            if info.fingerprint == parsed.prelude.sender.ik_fingerprint {
                println!("  cached sender fingerprint matches ({})", info.fingerprint);
            } else {
                println!(
                    "  warning: cached sender fingerprint {} differs from envelope {} (TOFU violation)",
                    info.fingerprint, parsed.prelude.sender.ik_fingerprint
                );
            }
        }
        None => {
            println!(
                "  note: sender identity {} has no cached bundle – consider `syc key import`",
                sender_identity
            );
        }
    }

    Ok(())
}

fn load_cached_bundle(
    context: &AppContext,
    identity: &str,
) -> Result<Option<crate::protocol_interface::PublicBundleInfo>> {
    let path = bundle_path_for_identity(&context.vault_path, identity);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path)?;
    let info = crate::protocol_interface::parse_public_bundle(&body)?;
    Ok(Some(info))
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/file_command_tests.rs"
    ));
}
