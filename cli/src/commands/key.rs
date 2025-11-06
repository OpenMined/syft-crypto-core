use crate::app::{
    AppContext, Result, ensure_vault_layout, fallback_identity_from_path, key_path_for_identity,
    read_identity_from_key, resolve_data_path,
};
use crate::commands::PlanPrinter;
use crate::protocol_interface::generate_identity_material;
use clap::{Args, Subcommand};
use serde_json::to_string_pretty;
use std::fs;
use std::path::{Path, PathBuf};

/// Identity and key-management subcommands.
#[derive(Subcommand, Debug)]
pub(crate) enum KeyCommand {
    /// Generate a new identity, signed pre-key, and PQ pre-key set
    Generate(KeyGenerateArgs),

    /// Import an existing bundle into the local vault after verifying signatures
    Import(KeyImportArgs),

    /// Restore identity material from a recovery package
    Recover(KeyRecoverArgs),

    /// List identities currently tracked in the local vault
    List(KeyListArgs),

    /// Validate bundle signatures and report metadata
    Verify(KeyVerifyArgs),
}

pub(crate) fn handle_key_command(context: &AppContext, command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Generate(args) => handle_key_generate(context, args),
        KeyCommand::Import(args) => handle_key_import(context, args),
        KeyCommand::Recover(args) => handle_key_recover(context, args),
        KeyCommand::List(args) => handle_key_list(context, args),
        KeyCommand::Verify(args) => handle_key_verify(context, args),
    }
}

/// Arguments for `syc key generate`.
#[derive(Args, Debug)]
pub(crate) struct KeyGenerateArgs {
    /// Identifier for the new identity (email, DID, etc.)
    #[arg(short, long, value_name = "IDENTITY")]
    pub(crate) identity: String,

    /// Optional path to export the public bundle alongside the private material
    #[arg(long, value_name = "FILE")]
    pub(crate) bundle_out: Option<PathBuf>,

    /// Allow replacing an existing identity when generating new material
    #[arg(long)]
    pub(crate) overwrite: bool,

    /// Simulate the operation without writing key material
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `syc key import`.
#[derive(Args, Debug)]
pub(crate) struct KeyImportArgs {
    /// Path to the bundle to import
    #[arg(short, long, value_name = "FILE")]
    pub(crate) bundle: PathBuf,

    /// Expected identity string; warn if the bundle claims a different identity
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) expected_identity: Option<String>,

    /// Perform verification only without writing to the vault
    #[arg(long)]
    pub(crate) verify_only: bool,

    /// Replace any existing identity without confirmation (bypasses TOFU)
    #[arg(long)]
    pub(crate) force: bool,
}

/// Arguments for `syc key recover`.
#[derive(Args, Debug)]
pub(crate) struct KeyRecoverArgs {
    /// Recovery package containing encrypted identity material
    #[arg(short, long, value_name = "FILE")]
    pub(crate) package: PathBuf,

    /// Identity label to associate with the recovered material
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Optional output location for decrypted artifacts
    #[arg(long, value_name = "DIR")]
    pub(crate) output: Option<PathBuf>,

    /// Simulate recovery without writing files
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// Arguments for `syc key list`.
#[derive(Args, Debug)]
pub(crate) struct KeyListArgs {
    /// Filter results to a single identity label
    #[arg(short, long, value_name = "IDENTITY")]
    pub(crate) identity: Option<String>,

    /// Include derived metadata such as key fingerprints
    #[arg(long)]
    pub(crate) verbose: bool,
}

/// Arguments for `syc key verify`.
#[derive(Args, Debug)]
pub(crate) struct KeyVerifyArgs {
    /// Path to the bundle to verify
    #[arg(short, long, value_name = "FILE")]
    pub(crate) bundle: PathBuf,

    /// Expected identity string; warn if the bundle claims a different identity
    #[arg(long, value_name = "IDENTITY")]
    pub(crate) expected_identity: Option<String>,

    /// Perform verification without touching the key vault
    #[arg(long)]
    pub(crate) verify_only: bool,

    /// Emit structured JSON describing the bundle
    #[arg(long)]
    pub(crate) json: bool,
}

fn handle_key_generate(context: &AppContext, args: KeyGenerateArgs) -> Result<()> {
    let plan = PlanPrinter::new("generate identity material");
    plan.field("vault", context.vault_path.display())
        .field("identity", &args.identity)
        .bool("overwrite existing", args.overwrite);
    if let Some(bundle_out) = &args.bundle_out {
        let resolved = resolve_data_path(context, bundle_out);
        plan.field("export public bundle to", resolved.display());
    }
    if args.dry_run {
        plan.info("dry-run: no files will be written");
    }
    plan.info("TODO: derive identity key, signed pre-key, and PQ pre-key using libsignal")
        .info("TODO: persist material in the configured vault and emit recovery bundle");

    if args.dry_run {
        plan.info("dry-run complete: no changes were made");
        return Ok(());
    }

    ensure_vault_layout(&context.vault_path)?;
    let key_path = key_path_for_identity(&context.vault_path, &args.identity);

    if key_path.exists() && !args.overwrite {
        return Err(format!(
            "key material already exists at {} (use --overwrite to replace)",
            key_path.display()
        )
        .into());
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let generated = generate_identity_material(&args.identity)?;

    fs::write(&key_path, &generated.key_file)?;
    println!("  wrote stub identity key material: {}", key_path.display());

    if let Some(bundle_out) = &args.bundle_out {
        let resolved = resolve_data_path(context, bundle_out);
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bundle_body = to_string_pretty(&generated.public_bundle)?;
        bundle_body.push('\n');
        fs::write(&resolved, bundle_body)?;
        println!("  exported stub bundle to {}", resolved.display());
    }

    Ok(())
}

fn handle_key_import(context: &AppContext, args: KeyImportArgs) -> Result<()> {
    let plan = PlanPrinter::new("import bundle into vault");
    plan.field("vault", context.vault_path.display());
    let bundle_path = resolve_data_path(context, &args.bundle);
    plan.field("bundle", bundle_path.display());
    match &args.expected_identity {
        Some(identity) => {
            plan.field("expected identity (TOFU guard)", identity);
        }
        None => {
            plan.field("expected identity", "auto-detect");
        }
    }
    plan.bool("verification only", args.verify_only)
        .bool("force overwrite", args.force)
        .info("TODO: parse bundle, verify signatures via PublicKeyBundle::verify_signatures")
        .info("TODO: compare claimed identity with vault contents and warn on mismatch");
    if !args.force {
        plan.info("TODO: block import when TOFU identity differs unless --force is supplied");
    }

    let bundle_body = read_bundle_body(&bundle_path)?;
    if let Some(expected) =
        missing_expected_identity(&bundle_body, args.expected_identity.as_deref())
    {
        println!(
            "  warning: expected identity '{}' not found in bundle contents",
            expected
        );
    }

    if args.verify_only {
        plan.info("note: verification only – no changes were written");
        return Ok(());
    }

    ensure_vault_layout(&context.vault_path)?;
    let bundles_dir = context.vault_path.join("bundles");
    fs::create_dir_all(&bundles_dir)?;
    let dest = bundles_dir.join(
        bundle_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
    );
    fs::write(&dest, bundle_body)?;
    println!("  stored bundle copy at {}", dest.display());

    Ok(())
}

fn handle_key_recover(context: &AppContext, args: KeyRecoverArgs) -> Result<()> {
    let plan = PlanPrinter::new("recover identity from package");
    plan.field("vault", context.vault_path.display())
        .field("package", args.package.display());
    if let Some(identity) = &args.identity {
        plan.field("target identity label", identity);
    } else {
        plan.field("target identity label", "derive from package");
    }
    if let Some(output) = &args.output {
        plan.field("staging output directory", output.display());
    }
    plan.bool("dry-run", args.dry_run)
        .info("TODO: decrypt recovery package and rehydrate key material")
        .info("TODO: verify signatures before committing recovered keys to vault");
    if args.dry_run {
        plan.info("dry-run complete: no changes were made");
    }
    Ok(())
}

fn handle_key_list(context: &AppContext, args: KeyListArgs) -> Result<()> {
    let plan = PlanPrinter::new("list known identities");
    plan.field("vault", context.vault_path.display());
    if let Some(identity) = &args.identity {
        plan.field("filter", identity);
    }
    plan.bool("verbose", args.verbose);

    ensure_vault_layout(&context.vault_path)?;
    let keys_dir = context.vault_path.join("keys");
    let mut found_any = false;

    if keys_dir.exists() {
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let identity = read_identity_from_key(entry.path())
                    .unwrap_or_else(|_| fallback_identity_from_path(entry.path()));

                if let Some(filter) = &args.identity
                    && filter != &identity
                {
                    continue;
                }

                found_any = true;
                if args.verbose {
                    let size = fs::metadata(entry.path())?.len();
                    println!("  - {} ({} bytes)", identity, size);
                } else {
                    println!("  - {}", identity);
                }
            }
        }
    }

    if !found_any {
        println!("  (no identities found)");
    }

    Ok(())
}

fn handle_key_verify(context: &AppContext, args: KeyVerifyArgs) -> Result<()> {
    let plan = PlanPrinter::new("verify bundle");
    plan.field("vault (for context only)", context.vault_path.display());
    let bundle_path = resolve_data_path(context, &args.bundle);
    plan.field("bundle", bundle_path.display());
    if let Some(identity) = &args.expected_identity {
        plan.field("expected identity", identity);
    }
    plan.bool("verify only", args.verify_only)
        .bool("emit json", args.json)
        .info("TODO: load bundle and validate both EC and PQ signatures")
        .info("TODO: surface fingerprints and metadata to caller");

    let body = read_bundle_body(&bundle_path)?;
    if let Some(expected) = missing_expected_identity(&body, args.expected_identity.as_deref()) {
        println!(
            "  warning: expected identity '{}' not mentioned in bundle",
            expected
        );
    }

    if args.json {
        println!(
            "{{\"bundle_path\":\"{}\",\"length\":{}}}",
            bundle_path.display(),
            body.len()
        );
    } else {
        println!("  bundle size: {} bytes", body.len());
    }

    Ok(())
}

fn read_bundle_body(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?)
}

fn missing_expected_identity<'a>(body: &str, expected: Option<&'a str>) -> Option<&'a str> {
    expected.filter(|identity| !body.contains(*identity))
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/key_command_tests.rs"
    ));
}
