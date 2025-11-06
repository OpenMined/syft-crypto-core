mod bytes;
mod file;
mod key;

use clap::{Parser, Subcommand};
use std::fmt::Display;
use std::path::PathBuf;

use crate::app::{AppContext, Result, yes_no};

pub(crate) use bytes::BytesCommand;
pub(crate) use file::FileCommand;
pub(crate) use key::KeyCommand;

/// Syft Crypto (syc) CLI – manage Signal-compatible post-quantum keys and files.
#[derive(Parser, Debug)]
#[command(name = "syc", version, about = "Syft Crypto CLI (syc)")]
pub(crate) struct Cli {
    /// Override the default vault directory (~/.syc)
    #[arg(
        global = true,
        long,
        value_name = "DIR",
        help = "Path to the syc vault (default: ~/.syc)"
    )]
    pub(crate) vault: Option<PathBuf>,

    /// Override the encrypted data root (defaults from vault config or env)
    #[arg(
        global = true,
        long,
        value_name = "DIR",
        help = "Root directory that SyftBox syncs (defaults via config or SYC_DATA_ROOT)"
    )]
    pub(crate) data_root: Option<PathBuf>,

    /// Override the plaintext shadow root (defaults from vault config or env)
    #[arg(
        global = true,
        long,
        value_name = "DIR",
        help = "Shadow directory for decrypted data (defaults via config or SYC_SHADOW_ROOT)"
    )]
    pub(crate) shadow_root: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Top-level commands exposed by the CLI.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Stream plaintext bytes into/out of the datasite
    #[command(subcommand)]
    Bytes(BytesCommand),

    /// Manage identity material, bundles, and recovery artifacts
    #[command(subcommand)]
    Key(KeyCommand),

    /// Encrypt, decrypt, and inspect sealed blobs
    #[command(subcommand)]
    File(FileCommand),
}

pub(crate) fn handle_command(context: &AppContext, command: Command) -> Result<()> {
    match command {
        Command::Bytes(cmd) => bytes::handle_bytes_command(context, cmd),
        Command::Key(cmd) => key::handle_key_command(context, cmd),
        Command::File(cmd) => file::handle_file_command(context, cmd),
    }
}

pub(crate) struct PlanPrinter;

impl PlanPrinter {
    pub(crate) fn new(title: &str) -> Self {
        println!("[plan] {}", title);
        Self
    }

    pub(crate) fn field<T: Display>(&self, name: &str, value: T) -> &Self {
        println!("  {}: {}", name, value);
        self
    }

    pub(crate) fn bool(&self, name: &str, value: bool) -> &Self {
        self.field(name, yes_no(value))
    }

    pub(crate) fn opt<T: Display>(&self, name: &str, value: Option<T>) -> &Self {
        if let Some(value) = value {
            self.field(name, value);
        }
        self
    }

    pub(crate) fn info(&self, message: &str) -> &Self {
        println!("  {}", message);
        self
    }
}

#[cfg(test)]
mod tests {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tests/cli/commands_mod_tests.rs"
    ));
}
