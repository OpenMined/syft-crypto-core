use super::*;
use crate::commands::file::FileInspectArgs;
use crate::commands::key::KeyRecoverArgs;
use crate::protocol_interface;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

fn setup_context() -> (tempfile::TempDir, AppContext) {
    let base = tempdir().unwrap();
    let vault = base.path().join("vault");
    let data = base.path().join("data");
    let shadow = base.path().join("shadow");
    fs::create_dir_all(&vault).unwrap();
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&shadow).unwrap();
    (
        base,
        AppContext {
            vault_path: vault,
            data_root: data,
            shadow_root: shadow,
        },
    )
}

#[test]
fn handle_command_routes_key_variant() {
    let (_tmp, context) = setup_context();
    let args = KeyRecoverArgs {
        package: PathBuf::from("package.zip"),
        identity: None,
        output: None,
        dry_run: true,
    };
    handle_command(&context, Command::Key(KeyCommand::Recover(args))).unwrap();
}

#[test]
fn handle_command_routes_file_variant() {
    let (_tmp, context) = setup_context();
    let file_path = context.data_root.join("blob.bin");
    fs::create_dir_all(file_path.parent().unwrap()).unwrap();
    let payload = protocol_interface::encrypt_bytes("alice", None, b"bytes").unwrap();
    fs::write(&file_path, payload).unwrap();

    let args = FileInspectArgs {
        input: PathBuf::from("blob.bin"),
        identity: None,
        verbose: false,
    };

    handle_command(&context, Command::File(FileCommand::Inspect(args))).unwrap();
}
