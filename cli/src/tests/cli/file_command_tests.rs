use super::*;
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

fn write_identity(context: &AppContext, identity: &str) {
    let keys_dir = context.vault_path.join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    let key_path = keys_dir.join(format!("{}.key", identity));
    let material = protocol_interface::generate_identity_material(identity).unwrap();
    fs::write(&key_path, material.key_file).unwrap();
}

#[test]
fn encrypt_relative_writes_placeholder_ciphertext() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    let relative = PathBuf::from("docs/note.txt");
    let shadow_file = context.shadow_root.join(&relative);
    fs::create_dir_all(shadow_file.parent().unwrap()).unwrap();
    fs::write(&shadow_file, b"secret").unwrap();

    let args = FileEncryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        sender: None,
        recipient: Some("bob".into()),
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    let ciphertext = fs::read(context.data_root.join(&relative)).unwrap();
    let inspection = protocol_interface::inspect_ciphertext(&ciphertext);
    assert!(inspection.envelope.is_stubbed());
    let decrypted = protocol_interface::decrypt_bytes("alice", &ciphertext, false).unwrap();
    assert_eq!(decrypted.plaintext, b"secret");
}

#[test]
fn encrypt_direct_mode_honors_dry_run() {
    let (_tmp, context) = setup_context();
    let src = context.shadow_root.join("input.txt");
    fs::write(&src, b"plain").unwrap();
    let dest = context.data_root.join("output.bin");

    let args = FileEncryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        sender: Some("alice".into()),
        recipient: None,
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    assert!(!dest.exists());
}

#[test]
fn decrypt_relative_recovers_plaintext() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    let relative = PathBuf::from("docs/note.txt");
    let data_file = context.data_root.join(&relative);
    fs::create_dir_all(data_file.parent().unwrap()).unwrap();
    let payload = protocol_interface::encrypt_bytes("alice", Some("bob"), b"cipher").unwrap();
    fs::write(&data_file, payload).unwrap();

    let args = FileDecryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        identity: None,
        skip_checks: false,
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    let plaintext = fs::read(context.shadow_root.join(&relative)).unwrap();
    assert_eq!(plaintext, b"cipher");
}

#[test]
fn decrypt_direct_fails_without_placeholder_header() {
    let (_tmp, context) = setup_context();
    let src = context.data_root.join("enc.bin");
    let dest = context.shadow_root.join("plain.txt");
    fs::write(&src, b"no-header").unwrap();

    let args = FileDecryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        identity: Some("alice".into()),
        skip_checks: false,
        dry_run: false,
    };

    let err = handle_file_command(&context, FileCommand::Decrypt(args)).unwrap_err();
    assert!(
        err
            .to_string()
            .contains("does not contain expected stub envelope"),
        "unexpected error: {}",
        err
    );
    assert!(!dest.exists());
}

#[test]
fn inspect_reads_file_metadata() {
    let (_tmp, context) = setup_context();
    let file = context.data_root.join("blob.bin");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    let payload = protocol_interface::encrypt_bytes("alice", None, b"data").unwrap();
    fs::write(&file, payload).unwrap();

    let args = FileInspectArgs {
        input: PathBuf::from("blob.bin"),
        identity: Some("alice".into()),
        verbose: true,
    };

    handle_file_command(&context, FileCommand::Inspect(args)).unwrap();
}
