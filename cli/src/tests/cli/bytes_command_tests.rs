use super::*;
use crate::commands::bytes::{BytesCommand, BytesReadArgs, BytesWriteArgs};
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
fn bytes_write_plaintext_and_read_back() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");

    let input_path = context.data_root.join("plain.txt");
    fs::write(&input_path, b"hello bytes").unwrap();

    handle_bytes_command(
        &context,
        BytesCommand::Write(BytesWriteArgs {
            relative: PathBuf::from("docs/plain.txt"),
            recipients: vec![],
            input: Some(input_path.clone()),
            plaintext: true,
            overwrite: false,
            hint: None,
        }),
    )
    .unwrap();

    let written = fs::read(context.data_root.join("docs/plain.txt")).unwrap();
    assert_eq!(written, b"hello bytes");

    let output_path = context.shadow_root.join("out.txt");
    handle_bytes_command(
        &context,
        BytesCommand::Read(BytesReadArgs {
            relative: PathBuf::from("docs/plain.txt"),
            identity: None,
            require_envelope: false,
            output: Some(output_path.clone()),
        }),
    )
    .unwrap();

    let output = fs::read(output_path).unwrap();
    assert_eq!(output, b"hello bytes");
}

#[test]
fn bytes_write_encrypted_and_read_back() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");

    let payload = b"secret via bytes";
    fs::write(context.shadow_root.join("input.bin"), payload).unwrap();

    handle_bytes_command(
        &context,
        BytesCommand::Write(BytesWriteArgs {
            relative: PathBuf::from("docs/encrypted.bin"),
            recipients: vec!["alice@example.org".into()],
            input: Some(context.shadow_root.join("input.bin")),
            plaintext: false,
            overwrite: false,
            hint: None,
        }),
    )
    .unwrap();

    let envelope = fs::read(context.data_root.join("docs/encrypted.bin")).unwrap();
    assert!(crate::protocol_interface::has_syc_magic(&envelope));

    let output_path = context.shadow_root.join("decrypted.bin");
    handle_bytes_command(
        &context,
        BytesCommand::Read(BytesReadArgs {
            relative: PathBuf::from("docs/encrypted.bin"),
            identity: Some("alice@example.org".into()),
            require_envelope: true,
            output: Some(output_path.clone()),
        }),
    )
    .unwrap();

    let plaintext = fs::read(output_path).unwrap();
    assert_eq!(plaintext, payload);
}

#[test]
fn bytes_write_errors_when_path_exists_without_overwrite() {
    let (_tmp, context) = setup_context();
    let relative = PathBuf::from("docs/existing.txt");
    let target = context.data_root.join(&relative);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, b"original").unwrap();
    let input_path = context.shadow_root.join("input.txt");
    fs::write(&input_path, b"new data").unwrap();

    let err = handle_bytes_command(
        &context,
        BytesCommand::Write(BytesWriteArgs {
            relative: relative.clone(),
            recipients: vec![],
            input: Some(input_path),
            plaintext: true,
            overwrite: false,
            hint: None,
        }),
    )
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("already exists (use --overwrite to replace)"),
        "unexpected error: {err}"
    );
}

#[test]
fn bytes_write_plaintext_flag_ignores_recipients() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");

    let input_path = context.shadow_root.join("note.txt");
    fs::write(&input_path, b"plaintext").unwrap();

    handle_bytes_command(
        &context,
        BytesCommand::Write(BytesWriteArgs {
            relative: PathBuf::from("docs/plain.txt"),
            recipients: vec!["bob@example.org".into()],
            input: Some(input_path),
            plaintext: true,
            overwrite: false,
            hint: None,
        }),
    )
    .unwrap();

    let written = fs::read(context.data_root.join("docs/plain.txt")).unwrap();
    assert_eq!(written, b"plaintext");
    assert!(
        !crate::protocol_interface::has_syc_magic(&written),
        "plaintext writes should not produce envelopes"
    );
}

#[test]
fn bytes_read_requires_envelope_when_flag_set() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice@example.org");

    let relative = PathBuf::from("docs/plain.txt");
    let target = context.data_root.join(&relative);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(&target, b"plaintext").unwrap();

    let err = handle_bytes_command(
        &context,
        BytesCommand::Read(BytesReadArgs {
            relative,
            identity: Some("alice@example.org".into()),
            require_envelope: true,
            output: None,
        }),
    )
    .unwrap_err();

    assert!(
        err.to_string().contains("does not contain an SYC envelope"),
        "unexpected error: {err}"
    );
}
