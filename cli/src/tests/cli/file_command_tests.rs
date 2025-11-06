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
    let envelope_bytes = fs::read(context.data_root.join(&relative)).unwrap();
    assert!(protocol_interface::has_syc_magic(&envelope_bytes));
    let parsed = protocol_interface::parse_envelope(&envelope_bytes).unwrap();
    protocol_interface::verify_stub_signature(&parsed, false).unwrap();
    let decrypted =
        protocol_interface::decrypt_bytes("alice", &parsed.ciphertext, false).unwrap();
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
fn encrypt_relative_mode_honors_dry_run() {
    let (_tmp, context) = setup_context();
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
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    assert!(
        !context.data_root.join(relative).exists(),
        "ciphertext should not be written during dry-run"
    );
}

#[test]
fn encrypt_direct_writes_ciphertext_with_detected_identity() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    let src = context.shadow_root.join("message.txt");
    fs::write(&src, b"top secret").unwrap();
    let dest = context.data_root.join("cipher.bin");

    let args = FileEncryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        sender: None,
        recipient: Some("bob".into()),
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Encrypt(args)).unwrap();
    let envelope_bytes = fs::read(&dest).unwrap();
    assert!(protocol_interface::has_syc_magic(&envelope_bytes));
    let parsed = protocol_interface::parse_envelope(&envelope_bytes).unwrap();
    protocol_interface::verify_stub_signature(&parsed, false).unwrap();
    let decrypted =
        protocol_interface::decrypt_bytes("alice", &parsed.ciphertext, false).unwrap();
    assert_eq!(decrypted.plaintext, b"top secret");
}

#[test]
fn encrypt_direct_requires_destination_path() {
    let (_tmp, context) = setup_context();
    let src = context.shadow_root.join("message.txt");
    fs::write(&src, b"secret").unwrap();

    let args = FileEncryptArgs {
        relative: None,
        src: Some(src),
        dest: None,
        sender: Some("alice".into()),
        recipient: None,
        dry_run: false,
    };

    let err = handle_file_command(&context, FileCommand::Encrypt(args)).unwrap_err();
    assert!(
        err.to_string().contains("--dest or --relative is required"),
        "unexpected error: {err}"
    );
}

#[test]
fn decrypt_relative_recovers_plaintext() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    let relative = PathBuf::from("docs/note.txt");
    let data_file = context.data_root.join(&relative);
    fs::create_dir_all(data_file.parent().unwrap()).unwrap();
    let payload =
        protocol_interface::encrypt_bytes("alice", Some("bob"), b"cipher").unwrap();
    let envelope = protocol_interface::build_stub_envelope(
        "alice",
        &[String::from("bob")],
        &payload,
        None,
    )
    .unwrap();
    fs::write(&data_file, envelope).unwrap();

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
fn decrypt_relative_dry_run_skips_writes() {
    let (_tmp, context) = setup_context();
    let relative = PathBuf::from("docs/note.txt");

    let args = FileDecryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        identity: Some("alice".into()),
        skip_checks: false,
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    assert!(
        !context.shadow_root.join(relative).exists(),
        "no plaintext should be written during dry-run"
    );
}

#[test]
fn decrypt_relative_warns_on_plaintext_payload() {
    let (_tmp, context) = setup_context();
    let relative = PathBuf::from("docs/note.txt");
    let data_file = context.data_root.join(&relative);
    fs::create_dir_all(data_file.parent().unwrap()).unwrap();
    fs::write(&data_file, b"unencrypted").unwrap();

    let args = FileDecryptArgs {
        relative: Some(relative.clone()),
        src: None,
        dest: None,
        identity: Some("alice".into()),
        skip_checks: false,
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    let plaintext = fs::read(context.shadow_root.join(&relative)).unwrap();
    assert_eq!(plaintext, b"unencrypted");
}

#[test]
fn decrypt_direct_allows_plaintext_when_skip_checks_enabled() {
    let (_tmp, context) = setup_context();
    write_identity(&context, "alice");
    let src = context.data_root.join("plain.bin");
    let dest = context.shadow_root.join("out.txt");
    fs::write(&src, b"raw bytes").unwrap();

    let args = FileDecryptArgs {
        relative: None,
        src: Some(src.clone()),
        dest: Some(dest.clone()),
        identity: None,
        skip_checks: true,
        dry_run: false,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    assert_eq!(fs::read(dest).unwrap(), b"raw bytes");
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
        err.to_string().contains("is not an SYC envelope"),
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
    let envelope =
        protocol_interface::build_stub_envelope("alice", &[], &payload, None).unwrap();
    fs::write(&file, envelope).unwrap();

    let args = FileInspectArgs {
        input: PathBuf::from("blob.bin"),
        identity: Some("alice".into()),
        verbose: true,
    };

    handle_file_command(&context, FileCommand::Inspect(args)).unwrap();
}

#[test]
fn decrypt_direct_dry_run_skips_outputs() {
    let (_tmp, context) = setup_context();
    let src = context.data_root.join("cipher.bin");
    fs::write(&src, b"ciphertext").unwrap();
    let dest = context.shadow_root.join("plain.txt");

    let args = FileDecryptArgs {
        relative: None,
        src: Some(src),
        dest: Some(dest.clone()),
        identity: Some("alice".into()),
        skip_checks: false,
        dry_run: true,
    };

    handle_file_command(&context, FileCommand::Decrypt(args)).unwrap();
    assert!(!dest.exists());
}
