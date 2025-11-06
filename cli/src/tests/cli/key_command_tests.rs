use super::*;
use crate::protocol_interface;
use std::path::PathBuf;
use tempfile::tempdir;

fn setup_context() -> (tempfile::TempDir, AppContext) {
    let base = tempdir().unwrap();
    let vault = base.path().join("vault");
    let data = base.path().join("data");
    let shadow = base.path().join("shadow");
    std::fs::create_dir_all(&vault).unwrap();
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&shadow).unwrap();
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
fn key_generate_dry_run_is_non_destructive() {
    let (_tmp, context) = setup_context();
    let args = KeyGenerateArgs {
        identity: "alice".into(),
        bundle_out: None,
        overwrite: false,
        dry_run: true,
    };
    handle_key_command(&context, KeyCommand::Generate(args)).unwrap();
    assert!(!context.vault_path.join("keys/alice.key").exists());
}

#[test]
fn key_generate_writes_key_and_bundle() {
    let (_tmp, context) = setup_context();
    let args = KeyGenerateArgs {
        identity: "bob".into(),
        bundle_out: Some(PathBuf::from("bundles/bob.json")),
        overwrite: false,
        dry_run: false,
    };
    handle_key_command(&context, KeyCommand::Generate(args)).unwrap();
    assert!(context.vault_path.join("keys/bob.key").exists());
    assert!(context.data_root.join("bundles/bob.json").exists());
}

#[test]
fn key_generate_creates_nested_bundle_directories() {
    let (_tmp, context) = setup_context();
    let args = KeyGenerateArgs {
        identity: "dave".into(),
        bundle_out: Some(PathBuf::from("nested/dirs/dave.json")),
        overwrite: true,
        dry_run: false,
    };
    handle_key_command(&context, KeyCommand::Generate(args)).unwrap();
    assert!(context.data_root.join("nested/dirs/dave.json").exists());
}

#[test]
fn key_generate_requires_overwrite_for_existing_material() {
    let (_tmp, context) = setup_context();
    handle_key_command(
        &context,
        KeyCommand::Generate(KeyGenerateArgs {
            identity: "carol".into(),
            bundle_out: None,
            overwrite: false,
            dry_run: false,
        }),
    )
    .unwrap();
    let err = handle_key_command(
        &context,
        KeyCommand::Generate(KeyGenerateArgs {
            identity: "carol".into(),
            bundle_out: None,
            overwrite: false,
            dry_run: false,
        }),
    )
    .unwrap_err();
    assert!(err.to_string().contains("key material already exists"));
}

#[test]
fn key_import_verify_only_does_not_write_bundle() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    std::fs::write(&bundle_path, "placeholder").unwrap();
    let args = KeyImportArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: Some("alice".into()),
        verify_only: true,
        force: false,
    };
    handle_key_command(&context, KeyCommand::Import(args)).unwrap();
    assert!(!context.vault_path.join("bundles/bundle.json").exists());
}

#[test]
fn key_import_persists_bundle_when_not_verify_only() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    std::fs::write(&bundle_path, "placeholder").unwrap();
    let args = KeyImportArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: None,
        verify_only: false,
        force: true,
    };
    handle_key_command(&context, KeyCommand::Import(args)).unwrap();
    assert!(context.vault_path.join("bundles/bundle.json").exists());
}

#[test]
fn key_recover_is_non_destructive_noop() {
    let (_tmp, context) = setup_context();
    let package = context.data_root.join("package.zip");
    std::fs::write(&package, b"archive").unwrap();
    let args = KeyRecoverArgs {
        package,
        identity: Some("alice".into()),
        output: Some(PathBuf::from("out")),
        dry_run: true,
    };
    handle_key_command(&context, KeyCommand::Recover(args)).unwrap();
}

#[test]
fn key_list_outputs_identities_even_with_filter() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let alice = key_path_for_identity(&context.vault_path, "alice");
    let bob = key_path_for_identity(&context.vault_path, "bob");
    let alice_material = protocol_interface::generate_identity_material("alice").unwrap();
    let bob_material = protocol_interface::generate_identity_material("bob").unwrap();
    std::fs::write(&alice, alice_material.key_file).unwrap();
    std::fs::write(&bob, bob_material.key_file).unwrap();

    let list_all = KeyListArgs {
        identity: None,
        verbose: true,
    };
    handle_key_command(&context, KeyCommand::List(list_all)).unwrap();

    let list_single = KeyListArgs {
        identity: Some("alice".into()),
        verbose: false,
    };
    handle_key_command(&context, KeyCommand::List(list_single)).unwrap();
}

#[test]
fn key_list_reports_empty_vault() {
    let (_tmp, context) = setup_context();
    ensure_vault_layout(&context.vault_path).unwrap();
    let args = KeyListArgs {
        identity: None,
        verbose: false,
    };
    handle_key_command(&context, KeyCommand::List(args)).unwrap();
}

#[test]
fn key_verify_handles_json_mode() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    std::fs::write(&bundle_path, "identity: alice").unwrap();
    let args = KeyVerifyArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: Some("alice".into()),
        verify_only: false,
        json: true,
    };
    handle_key_command(&context, KeyCommand::Verify(args)).unwrap();
}

#[test]
fn key_verify_warns_when_expected_identity_missing() {
    let (_tmp, context) = setup_context();
    let bundle_path = context.data_root.join("bundle.json");
    std::fs::write(&bundle_path, "placeholder").unwrap();
    let args = KeyVerifyArgs {
        bundle: PathBuf::from("bundle.json"),
        expected_identity: Some("carol".into()),
        verify_only: false,
        json: false,
    };
    handle_key_command(&context, KeyCommand::Verify(args)).unwrap();
}
