use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CONFIG_JSON: &str = r#"{
  "encrypted_root": "../datasites",
  "shadow_root": "../unencrypted"
}
"#;

const SAMPLE_MESSAGE: &str = r#"Hello Bob,

This is a placeholder message from Alice. Once the PQ encryption
plumbing is wired up, this text will be replaced with sealed bytes."#;

const SYC_MAGIC: &[u8; 4] = b"SYC1";

#[test]
fn simulate_workflow_matches_shell_script() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("cli crate should have a parent workspace root");
    let sandbox_root = repo_root.join("sandbox");

    let alice = sandbox_root.join("alice");
    let bob = sandbox_root.join("bob");

    let alice_vault = alice.join(".syc");
    let bob_vault = bob.join(".syc");

    // Clean up artefacts from prior runs but keep directories for inspection if this test fails.
    for path in files_to_clean(&sandbox_root) {
        if path.exists() {
            fs::remove_file(&path)?;
        }
    }

    // Ensure directory skeleton exists for both identities.
    for dir in directories_to_ensure(&sandbox_root) {
        fs::create_dir_all(dir)?;
    }

    // Write per-identity config pointing at datasites/unencrypted mirrors.
    write_file(&alice_vault.join("config/datasite.json"), CONFIG_JSON)?;
    write_file(&bob_vault.join("config/datasite.json"), CONFIG_JSON)?;

    // Seed Alice's plaintext message.
    write_file(
        &alice.join("unencrypted/alice@example.org/shared/bob@example.org/files/message.txt"),
        SAMPLE_MESSAGE,
    )?;

    // Generate Alice key material and public bundle.
    run_cli(&[
        "--vault",
        alice_vault.to_str().unwrap(),
        "key",
        "generate",
        "--identity",
        "alice@example.org",
        "--overwrite",
        "--bundle-out",
        "alice@example.org/public/crypto/did.json",
    ])?;

    // Generate Bob key material and public bundle.
    run_cli(&[
        "--vault",
        bob_vault.to_str().unwrap(),
        "key",
        "generate",
        "--identity",
        "bob@example.org",
        "--overwrite",
        "--bundle-out",
        "bob@example.org/public/crypto/did.json",
    ])?;

    // Encrypt Alice's message relative to her datasite/shadow roots.
    run_cli(&[
        "--vault",
        alice_vault.to_str().unwrap(),
        "file",
        "encrypt",
        "--relative",
        "alice@example.org/shared/bob@example.org/files/message.txt",
        "--recipient",
        "bob@example.org",
        "--sender",
        "alice@example.org",
    ])?;

    let alice_cipher =
        alice.join("datasites/alice@example.org/shared/bob@example.org/files/message.txt");
    let bob_cipher =
        bob.join("datasites/bob@example.org/shared/alice@example.org/files/message.txt");

    // Deliver ciphertext to Bob's datasite.
    fs::create_dir_all(
        bob_cipher
            .parent()
            .expect("cipher path should have a parent directory"),
    )?;
    fs::copy(&alice_cipher, &bob_cipher)?;

    // Inspect ciphertext as Bob.
    let inspect_output = Command::new(env!("CARGO_BIN_EXE_syc"))
        .args([
            "--vault",
            bob_vault.to_str().unwrap(),
            "file",
            "inspect",
            "--input",
            "bob@example.org/shared/alice@example.org/files/message.txt",
            "--identity",
            "bob@example.org",
            "--verbose",
        ])
        .output()?;
    assert!(
        inspect_output.status.success(),
        "inspect failed: {}{}",
        String::from_utf8_lossy(&inspect_output.stdout),
        String::from_utf8_lossy(&inspect_output.stderr)
    );
    let inspect_stdout = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(
        inspect_stdout.contains("envelope magic"),
        "inspect output should mention envelope magic"
    );

    // Decrypt into Bob's shadow tree.
    run_cli(&[
        "--vault",
        bob_vault.to_str().unwrap(),
        "file",
        "decrypt",
        "--relative",
        "bob@example.org/shared/alice@example.org/files/message.txt",
        "--identity",
        "bob@example.org",
    ])?;

    // Assertions mirroring simulate.sh expectations.
    assert!(alice_vault.join("keys/alice@example.org.key").exists());
    assert!(bob_vault.join("keys/bob@example.org.key").exists());

    assert!(
        alice
            .join("datasites/alice@example.org/public/crypto/did.json")
            .exists()
    );
    assert!(
        bob.join("datasites/bob@example.org/public/crypto/did.json")
            .exists()
    );

    let ciphertext = fs::read(&bob_cipher)?;
    assert!(
        ciphertext.starts_with(SYC_MAGIC),
        "ciphertext should start with SYC envelope magic"
    );

    let plaintext_path =
        bob.join("unencrypted/bob@example.org/shared/alice@example.org/files/message.txt");
    let mut plaintext = String::new();
    fs::File::open(&plaintext_path)?.read_to_string(&mut plaintext)?;
    assert_eq!(plaintext, SAMPLE_MESSAGE);

    // Use bytes helper to write encrypted content from Alice.
    let bytes_message = b"Hello from bytes CLI";
    let mut write_child = Command::new(env!("CARGO_BIN_EXE_syc"))
        .args([
            "--vault",
            alice_vault.to_str().unwrap(),
            "bytes",
            "write",
            "--relative",
            "alice@example.org/shared/bob@example.org/files/bytes.txt",
            "--recipient",
            "bob@example.org",
            "--overwrite",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .spawn()?;
    write_child
        .stdin
        .as_mut()
        .expect("bytes write stdin")
        .write_all(bytes_message)?;
    let status = write_child.wait()?;
    assert!(status.success(), "bytes write failed");

    // Deliver bytes ciphertext to Bob.
    let alice_bytes_cipher =
        alice.join("datasites/alice@example.org/shared/bob@example.org/files/bytes.txt");
    let bob_bytes_cipher =
        bob.join("datasites/bob@example.org/shared/alice@example.org/files/bytes.txt");
    fs::create_dir_all(bob_bytes_cipher.parent().expect("bytes path has parent"))?;
    fs::copy(&alice_bytes_cipher, &bob_bytes_cipher)?;

    // Read via bytes helper (stdout).
    let read_output = Command::new(env!("CARGO_BIN_EXE_syc"))
        .args([
            "--vault",
            bob_vault.to_str().unwrap(),
            "bytes",
            "read",
            "--relative",
            "bob@example.org/shared/alice@example.org/files/bytes.txt",
            "--identity",
            "bob@example.org",
        ])
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output()?;
    assert!(
        read_output.status.success(),
        "bytes read failed: {}",
        String::from_utf8_lossy(&read_output.stderr)
    );
    assert_eq!(read_output.stdout, bytes_message);

    Ok(())
}

fn run_cli(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_syc"))
        .args(args)
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "command `syc {}` failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    Ok(())
}

fn write_file(path: &Path, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, body)?;
    Ok(())
}

fn files_to_clean(root: &Path) -> Vec<PathBuf> {
    [
        "alice/datasites/alice@example.org/shared/bob@example.org/files/alice-to-bob.syc",
        "bob/datasites/bob@example.org/shared/alice@example.org/files/alice-to-bob.syc",
        "alice/unencrypted/alice@example.org/shared/bob@example.org/files/alice-message.txt",
        "bob/unencrypted/bob@example.org/shared/alice@example.org/files/decrypted-from-alice.txt",
        "alice/datasites/alice@example.org/shared/bob@example.org/files/message.txt",
        "alice/datasites/alice@example.org/shared/bob@example.org/files/bytes.txt",
        "bob/datasites/bob@example.org/shared/alice@example.org/files/message.txt",
        "bob/datasites/bob@example.org/shared/alice@example.org/files/bytes.txt",
        "alice/unencrypted/alice@example.org/shared/bob@example.org/files/message.txt",
        "bob/unencrypted/bob@example.org/shared/alice@example.org/files/message.txt",
    ]
    .iter()
    .map(|rel| root.join(rel))
    .collect()
}

fn directories_to_ensure(root: &Path) -> Vec<PathBuf> {
    [
        "alice/.syc/config",
        "alice/.syc/keys",
        "alice/.syc/bundles",
        "alice/unencrypted/alice@example.org/public/crypto",
        "alice/unencrypted/alice@example.org/shared/bob@example.org/files",
        "alice/datasites/alice@example.org/public/crypto",
        "alice/datasites/alice@example.org/shared/bob@example.org/files",
        "bob/.syc/config",
        "bob/.syc/keys",
        "bob/.syc/bundles",
        "bob/unencrypted/bob@example.org/public/crypto",
        "bob/unencrypted/bob@example.org/shared/alice@example.org/files",
        "bob/datasites/bob@example.org/public/crypto",
        "bob/datasites/bob@example.org/shared/alice@example.org/files",
    ]
    .iter()
    .map(|rel| root.join(rel))
    .collect()
}
