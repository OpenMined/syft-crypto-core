# SyC CLI Tutorial – Bytes Helper

The `syc bytes` commands let you stream plaintext into or out of the datasite without juggling temporary files. This tutorial mirrors the integration test flow using the `sandbox/` layout.

All commands run from the repository root.

> Quick start: run `just init-sandbox` first to create the sandbox directory structure, write the datasite configs, and generate Alice/Bob key material. Once that completes you can jump straight to step&nbsp;1 below.

---

## 1. Write Encrypted Bytes for Bob

```bash
printf 'Message via bytes helper\n' | syc \
  --vault sandbox/alice/.syc \
  bytes write \
  --relative alice@example.org/shared/bob@example.org/files/bytes.txt \
  --recipient bob@example.org
```

- `--relative` points to the datasite path (same structure as `file encrypt`).
- Data is read from stdin; use `--input <file>` to provide a source file.
- Supplying `--recipient` seals the bytes using the sender identity detected from Alice’s vault.

The SYC envelope now lives at:

```
sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/bytes.txt
```

Copy the ciphertext to Bob’s datasite (simulating delivery):

```bash
cp \
  sandbox/alice/datasites/alice@example.org/shared/bob@example.org/files/bytes.txt \
  sandbox/bob/datasites/bob@example.org/shared/alice@example.org/files/bytes.txt
```

## 2. Read and Decrypt as Bob

```bash
syc \
  --vault sandbox/bob/.syc \
  bytes read \
  --relative bob@example.org/shared/alice@example.org/files/bytes.txt \
  --identity bob@example.org
```

- The plaintext is emitted to stdout by default. Add `--output <file>` to write to disk.
- Omit `--identity` to auto-detect the single identity present in the vault.
- Use `--require-envelope` if you want the command to fail when the file is stored in plaintext.

## 3. Storing Plaintext

Skip recipients (or pass `--plaintext`) to keep bytes unencrypted:

```bash
echo 'local note' | syc \
  --vault sandbox/bob/.syc \
  bytes write \
  --relative bob@example.org/public/notes/note.txt \
  --plaintext
```

The file is written directly to the datasite tree. A subsequent `bytes read` will simply echo the contents.

---

## Quick Reference

- `bytes write … --recipient …` encrypts and stores an SYC envelope.
- `bytes write … --plaintext` stores raw bytes.
- `bytes read … --output <file>` decrypts to disk.
- `bytes read … --require-envelope` refuses plaintext inputs.
- `--overwrite` lets you replace an existing datasite file.
