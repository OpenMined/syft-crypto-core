# syft-crypto-python (PyO3 bindings)

Python bindings for the `syft-crypto-protocol` crate, built with [PyO3](https://pyo3.rs/) and [maturin](https://www.maturin.rs/).

## Quick start

```bash
uv venv
uv pip install maturin
uv run -- maturin develop --manifest-path bindings/python/Cargo.toml

python - <<'PY'
import syft_crypto_python as syc

material = syc.generate_identity_material("alice@example.com")
print(material.fingerprint)
print(material.did)
print(material.recovery_key_hex)
PY
```

## Building wheels

```bash
uv venv
uv pip install maturin
uv run -- maturin build --release --manifest-path bindings/python/Cargo.toml
ls dist
```

## Development

- Format Rust code with `cargo fmt`
- Format Python stubs with `uv run ruff format python`
- Lint Python code with `uv run ruff check python`

## Streaming (large files)

`encrypt_message` / `decrypt_message` hold the whole payload in memory. For files, use the
streaming API: it seals the file segment by segment (1 MiB by default) inside a single
envelope, so memory use does not grow with the file size, and it releases the GIL while
working.

```python
import syft_crypto_python as syc

# encrypt: src -> envelope file
syc.encrypt_file("alice@example.com", alice_keys,
                 [syc.EncryptionRecipient("bob@example.com", bob_bundle)],
                 "weights.safetensors", "weights.safetensors.syc",
                 filename_hint="weights.safetensors")

# inspect and verify the sender before touching the ciphertext
header = syc.parse_envelope_header_file("weights.safetensors.syc")
syc.verify_envelope_header_signature(header, alice_bundle.identity_key_bytes)
print(header.prelude["cipher"])   # suite, segment_count, last_segment_bytes, ciphertext_len

# decrypt: envelope file -> dst (signature and recipient are verified first)
syc.decrypt_file("bob@example.com", bob_keys, alice_bundle,
                 "weights.safetensors.syc", "weights.safetensors")
```

Segments are sealed and opened on all cores by default; pass `parallelism=1` to stay on one
thread, or `segment_size=` to change the 1 MiB default.

Both APIs read each other's envelopes: `decrypt_file` opens whole-payload envelopes and
`decrypt_message` opens streamed ones. On any error the partially written output file is removed.
