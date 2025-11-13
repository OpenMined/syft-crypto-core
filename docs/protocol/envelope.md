# SYC1 Envelope Format

This document describes the prototype “SYC1” envelope implemented inside the CLI. The structure mirrors the blueprint for a Signal-compatible container but currently uses placeholder fingerprints and signatures. Once libsignal integration lands, only the value providers change—the on-disk layout stays identical.

---

## High-Level Goals

- Detect encrypted assets by peeking at a fixed header (`SYC1`) instead of relying on file extensions.
- Carry signer and recipient metadata in a canonical JSON prelude so tooling (`syc file inspect`) can expose context without touching ciphertext.
- Allow signature verification prior to decryption and support optional payload integrity checks.
- Prevent the need for sidecar files which ensures atomicity when dealing with each file
- Allow for future format / version changes

---

## File Layout

```
┌─────────────┬────────┬──────────────┬─────────────────────┬──────────────┬────────────┐
│ MAGIC(4B)   │ VERSION│ PRELUDE LEN  │ PRELUDE (padded 4K) │ SIG LEN (2B) │ SIGNATURE  │
└─────────────┴────────┴──────────────┴─────────────────────┴──────────────┴────────────┘
                                                                             │
                                                                             ▼
                                                                       CIPHERTEXT STREAM
```

The header is binary. If you dump the file as UTF‑8 you may see odd characters such as `}` right after `SYC1`. That’s simply the little-endian representation of the prelude length (`0x7D` = 125) and signature length (`0x1D` = 29) landing on printable ASCII. Use `hexdump -C` to inspect the structure; you’ll see the magic (`53 59 43 31`), version byte, 4-byte prelude length, canonical JSON prelude (padded to 4 KiB), 2-byte signature length, the detached signature, and finally the ciphertext.

1. **Magic + Version**
   - Magic: ASCII `SYC1`.
   - Version: single byte (`1` for the current version).
2. **Prelude Length**
   - Unsigned 32-bit little-endian integer describing the canonical JSON prelude length (in bytes).
3. **Prelude**
   - RFC 8785 canonical JSON describing signer, recipients, wrapping metadata, cipher info, and optional integrity/public metadata.
   - We use canonical JSON so that there can't be errors in slight changes with the json with different libraries / formatting rules leading to different hashes
   - Padded up to the next 4 KiB boundary with zeros to remain predictable.
4. **Signature Length**
   - Unsigned 16-bit little-endian integer describing the length of the detached signature.
5. **Signature**
   - Signature bytes. Currently this is a deterministic placeholder.
6. **Ciphertext**
   - Remainder of the file: the encrypted payload emitted by the libsignal file layer.

![](./evelope-structure.png)


---

## Prelude Schema

```jsonc
{
  "version": 1,
  "canon": "jcs-rfc8785",
  "created_at": 1730338793,
  "sender": {
    "identity": "alice@example.org",
    "ik_fingerprint": "stub-alice_example_org"
  },
  "recipients": [
    {
      "identity": "bob@example.org",
      "device_label": "stub-device",
      "spk_fingerprint": "stub-bob_example_org:spk",
      "pqspk_fingerprint": "stub-bob_example_org:pqspk",
      "signed_prekey_id": 1
    }
  ],
  "recipient_set_fpr": "stub-fpr-1",
  "wrappings": [
    {
      "recipient_identity": "bob@example.org",
      "device_label": "stub-device",
      "wrap_ephemeral_public": "stub-epk",
      "wrap_ciphertext": "stub-kem-ciphertext"
    }
  ],
  "cipher": {
    "suite": "libsignal-file-v1",
    "segment_count": 1,
    "last_segment_bytes": 1234,
    "ciphertext_len": 1234
  },
  "integrity": null,
  "public_meta": {
    "filename_hint": "optional_hint.txt"
  }
}
```

Fields correspond to libsignal terminology:

- `sender.identity` / `sender.ik_fingerprint` describe the author (later derived from the Ed25519 identity key).
- Each entry in `recipients` mirrors a device binding: signed prekey fingerprint, PQ prekey fingerprint, and the signed prekey ID.
- `wrappings` contain PQXDH outputs: sender’s ephemeral public key and Kyber ciphertext for each target device.
- `cipher` summarises the Double Ratchet file-layer stats so `inspect` can report segment sizes without decryption.
- `integrity` will eventually hold a base64url SHA-256 hash of the ciphertext for tamper detection.
- `public_meta` carries small hints (e.g., `filename_hint`) that do not compromise confidentiality.

The JSON is produced via the RFC 8785 canonicalisation helper (`to_jcs_bytes`), ensuring deterministic hashing/signing.

---

## Signing Strategy

- `build_stub_envelope` currently concatenates a deterministic marker (`"syc-stub-signature-v1"`) with the first few prelude bytes. This makes it easy to detect tampering in tests without real key material.
- `verify_stub_signature` recomputes the placeholder and returns an error if it doesn’t match. Once libsignal signing is introduced, this function will call Ed25519 verification instead.
