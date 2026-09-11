"""File-based (streaming) encryption through the Python binding."""

import os
import resource
import sys

import pytest
import syft_crypto_python as syc

SENDER = "sender@example.org"
RECIPIENT = "recipient@example.org"


def party(identity):
    keys = syc.SyftRecoveryKey.generate().derive_keys()
    doc = keys.to_public_bundle().to_did_document(f"did:syft:{identity}")
    doc["identity"] = identity
    bundle = syc.SyftPublicKeyBundle.from_did_document(doc)
    return keys, bundle


@pytest.fixture(scope="module")
def parties():
    return party(SENDER), party(RECIPIENT)


def peak_rss_bytes():
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss if sys.platform == "darwin" else rss * 1024


def test_file_round_trip_is_memory_bounded(tmp_path, parties):
    (skeys, sbundle), (rkeys, rbundle) = parties
    src, enc, dst = tmp_path / "in.bin", tmp_path / "in.syc", tmp_path / "out.bin"
    size = 64 * 1024 * 1024 + 17  # 65 segments at the default 1 MiB
    with open(src, "wb") as f:
        for _ in range(64):
            f.write(os.urandom(1024 * 1024))
        f.write(b"x" * 17)

    # Single thread first: memory must stay at a few segments.
    before = peak_rss_bytes()
    written = syc.encrypt_file(
        SENDER,
        skeys,
        [syc.EncryptionRecipient(RECIPIENT, rbundle)],
        src,
        enc,
        filename_hint="in.bin",
        parallelism=1,
    )
    read_back = syc.decrypt_file(RECIPIENT, rkeys, sbundle, enc, dst, parallelism=1)
    grown = peak_rss_bytes() - before
    assert written == enc.stat().st_size
    assert read_back == size
    assert dst.read_bytes() == src.read_bytes()
    assert grown < 16 * 1024 * 1024, f"RSS grew by {grown / 2**20:.1f} MiB"

    # All cores: memory scales with workers (about 2 segments per worker), never with the file.
    workers = min(os.cpu_count() or 1, 32)
    before = peak_rss_bytes()
    syc.encrypt_file(
        SENDER, skeys, [syc.EncryptionRecipient(RECIPIENT, rbundle)], src, enc
    )
    assert syc.decrypt_file(RECIPIENT, rkeys, sbundle, enc, dst) == size
    grown = peak_rss_bytes() - before
    assert dst.read_bytes() == src.read_bytes()
    assert grown < (2 * workers + 8) * 1024 * 1024, (
        f"RSS grew by {grown / 2**20:.1f} MiB with {workers} workers"
    )


def test_header_parses_and_verifies_without_reading_ciphertext(tmp_path, parties):
    (skeys, sbundle), (rkeys, rbundle) = parties
    src, enc = tmp_path / "a.bin", tmp_path / "a.syc"
    src.write_bytes(os.urandom(3 * 1024 * 1024 + 5))
    syc.encrypt_file(
        SENDER,
        skeys,
        [syc.EncryptionRecipient(RECIPIENT, rbundle)],
        src,
        enc,
        segment_size=1024 * 1024,
    )

    header = syc.parse_envelope_header_file(enc)
    assert header.prelude["cipher"]["suite"] == "xchacha20poly1305-stream-v1"
    assert header.prelude["cipher"]["segment_count"] == 4
    assert header.header_len + header.ciphertext_len == enc.stat().st_size
    syc.verify_envelope_header_signature(header, sbundle.identity_key_bytes)
    _, stranger = party("stranger@example.org")
    with pytest.raises(ValueError):
        syc.verify_envelope_header_signature(header, stranger.identity_key_bytes)


def test_tampered_file_is_rejected_and_no_output_is_left(tmp_path, parties):
    (skeys, sbundle), (rkeys, rbundle) = parties
    src, enc, dst = tmp_path / "b.bin", tmp_path / "b.syc", tmp_path / "b.out"
    src.write_bytes(os.urandom(2 * 1024 * 1024 + 100))
    syc.encrypt_file(
        SENDER,
        skeys,
        [syc.EncryptionRecipient(RECIPIENT, rbundle)],
        src,
        enc,
        segment_size=1024 * 1024,
    )

    data = bytearray(enc.read_bytes())
    data[-50] ^= 0x01  # inside the last segment
    enc.write_bytes(bytes(data))
    with pytest.raises(ValueError):
        syc.decrypt_file(RECIPIENT, rkeys, sbundle, enc, dst)
    assert not dst.exists()

    # Truncated: drop the final segment entirely.
    enc.write_bytes(bytes(data[: -(100 + 16)]))
    with pytest.raises(ValueError):
        syc.decrypt_file(RECIPIENT, rkeys, sbundle, enc, dst)
    assert not dst.exists()


def test_wrong_recipient_is_rejected(tmp_path, parties):
    (skeys, sbundle), (rkeys, rbundle) = parties
    src, enc, dst = tmp_path / "c.bin", tmp_path / "c.syc", tmp_path / "c.out"
    src.write_bytes(b"hello")
    syc.encrypt_file(
        SENDER, skeys, [syc.EncryptionRecipient(RECIPIENT, rbundle)], src, enc
    )
    okeys, _ = party("other@example.org")
    with pytest.raises(ValueError):
        syc.decrypt_file("other@example.org", okeys, sbundle, enc, dst)
    assert not dst.exists()


def test_interop_with_bytes_api(tmp_path, parties):
    (skeys, sbundle), (rkeys, rbundle) = parties
    payload = os.urandom(2 * 1024 * 1024 + 9)

    # bytes -> file: an envelope from encrypt_message opens with decrypt_file
    env = syc.encrypt_message(
        SENDER, skeys, [syc.EncryptionRecipient(RECIPIENT, rbundle)], payload
    )
    enc, dst = tmp_path / "old.syc", tmp_path / "old.out"
    enc.write_bytes(env)
    assert syc.decrypt_file(RECIPIENT, rkeys, sbundle, enc, dst) == len(payload)
    assert dst.read_bytes() == payload

    # file -> bytes: an envelope from encrypt_file opens with decrypt_message
    src, enc2 = tmp_path / "new.bin", tmp_path / "new.syc"
    src.write_bytes(payload)
    syc.encrypt_file(
        SENDER,
        skeys,
        [syc.EncryptionRecipient(RECIPIENT, rbundle)],
        src,
        enc2,
        segment_size=512 * 1024,
    )
    parsed = syc.parse_envelope(enc2.read_bytes())
    assert parsed.prelude["cipher"]["segment_count"] == 5
    syc.verify_envelope_signature(parsed, sbundle.identity_key_bytes)
    assert syc.decrypt_message(RECIPIENT, rkeys, sbundle, parsed) == payload


def test_empty_file(tmp_path, parties):
    (skeys, sbundle), (rkeys, rbundle) = parties
    src, enc, dst = tmp_path / "e.bin", tmp_path / "e.syc", tmp_path / "e.out"
    src.write_bytes(b"")
    syc.encrypt_file(
        SENDER, skeys, [syc.EncryptionRecipient(RECIPIENT, rbundle)], src, enc
    )
    assert syc.decrypt_file(RECIPIENT, rkeys, sbundle, enc, dst) == 0
    assert dst.read_bytes() == b""
