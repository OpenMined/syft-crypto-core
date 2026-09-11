//! Streaming (segmented) encryption: round trips, geometry, tamper resistance, and
//! interoperability with the whole-payload suite.

use std::io::{Cursor, Read, Write};
use syft_crypto_protocol::{
    DEFAULT_SEGMENT_SIZE, FILE_CIPHER_SUITE, STREAM_CIPHER_SUITE, SegmentLayout, SyftPrivateKeys,
    SyftPublicKeyBundle, SyftRecoveryKey, decrypt_message, decrypt_stream, encrypt_message,
    encrypt_stream,
    encryption::{EncryptionRecipient, TAG_LEN},
    envelope::{parse_envelope, parse_envelope_header, verify_header_signature},
};

const SENDER: &str = "sender@example.org";
const RECIPIENT: &str = "recipient@example.org";

struct Party {
    keys: SyftPrivateKeys,
    bundle: SyftPublicKeyBundle,
}

fn party() -> Party {
    let keys = SyftRecoveryKey::generate().derive_keys().expect("keys");
    let bundle = keys.to_public_bundle(&mut rand::rng()).expect("bundle");
    Party { keys, bundle }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn seal(sender: &Party, recipient: &Party, plaintext: &[u8], segment: Option<usize>) -> Vec<u8> {
    let mut out = Vec::new();
    let written = encrypt_stream(
        SENDER,
        &sender.keys,
        &[EncryptionRecipient {
            identity: RECIPIENT,
            bundle: &recipient.bundle,
        }],
        plaintext.len() as u64,
        &mut Cursor::new(plaintext),
        &mut out,
        segment,
        Some("stream.bin"),
        &mut rand::rng(),
    )
    .expect("encrypt_stream");
    assert_eq!(usize::try_from(written).unwrap(), out.len());
    out
}

fn open(
    sender: &Party,
    recipient: &Party,
    envelope: &[u8],
) -> syft_crypto_protocol::Result<Vec<u8>> {
    let mut out = Vec::new();
    decrypt_stream(
        RECIPIENT,
        &recipient.keys,
        &sender.bundle,
        &mut Cursor::new(envelope),
        &mut out,
    )
    .map(|_| out)
}

fn header_len(envelope: &[u8]) -> usize {
    let mut cursor = Cursor::new(envelope);
    let header = parse_envelope_header(&mut cursor).expect("header");
    let len = usize::try_from(cursor.position()).unwrap();
    assert_eq!(header.header_len().expect("header_len"), len);
    len
}

// ============================================================================
// Round trips
// ============================================================================

#[test]
fn round_trips_across_segment_boundaries() {
    let (sender, recipient) = (party(), party());
    let seg = 1024;
    for len in [0, 1, seg - 1, seg, seg + 1, 3 * seg, 3 * seg + 7, 10 * seg] {
        let plaintext = pattern(len);
        let envelope = seal(&sender, &recipient, &plaintext, Some(seg));
        let opened = open(&sender, &recipient, &envelope).expect("decrypt_stream");
        assert_eq!(opened, plaintext, "len {len}");

        // The bytes API opens the same envelope.
        let parsed = parse_envelope(&envelope).expect("parse");
        assert_eq!(parsed.prelude.cipher.suite, STREAM_CIPHER_SUITE);
        let opened = decrypt_message(RECIPIENT, &recipient.keys, &sender.bundle, &parsed)
            .expect("decrypt_message");
        assert_eq!(opened, plaintext, "bytes api, len {len}");
    }
}

#[test]
fn default_segment_size_and_geometry_are_recorded_in_the_prelude() {
    let (sender, recipient) = (party(), party());
    let plaintext = pattern(DEFAULT_SEGMENT_SIZE * 2 + 5);
    let envelope = seal(&sender, &recipient, &plaintext, None);
    let parsed = parse_envelope(&envelope).expect("parse");
    let cipher = &parsed.prelude.cipher;
    assert_eq!(cipher.segment_count, 3);
    assert_eq!(cipher.last_segment_bytes, 5 + TAG_LEN as u64);
    assert_eq!(
        cipher.ciphertext_len,
        (plaintext.len() + 3 * TAG_LEN) as u64
    );
    assert_eq!(parsed.ciphertext.len() as u64, cipher.ciphertext_len);

    let layout = SegmentLayout::from_cipher_info(
        cipher.segment_count,
        cipher.last_segment_bytes,
        cipher.ciphertext_len,
    )
    .expect("layout");
    assert_eq!(layout.segment_size, DEFAULT_SEGMENT_SIZE);
    assert_eq!(
        layout,
        SegmentLayout::for_plaintext(plaintext.len() as u64, DEFAULT_SEGMENT_SIZE).unwrap()
    );
}

#[test]
fn empty_payload_is_one_empty_segment() {
    let (sender, recipient) = (party(), party());
    let envelope = seal(&sender, &recipient, &[], Some(64));
    let parsed = parse_envelope(&envelope).expect("parse");
    assert_eq!(parsed.prelude.cipher.segment_count, 1);
    assert_eq!(parsed.ciphertext.len(), TAG_LEN);
    assert_eq!(
        open(&sender, &recipient, &envelope).unwrap(),
        Vec::<u8>::new()
    );
}

#[test]
fn exact_multiple_ends_with_a_full_segment() {
    let layout = SegmentLayout::for_plaintext(4096, 1024).unwrap();
    assert_eq!(layout.segment_count, 4);
    assert_eq!(layout.last_segment_bytes, 1024 + TAG_LEN as u64);
    assert_eq!(layout.ciphertext_len, 4096 + 4 * TAG_LEN as u64);
}

#[test]
fn multiple_recipients_can_each_open_a_stream() {
    let sender = party();
    let (alice, bob) = (party(), party());
    let plaintext = pattern(5000);
    let mut envelope = Vec::new();
    encrypt_stream(
        SENDER,
        &sender.keys,
        &[
            EncryptionRecipient {
                identity: "alice@example.org",
                bundle: &alice.bundle,
            },
            EncryptionRecipient {
                identity: "bob@example.org",
                bundle: &bob.bundle,
            },
        ],
        plaintext.len() as u64,
        &mut Cursor::new(&plaintext),
        &mut envelope,
        Some(700),
        None,
        &mut rand::rng(),
    )
    .unwrap();
    for (identity, keys) in [
        ("alice@example.org", &alice.keys),
        ("bob@example.org", &bob.keys),
    ] {
        let mut out = Vec::new();
        decrypt_stream(
            identity,
            keys,
            &sender.bundle,
            &mut Cursor::new(&envelope),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }
    let mut out = Vec::new();
    let stranger = party();
    assert!(
        decrypt_stream(
            "carol@example.org",
            &stranger.keys,
            &sender.bundle,
            &mut Cursor::new(&envelope),
            &mut out
        )
        .is_err()
    );
}

// ============================================================================
// Interoperability with the whole-payload suite
// ============================================================================

#[test]
fn decrypt_stream_opens_whole_payload_envelopes() {
    let (sender, recipient) = (party(), party());
    let plaintext = pattern(3000);
    let envelope = encrypt_message(
        SENDER,
        &sender.keys,
        &[EncryptionRecipient {
            identity: RECIPIENT,
            bundle: &recipient.bundle,
        }],
        &plaintext,
        Some("old.bin"),
        &mut rand::rng(),
    )
    .unwrap();
    assert_eq!(
        parse_envelope(&envelope).unwrap().prelude.cipher.suite,
        FILE_CIPHER_SUITE
    );
    assert_eq!(open(&sender, &recipient, &envelope).unwrap(), plaintext);

    // ...and still refuses a truncated or extended one.
    let short = &envelope[..envelope.len() - 1];
    assert!(open(&sender, &recipient, short).is_err());
    let mut long = envelope.clone();
    long.push(0);
    assert!(open(&sender, &recipient, &long).is_err());
}

#[test]
fn header_parses_from_a_stream_and_verifies() {
    let (sender, recipient) = (party(), party());
    let plaintext = pattern(2500);
    let envelope = seal(&sender, &recipient, &plaintext, Some(1000));
    let mut cursor = Cursor::new(&envelope);
    let header = parse_envelope_header(&mut cursor).unwrap();
    assert_eq!(header.prelude.cipher.suite, STREAM_CIPHER_SUITE);
    assert_eq!(header.prelude.cipher.segment_count, 3);
    verify_header_signature(&header, &sender.bundle.identity_signing_public_key).unwrap();
    let other = party();
    assert!(verify_header_signature(&header, &other.bundle.identity_signing_public_key).is_err());
    // The reader is left at the first ciphertext byte.
    let mut rest = Vec::new();
    cursor.read_to_end(&mut rest).unwrap();
    assert_eq!(rest.len() as u64, header.prelude.cipher.ciphertext_len);
    // The in-memory parser agrees on where the header ends.
    let parsed = parse_envelope(&envelope).unwrap();
    assert_eq!(parsed.prelude_bytes, header.prelude_bytes);
    assert_eq!(parsed.signature, header.signature);
    assert_eq!(parsed.ciphertext, rest);
}

// ============================================================================
// Tamper resistance: every manipulation of the segment sequence must fail
// ============================================================================

fn segments(envelope: &[u8], seg: usize) -> (usize, Vec<Vec<u8>>) {
    let hdr = header_len(envelope);
    let body = &envelope[hdr..];
    let full = seg + TAG_LEN;
    let mut out: Vec<Vec<u8>> = body.chunks(full).map(|c| c.to_vec()).collect();
    // chunks() splits the last (shorter) segment correctly because all others are full-size
    assert!(out.iter().rev().skip(1).all(|s| s.len() == full));
    if out.is_empty() {
        out.push(Vec::new());
    }
    (hdr, out)
}

fn rebuild(envelope: &[u8], hdr: usize, segs: &[Vec<u8>]) -> Vec<u8> {
    let mut e = envelope[..hdr].to_vec();
    for s in segs {
        e.extend_from_slice(s);
    }
    e
}

#[test]
fn reordered_segments_are_rejected() {
    let (sender, recipient) = (party(), party());
    let seg = 512;
    let envelope = seal(&sender, &recipient, &pattern(seg * 4), Some(seg));
    let (hdr, mut segs) = segments(&envelope, seg);
    segs.swap(1, 2);
    let forged = rebuild(&envelope, hdr, &segs);
    assert!(open(&sender, &recipient, &forged).is_err());
    let parsed = parse_envelope(&forged).unwrap();
    assert!(decrypt_message(RECIPIENT, &recipient.keys, &sender.bundle, &parsed).is_err());
}

#[test]
fn dropped_middle_segment_is_rejected() {
    let (sender, recipient) = (party(), party());
    let seg = 512;
    let envelope = seal(&sender, &recipient, &pattern(seg * 4 + 3), Some(seg));
    let (hdr, mut segs) = segments(&envelope, seg);
    segs.remove(1);
    // Prelude still says 5 segments, so the stream is short: must fail, never partial-succeed.
    let mut out = Vec::new();
    let res = decrypt_stream(
        RECIPIENT,
        &recipient.keys,
        &sender.bundle,
        &mut Cursor::new(rebuild(&envelope, hdr, &segs)),
        &mut out,
    );
    assert!(res.is_err());
}

#[test]
fn truncated_tail_is_rejected() {
    let (sender, recipient) = (party(), party());
    let seg = 512;
    let envelope = seal(&sender, &recipient, &pattern(seg * 3 + 100), Some(seg));
    for cut in [1, TAG_LEN, 100 + TAG_LEN, seg + TAG_LEN + 5] {
        let short = &envelope[..envelope.len() - cut];
        assert!(open(&sender, &recipient, short).is_err(), "cut {cut}");
    }
}

#[test]
fn appended_or_duplicated_segment_is_rejected() {
    let (sender, recipient) = (party(), party());
    let seg = 512;
    let envelope = seal(&sender, &recipient, &pattern(seg * 2), Some(seg));
    let (hdr, segs) = segments(&envelope, seg);
    // Duplicate the last segment after itself.
    let mut dup = segs.clone();
    dup.push(segs.last().unwrap().clone());
    assert!(open(&sender, &recipient, &rebuild(&envelope, hdr, &dup)).is_err());
    // Any trailing garbage.
    let mut extended = envelope.clone();
    extended.extend_from_slice(&[0u8; 3]);
    assert!(open(&sender, &recipient, &extended).is_err());
}

#[test]
fn flipped_byte_in_any_segment_is_rejected() {
    let (sender, recipient) = (party(), party());
    let seg = 256;
    let envelope = seal(&sender, &recipient, &pattern(seg * 3 + 10), Some(seg));
    let hdr = header_len(&envelope);
    for offset in [hdr, hdr + seg + TAG_LEN + 1, envelope.len() - 1] {
        let mut forged = envelope.clone();
        forged[offset] ^= 0x01;
        assert!(
            open(&sender, &recipient, &forged).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn tampered_prelude_geometry_is_rejected_by_the_signature() {
    let (sender, recipient) = (party(), party());
    let seg = 512;
    let envelope = seal(&sender, &recipient, &pattern(seg * 2 + 1), Some(seg));
    // Flip a byte inside the (signed) prelude region.
    let mut forged = envelope.clone();
    let prelude_start = 4 + 1 + 4;
    let idx = (prelude_start..prelude_start + 200)
        .find(|&i| forged[i] == b'3')
        .expect("a '3' digit in the prelude JSON");
    forged[idx] = b'4';
    assert!(open(&sender, &recipient, &forged).is_err());
}

// ============================================================================
// Declared-length discipline on the encrypt side
// ============================================================================

#[test]
fn encrypt_rejects_reader_shorter_than_declared() {
    let (sender, recipient) = (party(), party());
    let data = pattern(1000);
    let mut out = Vec::new();
    let res = encrypt_stream(
        SENDER,
        &sender.keys,
        &[EncryptionRecipient {
            identity: RECIPIENT,
            bundle: &recipient.bundle,
        }],
        1500,
        &mut Cursor::new(&data),
        &mut out,
        Some(300),
        None,
        &mut rand::rng(),
    );
    assert!(res.is_err());
}

#[test]
fn encrypt_rejects_reader_longer_than_declared() {
    let (sender, recipient) = (party(), party());
    let data = pattern(1000);
    let mut out = Vec::new();
    let res = encrypt_stream(
        SENDER,
        &sender.keys,
        &[EncryptionRecipient {
            identity: RECIPIENT,
            bundle: &recipient.bundle,
        }],
        900,
        &mut Cursor::new(&data),
        &mut out,
        Some(300),
        None,
        &mut rand::rng(),
    );
    assert!(res.is_err());
}

#[test]
fn layout_rejects_inconsistent_prelude_values() {
    // count 0
    assert!(SegmentLayout::from_cipher_info(0, 16, 16).is_err());
    // last segment smaller than a tag
    assert!(SegmentLayout::from_cipher_info(1, 15, 15).is_err());
    // single segment with trailing bytes
    assert!(SegmentLayout::from_cipher_info(1, 16, 32).is_err());
    // not a whole number of full segments
    assert!(SegmentLayout::from_cipher_info(3, 20, 20 + 65).is_err());
    // last larger than a full segment
    assert!(SegmentLayout::from_cipher_info(2, 100, 100 + 50).is_err());
    // consistent
    let ok = SegmentLayout::from_cipher_info(3, 20, 20 + 2 * (48 + 16)).unwrap();
    assert_eq!(ok.segment_size, 48);
}

// ============================================================================
// Files: the intended use, through real file handles
// ============================================================================

#[test]
fn file_round_trip_with_bounded_buffers() {
    let (sender, recipient) = (party(), party());
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("weights.bin");
    let enc = dir.path().join("weights.bin.syc");
    let dst = dir.path().join("weights.out");

    // 8 MiB + 123 bytes: nine segments at the default size.
    let plaintext = pattern(8 * 1024 * 1024 + 123);
    std::fs::write(&src, &plaintext).unwrap();

    let len = std::fs::metadata(&src).unwrap().len();
    let mut reader = std::io::BufReader::new(std::fs::File::open(&src).unwrap());
    let mut writer = std::io::BufWriter::new(std::fs::File::create(&enc).unwrap());
    encrypt_stream(
        SENDER,
        &sender.keys,
        &[EncryptionRecipient {
            identity: RECIPIENT,
            bundle: &recipient.bundle,
        }],
        len,
        &mut reader,
        &mut writer,
        None,
        Some("weights.bin"),
        &mut rand::rng(),
    )
    .unwrap();
    writer.flush().unwrap();
    drop(writer);

    let mut reader = std::io::BufReader::new(std::fs::File::open(&enc).unwrap());
    let mut writer = std::io::BufWriter::new(std::fs::File::create(&dst).unwrap());
    let written = decrypt_stream(
        RECIPIENT,
        &recipient.keys,
        &sender.bundle,
        &mut reader,
        &mut writer,
    )
    .unwrap();
    writer.flush().unwrap();
    drop(writer);

    assert_eq!(written, len);
    assert_eq!(std::fs::read(&dst).unwrap(), plaintext);
    let enc_len = std::fs::metadata(&enc).unwrap().len();
    assert_eq!(
        enc_len,
        header_len(&std::fs::read(&enc).unwrap()) as u64 + len + 9 * TAG_LEN as u64
    );
}
