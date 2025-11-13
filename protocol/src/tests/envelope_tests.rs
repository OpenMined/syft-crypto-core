use super::*;
use serde_json::Map;

#[test]
fn canonicalizes_object_key_order() {
    let mut map = Map::new();
    map.insert("b".to_string(), Value::Number(2.into()));
    map.insert("a".to_string(), Value::Number(1.into()));
    let bytes = to_jcs_bytes(&Value::Object(map)).expect("canonical json");
    assert_eq!(bytes, br#"{"a":1,"b":2}"#);
}

#[test]
fn detects_non_canonical_input() {
    let json = br#"{"b":2,"a":1}"#;
    let err = from_jcs_bytes::<Value>(json).expect_err("should reject non-canonical");
    assert!(err.to_string().contains("canonical"));
}

#[test]
fn round_trips_complex_value() {
    let value = json!({
        "array": [true, false, null, "hi"],
        "nested": {"z": 3, "y": [1, 2, 3]},
    });
    let bytes = to_jcs_bytes(&value).expect("serialize");
    let decoded: Value = from_jcs_bytes(&bytes).expect("deserialize");
    assert_eq!(decoded, value);
}

#[test]
fn envelope_builds_and_parses() {
    let ciphertext = b"STUB-CIPHERTEXT";
    let envelope = build_stub_envelope(
        "alice@example.org",
        &[String::from("bob@example.org")],
        ciphertext,
        None,
    )
    .expect("envelope build");
    assert!(envelope.starts_with(MAGIC));
    let parsed = parse_envelope(&envelope).expect("parse");
    assert_eq!(parsed.prelude.sender.identity, "alice@example.org");
    assert_eq!(parsed.ciphertext, ciphertext);
    verify_stub_signature(&parsed, false).expect("signature verify");
}

#[test]
fn align_to_block_rounds_up() {
    assert_eq!(align_to_block(1, 4096).unwrap(), 4096);
    assert_eq!(align_to_block(4096, 4096).unwrap(), 4096);
    assert_eq!(align_to_block(4097, 4096).unwrap(), 8192);
}

#[test]
fn align_to_block_detects_overflow() {
    let result = align_to_block(usize::MAX, 2);
    assert!(result.is_err());
}

#[test]
fn parse_rejects_oversized_prelude() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.push(CURRENT_VERSION);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());

    let err = parse_envelope(&bytes).expect_err("should reject oversized prelude");
    assert!(err.to_string().contains("prelude too large"));
}

#[test]
fn parse_rejects_invalid_signature_length() {
    let ciphertext = b"payload";
    let envelope = build_stub_envelope("alice@example.org", &[], ciphertext, None)
        .expect("build envelope");
    let mut tampered = envelope.clone();

    let mut cursor = MAGIC.len() + 1;
    let prelude_len =
        u32::from_le_bytes(tampered[cursor..cursor + 4].try_into().expect("len slice")) as usize;
    cursor += 4;
    let padded_len = align_to_block(prelude_len, PRELUDE_PAD).expect("alignment");
    cursor += padded_len;

    tampered[cursor..cursor + 2].copy_from_slice(&10u16.to_le_bytes());

    let err = parse_envelope(&tampered).expect_err("should reject invalid signature len");
    assert!(err.to_string().contains("invalid signature length"));
}

#[test]
fn parse_rejects_ciphertext_length_mismatch() {
    let ciphertext = b"ciphertext";
    let mut envelope = build_stub_envelope("alice@example.org", &[], ciphertext, None)
        .expect("build envelope");
    envelope.pop().expect("non-empty envelope");

    let err = parse_envelope(&envelope).expect_err("should reject ciphertext mismatch");
    assert!(err.to_string().contains("ciphertext length mismatch"));
}
