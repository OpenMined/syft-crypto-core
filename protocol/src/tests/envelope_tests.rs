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
    assert_eq!(align_to_block(1, 4096), 4096);
    assert_eq!(align_to_block(4096, 4096), 4096);
    assert_eq!(align_to_block(4097, 4096), 8192);
}
