//! Public API tests for RecoveryKey
//!
//! These tests validate the user-facing RecoveryKey functionality.
//! Internal implementation tests remain in src/keys.rs.

use syft_crypto_protocol::{RecoveryError, RecoveryKey};

#[test]
fn test_recovery_key_generation() {
    let key1 = RecoveryKey::generate();
    let key2 = RecoveryKey::generate();

    println!("\n=== Recovery Key Generation ===");
    println!("Key 1: {}", key1.to_hex_string());
    println!("Key 2: {}", key2.to_hex_string());
    println!("Keys are different: {}", key1 != key2);

    // Different keys should be different
    assert_ne!(key1, key2);
}

#[test]
fn test_recovery_key_hex_roundtrip() {
    let key = RecoveryKey::generate();
    let hex = key.to_hex_string();
    let restored = RecoveryKey::from_hex_string(&hex).unwrap();

    println!("\n=== Hex Roundtrip Test ===");
    println!("Original key:  {:?}", key);
    println!("Hex format:    {}", hex);
    println!("Restored key:  {:?}", restored);
    println!("Match: {}", key == restored);

    assert_eq!(key, restored);
}

#[test]
fn test_recovery_key_hex_format() {
    let key = RecoveryKey::generate();
    let hex = key.to_hex_string();

    println!("\n=== Hex Format Test ===");
    println!("Full hex:      {}", hex);
    println!("Length:        {} (expected 79)", hex.len());
    println!("Dash count:    {} (expected 15)", hex.matches('-').count());
    println!("First 20 chars: {}", &hex[..20]);
    println!("Last 20 chars:  {}", &hex[hex.len() - 20..]);

    // Should be 79 characters: 64 hex + 15 dashes
    assert_eq!(hex.len(), 79);

    // Should have 15 dashes
    assert_eq!(hex.matches('-').count(), 15);

    // Should be parseable
    assert!(RecoveryKey::from_hex_string(&hex).is_ok());
}

#[test]
fn test_recovery_key_hex_with_dashes() {
    let hex_with_dashes =
        "a3f5-e8c9-1234-5678-9abc-def0-1234-5678-9abc-def0-1234-5678-9abc-def0-1234-5678";
    let key = RecoveryKey::from_hex_string(hex_with_dashes).unwrap();

    println!("\n=== Parsing Hex With Dashes ===");
    println!("Input:         {}", hex_with_dashes);
    println!("Parsed key:    {:?}", key);
    println!("Reformatted:   {}", key.to_hex_string());

    // Roundtrip should work
    let restored = RecoveryKey::from_hex_string(&key.to_hex_string()).unwrap();
    assert_eq!(key, restored);
}

#[test]
fn test_recovery_key_hex_without_dashes() {
    let hex_no_dashes = "a3f5e8c912345678 9abcdef012345678 9abcdef012345678 9abcdef012345678";
    let key = RecoveryKey::from_hex_string(hex_no_dashes).unwrap();

    println!("\n=== Parsing Hex Without Dashes (with spaces) ===");
    println!("Input:         {}", hex_no_dashes);
    println!("Parsed key:    {:?}", key);

    // Should work even with spaces (they get filtered out)
    let hex_string = key.to_hex_string();
    println!("Reformatted:   {}", hex_string);
    println!("Output length: {} (has dashes)", hex_string.len());

    assert_eq!(hex_string.len(), 79); // Formatted with dashes
}

#[test]
fn test_recovery_key_invalid_length() {
    let too_short = "a3f5-e8c9";
    let result = RecoveryKey::from_hex_string(too_short);

    println!("\n=== Invalid Length Test ===");
    println!("Input:  '{}'", too_short);
    println!("Error:  {:?}", result);

    assert!(result.is_err());
    match result.unwrap_err() {
        RecoveryError::InvalidLength { expected, actual } => {
            println!("Expected length: {}", expected);
            println!("Actual length:   {}", actual);
            assert_eq!(expected, 64);
            assert_eq!(actual, 8);
        }
        _ => panic!("Expected InvalidLength error"),
    }
}

#[test]
fn test_recovery_key_invalid_hex() {
    // Test strings with non-hex characters that get filtered out
    // This results in InvalidLength because the remaining valid hex chars are too few
    let invalid = "a3f5e8c9123456789abcdef012345678g"; // 'g' is not valid hex, filtered out
    let result = RecoveryKey::from_hex_string(invalid);

    println!("\n=== Invalid Hex Characters Test ===");
    println!("Input:  '{}'", invalid);
    println!("Error:  {:?}", result);
    println!("Note: Non-hex chars like 'g' get filtered out");

    assert!(result.is_err());
    match result.unwrap_err() {
        RecoveryError::InvalidLength { expected, actual } => {
            println!("Expected: {} hex chars", expected);
            println!("Got:      {} hex chars (after filtering)", actual);
            assert_eq!(expected, 64);
            assert!(actual < 64); // Some chars were filtered out
        }
        _ => panic!("Expected InvalidLength error"),
    }
}

#[test]
fn test_recovery_key_clone() {
    let key1 = RecoveryKey::generate();
    let key2 = key1.clone();

    println!("\n=== Clone Test ===");
    println!("Original: {}", key1.to_hex_string());
    println!("Cloned:   {}", key2.to_hex_string());
    println!("Equal:    {}", key1 == key2);

    assert_eq!(key1, key2);
}
