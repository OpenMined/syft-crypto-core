use syft_crypto_protocol::SyftRecoveryKey;

#[test]
fn test_build_envelope_and_verify_signature() {
    // Generate sender keys
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate recipient keys
    let recipient_recovery_key = SyftRecoveryKey::generate();
    let recipient_sk = recipient_recovery_key.derive_keys().unwrap();
    let recipient_pk_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Build envelope
    let sender_identity = "alice@example.com";
    let recipients = vec![("bob@example.com".to_string(), recipient_pk_bundle.clone())];
    let ciphertext = b"encrypted data here";

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        sender_identity,
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        ciphertext,
        Some("test.txt"),
        &mut rand::rng(),
    )
    .unwrap();

    // Parse the envelope
    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Verify signature
    let result = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        sender_sk.identity().identity_key(),
    );

    assert!(result.is_ok(), "Signature verification should succeed");
}

#[test]
fn test_envelope_contains_real_fingerprints() {
    // Generate sender keys
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate recipient keys
    let recipient_recovery_key = SyftRecoveryKey::generate();
    let recipient_sk = recipient_recovery_key.derive_keys().unwrap();
    let recipient_pk_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let sender_identity = "alice@example.com";
    let recipients = vec![("bob@example.com".to_string(), recipient_pk_bundle.clone())];
    let ciphertext = b"test data";

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        sender_identity,
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        ciphertext,
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Check sender fingerprint is real (not stub)
    assert!(
        !parsed.prelude.sender.ik_fingerprint.starts_with("stub-"),
        "Sender fingerprint should be real, not stub"
    );
    assert_eq!(
        parsed.prelude.sender.ik_fingerprint.len(),
        64,
        "Should be SHA-256 fingerprint (64 hex chars)"
    );

    // Check recipient fingerprints are real (not stub)
    let recipient_info = &parsed.prelude.recipients[0];
    let spk_fp = recipient_info.spk_fingerprint.as_ref().unwrap();
    let pqspk_fp = recipient_info.pqspk_fingerprint.as_ref().unwrap();

    assert!(
        !spk_fp.starts_with("stub-"),
        "SPK fingerprint should be real"
    );
    assert_eq!(spk_fp.len(), 64, "Should be SHA-256 fingerprint");

    assert!(
        !pqspk_fp.starts_with("stub-"),
        "PQSPK fingerprint should be real"
    );
    assert_eq!(pqspk_fp.len(), 64, "Should be SHA-256 fingerprint");
}

#[test]
fn test_signature_verification_fails_with_wrong_key() {
    // Generate sender keys
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let sender_identity = "alice@example.com";
    let recipients = vec![];
    let ciphertext = b"test data";

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        sender_identity,
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        ciphertext,
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Generate different key for verification (wrong key)
    let wrong_recovery_key = SyftRecoveryKey::generate();
    let wrong_sk = wrong_recovery_key.derive_keys().unwrap();

    // Try to verify with wrong key
    let result = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        wrong_sk.identity().identity_key(),
    );

    assert!(
        result.is_err(),
        "Signature verification should fail with wrong key"
    );
}

#[test]
fn test_signature_verification_checks_fingerprint() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"fingerprint test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let mut parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();
    parsed.prelude.sender.ik_fingerprint = "0".repeat(64);

    let err = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        sender_sk.identity().identity_key(),
    )
    .expect_err("fingerprint mismatch should fail");

    assert!(
        err.to_string().contains("fingerprint"),
        "Error should mention fingerprint mismatch"
    );
}

#[test]
fn test_envelope_with_multiple_recipients() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Generate 3 recipients
    let recipient1_recovery_key = SyftRecoveryKey::generate();
    let recipient1_sk = recipient1_recovery_key.derive_keys().unwrap();
    let recipient1_pk_bundle = recipient1_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient2_recovery_key = SyftRecoveryKey::generate();
    let recipient2_sk = recipient2_recovery_key.derive_keys().unwrap();
    let recipient2_pk_bundle = recipient2_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient3_recovery_key = SyftRecoveryKey::generate();
    let recipient3_sk = recipient3_recovery_key.derive_keys().unwrap();
    let recipient3_pk_bundle = recipient3_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipients = vec![
        ("bob@example.com".to_string(), recipient1_pk_bundle),
        ("charlie@example.com".to_string(), recipient2_pk_bundle),
        ("dave@example.com".to_string(), recipient3_pk_bundle),
    ];

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        b"multi-recipient test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Verify we have 3 recipients
    assert_eq!(
        parsed.prelude.recipients.len(),
        3,
        "Should have 3 recipients"
    );
    assert_eq!(parsed.prelude.wrappings.len(), 3, "Should have 3 wrappings");

    // Verify signature
    let result = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        sender_sk.identity().identity_key(),
    );
    assert!(result.is_ok(), "Signature should be valid");
}

#[test]
fn test_envelope_with_filename_hint() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test data",
        Some("secret-document.pdf"),
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    assert!(
        parsed.prelude.public_meta.is_some(),
        "Should have public metadata"
    );
    assert_eq!(
        parsed.prelude.public_meta.as_ref().unwrap().filename_hint,
        Some("secret-document.pdf".to_string()),
        "Filename hint should match"
    );
}

#[test]
fn test_envelope_ciphertext_preserved() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let original_ciphertext = b"this is the encrypted payload";

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        original_ciphertext,
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    assert_eq!(
        parsed.ciphertext, original_ciphertext,
        "Ciphertext should be preserved exactly"
    );
}

#[test]
fn test_envelope_format_has_syc_magic() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    // Check magic bytes
    assert_eq!(
        &envelope_bytes[0..4],
        b"SYC1",
        "Should start with SYC1 magic"
    );

    // Check version
    assert_eq!(envelope_bytes[4], 1, "Should have version 1");
}

#[test]
fn test_deterministic_fingerprints_in_envelope() {
    // Generate keys
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Build two envelopes with same keys
    let envelope1 = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let envelope2 = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed1 = syft_crypto_protocol::envelope::parse_envelope(&envelope1).unwrap();
    let parsed2 = syft_crypto_protocol::envelope::parse_envelope(&envelope2).unwrap();

    // Fingerprints should be the same (deterministic)
    assert_eq!(
        parsed1.prelude.sender.ik_fingerprint, parsed2.prelude.sender.ik_fingerprint,
        "Sender fingerprint should be deterministic"
    );

    // But signatures should be different (randomized)
    assert_ne!(
        parsed1.signature, parsed2.signature,
        "Signatures should differ due to randomization"
    );

    // Both should verify correctly
    assert!(
        syft_crypto_protocol::envelope::verify_signature(
            &parsed1,
            sender_sk.identity().identity_key()
        )
        .is_ok()
    );
    assert!(
        syft_crypto_protocol::envelope::verify_signature(
            &parsed2,
            sender_sk.identity().identity_key()
        )
        .is_ok()
    );
}

#[test]
fn test_build_envelope_empty_sender_identity() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let result = syft_crypto_protocol::envelope::build_envelope(
        "", // Empty sender identity
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test data",
        None,
        &mut rand::rng(),
    );

    assert!(result.is_err(), "Should reject empty sender_identity");
    assert!(
        result.unwrap_err().to_string().contains("sender_identity"),
        "Error should mention sender_identity"
    );
}

#[test]
fn test_build_envelope_empty_ciphertext() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let result = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"", // Empty ciphertext
        None,
        &mut rand::rng(),
    );

    assert!(result.is_err(), "Should reject empty ciphertext");
    assert!(
        result.unwrap_err().to_string().contains("ciphertext"),
        "Error should mention ciphertext"
    );
}

#[test]
fn test_build_envelope_mismatched_keys() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Create a different key pair (mismatched)
    let wrong_recovery_key = SyftRecoveryKey::generate();
    let wrong_sk = wrong_recovery_key.derive_keys().unwrap();

    let result = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        wrong_sk.identity(), // Wrong identity key pair
        &sender_pk_bundle,   // Correct public bundle
        &[],
        b"test data",
        None,
        &mut rand::rng(),
    );

    assert!(result.is_err(), "Should reject mismatched keys");
    assert!(
        result.unwrap_err().to_string().contains("does not match"),
        "Error should mention key mismatch"
    );
}

#[test]
fn test_build_envelope_zero_recipients_allowed() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let result = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[], // Zero recipients - should be allowed
        b"test data",
        None,
        &mut rand::rng(),
    );

    assert!(
        result.is_ok(),
        "Should allow zero recipients (self-encryption/broadcast)"
    );

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&result.unwrap()).unwrap();
    assert_eq!(
        parsed.prelude.recipients.len(),
        0,
        "Should have zero recipients"
    );
}

#[test]
fn test_build_prelude_single_recipient() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient_recovery_key = SyftRecoveryKey::generate();
    let recipient_sk = recipient_recovery_key.derive_keys().unwrap();
    let recipient_pk_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipients = vec![("bob@example.com".to_string(), recipient_pk_bundle)];

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    assert_eq!(parsed.prelude.recipients.len(), 1);
    assert_eq!(parsed.prelude.wrappings.len(), 1);
    assert_eq!(
        parsed.prelude.recipients[0].identity.as_deref(),
        Some("bob@example.com")
    );
}

#[test]
fn test_build_prelude_many_recipients() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Create 10 recipients
    let mut recipients = Vec::new();
    for i in 0..10 {
        let recovery_key = SyftRecoveryKey::generate();
        let sk = recovery_key.derive_keys().unwrap();
        let pk_bundle = sk.to_public_bundle(&mut rand::rng()).unwrap();
        recipients.push((format!("user{}@example.com", i), pk_bundle));
    }

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    assert_eq!(parsed.prelude.recipients.len(), 10);
    assert_eq!(parsed.prelude.wrappings.len(), 10);

    // Verify all identities are present
    for i in 0..10 {
        assert_eq!(
            parsed.prelude.recipients[i].identity.as_deref(),
            Some(format!("user{}@example.com", i).as_str())
        );
    }
}

#[test]
fn test_build_prelude_recipient_set_fingerprint_order() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient1_recovery_key = SyftRecoveryKey::generate();
    let recipient1_sk = recipient1_recovery_key.derive_keys().unwrap();
    let recipient1_pk_bundle = recipient1_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient2_recovery_key = SyftRecoveryKey::generate();
    let recipient2_sk = recipient2_recovery_key.derive_keys().unwrap();
    let recipient2_pk_bundle = recipient2_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Build with order: alice, bob
    let recipients_order1 = vec![
        (
            "alice@example.com".to_string(),
            recipient1_pk_bundle.clone(),
        ),
        ("bob@example.com".to_string(), recipient2_pk_bundle.clone()),
    ];

    let envelope1 = syft_crypto_protocol::envelope::build_envelope(
        "sender@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients_order1,
        b"test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    // Build with order: bob, alice
    let recipients_order2 = vec![
        ("bob@example.com".to_string(), recipient2_pk_bundle),
        ("alice@example.com".to_string(), recipient1_pk_bundle),
    ];

    let envelope2 = syft_crypto_protocol::envelope::build_envelope(
        "sender@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients_order2,
        b"test",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed1 = syft_crypto_protocol::envelope::parse_envelope(&envelope1).unwrap();
    let parsed2 = syft_crypto_protocol::envelope::parse_envelope(&envelope2).unwrap();

    // Recipient set fingerprint should be SAME because fingerprints are sorted
    // (order-independent by design to allow set-based comparison)
    assert_eq!(
        parsed1.prelude.recipient_set_fpr, parsed2.prelude.recipient_set_fpr,
        "Same recipient set should produce same fingerprint regardless of order"
    );

    // But recipient lists themselves preserve order
    assert_eq!(
        parsed1.prelude.recipients[0].identity.as_deref(),
        Some("alice@example.com")
    );
    assert_eq!(
        parsed1.prelude.recipients[1].identity.as_deref(),
        Some("bob@example.com")
    );
    assert_eq!(
        parsed2.prelude.recipients[0].identity.as_deref(),
        Some("bob@example.com")
    );
    assert_eq!(
        parsed2.prelude.recipients[1].identity.as_deref(),
        Some("alice@example.com")
    );
}

#[test]
fn test_build_prelude_null_separator_prevents_collision() {
    use syft_crypto_protocol::compute_key_fingerprint;

    // Demonstrate that null separator prevents collision
    // Example: ["a,b", "c"] vs ["a", "b,c"] would collide with comma separator
    // but won't collide with null separator

    let fps_scenario1 = ["abc", "def"];
    let fps_scenario2 = ["ab", "cdef"];

    // With null separator (what we use)
    let fpr1_null = compute_key_fingerprint(fps_scenario1.join("\0").as_bytes());
    let fpr2_null = compute_key_fingerprint(fps_scenario2.join("\0").as_bytes());

    assert_ne!(
        fpr1_null, fpr2_null,
        "Null separator should prevent collision"
    );

    // With comma separator
    let fps_scenario3 = ["a,b", "c"];
    let fps_scenario4 = ["a", "b,c"];

    let fpr3_comma = compute_key_fingerprint(fps_scenario3.join(",").as_bytes());
    let fpr4_comma = compute_key_fingerprint(fps_scenario4.join(",").as_bytes());

    // This would be the same (collision!) if we used comma
    assert_eq!(
        fpr3_comma, fpr4_comma,
        "Comma separator would allow collision (security issue)"
    );
}

#[test]
fn test_envelope_roundtrip_preserves_all_fields() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient1_recovery_key = SyftRecoveryKey::generate();
    let recipient1_sk = recipient1_recovery_key.derive_keys().unwrap();
    let recipient1_pk_bundle = recipient1_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient2_recovery_key = SyftRecoveryKey::generate();
    let recipient2_sk = recipient2_recovery_key.derive_keys().unwrap();
    let recipient2_pk_bundle = recipient2_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let sender_identity = "alice@example.com";
    let recipients = vec![
        ("bob@example.com".to_string(), recipient1_pk_bundle),
        ("charlie@example.com".to_string(), recipient2_pk_bundle),
    ];
    let ciphertext = b"secret message content";
    let filename_hint = Some("confidential.pdf");

    // Build envelope
    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        sender_identity,
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        ciphertext,
        filename_hint,
        &mut rand::rng(),
    )
    .unwrap();

    // Parse envelope
    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Verify all fields preserved
    assert_eq!(parsed.prelude.sender.identity, sender_identity);
    assert_eq!(parsed.prelude.recipients.len(), 2);
    assert_eq!(
        parsed.prelude.recipients[0].identity.as_deref(),
        Some("bob@example.com")
    );
    assert_eq!(
        parsed.prelude.recipients[1].identity.as_deref(),
        Some("charlie@example.com")
    );
    assert_eq!(parsed.ciphertext, ciphertext);
    assert_eq!(
        parsed.prelude.public_meta.as_ref().unwrap().filename_hint,
        Some("confidential.pdf".to_string())
    );

    // Verify signature
    let verify_result = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        sender_sk.identity().identity_key(),
    );
    assert!(verify_result.is_ok(), "Signature should verify correctly");
}

#[test]
fn test_envelope_with_large_prelude() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Create 50 recipients to make a large prelude
    let mut recipients = Vec::new();
    for i in 0..50 {
        let recovery_key = SyftRecoveryKey::generate();
        let sk = recovery_key.derive_keys().unwrap();
        let pk_bundle = sk.to_public_bundle(&mut rand::rng()).unwrap();
        recipients.push((format!("user{}@example.com", i), pk_bundle));
    }

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    assert_eq!(parsed.prelude.recipients.len(), 50);
    assert_eq!(parsed.prelude.wrappings.len(), 50);

    // Verify signature works with large prelude
    let verify_result = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        sender_sk.identity().identity_key(),
    );
    assert!(verify_result.is_ok());
}

#[test]
fn test_envelope_with_unicode_identities() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient_recovery_key = SyftRecoveryKey::generate();
    let recipient_sk = recipient_recovery_key.derive_keys().unwrap();
    let recipient_pk_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Use Unicode characters in identities
    let sender_identity = "alice@例え.jp"; // Japanese characters
    let recipients = vec![(
        "bob@مثال.com".to_string(), // Arabic characters
        recipient_pk_bundle,
    )];

    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        sender_identity,
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    assert_eq!(parsed.prelude.sender.identity, sender_identity);
    assert_eq!(
        parsed.prelude.recipients[0].identity.as_deref(),
        Some("bob@مثال.com")
    );

    // Verify signature with Unicode identities
    let verify_result = syft_crypto_protocol::envelope::verify_signature(
        &parsed,
        sender_sk.identity().identity_key(),
    );
    assert!(verify_result.is_ok());
}

#[test]
fn test_envelope_signature_covers_full_prelude() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipient_recovery_key = SyftRecoveryKey::generate();
    let recipient_sk = recipient_recovery_key.derive_keys().unwrap();
    let recipient_pk_bundle = recipient_sk.to_public_bundle(&mut rand::rng()).unwrap();

    let recipients = vec![("bob@example.com".to_string(), recipient_pk_bundle)];

    // Build envelope with specific data
    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &recipients,
        b"original ciphertext",
        Some("original.txt"),
        &mut rand::rng(),
    )
    .unwrap();

    let mut parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Signature should verify initially
    assert!(
        syft_crypto_protocol::envelope::verify_signature(
            &parsed,
            sender_sk.identity().identity_key()
        )
        .is_ok()
    );

    // Tamper with sender identity in prelude
    parsed.prelude.sender.identity = "eve@example.com".to_string();

    // Re-serialize the tampered prelude
    let tampered_prelude_bytes =
        syft_crypto_protocol::envelope::to_jcs_bytes(&parsed.prelude).unwrap();

    // Update the parsed envelope with tampered prelude bytes
    let mut tampered_parsed = parsed;
    tampered_parsed.prelude_bytes = tampered_prelude_bytes;

    // Signature should now fail (proves signature covers sender identity)
    let result = syft_crypto_protocol::envelope::verify_signature(
        &tampered_parsed,
        sender_sk.identity().identity_key(),
    );
    assert!(
        result.is_err(),
        "Signature should fail after tampering with prelude"
    );
}

#[test]
fn test_envelope_padding_not_signed() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Build envelope
    let envelope_bytes = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed = syft_crypto_protocol::envelope::parse_envelope(&envelope_bytes).unwrap();

    // Signature should verify
    assert!(
        syft_crypto_protocol::envelope::verify_signature(
            &parsed,
            sender_sk.identity().identity_key()
        )
        .is_ok()
    );

    // The padding comes after prelude but before signature
    // This test demonstrates that padding can be modified without breaking signature
    // (because only prelude_bytes are signed, not the raw envelope bytes)

    // We verify that the signature only covers prelude metadata (plus domain separator),
    // not the ciphertext or padding.
    let mut message = Vec::new();
    message.extend_from_slice(b"SYC1-PRELUDE");
    message.push(syft_crypto_protocol::envelope::CURRENT_VERSION);
    message.extend_from_slice(&parsed.prelude_bytes);

    assert!(
        sender_sk
            .identity()
            .identity_key()
            .public_key()
            .verify_signature(&message, &parsed.signature),
        "Signature should verify when domain-separated prelude is provided"
    );

    assert!(
        !sender_sk
            .identity()
            .identity_key()
            .public_key()
            .verify_signature(&parsed.prelude_bytes, &parsed.signature),
        "Raw prelude should fail verification without domain separator"
    );
}

#[test]
fn test_envelope_timestamp_changes_signature() {
    let sender_recovery_key = SyftRecoveryKey::generate();
    let sender_sk = sender_recovery_key.derive_keys().unwrap();
    let sender_pk_bundle = sender_sk.to_public_bundle(&mut rand::rng()).unwrap();

    // Build two envelopes at different times (even with same content)
    let envelope1 = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    // Small delay to ensure different timestamp (1 second for Unix timestamp granularity)
    std::thread::sleep(std::time::Duration::from_secs(1));

    let envelope2 = syft_crypto_protocol::envelope::build_envelope(
        "alice@example.com",
        sender_sk.identity(),
        &sender_pk_bundle,
        &[],
        b"test data",
        None,
        &mut rand::rng(),
    )
    .unwrap();

    let parsed1 = syft_crypto_protocol::envelope::parse_envelope(&envelope1).unwrap();
    let parsed2 = syft_crypto_protocol::envelope::parse_envelope(&envelope2).unwrap();

    // Timestamps should be different
    assert_ne!(
        parsed1.prelude.created_at, parsed2.prelude.created_at,
        "Timestamps should differ"
    );

    // Signatures should be different (because timestamp is part of prelude)
    assert_ne!(
        parsed1.signature, parsed2.signature,
        "Different timestamps should produce different signatures"
    );

    // Both should verify correctly with same key
    assert!(
        syft_crypto_protocol::envelope::verify_signature(
            &parsed1,
            sender_sk.identity().identity_key()
        )
        .is_ok()
    );
    assert!(
        syft_crypto_protocol::envelope::verify_signature(
            &parsed2,
            sender_sk.identity().identity_key()
        )
        .is_ok()
    );
}
