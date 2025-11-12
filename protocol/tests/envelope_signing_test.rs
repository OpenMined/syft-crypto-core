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
