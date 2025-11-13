use syft_crypto_protocol::{
    SyftRecoveryKey, decrypt_message, encrypt_message, encryption::EncryptionRecipient,
    envelope::parse_envelope,
};

#[test]
fn encrypt_decrypt_round_trip() {
    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender keys");
    let recipient_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient keys");
    let recipient_bundle = recipient_keys
        .to_public_bundle(&mut rand::rng())
        .expect("bundle");

    let plaintext = b"secret message from alice".to_vec();

    let envelope = encrypt_message(
        "alice@example.org",
        &sender_keys,
        &[EncryptionRecipient {
            identity: "bob@example.org",
            bundle: &recipient_bundle,
        }],
        &plaintext,
        Some("note.txt"),
        &mut rand::rng(),
    )
    .expect("envelope");

    let parsed = parse_envelope(&envelope).expect("parse");

    let decrypted = decrypt_message(
        "bob@example.org",
        &recipient_keys,
        &sender_keys
            .to_public_bundle(&mut rand::rng())
            .expect("sender bundle"),
        &parsed,
    )
    .expect("decrypt");

    assert_eq!(decrypted, plaintext);
}
