extern crate chacha20poly1305;
extern crate didcomm_rs;

use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    Error,
    Message,
};
use rand_core::OsRng;
use serde_json::Value;
use utilities::{get_keypair_set, KeyPairSet};

#[test]
fn can_create_flat_jwe_json() -> Result<(), Error> {
    let KeyPairSet {
        alice_private,
        bobs_public,
        ..
    } = get_keypair_set();
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let message = Message::new()
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
        .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
        .kid(&hex::encode(sign_keypair.public.to_bytes()));

    let jwe_string = message.seal_signed(
        &alice_private,
        Some(vec![Some(&bobs_public)]),
        SignatureAlgorithm::EdDsa,
        &sign_keypair.to_bytes(),
    )?;

    let jwe_object: Value = serde_json::from_str(&jwe_string)?;

    assert!(
        jwe_object["recipients"].as_array().is_none(),
        "recipients present in JWE"
    );
    assert!(
        jwe_object["encrypted_key"].as_str().is_some(),
        "no recipients fields in JWE top level"
    );
    assert!(
        jwe_object["header"].as_object().is_some(),
        "no recipients fields in JWE top level"
    );

    Ok(())
}

#[test]
fn can_receive_flat_jwe_json() -> Result<(), Error> {
    let KeyPairSet {
        alice_private,
        alice_public,
        bobs_private,
        bobs_public,
        ..
    } = get_keypair_set();
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    let body = r#"{"foo":"bar"}"#;
    let message = Message::new()
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
        .body(body) // packing in some payload
        .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
        .kid(&hex::encode(sign_keypair.public.to_bytes()));

    let jwe_string = message.seal_signed(
        &alice_private,
        Some(vec![Some(&bobs_public)]),
        SignatureAlgorithm::EdDsa,
        &sign_keypair.to_bytes(),
    )?;

    let received = Message::receive(&jwe_string, Some(&bobs_private), Some(&alice_public), None);

    // Assert
    assert!(&received.is_ok());
    let received = received.unwrap();
    let sample_body: Value = serde_json::from_str(body).unwrap();
    let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
    assert_eq!(sample_body.to_string(), received_body.to_string(),);

    Ok(())
}
