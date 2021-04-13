/// Integration tests of full cycles of message lifetime.
///

mod common;

#[cfg(not(feature = "resolve"))]
use {
    common::*,
    k256::elliptic_curve::rand_core::OsRng,
    x25519_dalek::{EphemeralSecret, PublicKey},
    didcomm_rs::crypto::{CryptoAlgorithm, SignatureAlgorithm, Signer},
};

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_raw() {
    // Arrange
    let m = Message::new()
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_")
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"])
        .set_body(sample_dids::TEST_DID_ENCRYPT_1.as_bytes());

    // Act
    let ready_to_send = m.clone().as_raw_json().unwrap();

    // checking if encryption fails on it
    let packed = m.clone().seal(b"anuhcphus");
    assert!(packed.is_err());

    // receiving raw message
    #[cfg(not(feature = "resolve"))]
    let received = Message::receive(&ready_to_send, None, None);
    #[cfg(feature = "resolve")]
    let received = Message::receive(&ready_to_send, b"");

    // Assert
    assert!(&received.is_ok());
    assert_eq!(m, received.unwrap());
}

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_encrypted_xc20p_json_test() {
    // Arrange
    // keys
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = EphemeralSecret::new(OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    // DIDComm related setup
    let ek = alice_secret.diffie_hellman(&bob_public);

    // Message construction
    let message = Message::new() // creating message
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp") // setting from
        .to(&["did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jwe(&CryptoAlgorithm::XC20P) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(r#"#z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW"#); // set kid header

    // Act
    let ready_to_send = message.seal(ek.as_bytes()).unwrap();
    let rk = bob_secret.diffie_hellman(&alice_public); // bob's shared secret calculation
    #[cfg(not(feature = "resolve"))]
    let received = Message::receive(&ready_to_send, Some(rk.as_bytes()), None); // and now we parse received
    #[cfg(feature = "resolve")]
    let received = Message::receive(&ready_to_send, &"6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR".from_base58().unwrap()); // and now we parse received

    // Assert
    assert!(&received.is_ok());
    let received = received.unwrap();
    assert_eq!(sample_dids::TEST_DID_SIGN_1.as_bytes().to_vec(), received.get_body().unwrap().as_ref().to_vec());
}

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_mediated_encrypted_xc20p_json_test() {
    // Arrange
    // keys
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let alice_secret_2 = EphemeralSecret::new(OsRng);
    let alice_public_2 = PublicKey::from(&alice_secret_2);
    let bob_mediator_secret = EphemeralSecret::new(OsRng);
    let bob_mediator_public = PublicKey::from(&bob_mediator_secret);
    let bob_secret = EphemeralSecret::new(OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    // DIDComm related setup
    let ek_to_bob = alice_secret.diffie_hellman(&bob_public);
    let ek_to_mediator = alice_secret_2.diffie_hellman(&bob_mediator_public);

    // Message construction
    let message = Message::new() // creating message
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp") // setting from
        .to(&["did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jwe(&CryptoAlgorithm::XC20P) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(r#"#z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW"#) // set kid header
        .routed_by(ek_to_bob.as_bytes(), "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"); // here we use destination key to bob and `to` header of mediator

    // Act + Assert as we go
    assert!(&message.is_ok());

    // Message envelope to mediator
    let ready_to_send = message
        .unwrap()
        .as_jwe(&CryptoAlgorithm::XC20P) // here this method call is crucial as mediator and end receiver may use different algorithms.
        .seal(ek_to_mediator.as_bytes()); // this would've failed without previous method call.

    assert!(&ready_to_send.is_ok());

    // Received by mediator
    let rk_mediator = bob_mediator_secret.diffie_hellman(&alice_public_2); // key to decrypt mediated message
    #[cfg(not(feature = "resolve"))]
    let received_mediated = Message::receive(&ready_to_send.unwrap(), Some(rk_mediator.as_bytes()), None);
    #[cfg(feature = "resolve")]
    let received_mediated = Message::receive(&ready_to_send.unwrap(), &"ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2".from_base58().unwrap());

    assert!(&received_mediated.is_ok());

    // Received by Bob
    let rk_bob = bob_secret.diffie_hellman(&alice_public); // key to decrypt final message
    #[cfg(not(feature = "resolve"))]
    let received_bob = Message::receive(&String::from_utf8_lossy(&received_mediated.unwrap().get_body().unwrap().as_ref()), Some(rk_bob.as_bytes()), None);
    #[cfg(feature = "resolve")]
    let received_bob = Message::receive(&String::from_utf8_lossy(&received_mediated.unwrap().body), &"HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap());

    assert!(&received_bob.is_ok());
    assert_eq!(received_bob.unwrap().get_body().unwrap().as_ref(), sample_dids::TEST_DID_SIGN_1.as_bytes());
}

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_signed_json_test() {
    // Arrange + Act
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    // Message construction an JWS wrapping
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jws(&SignatureAlgorithm::EdDsa)
        .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes());

    assert!(&message.is_ok());

    // Receiving JWS
    let received = Message::verify(&message.unwrap().as_bytes(), &sign_keypair.public.to_bytes());
    // Assert
    assert!(&received.is_ok());
    assert_eq!(sample_dids::TEST_DID_SIGN_1.as_bytes().to_vec(), received.unwrap().get_body().unwrap().as_ref());
}

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_direct_signed_and_encrypted_xc20p_test() {
    // Arrange
    // keys
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = EphemeralSecret::new(OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    // DIDComm related setup
    let ek = alice_secret.diffie_hellman(&bob_public);

    // Message construction
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jwe(&CryptoAlgorithm::XC20P) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#); // set kid header

    // Act
    // Send
    let ready_to_send = message.seal_signed(
        ek.as_bytes(),
        &sign_keypair.to_bytes(),
        SignatureAlgorithm::EdDsa)
        .unwrap();

    //Receive
    let rk = bob_secret.diffie_hellman(&alice_public); // bob's shared secret calculation
    #[cfg(not(feature = "resolve"))]
    let received = Message::receive(
        &ready_to_send,
        Some(rk.as_bytes()),
        Some(&sign_keypair.public.to_bytes())); // and now we parse received
    #[cfg(feature = "resolve")]
    let received = Message::receive(&ready_to_send, &"HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap());

    // Assert
    assert!(&received.is_ok());
    let received = received.unwrap();
    assert_eq!(sample_dids::TEST_DID_SIGN_1.as_bytes().to_vec(), received.get_body().unwrap().as_ref());
}
