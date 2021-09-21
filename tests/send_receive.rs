/// Integration tests of full cycles of message lifetime.
///

mod common;

use {
    didcomm_rs::{
        crypto::CryptoAlgorithm,
        Jwe,
        Mediated,
        Message,
    },
    utilities::{KeyPairSet, get_keypair_set},
};


#[cfg(not(feature = "resolve"))]
use {
    common::*,
    k256::elliptic_curve::rand_core::OsRng,
    didcomm_rs::crypto::{SignatureAlgorithm, Signer},
    serde_json::Value,
};

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_raw() {
    // Arrange
    let m = Message::new()
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_")
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"])
        .set_body(sample_dids::TEST_DID_ENCRYPT_1);

    // Act
    let ready_to_send = m.clone().as_raw_json().unwrap();

    // checking if encryption fails on it
    let packed = m.clone().seal(b"anuhcphus", None);
    assert!(packed.is_err());


    // receiving raw message
    #[cfg(not(feature = "resolve"))]
    let received = Message::receive(&ready_to_send, &[0; 32], None, None);
    #[cfg(feature = "resolve")]
    let received = Message::receive(&ready_to_send, b"", None, None);

    // Assert
    assert_eq!(m, received.unwrap());
}

#[test]
fn send_receive_mediated_encrypted_xc20p_json_test_new() {
    let KeyPairSet {
        alice_private,
        alice_public,
        bobs_private,
        bobs_public,
        mediators_private,
        mediators_public,
    } = get_keypair_set();
    let sealed = Message::new()
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
        .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
        .routed_by(
            &alice_private,
            "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
            Some(&mediators_public),
            Some(&bobs_public),
        );
    assert!(sealed.is_ok());

    let mediator_received = Message::receive(
        &sealed.unwrap(),
        &mediators_private,
        Some(&alice_public),
        None,
    );
    assert!(mediator_received.is_ok());

    let mediator_received_unwrapped = mediator_received.unwrap().get_body().unwrap();
    let pl_string = String::from_utf8_lossy(mediator_received_unwrapped.as_ref());
    let message_to_forward: Mediated = serde_json::from_str(&pl_string).unwrap();
    let attached_jwe = serde_json::from_slice::<Jwe>(&message_to_forward.payload);
    assert!(attached_jwe.is_ok());
    let str_jwe = serde_json::to_string(&attached_jwe.unwrap());
    assert!(str_jwe.is_ok());

    let bob_received = Message::receive(
        &String::from_utf8_lossy(&message_to_forward.payload),
        &bobs_private,
        Some(&alice_public),
        None,
    );
    assert!(bob_received.is_ok());
}

// #[test]
// #[cfg(not(feature = "resolve"))]
// fn send_receive_mediated_encrypted_xc20p_json_test() {
//     // Arrange
//     // keys
//     let alice_secret = EphemeralSecret::new(OsRng);
//     let alice_public = PublicKey::from(&alice_secret);
//     let alice_secret_2 = EphemeralSecret::new(OsRng);
//     let alice_public_2 = PublicKey::from(&alice_secret_2);
//     let bob_mediator_secret = EphemeralSecret::new(OsRng);
//     let bob_mediator_public = PublicKey::from(&bob_mediator_secret);
//     let bob_secret = EphemeralSecret::new(OsRng);
//     let bob_public = PublicKey::from(&bob_secret);
//     // DIDComm related setup
//     let ek_to_bob = alice_secret.diffie_hellman(&bob_public);
//     let ek_to_mediator = alice_secret_2.diffie_hellman(&bob_mediator_public);

//     // Message construction
//     let sealed = Message::new() // creating message
//         .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp") // setting from
//         .to(&["did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"]) // setting to
//         .set_body(sample_dids::TEST_DID_SIGN_1) // packing in some payload
//         .as_jwe(&CryptoAlgorithm::XC20P, Some(&bob_public.to_bytes())) // set JOSE header for XC20P algorithm
//         .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
//         .add_header_field("another_key".into(), "another_value".into()) // another coustom header
//         .kid(r#"#z6LShs9GGnqk85isEBzzshkuVWrVKsRp24GnDuHk8QWkARMW"#) // set kid header
//         .routed_by(ek_to_bob.as_bytes(), "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf", Some(&bob_mediator_public.to_bytes())); // here we use destination key to bob and `to` header of mediator

//     // Act + Assert as we go
//     assert!(&sealed.is_ok());

//     // Message envelope to mediator
//     let message_object: Message = serde_json::from_str(&message.unwrap()).unwrap();
//     let ready_to_send = message_object
//         .as_jwe(&CryptoAlgorithm::XC20P, Some(&bob_mediator_public.to_bytes())) // here this method call is crucial as mediator and end receiver may use different algorithms.
//         .seal(ek_to_mediator.as_bytes(), Some(&bob_mediator_public.to_bytes())); // this would've failed without previous method call.

//     assert!(&ready_to_send.is_ok());

//     // Received by mediator
//     let rk_mediator = bob_mediator_secret.diffie_hellman(&alice_public_2); // key to decrypt mediated message
//     #[cfg(not(feature = "resolve"))]
//     let received_mediated = Message::receive(&ready_to_send.unwrap(), rk_mediator.as_bytes(), Some(&bob_mediator_public.to_bytes()));
//     #[cfg(feature = "resolve")]
//     let received_mediated = Message::receive(&ready_to_send.unwrap(), &"ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2".from_base58().unwrap());

//     assert!(&received_mediated.is_ok());

//     // Received by Bob
//     let rk_bob = bob_secret.diffie_hellman(&alice_public); // key to decrypt final message
//     #[cfg(not(feature = "resolve"))]
//     let received_bob = Message::receive(&String::from_utf8_lossy(&received_mediated.unwrap().get_body().unwrap().as_ref()), rk_bob.as_bytes(), None);
//     #[cfg(feature = "resolve")]
//     let received_bob = Message::receive(&String::from_utf8_lossy(&received_mediated.unwrap().body), &"HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap());

//     assert!(&received_bob.is_ok());
//     assert_eq!(received_bob.unwrap().get_body().unwrap(), sample_dids::TEST_DID_SIGN_1);
// }

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_signed_json_test() {
    // Arrange + Act
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
    // Message construction an JWS wrapping
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1) // packing in some payload
        .as_jws(&SignatureAlgorithm::EdDsa)
        .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes());

    assert!(&message.is_ok());

    // Receiving JWS
    let received = Message::verify(&message.unwrap().as_bytes(), &sign_keypair.public.to_bytes());
    // Assert
    assert!(&received.is_ok());
    // convert to serde values to compare contents and not formatting
    let sample_body: Value = serde_json::from_str(sample_dids::TEST_DID_SIGN_1).unwrap();
    let received_body: Value = serde_json::from_str(&received.unwrap().get_body().unwrap()).unwrap();
    assert_eq!(
        sample_body.to_string(),
        received_body.to_string(),
    );
}

#[test]
#[cfg(not(feature = "resolve"))]
fn send_receive_direct_signed_and_encrypted_xc20p_test() {
    // Arrange
    // keys
    let KeyPairSet {
        alice_public,
        alice_private,
        bobs_private,
        bobs_public,
        ..
    } = get_keypair_set();
    let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);

    // Message construction
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1) // packing in some payload
        .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public)) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(&hex::encode(sign_keypair.public.to_bytes())); // set kid header

    // Act
    // Send
    let ready_to_send = message.seal_signed(
        &alice_private,
        &sign_keypair.to_bytes(),
        SignatureAlgorithm::EdDsa,
        Some(&bobs_public),
    )
        .unwrap();

    //Receive
    #[cfg(not(feature = "resolve"))]
    let received = Message::receive(
        &ready_to_send,
        &bobs_private,
        Some(&alice_public),
        None,
    );
    #[cfg(feature = "resolve")]
    let received = Message::receive(
        &ready_to_send,
        &"HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap(),
        None,
        None,
    );

    // Assert
    assert!(&received.is_ok());
    let received = received.unwrap();

    // convert to serde values to compare contents and not formatting
    let sample_body: Value = serde_json::from_str(sample_dids::TEST_DID_SIGN_1).unwrap();
    let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
    assert_eq!(
        sample_body.to_string(),
        received_body.to_string(),
    );
}
