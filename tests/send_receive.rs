mod common;

use common::*;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use didcomm_rs::crypto::CryptoAlgorithm;

#[test]
fn send_receive_raw() {
    // Arrange
    let m = Message::new()
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_")
        .to(vec!("did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"))
        .body(sample_dids::TEST_DID_ENCRYPT_1.as_bytes());

    // Act
    let ready_to_send = m.clone().as_raw_json().unwrap();
    let packed = m.clone().seal(b"anuhcphus");
    assert!(packed.is_err());
    let received = Message::receive(&ready_to_send, None);

    // Assert
    assert!(&received.is_ok());
    assert_eq!(m, received.unwrap());
}

#[test]
fn send_receive_encrypted_xc20p_json_test() {
    // Arrange
    // keys
    let alice_secret = EphemeralSecret::new(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let bob_secret = EphemeralSecret::new(OsRng);
    let bob_public = PublicKey::from(&bob_secret);
    // DIDComm related setup
    let ek = alice_secret.diffie_hellman(&bob_public);
    let alg = CryptoAlgorithm::XC20P; // decide which alg is used (based on key)

    // Message construction
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(vec!("did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe")) // setting to
        .body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jwe(alg) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#)); // set kid header

    // Act
    let ready_to_send = message.seal(ek.as_bytes()).unwrap();
    let rk = bob_secret.diffie_hellman(&alice_public); // bob's shared secret calculation
    let received = Message::receive(&ready_to_send, Some(rk.as_bytes())); // and now we parse received

    // Assert
    assert!(&received.is_ok());
    let received = received.unwrap();
    assert_eq!(sample_dids::TEST_DID_SIGN_1.as_bytes().to_vec(), received.body);
}

#[test]
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
    let alg = CryptoAlgorithm::XC20P; // decide which alg is used (based on key)


    // Message construction
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(vec!("did:xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe")) // setting to
        .body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jwe(alg) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#)) // set kid header
        .routed_by(ek_to_bob.as_bytes(), vec!("did:mediator:suetcpl23pt23rp2teu995t98u")); // here we use destination key to bob and `to` header of mediator

    // Act + Assert as we go
    assert!(&message.is_ok());

    // Message envelope to mediator
    let ready_to_send = message
        .unwrap()
        .as_jwe(CryptoAlgorithm::XC20P) // here this method call is crucial as mediator and end receiver may use different algorithms.
        .seal(ek_to_mediator.as_bytes()); // this would've failed without previous method call.

    assert!(&ready_to_send.is_ok());

    // Received by mediator
    let rk_mediator = bob_mediator_secret.diffie_hellman(&alice_public_2); // key to decrypt mediated message
    let received_mediated = Message::receive(&ready_to_send.unwrap(), Some(rk_mediator.as_bytes()));

    assert!(&received_mediated.is_ok());

    // Received by Bob
    let rk_bob = bob_secret.diffie_hellman(&alice_public); // key to decrypt final message
    let received_bob = Message::receive(&String::from_utf8_lossy(&received_mediated.unwrap().body), Some(rk_bob.as_bytes()));

    assert!(&received_bob.is_ok());
    assert_eq!(received_bob.unwrap().body, sample_dids::TEST_DID_SIGN_1.as_bytes());
}
