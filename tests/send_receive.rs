mod common;
use common::*;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use didcomm_rs::crypto::encryptor::CryptoAlgorithm;

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
    let mut message = Message::new(); // creating message
    message.body = sample_dids::TEST_DID_SIGN_1.as_bytes().to_vec(); // packing in some payload
    message.as_jwe(alg); // set JOSE header for XC20P algorithm
    message = message
        .add_header_field("my_custom_key".into(), "my_custom_value".into())
        .add_header_field("another_key".into(), "another_value".into());
    message.jwm_header.kid = 
        Some(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#)); // set kid header
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
fn send_receive_compact_test() {

}