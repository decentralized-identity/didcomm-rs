use rand::prelude::*;
use serde::{
    Serialize,
    Deserialize
};
use biscuit::ClaimsSet;
use std::collections::HashMap;
use super::prior_claims::PriorClaims;
use crate::Error;

/// DIDComm message structure.
/// [Specification](https://identity.foundation/didcomm-messaging/spec/#message-structure)
///
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub id: usize,
    #[serde(rename = "type")]
    pub m_type: String,
    pub to: Option<Vec<String>>,
    pub created_time: Option<usize>,
    pub expires_time: Option<usize>,
    from: Option<String>,
    /// A JWT, with sub: new DID and iss: prior DID, 
    /// with a signature from a key authorized by prior DID.
    from_prior: Option<ClaimsSet<PriorClaims>>,
    body: Option<ClaimsSet<HashMap<String, String>>>,
}

impl Message {
    /// Generates EMPTY default message.
    /// Use extension messages to build final one before `send`ing.
    ///
    pub fn new() -> Self {
        Message {
            id: 0,
            m_type: String::default(),
            to: None,
            created_time: None,
            expires_time: None,
            from: None,
            from_prior: None,
            body: None,
        }
    }
    /// Generates random `id` for existing `Message`
    /// Consumes it in process and returns new one.
    ///
    pub fn gen_random_id(self) -> Self {
        Message {
            id: rand::thread_rng().gen(),
            ..self
        }
    }
    /// Checks if message is rotation one.
    /// Exposed for explicit checks on sdk level.
    ///
    pub fn is_rotation(&self) -> bool {
        self.from_prior.is_some()
    }
    pub fn get_prior(&self) -> Result<ClaimsSet<PriorClaims>, Error> {
        if self.is_rotation() {
            let claim_set = self.from_prior.clone().unwrap();
            Ok(ClaimsSet {
                ..claim_set
            })
        } else {
           Err(Error::NoRotationData)
        }
    }
    /// Encrypts current message by consuming it.
    /// Uses provided cryptography function to perform
    ///     the encryption. Agnostic of actual algorythm used.
    /// Consuming is to make sure no changes are
    ///     possible post packaging / sending.
    /// Returns `Vec<u8>` to be sent to receiver.
    ///
    pub fn send(self, crypter: fn(&[u8], &[u8]) -> Vec<u8>, receiver_pk: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(crypter(receiver_pk, serde_json::to_string(&self)?.as_bytes()))
    }
    /// Decrypts received cypher into instance of `Message`.
    /// Received message should be encrypted with our pub key.
    /// Returns `Some(Message)` if decryption / deserialization
    ///     succeded. `None` othervice.
    /// This associated function returns `None` by design to 
    ///     awoid any issues with trying to read into `Message`s 
    ///     which were not sent to us as recepients.
    ///
    pub fn receive(
        received_message: &[u8],
        decrypter: fn(&[u8], &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
        our_sk: &[u8]) 
            -> Result<Self, Error> {
        if let Ok(raw_message_bytes) = decrypter(our_sk, received_message)
            .map_err(|e| Error::Other(e)) {
                return Ok(serde_json::from_slice(&raw_message_bytes)?);
            }
        Err(Error::PlugCryptoFailure)
    }
}

#[cfg(test)]
mod crypto_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;
    use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
    use chacha20poly1305::aead::{Aead, NewAead};
    use sodiumoxide::crypto::secretbox;
    use crate::Error;
    use super::*;

    #[test]
    fn plugin_crypto_test() {
        // Arrange
        let key = Key::from_slice(b"an example very very secret key.");
        // Plugable encryptor function to encrypt data
        let my_crypter = |k: &[u8], m: &[u8]| -> Vec<u8> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(b"extra long unique nonce!");
            aead.encrypt(nonce, m).expect("encryption failure!")
        };
        // Plugable decryptor function to decrypt data
        let my_decrypter = |k: &[u8], m: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(b"extra long unique nonce!");
            Ok(aead.decrypt(nonce, m).unwrap())
        };
        let m = Message::new()
            .gen_random_id();
        let id = m.id;

        // Act and Assert
        let crypted = m.send(my_crypter, key);
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m = Message::receive(&crypted.unwrap(), my_decrypter, key);
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().id); // Data consistancy check
    }

    #[test]
    fn plugin_crypto_test_libsodium_box() {
        // Arrange
        // Plugable encryptor function to encrypt data
        let my_crypter = |k: &[u8], m: &[u8]| -> Vec<u8> {
            let nonce = secretbox::Nonce::from_slice(b"extra long unique nonce!").unwrap();
            secretbox::seal(m, &nonce, &secretbox::Key::from_slice( k).unwrap())
        };
        // Plugable decryptor function to decrypt data
        let my_decrypter = |k: &[u8], m: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let nonce = secretbox::Nonce::from_slice(b"extra long unique nonce!").unwrap();
            match secretbox::open(m, &nonce, &secretbox::Key::from_slice(k).unwrap()) {
                Ok(v) => Ok(v),
                Err(_) => Err(Error::PlugCryptoFailure.into())
            }
        };
        let m = Message::new()
        .gen_random_id();
        let id = m.id;
        let key = secretbox::gen_key();

        // Act and Assert
        let crypted = m.send(my_crypter, &key.as_ref());
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m = Message::receive(&crypted.unwrap(), my_decrypter, &key.as_ref());
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().id); // Data consistancy check
    }
}