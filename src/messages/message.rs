use rand::prelude::*;
use serde::{
    Serialize,
    Deserialize
};
use biscuit::{Base64Url,
    ClaimsSet,
    CompactJson,
    Empty,
    JWT,
    RegisteredClaims,
    SingleOrMultiple,
    jwa::{
        EncryptionOptions,
        KeyManagementAlgorithm,
        ContentEncryptionAlgorithm,
        SignatureAlgorithm,
    }, jwe::{
        self,
        Compact,
    }, jwk::JWK,
    jws::{
        Compact as CompactJws,
        Secret,
        RegisteredHeader,
    }
};
use ring::signature::KeyPair;
use super::prior_claims::PriorClaims;
use crate::Error;

/// DIDComm message structure.
/// [Specification](https://identity.foundation/didcomm-messaging/spec/#message-structure)
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    headers: Headers,
    body: Vec<u8>,    
}

impl Message {
    /// Generates EMPTY default message.
    /// Use extension messages to build final one before `send`ing.
    ///
    pub fn new() -> Self {
        Message {
            headers: Headers {
                id: Headers::gen_random_id(),
                m_type: String::default(),
                to: vec!(String::default()),
                from: String::default(),
                created_time: None,
                expires_time: None,
                from_prior: None,
            },
            body: vec!(),
        }
    }
    /// Checks if message is rotation one.
    /// Exposed for explicit checks on sdk level.
    ///
    pub fn is_rotation(&self) -> bool {
        self.headers.from_prior.is_some()
    }
    pub fn get_prior(&self) -> Result<ClaimsSet<PriorClaims>, Error> {
        if self.is_rotation() {
            let claim_set = self.headers.from_prior.clone().unwrap();
            Ok(ClaimsSet {
                ..claim_set
            })
        } else {
           Err(Error::NoRotationData)
        }
    }
    pub fn get_headers(&self) -> &Headers {
        &self.headers
    }
    pub fn get_body(&self) -> &Vec<u8> {
        &self.body
    }
    /// Encrypts current message by consuming it.
    /// Uses provided cryptography function to perform
    ///     the encryption. Agnostic of actual algorythm used.
    /// Consuming is to make sure no changes are
    ///     possible post packaging / sending.
    /// Returns `Vec<u8>` to be sent to receiver.
    ///
    fn send_raw(self, crypter: fn(&[u8], &[u8]) -> Vec<u8>, receiver_pk: &[u8])
        -> Result<Vec<u8>, Error> {
            Ok(crypter(receiver_pk, serde_json::to_string(&self)?.as_bytes()))
    }
    /// Decrypts received cypher into instance of `Message`.
    /// Received message should be encrypted with our pub key.
    /// Returns `Ok(Message)` if decryption / deserialization
    ///     succeded. `Error` othervice.
    ///
    fn receive_raw(
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
    /// Encrypts current message by consuming it.
    /// Uses provided cryptography function to perform
    ///     the asymmentric encryption. Agnostic of actual algorythm used.
    /// Consuming is to make sure no changes are
    ///     possible post packaging / sending.
    /// Returns `Vec<u8>` to be sent to receiver.
    ///
    fn send_asymm(
        self,
        crypter: fn(plaintext: &[u8], nonce: &[u8], their_pk: &[u8], our_sk: &[u8])
            -> Result<Vec<u8>, Box<dyn std::error::Error>>,
        nonce: &[u8],
        their_pk: &[u8],
        our_sk: &[u8]
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        crypter(&serde_json::to_string(&self)?.as_bytes(), nonce, their_pk, our_sk)
    }
    /// Decrypts received cypher into instance of `Message`.
    /// Asymmetric crypto algorythm is expected.
    /// Returns `Ok(Message)` if decryption / deserialization
    ///     succeded. `Error` othervice.
    ///
    fn receive_asymm(
        received_message: &[u8],
        decrypter: fn(received_message: &[u8], nonce: &[u8], our_pk: &[u8], their_sk: &[u8])
            -> Result<Vec<u8>, Box<dyn std::error::Error>>,
        nonce: &[u8],
        our_pk: &[u8],
        their_sk: &[u8]
    ) -> Result<Self, Error> {
        if let Ok(raw_message_bytes) = decrypter(received_message, nonce, our_pk, their_sk)
            .map_err(|e| Error::Other(e)) {
                return Ok(serde_json::from_slice(&raw_message_bytes)?);
            }
        Err(Error::PlugCryptoFailure)
    }
    /// Packs the message into compact JWE with AES GCM encryption.
    /// Only 256 bit keys are supported.
    /// Returns serialized `Compact` JWE representation.
    ///
    fn pack_compact_jwe(self, key: &[u8]) -> Result<String, Error> {
        let mut nonce = [0u32; 4];
        for i in 0..3 {
            nonce[i] = rand::thread_rng().gen();
        }
        let nonce_counter = num::BigUint::from_slice(&nonce);
        assert!(nonce_counter.bits() <= 96);
        let mut nonce_bytes = nonce_counter.to_bytes_le();
        nonce_bytes.resize(96/8, 0);
        let header = jwe::RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        };
        let decrypted = jwe::Compact::new_decrypted(
            From::from(header),
            serde_json::to_string(&self)?.as_bytes().to_vec(),
        );    
        let options = EncryptionOptions::AES_GCM {nonce: nonce_bytes};
        let key: JWK<Empty> = JWK::new_octet_key(key, Default::default());
        let cipher = &decrypted.encrypt(&key, &options)?;
        Ok(serde_json::to_string(cipher)?)
    }
    /// Unpacks the message from JWE encrypted with AES GCM algorithm.
    /// Only 256 bit keys are supported.
    /// Results into `Message` or propagates underlying `Error`
    ///
    fn from_compact_jwe(payload: String, key: &[u8]) -> Result<Self, Error> {
        let encrypted: Compact<Vec<u8>, Empty> = serde_json::from_str(&payload)?;
        let key: JWK<Empty> = JWK::new_octet_key(key, Default::default());
        let mut decrypted = encrypted.decrypt(
            &key,
            KeyManagementAlgorithm::A256GCMKW,
            ContentEncryptionAlgorithm::A256GCM,
        )?;
        Ok(serde_json::from_slice(&decrypted.payload_mut()?)?)
    }
    /// Signs and packs message as BASE64URL
    /// Serialized into compact JWS
    /// Algorythm used - ES256
    ///
    fn sign_compact_jws(&self, key: &Secret) -> Result<String, Error> {
        let pack = |secret: &Secret, bytes: &[u8]| -> Result<String, Error> { // TODO: jwk must be implemented

            let claims = ClaimsSet::<Headers> {
                registered: RegisteredClaims {
                    issuer: Some("http://jolocom.com".to_string()),
                    subject: Some("Did goes here?".to_string()),
                    audience: Some(SingleOrMultiple::Single("Target did can be here".to_string())),
                    ..Default::default()
                },
                private: self.headers.clone()
            };

            Ok(JWT::new_decoded(From::from(
                RegisteredHeader {
                    algorithm: SignatureAlgorithm::ES256,
                    ..Default::default()
                }),
                claims)
                .into_encoded(secret)?
                .unwrap_encoded()
                .to_string())
        };
        match key {
            Secret::None => Err(Error::Generic("Empty key is not supported".into())),
            Secret::Bytes(i) => {
                let secret = Secret::Bytes(i.to_vec());
                pack(&secret, &i)
            }
            Secret::RsaKeyPair(kp) => {
                let pk = kp.public_key().as_ref();
                let inner = Secret::RsaKeyPair(kp.clone());
                pack(&inner, pk)
            },
            Secret::EcdsaKeyPair(ekp) => {
                let pk = ekp.public_key().as_ref();
                let inner = Secret::EcdsaKeyPair(ekp.clone());
                pack(&inner, pk)
            },
            // Secret::PublicKey(b) => {},
            _ => Err(Error::Generic("Unsupported JWS option!".into()))
        }
    }
    /// Decodes provided 'Compact' JWS and validates signature.
    /// Algorythm used for signing should be 'ES256'
    /// Returns `Ok(bool)` of validation and `Error` propagation
    ///     if input was not proper `Compact`
    ///
    fn validate_compact_jws(jws: &str, key: &Secret, out: &mut Headers) -> Result<bool, Error> {
        let token: CompactJws<ClaimsSet<Headers>, Empty> = JWT::<_, biscuit::Empty>::new_encoded(jws);

        *out = token.into_decoded(key, SignatureAlgorithm::ES256)?
            .unwrap_decoded()
            .1
            .private;

        Ok(true)
    }

    pub fn seal(self) -> Result<String, Error> {
        todo!()
        // Ok(String::from_utf8(self.pack_compact_jwe(key)?)?)
    }
    /// Wrap self to be mediated by some mediator.
    /// Takes one mediator at a time to make sure that mediated chain preserves unchanged.
    /// This method can be chained any number of times to match all the mediators in the chain.
    pub fn routed_by(self, ek: Vec<u8>) -> Self {
        Message::new()
        self
    }

    pub fn receive(jwm: String, pk: Vec<u8>) -> Result<Self, Error> {
        // todo!()
        Ok(Message::from_compact_jwe(jwm, &pk)?)
    }

}

// Required to be `Compact` serializable by biscuit crate
impl CompactJson for Message {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Headers {
    pub id: usize,
    #[serde(rename = "type")]
    pub m_type: String,
    pub to: Vec<String>,
    pub from: String,
    pub created_time: Option<usize>,
    pub expires_time: Option<usize>,
    /// A JWT, with sub: new DID and iss: prior DID, 
    /// with a signature from a key authorized by prior DID.
    from_prior: Option<ClaimsSet<PriorClaims>>,
}

impl Headers {
    /// Generates random `id`
    ///
    pub fn gen_random_id() -> usize {
            rand::thread_rng().gen()
    }
}

#[cfg(test)]
mod crypto_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;
    extern crate x25519_dalek;

    use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
    use chacha20poly1305::aead::{Aead, NewAead};
    use sodiumoxide::crypto::{
        secretbox,
        box_
    };
    use rand_core::OsRng;
    use x25519_dalek::{
        EphemeralSecret,
        PublicKey,
    };
    use crate::Error;
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn plugin_crypto_xChaCha20Paly1305_dummy_key() {
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
        let m = Message::new();
        let id = m.headers.id;

        // Act and Assert
        let crypted = m.send(my_crypter, key);
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m = Message::receive(&crypted.unwrap(), my_decrypter, key);
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().headers.id); // Data consistancy check
    }

    #[test]
    fn plugin_crypto_libsodium_box() {
        // Arrange
        // Plugable encryptor function to encrypt data
        let my_crypter = |k: &[u8], m: &[u8]|
            -> Vec<u8> {
            let nonce = secretbox::Nonce::from_slice(b"extra long unique nonce!").unwrap();
            secretbox::seal(m, &nonce, &secretbox::Key::from_slice( k).unwrap())
        };
        // Plugable decryptor function to decrypt data
        let my_decrypter = |k: &[u8], m: &[u8]|
            -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let nonce = secretbox::Nonce::from_slice(b"extra long unique nonce!").unwrap();
            secretbox::open(m, &nonce, &secretbox::Key::from_slice(k).unwrap())
                .map_err(|_| Error::PlugCryptoFailure.into())
        };
        let m = Message::new();
        let id = m.headers.id;
        let key = secretbox::gen_key();

        // Act and Assert
        let crypted = m.send(my_crypter, &key.as_ref());
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m = Message::receive(&crypted.unwrap(), my_decrypter, &key.as_ref());
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().headers.id); // Data consistancy check
    }

    #[test]
    fn plugin_crypto_asymm_libsodium_box() {
        // Arrange
        let (sender_pk, sender_sk) = box_::gen_keypair();
        let (receiver_pk, receiver_sk) = box_::gen_keypair();
        // Plugable encryptor function to encrypt data
        let nonce = box_::Nonce::from_slice(b"extra long unique nonce!").unwrap();
        let my_crypter = |m: &[u8], n: &[u8], pk: &[u8], sk: &[u8]|
            -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(box_::seal(m,
                &box_::Nonce::from_slice(n).unwrap(),
                &box_::PublicKey::from_slice(pk).unwrap(),
                &box_::SecretKey::from_slice(sk).unwrap())
            )
        };
        // Plugable decryptor function to decrypt data
        let my_decrypter = |m: &[u8], n: &[u8], pk: &[u8], sk: &[u8]|
            -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(box_::open(m,
                &box_::Nonce::from_slice(n).unwrap(),
                &box_::PublicKey::from_slice(pk).unwrap(),
                &box_::SecretKey::from_slice(sk).unwrap())
                .map_err(|_| Error::PlugCryptoFailure)?)
        };
        let m = Message::new();
        let id = m.headers.id;

        // Act and Assert
        let crypted =
            m.send_asymm(my_crypter,
            &nonce.as_ref(),
            &receiver_pk.as_ref(),
            &sender_sk.as_ref()
        );
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m = Message::receive_asymm(
            &crypted.unwrap(),
            my_decrypter,
            &nonce.as_ref(),
            &sender_pk.as_ref(),
            &receiver_sk.as_ref());
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().headers.id);
    }

    #[test]
    #[allow(non_snake_case)]
    fn plugin_crypto_xChaCha20Paly1305_x25519_dalek_shared_secret() {
        // Arrange
        let sender_sk = EphemeralSecret::new(OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let receiver_sk = EphemeralSecret::new(OsRng);
        let receiver_pk = PublicKey::from(&receiver_sk);
        let sender_shared = sender_sk.diffie_hellman(&receiver_pk);
        let receiver_shared = receiver_sk.diffie_hellman(&sender_pk);
        let m = Message::new();
        let id = m.headers.id;
        // Plugable encryptor function to encrypt data
        let my_crypter = |k: &[u8], m: &[u8]| -> Vec<u8> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(b"extra long unique nonce!");
            aead.encrypt(nonce, m).expect("encryption failure!")
        };
        // Plugable decryptor function to decrypt data
        let my_decrypter = |k: &[u8], m: &[u8]|
            -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(b"extra long unique nonce!");
            Ok(aead.decrypt(nonce, m).unwrap())
        };

        // Act and Assert
        let crypted = m.send(my_crypter, sender_shared.as_bytes());
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m =
            Message::receive(&crypted.unwrap(), my_decrypter, receiver_shared.as_bytes());
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().headers.id); // Data consistancy check
    }

    #[test]
    fn jwe_aes_gcm() -> Result<(), Error> {
        // Arrange
        let payload = b"my presous data!!!";
        let key: JWK<Empty> = JWK::new_octet_key(&vec![0; 256 / 8], Default::default());
        let mut m = Message::new();
        m.body = payload.to_vec();
        // Act
        let key = key.octet_key()?;
        let encrypted = m.pack_compact_jwe(key)?;
        let decrypted = Message::from_compact_jwe(encrypted, key)?;
        // Assert
        assert_eq!(payload.to_vec(), decrypted.body);
        Ok(())
    }

    #[test]
    fn jws_sign_validate_es256() -> Result<(), Error> {
        // Arrange
        let payload = b"another great payload";
        let pk = Secret::ecdsa_keypair_from_file(SignatureAlgorithm::ES256, "test_resources/ecdsa_private_key.p8")?;

        let mut m = Message::new();
        m.body = payload.to_vec();
        m.headers.from = "batman".into();
        // Act
        let signed = m.sign_compact_jws(&pk)?;
        // Assert
        let mut second_m = Message::new();
        assert!(Message::validate_compact_jws(&signed, &pk, &mut second_m.headers)?);
        assert_eq!(m.headers.from, second_m.headers.from);
        Ok(())
    }
}
