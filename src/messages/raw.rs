use std::convert::TryInto;
use serde_json::Value;

use crate::{DidcommHeader, Error, Jwe, Jws, Recepient, crypto::{
        SignatureAlgorithm,
        SymmetricCypherMethod,
        SigningMethod,
        Signer,
    }};
use super::Message;

#[derive(Serialize, Deserialize)]
pub struct PayloadToVerify {
    #[serde(flatten)]
    didcomm_header: DidcommHeader,
    #[cfg(feature = "resolve")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recepients: Option<Vec<Recepient>>,
    body: Value,
}

#[cfg(feature = "raw-crypto")]
impl Message {
    /// Encrypts current message by consuming it.
    /// Uses provided cryptography function to perform
    ///     the encryption. Agnostic of actual algorythm used.
    /// Consuming is to make sure no changes are
    ///     possible post packaging / sending.
    /// Returns `(JwmHeader, Vec<u8>)` to be sent to receiver.
    ///
    pub fn encrypt(self, crypter: SymmetricCypherMethod, encryption_key: &[u8])
        -> Result<String, Error> {
            let header = self.jwm_header.clone();
            let d_header = self.get_didcomm_header();
            let cyphertext = crypter(self.jwm_header.get_iv().as_ref(), encryption_key, serde_json::to_string(&self)?.as_bytes())?;
            let mut jwe = Jwe::new(header, self.recepients.clone(), cyphertext);
            let multi = self.recepients.is_some();
            jwe.header.skid = Some(d_header.from.clone().unwrap_or_default())   ; 
            if !multi {
                jwe.header.kid = Some(d_header.to[0].clone());
            }
            jwe.header.skid = d_header.from.clone();
            Ok(serde_json::to_string(&jwe)?)
    }
    /// Decrypts received cypher into instance of `Message`.
    /// Received message should be encrypted with our pub key.
    /// Returns `Ok(Message)` if decryption / deserialization
    ///     succeded. `Error` othervice.
    ///
    pub fn decrypt(
        received_message: &[u8],
        decrypter: SymmetricCypherMethod,
        key: &[u8]) 
            -> Result<Self, Error> {
        let jwe: Jwe = serde_json::from_slice(received_message)?;
        if let Ok(raw_message_bytes) = decrypter(jwe.header.get_iv().as_ref(), key, &jwe.payload()) {
            Ok(serde_json::from_slice(&raw_message_bytes)?)
        } else {
            Err(Error::PlugCryptoFailure)
        }
    }
    /// Signs message and turns it into `Jws` envelope.
    /// `Err` is returned if message is not properly prepared or data is malformed.
    /// Jws enveloped payload is base64_url encoded
    pub fn sign(self, signer: SigningMethod, signing_key: &[u8]) -> Result<String, Error> {
        let h = self.jwm_header.clone();
        if h.alg.is_none() {
            Err(Error::JwsParseError)
        } else {
            let jwm_header_string_base64 = base64_url::encode(&serde_json::to_string(&self.jwm_header)?);
            let payload: PayloadToVerify = PayloadToVerify {
                didcomm_header: self.get_didcomm_header().clone(),
                #[cfg(feature = "resolve")]
                recepients: self.recepients.clone(),
                body: self.get_body()?,
            };
            let payload_json_string = serde_json::to_string(&payload)?;
            let payload_string_base64 =
                base64_url::encode(&payload_json_string);
            let payload_to_sign = format!("{}.{}", &jwm_header_string_base64, &payload_string_base64);
            let signature = signer(signing_key, &payload_to_sign.as_bytes())?;
            let jws = Jws::new(payload_string_base64, Some(h.clone()), None, signature);
            let serialized_jws = serde_json::to_string(&jws)?;

            Ok(serialized_jws)
        }
    }
    /// Verifyes signature and returns payload message on verification success.
    /// `Err` return if signature invalid or data is malformed.
    /// Expects Jws's payload to be a valid serialized `Message` and base64_url encoded.
    ///
    pub fn verify(jws: &[u8], key: &[u8]) -> Result<Message, Error> {
        let jws: Jws = serde_json::from_slice(jws)?;
        if let Some(alg) = &jws.signature_value.alg() {
            let verifyer: SignatureAlgorithm = alg.try_into()?;
            if verifyer.validator()(key, &jws.payload.as_bytes(), &jws.signature_value.signature[..])? {
                Ok(serde_json::from_slice(&base64_url::decode(&jws.payload)?)?)
            } else {
                Err(Error::JwsParseError)
            }
        } else {
            Err(Error::JwsParseError)
        }
    }

    /// Verifies signature and returns payload message on verification success.
    /// `Err` return if signature invalid or data is malformed.
    /// Expects Jws's payload to be a valid serialized `Message` and base64_url encoded.
    pub fn verify_value(jws: &Value, key: &[u8]) -> Result<Message, Error> {
        let jws_string = serde_json::to_string(jws)?;
        Message::verify(&jws_string.into_bytes(), key)
    }
}

#[cfg(test)] 
mod raw_tests {
    use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
    use chacha20poly1305::aead::{Aead, NewAead};
    use sodiumoxide::crypto::secretbox;
    use x25519_dalek::{
        EphemeralSecret,
        PublicKey,
    };
    use super::{
        Message,
        Error,
    };
    use crate::crypto::CryptoAlgorithm;
    
    #[test]
    #[allow(non_snake_case)]
    #[cfg(feature="raw-crypto")]
    fn plugin_crypto_xChaCha20Paly1305_dummy_key() {
        // Arrange
        let key = Key::from_slice(b"an example very very secret key.");
        // Plugable encryptor function to encrypt data
        let my_crypter = Box::new(|n: &[u8], k: &[u8], m: &[u8]| -> Result<Vec<u8>, Error> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(n);
            aead.encrypt(nonce, m).map_err(|e| Error::Generic(e.to_string()))
        });
        // Plugable decryptor function to decrypt data
        let my_decrypter = Box::new(|n: &[u8], k: &[u8], m: &[u8]| -> Result<Vec<u8>, Error> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(n);
            Ok(aead.decrypt(nonce, m).unwrap())
        });
        let m = Message::new()
            .as_jwe(&CryptoAlgorithm::A256GCM);
        let id = m.get_didcomm_header().id;

        // Act and Assert
        let crypted = m.encrypt(my_crypter, key);
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m = Message::decrypt(&crypted.unwrap().as_bytes(), my_decrypter, key);
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().get_didcomm_header().id); // Data consistancy check
    }

    #[test]
    #[cfg(feature="raw-crypto")]
    fn plugin_crypto_libsodium_box() {
        // Arrange
        // Plugable encryptor function to encrypt data
        let my_crypter = Box::new(|n: &[u8], k: &[u8], m: &[u8]|
            -> Result<Vec<u8>, Error> {
            let nonce = secretbox::Nonce::from_slice(n).unwrap();
            Ok(secretbox::seal(m, &nonce, &secretbox::Key::from_slice( k).unwrap()))
        });
        // Plugable decryptor function to decrypt data
        let my_decrypter = Box::new(|n: &[u8], k: &[u8], m: &[u8]|
            -> Result<Vec<u8>, Error> {
            let nonce = secretbox::Nonce::from_slice(n).unwrap();
            Ok(secretbox::open(m, &nonce, &secretbox::Key::from_slice(k).unwrap())
                .unwrap())
        });
        let m = Message::new()
            .as_jwe(&CryptoAlgorithm::A256GCM);
        let id = m.get_didcomm_header().id;
        let key = secretbox::gen_key();

        // Act and Assert
        let crypted = m.encrypt(my_crypter, &key.as_ref());
        assert!(&crypted.is_ok()); // Encryption checkp();
        let crypted = crypted.unwrap();
        println!("{}", &crypted);
        let raw_m = Message::decrypt(&crypted.as_bytes(), my_decrypter, &key.as_ref());
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().get_didcomm_header().id); // Data consistancy check
    }

    #[test]
    #[allow(non_snake_case)]
    #[cfg(feature="raw-crypto")]
    fn plugin_crypto_xChaCha20Paly1305_x25519_dalek_shared_secret() {
        // Arrange
        let sender_sk = EphemeralSecret::new(rand_core::OsRng);
        let sender_pk = PublicKey::from(&sender_sk);
        let receiver_sk = EphemeralSecret::new(rand_core::OsRng);
        let receiver_pk = PublicKey::from(&receiver_sk);
        let sender_shared = sender_sk.diffie_hellman(&receiver_pk);
        let receiver_shared = receiver_sk.diffie_hellman(&sender_pk);
        let m = Message::new()
            .as_jwe(&CryptoAlgorithm::XC20P);
        let id = m.get_didcomm_header().id;
        // Plugable encryptor function to encrypt data
        let my_crypter = Box::new(|n: &[u8], k: &[u8], m: &[u8]| -> Result<Vec<u8>, Error> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(n);
            aead.encrypt(nonce, m).map_err(|e| Error::Generic(e.to_string()))
        });
        // Plugable decryptor function to decrypt data
        let my_decrypter = Box::new(|n: &[u8], k: &[u8], m: &[u8]|
            -> Result<Vec<u8>, Error> {
            let aead = XChaCha20Poly1305::new(k.into());
            let nonce = XNonce::from_slice(n);
            aead.decrypt(nonce, m).map_err(|e| Error::Generic(e.to_string()))
        });

        // Act and Assert
        let crypted = m.encrypt(my_crypter, sender_shared.as_bytes());
        assert!(&crypted.is_ok()); // Encryption check
        let raw_m =
            Message::decrypt(&crypted.unwrap().as_bytes(), my_decrypter, receiver_shared.as_bytes());
        assert!(&raw_m.is_ok()); // Decryption check
        assert_eq!(id, raw_m.unwrap().get_didcomm_header().id); // Data consistancy check
    }
}
