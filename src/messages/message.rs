use rand::prelude::*;
use serde::{
    Serialize,
    Deserialize
};
use biscuit::{
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
use super::{
    headers::Headers,
    prior_claims::PriorClaims,
    };
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
            headers: Headers::new(),
            body: vec!(),
        }
    }
    /// Checks if message is rotation one.
    /// Exposed for explicit checks on sdk level.
    ///
    pub fn is_rotation(&self) -> bool {
        self.headers.from_prior().is_some()
    }
    pub fn get_prior(&self) -> Result<ClaimsSet<PriorClaims>, Error> {
        if self.is_rotation() {
            let claim_set = self.headers.from_prior().clone().unwrap();
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
    /// FIXME: Use Compact::decode() instead of serde
    fn from_compact_jwe(payload: &str, key: &[u8]) -> Result<Self, Error> {
        let encrypted: Compact<Vec<u8>, Empty> = serde_json::from_str(payload)?;
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
        let pack = |secret: Secret| -> Result<String, Error> { // TODO: jwk must be implemented
            let claims = ClaimsSet::<Message> {
                registered: RegisteredClaims {
                    issuer: Some("http://jolocom.com".to_string()),
                    subject: Some("Did goes here?".to_string()),
                    audience: Some(SingleOrMultiple::Single("Target did can be here".to_string())),
                    ..Default::default()
                },
                private: self.clone()
            };

            Ok(JWT::new_decoded(From::from(
                RegisteredHeader {
                    algorithm: SignatureAlgorithm::ES256,
                    ..Default::default()
                }),
                claims)
                .into_encoded(&secret)?
                .unwrap_encoded()
                .to_string())
        };
        match key {
            Secret::Bytes(i) => {
                pack(Secret::Bytes(i.to_vec()))
            }
            Secret::RsaKeyPair(kp) => {
                pack(Secret::RsaKeyPair(kp.clone()))
            },
            Secret::EcdsaKeyPair(ekp) => {
                pack(Secret::EcdsaKeyPair(ekp.clone()))
            },
            Secret::None => Err(Error::Generic("Empty key is not supported".into())),
            // Secret::PublicKey(b) => {},
            _ => Err(Error::Generic("Unsupported JWS option!".into()))
        }
    }
    /// Decodes provided 'Compact' JWS and validates signature.
    /// Algorythm used for signing should be 'ES256'
    /// Returns `Ok(bool)` of validation and `Error` propagation
    ///     if input was not proper `Compact`
    ///
    /// WARNING: This method validates JWS ONLY!
    ///     To fully comply with DIDComm specifications additional validation of key
    /// used for signing is allowed to do so in the Document resolved form DID in the
    /// `from` attribute!
    ///
    fn validate_compact_jws(jws: &str, key: &Secret, out: &mut Self) -> Result<bool, Error> {
        let token: CompactJws<ClaimsSet<Self>, Empty> = JWT::<Self, biscuit::Empty>::new_encoded(jws);

        *out = token.into_decoded(key, SignatureAlgorithm::ES256)?
            .unwrap_decoded()
            .1
            .private;

        Ok(true)
    }
    /// Seals self and returns ready to send JWE
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    /// TODO: Add example[s]
    pub fn seal(self, ek: Vec<u8>) -> Result<String, Error> {
        self.pack_compact_jwe(&ek)
    }
    /// Signs raw message and then packs it to encrypted envelope
    /// [Spec](https://identity.foundation/didcomm-messaging/spec/#message-signing)
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `sk` - signing key for enveloped message JWS encryption
    /// TODO: Adde example[s]
    pub fn seal_signed(self, ek: Vec<u8>, sk: &Secret) -> Result<String, Error> {
        let mut crypto_envelope = Message {
            headers: Headers::encrypt_jws(self.headers.clone())?,
            body: self.sign_compact_jws(&sk)?.as_bytes().to_vec()
        };
        crypto_envelope.pack_compact_jwe(&ek)
    }
    /// Wrap self to be mediated by some mediator.
    /// Takes one mediator at a time to make sure that mediated chain preserves unchanged.
    /// This method can be chained any number of times to match all the mediators in the chain.
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `to` - list of destination recepients. can be empty (Optional) `String::default()`
    ///
    /// `form` - sender identifyer `String`
    ///
    /// `expires_time` - `Option<usize>` seconds from the UTC Epoch seconds,
    ///     signals when the message is no longer valid, and is to be used by
    ///     the recipient to discard expired messages on receipt
    /// TODO: Add example[s]
    pub fn routed_by(self,
        ek: Vec<u8>,
        to: Vec<String>,
        from: String,
        expires_time: Option<usize>)
        -> Result<Self, Error> {
        let payload = self.pack_compact_jwe(&ek)?;
        let forward_headers = Headers::forward(to, from, expires_time)?;
        let mut packed = Message::new();
        packed.headers = forward_headers;
        packed.body = payload.as_bytes().to_vec();
        Ok(packed)
    }
    /// Unseals sealed message and returns raw instance af the Message
    ///
    /// # Parameters
    ///
    /// `jwm` - `String` of Message sealed with `.seal()` method
    ///
    /// `pk` - encryption key for JWE decryption
    /// TODO: Add example[s]
    pub fn receive(jwm: &str, pk: Vec<u8>) -> Result<Self, Error> {
        // match Message::parse_type(jwm)? {
        //     Ok(MessageType::Jwe) => {},
        //     Ok(MessageType::Jws) => {},
        //     Ok(MessageType::JwsJwe) => {},
        //     Ok(MessageType::PlainText) => {},
        //     Err(_) => Error::FailedToIdentifyMessageType(),
        // }
        Message::from_compact_jwe(jwm, &pk)
    }
}

impl Into<Message> for &ClaimsSet<Message> {
    fn into(self) -> Message {
        self.private.to_owned()
    }
}

// Required to be `Compact` serializable by biscuit crate
impl CompactJson for Message {}

#[cfg(test)]
mod crypto_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;
    extern crate x25519_dalek;

    use crate::Error;
    use super::*;

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
        let decrypted = Message::from_compact_jwe(&encrypted, key)?;
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
        assert!(Message::validate_compact_jws(&signed, &pk, &mut second_m)?);
        assert_eq!(m.headers.from, second_m.headers.from);
        Ok(())
    }

    #[test]
    fn jwe_of_jws_unwrapping_es256() -> Result<(), Error> {
        // Arrange
        use biscuit::JWT;
        use biscuit::jwa::*;
        
        let mut m = Message::new();
        let data = b"super secret message";
        m.body = data.to_vec();
        let pk = Secret::ecdsa_keypair_from_file(SignatureAlgorithm::ES256, "test_resources/ecdsa_private_key.p8")?;
        // Act
        let ready_to_send = m.sign_compact_jws(&pk)?;//seal_signed(ek.octet_key()?.to_vec(), &pk)?;
        let decoded: JWT<Message, biscuit::Empty> = JWT::new_encoded(&ready_to_send);
        let decoded = decoded.into_decoded(&pk, SignatureAlgorithm::ES256)?;
        let mut from_signed_jws = Message::new();
        // let headers = decoded.header()?;
        let payload: Message = decoded.payload()?.into();
        // Assert
        assert_eq!("super secret message", std::str::from_utf8(&payload.body).unwrap());
        assert!(Message::validate_compact_jws(&ready_to_send, &pk, &mut from_signed_jws)?);
        Ok(())
    }
}
