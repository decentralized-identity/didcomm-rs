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
use rand::prelude::*;

// Required to be `Compact` serializable by biscuit crate
impl CompactJson for Message {}

#[cfg(feature = "jose-biscuit")]
impl Into<Message> for &ClaimsSet<Message> {
    fn into(self) -> Message {
        self.private.to_owned()
    }
}

#[cfg(feature = "jose-biscuit")]
impl Message {
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
    fn from_valid_compact_jws(jws: &str, key: &Secret) -> Result<Self, Error> {
        let token: CompactJws<ClaimsSet<Self>, Empty> = JWT::<Self, biscuit::Empty>::new_encoded(jws);

        Ok(token.into_decoded(key, SignatureAlgorithm::ES256)?
            .unwrap_decoded()
            .1
            .private)
    }
    /// Unseals sealed message and returns raw instance af the Message
    ///
    /// # Parameters
    ///
    /// `jwm` - `String` of Message sealed with `.seal()` method
    ///
    /// `pk` - encryption key for JWE decryption
    /// TODO: Add examples
    pub fn receive(incomming_message: &str, key: Secret) -> Result<Self, Error> {
        match key {
            Secret::None => {
                Ok(serde_json::from_str(incomming_message)?)
            },
            _ => {
                let jwt: JWT<Message, biscuit::Empty> = JWT::new_encoded(incomming_message); 
                let header = jwt.unverified_header()?;
                if header.registered().SignatureAlgorithm == SignatureAlgorithm::ES256 {
                    Message::from_valid_compact_jws(incomming_message, & key)
                } else if header.registered().
            cek_algorithm: KeyManagementAlgorithm::A256GCMKW,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
                    Message::from_compact_jwe(incomming_message, &key)
                }
            },
        }
    }
}

#[cfg(test, feature = "jose-biscuit")]
mod biscuit_tests {
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

