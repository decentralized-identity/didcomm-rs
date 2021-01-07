
use std::convert::TryFrom;
use crate::{
    SymmetricCypherMethod,
    AssymetricCyptherMethod,
    Error,
};

/// Plugable closure generator enum, which creates instance of crypto function
///     based on selected algorythm types.
/// # Attention:
/// Immutable by design and should be instance per invocation to make sure no
///     sensitive data is been stored in memory longer than necessary.
/// Underlying algorithms are implemented by Rust-crypto crate family.
///
/// Allowed (and implemented) cryptographical algorithms (JWA).
/// According to (spec)[https://identity.foundation/didcomm-messaging/spec/#sender-authenticated-encryption]
///
#[derive(Copy, Clone)]
pub enum CryptoAlgorithm {
    XC20P,
    A256GCM,
}

impl CryptoAlgorithm {
    /// Generates + invokes crypto of `SymmetricCypherMethod` which perfoms encryption.
    /// Algorithm selected is based on struct's `CryptoAlgorithm` property.
    ///
    pub fn encryptor(self) -> SymmetricCypherMethod {
        match self {
           CryptoAlgorithm::XC20P => {
               Box::new(|nonce: &[u8], key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                   check_nonce(nonce, 24)?;
                   use chacha20poly1305::{
                        XChaCha20Poly1305,
                        XNonce,
                        aead::{
                            Aead,
                            NewAead,
                        },
                    };
                    let nonce = XNonce::from_slice(nonce);
                    let aead = XChaCha20Poly1305::new(key.into());
                    aead.encrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           },
           CryptoAlgorithm::A256GCM => {
               Box::new(|nonce: &[u8], key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                   check_nonce(nonce, 12)?;
                   use aes_gcm::{
                       Aes256Gcm,
                       aead::{
                           Aead,
                           NewAead,
                           generic_array::GenericArray
                           }
                   };
                   let nonce = GenericArray::from_slice(&nonce[..12]);
                   let aead = Aes256Gcm::new(GenericArray::from_slice(key));
                   aead.encrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           }
       }
    }
    /// Generates + invokes crypto of `SymmetricCypherMethod` which perfoms decryption.
    /// Algorithm selected is based on struct's `CryptoAlgorithm` property.
    ///
    pub fn decryptor(&self) -> SymmetricCypherMethod {
        match self {
            CryptoAlgorithm::XC20P => {
                Box::new(|nonce: &[u8], key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    check_nonce(nonce, 24)?;
                    use chacha20poly1305::{
                            XChaCha20Poly1305,
                            XNonce,
                            aead::{
                                Aead,
                                NewAead,
                            },
                        };
                    let aead = XChaCha20Poly1305::new(key.into());
                    let nonce = XNonce::from_slice(&nonce);
                    aead.decrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           },
           CryptoAlgorithm::A256GCM => {
               Box::new(|nonce: &[u8], key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                   check_nonce(nonce, 12)?;
                   use aes_gcm::{
                       Aes256Gcm,
                       aead::{
                           Aead,
                           NewAead,
                           generic_array::GenericArray
                           }
                   };
                   let nonce = GenericArray::from_slice(&nonce[..12]);
                   let aead = Aes256Gcm::new(GenericArray::from_slice(key));
                   aead.decrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           }
       }
    }
    /// Not implemented - no usecase atm...
    pub fn assymetric_encryptor(self) -> AssymetricCyptherMethod {
        match self {
            CryptoAlgorithm::XC20P => {
                todo!()
            },
            CryptoAlgorithm::A256GCM => {
                todo!()
            }
        }
    }
}

impl TryFrom<&String> for CryptoAlgorithm {
    type Error = Error;
    fn try_from(incomming: &String) -> Result<Self, Error> {
        Ok(match &incomming[..] {
            "A256GCM" => Self::A256GCM,
            "ECDH-ES+A256KW" => Self::XC20P,
            _ => return Err(Error::JweParseError),
        })
    }
}
// inner helper function
fn check_nonce(nonce: &[u8], expected_len: usize) -> Result<(), Error> {
    if nonce.len() < expected_len {
        return Err(Error::PlugCryptoFailure);
    }
    Ok(())
}

#[cfg(test)]
mod batteries_tests {
    use super::*;
    use crate::{
        Message,
        Jwe,
    };

    #[test]
    fn xc20p_test() -> Result<(), Error> {
        // Arrange
        let payload = "test message's body - can be anything...";
        let mut m = Message::new();
        m.as_jwe(CryptoAlgorithm::XC20P); // Set jwe header manually - sohuld be preceeded by key properties
        m.body = payload.as_bytes().to_vec();
        let original_header = m.get_jwm_header().clone();
        let key = b"super duper key 32 bytes long!!!";
        // Act
        let (h, r) = m.encrypt(
            CryptoAlgorithm::XC20P.encryptor(),
            key
        )?;
        let jwe = Jwe::new(h, r);
        let str_jwe = serde_json::to_string(&jwe);
        assert!(&str_jwe.is_ok());
        let s = Message::decrypt(
            &str_jwe.unwrap().as_bytes(),
            CryptoAlgorithm::XC20P.decryptor(),
            key
            )?;
        let received_payload = &String::from_utf8(s.body.clone())?; // I know it's a String, but could be anything really.
        // Assert
        assert_eq!(*s.get_jwm_header(), original_header);
        assert_eq!(payload, received_payload);
        Ok(())
    }
    #[test]
    fn a256gcm_test() -> Result<(), Error> {
        // Arrange
        let payload = "test message's body - can be anything...";
        let mut m = Message::new();
        m.as_jwe(CryptoAlgorithm::A256GCM); // Set jwe header manually - sohuld be preceeded by key properties
        m.body = payload.as_bytes().to_vec();
        let original_header = m.get_jwm_header().clone();
        let key = b"super duper key 32 bytes long!!!";
        // Act
        let (h, r) = m.encrypt(
            CryptoAlgorithm::A256GCM.encryptor(),
            key
        )?;
        let jwe = Jwe::new(h, r);
        let str_jwe = serde_json::to_string(&jwe);
        assert!(&str_jwe.is_ok());
        let s = Message::decrypt(
            &str_jwe.unwrap().as_bytes(),
            CryptoAlgorithm::A256GCM.decryptor(),
            key
            )?;
        let received_payload = &String::from_utf8(s.body.clone())?; // I know it's a String, but could be anything really.
        // Assert
        assert_eq!(*s.get_jwm_header(), original_header);
        assert_eq!(payload, received_payload);
        Ok(())
    }
}
