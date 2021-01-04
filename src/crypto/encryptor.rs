use chacha20poly1305::{
    XChaCha20Poly1305,
    XNonce,
    aead::{
        Aead,
        NewAead,
    },
};
use crate::{
    SymmetricCypherMethod,
    AssymetricCyptherMethod,
    Error,
};

pub struct CryptoModule {
    key_type: CryptoKeyType,
    alg: CryptoAlgorithm,
}

impl CryptoModule {
    pub fn new(key_type: CryptoKeyType, alg: CryptoAlgorithm) -> Self {
        Self {
            key_type,
            alg
        }
    }
    pub fn encryptor(self) -> SymmetricCypherMethod {
        match self.alg {
           CryptoAlgorithm::XC20P => {
               Box::new(|nonce: &[u8], key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    let nonce = XNonce::from_slice(nonce);
                    let aead = XChaCha20Poly1305::new(key.into());
                    aead.encrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           },
           CryptoAlgorithm::A256GCM => {
               todo!()
           }
       }
    }
    pub fn decryptor(&self) -> SymmetricCypherMethod {
       match self.alg {
           CryptoAlgorithm::XC20P => {
               Box::new(|nonce: &[u8], key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
               let aead = XChaCha20Poly1305::new(key.into());
               let nonce = XNonce::from_slice(&nonce);
               aead.decrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           },
           CryptoAlgorithm::A256GCM => {
               todo!()
           }
       }
    }
    pub fn assymetric_encryptor(self) -> AssymetricCyptherMethod {
        match self.alg {
            CryptoAlgorithm::XC20P => {
//                Box::new(|m: &[u8], pk: &[u8], sk: &[u8]| -> Result<Vec<u8>, Error> {
//                   todo!() 
//                })
                todo!()
            },
            CryptoAlgorithm::A256GCM => {
                todo!()
            }
        }
    }
}

pub enum CryptoKeyType {
    X25519,
    P256,
}

pub enum CryptoAlgorithm {
    XC20P,
    A256GCM,
}

#[cfg(test)]
mod batteries_tests {
    use super::*;
    use crate::{
        Message,
        Jwe,
    };

    // FIXME!
    #[test]
    fn xc20p_test() -> Result<(), Error> {
        // Arrange
        let payload = "test message's body - can be anything...";
        let mut m = Message::new();
        m.as_jwe(); // Set jwe header manually - sohuld be preceeded by key properties
        m.body = payload.as_bytes().to_vec();
        let enc_module = CryptoModule::new(CryptoKeyType::X25519, CryptoAlgorithm::XC20P);
        let key = b"super duper key 32 bytes long!!!";
        // Act
        let (h, r) = m.encrypt(
            enc_module.encryptor(),
            key
        )?;
        let jwe = Jwe::new(h, r);
        let str_jwe = serde_json::to_string(&jwe);
        assert!(&str_jwe.is_ok());
        let dec_module = CryptoModule::new(CryptoKeyType::X25519, CryptoAlgorithm::XC20P);
        let s = Message::decrypt(
            &str_jwe.unwrap().as_bytes(),
            dec_module.decryptor(),
            key
            )?;
        //let received_payload = &String::from_utf8(s.body.clone())?;
        // Assert
        //assert_eq!(payload, received_payload);
        Ok(())
    }
}
