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
           CryptoAlgorithm::XC20P(byte_nonce) => {
               Box::new(|key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    let nonce = XNonce::from_slice(&byte_nonce);
                    let aead = XChaCha20Poly1305::new(key.into());
                    aead.encrypt(nonce, message).map_err(|e| Error::Generic(e.to_string()))
               })
           },
           CryptoAlgorithm::A256GCM => {
               todo!()
           }
       }
    }
    pub fn decryptor(&self, key: &[u8], message: &[u8]) -> SymmetricCypherMethod {
       match self.alg {
           CryptoAlgorithm::XC20P(byte_nonce) => {
               Box::new(|key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
               let aead = XChaCha20Poly1305::new(key.into());
               let nonce = XNonce::from_slice(&byte_nonce);
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
            CryptoAlgorithm::XC20P(byte_nonce) => {
                Box::new(|m: &[u8], pk: &[u8], sk: &[u8] -> Result<Vec<u8>, Error> {

                })
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
    XC20P(Vec<u8>),
    A256GCM,
}

#[cfg(test)]
mod batteries_tests {
    use super::*;
    use crate::Message;

    #[test]
    fn xc20p_test() -> Result<(), Error> {
        // Arrange
        let m = Message::new();
        let module = CryptoModule::new(CryptoKeyType::X25519, CryptoAlgorithm::XC20P(m.get_didcomm_header().id.to_ne_bytes().to_vec()));
        let r = m.send_raw(
            module.encryptor(),
            b"super duper key"
        )?;


        Ok(())
    }
}
