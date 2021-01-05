use k256::{
    ecdsa::{
        SigningKey,
        VerifyingKey,
        Signature,
        signature::{
            Signer,
            Verifier,
        },
    },
};

use crate::{
    Error,
    SigningMethod,
    ValidationMethod,
};

use core::convert::TryFrom;

/// Signature related batteries for DIDComm.
/// Implementation of all algorithms required by (spec)[https://identity.foundation/didcomm-messaging/spec/#algorithms]
/// 
pub enum SignatureAlgorithm {
    EdDsa,
    Es256,
    /// `ECDSA/secp256k1` signatures.
    Es256k,
}

impl SignatureAlgorithm {
    /// Builds signer FnOnce, which performs signing.
    ///
    /// # Examples
    /// ```
    /// # fn main() {
    /// use didcomm_rs::crypto::signer::SignatureAlgorithm;
    /// let signer = SignatureAlgorithm::Es256k.signer();
    /// # }
    ///```
    ///
    pub fn signer(&self) -> SigningMethod {
        match self {
            SignatureAlgorithm::EdDsa => {
                todo!()
            },
            SignatureAlgorithm::Es256 => {
                todo!()
            },
            SignatureAlgorithm::Es256k => {
                Box::new(|key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    let sk = SigningKey::from_bytes(key)
                        .map_err(|e| Error::Generic(e.to_string()))?;
                    let signature: Signature = sk.sign(message);
                    Ok(signature.as_ref().to_vec())
                })
            }
        }
    }
    /// Builds validator FnOnce, which performs signature validation.
    ///
    /// # Examples
    /// ```
    /// # fn main() {
    /// use didcomm_rs::crypto::signer::SignatureAlgorithm;
    /// let validator = SignatureAlgorithm::Es256k.validator();
    /// # }
    /// ```
    ///
    pub fn validator(&self) -> ValidationMethod {
        match self {
            SignatureAlgorithm::EdDsa => {
                todo!()
            },
            SignatureAlgorithm::Es256 => {
                todo!()
            },
            SignatureAlgorithm::Es256k => {
                Box::new(|key: &[u8], message: &[u8], signature: &[u8]| -> Result<bool, Error> {
                    let vk = VerifyingKey::from_sec1_bytes(key)
                        .map_err(|e| Error::Generic(e.to_string()))?;
                    let signature = Signature::try_from(signature)
                        .map_err(|e| Error::Generic(e.to_string()))?;
                    Ok(vk.verify(message, &signature).is_ok())
                })
            }
        }
    }
}

#[test]
fn es256k_test() {
    // Arrange
    let sk = SigningKey::random(&mut rand_core::OsRng);
    let vk = &sk.verify_key();
    let m = b"this is the message we're signing in this test...";
    // Act
    let signer = SignatureAlgorithm::Es256k.signer();
    let validator = SignatureAlgorithm::Es256k.validator();
    let signature = signer(&sk.to_bytes(), m);
    let validation = validator(&vk.to_bytes(), m, &signature.unwrap());
    // Assert
    assert!(&validation.is_ok());
    assert!(validation.unwrap());
}
