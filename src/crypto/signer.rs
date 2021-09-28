use std::convert::TryFrom;

use super::*;

/// Signature related batteries for DIDComm.
/// Implementation of all algorithms required by [spec](https://identity.foundation/didcomm-messaging/spec/#algorithms)
#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    /// `ed25519` signature
    EdDsa,
    /// `ECDSA/P-256` NIST signature
    Es256,
    /// `ECDSA/secp256k1` signature
    Es256k,
}

impl Signer for SignatureAlgorithm {
    /// Builds signer FnOnce, which performs signing.
    ///
    /// # Examples
    /// ```
    /// # fn main() {
    /// use didcomm_rs::crypto::{SignatureAlgorithm, Signer};
    /// let signer = SignatureAlgorithm::Es256k.signer();
    /// # }
    ///```
    fn signer(&self) -> SigningMethod {
        match self {
            // an &[u8] representing the scalar for the secret key, and a compressed Edwards-Y coordinate of a point on curve25519, both as bytes.
            SignatureAlgorithm::EdDsa => {
                Box::new(|key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    use ed25519_dalek::{Keypair, Signer};
                    let key = Keypair::from_bytes(key)?;
                    let s = key.sign(message);
                    Ok(s.to_bytes().to_vec())
                })
            }
            SignatureAlgorithm::Es256 => {
                Box::new(|key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
                    let sk = SigningKey::new(key)?;
                    let signature: Signature = sk.sign(message);
                    Ok(signature.as_ref().to_vec())
                })
            }
            SignatureAlgorithm::Es256k => {
                Box::new(|key: &[u8], message: &[u8]| -> Result<Vec<u8>, Error> {
                    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
                    let sk = SigningKey::new(key).map_err(|e| Error::Generic(e.to_string()))?;
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
    /// use didcomm_rs::crypto::{Signer, SignatureAlgorithm};
    /// let validator = SignatureAlgorithm::Es256k.validator();
    /// # }
    /// ```
    fn validator(&self) -> ValidationMethod {
        match self {
            SignatureAlgorithm::EdDsa => Box::new(
                |key: &[u8], message: &[u8], signature: &[u8]| -> Result<bool, Error> {
                    use ed25519_dalek::{PublicKey, Signature, Verifier};
                    let key = PublicKey::from_bytes(key)?;
                    let s = Signature::try_from(signature)?;
                    Ok(key.verify(message, &s).is_ok())
                },
            ),
            SignatureAlgorithm::Es256 => Box::new(
                |key: &[u8], message: &[u8], signature: &[u8]| -> Result<bool, Error> {
                    use p256::ecdsa::{signature::Verifier, Signature, VerifyKey};
                    let key = VerifyKey::new(key)?;
                    let s = Signature::try_from(signature)?;
                    Ok(key.verify(message, &s).is_ok())
                },
            ),
            SignatureAlgorithm::Es256k => Box::new(
                |key: &[u8], message: &[u8], signature: &[u8]| -> Result<bool, Error> {
                    use k256::ecdsa::{signature::Verifier, Signature, VerifyKey};
                    let vk = VerifyKey::new(key)?;
                    let signature = Signature::try_from(signature)?;
                    Ok(vk.verify(message, &signature).is_ok())
                },
            ),
        }
    }
}

impl TryFrom<&String> for SignatureAlgorithm {
    type Error = Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        match &value[..] {
            "EdDSA" => Ok(Self::EdDsa),
            "ES256" => Ok(Self::Es256),
            "ES256K" => Ok(Self::Es256k),
            _ => Err(Error::JwsParseError),
        }
    }
}

#[test]
fn es256k_test() {
    use k256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
    // Arrange
    let sk = SigningKey::random(&mut OsRng);
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
