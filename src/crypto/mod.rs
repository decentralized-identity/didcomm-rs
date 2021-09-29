//! Collection of utilities for cryptography related components.
pub mod encryptor;
pub mod signer;

#[cfg(feature = "raw-crypto")]
pub use {encryptor::CryptoAlgorithm, signer::SignatureAlgorithm};

pub use crate::Error;

/// Return `FnOnce` signature definition for symmetric cryptography method.
/// Arguments sequence: Nonce, Key, Message.
pub type SymmetricCypherMethod = Box<dyn Fn(&[u8], &[u8], &[u8], &[u8]) -> Result<Vec<u8>, Error>>;

/// Return `FnOnce` signature definition for asymmetric cryptography method.
/// Arguments sequence: Nonce, Key, Message.
pub type AsymmetricCypherMethod = Box<dyn Fn(&[u8], &[u8], &[u8], &[u8]) -> Result<Vec<u8>, Error>>;

/// Return `FnOnce` signature definition for signature signing method.
/// .0 == `key: &[u8]`; .1 == `message`;
pub type SigningMethod = Box<dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Error>>;

/// Return `FnOnce` signature definition for signature validating method.
/// .0 == `key: &[u8]`; .1 == `message`; .2 == `signature`;
pub type ValidationMethod = Box<dyn Fn(&[u8], &[u8], &[u8]) -> Result<bool, Error>>;

/// Trait must be implemented for pluggable cryptography.
/// Implemented by `CryptoAlgorithm` with `raw-crypto` feature.
pub trait Cypher {
    fn encryptor(&self) -> SymmetricCypherMethod;
    fn decryptor(&self) -> SymmetricCypherMethod;
    fn asymmetric_encryptor(&self) -> AsymmetricCypherMethod;
}

/// Trait must be implemented for pluggable signatures.
/// Implemented by `SignatureAlgorithm` with `raw-crypto` feature.
pub trait Signer {
    fn signer(&self) -> SigningMethod;
    fn validator(&self) -> ValidationMethod;
}
