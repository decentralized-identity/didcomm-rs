#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("plugged cryptography failure")]
    PlugCryptoFailure,
    #[error("not a rotation message")]
    NoRotationData,
    #[error("malformed DID string")]
    BadDid,
    #[error("no recepient set for jwe")]
    NoJweRecepient,
    #[error("not a JWS compact representation")]
    JwsParseError,
    #[error("failed to parse as JWE")]
    JweParseError,
    #[error("JWM header parsing failed - malformed alg")]
    JwmHeaderParseError,
    #[error("cannot resolve did document from JWE header from field")]
    DidResolveFailed,
    #[error("invalid key size {0}")]
    InvalidKeySize(String),
    #[error("{0} is not set")]
    PropertyIsNotSet(&'static str),
    #[error("{0}")]
    Generic(String),
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    RegexError(#[from] regex::Error),
    #[cfg(feature = "jose-biscuit")]
    #[error(transparent)]
    BisquitError(#[from] biscuit::errors::Error),
    #[error(transparent)]
    TryFromError(#[from] core::convert::Infallible),
    #[cfg(feature = "raw-crypto")]
    #[error(transparent)]
    EdDsaError(#[from] ed25519_dalek::SignatureError),
    #[error(transparent)]
    StringConversionError(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Base64DecodeError(#[from] base64_url::base64::DecodeError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error>),
}
