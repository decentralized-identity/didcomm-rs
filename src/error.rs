#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("plugged cryptography failure")]
    PlugCryptoFailure,
    #[error("not a rotation message")]
    NoRotationData,
    #[error("malformed DID string")]
    BadDid,
    #[error("not a JWE compact representation")]
    JweCompactParseError,
    #[error("not a JWS compact representation")]
    JwsParseError,
    #[error("failed to parse as JWE")]
    JweParseError,
    #[error("{0}")]
    Generic(String),
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    RegexError(#[from] regex::Error),
    #[cfg(feature = "jose-biscuit")]
    #[error(transparent)]
    BisquitError(#[from] biscuit::errors::Error),
    #[cfg(feature = "raw-crypto")]
    #[error(transparent)]
    EdDsaError(#[from] ed25519_dalek::SignatureError),
    #[error(transparent)]
    StringConversionError(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    #[error(transparent)]
    Other(Box<dyn std::error::Error>),
}
