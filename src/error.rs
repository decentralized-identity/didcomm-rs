#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("plugged cryptography failure")]
    PlugCryptoFailure,
    #[error("not a rotation message")]
    NoRotationData,
    #[error("malformed DID string")]
    BadDid,
    #[error("{0}")]
    Generic(String),
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    RegexError(#[from] regex::Error),
    #[error(transparent)]
    BisquitError(#[from] biscuit::errors::Error),
    #[error(transparent)]
    StringConversionError(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Other(Box<dyn std::error::Error>),
}