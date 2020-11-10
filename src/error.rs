#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("plugged cryptography failure")]
    PlugCryptoFailure,
    #[error("not a rotation message")]
    NoRotationData,
    #[error(transparent)]
    SerdeError(#[from] serde_json::Error),
    #[error(transparent)]
    Other(Box<dyn std::error::Error>),
}