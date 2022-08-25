use std::{convert::TryFrom, str::FromStr};

use crate::Error as CrateError;

/// header used for [DID rotation](https://identity.foundation/didcomm-messaging/spec/#did-rotation)
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PriorClaims {
    sub: Option<String>,

    iss: String,
}

impl FromStr for PriorClaims {
    type Err = CrateError;

    fn from_str(jwt: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(jwt)?)
    }
}

impl TryFrom<&[u8]> for PriorClaims {
    type Error = CrateError;

    fn try_from(jwt: &[u8]) -> Result<Self, Self::Error> {
        std::str::from_utf8(jwt)?.parse::<Self>()
    }
}
