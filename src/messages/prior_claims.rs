use crate::Error;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct PriorClaims {
    sub: String,

    iss: String,
}

impl PriorClaims {
    pub fn from_string(jwt: String) -> Result<Self, Error> {
        Ok(serde_json::from_str(&jwt)?)
    }

    pub fn from_bytes(jwt: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_string(String::from_utf8(jwt.to_vec())?)?)
    }
}
