use std::convert::TryFrom;

use regex::Regex;
use crate::Error;

#[derive(Serialize, Deserialize, Clone)]
pub struct GenericDid {
    #[serde(rename = "@context", skip_serializing_if = "String::is_empty", default)]
    context: String,
    id: String,
    #[serde(rename = "publicKey", skip_serializing_if = "Vec::is_empty", default)]
    public_key: Vec<u8>,
    authentication: Vec<Authentication>,
    serviec: Vec<Service>,
}

impl TryFrom<String> for GenericDid {
    type Error = Error;

    fn try_from(_: String) -> Result<Self, Error> {
        let r = Regex::new("")?;
        todo!()
    }

}

#[derive(Serialize, Deserialize, Clone)]
pub struct Authentication {

}

#[derive(Serialize, Deserialize, Clone)]
pub struct Service {

}