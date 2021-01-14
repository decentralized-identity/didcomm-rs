// use std::convert::{ TryFrom, TryInto };
use crate::{ Error, JwmHeader, Message, crypto::SignatureAlgorithm };

#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    pub payload: String,
    pub protected: Option<JwmHeader>,
    pub header: Option<JwmHeader>,
    pub signature: Vec<u8>,
}

impl Jws {
    pub fn new(payload: String, header: JwmHeader, signature: Vec<u8>) -> Self {
        Jws {
            payload,
            protected: None,
            header: Some(header),
            signature
        }
    }
}
