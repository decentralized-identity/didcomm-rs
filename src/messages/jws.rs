// use std::convert::{ TryFrom, TryInto };
use crate::{ Error, JwmHeader, Message, crypto::SignatureAlgorithm };

#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    payload: String,
    protected: JwmHeader,
    header: JwmHeader,
    signature: Vec<u8>,
}
