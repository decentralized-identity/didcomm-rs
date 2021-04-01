use super::{
    Shape,
    Message,
    didurl::DidUrl,
};
use crate::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct Mediated {
    pub next: DidUrl,
    #[serde(rename = "payloads~attach")]
    pub payload: Vec<u8>
}

impl Mediated {
    /// Constructor with empty payload
    /// # Parameters
    /// *next - `DidUrl` of delivery target.
    ///
    pub fn new(next: DidUrl) -> Self {
        Mediated{
            next,
            payload: vec!()
        }
    }
    /// Payload setter to be chained in forwarding calls.
    ///
    /// # Example
    /// ```rust
    /// use std::str::FromStr;
    /// use didcomm_rs::{Mediated, DidUrl};
    /// let warpper_payload = Mediated::new(DidUrl::from_str("did:key:abc").unwrap())
    ///     .with_payload(b"hello, abc".to_vec());
    /// ```
    ///
    pub fn with_payload(self, payload: Vec<u8>) -> Self {
        Mediated {
            payload,
            ..self
        }
    }
}

impl Shape for Mediated {
   type Err = Error;
   fn shape(m: &Message) -> Result<Self, Self::Err> {
       serde_json::from_slice(&m.body)
           .map_err(|e| Error::SerdeError(e))
   }
}

