use super::{Message, Shape};
use crate::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct Mediated {
    pub next: String,

    #[serde(rename = "payloads~attach")]
    pub payload: Vec<u8>,
}

impl Mediated {
    /// Constructor with empty payload
    /// # Parameters
    /// *next - `DidUrl` of delivery target.
    pub fn new(next: String) -> Self {
        Mediated {
            next,
            payload: vec![],
        }
    }

    /// Payload setter to be chained in forwarding calls.
    ///
    /// # Example
    /// ```rust
    /// use std::str::FromStr;
    /// use didcomm_rs::Mediated;
    /// let wrapper_payload = Mediated::new("did:key:abc".into())
    ///     .with_payload(b"hello, abc".to_vec());
    /// ```
    ///
    pub fn with_payload(self, payload: Vec<u8>) -> Self {
        Mediated { payload, ..self }
    }
}

impl Shape for Mediated {
    type Err = Error;

    fn shape(m: &Message) -> Result<Self, Self::Err> {
        serde_json::from_str::<Mediated>(&serde_json::to_string(&m.get_body()?)?)
            .map_err(|e| Error::SerdeError(e))
    }
}
