use super::{
    Shape,
    Message,
    didurl::DidUrl,
};
use crate::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct Mediated {
    next: DidUrl,
    #[serde(rename = "payloads~attach")]
    payload: Vec<u8>
}

impl Shape for Mediated {
   type Err = Error;
   fn shape(m: &Message) -> Result<Self, Self::Err> {
       serde_json::from_slice(&m.body)
           .map_err(|e| Error::SerdeError(e))
   }
}

