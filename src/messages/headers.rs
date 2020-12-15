use rand::Rng;
use biscuit::ClaimsSet;
use std::time::SystemTime;
use crate::Error;
use super::{MessageType, PriorClaims};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Headers {
    pub id: usize,
    #[serde(rename = "type")]
    pub m_type: MessageType,
    pub to: Vec<String>,
    pub from: String,
    pub created_time: Option<usize>,
    pub expires_time: Option<usize>,
    /// A JWT, with sub: new DID and iss: prior DID, 
    /// with a signature from a key authorized by prior DID.
    from_prior: Option<ClaimsSet<PriorClaims>>,
}

impl Headers {
    /// Constructor function with ~default values.
    pub fn new() -> Self {
        Headers {
            id: Headers::gen_random_id(),
            m_type: MessageType::DidcommUnknown,
            to: vec!(String::default()),
            from: String::default(),
            created_time: None,
            expires_time: None,
            from_prior: None,
        }
    }
    /// Generates random `id`
    /// TODO: Should this be public?
    pub fn gen_random_id() -> usize {
            rand::thread_rng().gen()
    }
    /// Getter method for `from_prior` retreival
    ///
    pub fn from_prior(&self) -> &Option<ClaimsSet<PriorClaims>> {
        &self.from_prior
    }
    /// Creates set of DIDComm related headers with the static forward type
    ///
    pub fn forward(to: Vec<String>, from: String, expires_time: Option<usize>) -> Result<Self, Error> {
        Ok(Headers {
            id: rand::thread_rng().gen(),
            m_type: MessageType::Forward,
            to,
            from,
            created_time: Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as usize),
            expires_time,
            from_prior: None,
        })
    }
    /// Creates set of DIDComm related headers for the JWE envelope over JWS
    ///
    pub fn encrypt_jws(wrapped: Headers)
        -> Result<Self, Error> {
        Ok(Headers {
            id: rand::thread_rng().gen(),
            m_type: MessageType::DidcommJwe,
            created_time: Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as usize),
            ..wrapped
        })
    }
}