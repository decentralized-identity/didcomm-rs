use std::{collections::HashMap, time::SystemTime};

use crate::{Error, PriorClaims};

/// Collection of DIDComm message specific headers, will be flattened into DIDComm plain message
/// according to [spec](https://datatracker.ietf.org/doc/html/draft-looker-jwm-01#section-4).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DidCommHeader {
    pub id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,

    #[serde(rename = "type")]
    pub m_type: String,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,

    pub from: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,

    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) other: HashMap<String, String>,

    /// A JWT, with sub: new DID and iss: prior DID,
    /// with a signature from a key authorized by prior DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    from_prior: Option<PriorClaims>,
}

impl DidCommHeader {
    /// Constructor function with ~default values.
    pub fn new() -> Self {
        DidCommHeader {
            id: DidCommHeader::gen_random_id(),
            thid: None,
            pthid: None,
            m_type: "JWM".into(),
            to: vec![String::default()],
            from: Some(String::default()),
            created_time: None,
            expires_time: None,
            from_prior: None,
            other: HashMap::new(),
        }
    }

    /// Generates random `id`
    /// TODO: Should this be public?
    pub fn gen_random_id() -> String {
        return uuid::Uuid::new_v4().to_string();
    }

    /// Returns DIDComm message URI as defined by spec:
    /// https://identity.foundation/didcomm-messaging/spec/#didcomm-message-uris
    pub fn get_message_uri(&self) -> String {
        format!(
            "didcomm://{}{}{}",
            self.id,
            self.thid.clone().unwrap_or_default(),
            self.pthid.clone().unwrap_or_default(),
        )
    }

    /// Sets current message's `thid` and `pthid` to one from `replying_to`
    /// Also adds `replying_to.from` into `to` set.
    ///
    /// # Parameters
    ///
    /// * `replying_to` - ref to header we're replying
    pub fn reply_to(&mut self, replying_to: &Self) {
        self.thid = replying_to.thid.clone();
        self.pthid = replying_to.pthid.clone();
        self.to.push(replying_to.from.clone().unwrap_or_default());
    }

    /// Getter method for `from_prior` retrieval
    pub fn from_prior(&self) -> Option<&PriorClaims> {
        self.from_prior.as_ref()
    }

    /// Creates set of DIDComm related headers with the static forward type
    pub fn forward(
        to: Vec<String>,
        from: Option<String>,
        expires_time: Option<u64>,
    ) -> Result<Self, Error> {
        Ok(DidCommHeader {
            to,
            from,
            created_time: Some(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
            ),
            expires_time,
            ..DidCommHeader::new()
        })
    }
}

impl Default for DidCommHeader {
    fn default() -> Self {
        DidCommHeader::new()
    }
}
