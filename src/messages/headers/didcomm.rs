use std::{collections::HashMap, time::SystemTime};

use crate::{Error, PriorClaims, Thread};

/// Collection of DIDComm message specific headers, will be flattened into DIDComm plain message
/// according to [spec](https://datatracker.ietf.org/doc/html/draft-looker-jwm-01#section-4).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
    /// A JWT, with sub: new DID and iss: prior DID,
    /// with a signature from a key authorized by prior DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    from_prior: Option<PriorClaims>,

    /// Optional thread decorator.
    #[serde(skip_serializing_if = "Option::is_none", rename = "~thread")]
    pub thread: Option<Thread>,
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub(crate) other: HashMap<String, String>,
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
            thread: None,
            other: HashMap::new(),
        }
    }

    /// Generates random `id`
    /// TODO: Should this be public?
    pub fn gen_random_id() -> String {
        uuid::Uuid::new_v4().to_string()
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

    /// Sets new message's header `thid` and `pthid` using sender's header.
    /// It also adds `sender_header.from` into `to` set.
    ///
    /// # Parameters
    ///
    /// * `sender_header` - ref to header we're replying
    pub fn reply_to(&mut self, sender_header: &Self) {
        match sender_header.thread {
            Some(ref thread) if thread.is_implicit_reply(&sender_header.id) => {
                let thid = sender_header.thread.as_ref().unwrap().thid.clone();
                // Do we need this?
                self.thread = Some(Thread::implicit_reply(&thid));
                self.thid = Some(thid);
            }
            _ => {
                self.thid = sender_header.thid.clone();
                self.pthid = sender_header.pthid.clone();
            }
        };
        self.to.push(sender_header.from.clone().unwrap_or_default());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_to_can_use_decorate_if_present() {
        let _header = DidCommHeader::default();
    }
}
