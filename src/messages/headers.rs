use rand::{Rng, thread_rng};
use std::{time::SystemTime, vec};
use crate::Error;
use super::{MessageType, PriorClaims};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DidcommHeader {
    pub id: usize,
    #[serde(rename = "type")]
    pub m_type: MessageType,
    pub to: Vec<String>,
    pub from: String,
    pub created_time: Option<usize>,
    pub expires_time: Option<usize>,
    /// A JWT, with sub: new DID and iss: prior DID, 
    /// with a signature from a key authorized by prior DID.
    from_prior: Option<PriorClaims>,
}

impl DidcommHeader {
    /// Constructor function with ~default values.
    pub fn new() -> Self {
        DidcommHeader {
            id: DidcommHeader::gen_random_id(),
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
    pub fn from_prior(&self) -> &Option<PriorClaims> {
        &self.from_prior
    }
    /// Creates set of DIDComm related headers with the static forward type
    ///
    pub fn forward(to: Vec<String>, from: String, expires_time: Option<usize>) -> Result<Self, Error> {
        Ok(DidcommHeader {
            id: rand::thread_rng().gen(),
            m_type: MessageType::Forward,
            to,
            from,
            created_time: Some(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as usize),
            expires_time,
            from_prior: None,
        })
    }
}

/// JWM Header as specifiead in [RFC](https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3)
/// With single deviation - allows raw text JWM to support DIDComm spec
/// `iv` property is not explicitly listed in the registered properties on the RFC but is present
///     within example lists - used here as DIDComm crypto nonce sharing property.
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JwmHeader {
    typ: String,
    // Some(String) if JWM is JWE encrypted.
    enc: Option<String>,
    // None if raw text message, Some(key ID) otherwise.
    kid: Option<String>,
    // None if raw text message, Some(String) for
    //  both JWE and/or JWS.
    alg: Option<String>,
    // Some(String) - serialized ephemeral public key.
    // TODO: implement proper struct for it:
    // https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3
    epk: Option<String>,
    // Some("JWM") should be used if nested JWS inside JWE.
    // None otherwise is *STRONGLY RECOMMENDED* by RFC.
    cty: Option<String>,
    // Nonce!
    iv: Vec<u8>,
}

impl JwmHeader {
    pub fn get_iv(&self) -> &[u8] {
        &self.iv
    }
    pub fn as_a256_gcm(self, kid: Option<String>, epk: Option<String>) -> Self {
        JwmHeader {
           enc: Some("A256GCM".into()),
           kid,
           epk,
           alg: Some("ECDH-ES+A256KW".into()),
           ..self
        }
    }
    pub fn as_es256(self, kid: Option<String>, alg: Option<String>) -> Self {
        JwmHeader {
           enc: None,
           kid, 
           alg,
           ..self
       }
    }
}

impl Default for JwmHeader {
    // Need to make sure nonce is 192 bytes long unigue for each message.
    // fill() does not have overload/optimizations for 192 bytes - split in two.
    //
    fn default() -> Self {
        let mut a: Vec<u8> = vec![0; 24];
        for v in &mut a {
            *v = rand::thread_rng().gen();
        }
        JwmHeader {
            typ: "JWM".into(),
            iv: a,
            enc: None,
            kid: None,
            epk: None,
            alg: None,
            cty: None,
        }
    }
}

#[test]
fn default_jwm_header_with_random_iv() {
    // Arrange
    let not_expected: Vec<u8> = vec![0; 24];
    // Act
    let h = JwmHeader::default();
    // Assert
    assert_ne!(not_expected, h.iv);
}
