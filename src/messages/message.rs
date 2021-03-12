use std::{convert::TryInto, time::SystemTime};
use serde::{Serialize, Deserialize};
use super::{
    headers::{DidcommHeader, JwmHeader},
    prior_claims::PriorClaims,
};
#[cfg(feature = "resolve")]
pub use ddoresolver_rs::*;
#[cfg(feature = "resolve")]
use arrayref::array_ref;
#[cfg(feature = "resolve")]
use x25519_dalek::{
    StaticSecret,
    PublicKey
};
use crate::{
    Error,
    Jwe,
    MessageType,
    crypto::{
        CryptoAlgorithm,
        SignatureAlgorithm,
        Cypher,
        Signer,
    },
};

/// DIDComm message structure.
/// [Specification](https://identity.foundation/didcomm-messaging/spec/#message-structure)
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Message {
    /// JOSE header, which is sent as public part with JWE.
    #[serde(flatten)]
    pub jwm_header: JwmHeader,
    /// DIDComm headers part, sent as part of encrypted message in JWE.
    #[serde(flatten)]
    didcomm_header: DidcommHeader,
    /// Message payload, which can be basically anything (JSON, text, file, etc.) represented
    ///     as bytes of data.
    pub body: Vec<u8>,
}

impl Message {
    /// Generates EMPTY default message.
    /// Use extension messages to build final one before `send`ing.
    ///
    pub fn new() -> Self {
        Message {
            jwm_header: JwmHeader::default(),
            didcomm_header: DidcommHeader::new(),
            body: vec!(),
        }
    }
    /// Setter of `from` header
    /// Helper method.
    ///
    pub fn from(mut self, from: &str) -> Self {
        self.didcomm_header.from = Some(String::from(from));
        self
    }
    /// Setter of `to` header
    /// Helper method.
    ///
    pub fn to(mut self, to: &[&str]) -> Self {
        for s in to {
            self.didcomm_header.to.push(s.to_string());
        }
        while let Some(a) = self.didcomm_header.to.iter().position(|e| e == &String::default()) {
            self.didcomm_header.to.remove(a);
        }
        self
    }
    /// Setter of `m_type` @type header
    /// Helper method.
    ///
    pub fn m_type(mut self, m_type: MessageType) -> Self {
        self.didcomm_header.m_type = m_type;
        self
    }
    /// Setter of the `body`
    /// Helper method.
    ///
    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }
    // Setter of the `kid` header
    // Helper method.
    //
    pub fn kid(mut self, kid: &str) -> Self {
        match &mut self.jwm_header.kid {
            Some(h) => *h = kid.into(),
            None => {
                self.jwm_header.kid = Some(kid.into());
            }
        }
        self
    }
    /// Sets times of creation as now and, optional, expires time.
    /// # Parameters
    /// * `expires` - time in seconds since Unix Epoch when message is
    /// considered to be invalid.
    ///
    pub fn timed(mut self, expires: Option<u64>) -> Self {
        self.didcomm_header.expires_time = expires;
        self.didcomm_header.created_time = 
            match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(t) => Some(t.as_secs()),
                Err(_) => None,
            };
        self
    }
    /// Checks if message is rotation one.
    /// Exposed for explicit checks on calling code level.
    ///
    pub fn is_rotation(&self) -> bool {
        self.didcomm_header.from_prior().is_some()
    }
    /// If message `is_rotation()` true - returns from_prion claims.
    /// Errors otherwise with `Error::NoRotationData`
    /// 
    pub fn get_prior(&self) -> Result<PriorClaims, Error> {
        if self.is_rotation() {
            Ok(self.didcomm_header.from_prior().clone().unwrap())
        } else {
           Err(Error::NoRotationData)
        }
    }
    /// `&DidcommHeader` getter.
    ///
    pub fn get_didcomm_header(&self) -> &DidcommHeader {
        &self.didcomm_header
    }
    /// Setter of `didcomm_header`.
    /// Replaces existing one with provided by consuming both values.
    /// Returns modified instance of `Self`.
    ///
    pub fn set_didcomm_header(mut self, h: DidcommHeader) -> Self {
        self.didcomm_header = h;
        self
    }
    /// Adds (or updates) custom unique header key-value pair to the header.
    /// This portion of header is not sent as JOSE header.
    ///
    pub fn add_header_field(mut self, key: String, value: String) -> Self {
        if key.len() == 0 {
            return self;
        }
        self.didcomm_header.other.insert(key, value);
        self
    }
    /// Creates set of Jwm related headers for the JWE
    /// Modifies JWM related header portion to match
    ///     encryption implementation and leaves other
    ///     parts unchanged.  TODO + FIXME: complete implementation
    pub fn as_jws(mut self, alg: &SignatureAlgorithm) -> Self {
        self.jwm_header.as_signed(alg);
        self
    }
    /// Creates set of Jwm related headers for the JWS
    /// Modifies JWM related header portion to match
    ///     signature implementation and leaves Other
    ///     parts unchanged.
    ///
    /// For `resolve` feature will set `kid` header automatically
    ///     based on the did document resolved.
    ///
    pub fn as_jwe(mut self, alg: &CryptoAlgorithm) -> Self {
        self.jwm_header.as_encrypted(alg);
        #[cfg(feature = "resolve")]
        {
            if let Some(from) = &self.didcomm_header.from {
                if let Some(document) = resolve_any(from) {
                    match alg {
                        CryptoAlgorithm::XC20P => 
                                self.jwm_header.kid = 
                                    document.find_public_key_id_for_curve("X25519"),
                        CryptoAlgorithm::A256GCM => todo!()
                    }
                }
            }
        }
        self
    }
    /// Serializez current state of the message into json.
    /// Consumes original message - use as raw sealing of envelope.
    ///
    pub fn as_raw_json(self) -> Result<String, Error> {
        Ok(serde_json::to_string(&self)?)
    }
    /// Seals self and returns ready to send JWE
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    // TODO: Feature-gate(split) this ("raw-crypto" / "jose-biscuit")?
    // TODO: Add examples
    #[cfg(not(feature = "resolve"))]
    pub fn seal(self, ek: &[u8]) -> Result<String, Error> {
        let alg = crypter_from_header(&self.jwm_header)?;
        self.encrypt(alg.encryptor(), ek)
    }
    #[cfg(feature = "resolve")]
    pub fn seal(self, sk: &[u8]) -> Result<String, Error> {
        if sk.len() != 32 { return Err(Error::InvalidKeySize("!32".into())); }
        if let Some(document) = resolve_any(&self.didcomm_header.to[0]) { // FIXME: should pack one for each recepient
            if let Some(agreement) = document.find_public_key_for_curve("X25519") {
                let shared = StaticSecret::from(array_ref!(sk, 0, 32).to_owned())
                    .diffie_hellman(&PublicKey::from(array_ref!(agreement, 0, 32).to_owned()));
                let alg = crypter_from_header(&self.jwm_header)?;
                self.encrypt(alg.encryptor(), shared.as_bytes())
            } else {
                Err(Error::DidResolveFailed)
            }
        } else {
            Err(Error::DidResolveFailed)
        }
    }
    /// Signs raw message and then packs it to encrypted envelope
    /// [Spec](https://identity.foundation/didcomm-messaging/spec/#message-signing)
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `sk` - signing key for enveloped message JWS encryption
    // TODO: Adde examples
    // 
    pub fn seal_signed(
        self,
        ek: &[u8],
        sk: &[u8],
        signing_algorithm: SignatureAlgorithm) 
    -> Result<String, Error> {
        let mut to = self.clone();
        let signed = self
            .as_jws(&signing_algorithm)
            .sign(signing_algorithm.signer(), sk)?;
        to.body = signed.as_bytes().to_vec();
        return to
            .m_type(MessageType::DidcommJws)
            .seal(ek);
    }
    // #[cfg(feature = "resolve")]
    // pub fn seal_signed(
    //     self,
    //     ek: &[u8],
    //     sk
    //     signing_algorithm: SignatureAlgorithm
    // ) -> Result<String, Error> {

    // }
    /// Wrap self to be mediated by some mediator.
    /// Warning: Should be called on a `Message` instance which is ready to be sent!
    /// If message is not properly set up for crypto - this method will propogate error from
    ///     called `.seal()` method.
    /// Takes one mediator at a time to make sure that mediated chain preserves unchanged.
    /// This method can be chained any number of times to match all the mediators in the chain.
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `to` - list of destination recepients. can be empty (Optional) `String::default()`
    ///
    /// `form` - used same as in wrapped message, fails if not present with `DidResolveFailed` error.
    ///
    /// TODO: Add examples
    pub fn routed_by(self, ek: &[u8], to: &[&str])
        -> Result<Self, Error> {
            let h = match &self.get_didcomm_header().from.clone() {
                Some(s) => s.to_owned(),
                None => String::default(),
            };
            let to_wrap: String;
            to_wrap = self.seal(ek)?;
            Ok(Message::new()
                .to(to)
                .from(&h)
                .m_type(MessageType::Forward)
                .body(to_wrap.as_bytes()))
    }
}

fn crypter_from_header(header: &JwmHeader) -> Result<CryptoAlgorithm, Error> {
    match &header.alg {
        None => Err(Error::JweParseError),
        Some(alg) => alg.try_into()
    }
}

/// Associated functions implementations.
/// Possibly not required as Jwe serialization covers this.
///
impl Message {
    /// Parses `iv` value as `Vec<u8>` from public header.
    /// Both regular JSON and Compact representations are accepted.
    /// Returns `Error` on failure.
    /// TODO: Add examples
    pub fn get_iv(received: &[u8]) -> Result<Vec<u8>, Error> {
        // parse from compact
        let as_str = String::from_utf8(received.to_vec())?;
        let json: serde_json::Value =
            if let Some(header_end) = as_str.find('.') {
                    serde_json::from_str(
                        &String::from_utf8(
                            base64_url::decode(&as_str[..header_end])?
                        )?
                    )?
            } else {
                serde_json::from_str(&as_str)?
            };
        if let Some(iv) = json.get("iv") {
            if let Some(t) = iv.as_str() {
            if t.len() != 24 {
                Err(Error::Generic(format!("IV [nonce] size is incorrect: {}", t.len())))
            } else {
                Ok(t.as_bytes().to_vec())
            }
            } else { 
                Err(Error::Generic("wrong nonce format".into()))
            }
        } else {
            Err(Error::Generic("iv is not found in JOSE header".into()))
        }
    }
    /// Construct a message from received data.
    /// Raw or JWE payload is accepted.
    ///
    #[cfg(not(feature = "resolve"))]
    pub fn receive(incomming: &str, crypto_key: Option<&[u8]>, validation_key: Option<&[u8]>) -> Result<Self, Error> {
        match crypto_key {
            None => serde_json::from_str(incomming)
                .map_err(|e| Error::SerdeError(e)),
            Some(key) => { // TODO: compact parsing validation should be here
                let jwe: Jwe = serde_json::from_str(&incomming)?;
                // Here we have JWE
                if let Some(alg) = &jwe.header.alg {
                    let a: CryptoAlgorithm = alg.try_into()?;
                    // TODO: public-private header validation should be here?
                    let m = Message::decrypt(incomming.as_bytes(), a.decryptor(), key)?;
                    // TODO: hate this tree - needs some refactoring
                    if &m.didcomm_header.m_type == &MessageType::DidcommJws {
                        if let Some(val_key) = validation_key {
                            Message::verify(&m.body, val_key)
                        } else {
                            Err(Error::Generic(String::from("Validation key is missing")))
                        }
                    } else {
                        Ok(m)
                    }
                } else { 
                    Err(Error::JweParseError)
                }
            }
        }
    }
    #[cfg(feature = "resolve")]
    pub fn receive(incomming: &str, sk: &[u8]) -> Result<Self, Error> {
        let jwe: Jwe = serde_json::from_str(incomming)?;
        if jwe.from().is_none() { return Err(Error::DidResolveFailed); }
        if let Some(document) = ddoresolver_rs::resolve_any(&jwe.from().to_owned().unwrap()) {
            if let Some(alg) = &jwe.header.alg {
                if let Some(k_arg) = document.find_public_key_for_curve("X25519") {
                    let shared = StaticSecret::from(array_ref!(sk, 0, 32).to_owned())
                        .diffie_hellman(&PublicKey::from(array_ref!(k_arg, 0, 32).to_owned()));
                    let a: CryptoAlgorithm = alg.try_into()?;
                    let m = Message::decrypt(incomming.as_bytes(), a.decryptor(), shared.as_bytes())?;
                    if &m.didcomm_header.m_type == &MessageType::DidcommJws {
                        if m.jwm_header.alg.is_none() { return Err(Error::JweParseError); }
                        if let Some(verifying_key) = document.find_public_key_for_curve(&m.jwm_header.alg.unwrap()) {
                            Ok(Message::verify(&m.body, &verifying_key)?)
                        } else {
                            Err(Error::JwsParseError)
                        }
                    } else {
                        Ok(m)
                    }
                } else {
                    Err(Error::BadDid)
                }
            } else {
                Err(Error::JweParseError)
            }
        } else {
            Err(Error::DidResolveFailed)
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn iv_from_json_test() {
        // Arrange
        // Example JWM from RFC: https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3
        // Extendet twice to be 192bit (24byte) nonce.
        let raw_json = r#" { "protected": "eyJ0eXAiOiJKV00iLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiUEdvWHpzME5XYVJfbWVLZ1RaTGJFdURvU1ZUYUZ1eXJiV0k3VjlkcGpDZyIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLU5oN1NoUkJfeGFDQlpSZElpVkN1bDNTb1IwWXc0VEdFUXFxR2lqMXZKcyIsInkiOiI5dEx4ODFQTWZRa3JPdzh5dUkyWXdJMG83TXROemFDR2ZDQmJaQlc1WXJNIn19",
                "recipients": [
                  {
                    "encrypted_key": "J1Fs9JaDjOT_5481ORQWfEZmHy7OjE3pTNKccnK7hlqjxbPalQWWLg"
                  }
                ],
                "iv": "u5kIzo0m_d2PjI4mu5kIzo0m",
                "ciphertext": "qGuFFoHy7HBmkf2BaY6eREwzEjn6O_FnRoXj2H-DAXo1PgQdfON-_1QbxtnT8e8z_M6Gown7s8fLtYNmIHAuixqFQnSA4fdMcMSi02z1MYEn2JC-1EkVbWr4TqQgFP1EyymB6XjCWDiwTYd2xpKoUshu8WW601HLSgFIRUG3-cK_ZSdFaoWosIgAH5EQ2ayJkRB_7dXuo9Bi1MK6TYGZKezc6rpCK_VRSnLXhFwa1C3T0QBes",
                "tag": "doeAoagwJe9BwKayfcduiw"
            }"#;
        // Act
        let iv = Message::get_iv(raw_json.as_bytes());
        // Assert
        assert!(iv.is_ok());
        assert_eq!("u5kIzo0m_d2PjI4mu5kIzo0m", &String::from_utf8(iv.unwrap()).unwrap());
    }
    #[test]
    fn iv_from_compact_json_test() {
        // Arrange
        // Example JWM from RFC: https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3
        let compact = r#"eyJ0eXAiOiJKV00iLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiUEdvWHpzME5XYVJfbWVLZ1RaTGJFdURvU1ZUYUZ1eXJiV0k3VjlkcGpDZyIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwiaXYiOiAidTVrSXpvMG1fZDJQakk0bXU1a0l6bzBtIn0."#;
        // Act
        let iv = Message::get_iv(compact.as_bytes());
        // Assert
        assert!(iv.is_ok());
        assert_eq!("u5kIzo0m_d2PjI4mu5kIzo0m", &String::from_utf8(iv.unwrap()).unwrap());
    }
}

#[cfg(test)]
mod crypto_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;

    #[cfg(feature = "resolve")]
    use base58::FromBase58;

    // use crate::Error;
   use super::*;

    #[test]
    #[cfg(not(feature = "resolve"))]
    fn receive_test() {
        // Arrange
        let received_jwe = r#"{"typ":"JWM","enc":"A256GCM","alg":"ECDH-ES+A256KW","iv":[222,55,121,212,26,150,141,210,48,185,246,138,32,22,45,133,228,160,150,177,17,158,190,224],"id":4351085393442299745,"type":"didcomm/unknown","to":["did:keri:usath909guh43y3slrih01hurdesntuhir0#90887"],"from":"did:keri:ulrchpl0940hu1092hoxkhp90#ucbpuei9","ciphertext":[222,225,218,187,202,113,141,242,209,52,161,232,221,47,154,87,33,190,83,39,189,167,177,23,86,181,37,104,202,145,80,26,90,161,105,53,56,145,151,235,181,35,107,193,123,208,139,133,186,194,183,110,153,68,209,173,49,118,37,238,99,213,6,92,136,29,23,232,41,215,232,126,246,123,92,134,17,186,181,164,115,178,123,174,210,18,228,30,105,151,226,238,121,11,106,207,166,252,36,76,80,24,102,211,180,144,206,85,194,130,36,53,52,104,59,44,39,174,58,223,144,114,42,29,176,1,205,125,142,173,202,1,93,55,221,39,74,94,37,129,188,211,136,144,211,98,100,161,186,165,204,248,104,160,205,238,126,39,129,240,116,51,183,67,247,0,254,253,202,46,44,103,40,254,202,169,119,184,158,132,118,39,75,44,70,4,156,147,122,6,42,167,216,86,96,202,231,189,167,167,130,53,147,146,187,251,252,182,101,33,164,111,14,81,107,194,250,167,109,185,80,16,236,163,151,17,172,168,44,170,160,11,59,178,162,135,219,23,136,23,71,138,185,81,175,226,207,126,237,128,99,196,43,104,207,47,139,94,167,137,15,181,245,194,142,180,141,134,201,34,104,190,132,161,244,41,38,102,159,243,126,35,77,29,86,34,4,249,199,124,31,231,198,61,126,160,109,63,211,200,46,14,33,113,254,90,189,216,86,64,65,115,191,203,188,232,116,78,252,76,140,75,17,184,25,241,236,191,213,213,87,73,142,42,246,166,147]}"#;
        let rk = [130, 110, 93, 113, 105, 127, 4, 210, 65, 234, 112, 90, 150, 120, 189, 252, 212, 165, 30, 209, 194, 213, 81, 38, 250, 187, 216, 14, 246, 250, 166, 92];
        // Act
        let received = Message::receive(received_jwe, Some(&rk), None);
        // Assert
        assert!(received.is_ok());
    }

    #[test]
    #[cfg(feature = "resolve")]
    fn send_receive_didkey_test() {
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(vec!("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"))
            .as_jwe(&CryptoAlgorithm::XC20P);
        // TODO: validate derived pub from priv key <<<
        let alice_private = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR".from_base58().unwrap();
        let bobs_private = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap();
        let jwe = m.seal(&alice_private);
        assert!(jwe.is_ok());

        let received = Message::receive(&jwe.unwrap(), &bobs_private);
        assert!(received.is_ok());
    }
}
