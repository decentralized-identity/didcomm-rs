use std::{convert::TryInto, str::FromStr, time::SystemTime};
use serde::{Serialize, Deserialize};
use super::{
    DidUrl,
    mediated::Mediated,
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
    pub fn routed_by(self, ek: &[u8], to: &str)
        -> Result<Self, Error> {
            let h = match &self.get_didcomm_header().from.clone() {
                Some(s) => s.to_owned(),
                None => String::default(),
            };
            let to_cloned = self.didcomm_header.to.clone();
            let to_recepients: Vec<&str> = to_cloned
                .iter()
                .map(String::as_str)
                .collect();
            let to_wrap: String;
            to_wrap = self.seal(ek)?;
            let body = Mediated::new(DidUrl::from_str(to)?)
                .with_payload(to_wrap.as_bytes().to_vec());
            Ok(Message::new()
                .to(&to_recepients)
                .from(&h)
                .m_type(MessageType::DidcommRaw)
                .body(serde_json::to_string(&body)?.as_bytes()))
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
            Some(key) => {
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
                        if let Ok(mediated) = serde_json::from_slice::<Mediated>(&m.body) {
                            Ok(Message {
                                body: mediated.payload,
                                ..m
                            })
                        } else {
                            Ok(m)
                        }
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
                        if let Ok(mediated) = serde_json::from_slice::<Mediated>(&m.body) {
                            Ok(Message {
                                body: mediated.payload,
                                ..m
                            })
                        } else {
                            Ok(m)
                        }
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
   fn create_and_send() {
       let rk = [130, 110, 93, 113, 105, 127, 4, 210, 65, 234, 112, 90, 150, 120, 189, 252, 212, 165, 30, 209, 194, 213, 81, 38, 250, 187, 216, 14, 246, 250, 166, 92];
        let m = Message::new()
            .as_jwe(&CryptoAlgorithm::XC20P);
        let p = m.seal(&rk);
        assert!(p.is_ok());
   }

    #[test]
    #[cfg(not(feature = "resolve"))]
    fn receive_test() {
        // Arrange
        let received_jwe = r#"{"typ":"JWM","enc":"XC20P","alg":"ECDH-ES+A256KW","iv":[227,154,25,80,3,225,217,179,39,204,103,60,92,16,59,171,110,156,28,196,83,9,237,84],"id":1117912036141727650,"type":"application/didcomm-plain+json","to":[""],"from":"","ciphertext":[62,11,202,108,20,132,51,66,76,129,34,228,203,69,243,45,221,224,164,191,183,21,5,252,46,47,30,28,202,26,161,139,123,56,73,253,63,129,111,225,250,98,11,81,77,12,125,221,149,202,85,102,211,239,86,176,188,98,152,61,170,137,215,232,139,252,28,40,203,98,222,104,145,158,149,65,27,234,205,140,161,220,125,66,226,176,57,151,33,77,106,148,185,95,75,83,230,40,12,218,152,207,246,117,125,201,42,205,31,157,45,227,128,223,14,43,80,112,191,141,119,11,187,183,161,185,106,13,192,198,64,141,114,169,56,90,80,89,218,245,20,15,117,25,189,223,92,64,194,39,77,197,45,8,155,89,124,19,185,112,6,231,207,95,208,51,134,180,251,232,0,161,197,128,98,50,13,55,156,95,244,136,13,30,171,51,124,231,204,236,35,35,30,160,57,247,223,106,13,20,84,89,24,192,22,190,125,63,133,234,58,209,167,212,9,249,149,213,248,135,23,51,145,74,9,99,105,35,134,115,175,94,190,169,189,167,163,145,237,32,151,215,93,200,76,206,103,91,253,128]}"#;
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
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
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
