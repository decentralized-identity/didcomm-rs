use std::convert::TryInto;
use serde::{Serialize, Deserialize};
use super::{
    headers::{DidcommHeader, JwmHeader},
    prior_claims::PriorClaims,
};
use crate::{
    Error,
    Jwe,
    MessageType,
    crypto::{
        CryptoAlgorithm,
        SignatureAlgorithm
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
        self.didcomm_header.from = String::from(from);
        self
    }
    /// Setter of `to` header
    /// Helper method.
    ///
    pub fn to(mut self, to: Vec<&str>) -> Self {
        for s in to {
            self.didcomm_header.to.push(String::from(s));
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
    pub fn kid(mut self, kid: String) -> Self {
        match &mut self.jwm_header.kid {
            Some(h) => *h = kid,
            None => {
                self.jwm_header.kid = Some(kid);
            }
        }
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
    pub fn as_jws(mut self, alg: SignatureAlgorithm) -> Self {
        self.jwm_header.as_signed(alg);
        self
    }
    /// Creates set of Jwm related headers for the JWS
    /// Modifies JWM related header portion to match
    ///     signature implementation and leaves Other
    ///     parts unchanged.
    //
    pub fn as_jwe(mut self, alg: CryptoAlgorithm) -> Self {
        self.jwm_header.as_encrypted(alg);
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
    pub fn seal(self, ek: &[u8]) -> Result<String, Error> {
        let alg = crypter_from_header(&self.jwm_header)?;
        self.encrypt(alg.encryptor(), ek)
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
            .as_jws(signing_algorithm.clone())
            .sign(signing_algorithm.signer(), sk)?;
        to.body = signed.as_bytes().to_vec();
        to
            .m_type(MessageType::DidcommJws)
            .seal(ek)
    }
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
    /// `form` - used same as in wrapped message.
    ///
    /// TODO: Add examples
    pub fn routed_by(self, ek: &[u8], to: Vec<&str>)
        -> Result<Self, Error> {
            let h = &self.get_didcomm_header().from.clone();
            let to_wrap = self.seal(ek)?;
            Ok(Message::new()
                .to(to)
                .from(h)
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
    // /// Construct a message from compact representation of received data.
    // /// Raw, JWE or JWS payload is accepted.
    // /// FIXME: NOT IMPLEMENTED
    // /// TODO: Add examples
    // pub fn receive_compact(incomming: &str, pk: &[u8]) -> Result<Self, Error> {
    //     todo!()
    // }
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

   // use crate::Error;
   use super::*;

    #[test]
    fn receive_test() {
        // Arrange
        let received_jwe = r#"{"typ":"JWM","enc":"XC20P","kid":"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ","alg":"ECDH-ES+A256KW","epk":null,"cty":null,"iv":[150,42,115,171,104,189,215,45,24,224,225,43,97,159,110,17,212,11,216,126,203,11,197,228],"ciphertext":[68,30,204,76,217,88,203,60,59,144,80,242,16,211,110,116,12,58,11,205,109,76,93,173,81,24,200,105,26,24,136,37,228,204,36,99,198,224,202,118,231,55,84,157,166,50,87,152,35,62,229,149,89,140,55,42,39,151,211,26,21,249,163,50,150,222,11,199,248,182,145,173,244,105,243,37,159,179,44,78,87,13,167,9,244,229,144,61,98,95,5,110,79,165,2,60,243,66,253,237,200,254,123,50,231,128,108,199,45,244,49,1,91,71,13,161,236,108,50,115,163,63,49,77,127,214,145,138,218,194,112,66,65,17,144,201,229,205,250,213,214,48,114,14,106,149,114,142,233,137,121,200,223,199,156,113,168,21,190,215,22,172,109,177,76,18,202,130,222,55,202,250,23,55,156,159,153,73,78,49,161,147,138,43,123,248,190,225,163,36,90,174,208,80,19,37,244,109,6,183,16,172,191,65,196,19,2,242,19,90,138,49,126,1,186,22,91,1,145,108,136,31,158,27,111,117,159,208,192,131,207,159,22,160,50,0,204,218,64,55,152,176,160,63,82,37,85,199,15,121,149,211,45,125,159,178,7,124,48,15,219,147,249,241,92,85,205,158,170,240,71,12,162,37,122,193,66,68,98,66,214,16,219,145,34,90,42,198,0,241,241,78,126,143,219,118,23,180,75,8,180,111,0,141,246,226,196,125,235,133,225,93,154,4,158,50,97,246,164,139,172,217,115,84,2,175,157,198,211,174,189,187,84,135,169,247,143,80,6,144,32,246,115,43,134,128,197,138,251,179,93,129,189,20,199,1,131,233,85,98,31,116,119,24,205,141,19,67,230,201,59,124,60,178,102,52,172,207,55,118,219,182,162,152,177,12,145,1,185,23,175,96,30,30,88,114,125,36,255,189,28,157,101,186,203,187,99,45,173,229,68,229,41,43,241,171,122,133,189,100,35,143,214,59,44,49,153,100,145,252,164,96,169,226,62,194,60,114,222,96,131,85,100,183,111,85,79,163,21,211,40,253,238,224,145,149,113,63,16,70,201,69,177,24,47,108,232,114,94,139,99,64,60,84,4,146,131,241,89,72,12,13,33,100,173,113,128,47,92,83,118,136,227,153,157,72,10,71,144,25,201,105,108,182,171,183,226,100,24,107,132,23,239,127,236,205,229,156,195,22,73,75,50,90,132,123,71,126,44,172,123,145,28,105,238,143,221,59,34,233,32,44,156,137,103,176,173,249,163,208,235,50,33,144,227,161,203,233,28,236,66,224,135,186,9,233,184,199,155,129,206,69,95,68,104,67,28,173,230,230,95,247,219,65,15,223,17,203,89,172,123,4,49,187,53,28,100,146,139,252,39,188,8,126,95,54,78,178,253,229,10,157,79,144,219,53,244,225,112,213,92,85,238,186,119,99,147,206,18,240,59,244,251,135,239,55,90,67,152,155,73,42,140,139,103,213,125,29,133,125,56,18,131,247,72,198,69,54,5,28,83,141,155,235,93,140,60,143,186,37,104,46,144,3,154,254,8,173,121,231,196,129,190,254,162,162,95,181,190,139,164,234,217,160,144,26,67,245,121,55,113,15,148,183,122,85,174,248,155,25,114,77,217,27,113,140,215,168,249,49,194,53,248,53,2,247,169,130,100,227,72,134,205,44,246,206,6,184,149,168,81,150,202,159,26,206,148,19,108,65,130,211,218,215,49,70,182,104,111,118,83,75,196,67,215,35,254,8,171,164,231,137,174,11,126,135,11,187,102,56,161,24,142,231,222,107,31,217,187,95,228,77,110,143,187,75,10,245,52,52,204,76,51,14,145,123,134,224,86,56,88,110,210,26,71,60,84,168,114,156,160,250,152,36,231,114,77,74,246,185,25,184,254,58,212,36,30,233,98,52,205,205,55,150,240,101,86,128,95,131,235,22,145,58,184,75,161,46,200,222,182,193,226,9,116,76,54,157,159,199,196,66,209,248,52,25,61,225,51,33,207,36,131,103,37,53,246,223,31,82,66,46,122,225,121,181,9,116,28,79,195,126,99,179,56,41,199,215,94,126,50,109,223,123,157,14,119,12,126,78,121,2,71,10,95,239,32,223,155,128,22,221,158,16,5,76,182,94,78,36,108,6,227,132,63,203,7,6,24,196,192,208,246,7,108,101,206,167,196,35,136,181,129,180,215,183,161,139,210,204,85,48,150,253,53,108,227,32,229,178,18,84,90,96,182,159,1,171,77,15,219,2,149,101,1,92,62,22,238,30,40,198,230,22,228,246,38,92,109,154,231,38,65,66,185,179,158,176,106,78,20,68,204,99,111,249,141,52,247,181,134,180,144,184,16,242,192,81,188,210,126,176,149,226,58,46,225,25,227,167,195,63,52,133,92,129,1,28,192,75,187,91,12,234,77,98,233,105,12,209,242,101,233,59,96,97,246,96,242,175,19,148,51,11,152,106,155,118,253,76,227,226,244,170,242,125,68,190,231,99,49,183,80,51,206,1,55,150,30,229,86,1,43,18,161,113,89,153,41,124,222,5,2,144,113,1,120,2,17,21,51,250,68,19,75,2,35,194,23,45,104,26,89,9,127,199,101,193,53,244,115,185,74,98,22,153,229,70,201,125,230,94,205,198,37,55,242,99,178,238,165,174,85,19,46,99,44,193,209,142,99,163,247,247,90,249,217,2,198,198,80,26,211,185,36,29,239,206,245,222,189,52,202,248,214,53,28,183,82,145,212,207,47,220,5,145,187,155,193,118,84,62,200,214,196,173,178,174,186,24,117,55,190,101,71,62,135,136,168,95,184,32,66,76,138,107,141,254,24,97,10,77,109,210,126,77,87,87,103,253,178,24,80,42,140,29,188,154,196,62,120,200,149,146,222,35,113,199,163,44,234,71,219,191,79,174,3,237,68,52,205,190,53,14,44,158,149,28,21,80,241,28,68,92,96,239,204,161,241,222,244,171,228,80,11,160,92,180,196,148,220,202,253,209,201,5,151,115,134,20,168,146,2,200,23,40,23,104,253,187,33,65,35,3,188,36,173,226,109,202,193,243,254,75,68,158,64,166,116,203,131,4,130,106,28,183,108,135,119,41,106,162,21,62,164,156,240,13,146,140,247,233,204,44,187,91,238,145,39,246,66,145,222,61,226,60,239,170,38,89,229,209,61,12,62,95,16,100,65,166,145,254,7,95,250,19,254,210,57,48,240,70,40,157,154,252,212,193,110,138,94,252,98,206,4,174,226,222,33,2,108,238,198,135,201,3,151,189,101,189,40,73,165,25,39,126,158,5,132,212,43,205,90,15,227,72,79,216,32,180,124,29,50,160,3,119,124,148,151,45,178,250,50,223,43,246,22,159,237,191,105,127,43,8,32,231,30,203,199,163,57,55,55,88,77,194,73,241,125,145,148,58,133,68,70,199,26,85,162,13,251,17,230,74,157,58,63,87,39,161,119,124,8,89,169,167,118,93,195,115,170,126,100,225,124,172,28,51,225,11,61,25,102,177,93,73,59,129,88,138,174,10,47,61,161,188,37,103,108,45,243,222,251,153,47,149,99,26,133,102,198,19,29,6,142,49,37,207,129,38,235,131,223,196,105,50,106,41,125,241,184,16,248,81,67,254,59,209,3,227,155,40,25,170,237,65,159,131,118,181,67,70,226,33,33,143,98,3,145,234,104,224,88,167,91,253,169,223,170,77,6,171,227,119,119,212,41,127,164,154,197,227,50,72,236,110,184,61,54,65,90,175,132,82,130,188,188,56,158,149,169,210,221,118,138,252,243,102,175,211,71,183,253,223,18,210,85,220,64,59,73,111,126,57,87,215,220,207,37,115,56,204,133,151,61,163,144,106,177,131,177,63,176,51,82,36,8,242,249,77,211,81,165,180,35,127,129,13,175,231,175,217,66,53,144,112,212,54,190,62,187,36,103,255,97,25,110,237,223,193,112,29,13,32,9,19,45,109,196,158,127,55,165,207,37,54,6,203,148,215,131,161,110,111,68,104,71,148,43,230,147,228,40,72,1,196,11,95,236,138,162,1,202,67,208,121,28,197,243,226,161,138,164,16,144,68,180,212,194,187,152,94,12,66,215,221,13,125,145,153,60,96,6,194,130,42,151,133,115,95,25,11,217,220,29,79,152,10,196,35,185,171,77,179,235,152,38,81,232,191,215,77,77,106,59,128,56,62,5,229,77,44,82,130,109,253,130,36,175,152,69,193,37,168,84,199,79,168,181,170,228,85,23,144,171,79,116,253,75,216,179,208,123,24,64,207,74,247,205,87,133,217,219,45,149,41,242,87,7,109,1,211,93]}"#;
        let rk = [130, 110, 93, 113, 105, 127, 4, 210, 65, 234, 112, 90, 150, 120, 189, 252, 212, 165, 30, 209, 194, 213, 81, 38, 250, 187, 216, 14, 246, 250, 166, 92];
        // Act
        let received = Message::receive(received_jwe, Some(&rk), None);
        // Assert
        assert!(received.is_ok());
    }
}
