use std::{convert::TryInto, time::SystemTime};
use base64_url::{encode, decode};
use serde::{Serialize, Deserialize};
use super::{
    mediated::Mediated,
    headers::{DidcommHeader, JwmHeader},
    prior_claims::PriorClaims,
};
use arrayref::array_ref;
#[cfg(feature = "resolve")]
pub use ddoresolver_rs::*;
use {
    x25519_dalek::{
        StaticSecret,
        PublicKey
    },
    rand_chacha::ChaCha20Rng,
    rand::{RngCore, SeedableRng},
    chacha20poly1305::{
        XChaCha20Poly1305,
        XNonce,
        aead::{
            Aead,
            NewAead
        },
    },
    crate::{
        Jwk,
        Recepient,
        KeyAlgorithm,
    },
};
#[cfg(feature = "raw-crypto")]
use crate::crypto::{
    CryptoAlgorithm,
    SignatureAlgorithm,
    Cypher,
    Signer,
};
use crate::{
    Error,
    Jwe,
    MessageType,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recepients: Option<Vec<Recepient>>,
    /// Message payload, which can be basically anything (JSON, text, file, etc.) represented
    ///     as base64url String of raw bytes of data.
    /// No direct access for encode/decode purposes! Use `get_body()` / `set_body()` methods instead.
    pub(crate) body: String,
}

impl Message {
    /// Generates EMPTY default message.
    /// Use extension messages to build final one before `send`ing.
    ///
    pub fn new() -> Self {
        Message {
            jwm_header: JwmHeader::default(),
            didcomm_header: DidcommHeader::new(),
            recepients: None,
            body: String::default(),
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
    /// Getter of the `body` as ref of bytes slice.
    /// Helpe method.
    ///
    pub fn get_body(&self) -> Result<impl AsRef<[u8]>, Error> {
        Ok(decode(&self.body)?)
    }
    /// Setter of the `body`
    /// Helper method.
    ///
    pub fn set_body(mut self, body: &[u8]) -> Self {
        self.body = encode(body);
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
    // TODO: Add examples
    // pub fn seal(self, ek: impl AsRef<[u8]>) -> Result<String, Error> {
    //     let alg = crypter_from_header(&self.jwm_header)?;
    //     self.encrypt(alg.encryptor(), ek.as_ref())
    // }
  //  #[cfg(feature = "resolve")]
    pub fn seal(mut self, sk: impl AsRef<[u8]>) -> Result<String, Error> {
        if sk.as_ref().len() != 32 { return Err(Error::InvalidKeySize("!32".into())); }
        match &self.didcomm_header.to.len() {
            1 => {
                let to = self.didcomm_header.to[0].clone();
                let shared = gen_shared_for_recepient(sk, &to)?;
                let alg = crypter_from_header(&self.jwm_header)?;
                self.encrypt(alg.encryptor(), shared.as_ref())
            },
            0 => todo!(), // What should happen in this scenario?
            _ => {
                // generate static secret
                let mut shared_key = [0u8; 32];
                let mut rng = ChaCha20Rng::from_seed(Default::default());
                rng.fill_bytes(&mut shared_key);
                let mut recepients: Vec<Recepient> = vec!();
                // create jwk from static secret per recepient
                for dest in &self.didcomm_header.to {
                    let shared = gen_shared_for_recepient(sk.as_ref(), dest)?;
                    let mut jwk = Jwk::new();
                    jwk.alg = KeyAlgorithm::EcdhEsA256kw;
                    jwk.kty = Some("oct".into());
                    jwk.use_ = Some("enc".into());
                    jwk.kid = Some(key_id_from_didurl( &dest));
                // encrypt jwk for each recepient using shared secret
                    let crypter = XChaCha20Poly1305::new(shared.as_ref().into());
                    let iv = self.jwm_header.get_iv();
                    let nonce = XNonce::from_slice(iv.as_ref());
                    let sealed_key = crypter
                        .encrypt(nonce, shared_key.as_ref())
                        .map_err(|e| Error::Generic(e.to_string()))?;
                    recepients.push(Recepient::new(jwk, encode(&sealed_key)));
                }
                self.recepients = Some(recepients);
                // encrypt original message with static secret
                let alg = crypter_from_header(&self.jwm_header)?;
                self.encrypt(alg.encryptor(), shared_key.as_ref())
            }
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
        to.body = encode(&signed.as_bytes());
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
    pub fn routed_by(self, ek: &[u8], mediator_did: &str)
        -> Result<String, Error> {
            let from = &self.didcomm_header.from.clone().unwrap_or_default();
            let alg = crypter_from_header(&self.jwm_header)?;
            let body = Mediated::new(self.didcomm_header.to[0].clone().into())
                .with_payload(self.seal(ek)?.as_bytes().to_vec());
            Message::new()
                .to(&[mediator_did])
                .from(&from)
                .as_jwe(&alg)
                .m_type(MessageType::DidcommForward)
                .set_body(serde_json::to_string(&body)?.as_bytes())
                .seal(ek)
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
    // #[cfg(not(feature = "resolve"))]
    // pub fn receive(incomming: &str, crypto_key: Option<&[u8]>, validation_key: Option<&[u8]>) -> Result<Self, Error> {
    //     match crypto_key {
    //         None => serde_json::from_str(incomming)
    //             .map_err(|e| Error::SerdeError(e)),
    //         Some(key) => {
    //             let jwe: Jwe = serde_json::from_str(&incomming)?;
    //             // Here we have JWE
    //             if let Some(alg) = &jwe.header.alg {
    //                 let a: CryptoAlgorithm = alg.try_into()?;
    //                 // TODO: public-private header validation should be here?
    //                 let m = Message::decrypt(incomming.as_bytes(), a.decryptor(), key)?;
    //                 // TODO: hate this tree - needs some refactoring
    //                 if &m.didcomm_header.m_type == &MessageType::DidcommJws {
    //                     if let Some(val_key) = validation_key {
    //                         Message::verify(&decode(&m.body)?, val_key)
    //                     } else {
    //                         Err(Error::Generic(String::from("Validation key is missing")))
    //                     }
    //                 } else {
    //                     if let Ok(mediated) = serde_json::from_slice::<Mediated>(&decode(&m.body)?) {
    //                         Ok(Message {
    //                             body: encode(&mediated.payload),
    //                             ..m
    //                         })
    //                     } else {
    //                         Ok(m)
    //                     }
    //                 }
    //             } else { 
    //                 Err(Error::JweParseError)
    //             }
    //         }
    //     }
    // }
    // #[cfg(feature = "resolve")]
    pub fn receive(incomming: &str, sk: &[u8]) -> Result<Self, Error> {
        let jwe: Jwe = serde_json::from_str(incomming)?;
        if jwe.header.skid.is_none() { return Err(Error::DidResolveFailed); }
        if let Some(document) = ddoresolver_rs::resolve_any(&jwe.header.skid.to_owned().unwrap()) {
            if let Some(alg) = &jwe.header.alg {
                if let Some(k_arg) = document.find_public_key_for_curve("X25519") {
                    let shared = StaticSecret::from(array_ref!(sk, 0, 32).to_owned())
                        .diffie_hellman(&PublicKey::from(array_ref!(k_arg, 0, 32).to_owned()));
                    let a: CryptoAlgorithm = alg.try_into()?;
                    let m: Message;
                    if jwe.recepients.is_some() {
                        if let Some(recepients) = jwe.recepients {
                            let mut key: Option<Vec<u8>> = None;
                            for recepient in recepients {
                                let cryptor = XChaCha20Poly1305::new(shared.as_bytes().into());
                                match cryptor.decrypt(
                                    jwe.header.get_iv().as_ref().into(), 
                                    decode(&recepient.encrypted_key).unwrap().as_ref())
                                {
                                    Ok(k) => {
                                        key = Some(k);
                                        break;
                                    },
                                    Err(_) => continue
                                }
                            }
                            if let Some(k) = key {
                                m = Message::decrypt(incomming.as_bytes(), a.decryptor(), &k)?;
                            } else {
                                return Err(Error::JweParseError);
                            }
                        } else {
                            return Err(Error::JweParseError);
                        }
                    } else {
                        m = Message::decrypt(incomming.as_bytes(), a.decryptor(), shared.as_bytes())?;
                    }
                    if &m.didcomm_header.m_type == &MessageType::DidcommJws {
                        if m.jwm_header.alg.is_none() { return Err(Error::JweParseError); }
                        if let Some(verifying_key) = document.find_public_key_for_curve(&m.jwm_header.alg.clone().unwrap_or_default()) {
                            Ok(Message::verify(m.get_body()?.as_ref(), &verifying_key)?)
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

fn gen_shared_for_recepient(sk: impl AsRef<[u8]>, did: &str) -> Result<impl AsRef<[u8]>, Error> {
    if let Some(document) = resolve_any(did) {
        if let Some(agreement) = document.find_public_key_for_curve("X25519") {
            let ss = StaticSecret::from(array_ref!(sk.as_ref(), 0, 32).to_owned())
                .diffie_hellman(&PublicKey::from(array_ref!(agreement, 0, 32).to_owned()));
            Ok(*ss.as_bytes())
        } else {
            Err(Error::DidResolveFailed)
        }
    } else {
        Err(Error::DidResolveFailed)
    }
}

fn key_id_from_didurl(url: &str) -> String {
    let re = regex::Regex::new(r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):(?P<key_id>[a-zA-Z0-9]*)([:?/]?)(\S)*$").unwrap();
    match  re.captures(url) {
        Some(s) =>
            match s.name("key_id") {
                Some(name) =>
                    format!("#{}", name.as_str()),
                None => String::default(),
            },
        None =>
            String::default()
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
        let received_jwe = r#"{"typ":"JWM","enc":"XC20P","alg":"ECDH-ES+A256KW","iv":"T9mr_1BU3QLAR2DDGbuazJaT_lSL4AV9","id":2680062373727502601,"type":"application/didcomm-plain+json","to":[""],"from":"","ciphertext":[109,30,156,163,61,55,151,194,203,62,125,236,136,173,157,86,62,59,159,166,31,90,81,51,134,227,152,107,182,102,217,115,1,89,85,36,161,177,231,240,118,199,154,24,123,24,6,164,214,38,122,173,221,73,30,140,152,174,189,254,196,245,195,191,220,204,165,159,125,154,158,11,27,250,194,84,185,246,218,49,197,98,19,99,53,67,5,140,9,214,189,191,224,25,12,23,141,31,63,109,68,61,186,249,231,189,158,237,129,224,214,111,144,110,117,63,8,141,246,155,119,13,143,189,77,57,188,7,176,3,60,109,101,63,103,163,140,16,50,6,235,202,169,39,20,166,188,242,161,38,199,155,2,45,9,255,62,80,165,104,60,220,189,202,18,207,146,139,181,136,67,178,57,32,194,208,212,221,202,238,61,154,3,125,131,27,38,216,116,101,2,227,36,210,253,218,103,80,181,209,251]}"#;
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

    #[test]
    #[cfg(feature = "resolve")]
    fn send_receive_didkey_multiple_receivers_test() {
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG", "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"])
            .as_jwe(&CryptoAlgorithm::XC20P);
        let alice_private = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR".from_base58().unwrap();
        let bobs_private = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap();
        let third_private = "ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2".from_base58().unwrap();
        let jwe = m.seal(&alice_private);
        assert!(jwe.is_ok());

        let jwe = jwe.unwrap();
        let received_bob = Message::receive(&jwe, &bobs_private);
        let received_third = Message::receive(&jwe, &third_private);
        assert!(received_bob.is_ok());
        assert!(received_third.is_ok());
    }

    #[test]
    fn mediated_didkey_test() {
        let mediator_private = "ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2".from_base58().unwrap();
        let alice_private = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR".from_base58().unwrap();
        let bobs_private = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap();
        let sealed = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P)
            .routed_by(&alice_private, "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf");
        assert!(sealed.is_ok());

        let mediator_received = Message::receive(&sealed.unwrap(), &mediator_private);
        assert!(mediator_received.is_ok());

        use crate::Mediated;
        let mediator_received_unwrapped = mediator_received.unwrap().get_body().unwrap();
        let pl_string = String::from_utf8_lossy(mediator_received_unwrapped.as_ref()); 
        let message_to_forward: Mediated = serde_json::from_str(&pl_string).unwrap();
        let attached_jwe = serde_json::from_slice::<Jwe>(&message_to_forward.payload);
        assert!(attached_jwe.is_ok());
        let str_jwe = serde_json::to_string(&attached_jwe.unwrap());
        assert!(str_jwe.is_ok());

        let bob_received = Message::receive(&String::from_utf8_lossy(&message_to_forward.payload), &bobs_private);
        assert!(bob_received.is_ok());
    }
}
