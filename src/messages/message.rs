use serde::{
    Serialize,
    Deserialize
};
use super::{
    headers::{DidcommHeader, JwmHeader},
    prior_claims::PriorClaims,
    };
use crate::Error;

/// DIDComm message structure.
/// [Specification](https://identity.foundation/didcomm-messaging/spec/#message-structure)
///
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Message {
    #[serde(flatten)]
    jwm_header: JwmHeader,
    #[serde(flatten)]
    didcomm_header: DidcommHeader,
    body: Vec<u8>,    
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
    /// Checks if message is rotation one.
    /// Exposed for explicit checks on sdk level.
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
    /// `&JwmHeader` getter.
    ///
    pub fn get_jwm_header(&self) -> &JwmHeader {
        &self.jwm_header
    }
    /// `&Vec<u8>` of `Message`'s body.
    ///
    pub fn get_body(&self) -> &Vec<u8> {
        &self.body
    }
    /// Creates set of Jwm related headers for the JWE
    /// Modifies JWM related header portion to match
    ///     encryption implementation and leaves other
    ///     parts unchanged.
    /// TODO: complete implementation
    pub fn as_jws(self) -> Self {
        Self { 
            jwm_header: JwmHeader {
                enc: Some("A256GCM".into()),
                kid: Some("".into()),
                epk: Some("".into()),
                alg: Some("ECDH-ES+A256KW".into()),
                ..self.jwm_header
            },
            ..self
        }
    }
    /// Creates set of Jwm related headers for the JWS
    /// Modifies JWM related header portion to match
    ///     signature implementation and leaves Other
    ///     parts unchanged.
    /// TODO: complete implementation
    pub fn as_jwe(self) -> Self {
        Self {
            jwm_header: JwmHeader {
                enc: None,
                kid: Some("".into()),
                alg: Some("ES256".into()),
                ..self.jwm_header
            },
            ..self
        }
    }
    /// Seals self and returns ready to send JWE
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    /// TODO: Add example[s]
    pub fn seal(self, ek: Vec<u8>) -> Result<String, Error> {
        self.pack_compact_jwe(&ek)
    }
    /// Signs raw message and then packs it to encrypted envelope
    /// [Spec](https://identity.foundation/didcomm-messaging/spec/#message-signing)
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `sk` - signing key for enveloped message JWS encryption
    /// TODO: Adde example[s]
    pub fn seal_signed(self, ek: Vec<u8>, sk: &Secret) -> Result<String, Error> {
        let mut crypto_envelope = Message {
            headers: Headers::encrypt_jws(self.headers.clone())?,
            body: self.sign_compact_jws(&sk)?.as_bytes().to_vec()
        };
        crypto_envelope.pack_compact_jwe(&ek)
    }
    /// Wrap self to be mediated by some mediator.
    /// Takes one mediator at a time to make sure that mediated chain preserves unchanged.
    /// This method can be chained any number of times to match all the mediators in the chain.
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `to` - list of destination recepients. can be empty (Optional) `String::default()`
    ///
    /// `form` - sender identifyer `String`
    ///
    /// `expires_time` - `Option<usize>` seconds from the UTC Epoch seconds,
    ///     signals when the message is no longer valid, and is to be used by
    ///     the recipient to discard expired messages on receipt
    /// TODO: Add example[s]
    pub fn routed_by(self,
        ek: Vec<u8>,
        to: Vec<String>,
        from: String,
        expires_time: Option<usize>)
        -> Result<Self, Error> {
        let payload = self.pack_compact_jwe(&ek)?;
        let forward_headers = DidcommHeader::forward(to, from, expires_time)?;
        let mut packed = Message::new();
        packed.headers = forward_headers;
        packed.body = payload.as_bytes().to_vec();
        Ok(packed)
    }
}

#[cfg(test)]
mod crypto_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;
    extern crate x25519_dalek;

    use crate::Error;
    use super::*;

}
