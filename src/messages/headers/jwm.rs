#[cfg(feature = "raw-crypto")]
use crate::crypto::{CryptoAlgorithm, SignatureAlgorithm};
use crate::{Jwk, MessageType};

/// JWM Header as specified in [RFC](https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3)
/// With single deviation - allows raw text JWM to support DIDComm spec
///
/// Designed to work for both [JWE](https://tools.ietf.org/html/rfc7516) and [JWS](https://tools.ietf.org/html/rfc7515) message types.
///
/// `iv` property is not explicitly listed in the registered properties on the RFC but is present
///     within example lists - used here as DIDComm crypto nonce sharing property.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct JwmHeader {
    pub typ: MessageType,

    // Some(String) if JWM is JWE encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enc: Option<String>,

    // None if raw text message, Some(key ID) otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub skid: Option<String>,

    // None if raw text message, Some(String) for
    //  both JWE and/or JWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    // Refers to a resource for a set of JSON-encoded public keys, one of
    // which corresponds to the key used to digitally sign the JWS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    // public key that corresponds to the key used to digitally sign the JWS.
    // TODO: implement proper struct for it:
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    // Some(String) - serialized ephemeral public key.
    // TODO: implement proper struct for it:
    // https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<Jwk>,

    // Some("JWM") should be used if nested JWS inside JWE.
    // None otherwise is *STRONGLY RECOMMENDED* by RFC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
}

impl JwmHeader {
    /// Setter of JOSE header properties to identify which signature alg used.
    /// Modifies `typ` and `alg` headers.
    #[cfg(feature = "raw-crypto")]
    pub fn as_signed(&mut self, alg: &SignatureAlgorithm) {
        self.typ = MessageType::DidCommJws;
        match alg {
            SignatureAlgorithm::EdDsa => {
                self.alg = Some(String::from("EdDSA"));
            }
            SignatureAlgorithm::Es256 => {
                self.alg = Some(String::from("ES256"));
            }
            SignatureAlgorithm::Es256k => {
                self.alg = Some(String::from("ES256K"));
            }
        }
    }

    /// Setter of JOSE header properties to identify which crypto alg and key type used.
    /// Modifies `enc`, `typ` and `alg` headers.
    #[cfg(feature = "raw-crypto")]
    pub fn as_encrypted(&mut self, alg: &CryptoAlgorithm) {
        self.typ = MessageType::DidCommJwe;
        match alg {
            CryptoAlgorithm::A256GCM => {
                self.enc = Some("A256GCM".into());
                self.alg = Some("ECDH-1PU+A256KW".into());
            }
            CryptoAlgorithm::XC20P => {
                self.enc = Some("XC20P".into());
                self.alg = Some("ECDH-1PU+XC20PKW".into());
            }
            CryptoAlgorithm::A256CBC => {
                self.alg = Some("A256CBC".into());
                self.enc = Some("ECDH-1PU+A256KW".into())
            }
        }
    }

    pub fn kid(&mut self, kid: Option<String>) {
        self.kid = kid;
    }
}

impl Default for JwmHeader {
    // Need to make sure nonce is 192 bit long unique for each message.
    fn default() -> Self {
        JwmHeader {
            typ: MessageType::DidCommRaw,
            enc: None,
            kid: None,
            skid: None,
            epk: None,
            alg: None,
            cty: None,
            jku: None,
            jwk: None,
        }
    }
}
