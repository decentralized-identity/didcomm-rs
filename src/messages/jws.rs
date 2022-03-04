use crate::{
    helpers::create_fallback_getter,
    messages::helpers::{serialization_base64_buffer, serialization_base64_jwm_header},
    Jwk,
    JwmHeader,
};

/// Signature data for [JWS](https://datatracker.ietf.org/doc/html/rfc7515) envelopes.
/// They can be used per recipient in [General JWS JSON](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1),
/// triggered by using [`.as_jws`][crate::Message::as_jws()] or as a single signature for the entire JWS in
/// [Flattened JWS JSON](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2), triggered by
/// [`.as_flat_jws`][crate::Message::as_flat_jws()].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Signature {
    /// integrity protected header elements
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serialization_base64_jwm_header")]
    pub protected: Option<JwmHeader>,

    /// header elements that are not integrity protected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<JwmHeader>,

    /// signature computed over protected header elements
    #[serde(default)]
    #[serde(with = "serialization_base64_buffer")]
    pub signature: Vec<u8>,
}

impl Signature {
    /// Creates a new `Signature` that can be used in JWS `signatures` property or
    /// as top-level (flattened) property in flattened JWS JSON serialization.
    ///
    /// # Arguments
    ///
    /// * `protected` - JWM header protected by signing
    ///
    /// * `header` - JWM header not protected by signing
    ///
    /// * `signature` - signature over JWS payload and protected header
    pub fn new(
        protected: Option<JwmHeader>,
        header: Option<JwmHeader>,
        signature: Vec<u8>,
    ) -> Self {
        Signature {
            protected,
            header,
            signature,
        }
    }

    create_fallback_getter!(header, protected, alg, String);

    create_fallback_getter!(header, protected, cty, String);

    create_fallback_getter!(header, protected, enc, String);

    create_fallback_getter!(header, protected, epk, Jwk);

    create_fallback_getter!(header, protected, jku, String);

    create_fallback_getter!(header, protected, jwk, Jwk);

    create_fallback_getter!(header, protected, kid, String);

    create_fallback_getter!(header, protected, skid, String);
}

/// A struct to generate and serialize [JWS](https://datatracker.ietf.org/doc/html/rfc7515)
/// envelopes for DIDComm messages.
#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    /// base64 encoded payload of the JWS
    pub payload: String,

    /// Top-level signature for flat JWS JSON messages.
    /// Will be ignored if `signatures` is not `None`
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,

    /// Pre-recipient signatures for flat JWS JSON messages.
    /// If not `None`, will be preferred over `signature`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<Signature>>,
}

impl Jws {
    /// Creates a new [general JWS](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1)
    /// object with signature values per recipient.
    ///
    /// # Arguments
    ///
    /// * `payload` - payload with encoded data
    ///
    /// * `signatures` - signature values per recipient
    pub fn new(payload: String, signatures: Vec<Signature>) -> Self {
        Jws {
            payload,
            signature: None,
            signatures: Some(signatures),
        }
    }

    /// Creates a new [flattened JWS](https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2)
    /// object with signature information on JWS' top level.
    ///
    /// # Arguments
    ///
    /// * `payload` - payload with encoded data
    ///
    /// * `signatures_value` - signature value that is used on JWS top-level
    pub fn new_flat(payload: String, signature_value: Signature) -> Self {
        Jws {
            payload,
            signature: Some(signature_value),
            signatures: None,
        }
    }
}
