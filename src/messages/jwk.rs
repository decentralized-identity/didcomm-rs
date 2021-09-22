use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Epk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// Json Web Keys structure defined by [RFC](https://tools.ietf.org/html/rfc7517)
///
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Jwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kty: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    pub key_ops: Vec<KeyOps>,
    pub alg: KeyAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<Epk>,
    #[serde(flatten)]
    pub(crate) other: HashMap<String, String>,
}

impl Jwk {
    /// Constructor with all default, empty or `None` values.
    ///
    pub fn new() -> Self {
        Self::default()
    }
    /// Creates `epk` jwk entry with required properties.
    /// Correctness is not verified by this constructor and totaly rely on caller.
    pub fn ephemeral(mut self, kty: String, crv: String, x: String, y: Option<String>) -> Self {
        self.epk = Some(Epk { kty, crv, x, y });
        self
    }
    /// Insert new custom, non-defined by spec, header.
    ///
    pub fn add_other_header(&mut self, k: String, v: String) {
        self.other.insert(k, v);
    }
}

// WARN: Does not support other key operation types ATM.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum KeyOps {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
    Other,
}

/// `alg` field values provided by [RFC](https://tools.ietf.org/html/rfc7518)
///
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum KeyAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS384,
    PS512,
    RSA1_5,
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    A128KW,
    A256KW,
    #[serde(rename = "dir")]
    Dir,
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsPlusA128kw,
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsPulsA192kw,
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256kw,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    #[serde(rename = "ECDH-1PU+A256KW")]
    Ecdh1puA256kw,
    #[serde(rename = "ECDH-1PU+XC20PKW")]
    Ecdh1puXc20pkw,
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128kw,
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192kw,
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256kw,
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "none")]
    None,
}

impl std::string::ToString for KeyAlgorithm {
    fn to_string(&self) -> String {
        // can't fail on enums
        serde_json::to_string(&self).unwrap()
    }
}

impl std::default::Default for KeyAlgorithm {
    fn default() -> Self {
        KeyAlgorithm::None
    }
}
