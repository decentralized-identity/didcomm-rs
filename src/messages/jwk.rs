use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Jwk {
    #[serde(skip_serializing_if = "Option::is_none")]
    kty: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    key_ops: Vec<KeyOps>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(flatten)]
    other: HashMap<String, String>,
}

impl Jwk {
    /// Constructor with all default, empty or `None` values.
    ///
    pub fn new() -> Self {
        Self::default()
    }
    /// Creates `epk` jwk entry with required properties.
    /// Correctness is not verified by this constructor and totaly rely on caller.
    ///
    pub fn ephemeral(mut self, kty: String, crv: String, x: String, y: String)
        -> Self {
        self.kty = Some(kty);
        self.crv = Some(crv);
        self.other.insert("x".into(), x);
        self.other.insert("y".into(), y);
        self
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
}

