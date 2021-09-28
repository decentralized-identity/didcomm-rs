use base64_url::{decode, encode};
use rand::{prelude::SliceRandom, Rng};

use crate::{
    messages::helpers::{create_fallback_getter, serialization_base64_jwm_header},
    Jwk,
    JwmHeader,
    Recipient,
};

/// JWE representation of `Message` with public header.
/// Can be serialized to JSON or Compact representations and from same.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serialization_base64_jwm_header")]
    pub protected: Option<JwmHeader>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<JwmHeader>,

    /// Top-level recipient data for flat JWE JSON messages.
    /// Will be ignored if `recipients` is not `None`
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<Recipient>,

    /// Pre-recipient data for flat JWE JSON messages.
    /// If not `None`, will be preferred over `recipient`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipients: Option<Vec<Recipient>>,

    ciphertext: String,

    iv: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl Jwe {
    /// Constructor, which should be used after message is encrypted.
    pub fn new(
        unprotected: Option<JwmHeader>,
        recipients: Option<Vec<Recipient>>,
        ciphertext: impl AsRef<[u8]>,
        protected: Option<JwmHeader>,
        tag: Option<impl AsRef<[u8]>>,
        iv_input: Option<String>,
    ) -> Self {
        Jwe {
            unprotected,
            recipients,
            ciphertext: encode(ciphertext.as_ref()),
            protected,
            iv: Self::ensure_iv(iv_input),
            tag: tag.map(|tag_unencoded| encode(tag_unencoded.as_ref())),
            recipient: None,
        }
    }

    /// Constructor for creating a flat JWE JSON
    pub fn new_flat(
        unprotected: Option<JwmHeader>,
        recipient: Recipient,
        ciphertext: impl AsRef<[u8]>,
        protected: Option<JwmHeader>,
        tag: Option<impl AsRef<[u8]>>,
        iv_input: Option<String>,
    ) -> Self {
        Jwe {
            unprotected,
            recipients: None,
            ciphertext: encode(ciphertext.as_ref()),
            protected,
            iv: Self::ensure_iv(iv_input),
            tag: tag.map(|tag_unencoded| encode(tag_unencoded.as_ref())),
            recipient: Some(recipient),
        }
    }

    pub fn generate_iv() -> String {
        let mut rng = rand::thread_rng();
        let mut a = rng.gen::<[u8; 24]>().to_vec();
        a.shuffle(&mut rng);
        encode(&a)
    }

    /// Getter for ciphered payload of JWE.
    pub fn payload(&self) -> Vec<u8> {
        decode(&self.ciphertext).unwrap()
    }

    /// `iv` getter
    pub fn get_iv(&self) -> impl AsRef<[u8]> {
        decode(&self.iv).unwrap()
    }

    /// Gets initial vector from option or creates a new one.
    ///
    /// # Arguments
    ///
    /// * `iv_input` - an option that may contain an initial vector
    fn ensure_iv(iv_input: Option<String>) -> String {
        iv_input.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let mut a = rng.gen::<[u8; 24]>().to_vec();
            a.shuffle(&mut rng);
            encode(&a)
        })
    }

    create_fallback_getter!(protected, unprotected, alg, String);

    create_fallback_getter!(protected, unprotected, cty, String);

    create_fallback_getter!(protected, unprotected, enc, String);

    create_fallback_getter!(protected, unprotected, epk, Jwk);

    create_fallback_getter!(protected, unprotected, jku, String);

    create_fallback_getter!(protected, unprotected, jwk, Jwk);

    create_fallback_getter!(protected, unprotected, kid, String);

    create_fallback_getter!(protected, unprotected, skid, String);
}

#[test]
fn default_jwe_with_random_iv() {
    // Arrange
    let not_expected: Vec<u8> = vec![0; 24];
    // Act
    let jwe = Jwe::new(None, None, vec![], None, Some(vec![]), None);
    // Assert
    assert_ne!(not_expected, decode(&jwe.iv).unwrap());
}
