use base64_url::{decode, encode};
use rand::{prelude::SliceRandom, Rng};

use crate::{
    messages::helpers::{create_fallback_getter, serialization_base64_jwm_header},
    Jwk,
    JwmHeader,
};

/// This struct presents single recipient of JWE `recipients` collection.
/// Each recipient should have same body cypher key encrypted with shared secret.
/// [Spec](https://tools.ietf.org/html/rfc7516#section-7.2.1)
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Recipient {
    pub header: Jwk,

    pub encrypted_key: String,
}

impl Recipient {
    pub fn new(header: Jwk, encrypted_key: String) -> Self {
        Recipient {
            header,
            encrypted_key,
        }
    }
}

/// JWE representation of `Message` with public header.
/// Can be serialized to JSON or Compact representations and from same.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    /// integrity protected header elements
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serialization_base64_jwm_header")]
    pub protected: Option<JwmHeader>,

    /// header elements that are not integrity protected
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

    /// Encrypted data of JWE as base64 encoded String
    ciphertext: String,

    /// Initial vector for encryption as base64 encoded String
    iv: String,

    /// base64 encoded JWE authentication tag
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

    /// Generate new random IV as String
    pub fn generate_iv() -> String {
        let mut rng = rand::thread_rng();
        let mut a = rng.gen::<[u8; 24]>().to_vec();
        a.shuffle(&mut rng);
        encode(&a)
    }

    /// Gets `iv` as byte array.
    pub fn get_iv(&self) -> impl AsRef<[u8]> {
        decode(&self.iv).unwrap()
    }

    /// Getter for ciphered payload of JWE.
    pub fn get_payload(&self) -> Vec<u8> {
        decode(&self.ciphertext).unwrap()
    }

    create_fallback_getter!(protected, unprotected, alg, String);

    create_fallback_getter!(protected, unprotected, cty, String);

    create_fallback_getter!(protected, unprotected, enc, String);

    create_fallback_getter!(protected, unprotected, epk, Jwk);

    create_fallback_getter!(protected, unprotected, jku, String);

    create_fallback_getter!(protected, unprotected, jwk, Jwk);

    create_fallback_getter!(protected, unprotected, kid, String);

    create_fallback_getter!(protected, unprotected, skid, String);

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
