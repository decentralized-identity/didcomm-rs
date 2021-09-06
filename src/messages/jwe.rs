use base64_url::{encode, decode};
use rand::{Rng, prelude::SliceRandom};
use crate::{
    Jwk,
    JwmHeader,
    Recepient,
    messages::serialization::{base64_buffer, base64_jwm_header},
};

macro_rules! create_getter {
    ($field_name:ident, $field_type:ident) => {
        pub fn $field_name(&self) -> Option<$field_type> {
            if let Some(protected) = &self.protected {
                if let Some(value) = &protected.$field_name {
                    return Some(value.clone());
                }
            }
            if let Some(unprotected) = &self.unprotected {
                if let Some(value) = &unprotected.$field_name {
                    return Some(value.clone());
                }
            }
            None
        }
    };
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RecipientValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<Jwk>,

	#[serde(with="base64_buffer")]
    pub encrypted_key: Vec<u8>,
}

/// JWE representation of `Message` with public header.
/// Can be serialized to JSON or Compact representations and from same.
///
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    #[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with="base64_jwm_header")]
    pub protected: Option<JwmHeader>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<JwmHeader>,

    #[serde(rename = "recipients")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recepients: Option<Vec<Recepient>>,

    ciphertext: String,

    iv: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_value: Option<RecipientValue>,
}

impl Jwe {
    /// Constructor, which should be used after message is encrypted.
    pub fn new(
        unprotected: Option<JwmHeader>,
        recepients: Option<Vec<Recepient>>,
        ciphertext: impl AsRef<[u8]>,
        protected: Option<JwmHeader>,
        recipient_value: Option<RecipientValue>,
        tag: Option<impl AsRef<[u8]>>,
        iv_input: Option<String>,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut a = rng.gen::<[u8; 24]>().to_vec();
        a.shuffle(&mut rng);
        let tag_value = match tag {
            Some(tag_unencoded) => Some(encode(tag_unencoded.as_ref())),
            None => None,
        };
        let iv = iv_input.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let mut a = rng.gen::<[u8; 24]>().to_vec();
            a.shuffle(&mut rng);
            encode(&a)
        });
        Jwe {
            unprotected,
            recepients,
            ciphertext: encode(ciphertext.as_ref()),
            protected,
            iv,
            recipient_value,
            tag: tag_value,
        }
    }

    pub fn generate_iv() -> String {
        let mut rng = rand::thread_rng();
        let mut a = rng.gen::<[u8; 24]>().to_vec();
        a.shuffle(&mut rng);
        encode(&a)
    }

    /// Getter for ciphered payload of JWE.
    ///
    pub fn payload(&self) -> Vec<u8> {
        decode(&self.ciphertext).unwrap()
    }

    /// `iv` getter
    pub fn get_iv(&self) -> impl AsRef<[u8]> {
        decode(&self.iv).unwrap()
    }

    create_getter!(enc, String);
    create_getter!(kid, String);
    create_getter!(skid, String);
    create_getter!(alg, String);
    create_getter!(jku, String);
    create_getter!(jwk, Jwk);
    create_getter!(epk, Jwk);
    create_getter!(cty, String);
}

#[test]
fn default_jwe_with_random_iv() {
    // Arrange
    let not_expected: Vec<u8> = vec![0; 24];
    // Act
    let jwe = Jwe::new(
        None,
        None,
        vec![],
        None,
        None,
        Some(vec![]),
        None,
    );
    // Assert
    assert_ne!(not_expected, decode(&jwe.iv).unwrap());
}