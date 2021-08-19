// use std::convert::{ TryFrom, TryInto };
use crate::{Jwk, JwmHeader};
use crate::messages::serialization::{base64_buffer, base64_jwm_header};

macro_rules! create_getter {
    ($field_name:ident, $field_type:ident) => {
        pub fn $field_name(&self) -> Option<$field_type> {
            if let Some(header) = &self.header {
                if let Some(value) = &header.$field_name {
                    return Some(value.clone());
                }
            }
            if let Some(protected) = &self.protected {
                if let Some(value) = &protected.$field_name {
                    return Some(value.clone());
                }
            }
            None
        }
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureValue {
    #[serde(skip_serializing_if = "Option::is_none")]
	#[serde(with="base64_jwm_header")]
    pub protected: Option<JwmHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<JwmHeader>,
	#[serde(with="base64_buffer")]
    pub signature: Vec<u8>,
}

impl SignatureValue {
    create_getter!(enc, String);
    create_getter!(kid, String);
    create_getter!(skid, String);
    create_getter!(alg, String);
    create_getter!(jku, String);
    create_getter!(jwk, Jwk);
    create_getter!(epk, Jwk);
    create_getter!(cty, String);
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    pub payload: String,
    #[serde(flatten)]
    pub signature_value: SignatureValue,
}

impl Jws {
    pub fn new(
        payload: String,
        protected: Option<JwmHeader>,
        header: Option<JwmHeader>,
        signature: Vec<u8>,
    ) -> Self {
        Jws {
            payload,
            signature_value: SignatureValue {
                protected,
                header,
                signature,
            },
        }
    }
}
