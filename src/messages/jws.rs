// use std::convert::{ TryFrom, TryInto };
use crate::{Jwk, JwmHeader};

// see https://users.rust-lang.org/t/serialize-a-vec-u8-to-json-as-base64/57781/2
mod base64_buffer {
    use serde::{Serialize, Deserialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64_url::encode(v);
        String::serialize(&base64, s)
    }
    
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64_url::decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e))
    }
}

// see https://users.rust-lang.org/t/serialize-a-vec-u8-to-json-as-base64/57781/2
mod base64_jwm_header {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::str::from_utf8;

    use crate::JwmHeader;

    pub fn serialize<S: Serializer>(v: &Option<JwmHeader>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = match v {
            Some(v) => {
                let header_string = serde_json::to_string(&v)
                    .map_err(|e| serde::ser::Error::custom(e))?;
                let header_buffer = header_string.into_bytes();
                Some(base64_url::encode(&header_buffer))
            },
            None => None,
        };
        <Option<String>>::serialize(&base64, s)
    }
    
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<JwmHeader>, D::Error> {
        let base64 = <Option<String>>::deserialize(d)?;
        match base64 {
            Some(v) => {
                let header_buffer = base64_url::decode(v.as_bytes())
                    .map_err(|e| serde::de::Error::custom(e))?;
                let header_string = from_utf8(&header_buffer)
                    .map_err(|e| serde::de::Error::custom(e))?;
                serde_json::from_str(&header_string)
                    .map_err(|e| serde::de::Error::custom(e))
            },
            None => Ok(None),
        }
    }
}

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
    create_getter!(iv, String);
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
