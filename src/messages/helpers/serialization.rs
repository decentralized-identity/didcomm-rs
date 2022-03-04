/// (de)serialzies between `Vec<u8>` and base64 `String`
/// see `<https://users.rust-lang.org/t/serialize-a-vec-u8-to-json-as-base64/57781/2>`
pub(crate) mod serialization_base64_buffer {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64_url::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let buffer: &[u8] = Deserialize::deserialize(d)?;
        base64_url::decode(buffer).map_err(serde::de::Error::custom)
    }
}

/// (de)serialzies between `Option<JwmHeader>` and base64 `String`
/// see `<https://users.rust-lang.org/t/serialize-a-vec-u8-to-json-as-base64/57781/2>`
pub(crate) mod serialization_base64_jwm_header {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::JwmHeader;

    pub fn serialize<S: Serializer>(v: &Option<JwmHeader>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = match v {
            Some(v) => {
                let header_string = serde_json::to_string(&v).map_err(serde::ser::Error::custom)?;
                Some(base64_url::encode(&header_string))
            }
            None => None,
        };
        <Option<String>>::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<JwmHeader>, D::Error> {
        let base64 = <Option<String>>::deserialize(d)?;
        match base64 {
            Some(v) => {
                let header_buffer =
                    base64_url::decode(v.as_bytes()).map_err(serde::de::Error::custom)?;
                serde_json::from_slice(&header_buffer).map_err(serde::de::Error::custom)
            }
            None => Ok(None),
        }
    }
}
