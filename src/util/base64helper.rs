use crate::Error;

pub fn to_base64(decoded: &str) -> String {
    base64_url::encode(decoded)
}

pub fn from_base64(encoded: &str) -> Result<Vec<u8>, Error> {
    base64_url::decode(encoded).map_err(|e| Error::Base64DecodeError(e))
}