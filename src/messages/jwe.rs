use crate::JwmHeader;
use crate::Recepient;
use base64_url::{encode, decode};
/// JWE representation of `Message` with public header.
/// Can be serialized to JSON or Compact representations and from same.
///
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    #[serde(flatten)]
    pub header: JwmHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recepients: Option<Vec<Recepient>>,
    ciphertext: String
}

impl Jwe {
    /// Constructor, which should be used after message is encrypted.
    ///
    pub fn new(header: JwmHeader, recepients: Option<Vec<Recepient>>, ciphertext: impl AsRef<[u8]>) -> Self {
        Jwe { header, recepients, ciphertext: encode(ciphertext.as_ref()) }
    }
    /// Getter for ciphered payload of JWE.
    ///
    pub fn payload(&self) -> Vec<u8> {
        decode(&self.ciphertext).unwrap()
    }
}
