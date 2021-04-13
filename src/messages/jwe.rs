use crate::JwmHeader;
use crate::Recepient;
/// JWE representation of `Message` with public header.
/// Can be serialized to JSON or Compact representations and from same.
///
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    #[serde(flatten)]
    pub header: JwmHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recepients: Option<Vec<Recepient>>,
    ciphertext: Vec<u8>
}

impl Jwe {
    /// Constructor, which should be used after message is encrypted.
    ///
    pub fn new(header: JwmHeader, recepients: Option<Vec<Recepient>>, ciphertext: Vec<u8>) -> Self {
        Jwe { header, recepients, ciphertext }
    }
    /// Getter for ciphered payload of JWE.
    ///
    pub fn payload(&self) -> &[u8] {
        &self.ciphertext
    }
}
