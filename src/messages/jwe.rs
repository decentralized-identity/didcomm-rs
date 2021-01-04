use crate::JwmHeader;
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    #[serde(flatten)]
    pub header: JwmHeader,
    ciphertext: Vec<u8>
}

impl Jwe {
    pub fn new(header: JwmHeader, ciphertext: Vec<u8>) -> Self {
        Jwe { header, ciphertext }
    }
    pub fn payload(&self) -> &[u8] {
        &self.ciphertext
    }
}