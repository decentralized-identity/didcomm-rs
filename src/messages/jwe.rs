use crate::{Error, JwmHeader, util::*};
/// JWE representation of `Message` with public header.
/// Can be serialized to JSON or Compact representations and from same.
///
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Jwe {
    #[serde(flatten)]
    pub header: JwmHeader,
    ciphertext: Vec<u8>
}

impl Jwe {
    /// Constructor, which should be used after message is encrypted.
    ///
    pub fn new(header: JwmHeader, ciphertext: Vec<u8>) -> Self {
        Jwe { header, ciphertext }
    }
    /// Constructor to build instance from received Compact representation.
    ///
    pub fn from_compact(data: &str) -> Result<Self, Error> {
        if data.chars().fold(0, |counter, c| if c == '.' {counter+ 1} else { counter }) != 1 {
            return Err(Error::JweCompactParseError);
        }
        let splitted = data.split('.').collect::<Vec<&str>>();
        Ok(Jwe {
            header: serde_json::from_str(&String::from_utf8(from_base64(&splitted[0])?)?)?,
            ciphertext: from_base64(&splitted[1])?
        })
    }
    /// Converts self into Compact `String`.
    ///
    pub fn as_compact(self) -> Result<String, Error> {
        Ok(format!("{}.{}",
            to_base64(
                &serde_json::to_string(&self.header)?
            ),
            to_base64(
                &String::from_utf8_lossy(&self.ciphertext)
            )
        ))
    }
    /// Getter for ciphered payload of JWE.
    ///
    pub fn payload(&self) -> &[u8] {
        &self.ciphertext
    }
}

#[test]
fn compact_serialization_test() {
    // Arrange
    let mut h = JwmHeader::default();
    let b = b"some sort of a message";
    // Act
    h.as_encrypted(&crate::crypto::CryptoAlgorithm::A256GCM);
    let b_encoded = to_base64(&String::from_utf8_lossy(b));
    let h_encoded = to_base64(&serde_json::to_string(&h).unwrap());
    let jwe = Jwe::new(h.clone(), b.clone().to_vec());
    let compact = jwe.as_compact();
    assert!(compact.is_ok());
    let compact = compact.unwrap();
    assert!(&compact.contains(&b_encoded));
    assert!(&compact.contains(&h_encoded));
    println!("{}", &compact);
    let deserialized = Jwe::from_compact(&compact);
    // Assert
    assert!(&deserialized.is_ok());
    let deserialized = deserialized.unwrap();
    assert_eq!(h, deserialized.header);
    assert_eq!(b.to_vec(), deserialized.ciphertext);
}