use std::{str::FromStr, string::ToString};

use crate::Error;

/// DID URL string
#[derive(Serialize, Deserialize, Debug)]
pub struct DidUrl(pub String);

impl ToString for DidUrl {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl FromStr for DidUrl {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let re = regex::Regex::new(r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):").unwrap();
        if re.is_match(s) {
            Ok(Self { 0: s.to_string() })
        } else {
            Err(Error::BadDid)
        }
    }
}
