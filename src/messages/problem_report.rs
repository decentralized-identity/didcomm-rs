use crate::Error;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Problem {
    code: String,
    comment: Option<String>,
    args: Vec<String>,
    escalate_to: Option<String>,
}

impl Problem {
    /// Parses given code into new instance of Problem
    /// If given string does not match regex "" - returns Err.
    ///
    pub fn from_code(code: &str) -> Result<Self, Error> {
        let re = Regex::new(r"^[e|w]\.[a-z0-9]{1,32}\.[a-zA-Z]*\.?[-a-zA-Z\-]*\.?[-a-zA-Z\-]*$")?;
        if re.is_match(code) {
            Ok(Problem {
                code: code.into(),
                ..Default::default()
            })
        } else {
            Err(Error::Generic(
                "Code badly formatted for this problem".into(),
            ))
        }
    }

    /// Takes `KnownProblem` variant and creates new Problem
    /// using it as code.
    /// Kwnown problems are defined in the specifications of
    /// the didcomm v2.
    ///
    pub fn from_known_problem(problem: KnownProblems) -> Self {
        Problem {
            code: problem.to_string(),
            ..Default::default()
        }
    }

    // TODO: someday? =)
    //pub fn elevate(self) -> Self {
    //    let new_code = match self.code.into() {
    //        KnownProblems::ProtocolWarning => KnownProblems::ProtocolError,
    //        KnownProblems::TrustWarning => KnownProblems::TrustlError,
    //        KnownProblems::CryptoTrustWarning => KnownProblems::CryptoTrusError,
    //        KnownProblems::XferWarning => KnownProblems::XferError,
    //        KnownProblems::DidWarning => KnownProblems::DidError,
    //        KnownProblems::MsgError => KnownProblems::MsgError,
    //        KnownProblems::MeResWarning => KnownProblems::MeResError,
    //        KnownProblems::MeWarning => KnownProblems::MeErro,
    //        KnownProblems::LegalWarning => KnownProblems::LegalError,
    //        KnownProblems::ReqWarning => KnownProblems::ReqError,
    //        KnownProblems::ReqTimeWarning => KnownProblems::ReqTimeError,
    //        _ => self.code,
    //    };
    //    Self {
    //        code: new_code,
    //        ..self
    //    }
    //}
}

/// Values defined in spec: https://identity.foundation/didcomm-messaging/spec/#problem-codes
/// Except `KnownProblems::Unknow`, which is default and should be used as little as possible
///
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum KnownProblems {
    // Protocol Error section
    ProtocolError,
    TrustlError,
    CryptoTrusError,
    XferError,
    DidError,
    MsgError,
    MeErro,
    MeResError,
    ReqError,
    ReqTimeError,
    LegalError,

    // Protocol warning section
    ProtocolWarning,
    TrustWarning,
    CryptoTrustWarning,
    XferWarning,
    DidWarning,
    MsgWarning,
    MeWarning,
    MeResWarning,
    ReqWarning,
    ReqTimeWarning,
    LegalWarning,

    /// Error - Unknown - No data
    #[serde(rename = "e.u.no-data")]
    Unknown,
}

impl Default for KnownProblems {
    fn default() -> Self {
        KnownProblems::Unknown
    }
}

impl ToString for KnownProblems {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap_or_default()
    }
}
