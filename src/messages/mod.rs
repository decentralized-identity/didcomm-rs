use serde::Serialize;
use biscuit::ClaimsSet;

#[derive(Serialize)]
struct PriorClaims {
    sub: String,
    iss: String,
}

#[derive(Serialize)]
pub struct Message {
    id: usize,
    #[serde(rename = "type")]
    m_type: String,
    from: Option<String>,
    to: Option<Vec<String>>,
    created_time: Option<usize>,
    expires_time: Option<usize>,
    from_prior: Option<ClaimsSet<PriorClaims>>,
    body: Option<Vec<String>>,
}
