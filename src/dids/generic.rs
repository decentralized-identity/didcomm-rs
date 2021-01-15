#[derive(Serialize, Deserialize, Clone)]
pub struct GenericDid {
    #[serde(rename = "@context", skip_serializing_if = "String::is_empty", default)]
    context: String,
    id: String,
    #[serde(rename = "publicKey", skip_serializing_if = "Vec::is_empty", default)]
    public_key: Vec<u8>,
    authentication: Vec<Authentication>,
    serviec: Vec<Service>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Authentication {

}

#[derive(Serialize, Deserialize, Clone)]
pub struct Service {

}