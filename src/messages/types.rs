#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessageType {
    #[serde(rename = "forward")]
    Forward,
    #[serde(rename = "application/pdf")]
    MediaPdf,
    #[serde(rename = "application/vnd.openxmlformats-")]
    MediaOpenXml,
    #[serde(rename = "application/json")]
    MediaJson,
    #[serde(rename = "application/ld+json")]
    MediaJsonLd,
    #[serde(rename = "application/zip")]
    ZipArchive,
    #[serde(rename = "application/octet-stream")]
    BinaryData,
    #[serde(rename = "dodcomm/jwe")]
    DidcommJwe,
    #[serde(rename = "dodcomm/jws")]
    DidcommJwm,
    #[serde(rename = "didcomm/unknown")]
    DidcommUnknown,
}