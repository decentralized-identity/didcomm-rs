#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
    #[serde(rename = "dodcomm/jwe")]
    DidcommJwe,
    #[serde(rename = "dodcomm/jws")]
    DidcommJws,
    #[serde(rename = "didcomm/unknown")]
    DidcommUnknown,
    #[serde(rename = "https://didcomm.org/routing/2.0/forward")]
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
}
