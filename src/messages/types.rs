/// Enum that represents DIDComm envelope type
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
    #[serde(rename = "application/didcomm-encrypted+json")]
    DidcommJwe,
    #[serde(rename = "application/didcomm-signed+json")]
    DidcommJws,
    #[serde(rename = "application/didcomm-plain+json")]
    DidcommRaw,
    #[serde(rename = "https://didcomm.org/routing/2.0/forward")]
    DidcommForward,
    #[serde(rename = "https://didcomm.org/out-of-band/2.0/invitation")]
    DidcommInvitation,
}

/// Enum that represents DIDComm message payload type
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ContentType {
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
