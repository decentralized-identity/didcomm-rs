use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{Error, Message, Result};

/// Attachment holding structure
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct Attachment {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastmod_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_count: Option<usize>,
    pub data: AttachmentData,
}

/// Attachment Data holding structure
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct AttachmentData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

/// Builder for `AttachmentData`
pub struct AttachmentDataBuilder {
    inner: AttachmentData,
}

impl AttachmentDataBuilder {
    /// Constructor for default and empty data
    ///
    pub fn new() -> Self {
        Self {
            inner: AttachmentData::default(),
        }
    }

    /// Attach `jws` stringified property.
    ///
    /// # Parameters
    ///
    /// * `jws` - JSON Web Signature serialized into String
    ///
    pub fn with_jws(mut self, jws: &str) -> Self {
        self.inner.jws = Some(jws.into());
        self
    }

    /// [optional] The hash of the content encoded in multi-hash format.
    /// Used as an integrity check for the attachment,
    ///  and MUST be used if the data is referenced via the links data attribute.
    ///
    /// # Parameters
    ///
    /// * `hash` - String of hash to be attached
    ///
    pub fn with_hash(mut self, hash: &str) -> Self {
        self.inner.hash = Some(hash.into());
        self
    }

    /// [optional] A list of zero or more locations at which the content may be fetched.
    /// Adds one link into list of links. No uniqueness is guarranteed.
    ///
    /// # Parameters
    ///
    /// * `link` - String representation of where to fetch the attachment
    ///
    pub fn with_link(mut self, link: &str) -> Self {
        self.inner.links.push(link.into());
        self
    }

    /// Raw bytes of the payload to be attached - will be BASE64URL encoded
    ///  before attaching.
    ///
    /// # Parameters
    ///
    /// * `payload` - set of bytes to be attached as payload
    ///
    pub fn with_raw_payload(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.inner.base64 = Some(base64_url::encode(payload.as_ref()));
        self
    }

    /// Same as `with_raw_payload`, but data is already encoded
    ///
    /// # Parameters
    ///
    /// * `payload` - BASE64URL encoded bytes of payload
    ///
    pub fn with_encoded_payload(mut self, payload: &str) -> Self {
        self.inner.base64 = Some(payload.into());
        self
    }

    /// Attach stringified JSON object
    ///
    /// # Parameters
    ///
    /// * `stringified` - String of JSON object
    ///
    pub fn with_json(mut self, stringified: &str) -> Self {
        self.inner.json = Some(stringified.into());
        self
    }

    fn finalize(self) -> AttachmentData {
        self.inner
    }
}

impl Default for AttachmentDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder of attachment metadata and payload.
/// Used to construct and inject Attachment into `Message`
///
pub struct AttachmentBuilder {
    inner: Attachment,
    timed: bool,
}

impl AttachmentBuilder {
    /// Constructor of new instance of the builder.
    ///
    /// # Parameters
    ///
    /// * `included_mod_time` - `bool` value indicating
    /// if this attachment should be timestamped on attaching.
    /// If `true` - will update `lastmod_time` property on
    /// builder consumption.
    ///
    pub fn new(include_mod_time: bool) -> Self {
        Self {
            inner: Attachment::default(),
            timed: include_mod_time,
        }
    }

    /// Optional, but recommended identifier of attachment content.
    ///
    /// # Parameters
    ///
    /// * `id` - String of `Attachment` identifier
    ///
    pub fn with_id(mut self, id: &str) -> Self {
        self.inner.id = Some(id.into());
        self
    }

    /// Human redable description string
    ///
    /// # Parameters
    ///
    /// * `description` - String of description for this `Attachment`
    ///
    pub fn with_description(mut self, description: &str) -> Self {
        self.inner.description = Some(description.into());
        self
    }

    /// Attachment file name specifier.
    ///
    /// # Parameters
    ///
    /// * `filename` - name of the file attached
    ///
    pub fn with_filename(mut self, filename: &str) -> Self {
        self.inner.filename = Some(filename.into());
        self
    }

    /// Describes the media (MIME) type of the attached content
    ///
    /// # Parameters
    ///
    /// * `media_type` - String of media type description
    ///
    pub fn with_media_type(mut self, media_type: &str) -> Self {
        self.inner.media_type = Some(media_type.into());
        self
    }

    /// Describes the format of the attachment if the `media_type` is not sufficient.
    ///
    /// # Parameters
    ///
    /// * `format` - String format identifier
    ///
    pub fn with_format(mut self, format: &str) -> Self {
        self.inner.format = Some(format.into());
        self
    }

    /// mostly relevant when content is included by reference instead of by value.
    /// Lets the receiver guess how expensive it will be, in time, bandwidth, and storage, to fully fetch the attachment.
    ///
    /// # Parameters
    ///
    /// * `bytes` - usize of bytes.
    ///
    pub fn external_size(mut self, bytes: usize) -> Self {
        self.inner.byte_count = Some(bytes);
        self
    }

    /// Attach actual payload in form of `AttachmentData`
    /// Consumes `AttachmentDataBuilder` to do so.
    ///
    /// # Parameters
    ///
    /// * `attachment_data` - 'AttachmentDataBuilder' instance, prepopulated.
    ///
    pub fn with_data(mut self, attachment_data: AttachmentDataBuilder) -> Self {
        self.inner.data = attachment_data.finalize();
        self
    }

    fn timestamp(&mut self) {
        if self.timed {
            self.inner.lastmod_time = Some(chrono::Utc::now().to_string());
        }
    }

    fn finalize(mut self) -> Attachment {
        self.timestamp();
        self.inner
    }
}

impl<T> TryFrom<(&str, T)> for AttachmentBuilder
where
    T: Serialize,
{
    type Error = Error;
    fn try_from((format, data): (&str, T)) -> std::result::Result<Self, Self::Error> {
        let serialized = serde_json::to_string(&data)?;
        let builder = AttachmentBuilder::new(true)
            .with_media_type("application/json")
            .with_format(format)
            .with_data(AttachmentDataBuilder::new().with_json(&serialized));
        Ok(builder)
    }
}

impl Message {
    /// Appends attachment into `attachments` field.
    /// Consumes instance of `AttachmentBuilder` to do so.
    ///
    /// # Parameters
    ///
    /// * `builder` - prepopulated instance of `AttachmentBuilder`
    ///
    pub fn append_attachment(&mut self, builder: AttachmentBuilder) {
        self.attachments.push(builder.finalize());
    }

    /// Returns iterator of all attachments.
    pub fn attachment_iter(&self) -> impl DoubleEndedIterator<Item = &Attachment> {
        self.attachments.iter()
    }

    /// Deserializes a the attachements with media-type `fmt` into `Vec<T>`.
    ///
    /// # Error:
    /// It returns an error if media type is not `application/json` or if the media is invalid JSON document.
    pub fn deserialize_attachments<'de, T>(&'de self, fmt: &str) -> Result<Vec<T>>
    where
        T: Deserialize<'de>,
    {
        if fmt != "application/json" {
            return Err(Error::AttachmentError("unsupported media type".into()));
        }

        self.attachments
            .iter()
            .filter(|&att| att.format == Some(fmt.into()))
            .map(|attachment| match attachment.media_type {
                Some(ref media_type) if media_type == "application/json" => {
                    match &attachment.data.json {
                        Some(json) => serde_json::from_str(json).map_err(Error::SerdeError),
                        None if attachment.id.is_some() => Err(Error::AttachmentError(format!(
                            "attachment with id {} contains invalid JSON data",
                            attachment.id.clone().unwrap()
                        ))),
                        _ => Err(Error::AttachmentError("NO ATTACHMENT ID".into())),
                    }
                }
                _ => Err(Error::AttachmentError("unsupported media type".into()))?,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::Message;
    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    struct Data;

    #[test]
    fn try_from_successfully_creates_builder() {
        for (&format, data) in [
            "dif/presentation-exchange/definitions@v1.0",
            "dif/presentation-exchange/submission@v1.0",
        ]
        .iter()
        .zip([Data, Data])
        {
            let builder = AttachmentBuilder::try_from((format, data));
            assert!(builder.is_ok(), "failed to create builder");
        }
    }

    #[test]
    fn deserialize_json_formatteed_attachments_successfully() {
        let mut message = Message::new();
        let builder = AttachmentBuilder::try_from(("application/json", Data))
            .expect("failed to create builder");
        message.append_attachment(builder);
        let data: Vec<Data> = message
            .deserialize_attachments("application/json")
            .expect("failed to get attachments");
        assert_eq!(data.len(), 1)
    }

    #[test]
    #[should_panic(expected = "unsupported media type")]
    fn cannot_deserialize_attachments_with_invalid_format() {
        let mut message = Message::new();
        let builder = AttachmentBuilder::try_from(("application/json", Data))
            .expect("failed to create builder");
        message.append_attachment(builder);
        message
            .deserialize_attachments::<Data>("application/yaml")
            .unwrap();
    }
}
