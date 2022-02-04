use serde::{Deserialize, Serialize};

use crate::Message;

/// Attachment holding structure
///
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct AttachmentData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
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

impl Message {
    /// Appends attachment into `attachments` field.
    /// Consumes instance of `AttachmentBuilder` to do so.
    ///
    /// # Parameters
    ///
    /// * `builder` - prepopulated instance of `AttachmentBuilder`
    ///
    pub fn apeend_attachment(&mut self, builder: AttachmentBuilder) {
        self.attachments.push(builder.finalize());
    }

    /// Returns iterator of all attachments, if any.
    /// If no attachment present - empty iterator will be returned.
    ///
    pub fn get_attachments(&self) -> impl DoubleEndedIterator<Item = &Attachment> {
        self.attachments.iter()
    }
}
