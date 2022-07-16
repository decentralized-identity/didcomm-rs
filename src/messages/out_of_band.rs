use super::{AttachmentBuilder, Message, MessageType};

impl Message {
    /// Transforms given `Message` into out_of_band invitation
    /// with given body and optional attachments.
    ///
    /// # Parameters
    ///
    /// * `body` - bytes of JSON serialized message body
    /// * `attachments` - optional set of `AttachmentBuilder` to be attached
    pub fn as_out_of_band_invitation(
        mut self,
        body: impl AsRef<[u8]>,
        attachments: Option<Vec<AttachmentBuilder>>,
    ) -> Self {
        self.jwm_header.typ = MessageType::DidCommRaw;
        self.didcomm_header.m_type = serde_json::to_value(&MessageType::DidCommInvitation)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        if let Some(attachments) = attachments {
            for attachment in attachments {
                self.append_attachment(attachment);
            }
        }
        self.body(std::str::from_utf8(body.as_ref()).unwrap())
    }
}
