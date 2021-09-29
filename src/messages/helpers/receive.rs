use std::convert::TryInto;

use arrayref::array_ref;
#[cfg(feature = "resolve")]
use ddoresolver_rs::*;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "raw-crypto")]
use crate::crypto::{CryptoAlgorithm, Cypher};
use crate::{
    helpers::{decrypt_cek, get_signing_sender_public_key},
    Error,
    Jwe,
    Jws,
    Message,
    MessageType,
    Recipient,
    Signature,
};

/// Helper type to check if received message is plain, signed or encrypted
#[derive(Serialize, Deserialize, Debug)]
struct UnknownReceivedMessage<'a> {
    #[serde(borrow)]
    pub signature: Option<&'a RawValue>,

    #[serde(borrow)]
    pub signatures: Option<&'a RawValue>,

    #[serde(borrow)]
    pub iv: Option<&'a RawValue>,
}

/// Tries to parse message and checks for well known fields to derive message type.
pub(crate) fn get_message_type(message: &str) -> Result<MessageType, Error> {
    // try to skip parsing by using known fields from jwe/jws
    let to_check: UnknownReceivedMessage = serde_json::from_str(message)?;
    if to_check.iv.is_some() {
        return Ok(MessageType::DidCommJwe);
    }
    if to_check.signatures.is_some() || to_check.signature.is_some() {
        return Ok(MessageType::DidCommJws);
    }
    let message: Message = serde_json::from_str(message)?;
    Ok(message.jwm_header.typ)
}

/// Receive a serialized message. This function handles receival of [`crate::Jwe`] envelopes.
///
/// # Arguments
///
/// * `incoming` - incoming message
///
/// * `encryption_receiver_private_key` - private key of receiver of a message, required
///
/// * `encryption_sender_public_key` - public key of message sender, can be omitted if public key
///                                    should be automatically resolved (requires `resolve` feature)
pub(crate) fn receive_jwe(
    incoming: &str,
    encryption_receiver_private_key: Option<&[u8]>,
    encryption_sender_public_key: Option<&[u8]>,
) -> Result<String, Error> {
    let jwe: Jwe = serde_json::from_str(incoming)?;
    let alg = &jwe.get_alg().ok_or(Error::JweParseError)?;
    let receiver_private_key = encryption_receiver_private_key
        .ok_or_else(|| Error::Generic("missing encryption receiver private key".to_string()))?;

    // get public key from input or from senders DID document
    let sender_public_key = match encryption_sender_public_key {
        Some(value) => value.to_vec(),
        None => {
            #[cfg(feature = "resolve")]
            {
                let skid = &jwe
                    .get_skid()
                    .ok_or_else(|| Error::Generic("skid missing".to_string()))?;
                let document = ddoresolver_rs::resolve_any(skid).ok_or(Error::DidResolveFailed)?;
                document
                    .find_public_key_for_curve("X25519")
                    .ok_or(Error::BadDid)?
            }
            #[cfg(not(feature = "resolve"))]
            {
                return Err(Error::DidResolveFailed);
            }
        }
    };

    let shared = StaticSecret::from(array_ref!(receiver_private_key, 0, 32).to_owned())
        .diffie_hellman(&PublicKey::from(
            array_ref!(sender_public_key, 0, 32).to_owned(),
        ));
    let a: CryptoAlgorithm = alg.try_into()?;
    let m: Message;
    let recipients_from_jwe: Option<Vec<Recipient>>;
    if jwe.recipients.as_ref().is_some() {
        recipients_from_jwe = jwe.recipients.clone();
    } else if let Some(recipient) = jwe.recipient.as_ref() {
        recipients_from_jwe = Some(vec![recipient.clone()]);
    } else {
        recipients_from_jwe = None;
    }
    if let Some(recipients) = recipients_from_jwe {
        let mut key: Vec<u8> = vec![];
        for recipient in recipients {
            let decrypted_key = decrypt_cek(
                &jwe,
                &receiver_private_key,
                &recipient,
                encryption_sender_public_key,
            );
            if decrypted_key.is_ok() {
                key = decrypted_key?;
                break;
            }
        }
        if !key.is_empty() {
            m = Message::decrypt(incoming.as_bytes(), a.decryptor(), &key)?;
        } else {
            return Err(Error::JweParseError);
        }
    } else {
        m = Message::decrypt(incoming.as_bytes(), a.decryptor(), shared.as_bytes())?;
    }

    Ok(serde_json::to_string(&m)?)
}

/// Receive a serialized message. This function handles receival of [`crate::Jws`] envelopes.
///
/// # Arguments
///
/// * `incoming` - incoming message
///
/// * `signing_sender_public_key` - senders public key, can be omitted if public key
///                                 should be automatically resolved (requires `resolve` feature)
pub(crate) fn receive_jws(
    incoming: &str,
    signing_sender_public_key: Option<&[u8]>,
) -> Result<String, Error> {
    // incoming data may be a jws string or a serialized message with jws data
    let mut message_verified = None::<Message>;
    if let Ok(message) = serde_json::from_str::<Message>(&incoming) {
        if message.jwm_header.alg.is_none() {
            return Err(Error::JweParseError);
        }
        let body = message.get_body()?;
        let to_verify = body.as_bytes();
        let key = get_signing_sender_public_key(
            signing_sender_public_key,
            message.jwm_header.kid.as_ref(),
        )?;
        message_verified = Some(Message::verify(to_verify, &key)?);
    } else if let Ok(jws) = serde_json::from_str::<Jws>(&incoming) {
        let signatures_values_to_verify: Vec<Signature>;
        if let Some(signatures) = &jws.signatures {
            signatures_values_to_verify = signatures.clone();
        } else if let Some(signature_value) = jws.signature {
            signatures_values_to_verify = vec![signature_value.clone()];
        } else {
            return Err(Error::JwsParseError);
        }

        let incoming_string = incoming.to_string();
        let to_verify = incoming_string.as_bytes();
        for signature_value in signatures_values_to_verify {
            if signature_value.get_alg().is_none() {
                continue;
            }
            let key = get_signing_sender_public_key(
                signing_sender_public_key,
                signature_value.get_kid().as_ref(),
            )?;
            if let Ok(message_result) = Message::verify(&to_verify, &key) {
                message_verified = Some(message_result);
                break;
            }
        }
    } else {
        return Err(Error::JwsParseError);
    }

    Ok(serde_json::to_string(
        &message_verified.ok_or(Error::JwsParseError)?,
    )?)
}
