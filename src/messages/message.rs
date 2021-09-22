use std::{convert::TryInto, time::SystemTime};
use aes_gcm::{Aes256Gcm, aead::generic_array::GenericArray};
use k256::elliptic_curve::rand_core;
use rand::{Rng, prelude::SliceRandom};
use serde::{Serialize, Deserialize};
use serde_json::{
    json,
    Value,
    value::RawValue,
};
use super::{
    mediated::Mediated,
    headers::{DidcommHeader, JwmHeader},
    prior_claims::PriorClaims,
};
use arrayref::array_ref;
#[cfg(feature = "resolve")]
pub use ddoresolver_rs::*;
use {
    x25519_dalek::{
        StaticSecret,
        PublicKey
    },
    rand_chacha::ChaCha20Rng,
    rand::{RngCore, SeedableRng},
    chacha20poly1305::{
        XChaCha20Poly1305,
        XNonce,
        aead::{
            Aead,
            NewAead
        },
    },
    crate::{
        Jwk,
        Recepient,
        KeyAlgorithm,
    },
};
#[cfg(feature = "raw-crypto")]
use crate::crypto::{
    CryptoAlgorithm,
    SignatureAlgorithm,
    Cypher,
    Signer,
};
use std::convert::TryFrom;
use sha2::{Digest, Sha256};
use crate::{Error, Jwe, Jws, MessageType, Signature};

/// DIDComm message structure.
/// [Specification](https://identity.foundation/didcomm-messaging/spec/#message-structure)
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Message {
    /// JOSE header, which is sent as public part with JWE.
    #[serde(flatten)]
    pub jwm_header: JwmHeader,
    /// DIDComm headers part, sent as part of encrypted message in JWE.
    #[serde(flatten)]
    pub didcomm_header: DidcommHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recepients: Option<Vec<Recepient>>,
    /// Message payload, which can be basically anything (JSON, text, file, etc.) represented
    ///     as base64url String of raw bytes of data.
    /// No direct access for encode/decode purposes! Use `get_body()` / `set_body()` methods instead.
    pub(crate) body: Value,
    /// Flag that toggles JWE serialization to flat JSON.
    /// Not part of the serialized JSON and ignored when deserializing.
    #[serde(skip)]
    pub serialize_flat_jwe: bool,
    /// Flag that toggles JWS serialization to flat JSON.
    /// Not part of the serialized JSON and ignored when deserializing.
    #[serde(skip)]
    pub serialize_flat_jws: bool,
}

/// Helper type to check if received message is plain, signed or encrypted
#[derive(Serialize, Deserialize, Debug)]
pub struct UnknownReceivedMessage<'a> {
    #[serde(borrow)]
    pub signature: Option<&'a RawValue>,
    #[serde(borrow)]
    pub signatures: Option<&'a RawValue>,
    #[serde(borrow)]
    pub iv: Option<&'a RawValue>,
}

impl Message {
    /// Generates EMPTY default message.
    /// Use extension messages to build final one before `send`ing.
    ///
    pub fn new() -> Self {
        match env_logger::try_init() { Ok(_) | Err(_) => () }
        Message {
            jwm_header: JwmHeader::default(),
            didcomm_header: DidcommHeader::new(),
            recepients: None,
            body: json!({}),
            serialize_flat_jwe: false,
            serialize_flat_jws: false,
        }
    }
    /// Setter of `from` header
    /// Helper method.
    ///
    pub fn from(mut self, from: &str) -> Self {
        self.didcomm_header.from = Some(String::from(from));
        self
    }
    /// Setter of `to` header
    /// Helper method.
    ///
    pub fn to(mut self, to: &[&str]) -> Self {
        for s in to {
            self.didcomm_header.to.push(s.to_string());
        }
        while let Some(a) = self.didcomm_header.to.iter().position(|e| e == &String::default()) {
            self.didcomm_header.to.remove(a);
        }
        self
    }
    /// Setter of `m_type` @type header
    /// Helper method.
    ///
    pub fn m_type(mut self, m_type: MessageType) -> Self {
        self.jwm_header.typ = m_type;
        self
    }
    /// Getter of the `body` as ref of bytes slice.
    /// Helpe method.
    ///
    pub fn get_body(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&self.body)?)
    }
    /// Setter of the `body`
    /// Helper method.
    ///
    pub fn set_body(mut self, body: &str) -> Self {
        self.body = serde_json::from_str(body).unwrap();
        self
    }
    // Setter of the `kid` header
    // Helper method.
    //
    pub fn kid(mut self, kid: &str) -> Self {
        match &mut self.jwm_header.kid {
            Some(h) => *h = kid.into(),
            None => {
                self.jwm_header.kid = Some(kid.into());
            }
        }
        self
    }
    /// Sets times of creation as now and, optional, expires time.
    /// # Parameters
    /// * `expires` - time in seconds since Unix Epoch when message is
    /// considered to be invalid.
    ///
    pub fn timed(mut self, expires: Option<u64>) -> Self {
        self.didcomm_header.expires_time = expires;
        self.didcomm_header.created_time =
            match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(t) => Some(t.as_secs()),
                Err(_) => None,
            };
        self
    }
    /// Checks if message is rotation one.
    /// Exposed for explicit checks on calling code level.
    ///
    pub fn is_rotation(&self) -> bool {
        self.didcomm_header.from_prior().is_some()
    }
    /// If message `is_rotation()` true - returns from_prion claims.
    /// Errors otherwise with `Error::NoRotationData`
    ///
    pub fn get_prior(&self) -> Result<PriorClaims, Error> {
        if self.is_rotation() {
            Ok(self.didcomm_header.from_prior().clone().unwrap())
        } else {
           Err(Error::NoRotationData)
        }
    }
    /// `&DidcommHeader` getter.
    ///
    pub fn get_didcomm_header(&self) -> &DidcommHeader {
        &self.didcomm_header
    }
    /// Setter of `didcomm_header`.
    /// Replaces existing one with provided by consuming both values.
    /// Returns modified instance of `Self`.
    ///
    pub fn set_didcomm_header(mut self, h: DidcommHeader) -> Self {
        self.didcomm_header = h;
        self
    }
    /// Adds (or updates) custom unique header key-value pair to the header.
    /// This portion of header is not sent as JOSE header.
    ///
    pub fn add_header_field(mut self, key: String, value: String) -> Self {
        if key.len() == 0 {
            return self;
        }
        self.didcomm_header.other.insert(key, value);
        self
    }
    /// Creates set of Jwm related headers for the JWE
    /// Modifies JWM related header portion to match
    ///     encryption implementation and leaves other
    ///     parts unchanged.  TODO + FIXME: complete implementation
    pub fn as_jws(mut self, alg: &SignatureAlgorithm) -> Self {
        self.jwm_header.as_signed(alg);
        self
    }
    /// Sets message to be serialized as flat JWS JSON and then calls `as_jws`.
    /// If this message has multiple targets, `seal`ing it will result in an Error.
    pub fn as_flat_jws(mut self, alg: &SignatureAlgorithm) -> Self {
        self.serialize_flat_jws = true;
        self.as_jws(alg)
    }
    /// Creates set of Jwm related headers for the JWS
    /// Modifies JWM related header portion to match
    ///     signature implementation and leaves Other
    ///     parts unchanged.
    ///
    /// For `resolve` feature will set `kid` header automatically
    ///     based on the did document resolved.
    ///
    pub fn as_jwe(mut self, alg: &CryptoAlgorithm, recipient_public_key: Option<&[u8]>) -> Self {
        self.jwm_header.as_encrypted(alg);
        if let Some(key) = recipient_public_key {
            self.jwm_header.kid = Some(base64_url::encode(&key));
        } else {
            #[cfg(feature = "resolve")]
            {
                if let Some(from) = &self.didcomm_header.from {
                    if let Some(document) = resolve_any(from) {
                        match alg {
                            CryptoAlgorithm::XC20P | CryptoAlgorithm::A256GCM =>
                                    self.jwm_header.kid =
                                        document.find_public_key_id_for_curve("X25519")
                        }
                    }
                }
            }
        }
        self
    }
    /// Sets message to be serialized as flat JWE JSON.
    /// If this message has multiple targets, `seal`ing it will result in an Error.
    pub fn as_flat_jwe(mut self, alg: &CryptoAlgorithm, recipient_public_key: Option<&[u8]>) -> Self {
        self.serialize_flat_jwe = true;
        self.as_jwe(alg, recipient_public_key)
    }
    /// Serializez current state of the message into json.
    /// Consumes original message - use as raw sealing of envelope.
    ///
    pub fn as_raw_json(self) -> Result<String, Error> {
        Ok(serde_json::to_string(&self)?)
    }
    /// Seals self and returns ready to send JWE
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    // TODO: Add examples
    // pub fn seal(self, ek: impl AsRef<[u8]>) -> Result<String, Error> {
    //     let alg = crypter_from_header(&self.jwm_header)?;
    //     self.encrypt(alg.encryptor(), ek.as_ref())
    // }
  //  #[cfg(feature = "resolve")]
    pub fn seal(
        mut self,
        sk: impl AsRef<[u8]>,
        recipient_public_key: Option<&[u8]>,
    ) -> Result<String, Error> {
        if sk.as_ref().len() != 32 { return Err(Error::InvalidKeySize("!32".into())); }
        // generate content encryption key
        let mut cek = [0u8; 32];
        let mut rng = ChaCha20Rng::from_seed(Default::default());
        rng.fill_bytes(&mut cek);
        trace!("sealing message with shared_key: {:?}", &cek.as_ref());

        if self.didcomm_header.to.len() == 0 as usize {
            todo!(); // What should happen in this scenario?
        } else if self.serialize_flat_jwe && self.didcomm_header.to.len() > 1 {
            return Err(Error::Generic("flat JWE serialization only supports a single `to`".to_string()));
        }

        let mut recepients: Vec<Recepient> = vec!();
        // create jwk from static secret per recepient
        for dest in &self.didcomm_header.to {
            let rv = self.encrypt_cek(&sk.as_ref(), dest, &cek, recipient_public_key)?;
            recepients.push(Recepient::new(
                rv.header,
                rv.encrypted_key,
            ));
        }
        self.recepients = Some(recepients);
        // encrypt original message with static secret
        let alg = crypter_from_header(&self.jwm_header)?;
        self.encrypt(alg.encryptor(), cek.as_ref())
    }
    /// Signs raw message and then packs it to encrypted envelope
    /// [Spec](https://identity.foundation/didcomm-messaging/spec/#message-signing)
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `signing_sender_private_key` - signing key for enveloped message JWS encryption
    ///
    /// `alg` - encryption algorithm used
    ///
    /// `recipient_public_key` - can be provided if key should not be resolved via recipients DID
    // TODO: Adde examples
    //
    pub fn seal_signed(
        self,
        ek: &[u8],
        signing_sender_private_key: &[u8],
        signing_algorithm: SignatureAlgorithm,
        encryption_recipient_public_key: Option<&[u8]>,
    ) -> Result<String, Error> {
        let mut to = self.clone();
        let signed = self
            .as_jws(&signing_algorithm)
            .sign(signing_algorithm.signer(), signing_sender_private_key)?;
        to.body = serde_json::from_str(&signed)?;
        return to
            .m_type(MessageType::DidcommJws)
            .seal(ek, encryption_recipient_public_key);
    }
    // #[cfg(feature = "resolve")]
    // pub fn seal_signed(
    //     self,
    //     ek: &[u8],
    //     sk
    //     signing_algorithm: SignatureAlgorithm
    // ) -> Result<String, Error> {

    // }
    /// Wrap self to be mediated by some mediator.
    /// Warning: Should be called on a `Message` instance which is ready to be sent!
    /// If message is not properly set up for crypto - this method will propogate error from
    ///     called `.seal()` method.
    /// Takes one mediator at a time to make sure that mediated chain preserves unchanged.
    /// This method can be chained any number of times to match all the mediators in the chain.
    ///
    /// # Parameters
    ///
    /// `ek` - encryption key for inner message payload JWE encryption
    ///
    /// `to` - list of destination recepients. can be empty (Optional) `String::default()`
    ///
    /// `form` - used same as in wrapped message, fails if not present with `DidResolveFailed` error.
    ///
    /// `recipient_public_key` - can be provided if key should not be resolved via recipients DID
    ///
    /// TODO: Add examples
    pub fn routed_by(
        self,
        ek: &[u8],
        mediator_did: &str,
        mediator_public_key: Option<&[u8]>,
        recipient_public_key: Option<&[u8]>,
    ) -> Result<String, Error> {
        let from = &self.didcomm_header.from.clone().unwrap_or_default();
        let alg = crypter_from_header(&self.jwm_header)?;
        let body = Mediated::new(self.didcomm_header.to[0].clone().into())
            .with_payload(self.seal(ek, recipient_public_key)?.as_bytes().to_vec());
        Message::new()
            .to(&[mediator_did])
            .from(&from)
            .as_jwe(&alg, mediator_public_key)
            .m_type(MessageType::DidcommForward)
            .set_body(&serde_json::to_string(&body)?)
            .seal(ek, mediator_public_key)
    }

    /// Creates a key used to encrypt/decrypt keys (key encryption key).
    ///
    /// # Parameters
    ///
    /// `did` - receiver of a message (during encryption) or sender of a message (during decryption)
    ///
    /// `sk` - senders private key (encryption) or receivers private key (decryption)
    ///
    /// `ze` - temporary secret zE
    ///
    /// `alg` - encryption algorithm used
    ///
    /// `recipient_public_key` - can be provided if key should not be resolved via recipients DID
    fn get_kek(
        did: &str,
        sk: &[u8],
        ze: impl AsRef<[u8]>,
        alg: &str,
        recipient_public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        // zS (shared for recipient)
        let shared = gen_shared_for_recepient(sk.as_ref(), did, recipient_public_key)?;
        trace!("sk: {:?} shared: {:?} dest: {:?}", sk, &shared.as_ref(), did);

        // shared secret
        let shared_secret = [ze.as_ref(), shared.as_ref()].concat();
        trace!("shared_secret: {:?}", &shared_secret);

        // key encryption key
        let kek = concat_kdf(&shared_secret, alg, None, None)?;
        trace!("kek: {:?}", &kek);

        Ok(kek)
    }

    /// Encrypts the content encryption key with a key encryption key.
    ///
    /// # Parameters
    ///
    /// `sk` - senders private key
    ///
    /// `dest` - receiver to encrypt cek for
    ///
    /// `cek` - key used to encrypt content with, will be encrypted per recipient
    ///
    /// `recipient_public_key` - can be provided if key should not be resolved via recipients DID
    fn encrypt_cek(
        &self,
        sk: &[u8],
        dest: &str,
        cek: &[u8; 32],
        recipient_public_key: Option<&[u8]>,
    ) -> Result<Recepient, Error> {
        trace!("creating per-recipient JWE value for {}", &dest);
        let alg = self.jwm_header.alg.as_ref()
            .ok_or_else(|| Error::Generic("missing encryption 'alg' in header".to_string()))?;
        trace!("using algorithm {}", &alg);

        // zE (temporary secret)
        let epk = StaticSecret::new(rand_core::OsRng);
        let epk_public = PublicKey::from(&epk);
        let ze = gen_shared_for_recepient(epk.to_bytes(), dest, recipient_public_key)?;
        trace!("ze: {:?} epk_public: {:?}, dest: {:?}", &ze.as_ref(), epk_public,  dest);

        // key encryption key
        let kek = Self::get_kek(dest, sk, ze, alg, recipient_public_key)?;
        trace!("kek: {:?}", &kek);

        // preparation for initial vector
        let mut rng = rand::thread_rng();
        let mut iv: Vec<u8>;

        // start building jwk
        let mut jwk = Jwk::new();
        jwk.kid = Some(key_id_from_didurl( &dest));

        let sealed_cek_and_tag: Vec<u8> = match alg.as_ref() {
            "ECDH-1PU+A256KW" => {
                jwk.alg = KeyAlgorithm::Ecdh1puA256kw;

                // initial vector
                iv = rng.gen::<[u8; 12]>().to_vec();
                iv.shuffle(&mut rng);

                // encrypt jwk for each recipient using shared secret
                let kek_key = GenericArray::from_slice(kek.as_slice());
                let crypter = Aes256Gcm::new(kek_key);
                trace!("iv: {:?}", &iv);
                let nonce = GenericArray::from_slice(iv.as_ref());
                trace!("nonce: {:?}", &nonce);
                crypter
                    .encrypt(nonce, cek.as_ref())
                    .map_err(|e| Error::Generic(e.to_string()))?
            },
            "ECDH-1PU+XC20PKW" => {
                jwk.alg = KeyAlgorithm::Ecdh1puXc20pkw;

                // initial vector
                iv = rng.gen::<[u8; 24]>().to_vec();
                iv.shuffle(&mut rng);

                // encrypt jwk for each recipient using shared secret
                let kek_key = chacha20poly1305::Key::from_slice(kek.as_slice());
                let crypter = XChaCha20Poly1305::new(kek_key);
                trace!("iv: {:?}", &iv);
                let nonce = XNonce::from_slice(iv.as_ref());
                trace!("nonce: {:?}", &nonce);
                crypter
                    .encrypt(nonce, cek.as_ref())
                    .map_err(|e| Error::Generic(e.to_string()))?
            },
            _ => { return Err(Error::Generic(format!("encryption algorithm '{}' not implemented", &alg))); },
        };

        let (sealed_cek, tag) = sealed_cek_and_tag.split_at(sealed_cek_and_tag.len() - 16);
        jwk.add_other_header("iv".to_string(), base64_url::encode(&iv));
        jwk.add_other_header("tag".to_string(), base64_url::encode(&tag));

        // finish jwk and build result
        let jwk = jwk.ephemeral(
            "OKP".to_string(),
            "X25519".to_string(),
            base64_url::encode(epk_public.as_bytes()),
            None,
        );
        Ok(Recepient {
            header: jwk,
            encrypted_key: base64_url::encode(sealed_cek),
        })
    }

    /// Decrypts the content encryption key with a key encryption key.
    ///
    /// # Parameters
    ///
    /// `jwe` - jwe to decrypt content encryption key for
    ///
    /// `sk` - receivers private key
    ///
    /// `recipient` - recipient data from JWE
    ///
    /// `recipient_public_key` - can be provided if key should not be resolved via recipients DID
    fn decrypt_cek(
        jwe: &Jwe,
        sk: &[u8],
        recipient: &Recepient,
        recipient_public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        trace!("decrypting per-recipient JWE value");
        let alg = jwe.alg()
            .ok_or_else(|| Error::Generic("missing encryption 'alg' in header".to_string()))?;
        trace!("using algorithm {}", &alg);

        let skid = jwe.skid()
            .ok_or_else(|| Error::Generic("missing 'skid' in header".to_string()))?;

        // zE (temporary secret)
        let epk = recipient.header.epk.as_ref()
            .ok_or_else(|| Error::Generic("JWM header is missing epk".to_string()))?;
        let epk_public_array: [u8; 32] = base64_url::decode(&epk.x)?
            .try_into()
            .map_err(|_err| Error::Generic("failed to decode epk public key".to_string()))?;
        let epk_public = PublicKey::from(epk_public_array);
        let ss = StaticSecret::from(array_ref!(sk, 0, 32).to_owned())
            .diffie_hellman(&epk_public);
        let ze = *ss.as_bytes();
        trace!("ze: {:?}", &ze.as_ref());

        // key encryption key
        let kek = Self::get_kek(&skid, sk, ze, &alg, recipient_public_key)?;
        trace!("kek: {:?}", &kek);

        let iv = recipient.header.other.get("iv")
            .ok_or_else(|| Error::Generic("missing iv in header".to_string()))?;
        let iv_bytes = base64_url::decode(&iv)?;

        let tag = recipient.header.other.get("tag")
            .ok_or_else(|| Error::Generic("missing tag in header".to_string()))?;
        let mut cyphertext_and_tag: Vec<u8> = vec![];
        cyphertext_and_tag.extend(base64_url::decode(&recipient.encrypted_key)?);
        cyphertext_and_tag.extend(&base64_url::decode(&tag)?);

        match alg.as_ref() {
            "ECDH-1PU+XC20PKW" => {
                let nonce = XNonce::from_slice(&iv_bytes);
                let kek_key = chacha20poly1305::Key::from_slice(kek.as_slice());
                let crypter = XChaCha20Poly1305::new(kek_key);

                let cek = crypter
                    .decrypt(nonce, cyphertext_and_tag.as_ref())
                    .map_err(|e| Error::Generic(e.to_string()))?;

                Ok(cek)
            },
            "ECDH-1PU+A256KW" => {
                let nonce = GenericArray::from_slice(&iv_bytes);
                let kek_key = GenericArray::from_slice(kek.as_slice());
                let crypter = Aes256Gcm::new(kek_key);

                let cek = crypter
                    .decrypt(nonce, cyphertext_and_tag.as_ref())
                    .map_err(|e| Error::Generic(e.to_string()))?;

                Ok(cek)
            },
            _ => Err(Error::Generic(format!("encryption algorithm '{}' not implemented", &alg))),
        }
    }
}

fn crypter_from_header(header: &JwmHeader) -> Result<CryptoAlgorithm, Error> {
    match &header.alg {
        None => Err(Error::JweParseError),
        Some(alg) => alg.try_into()
    }
}

fn length_and_input(vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut collected: Vec<u8> = u32::try_from(vector.len())
        .map_err(|err| Error::Generic(err.to_string()))?
        .to_be_bytes()
        .to_vec();
    collected.extend(vector);
    Ok(collected)
}

fn concat_kdf(
    secret: &Vec<u8>,
    alg: &str,
    producer_info: Option<&Vec<u8>>,
    consumer_info: Option<&Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let mut value = length_and_input(alg.as_bytes())?;
    if let Some(vector) = producer_info {
        value.extend(length_and_input(vector)?);
    } else {
        value.extend(&[0, 0, 0, 0]);
    }
    if let Some(vector) = consumer_info {
        value.extend(length_and_input(vector)?);
    } else {
        value.extend(&[0, 0, 0, 0]);
    }
    // only key length 256 is supported
    value.extend(&[0, 0, 1, 0]);

    // since our key length is 256 we only have to do one round
    let mut to_hash: Vec<u8> = vec![0, 0, 0, 1];
    to_hash.extend(secret);
    to_hash.extend(value);

    let mut hasher = Sha256::new();
    hasher.input(&to_hash);
    let hash_result = hasher.result();
    let hashed = hash_result.as_slice();

    Ok(hashed.to_vec())
  }

/// Associated functions implementations.
/// Possibly not required as Jwe serialization covers this.
///
impl Message {
    /// Parses `iv` value as `Vec<u8>` from public header.
    /// Both regular JSON and Compact representations are accepted.
    /// Returns `Error` on failure.
    /// TODO: Add examples
    pub fn get_iv(received: &[u8]) -> Result<Vec<u8>, Error> {
        // parse from compact
        let as_str = String::from_utf8(received.to_vec())?;
        let json: serde_json::Value =
            if let Some(header_end) = as_str.find('.') {
                    serde_json::from_str(
                        &String::from_utf8(
                            base64_url::decode(&as_str[..header_end])?
                        )?
                    )?
            } else {
                serde_json::from_str(&as_str)?
            };
        if let Some(iv) = json.get("iv") {
            if let Some(t) = iv.as_str() {
            if t.len() != 24 {
                Err(Error::Generic(format!("IV [nonce] size is incorrect: {}", t.len())))
            } else {
                Ok(t.as_bytes().to_vec())
            }
            } else {
                Err(Error::Generic("wrong nonce format".into()))
            }
        } else {
            Err(Error::Generic("iv is not found in JOSE header".into()))
        }
    }

    /// Construct a message from received data.
    /// Raw, JWS or JWE payload is accepted.
    /// 
    /// # Parameters
    ///
    /// `incoming` - serialized message as `Message`/`Jws`/`Jws`
    ///
    /// `encryption_receiver_private_key` - receivers private key, used to decrypt `kek` in JWE
    ///
    /// `encryption_sender_public_key` - senders public key, used to decrypt `kek` in JWE
    ///
    /// `signing_sender_public_key` - senders public key, the JWS envelope was signed with
    pub fn receive(
        incoming: &str,
        encryption_receiver_private_key: Option<&[u8]>,
        encryption_sender_public_key: Option<&[u8]>,
        signing_sender_public_key: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut current_message: String = incoming.to_string();

        if Self::get_message_type(&current_message)? == MessageType::DidcommJwe {
            current_message = Self::receive_jwe(
                &current_message,
                encryption_receiver_private_key,
                encryption_sender_public_key,
            )?;
        }

        if Self::get_message_type(&current_message)? == MessageType::DidcommJws {
            current_message = Self::receive_jws(&current_message, signing_sender_public_key)?;
        }

        Ok(serde_json::from_str(&current_message)?)
    }

    fn get_message_type(message: &str) -> Result<MessageType, Error> {
        // try to skip parsing by using known fields from jwe/jws
        let to_check: UnknownReceivedMessage = serde_json::from_str(message)?;
        if to_check.iv.is_some() {
            return Ok(MessageType::DidcommJwe);
        }
        if to_check.signatures.is_some() || to_check.signature.is_some() {
            return Ok(MessageType::DidcommJws);
        }
        let message: Message = serde_json::from_str(message)?;
        Ok(message.jwm_header.typ)
    }

    fn receive_jwe(
        incoming: &str,
        encryption_receiver_private_key: Option<&[u8]>,
        encryption_sender_public_key: Option<&[u8]>,
    ) -> Result<String, Error> {
        let jwe: Jwe = serde_json::from_str(incoming)?;
        let alg = &jwe.alg().ok_or(Error::JweParseError)?;

        // get public key from input or from senders DID document
        let sender_public_key = match encryption_sender_public_key {
            Some(value) => value.to_vec(),
            None => {
                #[cfg(feature = "resolve")]
                {
                    let skid = &jwe.skid().ok_or_else(|| Error::Generic("skid missing".to_string()))?;
                    let document = ddoresolver_rs::resolve_any(skid).ok_or(Error::DidResolveFailed)?;
                    document.find_public_key_for_curve("X25519").ok_or(Error::BadDid)?
                }
                #[cfg(not(feature = "resolve"))]
                {
                    return Err(Error::DidResolveFailed)
                }
            },
        };
        let receiver_private_key = encryption_receiver_private_key
            .ok_or_else(|| Error::Generic("missing encryption receiver private key".to_string()))?;

        let shared = StaticSecret::from(array_ref!(receiver_private_key, 0, 32).to_owned())
            .diffie_hellman(&PublicKey::from(array_ref!(sender_public_key, 0, 32).to_owned()));
        let a: CryptoAlgorithm = alg.try_into()?;
        let m: Message;
        let recipients_from_jwe: Option<Vec<Recepient>>; 
        if jwe.recepients.as_ref().is_some() {
            recipients_from_jwe = jwe.recepients.clone();
        } else if let Some(recepient) = jwe.recepient.as_ref() {
            recipients_from_jwe = Some(vec![recepient.clone()]);
        } else {
            recipients_from_jwe = None;
        }
        if let Some(recepients) = recipients_from_jwe {
            let mut key: Vec<u8> = vec![];
            for recepient in recepients {
                let decrypted_key = Message::decrypt_cek(
                    &jwe,
                    &receiver_private_key,
                    &recepient,
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

    fn receive_jws(
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
            let key = Self::get_signing_sender_public_key(
                signing_sender_public_key,
                message.jwm_header.kid.as_ref(),
            )?;
            message_verified = Some(Message::verify(to_verify, &key)?);
        } else if let Ok(jws) = serde_json::from_str::<Jws>(&incoming) {
            let signatures_values_to_verify: Vec<Signature>;
            if let Some(signature_value) = jws.signature {
                signatures_values_to_verify = vec![signature_value.clone()];
            } else if let Some(signatures) = &jws.signatures {
                signatures_values_to_verify = signatures.clone();
            } else {
                return Err(Error::JwsParseError);
            }
            
            let incoming_string = incoming.to_string();
            let to_verify = incoming_string.as_bytes();
            for signature_value in signatures_values_to_verify {
                if signature_value.alg().is_none() { continue; }
                let key = Self::get_signing_sender_public_key(
                    signing_sender_public_key,
                    signature_value.kid().as_ref(),
                )?;
                if let Ok(message_result) = Message::verify(&to_verify, &key) {
                    message_verified = Some(message_result);
                    break;
                }
            }
        } else {
            return Err(Error::JwsParseError);
        }

        Ok(serde_json::to_string(&message_verified.ok_or(Error::JwsParseError)?)?)
    }

    /// Use given key from `signing_sender_public_key` or if `None`, use key from "kid".
    /// `kid` is currently "resolved" by hex-decoding it and using it as the public key.
    ///
    /// # Parameters
    ///
    /// `signing_sender_public_key` - optional senders public to verify signature
    ///
    /// `kid` - key reference to senders public key to verify signature
    fn get_signing_sender_public_key(
        signing_sender_public_key: Option<&[u8]>,
        kid: Option<&String>,
    ) -> Result<Vec<u8>, Error> {
        if let Some(key) = signing_sender_public_key {
            return Ok(key.to_vec());
        }
        if let Some(kid) = kid {
            return hex::decode(&kid).map_err(|_| Error::JwsParseError);
        }

        Err(Error::JwsParseError)
    }
}

#[allow(unused_variables)]
fn gen_shared_for_recepient(
    sk: impl AsRef<[u8]>,
    did: &str,
    recipient_public_key: Option<&[u8]>,
) -> Result<impl AsRef<[u8]>, Error> {
    let recipient_public = match recipient_public_key {
        Some(value) => value.to_vec(),
        None => {
            #[cfg(feature = "resolve")]
            {
                let document = resolve_any(did).ok_or(Error::DidResolveFailed)?;
                document.find_public_key_for_curve("X25519").ok_or(Error::DidResolveFailed)?
            }
            #[cfg(not(feature = "resolve"))]
            {
                return Err(Error::DidResolveFailed)
            }
        },
    };
    let ss = StaticSecret::from(array_ref!(sk.as_ref(), 0, 32).to_owned())
        .diffie_hellman(&PublicKey::from(array_ref!(recipient_public, 0, 32).to_owned()));

    Ok(*ss.as_bytes())
}

fn key_id_from_didurl(url: &str) -> String {
    let re = regex::Regex::new(r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):(?P<key_id>[a-zA-Z0-9]*)([:?/]?)(\S)*$").unwrap();
    match  re.captures(url) {
        Some(s) =>
            match s.name("key_id") {
                Some(name) =>
                    format!("did:key:{}", name.as_str()),
                None => String::default(),
            },
        None =>
            String::default()
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn iv_from_json_test() {
        // Arrange
        // Example JWM from RFC: https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3
        // Extendet twice to be 192bit (24byte) nonce.
        let raw_json = r#" { "protected": "eyJ0eXAiOiJKV00iLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiUEdvWHpzME5XYVJfbWVLZ1RaTGJFdURvU1ZUYUZ1eXJiV0k3VjlkcGpDZyIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiLU5oN1NoUkJfeGFDQlpSZElpVkN1bDNTb1IwWXc0VEdFUXFxR2lqMXZKcyIsInkiOiI5dEx4ODFQTWZRa3JPdzh5dUkyWXdJMG83TXROemFDR2ZDQmJaQlc1WXJNIn19",
                "recipients": [
                  {
                    "encrypted_key": "J1Fs9JaDjOT_5481ORQWfEZmHy7OjE3pTNKccnK7hlqjxbPalQWWLg"
                  }
                ],
                "iv": "u5kIzo0m_d2PjI4mu5kIzo0m",
                "ciphertext": "qGuFFoHy7HBmkf2BaY6eREwzEjn6O_FnRoXj2H-DAXo1PgQdfON-_1QbxtnT8e8z_M6Gown7s8fLtYNmIHAuixqFQnSA4fdMcMSi02z1MYEn2JC-1EkVbWr4TqQgFP1EyymB6XjCWDiwTYd2xpKoUshu8WW601HLSgFIRUG3-cK_ZSdFaoWosIgAH5EQ2ayJkRB_7dXuo9Bi1MK6TYGZKezc6rpCK_VRSnLXhFwa1C3T0QBes",
                "tag": "doeAoagwJe9BwKayfcduiw"
            }"#;
        // Act
        let iv = Message::get_iv(raw_json.as_bytes());
        // Assert
        assert!(iv.is_ok());
        assert_eq!("u5kIzo0m_d2PjI4mu5kIzo0m", &String::from_utf8(iv.unwrap()).unwrap());
    }
    #[test]
    fn iv_from_compact_json_test() {
        // Arrange
        // Example JWM from RFC: https://tools.ietf.org/html/draft-looker-jwm-01#section-2.3
        let compact = r#"eyJ0eXAiOiJKV00iLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiUEdvWHpzME5XYVJfbWVLZ1RaTGJFdURvU1ZUYUZ1eXJiV0k3VjlkcGpDZyIsImFsZyI6IkVDREgtRVMrQTI1NktXIiwiaXYiOiAidTVrSXpvMG1fZDJQakk0bXU1a0l6bzBtIn0."#;
        // Act
        let iv = Message::get_iv(compact.as_bytes());
        // Assert
        assert!(iv.is_ok());
        assert_eq!("u5kIzo0m_d2PjI4mu5kIzo0m", &String::from_utf8(iv.unwrap()).unwrap());
    }
}

#[cfg(test)]
mod crypto_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;

    use super::*;

    use k256::elliptic_curve::rand_core::OsRng;
    use utilities::{KeyPairSet, get_keypair_set};

    #[cfg(feature = "resolve")]
    use base58::FromBase58;

    #[test]
    #[cfg(feature = "resolve")]
    fn create_and_send() {
        let KeyPairSet { alice_private, .. } = get_keypair_set();
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, None);
        let p = m.seal(&alice_private, None);
        assert!(p.is_ok());
    }

    #[test]
    fn create_and_send_without_resolving_dids() {
        let KeyPairSet { alice_private, bobs_public, .. } = get_keypair_set();
        let m = Message::new()
            .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public));
        let p = m.seal(&alice_private, Some(&bobs_public));
        assert!(p.is_ok());
    }

    #[test]
    #[cfg(feature = "resolve")]
    fn receive_test() {
        // Arrange
        let KeyPairSet { alice_public, alice_private, bobs_private, .. } = get_keypair_set();
        // alice seals JWE
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, None);
        let jwe = m.seal(&alice_private, None).unwrap();

        // Act
        // bob receives JWE
        let received = Message::receive(&jwe, Some(&bobs_private), Some(&alice_public), None);

        // Assert
        assert!(received.is_ok());
    }

    #[test]
    fn receive_test_without_resolving_dids() {
        // Arrange
        let KeyPairSet { alice_public, alice_private, bobs_private, bobs_public, .. } = get_keypair_set();
        // alice seals JWE
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public));
        let jwe = m.seal(&alice_private, Some(&bobs_public)).unwrap();

        // Act
        // bob receives JWE
        let received = Message::receive(&jwe, Some(&bobs_private), Some(&alice_public), None);

        // Assert
        assert!(received.is_ok());
    }

    #[test]
    #[cfg(feature = "resolve")]
    fn send_receive_didkey_test() {
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, None);
        // TODO: validate derived pub from priv key <<<
        let KeyPairSet { alice_private, bobs_private, .. } = get_keypair_set();
        let jwe = m.seal(&alice_private, None);
        assert!(jwe.is_ok());

        let received = Message::receive(&jwe.unwrap(), Some(&bobs_private), None, None);
        assert!(received.is_ok());
    }

    #[test]
    fn send_receive_didkey_explicit_pubkey_test() {
        let KeyPairSet { alice_public, alice_private, bobs_private, bobs_public, .. } = get_keypair_set();
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public));

        let jwe = m.seal(&alice_private, Some(&bobs_public));
        assert!(jwe.is_ok());

        let received = Message::receive(
            &jwe.unwrap(),
            Some(&bobs_private),
            Some(&alice_public),
            None,
        );
        assert!(received.is_ok());
    }


    #[test]
    #[cfg(feature = "resolve")]
    fn send_receive_didkey_test_1pu_aes256() {
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::A256GCM, None);
        // TODO: validate derived pub from priv key <<<
        let KeyPairSet { alice_private, bobs_private, .. } = get_keypair_set();
        let jwe = m.seal(&alice_private, None);
        assert!(jwe.is_ok());

        let received = Message::receive(&jwe.unwrap(), Some(&bobs_private), None, None);
        assert!(received.is_ok());
    }


    #[test]
    #[cfg(feature = "resolve")]
    fn send_receive_didkey_test_1pu_aes256_explicit_pubkey() {
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::A256GCM, None);
        // TODO: validate derived pub from priv key <<<
        let KeyPairSet { alice_private, bobs_private, .. } = get_keypair_set();
        let jwe = m.seal(&alice_private, None);
        assert!(jwe.is_ok());

        let KeyPairSet { alice_public, .. } = get_keypair_set();

        let received = Message::receive(
            &jwe.unwrap(),
            Some(&bobs_private),
            Some(&alice_public),
            None,
        );
        assert!(received.is_ok());
    }

    #[test]
    #[cfg(feature = "resolve")]
    fn send_receive_didkey_multiple_receivers_test() {
        let m = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG", "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"])
            .as_jwe(&CryptoAlgorithm::XC20P, None);
        let KeyPairSet { alice_private, bobs_private, .. } = get_keypair_set();
        let third_private = "ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2".from_base58().unwrap();
        let jwe = m.seal(&alice_private, None);
        assert!(jwe.is_ok());

        let jwe = jwe.unwrap();
        let received_bob = Message::receive(&jwe, Some(&bobs_private), None, None);
        let received_third = Message::receive(&jwe, Some(&third_private), None, None);
        assert!(received_bob.is_ok());
        assert!(received_third.is_ok());
    }

    #[test]
    #[cfg(feature = "resolve")]
    fn mediated_didkey_test() {
        let mediator_private = "ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2".from_base58().unwrap();
        let KeyPairSet { alice_private, bobs_private, .. } = get_keypair_set();
        let sealed = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, None)
            .routed_by(&alice_private, "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf", None, None);
        assert!(sealed.is_ok());

        let mediator_received = Message::receive(
            &sealed.unwrap(),
            Some(&mediator_private),
            None,
            None,
        );
        assert!(mediator_received.is_ok());

        use crate::Mediated;
        let mediator_received_unwrapped = mediator_received.unwrap().get_body().unwrap();
        let pl_string = String::from_utf8_lossy(mediator_received_unwrapped.as_ref());
        let message_to_forward: Mediated = serde_json::from_str(&pl_string).unwrap();
        let attached_jwe = serde_json::from_slice::<Jwe>(&message_to_forward.payload);
        assert!(attached_jwe.is_ok());
        let str_jwe = serde_json::to_string(&attached_jwe.unwrap());
        assert!(str_jwe.is_ok());

        let bob_received = Message::receive(
            &String::from_utf8_lossy(&message_to_forward.payload),
            Some(&bobs_private),
            None,
            None,
        );
        assert!(bob_received.is_ok());
    }

    #[test]
    fn can_pass_explicit_signing_verification_keys() -> Result<(), Error> {
        let KeyPairSet {
            alice_private,
            alice_public,
            bobs_private,
            bobs_public,
            ..
        } = get_keypair_set();
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let body = r#"{"foo":"bar"}"#;
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .set_body(&body) // packing in some payload
            .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
            .kid(&hex::encode(vec![1; 32])); // invalid key, passing no key will not succeed

        let jwe_string = message.seal_signed(
            &alice_private,
            &sign_keypair.to_bytes(),
            SignatureAlgorithm::EdDsa,
            Some(&bobs_public),
        )?;

        let received_failure_no_key = Message::receive(
            &jwe_string,
            Some(&bobs_private),
            Some(&alice_public),
            None,
        );
        let received_failure_wrong_key = Message::receive(
            &jwe_string,
            Some(&bobs_private),
            Some(&alice_public),
            Some(&vec![0; 32]),
        );
        let received_success = Message::receive(
            &jwe_string,
            Some(&bobs_private),
            Some(&alice_public),
            Some(&sign_keypair.public.to_bytes()),
        );

        // Assert
        assert!(&received_failure_no_key.is_err());
        assert!(&received_failure_wrong_key.is_err());
        assert!(&received_success.is_ok());
        let received = received_success.unwrap();
        let sample_body: Value = serde_json::from_str(&body).unwrap();
        let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
        assert_eq!(
            sample_body.to_string(),
            received_body.to_string(),
        );
        
        Ok(())
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;

    use k256::elliptic_curve::rand_core::OsRng;
    use std::str::from_utf8;
    use utilities::{KeyPairSet, get_keypair_set};

    #[test]
    fn sets_message_type_correctly_for_plain_messages() -> Result<(), Error> {
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"]);
        
        let jwm_string: String = serde_json::to_string(&message)?;
        let jwm_object: Value = serde_json::from_str(&jwm_string)?;

        assert_eq!(jwm_object["typ"].as_str().is_some(), true);
        assert_eq!(
            jwm_object["typ"].as_str().ok_or(Error::JwmHeaderParseError)?,
            "application/didcomm-plain+json",
        );
        
        Ok(())
    }

    #[test]
    fn sets_message_type_correctly_for_signed_messages() -> Result<(), Error> {
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let jws_string = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_flat_jws(&SignatureAlgorithm::EdDsa)
            .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes())?;

        let jws_object: Value = serde_json::from_str(&jws_string)?;
        assert_eq!(jws_object["protected"].as_str().is_some(), true);
        let protected_encoded = jws_object["protected"].as_str().ok_or(Error::JwmHeaderParseError)?;
        let protected_decoded_buffer = base64_url::decode(&protected_encoded.as_bytes())?;
        let protected_decoded_string = from_utf8(&protected_decoded_buffer)
            .map_err(|_| Error::JwsParseError)?;
        let protected_object: Value = serde_json::from_str(&protected_decoded_string)?;

        assert_eq!(
            protected_object["typ"].as_str().ok_or(Error::JwmHeaderParseError)?,
            "application/didcomm-signed+json",
        );
        
        Ok(())
    }

    // ignored until proper `typ` handling has been clarified
    #[ignore]
    #[test]
    fn sets_message_type_correctly_for_signed_and_encrypted_messages() -> Result<(), Error> {
        let KeyPairSet { alice_private, bobs_public, ..  } = get_keypair_set();
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
            .kid(&hex::encode(sign_keypair.public.to_bytes()));

        let jwe_string = message.seal_signed(
            &alice_private,
            &sign_keypair.to_bytes(),
            SignatureAlgorithm::EdDsa,
            Some(&bobs_public),
        )?;

        let jwe_object: Value = serde_json::from_str(&jwe_string)?;

        assert_eq!(jwe_object["protected"].as_str().is_some(), true);
        let protected_encoded = jwe_object["protected"].as_str().ok_or(Error::JwmHeaderParseError)?;
        let protected_decoded_buffer = base64_url::decode(&protected_encoded.as_bytes())?;
        let protected_decoded_string = from_utf8(&protected_decoded_buffer)
            .map_err(|_| Error::JwsParseError)?;
        let protected_object: Value = serde_json::from_str(&protected_decoded_string)?;

        assert_eq!(
            protected_object["typ"].as_str().ok_or(Error::JwmHeaderParseError)?,
            "application/didcomm-encrypted+json",
        );
        
        Ok(())
    }

    #[test]
    fn sets_message_type_correctly_for_forwarded_messages() -> Result<(), Error> {
        let KeyPairSet {
            alice_private,
            bobs_public,
            mediators_public,
            ..
        } = get_keypair_set();
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public));

        let jwe_string = message
            .routed_by(
                &alice_private,
                "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf",
                Some(&mediators_public),
                Some(&bobs_public),
            )?;

        let jwe_object: Value = serde_json::from_str(&jwe_string)?;

        assert_eq!(jwe_object["protected"].as_str().is_some(), true);
        let protected_encoded = jwe_object["protected"].as_str().ok_or(Error::JwmHeaderParseError)?;
        let protected_decoded_buffer = base64_url::decode(&protected_encoded.as_bytes())?;
        let protected_decoded_string = from_utf8(&protected_decoded_buffer)
            .map_err(|_| Error::JwsParseError)?;
        let protected_object: Value = serde_json::from_str(&protected_decoded_string)?;

        assert_eq!(
            protected_object["typ"].as_str().ok_or(Error::JwmHeaderParseError)?,
            "https://didcomm.org/routing/2.0/forward",
        );
        
        Ok(())
    }

    #[test]
    fn serializes_missing_body_as_empty_object() -> Result<(), Error> {
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"]);
        
        let jwm_string: String = serde_json::to_string(&message)?;
        let jwm_object: Value = serde_json::from_str(&jwm_string)?;

        assert_eq!(jwm_object["body"].as_object().is_some(), true);
        assert_eq!(
            serde_json::to_string(&jwm_object["body"])?,
            "{}",
        );
        
        Ok(())
    }

    #[test]
    fn serializes_existing_body_as_object() -> Result<(), Error> {
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .set_body(r#"{"foo":"bar"}"#);
        
        let jwm_string: String = serde_json::to_string(&message)?;
        let jwm_object: Value = serde_json::from_str(&jwm_string)?;

        assert_eq!(jwm_object["body"].as_object().is_some(), true);
        assert_eq!(
            serde_json::to_string(&jwm_object["body"])?,
            r#"{"foo":"bar"}"#,
        );
        
        Ok(())
    }
}

#[cfg(test)]
mod jwe_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;

    use super::*;

    use k256::elliptic_curve::rand_core::OsRng;
    use utilities::{KeyPairSet, get_keypair_set};

    #[test]
    fn can_create_flat_jwe_json() -> Result<(), Error> {
        let KeyPairSet { alice_private, bobs_public, ..  } = get_keypair_set();
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
            .kid(&hex::encode(sign_keypair.public.to_bytes()));

        let jwe_string = message.seal_signed(
            &alice_private,
            &sign_keypair.to_bytes(),
            SignatureAlgorithm::EdDsa,
            Some(&bobs_public),
        )?;

        let jwe_object: Value = serde_json::from_str(&jwe_string)?;

        assert_eq!(jwe_object["recipients"].as_array().is_none(), true, "recipients present in JWE");
        assert_eq!(jwe_object["encrypted_key"].as_str().is_some(), true, "no recipients fields in JWE top level");
        assert_eq!(jwe_object["header"].as_object().is_some(), true, "no recipients fields in JWE top level");
        
        Ok(())
    }

    #[test]
    fn can_receive_flat_jwe_json() -> Result<(), Error> {
        let KeyPairSet {
            alice_private,
            alice_public,
            bobs_private,
            bobs_public,
            ..
        } = get_keypair_set();
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let body = r#"{"foo":"bar"}"#;
        let message = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .set_body(&body) // packing in some payload
            .as_flat_jwe(&CryptoAlgorithm::XC20P, Some(&bobs_public))
            .kid(&hex::encode(sign_keypair.public.to_bytes()));

        let jwe_string = message.seal_signed(
            &alice_private,
            &sign_keypair.to_bytes(),
            SignatureAlgorithm::EdDsa,
            Some(&bobs_public),
        )?;

        let received = Message::receive(
            &jwe_string,
            Some(&bobs_private),
            Some(&alice_public),
            None,
        );

        // Assert
        assert!(&received.is_ok());
        let received = received.unwrap();
        let sample_body: Value = serde_json::from_str(&body).unwrap();
        let received_body: Value = serde_json::from_str(&received.get_body().unwrap()).unwrap();
        assert_eq!(
            sample_body.to_string(),
            received_body.to_string(),
        );
        
        Ok(())
    }
}

#[cfg(test)]
mod jws_tests {
    extern crate chacha20poly1305;
    extern crate sodiumoxide;

    use super::*;

    use k256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn can_create_flattened_jws_jsons() -> Result<(), Error> {
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let jws_string = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .kid(&hex::encode(sign_keypair.public.to_bytes()))
            .as_flat_jws(&SignatureAlgorithm::EdDsa)
            .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes())?;

        let jws_object: Value = serde_json::from_str(&jws_string)?;

        assert_eq!(jws_object["signature"].as_str().is_some(), true);
        assert_eq!(jws_object["signatures"].as_array().is_some(), false);
        
        Ok(())
    }

    #[test]
    fn can_create_general_jws_jsons() -> Result<(), Error> {
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let jws_string = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .kid(&hex::encode(sign_keypair.public.to_bytes()))
            .as_jws(&SignatureAlgorithm::EdDsa)
            .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes())?;

        let jws_object: Value = serde_json::from_str(&jws_string)?;

        assert_eq!(jws_object["signature"].as_str().is_some(), false);
        assert_eq!(jws_object["signatures"].as_array().is_some(), true);
        
        Ok(())
    }

    #[test]
    fn can_receive_flattened_jws_jsons() -> Result<(), Error> {
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let jws_string = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .kid(&hex::encode(sign_keypair.public.to_bytes()))
            .as_flat_jws(&SignatureAlgorithm::EdDsa)
            .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes())?;

        // 'verify' style receive
        let received = Message::verify(&jws_string.as_bytes(), &sign_keypair.public.to_bytes());
        assert_eq!(received.is_ok(), true);

        // generic 'receive' style
        let received = Message::receive(
            &jws_string,
            Some(&vec![]),
            Some(&sign_keypair.public.to_bytes()),
            None,
        );
        assert_eq!(received.is_ok(), true);
        
        Ok(())
    }

    #[test]
    fn can_receive_general_jws_jsons() -> Result<(), Error> {
        let sign_keypair = ed25519_dalek::Keypair::generate(&mut OsRng);
        let jws_string = Message::new()
            .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
            .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
            .kid(&hex::encode(sign_keypair.public.to_bytes()))
            .as_jws(&SignatureAlgorithm::EdDsa)
            .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes())?;

        // 'verify' style receive
        let received = Message::verify(&jws_string.as_bytes(), &sign_keypair.public.to_bytes());
        assert_eq!(received.is_ok(), true);

        // generic 'receive' style
        let received = Message::receive(
            &jws_string,
            Some(&vec![]),
            Some(&sign_keypair.public.to_bytes()),
            None,
        );
        assert_eq!(received.is_ok(), true);
        
        Ok(())
    }
}
