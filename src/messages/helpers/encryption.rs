use std::convert::{TryFrom, TryInto};

use aes_gcm::{aead::generic_array::GenericArray, Aes256Gcm};
use arrayref::array_ref;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305, XNonce,
};
#[cfg(feature = "resolve")]
use ddoresolver_rs::*;
use rand::{prelude::SliceRandom, Rng};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "raw-crypto")]
use crate::crypto::CryptoAlgorithm;
use crate::{Error, Jwe, Jwk, JwmHeader, KeyAlgorithm, Message, Recipient};

/// Decrypts the content encryption key with a key encryption key.
///
/// # Arguments
///
/// * `jwe` - jwe to decrypt content encryption key for
///
/// * `sk` - recipients private key
///
/// * `recipient` - recipient data from JWE
///
/// * `recipient_public_key` - can be provided if key should not be resolved via recipients DID
pub(crate) fn decrypt_cek(
    jwe: &Jwe,
    sk: &[u8],
    recipient: &Recipient,
    recipient_public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    trace!("decrypting per-recipient JWE value");
    let alg = jwe
        .get_alg()
        .ok_or_else(|| Error::Generic("missing encryption 'alg' in header".to_string()))?;
    trace!("using algorithm {}", &alg);

    let skid = jwe
        .get_skid()
        .ok_or_else(|| Error::Generic("missing 'skid' in header".to_string()))?;

    // zE (temporary secret)
    let epk = recipient
        .header
        .epk
        .as_ref()
        .ok_or_else(|| Error::Generic("JWM header is missing epk".to_string()))?;
    let epk_public_array: [u8; 32] = base64_url::decode(&epk.x)?
        .try_into()
        .map_err(|_err| Error::Generic("failed to decode epk public key".to_string()))?;
    let epk_public = PublicKey::from(epk_public_array);
    let ss = StaticSecret::from(array_ref!(sk, 0, 32).to_owned()).diffie_hellman(&epk_public);
    let ze = *ss.as_bytes();
    trace!("ze: {:?}", &ze.as_ref());

    // key encryption key
    let kek = generate_kek(&skid, sk, ze, &alg, recipient_public_key)?;
    trace!("kek: {:?}", &kek);

    let iv = recipient
        .header
        .other
        .get("iv")
        .ok_or_else(|| Error::Generic("missing iv in header".to_string()))?;
    let iv_bytes = base64_url::decode(&iv)?;

    let tag = recipient
        .header
        .other
        .get("tag")
        .ok_or_else(|| Error::Generic("missing tag in header".to_string()))?;
    let mut ciphertext_and_tag: Vec<u8> = vec![];
    ciphertext_and_tag.extend(base64_url::decode(&recipient.encrypted_key)?);
    ciphertext_and_tag.extend(&base64_url::decode(&tag)?);

    match alg.as_ref() {
        "ECDH-1PU+XC20PKW" => {
            let nonce = XNonce::from_slice(&iv_bytes);
            let kek_key = chacha20poly1305::Key::from_slice(kek.as_slice());
            let crypter = XChaCha20Poly1305::new(kek_key);

            let cek = crypter
                .decrypt(nonce, ciphertext_and_tag.as_ref())
                .map_err(|e| Error::Generic(e.to_string()))?;

            Ok(cek)
        }
        "ECDH-1PU+A256KW" => {
            let nonce = GenericArray::from_slice(&iv_bytes);
            let kek_key = GenericArray::from_slice(kek.as_slice());
            let crypter = Aes256Gcm::new(kek_key);

            let cek = crypter
                .decrypt(nonce, ciphertext_and_tag.as_ref())
                .map_err(|e| Error::Generic(e.to_string()))?;

            Ok(cek)
        }
        _ => Err(Error::Generic(format!(
            "encryption algorithm '{}' not implemented",
            &alg
        ))),
    }
}

/// Encrypts the content encryption key with a key encryption key.
///
/// # Arguments
///
/// * `message` - message the content encryption key should be encrypted for
///
/// * `sk` - senders private key
///
/// * `dest` - recipient to encrypt cek for
///
/// * `cek` - key used to encrypt content with, will be encrypted per recipient
///
/// * `recipient_public_key` - can be provided if key should not be resolved via recipients DID
pub(crate) fn encrypt_cek(
    message: &Message,
    sk: &[u8],
    dest: &str,
    cek: &[u8; 32],
    recipient_public_key: Option<Vec<u8>>,
) -> Result<Recipient, Error> {
    trace!("creating per-recipient JWE value for {}", &dest);
    let alg = message
        .jwm_header
        .alg
        .as_ref()
        .ok_or_else(|| Error::Generic("missing encryption 'alg' in header".to_string()))?;
    trace!("using algorithm {}", &alg);

    // zE (temporary secret)
    let epk = StaticSecret::new(rand_core::OsRng);
    let epk_public = PublicKey::from(&epk);
    let ze = generate_shared_for_recipient(epk.to_bytes(), dest, recipient_public_key.clone())?;
    trace!(
        "ze: {:?} epk_public: {:?}, dest: {:?}",
        &ze.as_ref(),
        epk_public,
        dest
    );

    // key encryption key
    let kek = generate_kek(dest, sk, ze, alg, recipient_public_key)?;
    trace!("kek: {:?}", &kek);

    // preparation for initial vector
    let mut rng = rand::thread_rng();
    let mut iv: Vec<u8>;

    // start building jwk
    let mut jwk = Jwk::new();
    jwk.kid = Some(get_did_from_didurl(dest));

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
        }
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
        }
        _ => {
            return Err(Error::Generic(format!(
                "encryption algorithm '{}' not implemented",
                &alg
            )));
        }
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
    Ok(Recipient {
        header: jwk,
        encrypted_key: base64_url::encode(sealed_cek),
    })
}

/// Create a `CryptoAlgorithm` by using headers `alg` value.
pub(crate) fn get_crypter_from_header(header: &JwmHeader) -> Result<CryptoAlgorithm, Error> {
    match &header.alg {
        None => Err(Error::JweParseError),
        Some(alg) => alg.try_into(),
    }
}

/// Use given key from `signing_sender_public_key` or if `None`, use key from "kid".
/// `kid` is currently "resolved" by hex-decoding it and using it as the public key.
///
/// # Arguments
///
/// * `signing_sender_public_key` - optional senders public to verify signature
///
/// * `kid` - key reference to senders public key to verify signature
pub(crate) fn get_signing_sender_public_key(
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

/// Concatenates key derivation function
fn concat_kdf(
    secret: &[u8],
    alg: &str,
    producer_info: Option<&Vec<u8>>,
    consumer_info: Option<&Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let mut value = get_length_and_input(alg.as_bytes())?;
    if let Some(vector) = producer_info {
        value.extend(get_length_and_input(vector)?);
    } else {
        value.extend(&[0, 0, 0, 0]);
    }
    if let Some(vector) = consumer_info {
        value.extend(get_length_and_input(vector)?);
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

/// Creates a key used to encrypt/decrypt keys (key encryption key).
///
/// # Arguments
///
/// * `did` - recipient of a message (during encryption) or sender of a message (during decryption)
///
/// * `sk` - senders private key (encryption) or recipient private key (decryption)
///
/// * `ze` - temporary secret zE
///
/// * `alg` - encryption algorithm used
///
/// * `recipient_public_key` - can be provided if key should not be resolved via recipients DID
fn generate_kek(
    did: &str,
    sk: &[u8],
    ze: impl AsRef<[u8]>,
    alg: &str,
    recipient_public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    // zS (shared for recipient)
    let shared = generate_shared_for_recipient(sk, did, recipient_public_key)?;
    trace!(
        "sk: {:?} shared: {:?} dest: {:?}",
        sk,
        &shared.as_ref(),
        did
    );

    // shared secret
    let shared_secret = [ze.as_ref(), shared.as_ref()].concat();
    trace!("shared_secret: {:?}", &shared_secret);

    // key encryption key
    let kek = concat_kdf(&shared_secret, alg, None, None)?;
    trace!("kek: {:?}", &kek);

    Ok(kek)
}

/// Generates shared secret for a message recipient with a senders public key and a recipients
/// private key. Key is taken from `recipient_public_key`, if it contains a value.
///
/// If `recipient_public_key` is set to `None`, the public key is automatically resolved by using
/// `recipient_did`, which is only possible if `resolve` feature is enabled.
///
/// If recipient_public_key` is set to `None`, and `resolve` feature is disabled, function
/// invocation will return an `Error`.
///
/// # Arguments
///
/// * `sender_private_key` - senders private key, used to generate a shared secret for recipient
///
/// * `recipient_did` - if `recipient_public_key` is `None`, used to resolved recipient public key
///                     if `resolve` feature is enabled
///
/// * `recipient_public_key` - public key, allows to skip public key resolving via
///                            via `recipient_did`
///
#[allow(unused_variables)]
fn generate_shared_for_recipient(
    sender_private_key: impl AsRef<[u8]>,
    recipient_did: &str,
    recipient_public_key: Option<Vec<u8>>,
) -> Result<impl AsRef<[u8]>, Error> {
    let recipient_public = match recipient_public_key {
        Some(value) => value.to_vec(),
        None => {
            #[cfg(feature = "resolve")]
            {
                let document = resolve_any(recipient_did).ok_or(Error::DidResolveFailed)?;
                document
                    .find_public_key_for_curve("X25519")
                    .ok_or(Error::DidResolveFailed)?
            }
            #[cfg(not(feature = "resolve"))]
            {
                return Err(Error::DidResolveFailed);
            }
        }
    };
    let ss = StaticSecret::from(array_ref!(sender_private_key.as_ref(), 0, 32).to_owned())
        .diffie_hellman(&PublicKey::from(
            array_ref!(recipient_public, 0, 32).to_owned(),
        ));

    Ok(*ss.as_bytes())
}

/// Combines length of array and its its length into a vector.
fn get_length_and_input(vector: &[u8]) -> Result<Vec<u8>, Error> {
    let mut collected: Vec<u8> = u32::try_from(vector.len())
        .map_err(|err| Error::Generic(err.to_string()))?
        .to_be_bytes()
        .to_vec();
    collected.extend(vector);
    Ok(collected)
}

/// Extracts key did part from a did url (drops path, query, and segment).
fn get_did_from_didurl(url: &str) -> String {
    let re = regex::Regex::new(
        r"(?x)
        ^
        (?P<did>
            did             # scheme
            :
            [a-z]+          # method
            :
            (?:[a-z]*:)*    # optional subdomains, postfixed with a ':'
            [a-zA-Z0-9]+    # method specific identifier
        )
        (?:/[^?\#]*)?        # optional path
        (?:\?[^\#]*)?        # optional query
        (?:\#.*)?            # optional fragment
        $
    ",
    )
    .unwrap();
    match re.captures(url) {
        Some(s) => s
            .name("did")
            .map(|v| v.as_str().to_string())
            .unwrap_or_else(String::default),
        None => String::default(),
    }
}
