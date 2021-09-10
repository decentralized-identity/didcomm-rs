use arrayref::array_ref;
use base58::FromBase58;
use x25519_dalek::{
    StaticSecret,
    PublicKey
};

pub struct KeyPairSet {
    pub alice_public: [u8; 32],
    pub alice_private: [u8; 32],
    pub bobs_public: [u8; 32],
    pub bobs_private: [u8; 32],
}

pub fn get_keypair_set() -> KeyPairSet {
    let alice_private = "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR".from_base58().unwrap();
    let bobs_private = "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap();

    let alice_secret_key: StaticSecret = StaticSecret::from(array_ref!(alice_private, 0, 32).to_owned());
    let bob_secret_key: StaticSecret = StaticSecret::from(array_ref!(bobs_private, 0, 32).to_owned());

    let alice_public: PublicKey = (&alice_secret_key).into();
    let bob_public: PublicKey = (&bob_secret_key).into();

    return KeyPairSet {
        alice_public: alice_public.to_bytes(),
        alice_private: alice_secret_key.to_bytes(),
        bobs_public: bob_public.to_bytes(),
        bobs_private: bob_secret_key.to_bytes(),
    }
}