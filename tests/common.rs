extern crate didcomm_rs;

pub use didcomm_rs::{Error, Message, Shape};
pub use std::str::FromStr;

#[allow(dead_code)]
pub mod sample_dids {
    pub const TEST_DID_SIGN_1: &str = r#"{
        "@context": "https://w3id.org/did/v1",
        "id": "did:uknow:d34db33f",
        "publicKey": [
            {
                "id": "did:uknow:d34db33f#cooked",
                "type": "Secp256k1VerificationKey2018",
                "owner": "did:uknow:d34db33f",
                "publicKeyHex": "b9c5714089478a327f09197987f16f9e5d936e8a"
            }
        ],
        "authentication": [
            {
                "type": "Secp256k1SignatureAuthentication2018",
                "publicKey": "did:uknow:d34db33f#cooked"
            }
        ],
        "service": [],
        "created": ""
    }"#;

    pub const TEST_DID_SIGN_2: &str = r#"{
        "service": [
            {
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#openid",
                "type": "OpenIdConnectVersion1.0Service",
                "serviceEndpoint": "https://openid.example.com/"
            }
        ],
        "authentication": [
            "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv",
            {
                "usage": "signing",
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#authentication",
                "type": "Ed25519VerificationKey2018",
                "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            }
        ],
        "capabilityDelegation": [
            "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
        ],
        "assertionMethod": [
            "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
        ],
        "capabilityInvocation": [
            "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv"
        ],
        "keyAgreement": [
            {
                "usage": "signing",
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#keyAgreement",
                "type": "X25519KeyAgreementKey2019",
                "publicKeyBase58": "ENpfk9K9J6uss5qu6BrAszioE732mYCobmMPSpvB3faM",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            }
        ],
        "publicKey": [
            {
                "type": "Secp256k1VerificationKey2018",
                "usage": "signing",
                "publicKeyHex": "0361f286ada2a6b2c74bc6ed44a71ef59fb9dd15eca9283cbe5608aeb516730f33",
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#primary",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            },
            {
                "usage": "recovery",
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#recovery",
                "publicKeyHex": "02c00982681081372cbb941cd2c9745908316e1373ac333479f0deabcad0e9d574",
                "type": "Secp256k1VerificationKey2018",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            },
            {
                "publicKeyBase58": "atEBuHypSkQx7486xT5FUkoBLqvNcWyNK2Xz9EPjdMy",
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#edv",
                "usage": "signing",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            },
            {
                "publicKeyPem": "-----BEGIN PUBLIC KEY\nMIIBCgKCAQEAvzoCEC2rpSpJQaWZbUmlsDNwp83Jr4fi6KmBWIwnj1MZ6CUQ7rBa\nsuLI8AcfX5/10scSfQNCsTLV2tMKQaHuvyrVfwY0dINk+nkqB74QcT2oCCH9XduJ\njDuwWA4xLqAKuF96FsIes52opEM50W7/W7DZCKXkC8fFPFj6QF5ZzApDw2Qsu3yM\nRmr7/W9uWeaTwfPx24YdY7Ah+fdLy3KN40vXv9c4xiSafVvnx9BwYL7H1Q8NiK9L\nGEN6+JSWfgckQCs6UUBOXSZdreNN9zbQCwyzee7bOJqXUDAuLcFARzPw1EsZAyjV\ntGCKIQ0/btqK+jFunT2NBC8RItanDZpptQIDAQAB\nEND PUBLIC KEY-----\r\n",
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#delegate",
                "type": "Secp256k1VerificationKey2018",
                "usage": "signing",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            },
            {
                "publicKeyJwk": {
                    "crv": "secp256k1",
                    "x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
                    "kty": "EC",
                    "y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
                    "kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw"
                },
                "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A#key-JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
                "type": "Ed25519VerificationKey2018",
                "usage": "signing",
                "controller": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
            }
        ],
        "@context": "https://w3id.org/did/v1",
        "id": "did:elem:ropsten:EiAS3mqC4OLMKOwcz3ItIL7XfWduPT7q3Fa4vHgiCfSG2A"
    }"#;

    pub const TEST_DID_ENCRYPT_1: &'static str = r###"{
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:jun:ErJ3ahRB-zmOvTp0QmcJQfLq3hCAHBpXmoYLeHK8fHhw",
        "verificationMethod": [
            {
                "id": "#DDMt6ythjG9pyuKcyFYHPC62gw6KjL8EdouCuNRm0GbU",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:jun:ErJ3ahRB-zmOvTp0QmcJQfLq3hCAHBpXmoYLeHK8fHhw",
                "publicKeyBase64": "DMt6ythjG9pyuKcyFYHPC62gw6KjL8EdouCuNRm0GbU="
            },
            {
                "id": "#CpPUgqlFBYtyXuCe6t8tXqeKo_wisONT9OzX-tRWNuGA",
                "type": "X25519KeyAgreementKey2019",
                "controller": "did:jun:ErJ3ahRB-zmOvTp0QmcJQfLq3hCAHBpXmoYLeHK8fHhw",
                "publicKeyBase64": "pPUgqlFBYtyXuCe6t8tXqeKo_wisONT9OzX-tRWNuGA="
            }
        ]
    }"###;

    pub const TEST_DID_ENCRYPT_2: &'static str = r###"{
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:jun:ELB1nzFeCRQjH5aWZRDmBDcDO1VepN1GPe6798tGOZCQ",
        "verificationMethod": [
            {
                "id": "#DJ-0_czJ5HuGj-rzi2PLen2SR6B7EjGBcOmPu_WyVp90",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:jun:ELB1nzFeCRQjH5aWZRDmBDcDO1VepN1GPe6798tGOZCQ",
                "publicKeyBase64": "J-0_czJ5HuGj-rzi2PLen2SR6B7EjGBcOmPu_WyVp90="
            },
            {
                "id": "#CSFgdHTP5cCCKY7p1GQY5h7C29htmbcVyX1a3ryqT3hM",
                "type": "X25519KeyAgreementKey2019",
                "controller": "did:jun:ELB1nzFeCRQjH5aWZRDmBDcDO1VepN1GPe6798tGOZCQ",
                "publicKeyBase64": "SFgdHTP5cCCKY7p1GQY5h7C29htmbcVyX1a3ryqT3hM="
            }
        ]
    }"###;
}
