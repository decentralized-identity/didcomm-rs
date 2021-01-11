# didcomm-rs

Rust implementation of DIDComm v2 [spec](https://identity.foundation/didcomm-messaging/spec)

#License

[Apache-2.0](LICENSE.md)

# Examples of usage

## Prepare message for direct send
    - Assuming `kid`: "Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"

```rust
    // decide which [Algorithm](crypto::encryptor::CryptoAlgorithm) is used (based on key)
    let alg = CryptoAlgorithm::XC20P;
    // key as bytes
    let ek = [130, 110, 93, 113, 105, 127, 4, 210, 65, 234, 112, 90, 150, 120, 189, 252, 212, 165, 30, 209, 194, 213, 81, 38, 250, 187, 216, 14, 246, 250, 166, 92]
    // creating message
    let mut message = Message::new();
    // packing in some payload (can be anything really)
    message.body = br#"{'key':'value','key2':'value2'}"#;
    // set JOSE header for XC20P algorithm
    message.as_jwe(alg);
    // add some custom app/protocol related headers to didcomm header portion
    // these are not included into JOSE header
    message = message // shadowing here is required to provide option of chainig calls
        .add_header_field("my_custom_key".into(), "my_custom_value".into())
        .add_header_field("another_key".into(), "another_value".into());
    // set `kid` property
    message.jwm_header.kid = 
        Some(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#));
    // encrypt and serialize message with JOSE header included
    let ready_to_send = message.seal(ek.as_bytes())?;
    // alternatively use compact JWE format
    let ready_to_send = message.seal_compact(ek.as_bytes())?;
    // use transport of choice to send `ready_to_send` data to the receiver!
```

# Status

In development - no releases
