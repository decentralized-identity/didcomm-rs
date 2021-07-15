# didcomm-rs

Rust implementation of DIDComm v2 [spec](https://identity.foundation/didcomm-messaging/spec)

![tests](https://github.com/decentralized-identity/didcomm-rs/workflows/tests/badge.svg)


#License

[Apache-2.0](LICENSE.md)

# Examples of usage

## 1. Prepare raw message for send and receive
### GoTo: [full test](https://github.com/decentralized-identity/didcomm-rs/blob/master/tests/send_receive.rs#L12)

```rust
    // Message construction
    let m = Message::new()
        // setting `from` header (sender) - Optional
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_")
        // setting `to` header (recepients) - Optional
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"])
        // populating body with some data - `Vec<bytes>`
        .set_body(some_payload.as_bytes());

    // Serialize message into JWM json (SENDER action)
    let ready_to_send = m.as_raw_json().unwrap();

    //... transport is happening here ...

    // On receival deserialize from json into Message (RECEIVER action)
    // Error handling recommended here
    let received = Message::receive(&ready_to_send, None).unwrap();
```

## 2. Prepare JWE message for direct send
### GoTo: [full test](https://github.com/decentralized-identity/didcomm-rs/blob/master/tests/send_receive.rs#L35)

```rust
    // decide which [Algorithm](crypto::encryptor::CryptoAlgorithm) is used (based on key)
    let alg = CryptoAlgorithm::XC20P;
    // key as bytes
    let ek = [130, 110, 93, 113, 105, 127, 4, 210, 65, 234, 112, 90, 150, 120, 189, 252, 212, 165, 30, 209, 194, 213, 81, 38, 250, 187, 216, 14, 246, 250, 166, 92]
    // creating message
    let mut message = Message::new()
    // packing in some payload (can be anything really)
        .set_body(br#"{'key':'value','key2':'value2'}"#)
    // set JOSE header for XC20P algorithm
        .as_jwe(alg)
    // add some custom app/protocol related headers to didcomm header portion
    // these are not included into JOSE header
        .add_header_field("my_custom_key".into(), "my_custom_value".into())
        .add_header_field("another_key".into(), "another_value".into());
    // set `kid` property
    message.jwm_header.kid = 
        Some(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#));
    // encrypt and serialize message with JOSE header included
    let ready_to_send = message.seal(ek.as_bytes())?;
    // use transport of choice to send `ready_to_send` data to the receiver!

    //... transport is happening here ...

```

## 3. Prepare JWS message -> send -> receive
* Here `Message` is signed but not encrypted.
* In such scenarios explicit use of `.sign(...)` and `Message::verify(...)` required.

```rust
    // Message construction an JWS wrapping
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(&["did::xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jws(&SignatureAlgorithm::EdDsa)
        .sign(SignatureAlgorithm::EdDsa.signer(), &sign_keypair.to_bytes()).unwrap();

    //... transport is happening here ...

    // Receiving JWS
    let received = Message::verify(&message.unwrap().as_bytes(), &sign_keypair.public.to_bytes());
```

## 4. Prepare JWE message to be mediated -> mediate -> receive
* Message should be encrypted by destination key first in `.routed_by()` method call using key for the recepient.
* Next it should be encrypted by mediator key in `.seal()` method call - this can be done multiple times - once for each mediator in chain but should be strictly sequentual to match mediators sequence in the chain.
* Method call `.seal()` **MUST** be preceeded by  `.as_jwe(CryptoAlgorithm)` as mediators may use different algorithms and key types than destination and this is not automatically predicted or populated.
* Keys used for encryption should be used in reverse order - final destination - last mediator - second to last mediator - etc. Onion style.

### GoTo: [full test](https://github.com/decentralized-identity/didcomm-rs/blob/master/tests/send_receive.rs#L67)

```rust
    // Message construction
    let message = Message::new()
        // setting from
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_")
        // setting to
        .to(&["did:xyz:34r3cu403hnth03r49g03", "did:xyz:30489jnutnjqhiu0uh540u8hunoe"])
        // packing in some payload
        .set_body(some_payload.as_bytes())
        // set JOSE header for XC20P algorithm
        .as_jwe(CryptoAlgorithm::XC20P)
        // custom header
        .add_header_field("my_custom_key".into(), "my_custom_value".into())
        // another coustom header
        .add_header_field("another_key".into(), "another_value".into())
        // set kid header
        .kid(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#))
        // here we use destination key to bob and `to` header of mediator - 
        //**THISH MUST BE LAST IN THE CHAIN** - after this call you'll get new instance of envelope `Message` destined to the mediator.
        // `ek_to_bob` - destination targeted encryption key
        .routed_by(ek_to_bob.as_bytes(), vec!("did:mediator:suetcpl23pt23rp2teu995t98u"));

    // Message envelope to mediator
    let ready_to_send = message
        .unwrap() // **ERROR HANDLE** here is recommended
        .as_jwe(CryptoAlgorithm::XC20P) // here this method call is crucial as mediator and end receiver may use different algorithms.
        // `ek_to_mediator` - mediator targeted encryption key
        .seal(ek_to_mediator.as_bytes()); // this would've failed without previous method call.

    //... transport to mediator is happening here ...

    // Received by mediator
    // `rk_mediator` - key to decrypt mediated message
    let received_mediated = Message::receive(&ready_to_send.unwrap(), Some(rk_mediator.as_bytes()));

    //... transport to destination is happening here ...

    // Received by Bob
    // `rk_bob` - key to decrypt final message
    let received_bob = Message::receive(&String::from_utf8_lossy(&received_mediated.unwrap().get_body()?.as_ref()), Some(rk_bob.as_bytes()));
```

## 5. Prepare JWS envelope wrapped into JWE -> sign -> pack -> receive
* JWS header is set automatically based on signing algorythm type.
* Message forming and encryption happens in same way as in other JWE examples.
* ED25519-dalek signature is used in this example with keypair for signing and public key for verification.

### GoTo: [full test](https://github.com/decentralized-identity/didcomm-rs/blob/master/tests/send_receive.rs#L119)

```rust
    // Message construction
    let message = Message::new() // creating message
        .from("did:xyz:ulapcuhsatnpuhza930hpu34n_") // setting from
        .to(&["did::xyz:34r3cu403hnth03r49g03"]) // setting to
        .set_body(sample_dids::TEST_DID_SIGN_1.as_bytes()) // packing in some payload
        .as_jwe(CryptoAlgorithm::XC20P) // set JOSE header for XC20P algorithm
        .add_header_field("my_custom_key".into(), "my_custom_value".into()) // custom header
        .add_header_field("another_key".into(), "another_value".into()) // another coustom header
        .kid(String::from(r#"Ef1sFuyOozYm3CEY4iCdwqxiSyXZ5Br-eUDdQXk6jaQ"#)); // set kid header

    // Send as signed and encrypted JWS wrapped into JWE
    let ready_to_send = message.seal_signed(
        encryption_key.as_bytes(),
        &sign_keypair.to_bytes(),
        SignatureAlgorithm::EdDsa)
        .unwrap();

    //... transport to destination is happening here ...

    //Receive - same method to receive for JWE or JWS wrapped into JWE but with pub verifying key
    let received = Message::receive(
        &ready_to_send,
        Some(decryption_key.as_bytes()),
        Some(&pub_sign_verify_key.to_bytes())); // and now we parse received
```
## 6. Multiple receivers static key wrap per recepient with shared secret
* ! Works with `resolve` feature only - requires resolution of public keys for each recepient for shared secret generation.
* Static key generated randomly in the background (`to` field has >1 recepient).

### GoTo: [full test](https://github.com/decentralized-identity/didcomm-rs/blob/master/src/messages/message.rs#L597)
```rust
// Creating message with multiple recepients.
let m = Message::new()
    .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
    .to(&["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG", "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"])
    .as_jwe(&CryptoAlgorithm::XC20P);

let jwe = m.seal(&sender_private);
// Packing was ok?
assert!(jwe.is_ok());

let jwe = jwe.unwrap();

// Each of the recepients receive it in same way as before (direct with single receiver)
let received_first = Message::receive(&jwe, &first_private);
let received_second = Message::receive(&jwe, &second_private);

// All good without any extra inputs
assert!(received_first.is_ok());
assert!(received_second.is_ok());
```

# Plugable cryptography

In order to use your own implementation[s] of message crypto and/or signature algorythms implement these trait[s]:

[`didcomm_rs::crypto::Cypher`](https://github.com/decentralized-identity/didcomm-rs/blob/master/src/crypto/mod.rs#L30)

[`didcomm_rs::crypto::Signer`](https://github.com/decentralized-identity/didcomm-rs/blob/master/src/crypto/mod.rs#L39)

Dont use `default` feature - might change in future.

When implemented - use them instead of `CrptoAlgorithm` and `SignatureAlgorithm` from examples above.

# Strongly typed Message payload (body)

### GoTo: [full test](https://github.com/decentralized-identity/didcomm-rs/blob/main/tests/shape.rs)

In most cases apllication implementation would prefer to have strongly typed body of the message instead of raw `Vec<u8>`.
For this scenario `Shape` trait should be implemented for target type.

* First, let's define our target type. JSON in this example.
```rust
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DesiredShape {
    num_field: usize,
    string_field: String,
}
```

* Next, implement `Shape` trait for it
```rust
impl Shape for DesiredShape {
    type Err = Error;
    fn shape(m: &Message) -> Result<DesiredShape, Error> {
        serde_json::from_slice(&m.body)
            .map_err(|e| Error::SerdeError(e))
    }
}
```

* Now we can call `shape()` on our `Message` and shape in in.
* In this example we expect JSON payload and use it's Deserializer to get our data, but your implementation can work with any serialization.
```rust
let received_typed_body = DesiredShape::shape(&m).unwrap(); // Where m = Message
```

# Disclaimer

This is a sample implementation of the DIDComm V2 spec. The DIDComm V2 spec is still actively being developed by the DIDComm WG in the DIF and therefore subject to change.

## Testing PR Mechanism
Do not merge this PR
