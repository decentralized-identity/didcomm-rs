//
//  main.swift
//  didcomm-rs_test_app
//
//  Created by Steven H. McCown on 5/10/21.
//

import Foundation

//------------------------------------------------------------------------------------------
// printJson()
// A helper function to pretty-print JSON data for debugging and displaying to the console.
func printJson(label: String, json: Data?) {
    
    let json: Data = json ?? "".data(using: .utf8)!
    if let jsonObject = try? JSONSerialization.jsonObject(with: json, options: .mutableContainers),
       let jsonData = try? JSONSerialization.data(withJSONObject: jsonObject, options: .prettyPrinted) {
        print("\(label):\n" + String(decoding: jsonData, as: UTF8.self))
    } else {
        
        print("The json data is malformed.")
    }
}

//------------------------------------------------------------------------------------------
// send_receive_didkey_test()
// calls into the linked didcomm_rs library to create, encrypt, and decrypt didcomm
// messages.  For simplicity, the actual transmission of the message is assumed to
// have been performed.
func send_receive_didkey_test() {

    // Visual separator
    print("\n--------------------------------------------------\n")
    print("send_receive_didkey_test()")
    print("\n--------------------------------------------------\n")

    // For this first part, Alice creates a didcomm message to send to Bob.
    
    // Create the DIDComm Message object.
    let m = Message.init()
    
    // Set the sender's DID (i.e., Alice's DID).  Using "did:key" lets the public key
    // be specified inline within the DID, so that no external DID Method or lookup is
    // necessary.  This keeps this particular test routine very simple.
    m.setFrom(from: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
    
    // Set the receiver's DID (i.e., Bob's DID).  Using "did:key" lets us specify the
    // public key inline, which keeps this test routine very simple.  Since this type is an
    // array, multiple recipients can be specified.
    m.setTo(str: ["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"])
    
    // Select the ChaCha20 encryptionalgorithm that DIDComm uses.  ChaCha20 is an alternative to
    // AES-256 that has a faster software implementation on CPUs without dedicated cryptographic
    // hardware instructions.
    m.setCryptoAlgorithmXc20P()
    
    // Add some data, in the form of a UInt8 array, to the body of the message.
    let body : [UInt8] = Array("Hello World!".utf8)
    m.setBody2(body: body)

    let plaintextMessage = m.asRawJson2()
    printJson(label: "Plaintext Message", json: plaintextMessage.data(using: .utf8))

    // Display the plaintextMessage.body without the base58 encoding.
    let plaintextMessageBody = String(bytes: m.getBody2(), encoding: .utf8)
    print("Plaintext Message (body): " + plaintextMessageBody!)
    
    // Visual separator
    print("\n--------------------------------------------------\n")

    // Encrypt the message using Alice's private key.  The didcomm_rs library is architected to require
    // private keys to be input via this function call.  In a future version of didcomm_rs, security could
    // be improved by leveraging a devices secure storage element (e.g., Apple's Secure Enclave) rather than
    // manipulating (loading, accessing, passing) the private key directly.
    let alice_private = m.unwrapBase58Key(key: "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR");
    let encryptedMessage = m.seal2(sk: alice_private);
    printJson(label: "\nencryptedMessage", json: encryptedMessage.data(using: .utf8))

    // *****
    // Alice transmits the message to Bob.  For simplicity, the actual transmission is assumed to
    // have been performed.  Message transmission can be performed using any of a variety of transport media.
    // *****

    // Bob receives the message from the transport medium used for transmission.
    
    // Decrypt the message using Bob's private key.  The didcomm_rs library is architected to require
    // private keys to be input via this function call.  In a future version of didcomm_rs, security could
    // be improved by leveraging a devices secure storage element (e.g., Apple's Secure Enclave) rather than
    // manipulating (loading, accessing, passing) the private key directly.
    let bobs_private = m.unwrapBase58Key(key: "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP");

    // Message.newReceive() processes the incoming message bytes to create a Message structure
    // that has been decrypted using the specified private key for the intended recipient.
    let receivedMessage = Message.newReceive(incomming: encryptedMessage, sk: bobs_private);

    // Visual separator
    print("\n--------------------------------------------------\n")

    // Get the raw json string for the decoded message (the Message.body value is still base58 encoded).
    let receivedJSON = receivedMessage.asRawJson2()
    printJson(label: "\nReceived message (decrypted)", json: receivedJSON.data(using: .utf8))
    
    // Display the receivedMessage.body without the base58 encoding.
    let receivedBody = String(bytes: receivedMessage.getBody2(), encoding: .utf8)
    print("Received Message (body): " + receivedBody!)
}

//------------------------------------------------------------------------------------------
func send_receive_didkey_multiple_receivers_test() {
    
    // Visual separator
    print("\n--------------------------------------------------\n")
    print("send_receive_didkey_multiple_receivers_test()")
    print("\n--------------------------------------------------\n")

    // Create a message.
    let m = Message.init()
    
    // Set sender address.
    m.setFrom(from: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
    
    // Set recipients.
    m.setTo(str: ["did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG", "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"])
    
    // Set the crypto algorithm.
    m.setCryptoAlgorithmXc20P()
    
    // Add some data, in the form of a UInt8 array, to the body of the message.
    let body : [UInt8] = Array("Hello World!".utf8)
    m.setBody2(body: body)

    // Get the JSON string representation of the plaintext message..
    let plaintextMessage = m.asRawJson2()

    // Display the plaintext message and contents.
    printJson(label: "Plaintext Message", json: plaintextMessage.data(using: .utf8))
    let plaintextMessageBody = String(bytes: m.getBody2(), encoding: .utf8)
    print("Plaintext Message (body): " + plaintextMessageBody!)
    
    // Visual separator
    print("\n--------------------------------------------------\n")

    let alice_private = m.unwrapBase58Key(key: "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR")
    let encryptedMessage = m.seal2(sk: alice_private);
    printJson(label: "\nencryptedMessage", json: encryptedMessage.data(using: .utf8))

    // *****
    // Alice transmits the message to Bob and Third.
    //
    // Bob and Third receive the message from the transport medium used for transmission.
    // *****

    // Visual separator
    print("\n--------------------------------------------------\n")
    print("Bob's Message:\n")

    let bobs_private = m.unwrapBase58Key(key: "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP")
    let receivedMessageBob = Message.newReceive(incomming: encryptedMessage, sk: bobs_private);

    // Get the JSON string representation for transmission.
    let receivedJSONBob = receivedMessageBob.asRawJson2()

    // Get the raw json string for the decoded message (the Message.body value is still base58 encoded).
    printJson(label: "\nReceived message (decrypted)", json: receivedJSONBob.data(using: .utf8))
    let receivedBodyBob = String(bytes: receivedMessageBob.getBody2(), encoding: .utf8)
    print("Received Message (body): " + receivedBodyBob!)

    // Visual separator
    print("\n--------------------------------------------------\n")
    print("Third's Message:\n")

    let third_private = m.unwrapBase58Key(key: "ACa4PPJ1LnPNq1iwS33V3Akh7WtnC71WkKFZ9ccM6sX2")
    let receivedMessageThird = Message.newReceive(incomming: encryptedMessage, sk: third_private);

    // Get the JSON string representation for transmission.
    let receivedJSONThird = receivedMessageThird.asRawJson2()

    // Get the raw json string for the decoded message (the Message.body value is still base58 encoded).
    printJson(label: "\nReceived message (decrypted)", json: receivedJSONThird.data(using: .utf8))
    let receivedBodyThird = String(bytes: receivedMessageThird.getBody2(), encoding: .utf8)
    print("Received Message (body): " + receivedBodyThird!)
}

//------------------------------------------------------------------------------------------
print("*** Starting didcomm-rs tests ***\n")

send_receive_didkey_test()
send_receive_didkey_multiple_receivers_test()

print("*** Ending didcomm-rs tests ***\n")
