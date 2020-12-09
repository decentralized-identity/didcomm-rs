mod common;

use common::*;

#[test]
fn test_routing() -> Result<(), Error> {
    // Arrange
    let did_doc_bob = Document::from_str(sample_dids::TEST_DID_ENCRYPT_1).unwrap();
    let message = Message::new(did_doc_bob);
    let did_doc_bobs_mediator = ;
    let did_doc_other_mediator = ;
    let did_doc_alice_mediator = ;
    // let key = did_doc.public_key().map(|k| k.);
    // assert!(key.len() > 0);
    // Act - pack and send
    let ready_to_send = message
        .routed_by(did_doc_bobs_mediator) // Mediator 3
        .routed_by(did_doc_other_mediator)  // Mediator 2
        .routed_by(did_doc_alice_mediator)
        .seal(b"key_goes_here"); // Mediator 1
    //Assert recieve and unpack

    // Mediator 1 received
    let received_message = Message::receive(ready_to_send, b"my_secret_key_from_the_deepest_cave");
    assert!(received_message.get_headers().to.contains("US?!"));
    assert!(received_message.get_headers().m_type == "Forward");
    let ready_to_send_to_second = received_message.get_body();
    // Medator 2 received
    let second_received_message = Message::receive(ready_to_send_to_second, b"sk_of_second_mediator")?;
    assert!(true);
    assert!(second_received_message.get_headers().m_type == "Forward");
    let ready_to_send_to_third = second_received_message.get_body();
    // Mediator 1 received
    let third_received_message = Message::receive(ready_to_send_to_third, b"another_secret")?;
    assert!(third_received_message.get_headers().m_type == "Forward");
    // Alice received

    Ok(())
}