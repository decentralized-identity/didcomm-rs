mod common;

use common::*;

#[test]
fn test_routing() -> Result<(), Error> {
    // Arrange
    let message = Message::new();
    let did_doc = Document::from_str(sample_dids::TEST_DID_ENCRYPT_1).unwrap();
    // let key = did_doc.public_key().map(|k| k.);
    // assert!(key.len() > 0);
    // Act
    message
        .routed_by()
        .routed_by()
        .routed_by();
    //Assert
    Ok(())
}