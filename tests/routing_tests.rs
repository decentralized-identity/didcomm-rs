mod common;

use common::{
    Error,
    Message,
};

#[test]
fn test_routing() -> Result<(), Error> {
    // Arrange
    let message = Message::new();
    // Act
    message
        .routed()
        .routed()
        .routed();
    //Assert
    Ok(())
}