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
    m.routed()
        .routed()
        .routed();
    //Assert
    Ok(())
}