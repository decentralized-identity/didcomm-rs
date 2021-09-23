mod common;

use common::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct DesiredShape {
    num_field: usize,

    string_field: String,
}

impl Shape for DesiredShape {
    type Err = Error;
    fn shape(m: &Message) -> Result<DesiredShape, Error> {
        serde_json::from_slice(m.get_body()?.as_ref()).map_err(|e| Error::SerdeError(e))
    }
}

#[test]
fn shape_desired_test() {
    // Arrange
    let initial_shape = DesiredShape {
        num_field: 42,
        string_field: "important data".into(),
    };
    let m = Message::new().set_body(&serde_json::to_string(&initial_shape).unwrap());

    // -- pack, send, receive happens here

    // Act
    let received_typed_body = DesiredShape::shape(&m).unwrap();

    // Assert
    assert_eq!(received_typed_body, initial_shape);
}
