extern crate didcomm_rs;

use didcomm_rs::{Error, Message};
use serde_json::Value;

#[test]
#[cfg(feature = "out-of-band")]
fn sets_m_type_correctly_for_out_of_band_invitation_message() -> Result<(), Error> {
    let message = Message::new()
        .as_out_of_band_invitation("{}", None)
        .as_raw_json()
        .unwrap();

    let object: Value = serde_json::from_str(&message)?;

    assert_ne!(
        object["type"].as_str().ok_or(Error::JwmHeaderParseError)?,
        "\"https://didcomm.org/out-of-band/2.0/invitation\"",
    );
    assert_eq!(
        object["type"].as_str().ok_or(Error::JwmHeaderParseError)?,
        "https://didcomm.org/out-of-band/2.0/invitation",
    );

    Ok(())
}
