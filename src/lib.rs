include!("didcomm-rs.uniffi.uniffi.rs");

#[macro_use]
extern crate serde;
extern crate base64_url;
mod messages;
mod error;

#[cfg(feature = "raw-crypto")]
pub mod crypto;

pub use error::*;
pub use messages::*;


// ----- For uniffi -----
// pub use mediated::*;

#[derive(Debug, thiserror::Error)]
pub enum MessageDecodeError {

    #[error("An invalid byte {b} was found at {offset}")]
    InvalidByte { offset: usize, b: u8 },

    #[error("Invalid length")]
    InvalidLength,

    #[error("An invalid last symbol {b} was found at {offset}")]
    InvalidLastSymbol { offset: usize, b: u8 },
}
// ----- For uniffi -----