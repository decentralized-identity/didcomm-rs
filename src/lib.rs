#[macro_use]
extern crate serde;

mod messages;
mod dids;
mod error;

pub use error::*;
pub use messages::Message;
pub use dids::*;

