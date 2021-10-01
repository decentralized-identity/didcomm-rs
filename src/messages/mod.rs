mod headers;
pub(crate) mod helpers;
mod jwe;
mod jws;
mod mediated;
mod message;

#[cfg(feature = "raw-crypto")]
mod message_raw_crypto;

pub use headers::*;
pub use jwe::*;
pub use jws::*;
pub use mediated::*;
pub use message::*;
#[cfg(feature = "raw-crypto")]
pub use message_raw_crypto::*;

/// trait that can be used to verify body, see example [here][crate]
pub trait Shape: Sized {
    type Err;

    fn shape(m: &Message) -> Result<Self, Self::Err>;
}
