mod attachment;
mod headers;
pub(crate) mod helpers;
mod jwe;
mod jws;
mod mediated;
mod message;
mod problem_report;

#[cfg(feature = "raw-crypto")]
mod message_raw_crypto;

#[cfg(feature = "out-of-band")]
pub mod out_of_band;

pub use attachment::*;
pub use headers::*;
pub use jwe::*;
pub use jws::*;
pub use mediated::*;
pub use message::*;
#[cfg(feature = "raw-crypto")]
pub use message_raw_crypto::*;
pub use problem_report::*;

/// trait that can be used to verify body, see example [here][crate]
pub trait Shape: Sized {
    type Err;

    fn shape(m: &Message) -> Result<Self, Self::Err>;
}
