mod attachment;
mod headers;
mod jwe;
mod jwk;
mod jws;
mod mediated;
mod message;
mod prior_claims;
mod problem_report;
mod types;

#[cfg(feature = "raw-crypto")]
mod raw;

#[cfg(feature = "out-of-band")]
pub mod out_of_band;

pub use attachment::*;
pub use headers::*;
pub use jwe::*;
pub use jwk::*;
pub use jws::*;
pub use mediated::*;
pub use message::*;
pub use prior_claims::*;
pub use problem_report::*;
pub use types::*;

#[cfg(feature = "raw-crypto")]
pub use raw::*;

pub trait Shape: Sized {
    type Err;

    fn shape(m: &Message) -> Result<Self, Self::Err>;
}
