mod message;
mod mediated;
mod didurl;
mod prior_claims;
mod headers;
mod types;
mod jwe;
mod jws;
mod jwk;

#[cfg(feature = "raw-crypto")]
mod raw;

pub use message::*;
pub use prior_claims::*;
pub use headers::*;
pub use types::*;
pub use jwe::*;
pub use jws::*;
pub use jwk::*;

#[cfg(feature = "raw-crypto")]
pub use raw::*;

pub trait Shape: Sized {
    type Err;

    fn shape(m: &Message) -> Result<Self, Self::Err>;
}

