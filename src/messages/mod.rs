mod attachment;
mod headers;
mod jwe;
mod jwk;
mod jws;
mod mediated;
mod message;
mod prior_claims;
mod types;

#[cfg(feature = "raw-crypto")]
mod raw;

pub use attachment::*;
pub use headers::*;
pub use jwe::*;
pub use jwk::*;
pub use jws::*;
pub use mediated::*;
pub use message::*;
pub use prior_claims::*;
pub use types::*;

#[cfg(feature = "raw-crypto")]
pub use raw::*;

pub trait Shape: Sized {
    type Err;

    fn shape(m: &Message) -> Result<Self, Self::Err>;
}
