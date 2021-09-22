mod mediated;
mod message;
// mod didurl;
mod headers;
mod jwe;
mod jwk;
mod jws;
mod prior_claims;
mod serialization;
mod types;

#[cfg(feature = "raw-crypto")]
mod raw;

pub use headers::*;
pub use jwe::*;
pub use jwk::*;
pub use jws::*;
// pub use didurl::*;
pub use mediated::*;
pub use message::*;
pub use prior_claims::*;
#[cfg(feature = "raw-crypto")]
pub use raw::*;
pub use types::*;

pub trait Shape: Sized {
    type Err;

    fn shape(m: &Message) -> Result<Self, Self::Err>;
}
