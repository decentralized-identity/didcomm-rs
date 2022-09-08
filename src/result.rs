//! Result type
//!
//! The `Result` type is an alias to `std::result::Result` with
//! `didcomm_rs::Error` as error.

/// [`Result`] type. See module level [documentation](self).
pub type Result<T> = std::result::Result<T, crate::Error>;
