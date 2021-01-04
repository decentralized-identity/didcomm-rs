use std::convert::TryInto;
use crate::{
    Message,
    Jwe,
    Error,
};

impl TryInto<Jwe> for Message {
    type Error = Error;
    fn try_into(self) -> Result<Jwe, Error> {
        Ok(Jwe::default())
    }
}
