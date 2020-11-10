#[macro_use]
extern crate serde;

mod messages;
mod error;

pub use error::*;
pub use messages::Message;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
