#[macro_use]
extern crate serde;

mod messages;

pub use messages::Message;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
