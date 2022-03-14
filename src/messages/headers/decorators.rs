//! Decorator Types.
//!
//! The decorator module provides implementations of some decorator data structures.
//!
//! Decorators represent additional metadata that adds semantic
//! content relevant to messaging in general but not tied to a specific domain.
//!
//! Decorators represents additional metadata that add semantics
//! content that are relevant to messing in general, but not tied to a specific domain.
//! For more details, see Aries RFC
//!

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A `~thread` message decorator that provides request/reply
/// and threading semantics according to Aries RFC 0008.
#[derive(Default, Deserialize, Serialize, PartialEq, Debug, Clone)]
#[serde(default)]
pub struct Thread {
    /// The ID of the message that serves as the thread start.
    pub thid: String,

    /// An optional parent `thid`.
    ///
    /// It's used when branching or nesting a new interaction off an
    /// existing one.
    pub pthid: String,

    /// The index of the message in the sequence of all the messages
    /// the current *sender* has contributed to in the thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_order: Option<usize>,

    /// A dictionary of sender_order/highest messages received on the thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_orders: Option<HashMap<String, usize>>,

    /// Code to convey an action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal_code: Option<String>,
}

impl Thread {
    /// Creates implicit thread.
    ///
    /// # Example
    ///
    /// ```
    /// use didcomm_rs::Thread;
    /// let message_id = "new-message";
    /// let thread = Thread::implicit(&message_id);
    /// assert_eq!(thread.thid, message_id.to_string())
    /// ```
    pub fn implicit(message_id: &str) -> Self {
        Self {
            thid: message_id.into(),
            sender_order: Some(0),
            ..Default::default()
        }
    }

    /// Create implicit message reply thread.
    ///
    /// # Example
    ///
    /// ```
    /// use didcomm_rs::Thread;
    /// let thid = "current-thread";
    /// let thread = Thread::implicit_reply(&thid);
    /// assert_eq!(thread.thid, thid);
    /// ```
    pub fn implicit_reply(thid: &str) -> Self {
        Self {
            thid: thid.into(),
            ..Default::default()
        }
    }

    /// Creates an effective implicit message reply thread.
    pub fn effective_implicit_reply(thid: &str, sender: &str) -> Self {
        let mut thr = Self::implicit_reply(thid);
        thr.received_orders = Some(HashMap::from([(sender.into(), 0)]));
        thr
    }

    /// Returns `true` if the thread is for an implicit reply message.
    pub fn is_implicit_reply(&self, message_id: &str) -> bool {
        if self.thid != message_id {
            match self.received_orders {
                Some(ref recv_orders) => recv_orders.values().all(|&x| x == 0),
                None => true,
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en;
    use fake::uuid::UUIDv4;
    use fake::Fake;
    use quickcheck::{Arbitrary, Gen};
    use uuid::Uuid;

    #[test]
    fn default_thread_can_be_created() {
        let thr = Thread::default();
        assert_eq!(thr.thid, thr.thid);
        assert_eq!(thr.thid, thr.pthid);
        assert!(thr.sender_order.is_none());
        assert!(thr.received_orders.is_none());
        assert!(thr.goal_code.is_none());
    }

    #[derive(Clone, Debug)]
    struct Id(String);

    #[derive(Clone, Debug)]
    struct Header {
        id: String,
        sender: String,
    }

    impl Arbitrary for Id {
        fn arbitrary(_: &mut Gen) -> Self {
            let s: Uuid = UUIDv4.fake();
            Self(s.to_string())
        }
    }

    impl Arbitrary for Header {
        fn arbitrary(_: &mut Gen) -> Self {
            let s: Uuid = UUIDv4.fake();
            Self {
                id: s.to_string(),
                sender: en::Username().fake(),
            }
        }
    }
    #[quickcheck_macros::quickcheck]
    fn create_implicit_thread(id: Id) -> bool {
        let thread = Thread::implicit(&id.0);
        thread.thid == id.0
    }

    #[quickcheck_macros::quickcheck]
    fn create_effective_implicit_reply_thread(header: Header) -> bool {
        let thread = Thread::effective_implicit_reply(&header.id, &header.sender);
        thread.thid == header.id
    }

    #[quickcheck_macros::quickcheck]
    fn implicit_thread_without_received_order_successfully_detected(id: Id) -> bool {
        let thr = Thread::implicit_reply(&id.0);
        !thr.is_implicit_reply(&id.0)
    }

    #[quickcheck_macros::quickcheck]
    fn non_implicit_thread_with_received_order_successfully_detected(id: Id) -> bool {
        let mut thr = Thread::implicit_reply(&id.0);
        thr.received_orders = Some(HashMap::from([("test".into(), 1)]));
        !thr.is_implicit_reply(&id.0)
    }
}
