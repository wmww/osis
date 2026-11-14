//! Wire and session (spec/wire.md §11, spec/sync-streams.md §1-§2): one connection's frames,
//! Hello, proofs, request ids, `WINDOW` accounting, the stall clock, unanswered-in bytes and the
//! push budget.
//!
//! State, per connection, in memory: Hello, proofs shown, request ids, the window, the stall
//! clock, unanswered-in bytes, push budget. Depends on osis-proto and the engine's proof calls.
//! Not built: every call below.

use crate::types::{ConnId, Cx, NodeKey};
use osis_base::Tid;
use osis_crypto::Epoch;
use osis_proto::Message;

/// A request's id on its connection (spec/wire.md §11.2).
pub type RequestId = osis_proto::msg::Id;

/// One message received, by role.
#[derive(Clone, Debug)]
pub enum Incoming {
    Request(RequestId, Message),
    Reply(RequestId, Message),
    Push(Message),
}

/// The module a received message goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum To {
    /// Resume, Digest, Members, Beacons, Offer, Shared, Lost.
    Opens,
    /// Pull, PullReply, Stream, Applied, Fetch.
    Streams,
    /// Deposit and Register answers.
    Inbox,
}

impl Incoming {
    /// Which module takes this message; `None` for one no module takes (not built).
    pub fn to(&self) -> Option<To> {
        None
    }
}

/// Why a session closes its connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close(pub &'static str);

/// What the peer proved on this connection (spec/sync-opens.md §2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proven {
    /// Its account, at the epoch proved.
    pub account: Option<(Tid, Epoch)>,
    /// The key actors it proved.
    pub actors: Vec<Tid>,
    /// It is another node of this node's account.
    pub own_node: bool,
}

/// One connection's session.
#[derive(Clone, Debug)]
pub struct Session {
    pub conn: ConnId,
    pub peer: NodeKey,
    pub dialer: bool,
    pub rank: u8,
    proven: Proven,
    next_id: RequestId,
    bytes: Vec<u8>,
}

impl Session {
    /// A session on a connection just up; queues Hello.
    pub fn new(conn: ConnId, peer: NodeKey, dialer: bool, rank: u8, cx: &mut Cx) -> Session {
        let _ = cx;
        Session { conn, peer, dialer, rank, proven: Proven::default(), next_id: 0, bytes: Vec::new() }
    }

    /// Takes bytes received; proofs run here. `Err`: the connection closes.
    pub fn receive(&mut self, bytes: &[u8], cx: &mut Cx) -> Result<Vec<Incoming>, Close> {
        let _ = (bytes, cx);
        Err(Close("session not built"))
    }

    /// Sends a request, in order while under `WINDOW`.
    pub fn request(&mut self, m: Message) -> RequestId {
        let _ = m;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    pub fn answer(&mut self, to: RequestId, m: Message) {
        let _ = (to, m);
    }

    /// Pushes; `false`: past `REPLY_BUDGET`, the pusher waits.
    pub fn push(&mut self, m: Message) -> bool {
        let _ = m;
        false
    }

    pub fn proven(&self) -> &Proven {
        &self.proven
    }

    /// The bytes to send, taken.
    pub fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}
