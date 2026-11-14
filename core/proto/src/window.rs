//! A requester's window and its stall clock (spec/sync-judgement.md §2): the upper layer's requests on a
//! connection go within it, whichever side dialed, and the reply allowances it charges.

use crate::frame::encode_frame;
use crate::msg::*;
use osis_base::format::MAX_MESSAGE;
use std::collections::{BTreeMap, VecDeque};

/// The oldest request in flight not moving this long (`Window`: no byte of a reply to it received,
/// none of its frame taken by the transport, no bytes but replies within `MAX_AHEAD`) closes the
/// connection, whichever side dialed; the node redials (spec/sync-judgement.md §2). A body fetch (of a
/// host or a reader) unanswered this long is asked of the next source too (node `asked`).
/// Liveness only, any link speed passes: 0 closes every connection with a request out at once
/// and asks every body twice, infinity keeps a peer that answers nothing and lets it hold the bodies it announced.
pub const STALL_TIMEOUT_MS: u64 = 2 * 60 * 1000;
/// Bytes in flight per session (spec/sync-judgement.md §2): per request sent and not answered, its frame
/// plus its reply allowance. The next request goes while below it, so one always goes: 0 sends
/// one at a time, infinity lets the peer's or our send queue overflow. Per-peer buffer against
/// throughput on long fat links (at most `WINDOW` per round trip).
pub const WINDOW: usize = 16 << 20;
/// Request bytes at the requester, or reply bytes at its peer, that a session within `WINDOW`
/// can have waiting to be written (the window plus one request or reply that overshoots it, and
/// its frame header): a send queue cap at or above it (plus pushes) never closes such a session.
pub const WINDOW_QUEUE: usize = WINDOW + MAX_MESSAGE + 4;
/// Reply allowance of a request whose reply is bounded small (Status of 1024 codes, Pong, Ok,
/// Error) and the smallest `max_reply`: the requests per
/// round trip are `WINDOW` over it. 0 fits no reply; at `MAX_MESSAGE` two go per round trip.
pub const SMALL_REPLY: usize = 16 << 10;
/// What a Fetch asks per ID at first: most replies fit (a role commit with its boxes is about
/// 15 KiB), a larger one takes one more round trip under `REPLY_BUDGET`. The Fetches per round
/// trip are `WINDOW` over it: at `SMALL_REPLY` a role commit is asked twice, at `REPLY_BUDGET`
/// two go per round trip.
pub const FIRST_REPLY: usize = 64 << 10;
/// Frame bytes plus allowances of the requests a session within `WINDOW` can have unanswered:
/// below `WINDOW` before its last one, which adds at most a whole frame and `MAX_MESSAGE`. A peer
/// that receives more before answering any of them closes the connection (spec/sync-judgement.md §2;
/// `Session`), so a pipelining peer cannot make one input cost more than a compliant one.
pub const MAX_UNANSWERED: usize = WINDOW + (MAX_MESSAGE + 4) + MAX_MESSAGE;
/// Bytes received that move the oldest request in flight since it last moved by its own events
/// (`Window`): what an honest peer can have queued ahead of its reply, the spec's Closing bound
/// (`SEND_QUEUE`) with the most a requester has in flight (`MAX_UNANSWERED`; spec/sync-judgement.md §2
/// Stall). Not picked: below it a slow link with a full push backlog closes honest peers; past it
/// a peer pushing while answering nothing keeps the connection longer, its own stream only.
pub const MAX_AHEAD: usize = crate::session::SEND_QUEUE + MAX_UNANSWERED;

/// The most reply bytes the peer may queue for a request (spec/sync-judgement.md §2): `MAX_MESSAGE` for
/// Prove, its `max_reply` for Fetch, Pull, Call and Sub, `SMALL_REPLY` for every other request,
/// 0 for a message that is no request.
pub fn allowance(msg: &Message) -> usize {
    use Message as M;
    let max_reply = |m: u64| usize::try_from(m).unwrap_or(usize::MAX);
    match msg {
        M::Prove { .. } => MAX_MESSAGE,
        M::Fetch { max_reply: m, .. } | M::Call { max_reply: m, .. } | M::Sub { max_reply: m, .. } => max_reply(*m),
        M::Pull(p) => max_reply(p.max_reply),
        m if m.is_request() => SMALL_REPLY,
        _ => 0,
    }
}
/// A requester's window (spec/sync-judgement.md §2): requests go in the order made while the bytes in
/// flight (per request sent and not answered, its frame plus `allowance`) are below `WINDOW`, so
/// one always goes. A `Session` sends every request of its upper layer by one, whichever side
/// dialed.
///
/// It also keeps the stall clock (`STALL_TIMEOUT_MS`): the oldest request sent and not answered
/// must move. It moves by its own events: when it goes out with none before it, when it becomes
/// the oldest (the one before it answered), when bytes of a reply to it arrive (a frame still
/// arriving included), and when the transport takes bytes this side wrote up to its frame's end.
/// Replies to other requests never move it (honest peers answer in arrival order). Bytes of any
/// other kind (pushes, Notifies, the peer's own requests) move it too until `MAX_AHEAD` of them
/// arrived since it last moved by its own: past that an honest peer's reply would have started.
#[derive(Clone, Default)]
pub(crate) struct Window {
    waiting: VecDeque<Message>,
    /// Requests sent and not answered: their send order, cost, and the end of their frame in
    /// this side's output (bytes written up to and including it).
    sent: BTreeMap<Id, (u64, usize, u64)>,
    /// `sent` by send order.
    order: BTreeMap<u64, Id>,
    /// Requests sent so far (the next one's order).
    seq: u64,
    in_flight: usize,
    /// When the oldest request sent last moved.
    moved: u64,
    /// Bytes received since it last moved by its own events.
    ahead: usize,
    /// Bytes of the frame still arriving already counted (`tail_in`).
    counted: usize,
    /// The last `taken` reported (bytes of this side's output the transport took).
    taken: u64,
}

impl Window {
    pub(crate) fn queue(&mut self, m: Message) {
        self.waiting.push_back(m);
    }

    /// Bytes in flight: frames plus allowances of the requests sent and not answered.
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Request `m` went as `frame` bytes, ending at byte `end` of this side's output: its cost
    /// counts until it is answered.
    pub(crate) fn sent(&mut self, m: &Message, frame: usize, end: u64, now: u64) {
        if self.sent.is_empty() {
            self.own_move(now);
        }
        let cost = frame.saturating_add(allowance(m));
        self.in_flight = self.in_flight.saturating_add(cost);
        self.sent.insert(m.id(), (self.seq, cost, end));
        self.order.insert(self.seq, m.id());
        self.seq += 1;
    }

    /// The oldest request sent and not answered.
    fn oldest(&self) -> Option<Id> {
        self.order.first_key_value().map(|(_, id)| *id)
    }

    /// Request `id` was answered: whether it was one sent.
    pub(crate) fn answered(&mut self, id: Id, now: u64) -> bool {
        if self.oldest() == Some(id) {
            self.own_move(now);
        }
        let Some((seq, cost, _)) = self.sent.remove(&id) else { return false };
        self.order.remove(&seq);
        self.in_flight = self.in_flight.saturating_sub(cost);
        true
    }

    /// The oldest request moved by an event of its own.
    fn own_move(&mut self, now: u64) {
        self.moved = now;
        self.ahead = 0;
    }

    /// A whole frame arrived (before it is handled): its bytes not counted while it was arriving
    /// count now, by its kind (`frame_bytes`).
    pub(crate) fn frame_in(&mut self, body: &[u8], now: u64) {
        let n = body.len().saturating_add(4).saturating_sub(self.counted);
        self.counted = 0;
        self.frame_bytes(crate::msg::peek_head(body), n, now);
    }

    /// The input ended inside a frame, `pending` bytes of it (length prefix included) in, its
    /// body as far as it came `partial`: its new bytes count once its kind and id are in.
    pub(crate) fn tail_in(&mut self, partial: Option<&[u8]>, pending: usize, now: u64) {
        let Some(head) = partial.and_then(crate::msg::peek_head) else { return };
        let n = pending.saturating_sub(self.counted);
        self.counted = pending;
        self.frame_bytes(Some(head), n, now);
    }

    /// `n` bytes of a frame with this head (kind, id) arrived. A reply to the oldest request moves
    /// it by its own event; a reply to any other moves nothing (honest peers answer in arrival
    /// order, so it says the oldest was skipped); any other bytes (pushes, Notifies, the peer's
    /// own requests, a frame with no head such as the Hello) move it while no more than
    /// `MAX_AHEAD` arrived since it last moved by its own events.
    fn frame_bytes(&mut self, head: Option<(u64, Id)>, n: usize, now: u64) {
        match head {
            Some((kind, id)) if crate::msg::is_reply_kind(kind) => {
                if n > 0 && self.oldest() == Some(id) {
                    self.own_move(now);
                }
            }
            _ => {
                self.ahead = self.ahead.saturating_add(n);
                if n > 0 && self.ahead <= MAX_AHEAD {
                    self.moved = now;
                }
            }
        }
    }

    /// The transport took `taken` bytes of this side's output so far (cumulative).
    pub(crate) fn taken(&mut self, taken: u64, now: u64) {
        let end = self.order.first_key_value().and_then(|(_, id)| self.sent.get(id)).map(|(_, _, end)| *end);
        if taken > self.taken && end.is_some_and(|e| self.taken < e) {
            self.own_move(now);
        }
        self.taken = self.taken.max(taken);
    }

    /// When the stall clock closes the connection: `STALL_TIMEOUT_MS` after the oldest request
    /// sent last moved; none while none is sent.
    pub(crate) fn stall_at(&self) -> Option<u64> {
        (!self.sent.is_empty()).then(|| self.moved.saturating_add(STALL_TIMEOUT_MS))
    }

    /// Sends what the window lets go and each frame `fits` (`Send` frames), this side's output
    /// having `written` bytes before them: the size of the first that does not fit, if any.
    pub(crate) fn flush_while(&mut self, mut written: u64, now: u64, mut fits: impl FnMut(usize) -> bool, mut send: impl FnMut(Vec<u8>)) -> Option<usize> {
        while self.in_flight < WINDOW.max(1) {
            let frame = encode_frame(&self.waiting.front()?.encode());
            if !fits(frame.len()) {
                return Some(frame.len());
            }
            let m = self.waiting.pop_front()?;
            written = written.saturating_add(frame.len() as u64);
            self.sent(&m, frame.len(), written, now);
            send(frame);
        }
        None
    }
}
