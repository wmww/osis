//! Client side of one connection (spec/sync.md §5-§9, spec/wire.md §11): a sans-I/O state machine
//! that turns commands into requests (batched under the caps, paged replies followed up), and
//! replies and pushes into events. Policy (what to sync, verify or fetch) stays
//! with the node.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame, send};
use crate::hello::{Hello, OFFSET_DIAGNOSTIC_MS, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
use crate::msg::*;
use osis_base::format::MAX_MESSAGE;
use osis_base::{BlobId, LabelId};
use std::collections::{BTreeMap, VecDeque};

/// Pings sent when the session starts (clock offset samples, spec/sync.md §6).
pub const INITIAL_PINGS: usize = 3;
/// Interval of later pings.
pub const PING_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// The oldest request in flight not moving this long (`Window`: no byte of a reply to it received,
/// none of its frame taken by the transport, no bytes but replies within `MAX_AHEAD`) closes the
/// connection, whichever side dialed; the node redials (spec/sync.md §6). A body fetch (of a
/// host or a reader) unanswered this long is asked of the next source too (node `asked`).
/// Liveness only, any link speed passes: 0 closes every connection with a request out at once
/// and asks every body twice, infinity keeps a peer that answers nothing and lets it hold the bodies it announced.
pub const STALL_TIMEOUT_MS: u64 = 2 * 60 * 1000;
/// Bytes in flight per session (spec/sync.md §6): per request sent and not answered, its frame
/// plus its reply allowance. The next request goes while below it, so one always goes: 0 sends
/// one at a time, infinity lets the peer's or our send queue overflow. Per-peer buffer against
/// throughput on long fat links (at most `WINDOW` per round trip).
pub const WINDOW: usize = 16 << 20;
/// Request bytes at the requester, or reply bytes at its peer, that a session within `WINDOW`
/// can have waiting to be written (the window plus one request or reply that overshoots it, and
/// its frame header): a send queue cap at or above it (plus pushes) never closes such a session.
pub const WINDOW_QUEUE: usize = WINDOW + MAX_MESSAGE + 4;
/// Reply allowance of a request whose reply is bounded small (Status of 1024 codes, Opened, a Path
/// page of `MAX_PATH_STEPS`, Pong, Ok, Error) and the smallest `max_reply`: the requests per
/// round trip are `WINDOW` over it. 0 fits no reply; at `MAX_MESSAGE` two go per round trip.
pub const SMALL_REPLY: usize = 16 << 10;
/// What a Fetch asks per ID at first: most replies fit (a role commit with its boxes is about
/// 15 KiB), a larger one takes one more round trip under `REPLY_BUDGET`. The Fetches per round
/// trip are `WINDOW` over it: at `SMALL_REPLY` a role commit is asked twice, at `REPLY_BUDGET`
/// two go per round trip.
pub const FIRST_REPLY: usize = 64 << 10;
/// Frame bytes plus allowances of the requests a session within `WINDOW` can have unanswered:
/// below `WINDOW` before its last one, which adds at most a whole frame and `MAX_MESSAGE`. A peer
/// that receives more before answering any of them closes the connection (spec/sync.md §6;
/// `ServingSession`), so a pipelining peer cannot make one input cost more than a compliant one.
pub const MAX_UNANSWERED: usize = WINDOW + (MAX_MESSAGE + 4) + MAX_MESSAGE;
/// Bytes received that move the oldest request in flight since it last moved by its own events
/// (`Window`): what an honest peer can have queued ahead of its reply, the spec's Closing bound
/// (`SEND_QUEUE`) with the most a requester has in flight (`MAX_UNANSWERED`; spec/sync.md §6
/// Stall). Not picked: below it a slow link with a full push backlog closes honest peers; past it
/// a peer pushing while answering nothing keeps the connection longer, its own stream only.
pub const MAX_AHEAD: usize = crate::serving::SEND_QUEUE + MAX_UNANSWERED;

/// The most reply bytes the peer may queue for a request (spec/sync.md §6): `MAX_MESSAGE` for
/// Prove, its `max_reply` for Fetch, Pull, Call and Sub, `SMALL_REPLY` for every other request,
/// 0 for a message that is no request.
pub fn allowance(msg: &Message) -> usize {
    use Message as M;
    match msg {
        M::Prove { .. } => MAX_MESSAGE,
        M::Fetch { max_reply, .. } | M::Call { max_reply, .. } | M::Sub { max_reply, .. } => usize::try_from(*max_reply).unwrap_or(usize::MAX),
        M::Pull(p) => usize::try_from(p.max_reply).unwrap_or(usize::MAX),
        M::Ping { .. } | M::Register { .. } | M::Delete { .. } | M::Auth { .. } | M::Unsub { .. } | M::Resume { .. } | M::Beacons { .. } | M::Offer { .. } | M::Lost { .. } | M::NoRecord { .. } | M::Stranded { .. } | M::Suspect { .. } => SMALL_REPLY,
        M::Error { .. } | M::Ok { .. } | M::Pong { .. } | M::Status { .. } | M::FetchReply { .. } | M::Reply { .. } | M::Notify { .. } | M::Proved { .. } | M::Resumed { .. } | M::Shared { .. } | M::PullReply(_) | M::Stream(_) | M::Applied { .. } | M::Digest { .. } | M::Members { .. } => 0,
    }
}
/// A requester's window (spec/sync.md §6): requests go in the order made while the bytes in
/// flight (per request sent and not answered, its frame plus `allowance`) are below `WINDOW`, so
/// one always goes. A `ClientSession` sends every request by one; a `ServingSession` the node's
/// own requests to the dialer (a stream's Pulls and Fetches, the shared set's).
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

    /// Requests sent or waiting.
    fn is_empty(&self) -> bool {
        self.waiting.is_empty() && self.sent.is_empty()
    }

    /// The next request to send, while the window has room.
    pub(crate) fn next(&mut self) -> Option<Message> {
        if self.in_flight >= WINDOW.max(1) {
            return None;
        }
        self.waiting.pop_front()
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

/// Bytes of the `Send` outputs in `out`.
fn sent_bytes(out: &[ClientOutput]) -> u64 {
    out.iter().map(|o| if let ClientOutput::Send(f) = o { f.len() as u64 } else { 0 }).sum()
}

/// Clock samples kept.
const MAX_SAMPLES: usize = 9;
/// Round trips before a clock offset is reported (one outlier among three moves nothing).
const MIN_PONGS: usize = 3;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// The peer's static key (a host's address key), bound by open signatures.
    pub peer_static_key: [u8; 32],
    /// This side's Hello challenge: 32 random bytes per connection.
    pub challenge: [u8; 32],
}

/// What the node asks of the session.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // steps carry parsed keys; boxing buys nothing here
pub enum Command {
    /// This node's connection proofs (spec/sync.md §10): the peer's come back as `Proved`.
    Prove(Vec<crate::Prover>),
    /// This node's records for the peer (spec/sync.md §10, Pair key): answered by `Resumed`.
    Resume { nonce: [u8; 32], tags: Vec<[u8; 32]> },
    /// A shared-set or stream message (spec/wire.md §11.2 Beacons to NoRecord, Pull to
    /// Applied), sent as is (a request once the window has room, in order with the session's
    /// own): the node answers these itself.
    Peer(Box<Message>),
    Register { label: LabelId, step: Step, claim_set: Option<ClaimSet> },
    Delete { label: LabelId, items: Vec<DeleteItem> },
    /// Client port (notes/client-port.md §2): `token` is the caller's, echoed in the events.
    /// Auth with the client's session id: a main session's without a secret, a thin client's
    /// with its bearer secret.
    Auth { token: u64, session: [u8; 16], secret: Option<osis_crypto::Secret32> },
    Call { token: u64, max_reply: u64, method: u64, args: Vec<osis_base::Value> },
    /// A subscription named by `token` until `Unsub` or a `Lapsed` Notify.
    Sub { token: u64, max_reply: u64, filter: osis_base::Value },
    Unsub { token: u64 },
    Close,
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ClientInput {
    /// The connection is up: send Hello.
    Start,
    Bytes(Vec<u8>),
    /// The timer last set by `SetTimer` fired.
    Timer,
    /// The transport has taken this many bytes of this session's output so far (cumulative;
    /// `Window`'s stall clock). A driver may report it only when the timer fires; one that never
    /// does delivers instantly.
    Taken(u64),
    Command(Command),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    /// Hellos exchanged; commands given earlier are sent now.
    Ready { version: u64 },
    /// Peer clock minus ours; `diagnostic` above `OFFSET_DIAGNOSTIC_MS`.
    ClockOffset { offset_ms: i64, diagnostic: bool },
    Registered { label: LabelId },
    DeleteStatus { label: LabelId, blob_ids: Vec<BlobId>, codes: Vec<Code> },
    /// A request was answered by Error, or could not be sent (code 2: a delete item whose time
    /// cannot be encoded). `fetch`: a Fetch's blob IDs left unanswered (empty for other kinds).
    Refused { label: Option<LabelId>, kind: Request, code: Code, fetch: Vec<BlobId> },
    /// A shared-set or stream message from the peer, for the node to answer.
    Peer(Box<Message>),
    /// The answer to a Resume: the listener's nonce and the tag of a record it holds.
    Resumed { nonce: [u8; 32], tag: Option<[u8; 32]> },
    /// The peer broke a protocol rule (diagnostic); a paged exchange it broke is abandoned.
    PeerError(Error),
    /// The peer's connection proofs that verified over this connection's challenge and the
    /// listener's key (spec/sync.md §10). Whether an account's key is at an open epoch is the
    /// node's to judge.
    Proved { proofs: Vec<crate::ActorProof> },
    /// The answer to an Auth, Call or Sub: a Reply, or the code of the Error answering it.
    Reply { token: u64, reply: Result<crate::api::Outcome, Code> },
    /// A Notify of a live subscription (after `Lapsed` the token is free).
    Notify { token: u64, payload: crate::api::Payload },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // steps carry parsed keys; boxing buys nothing here
pub enum ClientOutput {
    /// A frame to write.
    Send(Vec<u8>),
    Close,
    /// Fire `ClientInput::Timer` at this wall ms (replaces the previous timer).
    SetTimer(u64),
    Event(ClientEvent),
}

impl From<Vec<u8>> for ClientOutput {
    fn from(frame: Vec<u8>) -> ClientOutput {
        ClientOutput::Send(frame)
    }
}

/// A request's kind (`ClientEvent::Refused`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Ping,
    Register,
    Delete,
    /// A client-port request.
    Api,
    Prove,
    Resume,
}

#[derive(Clone, Debug)]
enum Pending {
    Prove,
    Resume,
    Ping { sent: u64 },
    Register(LabelId),
    Delete(LabelId, Vec<BlobId>),
    /// An Auth, Call or Sub with its token.
    Api(u64),
    /// An Unsub of subscription id.
    ApiUnsub(Id),
}

impl Pending {
    fn label(&self) -> Option<LabelId> {
        match self {
            Pending::Register(l) | Pending::Delete(l, _) => Some(*l),
            Pending::Prove | Pending::Resume | Pending::Ping { .. } | Pending::Api(_) | Pending::ApiUnsub(_) => None,
        }
    }

    fn kind(&self) -> Request {
        match self {
            Pending::Ping { .. } => Request::Ping,
            Pending::Prove => Request::Prove,
            Pending::Resume => Request::Resume,
            Pending::Register(_) => Request::Register,
            Pending::Delete(..) => Request::Delete,
            Pending::Api(_) | Pending::ApiUnsub(_) => Request::Api,
        }
    }
}

/// A request not answered yet: the command it serves (`ClientSession::commands`; `NO_COMMAND`
/// for pings). The node's own requests (`Command::Peer`) are in the window only.
#[derive(Clone)]
struct Req {
    cmd: u64,
    p: Pending,
}

/// The command tag of a request no command asked for (pings).
const NO_COMMAND: u64 = u64::MAX;

#[derive(Clone)]
pub struct ClientSession {
    cfg: ClientConfig,
    decoder: FrameDecoder,
    hello_sent: u64,
    peer: Option<Hello>,
    closed: bool,
    next_id: Id,
    /// Requests not yet answered: sent, or waiting in `window` for room.
    pending: BTreeMap<Id, Req>,
    window: Window,
    /// Last byte received, sent, or taken by the transport (`ping_if_quiet`).
    heard: u64,
    /// Bytes of `Send` outputs so far.
    written: u64,
    /// `now` of the running `handle`.
    now: u64,
    next_ping: u64,
    /// The timer last asked for by `SetTimer`.
    timer: u64,
    /// Commands given before the Hellos, with their tags.
    queued: VecDeque<(u64, Command)>,
    /// Commands given so far (the last one's tag).
    commands: u64,
    /// The command tag `request` gives (the command being handled, or the request being answered).
    tag: u64,
    /// Tags of the requests in `pending`, with their counts.
    open: BTreeMap<u64, usize>,
    samples: VecDeque<OffsetSample>,
    pongs: usize,
    /// Subscription ids reserved (spec/wire.md §11.1): from their Sub until the Unsub is
    /// answered or a Notify `Lapsed`; the token while delivered (none once unsubscribing).
    api_subs: BTreeMap<Id, Option<u64>>,
}

impl ClientSession {
    pub fn new(cfg: ClientConfig) -> ClientSession {
        ClientSession {
            cfg,
            decoder: FrameDecoder::new(),
            hello_sent: 0,
            peer: None,
            closed: false,
            next_id: 0,
            pending: BTreeMap::new(),
            window: Window::default(),
            heard: 0,
            written: 0,
            now: 0,
            next_ping: 0,
            timer: 0,
            queued: VecDeque::new(),
            commands: 0,
            tag: NO_COMMAND,
            open: BTreeMap::new(),
            samples: VecDeque::new(),
            pongs: 0,
            api_subs: BTreeMap::new(),
        }
    }

    /// Whether the Hellos have been exchanged.
    pub fn is_ready(&self) -> bool {
        self.peer.is_some()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Pings now, with nothing outstanding and nothing sent or heard for `quiet_ms`: the stall
    /// timeout then finds a dead connection. With a request outstanding that timeout runs already.
    pub fn ping_if_quiet(&mut self, now: u64, quiet_ms: u64) -> Vec<ClientOutput> {
        if self.window.is_empty() && self.heard.saturating_add(quiet_ms) <= now {
            self.next_ping = now;
        }
        self.handle(now, ClientInput::Timer)
    }

    /// Requests not yet answered (sent or waiting to be sent).
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }

    /// Requests waiting for room in the window (`WINDOW`).
    pub fn unsent(&self) -> usize {
        self.window.waiting.len()
    }

    /// Commands given so far: the tag of the last one (`answered`).
    pub fn commands(&self) -> u64 {
        self.commands
    }

    /// Whether every request of the commands tagged up to `tag` was answered (follow-up pages
    /// and resends included): one still unanswered is queued, in flight or held back.
    pub fn answered(&self, tag: u64) -> bool {
        self.queued.front().is_none_or(|(t, _)| *t > tag) && self.open.first_key_value().is_none_or(|(t, _)| *t > tag)
    }

    /// Bytes in flight against `WINDOW`.
    pub fn in_flight(&self) -> usize {
        self.window.in_flight
    }

    pub fn handle(&mut self, now: u64, input: ClientInput) -> Vec<ClientOutput> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        self.now = now;
        self.tag = NO_COMMAND;
        match input {
            ClientInput::Start => {
                self.hello_sent = now;
                out.push(ClientOutput::Send(encode_frame(&Hello::new(now, self.cfg.challenge).encode())));
            }
            ClientInput::Bytes(b) => {
                if !b.is_empty() {
                    self.heard = now;
                }
                self.decoder.push(&b);
                while !self.closed {
                    // the peer's first frame is its Hello (spec/wire.md §11.1)
                    self.decoder.set_max(if self.peer.is_some() { osis_base::format::MAX_MESSAGE } else { crate::frame::MAX_HELLO_BYTES });
                    match self.decoder.next_frame() {
                        Ok(Some(body)) => {
                            self.window.frame_in(&body, now);
                            self.frame(now, &body, &mut out)
                        }
                        Ok(None) => break,
                        Err(e) => {
                            event(&mut out, ClientEvent::PeerError(e));
                            self.close(&mut out);
                        }
                    }
                }
                self.window.tail_in(self.decoder.partial(), self.decoder.pending(), now);
            }
            ClientInput::Timer => {
                self.timer = 0;
                if self.window.stall_at().is_some_and(|t| t <= now) {
                    event(&mut out, ClientEvent::PeerError(Error::Timeout));
                    self.close(&mut out);
                    return out;
                }
                if self.is_ready() && self.next_ping <= now {
                    self.request(|id| Message::Ping { id, wall_ms: now }, Pending::Ping { sent: now });
                    self.next_ping = now.saturating_add(PING_INTERVAL_MS);
                }
            }
            ClientInput::Taken(n) => {
                if n > self.window.taken {
                    self.heard = now;
                }
                self.window.taken(n, now);
            }
            ClientInput::Command(c) => {
                self.commands = self.commands.saturating_add(1);
                self.tag = self.commands;
                if self.is_ready() {
                    self.command(c, &mut out);
                } else {
                    self.queued.push_back((self.commands, c));
                }
            }
        }
        self.flush(&mut out);
        self.arm(&mut out);
        self.written = self.written.saturating_add(sent_bytes(&out));
        out
    }

    /// Sends waiting requests while the window has room (one always goes when none is in flight).
    fn flush(&mut self, out: &mut Vec<ClientOutput>) {
        while !self.closed {
            let Some(mut msg) = self.window.next() else { break };
            if let (Some(Req { p: Pending::Ping { sent }, .. }), Message::Ping { wall_ms, .. }) = (self.pending.get_mut(&msg.id()), &mut msg) {
                // the clock sample starts when the ping leaves
                *sent = self.now;
                *wall_ms = self.now;
            }
            let frame = encode_frame(&msg.encode());
            let end = self.written.saturating_add(sent_bytes(out)).saturating_add(frame.len() as u64);
            self.window.sent(&msg, frame.len(), end, self.now);
            self.heard = self.now;
            out.push(ClientOutput::Send(frame));
        }
    }

    /// Asks for the timer at the next ping or request deadline, if that changed.
    fn arm(&mut self, out: &mut Vec<ClientOutput>) {
        if self.closed || !self.is_ready() {
            return;
        }
        let t = self.window.stall_at().map_or(self.next_ping, |s| s.min(self.next_ping));
        if t != self.timer {
            self.timer = t;
            out.push(ClientOutput::SetTimer(t));
        }
    }

    fn close(&mut self, out: &mut Vec<ClientOutput>) {
        self.closed = true;
        out.push(ClientOutput::Close);
    }

    /// Queues a request; `flush` sends it when the window has room.
    fn request(&mut self, msg: impl FnOnce(Id) -> Message, pending: Pending) {
        self.request_id(msg, pending);
    }

    /// `request`, returning the id it took.
    fn request_id(&mut self, msg: impl FnOnce(Id) -> Message, pending: Pending) -> Id {
        loop {
            // the node's range (`NODE_IDS`) is the node's own
            self.next_id = self.next_id.wrapping_add(1) & !NODE_IDS;
            if self.next_id != 0 && !self.pending.contains_key(&self.next_id) && !self.api_subs.contains_key(&self.next_id) {
                break;
            }
        }
        let id = self.next_id;
        self.pending.insert(id, Req { cmd: self.tag, p: pending });
        *self.open.entry(self.tag).or_insert(0) += 1;
        self.window.queue(msg(id));
        id
    }

    /// Request `id` was answered: its entry, if it was one sent.
    fn answered_req(&mut self, id: Id) -> Option<Req> {
        if !self.pending.contains_key(&id) || !self.window.answered(id, self.now) {
            return None;
        }
        let req = self.pending.remove(&id)?;
        if let Some(n) = self.open.get_mut(&req.cmd) {
            *n -= 1;
            if *n == 0 {
                self.open.remove(&req.cmd);
            }
        }
        Some(req)
    }

    fn command(&mut self, c: Command, out: &mut Vec<ClientOutput>) {
        match c {
            Command::Prove(provers) => {
                let Some(peer) = &self.peer else { return };
                // the listener's Hello challenge and its key, the key this side chose to dial
                let (ch, listener) = (peer.challenge, self.cfg.peer_static_key);
                let proofs = provers.iter().map(|p| p.sign(false, &ch, &listener)).collect();
                self.request(|id| Message::Prove { id, proofs }, Pending::Prove);
            }
            Command::Resume { nonce, tags } => {
                if self.peer.is_none() {
                    return;
                }
                self.request(|id| Message::Resume { id, nonce, tags }, Pending::Resume);
            }
            // the node's own requests (ids in its range, answered to the node) share the window;
            // its answers go at once
            Command::Peer(m) if m.is_request() => self.window.queue(*m),
            Command::Peer(m) => send(out, *m),
            Command::Register { label, step, claim_set } => self.request(|id| Message::Register { id, label, step, claim_set }, Pending::Register(label)),
            Command::Delete { label, items } => {
                let (items, bad): (Vec<DeleteItem>, Vec<DeleteItem>) = items.into_iter().partition(|i| i.to_value().is_ok());
                if !bad.is_empty() {
                    event(out, ClientEvent::Refused { label: Some(label), kind: Request::Delete, code: Code::MALFORMED, fetch: Vec::new() });
                }
                for chunk in items.chunks(MAX_ITEMS) {
                    let ids = chunk.iter().map(|i| i.blob).collect();
                    self.request(|id| Message::Delete { id, label, items: chunk.to_vec() }, Pending::Delete(label, ids));
                }
            }
            Command::Auth { token, session, secret } => {
                self.request(|id| Message::Auth { id, secret, session }, Pending::Api(token));
            }
            Command::Call { token, max_reply, method, args } => {
                self.request(|id| Message::Call { id, max_reply, method, args }, Pending::Api(token));
            }
            Command::Sub { token, max_reply, filter } => {
                let id = self.request_id(|id| Message::Sub { id, max_reply, filter }, Pending::Api(token));
                self.api_subs.insert(id, Some(token));
            }
            Command::Unsub { token } => {
                let Some(sub) = self.api_subs.iter().find(|(_, t)| **t == Some(token)).map(|(i, _)| *i) else { return };
                self.api_subs.insert(sub, None);
                // a Sub still unanswered: its reply frees the id (the Unsub is sent after it)
                self.request(|id| Message::Unsub { id, sub }, Pending::ApiUnsub(sub));
            }
            Command::Close => self.close(out),
        }
    }

    /// This connection's binding, once the peer's Hello is read: its Hello challenges (dialer's
    /// first) and the static key dialed.
    pub fn binding(&self) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        self.peer.as_ref().map(|p| (self.cfg.challenge, p.challenge, self.cfg.peer_static_key))
    }

    fn frame(&mut self, now: u64, body: &[u8], out: &mut Vec<ClientOutput>) {
        if self.peer.is_none() {
            let hello = match Hello::decode(body) {
                Ok(h) => h,
                Err(e) => {
                    event(out, ClientEvent::PeerError(e));
                    return self.close(out);
                }
            };
            let version = match negotiate(&[PROTOCOL_VERSION], &hello.versions) {
                Ok(v) => v,
                Err(e) => {
                    event(out, ClientEvent::PeerError(e));
                    return self.close(out);
                }
            };
            self.samples.push_back(OffsetSample { sent: self.hello_sent, peer: hello.wall_ms, received: now });
            self.peer = Some(hello);
            event(out, ClientEvent::Ready { version });
            self.tag = NO_COMMAND;
            for _ in 0..INITIAL_PINGS {
                self.request(|id| Message::Ping { id, wall_ms: now }, Pending::Ping { sent: now });
            }
            self.next_ping = now.saturating_add(PING_INTERVAL_MS);
            while let Some((t, c)) = self.queued.pop_front() {
                self.tag = t;
                self.command(c, out);
            }
            return;
        }
        let msg = match Message::decode(body) {
            Ok(m) => m,
            Err(r) => {
                // A request (or unknown kind) is answered; a broken reply or push is dropped.
                if r.wants_answer() {
                    send(out, Message::Error { id: r.id, code: r.code() });
                }
                event(out, ClientEvent::PeerError(r.error));
                return;
            }
        };
        match msg {
            Message::Ping { id, .. } => send(out, Message::Pong { id, wall_ms: now }),
            Message::Notify { sub, payload } => {
                let lapsed = payload == crate::api::Payload::Lapsed;
                if let Some(Some(token)) = self.api_subs.get(&sub).copied() {
                    event(out, ClientEvent::Notify { token, payload });
                }
                if lapsed {
                    self.api_subs.remove(&sub);
                }
            }
            m if m.for_node() => {
                if !m.is_request() {
                    self.window.answered(m.id(), now);
                }
                event(out, ClientEvent::Peer(Box::new(m)))
            }
            m if m.is_request() => send(out, Message::Error { id: m.id(), code: Code::UNSUPPORTED }),
            m => self.reply(now, m, out),
        }
    }

    fn reply(&mut self, now: u64, m: Message, out: &mut Vec<ClientOutput>) {
        let Some(Req { p: pending, cmd }) = self.answered_req(m.id()) else {
            event(out, ClientEvent::PeerError(Error::Malformed("reply to no request")));
            return;
        };
        // follow-ups (next pages, entries sent on their own) serve the same command
        self.tag = cmd;
        use ClientEvent as E;
        use Message as M;
        match (pending, m) {
            (Pending::Ping { sent }, M::Pong { wall_ms, .. }) => {
                if self.samples.len() == MAX_SAMPLES {
                    self.samples.pop_front();
                }
                self.samples.push_back(OffsetSample { sent, peer: wall_ms, received: now });
                self.pongs += 1;
                if let (true, Some(offset_ms)) = (self.pongs >= MIN_PONGS, estimate_offset(self.samples.make_contiguous())) {
                    event(out, E::ClockOffset { offset_ms, diagnostic: offset_ms.unsigned_abs() > OFFSET_DIAGNOSTIC_MS });
                }
            }
            (Pending::Api(token), M::Error { id, code }) => {
                // a refused Sub's id is free; one unsubscribed meanwhile has nobody waiting
                if self.api_subs.remove(&id) != Some(None) {
                    event(out, E::Reply { token, reply: Err(code) });
                }
            }
            (Pending::Api(token), M::Reply { id, outcome }) => {
                let live = self.api_subs.get(&id).copied();
                if !matches!(outcome, crate::api::Outcome::Ok { .. }) {
                    self.api_subs.remove(&id);
                }
                // a Sub unsubscribed before its reply: nobody waits for it any more
                if live != Some(None) {
                    event(out, E::Reply { token, reply: Ok(outcome) });
                }
            }
            (Pending::ApiUnsub(sub), M::Ok { .. } | M::Error { .. }) => {
                if self.api_subs.get(&sub) == Some(&None) {
                    self.api_subs.remove(&sub);
                }
            }
            (Pending::Prove, M::Proved { proofs, .. }) => {
                // proved over this side's challenge and the key it dialed: a proof of any other
                // connection, or the listener's relayed from one, does not verify
                let (ch, listener) = (self.cfg.challenge, self.cfg.peer_static_key);
                event(out, E::Proved { proofs: crate::prove::verified(proofs, true, &ch, &listener) });
            }
            (Pending::Resume, M::Resumed { nonce, tag, .. }) => event(out, E::Resumed { nonce, tag }),
            (p, M::Error { code, .. }) => event(out, E::Refused { label: p.label(), kind: p.kind(), code, fetch: Vec::new() }),
            (Pending::Register(label), M::Ok { .. }) => event(out, E::Registered { label }),
            (Pending::Delete(label, blob_ids), M::Status { codes, .. }) if codes.len() == blob_ids.len() => event(out, E::DeleteStatus { label, blob_ids, codes }),
            (_, _) => event(out, E::PeerError(Error::Malformed("reply of the wrong kind"))),
        }
    }
}

fn event(out: &mut Vec<ClientOutput>, e: ClientEvent) {
    out.push(ClientOutput::Event(e));
}
