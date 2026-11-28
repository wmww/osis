//! Wire and session (spec/wire.md §11.1-§11.2, spec/sync-streams.md §1-§2, spec/sync-opens.md
//! §1 Dial timeout, §2 Connection proofs, spec/sync-transport.md §1): one connection's frames,
//! Hello and its negotiation, connection proofs, request ids and where each message goes, the
//! window, pushes, the stall clock, unanswered requests received, clock samples; and the
//! deadlines of dials not up yet.
//!
//! Pure: messages in, frames out. No I/O and no clock read: time comes in an input (`Cx::now`,
//! `Sessions::set_now`), and what the transport took on a connection as `Sessions::taken`.
//!
//! State, per connection, in memory: Hello and the challenges, proofs shown and proven, request
//! ids and their order, the window, the stall clock, unanswered-in bytes, the bytes written and
//! taken. Depends on osis-proto and the engine's proof calls (`provers`).

use crate::types::{ConnId, Cx, NodeKey, Out};
use osis_base::{Mono, Tid, Time};
use osis_proto::frame::MAX_HELLO_BODY;
use osis_proto::limits::{MAX_ID, MAX_MESSAGE, MAX_PROOF_COPIES, MAX_PROOFS, NO_RECORD_ID, REPLY_BUDGET, SMALL_REPLY, TOP_BIT, WINDOW};
use osis_proto::msg::{Flow, answers, peek_head};
use osis_proto::prove::verified;
use osis_blob::Certificates;
use osis_proto::{ClockSamples, Code, FrameDecoder, Hello, Msg, OFFSET_DIAGNOSTIC_MS, OffsetSample, PROTOCOL_VERSION, Proof, Prover, encode_frame, negotiate};
use osis_store::{Claim, Named};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A request's id on its connection (spec/wire.md §11.2).
pub type RequestId = osis_proto::msg::Id;

/// How long the oldest request sent and not answered may stand without moving, and a connection
/// may wait for the peer's Hello, before it closes (spec/sync-streams.md §1 Stall,
/// spec/sync-transport.md §1). Local policy: "minutes". At 0 every connection with a request out
/// closes at once; at infinity a peer that answers nothing holds the connection, and what it
/// was asked, for good.
pub const STALL_TIMEOUT_MS: u64 = 2 * 60 * 1000;

/// How long a dial may take to come up, whatever steps the transport takes, before it closes as
/// failed (spec/sync-opens.md §1 Dial timeout). Local policy, the stall bound: at 0 no dial comes
/// up; at infinity one silent route or peer stalls that peer for good.
pub const DIAL_TIMEOUT_MS: u64 = STALL_TIMEOUT_MS;

/// Pings a dialer sends on a connection, one at a time, for its clock offset estimate
/// (spec/sync-streams.md §1; `ClockSamples` reports after three). At 0 no offset is estimated;
/// at infinity a connection never goes idle.
pub const PINGS: u32 = 3;

/// Unwritten bytes a peer must allow before it may close a connection, beside the closer's own
/// bytes in flight (spec/sync-streams.md §1 Closing).
const CLOSING: u64 = (WINDOW + 2 * (MAX_MESSAGE + 4)) as u64;
/// What the requests a peer receives before it answers any may come to (spec/sync-streams.md §1
/// Unanswered requests).
const UNANSWERED: u64 = (WINDOW + 2 * MAX_MESSAGE + 4) as u64;
/// Other bytes received that still move the stall clock since it last moved by its own events
/// (spec/sync-streams.md §1 Stall).
const OTHER_BYTES: u64 = CLOSING + UNANSWERED;

/// What a node holds out for every connection together (spec/sync-transport.md §5 Served
/// connections, local policy): bytes written and not taken by the transport, with the reply
/// allowances of the requests it is answering; never passed. Each connection's share is this over
/// the connections up. At 0 nothing is answered or sent; at infinity memory grows with the
/// connections (each bounded alone, `CLOSING`). It must take the costliest reply
/// (`REPLY_BUDGET` with its frame) whole, as one holding nothing may take one past its share.
pub const OUT_BOUND: u64 = 256 << 20;

/// What a node holds received for every connection together (spec/sync-transport.md §5 Served
/// connections, local policy): bytes of frames received and not yet run or answered, partial ones
/// included; past it the connection holding the most closes. At 0 every connection closes at its
/// first bytes; at infinity memory grows with the connections (each bounded alone,
/// `UNANSWERED` and one partial frame while it reads).
pub const IN_BOUND: u64 = 256 << 20;

/// A peer's request waiting for room (`Session::fits`): reading stops behind it.
#[derive(Clone, Debug)]
struct Held {
    id: RequestId,
    m: Msg,
    /// Its reply allowance.
    allowance: u64,
    /// Since when it waits.
    since: Mono,
}

/// One message received, by role.
#[derive(Clone, Debug)]
pub enum Incoming {
    /// The peer's proofs are done (`Session::proven`): opens begins.
    Proved,
    /// A request of the peer's: answered with `Session::answer` and its id.
    Request(RequestId, Msg),
    /// The answer to a request the module `To` sent. A Pull or Fetch the peer skipped (a later
    /// one answered first, spec/wire.md §11.2 Pull) is answered here as refused (Error 14) or
    /// as answered with none of its IDs.
    Reply(To, RequestId, Msg),
    Push(Msg),
}

/// The module a received message goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum To {
    /// Proved; Resume, Beacons, Offer, Lost, NoRecord; Digest, Members.
    Opens,
    /// Pull, Fetch; Stream, Applied.
    Streams,
    /// Answers to read's requests (Delete, deposits, stamps).
    Read,
    /// Register, Delete, Stranded.
    Inbox,
    /// The client port (spec/wire.md §11.2 kinds 24-29), the node's owner's (`Node::port`): the
    /// peer's Auth, Call, Sub and Unsub to answer; on a client connection (`Session::client`)
    /// the answers to the owner's own and the node's Notifies.
    Port,
}

impl Incoming {
    /// Which module takes this message; `None` for one no module takes.
    pub fn to(&self) -> Option<To> {
        match self {
            Incoming::Proved => Some(To::Opens),
            Incoming::Reply(to, ..) => Some(*to),
            Incoming::Request(_, m) | Incoming::Push(m) => match m.kind() {
                34 | 36 | 37 | 38 | 40 | 45 | 46 | 49 => Some(To::Opens),
                19 | 41 | 43 | 44 | 47 => Some(To::Streams),
                7 | 14 | 30 => Some(To::Inbox),
                24 | 25 | 27 | 28 if matches!(self, Incoming::Request(..)) => Some(To::Port),
                29 if matches!(self, Incoming::Push(..)) => Some(To::Port),
                _ => None,
            },
        }
    }
}

/// Why a session closes its connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close(pub &'static str);

/// What the peer proved on this connection (spec/sync-opens.md §2): its proofs' claims, each
/// signature verified here, and the copies they came with, kept with the connection alone. What
/// they prove is the engine's judgement, made on what this node holds now (`Engine::proven`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proven {
    /// What the record names: the claims in proof order, the peer's node thing's first.
    pub named: Named,
    pub copies: Certificates,
}

impl Proven {
    /// The peer's node thing: the thing its first proof was signed as.
    pub fn node(&self) -> Option<Tid> {
        self.named.node()
    }

    /// Proved nothing.
    pub fn is_empty(&self) -> bool {
        self.named.is_empty()
    }
}

/// What binds a signature or tag to this connection (spec/wire.md §11.1 Static key,
/// spec/sync-opens.md §3-§5): both Hello challenges and the listener's static key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub dialer_challenge: [u8; 32],
    pub listener_challenge: [u8; 32],
    pub listener_key: [u8; 32],
}

/// Where the proof exchange stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proofs {
    /// Before the peer's Hello.
    Hello,
    /// The dialer's Prove out (dialer), or not received yet (listener).
    Proving,
    Done,
}

/// A request this side made: waiting for the window, or sent and not answered.
#[derive(Clone, Debug)]
struct Req {
    kind: u64,
    /// The module its answer goes to; `None`: the session's own (Prove, Ping).
    by: Option<To>,
    /// Its frame length plus its reply allowance (spec/sync-streams.md §1 Requester).
    cost: u64,
    sent: Option<Sent>,
}

#[derive(Clone, Copy, Debug)]
struct Sent {
    seq: u64,
    /// Where its frame ends in the bytes written on the connection.
    end: u64,
    /// The transport took it whole while it was the oldest: that moved the stall clock once.
    taken: bool,
}

/// How a frame received moves the stall clock (spec/sync-streams.md §1 Stall).
enum Moves {
    /// A reply to the oldest request out: its own event.
    Own,
    /// A reply to another request (or a reply dropped).
    Nothing,
    /// Other bytes: a push, a request, a frame that is no message.
    Other(u64),
}

/// One connection's session.
#[derive(Clone, Debug)]
pub struct Session {
    pub conn: ConnId,
    pub peer: NodeKey,
    pub dialer: bool,
    pub rank: u8,
    listener_key: NodeKey,
    challenge: [u8; 32],
    binding: Option<Binding>,
    frames: FrameDecoder,
    proofs: Proofs,
    proven: Proven,
    acted_for: Option<Vec<Claim>>,
    /// The wall clock (Hello, Ping and Pong carry it) and the monotonic one (the stall clock).
    now: Time,
    mono: Mono,
    up_at: Mono,
    next_low: RequestId,
    next_top: RequestId,
    reqs: BTreeMap<RequestId, Req>,
    /// Requests made and not sent yet, for the window, in the order made, with their frames.
    waiting: VecDeque<(RequestId, Vec<u8>)>,
    /// Requests sent and not answered, by send order.
    order: BTreeMap<u64, RequestId>,
    /// Pulls and Fetches sent and not answered, oldest first: answered in order.
    ordered: VecDeque<RequestId>,
    seq: u64,
    in_flight: u64,
    /// When the oldest request out last moved, and other bytes received since it last moved by
    /// its own events.
    moved: Mono,
    other: u64,
    /// The peer's requests not answered yet, with their costs and frame lengths.
    unanswered: BTreeMap<RequestId, (u64, u64)>,
    unanswered_bytes: u64,
    bytes: Vec<u8>,
    /// Why a module closes this connection.
    closing: Option<&'static str>,
    /// Bytes written on the connection so far (handed out or still in `bytes`), and taken by
    /// the transport.
    written: u64,
    taken: u64,
    clock: ClockSamples,
    ping: Option<(RequestId, Time)>,
    pings: u32,
    offset: Option<i64>,
    /// Frames received after Hello.
    frames_in: u64,
    /// Keep or close: the quiet probe out (its Ping, and `frames_in` when it went), and whether
    /// the last one came back with nothing before it.
    probe: Option<(RequestId, u64)>,
    quiet: Option<u64>,
    /// A client connection (`client`): the dialer proves nothing.
    client: bool,
    /// The reply allowances of the peer's requests handed on and not answered (`OUT_BOUND`),
    /// and their sum.
    admitted: BTreeMap<RequestId, u64>,
    reserved: u64,
    /// Frame bytes of the peer's requests not answered (`IN_BOUND`).
    unanswered_len: u64,
    /// The peer's request waiting for room: nothing behind it is read meanwhile.
    held: Option<Held>,
    /// What `Sessions` lets this connection hold out (`fits`): the bound's room left beside the
    /// others' holdings, its share, and whether a request elsewhere waits for the bound's room
    /// (none goes past it). Unbounded on a session outside `Sessions`.
    room: u64,
    share: u64,
    blocked: bool,
    /// When the transport last took bytes of it.
    last_taken: Mono,
    /// Whether the transport was last told to read it.
    told_reading: bool,
    /// Own requests stopped for room (`pump`).
    starved: bool,
    /// Its holdings as `Sessions` last counted them (out, in).
    counted: (u64, u64),
}

impl Session {
    /// A session on a connection just up, with the listener's static key (the key dialed, or the
    /// key of this node's listener that took it); queues Hello.
    pub fn new(conn: ConnId, peer: NodeKey, dialer: bool, rank: u8, listener_key: NodeKey, cx: &mut Cx) -> Session {
        let mut challenge = [0u8; 32];
        cx.rng.fill_bytes(&mut challenge);
        let mut frames = FrameDecoder::new();
        frames.set_max(MAX_HELLO_BODY);
        let mut s = Session {
            conn,
            peer,
            dialer,
            rank,
            listener_key,
            challenge,
            binding: None,
            frames,
            proofs: Proofs::Hello,
            proven: Proven::default(),
            acted_for: None,
            now: cx.now,
            mono: cx.mono,
            up_at: cx.mono,
            next_low: 0,
            next_top: TOP_BIT,
            reqs: BTreeMap::new(),
            waiting: VecDeque::new(),
            order: BTreeMap::new(),
            ordered: VecDeque::new(),
            seq: 0,
            in_flight: 0,
            moved: cx.mono,
            other: 0,
            unanswered: BTreeMap::new(),
            unanswered_bytes: 0,
            bytes: Vec::new(),
            closing: None,
            written: 0,
            taken: 0,
            clock: ClockSamples::default(),
            ping: None,
            pings: 0,
            offset: None,
            frames_in: 0,
            probe: None,
            quiet: None,
            client: false,
            admitted: BTreeMap::new(),
            reserved: 0,
            unanswered_len: 0,
            held: None,
            room: u64::MAX,
            share: u64::MAX,
            blocked: false,
            last_taken: cx.mono,
            told_reading: true,
            starved: false,
            counted: (0, 0),
        };
        s.write(Hello::new(cx.now.0, challenge).encode());
        s
    }

    /// Makes this a client connection (spec/sync-transport.md §6): the owner's own, to use a
    /// node's client port. Its dialer sends no Prove, so it proves no actor, keeps no record and
    /// opens nothing (spec/sync-opens.md §2-§3): no pair rule closes it beside a sync connection
    /// to the same node. Set before the peer's Hello.
    pub fn client(&mut self) {
        self.client = true;
    }

    /// Takes bytes received; proofs run here. `Err`: the connection closes (with the Error frame
    /// queued that a broken frame is answered by).
    pub fn receive(&mut self, bytes: &[u8], cx: &mut Cx) -> Result<Vec<Incoming>, Close> {
        (self.now, self.mono) = (cx.now, cx.mono);
        self.frames.push(bytes);
        let mut ins = Vec::new();
        let (mut own, mut other) = (false, 0u64);
        loop {
            // a request waiting for room: read no further until it goes
            if let Some(h) = &self.held {
                if !self.fits(h.allowance) {
                    break;
                }
                if let Some(h) = self.held.take() {
                    self.run_request(h.id, h.m, h.allowance, cx, &mut ins)?;
                }
                continue;
            }
            let body = match self.frames.next_frame() {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(_) => {
                    self.error(0, Code::MALFORMED);
                    return Err(Close("frame length"));
                }
            };
            if self.binding.is_none() {
                self.hello(&body, cx)?;
            } else {
                self.frames_in += 1;
                match self.frame(body, cx, &mut ins)? {
                    Moves::Own => own = true,
                    Moves::Nothing => {}
                    Moves::Other(n) => other += n,
                }
            }
        }
        // bytes of a reply to the oldest request still arriving
        if let (false, Some(oldest), Some(part)) = (bytes.is_empty(), self.oldest(), self.frames.partial()) {
            own |= peek_head(part).is_some_and(|(kind, id)| id == oldest && osis_proto::msg::flow(kind) == Some(Flow::Reply));
        }
        if own {
            self.moved();
        } else if other > 0 {
            self.other = self.other.saturating_add(other);
            if self.other <= OTHER_BYTES {
                self.moved = self.mono;
            }
        }
        if self.unwritten() > CLOSING + self.in_flight {
            return Err(Close("the peer reads nothing"));
        }
        Ok(ins)
    }

    /// Sends a request for module `by`, in order while under `WINDOW`; its answer comes back as
    /// `Incoming::Reply(by, ..)`. Its id is chosen here (top bit set for the shared set's and the
    /// stream's requests, spec/wire.md §11.2).
    pub fn request(&mut self, by: To, m: Msg) -> RequestId {
        self.send_request(Some(by), m)
    }

    /// Answers the peer's request `to`.
    pub fn answer(&mut self, to: RequestId, mut m: Msg) {
        m.set_id(to);
        if let Some((cost, len)) = self.unanswered.remove(&to) {
            self.unanswered_bytes -= cost;
            self.unanswered_len -= len;
        }
        if let Some(a) = self.admitted.remove(&to) {
            self.reserved -= a;
        }
        self.write(m.encode());
    }

    /// Pushes (a Stream, a Notify) while the bytes the transport has not taken on this
    /// connection, the push included, stay within `REPLY_BUDGET`, or none are; `false`: it did
    /// not go, the pusher waits for room (spec/sync-streams.md §2).
    pub fn push(&mut self, m: Msg) -> bool {
        let body = m.encode();
        let u = self.unwritten();
        let len = body.len() as u64 + 4;
        if u > 0 && u + len > REPLY_BUDGET as u64 || !self.fits(len) {
            return false;
        }
        self.write(body);
        true
    }

    /// Pushes a message that never waits for room: opens' Digest and Members, once a connection
    /// and bounded by a record's shared set.
    pub fn push_now(&mut self, m: Msg) {
        self.write(m.encode());
    }

    /// A module closes the connection: the peer broke the protocol (the driver closes it after
    /// the message).
    pub fn close(&mut self, why: &'static str) {
        self.closing.get_or_insert(why);
    }

    /// Why a module closed the connection, if one did.
    pub fn closing(&self) -> Option<&'static str> {
        self.closing
    }

    /// What the peer proved: empty until `Incoming::Proved`.
    pub fn proven(&self) -> &Proven {
        &self.proven
    }

    /// Whether the proof exchange is done (`Incoming::Proved` was reported).
    pub fn proofs_done(&self) -> bool {
        self.proofs == Proofs::Done
    }

    /// The claims this node acted for when it proved on this connection (its Prove, or its
    /// Proved), whether or not its policy sent their proofs; none before it proved, and on a
    /// client connection.
    pub fn acted_for(&self) -> Option<&[Claim]> {
        self.acted_for.as_deref()
    }

    /// The challenges and the listener's key, once the peer's Hello came.
    pub fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }

    /// The peer's clock minus this node's (ms), once enough Pongs came back (spec/sync-streams.md
    /// §1): a diagnostic, never applied.
    pub fn clock_offset(&self) -> Option<i64> {
        self.offset
    }

    /// The bytes to send, taken.
    pub fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }

    /// The transport took `total` bytes of this connection's so far (`Input::Taken`, through
    /// `Sessions`).
    pub fn taken(&mut self, total: u64, mono: Mono) {
        self.mono = self.mono.max(mono);
        if total.min(self.written) > self.taken {
            self.last_taken = self.mono;
        }
        self.taken = self.taken.max(total.min(self.written));
        let Some(oldest) = self.oldest() else { return };
        let taken = self.taken;
        if let Some(s) = self.reqs.get_mut(&oldest).and_then(|r| r.sent.as_mut()).filter(|s| !s.taken && s.end <= taken) {
            s.taken = true;
            self.moved();
        }
    }

    /// When this connection closes unless it moves: waiting for the peer's Hello, or for the
    /// oldest request out.
    pub fn deadline(&self) -> Option<Mono> {
        let from = if self.binding.is_none() {
            self.up_at
        } else if !self.order.is_empty() {
            self.moved
        } else {
            return None;
        };
        Some(from.after(STALL_TIMEOUT_MS))
    }

    fn unwritten(&self) -> u64 {
        self.written - self.taken
    }

    /// What it holds out for the connection (`OUT_BOUND`): bytes written and not taken, and the
    /// reply allowances of the requests it is answering.
    pub fn out_held(&self) -> u64 {
        self.unwritten() + self.reserved
    }

    /// What it holds received for the connection (`IN_BOUND`): frame bytes not yet run, partial
    /// ones included, and those of the requests it has not answered.
    pub fn in_held(&self) -> u64 {
        self.frames.pending() as u64 + self.unanswered_len
    }

    /// Whether the transport should read the connection: no request waits for room.
    pub fn reading(&self) -> bool {
        self.held.is_none()
    }

    /// Whether `add` more bytes held out fit (spec/sync-transport.md §5 Served connections):
    /// within the bound's room and this connection's share, none waiting for that room before
    /// it; one holding nothing may go past its share.
    fn fits(&self, add: u64) -> bool {
        let h = self.out_held();
        !self.blocked && h.saturating_add(add) <= self.room && (h.saturating_add(add) <= self.share || h == 0)
    }

    fn oldest(&self) -> Option<RequestId> {
        self.order.first_key_value().map(|(_, id)| *id)
    }

    /// The oldest request out moved by its own events.
    fn moved(&mut self) {
        self.moved = self.mono;
        self.other = 0;
    }

    /// Frames `body` into the bytes to send.
    fn write(&mut self, body: Vec<u8>) {
        let frame = encode_frame(&body);
        self.written += frame.len() as u64;
        self.bytes.extend_from_slice(&frame);
    }

    fn error(&mut self, id: RequestId, code: Code) {
        self.write(Msg::Error { id, code }.encode());
    }

    fn send_request(&mut self, by: Option<To>, mut m: Msg) -> RequestId {
        let kind = m.kind();
        let id = self.fresh_id(kind);
        m.set_id(id);
        let body = m.encode();
        let cost = body.len() as u64 + 4 + allowance(&m);
        self.reqs.insert(id, Req { kind, by, cost, sent: None });
        self.waiting.push_back((id, body));
        self.pump();
        id
    }

    /// An id not in use: NoRecord's one id, else the next of its range (spec/wire.md §11.1-§11.2).
    fn fresh_id(&mut self, kind: u64) -> RequestId {
        if kind == 40 {
            return NO_RECORD_ID;
        }
        let top = osis_proto::msg::top_bit_kind(kind);
        loop {
            let id = if top {
                self.next_top = if self.next_top >= MAX_ID as RequestId { TOP_BIT + 1 } else { self.next_top + 1 };
                self.next_top
            } else {
                self.next_low = if self.next_low >= TOP_BIT - 1 { 1 } else { self.next_low + 1 };
                self.next_low
            };
            if !self.reqs.contains_key(&id) {
                return id;
            }
        }
    }

    /// Sends waiting requests while below `WINDOW` (so one always goes), in the order made.
    fn pump(&mut self) {
        self.starved = false;
        while self.in_flight < WINDOW as u64 {
            if self.waiting.front().is_some_and(|(_, b)| !self.fits(b.len() as u64 + 4)) {
                self.starved = true;
                return;
            }
            let Some((id, body)) = self.waiting.pop_front() else { return };
            if self.order.is_empty() {
                self.moved();
            }
            self.write(body);
            self.seq += 1;
            let (seq, end) = (self.seq, self.written);
            let Some(r) = self.reqs.get_mut(&id) else { continue };
            r.sent = Some(Sent { seq, end, taken: false });
            self.in_flight += r.cost;
            if matches!(r.kind, 19 | 41) {
                self.ordered.push_back(id);
            }
            self.order.insert(seq, id);
        }
    }

    /// Request `id` answered (or skipped): out of the window; the stall clock moves when it was
    /// the oldest.
    fn settled(&mut self, id: RequestId) -> Option<Req> {
        let r = self.reqs.remove(&id)?;
        if let Some(s) = r.sent {
            let was_oldest = self.order.first_key_value().is_some_and(|(q, _)| *q == s.seq);
            self.order.remove(&s.seq);
            self.in_flight -= r.cost;
            if was_oldest {
                self.moved();
            }
        }
        Some(r)
    }

    /// The peer's Hello: the version, the challenges, then the proofs (the dialer's first).
    fn hello(&mut self, body: &[u8], cx: &mut Cx) -> Result<(), Close> {
        let Ok(h) = Hello::decode(body) else {
            self.error(0, Code::MALFORMED);
            return Err(Close("malformed hello"));
        };
        negotiate(&[PROTOCOL_VERSION], &h.versions).map_err(|_| Close("no common version"))?;
        self.frames.set_max(MAX_MESSAGE);
        let (dialer_challenge, listener_challenge) = if self.dialer { (self.challenge, h.challenge) } else { (h.challenge, self.challenge) };
        self.binding = Some(Binding { dialer_challenge, listener_challenge, listener_key: self.listener_key.0 });
        self.proofs = Proofs::Proving;
        if self.dialer && !self.client {
            self.prove(cx)?;
        }
        self.next_ping();
        Ok(())
    }

    /// The dialer's Prove (spec/sync-opens.md §2 Order): its node thing's proofs, then its
    /// link keys'; none where its policy proves nothing to this peer (`Policy::identify`).
    fn prove(&mut self, cx: &mut Cx) -> Result<(), Close> {
        let Some(b) = self.binding else { return Ok(()) };
        let (proofs, copies) = self.signed(cx, cx.policy.identify(None), false, &b.listener_challenge)?;
        self.send_request(None, Msg::Prove { id: 0, proofs, copies });
        Ok(())
    }

    /// This node's proofs over `challenge`, by `by_listener`, in proof order, at most
    /// `MAX_PROOFS`, with their copies, at most `MAX_PROOF_COPIES`; none unless `identify` (its
    /// policy). What it acts for is noted either way.
    fn signed(&mut self, cx: &mut Cx, identify: bool, by_listener: bool, challenge: &[u8; 32]) -> Result<(Vec<Proof>, Certificates), Close> {
        let p = cx.engine.proving().map_err(|_| Close("engine"))?;
        self.acted_for = Some(p.provers.iter().map(|x| x.claim()).collect());
        if !identify {
            return Ok((Vec::new(), Certificates::default()));
        }
        let listener = self.listener_key.0;
        let proofs = p.provers.into_iter().take(MAX_PROOFS).map(|x| Prover { key: x.key, record: x.record, path: x.path }.sign(by_listener, challenge, &listener)).collect();
        let mut copies = p.copies;
        copies.commits.truncate(MAX_PROOF_COPIES);
        Ok((proofs, copies))
    }

    /// What verified proofs claim, with the copies they came with.
    fn judge(&self, proofs: Vec<Proof>, copies: Certificates) -> Proven {
        let claims = proofs.into_iter().map(|p| Claim { thing: p.thing(), key: p.key, path: p.path }).collect();
        Proven { named: Named { claims }, copies }
    }

    /// One frame after Hello, and how it moves the stall clock.
    fn frame(&mut self, body: Vec<u8>, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<Moves, Close> {
        let len = body.len() as u64 + 4;
        let m = match Msg::decode(&body) {
            Ok(m) => m,
            Err(r) => {
                if r.answered() {
                    self.error(if r.read { r.id } else { 0 }, r.code());
                }
                return Ok(Moves::Other(len));
            }
        };
        match m.flow() {
            Flow::Request => self.on_request(m, len, cx, ins).map(|()| Moves::Other(len)),
            Flow::Reply => self.on_reply(m, cx, ins).map(|oldest| if oldest { Moves::Own } else { Moves::Nothing }),
            Flow::Push => {
                ins.push(Incoming::Push(m));
                Ok(Moves::Other(len))
            }
        }
    }

    fn on_request(&mut self, m: Msg, len: u64, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<(), Close> {
        let id = m.id();
        if self.unanswered.contains_key(&id) {
            self.error(id, Code::MALFORMED);
            return Err(Close("request id reused"));
        }
        let a = allowance(&m);
        let cost = len + a;
        if self.unanswered_bytes + cost > UNANSWERED {
            return Err(Close("too many requests unanswered"));
        }
        self.unanswered.insert(id, (cost, len));
        self.unanswered_bytes += cost;
        self.unanswered_len += len;
        // within the bound's room and this connection's share, else it waits and reading stops
        // (spec/sync-transport.md §5 Served connections)
        if !self.fits(a) {
            self.held = Some(Held { id, m, allowance: a, since: self.mono });
            return Ok(());
        }
        self.run_request(id, m, a, cx, ins)
    }

    /// The peer's request `id`, its reply allowance `a` now held out until it is answered:
    /// answered here (Ping, Prove) or handed on.
    fn run_request(&mut self, id: RequestId, m: Msg, a: u64, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<(), Close> {
        self.admitted.insert(id, a);
        self.reserved += a;
        match m {
            Msg::Ping { .. } => self.answer(id, Msg::Pong { id, wall_ms: self.now.0 }),
            Msg::Prove { proofs, copies, .. } => self.proved_to(id, proofs, copies, cx, ins)?,
            m => ins.push(Incoming::Request(id, m)),
        }
        Ok(())
    }

    /// The dialer's Prove at the listener: its proofs judged, then the listener's own, by its
    /// policy (spec/sync-opens.md §1 Policy, §2 Order).
    fn proved_to(&mut self, id: RequestId, proofs: Vec<Proof>, copies: Certificates, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<(), Close> {
        let Some(b) = self.binding.filter(|_| !self.dialer && self.proofs == Proofs::Proving) else {
            self.answer(id, Msg::Error { id, code: Code::MALFORMED });
            return Ok(());
        };
        let proven = self.judge(verified(proofs, false, &b.listener_challenge, &b.listener_key), copies);
        if !cx.policy.sync_with(&proven) {
            return Err(Close("policy"));
        }
        let (proofs, copies) = self.signed(cx, cx.policy.identify(Some(&proven)), true, &b.dialer_challenge)?;
        self.proven = proven;
        self.proofs = Proofs::Done;
        self.answer(id, Msg::Proved { id, proofs, copies });
        ins.push(Incoming::Proved);
        Ok(())
    }

    /// A reply: dropped unless it answers a request out, by its kind. Whether it was the oldest.
    fn on_reply(&mut self, m: Msg, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<bool, Close> {
        let id = m.id();
        let Some((kind, by)) = self.reqs.get(&id).filter(|r| r.sent.is_some() && answers(r.kind, m.kind())).map(|r| (r.kind, r.by)) else { return Ok(false) };
        let oldest = self.oldest() == Some(id);
        if matches!(kind, 19 | 41) {
            // answered in order: those before it were skipped
            while let Some(skipped) = self.ordered.pop_front() {
                if skipped == id {
                    break;
                }
                if let Some(r) = self.settled(skipped) {
                    let reply = if r.kind == 41 { Msg::Error { id: skipped, code: Code::DECLINED } } else { Msg::FetchReply { id: skipped, items: Vec::new() } };
                    if let Some(to) = r.by {
                        ins.push(Incoming::Reply(to, skipped, reply));
                    }
                }
            }
        }
        self.settled(id);
        match by {
            Some(to) => ins.push(Incoming::Reply(to, id, m)),
            None => self.own_reply(kind, m, cx, ins)?,
        }
        self.pump();
        Ok(oldest)
    }

    /// The answer to the session's own Prove or Ping.
    fn own_reply(&mut self, kind: u64, m: Msg, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<(), Close> {
        match (kind, m) {
            (32, Msg::Proved { proofs, copies, .. }) => {
                let Some(b) = self.binding else { return Ok(()) };
                self.proven = self.judge(verified(proofs, true, &b.dialer_challenge, &b.listener_key), copies);
                if !cx.policy.sync_with(&self.proven) {
                    return Err(Close("policy"));
                }
                self.proofs = Proofs::Done;
                ins.push(Incoming::Proved);
            }
            (32, _) => return Err(Close("proofs refused")),
            (2, Msg::Pong { id, .. }) if self.probe.is_some_and(|(p, _)| p == id) => {
                // the peer answered the probe after everything it sent before it: quiet when
                // nothing else came between
                let at = self.probe.take().map_or(0, |(_, n)| n);
                self.quiet = (self.frames_in == at + 1).then_some(self.frames_in);
            }
            (2, Msg::Pong { wall_ms, .. }) => {
                if let Some((_, sent)) = self.ping.take() {
                    self.pings += 1;
                    let far = |o: Option<i64>| o.is_some_and(|o| o.unsigned_abs() > OFFSET_DIAGNOSTIC_MS);
                    let was = far(self.offset);
                    self.offset = self.clock.pong(OffsetSample { sent: sent.0, peer: wall_ms, received: self.now.0 }).or(self.offset);
                    // reported once a connection, when the estimate first goes past it
                    if let Some(o) = self.offset.filter(|_| far(self.offset) && !was) {
                        let key: String = self.peer.0[..8].iter().map(|b| format!("{b:02x}")).collect();
                        let detail = format!("the peer at key {key}.. runs {o:+} ms from this node's clock");
                        cx.engine.report(osis_engine::Diagnostic { kind: osis_engine::DiagnosticKind::ClockSkew, tids: Vec::new(), commit: None, peer: None, detail });
                    }
                }
                self.next_ping();
            }
            _ => self.ping = None,
        }
        Ok(())
    }

    /// Keep or close (spec/sync-opens.md §1): this side has nothing under way on the connection.
    /// Whether the peer is quiet too: a Ping sent while this side had nothing under way came back
    /// with no other frame before it, so whatever the peer sent in answer to what this side sent
    /// (a test's Offer after a filter, a Lost) has arrived and nothing came since. Else a probe
    /// goes (one at a time) and this is asked again when its Pong comes.
    pub fn quiet(&mut self) -> bool {
        let pings = [self.probe.map(|(p, _)| p), self.ping.map(|(p, _)| p)];
        if !self.unanswered.is_empty() || !self.waiting.is_empty() || self.reqs.keys().any(|id| !pings.contains(&Some(*id))) {
            self.quiet = None;
            return false;
        }
        if self.quiet == Some(self.frames_in) {
            return true;
        }
        if self.probe.is_none() {
            let id = self.send_request(None, Msg::Ping { id: 0, wall_ms: self.now.0 });
            self.probe = Some((id, self.frames_in));
        }
        false
    }

    /// The dialer's next Ping, one at a time, `PINGS` in all.
    fn next_ping(&mut self) {
        if self.dialer && self.ping.is_none() && self.pings < PINGS {
            let id = self.send_request(None, Msg::Ping { id: 0, wall_ms: self.now.0 });
            self.ping = Some((id, self.now));
        }
    }
}

/// A request's reply allowance (spec/sync-streams.md §1 Requester).
fn allowance(m: &Msg) -> u64 {
    match m {
        Msg::Prove { .. } => MAX_MESSAGE as u64,
        Msg::Fetch { max_reply, .. } | Msg::Want { max_reply, .. } | Msg::Call { max_reply, .. } | Msg::Sub { max_reply, .. } => *max_reply,
        Msg::Pull(p) => p.max_reply,
        _ => SMALL_REPLY as u64,
    }
}

/// Every connection's session: the driver owns it; a module that sends takes it `&mut` and sends
/// through `request`, `answer` and `push` of the connection it acts on. What a module sends
/// leaves at the end of the step (`take_sends`). Also the deadlines: each session's (the stall
/// clock, the peer's Hello) and each dial's not up yet; work per step is in proportion to the
/// sessions the step touched.
///
/// And the node-wide bounds on what connections hold (spec/sync-transport.md §5 Served
/// connections): the totals held out and received, kept by recounting the session last lent out
/// (`get_mut`: every change to a session goes through it), each lent session told its room and
/// share; the requests waiting for room, in the order they began to (`admit`).
#[derive(Clone, Debug, Default)]
pub struct Sessions {
    conns: BTreeMap<ConnId, Session>,
    now: Time,
    mono: Mono,
    /// Sessions this step reached: their bytes and deadlines are taken at its end.
    touched: BTreeSet<ConnId>,
    deadlines: BTreeSet<(Mono, ConnId)>,
    deadline: BTreeMap<ConnId, Mono>,
    /// Dials not up yet (their deadline is in `deadlines`).
    dials: BTreeSet<ConnId>,
    /// Held out and received over every session, as counted (`recount`).
    out_total: u64,
    in_total: u64,
    /// The session lent out last, not recounted yet.
    lent: Option<ConnId>,
    /// Sessions with a request waiting for room, in the order they began to wait.
    waiting: VecDeque<ConnId>,
    /// Sessions whose own requests stopped for room.
    starved: BTreeSet<ConnId>,
    /// A waiting request does not fit the bound's room: nothing else goes past it.
    room_blocked: bool,
}

impl Sessions {
    pub fn get(&self, conn: ConnId) -> Option<&Session> {
        self.conns.get(&conn)
    }

    pub fn get_mut(&mut self, conn: ConnId) -> Option<&mut Session> {
        self.recount();
        let (now, mono) = (self.now, self.mono);
        let n = self.conns.len().max(1) as u64;
        let s = self.conns.get_mut(&conn)?;
        self.touched.insert(conn);
        (s.now, s.mono) = (s.now.max(now), s.mono.max(mono));
        s.room = OUT_BOUND.saturating_sub(self.out_total - s.counted.0);
        s.share = OUT_BOUND / n;
        s.blocked = self.room_blocked;
        self.lent = Some(conn);
        Some(s)
    }

    /// The session lent out last counted again: the totals, the waiting order, the starved.
    fn recount(&mut self) {
        let Some(c) = self.lent.take() else { return };
        let Some(s) = self.conns.get_mut(&c) else { return };
        let now = (s.out_held(), s.in_held());
        self.out_total = self.out_total - s.counted.0 + now.0;
        self.in_total = self.in_total - s.counted.1 + now.1;
        s.counted = now;
        let waits = s.held.is_some();
        // one waiting for the bound's room: nothing else goes past it
        if s.held.as_ref().is_some_and(|h| self.out_total.saturating_add(h.allowance) > OUT_BOUND) {
            self.room_blocked = true;
        }
        if waits != self.waiting.contains(&c) {
            match waits {
                true => self.waiting.push_back(c),
                false => self.waiting.retain(|w| *w != c),
            }
        }
        match s.starved {
            true => self.starved.insert(c),
            false => self.starved.remove(&c),
        };
    }

    /// The requests waiting for room that fit now, each handed on with what its connection
    /// reads after it, in the order they began to wait (spec/sync-transport.md §5 Served
    /// connections): one that does not fit the bound's room stops those after it; one past only
    /// its own share (its bytes not taken yet) waits alone. Then own requests stopped for room
    /// go where they fit. Each result as `Session::receive`'s.
    pub fn admit(&mut self, cx: &mut Cx) -> Vec<(ConnId, Result<Vec<Incoming>, Close>)> {
        self.recount();
        self.room_blocked = false;
        let mut out = Vec::new();
        for c in self.waiting.clone() {
            let Some(s) = self.get_mut(c) else { continue };
            s.blocked = false;
            let Some(need) = s.held.as_ref().map(|h| h.allowance) else { continue };
            if s.fits(need) {
                let r = s.receive(&[], cx);
                out.push((c, r));
            } else if s.out_held().saturating_add(need) > s.room {
                self.recount();
                self.room_blocked = true;
                break;
            }
        }
        self.recount();
        for c in self.starved.clone() {
            if let Some(s) = self.get_mut(c) {
                s.pump();
            }
        }
        self.recount();
        out
    }

    /// The connection holding the most received while every connection together holds more
    /// than `IN_BOUND`: to close (spec/sync-transport.md §5 Served connections).
    pub fn over_in(&mut self) -> Option<ConnId> {
        self.recount();
        if self.in_total <= IN_BOUND {
            return None;
        }
        self.conns.iter().max_by_key(|(c, s)| (s.in_held(), std::cmp::Reverse(**c))).map(|(c, _)| *c)
    }

    /// The connections to close for the first request waiting for the bound's room once it has
    /// waited half the stall time (spec/sync-transport.md §5 Served connections): first those
    /// whose bytes the transport took none of while it waited, then the rest, the one holding
    /// the most first in each, until it fits; the waiting one itself among them.
    fn room_closes(&mut self, now: Mono) -> Vec<ConnId> {
        self.recount();
        let Some((c, since, need)) = self.room_wait() else { return Vec::new() };
        if since.after(STALL_TIMEOUT_MS / 2) > now {
            return Vec::new();
        }
        let mut order: Vec<(bool, u64, ConnId)> = self.conns.iter().map(|(k, s)| (s.last_taken > since, s.out_held(), *k)).collect();
        order.sort_by_key(|(took, held, k)| (*took, std::cmp::Reverse(*held), *k));
        let own = self.conns.get(&c).map_or(0, Session::out_held);
        let (mut total, mut n) = (self.out_total, self.conns.len() as u64);
        let mut out = Vec::new();
        for (_, held, k) in order {
            let fits = total + need <= OUT_BOUND && (own + need <= OUT_BOUND / n.max(1) || own == 0);
            if fits {
                break;
            }
            out.push(k);
            if k == c {
                break;
            }
            total -= held;
            n -= 1;
        }
        out
    }

    /// The first waiting request that does not fit the bound's room: its connection, since when
    /// it waits, its allowance.
    fn room_wait(&self) -> Option<(ConnId, Mono, u64)> {
        self.waiting.iter().find_map(|c| {
            let s = self.conns.get(c)?;
            let h = s.held.as_ref()?;
            (self.out_total.saturating_add(h.allowance) > OUT_BOUND).then_some((*c, h.since, h.allowance))
        })
    }

    pub fn conns(&self) -> impl Iterator<Item = ConnId> + '_ {
        self.conns.keys().copied()
    }

    /// The driver's: the step's clocks.
    pub fn set_now(&mut self, now: Time, mono: Mono) {
        (self.now, self.mono) = (self.now.max(now), self.mono.max(mono));
    }

    /// The driver's: a dial started now (`Out::Dial`): it closes as failed unless up within
    /// `DIAL_TIMEOUT_MS`.
    pub fn dialing(&mut self, conn: ConnId) {
        self.dials.insert(conn);
        self.track(conn, Some(self.mono.after(DIAL_TIMEOUT_MS)));
    }

    /// The driver's: a connection up.
    pub fn insert(&mut self, s: Session) {
        let conn = s.conn;
        self.recount();
        self.dials.remove(&conn);
        self.track(conn, None);
        self.conns.insert(conn, s);
        self.touched.insert(conn);
        // counted from nothing as it is lent next
        self.lent = Some(conn);
    }

    /// The driver's: a connection ended, or a dial failed.
    pub fn remove(&mut self, conn: ConnId) -> Option<Session> {
        self.recount();
        self.dials.remove(&conn);
        self.track(conn, None);
        self.touched.remove(&conn);
        self.waiting.retain(|w| *w != conn);
        self.starved.remove(&conn);
        let s = self.conns.remove(&conn)?;
        self.out_total -= s.counted.0;
        self.in_total -= s.counted.1;
        Some(s)
    }

    /// The driver's: the transport took `total` bytes of `conn`'s so far.
    pub fn taken(&mut self, conn: ConnId, total: u64) {
        if let Some(s) = self.get_mut(conn) {
            s.taken(total, s.mono);
        }
    }

    /// The driver's: the connections and dials whose deadline passed by `now`, each to close.
    pub fn tick(&mut self, now: Mono) -> Vec<(ConnId, Close)> {
        self.mono = self.mono.max(now);
        let mut out: Vec<(ConnId, Close)> = self.room_closes(now).into_iter().map(|c| (c, Close("holds the most while a request waits for room"))).collect();
        while let Some((at, conn)) = self.deadlines.first().copied().filter(|(at, _)| *at <= now) {
            self.deadlines.remove(&(at, conn));
            self.deadline.remove(&conn);
            if self.dials.remove(&conn) {
                out.push((conn, Close("dial timed out")));
            } else if let Some(s) = self.conns.get(&conn) {
                match s.deadline() {
                    Some(d) if d <= now => out.push((conn, Close(if s.binding.is_none() { "no hello" } else { "stalled" }))),
                    _ => {
                        self.touched.insert(conn);
                    }
                }
            }
        }
        out
    }

    /// The earliest deadline, a wait for the bound's room's included.
    pub fn next_wake(&self) -> Option<Mono> {
        let room = self.room_wait().map(|(_, since, _)| since.after(STALL_TIMEOUT_MS / 2));
        self.deadlines.first().map(|(at, _)| *at).into_iter().chain(room).min()
    }

    /// The driver's: the sessions this step touched that a module closed (their closes go with
    /// the step's outputs).
    pub(crate) fn closing(&self) -> Vec<ConnId> {
        self.touched.iter().filter(|c| self.conns.get(c).is_some_and(|s| s.closing().is_some())).copied().collect()
    }

    /// The driver's: the bytes of every session the step touched as sends, their deadlines
    /// taken again.
    pub fn take_sends(&mut self, out: &mut Vec<Out>) {
        self.recount();
        #[cfg(debug_assertions)]
        debug_assert_eq!((self.out_total, self.in_total), self.conns.values().fold((0, 0), |(o, i), s| (o + s.out_held(), i + s.in_held())), "the totals held, as counted");
        for c in std::mem::take(&mut self.touched) {
            let Some(s) = self.conns.get_mut(&c) else { continue };
            let bytes = s.take_bytes();
            let d = s.deadline();
            if !bytes.is_empty() {
                out.push(Out::Send(c, bytes));
            }
            // reading stops while a request waits for room, and goes on after it
            if s.reading() != s.told_reading {
                s.told_reading = s.reading();
                out.push(Out::Read(c, s.told_reading));
            }
            self.track(c, d);
        }
    }

    fn track(&mut self, conn: ConnId, at: Option<Mono>) {
        if let Some(old) = self.deadline.remove(&conn) {
            self.deadlines.remove(&(old, conn));
        }
        if let Some(at) = at {
            self.deadline.insert(conn, at);
            self.deadlines.insert((at, conn));
        }
    }
}
