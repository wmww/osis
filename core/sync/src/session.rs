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
//! taken. Depends on osis-proto and the engine's proof calls (`provers`, `own_node_key`,
//! `own_node`, `key_open`, `known_actor`, `account_tid`, `prove_rotations`, `take_rotations`).
//! Not built: closing a connection where this node came to act for an actor it did not prove
//! there (spec/sync-opens.md §1), and the engine's rotations in a Prove (`prove_rotations` and
//! `take_rotations` are not built: none are sent, those received are not taken).

use crate::types::{ConnId, Cx, NodeKey, Out};
use osis_base::{CreationRecord, Tid, WallMs};
use osis_proto::frame::MAX_HELLO_BODY;
use osis_proto::limits::{MAX_ID, MAX_MESSAGE, MAX_PROOFS, MAX_PROVE_ROTATIONS, NO_RECORD_ID, REPLY_BUDGET, SMALL_REPLY, TOP_BIT, WINDOW};
use osis_proto::msg::{Flow, answers, peek_head};
use osis_proto::prove::verified;
use osis_proto::{ActorProof, ClockSamples, Code, FrameDecoder, Hello, Msg, OffsetSample, PROTOCOL_VERSION, Prover, encode_frame, negotiate};
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
    /// Register, Delete, Stranded, Suspect.
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
                34 | 36 | 37 | 38 | 40 | 45 | 46 => Some(To::Opens),
                19 | 41 | 43 | 44 => Some(To::Streams),
                7 | 14 | 30 | 31 => Some(To::Inbox),
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

/// What the peer proved on this connection (spec/sync-opens.md §2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proven {
    /// Its account, proved at an epoch open here then: the account's creation record and the key
    /// it proved with (`Engine::key_open` judges it again).
    pub account: Option<(CreationRecord, [u8; 32])>,
    /// Key actors proved by their own signing keys, with that key (a static entry is checked
    /// against it), known here or not.
    pub key_actors: BTreeMap<Tid, [u8; 32]>,
    /// The peer's node, when it proved its node key and is another node of this node's account.
    pub node: Option<Tid>,
}

impl Proven {
    pub fn account(&self) -> Option<Tid> {
        self.account.as_ref().map(|(r, _)| r.tid())
    }

    /// Every actor proved: the account, the node, the key actors.
    pub fn actors(&self) -> Vec<Tid> {
        self.account().into_iter().chain(self.node).chain(self.key_actors.keys().copied()).collect()
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
    proved: Vec<Tid>,
    now: WallMs,
    up_at: WallMs,
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
    moved: WallMs,
    other: u64,
    /// The peer's requests not answered yet, with their costs.
    unanswered: BTreeMap<RequestId, u64>,
    unanswered_bytes: u64,
    bytes: Vec<u8>,
    /// Why a module closes this connection.
    closing: Option<&'static str>,
    /// Bytes written on the connection so far (handed out or still in `bytes`), and taken by
    /// the transport.
    written: u64,
    taken: u64,
    clock: ClockSamples,
    ping: Option<(RequestId, WallMs)>,
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
            proved: Vec::new(),
            now: cx.now,
            up_at: cx.now,
            next_low: 0,
            next_top: TOP_BIT,
            reqs: BTreeMap::new(),
            waiting: VecDeque::new(),
            order: BTreeMap::new(),
            ordered: VecDeque::new(),
            seq: 0,
            in_flight: 0,
            moved: cx.now,
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
        self.now = cx.now;
        self.frames.push(bytes);
        let mut ins = Vec::new();
        let (mut own, mut other) = (false, 0u64);
        loop {
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
        if let (Some(oldest), Some(part)) = (self.oldest(), self.frames.partial()) {
            own |= peek_head(part).is_some_and(|(kind, id)| id == oldest && osis_proto::msg::flow(kind) == Some(Flow::Reply));
        }
        if own {
            self.moved();
        } else if other > 0 {
            self.other = self.other.saturating_add(other);
            if self.other <= OTHER_BYTES {
                self.moved = self.now;
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
        if let Some(cost) = self.unanswered.remove(&to) {
            self.unanswered_bytes -= cost;
        }
        self.write(m.encode());
    }

    /// Pushes (a Stream, a Notify) while the bytes the transport has not taken on this
    /// connection, the push included, stay within `REPLY_BUDGET`, or none are; `false`: it did
    /// not go, the pusher waits for room (spec/sync-streams.md §2).
    pub fn push(&mut self, m: Msg) -> bool {
        let body = m.encode();
        let u = self.unwritten();
        if u > 0 && u + body.len() as u64 + 4 > REPLY_BUDGET as u64 {
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

    /// The actors this node proved on this connection (its Prove, or its Proved).
    pub fn proved(&self) -> &[Tid] {
        &self.proved
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
    pub fn taken(&mut self, total: u64, now: WallMs) {
        self.now = self.now.max(now);
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
    pub fn deadline(&self) -> Option<WallMs> {
        let from = if self.binding.is_none() {
            self.up_at
        } else if !self.order.is_empty() {
            self.moved
        } else {
            return None;
        };
        Some(WallMs(from.0.saturating_add(STALL_TIMEOUT_MS)))
    }

    fn unwritten(&self) -> u64 {
        self.written - self.taken
    }

    fn oldest(&self) -> Option<RequestId> {
        self.order.first_key_value().map(|(_, id)| *id)
    }

    /// The oldest request out moved by its own events.
    fn moved(&mut self) {
        self.moved = self.now;
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
        let top = matches!(kind, 19 | 36..=41);
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
        while self.in_flight < WINDOW as u64 {
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

    /// The dialer's Prove (spec/sync-opens.md §2 Order): its node key when the key it dialed is
    /// a node of its account by `reach.0`, then its account with the account's rotations, then
    /// its key actors.
    fn prove(&mut self, cx: &mut Cx) -> Result<(), Close> {
        let own = cx.engine.own_node_key(&self.peer.0).map_err(|_| Close("engine"))?;
        let Some(b) = self.binding else { return Ok(()) };
        let proofs = self.signed(cx, own, false, &b.listener_challenge)?;
        let rotations = if proofs.iter().any(|p| p.record.is_account()) {
            // the room the proofs leave, less the list's head (at most 9 bytes)
            let bare = Msg::Prove { id: MAX_ID as RequestId, proofs: proofs.clone(), rotations: Some(Vec::new()) }.encode().len();
            Some(rotations(cx, MAX_MESSAGE.saturating_sub(bare + 9))?)
        } else {
            None
        };
        self.send_request(None, Msg::Prove { id: 0, proofs, rotations });
        Ok(())
    }

    /// This node's proofs over `challenge`, by `by_listener`, in proof order, at most
    /// `MAX_PROOFS`; noted as what it proved here.
    fn signed(&mut self, cx: &mut Cx, own_node: bool, by_listener: bool, challenge: &[u8; 32]) -> Result<Vec<ActorProof>, Close> {
        let provers = cx.engine.provers(own_node).map_err(|_| Close("engine"))?;
        let listener = self.listener_key.0;
        let proofs: Vec<ActorProof> = provers.into_iter().take(MAX_PROOFS).map(|(key, record)| Prover { key, record }.sign(by_listener, challenge, &listener)).collect();
        self.proved = proofs.iter().map(ActorProof::actor).collect();
        Ok(proofs)
    }

    /// What verified proofs show: an account only at an epoch open here; the first proof as the
    /// peer's node only when it is another node of this node's account; every other key actor.
    fn judge(&self, cx: &mut Cx, proofs: Vec<ActorProof>) -> Proven {
        let mut p = Proven::default();
        for (i, a) in proofs.into_iter().enumerate() {
            let t = a.actor();
            if a.record.is_account() {
                if p.account.is_none() && cx.engine.key_open(&a.record, &a.key) {
                    p.account = Some((a.record, a.key));
                }
            } else if i == 0 && cx.engine.own_node(&t) {
                p.node = Some(t);
            } else {
                p.key_actors.insert(t, a.key);
            }
        }
        p
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
        let cost = len + allowance(&m);
        if self.unanswered_bytes + cost > UNANSWERED {
            return Err(Close("too many requests unanswered"));
        }
        self.unanswered.insert(id, cost);
        self.unanswered_bytes += cost;
        match m {
            Msg::Ping { .. } => self.answer(id, Msg::Pong { id, wall_ms: self.now.0 }),
            Msg::Prove { proofs, rotations, .. } => self.proved_to(id, proofs, rotations, cx, ins)?,
            m => ins.push(Incoming::Request(id, m)),
        }
        Ok(())
    }

    /// The dialer's Prove at the listener: its proofs judged, then the listener's own, only if it
    /// proved a known actor (spec/sync-opens.md §2 Order).
    fn proved_to(&mut self, id: RequestId, proofs: Vec<ActorProof>, rotations: Option<Vec<osis_base::Value>>, cx: &mut Cx, ins: &mut Vec<Incoming>) -> Result<(), Close> {
        let Some(b) = self.binding.filter(|_| !self.dialer && self.proofs == Proofs::Proving) else {
            self.answer(id, Msg::Error { id, code: Code::MALFORMED });
            return Ok(());
        };
        if let Some(r) = rotations {
            match cx.engine.take_rotations(r) {
                Ok(()) | Err(osis_engine::Error::NotBuilt(_)) => {}
                Err(_) => return Err(Close("engine")),
            }
        }
        let proven = self.judge(cx, verified(proofs, false, &b.listener_challenge, &b.listener_key));
        let known = proven.node.is_some() || proven.actors().iter().any(|a| cx.engine.known_actor(a));
        let mine = cx.engine.account_tid();
        let own = proven.node.is_some() || (mine.is_some() && proven.account() == mine);
        let proofs = if known { self.signed(cx, own, true, &b.dialer_challenge)? } else { Vec::new() };
        self.proven = proven;
        self.proofs = Proofs::Done;
        self.answer(id, Msg::Proved { id, proofs });
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
            (32, Msg::Proved { proofs, .. }) => {
                let Some(b) = self.binding else { return Ok(()) };
                self.proven = self.judge(cx, verified(proofs, true, &b.dialer_challenge, &b.listener_key));
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
                    self.offset = self.clock.pong(OffsetSample { sent: sent.0, peer: wall_ms, received: self.now.0 }).or(self.offset);
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
        Msg::Fetch { max_reply, .. } | Msg::Call { max_reply, .. } | Msg::Sub { max_reply, .. } => *max_reply,
        Msg::Pull(p) => p.max_reply,
        _ => SMALL_REPLY as u64,
    }
}

/// The account's rotations for a Prove, in the engine's order: as many as fit `room` bytes (what
/// the proofs leave of one message), at most `MAX_PROVE_ROTATIONS` (none while the engine does
/// not build them).
fn rotations(cx: &mut Cx, mut room: usize) -> Result<Vec<osis_base::Value>, Close> {
    let all = match cx.engine.prove_rotations() {
        Ok(r) => r,
        Err(osis_engine::Error::NotBuilt(_)) => Vec::new(),
        Err(_) => return Err(Close("engine")),
    };
    let mut out = Vec::new();
    for r in all.into_iter().take(MAX_PROVE_ROTATIONS) {
        let n = osis_base::cbor::encode(&r).len();
        if n > room {
            break;
        }
        room -= n;
        out.push(r);
    }
    Ok(out)
}

/// Every connection's session: the driver owns it; a module that sends takes it `&mut` and sends
/// through `request`, `answer` and `push` of the connection it acts on. What a module sends
/// leaves at the end of the step (`take_sends`). Also the deadlines: each session's (the stall
/// clock, the peer's Hello) and each dial's not up yet; work per step is in proportion to the
/// sessions the step touched.
#[derive(Clone, Debug, Default)]
pub struct Sessions {
    conns: BTreeMap<ConnId, Session>,
    now: WallMs,
    /// Sessions this step reached: their bytes and deadlines are taken at its end.
    touched: BTreeSet<ConnId>,
    deadlines: BTreeSet<(WallMs, ConnId)>,
    deadline: BTreeMap<ConnId, WallMs>,
    /// Dials not up yet (their deadline is in `deadlines`).
    dials: BTreeSet<ConnId>,
}

impl Sessions {
    pub fn get(&self, conn: ConnId) -> Option<&Session> {
        self.conns.get(&conn)
    }

    pub fn get_mut(&mut self, conn: ConnId) -> Option<&mut Session> {
        let now = self.now;
        let s = self.conns.get_mut(&conn)?;
        self.touched.insert(conn);
        s.now = s.now.max(now);
        Some(s)
    }

    pub fn conns(&self) -> impl Iterator<Item = ConnId> + '_ {
        self.conns.keys().copied()
    }

    /// The driver's: the step's time.
    pub fn set_now(&mut self, now: WallMs) {
        self.now = self.now.max(now);
    }

    /// The driver's: a dial started now (`Out::Dial`): it closes as failed unless up within
    /// `DIAL_TIMEOUT_MS`.
    pub fn dialing(&mut self, conn: ConnId) {
        self.dials.insert(conn);
        self.track(conn, Some(WallMs(self.now.0.saturating_add(DIAL_TIMEOUT_MS))));
    }

    /// The driver's: a connection up.
    pub(crate) fn insert(&mut self, s: Session) {
        let conn = s.conn;
        self.dials.remove(&conn);
        self.track(conn, None);
        self.conns.insert(conn, s);
        self.touched.insert(conn);
    }

    /// The driver's: a connection ended, or a dial failed.
    pub(crate) fn remove(&mut self, conn: ConnId) -> Option<Session> {
        self.dials.remove(&conn);
        self.track(conn, None);
        self.touched.remove(&conn);
        self.conns.remove(&conn)
    }

    /// The driver's: the transport took `total` bytes of `conn`'s so far.
    pub(crate) fn taken(&mut self, conn: ConnId, total: u64) {
        if let Some(s) = self.get_mut(conn) {
            s.taken(total, s.now);
        }
    }

    /// The driver's: the connections and dials whose deadline passed by `now`, each to close.
    pub fn tick(&mut self, now: WallMs) -> Vec<(ConnId, Close)> {
        self.set_now(now);
        let mut out = Vec::new();
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

    /// No request outstanding and no Hello awaited on any connection, no dial waiting
    /// (spec/sync-status.md §3 idle): exactly when no deadline is kept. As of the last step's end.
    pub fn idle(&self) -> bool {
        self.deadlines.is_empty()
    }

    /// The earliest deadline.
    pub fn next_wake(&self) -> Option<WallMs> {
        self.deadlines.first().map(|(at, _)| *at)
    }

    /// The driver's: the sessions this step touched that a module closed (their closes go with
    /// the step's outputs).
    pub(crate) fn closing(&self) -> Vec<ConnId> {
        self.touched.iter().filter(|c| self.conns.get(c).is_some_and(|s| s.closing().is_some())).copied().collect()
    }

    /// The driver's: the bytes of every session the step touched as sends, their deadlines
    /// taken again.
    pub(crate) fn take_sends(&mut self, out: &mut Vec<Out>) {
        for c in std::mem::take(&mut self.touched) {
            let Some(s) = self.conns.get_mut(&c) else { continue };
            let bytes = s.take_bytes();
            let d = s.deadline();
            if !bytes.is_empty() {
                out.push(Out::Send(c, bytes));
            }
            self.track(c, d);
        }
    }

    fn track(&mut self, conn: ConnId, at: Option<WallMs>) {
        if let Some(old) = self.deadline.remove(&conn) {
            self.deadlines.remove(&(old, conn));
        }
        if let Some(at) = at {
            self.deadline.insert(conn, at);
            self.deadlines.insert((at, conn));
        }
    }
}
