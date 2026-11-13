//! One connection, whichever side dialed it (spec/sync.md §4-§10, spec/wire.md §11): a sans-I/O
//! state machine answering the store's requests (Ping, Register, Delete) from a `LabelStore`,
//! handing node-kind messages and client-port requests to the upper layer, and sending the upper
//! layer's requests within the request window (`window`), each answer to one of them handed back
//! up. It sends no request of its own; the upper layer picks every id (spec/wire.md §11.2). The
//! driver feeds stream bytes and carries out the outputs.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame, send};
use crate::hello::{Hello, PROTOCOL_VERSION, negotiate};
use crate::msg::*;
use crate::relay::RelayVerdict;
use crate::store::{HeadKeys, LabelStore, Put, StepKey, StoreError};
use osis_base::format::MAX_MESSAGE;
use osis_base::{BlobId, LabelId};
use osis_crypto::{Domain, LabelRole, verify_delete};
use osis_label::auth::delete_digest;
use osis_label::{Class, Prefix, entry_digest, host_prefix, key_for_levels};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

/// Room left in a reply for everything but its events or items.
pub const REPLY_BUDGET: usize = MAX_MESSAGE - 64 * 1024;
/// Room in a reply for its head, and for one event without bytes on a page that must not be empty.
const REPLY_HEAD: usize = 1024;
/// Bytes of events or items a reply under `max_reply` may hold.
pub fn reply_bound(max_reply: u64) -> usize {
    usize::try_from(max_reply).unwrap_or(usize::MAX).min(REPLY_BUDGET).saturating_sub(REPLY_HEAD)
}
/// Labels whose head keys a connection caches (cleared when full). Performance switch: a peer
/// cycling past it makes the connection reload them (two store reads beyond the head lookup every
/// message makes, and up to 33 key parses); 0 reloads per message, infinity grows with the labels
/// a peer names, opened or not. An entry is about 7 KB (parsed keys), so about 450 KB per
/// connection, the scale of `MAX_CROSSED`.
const MAX_CACHED: usize = 64;
/// Unwritten push bytes a connection can hold (spec/sync.md §6): pushes go while the unwritten
/// bytes, the push included, fit `REPLY_BUDGET` or none are unwritten, so at most one push frame.
pub const PUSH_QUEUE: usize = MAX_MESSAGE + 4;
/// Bytes a peer can have unwritten to a compliant subscriber: its windowed replies plus the
/// pushes it holds. A send queue cap at or above it never closes such a connection.
pub const SEND_QUEUE: usize = crate::window::WINDOW_QUEUE + PUSH_QUEUE;
/// How often a driver reports `SessionInput::Taken` while a connection holds pushes back
/// (`Session::held`; ms). Minor consequence: pushes resume up to this late after the
/// queue has room; 0 spins the driver while a slow subscriber drains, infinity leaves them to
/// the next unrelated tick.
pub const PUSH_POLL_MS: u64 = 1000;

#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The listener's static key: this side's when it accepted the connection, the key dialed
    /// when it dialed (bound by open signatures and connection proofs).
    pub listener_key: [u8; 32],
    /// This side's Hello challenge: 32 random bytes per connection.
    pub challenge: [u8; 32],
    /// This side dialed the connection.
    pub dialed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionInput {
    /// The connection is up: send Hello.
    Start,
    /// Bytes received on the stream.
    Bytes(Vec<u8>),
    /// The transport has taken this many bytes of this connection's output so far (cumulative):
    /// pushes wait while too much is unwritten (spec/sync.md §6). A driver that never reports it
    /// delivers instantly (no push is held back); one that does reports it before input bytes,
    /// at ticks, and every `PUSH_POLL_MS` while `held`.
    Taken(u64),
    /// The answer to a client-port request handed out as `SessionOutput::Request` (Auth, Call,
    /// Sub): a Reply, or an Error with this code (Auth refused: 1). A reply above the request's
    /// `max_reply` goes as `TooLarge`.
    Reply { id: Id, reply: Result<crate::api::Outcome, Code> },
    /// Notify pushes, sent in order (as many as the last `SessionOutput::Room` allowed); one for
    /// a subscription no longer live is dropped, one above its `max_reply` goes as `Lapsed`.
    /// Each ends the grant: none gives it back.
    Notify(Vec<(Id, crate::api::Payload)>),
    /// A message of the upper layer's to send: a request (its id the upper layer's) within the
    /// request window (spec/sync.md §6), sent once it fits; an answer to a request handed up frees
    /// its charge; a relay-only push (a Stream without cursor) without room is dropped.
    Peer(Box<Message>),
    /// The upper layer has Notifies to send: `SessionOutput::Room` when the push rule allows.
    WantRoom,
    /// The node's room for this connection grew (`Session::set_room`): held requests,
    /// pushes and room go on as at a `Taken`.
    Resume,
    /// Node sync opened the label here by a sync-key or static-entry Hit: Deletes of it are
    /// taken while the head bears the sync key it has now (spec/sync.md §5).
    Open(LabelId),
    /// Node sync's open of the label here ended.
    Shut(LabelId),
}

/// A request's charge against `MAX_UNANSWERED`: its bytes framed and its reply allowance.
#[derive(Clone, Copy, Debug, Default)]
struct Charge {
    frame: usize,
    allowance: usize,
}

impl Charge {
    fn total(self) -> usize {
        self.frame.saturating_add(self.allowance)
    }

    fn add(&mut self, c: Charge) {
        self.frame = self.frame.saturating_add(c.frame);
        self.allowance = self.allowance.saturating_add(c.allowance);
    }

    fn sub(&mut self, c: Charge) {
        self.frame = self.frame.saturating_sub(c.frame);
        self.allowance = self.allowance.saturating_sub(c.allowance);
    }
}

/// A frame received and not yet run (`Session::admit`).
#[derive(Clone, Debug)]
struct Pending {
    msg: Result<Message, crate::msg::Rejected>,
    frame: usize,
    allowance: usize,
}

impl Pending {
    /// The room it needs to run: its reply allowance (an Error for a frame that does not
    /// decode).
    fn need(&self) -> usize {
        if self.msg.is_err() { crate::window::SMALL_REPLY } else { self.allowance }
    }
}

/// Bytes of the `Send` outputs in `out`.
fn sent_bytes(out: &[SessionOutput]) -> u64 {
    out.iter().map(|o| if let SessionOutput::Send(b) = o { b.len() as u64 } else { 0 }).sum()
}

/// A relay-only entry (spec/sync.md §5): accepted by stamp, passed on to the label's other
/// holders by node sync's stream, held by nobody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relayed {
    pub label: LabelId,
    pub blob_id: BlobId,
    /// Shared by every connection it goes to.
    pub blob: Arc<[u8]>,
    pub wrap: Wrap,
    pub stamp: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionOutput {
    /// A frame to write.
    Send(Vec<u8>),
    Close,
    /// The peer broke a protocol rule (diagnostic).
    PeerError(Error),
    StoreError(StoreError),
    /// A client-port request (Auth, Call, Sub) to answer by `SessionInput::Reply`; an Unsub
    /// (already answered: drop the subscription).
    Request(Box<Message>),
    /// For the upper layer: a node-kind message (`Message::for_node`: the shared set's, the
    /// stream's, Prove, Resume, Stranded, Suspect), which it answers by `SessionInput::Peer` (a
    /// request keeps its frame and reply allowance against `MAX_UNANSWERED` until answered); every
    /// answer to one of its own requests (a reply kind whose id the window knows); a Notify.
    Peer(Box<Message>),
    /// Notifies of up to `budget` bytes may go now (after `SessionInput::WantRoom`).
    Room { budget: usize },
}

fn key_of_role(r: LabelRole) -> StepKey {
    match r {
        LabelRole::Sync => StepKey::Sync,
        LabelRole::Write => StepKey::Write,
        LabelRole::Delete => StepKey::Delete,
    }
}

/// OK under the head's key, NOT_HEAD under a recent earlier one, else REFUSED. `struck`: a
/// signature of this message already verified under no key; then only the head's key is tried
/// (spec/wire.md §11.2), so a message of bogus signatures costs one verification per signature,
/// as an honest one does, not one per kept key.
fn check(k: &HeadKeys, key: StepKey, domain: Domain, digest: &[u8; 32], sig: &Signature, struck: &mut bool) -> Code {
    if key.of(&k.head).verify(domain, digest, sig).is_ok() {
        return Code::OK;
    }
    if !*struck && k.older.get(key as usize).is_some_and(|ks| ks.iter().any(|pk| pk.verify(domain, digest, sig).is_ok())) {
        return Code::NOT_HEAD;
    }
    *struck = true;
    Code::REFUSED
}
/// `check` of an entry's stamp or deposit signature (`plain`: `Stamp` or `Deposit`), or of one
/// under `RoleEntry` (spec/sync.md §5): its code, and whether it verified as a role entry.
fn check_entry(k: &HeadKeys, key: StepKey, plain: Domain, digest: &[u8; 32], sig: &Signature, struck: &mut bool) -> (Code, bool) {
    let mut first = *struck;
    let code = check(k, key, plain, digest, sig, &mut first);
    if code != Code::REFUSED {
        *struck = first;
        return (code, false);
    }
    let code = check(k, key, Domain::RoleEntry, digest, sig, struck);
    (code, code == Code::OK)
}

#[derive(Clone)]

pub struct Session {
    cfg: SessionConfig,
    decoder: FrameDecoder,
    version: Option<u64>,
    closed: bool,
    /// Labels node sync opened here by a sync-key or static-entry Hit (`SessionInput::Open`), by
    /// the sync key of the head then (spec/sync.md §5): a head with another sync key ends it
    /// (`still_open`). A Delete is taken only for one of them.
    opened: BTreeMap<LabelId, osis_crypto::VerifyingKey>,
    /// Head keys per label, as of its head (`MAX_CACHED`).
    keys: HashMap<LabelId, HeadKeys>,
    /// A signature of the message being handled verified under no key (`check`).
    struck: bool,
    /// The peer's Hello challenge (`binding`).
    peer_challenge: Option<[u8; 32]>,
    /// Bytes of `Send` outputs so far.
    written: u64,
    /// The last `SessionInput::Taken` (none: never reported, no flow control).
    taken: Option<u64>,
    /// Client-port requests handed out and not answered: their kind (24 Auth, 25 Call, 27 Sub),
    /// reply bound and charge.
    asked: BTreeMap<Id, (u64, usize, Charge)>,
    /// Node-kind requests handed up (`SessionOutput::Peer`) and not answered: their charge.
    node_asked: BTreeMap<Id, Charge>,
    /// The charges in `asked` and `node_asked`: counted against `MAX_UNANSWERED` by every input
    /// until answered; their frames are input held (`buffered`), their allowances output
    /// reserved (`holding`).
    asked_bytes: Charge,
    /// Live subscriptions by id (reserved from their Sub until Unsub or a lapse) with their
    /// `max_reply`.
    api_subs: BTreeMap<Id, usize>,
    /// An Auth was answered by a Reply.
    authed: bool,
    /// The upper layer waits for push room (`WantRoom`).
    room_wanted: bool,
    /// This connection's share of the node's output bound, the node's bytes left for it beyond
    /// what it held then, and that holding (`set_room`; unmetered: `usize::MAX`).
    share: usize,
    slack: usize,
    base: usize,
    /// Frames received and not yet run, in order: from the first request whose reply allowance
    /// did not fit the room (`fits`) on. No input comes while any wait (`takes_input`).
    pending: VecDeque<Pending>,
    /// What the last own request held back for room needs (`need`).
    flush_need: Option<usize>,
    /// The push room last granted (`SessionOutput::Room`), reserved until the upper layer's
    /// pushes (or an empty `Notify`, giving it back) arrive.
    granted: usize,
    /// The upper layer's requests (`SessionInput::Peer`), within the request window.
    requests: crate::window::Window,
}

/// The label's head keys, reloaded when the head changed (a store read, never the path); none
/// for an unknown label.
fn head_keys<'a>(keys: &'a mut HashMap<LabelId, HeadKeys>, store: &dyn LabelStore, label: &LabelId) -> Result<Option<&'a HeadKeys>, StoreError> {
    let Some(head) = store.head(label)? else {
        keys.remove(label);
        return Ok(None);
    };
    if keys.get(label).is_none_or(|k| k.head.id() != head) {
        if keys.len() >= MAX_CACHED {
            keys.clear();
        }
        let Some(k) = store.head_keys(label)? else { return Ok(None) };
        keys.insert(*label, k);
    }
    Ok(keys.get(label))
}

impl Session {
    pub fn new(cfg: SessionConfig) -> Session {
        Session {
            cfg,
            decoder: FrameDecoder::new(),
            version: None,
            closed: false,
            opened: BTreeMap::new(),
            keys: HashMap::new(),
            struck: false,
            peer_challenge: None,
            written: 0,
            taken: None,
            asked: BTreeMap::new(),
            node_asked: BTreeMap::new(),
            asked_bytes: Charge::default(),
            api_subs: BTreeMap::new(),
            authed: false,
            room_wanted: false,
            share: usize::MAX,
            slack: usize::MAX,
            base: 0,
            pending: VecDeque::new(),
            flush_need: None,
            granted: 0,
            requests: crate::window::Window::default(),
        }
    }

    /// The node's room for this connection's output (spec/sync.md §10 Served connections): its
    /// `share` of the node's bound, and the bytes the node has left beyond what the connection
    /// holds now (`holding`). A reply, push or own request goes only within both: within the
    /// share (or alone, when the connection holds nothing) and within what is left. Otherwise it
    /// waits, in order: requests are taken but run once their reply allowance fits, so the
    /// output never passes the node's bound; `need` tells what the first waiting one needs.
    pub fn set_room(&mut self, share: usize, slack: usize) {
        self.share = share;
        self.slack = slack;
        self.base = self.holding(&[]);
    }

    /// What the connection holds against the node's bound: its own output (`own`), and the
    /// reply allowances of requests handed up and not answered.
    pub fn holding(&self, out: &[SessionOutput]) -> usize {
        self.own(out).saturating_add(self.asked_bytes.allowance)
    }

    /// Its output: bytes written and not taken, and push room granted and not used.
    fn own(&self, out: &[SessionOutput]) -> usize {
        self.unsent(out).saturating_add(self.granted)
    }

    /// Whether it has no output of its own (`holding` aside from reservations for replies to
    /// come): then one reply or push may go past its share, within what the node has left.
    pub fn alone(&self) -> bool {
        self.own(&[]) == 0
    }

    /// Whether input may come: no received frame waits for room.
    pub fn takes_input(&self) -> bool {
        self.pending.is_empty()
    }

    /// The room the first thing waiting for it needs: a frame's reply allowance, an own
    /// request's frame, a push; none while nothing waits for room.
    pub fn need(&self) -> Option<usize> {
        if let Some(p) = self.pending.front() {
            return Some(p.need());
        }
        self.flush_need.or_else(|| self.held().then_some(crate::window::SMALL_REPLY))
    }

    /// The node's bytes left for this connection, with `out` written.
    fn left(&self, out: &[SessionOutput]) -> usize {
        self.slack.saturating_sub(self.holding(out).saturating_sub(self.base))
    }

    /// Whether `size` more bytes of output fit the room: the share (or no output of its own:
    /// a reservation for a reply to come is not held against what answers it) and what is left.
    fn fits(&self, out: &[SessionOutput], size: usize) -> bool {
        (self.own(out) == 0 || self.holding(out).saturating_add(size) <= self.share) && size <= self.left(out)
    }

    /// Whether an Auth was answered by a Reply (notes/client-port.md §3): the session counts as
    /// opened and is exempt from the idle timeout.
    pub fn authed(&self) -> bool {
        self.authed
    }

    /// Live subscriptions (client port).
    pub fn subs(&self) -> usize {
        self.api_subs.len()
    }

    /// Whose challenges and static key this connection binds: `(dialer challenge, listener
    /// challenge, listener key)`, whichever side dialed, once the peer's Hello arrived.
    pub fn binding(&self) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        let p = self.peer_challenge?;
        let (mine, key) = (self.cfg.challenge, self.cfg.listener_key);
        Some(if self.cfg.dialed { (mine, p, key) } else { (p, mine, key) })
    }

    /// Labels node sync opened on this connection (an open a new head ended stays listed until a
    /// Delete of the label finds it ended).
    pub fn opened(&self) -> impl Iterator<Item = &LabelId> {
        self.opened.keys()
    }

    /// Whether `label` is opened and its open holds at the head: under the head's sync key
    /// (spec/sync.md §5).
    fn holds(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<bool, StoreError> {
        Ok(match self.opened.get(label).copied() {
            None => false,
            Some(k) => self.keys(store, label)?.is_some_and(|h| h.head.keys.sync == k),
        })
    }

    /// `holds`, ending an open that no longer does (spec/sync.md §5).
    fn still_open(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<bool, StoreError> {
        if self.holds(store, label)? {
            return Ok(true);
        }
        self.end_open(label);
        Ok(false)
    }

    fn end_open(&mut self, label: &LabelId) {
        self.opened.remove(label);
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The negotiated protocol version: none until the peer's Hello arrived.
    pub fn version(&self) -> Option<u64> {
        self.version
    }

    /// Whether the upper layer's push room waits for the transport to take bytes
    /// (`SessionInput::Taken`).
    pub fn held(&self) -> bool {
        self.room_wanted
    }

    /// Push room for Notifies: what fits `REPLY_BUDGET` behind the unwritten bytes (all of it
    /// when none are unwritten) and the node's room (`fits`); none below `SMALL_REPLY`.
    fn room(&self, out: &[SessionOutput]) -> Option<usize> {
        let r = match self.backlog(out) {
            0 => REPLY_BUDGET,
            b => REPLY_BUDGET.saturating_sub(b),
        };
        // the share against the connection's own output only: a request waiting for these
        // pushes (a client-port settle) does not hold back the room that answers it
        let o = self.own(out);
        let share = if o == 0 { usize::MAX } else { self.share.saturating_sub(o) };
        Some(r.min(share).min(self.left(out))).filter(|r| *r >= crate::window::SMALL_REPLY)
    }

    /// Bytes written and not taken by the transport, with those in `out` (0 without reports).
    fn backlog(&self, out: &[SessionOutput]) -> usize {
        let Some(t) = self.taken else { return 0 };
        let o: usize = out.iter().map(|x| if let SessionOutput::Send(b) = x { b.len() } else { 0 }).sum();
        usize::try_from(self.written.saturating_sub(t)).unwrap_or(usize::MAX).saturating_add(o)
    }

    /// Bytes written and not taken (as far as reported), with those in `out`.
    fn unsent(&self, out: &[SessionOutput]) -> usize {
        let o: usize = out.iter().map(|x| if let SessionOutput::Send(b) = x { b.len() } else { 0 }).sum();
        let w = self.taken.map_or(0, |t| usize::try_from(self.written.saturating_sub(t)).unwrap_or(usize::MAX));
        w.saturating_add(o)
    }

    /// Whether a push of about `size` bytes waits: something is unwritten and it would not fit
    /// `REPLY_BUDGET` behind it, or it does not fit the node's room.
    fn no_room(&self, out: &[SessionOutput], size: usize) -> bool {
        let b = self.backlog(out);
        b > 0 && b.saturating_add(size) > REPLY_BUDGET || !self.fits(out, size)
    }

    /// When this side's oldest request stalls (`window::STALL_TIMEOUT_MS`, the requester's rule
    /// whichever side dialed): the driver closes the connection then. None while none is out.
    pub fn stall_at(&self) -> Option<u64> {
        self.requests.stall_at()
    }

    /// Bytes received and held: a partial frame, frames waiting to run (`pending`) and those
    /// of requests handed up and not answered.
    pub fn buffered(&self) -> usize {
        self.pending.iter().fold(self.decoder.pending().saturating_add(self.asked_bytes.frame), |b, p| b.saturating_add(p.frame))
    }

    /// Bytes written and not taken by the transport, as far as reported (`SessionInput::Taken`;
    /// none before the first report).
    pub fn unread(&self) -> usize {
        self.unsent(&[])
    }

    pub fn handle(&mut self, now: u64, store: &mut dyn LabelStore, input: SessionInput) -> Vec<SessionOutput> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        self.input(now, store, input, &mut out);
        self.run_pending(now, store, &mut out);
        if !self.closed {
            // the node's own requests go within the room too
            let before = self.written.saturating_add(sent_bytes(&out));
            let (h, o, left, share) = (self.holding(&out), self.own(&out), self.left(&out), self.share);
            let mut extra = 0usize;
            let mut sends = Vec::new();
            self.flush_need = self.requests.flush_while(
                before,
                now,
                |len| {
                    let ok = (o + extra == 0 || h + extra + len <= share) && extra + len <= left;
                    if ok {
                        extra += len;
                    }
                    ok
                },
                |f| sends.push(SessionOutput::Send(f)),
            );
            out.extend(sends);
        }
        self.written = self.written.saturating_add(sent_bytes(&out));
        out
    }

    fn input(&mut self, now: u64, store: &mut dyn LabelStore, input: SessionInput, out: &mut Vec<SessionOutput>) {
        match input {
            SessionInput::Peer(m) if m.is_request() => self.requests.queue(*m),
            // a relay-only push (no cursor) without room is dropped, as the session's own relays
            SessionInput::Peer(m) if matches!(&*m, Message::Stream(s) if s.cursor.is_none() && self.no_room(out, s.events.iter().map(|(_, e)| event_size(e)).sum())) => {}
            SessionInput::Peer(m) => {
                // the stream's push spends the room granted
                if matches!(&*m, Message::Stream(s) if s.cursor.is_some()) {
                    self.granted = 0;
                }
                if crate::msg::is_reply_kind(m.kind())
                    && let Some(c) = self.node_asked.remove(&m.id())
                {
                    self.asked_bytes.sub(c);
                }
                send(out, *m)
            }
            SessionInput::Start => out.push(SessionOutput::Send(encode_frame(&Hello::new(now, self.cfg.challenge).encode()))),
            SessionInput::Bytes(b) => {
                self.decoder.push(&b);
                // frame bytes plus reply allowances of the requests received and not run, all
                // unanswered when the last was sent, and of those handed out earlier and still
                // unanswered (`MAX_UNANSWERED`)
                let mut charged = self.pending.iter().fold(self.asked_bytes.total(), |c, p| c.saturating_add(p.frame).saturating_add(p.allowance));
                while !self.closed {
                    // before the peer's Hello only a Hello-sized frame is taken (spec/wire.md §11.1)
                    self.decoder.set_max(if self.version.is_some() { osis_base::format::MAX_MESSAGE } else { crate::frame::MAX_HELLO_BYTES });
                    match self.decoder.next_frame() {
                        Ok(Some(body)) => {
                            self.requests.frame_in(&body, now);
                            self.admit(&body, &mut charged, out);
                        }
                        Ok(None) => break,
                        Err(e) => {
                            out.push(SessionOutput::PeerError(e));
                            send(out, Message::Error { id: 0, code: Code::MALFORMED });
                            self.close(out);
                        }
                    }
                }
                self.requests.tail_in(self.decoder.partial(), self.decoder.pending(), now);
            }
            SessionInput::Taken(n) => {
                self.taken = Some(self.taken.map_or(n, |t| t.max(n)));
                self.requests.taken(n, now);
                self.resume(out);
            }
            SessionInput::Resume => {
                self.run_pending(now, store, out);
                self.resume(out);
            }
            SessionInput::WantRoom => match self.room(out) {
                Some(budget) => self.grant(budget, out),
                None => self.room_wanted = true,
            },
            SessionInput::Reply { id, reply } => self.api_reply(id, reply, out),
            SessionInput::Open(l) => match self.head(store, &l) {
                Ok(Some(h)) => {
                    self.opened.insert(l, h.keys.sync);
                }
                Ok(None) => self.end_open(&l),
                Err(e) => out.push(SessionOutput::StoreError(e)),
            },
            SessionInput::Shut(l) => self.end_open(&l),
            SessionInput::Notify(notes) => {
                // spends the room granted, or gives it back (none)
                self.granted = 0;
                self.notify(notes, out)
            }
        }
    }

    /// Held pushes go on, labels in turn, then the room the upper layer waits for.
    fn resume(&mut self, out: &mut Vec<SessionOutput>) {
        if self.room_wanted
            && let Some(budget) = self.room(out)
        {
            self.room_wanted = false;
            self.grant(budget, out);
        }
    }

    /// Grants the upper layer push room, reserved until its pushes or an empty `Notify` come.
    fn grant(&mut self, budget: usize, out: &mut Vec<SessionOutput>) {
        self.granted = budget;
        out.push(SessionOutput::Room { budget });
    }

    /// Notify pushes, in order, within the room last granted.
    fn notify(&mut self, notes: Vec<(Id, crate::api::Payload)>, out: &mut Vec<SessionOutput>) {
        for (sub, payload) in notes {
            let Some(max) = self.api_subs.get(&sub).copied() else { continue };
            let mut m = Message::Notify { sub, payload };
            let mut body = m.encode();
            if body.len() > max {
                m = Message::Notify { sub, payload: crate::api::Payload::Lapsed };
                body = m.encode();
            }
            if matches!(m, Message::Notify { payload: crate::api::Payload::Lapsed, .. }) {
                self.api_subs.remove(&sub);
            }
            out.push(SessionOutput::Send(encode_frame(&body)));
        }
    }

    /// Answers a client-port request: the reply bounded by its `max_reply`; a refused or failed
    /// Sub frees its id; a Reply to Auth authenticates the session.
    fn api_reply(&mut self, id: Id, reply: Result<crate::api::Outcome, Code>, out: &mut Vec<SessionOutput>) {
        let Some((kind, max, charge)) = self.asked.remove(&id) else { return };
        self.asked_bytes.sub(charge);
        let ok = matches!(reply, Ok(crate::api::Outcome::Ok { .. }));
        if kind == 27 && !ok {
            self.api_subs.remove(&id);
        }
        match reply {
            Err(code) => send(out, Message::Error { id, code }),
            Ok(outcome) => {
                if kind == 24 && ok {
                    self.authed = true;
                }
                let mut body = Message::Reply { id, outcome }.encode();
                if body.len() > max {
                    if kind == 27 {
                        self.api_subs.remove(&id);
                    }
                    body = Message::Reply { id, outcome: crate::api::Outcome::too_large(max) }.encode();
                }
                out.push(SessionOutput::Send(encode_frame(&body)));
            }
        }
    }

    fn close(&mut self, out: &mut Vec<SessionOutput>) {
        self.closed = true;
        out.push(SessionOutput::Close);
    }

    /// Takes a received frame: the peer's Hello at once; any other decoded and charged
    /// (`MAX_UNANSWERED`), to run in order once its reply allowance fits the room
    /// (`run_pending`).
    fn admit(&mut self, body: &[u8], charged: &mut usize, out: &mut Vec<SessionOutput>) {
        if self.version.is_none() {
            match Hello::decode(body).and_then(|h| negotiate(&[PROTOCOL_VERSION], &h.versions).map(|v| (v, h.challenge))) {
                Ok((v, challenge)) => {
                    self.version = Some(v);
                    self.peer_challenge = Some(challenge);
                }
                Err(e) => {
                    out.push(SessionOutput::PeerError(e));
                    self.close(out);
                }
            }
            return;
        }
        let frame = body.len().saturating_add(4);
        *charged = charged.saturating_add(frame);
        let msg = Message::decode(body);
        // a peer within its window (spec/sync.md §6) never sends more before any is answered:
        // one that does is closed before the request runs, so one input costs at most a few
        // requests' reads (a Reconcile reads its ranges' live IDs: up to the whole label), and
        // the requests waiting for room stay within its window
        let allowance = msg.as_ref().map_or(0, crate::window::allowance);
        *charged = charged.saturating_add(allowance);
        if *charged > crate::window::MAX_UNANSWERED {
            out.push(SessionOutput::PeerError(Error::Cap("requests past the request window")));
            self.close(out);
            return;
        }
        self.pending.push_back(Pending { msg, frame, allowance });
    }

    /// Runs the frames waiting, in order, while each one's reply fits the room (`fits`).
    fn run_pending(&mut self, now: u64, store: &mut dyn LabelStore, out: &mut Vec<SessionOutput>) {
        while let Some(p) = self.pending.front() {
            if self.closed {
                self.pending.clear();
                return;
            }
            let need = p.need();
            if need > 0 && !self.fits(out, need) {
                return;
            }
            let Some(p) = self.pending.pop_front() else { return };
            self.run(now, store, p, out);
            // a peer within its window (spec/sync.md §6) never has more replies unwritten: one
            // that pipelines past it is closed here, before its further requests cost reads and
            // memory, not after (the driver's queue cap sees only what this input made). The
            // node's own requests unanswered may be unwritten too (an answered one was
            // delivered).
            if self.unsent(out) > SEND_QUEUE.saturating_add(self.requests.in_flight()) {
                out.push(SessionOutput::PeerError(Error::Cap("replies past the request window")));
                self.close(out);
            }
        }
    }

    fn run(&mut self, now: u64, store: &mut dyn LabelStore, p: Pending, out: &mut Vec<SessionOutput>) {
        let msg = match p.msg {
            Ok(m) => m,
            Err(r) => {
                // a request (or unknown kind) is answered; a broken reply or push is dropped
                if r.wants_answer() {
                    send(out, Message::Error { id: r.id, code: r.code() });
                }
                out.push(SessionOutput::PeerError(r.error));
                return;
            }
        };
        let id = msg.id();
        let charge = Charge { frame: p.frame, allowance: p.allowance };
        if matches!(msg, Message::Auth { .. } | Message::Call { .. } | Message::Sub { .. } | Message::Unsub { .. }) {
            if let Some(reply) = self.api_request(msg, charge, out) {
                send(out, reply);
            }
            return;
        }
        self.struck = false;
        match self.dispatch(now, store, msg, charge, out) {
            Ok(Some(reply)) => send(out, reply),
            Ok(None) => {}
            Err(e) => {
                out.push(SessionOutput::StoreError(e));
                send(out, Message::Error { id, code: Code::REFUSED });
            }
        }
    }

    fn keys(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<Option<&HeadKeys>, StoreError> {
        head_keys(&mut self.keys, store, label)
    }

    fn head(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<Option<Step>, StoreError> {
        Ok(self.keys(store, label)?.map(|k| k.head.clone()))
    }

    /// `charge`: the request's frame bytes plus reply allowance (a node request handed up keeps it
    /// against `MAX_UNANSWERED` until the upper layer answers).
    fn dispatch(&mut self, now: u64, store: &mut dyn LabelStore, msg: Message, charge: Charge, out: &mut Vec<SessionOutput>) -> Result<Option<Message>, StoreError> {
        use Message as M;
        // an answer goes up to the request it answers; one to nothing breaks the protocol
        if crate::msg::is_reply_kind(msg.kind()) {
            if self.requests.answered(msg.id(), now) {
                out.push(SessionOutput::Peer(Box::new(msg)));
            } else {
                out.push(SessionOutput::PeerError(Error::Malformed("reply to no request")));
            }
            return Ok(None);
        }
        if msg.for_node() || matches!(msg, M::Notify { .. }) {
            if msg.is_request() {
                let std::collections::btree_map::Entry::Vacant(e) = self.node_asked.entry(msg.id()) else {
                    return Ok(Some(M::Error { id: msg.id(), code: Code::MALFORMED }));
                };
                e.insert(charge);
                self.asked_bytes.add(charge);
            }
            out.push(SessionOutput::Peer(Box::new(msg)));
            return Ok(None);
        }
        Ok(Some(match msg {
            M::Ping { id, .. } => M::Pong { id, wall_ms: now },
            M::Register { id, label, step, claim_set } => self.register(store, id, label, step, claim_set)?,
            M::Delete { id, label, .. } if !self.still_open(store, &label)? => M::Error { id, code: Code::NOT_OPENED },
            M::Delete { id, label, items } => {
                let mut codes = Vec::with_capacity(items.len());
                for item in &items {
                    codes.push(self.delete(store, now, &label, item)?);
                }
                M::Status { id, codes }
            }
            // a Fetch is the stream's alone (spec/wire.md §11.2: its id in the node's range)
            M::Fetch { id, .. } => M::Error { id, code: Code::UNSUPPORTED },
            _ => return Ok(None),
        }))
    }

    /// A client-port request (spec/wire.md §11.2): handed out for the upper layer to answer,
    /// except what the protocol answers itself: a Call, Sub or Unsub before Auth (Error 1), a
    /// Sub reusing a live subscription's id (2) or past `MAX_SUBS` (4), an Unsub (Ok). One handed
    /// out keeps its `charge` against `MAX_UNANSWERED` until answered.
    fn api_request(&mut self, msg: Message, charge: Charge, out: &mut Vec<SessionOutput>) -> Option<Message> {
        use Message as M;
        let id = msg.id();
        if self.asked.contains_key(&id) {
            return Some(M::Error { id, code: Code::MALFORMED });
        }
        match &msg {
            M::Auth { .. } => {
                self.asked.insert(id, (24, crate::window::SMALL_REPLY, charge));
            }
            M::Call { max_reply, .. } | M::Sub { max_reply, .. } => {
                let sub = matches!(msg, M::Sub { .. });
                if !self.authed {
                    return Some(M::Error { id, code: Code::REFUSED });
                }
                if sub && self.api_subs.contains_key(&id) {
                    return Some(M::Error { id, code: Code::MALFORMED });
                }
                if sub && self.api_subs.len() >= crate::api::MAX_SUBS {
                    return Some(M::Error { id, code: Code::RATE_LIMITED });
                }
                let max = usize::try_from(*max_reply).unwrap_or(usize::MAX);
                if sub {
                    self.api_subs.insert(id, max);
                }
                self.asked.insert(id, (msg.kind(), max, charge));
            }
            M::Unsub { .. } if !self.authed => return Some(M::Error { id, code: Code::REFUSED }),
            M::Unsub { sub, .. } => {
                self.api_subs.remove(sub);
                out.push(SessionOutput::Request(Box::new(msg)));
                return Some(M::Ok { id });
            }
            _ => return None,
        }
        self.asked_bytes.add(charge);
        out.push(SessionOutput::Request(Box::new(msg)));
        None
    }

    fn register(&mut self, store: &mut dyn LabelStore, id: Id, label: LabelId, step: Step, claim_set: Option<ClaimSet>) -> Result<Message, StoreError> {
        if step.label != label || claim_set.as_ref().is_some_and(|c| c.hash() != step.claims_hash) {
            return Ok(Message::Error { id, code: Code::MALFORMED });
        }
        let head = self.head(store, &label)?;
        match &head {
            None if step.prev.is_none() => {
                if step.verify_genesis().is_err() {
                    return Ok(Message::Error { id, code: Code::REFUSED });
                }
                let code = store.admit_label(&label)?;
                if code != Code::OK {
                    return Ok(Message::Error { id, code });
                }
            }
            None => return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }),
            Some(h) if h.id() == step.id() => return Ok(Message::Ok { id }),
            // not a child of the head: the code alone, never the head (an ex-holder or link
            // holder would watch rotations; a registrar behind learns it by Behind items,
            // spec/sync.md §5)
            Some(h) => {
                if step.verify_child(h).is_err() {
                    return Ok(Message::Error { id, code: Code::NOT_HEAD });
                }
            }
        }
        let code = store.push_step(&label, step, claim_set)?;
        if code != Code::OK {
            return Ok(Message::Error { id, code });
        }
        Ok(Message::Ok { id })
    }

    /// The signatures of a delete of held entry `item.blob` (spec/sync.md §5): by the head's
    /// delete key, or by delete keys of levels (checked against the blob prefix's commitment
    /// groups: every group) with the label key the
    /// levels need. The prefix (`blob_prefix`, never the whole blob) is read only once the label
    /// signature holds.
    fn delete_auth(&mut self, store: &dyn LabelStore, label: &LabelId, item: &DeleteItem) -> Result<Code, StoreError> {
        let Some(k) = head_keys(&mut self.keys, store, label)? else { return Ok(Code::UNKNOWN_LABEL) };
        let levels = item.levels();
        let Ok(digest) = delete_digest(label, &item.blob, &levels) else { return Ok(Code::MALFORMED) };
        let key = match key_for_levels(&levels) {
            Ok(LabelRole::Delete) => StepKey::Delete,
            Ok(role) => key_of_role(role),
            Err(_) => return Ok(Code::REFUSED),
        };
        let code = check(k, key, Domain::Delete, &digest, &item.sig, &mut self.struck);
        if !item.by.is_empty() {
            let prefix = match code {
                Code::REFUSED => None,
                _ => store.blob_prefix(&item.blob)?.and_then(|b| Prefix::parse(&b).ok()),
            };
            let Some(prefix) = prefix else { return Ok(Code::REFUSED) };
            // the label signature was checked above; the delete-key signatures against the groups
            let groups = prefix.groups();
            let mut covered = vec![false; groups.len()];
            for (level, dsig) in &item.by {
                let mut any = false;
                for (gi, c) in covered.iter_mut().enumerate() {
                    if prefix.key_at(gi, *level).is_some_and(|k| verify_delete(&k, &digest, dsig).is_ok()) {
                        *c = true;
                        any = true;
                    }
                }
                if !any {
                    return Ok(Code::REFUSED);
                }
            }
            if covered.is_empty() || !covered.iter().all(|c| *c) {
                return Ok(Code::REFUSED);
            }
        }
        Ok(code)
    }

    /// One Delete item (spec/sync.md §5). A delete-key signature is checked against the blob's
    /// prefix: without the entry it cannot be (nor a tombstone revealed).
    fn delete(&mut self, store: &mut dyn LabelStore, now: u64, label: &LabelId, item: &DeleteItem) -> Result<Code, StoreError> {
        if self.keys(store, label)?.is_none() {
            return Ok(Code::UNKNOWN_LABEL);
        }
        if delete_digest(label, &item.blob, &item.levels()).is_err() {
            return Ok(Code::MALFORMED);
        }
        let entry = store.entry(label, &item.blob)?;
        if entry.is_none() {
            // a level's signature needs the prefix; the delete key's alone can be checked
            if !item.by.is_empty() {
                return Ok(Code::REFUSED);
            }
            let code = self.delete_auth(store, label, item)?;
            if code != Code::OK {
                return Ok(code);
            }
            return Ok(if store.tombstoned(label, &item.blob)? { Code::OK } else { Code::REFUSED });
        }
        let code = self.delete_auth(store, label, item)?;
        if code != Code::OK {
            return Ok(code);
        }
        store.delete(label, &item.blob, now)
    }
}

/// What a stamped entry put into the store gave: its code, or a relay-only blob to push to the
/// label's other holders (`put_stamped`).
pub enum Taken {
    Code(Code),
    Relay(Relayed),
}

/// A stamped entry whose stamp verified, put into the store (spec/sync.md §5, Taking a stamped
/// entry): a relay-only blob passes the relay gate and is not stored; an expired or tombstoned
/// one is refused. Used by node sync's pull of a sync ID it cannot read.
#[allow(clippy::too_many_arguments)]
pub fn put_stamped(store: &mut dyn LabelStore, now: u64, label: &LabelId, blob_id: BlobId, blob: &[u8], wrap: Wrap, stamp: Signature, role: bool) -> Result<Taken, StoreError> {
    let Ok(prefix) = host_prefix(blob) else { return Ok(Taken::Code(Code::MALFORMED)) };
    let class = prefix.as_ref().map(|p| p.class()).unwrap_or_default();
    let expiry = prefix.and_then(|p| p.expiry()).map(|t| t.0);
    if class == Class::Relay {
        return Ok(match store.relay(label, &blob_id, blob.len(), expiry, now)? {
            RelayVerdict::Push => Taken::Relay(Relayed { label: *label, blob_id, blob: blob.into(), wrap, stamp }),
            RelayVerdict::Seen => Taken::Code(Code::OK),
            RelayVerdict::Refused(c) => Taken::Code(c),
        });
    }
    if expiry.is_some_and(|t| t <= now) {
        return Ok(Taken::Code(Code::EXPIRED));
    }
    if store.tombstoned(label, &blob_id)? {
        return Ok(Taken::Code(Code::TOMBSTONED));
    }
    Ok(Taken::Code(store.put(label, Put { blob_id, blob, wrap, stamp: Some(stamp), expiry, ephemeral: class.in_memory(), now, role })?))
}

/// A stamped entry pulled from a reader of `label` at a node that cannot read it (spec/sync.md
/// §10, Stream): its stamp checked under the head keys `k`, then `put_stamped`. `struck` as for
/// `check`.
#[allow(clippy::too_many_arguments)]
pub fn pulled(store: &mut dyn LabelStore, now: u64, label: &LabelId, k: &HeadKeys, blob: &[u8], wrap: Wrap, stamp: Signature, struck: &mut bool) -> Result<Taken, StoreError> {
    let blob_id = osis_label::blob_id(blob);
    let (code, role) = check_entry(k, StepKey::Write, Domain::Stamp, &entry_digest(label, &blob_id, &wrap), &stamp, struck);
    if code != Code::OK {
        return Ok(Taken::Code(code));
    }
    put_stamped(store, now, label, blob_id, blob, wrap, stamp, role)
}

/// A Deposit of `blob` under `label` (spec/sync.md §5), whose head keys are `k`: its code, and
/// whether `sig` verified under the head's deposit key (only then may the depositor learn more
/// than the code). Taken as an unstamped entry within the store's deposit rules; a relay-only
/// blob is refused. `struck` as for `check`. Shared by a session's Deposit and node sync's
/// Deposit items at a node that cannot read the inbox.
#[allow(clippy::too_many_arguments)]
pub fn deposit(store: &mut dyn LabelStore, now: u64, label: &LabelId, k: &HeadKeys, blob: &[u8], wrap: Wrap, sig: &Signature, struck: &mut bool) -> Result<(Code, bool), StoreError> {
    let blob_id = osis_label::blob_id(blob);
    let (code, role) = check_entry(k, StepKey::Deposit, Domain::Deposit, &entry_digest(label, &blob_id, &wrap), sig, struck);
    if code != Code::OK {
        return Ok((code, false));
    }
    let Ok(prefix) = host_prefix(blob) else { return Ok((Code::MALFORMED, true)) };
    let class = prefix.as_ref().map(|p| p.class()).unwrap_or_default();
    let expiry = prefix.and_then(|p| p.expiry()).map(|t| t.0);
    if class == Class::Relay {
        return Ok((Code::REFUSED, true));
    }
    if expiry.is_some_and(|t| t <= now) {
        return Ok((Code::EXPIRED, true));
    }
    if store.tombstoned(label, &blob_id)? {
        return Ok((Code::TOMBSTONED, true));
    }
    Ok((store.put(label, Put { blob_id, blob, wrap, stamp: None, expiry, ephemeral: class.in_memory(), now, role })?, true))
}

impl From<Vec<u8>> for SessionOutput {
    fn from(frame: Vec<u8>) -> SessionOutput {
        SessionOutput::Send(frame)
    }
}


#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::examples::{CHALLENGE, Fixture, STATIC_KEY};
    use crate::store::MemoryLabelStore;

    fn reply(out: &[SessionOutput]) -> Message {
        out.iter().find_map(|o| if let SessionOutput::Send(b) = o { Message::decode(&b[4..]).ok() } else { None }).unwrap()
    }

    // spec/sync.md §10 (Connection proofs, Pair key): Prove and Resume are the node's, not the
    // store's: the session hands them up unanswered and sends the upper layer's answers
    #[test]
    fn prove_and_resume_go_up() {
        let mut store = MemoryLabelStore::new();
        let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: CHALLENGE, dialed: false });
        c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        for m in [Message::Prove { id: 1, proofs: vec![] }, Message::Resume { id: 2, nonce: [3; 32], tags: vec![[4; 32]] }] {
            let out = c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&m.encode())));
            assert_eq!(out, vec![SessionOutput::Peer(Box::new(m))]);
        }
        for m in [Message::Proved { id: 1, proofs: vec![] }, Message::Resumed { id: 2, nonce: [5; 32], tag: None }] {
            let out = c.handle(0, &mut store, SessionInput::Peer(Box::new(m.clone())));
            assert_eq!(reply(&out), m);
        }
        assert!(!c.is_closed());
    }

    // spec/sync.md §6 (request window): a node request handed up counts against `MAX_UNANSWERED`
    // until the upper layer answers it, input after input: answered, it frees its room; left
    // unanswered, a peer adding more is closed before the one past the bound goes up
    #[test]
    fn node_requests_count_until_answered_spec_sync_6() {
        let mut store = MemoryLabelStore::new();
        let fetch = |k: u32| Message::Fetch { id: crate::msg::NODE_IDS | k, label: LabelId([9; 16]), max_reply: REPLY_BUDGET as u64, ids: vec![BlobId([1; 32])] };
        let start = |store: &mut MemoryLabelStore| {
            let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: CHALLENGE, dialed: false });
            c.handle(0, store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
            c
        };
        let mut c = start(&mut store);
        for k in 0..10 {
            let out = c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&fetch(k).encode())));
            assert_eq!(out, vec![SessionOutput::Peer(Box::new(fetch(k)))]);
            let out = c.handle(0, &mut store, SessionInput::Peer(Box::new(Message::FetchReply { id: crate::msg::NODE_IDS | k, items: vec![] })));
            assert!(matches!(reply(&out), Message::FetchReply { .. }));
        }
        assert!(!c.is_closed());
        let mut c = start(&mut store);
        let mut up = 0;
        for k in 0..10 {
            let out = c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&fetch(k).encode())));
            up += out.iter().filter(|o| matches!(o, SessionOutput::Peer(_))).count();
            if c.is_closed() {
                assert!(out.iter().any(|o| matches!(o, SessionOutput::PeerError(Error::Cap("requests past the request window")))), "{out:?}");
                break;
            }
        }
        assert!(c.is_closed());
        let each = encode_frame(&fetch(0).encode()).len() + crate::window::allowance(&fetch(0));
        assert_eq!(up, crate::window::MAX_UNANSWERED / each);
    }

    /// A session past the Hellos, the transport having taken what it wrote.
    fn started(store: &mut MemoryLabelStore) -> Session {
        let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: CHALLENGE, dialed: false });
        c.handle(0, store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        let taken = c.written;
        c.handle(0, store, SessionInput::Taken(taken));
        c
    }

    /// A framed Ping.
    fn ping(id: Id) -> Vec<u8> {
        encode_frame(&Message::Ping { id, wall_ms: 0 }.encode())
    }

    /// The Pongs in `out`.
    fn pongs(out: &[SessionOutput]) -> usize {
        out.iter().filter(|o| matches!(o, SessionOutput::Send(b) if matches!(Message::decode(&b[4..]), Ok(Message::Pong { .. })))).count()
    }

    // spec/sync.md §6 (request window), spec/requirements.md (peer input never causes unbounded
    // work): a peer pipelining requests (two per input, within `MAX_UNANSWERED`) without taking
    // the replies is closed once they pass `SEND_QUEUE`; the rest of its input costs nothing
    #[test]
    fn pipelined_replies_bounded() {
        let mut store = MemoryLabelStore::new();
        let mut c = started(&mut store);
        // as many Pings per input as the unanswered bound takes
        let per = crate::window::MAX_UNANSWERED / (ping(1).len() + crate::window::SMALL_REPLY);
        let mut sent = 0;
        for round in 0..1_000_000u32 {
            let bytes: Vec<u8> = (0..per as u32).flat_map(|k| ping(10 + round * per as u32 + k)).collect();
            let out = c.handle(0, &mut store, SessionInput::Bytes(bytes));
            sent += out.iter().map(|x| if let SessionOutput::Send(b) = x { b.len() } else { 0 }).sum::<usize>();
            if c.is_closed() {
                assert!(out.iter().any(|o| matches!(o, SessionOutput::PeerError(Error::Cap("replies past the request window")))), "{out:?}");
                break;
            }
        }
        assert!(c.is_closed());
        assert!(sent > SEND_QUEUE && sent <= SEND_QUEUE + 2 * crate::window::SMALL_REPLY, "{sent}");
    }

    // spec/sync.md §10 (Served connections): with a room set, requests are taken but each runs,
    // in order, only once its reply allowance fits: within the share, or alone when the
    // connection holds nothing, and always within what the node has left; no input is taken
    // while one waits; the rest run as the transport takes the replies
    #[test]
    fn replies_wait_for_room_spec_sync_10() {
        let mut store = MemoryLabelStore::new();
        let mut c = started(&mut store);
        let allowance = crate::window::SMALL_REPLY;
        let ids = |out: &[SessionOutput]| out.iter().filter_map(|o| if let SessionOutput::Send(b) = o { Message::decode(&b[4..]).ok().map(|m| m.id()) } else { None }).collect::<Vec<_>>();
        // a reply, framed
        let pong = encode_frame(&Message::Pong { id: 100, wall_ms: 0 }.encode()).len();
        // two replies and an allowance fit; three and an allowance do not
        let share = 2 * pong + allowance + pong / 2;
        c.set_room(share, 64 << 20);
        let out = c.handle(0, &mut store, SessionInput::Bytes((100..108).flat_map(ping).collect()));
        assert_eq!(ids(&out), vec![100, 101, 102], "three fit the share");
        assert!(c.holding(&[]) <= share);
        assert!(!c.takes_input() && c.need() == Some(allowance));
        // the transport takes them: the next three
        let mut taken = c.written;
        c.set_room(share, 64 << 20);
        let out = c.handle(0, &mut store, SessionInput::Taken(taken));
        assert_eq!(ids(&out), vec![103, 104, 105]);
        // the node has nothing left: none runs, even holding nothing
        taken = c.written;
        c.set_room(share, 0);
        let out = c.handle(0, &mut store, SessionInput::Taken(taken));
        assert!(ids(&out).is_empty() && c.holding(&[]) == 0 && c.need() == Some(allowance));
        // a share smaller than one reply: one at a time, each alone
        c.set_room(pong / 2, 64 << 20);
        let out = c.handle(0, &mut store, SessionInput::Resume);
        assert_eq!(ids(&out), vec![106]);
        taken = c.written;
        c.set_room(pong / 2, 64 << 20);
        let out = c.handle(0, &mut store, SessionInput::Taken(taken));
        assert_eq!(ids(&out), vec![107]);
        assert!(c.takes_input() && c.need().is_none());
    }

    // spec/sync.md §10 (Served connections): push room granted is reserved against the room
    // until the pushes it was for (or an empty Notify, giving it back) arrive; a reservation for
    // a reply to come (a request handed up, as a settle waiting for its Notifies) does not hold
    // back the room that lets those pushes go, even under a share smaller than both
    #[test]
    fn granted_room_is_reserved_spec_sync_10() {
        let mut store = MemoryLabelStore::new();
        let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: CHALLENGE, dialed: false });
        c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        let taken = c.written;
        c.handle(0, &mut store, SessionInput::Taken(taken));
        let small = crate::window::SMALL_REPLY;
        let share = small + small / 2;
        c.set_room(share, 1 << 20);
        // a request handed up: its reply allowance is held for it (its frame is input held)
        let fetch = Message::Fetch { id: crate::msg::NODE_IDS | 1, label: LabelId([9; 16]), max_reply: small as u64, ids: vec![BlobId([1; 32])] };
        let out = c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&fetch.encode())));
        assert_eq!(out, vec![SessionOutput::Peer(Box::new(fetch))]);
        let asked = c.holding(&[]);
        assert!(asked == small && asked + small > share);
        // room for the pushes it waits on all the same, reserved once granted
        c.set_room(share, 1 << 20);
        let out = c.handle(0, &mut store, SessionInput::WantRoom);
        let budget = out.iter().find_map(|o| if let SessionOutput::Room { budget } = o { Some(*budget) } else { None }).expect("room granted");
        assert_eq!(c.holding(&[]), asked + budget);
        // given back unused
        c.handle(0, &mut store, SessionInput::Notify(Vec::new()));
        assert_eq!(c.holding(&[]), asked);
    }

    // spec/sync.md §6 (Requester, Closing): the node's own requests to the dialer, unwritten
    // within their window, come on top of the replies a compliant dialer's window allows, so
    // the two together close no connection
    #[test]
    fn own_requests_unwritten_close_nothing() {
        let mut store = MemoryLabelStore::new();
        let mut c = started(&mut store);
        // three filter pages just under 8 MiB each: below `WINDOW` before the third
        let page = |k: u32| Message::Beacons { id: crate::msg::NODE_IDS | k, generation: 1, base: None, f: 8, lo: 0, hi: 256, gcs: vec![0; (8 << 20) - (64 << 10)], more: false };
        for k in 1..=3 {
            c.handle(0, &mut store, SessionInput::Peer(Box::new(page(k))));
        }
        assert!(c.requests.in_flight() > crate::window::WINDOW);
        // a dialer within its window: requests while what it has in flight is below `WINDOW`
        let (mut bytes, mut in_flight, mut n) = (Vec::new(), 0, 0u32);
        while in_flight < crate::window::WINDOW {
            let f = ping(10 + n);
            in_flight += f.len() + crate::window::SMALL_REPLY;
            bytes.extend(f);
            n += 1;
        }
        let out = c.handle(0, &mut store, SessionInput::Bytes(bytes));
        assert!(!c.is_closed());
        assert_eq!(pongs(&out), n as usize);
    }

    // spec/sync.md §6 (request window), spec/requirements.md (peer input never causes unbounded
    // work): requests that would carry more than `MAX_UNANSWERED` unanswered in one input close
    // the connection before any runs; spread over inputs, each runs
    #[test]
    fn pipelined_requests_bounded() {
        let mut store = MemoryLabelStore::new();
        let mut c = started(&mut store);
        // within the bound: three per input, input after input
        for round in 0..4u32 {
            let out = c.handle(0, &mut store, SessionInput::Bytes((0..3).flat_map(|k| ping(10 + 3 * round + k)).collect()));
            assert_eq!(pongs(&out), 3);
        }
        assert!(!c.is_closed());
        // past it in one input: closed before any of them runs (frames are taken, then run)
        let mut c = started(&mut store);
        let n = crate::window::MAX_UNANSWERED / crate::window::SMALL_REPLY + 1;
        let out = c.handle(0, &mut store, SessionInput::Bytes((0..n as u32).flat_map(|k| ping(10 + k)).collect()));
        assert!(c.is_closed());
        assert!(out.iter().any(|o| matches!(o, SessionOutput::PeerError(Error::Cap("requests past the request window")))), "{out:?}");
        assert_eq!(pongs(&out), 0);
    }

    /// A Delete item of a blob this store does not hold, signed by delete secret `k`.
    fn delete_by(k: u8, label: &LabelId) -> DeleteItem {
        DeleteItem::sign(&crate::store::tests::secret(k), label, BlobId([0xd1; 32])).unwrap()
    }

    /// A session on which node sync opened `label` (its Deletes taken).
    fn opened_on(store: &mut MemoryLabelStore, label: LabelId) -> Session {
        let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: CHALLENGE, dialed: false });
        c.handle(0, store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        c.handle(0, store, SessionInput::Open(label));
        c
    }

    /// The codes of a Delete of `items` on a connection.
    fn delete_codes(c: &mut Session, store: &mut MemoryLabelStore, id: Id, label: LabelId, items: Vec<DeleteItem>) -> Vec<Code> {
        let out = c.handle(0, store, SessionInput::Bytes(encode_frame(&Message::Delete { id, label, items }.encode())));
        let Message::Status { codes, .. } = reply(&out) else { panic!("{out:?}") };
        codes
    }

    // spec/sync.md §5, spec/requirements.md (peer input never causes unbounded work): checking
    // a Delete's signature reads the head keys the store keeps, never the
    // label's path, however long and whatever the connection has cached; a recent earlier key
    // still gets code 9
    #[test]
    fn delete_check_reads_no_path() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new();
        let path = crate::store::tests::path(1000, |i, r| 1 + ((i + r) % 200) as u8);
        for s in &path {
            store.push_step(&f.label, s.clone(), None).unwrap();
        }
        // step 995's delete key: four keys before the head's
        let old = delete_by(1 + ((995 + 2) % 200) as u8, &f.label);
        let bad = DeleteItem { sig: Signature([0; 64]), ..old.clone() };
        for _ in 0..2 {
            // a fresh connection: nothing cached
            let mut c = opened_on(&mut store, f.label);
            store.step_reads.set(0);
            assert_eq!(delete_codes(&mut c, &mut store, 1, f.label, vec![old.clone(), bad.clone()]), vec![Code::NOT_HEAD, Code::REFUSED]);
            assert_eq!(store.step_reads.get(), 0);
        }
    }

    // spec/wire.md §11.2, spec/requirements.md (peer input never causes unbounded work): once a
    // signature of a message verifies under no key, the message's later ones are tried against
    // the head's key only (one verification each, not one per kept key): an old key's signature
    // after a bogus one gets 1, before it 9, and the next message starts over; node sync's
    // stamp checks (`pulled`) share the rule through their `struck`
    #[test]
    fn bogus_signature_stops_older_keys() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new();
        let path = crate::store::tests::path(10, |i, r| 1 + ((i + r) % 200) as u8);
        for s in &path {
            store.push_step(&f.label, s.clone(), None).unwrap();
        }
        // step 5's delete key (by `path`'s rule above)
        let old = delete_by(8, &f.label);
        let bad = DeleteItem { sig: Signature([0; 64]), ..old.clone() };
        let mut c = opened_on(&mut store, f.label);
        let cases = [(vec![old.clone(), bad.clone()], vec![Code::NOT_HEAD, Code::REFUSED]), (vec![bad.clone(), old.clone()], vec![Code::REFUSED, Code::REFUSED]), (vec![old.clone()], vec![Code::NOT_HEAD])];
        for (i, (items, want)) in cases.into_iter().enumerate() {
            assert_eq!(delete_codes(&mut c, &mut store, 1 + i as u32, f.label, items), want, "message {i}");
        }
        // stamps: step 5's write key
        let e = f.entry(Fixture::blob(1));
        let blob_id = osis_label::blob_id(&e.blob);
        let old = osis_label::sign_stamp(&crate::store::tests::secret(7), &f.label, &blob_id, &e.wrap, false);
        let k = store.head_keys(&f.label).unwrap().unwrap();
        let code = |store: &mut MemoryLabelStore, stamp: Signature, struck: &mut bool| match pulled(store, 0, &f.label, &k, &e.blob, e.wrap, stamp, struck).unwrap() {
            Taken::Code(c) => c,
            Taken::Relay(_) => panic!("relayed"),
        };
        for (i, (stamps, want)) in [(vec![old, Signature([0; 64])], vec![Code::NOT_HEAD, Code::REFUSED]), (vec![Signature([0; 64]), old], vec![Code::REFUSED, Code::REFUSED])].into_iter().enumerate() {
            let mut struck = false;
            let got: Vec<Code> = stamps.into_iter().map(|s| code(&mut store, s, &mut struck)).collect();
            assert_eq!(got, want, "stamps {i}");
        }
    }

    /// Holds a stamped entry (as node sync's pull puts one).
    fn held(store: &mut MemoryLabelStore, label: &LabelId, e: &crate::examples::Stamped) {
        let put = Put { blob_id: osis_label::blob_id(&e.blob), blob: &e.blob, wrap: e.wrap, stamp: Some(e.stamp), expiry: None, ephemeral: false, now: 0, role: false };
        assert_eq!(store.put(label, put).unwrap(), Code::OK);
    }

    // spec/sync.md §5 (Delete), spec/requirements.md (peer input never causes unbounded work): items
    // carrying a delete-key signature but no valid label signature are refused without reading
    // the blob (up to MAX_BLOB each) for its prefix
    #[test]
    fn unsigned_delete_items_read_no_blob() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new();
        store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let e = f.entry(Fixture::blob(1));
        let blob_id = osis_label::blob_id(&e.blob);
        held(&mut store, &f.label, &e);
        let mut c = opened_on(&mut store, f.label);
        let dk = osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([0x7a; 32]));
        let mut item = DeleteItem::sign_by(&f.sync, &[(2, &dk)], &[0x7d; 16], &[0x7e; 16], &f.label, blob_id).unwrap();
        item.sig = Signature([0; 64]);
        store.blob_reads.set(0);
        let out = c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&Message::Delete { id: 2, label: f.label, items: vec![item; 64] }.encode())));
        let codes = out.iter().find_map(|o| if let SessionOutput::Send(b) = o { if let Ok(Message::Status { codes, .. }) = Message::decode(&b[4..]) { Some(codes) } else { None } } else { None }).unwrap();
        assert_eq!(codes, vec![Code::REFUSED; 64]);
        assert_eq!(store.blob_reads.get(), 0);
    }

    // spec/sync.md §5 (Delete): a signed delete by level checks the blob's prefix
    // (`blob_prefix`), never reading the whole blob (up to MAX_BLOB per item)
    #[test]
    fn delete_by_level_reads_prefix_only() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new();
        store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let dk = osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([0x7a; 32]));
        let commit = osis_crypto::commitment(2, &dk.verifying_key(), &[1; 16], &[0x7e; 16]).unwrap();
        let e = f.entry(Fixture::blob_with(1, None, vec![commit]));
        let blob_id = osis_label::blob_id(&e.blob);
        held(&mut store, &f.label, &e);
        let mut c = opened_on(&mut store, f.label);
        let item = DeleteItem::sign_by(&f.sync, &[(2, &dk)], &[1; 16], &[0x7e; 16], &f.label, blob_id).unwrap();
        let wrong = DeleteItem::sign_by(&f.sync, &[(2, &dk)], &[2; 16], &[0x7e; 16], &f.label, blob_id).unwrap();
        store.blob_reads.set(0);
        let out = c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&Message::Delete { id: 2, label: f.label, items: vec![wrong, item] }.encode())));
        let Message::Status { codes, .. } = reply(&out) else { panic!("{out:?}") };
        assert_eq!(codes, vec![Code::REFUSED, Code::OK]);
        assert_eq!(store.blob_reads.get(), 0);
        assert!(store.entry(&f.label, &blob_id).unwrap().is_none());
    }

    // spec/sync.md §5 (Deposit): a deposit verifies under the head's deposit key (another key
    // learns its code only), is held unstamped within the deposit budget (64 + 4 x claim slots,
    // then code 5), an ephemeral blob too; a relay-only one is refused here, whatever the store
    // behind it checks, and nothing of it is held
    #[test]
    fn deposit_rules_spec_sync_5() {
        let now = 1_700_000_000_000;
        let l = crate::examples::Label::new(3);
        let mut store = MemoryLabelStore::new();
        store.push_step(&l.id, l.steps[0].clone(), Some(l.sets[0].clone())).unwrap();
        let k = store.head_keys(&l.id).unwrap().unwrap();
        let dk = l.head_keys().deposit.clone();
        let put = |store: &mut MemoryLabelStore, blob: Vec<u8>, key: &osis_crypto::SigningSecret| {
            let OfferItem::Deposit { blob, wrap, sig, .. } = l.deposit(blob, key) else { unreachable!() };
            deposit(store, now, &l.id, &k, &blob, wrap, &sig, &mut false).unwrap()
        };
        assert_eq!(put(&mut store, crate::examples::blob(0), &l.head_keys().write.clone()), (Code::REFUSED, false));
        let max = 64 + 4 * l.sets[0].claims.len() as u64;
        for n in 0..max {
            assert_eq!(put(&mut store, crate::examples::blob(n), &dk), (Code::OK, true), "{n}");
        }
        assert_eq!(put(&mut store, crate::examples::blob(max), &dk), (Code::BUDGET_FULL, true));
        assert!(store.entry(&l.id, &crate::examples::bid(0)).unwrap().is_some_and(|m| m.stamp.is_none()), "held deposited");
        // a fresh label: ephemeral held deposited, relay-only refused
        let mut store = MemoryLabelStore::new();
        store.push_step(&l.id, l.steps[0].clone(), Some(l.sets[0].clone())).unwrap();
        for (n, class) in [(1u8, Class::Ephemeral), (2, Class::Relay)] {
            let p = Prefix::new(crate::examples::salt(u64::from(n)), Some(osis_base::WallMs(now + osis_base::format::MAX_DRIFT_MS)), vec![]).unwrap().with_class(class);
            let b = osis_label::frame(&p, &[n; 50], &mut osis_crypto::SeededRng::from_seed([n; 32])).unwrap().1;
            let code = put(&mut store, b.clone(), &dk);
            let held = store.entry(&l.id, &osis_label::blob_id(&b)).unwrap();
            if class == Class::Relay {
                assert_eq!(code, (Code::REFUSED, true));
                assert!(held.is_none());
            } else {
                assert_eq!(code, (Code::OK, true));
                assert!(held.is_some_and(|m| m.stamp.is_none()), "held deposited");
            }
        }
    }

    // spec/sync.md §6 (flow control): a relay-only push (a Stream without cursor) goes only when
    // it fits `REPLY_BUDGET` behind the unwritten bytes, else it is dropped; a stream push with a
    // cursor always goes
    #[test]
    fn relay_push_without_room_is_dropped_spec_sync_6() {
        let mut store = MemoryLabelStore::new();
        let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: CHALLENGE, dialed: false });
        c.handle(0, &mut store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        let taken = c.written;
        c.handle(0, &mut store, SessionInput::Taken(taken));
        let push = |n: usize, cursor: Option<Vec<u8>>| {
            let ev = Event::Added { blob_id: BlobId([n as u8; 32]), blob: Some(vec![1; n]), wrap: [0; WRAP_LEN], stamp: None };
            SessionInput::Peer(Box::new(Message::Stream(Box::new(crate::msg::Stream { events: vec![(LabelId([7; 16]), ev)], cursor, report: false }))))
        };
        // 8 MiB unwritten
        assert_eq!(c.handle(0, &mut store, push(8 << 20, Some(vec![1; 72]))).len(), 1);
        assert!(c.handle(0, &mut store, push(1 << 20, None)).is_empty(), "no room: dropped");
        assert_eq!(c.handle(0, &mut store, push(100, None)).len(), 1);
        assert_eq!(c.handle(0, &mut store, push(1 << 20, Some(vec![2; 72]))).len(), 1, "a cursor push goes");
    }

    /// A dialer of `STATIC_KEY` past the Hellos, its challenge `[1; 32]`, the listener's `[2; 32]`.
    fn dialer(store: &mut MemoryLabelStore) -> Session {
        let mut c = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: [1; 32], dialed: true });
        c.handle(0, store, SessionInput::Start);
        c.handle(0, store, SessionInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        c
    }

    // spec/sync.md §10 (Connection proofs): both sides bind the same (dialer challenge, listener
    // challenge, listener key): a dialed session its own challenge first and the key it dialed,
    // an accepted one the peer's first and its own key; none before the peer's Hello
    #[test]
    fn binding_orders_dialer_first_spec_sync_10() {
        let mut store = MemoryLabelStore::new();
        let mut acc = Session::new(SessionConfig { listener_key: STATIC_KEY, challenge: [2; 32], dialed: false });
        acc.handle(0, &mut store, SessionInput::Start);
        assert_eq!(acc.binding(), None);
        acc.handle(0, &mut store, SessionInput::Bytes(encode_frame(&Hello::new(0, [1; 32]).encode())));
        let dialed = dialer(&mut store);
        assert_eq!(dialed.binding(), Some(([1; 32], [2; 32], STATIC_KEY)));
        assert_eq!(acc.binding(), dialed.binding());
    }

    // spec/sync.md §6 (request window), spec/wire.md §11.2: every answer to one of the upper
    // layer's requests (ids below `NODE_IDS`) comes up, by its id, the session answering none; a
    // reply to no request in flight (answered already, or never asked) is a protocol error,
    // handed up to nobody
    #[test]
    fn answers_to_upper_requests_come_up_spec_sync_6() {
        let mut store = MemoryLabelStore::new();
        let mut c = dialer(&mut store);
        let l = crate::examples::Label::new(3);
        let reqs = [
            Message::Ping { id: 1, wall_ms: 0 },
            l.register(2, 0),
            Message::Delete { id: 3, label: l.id, items: vec![DeleteItem::sign(&l.head_keys().delete, &l.id, BlobId([1; 32])).unwrap()] },
            Message::Auth { id: 4, secret: None, session: [0; 16] },
            Message::Prove { id: 5, proofs: vec![] },
        ];
        for m in reqs.clone() {
            assert_eq!(reply(&c.handle(0, &mut store, SessionInput::Peer(Box::new(m.clone())))), m);
        }
        let answers = vec![
            Message::Pong { id: 1, wall_ms: 7 },
            Message::Ok { id: 2 },
            Message::Status { id: 3, codes: vec![Code::OK] },
            Message::Error { id: 4, code: Code::REFUSED },
            Message::Proved { id: 5, proofs: vec![] },
        ];
        let bytes: Vec<u8> = answers.iter().flat_map(|m| encode_frame(&m.encode())).collect();
        let out = c.handle(1, &mut store, SessionInput::Bytes(bytes));
        assert_eq!(out, answers.into_iter().map(|m| SessionOutput::Peer(Box::new(m))).collect::<Vec<_>>());
        assert_eq!(c.stall_at(), None, "none out");
        for stray in [Message::Ok { id: 2 }, Message::Pong { id: 9, wall_ms: 0 }] {
            let out = c.handle(2, &mut store, SessionInput::Bytes(encode_frame(&stray.encode())));
            assert_eq!(out, vec![SessionOutput::PeerError(Error::Malformed("reply to no request"))], "{stray:?}");
        }
    }

    // spec/wire.md §11.2 (Ping): a dialer answers the listener's Ping as a listener does, from
    // the session, handing nothing up
    #[test]
    fn dialer_answers_ping_spec_wire_11_2() {
        let mut store = MemoryLabelStore::new();
        let mut c = dialer(&mut store);
        let out = c.handle(42, &mut store, SessionInput::Bytes(ping(3)));
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(reply(&out), Message::Pong { id: 3, wall_ms: 42 });
        assert_eq!(c.stall_at(), None, "the answer is no request of its own");
    }

    // spec/wire.md §11.1, spec/sync.md §6 (Stall): a reply that does not decode is dropped, never
    // answered (an Error under the requester's own id would be a reply to nothing at the peer);
    // the request stays out, so the stall clock still closes the connection if no answer comes
    #[test]
    fn a_broken_reply_is_dropped_and_its_request_still_stalls_spec_wire_11_1() {
        let mut store = MemoryLabelStore::new();
        let mut c = dialer(&mut store);
        c.handle(0, &mut store, SessionInput::Peer(Box::new(Message::Ping { id: 1, wall_ms: 0 })));
        // a Pong of id 1 with its wall clock a string
        let broken = osis_base::Value::List(vec![osis_base::Value::uint(Message::Pong { id: 1, wall_ms: 0 }.kind()), osis_base::Value::uint(1), osis_base::Value::Str("x".into())]);
        let out = c.handle(5, &mut store, SessionInput::Bytes(encode_frame(&osis_base::cbor::encode(&broken))));
        assert!(matches!(out[..], [SessionOutput::PeerError(_)]), "{out:?}");
        assert_eq!(c.stall_at(), Some(5 + crate::window::STALL_TIMEOUT_MS), "still out: its stall clock runs");
        let out = c.handle(6, &mut store, SessionInput::Bytes(encode_frame(&Message::Pong { id: 1, wall_ms: 0 }.encode())));
        assert!(matches!(&out[..], [SessionOutput::Peer(m)] if matches!(**m, Message::Pong { id: 1, .. })), "{out:?}");
    }
}
