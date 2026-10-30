//! Server side of one connection (spec/sync.md §4-§9, spec/wire.md §11): a sans-I/O state machine
//! answering every request from a `LabelStore`. The driver feeds stream bytes and cross-connection
//! notices and carries out the outputs.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame, send};
use crate::hello::{Hello, PROTOCOL_VERSION, negotiate};
use crate::msg::*;
use crate::rbsr;
use crate::relay::RelayVerdict;
use crate::store::{EntryMeta, LabelStore, LogRecord, Put, StoreError};
use osis_base::format::MAX_MESSAGE;
use osis_base::{BlobId, LabelId, WallMs};
use osis_crypto::{Domain, LabelRole, VerifyingKey, verify_delete};
use osis_label::auth::delete_digest;
use osis_label::{Class, OpenOutcome, entry_digest, evaluate_open, key_for_level, server_prefix};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

/// Room left in a reply for everything but its events or items.
pub const REPLY_BUDGET: usize = MAX_MESSAGE - 64 * 1024;
/// Log records or entries read from the store per call.
const LOG_BATCH: usize = 256;
/// Earlier distinct keys per role tried for code 9 (each a signature check per refused item).
const OLDER_KEYS: usize = 8;
/// Labels whose parsed path a connection caches.
const MAX_CACHED: usize = 4096;
/// Blob IDs a connection remembers as crossed (an optimization only: past it the set is cleared,
/// so a peer streaming entries cannot grow it without bound).
const MAX_CROSSED: usize = 1 << 14;
/// Unwritten push bytes a connection can hold (spec/sync.md §6): pushes go while the unwritten
/// bytes, the push included, fit `REPLY_BUDGET` or none are unwritten, so at most one push frame.
pub const PUSH_QUEUE: usize = MAX_MESSAGE + 4;
/// Bytes a peer can have unwritten to a compliant subscriber: its windowed replies plus the
/// pushes it holds. A send queue cap at or above it never closes such a connection.
pub const SEND_QUEUE: usize = crate::client::WINDOW_QUEUE + PUSH_QUEUE;
/// How often a driver reports `ServerInput::Taken` while a connection holds pushes back
/// (`ServerConnection::held`; ms). Minor consequence: pushes resume up to this late after the
/// queue has room; 0 spins the driver while a slow subscriber drains, infinity leaves them to
/// the next unrelated tick.
pub const PUSH_POLL_MS: u64 = 1000;
/// Domain of replay cursor IDs.
const REPLAY: &str = "osis v1 replay";

#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// This side's static key (bound by open signatures).
    pub static_key: [u8; 32],
    /// This side's Hello challenge: 32 random bytes per connection.
    pub challenge: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerInput {
    /// The connection is up: send Hello.
    Start,
    /// Bytes received on the stream.
    Bytes(Vec<u8>),
    /// A label's log grew (on any connection): push to a subscription.
    Changed(LabelId),
    /// A relay-only entry accepted on another connection: push it if subscribed (dropped while
    /// the connection's unwritten bytes leave no room).
    Relay(Relayed),
    /// The transport has taken this many bytes of this connection's output so far (cumulative):
    /// pushes wait while too much is unwritten (spec/sync.md §6). A driver that never reports it
    /// delivers instantly (no push is held back); one that does reports it before input bytes,
    /// at ticks, and every `PUSH_POLL_MS` while `held`.
    Taken(u64),
}

/// A relay-only entry (spec/sync.md §5): accepted by stamp, pushed to the label's current
/// subscribers on other connections, held by nobody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relayed {
    pub label: LabelId,
    pub blob_id: BlobId,
    pub blob: Vec<u8>,
    pub wrap: Wrap,
    pub stamp: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerOutput {
    /// A frame to write.
    Send(Vec<u8>),
    Close,
    /// This connection grew a label's log: deliver `ServerInput::Changed` to every connection.
    Changed(LabelId),
    /// A relay-only entry accepted: deliver `ServerInput::Relay` to every other connection.
    Relay(Relayed),
    /// The peer broke a protocol rule (diagnostic).
    PeerError(Error),
    StoreError(StoreError),
}

/// A role key a step registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Sync,
    Write,
    Delete,
    Deposit,
}

impl Key {
    fn of(self, s: &Step) -> &VerifyingKey {
        match self {
            Key::Sync => &s.keys.sync,
            Key::Write => &s.keys.write,
            Key::Delete => &s.keys.delete,
            Key::Deposit => &s.keys.deposit,
        }
    }

    fn from_role(r: LabelRole) -> Key {
        match r {
            LabelRole::Sync => Key::Sync,
            LabelRole::Write => Key::Write,
            LabelRole::Delete => Key::Delete,
        }
    }
}

/// A label's path as of its head, parsed once per head change.
struct Cached {
    head: StepId,
    path: Vec<Step>,
    /// Per key kind: up to `OLDER_KEYS` distinct earlier keys, newest first, not the head's.
    older: [Vec<VerifyingKey>; 4],
}

impl Cached {
    fn new(head: StepId, path: Vec<Step>) -> Cached {
        let older = [Key::Sync, Key::Write, Key::Delete, Key::Deposit].map(|k| {
            let mut v: Vec<VerifyingKey> = Vec::new();
            let head_key = path.last().map(|h| *k.of(h));
            for s in path.iter().rev() {
                let pk = *k.of(s);
                if Some(pk) != head_key && !v.contains(&pk) && v.len() < OLDER_KEYS {
                    v.push(pk);
                }
            }
            v
        });
        Cached { head, path, older }
    }

    fn head_step(&self) -> Option<&Step> {
        self.path.last()
    }

    /// OK under the head's key, NOT_HEAD under a recent earlier one, else REFUSED.
    fn check(&self, key: Key, domain: Domain, digest: &[u8; 32], sig: &Signature) -> Code {
        let Some(head) = self.head_step() else { return Code::UNKNOWN_LABEL };
        if key.of(head).verify(domain, digest, sig).is_ok() {
            return Code::OK;
        }
        let i = key as usize;
        if self.older.get(i).is_some_and(|ks| ks.iter().any(|k| k.verify(domain, digest, sig).is_ok())) {
            return Code::NOT_HEAD;
        }
        Code::REFUSED
    }
}

pub struct ServerConnection {
    cfg: ServerConfig,
    decoder: FrameDecoder,
    version: Option<u64>,
    closed: bool,
    opened: BTreeSet<LabelId>,
    /// Subscribed labels and the log position pushed so far.
    subs: BTreeMap<LabelId, u64>,
    /// Last complete Sync per label: its cursor sequence number.
    synced: BTreeMap<LabelId, u64>,
    /// Last Sync's inline limit per label (pushes use it).
    inline: BTreeMap<LabelId, u64>,
    /// Replays in progress: the log position taken at their start.
    replays: BTreeMap<LabelId, u64>,
    /// Blobs whose bytes crossed this connection (at most `MAX_CROSSED`): not inlined back.
    crossed: HashSet<BlobId>,
    cache: HashMap<LabelId, Cached>,
    /// Dialable key of the last member proof that opened a label.
    member: Option<[u8; 32]>,
    /// Presence entries uploaded on this connection (spec/sync.md §5): removed when it closes
    /// (and no other connection uploaded them); pruned of entries gone at `prune_at`.
    presence: BTreeSet<(LabelId, BlobId)>,
    prune_at: usize,
    /// Bytes of `Send` outputs so far.
    written: u64,
    /// The last `ServerInput::Taken` (none: never reported, no flow control).
    taken: Option<u64>,
    /// Subscribed labels whose pushes wait for room in the send queue (from their position in
    /// `subs`).
    owed: BTreeSet<LabelId>,
}

/// Presence uploads a connection remembers before it first drops those no longer held.
/// Performance switch: pruning keeps the set at about twice the live entries (bounded by the
/// ephemeral caps); 0 prunes at every upload, infinity never (a connection replacing its
/// presence would grow the set without bound).
const PRESENCE_PRUNE: usize = 1024;

/// The label's parsed path, reloaded when the head changed; none for an unknown label.
fn cached<'a>(cache: &'a mut HashMap<LabelId, Cached>, store: &dyn LabelStore, label: &LabelId) -> Result<Option<&'a Cached>, StoreError> {
    let Some(head) = store.head(label)? else {
        cache.remove(label);
        return Ok(None);
    };
    if cache.get(label).is_none_or(|c| c.head != head) {
        if cache.len() >= MAX_CACHED {
            cache.clear();
        }
        cache.insert(*label, Cached::new(head, store.path(label)?));
    }
    Ok(cache.get(label))
}

/// Replay cursor ID of a log (spec/wire.md §11.2).
pub fn replay_id(log_id: &[u8; 16]) -> [u8; 16] {
    let h = osis_base::hash::hash(&[REPLAY.as_bytes(), &log_id[..]].concat());
    let mut id = [0u8; 16];
    id.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
    id
}

/// Replay position of a blob ID: its first 63 bits, big-endian (a wire integer stays below
/// 2^63).
fn replay_pos(id: &BlobId) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(id.0.get(..8).unwrap_or(&[0; 8]));
    u64::from_be_bytes(b) >> 1
}

/// The greatest blob ID at a replay position (continuing after it skips the position).
fn after_pos(pos: u64) -> BlobId {
    let mut b = [0xff; 32];
    if let Some(d) = b.get_mut(..8) {
        d.copy_from_slice(&((pos << 1) | 1).to_be_bytes());
    }
    BlobId(b)
}

impl ServerConnection {
    pub fn new(cfg: ServerConfig) -> ServerConnection {
        ServerConnection {
            cfg,
            decoder: FrameDecoder::new(),
            version: None,
            closed: false,
            opened: BTreeSet::new(),
            subs: BTreeMap::new(),
            synced: BTreeMap::new(),
            inline: BTreeMap::new(),
            replays: BTreeMap::new(),
            crossed: HashSet::new(),
            cache: HashMap::new(),
            member: None,
            presence: BTreeSet::new(),
            prune_at: PRESENCE_PRUNE,
            written: 0,
            taken: None,
            owed: BTreeSet::new(),
        }
    }

    /// Presence entries uploaded on this connection (some may be gone since): the server removes
    /// them when it closes, unless another open connection uploaded them too (spec/sync.md §5).
    pub fn presence(&self) -> &BTreeSet<(LabelId, BlobId)> {
        &self.presence
    }

    /// The dialable key of the last member proof that opened a label here (spec/sync.md §5).
    pub fn member(&self) -> Option<[u8; 32]> {
        self.member
    }

    /// Labels opened on this connection.
    pub fn opened(&self) -> &BTreeSet<LabelId> {
        &self.opened
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The negotiated protocol version: none until the peer's Hello arrived.
    pub fn version(&self) -> Option<u64> {
        self.version
    }

    /// Whether pushes wait for the transport to take bytes (`ServerInput::Taken`).
    pub fn held(&self) -> bool {
        !self.owed.is_empty()
    }

    /// Bytes written and not taken by the transport, with those in `out` (0 without reports).
    fn backlog(&self, out: &[ServerOutput]) -> usize {
        let Some(t) = self.taken else { return 0 };
        let o: usize = out.iter().map(|x| if let ServerOutput::Send(b) = x { b.len() } else { 0 }).sum();
        usize::try_from(self.written.saturating_sub(t)).unwrap_or(usize::MAX).saturating_add(o)
    }

    /// Whether a push of about `size` bytes waits: something is unwritten and it would not fit
    /// `REPLY_BUDGET` behind it.
    fn no_room(&self, out: &[ServerOutput], size: usize) -> bool {
        let b = self.backlog(out);
        b > 0 && b.saturating_add(size) > REPLY_BUDGET
    }

    /// Bytes received and not yet parsed (a partial frame).
    pub fn buffered(&self) -> usize {
        self.decoder.pending()
    }

    pub fn handle(&mut self, now: u64, store: &mut dyn LabelStore, input: ServerInput) -> Vec<ServerOutput> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        self.input(now, store, input, &mut out);
        let n: usize = out.iter().map(|x| if let ServerOutput::Send(b) = x { b.len() } else { 0 }).sum();
        self.written = self.written.saturating_add(n as u64);
        out
    }

    fn input(&mut self, now: u64, store: &mut dyn LabelStore, input: ServerInput, out: &mut Vec<ServerOutput>) {
        match input {
            ServerInput::Start => out.push(ServerOutput::Send(encode_frame(&Hello::new(now, self.cfg.challenge).encode()))),
            ServerInput::Bytes(b) => {
                self.decoder.push(&b);
                while !self.closed {
                    // before the peer's Hello only a Hello-sized frame is taken (spec/wire.md §11.1)
                    self.decoder.set_max(if self.version.is_some() { osis_base::format::MAX_MESSAGE } else { crate::frame::MAX_HELLO_BYTES });
                    match self.decoder.next_frame() {
                        Ok(Some(body)) => self.frame(now, store, &body, out),
                        Ok(None) => break,
                        Err(e) => {
                            out.push(ServerOutput::PeerError(e));
                            send(out, Message::Error { id: 0, code: Code::MALFORMED });
                            self.close(out);
                        }
                    }
                }
            }
            ServerInput::Changed(label) => {
                if let Err(e) = self.push(store, &label, out) {
                    out.push(ServerOutput::StoreError(e));
                }
            }
            ServerInput::Relay(r) => {
                // a slow subscriber misses relay-only entries rather than queueing them
                let ev = Event::Added { blob_id: r.blob_id, blob: Some(r.blob), wrap: r.wrap, stamp: Some(r.stamp) };
                if let Some(seq) = self.subs.get(&r.label).copied()
                    && !self.no_room(out, event_size(&ev))
                {
                    match store.log_head(&r.label) {
                        Ok((log_id, _)) => send(out, Message::Push { label: r.label, events: vec![ev], cursor: Cursor { log_id, seq } }),
                        Err(e) => out.push(ServerOutput::StoreError(e)),
                    }
                }
            }
            ServerInput::Taken(n) => {
                self.taken = Some(self.taken.map_or(n, |t| t.max(n)));
                for l in self.owed.clone() {
                    if let Err(e) = self.push(store, &l, out) {
                        out.push(ServerOutput::StoreError(e));
                    }
                }
            }
        }
    }

    fn close(&mut self, out: &mut Vec<ServerOutput>) {
        self.closed = true;
        out.push(ServerOutput::Close);
    }

    fn frame(&mut self, now: u64, store: &mut dyn LabelStore, body: &[u8], out: &mut Vec<ServerOutput>) {
        if self.version.is_none() {
            match Hello::decode(body).and_then(|h| negotiate(&[PROTOCOL_VERSION], &h.versions)) {
                Ok(v) => self.version = Some(v),
                Err(e) => {
                    out.push(ServerOutput::PeerError(e));
                    self.close(out);
                }
            }
            return;
        }
        let msg = match Message::decode(body) {
            Ok(m) => m,
            Err(r) => {
                let code = r.code();
                let id = r.id;
                out.push(ServerOutput::PeerError(r.error));
                send(out, Message::Error { id, code });
                return;
            }
        };
        let id = msg.id();
        match self.dispatch(now, store, msg, out) {
            Ok(Some(reply)) => send(out, reply),
            Ok(None) => {}
            Err(e) => {
                out.push(ServerOutput::StoreError(e));
                send(out, Message::Error { id, code: Code::REFUSED });
            }
        }
    }

    fn cached(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<Option<&Cached>, StoreError> {
        cached(&mut self.cache, store, label)
    }

    fn head(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<Option<Step>, StoreError> {
        Ok(self.cached(store, label)?.and_then(|c| c.head_step().cloned()))
    }

    fn dispatch(&mut self, now: u64, store: &mut dyn LabelStore, msg: Message, out: &mut Vec<ServerOutput>) -> Result<Option<Message>, StoreError> {
        use Message as M;
        Ok(Some(match msg {
            M::Ping { id, .. } => M::Pong { id, wall_ms: now },
            M::Open { id, label, proof } => self.open(store, id, label, proof)?,
            M::Register { id, label, step, claim_set } => self.register(store, id, label, step, claim_set, out)?,
            M::Path { id, label, after } => self.path(store, id, label, after)?,
            M::Upload { id, label, entries } => {
                let ids: Vec<BlobId> = entries.iter().map(|e| osis_label::blob_id(&e.blob)).collect();
                let codes = self.accept_all(store, now, &label, &entries, &ids, out)?;
                let head = if codes.contains(&Code::NOT_HEAD) { self.head(store, &label)? } else { None };
                M::Status { id, codes, head }
            }
            M::Deposit { id, label, blob, wrap, sig } => {
                let Some(c) = self.cached(store, &label)? else {
                    return Ok(Some(M::Budget { id, code: Code::UNKNOWN_LABEL, entries_left: 0, bytes_left: 0, head: None }));
                };
                let blob_id = osis_label::blob_id(&blob);
                let mut code = c.check(Key::Deposit, Domain::Deposit, &entry_digest(&label, &blob_id, &wrap), &sig);
                let head = if code == Code::NOT_HEAD { c.head_step().cloned() } else { None };
                if code == Code::OK {
                    code = self.accept(store, now, &label, blob_id, &blob, wrap, None, out)?;
                }
                changed(&[code], &label, out);
                let b = store.budget(&label)?;
                M::Budget { id, code, entries_left: b.entries_left, bytes_left: b.bytes_left, head }
            }
            M::Delete { id, label, items } => {
                let mut codes = Vec::with_capacity(items.len());
                for item in &items {
                    codes.push(self.delete(store, now, &label, item)?);
                }
                changed(&codes, &label, out);
                let head = if codes.contains(&Code::NOT_HEAD) { self.head(store, &label)? } else { None };
                M::Status { id, codes, head }
            }
            M::Sync { id, label, cursor, inline_limit, entries, gained } => self.sync(store, now, id, label, cursor, inline_limit, entries, gained, out)?,
            M::Reconcile { id, label, ranges } => {
                if !self.opened.contains(&label) {
                    return Ok(Some(M::Error { id, code: Code::NOT_OPENED }));
                }
                match rbsr::respond(&store.live_ids(&label)?, &ranges) {
                    Ok(ranges) => M::ReconcileReply { id, ranges },
                    Err(_) => M::Error { id, code: Code::MALFORMED },
                }
            }
            M::Fetch { id, label, ids } => self.fetch(store, id, label, ids)?,
            M::Subscribe { id, labels } => {
                let mut codes = Vec::with_capacity(labels.len());
                for l in labels {
                    codes.push(if self.opened.contains(&l) {
                        let seq = match self.synced.get(&l) {
                            Some(s) => *s,
                            None => store.log_head(&l)?.1,
                        };
                        self.subs.insert(l, seq);
                        Code::OK
                    } else {
                        Code::NOT_OPENED
                    });
                }
                M::Status { id, codes, head: None }
            }
            M::Unsubscribe { id, labels } => {
                for l in labels {
                    self.subs.remove(&l);
                    self.owed.remove(&l);
                }
                M::Ok { id }
            }
            // Replies and pushes: this side sends no requests.
            _ => return Ok(None),
        }))
    }

    fn open(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, proof: Proof) -> Result<Message, StoreError> {
        let Some(c) = cached(&mut self.cache, store, &label)? else { return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }) };
        let (path, head_id) = (&c.path, c.head);
        if !self.opened.contains(&label) && self.opened.len() >= MAX_OPEN_LABELS {
            return Ok(Message::Error { id, code: Code::RATE_LIMITED });
        }
        // The one claim set the proof needs: its step's (claim), the head's (static entry).
        // a member node's proof: the store knows its dialable key (spec/sync.md §5)
        if let Proof::Member { dialable, .. } = &proof {
            let key = dialable.to_bytes();
            let ok = proof.verify_sig(&label, &self.cfg.challenge, &self.cfg.static_key).is_ok() && store.member_open(&key, &label)?;
            return Ok(match path.last() {
                Some(head) if ok => {
                    self.opened.insert(label);
                    self.member = Some(key);
                    Message::Opened { id, head: head.clone(), entry_box: None }
                }
                _ => Message::Error { id, code: Code::REFUSED },
            });
        }
        let want = match &proof {
            Proof::Member { .. } => None,
            Proof::Sync { .. } => None,
            Proof::Claim { step, .. } => Some(*step),
            Proof::Static { .. } => Some(head_id),
        };
        let set: Option<(StepId, Arc<ClaimSet>)> = match want {
            Some(s) => store.claim_set(&label, &s)?.map(|c| (s, c)),
            None => None,
        };
        let claims = |s: &StepId| set.as_ref().filter(|(id, _)| id == s).map(|(_, c)| c.as_ref());
        Ok(match evaluate_open(path, &claims, &proof, &self.cfg.challenge, &self.cfg.static_key) {
            OpenOutcome::Opened(entry_box) => match path.last() {
                Some(head) => {
                    self.opened.insert(label);
                    Message::Opened { id, head: head.clone(), entry_box: entry_box.cloned() }
                }
                None => Message::Error { id, code: Code::UNKNOWN_LABEL },
            },
            OpenOutcome::Child(step) => Message::Step { id, step: step.clone() },
            OpenOutcome::Refused => Message::Error { id, code: Code::REFUSED },
        })
    }

    fn register(&mut self, store: &mut dyn LabelStore, id: Id, label: LabelId, step: Step, claim_set: Option<ClaimSet>, out: &mut Vec<ServerOutput>) -> Result<Message, StoreError> {
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
            Some(h) => {
                if step.verify_child(h).is_err() {
                    return Ok(Message::Step { id, step: h.clone() });
                }
            }
        }
        store.push_step(&label, step, claim_set)?;
        out.push(ServerOutput::Changed(label));
        Ok(Message::Ok { id })
    }

    fn path(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, after: Option<StepId>) -> Result<Message, StoreError> {
        if !self.opened.contains(&label) {
            return Ok(Message::Error { id, code: Code::NOT_OPENED });
        }
        let Some(c) = self.cached(store, &label)? else { return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }) };
        let start = match after {
            None => 0,
            Some(a) => match c.path.iter().position(|s| s.id() == a) {
                Some(i) => i + 1,
                None => return Ok(Message::Error { id, code: Code::REFUSED }),
            },
        };
        let rest = c.path.get(start..).unwrap_or(&[]);
        let more = rest.len() > MAX_PATH_STEPS;
        Ok(Message::PathReply { id, steps: rest.iter().take(MAX_PATH_STEPS).cloned().collect(), more })
    }

    fn fetch(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, ids: Vec<BlobId>) -> Result<Message, StoreError> {
        if !self.opened.contains(&label) {
            return Ok(Message::Error { id, code: Code::NOT_OPENED });
        }
        let mut items = Vec::new();
        let mut used = 0;
        for blob_id in ids {
            let entry = match store.entry(&label, &blob_id)? {
                Some(m) => store.blob(&blob_id)?.map(|b| (b, m.wrap, m.stamp)),
                None => None,
            };
            let size = 120 + entry.as_ref().map_or(0, |e| e.0.len());
            if used + size > REPLY_BUDGET {
                break;
            }
            used += size;
            if entry.is_some() {
                self.cross(blob_id);
            }
            items.push(Fetched { blob_id, entry });
        }
        Ok(Message::FetchReply { id, items })
    }

    /// The event for a log record, or none for a superseded add or a gained blob.
    fn event(&self, store: &dyn LabelStore, label: &LabelId, seq: u64, rec: LogRecord, inline_limit: u64, gained: &HashSet<BlobId>) -> Result<Option<Event>, StoreError> {
        Ok(match rec {
            LogRecord::Added(b) => match store.entry(label, &b)? {
                Some(m) if m.add_seq == seq && !gained.contains(&b) => Some(self.added(store, b, m, inline_limit)?),
                _ => None,
            },
            LogRecord::Deleted(b) => Some(Event::Deleted(b)),
            LogRecord::Pending(b, at) => Some(Event::Pending { blob_id: b, at }),
            LogRecord::Head(s) => Some(Event::Head(s)),
        })
    }

    fn added(&self, store: &dyn LabelStore, blob_id: BlobId, m: EntryMeta, inline_limit: u64) -> Result<Event, StoreError> {
        let blob = if m.size <= inline_limit && !self.crossed.contains(&blob_id) { store.blob(&blob_id)? } else { None };
        Ok(Event::Added { blob_id, blob, wrap: m.wrap, stamp: m.stamp })
    }

    fn take(&mut self, e: &Event) {
        if let Event::Added { blob_id, blob: Some(_), .. } = e {
            self.cross(*blob_id);
        }
    }

    fn cross(&mut self, blob_id: BlobId) {
        if self.crossed.len() >= MAX_CROSSED {
            self.crossed.clear();
        }
        self.crossed.insert(blob_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn sync(&mut self, store: &mut dyn LabelStore, now: u64, id: Id, label: LabelId, cursor: Option<Cursor>, inline_limit: u64, entries: Vec<Entry>, gained: Vec<BlobId>, out: &mut Vec<ServerOutput>) -> Result<Message, StoreError> {
        if !self.opened.contains(&label) {
            return Ok(Message::Error { id, code: Code::NOT_OPENED });
        }
        let (log_id, head_seq) = store.log_head(&label)?;
        let invalid = Message::Error { id, code: Code::CURSOR_INVALID };
        // Log mode from a sequence number, or a replay (in blob ID order) after a position.
        enum From {
            Log(u64),
            Replay { start: u64, after: Option<BlobId> },
        }
        let from = match cursor {
            None => From::Replay { start: head_seq, after: None },
            Some(c) if c.log_id == log_id => {
                if store.log_after(&label, c.seq, 0)?.is_none() {
                    return Ok(invalid);
                }
                From::Log(c.seq)
            }
            Some(c) if c.log_id == replay_id(&log_id) => match self.replays.get(&label) {
                Some(start) => From::Replay { start: *start, after: Some(after_pos(c.seq)) },
                None => return Ok(invalid),
            },
            Some(_) => return Ok(invalid),
        };
        self.inline.insert(label, inline_limit);
        let ids: Vec<BlobId> = entries.iter().map(|e| osis_label::blob_id(&e.blob)).collect();
        for b in &ids {
            self.cross(*b);
        }
        let codes = self.accept_all(store, now, &label, &entries, &ids, out)?;
        let mut want = Vec::new();
        for g in &gained {
            if store.entry(&label, g)?.is_none() && !store.tombstoned(&label, g)? {
                want.push(*g);
            }
        }
        // The requester holds what it gained and what it just sent: no add events for those.
        let gained: HashSet<BlobId> = gained.into_iter().chain(ids).collect();
        let budget = REPLY_BUDGET.saturating_sub(40 * want.len() + 10 * codes.len());
        let (mut events, mut used, mut more) = (Vec::new(), 0, false);
        let cursor = match from {
            From::Log(seq) => {
                let mut pos = seq;
                'log: loop {
                    let Some(recs) = store.log_after(&label, pos, LOG_BATCH)? else { return Ok(invalid) };
                    if recs.is_empty() {
                        break;
                    }
                    for (seq, rec) in recs {
                        if let Some(e) = self.event(store, &label, seq, rec, inline_limit, &gained)? {
                            let size = event_size(&e);
                            if used + size > budget && !events.is_empty() {
                                more = true;
                                break 'log;
                            }
                            used += size;
                            self.take(&e);
                            events.push(e);
                        }
                        pos = seq;
                    }
                }
                Cursor { log_id, seq: pos }
            }
            From::Replay { start, mut after } => {
                'live: loop {
                    let live = store.live_by_id(&label, after.as_ref(), LOG_BATCH)?;
                    if live.is_empty() {
                        break;
                    }
                    for (b, m) in live {
                        if !gained.contains(&b) {
                            let e = self.added(store, b, m, inline_limit)?;
                            let size = event_size(&e);
                            if used + size > budget && !events.is_empty() {
                                more = true;
                                break 'live;
                            }
                            used += size;
                            self.take(&e);
                            events.push(e);
                        }
                        after = Some(b);
                    }
                }
                match (more, after) {
                    (true, Some(last)) => {
                        self.replays.insert(label, start);
                        Cursor { log_id: replay_id(&log_id), seq: replay_pos(&last) }
                    }
                    _ => {
                        self.replays.remove(&label);
                        Cursor { log_id, seq: start }
                    }
                }
            }
        };
        if !more {
            self.synced.insert(label, cursor.seq);
        }
        Ok(Message::SyncReply { id, events, want, codes, cursor, more })
    }

    fn push(&mut self, store: &dyn LabelStore, label: &LabelId, out: &mut Vec<ServerOutput>) -> Result<(), StoreError> {
        let Some(mut seq) = self.subs.get(label).copied() else { return Ok(()) };
        if self.backlog(out) >= REPLY_BUDGET {
            self.owed.insert(*label);
            return Ok(());
        }
        let inline_limit = self.inline.get(label).copied().unwrap_or(0);
        let (log_id, head) = store.log_head(label)?;
        let none = HashSet::new();
        let (mut events, mut used) = (Vec::new(), 0);
        loop {
            let Some(recs) = store.log_after(label, seq, LOG_BATCH)? else {
                // The log no longer reaches the subscription: the client's next Sync recovers.
                seq = head;
                break;
            };
            if recs.is_empty() {
                break;
            }
            for (s, rec) in recs {
                if let Some(e) = self.event(store, label, s, rec, inline_limit, &none)? {
                    let size = event_size(&e);
                    if self.backlog(out) + used + size > REPLY_BUDGET {
                        if !events.is_empty() {
                            send(out, Message::Push { label: *label, events: std::mem::take(&mut events), cursor: Cursor { log_id, seq } });
                            used = 0;
                        }
                        if self.no_room(out, size) {
                            // the rest goes from `seq` once the transport takes bytes (`Taken`)
                            self.owed.insert(*label);
                            self.subs.insert(*label, seq);
                            return Ok(());
                        }
                    }
                    used += size;
                    self.take(&e);
                    events.push(e);
                }
                seq = s;
            }
        }
        if !events.is_empty() {
            send(out, Message::Push { label: *label, events, cursor: Cursor { log_id, seq } });
        }
        self.subs.insert(*label, seq);
        self.owed.remove(label);
        Ok(())
    }

    /// The stamped entries of an Upload or Sync (`ids`: their blob IDs), one code each.
    fn accept_all(&mut self, store: &mut dyn LabelStore, now: u64, label: &LabelId, entries: &[Entry], ids: &[BlobId], out: &mut Vec<ServerOutput>) -> Result<Vec<Code>, StoreError> {
        let mut codes = Vec::with_capacity(entries.len());
        for (e, b) in entries.iter().zip(ids) {
            codes.push(self.accept(store, now, label, *b, &e.blob, e.wrap, Some(e.stamp), out)?);
        }
        changed(&codes, label, out);
        Ok(codes)
    }

    /// Upload (stamp) or deposit (no stamp, already authorized) of one entry (spec/sync.md §5).
    /// A relay-only blob (stamped only) is not stored: it goes to the other connections'
    /// subscribers (`ServerOutput::Relay`).
    #[allow(clippy::too_many_arguments)]
    fn accept(&mut self, store: &mut dyn LabelStore, now: u64, label: &LabelId, blob_id: BlobId, blob: &[u8], wrap: Wrap, stamp: Option<Signature>, out: &mut Vec<ServerOutput>) -> Result<Code, StoreError> {
        // An oversized blob never gets here: the message decoder refuses it (msg tests `field_sizes`).
        debug_assert!(blob.len() <= osis_base::format::MAX_BLOB);
        let Some(c) = self.cached(store, label)? else { return Ok(Code::UNKNOWN_LABEL) };
        if let Some(stamp) = stamp {
            let code = c.check(Key::Write, Domain::Upload, &entry_digest(label, &blob_id, &wrap), &stamp);
            if code != Code::OK {
                return Ok(code);
            }
        }
        let Ok(prefix) = server_prefix(blob) else { return Ok(Code::MALFORMED) };
        let class = prefix.as_ref().map(|p| p.class()).unwrap_or_default();
        let expiry = prefix.and_then(|p| p.expiry()).map(|t| t.0);
        // readers write no ephemeral data: an ephemeral or relay-only blob needs a stamp, at
        // every store (spec/sync.md §5)
        if class != Class::Durable && stamp.is_none() {
            return Ok(Code::REFUSED);
        }
        if class == Class::Relay {
            let Some(stamp) = stamp else { return Ok(Code::REFUSED) };
            return Ok(match store.relay(label, &blob_id, blob.len(), expiry, now)? {
                RelayVerdict::Push => {
                    out.push(ServerOutput::Relay(Relayed { label: *label, blob_id, blob: blob.to_vec(), wrap, stamp }));
                    Code::OK
                }
                RelayVerdict::Seen => Code::OK,
                RelayVerdict::Refused(c) => c,
            });
        }
        if expiry.is_some_and(|t| t <= now) {
            return Ok(Code::EXPIRED);
        }
        if store.tombstoned(label, &blob_id)? {
            return Ok(Code::TOMBSTONED);
        }
        let presence = class == Class::Presence;
        let code = store.put(label, Put { blob_id, blob, wrap, stamp, expiry, ephemeral: class.in_memory(), presence })?;
        if presence && code == Code::OK {
            self.presence.insert((*label, blob_id));
            if self.presence.len() > self.prune_at {
                let mut gone = Vec::new();
                for (l, b) in &self.presence {
                    if store.entry(l, b)?.is_none() {
                        gone.push((*l, *b));
                    }
                }
                for k in gone {
                    self.presence.remove(&k);
                }
                self.prune_at = self.presence.len().saturating_mul(2).max(PRESENCE_PRUNE);
            }
        }
        Ok(code)
    }

    /// One Delete item (spec/sync.md §5): by the head's delete key, or by a level's delete key
    /// (checked against the blob prefix's commitment at that level) with the label key the level
    /// needs.
    fn delete(&mut self, store: &mut dyn LabelStore, now: u64, label: &LabelId, item: &DeleteItem) -> Result<Code, StoreError> {
        let Some(c) = self.cached(store, label)? else { return Ok(Code::UNKNOWN_LABEL) };
        let Ok(digest) = delete_digest(label, &item.blob, item.at, item.by.map(|b| b.0)) else { return Ok(Code::MALFORMED) };
        let entry = store.entry(label, &item.blob)?;
        let (key, by) = match &item.by {
            None => (Key::Delete, None),
            Some((level, dsig)) => match key_for_level(*level) {
                Ok(role) => (Key::from_role(role), Some((*level, dsig))),
                Err(_) => return Ok(Code::REFUSED),
            },
        };
        let code = c.check(key, Domain::Delete, &digest, &item.sig);
        // A delete-key signature is checked against the blob's prefix: without the blob it cannot
        // be (nor a tombstone revealed). The blob is read only for an item whose label signature
        // holds (an unsigned item would cost a blob read of up to MAX_BLOB each).
        if let Some((level, dsig)) = by {
            let prefix = match (code, &entry) {
                (Code::REFUSED, _) | (_, None) => None,
                _ => store.blob(&item.blob)?.and_then(|b| server_prefix(&b).ok().flatten()),
            };
            if !prefix.and_then(|p| p.key_at(level)).is_some_and(|k| verify_delete(&k, &digest, dsig).is_ok()) {
                return Ok(Code::REFUSED);
            }
        }
        if code != Code::OK {
            return Ok(code);
        }
        if entry.is_none() {
            return Ok(if store.tombstoned(label, &item.blob)? { Code::OK } else { Code::REFUSED });
        }
        match item.at {
            Some(WallMs(at)) if at > now => store.schedule_delete(label, &item.blob, at),
            _ => store.delete(label, &item.blob, now),
        }
    }
}

impl From<Vec<u8>> for ServerOutput {
    fn from(frame: Vec<u8>) -> ServerOutput {
        ServerOutput::Send(frame)
    }
}

fn changed(codes: &[Code], label: &LabelId, out: &mut Vec<ServerOutput>) {
    if codes.contains(&Code::OK) && !out.contains(&ServerOutput::Changed(*label)) {
        out.push(ServerOutput::Changed(*label));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::examples::{CHALLENGE, Fixture, STATIC_KEY};
    use crate::store::MemoryLabelStore;

    // spec/requirements.md (peer input never causes unbounded allocation): a peer streaming Syncs
    // of refused entries does not grow the connection's crossed set past its cap
    #[test]
    fn crossed_set_bounded() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE });
        let mut feed = |c: &mut ServerConnection, body: Vec<u8>| c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&body)));
        feed(&mut c, Hello::new(0, [2; 32]).encode());
        let out = feed(&mut c, Message::Open { id: 1, label: f.label, proof: Proof::sync(&f.sync, &f.label, &CHALLENGE, &STATIC_KEY) }.encode());
        assert!(out.iter().any(|o| matches!(o, ServerOutput::Send(b) if matches!(Message::decode(&b[4..]), Ok(Message::Opened { .. })))));
        let n = MAX_CROSSED / 2 + 1;
        for round in 0..3u32 {
            let entries = (0..n).map(|i| Entry { blob: [round.to_be_bytes(), (i as u32).to_be_bytes()].concat(), wrap: [0; WRAP_LEN], stamp: Signature([0; 64]) }).collect();
            feed(&mut c, Message::Sync { id: 2 + round, label: f.label, cursor: None, inline_limit: 0, entries, gained: vec![] }.encode());
            assert!(c.crossed.len() <= MAX_CROSSED, "{}", c.crossed.len());
        }
        assert!(!c.is_closed());
    }

    // spec/sync.md §5 (Delete), spec/requirements.md (peer input never causes unbounded work): items
    // carrying a delete-key signature but no valid label signature are refused without reading
    // the blob (up to MAX_BLOB each) for its prefix
    #[test]
    fn unsigned_delete_items_read_no_blob() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let e = f.entry(Fixture::blob(1));
        let blob_id = osis_label::blob_id(&e.blob);
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE });
        c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Message::Upload { id: 1, label: f.label, entries: vec![e] }.encode())));
        assert!(out.iter().any(|o| matches!(o, ServerOutput::Changed(_))), "uploaded");
        let dk = osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([0x7a; 32]));
        let mut item = DeleteItem::sign_by(&f.sync, &dk, 2, &[0x7d; 16], &[0x7e; 16], &f.label, blob_id, None).unwrap();
        item.sig = Signature([0; 64]);
        store.blob_reads.set(0);
        let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Message::Delete { id: 2, label: f.label, items: vec![item; 64] }.encode())));
        let codes = out.iter().find_map(|o| if let ServerOutput::Send(b) = o { if let Ok(Message::Status { codes, .. }) = Message::decode(&b[4..]) { Some(codes) } else { None } } else { None }).unwrap();
        assert_eq!(codes, vec![Code::REFUSED; 64]);
        assert_eq!(store.blob_reads.get(), 0);
    }
}
