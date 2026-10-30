//! Server side of one connection (spec/sync.md §4-§9, spec/wire.md §11): a sans-I/O state machine
//! answering every request from a `LabelStore`. The driver feeds stream bytes and cross-connection
//! notices and carries out the outputs.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame, send};
use crate::hello::{Hello, PROTOCOL_VERSION, negotiate};
use crate::msg::*;
use crate::rbsr;
use crate::relay::RelayVerdict;
use crate::store::{EntryMeta, HeadKeys, LabelStore, LogRecord, Put, Replaced, StepKey, StoreError};
use osis_base::format::MAX_MESSAGE;
use osis_base::{BlobId, LabelId, WallMs};
use osis_crypto::{Domain, LabelRole, verify_delete};
use osis_label::auth::delete_digest;
use osis_label::{Class, OpenOutcome, PathIndex, Prefix, entry_digest, evaluate_open, key_for_level, server_prefix};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

/// Room left in a reply for everything but its events or items.
pub const REPLY_BUDGET: usize = MAX_MESSAGE - 64 * 1024;
/// Log records or entries read from the store per call.
const LOG_BATCH: usize = 256;
/// Labels whose head keys a connection caches (cleared when full). Performance switch: a peer
/// cycling past it makes the connection reload them (two store reads beyond the head lookup every
/// message makes, and up to 33 key parses); 0 reloads per message, infinity grows with the labels
/// a peer names, opened or not. An entry is about 7 KB (parsed keys), so about 450 KB per
/// connection, the scale of `MAX_CROSSED`.
const MAX_CACHED: usize = 64;
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
    /// Names this connection's tie to the presence entries it uploads (`Put::tie`): unique
    /// among the connections over one store.
    pub tie: u64,
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
    /// Shared by every connection it goes to.
    pub blob: Arc<[u8]>,
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

fn key_of_role(r: LabelRole) -> StepKey {
    match r {
        LabelRole::Sync => StepKey::Sync,
        LabelRole::Write => StepKey::Write,
        LabelRole::Delete => StepKey::Delete,
    }
}

/// A label's path indexes in the store, as `evaluate_open` reads them.
struct Index<'a> {
    store: &'a dyn LabelStore,
    label: &'a LabelId,
}

impl PathIndex for Index<'_> {
    type Error = StoreError;
    fn step_with_sync(&self, pk: &osis_crypto::VerifyingKey) -> Result<Option<StepId>, StoreError> {
        self.store.step_with_sync(self.label, pk)
    }
    fn claims(&self, step: &StepId) -> Result<Option<Arc<ClaimSet>>, StoreError> {
        self.store.claim_set(self.label, step)
    }
    fn child(&self, step: &StepId) -> Result<Option<Step>, StoreError> {
        match self.store.child(self.label, Some(step))? {
            Some(c) => self.store.step(self.label, &c),
            None => Ok(None),
        }
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

/// What an open holds under.
#[derive(Clone, Copy)]
enum Under {
    /// The sync key of the head it was proven at.
    Sync(osis_crypto::VerifyingKey),
    /// A member proof (spec/sync.md §5, member peer): the store's word, not a step's.
    Member,
}

pub struct ServerConnection {
    cfg: ServerConfig,
    decoder: FrameDecoder,
    version: Option<u64>,
    closed: bool,
    /// Opened labels and the sync key each open holds under (spec/sync.md §5): a head with
    /// another sync key ends it (`still_open`).
    opened: BTreeMap<LabelId, Under>,
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
    /// Head keys per label, as of its head (`MAX_CACHED`).
    keys: HashMap<LabelId, HeadKeys>,
    /// A signature of the message being handled verified under no key (`check`).
    struck: bool,
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
    /// `subs`), in the order they were held: resumed in turn, so a busy label starves no other.
    owed: VecDeque<LabelId>,
}

/// Presence uploads a connection remembers before it first drops those no longer held.
/// Performance switch: pruning keeps the set at about twice the live entries (bounded by the
/// ephemeral caps); 0 prunes at every upload, infinity never (a connection replacing its
/// presence would grow the set without bound).
const PRESENCE_PRUNE: usize = 1024;

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
            opened: BTreeMap::new(),
            subs: BTreeMap::new(),
            synced: BTreeMap::new(),
            inline: BTreeMap::new(),
            replays: BTreeMap::new(),
            crossed: HashSet::new(),
            keys: HashMap::new(),
            struck: false,
            member: None,
            presence: BTreeSet::new(),
            prune_at: PRESENCE_PRUNE,
            written: 0,
            taken: None,
            owed: VecDeque::new(),
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

    /// Labels opened on this connection (an open a new head ended stays listed until a
    /// request or push about the label finds it ended).
    pub fn opened(&self) -> impl Iterator<Item = &LabelId> {
        self.opened.keys()
    }

    /// Whether `label` is subscribed here: only then does a relay-only entry go to it.
    pub fn subscribed(&self, label: &LabelId) -> bool {
        self.subs.contains_key(label)
    }

    /// Whether no label is opened on this connection (as `opened`).
    pub fn none_opened(&self) -> bool {
        self.opened.is_empty()
    }

    /// Whether `label` is opened and its open holds at the head: under the head's sync key, or
    /// by a member proof, which holds across steps (spec/sync.md §5).
    fn holds(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<bool, StoreError> {
        Ok(match self.opened.get(label).copied() {
            None => false,
            Some(Under::Member) => true,
            Some(Under::Sync(k)) => self.keys(store, label)?.is_some_and(|h| h.head.keys.sync == k),
        })
    }

    /// `holds`, ending an open that no longer does, with its subscription (spec/sync.md §5).
    fn still_open(&mut self, store: &dyn LabelStore, label: &LabelId) -> Result<bool, StoreError> {
        if self.holds(store, label)? {
            return Ok(true);
        }
        self.end_open(label);
        Ok(false)
    }

    fn end_open(&mut self, label: &LabelId) {
        self.opened.remove(label);
        self.subs.remove(label);
        self.owed.retain(|x| x != label);
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

    /// Queues `label`'s pushes behind those already held (`owed`).
    fn owe(&mut self, label: LabelId) {
        if !self.owed.contains(&label) {
            self.owed.push_back(label);
        }
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
            // while pushes are held, a label waits its turn (`owed`)
            ServerInput::Changed(label) if self.held() => {
                if self.subs.contains_key(&label) {
                    self.owe(label);
                }
            }
            ServerInput::Changed(label) => {
                if let Err(e) = self.push(store, &label, out) {
                    out.push(ServerOutput::StoreError(e));
                }
            }
            ServerInput::Relay(r) => {
                // a slow subscriber misses relay-only entries rather than queueing them
                let ev = Event::Added { blob_id: r.blob_id, blob: Some(r.blob.to_vec()), wrap: r.wrap, stamp: Some(r.stamp) };
                // an open a new head ended gets none (its held push ends it)
                if let Some(seq) = self.subs.get(&r.label).copied()
                    && !self.no_room(out, event_size(&ev))
                    && self.holds(store, &r.label).unwrap_or_else(|e| {
                        out.push(ServerOutput::StoreError(e));
                        false
                    })
                {
                    match store.log_head(&r.label) {
                        Ok((log_id, _)) => send(out, Message::Push { label: r.label, events: vec![ev], cursor: Cursor { log_id, seq } }),
                        Err(e) => out.push(ServerOutput::StoreError(e)),
                    }
                }
            }
            ServerInput::Taken(n) => {
                self.taken = Some(self.taken.map_or(n, |t| t.max(n)));
                // in turn: one held again goes to the back, and the rest keep their place
                while let Some(l) = self.owed.pop_front() {
                    if let Err(e) = self.push(store, &l, out) {
                        out.push(ServerOutput::StoreError(e));
                        self.owe(l);
                    }
                    if self.owed.back() == Some(&l) {
                        break;
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
        self.struck = false;
        match self.dispatch(now, store, msg, out) {
            Ok(Some(reply)) => send(out, reply),
            Ok(None) => {}
            Err(e) => {
                out.push(ServerOutput::StoreError(e));
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
                let Some(k) = head_keys(&mut self.keys, store, &label)? else {
                    return Ok(Some(M::Budget { id, code: Code::UNKNOWN_LABEL, entries_left: 0, bytes_left: 0, head: None }));
                };
                let blob_id = osis_label::blob_id(&blob);
                let mut code = check(k, StepKey::Deposit, Domain::Deposit, &entry_digest(&label, &blob_id, &wrap), &sig, &mut self.struck);
                let head = if code == Code::NOT_HEAD { Some(k.head.clone()) } else { None };
                if code == Code::OK {
                    code = self.accept(store, now, &label, blob_id, &blob, wrap, None, &[], out)?;
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
                if !self.still_open(store, &label)? {
                    return Ok(Some(M::Error { id, code: Code::NOT_OPENED }));
                }
                if ranges.iter().any(|r| matches!(r.mode, Mode::Diff { .. })) {
                    return Ok(Some(M::Error { id, code: Code::MALFORMED }));
                }
                // only the asked ranges are read (sorted and disjoint: at most the label once)
                let mut mine = Vec::with_capacity(ranges.len());
                for r in &ranges {
                    let upper = (!r.upper.is_end()).then(|| BlobId(r.upper.padded()));
                    mine.push(store.live_ids_in(&label, &BlobId(r.lower.padded()), upper.as_ref())?);
                }
                match rbsr::respond_in(&ranges, &mine) {
                    Ok(ranges) => M::ReconcileReply { id, ranges },
                    Err(_) => M::Error { id, code: Code::MALFORMED },
                }
            }
            M::Fetch { id, label, ids } => self.fetch(store, id, label, ids)?,
            M::Subscribe { id, labels } => {
                let mut codes = Vec::with_capacity(labels.len());
                for l in labels {
                    codes.push(if self.still_open(store, &l)? {
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
                    self.owed.retain(|x| *x != l);
                }
                M::Ok { id }
            }
            // Replies and pushes: this side sends no requests.
            _ => return Ok(None),
        }))
    }

    fn open(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, proof: Proof) -> Result<Message, StoreError> {
        let Some(head) = self.head(store, &label)? else { return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }) };
        if !self.opened.contains_key(&label) && self.opened.len() >= MAX_OPEN_LABELS {
            return Ok(Message::Error { id, code: Code::RATE_LIMITED });
        }
        // a member node's proof: the store knows its dialable key (spec/sync.md §5)
        if let Proof::Member { dialable, .. } = &proof {
            let key = dialable.to_bytes();
            if !(proof.verify_sig(&label, &self.cfg.challenge, &self.cfg.static_key).is_ok() && store.member_open(&key, &label)?) {
                return Ok(Message::Error { id, code: Code::REFUSED });
            }
            self.opened.insert(label, Under::Member);
            self.member = Some(key);
            return Ok(Message::Opened { id, head, entry_box: None });
        }
        Ok(match evaluate_open(&head, &Index { store, label: &label }, &proof, &self.cfg.challenge, &self.cfg.static_key)? {
            // every open proof holds at the head only: under the head's sync key (a claim or
            // static entry is listed by a reader of the head's read epoch)
            OpenOutcome::Opened(entry_box) => {
                self.opened.insert(label, Under::Sync(head.keys.sync));
                Message::Opened { id, head, entry_box }
            }
            OpenOutcome::Child(step) => Message::Step { id, step },
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
        let code = store.push_step(&label, step, claim_set)?;
        if code != Code::OK {
            return Ok(Message::Error { id, code });
        }
        out.push(ServerOutput::Changed(label));
        Ok(Message::Ok { id })
    }

    /// Pages forward from `after` by the store's child index: a step read and a child lookup
    /// per step sent, never the whole path.
    fn path(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, after: Option<StepId>) -> Result<Message, StoreError> {
        if !self.still_open(store, &label)? {
            return Ok(Message::Error { id, code: Code::NOT_OPENED });
        }
        let Some(head) = store.head(&label)? else { return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }) };
        let mut at = match after {
            Some(a) if a == head => None,
            a => match store.child(&label, a.as_ref())? {
                Some(c) => Some(c),
                None => return Ok(Message::Error { id, code: Code::REFUSED }),
            },
        };
        let mut steps = Vec::new();
        while let Some(s) = at {
            if steps.len() >= MAX_PATH_STEPS {
                break;
            }
            steps.push(store.step(&label, &s)?.ok_or_else(|| StoreError("step missing on the path".into()))?);
            at = if s == head { None } else { store.child(&label, Some(&s))? };
        }
        Ok(Message::PathReply { id, steps, more: at.is_some() })
    }

    fn fetch(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, ids: Vec<BlobId>) -> Result<Message, StoreError> {
        if !self.still_open(store, &label)? {
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
        if !self.still_open(store, &label)? {
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

    /// Pushes `label`'s new log events. An open a new head ends (`still_open`) gets the events up
    /// to and with that head's, and nothing after: its subscription ends.
    fn push(&mut self, store: &dyn LabelStore, label: &LabelId, out: &mut Vec<ServerOutput>) -> Result<(), StoreError> {
        let Some(mut seq) = self.subs.get(label).copied() else { return Ok(()) };
        if self.backlog(out) >= REPLY_BUDGET {
            self.owe(*label);
            return Ok(());
        }
        let ends = match self.opened.get(label).copied() {
            Some(Under::Sync(k)) if !self.holds(store, label)? => Some(k),
            _ => None,
        };
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
                let ending = matches!((&rec, ends), (LogRecord::Head(st), Some(k)) if st.keys.sync != k);
                if ending {
                    // pushed whatever the queue holds: the last event of this subscription
                    let e = self.event(store, label, s, rec, inline_limit, &none)?;
                    events.extend(e);
                    send(out, Message::Push { label: *label, events, cursor: Cursor { log_id, seq: s } });
                    self.end_open(label);
                    return Ok(());
                }
                if let Some(e) = self.event(store, label, s, rec, inline_limit, &none)? {
                    let size = event_size(&e);
                    if self.backlog(out) + used + size > REPLY_BUDGET {
                        if !events.is_empty() {
                            send(out, Message::Push { label: *label, events: std::mem::take(&mut events), cursor: Cursor { log_id, seq } });
                            used = 0;
                        }
                        if self.no_room(out, size) {
                            // the rest goes from `seq` once the transport takes bytes (`Taken`)
                            self.owe(*label);
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
        if ends.is_some() {
            // the ending head's record is gone from the log: the current head ends it
            events.extend(self.keys(store, label)?.map(|h| Event::Head(h.head.clone())));
            send(out, Message::Push { label: *label, events, cursor: Cursor { log_id, seq } });
            self.end_open(label);
            return Ok(());
        }
        if !events.is_empty() {
            send(out, Message::Push { label: *label, events, cursor: Cursor { log_id, seq } });
        }
        self.subs.insert(*label, seq);
        self.owed.retain(|x| x != label);
        Ok(())
    }

    /// The stamped entries of an Upload or Sync (`ids`: their blob IDs), one code each.
    fn accept_all(&mut self, store: &mut dyn LabelStore, now: u64, label: &LabelId, entries: &[Entry], ids: &[BlobId], out: &mut Vec<ServerOutput>) -> Result<Vec<Code>, StoreError> {
        let mut codes = Vec::with_capacity(entries.len());
        for (e, b) in entries.iter().zip(ids) {
            codes.push(self.accept(store, now, label, *b, &e.blob, e.wrap, Some(e.stamp), &e.replaces, out)?);
        }
        changed(&codes, label, out);
        Ok(codes)
    }

    /// Upload (stamp) or deposit (no stamp, already authorized) of one entry (spec/sync.md §5),
    /// with the entries it replaces: each authorized as a Delete of it would be (or by this
    /// connection's tie), all removed iff the entry is admitted. A relay-only blob (stamped
    /// only) is not stored: it goes to the other connections' subscribers (`ServerOutput::Relay`).
    #[allow(clippy::too_many_arguments)]
    fn accept(&mut self, store: &mut dyn LabelStore, now: u64, label: &LabelId, blob_id: BlobId, blob: &[u8], wrap: Wrap, stamp: Option<Signature>, replaces: &[Replace], out: &mut Vec<ServerOutput>) -> Result<Code, StoreError> {
        // An oversized blob never gets here: the message decoder refuses it (msg tests `field_sizes`).
        debug_assert!(blob.len() <= osis_base::format::MAX_BLOB);
        let Some(k) = head_keys(&mut self.keys, store, label)? else { return Ok(Code::UNKNOWN_LABEL) };
        if let Some(stamp) = stamp {
            let code = check(k, StepKey::Write, Domain::Upload, &entry_digest(label, &blob_id, &wrap), &stamp, &mut self.struck);
            if code != Code::OK {
                return Ok(code);
            }
        }
        let mut replaced = Vec::with_capacity(replaces.len());
        for r in replaces {
            match r {
                Replace::Untie(b) => replaced.push(Replaced::Untie(*b)),
                // one no longer held is skipped unchecked: nothing to remove
                Replace::Delete(item) => {
                    if store.entry(label, &item.blob)?.is_none() {
                        continue;
                    }
                    let code = self.delete_auth(store, label, item)?;
                    if code != Code::OK {
                        return Ok(code);
                    }
                    replaced.push(Replaced::Delete(item.blob));
                }
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
            // held by nobody, so it replaces nothing
            let Some(stamp) = stamp.filter(|_| replaces.is_empty()) else { return Ok(Code::REFUSED) };
            return Ok(match store.relay(label, &blob_id, blob.len(), expiry, now)? {
                RelayVerdict::Push => {
                    out.push(ServerOutput::Relay(Relayed { label: *label, blob_id, blob: blob.into(), wrap, stamp }));
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
        let code = store.put(label, Put { blob_id, blob, wrap, stamp, expiry, ephemeral: class.in_memory(), presence, tie: self.cfg.tie, replaces: &replaced, now })?;
        if code == Code::OK {
            for r in &replaced {
                if let Replaced::Untie(b) = r {
                    self.presence.remove(&(*label, *b));
                }
            }
        }
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

    /// The signatures of a delete of held entry `item.blob` (spec/sync.md §5): by the head's
    /// delete key, or by a level's delete key (checked against the blob prefix's commitment at
    /// that level) with the label key the level needs. The prefix (`blob_prefix`, never the
    /// whole blob) is read only once the label signature holds.
    fn delete_auth(&mut self, store: &dyn LabelStore, label: &LabelId, item: &DeleteItem) -> Result<Code, StoreError> {
        let Some(k) = head_keys(&mut self.keys, store, label)? else { return Ok(Code::UNKNOWN_LABEL) };
        let Ok(digest) = delete_digest(label, &item.blob, item.at, item.by.map(|b| b.0)) else { return Ok(Code::MALFORMED) };
        let (key, by) = match &item.by {
            None => (StepKey::Delete, None),
            Some((level, dsig)) => match key_for_level(*level) {
                Ok(role) => (key_of_role(role), Some((*level, dsig))),
                Err(_) => return Ok(Code::REFUSED),
            },
        };
        let code = check(k, key, Domain::Delete, &digest, &item.sig, &mut self.struck);
        if let Some((level, dsig)) = by {
            let prefix = match code {
                Code::REFUSED => None,
                _ => store.blob_prefix(&item.blob)?.and_then(|b| Prefix::parse(&b).ok()),
            };
            if !prefix.and_then(|p| p.key_at(level)).is_some_and(|k| verify_delete(&k, &digest, dsig).is_ok()) {
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
        if delete_digest(label, &item.blob, item.at, item.by.map(|b| b.0)).is_err() {
            return Ok(Code::MALFORMED);
        }
        let entry = store.entry(label, &item.blob)?;
        if entry.is_none() {
            // a level's signature needs the prefix; the delete key's alone can be checked
            if item.by.is_some() {
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
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
        let mut feed = |c: &mut ServerConnection, body: Vec<u8>| c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&body)));
        feed(&mut c, Hello::new(0, [2; 32]).encode());
        let out = feed(&mut c, Message::Open { id: 1, label: f.label, proof: Proof::sync(&f.sync, &f.label, &CHALLENGE, &STATIC_KEY) }.encode());
        assert!(out.iter().any(|o| matches!(o, ServerOutput::Send(b) if matches!(Message::decode(&b[4..]), Ok(Message::Opened { .. })))));
        let n = MAX_CROSSED / 2 + 1;
        for round in 0..3u32 {
            let entries = (0..n).map(|i| Entry { blob: [round.to_be_bytes(), (i as u32).to_be_bytes()].concat(), wrap: [0; WRAP_LEN], stamp: Signature([0; 64]), replaces: Vec::new() }).collect();
            feed(&mut c, Message::Sync { id: 2 + round, label: f.label, cursor: None, inline_limit: 0, entries, gained: vec![] }.encode());
            assert!(c.crossed.len() <= MAX_CROSSED, "{}", c.crossed.len());
        }
        assert!(!c.is_closed());
    }

    fn opened(f: &Fixture, store: &mut MemoryLabelStore) -> ServerConnection {
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
        c.handle(0, store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        let open = Message::Open { id: 1, label: f.label, proof: Proof::sync(&f.sync, &f.label, &CHALLENGE, &STATIC_KEY) };
        let out = c.handle(0, store, ServerInput::Bytes(encode_frame(&open.encode())));
        assert!(out.iter().any(|o| matches!(o, ServerOutput::Send(b) if matches!(Message::decode(&b[4..]), Ok(Message::Opened { .. })))));
        c
    }

    fn reply(out: &[ServerOutput]) -> Message {
        out.iter().find_map(|o| if let ServerOutput::Send(b) = o { Message::decode(&b[4..]).ok() } else { None }).unwrap()
    }

    // spec/wire.md §11.3, spec/requirements.md (peer input never causes unbounded work): a
    // Reconcile reads only the live IDs inside its ranges, so repeating a narrow range over a
    // large label costs what the range holds, and the whole space costs the label once
    #[test]
    fn reconcile_reads_only_asked_ranges() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let n = 4096u32;
        let mut ids = Vec::new();
        for i in 0..n {
            let blob = i.to_be_bytes().to_vec();
            let blob_id = osis_label::blob_id(&blob);
            let put = Put { blob_id, blob: &blob, wrap: [0; WRAP_LEN], stamp: Some(Signature([0; 64])), expiry: None, ephemeral: false, presence: false, tie: 0, replaces: &[], now: 0 };
            assert_eq!(store.put(&f.label, put).unwrap(), Code::OK);
            ids.push(blob_id);
        }
        ids.sort();
        let mut c = opened(&f, &mut store);
        // [ids[100], ids[110]): ten IDs, asked by fingerprint and by list
        let (lo, hi) = (rbsr::Bound::of(&ids[100]), rbsr::Bound::of(&ids[110]));
        for (i, mode) in [Mode::Fingerprint([0; 16]), Mode::Ids(vec![])].into_iter().enumerate() {
            store.ids_read.set(0);
            let msg = Message::Reconcile { id: 2 + i as u32, label: f.label, ranges: vec![Range { lower: lo.clone(), upper: hi.clone(), mode }] };
            let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&msg.encode())));
            let Message::ReconcileReply { ranges, .. } = reply(&out) else { panic!("{out:?}") };
            let want = match i {
                0 => Mode::Ids(ids[100..110].to_vec()),
                _ => Mode::Diff { theirs: ids[100..110].to_vec(), lacking: vec![] },
            };
            assert_eq!(ranges, vec![Range { lower: lo.clone(), upper: hi.clone(), mode: want }]);
            assert_eq!(store.ids_read.get(), 10);
        }
        store.ids_read.set(0);
        let whole = Message::Reconcile { id: 9, label: f.label, ranges: vec![Range { lower: rbsr::Bound::empty(), upper: rbsr::Bound::empty(), mode: Mode::Fingerprint([0; 16]) }] };
        let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&whole.encode())));
        assert!(matches!(reply(&out), Message::ReconcileReply { ranges, .. } if ranges.len() == rbsr::SPLIT));
        assert_eq!(store.ids_read.get(), u64::from(n));
    }

    // spec/sync.md §5, spec/requirements.md (peer input never causes unbounded work): checking
    // an Upload (which needs no open) reads the head keys the store keeps, never the label's
    // path, however long and whatever the connection has cached; a recent earlier key still
    // gets code 9 and the head
    #[test]
    fn upload_check_reads_no_path() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        let path = crate::store::tests::path(1000, |i, r| 1 + ((i + r) % 200) as u8);
        for s in &path {
            store.push_step(&f.label, s.clone(), None).unwrap();
        }
        let e = f.entry(Fixture::blob(1));
        let blob_id = osis_label::blob_id(&e.blob);
        // step 995's write key: four keys before the head's
        let old = Entry { stamp: osis_label::sign_stamp(&crate::store::tests::secret(1 + ((995 + 1) % 200) as u8), &f.label, &blob_id, &e.wrap), ..e.clone() };
        let bad = Entry { stamp: Signature([0; 64]), ..e };
        for _ in 0..2 {
            // a fresh connection: nothing cached
            let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
            c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
            store.step_reads.set(0);
            let up = Message::Upload { id: 1, label: f.label, entries: vec![old.clone(), bad.clone()] };
            let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&up.encode())));
            let Message::Status { codes, head, .. } = reply(&out) else { panic!("{out:?}") };
            assert_eq!(codes, vec![Code::NOT_HEAD, Code::REFUSED]);
            assert_eq!(head.map(|h| h.id()), Some(path[999].id()));
            assert_eq!(store.step_reads.get(), 0);
        }
    }

    // spec/wire.md §11.2, spec/requirements.md (peer input never causes unbounded work): once a
    // signature of a message verifies under no key, the message's later ones are tried against
    // the head's key only (one verification each, not one per kept key): an old key's stamp after
    // a bogus one gets 1, before it 9, and the next message starts over
    #[test]
    fn bogus_signature_stops_older_keys() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        let path = crate::store::tests::path(10, |i, r| 1 + ((i + r) % 200) as u8);
        for s in &path {
            store.push_step(&f.label, s.clone(), None).unwrap();
        }
        let e = f.entry(Fixture::blob(1));
        let blob_id = osis_label::blob_id(&e.blob);
        let old = Entry { stamp: osis_label::sign_stamp(&crate::store::tests::secret(1 + ((5 + 1) % 200) as u8), &f.label, &blob_id, &e.wrap), ..e.clone() };
        let bad = Entry { stamp: Signature([0; 64]), ..e };
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
        c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        for (i, (entries, want)) in [(vec![old.clone(), bad.clone()], vec![Code::NOT_HEAD, Code::REFUSED]), (vec![bad.clone(), old.clone()], vec![Code::REFUSED, Code::REFUSED]), (vec![old.clone()], vec![Code::NOT_HEAD])].into_iter().enumerate() {
            let up = Message::Upload { id: 1 + i as u32, label: f.label, entries };
            let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&up.encode())));
            let Message::Status { codes, .. } = reply(&out) else { panic!("{out:?}") };
            assert_eq!(codes, want, "message {i}");
        }
    }

    // spec/sync.md §5 (Open), spec/requirements.md (peer input never causes unbounded work): an
    // Open reads the store's path indexes, never the path: on a 1000-step label a stranger's sync
    // key, an unknown or unproven claim, an old sync key (its newest step's child) and a held
    // claim each cost at most one step read, on a fresh connection and repeated past the cache
    #[test]
    fn open_reads_no_path() {
        use crate::store::tests::{path, secret};
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        let path = path(1000, |i, r| 1 + ((i + r) % 200) as u8);
        let claim = secret(240);
        for (i, s) in path.iter().enumerate() {
            let set = (i == 500).then(|| ClaimSet { claims: vec![claim.verifying_key().to_bytes()], entries: BTreeMap::new() });
            store.push_step(&f.label, s.clone(), set).unwrap();
        }
        let proof = |k: u8| Proof::sync(&secret(k), &f.label, &CHALLENGE, &STATIC_KEY);
        let claim_at = |i: usize, k: &osis_crypto::SigningSecret| Proof::claim(path[i].id(), k, &f.label, &CHALLENGE, &STATIC_KEY);
        // the expected reply: refused (none), else the step sent (Step, or Opened with the head)
        let cases = [
            (proof(250), None),
            (claim_at(400, &claim), None),
            (claim_at(500, &secret(241)), None),
            // secret(11) is step 10's sync key, last at step 810
            (proof(11), Some(811)),
            (claim_at(500, &claim), Some(501)),
            (proof(200), Some(999)),
        ];
        for (n, (pr, want)) in cases.into_iter().enumerate() {
            let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
            c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
            for round in 0..3u32 {
                store.step_reads.set(0);
                let open = Message::Open { id: 1 + round, label: f.label, proof: pr.clone() };
                let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&open.encode())));
                let m = reply(&out);
                let ok = match (&m, want) {
                    (Message::Error { code, .. }, None) => *code == Code::REFUSED,
                    (Message::Step { step, .. }, Some(i)) => *step == path[i] && i < 999,
                    (Message::Opened { head, .. }, Some(999)) => *head == path[999],
                    _ => false,
                };
                assert!(ok, "case {n}: {m:?}");
                assert!(store.step_reads.get() <= 1, "case {n}: {} step reads", store.step_reads.get());
            }
        }
    }

    // spec/sync.md §5 (Open): the index-based Open answers as the former scan of the path did,
    // on paths whose sync keys repeat (re-used after rotation): a sync key opens at the head, else
    // gets the child of the newest step registering it; a claim needs its step on the path and V
    // in its held set, then opens at the head or gets the step's child
    #[test]
    fn open_matches_path_scan() {
        use crate::store::tests::{path, secret};
        let f = Fixture::new(0x10);
        for seed in 0..24u64 {
            let r = |i: usize, k: u64| osis_base::hash::hash(&[seed.to_le_bytes(), (i as u64).to_le_bytes(), k.to_le_bytes()].concat())[0];
            let n = 1 + r(0, 9) as usize % 24;
            let pool = 1 + seed as u8 % 4;
            let path = path(n, |i, role| 1 + (r(i, role as u64) % pool));
            let mut store = MemoryLabelStore::new([1; 32]);
            let claim = secret(240);
            let held: Vec<bool> = (0..n).map(|i| r(i, 7) % 3 == 0).collect();
            for (i, s) in path.iter().enumerate() {
                let set = held[i].then(|| ClaimSet { claims: vec![claim.verifying_key().to_bytes()], entries: BTreeMap::new() });
                store.push_step(&f.label, s.clone(), set).unwrap();
            }
            // the former rule over the whole path: Some((i, opened)) = Opened with path[i] (the
            // head), else Step with path[i] (the matched step's child, the head included)
            let child = |i: usize| (i + 1 < n).then_some((i + 1, false));
            let mut cases: Vec<(Proof, Option<(usize, bool)>)> = Vec::new();
            for k in 1..=pool + 1 {
                let want = path.iter().rposition(|s| s.keys.sync == secret(k).verifying_key()).and_then(|i| if i + 1 == n { Some((i, true)) } else { child(i) });
                cases.push((Proof::sync(&secret(k), &f.label, &CHALLENGE, &STATIC_KEY), want));
            }
            for i in 0..n {
                for (key, ok) in [(&claim, held[i]), (&secret(241), false)] {
                    let want = if !ok { None } else if i + 1 == n { Some((i, true)) } else { child(i) };
                    cases.push((Proof::claim(path[i].id(), key, &f.label, &CHALLENGE, &STATIC_KEY), want));
                }
            }
            cases.push((Proof::claim(StepId([7; 32]), &claim, &f.label, &CHALLENGE, &STATIC_KEY), None));
            for (pr, want) in cases {
                let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
                c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
                let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Message::Open { id: 1, label: f.label, proof: pr.clone() }.encode())));
                let m = reply(&out);
                let ok = match (&m, want) {
                    (Message::Error { code, .. }, None) => *code == Code::REFUSED,
                    (Message::Step { step, .. }, Some((i, false))) => *step == path[i],
                    (Message::Opened { head, .. }, Some((i, true))) => *head == path[i],
                    _ => false,
                };
                let at = |s: &Step| path.iter().position(|p| p == s);
                let got = match &m {
                    Message::Step { step, .. } => format!("step {:?}", at(step)),
                    Message::Opened { head, .. } => format!("opened {:?}", at(head)),
                    m => format!("{m:?}"),
                };
                assert!(ok, "seed {seed} n {n}: {pr:?} gave {got}, want {want:?}");
            }
        }
    }

    // spec/wire.md §11.2 (Path): pages of at most MAX_PATH_STEPS steps from `after` (none:
    // genesis) give the whole path in order, `more` until the head; each page reads only the
    // steps it sends; `after` the head gives an empty page, a step not on the path is refused
    #[test]
    fn path_pages_by_child_index() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        let path = crate::store::tests::path(2 * MAX_PATH_STEPS + 7, |i, r| 1 + ((i + r) % 200) as u8);
        for s in &path {
            store.push_step(&f.label, s.clone(), None).unwrap();
        }
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
        c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        let head_key = crate::store::tests::secret(1 + ((path.len() - 1) % 200) as u8);
        let open = Message::Open { id: 1, label: f.label, proof: Proof::sync(&head_key, &f.label, &CHALLENGE, &STATIC_KEY) };
        assert!(matches!(reply(&c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&open.encode())))), Message::Opened { .. }));
        let ask = |c: &mut ServerConnection, store: &mut MemoryLabelStore, id: u32, after: Option<StepId>| {
            store.step_reads.set(0);
            let out = c.handle(0, store, ServerInput::Bytes(encode_frame(&Message::Path { id, label: f.label, after }.encode())));
            (reply(&out), store.step_reads.get())
        };
        let (mut got, mut after, mut id) = (Vec::new(), None, 2);
        loop {
            let (Message::PathReply { steps, more, .. }, reads) = ask(&mut c, &mut store, id, after) else { panic!() };
            assert_eq!(reads, steps.len() as u64);
            assert!(steps.len() <= MAX_PATH_STEPS);
            after = steps.last().map(|s| s.id());
            got.extend(steps);
            id += 1;
            if !more {
                break;
            }
        }
        assert_eq!(got, path);
        assert_eq!(id, 5, "three pages");
        assert!(matches!(ask(&mut c, &mut store, 9, after).0, Message::PathReply { steps, more: false, .. } if steps.is_empty()));
        assert!(matches!(ask(&mut c, &mut store, 10, Some(StepId([7; 32]))).0, Message::Error { code: Code::REFUSED, .. }));
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
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
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

    // spec/sync.md §5 (Delete): a signed delete by level checks the blob's prefix
    // (`blob_prefix`), never reading the whole blob (up to MAX_BLOB per item)
    #[test]
    fn delete_by_level_reads_prefix_only() {
        let f = Fixture::new(0x10);
        let mut store = MemoryLabelStore::new([1; 32]);
        store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        let dk = osis_crypto::DeleteSecret::derive(&osis_crypto::Secret32::from_bytes([0x7a; 32]));
        let commit = osis_crypto::commitment(2, &dk.verifying_key(), &[1; 16], &[0x7e; 16]).unwrap();
        let e = f.entry(Fixture::blob_with(1, None, vec![commit]));
        let blob_id = osis_label::blob_id(&e.blob);
        let mut c = ServerConnection::new(ServerConfig { static_key: STATIC_KEY, challenge: CHALLENGE, tie: 0 });
        c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Hello::new(0, [2; 32]).encode())));
        c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Message::Upload { id: 1, label: f.label, entries: vec![e] }.encode())));
        let item = DeleteItem::sign_by(&f.sync, &dk, 2, &[1; 16], &[0x7e; 16], &f.label, blob_id, None).unwrap();
        let wrong = DeleteItem::sign_by(&f.sync, &dk, 2, &[2; 16], &[0x7e; 16], &f.label, blob_id, None).unwrap();
        store.blob_reads.set(0);
        let out = c.handle(0, &mut store, ServerInput::Bytes(encode_frame(&Message::Delete { id: 2, label: f.label, items: vec![wrong, item] }.encode())));
        let Message::Status { codes, .. } = reply(&out) else { panic!("{out:?}") };
        assert_eq!(codes, vec![Code::REFUSED, Code::OK]);
        assert_eq!(store.blob_reads.get(), 0);
        assert!(store.entry(&f.label, &blob_id).unwrap().is_none());
    }
}
