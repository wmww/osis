//! Client side of one connection (spec/sync.md §5-§9, spec/wire.md §11): a sans-I/O state machine
//! that turns commands into requests (batched under the caps, paged replies followed up), and
//! replies and pushes into events. Policy (what to sync, verify, fetch or upload) stays
//! with the node.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame, send};
use crate::hello::{Hello, OFFSET_DIAGNOSTIC_MS, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
use crate::msg::*;
use crate::rbsr::Reconciler;
use crate::server::REPLY_BUDGET;
use osis_base::format::MAX_MESSAGE;
use osis_base::{BlobId, LabelId};
use osis_crypto::SigningSecret;
use std::collections::{BTreeMap, VecDeque};

/// Pings sent when the session starts (clock offset samples, spec/sync.md §6).
pub const INITIAL_PINGS: usize = 3;
/// Interval of later pings.
pub const PING_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// Requests in flight with nothing moving this long (no byte received, none of ours taken by the
/// transport, `ClientInput::Sent`) close the session; the node redials (spec/sync.md §6). Liveness
/// only, any link speed passes: 0 closes every session at once, infinity keeps a hung peer.
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
/// Reply allowance of a request whose reply holds no events, items, steps or ranges (Status of
/// 1024 codes and a head step, Opened, Budget, Pong, Ok, Error).
pub const SMALL_REPLY: usize = MAX_MESSAGE - REPLY_BUDGET;
/// Clock samples kept.
const MAX_SAMPLES: usize = 9;
/// Round trips before a clock offset is reported (one outlier among three moves nothing).
const MIN_PONGS: usize = 3;
/// Reconcile messages one reconciliation may send before it is abandoned (a misbehaving peer).
pub const MAX_RECONCILE_MESSAGES: usize = 4096;
/// IDs one reconciliation may find missing on either side, and ranges it may have queued, before
/// it is abandoned (a responder splitting without end; about 64 MB and 13 MB at most).
pub const MAX_RECONCILE_IDS: usize = 1 << 21;
pub const MAX_RECONCILE_QUEUED: usize = 1 << 17;
/// Sync pages in a row without events before the exchange is abandoned (a peer handing out
/// fresh cursors and nothing else).
pub const MAX_EMPTY_PAGES: u32 = 16;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// The peer's static key (a server's address key), bound by open signatures.
    pub peer_static_key: [u8; 32],
    /// This side's Hello challenge: 32 random bytes per connection.
    pub challenge: [u8; 32],
}

/// The key an Open is signed with (spec/sync.md §5).
#[derive(Clone)]
pub enum OpenKey {
    Sync(SigningSecret),
    Claim { step: StepId, key: SigningSecret },
    /// A key actor's signing key (its static entry).
    Static(SigningSecret),
    /// A node's dialable key, to a member peer (spec/sync.md §5).
    Member(SigningSecret),
}

/// What the node asks of the session.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)] // steps carry parsed keys; boxing buys nothing here
pub enum Command {
    Open { label: LabelId, key: OpenKey },
    Register { label: LabelId, step: Step, claim_set: Option<ClaimSet> },
    /// The registration path after `after` (from the genesis step when none), all pages.
    Path { label: LabelId, after: Option<StepId> },
    /// Cursor sync (none: replay the label's live entries) with our new stamped entries and the
    /// IDs gained from other sources since the cursor. Over `MAX_GAINED` gained IDs falls back to
    /// reconciliation (`NeedReconcile`); entries beyond one message go as Uploads.
    Sync { label: LabelId, cursor: Option<Cursor>, inline_limit: u64, entries: Vec<Entry>, gained: Vec<BlobId> },
    /// Range reconciliation of our live IDs for the label against the peer's.
    Reconcile { label: LabelId, ids: Vec<BlobId> },
    Fetch { label: LabelId, ids: Vec<BlobId> },
    Upload { label: LabelId, entries: Vec<Entry> },
    Deposit { label: LabelId, blob: Vec<u8>, wrap: Wrap, sig: Signature },
    Delete { label: LabelId, items: Vec<DeleteItem> },
    Subscribe { labels: Vec<LabelId> },
    Unsubscribe { labels: Vec<LabelId> },
    /// Stop following a label's Path pages (the node no longer wants them).
    StopPath { label: LabelId },
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
    /// The transport took bytes this session wrote since the last `Sent` (progress for
    /// `STALL_TIMEOUT_MS`; a driver may report it only when the timer fires).
    Sent,
    Command(Command),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    /// Hellos exchanged; commands given earlier are sent now.
    Ready { version: u64 },
    /// Peer clock minus ours; `diagnostic` above `OFFSET_DIAGNOSTIC_MS`.
    ClockOffset { offset_ms: i64, diagnostic: bool },
    Opened { label: LabelId, head: Step, entry_box: Option<SecretBox> },
    /// An Open matched a superseded step: its child on the path. Verify it under that step's
    /// delete key before use (`Step::verify_child`).
    Step { label: LabelId, step: Step },
    Registered { label: LabelId },
    /// A Register was not accepted: the server's head.
    Head { label: LabelId, head: Step },
    PathSteps { label: LabelId, steps: Vec<Step>, more: bool },
    /// Status per entry of an Upload or a Sync, with the head when a code is 9.
    EntryStatus { label: LabelId, blob_ids: Vec<BlobId>, codes: Vec<Code>, head: Option<Step> },
    DeleteStatus { label: LabelId, blob_ids: Vec<BlobId>, codes: Vec<Code>, head: Option<Step> },
    Budget { label: LabelId, blob_id: BlobId, code: Code, entries_left: u64, bytes_left: u64, head: Option<Step> },
    /// Log events of a Sync reply or a Push, in order; then keep `cursor` for the label (none:
    /// a bundle, a peer with no cursor, a Push while a Sync of the label runs).
    Events { label: LabelId, events: Vec<Event>, cursor: Option<Cursor> },
    /// Gained IDs the peer lacks: upload them.
    Want { label: LabelId, ids: Vec<BlobId> },
    /// A Sync ran through its last page.
    Synced { label: LabelId },
    /// Cursor sync cannot proceed (cursor invalid, or too many gained IDs): reconcile. Entries the
    /// Sync carried have been sent as an Upload.
    NeedReconcile { label: LabelId },
    /// Range reconciliation done: IDs the peer holds that we lack, and the reverse.
    Reconciled { label: LabelId, need: Vec<BlobId>, have: Vec<BlobId> },
    Fetched { label: LabelId, items: Vec<Fetched> },
    Subscribed { labels: Vec<LabelId>, codes: Vec<Code> },
    /// A request was answered by Error, or could not be sent (code 2: a delete item whose time
    /// cannot be encoded).
    Refused { label: Option<LabelId>, kind: Request, code: Code },
    /// The peer broke a protocol rule (diagnostic); a paged exchange it broke is abandoned.
    PeerError(Error),
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
    Open,
    Register,
    Path,
    Upload,
    Deposit,
    Delete,
    Sync,
    Reconcile,
    Fetch,
    Subscribe,
    Unsubscribe,
}

#[derive(Clone, Debug)]
enum Pending {
    Ping { sent: u64 },
    Open(LabelId),
    Register(LabelId),
    Path(LabelId),
    /// A Path exchange the node stopped: its reply is dropped.
    PathStopped(LabelId),
    Upload(LabelId, Vec<BlobId>),
    Deposit(LabelId, BlobId),
    Delete(LabelId, Vec<BlobId>),
    /// `gained`: the IDs the request listed (a Want may name only those); `empty`: pages in a
    /// row without events before this one.
    Sync { label: LabelId, cursor: Option<Cursor>, entries: Vec<Entry>, inline_limit: u64, gained: Vec<BlobId>, empty: u32 },
    Reconcile(LabelId, u64),
    Fetch(LabelId, Vec<BlobId>),
    Subscribe(Vec<LabelId>),
    Unsubscribe,
}

impl Pending {
    fn label(&self) -> Option<LabelId> {
        match self {
            Pending::Open(l) | Pending::Register(l) | Pending::Path(l) | Pending::PathStopped(l) | Pending::Upload(l, _) | Pending::Deposit(l, _) | Pending::Delete(l, _) | Pending::Reconcile(l, _) | Pending::Fetch(l, _) => Some(*l),
            Pending::Sync { label, .. } => Some(*label),
            Pending::Ping { .. } | Pending::Subscribe(_) | Pending::Unsubscribe => None,
        }
    }

    fn kind(&self) -> Request {
        match self {
            Pending::Ping { .. } => Request::Ping,
            Pending::Open(_) => Request::Open,
            Pending::Register(_) => Request::Register,
            Pending::Path(_) | Pending::PathStopped(_) => Request::Path,
            Pending::Upload(..) => Request::Upload,
            Pending::Deposit(..) => Request::Deposit,
            Pending::Delete(..) => Request::Delete,
            Pending::Sync { .. } => Request::Sync,
            Pending::Reconcile(..) => Request::Reconcile,
            Pending::Fetch(..) => Request::Fetch,
            Pending::Subscribe(_) => Request::Subscribe,
            Pending::Unsubscribe => Request::Unsubscribe,
        }
    }
}

impl Pending {
    /// The most reply bytes the peer may queue for this request (spec/sync.md §6).
    fn allowance(&self) -> usize {
        match self {
            Pending::Path(_) | Pending::PathStopped(_) | Pending::Sync { .. } | Pending::Reconcile(..) | Pending::Fetch(..) => MAX_MESSAGE,
            _ => SMALL_REPLY,
        }
    }
}

/// A request: its `cost` against `WINDOW` once it left the queue, and the command it serves
/// (`ClientSession::commands`; `NO_COMMAND` for pings).
struct Req {
    cost: Option<usize>,
    cmd: u64,
    p: Pending,
}

/// The command tag of a request no command asked for (pings).
const NO_COMMAND: u64 = u64::MAX;

struct Rec {
    r: Reconciler,
    own: Vec<BlobId>,
    sent: usize,
}

pub struct ClientSession {
    cfg: ClientConfig,
    decoder: FrameDecoder,
    hello_sent: u64,
    peer: Option<Hello>,
    closed: bool,
    next_id: Id,
    /// Requests not yet answered: sent, or waiting in `waiting` for room in the window.
    pending: BTreeMap<Id, Req>,
    /// Requests not yet sent, in order.
    waiting: VecDeque<(Id, Message)>,
    /// Bytes in flight (costs of the sent requests of `pending`).
    in_flight: usize,
    /// Last progress (a byte received, `Sent`, the first request going out after none was in
    /// flight).
    progress: u64,
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
    recs: BTreeMap<LabelId, Rec>,
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
            waiting: VecDeque::new(),
            in_flight: 0,
            progress: 0,
            now: 0,
            next_ping: 0,
            timer: 0,
            queued: VecDeque::new(),
            commands: 0,
            tag: NO_COMMAND,
            open: BTreeMap::new(),
            samples: VecDeque::new(),
            pongs: 0,
            recs: BTreeMap::new(),
        }
    }

    /// Whether the Hellos have been exchanged.
    pub fn is_ready(&self) -> bool {
        self.peer.is_some()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Requests not yet answered (sent or waiting to be sent).
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }

    /// Requests waiting for room in the window (`WINDOW`).
    pub fn unsent(&self) -> usize {
        self.waiting.len()
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
        self.in_flight
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
                    self.progress = now;
                }
                self.decoder.push(&b);
                while !self.closed {
                    // the peer's first frame is its Hello (spec/wire.md §11.1)
                    self.decoder.set_max(if self.peer.is_some() { osis_base::format::MAX_MESSAGE } else { crate::frame::MAX_HELLO_BYTES });
                    match self.decoder.next_frame() {
                        Ok(Some(body)) => self.frame(now, &body, &mut out),
                        Ok(None) => break,
                        Err(e) => {
                            event(&mut out, ClientEvent::PeerError(e));
                            self.close(&mut out);
                        }
                    }
                }
            }
            ClientInput::Timer => {
                self.timer = 0;
                if self.in_flight > 0 && self.progress.saturating_add(STALL_TIMEOUT_MS) <= now {
                    event(&mut out, ClientEvent::PeerError(Error::Timeout));
                    self.close(&mut out);
                    return out;
                }
                if self.is_ready() && self.next_ping <= now {
                    self.request(|id| Message::Ping { id, wall_ms: now }, Pending::Ping { sent: now });
                    self.next_ping = now.saturating_add(PING_INTERVAL_MS);
                }
            }
            ClientInput::Sent => self.progress = now,
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
        out
    }

    /// Sends waiting requests while the window has room (one always goes when none is in flight).
    fn flush(&mut self, out: &mut Vec<ClientOutput>) {
        while !self.closed && self.in_flight < WINDOW.max(1) {
            let Some((id, mut msg)) = self.waiting.pop_front() else { break };
            let Some(req) = self.pending.get_mut(&id) else { continue };
            if let (Pending::Ping { sent }, Message::Ping { wall_ms, .. }) = (&mut req.p, &mut msg) {
                // the clock sample starts when the ping leaves
                *sent = self.now;
                *wall_ms = self.now;
            }
            let frame = encode_frame(&msg.encode());
            let cost = frame.len().saturating_add(req.p.allowance());
            if self.in_flight == 0 {
                self.progress = self.now;
            }
            req.cost = Some(cost);
            self.in_flight = self.in_flight.saturating_add(cost);
            out.push(ClientOutput::Send(frame));
        }
    }

    /// Asks for the timer at the next ping or request deadline, if that changed.
    fn arm(&mut self, out: &mut Vec<ClientOutput>) {
        if self.closed || !self.is_ready() {
            return;
        }
        let mut t = self.next_ping;
        if self.in_flight > 0 {
            t = t.min(self.progress.saturating_add(STALL_TIMEOUT_MS));
        }
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
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id != 0 && !self.pending.contains_key(&self.next_id) {
                break;
            }
        }
        let id = self.next_id;
        self.pending.insert(id, Req { cost: None, cmd: self.tag, p: pending });
        *self.open.entry(self.tag).or_insert(0) += 1;
        self.waiting.push_back((id, msg(id)));
    }

    fn command(&mut self, c: Command, out: &mut Vec<ClientOutput>) {
        match c {
            Command::Open { label, key } => {
                let Some(peer) = &self.peer else { return };
                let (ch, sk) = (peer.challenge, self.cfg.peer_static_key);
                let proof = match &key {
                    OpenKey::Sync(k) => Proof::sync(k, &label, &ch, &sk),
                    OpenKey::Claim { step, key } => Proof::claim(*step, key, &label, &ch, &sk),
                    OpenKey::Static(k) => Proof::static_entry(k, &label, &ch, &sk),
                    OpenKey::Member(k) => Proof::member(k, &label, &ch, &sk),
                };
                self.request(|id| Message::Open { id, label, proof }, Pending::Open(label));
            }
            Command::Register { label, step, claim_set } => self.request(|id| Message::Register { id, label, step, claim_set }, Pending::Register(label)),
            Command::Path { label, after } => self.request(|id| Message::Path { id, label, after }, Pending::Path(label)),
            Command::Sync { label, cursor, inline_limit, entries, gained } => {
                if gained.len() > MAX_GAINED {
                    self.upload(label, entries);
                    event(out, ClientEvent::NeedReconcile { label });
                    return;
                }
                let mut budget = REPLY_BUDGET.saturating_sub(40 * gained.len());
                let mut inline = Vec::new();
                let mut rest = Vec::new();
                for e in entries {
                    let size = entry_size(&e);
                    if rest.is_empty() && size <= budget {
                        budget -= size;
                        inline.push(e);
                    } else {
                        rest.push(e);
                    }
                }
                let pending = Pending::Sync { label, cursor, entries: inline.clone(), inline_limit, gained: gained.clone(), empty: 0 };
                self.request(|id| Message::Sync { id, label, cursor, inline_limit, entries: inline, gained }, pending);
                self.upload(label, rest);
            }
            Command::Reconcile { label, mut ids } => {
                ids.sort();
                ids.dedup();
                self.recs.insert(label, Rec { r: Reconciler::new(&ids), own: ids, sent: 0 });
                self.reconcile_send(label, out);
            }
            Command::Fetch { label, ids } => {
                for chunk in ids.chunks(MAX_ITEMS) {
                    self.request(|id| Message::Fetch { id, label, ids: chunk.to_vec() }, Pending::Fetch(label, chunk.to_vec()));
                }
            }
            Command::Upload { label, entries } => self.upload(label, entries),
            Command::Deposit { label, blob, wrap, sig } => {
                let blob_id = osis_label::blob_id(&blob);
                self.request(|id| Message::Deposit { id, label, blob, wrap, sig }, Pending::Deposit(label, blob_id));
            }
            Command::Delete { label, items } => {
                let (items, bad): (Vec<DeleteItem>, Vec<DeleteItem>) = items.into_iter().partition(|i| i.to_value().is_ok());
                if !bad.is_empty() {
                    event(out, ClientEvent::Refused { label: Some(label), kind: Request::Delete, code: Code::MALFORMED });
                }
                for chunk in items.chunks(MAX_ITEMS) {
                    let ids = chunk.iter().map(|i| i.blob).collect();
                    self.request(|id| Message::Delete { id, label, items: chunk.to_vec() }, Pending::Delete(label, ids));
                }
            }
            Command::Subscribe { labels } => {
                for chunk in labels.chunks(MAX_LABELS) {
                    self.request(|id| Message::Subscribe { id, labels: chunk.to_vec() }, Pending::Subscribe(chunk.to_vec()));
                }
            }
            Command::Unsubscribe { labels } => {
                for chunk in labels.chunks(MAX_LABELS) {
                    self.request(|id| Message::Unsubscribe { id, labels: chunk.to_vec() }, Pending::Unsubscribe);
                }
            }
            Command::StopPath { label } => {
                for r in self.pending.values_mut() {
                    if matches!(r.p, Pending::Path(l) if l == label) {
                        r.p = Pending::PathStopped(label);
                    }
                }
            }
            Command::Close => self.close(out),
        }
    }

    /// Uploads in batches within the item cap and the message size.
    fn upload(&mut self, label: LabelId, entries: Vec<Entry>) {
        let mut batch: Vec<Entry> = Vec::new();
        let mut used = 0;
        for e in entries {
            let size = entry_size(&e);
            if !batch.is_empty() && (batch.len() == MAX_ITEMS || used + size > REPLY_BUDGET) {
                self.upload_batch(label, std::mem::take(&mut batch));
                used = 0;
            }
            used += size;
            batch.push(e);
        }
        if !batch.is_empty() {
            self.upload_batch(label, batch);
        }
    }

    fn upload_batch(&mut self, label: LabelId, entries: Vec<Entry>) {
        let ids = entries.iter().map(|e| osis_label::blob_id(&e.blob)).collect();
        self.request(|id| Message::Upload { id, label, entries }, Pending::Upload(label, ids));
    }

    fn reconcile_send(&mut self, label: LabelId, out: &mut Vec<ClientOutput>) {
        let mut batches = Vec::new();
        let Some(rec) = self.recs.get_mut(&label) else { return };
        while let Some(b) = rec.r.next_batch() {
            batches.push(b);
        }
        rec.sent += batches.len();
        let found = rec.r.need.len().saturating_add(rec.r.have.len());
        if rec.sent > MAX_RECONCILE_MESSAGES || found > MAX_RECONCILE_IDS || rec.r.queued() > MAX_RECONCILE_QUEUED {
            self.recs.remove(&label);
            event(out, ClientEvent::Refused { label: Some(label), kind: Request::Reconcile, code: Code::REFUSED });
            return;
        }
        if rec.r.is_done() {
            if let Some(rec) = self.recs.remove(&label) {
                event(out, ClientEvent::Reconciled { label, need: rec.r.need.into_iter().collect(), have: rec.r.have.into_iter().collect() });
            }
            return;
        }
        for (token, ranges) in batches {
            self.request(|id| Message::Reconcile { id, label, ranges }, Pending::Reconcile(label, token));
        }
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
            Message::Push { label, events, cursor } => {
                // while a Sync of the label runs (a replay above all) its pages still bring
                // entries from before the push: keeping the push's cursor would skip them for
                // good if the connection ended first; likewise while a reconciliation runs (the
                // Sync from the kept cursor follows it)
                let syncing = self.pending.values().any(|r| matches!(r.p, Pending::Sync { label: l, .. } | Pending::Reconcile(l, _) if l == label));
                event(out, ClientEvent::Events { label, events, cursor: (!syncing).then_some(cursor) })
            }
            m if m.is_request() => send(out, Message::Error { id: m.id(), code: Code::UNSUPPORTED }),
            m => self.reply(now, m, out),
        }
    }

    fn reply(&mut self, now: u64, m: Message, out: &mut Vec<ClientOutput>) {
        let Some(Req { cost: Some(cost), .. }) = self.pending.get(&m.id()) else {
            event(out, ClientEvent::PeerError(Error::Malformed("reply to no request")));
            return;
        };
        self.in_flight = self.in_flight.saturating_sub(*cost);
        let Some(Req { p: pending, cmd, .. }) = self.pending.remove(&m.id()) else { return };
        if let Some(n) = self.open.get_mut(&cmd) {
            *n -= 1;
            if *n == 0 {
                self.open.remove(&cmd);
            }
        }
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
            (Pending::Sync { label, entries, .. }, M::Error { code: Code::CURSOR_INVALID, .. }) => {
                // The entries were not taken: send them on their own.
                self.upload(label, entries);
                event(out, E::NeedReconcile { label });
            }
            (Pending::Reconcile(label, _), M::Error { code, .. }) => {
                if self.recs.remove(&label).is_some() {
                    event(out, E::Refused { label: Some(label), kind: Request::Reconcile, code });
                }
            }
            (p, M::Error { code, .. }) => event(out, E::Refused { label: p.label(), kind: p.kind(), code }),
            (Pending::Open(label), M::Opened { head, entry_box, .. }) => event(out, E::Opened { label, head, entry_box }),
            (Pending::Open(label), M::Step { step, .. }) => event(out, E::Step { label, step }),
            (Pending::Register(label), M::Ok { .. }) => event(out, E::Registered { label }),
            (Pending::Register(label), M::Step { step, .. }) => event(out, E::Head { label, head: step }),
            (Pending::PathStopped(_), M::PathReply { .. }) => {}
            (Pending::Path(label), M::PathReply { steps, more, .. }) => {
                let last = steps.last().map(Step::id);
                event(out, E::PathSteps { label, steps, more });
                match (more, last) {
                    (true, Some(after)) => self.request(|id| Message::Path { id, label, after: Some(after) }, Pending::Path(label)),
                    (true, None) => event(out, E::PeerError(Error::Malformed("path page without steps"))),
                    _ => {}
                }
            }
            (Pending::Upload(label, blob_ids), M::Status { codes, head, .. }) if codes.len() == blob_ids.len() => event(out, E::EntryStatus { label, blob_ids, codes, head }),
            (Pending::Delete(label, blob_ids), M::Status { codes, head, .. }) if codes.len() == blob_ids.len() => event(out, E::DeleteStatus { label, blob_ids, codes, head }),
            (Pending::Subscribe(labels), M::Status { codes, .. }) if codes.len() == labels.len() => event(out, E::Subscribed { labels, codes }),
            (Pending::Unsubscribe, M::Ok { .. }) => {}
            (Pending::Deposit(label, blob_id), M::Budget { code, entries_left, bytes_left, head, .. }) => event(out, E::Budget { label, blob_id, code, entries_left, bytes_left, head }),
            (Pending::Sync { label, cursor: asked, entries, inline_limit, gained, empty }, M::SyncReply { events, want, codes, cursor, more, .. }) if codes.len() == entries.len() => {
                if !entries.is_empty() {
                    let blob_ids = entries.iter().map(|e| osis_label::blob_id(&e.blob)).collect();
                    event(out, E::EntryStatus { label, blob_ids, codes, head: None });
                }
                let empty = if events.is_empty() { empty.saturating_add(1) } else { 0 };
                let stuck = more && events.is_empty() && (asked == Some(cursor) || empty >= MAX_EMPTY_PAGES);
                event(out, E::Events { label, events, cursor: Some(cursor) });
                // a Want answers the gained IDs this Sync listed, nothing else (spec/wire.md §11.2)
                let asked_for: std::collections::BTreeSet<BlobId> = gained.into_iter().collect();
                let n = want.len();
                let want: Vec<BlobId> = want.into_iter().filter(|b| asked_for.contains(b)).collect();
                if want.len() < n {
                    event(out, E::PeerError(Error::Malformed("want names an ID the sync did not list")));
                }
                if !want.is_empty() {
                    event(out, E::Want { label, ids: want });
                }
                if stuck {
                    event(out, E::PeerError(Error::Malformed("sync page without progress")));
                } else if more {
                    let next = |id| Message::Sync { id, label, cursor: Some(cursor), inline_limit, entries: vec![], gained: vec![] };
                    self.request(next, Pending::Sync { label, cursor: Some(cursor), entries: vec![], inline_limit, gained: vec![], empty });
                } else {
                    event(out, E::Synced { label });
                }
            }
            (Pending::Reconcile(label, token), M::ReconcileReply { ranges, .. }) => {
                if let Some(rec) = self.recs.get_mut(&label) {
                    rec.r.on_reply(token, &rec.own, &ranges);
                    self.reconcile_send(label, out);
                }
            }
            (Pending::Fetch(label, ids), M::FetchReply { items, .. }) => {
                let n = items.len();
                let consistent = n <= ids.len() && items.iter().zip(&ids).all(|(f, i)| f.blob_id == *i);
                if !consistent {
                    event(out, E::PeerError(Error::Malformed("fetch reply items")));
                    return;
                }
                event(out, E::Fetched { label, items });
                let rest: Vec<BlobId> = ids.get(n..).unwrap_or(&[]).to_vec();
                if n > 0 && !rest.is_empty() {
                    self.request(|id| Message::Fetch { id, label, ids: rest.clone() }, Pending::Fetch(label, rest.clone()));
                } else if !rest.is_empty() {
                    event(out, E::Refused { label: Some(label), kind: Request::Fetch, code: Code::TOO_LARGE });
                }
            }
            (_, _) => event(out, E::PeerError(Error::Malformed("reply of the wrong kind"))),
        }
    }
}

fn event(out: &mut Vec<ClientOutput>, e: ClientEvent) {
    out.push(ClientOutput::Event(e));
}
