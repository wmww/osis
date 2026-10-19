//! Client side of one connection (spec/sync.md §5-§9, spec/wire.md §11): a sans-I/O state machine
//! that turns commands into requests (batched under the caps, paged replies followed up), and
//! replies, pushes and signals into events. Policy (what to sync, verify, fetch or upload) stays
//! with the node.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame};
use crate::hello::{Hello, OFFSET_DIAGNOSTIC_MS, OffsetSample, PROTOCOL_VERSION, estimate_offset, negotiate};
use crate::msg::*;
use crate::rbsr::Reconciler;
use crate::server::REPLY_BUDGET;
use osis_core::{BlobId, LabelId};
use osis_crypto::SigningSecret;
use std::collections::{BTreeMap, VecDeque};

/// Pings sent when the session starts (clock offset samples, spec/sync.md §6).
pub const INITIAL_PINGS: usize = 3;
/// Interval of later pings.
pub const PING_INTERVAL_MS: u64 = 5 * 60 * 1000;
/// Clock samples kept.
const MAX_SAMPLES: usize = 9;
/// Reconcile messages one reconciliation may send before it is abandoned (a misbehaving peer).
pub const MAX_RECONCILE_MESSAGES: usize = 4096;

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
    Claim { step_id: [u8; 32], key: SigningSecret },
    /// A key actor's signing key (its static entry).
    Static(SigningSecret),
}

/// What the node asks of the session.
#[derive(Clone)]
pub enum Command {
    Open { label: LabelId, key: OpenKey },
    Register { label: LabelId, step: Vec<u8>, claim_set: Option<Vec<u8>> },
    /// The registration path after `after` (from the genesis step when none), all pages.
    Path { label: LabelId, after: Option<[u8; 32]> },
    /// Cursor sync (none: replay the label's live entries) with our new stamped entries and the
    /// IDs gained from other sources since the cursor. Over `MAX_GAINED` gained IDs falls back to
    /// reconciliation (`NeedReconcile`); entries beyond one message go as Uploads.
    Sync { label: LabelId, cursor: Option<Cursor>, inline_limit: u64, entries: Vec<Entry>, gained: Vec<BlobId> },
    /// Range reconciliation of our live IDs for the label against the peer's.
    Reconcile { label: LabelId, ids: Vec<BlobId> },
    Fetch { label: LabelId, ids: Vec<BlobId> },
    Upload { label: LabelId, entries: Vec<Entry> },
    Deposit { label: LabelId, blob: Vec<u8>, wrap: Wrap, sig: Sig },
    Delete { label: LabelId, items: Vec<DeleteItem> },
    Subscribe { labels: Vec<LabelId> },
    Unsubscribe { labels: Vec<LabelId> },
    Signal { label: LabelId, blob: Vec<u8>, wrap: Wrap, auth: SignalAuth },
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
    Command(Command),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientEvent {
    /// Hellos exchanged; commands given earlier are sent now.
    Ready { version: u64 },
    /// Peer clock minus ours; `diagnostic` above `OFFSET_DIAGNOSTIC_MS`.
    ClockOffset { offset_ms: i64, diagnostic: bool },
    Opened { label: LabelId, head: Vec<u8>, entry_box: Option<Vec<u8>> },
    /// An Open matched a superseded step: its child on the path. Verify it under that step's
    /// delete key before use.
    Step { label: LabelId, step: Vec<u8> },
    Registered { label: LabelId },
    /// A Register was not accepted: the server's head.
    Head { label: LabelId, head: Vec<u8> },
    PathSteps { label: LabelId, steps: Vec<Vec<u8>>, more: bool },
    /// Status per entry of an Upload or a Sync, with the head when a code is 9.
    EntryStatus { label: LabelId, blob_ids: Vec<BlobId>, codes: Vec<Code>, head: Option<Vec<u8>> },
    DeleteStatus { label: LabelId, blob_ids: Vec<BlobId>, codes: Vec<Code>, head: Option<Vec<u8>> },
    Budget { label: LabelId, blob_id: BlobId, code: Code, entries_left: u64, bytes_left: u64, head: Option<Vec<u8>> },
    /// Log events of a Sync reply or a Push, in order; then keep `cursor` for the label (none:
    /// a bundle, a peer with no cursor).
    Events { label: LabelId, events: Vec<Event>, cursor: Option<Cursor> },
    /// Gained IDs the peer lacks: upload them.
    Want { label: LabelId, ids: Vec<BlobId> },
    /// A Sync ran through its last page.
    Synced { label: LabelId },
    /// Cursor sync cannot proceed (cursor invalid, or too many gained IDs): reconcile.
    NeedReconcile { label: LabelId },
    /// Range reconciliation done: IDs the peer holds that we lack, and the reverse.
    Reconciled { label: LabelId, need: Vec<BlobId>, have: Vec<BlobId> },
    Fetched { label: LabelId, items: Vec<Fetched> },
    Subscribed { labels: Vec<LabelId>, codes: Vec<Code> },
    Signal { label: LabelId, blob: Vec<u8>, wrap: Wrap, auth: SignalAuth },
    /// A request was answered by Error (`kind`: the request's message kind).
    Refused { label: Option<LabelId>, kind: u64, code: Code },
    /// The peer broke a protocol rule (diagnostic).
    PeerError(Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug)]
enum Pending {
    Ping { sent: u64 },
    Open(LabelId),
    Register(LabelId),
    Path(LabelId),
    Upload(LabelId, Vec<BlobId>),
    Deposit(LabelId, BlobId),
    Delete(LabelId, Vec<BlobId>),
    Sync { label: LabelId, blob_ids: Vec<BlobId>, inline_limit: u64 },
    Reconcile(LabelId),
    Fetch(LabelId, Vec<BlobId>),
    Subscribe(Vec<LabelId>),
    Unsubscribe,
}

impl Pending {
    fn label(&self) -> Option<LabelId> {
        match self {
            Pending::Open(l) | Pending::Register(l) | Pending::Path(l) | Pending::Upload(l, _) | Pending::Deposit(l, _) | Pending::Delete(l, _) | Pending::Reconcile(l) | Pending::Fetch(l, _) => Some(*l),
            Pending::Sync { label, .. } => Some(*label),
            Pending::Ping { .. } | Pending::Subscribe(_) | Pending::Unsubscribe => None,
        }
    }
}

struct Rec {
    r: Reconciler,
    own: Vec<BlobId>,
    outstanding: usize,
    sent: usize,
}

pub struct ClientSession {
    cfg: ClientConfig,
    decoder: FrameDecoder,
    hello_sent: u64,
    peer: Option<Hello>,
    closed: bool,
    next_id: Id,
    pending: BTreeMap<Id, (u64, Pending)>,
    queued: VecDeque<Command>,
    samples: VecDeque<OffsetSample>,
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
            queued: VecDeque::new(),
            samples: VecDeque::new(),
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

    /// Requests sent and not yet answered.
    pub fn outstanding(&self) -> usize {
        self.pending.len()
    }

    pub fn handle(&mut self, now: u64, input: ClientInput) -> Vec<ClientOutput> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        match input {
            ClientInput::Start => {
                self.hello_sent = now;
                out.push(ClientOutput::Send(encode_frame(&Hello::new(now, self.cfg.challenge).encode())));
            }
            ClientInput::Bytes(b) => {
                self.decoder.push(&b);
                while !self.closed {
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
                if self.is_ready() {
                    self.request(now, &mut out, |id| Message::Ping { id, wall_ms: now }, Pending::Ping { sent: now });
                    out.push(ClientOutput::SetTimer(now.saturating_add(PING_INTERVAL_MS)));
                }
            }
            ClientInput::Command(c) => {
                if self.is_ready() {
                    self.command(now, c, &mut out);
                } else {
                    self.queued.push_back(c);
                }
            }
        }
        out
    }

    fn close(&mut self, out: &mut Vec<ClientOutput>) {
        self.closed = true;
        out.push(ClientOutput::Close);
    }

    fn request(&mut self, now: u64, out: &mut Vec<ClientOutput>, msg: impl FnOnce(Id) -> Message, pending: Pending) {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id != 0 && !self.pending.contains_key(&self.next_id) {
                break;
            }
        }
        let id = self.next_id;
        self.pending.insert(id, (now, pending));
        send(out, msg(id));
    }

    fn command(&mut self, now: u64, c: Command, out: &mut Vec<ClientOutput>) {
        match c {
            Command::Open { label, key } => {
                let Some(peer) = &self.peer else { return };
                let (challenge, sk) = (peer.challenge, self.cfg.peer_static_key);
                let sig = |k: &SigningSecret| osis_crypto::sign_open(k, &label, &challenge, &sk).0;
                let pk = |k: &SigningSecret| k.verifying_key().to_bytes();
                let proof = match &key {
                    OpenKey::Sync(k) => Proof::Sync { pk: pk(k), sig: sig(k) },
                    OpenKey::Claim { step_id, key } => Proof::Claim { step_id: *step_id, pk: pk(key), sig: sig(key) },
                    OpenKey::Static(k) => Proof::Static { pk: pk(k), sig: sig(k) },
                };
                self.request(now, out, |id| Message::Open { id, label, proof }, Pending::Open(label));
            }
            Command::Register { label, step, claim_set } => self.request(now, out, |id| Message::Register { id, label, step, claim_set }, Pending::Register(label)),
            Command::Path { label, after } => self.request(now, out, |id| Message::Path { id, label, after }, Pending::Path(label)),
            Command::Sync { label, cursor, inline_limit, entries, gained } => {
                if gained.len() > MAX_GAINED {
                    self.upload(now, label, entries, out);
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
                let blob_ids = inline.iter().map(|e| osis_crypto::blob_id(&e.blob)).collect();
                self.request(now, out, |id| Message::Sync { id, label, cursor, inline_limit, entries: inline, gained }, Pending::Sync { label, blob_ids, inline_limit });
                self.upload(now, label, rest, out);
            }
            Command::Reconcile { label, mut ids } => {
                ids.sort();
                ids.dedup();
                let rec = Rec { r: Reconciler::new(&ids), own: ids, outstanding: 0, sent: 0 };
                self.recs.insert(label, rec);
                self.reconcile_send(now, label, out);
            }
            Command::Fetch { label, ids } => {
                for chunk in ids.chunks(MAX_ITEMS) {
                    let ids = chunk.to_vec();
                    self.request(now, out, |id| Message::Fetch { id, label, ids: ids.clone() }, Pending::Fetch(label, ids.clone()));
                }
            }
            Command::Upload { label, entries } => self.upload(now, label, entries, out),
            Command::Deposit { label, blob, wrap, sig } => {
                let blob_id = osis_crypto::blob_id(&blob);
                self.request(now, out, |id| Message::Deposit { id, label, blob, wrap, sig }, Pending::Deposit(label, blob_id));
            }
            Command::Delete { label, items } => {
                for chunk in items.chunks(MAX_ITEMS) {
                    let ids = chunk.iter().map(|i| i.blob_id).collect();
                    self.request(now, out, |id| Message::Delete { id, label, items: chunk.to_vec() }, Pending::Delete(label, ids));
                }
            }
            Command::Subscribe { labels } => {
                for chunk in labels.chunks(MAX_LABELS) {
                    self.request(now, out, |id| Message::Subscribe { id, labels: chunk.to_vec() }, Pending::Subscribe(chunk.to_vec()));
                }
            }
            Command::Unsubscribe { labels } => {
                for chunk in labels.chunks(MAX_LABELS) {
                    self.request(now, out, |id| Message::Unsubscribe { id, labels: chunk.to_vec() }, Pending::Unsubscribe);
                }
            }
            Command::Signal { label, blob, wrap, auth } => send(out, Message::Signal { label, blob, wrap, auth }),
            Command::Close => self.close(out),
        }
    }

    /// Uploads in batches within the item cap and the message size.
    fn upload(&mut self, now: u64, label: LabelId, entries: Vec<Entry>, out: &mut Vec<ClientOutput>) {
        let mut batch: Vec<Entry> = Vec::new();
        let mut used = 0;
        for e in entries {
            let size = entry_size(&e);
            if !batch.is_empty() && (batch.len() == MAX_ITEMS || used + size > REPLY_BUDGET) {
                self.upload_batch(now, label, std::mem::take(&mut batch), out);
                used = 0;
            }
            used += size;
            batch.push(e);
        }
        if !batch.is_empty() {
            self.upload_batch(now, label, batch, out);
        }
    }

    fn upload_batch(&mut self, now: u64, label: LabelId, entries: Vec<Entry>, out: &mut Vec<ClientOutput>) {
        let ids = entries.iter().map(|e| osis_crypto::blob_id(&e.blob)).collect();
        self.request(now, out, |id| Message::Upload { id, label, entries }, Pending::Upload(label, ids));
    }

    fn reconcile_send(&mut self, now: u64, label: LabelId, out: &mut Vec<ClientOutput>) {
        let mut batches = Vec::new();
        let Some(rec) = self.recs.get_mut(&label) else { return };
        while let Some(b) = rec.r.next_batch() {
            batches.push(b);
        }
        rec.outstanding += batches.len();
        rec.sent += batches.len();
        let (done, over) = (rec.outstanding == 0, rec.sent > MAX_RECONCILE_MESSAGES);
        if over {
            self.recs.remove(&label);
            event(out, ClientEvent::Refused { label: Some(label), kind: 17, code: Code::REFUSED });
            return;
        }
        if done {
            if let Some(rec) = self.recs.remove(&label) {
                event(out, ClientEvent::Reconciled { label, need: rec.r.need.into_iter().collect(), have: rec.r.have.into_iter().collect() });
            }
            return;
        }
        for ranges in batches {
            self.request(now, out, |id| Message::Reconcile { id, label, ranges }, Pending::Reconcile(label));
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
            for _ in 0..INITIAL_PINGS {
                self.request(now, out, |id| Message::Ping { id, wall_ms: now }, Pending::Ping { sent: now });
            }
            out.push(ClientOutput::SetTimer(now.saturating_add(PING_INTERVAL_MS)));
            while let Some(c) = self.queued.pop_front() {
                self.command(now, c, out);
            }
            return;
        }
        let msg = match Message::decode(body) {
            Ok(m) => m,
            Err(r) => {
                event(out, ClientEvent::PeerError(r.error));
                // Only a request is answered; a broken reply or push is dropped.
                return;
            }
        };
        match msg {
            Message::Ping { id, .. } => send(out, Message::Pong { id, wall_ms: now }),
            Message::Push { label, events, cursor } => event(out, ClientEvent::Events { label, events, cursor: Some(cursor) }),
            Message::Signal { label, blob, wrap, auth } => event(out, ClientEvent::Signal { label, blob, wrap, auth }),
            m if m.is_request() => send(out, Message::Error { id: m.id(), code: Code::UNSUPPORTED }),
            m => self.reply(now, m, out),
        }
    }

    fn reply(&mut self, now: u64, m: Message, out: &mut Vec<ClientOutput>) {
        let Some((_, pending)) = self.pending.remove(&m.id()) else {
            event(out, ClientEvent::PeerError(Error::Malformed("reply to no request")));
            return;
        };
        use ClientEvent as E;
        use Message as M;
        match (pending, m) {
            (Pending::Ping { sent }, M::Pong { wall_ms, .. }) => {
                if self.samples.len() == MAX_SAMPLES {
                    self.samples.pop_front();
                }
                self.samples.push_back(OffsetSample { sent, peer: wall_ms, received: now });
                let samples: Vec<OffsetSample> = self.samples.iter().copied().collect();
                if let Some(offset_ms) = estimate_offset(&samples) {
                    event(out, E::ClockOffset { offset_ms, diagnostic: offset_ms.unsigned_abs() > OFFSET_DIAGNOSTIC_MS });
                }
            }
            (Pending::Sync { label, .. }, M::Error { code: Code::CURSOR_INVALID, .. }) => event(out, E::NeedReconcile { label }),
            (Pending::Reconcile(label), M::Error { code, .. }) => {
                if self.recs.remove(&label).is_some() {
                    event(out, E::Refused { label: Some(label), kind: 17, code });
                }
            }
            (p, M::Error { code, .. }) => {
                let kind = match &p {
                    Pending::Ping { .. } => 2,
                    Pending::Open(_) => 4,
                    Pending::Register(_) => 7,
                    Pending::Path(_) => 8,
                    Pending::Upload(..) => 10,
                    Pending::Deposit(..) => 12,
                    Pending::Delete(..) => 14,
                    Pending::Sync { .. } => 15,
                    Pending::Reconcile(_) => 17,
                    Pending::Fetch(..) => 19,
                    Pending::Subscribe(_) => 21,
                    Pending::Unsubscribe => 22,
                };
                event(out, E::Refused { label: p.label(), kind, code });
            }
            (Pending::Open(label), M::Opened { head, entry_box, .. }) => event(out, E::Opened { label, head, entry_box }),
            (Pending::Open(label), M::Step { step, .. }) => event(out, E::Step { label, step }),
            (Pending::Register(label), M::Ok { .. }) => event(out, E::Registered { label }),
            (Pending::Register(label), M::Step { step, .. }) => event(out, E::Head { label, head: step }),
            (Pending::Path(label), M::PathReply { steps, more, .. }) => {
                let last = steps.last().map(|s| osis_core::hash::hash(s));
                event(out, E::PathSteps { label, steps, more });
                if let (true, Some(after)) = (more, last) {
                    self.request(now, out, |id| Message::Path { id, label, after: Some(after) }, Pending::Path(label));
                }
            }
            (Pending::Upload(label, blob_ids), M::Status { codes, head, .. }) if codes.len() == blob_ids.len() => event(out, E::EntryStatus { label, blob_ids, codes, head }),
            (Pending::Delete(label, blob_ids), M::Status { codes, head, .. }) if codes.len() == blob_ids.len() => event(out, E::DeleteStatus { label, blob_ids, codes, head }),
            (Pending::Subscribe(labels), M::Status { codes, .. }) if codes.len() == labels.len() => event(out, E::Subscribed { labels, codes }),
            (Pending::Unsubscribe, M::Ok { .. }) => {}
            (Pending::Deposit(label, blob_id), M::Budget { code, entries_left, bytes_left, head, .. }) => event(out, E::Budget { label, blob_id, code, entries_left, bytes_left, head }),
            (Pending::Sync { label, blob_ids, inline_limit }, M::SyncReply { events, want, codes, cursor, more, .. }) if codes.len() == blob_ids.len() => {
                if !blob_ids.is_empty() {
                    event(out, E::EntryStatus { label, blob_ids, codes, head: None });
                }
                event(out, E::Events { label, events, cursor: Some(cursor) });
                if !want.is_empty() {
                    event(out, E::Want { label, ids: want });
                }
                if more {
                    let next = |id| Message::Sync { id, label, cursor: Some(cursor), inline_limit, entries: vec![], gained: vec![] };
                    self.request(now, out, next, Pending::Sync { label, blob_ids: vec![], inline_limit });
                } else {
                    event(out, E::Synced { label });
                }
            }
            (Pending::Reconcile(label), M::ReconcileReply { ranges, .. }) => {
                if let Some(rec) = self.recs.get_mut(&label) {
                    rec.outstanding = rec.outstanding.saturating_sub(1);
                    rec.r.on_reply(&rec.own, &ranges);
                    self.reconcile_send(now, label, out);
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
                    self.request(now, out, |id| Message::Fetch { id, label, ids: rest.clone() }, Pending::Fetch(label, rest.clone()));
                } else if !rest.is_empty() {
                    event(out, E::Refused { label: Some(label), kind: 19, code: Code::TOO_LARGE });
                }
            }
            (_, _) => event(out, E::PeerError(Error::Malformed("reply of the wrong kind"))),
        }
    }
}

fn send<O: From<Vec<u8>>>(out: &mut Vec<O>, msg: Message) {
    out.push(O::from(encode_frame(&msg.encode())));
}

fn event(out: &mut Vec<ClientOutput>, e: ClientEvent) {
    out.push(ClientOutput::Event(e));
}
