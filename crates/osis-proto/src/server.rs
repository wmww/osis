//! Server side of one connection (spec/sync.md §4-§9, spec/wire.md §11): a sans-I/O state machine
//! answering every request from a `LabelStore`. The driver feeds stream bytes and cross-connection
//! notices and carries out the outputs.

use crate::Error;
use crate::frame::{FrameDecoder, encode_frame};
use crate::hello::{Hello, PROTOCOL_VERSION, negotiate};
use crate::label::{self, ClaimSet, StepInfo, StepKey};
use crate::msg::*;
use crate::rbsr;
use crate::store::{LabelStore, LogRecord, Put, StoreError, StoredStep};
use osis_core::format::{MAX_BLOB, MAX_MESSAGE};
use osis_core::{BlobId, LabelId};
use osis_crypto::{Domain, Signature, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Room left in a reply for everything but its events or items.
pub const REPLY_BUDGET: usize = MAX_MESSAGE - 64 * 1024;
/// Log records read from the store per call.
const LOG_BATCH: usize = 256;

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
    /// A signal accepted on another connection: forward if subscribed.
    Signal { label: LabelId, blob: Vec<u8>, wrap: Wrap, auth: SignalAuth },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerOutput {
    /// A frame to write.
    Send(Vec<u8>),
    Close,
    /// This connection grew a label's log: deliver `ServerInput::Changed` to every connection.
    Changed(LabelId),
    /// A valid signal: deliver `ServerInput::Signal` to every other connection.
    Signal { label: LabelId, blob: Vec<u8>, wrap: Wrap, auth: SignalAuth },
    /// The peer broke a protocol rule (diagnostic).
    PeerError(Error),
    StoreError(StoreError),
}

#[derive(Clone, Copy, Debug)]
struct Sub {
    seq: u64,
    inline_limit: u64,
}

pub struct ServerConnection {
    cfg: ServerConfig,
    decoder: FrameDecoder,
    version: Option<u64>,
    closed: bool,
    opened: BTreeSet<LabelId>,
    subs: BTreeMap<LabelId, Sub>,
    /// Last complete Sync per label: its cursor sequence number and inline limit.
    synced: BTreeMap<LabelId, Sub>,
    /// Blobs whose bytes crossed this connection.
    crossed: HashSet<BlobId>,
}

type Steps = Vec<(StepInfo, Option<Vec<u8>>)>;

fn load_path(store: &dyn LabelStore, label: &LabelId) -> Result<Steps, StoreError> {
    store
        .path(label)?
        .into_iter()
        .map(|s: StoredStep| StepInfo::parse(&s.step).map(|i| (i, s.claim_set)).map_err(|e| StoreError(format!("stored step unreadable: {e}"))))
        .collect()
}

/// OK under the head's key, NOT_HEAD under an older step's, else REFUSED.
fn check_sig(path: &Steps, key: StepKey, domain: Domain, digest: &[u8; 32], sig: &Sig) -> Code {
    let mut steps = path.iter().rev();
    match steps.next() {
        Some((head, _)) if label::verify(head.key(key), domain, digest, sig) => Code::OK,
        Some(_) if steps.any(|(s, _)| label::verify(s.key(key), domain, digest, sig)) => Code::NOT_HEAD,
        _ => Code::REFUSED,
    }
}

fn head_bytes(path: &Steps) -> Option<Vec<u8>> {
    path.last().map(|(s, _)| s.bytes.clone())
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
            crossed: HashSet::new(),
        }
    }

    /// Labels opened on this connection.
    pub fn opened(&self) -> &BTreeSet<LabelId> {
        &self.opened
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn handle(&mut self, now: u64, store: &mut dyn LabelStore, input: ServerInput) -> Vec<ServerOutput> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        match input {
            ServerInput::Start => out.push(ServerOutput::Send(encode_frame(&Hello::new(now, self.cfg.challenge).encode()))),
            ServerInput::Bytes(b) => {
                self.decoder.push(&b);
                while !self.closed {
                    match self.decoder.next_frame() {
                        Ok(Some(body)) => self.frame(now, store, &body, &mut out),
                        Ok(None) => break,
                        Err(e) => {
                            out.push(ServerOutput::PeerError(e));
                            send(&mut out, Message::Error { id: 0, code: Code::MALFORMED });
                            self.close(&mut out);
                        }
                    }
                }
            }
            ServerInput::Changed(label) => {
                if let Err(e) = self.push(store, &label, &mut out) {
                    out.push(ServerOutput::StoreError(e));
                }
            }
            ServerInput::Signal { label, blob, wrap, auth } => {
                if self.subs.contains_key(&label) {
                    send(&mut out, Message::Signal { label, blob, wrap, auth });
                }
            }
        }
        out
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
                out.push(ServerOutput::PeerError(r.error));
                send(out, Message::Error { id: r.id, code: r.code() });
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

    fn dispatch(&mut self, now: u64, store: &mut dyn LabelStore, msg: Message, out: &mut Vec<ServerOutput>) -> Result<Option<Message>, StoreError> {
        use Message as M;
        Ok(Some(match msg {
            M::Ping { id, .. } => M::Pong { id, wall_ms: now },
            M::Open { id, label, proof } => self.open(store, id, label, proof)?,
            M::Register { id, label, step, claim_set } => register(store, id, label, step, claim_set, out)?,
            M::Path { id, label, after } => self.path(store, id, label, after)?,
            M::Upload { id, label, entries } => {
                let path = load_path(store, &label)?;
                let codes = entries.into_iter().map(|e| accept(store, now, &label, &path, &e.blob, e.wrap, Some(e.stamp))).collect::<Result<Vec<_>, _>>()?;
                changed(&codes, &label, out);
                let head = if codes.contains(&Code::NOT_HEAD) { head_bytes(&path) } else { None };
                M::Status { id, codes, head }
            }
            M::Deposit { id, label, blob, wrap, sig } => {
                let path = load_path(store, &label)?;
                if path.is_empty() {
                    return Ok(Some(M::Budget { id, code: Code::UNKNOWN_LABEL, entries_left: 0, bytes_left: 0, head: None }));
                }
                let blob_id = osis_crypto::blob_id(&blob);
                let mut code = check_sig(&path, StepKey::Deposit, Domain::Deposit, &label::entry_digest(&label, &blob_id, &wrap), &sig);
                if code == Code::OK {
                    code = accept(store, now, &label, &path, &blob, wrap, None)?;
                }
                changed(&[code], &label, out);
                let b = store.budget(&label)?;
                let head = if code == Code::NOT_HEAD { head_bytes(&path) } else { None };
                M::Budget { id, code, entries_left: b.entries_left, bytes_left: b.bytes_left, head }
            }
            M::Delete { id, label, items } => {
                let path = load_path(store, &label)?;
                let mut codes = Vec::with_capacity(items.len());
                for item in &items {
                    codes.push(delete(store, now, &label, &path, item)?);
                }
                changed(&codes, &label, out);
                let head = if codes.contains(&Code::NOT_HEAD) { head_bytes(&path) } else { None };
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
                        let sub = match self.synced.get(&l) {
                            Some(s) => *s,
                            None => Sub { seq: store.log_head(&l)?.1, inline_limit: 0 },
                        };
                        self.subs.insert(l, sub);
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
                }
                M::Ok { id }
            }
            M::Signal { label, blob, wrap, auth } => {
                let path = load_path(store, &label)?;
                let key = if auth.deposit { StepKey::Deposit } else { StepKey::Write };
                let digest = label::entry_digest(&label, &osis_crypto::blob_id(&blob), &wrap);
                if path.last().is_some_and(|(h, _)| label::verify(h.key(key), Domain::SignalPublish, &digest, &auth.sig)) {
                    out.push(ServerOutput::Signal { label, blob, wrap, auth });
                }
                return Ok(None);
            }
            // Replies and pushes: this side sends no requests.
            _ => return Ok(None),
        }))
    }

    fn open(&mut self, store: &dyn LabelStore, id: Id, label: LabelId, proof: Proof) -> Result<Message, StoreError> {
        let path = load_path(store, &label)?;
        let refused = Message::Error { id, code: Code::REFUSED };
        let Some((head, head_claims)) = path.last() else { return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }) };
        if !self.opened.contains(&label) && self.opened.len() >= MAX_OPEN_LABELS {
            return Ok(Message::Error { id, code: Code::RATE_LIMITED });
        }
        let (pk, sig) = match &proof {
            Proof::Sync { pk, sig } | Proof::Claim { pk, sig, .. } | Proof::Static { pk, sig } => (pk, sig),
        };
        let Ok(vk) = VerifyingKey::from_bytes(pk) else { return Ok(refused) };
        if osis_crypto::verify_open(&vk, &label, &self.cfg.challenge, &self.cfg.static_key, &Signature(*sig)).is_err() {
            return Ok(refused);
        }
        // The step the key matched, by index on the path.
        let at = match &proof {
            Proof::Sync { pk, .. } => path.iter().rposition(|(s, _)| s.sync == *pk),
            Proof::Claim { step_id, pk, .. } => path.iter().position(|(s, cs)| s.id == *step_id && cs.as_deref().and_then(|c| ClaimSet::parse(c).ok()).is_some_and(|c| c.claims.contains(pk))),
            Proof::Static { .. } => {
                let entry = osis_crypto::static_entry(&label, &vk);
                let Some(cs) = head_claims.as_deref().and_then(|c| ClaimSet::parse(c).ok()).filter(|c| c.claims.contains(&entry)) else { return Ok(refused) };
                self.opened.insert(label);
                return Ok(Message::Opened { id, head: head.bytes.clone(), entry_box: cs.boxes.get(&entry).cloned() });
            }
        };
        Ok(match at {
            Some(i) if i + 1 == path.len() => {
                self.opened.insert(label);
                Message::Opened { id, head: head.bytes.clone(), entry_box: None }
            }
            Some(i) => match path.get(i + 1) {
                Some((child, _)) => Message::Step { id, step: child.bytes.clone() },
                None => refused,
            },
            None => refused,
        })
    }

    fn path(&self, store: &dyn LabelStore, id: Id, label: LabelId, after: Option<[u8; 32]>) -> Result<Message, StoreError> {
        if !self.opened.contains(&label) {
            return Ok(Message::Error { id, code: Code::NOT_OPENED });
        }
        let path = load_path(store, &label)?;
        let start = match after {
            None => 0,
            Some(a) => match path.iter().position(|(s, _)| s.id == a) {
                Some(i) => i + 1,
                None => return Ok(Message::Error { id, code: Code::REFUSED }),
            },
        };
        let rest: Vec<Vec<u8>> = path.iter().skip(start).map(|(s, _)| s.bytes.clone()).collect();
        let more = rest.len() > MAX_PATH_STEPS;
        Ok(Message::PathReply { id, steps: rest.into_iter().take(MAX_PATH_STEPS).collect(), more })
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
                self.crossed.insert(blob_id);
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

    fn added(&self, store: &dyn LabelStore, blob_id: BlobId, m: crate::store::EntryMeta, inline_limit: u64) -> Result<Event, StoreError> {
        let blob = if m.size <= inline_limit && !self.crossed.contains(&blob_id) { store.blob(&blob_id)? } else { None };
        Ok(Event::Added { blob_id, blob, wrap: m.wrap, stamp: m.stamp })
    }

    fn take(&mut self, e: &Event) {
        if let Event::Added { blob_id, blob: Some(_), .. } = e {
            self.crossed.insert(*blob_id);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sync(&mut self, store: &mut dyn LabelStore, now: u64, id: Id, label: LabelId, cursor: Option<Cursor>, inline_limit: u64, entries: Vec<Entry>, gained: Vec<BlobId>, out: &mut Vec<ServerOutput>) -> Result<Message, StoreError> {
        if !self.opened.contains(&label) {
            return Ok(Message::Error { id, code: Code::NOT_OPENED });
        }
        let path = load_path(store, &label)?;
        let (log_id, _) = store.log_head(&label)?;
        if cursor.is_some_and(|c| c.log_id != log_id) {
            return Ok(Message::Error { id, code: Code::CURSOR_INVALID });
        }
        if let Some(c) = cursor
            && store.log_after(&label, c.seq, 0)?.is_none()
        {
            return Ok(Message::Error { id, code: Code::CURSOR_INVALID });
        }
        for e in &entries {
            self.crossed.insert(osis_crypto::blob_id(&e.blob));
        }
        let codes = entries.iter().map(|e| accept(store, now, &label, &path, &e.blob, e.wrap, Some(e.stamp))).collect::<Result<Vec<_>, _>>()?;
        changed(&codes, &label, out);
        let mut want = Vec::new();
        for g in &gained {
            if store.entry(&label, g)?.is_none() && !store.tombstoned(&label, g)? {
                want.push(*g);
            }
        }
        // The requester holds what it gained and what it just sent: no add events for those.
        let gained: HashSet<BlobId> = gained.into_iter().chain(entries.iter().map(|e| osis_crypto::blob_id(&e.blob))).collect();
        let budget = REPLY_BUDGET.saturating_sub(40 * want.len() + 10 * codes.len());
        let (head_seq, mut events, mut used, mut more) = (store.log_head(&label)?.1, Vec::new(), 0, false);
        let pos = match cursor {
            Some(c) => {
                let mut pos = c.seq;
                'log: loop {
                    let Some(recs) = store.log_after(&label, pos, LOG_BATCH)? else { return Ok(Message::Error { id, code: Code::CURSOR_INVALID }) };
                    if recs.is_empty() {
                        break;
                    }
                    for (seq, rec) in recs {
                        if let Some(e) = self.event(store, &label, seq, rec, inline_limit, &gained)? {
                            let size = event_size(&e);
                            if used + size > budget {
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
                pos
            }
            None => {
                let mut pos = 0;
                'live: loop {
                    let live = store.live_after(&label, pos, LOG_BATCH)?;
                    if live.is_empty() {
                        break;
                    }
                    for (b, m) in live {
                        let seq = m.add_seq;
                        if gained.contains(&b) {
                            pos = seq;
                            continue;
                        }
                        let e = self.added(store, b, m, inline_limit)?;
                        let size = event_size(&e);
                        if used + size > budget {
                            more = true;
                            break 'live;
                        }
                        used += size;
                        self.take(&e);
                        events.push(e);
                        pos = seq;
                    }
                }
                if more { pos } else { head_seq }
            }
        };
        if !more {
            self.synced.insert(label, Sub { seq: pos, inline_limit });
        }
        Ok(Message::SyncReply { id, events, want, codes, cursor: Cursor { log_id, seq: pos }, more })
    }

    fn push(&mut self, store: &dyn LabelStore, label: &LabelId, out: &mut Vec<ServerOutput>) -> Result<(), StoreError> {
        let Some(mut sub) = self.subs.get(label).copied() else { return Ok(()) };
        let (log_id, head) = store.log_head(label)?;
        let none = HashSet::new();
        let (mut events, mut used) = (Vec::new(), 0);
        loop {
            let Some(recs) = store.log_after(label, sub.seq, LOG_BATCH)? else {
                // The log no longer reaches the subscription: the client's next Sync recovers.
                sub.seq = head;
                break;
            };
            if recs.is_empty() {
                break;
            }
            for (seq, rec) in recs {
                if let Some(e) = self.event(store, label, seq, rec, sub.inline_limit, &none)? {
                    let size = event_size(&e);
                    if used + size > REPLY_BUDGET && !events.is_empty() {
                        send(out, Message::Push { label: *label, events: std::mem::take(&mut events), cursor: Cursor { log_id, seq: sub.seq } });
                        used = 0;
                    }
                    used += size;
                    self.take(&e);
                    events.push(e);
                }
                sub.seq = seq;
            }
        }
        if !events.is_empty() {
            send(out, Message::Push { label: *label, events, cursor: Cursor { log_id, seq: sub.seq } });
        }
        self.subs.insert(*label, sub);
        Ok(())
    }
}

fn send<O: From<Vec<u8>>>(out: &mut Vec<O>, msg: Message) {
    out.push(O::from(encode_frame(&msg.encode())));
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

/// Upload (stamp) or deposit (no stamp, already authorized) of one entry (spec/sync.md §5).
fn accept(store: &mut dyn LabelStore, now: u64, label: &LabelId, path: &Steps, blob: &[u8], wrap: Wrap, stamp: Option<Sig>) -> Result<Code, StoreError> {
    if path.is_empty() {
        return Ok(Code::UNKNOWN_LABEL);
    }
    if blob.len() > MAX_BLOB {
        return Ok(Code::TOO_LARGE);
    }
    let blob_id = osis_crypto::blob_id(blob);
    if let Some(stamp) = stamp {
        let code = check_sig(path, StepKey::Write, Domain::Upload, &label::entry_digest(label, &blob_id, &wrap), &stamp);
        if code != Code::OK {
            return Ok(code);
        }
    }
    let Ok(prefix) = label::prefix(blob) else { return Ok(Code::MALFORMED) };
    if prefix.expiry.is_some_and(|t| t <= now) {
        return Ok(Code::EXPIRED);
    }
    if store.tombstoned(label, &blob_id)? {
        return Ok(Code::TOMBSTONED);
    }
    store.put(label, Put { blob_id, blob, wrap, stamp, expiry: prefix.expiry })
}

/// One Delete item (spec/sync.md §5): by the head's delete key, or by token with the write key
/// (level 3) or the sync key (levels 1, 2).
fn delete(store: &mut dyn LabelStore, now: u64, label: &LabelId, path: &Steps, item: &DeleteItem) -> Result<Code, StoreError> {
    if path.is_empty() {
        return Ok(Code::UNKNOWN_LABEL);
    }
    let digest = label::delete_digest(label, &item.blob_id, item.at, item.token.as_ref());
    let entry = store.entry(label, &item.blob_id)?;
    let key = match &item.token {
        None => StepKey::Delete,
        Some(token) => {
            // Without the blob the token cannot be checked (nor a tombstone revealed).
            let Some(blob) = (if entry.is_some() { store.blob(&item.blob_id)? } else { None }) else { return Ok(Code::REFUSED) };
            let Ok(prefix) = label::prefix(&blob) else { return Ok(Code::REFUSED) };
            match prefix.commitments.iter().find(|c| osis_crypto::verify_presented_token(token, c, &prefix.salt)) {
                Some([3, ..]) => StepKey::Write,
                Some(_) => StepKey::Sync,
                None => return Ok(Code::REFUSED),
            }
        }
    };
    let code = check_sig(path, key, Domain::Delete, &digest, &item.sig);
    if code != Code::OK {
        return Ok(code);
    }
    if entry.is_none() {
        return Ok(if store.tombstoned(label, &item.blob_id)? { Code::OK } else { Code::REFUSED });
    }
    match item.at {
        Some(at) if at > now => store.schedule_delete(label, &item.blob_id, at)?,
        _ => store.delete(label, &item.blob_id, now)?,
    }
    Ok(Code::OK)
}

/// Register (spec/sync.md §5): a new label's genesis, or a child of the head; else the head.
fn register(store: &mut dyn LabelStore, id: Id, label: LabelId, step: Vec<u8>, claim_set: Option<Vec<u8>>, out: &mut Vec<ServerOutput>) -> Result<Message, StoreError> {
    let malformed = Message::Error { id, code: Code::MALFORMED };
    let Ok(s) = StepInfo::parse(&step) else { return Ok(malformed) };
    if s.label != label {
        return Ok(malformed);
    }
    if let Some(cs) = &claim_set
        && (osis_core::hash::hash(cs) != s.claims_hash || ClaimSet::parse(cs).is_err())
    {
        return Ok(malformed);
    }
    let path = load_path(store, &label)?;
    let accept = match path.last() {
        None if s.prev.is_none() => {
            if !s.is_valid_genesis() {
                return Ok(Message::Error { id, code: Code::REFUSED });
            }
            true
        }
        None => return Ok(Message::Error { id, code: Code::UNKNOWN_LABEL }),
        Some((head, _)) if head.id == s.id => return Ok(Message::Ok { id }),
        Some((head, _)) => head.is_parent_of(&s),
    };
    if !accept {
        return Ok(Message::Step { id, step: head_bytes(&path).unwrap_or_default() });
    }
    store.push_step(&label, StoredStep { step, claim_set })?;
    out.push(ServerOutput::Changed(label));
    Ok(Message::Ok { id })
}
