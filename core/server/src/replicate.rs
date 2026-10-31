//! Blind-to-blind replication, push only (spec/sync.md §5 Upload: anyone holding a stamped entry
//! may relay it; download needs an open, so a blind node never pulls). A `Replicator` drives an
//! osis-proto `ClientSession` on a connection this node dialed to a peer server: per label it
//! walks its own log from the position the peer acknowledged, registers the steps it logged
//! (with their claim sets) and uploads the stamped entries still live, in log order; deposits
//! (no stamp), deletions and pending deletions cannot be relayed (their signatures are not
//! kept), and entries that came from this peer are not sent back. One batch is in flight at a
//! time; its position is stored when every request of it was answered without a retryable
//! refusal (codes 4, 12), else the label is retried with backoff from the same position.
//! A log that no longer reaches the acknowledged position is replayed per run of steps with
//! one write key: the run's steps, then the live entries stamped under that key. Presence entries
//! are not replicated.

use crate::store::BackendStore;
use osis_base::{BlobId, LabelId};
use osis_crypto::VerifyingKey;
use osis_proto::msg::{Entry, Step};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, LabelStore, LogRecord, StoreError};
use osis_store::Backend;
use std::collections::{BTreeMap, BTreeSet};

/// A presence entry is never replicated: only its author uploads it, tied to its connection
/// (spec/sync.md §5); a copy at a peer server would outlive the author's departure.
fn is_presence(blob: &[u8]) -> bool {
    osis_label::Prefix::parse(blob).is_ok_and(|p| p.class() == osis_label::Class::Presence)
}

/// Log records or entries read per batch.
const BATCH_RECORDS: usize = 256;
/// Blob bytes per batch.
const BATCH_BYTES: usize = 4 << 20;
/// Labels examined per call (labels with nothing to send cost store reads only).
const MAX_STEPS: usize = 64;
/// Retry backoff bounds.
const RETRY_MIN_MS: u64 = 1_000;
const RETRY_MAX_MS: u64 = 60_000;

/// What completing the in-flight batch records.
#[derive(Clone, Copy, Debug)]
enum Done {
    /// The peer has the label's log up to this sequence number.
    Log(u64),
    /// A replay advanced to (run, last ID sent in it); the run's steps are at the peer.
    Replay(usize, Option<BlobId>),
    /// The replay is complete.
    Replayed,
}

struct Inflight {
    label: LabelId,
    log_id: [u8; 16],
    done: Done,
    failed: bool,
}

/// A replay in progress: the log head taken at its start, the path's runs of steps sharing a
/// write key, the current run, whether its steps were sent, the last ID sent in it.
struct Replay {
    start: u64,
    runs: Vec<(Vec<Step>, VerifyingKey)>,
    run: usize,
    registered: bool,
    after: Option<BlobId>,
}

/// A batch: the log ID it refers to, its commands, what completing it records.
type Batch = ([u8; 16], Vec<Command>, Done);

pub struct Replicator {
    peer: [u8; 32],
    session: ClientSession,
    dirty: BTreeSet<LabelId>,
    /// Labels still to enumerate (after this one; `Some(None)`: from the start).
    scan: Option<Option<LabelId>>,
    inflight: Option<Inflight>,
    replays: BTreeMap<LabelId, Replay>,
    /// Labels held back after a refusal: (retry at, backoff).
    retry: BTreeMap<LabelId, (u64, u64)>,
    diags: Vec<String>,
}

fn retryable(c: Code) -> bool {
    c == Code::RATE_LIMITED || c == Code::STORAGE_CAP
}

impl Replicator {
    /// `peer`: the peer server's static key. Every held label is enumerated (in bounded steps).
    pub fn new(peer: [u8; 32], challenge: [u8; 32]) -> Replicator {
        Replicator {
            peer,
            session: ClientSession::new(ClientConfig { peer_static_key: peer, challenge }),
            dirty: BTreeSet::new(),
            scan: Some(None),
            inflight: None,
            replays: BTreeMap::new(),
            retry: BTreeMap::new(),
            diags: Vec::new(),
        }
    }

    /// Labels whose logs may hold something the peer lacks.
    pub fn mark(&mut self, labels: impl IntoIterator<Item = LabelId>) {
        for l in labels {
            if !self.retry.contains_key(&l) {
                self.dirty.insert(l);
            }
        }
    }

    /// When `handle` should next be called without input: now when work is queued and nothing is
    /// in flight, else the earliest retry.
    pub fn next_due(&self, now: u64) -> Option<u64> {
        let ready = self.session.is_ready() && !self.session.is_closed() && self.inflight.is_none();
        if ready && (!self.dirty.is_empty() || self.scan.is_some()) {
            return Some(now);
        }
        self.retry.values().map(|r| r.0).min()
    }

    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diags)
    }

    /// Feeds the session (if `input`), completes the in-flight batch when every request has been
    /// answered, releases due retries and starts the next batch.
    pub fn handle<B: Backend>(&mut self, now: u64, store: &mut BackendStore<B>, input: Option<ClientInput>) -> Vec<ClientOutput> {
        let mut out = match input {
            Some(i) => self.session.handle(now, i),
            None => Vec::new(),
        };
        if let Some(f) = &mut self.inflight {
            for o in &out {
                let ClientOutput::Event(e) = o else { continue };
                let bad = match e {
                    ClientEvent::EntryStatus { label, codes, .. } => *label == f.label && codes.iter().any(|c| retryable(*c)),
                    ClientEvent::Refused { label, code, .. } => *label == Some(f.label) && retryable(*code),
                    _ => false,
                };
                f.failed |= bad;
            }
        }
        let due: Vec<LabelId> = self.retry.iter().filter(|(_, r)| r.0 <= now).map(|(l, _)| *l).collect();
        for l in due {
            self.dirty.insert(l);
        }
        self.pump(now, store, &mut out);
        out
    }

    fn hold(&mut self, now: u64, label: LabelId) {
        let backoff = self.retry.get(&label).map_or(RETRY_MIN_MS, |r| (r.1 * 2).min(RETRY_MAX_MS));
        self.retry.insert(label, (now.saturating_add(backoff), backoff));
        self.dirty.remove(&label);
    }

    fn pump<B: Backend>(&mut self, now: u64, store: &mut BackendStore<B>, out: &mut Vec<ClientOutput>) {
        if !self.session.is_ready() || self.session.is_closed() {
            return;
        }
        if self.inflight.is_some() && self.session.outstanding() == 0
            && let Some(f) = self.inflight.take()
        {
            if f.failed {
                self.diags.push(format!("label {:?}: refused for now, retrying", f.label));
                self.hold(now, f.label);
            } else if let Err(e) = self.complete(store, f.label, f.log_id, f.done) {
                self.diags.push(e.to_string());
                self.hold(now, f.label);
            }
        }
        let mut steps = 0;
        while self.inflight.is_none() && steps < MAX_STEPS {
            steps += 1;
            let label = match self.dirty.pop_first() {
                Some(l) => l,
                None => match self.scan {
                    Some(after) => {
                        match store.labels_after(after.as_ref(), BATCH_RECORDS) {
                            Ok(ls) => {
                                self.scan = if ls.len() < BATCH_RECORDS { None } else { ls.last().map(|l| Some(*l)) };
                                self.mark(ls);
                            }
                            Err(e) => {
                                self.diags.push(e.to_string());
                                self.scan = None;
                            }
                        }
                        continue;
                    }
                    None => break,
                },
            };
            if self.retry.get(&label).is_some_and(|r| r.0 > now) {
                continue;
            }
            match self.batch(store, &label) {
                Ok(None) => {
                    self.retry.remove(&label);
                }
                Ok(Some((log_id, cmds, done))) => {
                    if cmds.is_empty() {
                        if let Err(e) = self.complete(store, label, log_id, done) {
                            self.diags.push(e.to_string());
                            self.hold(now, label);
                        }
                        continue;
                    }
                    for c in cmds {
                        out.extend(self.session.handle(now, ClientInput::Command(c)));
                    }
                    self.inflight = Some(Inflight { label, log_id, done, failed: false });
                }
                Err(e) => {
                    self.diags.push(e.to_string());
                    self.hold(now, label);
                }
            }
        }
    }

    fn complete<B: Backend>(&mut self, store: &mut BackendStore<B>, label: LabelId, log_id: [u8; 16], done: Done) -> Result<(), StoreError> {
        match done {
            Done::Log(seq) => store.set_replica_pos(&self.peer, &label, log_id, seq)?,
            Done::Replay(run, after) => {
                if let Some(r) = self.replays.get_mut(&label) {
                    if run == r.run {
                        r.registered = true;
                        r.after = after;
                    } else {
                        (r.run, r.registered, r.after) = (run, false, None);
                    }
                }
            }
            Done::Replayed => {
                if let Some(r) = self.replays.remove(&label) {
                    store.set_replica_pos(&self.peer, &label, log_id, r.start)?;
                }
            }
        }
        self.retry.remove(&label);
        // More may remain (the batch was bounded, or the log grew meanwhile).
        self.dirty.insert(label);
        Ok(())
    }

    /// The next batch for a label: none when the peer is up to date.
    fn batch<B: Backend>(&mut self, store: &BackendStore<B>, label: &LabelId) -> Result<Option<Batch>, StoreError> {
        let Some(_) = store.head(label)? else { return Ok(None) };
        let (log_id, head) = store.log_head(label)?;
        if !self.replays.contains_key(label) {
            let pos = match store.replica_pos(&self.peer, label)? {
                Some((id, seq)) if id == log_id => seq,
                _ => 0,
            };
            if pos >= head {
                return Ok(None);
            }
            if let Some(recs) = store.log_after(label, pos, BATCH_RECORDS)? {
                let (cmds, last) = self.log_batch(store, label, pos, recs)?;
                return Ok(Some((log_id, cmds, Done::Log(last))));
            }
            let mut runs: Vec<(Vec<Step>, VerifyingKey)> = Vec::new();
            for s in store.path(label)? {
                match runs.last_mut() {
                    Some((steps, k)) if *k == s.keys.write => steps.push(s),
                    _ => {
                        let k = s.keys.write;
                        runs.push((vec![s], k));
                    }
                }
            }
            self.replays.insert(*label, Replay { start: head, runs, run: 0, registered: false, after: None });
        }
        let Some(r) = self.replays.get(label) else { return Ok(None) };
        let Some((steps, write)) = r.runs.get(r.run) else { return Ok(Some((log_id, Vec::new(), Done::Replayed))) };
        let mut cmds = Vec::new();
        if !r.registered {
            for s in steps {
                cmds.push(register(store, label, s.clone())?);
            }
        }
        let live = store.live_by_id(label, r.after.as_ref(), BATCH_RECORDS)?;
        let full = live.len() == BATCH_RECORDS;
        let last = live.last().map(|l| l.0);
        let (mut entries, mut bytes, mut end) = (Vec::new(), 0, last);
        for (id, m) in live {
            let Some(stamp) = m.stamp else { continue };
            if store.origin(label, &id) == Some(self.peer) || osis_label::verify_stamp(write, label, &id, &m.wrap, &stamp).is_err() {
                continue;
            }
            let Some(blob) = store.blob(&id)? else { continue };
            if is_presence(&blob) {
                continue;
            }
            bytes += blob.len();
            entries.push(Entry { blob, wrap: m.wrap, stamp, replaces: Vec::new() });
            if bytes >= BATCH_BYTES {
                end = Some(id);
                break;
            }
        }
        if !entries.is_empty() {
            cmds.push(Command::Upload { label: *label, entries });
        }
        let done = if full || end != last { Done::Replay(r.run, end) } else { Done::Replay(r.run + 1, None) };
        Ok(Some((log_id, cmds, done)))
    }

    /// Commands for log records after `pos`: Register per new head, Upload for stamped entries
    /// whose latest add is the record (not from this peer); bounded by `BATCH_BYTES`. Returns the
    /// last sequence number covered.
    fn log_batch<B: Backend>(&self, store: &BackendStore<B>, label: &LabelId, pos: u64, recs: Vec<(u64, LogRecord)>) -> Result<(Vec<Command>, u64), StoreError> {
        let mut cmds = Vec::new();
        let mut entries = Vec::new();
        let (mut last, mut bytes) = (pos, 0);
        for (seq, rec) in recs {
            match rec {
                LogRecord::Head(step) => {
                    if !entries.is_empty() {
                        cmds.push(Command::Upload { label: *label, entries: std::mem::take(&mut entries) });
                    }
                    cmds.push(register(store, label, step)?);
                }
                LogRecord::Added(id) => {
                    if let Some(m) = store.entry(label, &id)?
                        && m.add_seq == seq
                        && store.origin(label, &id) != Some(self.peer)
                        && let (Some(stamp), Some(blob)) = (m.stamp, store.blob(&id)?)
                        && !is_presence(&blob)
                    {
                        bytes += blob.len();
                        entries.push(Entry { blob, wrap: m.wrap, stamp, replaces: Vec::new() });
                    }
                }
                LogRecord::Deleted(_) | LogRecord::Pending(..) => {}
            }
            last = seq;
            if bytes >= BATCH_BYTES {
                break;
            }
        }
        if !entries.is_empty() {
            cmds.push(Command::Upload { label: *label, entries });
        }
        Ok((cmds, last))
    }

    /// A diagnostic for a replication outcome worth logging.
    pub fn diagnostic(e: &ClientEvent) -> Option<String> {
        match e {
            ClientEvent::EntryStatus { label, codes, .. } => {
                let refused: Vec<u64> = codes.iter().filter(|c| **c != Code::OK && **c != Code::TOMBSTONED).map(|c| c.0).collect();
                (!refused.is_empty()).then(|| format!("label {label:?}: {} entries refused, codes {refused:?}", refused.len()))
            }
            ClientEvent::Refused { label, kind, code, .. } => Some(format!("label {label:?}: {kind:?} refused, code {}", code.0)),
            ClientEvent::PeerError(err) => Some(format!("protocol error: {err}")),
            _ => None,
        }
    }
}

fn register<B: Backend>(store: &BackendStore<B>, label: &LabelId, step: Step) -> Result<Command, StoreError> {
    let claim_set = store.claim_set(label, &step.id())?.map(|c| (*c).clone());
    Ok(Command::Register { label: *label, step, claim_set })
}
