//! Blind-to-blind replication, push only (spec/sync.md §5 Upload: anyone holding a stamped entry
//! may relay it; download needs an open, so a blind node never pulls). A `Replicator` drives an
//! osis-proto `ClientSession` on a connection this node dialed to a peer server: per label it
//! walks its own log from the position the peer acknowledged, registers the steps it logged
//! (with their claim sets) and uploads the stamped entries still live; deposits (no stamp),
//! deletions and pending deletions cannot be relayed (their signatures are not kept). One batch
//! is in flight at a time; its position is stored when every request of it was answered, so a
//! dropped connection re-sends at most one batch (identical re-uploads change nothing). A log
//! that no longer reaches the acknowledged position is replayed: the path, then every live
//! stamped entry by ID.

use osis_core::{BlobId, LabelId};
use osis_proto::msg::{Entry, Step};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, LabelStore, LogRecord, StoreError};
use osis_store::Backend;
use std::collections::{BTreeMap, BTreeSet};

use crate::store::BackendStore;

/// Log records read per batch.
const BATCH_RECORDS: usize = 256;
/// Blob bytes per batch.
const BATCH_BYTES: usize = 4 << 20;

/// What completing the in-flight batch records.
#[derive(Clone, Copy, Debug)]
enum Done {
    /// The peer has the label's log up to this sequence number.
    Log(u64),
    /// A replay page ended at this ID (`None`: the replay is complete).
    Replay(Option<BlobId>),
}

/// A batch: the log ID it refers to, its commands, what completing it records.
type Batch = ([u8; 16], Vec<Command>, Done);

pub struct Replicator {
    peer: [u8; 32],
    session: ClientSession,
    dirty: BTreeSet<LabelId>,
    inflight: Option<(LabelId, [u8; 16], Done)>,
    /// Replays in progress: the log head taken at their start and the last ID sent.
    replays: BTreeMap<LabelId, (u64, Option<BlobId>)>,
    diags: Vec<String>,
}

impl Replicator {
    /// `peer`: the peer server's static key (checked by the transport, bound by nothing here:
    /// replication needs no open).
    pub fn new(peer: [u8; 32], challenge: [u8; 32]) -> Replicator {
        Replicator {
            peer,
            session: ClientSession::new(ClientConfig { peer_static_key: peer, challenge }),
            dirty: BTreeSet::new(),
            inflight: None,
            replays: BTreeMap::new(),
            diags: Vec::new(),
        }
    }

    /// Labels whose logs may hold something the peer lacks.
    pub fn mark(&mut self, labels: impl IntoIterator<Item = LabelId>) {
        self.dirty.extend(labels);
    }

    /// Whether nothing is queued or in flight.
    pub fn is_idle(&self) -> bool {
        self.dirty.is_empty() && self.inflight.is_none()
    }

    pub fn take_diagnostics(&mut self) -> Vec<String> {
        std::mem::take(&mut self.diags)
    }

    /// Feeds the session (if `input`), completes the in-flight batch when every request has been
    /// answered, and starts the next one.
    pub fn handle<B: Backend>(&mut self, now: u64, store: &mut BackendStore<B>, input: Option<ClientInput>) -> Vec<ClientOutput> {
        let mut out = match input {
            Some(i) => self.session.handle(now, i),
            None => Vec::new(),
        };
        if let Err(e) = self.pump(now, store, &mut out) {
            self.diags.push(e.to_string());
        }
        out
    }

    fn pump<B: Backend>(&mut self, now: u64, store: &mut BackendStore<B>, out: &mut Vec<ClientOutput>) -> Result<(), StoreError> {
        if !self.session.is_ready() || self.session.is_closed() {
            return Ok(());
        }
        if self.inflight.is_some() && self.session.outstanding() == 0
            && let Some((label, log_id, done)) = self.inflight.take()
        {
            self.complete(store, label, log_id, done)?;
        }
        while self.inflight.is_none() {
            let Some(label) = self.dirty.pop_first() else { break };
            let Some((log_id, cmds, done)) = self.batch(store, &label)? else { continue };
            if cmds.is_empty() {
                self.complete(store, label, log_id, done)?;
                continue;
            }
            for c in cmds {
                out.extend(self.session.handle(now, ClientInput::Command(c)));
            }
            self.inflight = Some((label, log_id, done));
        }
        Ok(())
    }

    fn complete<B: Backend>(&mut self, store: &mut BackendStore<B>, label: LabelId, log_id: [u8; 16], done: Done) -> Result<(), StoreError> {
        match done {
            Done::Log(seq) => store.set_replica_pos(&self.peer, &label, log_id, seq)?,
            Done::Replay(Some(last)) => {
                if let Some(r) = self.replays.get_mut(&label) {
                    r.1 = Some(last);
                }
            }
            Done::Replay(None) => {
                if let Some((start, _)) = self.replays.remove(&label) {
                    store.set_replica_pos(&self.peer, &label, log_id, start)?;
                }
            }
        }
        // More may remain (the batch was bounded, or the log grew meanwhile).
        self.dirty.insert(label);
        Ok(())
    }

    /// The next batch for a label: none when the peer is up to date.
    fn batch<B: Backend>(&mut self, store: &BackendStore<B>, label: &LabelId) -> Result<Option<Batch>, StoreError> {
        let Ok((log_id, head)) = store.log_head(label) else { return Ok(None) };
        let mut cmds = Vec::new();
        if !self.replays.contains_key(label) {
            let pos = match store.replica_pos(&self.peer, label)? {
                Some((id, seq)) if id == log_id => seq,
                _ => 0,
            };
            if pos >= head {
                return Ok(None);
            }
            match store.log_after(label, pos, BATCH_RECORDS)? {
                Some(recs) => {
                    let (cmds, last) = log_batch(store, label, pos, recs)?;
                    return Ok(Some((log_id, cmds, Done::Log(last))));
                }
                None => {
                    self.replays.insert(*label, (head, None));
                    for s in store.path(label)? {
                        cmds.push(register(store, label, s)?);
                    }
                }
            }
        }
        let after = self.replays.get(label).and_then(|r| r.1);
        let live = store.live_by_id(label, after.as_ref(), BATCH_RECORDS)?;
        let full = live.len() == BATCH_RECORDS;
        let last = live.last().map(|l| l.0);
        let mut entries = Vec::new();
        let mut bytes = 0;
        let mut end = last;
        for (id, m) in live {
            let (Some(stamp), Some(blob)) = (m.stamp, store.blob(&id)?) else { continue };
            bytes += blob.len();
            entries.push(Entry { blob, wrap: m.wrap, stamp });
            if bytes >= BATCH_BYTES {
                end = Some(id);
                break;
            }
        }
        if !entries.is_empty() {
            cmds.push(Command::Upload { label: *label, entries });
        }
        let more = full || end != last;
        Ok(Some((log_id, cmds, Done::Replay(if more { end } else { None }))))
    }

    /// A diagnostic for a replication outcome worth logging.
    pub fn diagnostic(e: &ClientEvent) -> Option<String> {
        match e {
            ClientEvent::EntryStatus { label, codes, .. } => {
                let refused: Vec<u64> = codes.iter().filter(|c| **c != Code::OK && **c != Code::TOMBSTONED).map(|c| c.0).collect();
                (!refused.is_empty()).then(|| format!("label {label:?}: {} entries refused, codes {refused:?}", refused.len()))
            }
            ClientEvent::Head { label, .. } => Some(format!("label {label:?}: the peer holds another head")),
            ClientEvent::Refused { label, kind, code } => Some(format!("label {label:?}: request kind {kind} refused, code {}", code.0)),
            ClientEvent::PeerError(err) => Some(format!("protocol error: {err}")),
            _ => None,
        }
    }
}

fn register<B: Backend>(store: &BackendStore<B>, label: &LabelId, step: Step) -> Result<Command, StoreError> {
    let claim_set = store.claim_set(label, &step.id())?.map(|c| (*c).clone());
    Ok(Command::Register { label: *label, step, claim_set })
}

/// Commands for log records after `pos`: Register per new head, Upload for stamped entries whose
/// latest add is the record; bounded by `BATCH_BYTES`. Returns the last sequence number covered.
fn log_batch<B: Backend>(store: &BackendStore<B>, label: &LabelId, pos: u64, recs: Vec<(u64, LogRecord)>) -> Result<(Vec<Command>, u64), StoreError> {
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
                    && let (Some(stamp), Some(blob)) = (m.stamp, store.blob(&id)?)
                {
                    bytes += blob.len();
                    entries.push(Entry { blob, wrap: m.wrap, stamp });
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
