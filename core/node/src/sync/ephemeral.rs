//! The ephemeral lane (notes/ephemeral.md Synced ephemeral data): memory commits (the engine's
//! memory class, issues/eph-unify.md) travel as ordinary entries (sealed with the ephemeral or
//! relay prefix class, wrapped, stamped, uploaded, announced by the host's log and pushes) but
//! are held in memory only: here as blobs per label, in the engine as memory commits; nothing of
//! them reaches the store or the sync records. The engine hands the lane its own memory commits
//! to place (`Engine::take_memory_commits`, coalesced per aspect while an upload is in flight),
//! received blobs go to `Engine::ingest_memory` within the room the node cap leaves, and the
//! commits the engine forgets (covered by a memory snapshot, superseded, expired, freed) come
//! back as drops (`Engine::take_memory_drops`): their entries are forgotten here and a writer
//! deletes them at a host once the snapshot that covers them is held there (`waiting`). Holders
//! bring what a host or peer lacks: a node lists the ephemeral entries it holds under a label as
//! `gained` in its first Sync of the label on each connection and uploads what the peer wants;
//! an entry received from one host or peer goes to the others it syncs the label with (stamped
//! entries only; own ones are stamped here). Relay-only entries (signals) are delivered and
//! passed to nobody. Per label, the bytes held from others are capped
//! (`SyncConfig::ephemeral_bytes`): past it further ephemeral commits of the label are not
//! applied (`EphemeralRefused`). A host refusing an entry for its cap triggers nothing but a
//! report and the retry at the periodic pass (`eph_retry`).

use super::state::HostKey;
use super::{Action, ConnId, Phase, SyncEngine};
use crate::engine::MemoryDrop;
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use crate::labeling::{HeadKeys, delete_item, delete_item_by_level, delete_key, open_commit, seal_body_as};
use crate::Ingested;
use osis_base::{BlobId, CommitId, LabelId, Tid};
use osis_commit::{CommitBlob, DeleteKey, EphClass};
use osis_crypto::{Signature, SigningSecret, VerifyingKey};
use osis_label::Class;
use osis_proto::{Code, Command};
use std::collections::{BTreeMap, BTreeSet};

/// Where an ephemeral or relay-only entry came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayFrom {
    /// A host or a peer this node dialed (`None`: a bundle, nobody).
    Host(Option<HostKey>),
    /// A session this node serves.
    Served(ConnId),
}

impl RelayFrom {
    fn host(self) -> Option<HostKey> {
        match self {
            RelayFrom::Host(s) => s,
            RelayFrom::Served(_) => None,
        }
    }
}

/// One ephemeral entry held under a label (in memory).
#[derive(Clone)]
pub(crate) struct LaneEntry {
    pub commit: CommitId,
    pub blob: Vec<u8>,
    pub wrap: [u8; osis_crypto::WRAP_LEN],
    /// Under the label's write key: a writer stamps every entry it uploads under the head's
    /// write key there (`eph_upload`); a reader relays the stamp it received.
    pub stamp: Option<Signature>,
    /// Built here: not counted against the cap.
    pub own: bool,
    /// What a delete signature by a delete key needs (spec/crypto.md §7): the blob's prefix
    /// salt, the header's blind, the first part's thing, the header's actor and its keys.
    pub salt: [u8; 16],
    pub blind: [u8; 16],
    pub tid: Tid,
    pub actor: Tid,
    pub keys: Vec<DeleteKey>,
    /// What it counts against the label's cap (others' entries: `Engine::memory_charge` of
    /// its parts, at least its bytes).
    pub charge: u64,
}

/// A waiting delete (`Lane::waiting`) with its entry: what an upload carries as a replacement.
pub(crate) type Waiting = (BlobId, BTreeSet<CommitId>, osis_label::DeleteItem);

/// Waiting deletes per (label, host) at most. Resource bound against a host that never holds
/// covers (refuses them other than for its cap, or deletes them): past it the oldest waiting
/// delete there is dropped, its entry left at that host as a covered replay (a writer that
/// fetches it deletes it then; else the host's cap bounds it). 0: no delete waits for its cover
/// (each absorbed entry stays up there until fetched again); infinity: the set grows with every
/// absorbed own commit and `eph_flush` walks it all each step. An honest host holds a cover
/// within a round trip: what waits is what covers in flight absorb (a replacement message
/// carries at most 1024). About 300 bytes each: about 1.2 MiB per (label, host) at the bound.
pub(crate) const WAITING_MAX: usize = 1 << 12;

type WaitKey = (LabelId, BlobId, HostKey);
type WaitVal = (BTreeSet<CommitId>, osis_label::DeleteItem);

/// `Lane::waiting`: per (label, blob, host) the covers a delete waits for, bounded per
/// (label, host) by `WAITING_MAX` (the oldest dropped).
#[derive(Default)]
pub(crate) struct WaitingDeletes {
    map: BTreeMap<WaitKey, (WaitVal, u64)>,
    /// Insertion order per (label, host), and how many wait there.
    order: BTreeSet<(LabelId, HostKey, u64, BlobId)>,
    count: BTreeMap<(LabelId, HostKey), usize>,
    next: u64,
}

impl WaitingDeletes {
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// How many wait at host `s` under `l`.
    pub fn at(&self, l: LabelId, s: HostKey) -> usize {
        self.count.get(&(l, s)).copied().unwrap_or(0)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&WaitKey, &WaitVal)> {
        self.map.iter().map(|(k, (v, _))| (k, v))
    }

    /// The waiting deletes under `l`.
    pub fn of_label(&self, l: LabelId) -> impl Iterator<Item = (&WaitKey, &WaitVal)> {
        self.map.range((l, BlobId([0; 32]), [0u8; 32])..).take_while(move |((l2, _, _), _)| *l2 == l).map(|(k, (v, _))| (k, v))
    }

    pub fn get(&self, k: &WaitKey) -> Option<&WaitVal> {
        self.map.get(k).map(|(v, _)| v)
    }

    pub fn get_mut(&mut self, k: &WaitKey) -> Option<&mut WaitVal> {
        self.map.get_mut(k).map(|(v, _)| v)
    }

    pub fn remove(&mut self, k: &WaitKey) -> Option<WaitVal> {
        let (v, n) = self.map.remove(k)?;
        self.order.remove(&(k.0, k.2, n, k.1));
        if let Some(c) = self.count.get_mut(&(k.0, k.2)) {
            *c -= 1;
            if *c == 0 {
                self.count.remove(&(k.0, k.2));
            }
        }
        Some(v)
    }

    /// Adds (or replaces) a waiting delete; past `WAITING_MAX` at its (label, host) the oldest
    /// there is dropped.
    pub fn insert(&mut self, k: WaitKey, v: WaitVal) {
        if let Some((old, _)) = self.map.get_mut(&k) {
            *old = v;
            return;
        }
        let (l, b, s) = k;
        if self.at(l, s) >= WAITING_MAX
            && let Some(&(_, _, _, oldest)) = self.order.range((l, s, 0, BlobId([0; 32]))..).next()
        {
            self.remove(&(l, oldest, s));
        }
        *self.count.entry((l, s)).or_default() += 1;
        self.next += 1;
        self.order.insert((l, s, self.next, b));
        self.map.insert(k, (v, self.next));
    }
}

/// Ephemeral entries remembered per label with a value and a weight, at most `max` weight per
/// label, the oldest forgotten past it (`Lane::unfit`).
pub(crate) struct PerLabel<V> {
    map: BTreeMap<(LabelId, BlobId), (V, usize)>,
    /// Per label, its entries oldest first and their total weight.
    order: BTreeMap<LabelId, (std::collections::VecDeque<BlobId>, usize)>,
    max: usize,
}

impl<V> PerLabel<V> {
    fn new(max: usize) -> PerLabel<V> {
        PerLabel { map: BTreeMap::new(), order: BTreeMap::new(), max }
    }

    pub fn contains(&self, l: LabelId, b: BlobId) -> bool {
        self.map.contains_key(&(l, b))
    }

    /// Remembers `b` of `l` with `v` weighing `w` (replacing what it had, as the newest);
    /// whether `l` had none before.
    pub fn insert(&mut self, l: LabelId, b: BlobId, v: V, w: usize) -> bool {
        let had = self.order.contains_key(&l);
        self.remove(l, b);
        self.map.insert((l, b), (v, w));
        let (q, total) = self.order.entry(l).or_default();
        q.push_back(b);
        *total += w;
        while *total > self.max
            && let Some(old) = q.pop_front()
            && let Some((_, ow)) = self.map.remove(&(l, old))
        {
            *total -= ow;
        }
        if q.is_empty() {
            self.order.remove(&l);
        }
        !had
    }

    pub fn remove(&mut self, l: LabelId, b: BlobId) -> Option<V> {
        let (v, w) = self.map.remove(&(l, b))?;
        if let Some((q, total)) = self.order.get_mut(&l) {
            q.retain(|x| *x != b);
            *total -= w;
            if q.is_empty() {
                self.order.remove(&l);
            }
        }
        Some(v)
    }
}

/// Never-fitting entries remembered per label (`Lane::unfit`). Resource bound: about 100 bytes
/// each, 400 KiB per label at the bound; a host's cap holds a few hundred such entries per
/// label (about 25 KB each at the least), so honest hosts never reach it (0: each is fetched
/// again after every drop under the cap; infinity: a writer uploading and deleting such entries
/// grows the set for good).
const UNFIT_MAX: usize = 1 << 12;

impl Default for PerLabel<()> {
    fn default() -> Self {
        PerLabel::new(UNFIT_MAX)
    }
}

/// The lane's state (in memory).
#[derive(Default)]
pub(crate) struct Lane {
    pub entries: BTreeMap<(LabelId, BlobId), LaneEntry>,
    pub by_commit: BTreeMap<CommitId, BTreeSet<(LabelId, BlobId)>>,
    /// Entries known held at a host or peer (on the connection up now).
    pub present: BTreeSet<(HostKey, LabelId, BlobId)>,
    /// Bytes held from others per label.
    pub bytes: BTreeMap<LabelId, u64>,
    /// Labels whose cap was hit (reported once until bytes drop under it).
    pub refused: BTreeSet<LabelId>,
    /// Labels whose share for unverified entries was hit (reported once until a waiting entry
    /// leaves it, which reconciles the label: room in the cap is no room in the share, and
    /// reconciling at it fetched what the share refused again at every drop).
    pub refused_pending: BTreeSet<LabelId>,
    /// Entries that can never fit their label's cap here (encoded past the whole cap, a part
    /// whose decoded bound is, `Engine::memory_bound`, or refused for the cap with nothing
    /// else held there): not fetched or opened again, so each drop under the cap does not fetch
    /// them again (up to `MAX_BLOB` each). Forgotten when a host deletes them.
    pub unfit: PerLabel<()>,
    /// Per connection and label: whether the first Sync listed the held entries, and those it
    /// listed that the peer has not asked for yet.
    pub announced: BTreeSet<(ConnId, LabelId)>,
    pub gained: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    /// Lane uploads (relay-only ones included) and deletes sent and not answered: their
    /// statuses are the lane's, never a sync record's.
    pub uploads: BTreeSet<(ConnId, LabelId, BlobId)>,
    /// Those of `uploads` of own plain entries, kept while unanswered whether or not the entry
    /// is still held (one forgotten meanwhile, covered by a snapshot, still holds the label
    /// busy, `eph_busy`).
    pub own_uploads: BTreeSet<(ConnId, LabelId, BlobId)>,
    /// Lane deletes in flight with the item sent and the label key that signed it.
    pub deletes: BTreeMap<(ConnId, LabelId, BlobId), (osis_label::DeleteItem, VerifyingKey)>,
    /// Lane deletes to send again (`Redo`).
    pub redelete: BTreeMap<(ConnId, LabelId, BlobId), (osis_label::DeleteItem, Redo)>,
    /// Entries in flight on a connection that this node stamped, with the write key.
    pub stamped: BTreeMap<(ConnId, LabelId, BlobId), VerifyingKey>,
    /// Entries this node stamped that a connection's head refused as stamped under another write
    /// key (code 9), or own or unstamped ones that had no write key to go under there, with the
    /// key tried (`None`): stamped again
    /// and sent once the connection's keys give another (`eph_restamp`), dropped once this node
    /// is no longer a writer of the label.
    pub restamp: BTreeMap<(ConnId, LabelId, BlobId), Option<VerifyingKey>>,
    /// Entries a host refused for its cap (reported once each) or its rate (code 4), per
    /// connection: uploaded there again at the periodic pass (`eph_retry`).
    pub capped: BTreeSet<(ConnId, LabelId, BlobId)>,
    /// Entries forgotten while their upload was in flight on a connection, with the cover that
    /// absorbed them: deleted there once the upload is answered OK (else a slow host kept every
    /// covered entry; `waiting` while that cover is not held there), and not taken back
    /// meanwhile from a peer that has it (it is no longer covered by anything held).
    pub orphans: BTreeMap<(LabelId, BlobId, ConnId), (osis_label::DeleteItem, BTreeSet<CommitId>)>,
    /// Deletes of covered entries at a host, waiting until the snapshots that cover them are
    /// held there (`eph_flush`): deleting first lost their writes at that host for good when the
    /// coverer never came (its author crashed in between; the tombstone keeps holders from
    /// bringing them back). An own snapshot refused for the cap deletes them at once and goes
    /// again (room for it).
    pub waiting: WaitingDeletes,
    /// Waiting deletes an own upload in flight carries as replacements (spec/sync.md §5,
    /// Replace: the host removes them iff it admits the upload), by upload: back in
    /// `waiting` unless it is answered OK.
    pub replacing: BTreeMap<(ConnId, LabelId, BlobId), Vec<Waiting>>,
    /// (host, label) reconciled since start, and the reconciliations running (`sync_label`)
    /// with the ephemeral entries their set listed: only those the reply can say the peer holds
    /// (one arriving meanwhile from elsewhere is not known there).
    pub reconciled: BTreeSet<(HostKey, LabelId)>,
    pub reconciling: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    /// What each label's reconciliation on a connection asked for: one ending with any of it
    /// unanswered reconciles that label again on the next (nothing else here knows of an
    /// ephemeral entry the cursor passed, so nothing would ask for it again).
    pub reconcile_fetches: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    /// Entries whose commit waits in the engine (pending: a record or chain not here yet):
    /// neither served nor spread, with where they came from; their charge per label
    /// (`PENDING_SHARE`: what the blob could cost decoded, `Engine::memory_bound`, at least
    /// its bytes): what its promotion is counted at most (`eph_promote`).
    pub pending: BTreeMap<(LabelId, BlobId), (LaneEntry, Option<HostKey>)>,
    pub pending_bytes: BTreeMap<LabelId, u64>,
    /// Held entry IDs by blob (serving a fetch by ID).
    pub by_blob: BTreeSet<(BlobId, LabelId)>,
    /// Relay-only entries received (`RelaySeen`).
    pub relays: RelaySeen,
}

/// The share of `SyncConfig::ephemeral_bytes` a label's unverified entries (waiting for a record
/// or for validity) may take. Resource bound: past it further such entries are not kept (they
/// come back at a restart's reconciliation); 1 (the whole cap): a writer's commits under made-up
/// authors could fill what honest ones need; infinity (none): an honest commit arriving before
/// its author's record is lost until then.
const PENDING_SHARE: u64 = 4;

/// Relay-only entries remembered as received, node-wide, until their prefix expiry. Resource
/// bound against hostile writers: past it the earliest-expiring is forgotten and its expiry
/// becomes its label's floor, at or below which relay-only entries are dropped, so none is
/// delivered twice (0: only increasing expiries pass; infinity: memory grows with every signal of
/// the replay window). About 200 bytes each: 13 MiB at the bound.
const RELAYS_REMEMBERED: usize = 1 << 16;

/// Relay-only entries received: (label, blob) until their prefix expiry, and a floor per label.
#[derive(Default)]
pub(crate) struct RelaySeen {
    ids: std::collections::HashSet<(LabelId, BlobId)>,
    by_expiry: BTreeSet<(u64, LabelId, BlobId)>,
    floor: BTreeMap<LabelId, u64>,
}

impl RelaySeen {
    /// Whether relay-only entry `b` of `l`, expiring at `t`, is seen here for the first time
    /// (`now` wall ms): not a repeat, not at or below the label's floor.
    pub(crate) fn first(&mut self, l: LabelId, b: BlobId, t: u64, now: u64) -> bool {
        if !self.fresh(l, b, t, now) {
            return false;
        }
        self.record(l, b, t);
        true
    }

    /// Whether relay-only entry `b` of `l`, expiring at `t`, would be seen here for the first
    /// time, without recording it (checked before opening it; recorded once verified, so a
    /// stranger's junk cannot raise a label's floor).
    pub(crate) fn fresh(&mut self, l: LabelId, b: BlobId, t: u64, now: u64) -> bool {
        while let Some(x) = self.by_expiry.first().copied()
            && x.0 <= now
        {
            self.by_expiry.pop_first();
            self.ids.remove(&(x.1, x.2));
        }
        self.floor.retain(|_, f| *f > now);
        !(self.floor.get(&l).is_some_and(|f| t <= *f) || self.ids.contains(&(l, b)))
    }

    /// Records relay-only entry `b` of `l`, expiring at `t`, as seen.
    pub(crate) fn record(&mut self, l: LabelId, b: BlobId, t: u64) {
        if !self.ids.insert((l, b)) {
            return;
        }
        self.by_expiry.insert((t, l, b));
        if self.ids.len() > RELAYS_REMEMBERED
            && let Some((t0, l0, b0)) = self.by_expiry.pop_first()
        {
            self.ids.remove(&(l0, b0));
            let f = self.floor.entry(l0).or_default();
            *f = (*f).max(t0);
        }
    }
}

/// `OSIS_EPH_TRACE` (diagnostics): unset, no trace; `all`, every lane event; else a hex prefix
/// of the commit IDs (or blob IDs) to follow. Read once per process.
fn eph_trace_filter() -> Option<&'static str> {
    static F: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    F.get_or_init(|| std::env::var("OSIS_EPH_TRACE").ok().map(|v| v.to_ascii_lowercase())).as_deref()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A host key, short, for the trace.
fn host6(s: &HostKey) -> String {
    hex(&s[..3])
}

impl SyncEngine {
    /// One stderr line per lane event of a traced commit (`eph_trace_filter`): `EPH node <tid>
    /// commit <c> blob <b> label <l>: <what>`. The commit is `c`, else the lane's entry's (held
    /// or waiting), else unknown (`-`: a blob not opened yet, matched by its ID). Off, it costs one
    /// load: callers compute nothing for it (a commit ID to hash goes through `eph_trace_filter`).
    /// IDs, sizes and outcomes only, never keys or plaintext.
    fn eph_trace(&self, l: &LabelId, b: &BlobId, c: Option<&CommitId>, what: impl FnOnce() -> String) {
        let Some(f) = eph_trace_filter() else { return };
        let c = c.copied().or_else(|| self.eph.entries.get(&(*l, *b)).or_else(|| self.eph.pending.get(&(*l, *b)).map(|x| &x.0)).map(|e| e.commit));
        let (ch, bh) = (c.map(|c| hex(&c.0)), hex(&b.0));
        if f != "all" && !ch.as_deref().is_some_and(|x| x.starts_with(f)) && !bh.starts_with(f) {
            return;
        }
        let t = self.engine.tid().to_string();
        eprintln!("EPH node {} commit {} blob {} label {}: {}", &t[..t.len().min(6)], ch.as_deref().map_or("-", |x| &x[..12]), &bh[..12], &hex(&l.0)[..8], what());
    }

    /// The write key that stamps under `l` of `g` now: an open connection's, else the served
    /// head's (a label synced with nobody, or served to peers).
    fn eph_stamp_key(&mut self, g: &Tid, l: &LabelId) -> Option<SigningSecret> {
        for c in self.conns.values() {
            if let Some(x) = c.labels.get(l).filter(|x| x.phase == Phase::Open && !x.receipts)
                && let Some(w) = &x.keys.write
            {
                return Some(w.clone());
            }
        }
        let served = self.served_labels();
        let head = served.get(l)?.head()?.clone();
        let index = self.group_label(g, l).map(|gl| gl.index)?;
        self.engine.head_keys(g, index, &head).ok()?.write
    }

    /// Open connections with label `l` (connection, host key, keys).
    fn eph_conns(&self, l: &LabelId) -> Vec<(ConnId, HostKey, HeadKeys)> {
        self.conns.iter().filter_map(|(id, c)| c.labels.get(l).filter(|x| x.phase == Phase::Open && !x.receipts && c.up).map(|x| (*id, c.host, x.keys.clone()))).collect()
    }

    /// An open connection with label `l` to host `s`.
    fn eph_conn_to(&self, l: &LabelId, s: HostKey) -> Option<ConnId> {
        self.eph_conns(l).into_iter().find(|(_, host, _)| *host == s).map(|x| x.0)
    }

    /// Per step: promotes entries whose commits applied, compacts the memory aspects due
    /// (`Engine::memory_compactions`), takes the own memory commits to send (coalesced while an
    /// own upload is in flight), forgets (and deletes where it uploaded) what the engine
    /// dropped, reconciles the labels of aspects whose snapshot fell invalid, places what is to
    /// send, and sends the signals.
    pub(crate) fn eph_step(&mut self, out: &mut Vec<Action>) -> Result<()> {
        self.eph_promote(out)?;
        let busy = self.eph_busy();
        let signals = self.engine.take_signals()?;
        // a snapshot fell invalid: a writer snapshots what it still holds (placed below), and
        // the labels are reconciled for the rest
        for (t, _) in self.engine.take_memory_invalidated()? {
            self.eph_reconcile_thing(&t);
        }
        self.engine.memory_compactions(false)?;
        let commits = self.engine.take_memory_commits(&busy)?;
        // what a snapshot covers is deleted at a host once the snapshot is held there
        // (`waiting`): a holder applies the snapshot first, and an author crashing in between
        // loses nothing
        let dropped = self.engine.take_memory_drops();
        self.eph_forget(&dropped, out)?;
        for c in commits {
            if let Some(blob) = self.engine.memory_blob(&c)? {
                self.eph_place(c, blob, EphClass::Plain, out)?;
            }
        }
        for c in signals {
            self.eph_place(c.id, c.blob, EphClass::Relay, out)?;
        }
        self.eph_restamp(out)?;
        self.eph_redelete(out)?;
        self.eph_flush(out)?;
        #[cfg(debug_assertions)]
        self.eph_check_counts();
        Ok(())
    }

    /// Reconciles the labels whose closure holds `t` at their next periodic pass: a memory
    /// snapshot of one of its aspects fell invalid here, and the bodies it covered are gone
    /// until copies holders still have (their authors', notes/ephemeral.md) arrive again.
    fn eph_reconcile_thing(&mut self, t: &Tid) {
        let labels: Vec<LabelId> = self.labels().into_iter().filter(|(g, _)| self.engine.in_ephemeral_closure(g, t)).map(|(_, gl)| gl.id).collect();
        self.eph.reconciled.retain(|(_, l)| !labels.contains(l));
    }

    /// Debug builds: the labels' counts are their entries' charges.
    #[cfg(debug_assertions)]
    fn eph_check_counts(&self) {
        let mut bytes: BTreeMap<LabelId, u64> = BTreeMap::new();
        for ((l, _), e) in self.eph.entries.iter().filter(|(_, e)| !e.own) {
            *bytes.entry(*l).or_default() += e.charge;
        }
        let mut pending: BTreeMap<LabelId, u64> = BTreeMap::new();
        for ((l, _), (e, _)) in &self.eph.pending {
            *pending.entry(*l).or_default() += e.charge;
        }
        let nonzero = |m: &BTreeMap<LabelId, u64>| m.iter().filter(|(_, n)| **n > 0).map(|(l, n)| (*l, *n)).collect::<BTreeMap<_, _>>();
        assert_eq!(nonzero(&bytes), nonzero(&self.eph.bytes), "label counts");
        assert_eq!(nonzero(&pending), nonzero(&self.eph.pending_bytes), "waiting counts");
    }

    /// Deletes waiting for another head key (`Redo::Head`): sent again once the connection's
    /// keys give another key for them; dropped once they give none and this node no longer
    /// has the role (`eph_may_delete`; a key missing for now, not established or uncovered,
    /// comes back).
    fn eph_redelete(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.eph.redelete.is_empty() {
            return Ok(());
        }
        let mut due = Vec::new();
        let mut keyless = Vec::new();
        for ((c, l, b), (item, redo)) in &self.eph.redelete {
            let Redo::Head(tried) = redo else { continue };
            let Some(lc) = self.lc(*c, l).filter(|x| x.phase == Phase::Open) else { continue };
            match delete_key(&lc.keys, item).map(|k| k.verifying_key()) {
                Some(k) if Some(k) != *tried => due.push((*c, *l, *b)),
                Some(_) => {}
                None => keyless.push((*c, *l, *b)),
            }
        }
        for (conn, l, b) in keyless {
            if !self.redelete_may(conn, l, b) {
                self.eph.redelete.remove(&(conn, l, b));
            }
        }
        for (conn, l, b) in due {
            if let Some((item, _)) = self.eph.redelete.remove(&(conn, l, b)) {
                self.eph_delete_now(conn, l, b, item, out)?;
            }
        }
        Ok(())
    }

    /// Entries waiting for another write key on a connection (`Lane::restamp`): sent
    /// stamped under it once the label is open there with one; dropped (reported) once this
    /// node is no longer a writer of the label, or the entry is gone.
    fn eph_restamp(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.eph.restamp.is_empty() {
            return Ok(());
        }
        let waiting: Vec<((ConnId, LabelId, BlobId), Option<VerifyingKey>)> = self.eph.restamp.iter().map(|(k, v)| (*k, *v)).collect();
        let mut lost = BTreeSet::new();
        for ((conn, l, b), tried) in waiting {
            if !self.eph.entries.contains_key(&(l, b)) {
                self.eph.restamp.remove(&(conn, l, b));
                continue;
            }
            if !self.eph_writes(conn, &l) {
                self.eph.restamp.remove(&(conn, l, b));
                if self.eph.entries.get(&(l, b)).is_some_and(|e| e.own) {
                    lost.insert(l);
                }
                continue;
            }
            let Some(lc) = self.lc(conn, &l).filter(|x| x.phase == Phase::Open) else { continue };
            if lc.keys.write.as_ref().is_some_and(|w| Some(w.verifying_key()) != tried) {
                self.eph_upload_on(conn, l, &[b], out)?;
            }
        }
        for l in lost {
            self.eph_report(&l, "this node no longer writes the label: its own ephemeral entries are not sent");
        }
        Ok(())
    }

    /// Whether this node still has the role `item` is signed for under `l` (admin for the head
    /// delete key, else writer): a key it lacks for now may come back.
    fn eph_may_delete(&mut self, conn: ConnId, l: &LabelId, item: &osis_label::DeleteItem) -> bool {
        let need = if item.by.is_none() { osis_base::Role::Admin } else { osis_base::Role::Write };
        self.group_of(l, Some(conn)).is_some_and(|g| self.engine.role_on(&g) >= Some(need))
    }

    fn redelete_may(&mut self, conn: ConnId, l: LabelId, b: BlobId) -> bool {
        let Some(item) = self.eph.redelete.get(&(conn, l, b)).map(|x| x.0.clone()) else { return false };
        self.eph_may_delete(conn, &l, &item)
    }

    /// Whether this node writes label `l` (its group's role on `conn`).
    fn eph_writes(&mut self, conn: ConnId, l: &LabelId) -> bool {
        self.group_of(l, Some(conn)).is_some_and(|g| self.engine.role_on(&g) >= Some(osis_base::Role::Write))
    }

    /// Whether an entry of commit `c` under `l` is held at host `s`.
    fn eph_held_at(&self, c: &CommitId, l: &LabelId, s: HostKey) -> bool {
        self.eph.by_commit.get(c).is_some_and(|ks| ks.iter().any(|(l2, b)| l2 == l && self.eph.present.contains(&(s, *l2, *b))))
    }

    /// Whether every cover of `cs` is held at host `s` under `l`. One never placed under `l`
    /// (its thing's placement there not back yet after a restart) keeps the entry it covers at
    /// the host under `l` until a later cover is placed there (`eph_forget` moves the waiting
    /// delete to it): a reader of `l` alone would lose the entry otherwise.
    fn eph_covers_held_at(&self, cs: &BTreeSet<CommitId>, l: &LabelId, s: HostKey) -> bool {
        self.eph_covers_held_with(cs, l, s, None)
    }

    /// `eph_covers_held_at`, counting commit `also` (being uploaded there) as held.
    fn eph_covers_held_with(&self, cs: &BTreeSet<CommitId>, l: &LabelId, s: HostKey, also: Option<&CommitId>) -> bool {
        cs.iter().all(|c| Some(c) == also || self.eph_held_at(c, l, s))
    }

    /// Sends the waiting deletes whose covers are held at their host now (on a connection
    /// where the label is open).
    fn eph_flush(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.eph.waiting.is_empty() {
            return Ok(());
        }
        let ready: Vec<(LabelId, BlobId, HostKey)> = self.eph.waiting.iter().filter(|((l, _, s), (cs, _))| self.eph_covers_held_at(&self.eph_covers(cs), l, *s)).map(|(k, _)| *k).collect();
        for (l, b, s) in ready {
            let Some(conn) = self.eph_conn_to(&l, s) else { continue };
            let Some((_, item)) = self.eph.waiting.remove(&(l, b, s)) else { continue };
            self.eph_delete_now(conn, l, b, item, out)?;
        }
        Ok(())
    }

    /// Those of the covers `cs` this node holds (their entries placed, or about to be); a cover
    /// since covered itself was replaced in the waiting deletes by what covered it
    /// (`eph_forget`), so one held nowhere adds nothing.
    fn eph_covers(&self, cs: &BTreeSet<CommitId>) -> BTreeSet<CommitId> {
        cs.iter().filter(|c| self.eph.by_commit.contains_key(c) || self.engine.holds_memory(c)).copied().collect()
    }

    /// Deletes absorbed entry `b` of `l` at host `s` on `conn` once `covers` (or what absorbed
    /// them since) are held there.
    #[allow(clippy::too_many_arguments)]
    fn eph_delete_after(&mut self, conn: ConnId, s: HostKey, l: LabelId, b: BlobId, item: osis_label::DeleteItem, covers: BTreeSet<CommitId>, out: &mut Vec<Action>) -> Result<()> {
        let cs = self.eph_covers(&covers);
        if !cs.is_empty() && !self.eph_covers_held_at(&cs, &l, s) {
            self.eph_trace(&l, &b, None, || format!("delete at host {} waits for {} covers", host6(&s), cs.len()));
            self.eph.waiting.insert((l, b, s), (cs, item));
            return Ok(());
        }
        self.eph_delete_now(conn, l, b, item, out)
    }

    /// Sends at once the waiting deletes at `host` under `l` of what own entry `b`'s commit
    /// absorbs (refused for the cap: room for it). Whether there were any.
    fn eph_free_for(&mut self, conn: ConnId, host: HostKey, l: LabelId, b: BlobId, out: &mut Vec<Action>) -> Result<bool> {
        let Some(commit) = self.eph.entries.get(&(l, b)).filter(|e| e.own).map(|e| e.commit) else { return Ok(false) };
        let freed: Vec<(LabelId, BlobId, HostKey)> = self.eph.waiting.iter().filter(|((l2, _, s), (cs, _))| *l2 == l && *s == host && cs.contains(&commit)).map(|(k, _)| *k).collect();
        for k in &freed {
            if let Some((_, item)) = self.eph.waiting.remove(k) {
                self.eph_delete_now(conn, k.0, k.1, item, out)?;
            }
        }
        Ok(!freed.is_empty())
    }

    /// Sends a delete signed under `conn`'s keys now; when they hold no key for it, it waits for
    /// one while this node has the role (`eph_may_delete`, `Redo::Head`), else it is dropped.
    fn eph_delete_now(&mut self, conn: ConnId, l: LabelId, b: BlobId, item: osis_label::DeleteItem, out: &mut Vec<Action>) -> Result<()> {
        if self.eph.deletes.contains_key(&(conn, l, b)) {
            return Ok(());
        }
        self.eph.redelete.remove(&(conn, l, b));
        let Some((item, key)) = self.eph_resign(conn, l, item.clone()) else {
            let keyed = self.lc(conn, &l).and_then(|lc| delete_key(&lc.keys, &item).map(|k| k.verifying_key()));
            if keyed.is_some() || self.eph_may_delete(conn, &l, &item) {
                self.eph.redelete.insert((conn, l, b), (item, Redo::Head(keyed)));
            }
            return Ok(());
        };
        self.eph_trace(&l, &b, None, || format!("delete sent on conn {conn}"));
        self.eph.deletes.insert((conn, l, b), (item.clone(), key));
        self.command(conn, Command::Delete { label: l, items: vec![item] }, out)
    }

    /// A delete made under an earlier head (waiting for a cover, carried by one refused 9, or
    /// refused 9 itself) signed under the head `l` is open with on `conn` now, with that key;
    /// `None` when the connection holds no key for it (a writer demoted, or an admin's delete
    /// by the head delete key once it is no longer admin): refused under every head, it is not
    /// sent (the entry leaves that host at its expiry, or by another writer's delete).
    fn eph_resign(&self, conn: ConnId, l: LabelId, item: osis_label::DeleteItem) -> Option<(osis_label::DeleteItem, VerifyingKey)> {
        let k = delete_key(&self.lc(conn, &l)?.keys, &item)?;
        Some((item.resign(k, &l).ok()?, k.verifying_key()))
    }

    /// What waits for an own ephemeral upload in flight (sent, not answered): the groups of the
    /// labels where every connection the label is open on has an own entry in flight. Their next
    /// writes wait and join (`Engine::take_memory_commits`) until an answer (or a connection's end)
    /// frees one, so a node sends about one such commit per label per round trip of its fastest
    /// connection, whatever its write rate, and a slow or silent connection holds up nothing
    /// another one can carry (spec/sync.md §9). A thing under several labels waits while any of
    /// them is busy.
    fn eph_busy(&self) -> BTreeSet<Tid> {
        let mut plain: BTreeMap<LabelId, (Option<Tid>, BTreeSet<ConnId>)> = BTreeMap::new();
        for (c, l, _) in &self.eph.own_uploads {
            let p = plain.entry(*l).or_default();
            p.0 = p.0.or_else(|| self.conns.get(c).and_then(|x| x.labels.get(l)).map(|x| x.group));
            p.1.insert(*c);
        }
        plain.iter().filter(|(l, (_, cs))| self.eph_conns(l).iter().all(|(c, _, _)| cs.contains(c))).filter_map(|(_, (g, _))| *g).collect()
    }

    /// Entries whose commit was waiting in the engine (a record or chain): held now, they join
    /// the lane and spread; gone meanwhile (its things freed, expired, bad input), they go.
    fn eph_promote(&mut self, out: &mut Vec<Action>) -> Result<()> {
        // the engine's applied list is taken whether or not anything waits: it grows otherwise
        let applied: BTreeSet<CommitId> = self.engine.take_memory_applied().into_iter().collect();
        if self.eph.pending.is_empty() {
            return Ok(());
        }
        let keys: Vec<(LabelId, BlobId)> = self.eph.pending.keys().copied().collect();
        let mut promoted = BTreeSet::new();
        for (l, b) in keys {
            let Some((e, _)) = self.eph.pending.get(&(l, b)) else { continue };
            let c = e.commit;
            // still waiting
            if self.engine.memory_pending(&c) && !applied.contains(&c) {
                continue;
            }
            let held = self.engine.holds_memory(&c);
            self.eph_trace(&l, &b, Some(&c), || format!("wait over (held {held})"));
            promoted.insert(c);
            let Some((e, from)) = self.eph.pending.remove(&(l, b)) else { continue };
            if let Some(n) = self.eph.pending_bytes.get_mut(&l) {
                *n = n.saturating_sub(e.charge);
            }
            // room in the share: what it refused is fetched again at the next periodic pass
            if self.eph.refused_pending.remove(&l) {
                self.eph.reconciled.retain(|(_, x)| *x != l);
            }
            // the commit is held now, but this blob may be a junk copy (the real header with junk
            // parts or signature, kept apart beside the real one): it arrives again, so its copy
            // is checked against the held commit before it is kept or spread
            // (counted even past the cap: the engine decoded it within its share, and holds it)
            if held && !self.eph.entries.contains_key(&(l, b)) {
                self.eph_added_with(RelayFrom::Host(from), l, b, e.blob, e.wrap, e.stamp, Class::Ephemeral, Some(e.charge), out)?;
            }
        }
        // the node counts what the engine holds: a waiting commit held now is kept by an entry
        // (a junk copy is not; the real one, also waiting, is)
        for c in promoted {
            debug_assert!(!self.engine.holds_memory(&c) || self.eph.by_commit.contains_key(&c) || self.engine.memory_pending(&c), "promoted ephemeral commit {c:?} held by the engine, counted by no entry");
        }
        Ok(())
    }

    /// An ephemeral commit of `l` refused for this node's cap: reported once until bytes drop.
    fn eph_capped(&mut self, l: LabelId) {
        if self.eph.refused.insert(l) {
            self.eph_report(&l, "this node's ephemeral cap for the label refused a commit: commits that would pass it are not applied here");
        }
    }

    /// Ephemeral entry `b` of `l` can never fit this node's cap for it: remembered (`Unfit`),
    /// reported once while the label has such entries.
    fn eph_unfit(&mut self, l: LabelId, b: BlobId) {
        if self.eph.unfit.insert(l, b, (), 1) {
            self.eph_report(&l, "an ephemeral commit larger than this node's whole ephemeral cap for the label is not applied");
        }
    }

    fn eph_report(&mut self, l: &LabelId, detail: &str) {
        let now = self.engine.now();
        let tids = self.group_of(l, None).into_iter().collect();
        self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::EphemeralRefused, tids, commit: None, peer: None, detail: detail.into() }, now);
        self.engine.core.events.flush();
    }

    /// Places an ephemeral commit built here (`blob`: its header and parts) under every synced
    /// label whose closure (ephemeral placements included) holds its things, one blob per
    /// projection the label's actor may read (spec/sync.md §3), and sends it on every connection
    /// where the label is open.
    fn eph_place(&mut self, id: CommitId, blob: CommitBlob, kind: EphClass, out: &mut Vec<Action>) -> Result<()> {
        let class = Class::of_marker(Some(kind));
        for (g, gl) in self.labels() {
            if gl.replaced {
                continue;
            }
            let l = gl.id;
            // the records of their owner chains ride beside the parts (spec/commits.md §2)
            if !blob.header.aspects.iter().any(|a| self.engine.in_ephemeral_closure(&g, &a.tid)) {
                continue;
            }
            let readers: Vec<Option<Tid>> = blob.header.aspects.iter().map(|a| Some(self.engine.ephemeral_reader(&a.tid))).collect();
            let actor = self.engine.group_actor(&g);
            let Some(secret) = self.engine.wrap_secret(&g, None)? else { continue };
            let projections = osis_commit::project(&blob, |ai| readers.get(ai).copied().flatten())?;
            let stamp_key = self.eph_stamp_key(&g, &l);
            for p in projections {
                let Some(reader) = p.readers else { continue };
                if reader != actor && !self.engine.may_read(&actor, &reader) {
                    continue;
                }
                let body = crate::labeling::Body { commit: id, reader, parts: p.parts.clone(), expires: p.expires, keys: p.keys.clone(), blind: blob.header.blind, plaintext: p.plaintext, role_commit: false, order: crate::labeling::fetch_order(&blob.header) };
                let s = seal_body_as(&body, class, &mut *self.rng)?;
                let wrap = osis_crypto::wrap(&secret, &s.id, &s.key, body.order)?;
                let stamp = stamp_key.as_ref().map(|w| osis_label::sign_stamp(w, &l, &s.id, &wrap));
                if kind == EphClass::Relay {
                    self.eph_send_relay(l, s.blob, wrap, stamp, out)?;
                    continue;
                }
                let ai = p.parts.first().map_or(0, |x| x.0);
                let a = blob.header.aspects.get(ai);
                let e = LaneEntry { commit: id, blob: s.blob, wrap, stamp, own: true, salt: s.salt, blind: blob.header.blind, tid: a.map_or(g, |a| a.tid), actor: blob.header.actor, keys: p.keys, charge: 0 };
                self.eph_keep(l, s.id, e);
                self.engine.ephemeral_kept(g, p.parts.iter().filter_map(|(ai, _)| blob.header.aspects.get(*ai).map(|a| a.tid)));
                self.eph_spread(l, s.id, None, out)?;
            }
        }
        Ok(())
    }

    /// Keeps an entry under `l` (served to peers from now on).
    fn eph_keep(&mut self, l: LabelId, b: BlobId, e: LaneEntry) {
        self.eph_trace(&l, &b, Some(&e.commit), || format!("kept ({}, charge {})", if e.own { "own" } else { "others'" }, e.charge));
        if !e.own {
            *self.eph.bytes.entry(l).or_default() += e.charge;
        }
        self.eph.by_commit.entry(e.commit).or_default().insert((l, b));
        self.eph.by_blob.insert((b, l));
        self.eph.entries.insert((l, b), e);
        self.state.feed.added(l, b);
    }

    /// Sends a relay-only entry on every connection where `l` is open (and to the served
    /// sessions, as a co-reader peer would push it), stamped.
    fn eph_send_relay(&mut self, l: LabelId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, out: &mut Vec<Action>) -> Result<()> {
        let blob_id = osis_label::blob_id(&blob);
        if blob.len() > osis_base::format::MAX_RELAY_BLOB {
            self.eph_report(&l, "a signal too large for a relay-only blob was not sent");
            return Ok(());
        }
        // never delivered here again (a co-reader peer's path may bring it back)
        let t = osis_label::Prefix::parse(&blob).ok().and_then(|p| p.expiry()).map_or(0, |t| t.0);
        let now = self.now();
        self.eph.relays.first(l, blob_id, t, now);
        for (conn, _, keys) in self.eph_conns(&l) {
            let st = match (stamp, &keys.write) {
                (Some(s), _) => s,
                (None, Some(w)) => osis_label::sign_stamp(w, &l, &blob_id, &wrap),
                (None, None) => continue,
            };
            self.eph.uploads.insert((conn, l, blob_id));
            self.command(conn, Command::Upload { label: l, entries: vec![osis_proto::Entry { blob: blob.clone(), wrap, stamp: st, replaces: Vec::new() }] }, out)?;
        }
        if let Some(stamp) = stamp
            && !self.served.is_empty()
        {
            let labels = self.served_labels();
            let conns: Vec<ConnId> = self.served.keys().copied().collect();
            let r = osis_proto::Relayed { label: l, blob_id, blob: blob.into(), wrap, stamp };
            for c in conns {
                self.serve_with(c, osis_proto::ServingInput::Relay(r.clone()), &labels, out)?;
            }
        }
        Ok(())
    }

    /// Uploads entry `b` of `l` on every connection where the label is open and the peer is not
    /// known to hold it (but `from`, where it came from).
    ///
    /// Invariant (spec/sync.md §6): once the connected nodes hold the same valid ephemeral
    /// commits and a writer among them holds each, every host of the label holds them. It rests
    /// on: `present` names only what was learned on the connection up now (`eph_lost` clears
    /// it, a promoted entry adds nothing from before its wait); every entry kept goes to each
    /// open connection not known to hold it, here or by the first Sync's `gained` list; and a
    /// writer stamps what it uploads under the head's current key (`eph_upload`), so a stamp
    /// from before a rotation does not strand an entry. A reader alone holding an entry stamped
    /// under an earlier key cannot put it back.
    fn eph_spread(&mut self, l: LabelId, b: BlobId, from: Option<HostKey>, out: &mut Vec<Action>) -> Result<()> {
        let conns = self.eph_conns(&l);
        self.eph_trace(&l, &b, None, || format!("spread on {} open connections", conns.len()));
        for (conn, host, keys) in conns {
            if Some(host) == from || self.eph.present.contains(&(host, l, b)) {
                self.eph_trace(&l, &b, None, || format!("not spread to host {}: {}", host6(&host), if Some(host) == from { "came from it" } else { "present" }));
                continue;
            }
            self.eph_upload(conn, l, &[b], &keys, out)?;
        }
        Ok(())
    }

    /// Uploads lane entries `ids` of `l` on `conn`, stamped under the connection's write key
    /// (a reader: others' stamped ones as they are).
    fn eph_upload(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId], keys: &HeadKeys, out: &mut Vec<Action>) -> Result<()> {
        let mut entries = Vec::new();
        let mut room = osis_proto::msg::MAX_ITEMS;
        for b in ids {
            // one upload of an entry in flight per connection: a second status would reach the
            // sync records (`eph_status`)
            if self.eph.uploads.contains(&(conn, l, *b)) {
                continue;
            }
            let Some((own, stamped)) = self.eph.entries.get(&(l, *b)).map(|e| (e.own, e.stamp.is_some())) else { continue };
            // a writer stamps whatever it uploads under this connection's head, its own entries
            // and others' alike: one stamped before a rotation (built offline, for another
            // host, or another's stamped before a demotion and promotion) is refused under it
            // (code 9), and only a writer can put it back (spec/sync.md §9). An own or unstamped
            // entry with no write key there waits for one (`eph_restamp`), unless this node does
            // not write the label (a thing also under a group it only reads): never sent there
            if (own || !stamped) && keys.write.is_none() {
                if self.eph_writes(conn, &l) {
                    self.eph.restamp.insert((conn, l, *b), None);
                }
                continue;
            }
            let Some(e) = self.eph.entries.get_mut(&(l, *b)) else { continue };
            let stamp = match (e.stamp, &keys.write) {
                (_, Some(w)) => {
                    let s = osis_label::sign_stamp(w, &l, b, &e.wrap);
                    e.stamp = Some(s);
                    self.eph.stamped.insert((conn, l, *b), w.verifying_key());
                    s
                }
                (Some(s), _) => s,
                _ => continue,
            };
            let (blob, wrap) = (e.blob.clone(), e.wrap);
            let replaces = self.eph_replaces(conn, l, *b, &mut room);
            self.eph_trace(&l, b, None, || format!("upload on conn {conn} ({} replaced)", replaces.len()));
            entries.push(osis_proto::Entry { blob, wrap, stamp, replaces });
            self.eph.uploads.insert((conn, l, *b));
            if own {
                self.eph.own_uploads.insert((conn, l, *b));
            }
            self.eph.restamp.remove(&(conn, l, *b));
        }
        if !entries.is_empty() {
            self.command(conn, Command::Upload { label: l, entries }, out)?;
        }
        Ok(())
    }

    /// The waiting deletes at `conn`'s host under `l` that own entry `b` completes (the covers
    /// they wait on are held there once `b` is), at most `room`: carried by its upload as
    /// replacements (spec/sync.md §5), so the host admits the cover and removes what it
    /// absorbs in one step (a holder sees the cover first; no window where neither is there).
    fn eph_replaces(&mut self, conn: ConnId, l: LabelId, b: BlobId, room: &mut usize) -> Vec<osis_label::DeleteItem> {
        let Some(commit) = self.eph.entries.get(&(l, b)).filter(|e| e.own).map(|e| e.commit) else { return Vec::new() };
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Vec::new() };
        let ready: Vec<BlobId> = self
            .eph
            .waiting
            .of_label(l)
            .filter(|((_, _, s), (cs, _))| *s == host && cs.contains(&commit) && self.eph_covers_held_with(&self.eph_covers(cs), &l, host, Some(&commit)))
            .map(|((_, x, _), _)| *x)
            .take(*room)
            .collect();
        let mut replaces = Vec::new();
        let mut moved = Vec::new();
        for x in ready {
            let Some((_, item)) = self.eph.waiting.get(&(l, x, host)) else { continue };
            // one this connection holds no key for stays waiting, uncarried (carried, it would
            // refuse the cover): it goes alone once the cover is held (`eph_delete_now`)
            let Some((signed, _)) = self.eph_resign(conn, l, item.clone()) else { continue };
            let Some((cs, item)) = self.eph.waiting.remove(&(l, x, host)) else { continue };
            replaces.push(signed);
            moved.push((x, cs, item));
        }
        *room -= replaces.len();
        if !moved.is_empty() {
            self.eph.replacing.insert((conn, l, b), moved);
        }
        replaces
    }

    /// The replacements upload `b` of `l` on `conn` carried: done (`ok`), else waiting again.
    /// Whether it carried any.
    fn eph_replaced(&mut self, conn: ConnId, host: HostKey, l: LabelId, b: BlobId, ok: bool) -> bool {
        let Some(moved) = self.eph.replacing.remove(&(conn, l, b)) else { return false };
        for (x, cs, item) in moved {
            if ok {
                self.eph.present.remove(&(host, l, x));
            } else {
                self.eph.waiting.insert((l, x, host), (cs, item));
            }
        }
        true
    }

    /// `eph_upload` under the keys `l` is open with on `conn`.
    pub(crate) fn eph_upload_on(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId], out: &mut Vec<Action>) -> Result<()> {
        match self.lc(conn, &l).map(|x| x.keys.clone()) {
            Some(keys) => self.eph_upload(conn, l, ids, &keys, out),
            None => Ok(()),
        }
    }

    /// The held entry IDs of `l` a first Sync on `conn` lists as gained (none past the message
    /// cap: then everything goes after the Sync, `eph_synced`).
    pub(crate) fn eph_gained(&mut self, conn: ConnId, l: LabelId) -> Vec<BlobId> {
        if !self.eph.announced.insert((conn, l)) {
            return Vec::new();
        }
        let ids: BTreeSet<BlobId> = Self::eph_entries_of(&self.eph, &l).map(|(b, _)| b).collect();
        if ids.is_empty() || ids.len() > osis_proto::msg::MAX_GAINED {
            if !ids.is_empty() {
                self.eph.announced.remove(&(conn, l));
            }
            return Vec::new();
        }
        self.eph.gained.insert((conn, l), ids.clone());
        ids.into_iter().collect()
    }

    /// The peer asked for gained IDs it lacks: the lane's go up. The rest of `ids`.
    pub(crate) fn eph_want(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<Vec<BlobId>> {
        let (mine, rest): (Vec<BlobId>, Vec<BlobId>) = ids.into_iter().partition(|b| self.eph.entries.contains_key(&(l, *b)));
        for b in &mine {
            self.eph_trace(&l, b, None, || format!("wanted by conn {conn}"));
        }
        if let Some(g) = self.eph.gained.get_mut(&(conn, l)) {
            for b in &mine {
                g.remove(b);
            }
        }
        if !mine.is_empty() {
            self.eph_upload_on(conn, l, &mine, out)?;
        }
        Ok(rest)
    }

    /// A Sync of `l` on `conn` ran through: what it listed as gained and the peer did not want,
    /// the peer holds; anything else held goes up (an announcement that did not fit).
    pub(crate) fn eph_synced(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        if let Some(g) = self.eph.gained.remove(&(conn, l)) {
            for b in g {
                self.eph.present.insert((host, l, b));
            }
        }
        // not announced (too many): everything held goes, the peer keeps one copy
        let all = self.eph.announced.insert((conn, l));
        let ids: Vec<BlobId> = Self::eph_entries_of(&self.eph, &l).map(|(b, _)| b).filter(|b| all || !self.eph.present.contains(&(host, l, *b))).collect();
        if !ids.is_empty() {
            self.eph_upload_on(conn, l, &ids, out)?;
        }
        Ok(())
    }

    /// Statuses of lane uploads; the rest are returned for the durable path.
    pub(crate) fn eph_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>, out: &mut Vec<Action>) -> Result<(Vec<BlobId>, Vec<Code>)> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok((ids, codes)) };
        let mut rest = (Vec::new(), Vec::new());
        for (b, code) in ids.into_iter().zip(codes) {
            let lane = self.eph.uploads.remove(&(conn, l, b)) || (self.eph.entries.contains_key(&(l, b)) && !self.state.entries.contains_key(&(l, b)));
            self.eph.own_uploads.remove(&(conn, l, b));
            if !lane {
                rest.0.push(b);
                rest.1.push(code);
                continue;
            }
            self.eph_trace(&l, &b, None, || format!("upload status {} on conn {conn}", code.0));
            let replaced = self.eph_replaced(conn, host, l, b, code == Code::OK);
            let key = self.eph.stamped.remove(&(conn, l, b));
            if !self.eph.entries.contains_key(&(l, b)) {
                // a relay-only entry, or one forgotten meanwhile: deleted now that it is there
                // (once what absorbed it is there too)
                if let Some((item, cover)) = self.eph.orphans.remove(&(l, b, conn))
                    && code == Code::OK
                {
                    self.eph_delete_after(conn, host, l, b, item, cover, out)?;
                }
                continue;
            }
            match code {
                Code::OK => {
                    self.eph.capped.remove(&(conn, l, b));
                    self.eph.present.insert((host, l, b));
                }
                // the defined outcome (spec/sync.md §5): it stays out there until room appears;
                // nothing is compacted for it (a host's refusal triggers nothing, §9)
                Code::STORAGE_CAP => {
                    // an own snapshot whose upload did not already count the room of what it
                    // covers (carried as replacements): that goes first there, and it goes again
                    if !replaced && self.eph_free_for(conn, host, l, b, out)? {
                        self.eph_upload_on(conn, l, &[b], out)?;
                    } else if self.eph.capped.insert((conn, l, b)) {
                        self.eph_report(&l, "a host's ephemeral cap was reached: an entry stays out there until room appears (retried at the periodic pass)");
                    }
                }
                Code::TOMBSTONED => {
                    self.eph.present.remove(&(host, l, b));
                }
                // its rate used up (deletes and replacements count): again at the periodic pass
                Code::RATE_LIMITED => {
                    self.eph.capped.insert((conn, l, b));
                }
                // stamped under a write key older than the head's (a rotation this node had
                // not read): again under the next one (the new head comes by push or the next Sync)
                Code::NOT_HEAD if key.is_some() => {
                    self.eph.restamp.insert((conn, l, b), key);
                }
                c => self.diag(format!("ephemeral upload refused: code {}", c.0)),
            }
        }
        Ok(rest)
    }

    /// An ephemeral or relay-only entry arrived under `l` (a log event, a fetch, a peer's
    /// upload; `from` where it came from): kept, applied and spread once the engine verified and
    /// holds its commit; one waiting for its author's record kept apart, unspread; a relay-only
    /// one delivered and passed on (`relay_in`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn eph_added(&mut self, from: RelayFrom, l: LabelId, b: BlobId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, class: Class, out: &mut Vec<Action>) -> Result<()> {
        self.eph_added_with(from, l, b, blob, wrap, stamp, class, None, out)
    }

    /// `eph_added`; `promoted`: a waiting entry whose commit the engine holds now, with what
    /// its wait was charged: kept and counted past the cap (the node's count is what the engine
    /// holds), its copy checked within that charge.
    #[allow(clippy::too_many_arguments)]
    fn eph_added_with(&mut self, from: RelayFrom, l: LabelId, b: BlobId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, class: Class, promoted: Option<u64>, out: &mut Vec<Action>) -> Result<()> {
        // the ID must name these bytes: the wrap's nonce is only its first 24 bytes, so one blob
        // would open under 2^64 IDs, each kept and charged apart (the durable path checks in
        // `put_blobs`)
        self.eph_trace(&l, &b, None, || format!("arrived {class:?} from {}{}", match from {
            RelayFrom::Host(Some(s)) => format!("host {}", host6(&s)),
            RelayFrom::Host(None) => "a bundle".into(),
            RelayFrom::Served(c) => format!("served conn {c}"),
        }, if promoted.is_some() { ", promoted" } else { "" }));
        if osis_label::blob_id(&blob) != b {
            self.diag(format!("label {l:?}: an ephemeral blob not matching its ID dropped"));
            return Ok(());
        }
        if class == Class::Relay {
            return self.relay_in(from, l, b, blob, wrap, stamp, out);
        }
        if self.eph.unfit.contains(l, b) {
            self.eph_trace(&l, &b, None, || "dropped: known unfit".into());
            return Ok(());
        }
        let host = from.host();
        // the one routing point: a blob whose prefix says ephemeral is the lane's, whatever an
        // announcement without its bytes made the durable path record (spec/sync.md §4)
        if self.state.entries.contains_key(&(l, b)) {
            self.state.forget_ephemeral(l, b);
        }
        // an own entry forgotten while its upload was in flight (being deleted where it lands)
        if self.eph.orphans.range((l, b, 0)..).next().is_some_and(|((l2, b2, _), _)| (*l2, *b2) == (l, b)) {
            self.eph_trace(&l, &b, None, || "dropped: own entry being deleted".into());
            return Ok(());
        }
        if self.eph.entries.contains_key(&(l, b)) || self.eph.pending.contains_key(&(l, b)) {
            self.eph_trace(&l, &b, None, || "already held or waiting".into());
            if let Some(s) = host {
                self.eph.present.insert((s, l, b));
            }
            return Ok(());
        }
        let Some(g) = self.group_of(&l, None) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else {
            self.eph_trace(&l, &b, None, || "dropped: no secret unwraps it".into());
            return Ok(());
        };
        let (pt, cb) = match open_commit(&blob, &key) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("ephemeral blob {b:?}: {e}"));
                return Ok(());
            }
        };
        if Class::of_marker(cb.header.ephemeral) != class {
            self.diag(format!("ephemeral blob {b:?}: its commit's class is not its prefix's"));
            return Ok(());
        }
        // the cap on what others make this node hold per label (notes/ephemeral.md Node cap):
        // the engine decodes it only within the room left (a blob of tiny map entries decodes to
        // about 200 times its size)
        let size = blob.len() as u64;
        let cap = self.cfg.ephemeral_bytes;
        let (bound, part) = crate::Engine::memory_bound(&cb);
        if size > cap || part > cap {
            self.eph_trace(&l, &b, eph_trace_filter().map(|_| cb.id()).as_ref(), || format!("dropped: unfit ({size} B, part {part}, cap {cap})"));
            self.eph_unfit(l, b);
            return Ok(());
        }
        let used = self.eph.bytes.get(&l).copied().unwrap_or(0);
        let room = cap.saturating_sub(used);
        if promoted.is_none() && size > room {
            self.eph_trace(&l, &b, eph_trace_filter().map(|_| cb.id()).as_ref(), || format!("dropped: capped ({size} B, room {room})"));
            self.eph_capped(l);
            return Ok(());
        }
        let room = promoted.map_or(room, |r| room.max(r));
        let commit = cb.id();
        let h = cb.header.clone();
        let first = cb.parts.first().map_or(0, |p| p.ai);
        // unverified blobs wait under a share of the cap, charged by what they could cost
        // decoded (their retry decodes within it, and is counted at promotion): one past it is
        // not kept apart, and what already waits (an honest copy of the same commit included)
        // stays
        let waits = bound.max(size);
        let pending_used = self.eph.pending_bytes.get(&l).copied().unwrap_or(0);
        let may_wait = pending_used.saturating_add(waits) <= cap / PENDING_SHARE;
        let ingested = self.engine.ingest_memory(&pt, room);
        self.eph_trace(&l, &b, Some(&commit), || format!("ingested: {ingested:?} (may wait {may_wait}, room {room})"));
        let salt = osis_label::Prefix::parse(&blob).map(|p| *p.salt()).unwrap_or_default();
        let a = h.aspects.get(first);
        let keys = a.map(|a| a.keys.iter().filter_map(|i| h.keys.get(*i).copied()).collect()).unwrap_or_default();
        let e = LaneEntry { commit, blob, wrap, stamp, own: false, salt, blind: h.blind, tid: a.map_or(g, |a| a.tid), actor: h.actor, keys, charge: size };
        match ingested {
            // held, or applied and dropped at once (covered by a held snapshot, superseded,
            // expired): kept all the same, so the drop the engine reports deletes it where it
            // is (`eph_forget`); a copy of a held commit is checked before it is kept or spread
            // (a header with junk parts would be served on as the commit's)
            Ok(Ingested::Applied(_)) => {}
            Ok(Ingested::Duplicate(_)) if self.engine.holds_memory(&commit) => {
                if self.engine.parts_genuine(&cb) == Some(false) {
                    self.diag(format!("ephemeral commit {commit:?}: a copy that is not the commit's"));
                    return Ok(());
                }
            }
            Ok(Ingested::Duplicate(_)) => return Ok(()),
            Ok(Ingested::Pending(..)) => {
                // not fully checked: kept apart under a share of the cap, neither served nor
                // spread
                if !may_wait {
                    // nor by the engine: the label is reconciled once a waiting entry leaves
                    // the share
                    self.eph_trace(&l, &b, Some(&commit), || "dropped: waiting share full".into());
                    self.engine.forget_pending_memory(&commit)?;
                    if self.eph.refused_pending.insert(l) {
                        self.eph_report(&l, "this node's share for unverified ephemeral commits was reached: further ones are not kept");
                    }
                    return Ok(());
                }
                let mut e = e;
                e.charge = waits;
                *self.eph.pending_bytes.entry(l).or_default() += e.charge;
                if let Some(s) = host {
                    self.eph.present.insert((s, l, b));
                }
                self.eph.pending.insert((l, b), (e, host));
                return Ok(());
            }
            // refused with nothing else held here: it never fits
            Ok(Ingested::TooLarge(_)) if used == 0 && promoted.is_none() => {
                self.eph_unfit(l, b);
                return Ok(());
            }
            Ok(Ingested::TooLarge(_)) => {
                self.eph_capped(l);
                return Ok(());
            }
            Ok(Ingested::Parked(_)) => {
                self.diag(format!("ephemeral commit {commit:?}: parked (not interpreted by this build), dropped"));
                return Ok(());
            }
            Err(err) => {
                self.diag(format!("ephemeral commit {commit:?}: {err}"));
                return Ok(());
            }
        }
        // a promoted entry is present where `present` says (marked when it arrived, cleared when
        // that connection ended): the host it came from may have restarted since, and marking
        // it present there again left it at no host (random churn seed 154)
        let host = if promoted.is_some() { None } else { host };
        if let Some(s) = host {
            self.eph.present.insert((s, l, b));
        }
        // counted as held in memory (decoded), not as its bytes: a blob of tiny entries takes
        // about 200 times its size; within the room given, so the label stays under the cap
        let mut e = e;
        e.charge = self.engine.memory_charge(&commit)?.max(size);
        self.eph_keep(l, b, e);
        self.engine.ephemeral_kept(g, cb.parts.iter().filter_map(|p| h.aspects.get(p.ai).map(|a| a.tid)));
        // unstamped (its stamp is under an earlier write key): a writer stamps it (`eph_upload`)
        self.eph_spread(l, b, host, out)?;
        Ok(())
    }

    /// A relay-only entry (a push, a fetch, a served session's upload; `from` where it came
    /// from): dropped unopened when too large, outside its prefix window or seen before
    /// (`RelaySeen`); else verified and its signals delivered once, then passed on as a host
    /// would: to the sessions this node serves, and, from one of them, to the hosts it syncs the
    /// label with (spec/sync.md §5, §9).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relay_in(&mut self, from: RelayFrom, l: LabelId, b: BlobId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, out: &mut Vec<Action>) -> Result<()> {
        if blob.len() > osis_base::format::MAX_RELAY_BLOB {
            return Ok(());
        }
        let Some(t) = osis_label::Prefix::parse(&blob).ok().and_then(|p| p.expiry()).map(|t| t.0) else { return Ok(()) };
        let now = self.now();
        if t <= now || t > now.saturating_add(2 * osis_base::format::MAX_DRIFT_MS) || !self.eph.relays.fresh(l, b, t, now) {
            return Ok(());
        }
        let Some(g) = self.group_of(&l, None) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else { return Ok(()) };
        let (_, cb) = match open_commit(&blob, &key) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("relay-only blob {b:?}: {e}"));
                return Ok(());
            }
        };
        if cb.header.ephemeral != Some(EphClass::Relay) {
            self.diag(format!("relay-only blob {b:?}: not a relay-only commit"));
            return Ok(());
        }
        let id = cb.id();
        match self.engine.ingest_relay(cb) {
            Ok(true) => self.eph.relays.record(l, b, t),
            Ok(false) => return Ok(()),
            Err(e) => {
                self.diag(format!("relay-only commit {id:?}: {e}"));
                return Ok(());
            }
        }
        let Some(stamp) = stamp else { return Ok(()) };
        let r = osis_proto::Relayed { label: l, blob_id: b, blob: blob.into(), wrap, stamp };
        if !self.served.is_empty() {
            let labels = self.served_labels();
            let conns: Vec<ConnId> = self.served.keys().copied().filter(|c| from != RelayFrom::Served(*c)).collect();
            for c in conns {
                self.serve_with(c, osis_proto::ServingInput::Relay(r.clone()), &labels, out)?;
            }
        }
        if let RelayFrom::Served(_) = from {
            for (conn, _, _) in self.eph_conns(&l) {
                self.eph.uploads.insert((conn, l, b));
                self.command(conn, Command::Upload { label: l, entries: vec![osis_proto::Entry { blob: r.blob.to_vec(), wrap: r.wrap, stamp: r.stamp, replaces: Vec::new() }] }, out)?;
            }
        }
        Ok(())
    }

    /// Entries the peer on `conn` refused under `l` for its cap go up again (the periodic pass:
    /// others' compactions or expiries may have made room).
    pub(crate) fn eph_retry(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        self.eph_retry_deletes(conn, l, out)?;
        let ids: Vec<BlobId> = self.eph.capped.range((conn, l, BlobId([0; 32]))..).take_while(|(c, x, _)| *c == conn && *x == l).map(|x| x.2).filter(|b| self.eph.entries.contains_key(&(l, *b))).collect();
        if !ids.is_empty() {
            self.eph_upload_on(conn, l, &ids, out)?;
        }
        Ok(())
    }

    /// Lane deletes rate limited under `l` on `conn` go again (the periodic pass).
    pub(crate) fn eph_retry_deletes(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        if self.lc(conn, &l).is_none_or(|x| x.phase != Phase::Open) {
            return Ok(());
        }
        let limited: Vec<BlobId> = self.eph.redelete.range((conn, l, BlobId([0; 32]))..).take_while(|((c, x, _), _)| *c == conn && *x == l).filter(|(_, (_, redo))| *redo == Redo::Limited).map(|(k, _)| k.2).collect();
        for b in limited {
            if let Some((item, _)) = self.eph.redelete.remove(&(conn, l, b)) {
                self.eph_delete_now(conn, l, b, item, out)?;
            }
        }
        Ok(())
    }

    /// An ephemeral entry was deleted at `host`: no longer present there.
    pub(crate) fn eph_deleted(&mut self, host: Option<HostKey>, l: LabelId, b: BlobId) -> bool {
        self.eph.unfit.remove(l, b);
        if let Some(s) = host {
            self.eph.waiting.remove(&(l, b, s));
            let conns: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.host == s).map(|(id, _)| *id).collect();
            for c in conns {
                self.eph.redelete.remove(&(c, l, b));
            }
        }
        if !self.eph.entries.contains_key(&(l, b)) {
            return false;
        }
        if let Some(s) = host {
            self.eph.present.remove(&(s, l, b));
        }
        true
    }

    /// Forgets the entries of the memory commits the engine dropped; a writer deletes them
    /// where they were uploaded (by the part's level-3 delete key and the label's write key,
    /// spec/sync.md §5): a covered one once a snapshot covering it is held there, a superseded
    /// one (its author only) once a superseder is, the rest at once.
    fn eph_forget(&mut self, commits: &[(CommitId, MemoryDrop)], out: &mut Vec<Action>) -> Result<()> {
        for (c, why) in commits {
            // deletes waiting for it wait for what covers it now, and go once they wait for
            // nothing (issues/eph-host-deletes-under-others-snapshots.md: a covered entry leaves
            // the host under any author's snapshot)
            let (cover, author_only) = match why {
                MemoryDrop::Covered { by } => (by.clone(), false),
                MemoryDrop::Superseded { by } => (by.clone(), true),
                MemoryDrop::Gone => (BTreeSet::new(), false),
            };
            for (l, b) in self.eph.by_commit.get(c).into_iter().flatten() {
                self.eph_trace(l, b, Some(c), || format!("forgotten by the engine (covers {}, author only {author_only})", cover.len()));
            }
            let moved: Vec<(LabelId, BlobId, HostKey)> = self.eph.waiting.iter().filter(|(_, (w, _))| w.contains(c)).map(|(k, _)| *k).collect();
            for k in moved {
                let Some(w) = self.eph.waiting.get_mut(&k) else { continue };
                w.0.remove(c);
                w.0.extend(cover.iter().copied());
                if w.0.is_empty()
                    && let Some((_, item)) = self.eph.waiting.remove(&k)
                    && let Some(conn) = self.eph_conn_to(&k.0, k.2)
                {
                    self.eph_delete_now(conn, k.0, k.1, item, out)?;
                }
            }
            let Some(keys) = self.eph.by_commit.remove(c) else { continue };
            for (l, b) in keys {
                let Some(e) = self.eph_unkeep(l, b) else { continue };
                let dks = self.engine.ephemeral_delete_secrets_for(&e.tid, &e.actor, &e.keys);
                self.eph_trace(&l, &b, Some(c), || format!("forget: {} delete secrets, present at {:?}", dks.len(), self.eph.present.iter().filter(|(_, pl, pb)| *pl == l && *pb == b).map(|(s, _, _)| host6(s)).collect::<Vec<_>>()));
                for (conn, host, hk) in self.eph_conns(&l) {
                    self.eph.capped.remove(&(conn, l, b));
                    let present = self.eph.present.remove(&(host, l, b));
                    if !(present || self.eph.uploads.contains(&(conn, l, b))) || (author_only && !e.own) {
                        continue;
                    }
                    if let Some(item) = eph_delete_item(&hk, &l, b, &e, &dks) {
                        if present {
                            self.eph_delete_after(conn, host, l, b, item, cover.clone(), out)?;
                        } else {
                            self.eph.orphans.insert((l, b, conn), (item, cover.clone()));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Forgets lane entry `b` of `l` (no longer served); its bytes leave the label's count.
    fn eph_unkeep(&mut self, l: LabelId, b: BlobId) -> Option<LaneEntry> {
        self.eph_trace(&l, &b, None, || "dropped from the lane".into());
        let e = self.eph.entries.remove(&(l, b))?;
        self.eph.by_blob.remove(&(b, l));
        if !e.own
            && let Some(n) = self.eph.bytes.get_mut(&l)
        {
            *n = n.saturating_sub(e.charge);
            // room again after a refusal: the label is reconciled at its next periodic pass, so
            // what was refused is fetched again (`SyncEngine::timers`)
            if *n < self.cfg.ephemeral_bytes && self.eph.refused.remove(&l) {
                self.eph.reconciled.retain(|(_, x)| *x != l);
            }
        }
        self.state.feed.deleted(l, b);
        Some(e)
    }

    /// Fetches of `l` on `conn` answered (`refused` false) or refused: they leave
    /// `reconcile_fetches`; a refused one a reconciliation asked for reconciles the label again
    /// (on this connection's next sync, `sync_label`, or the next periodic pass).
    pub(crate) fn eph_fetch_done(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId], refused: bool) {
        for b in ids {
            self.eph_trace(&l, b, None, || format!("fetch on conn {conn} {}", if refused { "refused" } else { "answered" }));
        }
        let Some(asked) = self.eph.reconcile_fetches.get_mut(&(conn, l)) else { return };
        let mut lost = false;
        for b in ids {
            lost |= asked.remove(b) && refused;
        }
        if asked.is_empty() {
            self.eph.reconcile_fetches.remove(&(conn, l));
        }
        if lost && let Some(c) = self.conns.get(&conn) {
            self.eph.reconciled.remove(&(c.host, l));
        }
    }

    /// A connection ended: what it knew of its peer goes with it.
    pub(crate) fn eph_lost(&mut self, conn: ConnId, host: HostKey, fetching: &BTreeSet<BlobId>) {
        let unanswered: Vec<LabelId> = self.eph.reconcile_fetches.iter().filter(|((c, _), ids)| *c == conn && !ids.is_disjoint(fetching)).map(|((_, l), _)| *l).collect();
        for l in unanswered {
            self.eph.reconciled.remove(&(host, l));
        }
        self.eph.reconcile_fetches.retain(|(c, _), _| *c != conn);
        self.eph.present.retain(|(s, _, _)| *s != host);
        self.eph.announced.retain(|(c, _)| *c != conn);
        self.eph.gained.retain(|(c, _), _| *c != conn);
        self.eph.reconciling.retain(|(c, _), _| *c != conn);
        self.eph.uploads.retain(|(c, _, _)| *c != conn);
        self.eph.own_uploads.retain(|(c, _, _)| *c != conn);
        self.eph.stamped.retain(|(c, _, _), _| *c != conn);
        self.eph.restamp.retain(|(c, _, _), _| *c != conn);
        self.eph.deletes.retain(|(c, _, _), _| *c != conn);
        self.eph.redelete.retain(|(c, _, _), _| *c != conn);
        self.eph.capped.retain(|(c, _, _)| *c != conn);
        self.eph.orphans.retain(|(_, _, c), _| *c != conn);
        let carried: Vec<(ConnId, LabelId, BlobId)> = self.eph.replacing.keys().filter(|(c, _, _)| *c == conn).copied().collect();
        for (c, l, b) in carried {
            self.eph_replaced(c, host, l, b, false);
        }
    }

    /// Statuses of lane deletes are taken out (the rest returned for the durable path).
    pub(crate) fn eph_delete_status(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, codes: Vec<Code>) -> (Vec<BlobId>, Vec<Code>) {
        let (mut rest, mut rest_codes) = (Vec::new(), Vec::new());
        for (b, code) in ids.into_iter().zip(codes) {
            let Some((item, key)) = self.eph.deletes.remove(&(conn, l, b)) else {
                rest.push(b);
                rest_codes.push(code);
                continue;
            };
            self.eph_trace(&l, &b, None, || format!("delete status {} on conn {conn}", code.0));
            match code {
                // signed under a key older than the head's (a rotation this node had not read):
                // again under the next one
                Code::NOT_HEAD => {
                    self.eph.redelete.insert((conn, l, b), (item, Redo::Head(Some(key))));
                }
                Code::RATE_LIMITED => {
                    self.eph.redelete.insert((conn, l, b), (item, Redo::Limited));
                }
                // done, or nothing left to delete there (not held, label not open: the next
                // open reconciles it)
                Code::OK => {}
                c => self.diag(format!("ephemeral delete refused: code {}", c.0)),
            }
        }
        (rest, rest_codes)
    }

    /// Ephemeral entries held under `l` (serving peers): ID and entry.
    pub(crate) fn eph_entries_of<'a>(lane: &'a Lane, l: &LabelId) -> impl Iterator<Item = (BlobId, &'a LaneEntry)> {
        let l = *l;
        lane.entries.range((l, BlobId([0; 32]))..).take_while(move |((x, _), _)| *x == l).map(|((_, b), e)| (*b, e))
    }

    /// Tests: compacts every memory aspect held here now (forced) and sends the snapshots as
    /// `eph_step` would.
    #[doc(hidden)]
    pub fn compact_ephemeral_now(&mut self) -> Result<Vec<Action>> {
        let mut out = Vec::new();
        self.engine.memory_compactions(true)?;
        let commits = self.engine.take_memory_commits(&BTreeSet::new())?;
        let dropped = self.engine.take_memory_drops();
        self.eph_forget(&dropped, &mut out)?;
        for c in commits {
            if let Some(blob) = self.engine.memory_blob(&c)? {
                self.eph_place(c, blob, EphClass::Plain, &mut out)?;
            }
        }
        Ok(out)
    }

    /// Tests: the ephemeral entries held under `l` (blob ID and size), to check them against a
    /// host's cap.
    #[doc(hidden)]
    pub fn ephemeral_held_entries(&self, l: &LabelId) -> Vec<(BlobId, usize)> {
        Self::eph_entries_of(&self.eph, l).map(|(b, e)| (b, e.blob.len())).collect()
    }

    /// What the ephemeral entries held from others under `l` count against its cap (their
    /// `charge`: memory held, not encoded bytes; tests, diagnostics).
    pub fn ephemeral_bytes(&self, l: &LabelId) -> u64 {
        self.eph.bytes.get(l).copied().unwrap_or(0)
    }

    /// The encoded bytes and the charge of each entry held from others under `l` (tests).
    pub fn ephemeral_held_from_others(&self, l: &LabelId) -> Vec<(usize, u64)> {
        Self::eph_entries_of(&self.eph, l).filter(|(_, e)| !e.own).map(|(_, e)| (e.blob.len(), e.charge)).collect()
    }

    /// What entries under `l` not fully checked count against its share (tests, diagnostics).
    pub fn ephemeral_pending_bytes(&self, l: &LabelId) -> u64 {
        self.eph.pending_bytes.get(l).copied().unwrap_or(0)
    }

    /// Tests: the ephemeral entries of commit `c` held here, as the log events a host pushes
    /// (a capture to replay).
    #[doc(hidden)]
    pub fn ephemeral_entry_events(&self, c: &CommitId) -> Vec<(LabelId, osis_proto::Event)> {
        let keys = self.eph.by_commit.get(c).cloned().unwrap_or_default();
        keys.into_iter().filter_map(|(l, b)| self.eph.entries.get(&(l, b)).map(|e| (l, osis_proto::Event::Added { blob_id: b, blob: Some(e.blob.clone()), wrap: e.wrap, stamp: e.stamp }))).collect()
    }

    /// Tests: the entries of ephemeral commit `c` held here, with the hosts this node counts
    /// them held at (by host key).
    #[doc(hidden)]
    pub fn ephemeral_entries_of(&self, c: &CommitId) -> Vec<(LabelId, BlobId, Vec<[u8; 32]>)> {
        let keys = self.eph.by_commit.get(c).cloned().unwrap_or_default();
        keys.into_iter().map(|(l, b)| (l, b, self.eph.present.iter().filter(|(_, pl, pb)| *pl == l && *pb == b).map(|(s, _, _)| *s).collect())).collect()
    }

    /// Tests, diagnostics: the lane under `l` as text, an entry per line (commit, own, bytes, the
    /// hosts it is present at by key prefix, in-flight uploads and cap refusals), then pending entries and the label's flags.
    #[doc(hidden)]
    pub fn ephemeral_dump(&self, l: &LabelId) -> String {
        use std::fmt::Write;
        let lane = &self.eph;
        let key = |s: &[u8; 32]| osis_base::hex::encode(&s[..4]);
        let mut out = String::new();
        for (b, e) in Self::eph_entries_of(lane, l) {
            let at: Vec<String> = lane.present.iter().filter(|(_, pl, pb)| pl == l && *pb == b).map(|(s, _, _)| key(s)).collect();
            let up: Vec<u64> = lane.uploads.iter().filter(|(_, ul, ub)| ul == l && *ub == b).map(|x| x.0).collect();
            let capped: Vec<u64> = lane.capped.iter().filter(|(_, cl, cb)| cl == l && *cb == b).map(|x| x.0).collect();
            let _ = writeln!(out, "  {b:?} commit {:?} own {} {} B present {at:?} uploading {up:?} capped {capped:?}", e.commit, e.own, e.blob.len());
        }
        for ((pl, b), (e, from)) in &lane.pending {
            if pl == l {
                let _ = writeln!(out, "  pending {b:?} commit {:?} from {:?}", e.commit, from.as_ref().map(key));
            }
        }
        let _ = writeln!(out, "  bytes {:?} refused {}", lane.bytes.get(l), lane.refused.contains(l));
        out
    }

    /// Ephemeral entries held under `l` (tests, diagnostics).
    pub fn ephemeral_entries(&self, l: &LabelId) -> usize {
        Self::eph_entries_of(&self.eph, l).count()
    }
}

/// Why a lane delete waits to go again (`Lane::redelete`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Redo {
    /// Refused under an older head (code 9) with this key, or the connection held none for it
    /// (`None`; keys not established yet, roles uncovered): sent once its keys give another,
    /// dropped once they give none and this node lacks the role (`eph_redelete`).
    Head(Option<VerifyingKey>),
    /// Rate limited (code 4): sent at the periodic pass (`eph_retry`).
    Limited,
}

/// A delete of lane entry `e` (`b` under `l`) by a level's delete key first, else by the head
/// delete key: a level's signature holds across heads and its label key (write, sync) stays with
/// an admin demoted to writer, whose waiting deletes by the delete key no head would take.
fn eph_delete_item(hk: &HeadKeys, l: &LabelId, b: BlobId, e: &LaneEntry, dks: &[(u8, osis_crypto::DeleteSecret)]) -> Option<osis_label::DeleteItem> {
    delete_item_by_level(hk, l, b, None, (&e.salt, &e.blind), dks).or_else(|| delete_item(hk, l, b, None, None, &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u32) -> BlobId {
        let mut x = [0u8; 32];
        x[..4].copy_from_slice(&n.to_le_bytes());
        BlobId(x)
    }

    // spec/sync.md §9, notes/ephemeral.md (waiting deletes bounded per label and host): past
    // `WAITING_MAX` at one (label, host) the oldest there is dropped, others untouched
    #[test]
    fn waiting_deletes_bounded_per_host() {
        let mut w = WaitingDeletes::default();
        let (l, s1, s2) = (LabelId([1; 16]), [1u8; 32], [2u8; 32]);
        let item = |x: BlobId| osis_label::DeleteItem { blob: x, at: None, by: None, sig: osis_crypto::Signature([0; 64]) };
        w.insert((l, b(u32::MAX), s2), (BTreeSet::new(), item(b(u32::MAX))));
        // inserted in descending blob order: the oldest is not the smallest key
        for n in (0..=WAITING_MAX as u32).rev() {
            w.insert((l, b(n), s1), (BTreeSet::new(), item(b(n))));
        }
        assert_eq!(w.at(l, s1), WAITING_MAX);
        assert!(w.get(&(l, b(WAITING_MAX as u32), s1)).is_none(), "the oldest dropped");
        assert!(w.get(&(l, b(0), s1)).is_some() && w.get(&(l, b(u32::MAX), s2)).is_some());
        w.insert((l, b(0), s1), (BTreeSet::new(), item(b(0))));
        assert_eq!(w.at(l, s1), WAITING_MAX, "a replacement adds nothing");
        assert!(w.remove(&(l, b(0), s1)).is_some());
        assert_eq!((w.at(l, s1), w.at(l, s2)), (WAITING_MAX - 1, 1));
    }

    // spec/sync.md §9, notes/ephemeral.md (entries refused for the waiting share bounded per label by the
    // records they lack): past the weight the oldest go, other labels untouched; a replacement
    // is weighed anew; one heavier than the bound is not kept
    #[test]
    fn per_label_bounded_by_weight() {
        let mut m: PerLabel<()> = PerLabel::new(10);
        let (l1, l2) = (LabelId([1; 16]), LabelId([2; 16]));
        assert!(m.insert(l1, b(0), (), 4));
        assert!(!m.insert(l1, b(1), (), 4));
        assert!(m.insert(l2, b(9), (), 10));
        m.insert(l1, b(2), (), 4);
        assert!(!m.contains(l1, b(0)) && m.contains(l1, b(1)) && m.contains(l1, b(2)) && m.contains(l2, b(9)), "the oldest of l1 forgotten");
        m.insert(l1, b(1), (), 1);
        m.insert(l1, b(3), (), 5);
        assert!(m.contains(l1, b(1)) && m.contains(l1, b(2)) && m.contains(l1, b(3)), "the replacement weighs 1, now the newest but one");
        assert!(m.remove(l1, b(2)).is_some());
        m.insert(l1, b(4), (), 11);
        assert!(!m.contains(l1, b(4)) && !m.contains(l1, b(1)) && !m.contains(l1, b(3)), "too heavy: kept nothing");
        assert!(m.insert(l1, b(5), (), 10), "l1 empty again");
        assert!(m.contains(l2, b(9)));
    }

    // spec/sync.md §9 (relay-only entries remembered, a floor past the bound; security review
    // L1): a repeat is dropped; past the bound the earliest-expiring entry is forgotten and its
    // label refuses everything expiring at or before it, so a forgotten one never comes back
    #[test]
    fn relay_seen_once_past_the_bound_spec_sync_9() {
        let mut r = RelaySeen::default();
        let (l, other) = (LabelId([1; 16]), LabelId([2; 16]));
        let now = 1_000_000;
        assert!(r.first(l, b(0), now + 10, now));
        assert!(!r.first(l, b(0), now + 10, now), "a repeat");
        for n in 1..=RELAYS_REMEMBERED as u32 {
            assert!(r.first(l, b(n), now + 10 + u64::from(n), now));
        }
        assert!(!r.first(l, b(0), now + 10, now), "forgotten, under the floor: still not twice");
        assert!(r.first(other, b(0), now + 10, now), "the floor is per label");
        assert!(r.first(l, b(RELAYS_REMEMBERED as u32 + 1), now + 20 + RELAYS_REMEMBERED as u64, now));
        // past their expiry entries and floors go
        assert!(r.first(l, b(7), now + 1_000_000_000, now + 500_000_000));
        assert_eq!(r.ids.len(), 1);
        assert!(r.floor.is_empty());
    }
}

