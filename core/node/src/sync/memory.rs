//! Memory class in node-sync (spec/sync.md §9, notes/ephemeral.md): the bodies of memory
//! commits are judged, placed, uploaded, relayed and deleted like durable bodies (the pass,
//! `pass/`), with every record about them kept in memory (`State::memory_entries`, the store's
//! memory overlay for their blobs). What stays particular to the class is here: the node cap on
//! what others make this node hold per label (`SyncConfig::ephemeral_bytes`: a received memory
//! commit is ingested within the room left, `ingest_memory_entry`), the share of it unverified
//! commits may wait in, entries that never fit, the restart reconciliation (the entries a
//! persisted cursor passed are in no memory after a start), the headers of forgotten memory
//! commits (their entries are deleted at hosts by them), the hold-back and coalescing of own
//! writes while an own upload is in flight (`coalesce_own`), and relay-only commits (ephemeral signals:
//! delivered and passed on, held by nobody).

use super::state::{Entry, HostKey, Kind};
use super::work::Left;
use super::{Action, ConnId, Phase, SyncEngine};
use crate::engine::MemoryDrop;
use crate::error::Result;
use crate::events::{Diagnostic, DiagnosticKind};
use crate::labeling::{Body, BodyCtx, HeadKeys};
use crate::Ingested;
use osis_base::{BlobId, CommitId, LabelId, Tid};
use osis_commit::{CommitBlob, EphClass, Form};
use osis_crypto::Signature;
use osis_label::Class;
use osis_proto::{Code, Command};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Where a relay-only entry came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayFrom {
    /// A host or a peer this node dialed (`None`: a bundle, nobody).
    Host(Option<HostKey>),
    /// A session this node serves.
    Served(ConnId),
}

/// Entries remembered per label with a weight, at most `max` weight per label, the oldest
/// forgotten past it (`Memory::unfit`).
pub(crate) struct PerLabel {
    map: BTreeMap<(LabelId, BlobId), usize>,
    /// Per label, its entries oldest first and their total weight.
    order: BTreeMap<LabelId, (std::collections::VecDeque<BlobId>, usize)>,
    max: usize,
}

impl PerLabel {
    fn new(max: usize) -> PerLabel {
        PerLabel { map: BTreeMap::new(), order: BTreeMap::new(), max }
    }

    pub fn contains(&self, l: LabelId, b: BlobId) -> bool {
        self.map.contains_key(&(l, b))
    }

    /// Remembers `b` of `l` weighing `w` (replacing what it had, as the newest); whether `l`
    /// had none before.
    pub fn insert(&mut self, l: LabelId, b: BlobId, w: usize) -> bool {
        let had = self.order.contains_key(&l);
        self.remove(l, b);
        self.map.insert((l, b), w);
        let (q, total) = self.order.entry(l).or_default();
        q.push_back(b);
        *total += w;
        while *total > self.max
            && let Some(old) = q.pop_front()
            && let Some(ow) = self.map.remove(&(l, old))
        {
            *total -= ow;
        }
        if q.is_empty() {
            self.order.remove(&l);
        }
        !had
    }

    pub fn remove(&mut self, l: LabelId, b: BlobId) {
        if let Some(w) = self.map.remove(&(l, b))
            && let Some((q, total)) = self.order.get_mut(&l)
        {
            q.retain(|x| *x != b);
            *total -= w;
            if q.is_empty() {
                self.order.remove(&l);
            }
        }
    }
}

/// Never-fitting entries remembered per label (`Memory::unfit`). Resource bound: about 100 bytes
/// each, 400 KiB per label at the bound; a host's cap holds a few hundred such entries per
/// label (about 25 KB each at the least), so honest hosts never reach it (0: each is fetched
/// again at every reconciliation; infinity: a writer uploading and deleting such entries grows
/// the set for good).
const UNFIT_MAX: usize = 1 << 12;

impl Default for PerLabel {
    fn default() -> Self {
        PerLabel::new(UNFIT_MAX)
    }
}

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

/// Entries of a label refused for its cap or share here, with the label's held and pending
/// charges when the last was refused: fetched again once either dropped below that (room
/// appeared), never while nothing changed.
#[derive(Default)]
pub(crate) struct Refused {
    pub used_at: u64,
    pub ids: BTreeSet<BlobId>,
}

/// A memory commit the engine forgot (covered, superseded, expired, freed) whose entries this
/// node still knows: what deleting them at a host needs of its header, and why it went.
pub(crate) struct Forgotten {
    pub header: Arc<osis_commit::Header>,
    pub why: MemoryDrop,
}

/// The memory class's state beside the sync records (all in memory).
#[derive(Default)]
pub(crate) struct Memory {
    /// (host, label) reconciled since this node started (`sync_label`).
    pub reconciled: BTreeSet<(HostKey, LabelId)>,
    /// Reconciliations running after a start (`sync_label`): their reply keeps the cursor and
    /// syncs from it (`reconciled`).
    pub reconciling: BTreeSet<(ConnId, LabelId)>,
    /// What each such reconciliation asked for: one ending with any of it unanswered
    /// reconciles that label again on the next connection (nothing else here knows of an entry
    /// the cursor passed, so nothing would ask for it again).
    pub reconcile_fetches: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    /// Entries refused for the label's cap or share here (their bytes dropped, their record
    /// kept unopened): fetched again once room appears (`retry_refused`), not before.
    pub refused: BTreeMap<LabelId, Refused>,
    /// Entries that can never fit their label's cap here (encoded past the whole cap, or a part
    /// whose decoded bound is): not fetched again. Forgotten when a host deletes them.
    pub unfit: PerLabel,
    /// Labels whose cap or share refusal was reported (once until room appears).
    pub reported: BTreeSet<LabelId>,
    /// Forgotten memory commits with entries still known (`Engine::take_memory_drops`).
    pub forgotten: BTreeMap<CommitId, Forgotten>,
    /// Uploads of this node's own memory bodies unanswered per connection and label: its later
    /// own writes there wait (`coalesce_own`, spec/sync.md §9).
    pub own_uploads: BTreeSet<(ConnId, LabelId, BlobId)>,
    /// Per connection and label, the memory entries its first Sync listed as gained
    /// (`memory_gained`) that the peer has not asked for yet: present there once the Sync ran
    /// through (`memory_synced`), since presence of a memory entry is per connection.
    pub gained: BTreeMap<(ConnId, LabelId), BTreeSet<BlobId>>,
    pub announced: BTreeSet<(ConnId, LabelId)>,
    /// Own commits a coalescing snapshot was made of: never coalesced again (one the snapshot
    /// could not cover, behind an invalid body of its session, goes as it is, else a snapshot
    /// per pass spun). Trimmed to the commits held.
    pub coalesced: BTreeSet<CommitId>,
    /// Relay-only entries received (`RelaySeen`).
    pub relays: RelaySeen,
}

impl SyncEngine {
    /// Open connections with label `l` (connection, host key, keys).
    fn open_conns(&self, l: &LabelId) -> Vec<(ConnId, HostKey, HeadKeys)> {
        self.conns.iter().filter_map(|(id, c)| c.labels.get(l).filter(|x| x.phase == Phase::Open && !x.receipts && c.up).map(|x| (*id, c.host, x.keys.clone()))).collect()
    }

    /// Per step, before the engine's changes are drained: the aspects whose memory snapshot
    /// fell invalid have their labels reconciled (a writer wrote a fresh snapshot, an own commit
    /// the passes place), the memory aspects due are compacted (`Engine::memory_compactions`),
    /// the commits the engine forgot are noted (their entries' charge released, their labels
    /// judged again), entries whose commit waited unverified are charged as held, refused entries
    /// are fetched again where room appeared, and ephemeral signals go.
    pub(crate) fn memory_step(&mut self, out: &mut Vec<Action>) -> Result<()> {
        for (t, _) in self.engine.take_memory_invalidated()? {
            self.memory_reconcile_thing(&t);
        }
        self.engine.memory_compactions(false)?;
        let dropped = self.engine.take_memory_drops();
        self.memory_dropped(&dropped);
        self.retry_refused();
        let signals = self.engine.take_signals();
        for c in signals {
            self.place_relay(c.id, c.blob, out)?;
        }
        self.memory.coalesced.retain(|c| self.engine.holds_memory(c));
        Ok(())
    }

    /// Reconciles the labels whose closure holds `t` at their next sync: a memory snapshot of
    /// one of its aspects fell invalid here, and the bodies it covered are gone until copies
    /// holders still have arrive again (spec/sync.md §9).
    fn memory_reconcile_thing(&mut self, t: &Tid) {
        let labels: Vec<LabelId> = self.labels().into_iter().filter(|(g, _)| *g == *t || self.engine.closure(g).contains(t)).map(|(_, gl)| gl.id).collect();
        self.memory.reconciled.retain(|(_, l)| !labels.contains(l));
    }

    /// Memory commits the engine forgot: their entries' charge is released, their header and
    /// why (what carries them) kept while entries of them are known (deletes at hosts are judged
    /// by them, `pass/delete`), and their labels judged again.
    fn memory_dropped(&mut self, dropped: &[(CommitId, Arc<osis_commit::Header>, MemoryDrop)]) {
        let mut labels = BTreeSet::new();
        for (c, header, why) in dropped {
            let entries: Vec<(LabelId, BlobId)> = self.entries_of_commit(c);
            for (l, b) in &entries {
                self.state.charge_memory(*l, *b, None);
                self.state.touch(*l, *b);
                labels.insert(*l);
            }
            // recorded with or without entries: one forgotten before it was placed may stand
            // for what carries another (`carriers_of_forgotten`); the sweep keeps what is needed
            self.memory.forgotten.insert(*c, Forgotten { header: header.clone(), why: why.clone() });
        }
        if !labels.is_empty() {
            self.mark_labels(labels.iter());
        }
    }

    /// Every entry of commit `c` this node knows, by label.
    pub(crate) fn entries_of_commit(&self, c: &CommitId) -> Vec<(LabelId, BlobId)> {
        self.state.commit_labels.range((*c, LabelId([0; 16]))..=(*c, LabelId([0xff; 16]))).flat_map(|(_, l)| self.state.entries_of(l, c).map(move |(b, _)| (*l, b))).collect()
    }

    /// Whether any entry of commit `c` is known here.
    fn has_entries(&self, c: &CommitId) -> bool {
        self.state.commit_labels.range((*c, LabelId([0; 16]))..=(*c, LabelId([0xff; 16]))).next().is_some()
    }

    /// The commits that carry forgotten commit `c`'s writes now: those its drop named, each
    /// forgotten in turn (superseded or covered before it was placed) replaced by what carries
    /// it, to the commits held or with entries here.
    pub(super) fn carriers_of_forgotten(&self, c: &CommitId) -> Vec<CommitId> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::from([*c]);
        let mut stack: Vec<CommitId> = self.memory.forgotten.get(c).map(|f| f.why.by()).unwrap_or_default();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            match self.memory.forgotten.get(&x) {
                Some(f) if !self.has_entries(&x) => stack.extend(f.why.by()),
                _ => out.push(x),
            }
        }
        out
    }

    /// Forgets the headers of forgotten commits no entry names any more, or held again, but
    /// those that stand for what carries another forgotten commit (`carriers_of_forgotten`).
    /// With the tombstones' expiry (a scan of every deleted body: not per write).
    pub(crate) fn sweep_forgotten(&mut self) {
        if self.memory.forgotten.is_empty() {
            return;
        }
        // kept while an entry of the commit is known or one of its bodies left a label by a
        // delete within the tombstone (a host that got it late announces it again)
        let deleted: BTreeSet<CommitId> = self.state.deleted.keys().map(|(_, c, _)| *c).collect();
        let mut keep: BTreeSet<CommitId> = self.memory.forgotten.keys().filter(|c| !self.engine.holds_memory(c) && (self.has_entries(c) || deleted.contains(c))).copied().collect();
        let mut stack: Vec<CommitId> = keep.iter().copied().collect();
        while let Some(c) = stack.pop() {
            for x in self.memory.forgotten.get(&c).map(|f| f.why.by()).unwrap_or_default() {
                if self.memory.forgotten.contains_key(&x) && keep.insert(x) {
                    stack.push(x);
                }
            }
        }
        self.memory.forgotten.retain(|c, _| keep.contains(c));
    }

    /// Entries refused for a label's cap or share are fetched again where room appeared: their
    /// records are opened again (`Kind::Unknown`, fetched by the next pass).
    fn retry_refused(&mut self) {
        let labels: Vec<LabelId> = self.memory.refused.keys().copied().collect();
        let mut marked = Vec::new();
        for l in labels {
            let used = self.state.memory_bytes.get(&l).copied().unwrap_or(0);
            let Some(r) = self.memory.refused.get(&l) else { continue };
            if used >= r.used_at {
                continue;
            }
            let Some(Refused { ids, .. }) = self.memory.refused.remove(&l) else { continue };
            for b in ids {
                if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
                    e.kind = Kind::Unknown;
                    self.state.set_entry(l, b, e);
                }
            }
            self.memory.reported.remove(&l);
            marked.push(l);
        }
        if !marked.is_empty() {
            self.mark_labels(marked.iter());
        }
    }

    /// Whether entry `b` of `l` is not fetched here for now (refused for the cap or share, or
    /// never fitting).
    pub(crate) fn memory_skips(&self, l: &LabelId, b: &BlobId) -> bool {
        self.memory.unfit.contains(*l, *b) || self.memory.refused.get(l).is_some_and(|r| r.ids.contains(b)) || self.state.tombs.contains_key(&(*l, *b))
    }

    /// Ingests the memory commit of entry `b` of `l` (opened as `cb`, plaintext `pt`, `size`
    /// encoded bytes) within the room its label's cap leaves (spec/sync.md §9): applied, it is
    /// charged what it costs held (`Engine::memory_charge`); waiting unverified, it is charged
    /// against the pending share by what it could cost decoded (`Engine::memory_bound`);
    /// refused (nothing applies there), its bytes go and its record waits unopened for room
    /// (`refused`), or for good when it can never fit (`unfit`).
    pub(crate) fn ingest_memory_entry(&mut self, l: LabelId, b: BlobId, size: usize, pt: &[u8], cb: &CommitBlob) -> Result<()> {
        let commit = cb.id();
        if cb.header.ephemeral != Some(EphClass::Plain) {
            self.diag(format!("ephemeral blob {b:?}: not a plain ephemeral commit"));
            return self.mark_bad(l, b);
        }
        let size = size as u64;
        let cap = self.cfg.ephemeral_bytes;
        // the engine decodes it only within the room left (a blob of tiny map entries decodes to
        // about 200 times its size)
        let (_, part) = crate::Engine::memory_bound(cb);
        if size > cap || part > cap {
            return self.refuse_memory(l, b, true);
        }
        let used = self.state.memory_bytes.get(&l).copied().unwrap_or(0);
        let room = cap.saturating_sub(used);
        if size > room {
            return self.refuse_memory(l, b, false);
        }
        match self.engine.ingest_memory(pt, room) {
            // held, or applied and dropped at once (covered by a held snapshot, superseded,
            // expired): the drop the engine reports deletes it where it is
            Ok(Ingested::Applied(_)) => {}
            // a copy of a held commit is checked before it is kept or served on (a header with
            // junk parts would be served as the commit's)
            Ok(Ingested::Duplicate(_)) if self.engine.holds_memory(&commit) => {
                if self.engine.parts_genuine(cb) == Some(false) {
                    self.diag(format!("ephemeral commit {commit:?}: a copy that is not the commit's"));
                    return self.mark_bad(l, b);
                }
            }
            Ok(Ingested::Duplicate(_)) => return Ok(()),
            // held by the engine, pending (drift, parked): its bytes take their room
            Ok(Ingested::Pending(..)) => {
                self.state.charge_memory(l, b, Some(size));
                return Ok(());
            }
            // nothing kept: the entry takes its bytes' worth of the cap until fetched again
            Ok(Ingested::Awaits(commit, r)) => {
                self.mark_awaits(l, b, commit, r)?;
                self.state.charge_memory(l, b, Some(size));
                return Ok(());
            }
            // refused with nothing else held here: it never fits
            Ok(Ingested::TooLarge(_)) => return self.refuse_memory(l, b, used == 0),
            Ok(Ingested::Parked(_)) => {
                self.diag(format!("ephemeral commit {commit:?}: parked (not interpreted by this build), dropped"));
                return self.mark_bad(l, b);
            }
            Err(err) => {
                self.diag(format!("ephemeral commit {commit:?}: {err}"));
                return self.mark_bad(l, b);
            }
        }
        // counted as held in memory (decoded), not as its bytes, within the room given, so the
        // label stays under the cap
        let charge = self.engine.memory_charge(&commit)?.max(size);
        self.state.charge_memory(l, b, Some(charge));
        Ok(())
    }

    /// Entry `b` of `l` is no valid memory commit blob: never opened or judged again.
    fn mark_bad(&mut self, l: LabelId, b: BlobId) -> Result<()> {
        if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
            e.kind = Kind::Bad;
            self.state.set_entry(l, b, e);
        }
        self.state.remove_blob(&b);
        self.delete_blobs(&[b])
    }

    /// Entry `b` of `l` was refused for the label's cap (`unfit`: it can never fit): its bytes
    /// and blob record go, its entry record waits unopened; reported once per label until room
    /// appears.
    fn refuse_memory(&mut self, l: LabelId, b: BlobId, unfit: bool) -> Result<()> {
        if let Some(mut e) = self.state.entries.get(&(l, b)).cloned() {
            e.kind = Kind::Unknown;
            self.state.set_entry(l, b, e);
        }
        self.state.remove_blob(&b);
        self.delete_blobs(&[b])?;
        if unfit {
            if self.memory.unfit.insert(l, b, 1) {
                self.memory_report(&l, "an ephemeral commit larger than this node's whole ephemeral cap for the label is not applied");
            }
        } else {
            let used = self.state.memory_bytes.get(&l).copied().unwrap_or(0);
            let r = self.memory.refused.entry(l).or_default();
            r.ids.insert(b);
            r.used_at = if r.ids.len() == 1 { used } else { r.used_at.min(used) };
            if self.memory.reported.insert(l) {
                self.memory_report(&l, "this node's ephemeral cap for the label refused a commit: commits that would pass it are not applied here until room appears");
            }
        }
        Ok(())
    }

    pub(crate) fn memory_report(&mut self, l: &LabelId, detail: &str) {
        let now = self.engine.now();
        let tids = self.group_of(l, None).into_iter().collect();
        self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::EphemeralRefused, tids, commit: None, peer: None, detail: detail.into() }, now);
        self.engine.core.events.flush();
    }

    /// A memory entry of `l` was deleted at a host or expired there: no longer unfit.
    pub(crate) fn memory_entry_gone(&mut self, l: LabelId, b: BlobId) {
        self.memory.unfit.remove(l, b);
        if let Some(r) = self.memory.refused.get_mut(&l) {
            r.ids.remove(&b);
            if r.ids.is_empty() {
                self.memory.refused.remove(&l);
            }
        }
    }

    /// Before a pass sends under `l` on `conn` (spec/sync.md §9 Sending): this node's own memory
    /// bodies not yet placed under `l` (writes and snapshots) wait while an own upload of the
    /// label is unanswered on the connection (judged again once it is); otherwise two or more
    /// of this session's plain writes on one aspect are replaced by one snapshot of their join
    /// (`Engine::coalesce`): covered here, never uploaded, so an aspect goes up as about one
    /// entry per round trip whatever the write rate. A body the snapshot could not cover (behind
    /// an invalid one of its session) and a snapshot among them go as they are. `bodies` is
    /// brought up to date.
    pub(super) fn coalesce_own(&mut self, conn: ConnId, l: LabelId, ctx: &BodyCtx, snaps: &super::pass::Snaps, bodies: &mut Vec<Body>, left: &mut Left) -> Result<()> {
        let nonce = self.engine.core.session.nonce;
        let mut own: BTreeMap<(Tid, osis_base::Ak), (Vec<CommitId>, bool)> = BTreeMap::new();
        let mut fresh = BTreeSet::new();
        for b in bodies.iter() {
            let Some((plain, compaction, aspects)) = self.engine.core.ix.commits.get(&b.commit).filter(|m| m.view.memory).map(|m| (matches!(m.view.form, Form::Session(n) if n == nonce) && !m.view.kind.is_compaction(), m.view.kind.is_compaction(), b.parts.iter().filter_map(|ai| m.view.aspects.get(*ai)).map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>())) else { continue };
            if !self.own(&b.commit) || self.state.entries_of(&l, &b.commit).next().is_some() {
                continue;
            }
            // one a snapshot under the label covers is not placed (may-hold, spec/sync.md §6):
            // not this round's either (an own body stays held under another's snapshot)
            let mut covered = false;
            for (t, a) in &aspects {
                for s in snaps.get(&(*t, a.clone())).cloned().into_iter().flatten() {
                    if s != b.commit && self.engine.covered(&s, &b.commit, t, a)? == Some(true) {
                        covered = true;
                    }
                }
            }
            if covered {
                continue;
            }
            fresh.insert(b.commit);
            // only this session's plain writes and own snapshots coalesce (an earlier session's
            // or an expiring write goes as it is), each once
            if (!plain && !compaction) || self.memory.coalesced.contains(&b.commit) {
                continue;
            }
            for (t, a) in aspects {
                let e = own.entry((t, a)).or_default();
                if !e.0.contains(&b.commit) {
                    e.0.push(b.commit);
                }
                e.1 |= !plain;
            }
        }
        if fresh.is_empty() {
            return Ok(());
        }
        let busy = self.memory.own_uploads.range((conn, l, BlobId([0; 32]))..=(conn, l, BlobId([0xff; 32]))).next().is_some();
        if busy {
            bodies.retain(|b| !fresh.contains(&b.commit));
            left.commits.extend(fresh);
            return Ok(());
        }
        let mut moved = BTreeSet::new();
        for ((tid, ak), (ids, whole)) in own {
            // a snapshot among them (the trigger's, or an earlier coalescing's that did not
            // cover a body behind an invalid one): all go as they are, so coalescing ends after
            // one snapshot per round and never spins
            if ids.len() < 2 || whole {
                continue;
            }
            self.memory.coalesced.extend(ids.iter().copied());
            if let Some(s) = self.engine.coalesce(&tid, &ak, &ids)? {
                moved.extend(ids);
                moved.insert(s);
            }
        }
        if moved.is_empty() {
            return Ok(());
        }
        // the coalesced commits' bodies as they are now (a part on another aspect stays held),
        // and the snapshots'
        bodies.retain(|b| !moved.contains(&b.commit));
        for c in moved {
            if self.engine.holds_memory(&c) {
                bodies.extend(self.engine.commit_bodies_under(ctx, &c)?);
            }
        }
        Ok(())
    }

    /// Notes an upload of `b` under `l` on `conn` when it is this node's own memory body (a
    /// write or a snapshot of its own: `own_uploads`).
    pub(super) fn note_own_upload(&mut self, conn: ConnId, l: LabelId, b: BlobId) {
        let Some(Entry { kind: Kind::Commit { commit, .. }, memory: true, .. }) = self.state.entries.get(&(l, b)) else { return };
        if self.own(commit) {
            self.memory.own_uploads.insert((conn, l, b));
        }
    }

    /// The memory entries of `l` held here, listed as gained by the first Sync of `l` on `conn`
    /// (spec/sync.md §6: the peer asks for those it lacks; the rest it holds, learned at the
    /// Sync's end, `memory_synced`). None when more than a Sync takes: those are learned by
    /// uploads answered OK (the pass uploads what counts as absent).
    pub(crate) fn memory_gained(&mut self, conn: ConnId, l: LabelId) -> Vec<BlobId> {
        if !self.memory.announced.insert((conn, l)) {
            return Vec::new();
        }
        let ids: BTreeSet<BlobId> = self.memory_entries_of(&l).filter(|(_, e)| matches!(e.kind, Kind::Commit { .. })).map(|(b, _)| b).collect();
        if ids.is_empty() || ids.len() > osis_proto::msg::MAX_GAINED {
            return Vec::new();
        }
        self.memory.gained.insert((conn, l), ids.clone());
        ids.into_iter().collect()
    }

    /// The peer wants gained entries: those are not present there (the pass uploads them); one
    /// of a forgotten commit, held nowhere and uploading nowhere, goes (`absent_at`).
    pub(crate) fn memory_want(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId]) -> Result<()> {
        let Some(mut g) = self.memory.gained.remove(&(conn, l)) else { return Ok(()) };
        for b in ids {
            if !g.remove(b) {
                continue;
            }
            let dead = matches!(self.state.entries.get(&(l, *b)), Some(Entry { kind: Kind::Commit { commit, .. }, .. }) if !self.engine.holds_memory(commit));
            if dead && !self.state.present_anywhere(&l, b) && !self.upload_in_flight(&l, b) {
                self.absent_at(None, l, *b)?;
            }
        }
        self.memory.gained.insert((conn, l), g);
        Ok(())
    }

    /// A Sync of `l` on `conn` ran through: what it listed as gained and the peer did not want,
    /// the peer holds.
    pub(crate) fn memory_synced(&mut self, conn: ConnId, l: LabelId) {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return };
        for b in self.memory.gained.remove(&(conn, l)).unwrap_or_default() {
            self.state.set_present(host, l, b, true);
        }
    }

    /// Fetches of `l` on `conn` answered (`refused` false) or refused: they leave
    /// `reconcile_fetches`; a refused one a reconciliation asked for reconciles the label again
    /// (on this connection's next sync, or the next periodic pass).
    pub(crate) fn memory_fetch_done(&mut self, conn: ConnId, l: LabelId, ids: &[BlobId], refused: bool) {
        let Some(asked) = self.memory.reconcile_fetches.get_mut(&(conn, l)) else { return };
        let mut lost = false;
        for b in ids {
            lost |= asked.remove(b) && refused;
        }
        if asked.is_empty() {
            self.memory.reconcile_fetches.remove(&(conn, l));
        }
        if lost && let Some(c) = self.conns.get(&conn) {
            self.memory.reconciled.remove(&(c.host, l));
        }
    }

    /// A connection ended: what waited on it goes with it; a restart reconciliation with
    /// fetches unanswered runs again on the next connection. A memory entry counts as present
    /// at a host only as learned on the connection up now (spec/sync.md §9: a restarted host
    /// lost them, and its durable log says nothing of it), so the next connection's passes
    /// upload what the host lacks and are answered OK for what it kept.
    pub(crate) fn memory_lost(&mut self, conn: ConnId, host: HostKey, fetching: &BTreeSet<BlobId>) -> Result<()> {
        let gone: Vec<(LabelId, BlobId)> = self.state.memory_entries.iter().filter(|(l, b)| self.state.is_present(&host, l, b)).copied().collect();
        for (l, b) in gone {
            self.state.set_present(host, l, b, false);
        }
        // an entry of a forgotten commit the host may have kept (its upload or delete unanswered
        // when the connection ended) stays known until the next connection's Sync says
        // (`memory_gained`: wanted, it is held nowhere and goes; else it is present and deleted)
        let unanswered: Vec<LabelId> = self.memory.reconcile_fetches.iter().filter(|((c, _), ids)| *c == conn && !ids.is_disjoint(fetching)).map(|((_, l), _)| *l).collect();
        for l in unanswered {
            self.memory.reconciled.remove(&(host, l));
        }
        self.memory.reconcile_fetches.retain(|(c, _), _| *c != conn);
        self.memory.reconciling.retain(|(c, _)| *c != conn);
        self.memory.own_uploads.retain(|(c, _, _)| *c != conn);
        self.memory.gained.retain(|(c, _), _| *c != conn);
        self.memory.announced.retain(|(c, _)| *c != conn);
        Ok(())
    }

    /// Places a relay-only commit built here (`blob`: its header and parts) as one blob
    /// (spec/sync.md §3, §9) under every synced label whose closure holds a thing of it the
    /// label's actor may read, and sends it on every connection where the label is open.
    fn place_relay(&mut self, id: CommitId, blob: CommitBlob, out: &mut Vec<Action>) -> Result<()> {
        let body = Body {
            commit: id,
            parts: blob.parts.iter().map(|p| p.ai).collect(),
            expires: osis_commit::blob_expiry(&blob.header),
            blind: blob.header.blind,
            plaintext: blob.encode(),
            role_commit: false,
            order: crate::labeling::fetch_order(&blob.header),
            to_label: false,
        };
        let mut sealed: Option<crate::labeling::Sealed> = None;
        for (g, gl) in self.labels() {
            if gl.replaced {
                continue;
            }
            let l = gl.id;
            let closure = self.engine.closure(&g);
            let actor = self.engine.group_actor(&g);
            if !blob.header.aspects.iter().any(|a| (a.tid == g || closure.contains(&a.tid)) && self.engine.may_read(&actor, &self.engine.core.reader_of(&a.tid))) {
                continue;
            }
            let Some(secret) = self.engine.wrap_secret(&g, None)? else { continue };
            if sealed.is_none() {
                sealed = self.engine.seal(&body, Class::Relay, &[], &mut *self.rng)?;
            }
            let Some(s) = &sealed else { break };
            let stamp_key = self.relay_stamp_key(&g, &l);
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key, body.order)?;
            let stamp = stamp_key.as_ref().map(|w| osis_label::sign_stamp(w, &l, &s.id, &wrap));
            self.send_relay(l, s.blob.clone(), wrap, stamp, out)?;
        }
        Ok(())
    }

    /// A write key for `l` of `g`: an open connection's, else the head this node serves the
    /// label at.
    fn relay_stamp_key(&mut self, g: &Tid, l: &LabelId) -> Option<osis_crypto::SigningSecret> {
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

    /// Sends a relay-only entry on every connection where `l` is open (and to the served
    /// sessions, as a co-reader peer would push it), stamped.
    fn send_relay(&mut self, l: LabelId, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<Signature>, out: &mut Vec<Action>) -> Result<()> {
        let blob_id = osis_label::blob_id(&blob);
        if blob.len() > osis_base::format::MAX_RELAY_BLOB {
            self.memory_report(&l, "an ephemeral signal too large for a relay-only blob was not sent");
            return Ok(());
        }
        // never delivered here again (a co-reader peer's path may bring it back)
        let t = osis_label::Prefix::parse(&blob).ok().and_then(|p| p.expiry()).map_or(0, |t| t.0);
        let now = self.now();
        self.memory.relays.first(l, blob_id, t, now);
        for (conn, _, keys) in self.open_conns(&l) {
            let st = match (stamp, &keys.write) {
                (Some(s), _) => s,
                (None, Some(w)) => osis_label::sign_stamp(w, &l, &blob_id, &wrap),
                (None, None) => continue,
            };
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
        if t <= now || t > now.saturating_add(2 * osis_base::format::MAX_DRIFT_MS) || !self.memory.relays.fresh(l, b, t, now) {
            return Ok(());
        }
        let Some(g) = self.group_of(&l, None) else { return Ok(()) };
        let secrets = self.read_secrets(&g);
        let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &b, &wrap) else { return Ok(()) };
        let cb = match self.engine.open_commit(&blob, &key, Some(&g)) {
            Ok(o) => o.commit,
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
            Ok(true) => self.memory.relays.record(l, b, t),
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
            for (conn, _, _) in self.open_conns(&l) {
                self.command(conn, Command::Upload { label: l, entries: vec![osis_proto::Entry { blob: r.blob.to_vec(), wrap: r.wrap, stamp: r.stamp, replaces: Vec::new() }] }, out)?;
            }
        }
        Ok(())
    }

    /// Statuses of relay-only uploads need nothing; a code other than OK is noted.
    pub(crate) fn relay_status(&mut self, b: &BlobId, code: Code) -> bool {
        if self.state.blobs.contains_key(b) || self.state.named(b) {
            return false;
        }
        if code != Code::OK {
            self.diag(format!("relay-only upload refused: code {}", code.0));
        }
        true
    }

    /// Tests: compacts every memory aspect held here now (forced) and runs the passes that place
    /// the snapshots.
    #[doc(hidden)]
    pub fn compact_ephemeral_now(&mut self) -> Result<Vec<Action>> {
        let mut out = Vec::new();
        self.engine.memory_compactions(true)?;
        self.memory_step(&mut out)?;
        self.engine_events()?;
        self.run_dirty(&mut out)?;
        Ok(out)
    }

    /// The memory entries held under `l`.
    fn memory_entries_of<'a>(&'a self, l: &LabelId) -> impl Iterator<Item = (BlobId, &'a Entry)> + 'a {
        self.state.label_entries(l).filter(|(_, e)| e.memory)
    }

    /// Tests: the ephemeral entries held under `l` (blob ID and size), to check them against a
    /// host's cap.
    #[doc(hidden)]
    pub fn ephemeral_held_entries(&self, l: &LabelId) -> Vec<(BlobId, usize)> {
        self.memory_entries_of(l).filter_map(|(b, _)| self.state.memory_sizes.get(&(*l, b)).map(|n| (b, *n))).collect()
    }

    /// Tests: this node's own held memory commits with no entry under any label yet (what the
    /// passes are about to place), oldest first.
    #[doc(hidden)]
    pub fn unplaced_memory_commits(&self) -> Vec<CommitId> {
        let me = self.engine.tid();
        let mut v: Vec<(osis_base::Ts, CommitId)> = self.engine.core.ix.commits.iter().filter(|(c, m)| m.view.memory && m.view.author == me && !self.state.memory_commits.contains(c)).map(|(c, m)| (m.view.ts, *c)).collect();
        v.sort();
        v.into_iter().map(|x| x.1).collect()
    }

    /// What the ephemeral entries held from others under `l` count against its cap (their
    /// charge: memory held, not encoded bytes; tests, diagnostics).
    pub fn ephemeral_bytes(&self, l: &LabelId) -> u64 {
        self.state.memory_bytes.get(l).copied().unwrap_or(0)
    }

    /// The encoded bytes and the charge of each entry held from others under `l` (tests).
    pub fn ephemeral_held_from_others(&self, l: &LabelId) -> Vec<(usize, u64)> {
        self.state.memory_charge.range((*l, BlobId([0; 32]))..=(*l, BlobId([0xff; 32]))).map(|((_, b), c)| (self.state.memory_sizes.get(&(*l, *b)).copied().unwrap_or(0), *c)).collect()
    }


    /// Tests: the ephemeral entries of commit `c` held here, as the log events a host pushes
    /// (a capture to replay).
    #[doc(hidden)]
    pub fn ephemeral_entry_events(&mut self, c: &CommitId) -> Vec<(LabelId, osis_proto::Event)> {
        let keys = self.entries_of_commit(c);
        let mut out = Vec::new();
        for (l, b) in keys {
            let Some(e) = self.state.entries.get(&(l, b)).cloned().filter(|e| e.memory) else { continue };
            let Some(blob) = self.engine.blob(&b).ok().flatten() else { continue };
            out.push((l, osis_proto::Event::Added { blob_id: b, blob: Some(blob), wrap: e.wrap, stamp: e.stamp }));
        }
        out
    }

    /// Tests: the entries of ephemeral commit `c` held here, with the hosts this node counts
    /// them present at (by host key).
    #[doc(hidden)]
    pub fn ephemeral_entries_of(&self, c: &CommitId) -> Vec<(LabelId, BlobId, Vec<[u8; 32]>)> {
        self.entries_of_commit(c).into_iter().filter(|(l, b)| self.state.is_memory(l, b)).map(|(l, b)| (l, b, self.state.hosts_of(&l, &b))).collect()
    }

    /// Tests, diagnostics: the memory entries under `l` as text, one per line (commit, own,
    /// the hosts it is present at by key prefix), then the label's counts.
    #[doc(hidden)]
    pub fn ephemeral_dump(&self, l: &LabelId) -> String {
        use std::fmt::Write;
        let key = |s: &[u8; 32]| osis_base::hex::encode(&s[..4]);
        let rows: Vec<(BlobId, Kind)> = self.memory_entries_of(l).map(|(b, e)| (b, e.kind.clone())).collect();
        let mut out = String::new();
        for (b, kind) in rows {
            let at: Vec<String> = self.state.hosts_of(l, &b).iter().map(key).collect();
            let (commit, own) = match &kind {
                Kind::Commit { commit, .. } => (Some(*commit), self.own(commit)),
                _ => (None, false),
            };
            let size = self.state.memory_sizes.get(&(*l, b)).copied().unwrap_or(0);
            let charge = self.state.memory_charge.get(&(*l, b)).copied();
            let _ = writeln!(out, "  {b:?} commit {commit:?} own {own} {size} B charge {charge:?} present {at:?}");
        }
        let _ = writeln!(out, "  bytes {:?} refused {:?}", self.state.memory_bytes.get(l), self.memory.refused.get(l).map(|r| r.ids.len()));
        out
    }

    /// Tests: what node-sync keeps beside the memory entries: forgotten headers, deleted bodies,
    /// tombstones, carriers, blob records, class marks of entries and commits.
    #[doc(hidden)]
    pub fn memory_kept(&self) -> [usize; 7] {
        let s = &self.state;
        [self.memory.forgotten.len(), s.deleted.len(), s.tombs.len(), s.carriers.len(), s.blobs.values().filter(|r| r.memory).count(), s.memory_entries.len(), s.memory_commits.len()]
    }

    /// Memory entries held under `l` whose commit the engine holds (tests, diagnostics).
    pub fn ephemeral_entries(&self, l: &LabelId) -> usize {
        self.memory_entries_of(l).filter(|(_, e)| matches!(&e.kind, Kind::Commit { commit, .. } if self.engine.holds_memory(commit))).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u32) -> BlobId {
        let mut x = [0u8; 32];
        x[..4].copy_from_slice(&n.to_be_bytes());
        BlobId(x)
    }

    // the per-label bound: past it the oldest goes, per label
    #[test]
    fn per_label_bounded_by_weight() {
        let mut p = PerLabel::new(3);
        let (l1, l2) = (LabelId([1; 16]), LabelId([2; 16]));
        for i in 0..5 {
            p.insert(l1, b(i), 1);
        }
        p.insert(l2, b(9), 1);
        assert!(!p.contains(l1, b(0)) && !p.contains(l1, b(1)));
        assert!(p.contains(l1, b(2)) && p.contains(l1, b(3)) && p.contains(l1, b(4)));
        assert!(p.contains(l2, b(9)));
        p.remove(l1, b(3));
        assert!(!p.contains(l1, b(3)));
        p.insert(l1, b(5), 1);
        assert!(p.contains(l1, b(2)), "room for one more");
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
