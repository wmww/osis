//! Judgement for read sync IDs (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1) on a
//! fake ground: the engine's facts and the own store as stamped values, and one source K keeping
//! S unread that judges nothing (it pulls a writer's store, refuses a tombstoned blob ID, takes
//! Deletes; a test may delete there as a hostile writer). `Read` runs as in a node while the
//! engine facade, streams' `known` by commit and the store's entries by commit are not built:
//! every test here needs the real facade (sync-facade) and streams to run end to end in a world.
//! Each negative control of core/test/tla/net/NetHold.tla and NetDestroy.tla has a test here that
//! fails without its rule, and each area-4 scenario of the Phase 1 checklist (issues/sync-rewrite.md) one.

use osis_base::memo::Stamped;
use osis_base::{BlobId, CommitId, SyncId, WallMs};
use osis_crypto::{LabelRole, Secret32, Signature, SigningSecret, label_role_key};
use osis_engine::labeling::HeadKeys;
use osis_engine::sync::{BodyFacts, BodyMeta, Destruction, ReadCredentials};
use osis_label::{Class, Step, StepKeys};
use osis_sync::read::{BlobInfo, Facts, Ground, PieceAt, Read, RecordsMissing, Seen, SrcView, Verdict, Why};
use osis_engine::sync::Pieces;
use osis_base::Tid;
use osis_sync::store::{Source, Stand};
use osis_sync::types::{ConnId, Entry};
use osis_sync::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const S: SyncId = SyncId([1; 16]);
const S2: SyncId = SyncId([2; 16]);
const KC: ConnId = ConnId(1);
const K: Source = Source::Conn(KC);
const RC: ConnId = ConnId(2);

fn cid(i: u8) -> CommitId {
    CommitId([i; 32])
}

fn key(role: LabelRole, e: u64) -> SigningSecret {
    let mut b = [role as u8 + 9; 32];
    b[..8].copy_from_slice(&e.to_le_bytes());
    label_role_key(role, &Secret32::from_bytes(b))
}

fn step(e: u64) -> Step {
    let vk = |r| key(r, e).verifying_key();
    Step {
        label: S,
        prev: None,
        keys: StepKeys { sync: vk(LabelRole::Sync), write: vk(LabelRole::Write), delete: vk(LabelRole::Delete), deposit: vk(LabelRole::Write) },
        step_key: [e as u8; 32],
        claims_hash: [0; 32],
        sig: Signature([0; 64]),
    }
}

/// A reader's credentials at head step `e`: a writer, with the delete key when `delete`.
fn creds(e: u64, writer: bool, delete: bool) -> Arc<ReadCredentials> {
    let hk = HeadKeys { sync: None, sync_established: true, write: writer.then(|| key(LabelRole::Write, e)), delete: delete.then(|| key(LabelRole::Delete, e)), deposit: None, epochs: [None; 3] };
    let mut keys = BTreeMap::new();
    for i in 0..=e {
        keys.insert(step(i).id(), hk.clone());
    }
    Arc::new(ReadCredentials { head: Some(step(e)), keys, read_secrets: Vec::new(), statics: BTreeSet::new(), ..Default::default() })
}

fn meta() -> BodyMeta {
    BodyMeta { parts: [0].into(), expires: None, order: 1, copy: false, certificate: false, header_only: false }
}

/// A body of this node's own, established uncovered: must-hold.
fn uncovered() -> Facts {
    Facts {
        body: BodyFacts { required: true, closure: true, dropped: None, kept: false, covered: Some(false), sole_certificate: false, lasting_header: false },
        must_not: None,
        own: true,
        repair: false,
        role: false,
        carriers: Vec::new(),
        later_unheld: Vec::new(),
        missing: false,
    }
}

/// Covered by snapshot `by`, past its keep bound: its live write needs `by` as carrier.
fn covered(by: CommitId) -> Facts {
    let mut f = uncovered();
    f.body.covered = Some(true);
    f.carriers = vec![[by].into()];
    f
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    Delete(ConnId, BlobId),
    Deposit(ConnId, BlobId),
    Forget(SyncId),
    Fetch(ConnId, BlobId),
    LogPiece(BlobId),
    TakePiece(BlobId),
    Repair(CommitId, BlobId),
    DropPiece(BlobId),
    DeleteFreed(ConnId, BlobId),
    FreedDone(BlobId),
}

/// K: a node keeping S unread. It pulls what it lacks of a writer's store (a tombstoned blob ID
/// refused as deleted), takes Deletes, and judges nothing.
#[derive(Default)]
struct Kstore {
    held: BTreeMap<(SyncId, BlobId), CommitId>,
    tomb: BTreeSet<(SyncId, BlobId)>,
    refused: BTreeSet<(SyncId, BlobId)>,
    full: bool,
}

/// The engine, the own store and K as `Read` sees them.
#[derive(Default)]
struct Fake {
    now: u64,
    added: Vec<CommitId>,
    bodies: Stamped<CommitId, Arc<BTreeMap<SyncId, BodyMeta>>>,
    facts: Stamped<(SyncId, CommitId), Facts>,
    marks: Stamped<(SyncId, CommitId), u64>,
    creds: Stamped<SyncId, Arc<ReadCredentials>>,
    doom: Stamped<SyncId, Arc<Destruction>>,
    own: Stamped<(SyncId, CommitId), Vec<Entry>>,
    tombs: Stamped<(SyncId, CommitId), Vec<BlobId>>,
    sources: Stamped<SyncId, Arc<Vec<SrcView>>>,
    srcs: Stamped<(SyncId, Source), SrcView>,
    src_feed: Vec<(SyncId, Source)>,
    seen: Stamped<(Source, SyncId, CommitId), Seen>,
    seen_feed: Vec<(Source, SyncId, CommitId)>,
    anywhere: Stamped<(SyncId, CommitId), bool>,
    /// S not read here, its closure not settled, or no reader can pull it.
    unread: Stamped<SyncId, ()>,
    unsettled: Stamped<SyncId, ()>,
    unpullable: Stamped<SyncId, ()>,
    /// Blobs held with other parts than `{0}`, as a copy, or without bytes (`None`).
    blobs: Stamped<BlobId, Option<BlobInfo>>,
    /// Blobs holding a part dropped here for good (a purge).
    dropped: Stamped<BlobId, ()>,
    /// Whether each logging was a fresh encryption.
    fresh: Vec<bool>,
    all: Stamped<(Source, SyncId), BTreeSet<BlobId>>,
    stands: Stamped<(Source, SyncId, CommitId), Stand>,
    heard: Stamped<SyncId, bool>,
    next: u32,
    sent: Vec<Sent>,
    logged: Vec<(SyncId, CommitId, BlobId)>,
    /// Per S, the records it carries that no own record blob does, and own record blobs gone.
    records: Stamped<SyncId, RecordsMissing>,
    /// Record blobs logged, and rows of gone ones forgotten.
    record_logs: Vec<(SyncId, BTreeSet<osis_base::Tid>)>,
    records_forgotten: Vec<(SyncId, BlobId)>,
    k: Kstore,
    /// Pieces per body, what the own store has of each, what each source shows of each.
    pieces: Stamped<(SyncId, CommitId), Arc<Pieces>>,
    piece_at: Stamped<(SyncId, BlobId), PieceAt>,
    piece_seen: Stamped<(Source, SyncId, BlobId), (bool, bool)>,
    /// Freed links in the set (and a feed of those added), the sync IDs carrying each thing.
    freed: Stamped<(BlobId, Tid), ()>,
    freed_feed: Vec<(BlobId, Tid)>,
    carrying: Stamped<Tid, BTreeSet<SyncId>>,
}

impl Ground for Fake {
    fn pieces(&mut self, s: &SyncId, c: &CommitId) -> Result<Arc<Pieces>> {
        Ok(self.pieces.get(&(*s, *c)).cloned().unwrap_or_default())
    }
    fn piece(&mut self, s: &SyncId, b: &BlobId) -> Result<PieceAt> {
        Ok(self.piece_at.get(&(*s, *b)).copied().unwrap_or(PieceAt::Absent))
    }
    fn piece_seen(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<(bool, bool)> {
        Ok(self.piece_seen.get(&(*at, *s, *b)).copied().unwrap_or((false, false)))
    }
    fn log_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.sent.push(Sent::LogPiece(*b));
        self.piece_at.insert((*s, *b), PieceAt::Own);
        Ok(())
    }
    fn take_piece(&mut self, _s: &SyncId, b: &BlobId) -> Result<()> {
        self.sent.push(Sent::TakePiece(*b));
        Ok(())
    }
    fn repair(&mut self, c: &CommitId, b: &BTreeSet<BlobId>) -> Result<()> {
        self.sent.extend(b.iter().map(|b| Sent::Repair(*c, *b)));
        Ok(())
    }
    fn freed_added(&mut self) -> Result<Vec<(BlobId, Tid)>> {
        Ok(std::mem::take(&mut self.freed_feed))
    }
    fn freed_link(&mut self, b: &BlobId, t: &Tid) -> Result<bool> {
        Ok(self.freed.contains_key(&(*b, *t)))
    }
    fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        Ok(self.carrying.get(t).cloned().unwrap_or_default())
    }
    fn drop_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.sent.push(Sent::DropPiece(*b));
        self.piece_at.insert((*s, *b), PieceAt::Tombstoned);
        Ok(())
    }
    fn delete_freed(&mut self, at: &SrcView, _s: &SyncId, _head: &osis_label::StepId, b: &BlobId, _t: &Tid) -> Result<()> {
        self.sent.push(Sent::DeleteFreed(at.conn, *b));
        Ok(())
    }
    fn freed_done(&mut self, b: &BlobId, t: &Tid) -> Result<()> {
        self.sent.push(Sent::FreedDone(*b));
        self.freed.remove(&(*b, *t));
        Ok(())
    }
    fn commits_added(&mut self) -> Result<Vec<CommitId>> {
        Ok(std::mem::take(&mut self.added))
    }
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<BTreeMap<SyncId, BodyMeta>>> {
        Ok(self.bodies.get(c).cloned().unwrap_or_default())
    }
    fn facts(&mut self, s: &SyncId, c: &CommitId) -> Result<Facts> {
        Ok(self.facts.get(&(*s, *c)).cloned().unwrap_or_else(uncovered))
    }
    fn fall_mark(&mut self, s: &SyncId, c: &CommitId) -> Result<u64> {
        Ok(self.marks.get(&(*s, *c)).copied().unwrap_or(0))
    }
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        Ok(self.creds.get(s).cloned())
    }
    fn destruction(&mut self, s: &SyncId) -> Result<Option<Arc<Destruction>>> {
        Ok(self.doom.get(s).cloned())
    }
    fn reads(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unread.contains_key(s))
    }
    fn closure_settled(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unsettled.contains_key(s))
    }
    fn pullable(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unpullable.contains_key(s))
    }
    fn records_missing(&mut self, s: &SyncId) -> Result<RecordsMissing> {
        Ok(self.records.get(s).cloned().unwrap_or_default())
    }
    fn forget_record_blobs(&mut self, s: &SyncId, gone: &BTreeSet<BlobId>) -> Result<()> {
        self.records_forgotten.extend(gone.iter().map(|b| (*s, *b)));
        let mut r = self.records.get(s).cloned().unwrap_or_default();
        r.gone.clear();
        self.records.insert(*s, r);
        Ok(())
    }
    fn log_records(&mut self, s: &SyncId, records: &BTreeSet<osis_base::Tid>) -> Result<()> {
        self.record_logs.push((*s, records.clone()));
        let mut r = self.records.get(s).cloned().unwrap_or_default();
        r.records.retain(|t| !records.contains(t));
        self.records.insert(*s, r);
        Ok(())
    }
    fn now(&self) -> WallMs {
        WallMs(self.now)
    }
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>> {
        Ok(self.blobs.get(b).cloned().unwrap_or(Some(BlobInfo { parts: [0].into(), copy: false })))
    }
    fn dropped(&mut self, b: &BlobId) -> Result<bool> {
        Ok(self.dropped.contains_key(b))
    }
    // every entry of a commit carries its whole body here: none is a strict subset, any held
    // one carries it (the engine's own judgement: core/engine/src/sync/tests_facts.rs)
    fn strict_subset(&mut self, _s: &SyncId, _b: &BlobId, _held: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(false)
    }
    fn neither(&mut self, _s: &SyncId, _c: &CommitId, there: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(!there.is_empty())
    }
    fn own(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<Entry>> {
        Ok(self.own.get(&(*s, *c)).cloned().unwrap_or_default())
    }
    fn own_tombstones(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>> {
        Ok(self.tombs.get(&(*s, *c)).cloned().unwrap_or_default())
    }
    fn own_empty(&mut self, s: &SyncId) -> Result<bool> {
        let keys: Vec<(SyncId, CommitId)> = self.own.keys().filter(|(x, _)| x == s).copied().collect();
        Ok(keys.iter().all(|k| self.own.get(k).is_none_or(Vec::is_empty)))
    }
    fn deletes_known(&mut self, s: &SyncId) -> Result<bool> {
        let keys: Vec<(Source, SyncId, CommitId)> = self.seen.keys().filter(|(_, x, _)| x == s).copied().collect();
        let pieces: Vec<(Source, SyncId, BlobId)> = self.piece_seen.keys().filter(|(_, x, _)| x == s).copied().collect();
        Ok(keys.iter().any(|k| self.seen.get(k).is_some_and(|v| !v.deleted.is_empty())) || pieces.iter().any(|k| self.piece_seen.get(k).is_some_and(|v| v.1)))
    }
    fn sources(&mut self, s: &SyncId) -> Result<Arc<Vec<SrcView>>> {
        Ok(self.sources.get(s).cloned().unwrap_or_default())
    }
    fn source(&mut self, s: &SyncId, at: &Source) -> Result<Option<SrcView>> {
        Ok(self.srcs.get(&(*s, *at)).cloned())
    }
    fn sources_added(&mut self) -> Result<Vec<(SyncId, Source)>> {
        Ok(std::mem::take(&mut self.src_feed))
    }
    fn seen(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Seen> {
        Ok(self.seen.get(&(*at, *s, *c)).cloned().unwrap_or_default())
    }
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, CommitId)>> {
        Ok(std::mem::take(&mut self.seen_feed))
    }
    fn present_anywhere(&mut self, s: &SyncId, c: &CommitId) -> Result<bool> {
        Ok(self.anywhere.get(&(*s, *c)).copied().unwrap_or(false))
    }
    fn seen_all(&mut self, at: &Source, s: &SyncId) -> Result<BTreeSet<BlobId>> {
        Ok(self.all.get(&(*at, *s)).cloned().unwrap_or_default())
    }
    fn heard_out(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.heard.get(s).copied().unwrap_or(false))
    }
    fn stand(&mut self, at: &Source, s: &SyncId, c: &CommitId) -> Result<Option<Stand>> {
        Ok(self.stands.get(&(*at, *s, *c)).cloned())
    }
    fn log_own(&mut self, s: &SyncId, c: &CommitId, fresh: bool) -> Result<Option<BlobId>> {
        self.fresh.push(fresh);
        self.next += 1;
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&self.next.to_be_bytes());
        b[4] = c.0[0];
        let blob = BlobId(b);
        let mut v = self.own(s, c)?;
        v.push(Entry { blob, wrap: [0; osis_crypto::WRAP_LEN], stamp: None, deposited: false, own: true, role: false, class: Class::Durable, expires: None });
        self.own.insert((*s, *c), v);
        self.logged.push((*s, *c, blob));
        Ok(Some(blob))
    }
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &CommitId) -> Result<()> {
        let v: Vec<Entry> = self.own(s, c)?.into_iter().filter(|e| e.blob != *b).collect();
        self.own.insert((*s, *c), v);
        let mut t = self.own_tombstones(s, c)?;
        t.push(*b);
        self.tombs.insert((*s, *c), t);
        Ok(())
    }
    fn lift(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let keys: Vec<(SyncId, CommitId)> = self.tombs.keys().filter(|(x, _)| x == s).copied().collect();
        for k in keys {
            let t = self.tombs.get(&k).cloned().unwrap_or_default();
            if t.contains(b) {
                self.tombs.insert(k, t.into_iter().filter(|x| x != b).collect());
            }
        }
        Ok(())
    }
    fn fetch(&mut self, at: &SrcView, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = s;
        self.sent.push(Sent::Fetch(at.conn, *b));
        Ok(())
    }
    fn delete(&mut self, at: &SrcView, s: &SyncId, b: &BlobId, key: &SigningSecret) -> Result<()> {
        let _ = (s, key);
        self.sent.push(Sent::Delete(at.conn, *b));
        Ok(())
    }
    fn deposit(&mut self, at: &SrcView, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<()> {
        let _ = (s, c);
        self.sent.push(Sent::Deposit(at.conn, *b));
        Ok(())
    }
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &CommitId, stand: &Stand) -> Result<()> {
        self.stands.insert((*at, *s, *c), stand.clone());
        Ok(())
    }
    fn forget(&mut self, s: &SyncId) -> Result<()> {
        self.sent.push(Sent::Forget(*s));
        Ok(())
    }
}

impl Fake {
    /// A `known` row written: the feed and the per-commit presence follow it.
    fn put_seen(&mut self, k: (Source, SyncId, CommitId), v: Seen) {
        if self.seen.get(&k) == Some(&v) {
            return;
        }
        self.seen.insert(k, v);
        self.seen_feed.push(k);
        let (_, s, c) = k;
        let any = self.seen.iter().any(|((_, x, y), v)| *x == s && *y == c && !v.present.is_empty());
        if self.anywhere.get(&(s, c)).copied().unwrap_or(false) != any {
            self.anywhere.insert((s, c), any);
        }
    }

    fn set_sources(&mut self, s: SyncId, v: Vec<SrcView>) {
        let old = self.sources.get(&s).cloned().unwrap_or_default();
        for x in old.iter().filter(|x| !v.iter().any(|y| y.at == x.at)) {
            self.srcs.remove(&(s, x.at));
        }
        for x in &v {
            if self.srcs.get(&(s, x.at)) != Some(x) {
                self.srcs.insert((s, x.at), x.clone());
                self.src_feed.push((s, x.at));
            }
        }
        self.sources.insert(s, Arc::new(v));
    }
}

/// A reader running `Read` over a fake ground, with K as its one store source.
struct W {
    g: Fake,
    read: Read,
    /// K pulls this node's store (it is a writer at K's head).
    pulls: bool,
    /// What K took of what was sent.
    taken: Vec<Sent>,
}

impl W {
    /// A writer of S holding the delete key, K a store source at head 0.
    fn new() -> W {
        let mut g = Fake::default();
        g.creds.insert(S, creds(0, true, true));
        g.creds.insert(S2, creds(0, true, true));
        let mut w = W { g, read: Read::default(), pulls: true, taken: Vec::new() };
        w.source(S, K, KC, true);
        w.source(S2, K, KC, true);
        w
    }

    fn source(&mut self, s: SyncId, at: Source, conn: ConnId, store: bool) {
        let mut v = (*self.g.sources(&s).unwrap()).clone();
        v.retain(|x| x.conn != conn);
        v.push(SrcView { at, conn, store, head: Some(step(0).id()), full: false, role_unheld: false });
        self.g.set_sources(s, v);
    }

    fn edit_source(&mut self, conn: ConnId, f: impl Fn(&mut SrcView)) {
        for s in [S, S2] {
            let mut v = (*self.g.sources(&s).unwrap()).clone();
            v.iter_mut().filter(|x| x.conn == conn).for_each(&f);
            self.g.set_sources(s, v);
        }
        self.settle();
    }

    /// The engine holds `c` with a body under each of `ids`, judged `f`.
    fn hold(&mut self, c: CommitId, ids: &[SyncId], f: Facts) {
        for s in ids {
            self.g.facts.insert((*s, c), f.clone());
        }
        self.g.bodies.insert(c, Arc::new(ids.iter().map(|s| (*s, meta())).collect()));
        self.g.added.push(c);
        self.settle();
    }

    fn judge(&mut self, s: SyncId, c: CommitId, f: Facts) {
        self.g.facts.insert((s, c), f);
        self.settle();
    }

    fn settle(&mut self) {
        for _ in 0..16 {
            if !self.read.settle_on(&mut self.g).unwrap() {
                return;
            }
        }
        panic!("read's settle does not end");
    }

    /// One exchange with K: K takes the Deletes sent, pulls this node's store, and its stream
    /// is read to its end.
    fn exchange(&mut self) {
        self.settle();
        for m in std::mem::take(&mut self.g.sent) {
            if matches!(m, Sent::Delete(c, _) | Sent::Deposit(c, _) if c == KC) {
                self.taken.push(m.clone());
            }
            match m {
                Sent::Delete(c, b) if c == KC => {
                    for s in [S, S2] {
                        if self.g.k.held.remove(&(s, b)).is_some() {
                            self.g.k.tomb.insert((s, b));
                        }
                    }
                }
                Sent::Deposit(c, b) if c == KC => self.k_take(b),
                other => self.g.sent.push(other),
            }
        }
        if self.pulls {
            let own: Vec<((SyncId, CommitId), Vec<Entry>)> = self.g.own.iter().map(|(k, v)| (*k, v.clone())).collect();
            for ((s, c), es) in own {
                for e in es {
                    if self.g.k.tomb.contains(&(s, e.blob)) {
                        self.g.k.refused.insert((s, e.blob));
                    } else if !self.g.k.full {
                        self.g.k.held.insert((s, e.blob), c);
                    }
                }
            }
        }
        self.stream();
        self.settle();
    }

    fn k_take(&mut self, b: BlobId) {
        for (s, c, x) in self.g.logged.clone() {
            if x == b && !self.g.k.tomb.contains(&(s, b)) {
                self.g.k.held.insert((s, b), c);
            }
        }
    }

    /// A hostile writer deletes every entry of `c` at K.
    fn k_delete(&mut self, c: CommitId) {
        let blobs: Vec<(SyncId, BlobId)> = self.g.k.held.iter().filter(|(_, x)| **x == c).map(|(k, _)| *k).collect();
        for k in blobs {
            self.g.k.held.remove(&k);
            self.g.k.tomb.insert(k);
        }
        self.stream();
        self.settle();
    }

    /// K's stream read to its end: what is present there, and what was deleted or refused as
    /// tombstoned.
    fn stream(&mut self) {
        let mut seen: BTreeMap<(Source, SyncId, CommitId), Seen> = BTreeMap::new();
        let commit_of: BTreeMap<BlobId, CommitId> = self.g.logged.iter().map(|(_, c, b)| (*b, *c)).collect();
        for ((s, b), c) in &self.g.k.held {
            seen.entry((K, *s, *c)).or_default().present.insert(*b);
        }
        for (s, b) in self.g.k.tomb.iter().chain(self.g.k.refused.iter()) {
            if let Some(c) = commit_of.get(b) {
                seen.entry((K, *s, *c)).or_default().deleted.insert(*b);
            }
        }
        let keys: BTreeSet<(Source, SyncId, CommitId)> = seen.keys().chain(self.g.seen.keys().filter(|(a, _, _)| *a == K)).copied().collect();
        for k in keys {
            let mut now = seen.remove(&k).unwrap_or_default();
            // deletes seen are kept within the tombstone lifetime
            if let Some(old) = self.g.seen.get(&k) {
                now.deleted.extend(old.deleted.iter().copied());
            }
            self.g.put_seen(k, now);
        }
        for s in [S, S2] {
            let all: BTreeSet<BlobId> = self.g.k.held.keys().filter(|(x, _)| *x == s).map(|(_, b)| *b).collect();
            if self.g.all.get(&(K, s)) != Some(&all) {
                self.g.all.insert((K, s), all);
            }
        }
        let full = self.g.k.full;
        if self.g.sources(&S).unwrap().iter().any(|x| x.conn == KC && x.full != full) {
            self.edit_source(KC, |x| x.full = full);
        }
    }

    /// `TOMBSTONE_LIFETIME` passes at K and here.
    fn expire_tombstones(&mut self) {
        self.g.k.tomb.clear();
        self.g.k.refused.clear();
        let keys: Vec<(Source, SyncId, CommitId)> = self.g.seen.keys().copied().collect();
        for k in keys {
            let mut v = self.g.seen.get(&k).cloned().unwrap_or_default();
            if !v.deleted.is_empty() {
                v.deleted.clear();
                self.g.put_seen(k, v);
            }
        }
        self.g.stands = Stamped::default();
        self.settle();
    }

    fn at_k(&self, s: SyncId, c: CommitId) -> usize {
        self.g.k.held.values().filter(|x| **x == c).count() * usize::from(self.g.k.held.keys().any(|(x, _)| *x == s))
    }

    fn own_blobs(&mut self, s: SyncId, c: CommitId) -> Vec<BlobId> {
        self.g.own(&s, &c).unwrap().into_iter().map(|e| e.blob).collect()
    }

    /// Deletes sent so far, K's taken included.
    fn deletes(&self) -> usize {
        self.sent().filter(|m| matches!(m, Sent::Delete(..))).count()
    }

    fn sent(&self) -> impl Iterator<Item = &Sent> {
        self.taken.iter().chain(self.g.sent.iter())
    }

    /// Times `c` was logged under `s` (its first logging included).
    fn logs(&self, s: SyncId, c: CommitId) -> usize {
        self.g.logged.iter().filter(|(x, y, _)| *x == s && *y == c).count()
    }
}

// spec/sync-judgement.md §3 (own store): a must-hold body of this node's own is logged in its own
// store once, whatever peers are connected, and K, pulling a writer's store, takes it.
#[test]
fn must_hold_is_logged_once_and_pulled() {
    let mut w = W::new();
    w.hold(cid(1), &[S], uncovered());
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
    w.exchange();
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 1);
    assert_eq!(w.at_k(S, cid(1)), 1);
}

// spec/sync-judgement.md §2 (must-not-hold): outside the required set or purged is must-not-hold;
// covered is may-hold; a cover not judged yet leaves it unjudged, and nothing acts on it.
#[test]
fn verdicts_follow_the_facts() {
    let mut w = W::new();
    let mut f = uncovered();
    f.body.covered = None;
    w.hold(cid(1), &[S], f);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Unjudged));
    assert_eq!(w.logs(S, cid(1)), 0);
    w.judge(S, cid(1), covered(cid(9)));
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::May));
    let mut f = uncovered();
    f.must_not = Some(Why::Purged);
    w.judge(S, cid(1), f);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::MustNot(Why::Purged)));
    let mut f = uncovered();
    f.body.required = false;
    w.judge(S, cid(1), f);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::MustNot(Why::OutsideRequired)));
}

// spec/sync-judgement.md §1 (one the node dropped for good makes the blob must-not-hold): an own
// entry whose blob holds a part purged here leaves the own store while the body stays
// must-hold, and the rest of the body is logged again as a fresh encryption without it.
#[test]
fn entry_holding_a_purged_part_leaves_spec_sync_judgement_1() {
    let mut w = W::new();
    w.hold(cid(1), &[S], uncovered());
    w.exchange();
    let old = w.own_blobs(S, cid(1));
    assert_eq!(old.len(), 1);
    w.g.dropped.insert(old[0], ());
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must), "the body S needs now stays must-hold");
    let now = w.own_blobs(S, cid(1));
    assert!(!now.contains(&old[0]), "the entry holding the purged part left");
    assert_eq!(now.len(), 1, "the rest of the body logged again");
}

// spec/sync-judgement.md §3 (own store) (aged-covers): an entry covered and dropped leaves the own
// store with no delete key, and a body its author keeps as local data under another writer's
// cover leaves the log too, so K does not pull it back once its tombstone expires (HN_ownlog).
#[test]
fn covered_entry_leaves_own_log_without_a_delete_key() {
    let mut w = W::new();
    w.g.creds.insert(S, creds(0, true, false));
    w.hold(cid(1), &[S], uncovered());
    w.hold(cid(2), &[S], uncovered());
    w.exchange();
    // the author keeps the body (not dropped by the engine), covered by snapshot 2 held in S
    w.judge(S, cid(1), covered(cid(2)));
    assert!(w.own_blobs(S, cid(1)).is_empty(), "the covered entry stays in the own log");
    assert_eq!(w.deletes(), 0, "no delete key: nothing deleted at K");
    // K's tombstone of nothing: what it holds stays until a key holder deletes it
    w.g.k.held.clear();
    w.exchange();
    assert_eq!(w.at_k(S, cid(1)), 0, "K pulled the covered body back");
}

// spec/sync-judgement.md §3 (deletes): a delete-key holder deletes a covered entry at K only once
// K's stream shows its carrier, whatever this node holds or sent (HN_known).
#[test]
fn delete_waits_for_carrier_in_known() {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    w.g.k.held.insert((S, b), cid(1));
    w.stream();
    w.hold(cid(2), &[S], uncovered());
    w.judge(S, cid(1), covered(cid(2)));
    w.settle();
    assert_eq!(w.deletes(), 0, "deleted while K's stream shows no carrier");
    let b = w.own_blobs(S, cid(2))[0];
    w.g.k.held.insert((S, b), cid(2));
    w.stream();
    w.settle();
    assert_eq!(w.deletes(), 1);
}

// spec/sync-judgement.md §3 (deletes): at a source full for S a carrier it lacks counts as held
// (HN_full).
#[test]
fn full_source_counts_a_carrier_it_lacks() {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    w.g.k.held.insert((S, b), cid(1));
    w.hold(cid(2), &[S], uncovered());
    w.judge(S, cid(1), covered(cid(2)));
    w.g.k.full = true;
    w.stream();
    w.settle();
    assert_eq!(w.deletes(), 1);
}

// spec/sync-judgement.md §3 (between readers): no Delete is sent to a source that reads S; its
// view is its own (HN_readers).
#[test]
fn no_delete_between_readers() {
    let mut w = W::new();
    w.source(S, Source::Conn(RC), RC, false);
    w.hold(cid(2), &[S], uncovered());
    w.hold(cid(1), &[S], uncovered());
    let (b1, b2) = (w.own_blobs(S, cid(1))[0], w.own_blobs(S, cid(2))[0]);
    for (c, b) in [(cid(1), b1), (cid(2), b2)] {
        w.g.put_seen((Source::Conn(RC), S, c), Seen { present: [b].into(), deleted: BTreeSet::new() });
    }
    w.judge(S, cid(1), covered(cid(2)));
    assert!(!w.g.sent.iter().any(|m| matches!(m, Sent::Delete(c, _) if *c == RC)));
    let mut f = uncovered();
    f.must_not = Some(Why::Purged);
    w.judge(S, cid(1), f);
    assert!(!w.g.sent.iter().any(|m| matches!(m, Sent::Delete(c, _) if *c == RC)));
}

/// A body must-hold here, logged and pulled by K.
fn at_k_must_hold() -> W {
    let mut w = W::new();
    w.hold(cid(1), &[S], uncovered());
    w.exchange();
    w
}

// spec/sync-judgement.md §4 (logs the body again once) (log-liar): a peer deleting at K what this node
// needs (a cover it hides) gets one fresh encryption per change of ground, however often it
// deletes (HN_stand).
#[test]
fn logged_again_once_per_ground() {
    let mut w = at_k_must_hold();
    for _ in 0..5 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 2, "first logging and one more");
}

// spec/sync-judgement.md §4 (head moves): once K's head moves the node logs it again once more
// (HN_standhead).
#[test]
fn head_move_allows_one_more() {
    let mut w = at_k_must_hold();
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    w.g.creds.insert(S, creds(1, true, true));
    w.edit_source(KC, |x| x.head = Some(step(1).id()));
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 3);
}

// spec/sync-judgement.md §4 (such a part falls) (again-stand): a held cover or killing write
// falling here, with no head move, allows one more logging (HN_standfall).
#[test]
fn fall_allows_one_more() {
    let mut w = at_k_must_hold();
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    w.g.marks.insert((S, cid(1)), 1);
    w.settle();
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 3);
}

// spec/sync-judgement.md §4 (judged invalid here counts as a fall): the stand compares the engine's
// fall mark, which a snapshot arriving invalid moves as one held valid falling does; nothing
// else of the body changes here (HN_fallany).
#[test]
fn stand_follows_the_fall_mark_alone() {
    let mut w = at_k_must_hold();
    w.k_delete(cid(1));
    w.exchange();
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 2);
    w.g.marks.insert((S, cid(1)), 1);
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 3);
}

// spec/sync-judgement.md §4 (fresh encryption) (deposit-storm): logged again as a fresh blob ID
// under that sync ID alone, never the deleted one and never one logged under another sync ID
// (HN_fresh).
#[test]
fn again_is_fresh_per_sync_id() {
    let mut w = W::new();
    w.hold(cid(1), &[S, S2], uncovered());
    w.exchange();
    let first: BTreeSet<BlobId> = w.g.logged.iter().map(|(_, _, b)| *b).collect();
    w.k_delete(cid(1));
    w.exchange();
    let again: Vec<(SyncId, BlobId)> = w.g.logged.iter().filter(|(_, _, b)| !first.contains(b)).map(|(s, _, b)| (*s, *b)).collect();
    assert_eq!(again.len(), 2, "one logging again per sync ID");
    assert_ne!(again[0].1, again[1].1);
    assert_eq!(w.at_k(S, cid(1)), 2, "K holds a fresh entry under each sync ID");
}

/// An own role commit (cid 7) S must hold, and a must-hold body (cid 1) K holds.
fn with_role() -> W {
    let mut w = W::new();
    let mut f = uncovered();
    f.role = true;
    w.hold(cid(7), &[S], f);
    w.hold(cid(1), &[S], uncovered());
    w
}

// spec/sync-judgement.md §3 (role entries first) (eph-seed8, eph-reverts-seeds): logging again
// and deleting toward K wait while K lacks a role commit of this node's it can take now, read
// from the own store and K's stream, never from what was sent; a full K is skipped
// (HN_rolefirst).
#[test]
fn role_entries_first() {
    let mut w = with_role();
    w.pulls = false;
    let b1 = w.own_blobs(S, cid(1))[0];
    w.g.k.held.insert((S, b1), cid(1));
    w.stream();
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 1, "logged again before K took the role commit");
    w.hold(cid(2), &[S], uncovered());
    let b2 = w.own_blobs(S, cid(2))[0];
    w.g.k.held.insert((S, b2), cid(2));
    w.stream();
    w.judge(S, cid(2), covered(cid(1)));
    assert_eq!(w.deletes(), 0, "deleted before K took the role commit");
    // a full K skips the wait
    w.g.k.full = true;
    w.stream();
    w.settle();
    assert_eq!(w.logs(S, cid(1)), 2);
    // K takes the role commit: no wait
    let mut w = with_role();
    w.exchange();
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 2);
}

// spec/sync-judgement.md §3 (role entries first): a delete toward K waits while K's stream shows
// a role commit this node does not hold (HN_delview).
#[test]
fn delete_waits_for_a_role_commit_shown() {
    let mut w = W::new();
    w.hold(cid(2), &[S], uncovered());
    w.hold(cid(1), &[S], uncovered());
    w.exchange();
    w.edit_source(KC, |x| x.role_unheld = true);
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.deletes(), 0);
    w.edit_source(KC, |x| x.role_unheld = false);
    assert_eq!(w.deletes(), 1);
}

// spec/sync-judgement.md §2 (established uncovered) (never-quiet): a later snapshot of the aspect
// this node does not hold, present under S, keeps the body from must-hold, so its author does not
// log it again for ever (HN_snap); one this node judged invalid does not count (HN_invalid).
#[test]
fn later_unheld_snapshot_blocks_uncovered() {
    let mut w = at_k_must_hold();
    w.g.k.held.insert((S, BlobId([5; 32])), cid(5));
    w.stream();
    let mut f = uncovered();
    f.later_unheld = vec![(cid(5), false)];
    w.judge(S, cid(1), f.clone());
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::May));
    for _ in 0..3 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 1);
    f.later_unheld = vec![(cid(5), true)];
    w.judge(S, cid(1), f);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
}

// spec/sync-judgement.md §4 (a part counting missing again lifts this node's own tombstones) (eph-reverts-seeds): a part
// counting missing again lifts this node's own tombstones of its entries, so it is fetched again.
#[test]
fn missing_again_lifts_own_tombstones() {
    let mut w = W::new();
    w.hold(cid(2), &[S], uncovered());
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.g.tombs.get(&(S, cid(1))).cloned(), Some(vec![b]));
    let mut f = uncovered();
    f.body.covered = None;
    f.missing = true;
    w.judge(S, cid(1), f);
    assert_eq!(w.g.tombs.get(&(S, cid(1))).cloned(), Some(vec![]));
}

// spec/sync-judgement.md §3 (Dropped bodies: a body counting as never received again is fetched
// again where present): a body dropped here (no own entry, no tombstone) that counts missing is
// fetched from each source whose stream shows an entry of it, a source joining later included,
// and logged only once it is held again. Fails without the Fetch act (nothing re-announces an
// entry a stream already applied).
#[test]
fn missing_body_is_fetched_where_present() {
    let mut w = W::new();
    w.source(S, Source::Conn(RC), RC, false);
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    w.g.own.insert((S, cid(1)), Vec::new());
    w.g.put_seen((Source::Conn(RC), S, cid(1)), Seen { present: [b].into(), deleted: BTreeSet::new() });
    let logs = w.g.logged.len();
    let mut f = uncovered();
    f.missing = true;
    w.judge(S, cid(1), f);
    assert!(w.g.sent.contains(&Sent::Fetch(RC, b)), "fetched at the reader showing it: {:?}", w.g.sent);
    assert_eq!(w.g.logged.len(), logs, "nothing logged while the body is missing");
    let rc2 = ConnId(RC.0 + 100);
    w.source(S, Source::Conn(rc2), rc2, false);
    w.g.put_seen((Source::Conn(rc2), S, cid(1)), Seen { present: [b].into(), deleted: BTreeSet::new() });
    w.settle();
    assert!(w.g.sent.contains(&Sent::Fetch(rc2, b)), "a source joining that shows it is asked too");
    w.judge(S, cid(1), uncovered());
    assert_eq!(w.g.logged.len(), logs + 1, "logged once held again");
}

// spec/sync-judgement.md §4 (the stand's state): durable (forget-lost-mem): a start (or the reload a forget
// runs) judges every held commit again: a must-hold value whose entry the restart lost is logged
// again, and a stand kept in K's record still holds (a restart is no change of ground).
#[test]
fn restart_judges_again_and_keeps_the_stand() {
    let mut w = at_k_must_hold();
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 2);
    // restart: read's state is gone, the store's rows stay
    w.read = Read::default();
    w.g.added = vec![cid(1)];
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 2, "a restart counted as a change of ground");
    // a memory-class entry lost at the restart: logged again
    w.g.own.insert((S, cid(1)), Vec::new());
    w.read = Read::default();
    w.g.added = vec![cid(1)];
    w.settle();
    assert_eq!(w.logs(S, cid(1)), 3);
}

// spec/sync-judgement.md §3 (reader that is not a writer): a must-hold body K lacks is given as a
// held entry (relayed or deposited), and K pulls nothing from a non-writer.
#[test]
fn non_writer_deposits() {
    let mut w = W::new();
    w.pulls = false;
    w.g.creds.insert(S, creds(0, false, false));
    w.hold(cid(1), &[S], uncovered());
    w.settle();
    let b = w.own_blobs(S, cid(1))[0];
    assert_eq!(w.g.sent, vec![Sent::Deposit(KC, b)]);
    w.exchange();
    assert_eq!(w.at_k(S, cid(1)), 1);
}

// spec/sync-compaction.md §1 (duplicates): of two entries of one body at K the delete-key holder
// deletes the higher blob ID.
#[test]
fn duplicate_higher_goes() {
    let mut w = at_k_must_hold();
    w.g.k.held.insert((S, BlobId([0xff; 32])), cid(1));
    w.stream();
    w.settle();
    assert_eq!(w.g.sent, vec![Sent::Delete(KC, BlobId([0xff; 32]))]);
}

/// S is a released thing's own sync ID: content `cid(1)` at K, destroying request `cid(3)`
/// logged by the releaser (another node) at K or not.
fn released(request_at_k: bool) -> W {
    let mut w = at_k_must_hold();
    w.g.doom.insert(S, Arc::new(Destruction { requests: vec![cid(3)], ..Default::default() }));
    if request_at_k {
        w.g.k.held.insert((S, BlobId([3; 32])), cid(3));
        w.g.logged.push((S, cid(3), BlobId([3; 32])));
    }
    w.stream();
    w.settle();
    w
}

// spec/sync-judgement.md §5 (told) (destroyed-label): nothing is deleted at K before the destroying
// request is held there (DN_told).
#[test]
fn nothing_emptied_before_told() {
    let mut w = released(false);
    w.exchange();
    assert_eq!(w.deletes(), 0);
    assert_eq!(w.at_k(S, cid(1)), 1);
    w.g.k.held.insert((S, BlobId([3; 32])), cid(3));
    w.g.logged.push((S, cid(3), BlobId([3; 32])));
    w.stream();
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::MustNot(Why::Emptied)));
    assert!(w.own_blobs(S, cid(1)).is_empty());
    assert_eq!(w.deletes(), 1);
}

// spec/sync-judgement.md §5 (emptying deletes none): told, it deletes every other
// entry at K and keeps the request there until its expiry (DN_req).
#[test]
fn emptying_keeps_the_requests() {
    let mut w = released(true);
    w.exchange();
    assert!(w.g.k.held.contains_key(&(S, BlobId([3; 32]))));
    assert_eq!(w.at_k(S, cid(1)), 0);
}

// spec/sync-judgement.md §5 (it forgets the sync IDs once its sources): told and emptied, it forgets S
// only once its sources are heard out with no entry and no tombstone known there: not while the
// request lives at K (DN_forget).
#[test]
fn forget_waits_for_nothing_known() {
    let mut w = released(true);
    w.g.heard.insert(S, true);
    w.exchange();
    assert!(!w.g.sent.contains(&Sent::Forget(S)), "forgot while the request is at K");
    // the request expires at K (no tombstone)
    w.g.k.held.clear();
    w.stream();
    w.settle();
    assert!(!w.g.sent.contains(&Sent::Forget(S)), "forgot while its delete's tombstone lasts at K");
    w.expire_tombstones();
    assert!(w.g.sent.contains(&Sent::Forget(S)));
}

// spec/sync-judgement.md §5 (untold) (released-team): a node away for the whole window leaves S
// deleting nothing, once the window ends (no other event needed); while it does not know of the destruction a delete at K costs it one logging
// again, not a loop (DN_stand).
#[test]
fn untold_leaves_and_logs_again_once() {
    let mut w = at_k_must_hold();
    for _ in 0..4 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 2);
    let mut m = meta();
    m.expires = Some(WallMs(10));
    w.g.bodies.insert(cid(3), Arc::new([(S, m)].into()));
    // a request is held like any commit: read follows its bodies
    w.g.added.push(cid(3));
    w.g.doom.insert(S, Arc::new(Destruction { requests: vec![cid(3)], ..Default::default() }));
    w.settle();
    assert!(!w.g.sent.contains(&Sent::Forget(S)));
    // the window's end alone moves it: read's wake is the request's expiry
    assert_eq!(w.read.next_wake(), Some(WallMs(10)));
    w.g.now = 11;
    w.settle();
    assert!(w.g.sent.contains(&Sent::Forget(S)));
    assert_eq!(w.deletes(), 0);
}

// spec/sync-judgement.md §3 (driven by events): work follows change: a fact of one body, or K's
// stream showing one entry, judges that body alone, at n and 10n bodies.
#[test]
fn work_follows_change() {
    let mut costs = Vec::new();
    for n in [20u8, 200] {
        let mut w = W::new();
        for i in 0..n {
            w.g.facts.insert((S, CommitId([i, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])), uncovered());
        }
        for i in 0..n {
            let c = CommitId([i, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            w.g.bodies.insert(c, Arc::new([(S, meta())].into()));
            w.g.added.push(c);
        }
        w.exchange();
        let c = CommitId([3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        osis_base::costs::take();
        w.judge(S, c, covered(cid(250)));
        w.k_delete(c);
        let judged: u64 = osis_base::costs::take().iter().filter(|(k, _, _)| *k == "read: judged").map(|(_, _, n)| n).sum();
        costs.push(judged);
    }
    assert_eq!(costs[0], costs[1], "judgements per change grow with the bodies held");
    assert!(costs[0] <= 4, "{costs:?}");
}

// spec/sync-judgement.md §2 (header-only blob): a certificate is must-hold whatever snapshot
// covers it: it neither leaves the own log nor is deleted at K as covered.
#[test]
fn must_hold_certificate_is_never_covered_and_dropped() {
    let mut w = W::new();
    w.hold(cid(2), &[S], uncovered());
    let mut f = covered(cid(2));
    f.body.closure = false;
    w.hold(cid(1), &[S], f);
    w.exchange();
    w.exchange();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
    assert_eq!(w.own_blobs(S, cid(1)).len(), 1);
    assert_eq!(w.deletes(), 0);
    assert_eq!(w.logs(S, cid(1)), 1, "logged and dropped in a loop");
}

// spec/sync-judgement.md §3 (deletes): a body dropped as invalid is never deleted at a peer,
// whatever covers it (spec/permissions.md §6).
#[test]
fn invalid_body_is_never_deleted_at_k() {
    let mut w = at_k_must_hold();
    w.hold(cid(2), &[S], uncovered());
    w.exchange();
    let mut f = covered(cid(2));
    f.body.dropped = Some(osis_engine::engine::DropFor::Invalid);
    w.judge(S, cid(1), f);
    w.exchange();
    assert_eq!(w.deletes(), 0);
    assert_eq!(w.at_k(S, cid(1)), 1);
}

// spec/sync-judgement.md §3 (own store): a must-hold body with no own entry is logged as a held
// blob verbatim where one is (not fresh); logging again (§4) is always a fresh encryption.
#[test]
fn first_logging_is_verbatim_again_is_fresh() {
    let mut w = at_k_must_hold();
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.g.fresh, vec![false, true]);
}

// spec/sync-judgement.md §3 (own store): a node logs what S must hold only while a reader can
// pull it from here; once one can, it logs it.
#[test]
fn logs_only_while_a_reader_can_pull() {
    let mut w = W::new();
    w.g.unpullable.insert(S, ());
    w.hold(cid(1), &[S], uncovered());
    assert_eq!(w.logs(S, cid(1)), 0);
    w.g.unpullable.remove(&S);
    w.settle();
    assert_eq!(w.logs(S, cid(1)), 1);
}

// spec/permissions.md §4 (Logging certificates: the records missing go as one record blob of the
// logging node's, while held in its own store), spec/sync-judgement.md §3 (own store: logged only while a reader can
// pull it): a sync ID's missing records are logged once as one record blob once a reader can pull
// S, again only for what goes missing later; a sealed record blob's row whose own entry went is
// forgotten.
#[test]
fn missing_records_are_logged_once_a_reader_can_pull() {
    let mut w = W::new();
    let (r1, r2) = (osis_base::Tid::from_bytes([1; 15]), osis_base::Tid::from_bytes([2; 15]));
    w.g.unpullable.insert(S, ());
    w.g.records.insert(S, RecordsMissing { records: [r1].into(), gone: BTreeSet::new() });
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.record_logs.is_empty(), "no reader can pull S yet");
    w.g.unpullable.remove(&S);
    w.settle();
    assert_eq!(w.g.record_logs, vec![(S, [r1].into())]);
    w.settle();
    assert_eq!(w.g.record_logs.len(), 1, "once");
    w.g.records.insert(S, RecordsMissing { records: [r2].into(), gone: [BlobId([9; 32])].into() });
    w.settle();
    assert_eq!(w.g.record_logs, vec![(S, [r1].into()), (S, [r2].into())]);
    assert_eq!(w.g.records_forgotten, vec![(S, BlobId([9; 32]))]);
}

// spec/sync-judgement.md §2 (outside the required set): while a group of the closure holds part
// of its `group.0` only as a header, a body outside the closure is not judged, so nothing of it
// is deleted at K; nor is anything judged under a sync ID this node does not read.
#[test]
fn nothing_judged_outside_an_unsettled_closure_or_an_unread_sync_id() {
    let mut w = at_k_must_hold();
    w.g.unsettled.insert(S, ());
    w.g.bodies.insert(cid(1), Arc::new(BTreeMap::new()));
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Unjudged));
    w.exchange();
    assert_eq!(w.deletes(), 0);
    w.g.unsettled.remove(&S);
    w.exchange();
    assert_eq!(w.deletes(), 1, "retag: outside the required set, deleted under the old sync ID");
    // under a sync ID it does not read, nothing is judged
    let mut w = at_k_must_hold();
    w.g.unread.insert(S, ());
    w.g.bodies.insert(cid(1), Arc::new(BTreeMap::new()));
    w.exchange();
    assert_eq!(w.deletes(), 0, "deleted under a sync ID it left");
}

// spec/sync-compaction.md §1 (duplicates): only entries of one commit with the same delta set are
// duplicates, and one whose bytes are not held is none; where S's body is a per-sync-ID copy a
// shared blob beside the copy goes whatever its ID.
#[test]
fn duplicates_by_delta_set_and_copy() {
    let mut w = at_k_must_hold();
    let (lo, hi) = (BlobId([0; 32]), BlobId([0xff; 32]));
    w.g.blobs.insert(hi, Some(BlobInfo { parts: [0, 1].into(), copy: false }));
    w.g.k.held.insert((S, hi), cid(1));
    w.stream();
    w.settle();
    assert_eq!(w.deletes(), 0, "a blob of other parts deleted as a duplicate");
    w.g.blobs.insert(hi, None);
    w.settle();
    assert_eq!(w.deletes(), 0, "an entry without bytes deleted as a duplicate");
    // S's body is a copy: the shared blob (lower ID) goes beside it
    let mut m = meta();
    m.copy = true;
    w.g.bodies.insert(cid(1), Arc::new([(S, m)].into()));
    w.g.blobs.insert(hi, Some(BlobInfo { parts: [0].into(), copy: true }));
    w.g.k.held.insert((S, lo), cid(1));
    w.stream();
    w.settle();
    let shared: Vec<BlobId> = w.g.k.held.keys().filter(|(_, b)| *b != hi && *b != lo).map(|(_, b)| *b).collect();
    let deleted: BTreeSet<BlobId> = w.g.sent.iter().filter_map(|m| if let Sent::Delete(_, b) = m { Some(*b) } else { None }).collect();
    assert!(!deleted.contains(&hi), "the copy was deleted");
    assert!(deleted.contains(&lo) && shared.iter().all(|b| deleted.contains(b)), "{deleted:?}");
}

// spec/sync-judgement.md §5 (it forgets the sync IDs once its sources): an entry at any source, one
// holding no destroying request included, keeps S; past the requests' expiry it is emptied there
// too (no reader can be told any more), then S is forgotten.
#[test]
fn forget_counts_every_source() {
    let mut w = released(true);
    let k2 = ConnId(3);
    w.source(S, Source::Conn(k2), k2, true);
    let b = w.g.logged.iter().find(|(_, c, _)| *c == cid(1)).unwrap().2;
    w.g.put_seen((Source::Conn(k2), S, cid(1)), Seen { present: [b].into(), deleted: BTreeSet::new() });
    w.g.all.insert((Source::Conn(k2), S), [b].into());
    w.g.heard.insert(S, true);
    w.exchange();
    w.g.k.held.clear();
    w.stream();
    w.expire_tombstones();
    assert!(!w.g.sent.contains(&Sent::Forget(S)), "forgot while a source shows an entry");
    assert!(!w.sent().any(|m| *m == Sent::Delete(k2, b)), "emptied a source not told");
    let mut m = meta();
    m.expires = Some(WallMs(10));
    w.g.bodies.insert(cid(3), Arc::new([(S, m)].into()));
    // a request is held like any commit: read follows its bodies
    w.g.added.push(cid(3));
    w.g.now = 11;
    w.settle();
    assert!(w.sent().any(|m| *m == Sent::Delete(k2, b)));
}

// spec/sync-judgement.md §3 (role entries first): at a start every commit is judged again, in no
// set order; a delete still waits for an own role commit K lacks, whichever is judged first.
#[test]
fn role_entries_first_at_a_start() {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(9), &[S], uncovered());
    w.hold(cid(2), &[S], uncovered());
    for c in [cid(9), cid(2)] {
        let b = w.own_blobs(S, c)[0];
        w.g.k.held.insert((S, b), c);
    }
    w.stream();
    // restart: the delete candidate (2) is judged before the role commit (7)
    let mut f = uncovered();
    f.role = true;
    w.g.facts.insert((S, cid(7)), f);
    w.g.bodies.insert(cid(7), Arc::new([(S, meta())].into()));
    w.g.facts.insert((S, cid(2)), covered(cid(9)));
    w.read = Read::default();
    w.g.added = vec![cid(2), cid(9), cid(7)];
    w.settle();
    assert_eq!(w.deletes(), 0, "deleted before K took the role commit");
}

// spec/sync-judgement.md §3 (driven by events): a source's stream event judges that body at that
// source alone, a reader source joining judges nothing, and a writer's store source joining
// judges only what its stream shows: the same work at n and 10n sources.
#[test]
fn work_follows_sources() {
    let mut costs = Vec::new();
    for n in [3u32, 30] {
        let mut w = W::new();
        for i in 0..n {
            let c = ConnId(100 + u64::from(i));
            w.source(S, Source::Conn(c), c, i % 2 == 0);
        }
        for i in 0..20 {
            w.hold(cid(i), &[S], uncovered());
        }
        w.exchange();
        osis_base::costs::take();
        w.k_delete(cid(3));
        let c = ConnId(99);
        w.source(S, Source::Conn(c), c, false);
        w.settle();
        let c = ConnId(98);
        w.source(S, Source::Conn(c), c, true);
        w.settle();
        let taken = osis_base::costs::take();
        let n = |name: &str| taken.iter().filter(|(k, _, _)| *k == name).map(|(_, _, n)| n).sum::<u64>();
        costs.push((n("read: judged"), n("read: toward")));
    }
    assert_eq!(costs[0], costs[1], "work per source event grows with the sources");
    assert!(costs[0].1 <= 4, "{costs:?}");
}

/// The judgements (`read: judged`, `read: toward` settles) node 0 and node 1 make for a write and
/// a grant on thing 0, after `n` writes on each of 3 other things node 0 made (other sync IDs),
/// each run to quiet: through the product's sync over the real engine.
fn judged_per_event(n: usize) -> (u64, u64) {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world};
    let mut w = world(0, 2);
    let mut steps = vec![New(0), Grant(0, 0, 1, Gives::Reads), New(0), New(0), New(0), Run];
    steps.extend((0..n).flat_map(|_| [Write(0, 1), Write(0, 2), Write(0, 3), Run]));
    for s in &steps {
        crate::harness::step(&mut w, s);
    }
    osis_base::costs::take();
    for s in [Write(0, 0), Run, Grant(0, 0, 1, Gives::Writes), Run] {
        crate::harness::step(&mut w, &s);
    }
    let taken = osis_base::costs::take();
    let n = |name: &str| taken.iter().filter(|(k, _, _)| *k == name).map(|(_, _, n)| n).sum::<u64>();
    (n("read: judged"), n("read: toward"))
}

// spec/sync.md §2 (work in proportion to change): over the real engine, a write and a role
// change on one thing re-judge the (sync ID, commit) pairs they moved, never every pair held: the
// same judgements after n and 10n commits under other sync IDs (the engine's values kept per key
// are brought up to date by `Engine::follow`).
#[test]
fn an_event_on_one_sync_id_judges_what_it_moved() {
    let (a, b) = (judged_per_event(2), judged_per_event(20));
    assert_eq!(a, b, "judgements per event grow with the commits under other sync IDs");
}

fn bid(i: u8) -> BlobId {
    BlobId([i; 32])
}

/// A writer holding own body `cid(1)` under S with pieces `held` and `missing`.
fn with_pieces(held: &[u8], missing: &[u8]) -> W {
    let mut w = W::new();
    let p = Pieces { held: held.iter().map(|i| bid(*i)).collect(), missing: missing.iter().map(|i| bid(*i)).collect() };
    w.g.pieces.insert((S, cid(1)), Arc::new(p));
    w.hold(cid(1), &[S], uncovered());
    w
}

fn sent_of(w: &W, f: impl Fn(&Sent) -> bool) -> usize {
    w.sent().filter(|m| f(m)).count()
}

// spec/sync-judgement.md §1 (chunk and tree-node blobs): they go under S as the same blobs;
// each held piece of a must-hold body is logged once; one tombstoned under S never again; none of
// a body that is not must-hold.
#[test]
fn pieces_of_a_must_hold_body_are_logged_once_spec_sync_judgement_1() {
    let mut w = W::new();
    w.g.piece_at.insert((S, bid(12)), PieceAt::Tombstoned);
    w.g.pieces.insert((S, cid(1)), Arc::new(Pieces { held: [bid(10), bid(11), bid(12)].into(), missing: BTreeSet::new() }));
    w.g.pieces.insert((S, cid(2)), Arc::new(Pieces { held: [bid(20)].into(), missing: BTreeSet::new() }));
    w.hold(cid(1), &[S], uncovered());
    w.hold(cid(2), &[S], covered(cid(9)));
    w.exchange();
    w.exchange();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::LogPiece(_))), 2, "{:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::LogPiece(bid(10))) && w.g.sent.contains(&Sent::LogPiece(bid(11))));
}

// spec/sync-judgement.md §1 (chunk and tree-node blobs): a missing piece a
// peer's entry here holds is taken from it; one a source shows is fetched there.
#[test]
fn a_missing_piece_is_taken_or_fetched_spec_sync_judgement_1() {
    let mut w = W::new();
    w.g.piece_at.insert((S, bid(10)), PieceAt::Peer);
    w.g.piece_seen.insert((K, S, bid(11)), (true, false));
    w.g.pieces.insert((S, cid(1)), Arc::new(Pieces { held: BTreeSet::new(), missing: [bid(10), bid(11), bid(12)].into() }));
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.sent.contains(&Sent::TakePiece(bid(10))), "{:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::Fetch(KC, bid(11))));
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::TakePiece(_) | Sent::Fetch(..))), 2, "nothing for one no source shows");
}

// spec/sync-ids.md §1 (Repair): a held piece of an own body that every source showing it deleted
// (none present) is repaired once, judged with S's sources heard out; not while one shows it
// present, nor for a body not this node's own.
#[test]
fn a_piece_every_source_deleted_is_repaired_once_spec_sync_ids_1() {
    let mut w = with_pieces(&[10], &[]);
    w.g.heard.insert(S, true);
    w.source(S, Source::Conn(RC), RC, false);
    w.g.piece_seen.insert((K, S, bid(10)), (false, true));
    w.g.piece_seen.insert((Source::Conn(RC), S, bid(10)), (true, false));
    w.settle();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Repair(..))), 0, "present at a reader source: not lost");
    w.g.piece_seen.insert((Source::Conn(RC), S, bid(10)), (false, false));
    w.g.heard.insert(S, false);
    w.settle();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Repair(..))), 0, "not before S's sources are heard out");
    w.g.heard.insert(S, true);
    w.settle();
    w.exchange();
    assert_eq!(w.g.sent.iter().filter(|m| **m == Sent::Repair(cid(1), bid(10))).count(), 1, "{:?}", w.g.sent);
    let mut other = with_pieces(&[10], &[]);
    let mut f = uncovered();
    f.own = false;
    other.judge(S, cid(1), f);
    other.g.heard.insert(S, true);
    other.g.piece_seen.insert((K, S, bid(10)), (false, true));
    other.settle();
    assert_eq!(sent_of(&other, |m| matches!(m, Sent::Repair(..))), 0, "another's body is not repaired here");
}

// spec/sync-ids.md §1 (Repair): a commit a repair wrote is never repaired: a source deleting what
// it wrote afresh is refusing it, not a purger that missed a reuse, so a store refusing each
// re-encryption makes this node write one repair per piece its other own commits link, not one
// per refusal.
#[test]
fn a_repair_commit_is_never_repaired_spec_sync_ids_1() {
    let mut w = with_pieces(&[10], &[]);
    let mut f = uncovered();
    f.repair = true;
    w.judge(S, cid(1), f);
    w.g.heard.insert(S, true);
    w.g.piece_seen.insert((K, S, bid(10)), (false, true));
    w.settle();
    w.exchange();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Repair(..))), 0, "{:?}", w.g.sent);
}

// spec/sync-compaction.md §1 (Freed links): a freed link's own entry leaves, it is deleted at each
// source keeping S unread that shows it (not at a reader source), and it leaves the set once no
// entry of it is known here.
#[test]
fn a_freed_link_is_dropped_deleted_at_stores_then_done_spec_sync_compaction_1() {
    let mut w = W::new();
    let t = Tid::from_bytes([7; 15]);
    w.source(S, Source::Conn(RC), RC, false);
    w.g.carrying.insert(t, [S].into());
    w.g.piece_at.insert((S, bid(10)), PieceAt::Own);
    w.g.piece_seen.insert((K, S, bid(10)), (true, false));
    w.g.piece_seen.insert((Source::Conn(RC), S, bid(10)), (true, false));
    w.g.freed.insert((bid(10), t), ());
    w.g.freed_feed.push((bid(10), t));
    w.settle();
    assert!(w.g.sent.contains(&Sent::DropPiece(bid(10))), "{:?}", w.g.sent);
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::DeleteFreed(..))), 1, "at K alone: {:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::DeleteFreed(KC, bid(10))));
    assert!(!w.g.sent.contains(&Sent::FreedDone(bid(10))), "K still shows it");
    w.g.piece_seen.insert((K, S, bid(10)), (false, true));
    w.settle();
    assert!(w.g.sent.contains(&Sent::FreedDone(bid(10))), "{:?}", w.g.sent);
    assert!(!w.g.freed.contains_key(&(bid(10), t)));
}

/// The bodies and judgements read settles (`read: bodies`, `read: judged`) and the engine's settles of what is published and certified
/// (`labeling::published`, `sync::certified`) node 0 makes for one more thing published under an
/// actor G of its account (a labeled thing whose first admin is G, in no group: its `sync.0` and
/// `created.0` commits go under G's sync IDs as published), after `n` such things, run to quiet.
fn judged_per_publish(n: usize) -> u64 {
    let mut w = crate::harness::history::world(0, 1);
    let account = w.node(0).account.expect("an account");
    let g = w.write(0, |e| {
        let mut m = osis_engine::Mutation::new();
        let g = e.new_thing(&mut m, account);
        e.commit(m).expect("made");
        e.give_own_secrets(&g).expect("secrets of its own");
        g
    });
    w.run();
    let publish = |w: &mut crate::harness::World| {
        w.write(0, |e| {
            let mut m = osis_engine::Mutation::new();
            let t = e.new_thing(&mut m, g);
            e.commit(m).expect("made");
            e.give_own_secrets(&t).expect("secrets of its own");
        });
        w.run();
    };
    for _ in 0..n {
        publish(&mut w);
    }
    osis_base::costs::take();
    publish(&mut w);
    assert_eq!(w.engine(0).published_under(&g).len(), n + 1, "each published under G");
    // bodies and judgements, and the engine's keys of what is published and certified that moved
    let counted = ["read: bodies", "read: judged", "published", "sync: certified things", "sync: certified inboxes", "sync: certified authored", "sync: certified pieces"];
    osis_base::costs::take().iter().filter(|(k, _, _)| counted.contains(k)).map(|(_, _, n)| n).sum()
}

// spec/sync.md §2 (Work in proportion to change), spec/sync-judgement.md §1 (Entitlement: a part
// published there): a thing coming to be published under G judges its own
// commits, not every body under G's sync IDs, and moves no other thing's publisher, inbox or
// certificates: the same counts after n and 10n such things.
#[test]
fn a_thing_published_under_an_actor_judges_what_it_moved_spec_sync_2() {
    let (a, b) = (judged_per_publish(2), judged_per_publish(20));
    assert_eq!(a, b, "judgements per publish grow with the things published before");
}
