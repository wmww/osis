//! Judgement for read sync IDs (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1) on a
//! fake ground: the engine's facts and the own store as stamped values, and one source K keeping
//! S unread that judges nothing (it pulls a writer's store, refuses a tombstoned blob ID, takes
//! Deletes; a test may delete there as a hostile writer). `Read` runs as in a node over this
//! fake ground (the product's is `read::live`); a few tests run it in a world.
//! Each negative control of core/test/tla/net/NetHold.tla has a test here that
//! fails without its rule, and each judgement scenario from the old sync's issues one.

use osis_base::memo::Stamped;
use osis_base::{BlobId, CommitId, SyncId, Time};
use osis_crypto::{RoleKey, Secret32, Signature, SigningSecret, role_key};
use osis_engine::sync_ids::HeadKeys;
use osis_engine::retention::{End, Minting, Standing};
use osis_engine::sync::{BodyFacts, BodyId, BodyMeta, Loss, ReadCredentials, Strip};
use osis_blob::{Class, Step, StepId, StepKeys};
use osis_sync::read::{BlobInfo, Facts, Ground, PieceAt, Read, CertBlobsMissing, Seen, SrcView, StepReady, Verdict, Why};
use osis_engine::sync::PieceLink;
use osis_base::Tid;
use osis_sync::inbox::Promotion;
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

/// The `i`th of a run of commits tagged `tag` (more than `cid` names).
fn cidn(i: u8, tag: u8) -> CommitId {
    let mut c = [0; 32];
    (c[0], c[1]) = (i, tag);
    CommitId(c)
}

fn key(role: RoleKey, e: u64) -> SigningSecret {
    let mut b = [role as u8 + 9; 32];
    b[..8].copy_from_slice(&e.to_le_bytes());
    role_key(role, &Secret32::from_bytes(b))
}

fn step(e: u64) -> Step {
    let vk = |r| key(r, e).verifying_key();
    Step {
        sync_id: S,
        prev: None,
        keys: StepKeys { sync: vk(RoleKey::Sync), write: vk(RoleKey::Write), delete: vk(RoleKey::Delete), deposit: vk(RoleKey::Write) },
        step_key: [e as u8; 32],
        sig: Signature([0; 64]),
    }
}

/// A stamp under step `e`'s write key, as the fake ground signs and checks it.
fn stamp_at(e: u64) -> Signature {
    Signature([e as u8 + 1; 64])
}

/// A reader's credentials at head step `e`: a writer, with the delete key when `delete`.
fn creds(e: u64, writer: bool, delete: bool) -> Arc<ReadCredentials> {
    let hk = HeadKeys { sync: None, sync_established: true, write: writer.then(|| key(RoleKey::Write, e)), delete: delete.then(|| key(RoleKey::Delete, e)), deposit: None, epochs: [None; 3] };
    let mut keys = BTreeMap::new();
    for i in 0..=e {
        keys.insert(step(i).id(), hk.clone());
    }
    Arc::new(ReadCredentials { head: Some(step(e)), keys, ..Default::default() })
}

fn meta() -> BodyMeta {
    BodyMeta { parts: [0].into(), expires: None, order: 1, copy: false, certificate: false, header_only: false, mints: BTreeSet::new() }
}

/// A body's facts and its carriers (`Ground::facts`, `Ground::carriers`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fx {
    facts: Facts,
    carriers: Vec<BTreeSet<CommitId>>,
}

impl std::ops::Deref for Fx {
    type Target = Facts;
    fn deref(&self) -> &Facts {
        &self.facts
    }
}

impl std::ops::DerefMut for Fx {
    fn deref_mut(&mut self) -> &mut Facts {
        &mut self.facts
    }
}

/// A body of this node's own, established uncovered: must-hold.
fn uncovered() -> Fx {
    let facts = Facts {
        body: BodyFacts { required: true, closure: true, dropped: None, invalid: false, kept: false, peer_delete_from: 0, covered: Some(false), lasting_header: false },
        must_not: None,
        own: true,
        repair_fresh: Arc::default(),
        role: false,
        later_unheld: Vec::new(),
        missing: false,
    };
    Fx { facts, carriers: Vec::new() }
}

/// Covered by snapshot `by`, past its keep bound: its live write needs `by` as carrier.
fn covered(by: CommitId) -> Fx {
    let mut f = uncovered();
    f.body.covered = Some(true);
    f.carriers = vec![[by].into()];
    f
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    Delete(ConnId, BlobId),
    Deposit(ConnId, BlobId),
    Fetch(ConnId, BlobId),
    Want(ConnId, CommitId),
    Take(BlobId),
    LogPiece(BlobId),
    TakePiece(BlobId),
    Repair(CommitId, BlobId),
    DropBlob(BlobId),
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
    /// Own entries of held commits added (`Ground::entries_added`).
    entries_feed: Vec<(SyncId, CommitId)>,
    /// The pass place now, and per S the place the last complete pass began at (none: every
    /// pass wanted has ended).
    place: u64,
    done: Stamped<SyncId, u64>,
    /// Entries dropped with no tombstone (`Ground::unlog`).
    unlogged: Vec<(SyncId, BlobId)>,
    bodies: Stamped<CommitId, Arc<BTreeMap<SyncId, BodyMeta>>>,
    /// Something else `Ground::bodies` reads, written without changing what it gives.
    bodies_read: Stamped<CommitId, u64>,
    facts: Stamped<(SyncId, CommitId), Fx>,
    marks: Stamped<(SyncId, CommitId), u64>,
    creds: Stamped<SyncId, Arc<ReadCredentials>>,
    own: Stamped<(SyncId, CommitId), Vec<Entry>>,
    tombs: Stamped<(SyncId, CommitId), Vec<BlobId>>,
    /// Own entries naming no commit held here (a commit forgotten with a released thing).
    orphans: Stamped<SyncId, BTreeSet<BlobId>>,
    sources: Stamped<SyncId, Arc<Vec<SrcView>>>,
    srcs: Stamped<(SyncId, Source), SrcView>,
    /// The connection each source's record is on (digests agreed), and those told full per S.
    conns: Stamped<Source, ConnId>,
    told_full: Stamped<(ConnId, SyncId), ()>,
    /// Requests sent, numbered.
    requests: osis_proto::msg::Id,
    src_feed: Vec<(SyncId, Source)>,
    seen: Stamped<(Source, SyncId, CommitId), Seen>,
    seen_feed: Vec<(Source, SyncId, CommitId)>,
    anywhere: Stamped<(SyncId, CommitId), bool>,
    /// S not read here, its closure not settled, or no reader can pull it.
    unread: Stamped<SyncId, ()>,
    /// Sync IDs whose holding moved (`unread` written through `Fake::set_reads`).
    holdings_feed: Vec<SyncId>,
    unsettled: Stamped<SyncId, ()>,
    unpullable: Stamped<SyncId, ()>,
    /// Sync IDs whose first sync here has not ended (`Ground::first_synced`).
    first_syncing: Stamped<SyncId, ()>,
    /// Bodies this node may not log under their sync ID (`Ground::may_log`).
    unloggable: Stamped<(SyncId, CommitId), ()>,
    /// Blobs held with other parts than `{0}`, as a copy, or without bytes (`None`).
    blobs: Stamped<BlobId, Option<BlobInfo>>,
    /// Blobs holding a part dropped here for good (a purge).
    gone: Stamped<BlobId, Strip>,
    /// (b, o): blob b loses as spare to blob o (`Ground::loses`).
    spare: Stamped<(BlobId, BlobId), ()>,
    /// Blobs carrying a part counting missing here (`Ground::gives_missing`).
    gives: Stamped<BlobId, ()>,
    /// Whether each logging was a fresh encryption.
    fresh: Vec<bool>,
    all: Stamped<(Source, SyncId), BTreeSet<BlobId>>,
    stands: Stamped<(Source, SyncId, CommitId), Stand>,
    heard: Stamped<SyncId, bool>,
    next: u32,
    sent: Vec<Sent>,
    logged: Vec<(SyncId, CommitId, BlobId)>,
    /// Each held commit's `ts` (`Ground::ts`; none: unknown).
    made: BTreeMap<CommitId, osis_base::Ts>,
    /// Entries stamped in place.
    restamped: Vec<(SyncId, CommitId, BlobId)>,
    /// Peers' deposits not promoted (`Ground::promotion`; every other one is).
    promotions: Stamped<BlobId, Promotion>,
    /// Per (S, kind), the records or a rotation's lists it carries that no own certificate blob
    /// does, and own certificate blobs gone.
    records: Stamped<SyncId, CertBlobsMissing>,
    /// Per S, the records it carries as certificates (`Ground::certificate_records`).
    carried: Stamped<SyncId, Arc<BTreeSet<osis_base::Tid>>>,
    /// Certificate blobs logged, and rows of gone ones forgotten.
    record_logs: CertLogs,
    records_forgotten: Vec<(SyncId, BlobId)>,
    k: Kstore,
    /// Roots per body, what lies below each held piece, what the own store has of each, what
    /// each source shows of each.
    roots: Stamped<CommitId, Arc<Vec<PieceLink>>>,
    below: Stamped<PieceLink, Arc<Vec<PieceLink>>>,
    piece_at: Stamped<(SyncId, BlobId), PieceAt>,
    piece_seen: Stamped<(Source, SyncId, BlobId), (bool, bool)>,
    /// Freed links in the set (and a feed of those added), the sync IDs carrying each thing.
    freed: Stamped<(BlobId, Tid), ()>,
    freed_feed: Vec<(BlobId, Tid)>,
    carrying: Stamped<Tid, BTreeSet<SyncId>>,
    /// Each thing's held mintings.
    mintings: Stamped<Tid, Arc<Vec<Minting>>>,
    /// Commits the engine would forget once no entry of them is known, and those forgotten.
    forgettable: Stamped<CommitId, ()>,
    forgotten: Vec<CommitId>,
    /// Per commit, sync IDs holding an entry or tombstone of a blob of it (`known_under`).
    known: Stamped<CommitId, BTreeSet<SyncId>>,
    /// Per S, whether its step may be issued (`step_ready`), and the steps issued.
    step: Stamped<SyncId, StepReady>,
    issued: Vec<SyncId>,
}

impl Ground for Fake {
    fn mintings(&mut self, t: &Tid) -> Arc<Vec<Minting>> {
        self.mintings.get(t).cloned().unwrap_or_default()
    }
    fn piece_roots(&mut self, c: &CommitId, _parts: &osis_engine::sync::PartSet) -> Result<Arc<Vec<PieceLink>>> {
        Ok(self.roots.get(c).cloned().unwrap_or_default())
    }
    fn piece_below(&mut self, p: &PieceLink) -> Result<Option<Arc<Vec<PieceLink>>>> {
        Ok(self.below.get(p).cloned())
    }
    fn piece(&mut self, s: &SyncId, b: &BlobId) -> Result<PieceAt> {
        Ok(self.piece_at.get(&(*s, *b)).copied().unwrap_or(PieceAt::Absent))
    }
    fn blob_shown(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> bool {
        self.piece_seen.get(&(*at, *s, *b)).is_some_and(|x| x.0)
    }
    fn blob_deleted(&mut self, at: &Source, s: &SyncId, b: &BlobId) -> Result<bool> {
        Ok(self.piece_seen.get(&(*at, *s, *b)).is_some_and(|x| x.1))
    }
    fn log_piece(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.sent.push(Sent::LogPiece(*b));
        self.piece_at.insert((*s, *b), PieceAt::Own);
        Ok(())
    }
    fn take(&mut self, _s: &SyncId, b: &BlobId) -> Result<()> {
        self.sent.push(Sent::Take(*b));
        Ok(())
    }
    fn stands(&mut self, s: &SyncId, _c: &BodyId, e: &Entry) -> Result<bool> {
        Ok(self.head_stamp(s).is_none_or(|h| e.stamp == Some(h)))
    }
    fn promotion(&mut self, _s: &SyncId, _c: &BodyId, b: &BlobId) -> Result<Promotion> {
        Ok(self.promotions.get(b).copied().unwrap_or(Promotion::Yes))
    }
    fn restamp(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        let Some(h) = self.head_stamp(s) else { return Ok(()) };
        let keys: Vec<(SyncId, CommitId)> = self.own.keys().filter(|(x, _)| x == s).copied().collect();
        for k in keys {
            let mut v = self.own.get(&k).cloned().unwrap_or_default();
            if let Some(e) = v.iter_mut().find(|e| e.blob == *b) {
                *e = Entry { stamp: Some(h), deposited: false, own: true, ..e.clone() };
                self.own.insert(k, v);
                self.restamped.push((k.0, k.1, *b));
            }
        }
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
    fn freed_added(&mut self) -> Vec<(BlobId, Tid)> {
        std::mem::take(&mut self.freed_feed)
    }
    fn freed_link(&mut self, b: &BlobId, t: &Tid) -> bool {
        self.freed.contains_key(&(*b, *t))
    }
    fn carrying(&mut self, t: &Tid) -> Result<BTreeSet<SyncId>> {
        Ok(self.carrying.get(t).cloned().unwrap_or_default())
    }
    fn drop_blob(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.sent.push(Sent::DropBlob(*b));
        self.piece_at.insert((*s, *b), PieceAt::Tombstoned);
        if let Some(mut o) = self.orphans.get(s).cloned().filter(|o| o.contains(b)) {
            o.remove(b);
            self.orphans.insert(*s, o);
        }
        let keys: Vec<(SyncId, CommitId)> = self.own.keys().filter(|(x, _)| x == s).copied().collect();
        for k in keys {
            if let Some(v) = self.own.get(&k).filter(|v| v.iter().any(|e| e.blob == *b)) {
                let v: Vec<Entry> = v.iter().filter(|e| e.blob != *b).cloned().collect();
                self.own.insert(k, v);
            }
        }
        Ok(())
    }
    fn delete_freed(&mut self, conn: ConnId, _s: &SyncId, _head: &osis_blob::StepId, b: &BlobId, _t: &Tid) -> Result<Option<osis_proto::msg::Id>> {
        self.sent.push(Sent::DeleteFreed(conn, *b));
        self.requests += 1;
        Ok(Some(self.requests))
    }
    fn freed_done(&mut self, b: &BlobId, t: &Tid) -> Result<()> {
        self.sent.push(Sent::FreedDone(*b));
        self.freed.remove(&(*b, *t));
        Ok(())
    }
    fn commits_added(&mut self) -> Vec<CommitId> {
        std::mem::take(&mut self.added)
    }
    fn forgettable(&mut self, c: &CommitId) -> Result<Option<bool>> {
        Ok(self.bodies.contains_key(c).then(|| self.forgettable.contains_key(c)))
    }
    fn known_under(&mut self, c: &CommitId, _at: &BTreeSet<SyncId>) -> Result<BTreeSet<(SyncId, BodyId)>> {
        Ok(self.known.get(c).into_iter().flatten().map(|s| (*s, BodyId::unit(*c))).collect())
    }
    fn forget_commits(&mut self, cs: &[CommitId]) -> Result<()> {
        for c in cs {
            self.forgotten.push(*c);
            self.forgettable.remove(c);
            self.bodies.remove(c);
        }
        Ok(())
    }
    fn place(&mut self) -> u64 {
        self.place
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> bool {
        self.done.get(s).is_none_or(|d| *d > since)
    }
    fn unlog(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.unlogged.push((*s, *b));
        let keys: Vec<(SyncId, CommitId)> = self.own.keys().filter(|(x, _)| x == s).copied().collect();
        for k in keys {
            if let Some(v) = self.own.get(&k).filter(|v| v.iter().any(|e| e.blob == *b)) {
                let v: Vec<Entry> = v.iter().filter(|e| e.blob != *b).cloned().collect();
                self.own.insert(k, v);
            }
        }
        Ok(())
    }
    fn entries_added(&mut self) -> Result<Vec<(SyncId, BodyId)>> {
        Ok(std::mem::take(&mut self.entries_feed).into_iter().map(|(s, c)| (s, BodyId::unit(c))).collect())
    }
    fn bodies(&mut self, c: &CommitId) -> Result<Arc<osis_engine::sync::Bodies>> {
        let _ = self.bodies_read.get(c);
        Ok(Arc::new(self.bodies.get(c).into_iter().flat_map(|m| m.iter()).map(|(s, m)| ((*s, None), m.clone())).collect()))
    }
    fn facts(&mut self, s: &SyncId, c: &BodyId) -> Result<Facts> {
        let c = &c.commit;
        Ok(self.facts.get(&(*s, *c)).cloned().unwrap_or_else(uncovered).facts)
    }
    fn carriers(&mut self, s: &SyncId, c: &BodyId) -> Result<Vec<BTreeSet<CommitId>>> {
        let c = &c.commit;
        Ok(self.facts.get(&(*s, *c)).map(|f| f.carriers.clone()).unwrap_or_default())
    }
    fn fall_mark(&mut self, s: &SyncId, c: &BodyId) -> u64 {
        let c = &c.commit;
        self.marks.get(&(*s, *c)).copied().unwrap_or(0)
    }
    fn credentials(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        Ok(self.creds.get(s).cloned())
    }
    fn reads(&mut self, s: &SyncId) -> bool {
        !self.unread.contains_key(s)
    }
    fn holdings_moved(&mut self) -> Vec<SyncId> {
        std::mem::take(&mut self.holdings_feed)
    }
    fn unit_settled(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unsettled.contains_key(s))
    }
    fn first_synced(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.first_syncing.contains_key(s))
    }
    fn pullable(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unpullable.contains_key(s))
    }
    fn may_log(&mut self, s: &SyncId, c: &BodyId) -> Result<bool> {
        let c = &c.commit;
        Ok(!self.unloggable.contains_key(&(*s, *c)))
    }
    fn certificate_records(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<osis_base::Tid>>> {
        Ok(self.carried.get(s).cloned().unwrap_or_default())
    }
    fn cert_blobs_missing(&mut self, s: &SyncId) -> Result<CertBlobsMissing> {
        Ok(self.records.get(s).cloned().unwrap_or_default())
    }
    fn forget_cert_blobs(&mut self, s: &SyncId, gone: &BTreeSet<BlobId>) -> Result<()> {
        self.records_forgotten.extend(gone.iter().map(|b| (*s, *b)));
        let mut x = self.records.get(s).cloned().unwrap_or_default();
        x.gone.clear();
        self.records.insert(*s, x);
        Ok(())
    }
    fn log_cert_blob(&mut self, s: &SyncId, tids: &BTreeSet<osis_base::Tid>) -> Result<()> {
        self.record_logs.push((*s, tids.clone()));
        let mut x = self.records.get(s).cloned().unwrap_or_default();
        x.missing.retain(|t| !tids.contains(t));
        self.records.insert(*s, x);
        Ok(())
    }
    fn now(&self) -> Time {
        Time(self.now)
    }
    fn blob(&mut self, b: &BlobId) -> Result<Option<BlobInfo>> {
        Ok(self.blobs.get(b).cloned().unwrap_or(Some(BlobInfo { parts: [0].into(), sealed: Default::default(), copy: false })))
    }
    fn gone(&mut self, b: &BlobId) -> Option<Strip> {
        self.gone.get(b).cloned()
    }
    // every entry of a commit carries its whole body here: none loses to another but as `spare`
    // says (the engine's own judgement: core/engine/src/sync/tests_facts.rs)
    fn loses(&mut self, _s: &SyncId, b: &BlobId, o: &BlobId, _stands: (bool, bool)) -> Result<Option<Loss>> {
        Ok(self.spare.get(&(*b, *o)).map(|_| Loss::Spare))
    }
    fn gives_missing(&mut self, b: &BlobId) -> bool {
        self.gives.get(b).is_some()
    }
    fn neither(&mut self, _s: &SyncId, _c: &BodyId, there: &BTreeSet<BlobId>) -> Result<bool> {
        Ok(!there.is_empty())
    }
    fn own(&mut self, s: &SyncId, c: &BodyId) -> Result<Vec<Entry>> {
        let c = &c.commit;
        Ok(self.own.get(&(*s, *c)).cloned().unwrap_or_default())
    }
    fn own_tombstones(&mut self, s: &SyncId, c: &BodyId) -> Result<Vec<BlobId>> {
        let c = &c.commit;
        Ok(self.tombs.get(&(*s, *c)).cloned().unwrap_or_default())
    }
    fn sources(&mut self, s: &SyncId) -> Arc<Vec<SrcView>> {
        self.sources.get(s).cloned().unwrap_or_default()
    }
    fn source(&mut self, s: &SyncId, at: &Source) -> Option<SrcView> {
        self.srcs.get(&(*s, *at)).cloned()
    }
    fn connected(&mut self, at: &Source) -> Option<ConnId> {
        self.conns.get(at).copied()
    }
    fn told_full(&mut self, conn: ConnId, s: &SyncId) -> bool {
        self.told_full.contains_key(&(conn, *s))
    }
    fn holds(&mut self, c: &CommitId) -> bool {
        self.bodies.get(c).is_some()
    }
    fn kept_at(&mut self, s: &SyncId, at: &Source) -> bool {
        self.srcs.get(&(*s, *at)).is_some_and(|v| v.store)
    }
    fn head_at(&mut self, s: &SyncId, at: &Source) -> Option<StepId> {
        self.srcs.get(&(*s, *at)).and_then(|v| v.head)
    }
    fn shown_at(&mut self, s: &SyncId, c: &BodyId) -> Result<BTreeSet<Source>> {
        let c = &c.commit;
        Ok(self.seen.iter().filter(|((_, x, y), v)| x == s && y == c && !v.present.is_empty()).map(|((at, ..), _)| *at).collect())
    }
    fn sources_added(&mut self) -> Vec<(SyncId, Source)> {
        std::mem::take(&mut self.src_feed)
    }
    fn seen(&mut self, at: &Source, s: &SyncId, c: &BodyId) -> Result<Seen> {
        let c = &c.commit;
        Ok(self.seen.get(&(*at, *s, *c)).cloned().unwrap_or_default())
    }
    fn seen_added(&mut self) -> Result<Vec<(Source, SyncId, BodyId)>> {
        Ok(std::mem::take(&mut self.seen_feed).into_iter().map(|(at, s, c)| (at, s, BodyId::unit(c))).collect())
    }
    fn present_anywhere(&mut self, s: &SyncId, c: &BodyId) -> Result<bool> {
        let c = &c.commit;
        Ok(self.anywhere.get(&(*s, *c)).copied().unwrap_or(false))
    }
    fn heard_out(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.heard.get(s).copied().unwrap_or(false))
    }
    fn step_ready(&mut self, s: &SyncId) -> Result<StepReady> {
        Ok(self.step.get(s).copied().unwrap_or_default())
    }
    fn issue_step(&mut self, s: &SyncId) -> Result<bool> {
        self.issued.push(*s);
        self.step.remove(s);
        Ok(true)
    }
    fn stand(&mut self, at: &Source, s: &SyncId, c: &BodyId) -> Result<Option<Stand>> {
        let c = &c.commit;
        Ok(self.stands.get(&(*at, *s, *c)).cloned())
    }
    fn ts(&mut self, c: &CommitId) -> Option<osis_base::Ts> {
        self.made.get(c).copied()
    }
    fn log_own(&mut self, s: &SyncId, c: &BodyId, fresh: bool, _skip: &[BlobId]) -> Result<Option<BlobId>> {
        let c = &c.commit;
        self.fresh.push(fresh);
        self.next += 1;
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&self.next.to_be_bytes());
        b[4] = c.0[0];
        let blob = BlobId(b);
        let mut v = self.own(s, &osis_engine::sync::BodyId::unit(*c))?;
        let stamp = self.head_stamp(s);
        v.push(Entry { blob, wrap: [0; osis_crypto::WRAP_LEN], stamp, deposited: stamp.is_none(), own: true, role: false, class: Class::Durable, expires: None });
        self.own.insert((*s, *c), v);
        self.logged.push((*s, *c, blob));
        Ok(Some(blob))
    }
    fn drop_own(&mut self, s: &SyncId, b: &BlobId, c: &BodyId) -> Result<()> {
        let c = &c.commit;
        let v: Vec<Entry> = self.own(s, &osis_engine::sync::BodyId::unit(*c))?.into_iter().filter(|e| e.blob != *b).collect();
        self.own.insert((*s, *c), v);
        let mut t = self.own_tombstones(s, &osis_engine::sync::BodyId::unit(*c))?;
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
    fn fetch(&mut self, conn: ConnId, s: &SyncId, b: &BlobId) -> Result<()> {
        let _ = s;
        self.sent.push(Sent::Fetch(conn, *b));
        Ok(())
    }
    fn want(&mut self, conn: ConnId, s: &SyncId, c: &CommitId) -> Result<()> {
        let _ = s;
        self.sent.push(Sent::Want(conn, *c));
        Ok(())
    }
    /// By the head's delete key alone (levels: the World tests, `deletes::`).
    fn delete_item(&mut self, s: &SyncId, head: &osis_blob::StepId, b: &BlobId) -> Result<Option<osis_blob::DeleteItem>> {
        Ok(self.creds.get(s).and_then(|c| c.keys.get(head)?.delete.as_ref().map(|d| osis_blob::DeleteItem::sign(d, s, *b))))
    }
    fn delete(&mut self, conn: ConnId, s: &SyncId, head: &osis_blob::StepId, b: &BlobId) -> Result<Option<osis_proto::msg::Id>> {
        if self.delete_item(s, head, b)?.is_none() {
            return Ok(None);
        }
        self.sent.push(Sent::Delete(conn, *b));
        self.requests += 1;
        Ok(Some(self.requests))
    }
    fn deposit(&mut self, conn: ConnId, s: &SyncId, c: &BodyId, head: &StepId, b: &BlobId) -> Result<bool> {
        // stamped under the source's head (this node's): pulled as it is
        let ours = self.creds.get(s).and_then(|x| x.head.as_ref()).map(|h| h.id());
        let stamp = self.own.get(&(*s, c.commit)).and_then(|v| v.iter().find(|e| e.blob == *b)).and_then(|e| e.stamp);
        if ours == Some(*head) && stamp.is_some() && stamp == self.head_stamp(s) {
            return Ok(false);
        }
        self.sent.push(Sent::Deposit(conn, *b));
        Ok(false)
    }
    fn set_stand(&mut self, at: &Source, s: &SyncId, c: &BodyId, stand: &Stand) -> Result<()> {
        let c = &c.commit;
        self.stands.insert((*at, *s, *c), stand.clone());
        Ok(())
    }
}

impl Fake {
    /// The stamp this node signs under S's head write key, where it holds it: step `e`'s is
    /// `stamp_at(e)`.
    fn head_stamp(&self, s: &SyncId) -> Option<Signature> {
        let c = self.creds.get(s)?;
        let head = c.head.as_ref()?;
        c.keys.get(&head.id())?.write.as_ref()?;
        Some(stamp_at(head.step_key[0] as u64))
    }

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

    /// Whether this node holds S read (`Store::holding`): the holdings feed follows it.
    fn set_reads(&mut self, s: SyncId, reads: bool) {
        match reads {
            true => self.unread.remove(&s),
            false => self.unread.insert(s, ()),
        };
        self.holdings_feed.push(s);
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
        let mut v = (*self.g.sources(&s)).clone();
        v.retain(|x| x.at != at);
        v.push(SrcView { at, store, head: Some(step(0).id()), role_unheld: false });
        self.g.set_sources(s, v);
        self.g.conns.insert(at, conn);
    }

    fn edit_source(&mut self, at: Source, f: impl Fn(&mut SrcView)) {
        for s in [S, S2] {
            let mut v = (*self.g.sources(&s)).clone();
            v.iter_mut().filter(|x| x.at == at).for_each(&f);
            self.g.set_sources(s, v);
        }
        self.settle();
    }

    /// The engine holds `c` with a body under each of `ids`, judged `f`.
    fn hold(&mut self, c: CommitId, ids: &[SyncId], f: Fx) {
        for s in ids {
            self.g.facts.insert((*s, c), f.clone());
        }
        self.g.bodies.insert(c, Arc::new(ids.iter().map(|s| (*s, meta())).collect()));
        self.g.added.push(c);
        self.settle();
    }

    fn judge(&mut self, s: SyncId, c: CommitId, f: Fx) {
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
            self.g.all.insert((K, s), all);
        }
        let full = self.g.k.full;
        for s in [S, S2] {
            if self.g.told_full.contains_key(&(KC, s)) != full {
                match full {
                    true => self.g.told_full.insert((KC, s), ()),
                    false => self.g.told_full.remove(&(KC, s)),
                };
            }
        }
    }

    fn at_k(&self, s: SyncId, c: CommitId) -> usize {
        self.g.k.held.values().filter(|x| **x == c).count() * usize::from(self.g.k.held.keys().any(|(x, _)| *x == s))
    }

    fn own_blobs(&mut self, s: SyncId, c: CommitId) -> Vec<BlobId> {
        self.g.own(&s, &osis_engine::sync::BodyId::unit(c)).unwrap().into_iter().map(|e| e.blob).collect()
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

// spec/sync-judgement.md §3 (own store: what is logged together goes in `ts` order): two own
// commits held at once, the one made
// later with the smaller commit ID, are logged in the order made under each sync ID.
#[test]
fn what_is_logged_together_goes_in_the_order_made_spec_sync_judgement_3() {
    let mut w = W::new();
    for (c, ts) in [(cid(2), 1u64 << 16), (cid(1), 2 << 16)] {
        for s in [S, S2] {
            w.g.facts.insert((s, c), uncovered());
        }
        w.g.bodies.insert(c, Arc::new([(S, meta()), (S2, meta())].into()));
        w.g.added.push(c);
        w.g.made.insert(c, osis_base::Ts::from_u64(ts).unwrap());
    }
    w.settle();
    for s in [S, S2] {
        let order: Vec<CommitId> = w.g.logged.iter().filter(|(x, ..)| *x == s).map(|(_, c, _)| *c).collect();
        assert_eq!(order, [cid(2), cid(1)], "logged under {s:?} in the order made");
    }
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

// spec/sync-judgement.md §2 (Per blob; the rewrite): an own
// entry whose blob holds a part purged here leaves the own store while the body stays
// must-hold, and the rest of the body is logged again as a fresh encryption without it.
#[test]
fn entry_holding_a_purged_part_leaves_spec_sync_judgement_2() {
    let mut w = W::new();
    w.hold(cid(1), &[S], uncovered());
    w.exchange();
    let old = w.own_blobs(S, cid(1));
    assert_eq!(old.len(), 1);
    w.g.gone.insert(old[0], Strip { live: Default::default(), covers: Vec::new(), from: 0 });
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must), "the body S needs now stays must-hold");
    let now = w.own_blobs(S, cid(1));
    assert!(!now.contains(&old[0]), "the entry holding the purged part left");
    assert_eq!(now.len(), 1, "the rest of the body logged again");
}

// spec/sync-judgement.md §2 (Per blob, a strip; spec/sync-compaction.md §1 Carriers): an entry
// stripping here is deleted at K only once each part of it held here has another entry there not
// stripped carrying it, each part it strips as covered has a snapshot reaching it there, and
// `MAX_DRIFT` passed its keep bound. Each step lacks one of the three.
#[test]
fn a_strip_deletes_at_k_once_k_carries_the_rest_spec_sync_judgement_2() {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(1), &[S], uncovered());
    let (b, carrier, other, cover) = (BlobId([31; 32]), BlobId([32; 32]), BlobId([33; 32]), BlobId([34; 32]));
    w.g.blobs.insert(b, Some(BlobInfo { parts: [0, 1].into(), sealed: Default::default(), copy: false }));
    w.g.blobs.insert(other, Some(BlobInfo { parts: [2].into(), sealed: Default::default(), copy: false }));
    w.g.gone.insert(b, Strip { live: [0].into(), covers: vec![[cid(9)].into()], from: 5_000 });
    let k = |w: &mut W, at: &[(BlobId, CommitId)]| {
        w.g.k.held = at.iter().map(|(x, c)| ((S, *x), *c)).collect();
        w.stream();
        w.settle();
        w.deletes()
    };
    assert_eq!(k(&mut w, &[(b, cid(1)), (carrier, cid(1)), (cover, cid(9))]), 0, "deleted before its keep bound's drift passed");
    w.g.now = 5_000;
    assert_eq!(k(&mut w, &[(b, cid(1)), (other, cid(1)), (cover, cid(9))]), 0, "deleted with no entry there carrying its live part");
    assert_eq!(k(&mut w, &[(b, cid(1)), (carrier, cid(1))]), 0, "deleted with no snapshot there covering its stripped part");
    assert_eq!(k(&mut w, &[(b, cid(1)), (carrier, cid(1)), (cover, cid(9))]), 1);
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

// spec/commits.md §5 (unread delete margin): a body covered and dropped is deleted at K only `MAX_DRIFT`
// past its keep-at-least bound, on this node's clock; the own log drops it at once.
#[test]
fn covered_delete_waits_max_drift_spec_commits_5() {
    let (mut w, _) = two_shown();
    let mut f = covered(cid(2));
    f.body.peer_delete_from = 5_000;
    w.judge(S, cid(1), f);
    w.settle();
    assert!(w.own_blobs(S, cid(1)).is_empty(), "the own log waits for no drift");
    assert_eq!(w.deletes(), 0, "deleted at K before every node's clock agrees it left history");
    assert_eq!(w.read.next_wake(), Some(Time(5_000)), "no wake at the wait's end");
    w.g.now = 5_000;
    w.settle();
    assert_eq!(w.deletes(), 1, "not deleted once the wait ended");
}

// spec/sync-judgement.md §3 (Deletes: what is owed at a source is judged from `known` alone,
// connected or not, and sent once the source is connected): a Delete owed while K is away goes on
// K's next connection; one sent and never answered goes again on each later connection, owing
// no more as the reconnects add up; one answered is never sent again. Fails with acts keyed by
// connection (each reconnect resends what was answered) or with nothing carried to the next one.
#[test]
fn an_act_owed_goes_on_each_connection_until_answered_spec_sync_judgement_3() {
    let (mut w, b1) = two_shown();
    w.g.conns.remove(&K);
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.deletes(), 0, "sent while K is away");
    assert_eq!(w.read.owed_pending(), 1);
    let on = |w: &mut W, c: ConnId| {
        w.g.conns.insert(K, c);
        w.settle();
        w.g.sent.iter().filter(|m| **m == Sent::Delete(c, b1)).count()
    };
    for i in 0..5 {
        assert_eq!(on(&mut w, ConnId(200 + i)), 1, "not sent on K's connection {i}");
        assert_eq!(w.read.owed_pending(), 1, "what is owed grows with the reconnects");
    }
    w.read.answered(ConnId(204), w.g.requests, true);
    assert_eq!(w.read.owed_pending(), 0);
    assert_eq!(on(&mut w, ConnId(300)), 0, "a Delete taken sent again");
    assert_eq!(w.deletes(), 5);
}

/// K showing cid(1) and cid(2) under S, this node a writer holding both; K's record on `KC`.
fn two_shown() -> (W, BlobId) {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(1), &[S], uncovered());
    w.hold(cid(2), &[S], uncovered());
    let (b1, b2) = (w.own_blobs(S, cid(1))[0], w.own_blobs(S, cid(2))[0]);
    w.g.k.held.insert((S, b1), cid(1));
    w.g.k.held.insert((S, b2), cid(2));
    w.stream();
    (w, b1)
}

/// The named `osis_base::costs` counts since the last take (each summed over its spans).
fn taken<const N: usize>(names: [&str; N]) -> [u64; N] {
    let t = osis_base::costs::take();
    names.map(|name| t.iter().filter(|(k, _, _)| *k == name).map(|(_, _, n)| n).sum())
}

/// K's record taken by connection `c` (its digests agreed): what read sends there.
fn k_on(w: &mut W, c: ConnId) -> Vec<Sent> {
    w.g.conns.insert(K, c);
    w.settle();
    w.g.sent.iter().filter(|m| matches!(m, Sent::Delete(x, _) | Sent::Fetch(x, _) | Sent::Deposit(x, _) if *x == c)).cloned().collect()
}

// spec/sync-judgement.md §3 (Deletes: a delete owed at a source is judged from `known` alone,
// connected or not), a must-hold body never deleted: K goes away and comes back once, then
// away again; cid(1) comes to be covered (a Delete owed at K) and, still while K is away, must-hold
// again: K's next connection gets no Delete. Then covered again while away: the Delete goes once
// on the connection after. Fails with an act kept owed once the judgement no longer holds it
// (`Read::react`), which deletes a must-hold body at K.
#[test]
fn a_delete_owed_while_away_goes_nowhere_once_the_body_is_must_hold_again_spec_sync_judgement_3() {
    let (mut w, b1) = two_shown();
    w.g.conns.remove(&K);
    w.settle();
    assert!(k_on(&mut w, ConnId(200)).is_empty());
    w.g.conns.remove(&K);
    w.settle();
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.read.owed_pending(), 1, "the Delete is owed while K is away");
    w.judge(S, cid(1), uncovered());
    assert_eq!(w.read.owed_pending(), 0, "owed once must-hold again");
    assert!(k_on(&mut w, ConnId(201)).is_empty(), "a must-hold body deleted at K on its return: {:?}", w.g.sent);
    w.g.conns.remove(&K);
    w.settle();
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(k_on(&mut w, ConnId(202)), vec![Sent::Delete(ConnId(202), b1)]);
    assert_eq!(w.deletes(), 1);
}

// spec/sync-opens.md §4 (Shared set), spec/sync-judgement.md §3 (Deletes): a source of S is a
// member S of the peer. K
// goes away and comes back once, then away again with a Delete of S owed there; K stops being a
// source of S while away (its member closed: its right ended, or the Members exchange closed it):
// its next connection gets nothing of S. Fails with acts owed past the source's membership.
#[test]
fn nothing_goes_to_a_source_no_longer_a_member_spec_sync_opens_4() {
    let (mut w, _) = two_shown();
    w.g.conns.remove(&K);
    w.settle();
    assert!(k_on(&mut w, ConnId(200)).is_empty());
    w.g.conns.remove(&K);
    w.settle();
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.read.owed_pending(), 1, "the Delete is owed while K is away");
    w.g.set_sources(S, Vec::new());
    w.settle();
    assert_eq!(w.read.owed_pending(), 0, "owed at a source no longer one");
    assert!(k_on(&mut w, ConnId(201)).is_empty(), "sent to K, no longer a member of S: {:?}", w.g.sent);
}

// spec/sync-judgement.md §3 (Deletes: a delete owed stays owed while `known` lists the entry
// there, and is sent once the source is connected), spec/sync-ids.md §6 (refused for now: code 4):
// a Delete K refuses is not sent again on that connection and goes again on the next; one K takes
// is done. Fails with a refused Delete marked done (K keeps the entry until this node restarts).
#[test]
fn a_refused_delete_goes_again_on_the_next_connection_spec_sync_judgement_3() {
    let (mut w, b1) = two_shown();
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.deletes(), 1);
    w.read.answered(KC, w.g.requests, false);
    w.settle();
    assert_eq!(w.deletes(), 1, "sent again on the connection that refused it");
    assert_eq!(k_on(&mut w, ConnId(200)), vec![Sent::Delete(ConnId(200), b1)], "a refused Delete not sent on the next connection");
    w.read.answered(ConnId(200), w.g.requests, true);
    assert!(k_on(&mut w, ConnId(201)).is_empty(), "a Delete taken sent again");
}

// spec/sync-judgement.md §3 (Dropped bodies: fetched again where present): a missing body's Fetch
// goes once per connection while it is missing, never again on one connection however often read
// settles, and once more on each new one. Fails with a Fetch resent at each settle (a loop) or
// marked done (a Fetch whose answer was lost with its connection never goes again).
#[test]
fn a_missing_body_is_fetched_once_per_connection_spec_sync_judgement_3() {
    let (mut w, b1) = two_shown();
    w.g.own.insert((S, cid(1)), Vec::new());
    let mut f = uncovered();
    f.missing = true;
    w.judge(S, cid(1), f);
    let fetches = |w: &W| w.g.sent.iter().filter(|m| matches!(m, Sent::Fetch(..))).count();
    assert_eq!(fetches(&w), 1);
    for _ in 0..3 {
        w.g.added.push(cid(1));
        w.settle();
    }
    assert_eq!(fetches(&w), 1, "fetched again on one connection");
    assert_eq!(k_on(&mut w, ConnId(200)), vec![Sent::Fetch(ConnId(200), b1)]);
    assert_eq!(fetches(&w), 2);
}

// spec/sync-judgement.md §3 (Dropped bodies: Asked by ID): a missing body is asked for by commit
// ID from a source reading S though no stream shows an entry of it, once per connection however
// often read settles, once more on each new one, never from a source keeping S unread (it cannot
// answer by ID), and no more once it stops counting missing. Fails without the ask (a holder
// whose own judgement logged nothing is never reached) or with it sent at each settle (a loop).
#[test]
fn a_missing_body_is_asked_for_by_id_once_per_connection_spec_sync_judgement_3() {
    let (mut w, _) = two_shown();
    let r = Source::Conn(ConnId(300));
    w.source(S, r, ConnId(300), false);
    w.g.own.insert((S, cid(1)), Vec::new());
    let mut f = uncovered();
    f.missing = true;
    w.judge(S, cid(1), f.clone());
    let wants = |w: &W| w.g.sent.iter().filter(|m| matches!(m, Sent::Want(..))).cloned().collect::<Vec<_>>();
    assert_eq!(wants(&w), vec![Sent::Want(ConnId(300), cid(1))], "asked of the reader alone");
    for _ in 0..3 {
        w.g.added.push(cid(1));
        w.settle();
    }
    assert_eq!(wants(&w).len(), 1, "asked again on one connection");
    w.g.conns.insert(r, ConnId(301));
    w.settle();
    assert_eq!(wants(&w).last(), Some(&Sent::Want(ConnId(301), cid(1))), "asked once more on a new connection");
    f.missing = false;
    w.judge(S, cid(1), f);
    w.g.conns.insert(r, ConnId(302));
    w.settle();
    assert_eq!(wants(&w).len(), 2, "no longer missing, no longer asked");
}

// spec/sync-judgement.md §3 (Deletes: at a source full for S a carrier it lacks counts as held;
// Role entries first: a full source is skipped), spec/sync-streams.md §4 (Full: a peer's `full`
// lasts with the connection it was told on): a Delete owed only because K is full (HN_full) goes only on a
// connection K told it is full on, and on K's next connection only once told there too; the
// judgement reads no connection. Fails with the judgement reading `full` of a connection (it
// re-judges at each reconnect) or with the act sent whatever K told.
#[test]
fn a_delete_owed_only_while_full_goes_where_told_full_spec_sync_judgement_3() {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    w.g.k.held.insert((S, b), cid(1));
    w.stream();
    w.hold(cid(2), &[S], uncovered());
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.deletes(), 0, "deleted with no carrier at a K not full");
    w.g.k.full = true;
    w.stream();
    w.settle();
    assert_eq!(w.deletes(), 1, "not deleted at a K told full");
    let c2 = ConnId(KC.0 + 70);
    w.g.conns.insert(K, c2);
    osis_base::costs::take();
    w.settle();
    assert_eq!(taken(["read: toward"]), [0], "a reconnect judged K's bodies again");
    assert_eq!(w.deletes(), 1, "sent on a connection K did not tell full on");
    w.g.told_full.insert((c2, S), ());
    w.settle();
    assert!(w.g.sent.contains(&Sent::Delete(c2, b)), "not sent once K told full there");
}

// spec/sync-judgement.md §3 (Deletes: one owed only while full goes only where told full): where
// a source's acts go (`read: owed`) reads by stamp which of its acts are owed only while full: a
// Delete owed only while K is full, sent and taken, then read settling with every key compared
// (`memo::check_effects`). Failed with that set read from the acts unstamped: the comparison
// found the Delete's sync ID still kept where a settle gives none.
#[test]
fn where_acts_go_reads_the_full_only_acts_by_stamp() {
    let mut w = W::new();
    w.pulls = false;
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    w.g.k.held.insert((S, b), cid(1));
    w.g.k.full = true;
    w.stream();
    w.hold(cid(2), &[S], uncovered());
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.deletes(), 1, "not deleted at a K told full");
    osis_base::memo::check_effects(true);
    w.read.answered(KC, w.g.requests, true);
    for _ in 0..300 {
        w.read.settle_on(&mut w.g).unwrap();
    }
    osis_base::memo::check_effects(false);
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
    w.edit_source(K, |x| x.head = Some(step(1).id()));
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 3);
}

// spec/sync-judgement.md §4 (such a part falls; judged invalid here counts as a fall) (again-stand):
// a held cover or killing write falling here, with no head move, allows one more logging
// (HN_standfall); the stand compares the engine's fall mark alone, which a snapshot arriving
// invalid moves as one held valid falling does (HN_fallany).
#[test]
fn fall_allows_one_more() {
    let mut w = at_k_must_hold();
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 2);
    w.g.marks.insert((S, cid(1)), 1);
    w.settle();
    for _ in 0..2 {
        w.k_delete(cid(1));
        w.exchange();
    }
    assert_eq!(w.logs(S, cid(1)), 3);
}

// spec/sync-judgement.md §4 (fresh encryption) (deposit-storm): logged again as a fresh blob ID
// under that sync ID alone, never the deleted one and never one logged under another sync ID
// (HN_fresh). spec/sync-judgement.md §3 (own store): the first logging is of a held blob
// verbatim where one is (not fresh).
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
    assert_eq!(w.g.fresh, vec![false, false, true, true], "verbatim first, fresh again");
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

// spec/sync-judgement.md §3 (Role entries first: a logging again waits for any role commit S must
// hold here, own or pulled): a role commit this node pulled (a removal by another) that K lacks
// holds back a logging again toward K, so the body goes back there only once what this node's
// judgement rests on is there too, and a node judging otherwise for want of it fetches it there
// before it deletes (drop-rejoin: a node without the revocation deletes a body logged again).
// Fails with own role commits alone waited for.
#[test]
fn a_logging_again_waits_for_every_role_commit_held_spec_sync_judgement_3() {
    let mut w = W::new();
    let mut f = uncovered();
    f.role = true;
    f.own = false;
    w.hold(cid(7), &[S], f);
    w.hold(cid(1), &[S], uncovered());
    w.pulls = false;
    let b1 = w.own_blobs(S, cid(1))[0];
    w.g.k.held.insert((S, b1), cid(1));
    w.stream();
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 1, "logged again before K held the pulled role commit");
}

// spec/sync-judgement.md §3 (role entries first): a delete toward K waits while K's stream shows
// a role commit this node does not hold (HN_delview).
#[test]
fn delete_waits_for_a_role_commit_shown() {
    let mut w = W::new();
    w.hold(cid(2), &[S], uncovered());
    w.hold(cid(1), &[S], uncovered());
    w.exchange();
    w.edit_source(K, |x| x.role_unheld = true);
    w.judge(S, cid(1), covered(cid(2)));
    assert_eq!(w.deletes(), 0);
    w.edit_source(K, |x| x.role_unheld = false);
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

// spec/sync-judgement.md §3 (Dropped bodies), §2 (Per blob): a body counting missing keeps its
// own tombstone of an entry that would leave again at once on arrival (it strips here, or loses
// as spare to an entry held) and does not fetch it where shown: else fetch, drop and lift go
// round for as long as the body counts missing. Control: an entry that would stay is lifted and
// fetched, and so is one that would leave but carries a part counting missing here (it gives that
// part: kept out, a body whose only copies strip here would count missing for good).
#[test]
fn missing_body_keeps_out_an_entry_that_would_leave_at_once() {
    for case in ["strips", "spare", "control", "strips, gives", "spare, gives"] {
        let mut w = W::new();
        w.source(S, Source::Conn(RC), RC, false);
        w.hold(cid(1), &[S], uncovered());
        let held = w.own_blobs(S, cid(1))[0];
        let b = BlobId([77; 32]);
        if case.starts_with("strips") {
            drop(w.g.gone.insert(b, Strip { live: Default::default(), covers: Vec::new(), from: 0 }));
        }
        if case.starts_with("spare") {
            w.g.spare.insert((b, held), ());
        }
        if case.ends_with("gives") {
            w.g.gives.insert(b, ());
        }
        w.g.tombs.insert((S, cid(1)), vec![b]);
        w.g.put_seen((Source::Conn(RC), S, cid(1)), Seen { present: [b].into(), deleted: BTreeSet::new() });
        let mut f = uncovered();
        f.missing = true;
        w.judge(S, cid(1), f);
        let kept = w.g.tombs.get(&(S, cid(1))).is_some_and(|t| t.contains(&b));
        let fetched = w.g.sent.contains(&Sent::Fetch(RC, b));
        match case {
            "strips" | "spare" => assert!(kept && !fetched, "{case}: its tombstone stays and it is not fetched: {:?}", w.g.sent),
            _ => assert!(!kept && fetched, "{case}: lifted and fetched"),
        }
    }
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

// spec/sync-judgement.md §3 (Dropped bodies: fetched again where present): a body counting missing
// whose entry this node still holds (its cover or purge fell before the entry left) takes it again
// from its own store, and fetches only the entries of it it lacks. Fails without `Act::Take`
// (the held blob is never fetched: its bytes are here).
#[test]
fn missing_body_held_here_is_taken_again_spec_sync_judgement_3() {
    let mut w = W::new();
    w.source(S, Source::Conn(RC), RC, false);
    w.hold(cid(1), &[S], uncovered());
    let b = w.own_blobs(S, cid(1))[0];
    let other = BlobId([77; 32]);
    w.g.put_seen((Source::Conn(RC), S, cid(1)), Seen { present: [b, other].into(), deleted: BTreeSet::new() });
    let mut f = uncovered();
    f.missing = true;
    w.judge(S, cid(1), f);
    assert!(w.g.sent.contains(&Sent::Take(b)), "{:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::Fetch(RC, other)));
    assert!(!w.g.sent.contains(&Sent::Fetch(RC, b)), "what is held is taken, not fetched");
}

// spec/sync-judgement.md §3 (Own store: a held blob verbatim, stamped when it writes S): an entry
// pulled from a peer stands as this node's log of the body, so nothing is encrypted afresh, but
// at a writer of S's head one not stamped under it is stamped in place (same blob), and of two
// such duplicates only one.
#[test]
fn a_peers_entry_stands_as_the_log_spec_sync_judgement_3() {
    let peer = |b: u8, stamped: bool| Entry { blob: BlobId([b; 32]), wrap: [0; osis_crypto::WRAP_LEN], stamp: stamped.then_some(stamp_at(0)), deposited: !stamped, own: false, role: false, class: Class::Durable, expires: None };
    for (writer, stamped, restamps) in [(true, true, 0), (false, false, 0), (true, false, 1)] {
        let mut w = W::new();
        w.g.creds.insert(S, creds(0, writer, true));
        w.g.own.insert((S, cid(1)), vec![peer(66, stamped), peer(67, stamped)]);
        // a deposit duplicating another adds no delta (`inbox::adds_delta`)
        w.g.promotions.insert(BlobId([67; 32]), Promotion::No);
        let mut f = uncovered();
        f.own = false;
        w.hold(cid(1), &[S], f);
        assert!(w.g.logged.is_empty(), "writer {writer}, stamped {stamped}: nothing encrypted afresh");
        assert_eq!(w.g.restamped, vec![(S, cid(1), BlobId([66; 32]))][..restamps], "writer {writer}, stamped {stamped}");
    }
}

// spec/sync-inbox.md §4 (promotion: a writer stamps a deposit in its own store, one stamped copy
// per delta), spec/sync-judgement.md §3 (Own store): a peer's deposit of a must-hold body is
// stamped in place only as `promotion` says: promoted beside an entry that stands (it adds a
// delta), not promoted yet holding the body back from a log of its own, never promoted leaving
// the body to be logged as any.
#[test]
fn a_deposit_is_stamped_only_as_promoted_spec_sync_inbox_4() {
    let deposit = |b: u8| Entry { blob: BlobId([b; 32]), wrap: [0; osis_crypto::WRAP_LEN], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: None };
    let standing = Entry { stamp: Some(stamp_at(0)), deposited: false, ..deposit(65) };
    for (promotion, beside, restamps, logs) in [(Promotion::Yes, true, 1, 0), (Promotion::Yes, false, 1, 0), (Promotion::Wait, false, 0, 0), (Promotion::No, false, 0, 1), (Promotion::No, true, 0, 0)] {
        let mut w = W::new();
        let mut held = vec![deposit(66)];
        if beside {
            held.push(standing.clone());
        }
        w.g.own.insert((S, cid(1)), held);
        w.g.promotions.insert(BlobId([66; 32]), promotion);
        let mut f = uncovered();
        f.own = false;
        w.hold(cid(1), &[S], f);
        let what = format!("{promotion:?}, beside a standing entry {beside}");
        assert_eq!(w.g.restamped.iter().filter(|x| x.2 == BlobId([66; 32])).count(), restamps, "{what}");
        assert_eq!(w.g.logged.len(), logs, "{what}");
    }
    // one waiting is stamped once promoted (its evidence came under S), never logged meanwhile
    let mut w = W::new();
    w.g.own.insert((S, cid(1)), vec![deposit(66)]);
    w.g.promotions.insert(BlobId([66; 32]), Promotion::Wait);
    let mut f = uncovered();
    f.own = false;
    w.hold(cid(1), &[S], f);
    w.g.promotions.insert(BlobId([66; 32]), Promotion::Yes);
    w.settle();
    assert_eq!((w.g.restamped.len(), w.g.logged.len()), (1, 0), "promoted once its evidence is under S"
);
}

/// A writer of S at head 0 holding `n` own must-hold bodies under S, each logged once, then S's
/// head moving to step 1.
fn head_moved(n: u8) -> W {
    let mut w = W::new();
    for i in 0..n {
        w.hold(cidn(i, 2), &[S], uncovered());
    }
    w.exchange();
    assert_eq!(w.g.logged.len(), n as usize);
    osis_base::costs::take();
    w.g.creds.insert(S, creds(1, true, true));
    w.settle();
    w
}

// spec/sync-judgement.md §3 (Own store: stamped when it writes S, in place on a head move), spec/sync-ids.md
// §6 (a stamp under a superseded write key is refused): at a writer, an own entry stands as its
// log only stamped under S's head write key, so a head move stamps each own entry of a must-hold
// body in place once (no fresh encryption, nothing deposited), judging each body once more and
// no more, at n and 10n bodies; the next head move does it again.
#[test]
fn a_head_move_restamps_each_own_entry_once_spec_sync_judgement_3() {
    let mut judged = Vec::new();
    for n in [10u8, 100] {
        let mut w = head_moved(n);
        judged.push(taken(["read: judged"])[0]);
        assert_eq!(w.g.restamped.len(), n as usize, "each body's own entry once");
        let blobs: BTreeSet<BlobId> = w.g.restamped.iter().map(|x| x.2).collect();
        assert_eq!(blobs.len(), n as usize);
        assert_eq!(w.g.logged.len(), n as usize, "nothing encrypted afresh");
        assert!(!w.sent().any(|m| matches!(m, Sent::Deposit(..))), "nothing deposited");
        assert!(w.g.own.iter().all(|(_, v)| v.iter().all(|e| e.stamp == Some(stamp_at(1)))), "every own entry under step 1's key");
        w.settle();
        assert_eq!(w.g.restamped.len(), n as usize, "a settle with no head move stamps nothing");
        w.g.creds.insert(S, creds(2, true, true));
        w.settle();
        assert_eq!(w.g.restamped.len(), 2 * n as usize, "the next head move stamps each again");
    }
    // twice per body (the head move, then its restamp), each counted by the judgement and its
    // effects
    assert_eq!(judged, vec![4 * 10, 4 * 100], "judgements per body per head move");
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

// spec/sync-judgement.md §4 (logs the body again once): a body K deleted while it was not
// judged yet here (K's stream shows it deleted only) is logged again there once its verdict turns
// must-hold: a source showing it deleted is judged as the verdict moves, as one showing it present.
#[test]
fn deleted_while_unjudged_is_logged_again_once_must_hold() {
    let mut w = at_k_must_hold();
    let mut f = uncovered();
    f.body.covered = None;
    w.judge(S, cid(1), f);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Unjudged));
    w.k_delete(cid(1));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 1, "unjudged calls for nothing");
    w.judge(S, cid(1), uncovered());
    assert_eq!(w.logs(S, cid(1)), 2, "must-hold: logged again at K");
}

// spec/sync-judgement.md §3 (giving a body: nothing but role commits given at a source on an
// earlier step of its recorded path), spec/sync-ids.md §6 (Steps): a non-writer whose `sync.0`
// records step 1 gives K, standing at step 0, nothing until K stands at step 1.
#[test]
fn a_non_writer_deposits_nothing_at_a_source_behind_its_head_spec_sync_judgement_3() {
    let mut w = W::new();
    w.pulls = false;
    w.g.creds.insert(S, creds(1, false, false));
    w.hold(cid(1), &[S], uncovered());
    w.settle();
    assert!(!w.g.sent.iter().any(|m| matches!(m, Sent::Deposit(..))), "{:?}", w.g.sent);
    w.edit_source(K, |x| x.head = Some(step(1).id()));
    let b = w.own_blobs(S, cid(1))[0];
    assert!(w.g.sent.contains(&Sent::Deposit(KC, b)), "{:?}", w.g.sent);
}

// spec/sync-ids.md §6 (Steps: registering waits on the source holding the role commits the step
// depends on; Taking a stamped entry: one under a superseded write key goes as a deposit): a
// non-writer at step 1 gives K, standing at step 0, a role commit it holds unstamped, so the
// registration it waits on can pass.
#[test]
fn a_non_writer_deposits_a_role_commit_at_a_source_behind_its_head_spec_sync_ids_6() {
    let mut w = W::new();
    w.pulls = false;
    w.g.creds.insert(S, creds(1, false, false));
    let mut f = uncovered();
    f.role = true;
    w.hold(cid(1), &[S], f);
    w.settle();
    let b = w.own_blobs(S, cid(1))[0];
    assert!(w.g.sent.contains(&Sent::Deposit(KC, b)), "{:?}", w.g.sent);
}

// spec/sync-compaction.md §1 (duplicates: of two entries of one body at K the delete-key holder
// deletes the higher blob ID; Only what the node checked): a blob of the
// same opened parts whose unopened sections differ from the node's by their bytes (a forged
// section of a thing it does not read, ground to the lowest blob ID and stamped by a writer that
// copied it as it came) is no duplicate: neither goes. One whose unopened sections are byte for
// byte the node's is, and the higher ID goes.
#[test]
fn duplicates_compare_unopened_sections_by_bytes() {
    let mut w = at_k_must_hold();
    let own: Vec<BlobId> = w.g.k.held.keys().map(|(_, b)| *b).collect();
    for b in &own {
        w.g.blobs.insert(*b, Some(BlobInfo { parts: [0].into(), sealed: [[1; 32]].into(), copy: false }));
    }
    let lo = BlobId([0; 32]);
    w.g.blobs.insert(lo, Some(BlobInfo { parts: [0].into(), sealed: [[2; 32]].into(), copy: false }));
    w.g.k.held.insert((S, lo), cid(1));
    w.stream();
    w.settle();
    assert_eq!(w.deletes(), 0, "a blob with other unopened bytes deleted as a duplicate");
    w.g.blobs.insert(lo, Some(BlobInfo { parts: [0].into(), sealed: Default::default(), copy: false }));
    w.stream();
    w.settle();
    assert_eq!(w.deletes(), 0, "a blob lacking an unopened section deleted as a duplicate");
    w.g.blobs.insert(lo, Some(BlobInfo { parts: [0].into(), sealed: [[1; 32]].into(), copy: false }));
    w.stream();
    w.settle();
    let deleted: BTreeSet<BlobId> = w.g.sent.iter().filter_map(|m| if let Sent::Delete(_, b) = m { Some(*b) } else { None }).collect();
    assert_eq!(deleted, own.into_iter().collect(), "the same bytes: the higher ID goes");
}

// spec/sync-judgement.md §3 (driven by events): work follows change: a fact of one body, or K's
// stream showing one entry, judges that body alone, at n and 10n bodies.
#[test]
fn work_follows_change() {
    let mut costs = Vec::new();
    for n in [20u8, 200] {
        let mut w = W::new();
        for i in 0..n {
            w.g.facts.insert((S, cidn(i, 1)), uncovered());
        }
        for i in 0..n {
            let c = cidn(i, 1);
            w.g.bodies.insert(c, Arc::new([(S, meta())].into()));
            w.g.added.push(c);
        }
        w.exchange();
        let c = cidn(3, 1);
        osis_base::costs::take();
        w.judge(S, c, covered(cid(250)));
        w.k_delete(c);
        let [judged] = taken(["read: judged"]);
        costs.push(judged);
    }
    assert_eq!(costs[0], costs[1], "judgements per change grow with the bodies held");
    assert!(costs[0] <= 4, "{costs:?}");
}

// spec/sync-judgement.md §2 (header-only blob): a certificate is must-hold whatever snapshot
// covers it: it neither leaves the own log nor is deleted at K as covered. §2 (Loggable): one
// this node may not log now is may-hold, kept as it is (a may-hold body that is not loggable is
// kept if it arrives), and is must-hold again once it may.
#[test]
fn an_unloggable_certificate_is_kept_not_covered_and_dropped_spec_sync_judgement_2() {
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
    w.g.unloggable.insert((S, cid(1)), ());
    w.exchange();
    w.exchange();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::May));
    assert_eq!(w.own_blobs(S, cid(1)).len(), 1, "an unloggable certificate left the own log");
    assert_eq!(w.deletes(), 0, "an unloggable certificate was deleted at K");
    w.g.unloggable.remove(&(S, cid(1)));
    w.exchange();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
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
    // a head move's stamp in place is a log too: it waits for a reader, then is made once
    w.g.unpullable.insert(S, ());
    w.settle();
    w.g.creds.insert(S, creds(1, true, true));
    w.settle();
    assert!(w.g.restamped.is_empty(), "stamped while no reader can pull");
    w.g.unpullable.remove(&S);
    w.settle();
    assert_eq!(w.g.restamped.len(), 1);
}

// spec/sync.md §2 (work in proportion to change), spec/sync-judgement.md §3 (own store): whether
// a reader can pull S flips at every connection lost and made again; it moves only the bodies
// and certificate blobs with something to log, so at n and 10n logged bodies a flip judges
// the same few.
#[test]
fn a_pull_flip_judges_only_what_is_to_log() {
    let mut costs = Vec::new();
    for n in [10u8, 100] {
        let mut w = W::new();
        for i in 0..n {
            w.hold(cid(i), &[S], uncovered());
        }
        w.exchange();
        assert_eq!(w.g.logged.len(), n as usize);
        osis_base::costs::take();
        w.g.unpullable.insert(S, ());
        w.settle();
        w.hold(cid(200), &[S], uncovered());
        w.g.unpullable.remove(&S);
        w.settle();
        assert_eq!(w.logs(S, cid(200)), 1, "the body held while no reader could pull is logged once one can");
        costs.push(taken(["read: judged", "read: certificate blobs"]));
    }
    assert_eq!(costs[0], costs[1], "judgements per pull flip grow with the logged bodies");
}

// spec/sync-judgement.md §2 (Loggable): a body of S's required set this node may not log under S
// is may-hold, so a non-writer gives it no source and owes it nowhere; once it may (the judgement
// reads it, so it moves then), it is must-hold, logged once and given. spec/sync-judgement.md §3
// (giving a body): a must-hold body K lacks is given as a held entry (deposited).
#[test]
fn a_body_this_node_may_not_log_is_may_hold_until_it_may_spec_sync_judgement_2() {
    let mut w = W::new();
    w.pulls = false;
    w.g.creds.insert(S, creds(0, false, false));
    w.g.unloggable.insert((S, cid(1)), ());
    w.hold(cid(1), &[S], uncovered());
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::May));
    assert_eq!(w.logs(S, cid(1)), 0);
    assert!(w.g.sent.is_empty(), "{:?}", w.g.sent);
    w.g.unloggable.remove(&(S, cid(1)));
    w.settle();
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
    assert_eq!(w.logs(S, cid(1)), 1);
    let b = w.own_blobs(S, cid(1))[0];
    assert_eq!(w.g.sent, vec![Sent::Deposit(KC, b)]);
    w.exchange();
    assert_eq!(w.at_k(S, cid(1)), 1);
}

// spec/sync-judgement.md §3 (own store), spec/permissions.md §4 (Logging certificates): a body
// and S's missing records judged while S is not yet held read (the engine's sync set lists S
// before the store's holdings do) are logged once S comes to be read, with no restart.
#[test]
fn what_s_carries_is_logged_once_s_comes_to_be_read_spec_sync_judgement_3() {
    let mut w = W::new();
    let r1 = osis_base::Tid::from_bytes([1; 15]);
    w.g.set_reads(S, false);
    w.g.records.insert(S, CertBlobsMissing { missing: [r1].into(), ..Default::default() });
    w.hold(cid(1), &[S], uncovered());
    assert_eq!(w.logs(S, cid(1)), 0);
    assert!(w.g.record_logs.is_empty());
    w.g.set_reads(S, true);
    w.settle();
    assert_eq!(w.logs(S, cid(1)), 1, "the body logged");
    assert_eq!(w.g.record_logs, vec![(S, [r1].into())], "the record blob logged");
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
    w.g.records.insert(S, CertBlobsMissing { missing: [r1].into(), ..Default::default() });
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.record_logs.is_empty(), "no reader can pull S yet");
    w.g.unpullable.remove(&S);
    w.settle();
    assert_eq!(w.g.record_logs, vec![(S, [r1].into())]);
    w.settle();
    assert_eq!(w.g.record_logs.len(), 1, "once");
    w.g.records.insert(S, CertBlobsMissing { missing: [r2].into(), gone: [BlobId([9; 32])].into(), ..Default::default() });
    w.settle();
    assert_eq!(w.g.record_logs, vec![(S, [r1].into()), (S, [r2].into())]);
    assert_eq!(w.g.records_forgotten, vec![(S, BlobId([9; 32]))]);
}

// spec/sync-judgement.md §3 (own store: logged only while a reader can pull it, stamped in place
// on a head move): a certificate blob not stamped under S's head is stamped in place only once a
// reader can pull S.
#[test]
fn a_stale_certificate_blob_is_stamped_once_a_reader_can_pull() {
    let mut w = W::new();
    let rb = BlobId([77; 32]);
    w.g.unpullable.insert(S, ());
    w.g.own.insert((S, cid(9)), vec![Entry { blob: rb, wrap: [0; osis_crypto::WRAP_LEN], stamp: None, deposited: false, own: true, role: false, class: Class::Durable, expires: None }]);
    w.g.records.insert(S, CertBlobsMissing { stale: [rb].into(), ..Default::default() });
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.restamped.is_empty(), "no reader can pull S yet");
    w.g.unpullable.remove(&S);
    w.settle();
    assert_eq!(w.g.restamped, vec![(S, cid(9), rb)]);
}

// spec/sync-judgement.md §2 (outside the required set): while a thing of the sync unit holds part
// of its `holds.0` only as a header, a body outside the sync unit is not judged, so nothing of it
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
    w.g.blobs.insert(hi, Some(BlobInfo { parts: [0, 1].into(), sealed: Default::default(), copy: false }));
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
    w.g.blobs.insert(hi, Some(BlobInfo { parts: [0].into(), sealed: Default::default(), copy: true }));
    w.g.k.held.insert((S, lo), cid(1));
    w.stream();
    w.settle();
    let shared: Vec<BlobId> = w.g.k.held.keys().filter(|(_, b)| *b != hi && *b != lo).map(|(_, b)| *b).collect();
    let deleted: BTreeSet<BlobId> = w.g.sent.iter().filter_map(|m| if let Sent::Delete(_, b) = m { Some(*b) } else { None }).collect();
    assert!(!deleted.contains(&hi), "the copy was deleted");
    assert!(deleted.contains(&lo) && shared.iter().all(|b| deleted.contains(b)), "{deleted:?}");
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
        costs.push(taken(["read: judged", "read: toward"]));
    }
    assert_eq!(costs[0], costs[1], "work per source event grows with the sources");
    assert!(costs[0][1] <= 4, "{costs:?}");
}

/// The judgements one delivered commit costs (`read: judged`) with `n` other bodies held and
/// judged under S: the delivery makes body `c0` loggable (its ground row leaves), and brings a
/// body of its own.
fn judged_per_delivery(n: u16) -> u64 {
    let id = |i: u16| {
        let mut b = [7u8; 32];
        b[..2].copy_from_slice(&i.to_be_bytes());
        CommitId(b)
    };
    let mut w = W::new();
    for i in 0..n {
        w.g.facts.insert((S, id(i)), uncovered());
        w.g.bodies.insert(id(i), Arc::new([(S, meta())].into()));
        w.g.added.push(id(i));
    }
    let c0 = id(n);
    w.g.unloggable.insert((S, c0), ());
    w.hold(c0, &[S], uncovered());
    w.exchange();
    osis_base::costs::take();
    w.g.unloggable.remove(&(S, c0));
    w.hold(id(n + 1), &[S], uncovered());
    taken(["read: judged"])[0]
}

// spec/sync-judgement.md §3 (driven by events): a delivered commit judges what it moved: a
// ground row leaving moves the judgements that read that row alone, never those that read
// another row of its container absent: the same judgements at n and 10n bodies held.
#[test]
fn a_delivery_judges_what_it_moved_at_n_and_10n_bodies() {
    let (a, b) = (judged_per_delivery(64), judged_per_delivery(640));
    assert_eq!(a, b, "judgements per delivered commit grow with the bodies held");
    // the two bodies it moved, each judged again as its own entries move
    assert!(a <= 8, "{a}");
}

/// The judgements (`read: judged`, `read: toward` settles) node 0 and node 1 make for a write and
/// a grant on thing 0, after `n` writes on each of 3 other things node 0 made (other sync IDs),
/// each run to quiet: through the product's sync over the real engine.
fn judged_per_event(n: usize) -> [u64; 2] {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world_of};
    let mut w = world_of(0, 2, 2);
    let mut steps = vec![New(0), Grant(0, 0, 1, Gives::Reads), New(0), New(0), New(0), Run];
    steps.extend((0..n).flat_map(|_| [Write(0, 1), Write(0, 2), Write(0, 3), Run]));
    for s in &steps {
        crate::harness::step(&mut w, s);
    }
    osis_base::costs::take();
    for s in [Write(0, 0), Run, Grant(0, 0, 1, Gives::Writes), Run] {
        crate::harness::step(&mut w, &s);
    }
    taken(["read: judged", "read: toward"])
}

/// The judgements (`read: judged`) and those giving the value held (`read: judged unchanged`)
/// node 0 and node 1 make for a thing node 0 makes, writes and grants node 1 read on, after `n`
/// such things (each its own sync ID, carrying the accounts' certificates as copies), run to quiet.
fn judged_per_sync_id(n: usize) -> [u64; 2] {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world_of};
    let mut w = world_of(0, 2, 2);
    let round = |k: usize| [New(0), Write(0, k), Grant(0, k, 1, Gives::Reads), Run];
    for k in 0..n {
        for s in &round(k) {
            crate::harness::step(&mut w, s);
        }
    }
    osis_base::costs::take();
    for s in &round(n) {
        crate::harness::step(&mut w, s);
    }
    taken(["read: judged", "read: judged unchanged"])
}

// spec/sync.md §2 (work in proportion to change): a sync ID coming to be read re-judges nothing
// under the others, though a commit has a body under each (an account's certificates go as a
// copy under every sync ID): the same judgements, and the same judgements giving the value
// already held, after n and 10n other sync IDs. A judgement reading what decides another sync
// ID's body (the commit's bodies whole, its blobs under every sync ID) grows with them.
#[test]
fn a_new_sync_id_judges_nothing_again_under_the_others() {
    let (a, b) = (judged_per_sync_id(1), judged_per_sync_id(10));
    assert_eq!(a, b, "(judgements, unchanged) for a new sync ID grow with the sync IDs read");
}

// spec/sync.md §2 (work in proportion to change): over the real engine, a write and a role
// change on one thing re-judge the (sync ID, commit) pairs they moved, never every pair held: the
// same judgements after n and 10n commits under other sync IDs (the engine's values kept per key
// are brought up to date by `Engine::follow`), up to `REJUDGED`: a pair the events moved is judged
// again when a row it read (its certificates, `Certified::naming`) lands in a later follow than
// its first judgement, which turns on how the commit IDs of that run sort, not on n. Growth with
// n would judge some of the 54 more commits under other sync IDs at the larger size.
#[test]
fn an_event_on_one_sync_id_judges_what_it_moved() {
    // the grant commit judged once more at each of its 4 (sync ID, commit) pairs, twice over
    const REJUDGED: u64 = 8;
    let (a, b) = (judged_per_event(2), judged_per_event(20));
    assert!(b[0] <= a[0] + REJUDGED && a[0] <= b[0] + REJUDGED, "judgements per event grow with the commits under other sync IDs: {a:?} {b:?}");
    assert_eq!(a[1], b[1], "toward judgements per event grow with the commits under other sync IDs");
}

fn bid(i: u8) -> BlobId {
    BlobId([i; 32])
}

/// A piece link to blob `bid(i)` (a chunk when `leaf`).
fn pl(i: u8, leaf: bool) -> PieceLink {
    let link = osis_base::Link { hash: [i; 32], blob: bid(i), suite: 0, key: [0; 32], salt: [0; 16], del: osis_base::Del::NONE };
    PieceLink::new(link, None, leaf)
}

/// A writer holding own body `cid(1)` under S linking chunks `held` (held here) and `missing`.
fn with_pieces(held: &[u8], missing: &[u8]) -> W {
    let mut w = W::new();
    for i in held {
        w.g.below.insert(pl(*i, true), Arc::default());
    }
    let roots = held.iter().chain(missing).map(|i| pl(*i, true)).collect();
    w.g.roots.insert(cid(1), Arc::new(roots));
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
    // cid(1) links node 10 over chunks 11 and 12; cid(2) links chunk 20
    w.g.below.insert(pl(10, false), Arc::new(vec![pl(11, true), pl(12, true)]));
    for i in [11, 12, 20] {
        w.g.below.insert(pl(i, true), Arc::default());
    }
    w.g.roots.insert(cid(1), Arc::new(vec![pl(10, false)]));
    w.g.roots.insert(cid(2), Arc::new(vec![pl(20, true)]));
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
    w.g.roots.insert(cid(1), Arc::new(vec![pl(10, true), pl(11, true), pl(12, true)]));
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.sent.contains(&Sent::TakePiece(bid(10))), "{:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::Fetch(KC, bid(11))));
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::TakePiece(_) | Sent::Fetch(..))), 2, "nothing for one no source shows");
}

// spec/sync-ids.md §1 (Repair): a held piece of an own body that every source showing it deleted
// (none present) is repaired once, judged with S's sources heard out; not while one shows it
// present (a body not this node's own: `a_lost_piece_an_own_body_comes_to_link_is_repaired`).
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
}

// spec/sync-ids.md §1 (Repair): what a repair encrypted afresh is never repaired by way of it: a
// source deleting it is refusing, not a purger that missed a reuse, so a store refusing each
// re-encryption makes this node write one repair per piece its other own commits link, not one
// per refusal; a chunk the repair reused is repaired through it like any own commit's.
#[test]
fn a_repair_repairs_what_it_reused_not_what_it_wrote_afresh_spec_sync_ids_1() {
    let mut w = with_pieces(&[10, 11], &[]);
    let mut f = uncovered();
    f.repair_fresh = Arc::new([bid(10)].into());
    w.judge(S, cid(1), f);
    w.g.heard.insert(S, true);
    w.g.piece_seen.insert((K, S, bid(10)), (false, true));
    w.settle();
    w.exchange();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Repair(..))), 0, "{:?}", w.g.sent);
    w.g.piece_seen.insert((K, S, bid(11)), (false, true));
    w.settle();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Repair(..))), 1, "{:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::Repair(cid(1), bid(11))), "{:?}", w.g.sent);
}

/// A piece link to blob `i` (big-endian in its first bytes), a chunk when `leaf`.
fn plw(i: u32, leaf: bool) -> PieceLink {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_be_bytes());
    b[4] = 0xee;
    let link = osis_base::Link { hash: b, blob: BlobId(b), suite: 0, key: [0; 32], salt: [0; 16], del: osis_base::Del::NONE };
    PieceLink::new(link, None, leaf)
}

/// Pieces judged when own body `cid(2)` links node 1001 over the `n` chunks of `cid(1)`'s node
/// 1000 but one, and one new chunk: a small edit to a large value.
fn pieces_judged_for_an_edit(n: u32) -> u64 {
    let mut w = W::new();
    let chunks: Vec<PieceLink> = (0..n).map(|i| plw(i, true)).collect();
    for c in &chunks {
        w.g.below.insert(*c, Arc::default());
    }
    w.g.below.insert(plw(1000, false), Arc::new(chunks.clone()));
    w.g.roots.insert(cid(1), Arc::new(vec![plw(1000, false)]));
    w.hold(cid(1), &[S], uncovered());
    w.exchange();
    let mut edited = chunks[..chunks.len() - 1].to_vec();
    edited.push(plw(999, true));
    w.g.below.insert(plw(999, true), Arc::default());
    w.g.below.insert(plw(1001, false), Arc::new(edited));
    w.g.roots.insert(cid(2), Arc::new(vec![plw(1001, false)]));
    osis_base::costs::take();
    w.hold(cid(2), &[S], uncovered());
    w.exchange();
    taken(["read: piece judged"])[0]
}

// spec/sync.md §2 (work in proportion to change): a body sharing most of its tree with one
// already followed judges only its new pieces: the same at n and 10n chunks.
#[test]
fn an_edit_judges_its_new_pieces_alone() {
    let (a, b) = (pieces_judged_for_an_edit(10), pieces_judged_for_an_edit(100));
    assert_eq!(a, b, "pieces judged per edit grow with the tree");
    assert!(a <= 4, "the new node and the new chunk, each again once logged: {a}");
}

// spec/sync-judgement.md §1 (chunk and tree-node blobs): only a must-hold body's pieces go under
// S: once it is no longer must-hold, a piece it alone linked is not fetched where a source
// comes to show it.
#[test]
fn pieces_are_followed_only_while_a_must_hold_body_links_them_spec_sync_judgement_1() {
    let mut w = with_pieces(&[], &[10]);
    w.judge(S, cid(1), covered(cid(9)));
    w.g.piece_seen.insert((K, S, bid(10)), (true, false));
    w.settle();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Fetch(..))), 0, "{:?}", w.g.sent);
}

// spec/sync-judgement.md §1 (chunk and tree-node blobs): a held piece no must-hold body links
// calls for nothing (its own entry gone, it is not logged); once a body links its node again,
// it and what lies below the node act again, as they stand.
#[test]
fn a_piece_no_must_hold_body_links_acts_again_once_linked_spec_sync_judgement_1() {
    let mut w = W::new();
    w.g.below.insert(pl(30, false), Arc::new(vec![pl(31, true)]));
    w.g.below.insert(pl(31, true), Arc::default());
    w.g.roots.insert(cid(1), Arc::new(vec![pl(30, false)]));
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.sent.contains(&Sent::LogPiece(bid(31))), "{:?}", w.g.sent);
    w.judge(S, cid(1), covered(cid(9)));
    w.g.sent.clear();
    w.g.piece_at.insert((S, bid(31)), PieceAt::Absent);
    w.settle();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::LogPiece(_))), 0, "not linked: {:?}", w.g.sent);
    w.g.roots.insert(cid(2), Arc::new(vec![pl(30, false)]));
    w.hold(cid(2), &[S], uncovered());
    assert_eq!(w.g.sent.iter().filter(|m| **m == Sent::LogPiece(bid(31))).count(), 1, "{:?}", w.g.sent);
}

// spec/sync-ids.md §1 (Repair): a piece already lost when an own body comes to link it is
// repaired in that body.
#[test]
fn a_lost_piece_an_own_body_comes_to_link_is_repaired_spec_sync_ids_1() {
    let mut w = W::new();
    w.g.below.insert(pl(10, true), Arc::default());
    w.g.below.insert(pl(30, false), Arc::new(vec![pl(10, true)]));
    w.g.roots.insert(cid(1), Arc::new(vec![pl(10, true)]));
    let mut f = uncovered();
    f.own = false;
    w.hold(cid(1), &[S], f);
    w.g.heard.insert(S, true);
    w.g.piece_seen.insert((K, S, bid(10)), (false, true));
    w.settle();
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::Repair(..))), 0, "another's body is not repaired here");
    w.g.roots.insert(cid(2), Arc::new(vec![pl(30, false)]));
    w.hold(cid(2), &[S], uncovered());
    assert_eq!(w.g.sent.iter().filter(|m| **m == Sent::Repair(cid(2), bid(10))).count(), 1, "{:?}", w.g.sent);
}

/// Pieces followed after `k` own bodies, each a node over 10 fresh chunks replacing the one
/// before (judged covered); `release`: the engine releases a replaced body's pieces (no history).
fn followed_after_replacements(k: u8, release: bool) -> usize {
    let mut w = W::new();
    let tree = |i: u8| (plw(10_000 + u32::from(i), false), (0..10).map(|j| plw(u32::from(i) * 100 + j, true)).collect::<Vec<_>>());
    for i in 1..=k {
        let (node, chunks) = tree(i);
        for c in &chunks {
            w.g.below.insert(*c, Arc::default());
        }
        w.g.below.insert(node, Arc::new(chunks));
        w.g.roots.insert(cid(i), Arc::new(vec![node]));
        w.hold(cid(i), &[S], uncovered());
        if i > 1 {
            w.judge(S, cid(i - 1), covered(cid(i)));
            if release {
                let (node, chunks) = tree(i - 1);
                for p in chunks.iter().chain([&node]) {
                    w.g.below.remove(p);
                }
                w.settle();
            }
        }
    }
    w.read.pieces_followed()
}

// spec/sync-judgement.md §1 (chunk and tree-node blobs): bound of the pieces followed: a piece no
// must-hold body links stays followed (dormant) only while it is held: a flood of large bodies
// each replaced leaves the live tree's pieces followed, at k and 10k bodies; with the replaced
// ones held (history), one per held piece.
#[test]
fn replaced_bodies_leave_no_pieces_followed_once_released_spec_sync_judgement_1() {
    assert_eq!(followed_after_replacements(3, true), 11);
    assert_eq!(followed_after_replacements(30, true), 11);
    assert_eq!(followed_after_replacements(3, false), 33, "dormant while held");
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
    assert!(w.g.sent.contains(&Sent::DropBlob(bid(10))), "{:?}", w.g.sent);
    assert_eq!(sent_of(&w, |m| matches!(m, Sent::DeleteFreed(..))), 1, "at K alone: {:?}", w.g.sent);
    assert!(w.g.sent.contains(&Sent::DeleteFreed(KC, bid(10))));
    assert!(!w.g.sent.contains(&Sent::FreedDone(bid(10))), "K still shows it");
    w.g.piece_seen.insert((K, S, bid(10)), (false, true));
    w.settle();
    assert!(w.g.sent.contains(&Sent::FreedDone(bid(10))), "{:?}", w.g.sent);
    assert!(!w.g.freed.contains_key(&(bid(10), t)));
}

/// The thing whose mintings the minting tests copy under S (its record goes there; S's closure
/// lacks it).
const T: Tid = Tid::from_bytes([7; 15]);

fn minting(c: u8, valued: bool, end: End) -> Minting {
    Minting { commit: cid(c), standing: Standing { valued, end } }
}

/// A peer's entry `b` in the own store (pulled from a reader).
fn peer_entry(b: u8) -> Entry {
    Entry { blob: BlobId([b; 32]), wrap: [0; osis_crypto::WRAP_LEN], stamp: Some(stamp_at(0)), deposited: false, own: false, role: false, class: Class::Durable, expires: None }
}

impl W {
    /// The engine holds `ms` as T's mintings, each a header-only copy in S's required set.
    fn mintings(&mut self, ms: &[Minting]) {
        self.g.mintings.insert(T, Arc::new(ms.to_vec()));
        for m in ms {
            let mut f = uncovered();
            f.own = false;
            f.body.closure = false;
            self.g.facts.insert((S, m.commit), f);
            let meta = BodyMeta { parts: BTreeSet::new(), copy: true, certificate: true, header_only: true, mints: [T].into(), ..meta() };
            self.g.bodies.insert(m.commit, Arc::new([(S, meta)].into()));
            self.g.added.push(m.commit);
        }
        self.settle();
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record: logged only where no entry there
// holds a minting of the same standing, the copies under a sync ID are its witness and its ties):
// two durable mintings of T tie; one held there keeps the witness (the lower commit ID) unlogged
// and both are kept; once it leaves, the witness is logged.
#[test]
fn a_tie_held_keeps_the_witness_unlogged_spec_commits_5() {
    let mut w = W::new();
    w.g.own.insert((S, cid(2)), vec![peer_entry(12)]);
    w.mintings(&[minting(1, true, End::Never), minting(2, true, End::Never)]);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::May));
    assert_eq!(w.read.verdict(&S, &cid(2)), Some(Verdict::May));
    w.exchange();
    assert_eq!(w.logs(S, cid(1)), 0, "a tie held: the witness is not logged");
    assert_eq!(w.own_blobs(S, cid(2)), vec![BlobId([12; 32])], "the tie is kept");
    w.g.own.insert((S, cid(2)), Vec::new());
    w.settle();
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
    assert_eq!(w.logs(S, cid(1)), 1, "no tie held: the witness is logged");
}

// spec/commits.md §5 (A thing's mintings travel with its record: a copy of a destroyed thing's
// witness a node logged before and that went is logged again while the sync ID needs the thing):
// T destroyed (its one minting gone), its witness's own entry gone, is logged again.
#[test]
fn a_destroyed_things_witness_that_went_is_logged_again_spec_commits_5() {
    let mut w = W::new();
    w.mintings(&[minting(1, false, End::At(50, None))]);
    assert_eq!(w.read.verdict(&S, &cid(1)), Some(Verdict::Must));
    assert_eq!(w.logs(S, cid(1)), 1);
    let b = w.own_blobs(S, cid(1))[0];
    w.g.drop_own(&S, &b, &osis_engine::sync::BodyId::unit(cid(1))).unwrap();
    w.settle();
    assert_eq!(w.logs(S, cid(1)), 2, "logged again");
}

// spec/commits.md §5 (A thing's mintings travel with its record): read ranks a minting only while
// its header-only copy is in S's required set as one: a copy leaving it (T's record no longer
// goes under S) leaves nothing ranked, and with none left the thing is no longer followed.
#[test]
fn a_minting_copy_leaving_the_required_set_leaves_nothing_ranked_spec_commits_5() {
    let mut w = W::new();
    w.mintings(&[minting(1, true, End::Never), minting(2, true, End::Never)]);
    assert_eq!(w.read.mintings_ranked(), 2);
    for (c, left) in [(1, 1), (2, 0)] {
        w.g.bodies.insert(cid(c), Arc::new(BTreeMap::new()));
        w.settle();
        assert_eq!(w.read.mintings_ranked(), left, "after cid({c}) left");
        assert_eq!(w.read.ranks_thing(&S, &T), left > 0, "after cid({c}) left");
    }
}

/// The record blobs logged.
type CertLogs = Vec<(SyncId, BTreeSet<Tid>)>;

// spec/commits.md §5 (Forgetting: once every part dropped as covered, no entry of a blob of it
// known and no delete of one within `TOMBSTONE_LIFETIME`): a commit the engine would forget is
// kept while an own entry, an own tombstone or a source showing an entry of it is known under a
// sync ID carrying it, and forgotten once none is, once.
#[test]
fn a_covered_commit_is_forgotten_once_no_entry_of_it_is_known_spec_commits_5() {
    let mut w = W::new();
    let c = cid(3);
    let b = BlobId([3; 32]);
    w.g.tombs.insert((S, c), vec![b]);
    w.hold(c, &[S], covered(cid(4)));
    w.g.forgettable.insert(c, ());
    w.settle();
    assert!(w.g.forgotten.is_empty(), "forgotten with its own tombstone known");
    w.g.tombs.remove(&(S, c));
    w.g.anywhere.insert((S, c), true);
    w.settle();
    assert!(w.g.forgotten.is_empty(), "forgotten while a source shows an entry");
    w.g.anywhere.insert((S, c), false);
    w.settle();
    assert_eq!(w.g.forgotten, vec![c]);
    w.settle();
    assert_eq!(w.g.forgotten, vec![c], "once");
}

// spec/commits.md §5 (Forgetting: no delete of one of its blobs within `TOMBSTONE_LIFETIME`): a
// tombstone under a sync ID that no longer carries a body of the commit (its body moved to S2)
// keeps it until the tombstone ends.
#[test]
fn a_tombstone_where_the_body_no_longer_goes_keeps_the_commit_spec_commits_5() {
    let mut w = W::new();
    let c = cid(3);
    w.g.tombs.insert((S, c), vec![BlobId([3; 32])]);
    w.g.known.insert(c, [S].into());
    w.hold(c, &[S2], covered(cid(4)));
    w.g.forgettable.insert(c, ());
    w.settle();
    assert!(w.g.forgotten.is_empty(), "forgotten with a tombstone known under S");
    w.g.tombs.remove(&(S, c));
    w.g.known.insert(c, BTreeSet::new());
    w.settle();
    assert_eq!(w.g.forgotten, vec![c]);
}

impl W {
    /// Commit `c` held with its body under `ids` alone, and a peer's entry `b` of it pulled into
    /// the own store of S at pass place `place`.
    fn pulled(&mut self, c: CommitId, ids: &[SyncId], b: u8, place: u64) {
        self.g.place = place;
        self.g.bodies.insert(c, Arc::new(ids.iter().map(|s| (*s, meta())).collect()));
        self.g.added.push(c);
        self.g.own.insert((S, c), vec![peer_entry(b)]);
        self.g.entries_feed.push((S, c));
        self.settle();
    }

    /// A complete pass of S begun at pass place `at` ended.
    fn pass(&mut self, at: u64) {
        self.g.done.insert(S, at);
        self.settle();
    }
}

// spec/sync-judgement.md §2 (must-not-hold: outside the required set), §1 (Unjudged blobs): a
// peer's entry pulled under S of a commit S carries no body of here is judged under S all the
// same, but finally only past a complete pass of S begun after it came (status runs one: read
// wants it); then it leaves the own store with no tombstone.
#[test]
fn a_pulled_entry_outside_the_required_set_leaves_after_a_pass_spec_sync_judgement_2() {
    let mut w = W::new();
    w.g.done.insert(S, 0);
    let c = cid(40);
    w.pulled(c, &[S2], 40, 5);
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Unjudged), "no pass since it came");
    assert_eq!(w.read.passes_wanted().get(&S), Some(&5), "a pass of S begun after place 5 is wanted");
    assert_eq!(w.g.own(&S, &osis_engine::sync::BodyId::unit(c)).unwrap().len(), 1, "kept while it waits");
    w.pass(5);
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Unjudged), "a pass begun at its place counts not");
    w.pass(6);
    assert_eq!(w.read.verdict(&S, &c), None, "judged outside, dropped, no longer followed");
    assert_eq!(w.g.unlogged, vec![(S, BlobId([40; 32]))], "dropped with no tombstone");
    assert!(w.g.own_tombstones(&S, &osis_engine::sync::BodyId::unit(c)).unwrap().is_empty());
    assert!(w.read.passes_wanted().is_empty(), "no pass wanted any more");
}

// spec/sync-judgement.md §1 (Unjudged blobs: kept while it cannot judge them): while S's closure is
// not settled an entry is unjudged and wants no pass; settled, it waits a pass after what its
// bodies read last moved: a move during the wait (its commit coming under S) keeps it.
#[test]
fn an_unjudgeable_entry_is_kept_then_judged_spec_sync_judgement_1() {
    let mut w = W::new();
    w.g.done.insert(S, 0);
    w.g.unsettled.insert(S, ());
    let c = cid(41);
    w.pulled(c, &[S2], 41, 3);
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Unjudged));
    assert!(w.read.passes_wanted().is_empty(), "nothing to wait for while it cannot judge");
    w.g.unsettled.remove(&S);
    w.settle();
    assert_eq!(w.read.passes_wanted().get(&S), Some(&3));
    // what its bodies read moves at place 7 and S carries it: must-hold, never dropped
    w.g.place = 7;
    w.g.bodies.insert(c, Arc::new([(S, meta()), (S2, meta())].into()));
    w.settle();
    w.pass(8);
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Must));
    assert!(w.g.unlogged.is_empty(), "never dropped");
    assert_eq!(w.g.own(&S, &osis_engine::sync::BodyId::unit(c)).unwrap().len(), 1);
}

// spec/sync-judgement.md §3 (Own store: another's body is logged once a complete pass of S begun
// after what decides it last moved did): before S's first sync here ends, a peer's must-hold body
// waits for a pass begun after its bodies last moved; its bodies read again unchanged move
// nothing, so a pass begun before that read still ends the wait. Fails with every read of the
// bodies counted as a move: a node cut off from S's other holders, whose wait ends only at
// `PASS_WAIT_MS`, then waits a pass more each time its bodies are read again.
#[test]
fn a_body_read_again_unchanged_holds_back_no_log_spec_sync_judgement_3() {
    let mut w = W::new();
    w.g.first_syncing.insert(S, ());
    w.g.done.insert(S, 0);
    let c = cid(43);
    let mut f = uncovered();
    f.own = false;
    w.g.place = 5;
    w.hold(c, &[S], f);
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Must));
    assert_eq!(w.logs(S, c), 0, "held back until a pass begun after place 5");
    // the bodies read again, the same: something they read was written
    w.g.place = 7;
    w.g.bodies_read.insert(c, 1);
    w.settle();
    w.pass(6);
    assert_eq!(w.logs(S, c), 1, "a pass begun after the bodies last moved ends the wait");
}

// spec/sync-judgement.md §3 (Own store: a record blob, another's certificate, is logged before
// S's first sync here ends only once a complete pass of S begun after what decides it last moved
// did), spec/permissions.md §4 (Logging certificates): S's record blobs first followed at place
// 5, the records S carries move at place 7 (a commit under another sync ID names one more); a
// pass begun at 6 logs nothing, one begun at 8 logs the record blob of what S carries then.
// Fails with the wait counted from where S's record blobs were first followed: a new reader logs
// a record blob of the records it has learned so far, which loses to its source's once the rest
// arrive.
#[test]
fn a_record_blob_waits_a_pass_after_the_records_last_moved_spec_sync_judgement_3() {
    let mut w = W::new();
    let (r1, r2) = (osis_base::Tid::from_bytes([1; 15]), osis_base::Tid::from_bytes([2; 15]));
    w.g.first_syncing.insert(S, ());
    w.g.done.insert(S, 0);
    w.g.place = 5;
    w.g.carried.insert(S, Arc::new([r1].into()));
    w.g.records.insert(S, CertBlobsMissing { missing: [r1].into(), ..Default::default() });
    w.hold(cid(1), &[S], uncovered());
    assert!(w.g.record_logs.is_empty(), "held back until a pass begun after place 5");
    w.g.place = 7;
    w.g.carried.insert(S, Arc::new([r1, r2].into()));
    w.g.records.insert(S, CertBlobsMissing { missing: [r1, r2].into(), ..Default::default() });
    w.settle();
    w.pass(6);
    assert!(w.g.record_logs.is_empty(), "a pass begun before the records moved ends no wait");
    w.pass(8);
    assert_eq!(w.g.record_logs, vec![(S, [r1, r2].into())], "logged once a pass begun after the move ended");
}

// spec/sync-judgement.md §2, §3 (Own store): judged outside S wrongly (its bodies' inputs had
// settled and a pass ended, then a later arrival puts it under S), the entry left untombed, so
// the node logs the body again under S once S carries it.
#[test]
fn an_entry_judged_outside_then_listed_is_held_again_spec_sync_judgement_2() {
    let mut w = W::new();
    w.g.done.insert(S, 0);
    let c = cid(42);
    w.pulled(c, &[S2], 42, 2);
    w.pass(3);
    assert!(w.g.own(&S, &osis_engine::sync::BodyId::unit(c)).unwrap().is_empty(), "dropped as outside");
    w.g.place = 4;
    w.g.bodies.insert(c, Arc::new([(S, meta()), (S2, meta())].into()));
    w.settle();
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Must));
    assert!(w.g.logged.iter().any(|(s, x, _)| *s == S && *x == c), "logged again under S");
}

// spec/sync-judgement.md §2: one pulled entry outside S costs the same judgements whatever else is
// held (n and 10n bodies under S).
#[test]
fn a_pulled_entry_outside_s_costs_the_same_at_n_and_10n_spec_sync_judgement_2() {
    let mut costs = Vec::new();
    for n in [20u8, 200] {
        let mut w = W::new();
        w.g.done.insert(S, 0);
        for i in 0..n {
            let c = cidn(i, 2);
            w.g.bodies.insert(c, Arc::new([(S, meta())].into()));
            w.g.added.push(c);
        }
        w.exchange();
        osis_base::costs::take();
        w.pulled(cid(250), &[S2], 250, 9);
        w.pass(10);
        let [judged] = taken(["read: judged"]);
        assert!(w.g.unlogged.iter().any(|(_, b)| *b == BlobId([250; 32])));
        costs.push(judged);
    }
    assert_eq!(costs[0], costs[1], "judgements per pulled entry grow with the bodies held");
    assert!(costs[0] <= 10, "{costs:?}");
}

// spec/sync-judgement.md §2 (outside the required set: only at the end of a complete pass begun
// after what decides the commit's body under S last moved): a move of its bodies' inputs during
// the wait (still not under S) waits for a pass begun after it.
#[test]
fn a_move_of_its_bodies_inputs_restarts_the_wait_spec_sync_judgement_2() {
    let mut w = W::new();
    w.g.done.insert(S, 0);
    let c = cid(43);
    w.pulled(c, &[S2], 43, 2);
    w.g.place = 5;
    let mut m = meta();
    m.order = 2;
    w.g.bodies.insert(c, Arc::new([(S2, m)].into()));
    w.settle();
    w.pass(4);
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Unjudged), "a pass begun before the move counts not");
    assert_eq!(w.read.passes_wanted().get(&S), Some(&5));
    w.pass(6);
    assert_eq!(w.read.verdict(&S, &c), None);
    assert_eq!(w.g.unlogged.len(), 1);
}

/// The durable commits (engine store, sync store) of one node's start, run to quiet.
type Commits = (u64, u64);

/// Per node of `starts`: its first start's commits, the bodies it logged there that the session
/// did not, its quiet start's commits.
type Start = (Commits, BTreeSet<(SyncId, BlobId)>, Commits);

/// `history::shared(n)`, then every node restarts cut off from the others (its first start after
/// the session), run to quiet; then healed and run, every node restarts cut off again (a quiet
/// start), run to quiet. Per node a `Start` (bodies: the entries naming a commit and the own
/// entries, certificate blobs too, per sync ID read).
fn starts(n: usize) -> Vec<Start> {
    let mut w = crate::harness::history::shared(n);
    w.cap = crate::harness::WIDE_CAP;
    let bodies = |w: &mut crate::harness::World, i: usize| -> BTreeSet<(SyncId, BlobId)> {
        let mut out = BTreeSet::new();
        for (s, _) in w.store(i).syncs().into_iter().filter(|(_, (_, h))| *h == osis_engine::sync::Holding::Read) {
            for e in w.store(i).entries(&s).unwrap() {
                if e.own || w.engine(i).blob_commit(&e.blob).is_some() {
                    out.insert((s, e.blob));
                }
            }
        }
        out
    };
    let commits = |w: &mut crate::harness::World, i: usize| (w.engine(i).store_writes().committed, w.store(i).committed());
    // every node restarts cut off from the others, run to quiet: each node's commits
    let restart = |w: &mut crate::harness::World| {
        for i in 0..3 {
            w.power_off(i);
        }
        for (i, j) in [(0, 1), (0, 2), (1, 2)] {
            w.partition(i, j);
        }
        for i in 0..3 {
            w.power_on(i);
        }
        w.run();
        (0..3).map(|i| commits(w, i)).collect::<Vec<_>>()
    };
    let before: Vec<_> = (0..3).map(|i| bodies(&mut w, i)).collect();
    let first = restart(&mut w);
    let new: Vec<BTreeSet<_>> = (0..3).map(|i| bodies(&mut w, i).difference(&before[i]).copied().collect()).collect();
    w.heal();
    w.run();
    let quiet = restart(&mut w);
    first.into_iter().zip(new).zip(quiet).map(|((c, new), q)| (c, new, q)).collect()
}

// spec/sync-judgement.md §3 (own store: must-hold bodies are logged), spec/permissions.md §4
// (Logging certificates), spec/sync-set.md §3: a start judges what left the sync set by the
// whole set; a node logs what S must hold while it runs; no per-session growth (notes/growth.md).
// A start after a session finds nothing owed. A body a node could not wrap for S when
// first judged (no read epoch of S's thing held yet: a contact's profile read through a redeemed
// link) is logged in the session once it can, so a first start logs no body or certificate blob
// the session left unlogged; it commits the same at n and 10n things shared with a reader and a
// node keeping them unread; a start with nothing new after it commits nothing.
#[test]
fn a_start_after_a_session_finds_nothing_owed_at_n_and_10n_spec_sync_judgement_3() {
    let (a, b) = (starts(1), starts(10));
    for (i, (_, new, _)) in a.iter().chain(&b).enumerate() {
        assert!(new.is_empty(), "node {}: bodies a start logged that the session did not: {new:?}", i % 3);
    }
    let first = |x: &[Start]| x.iter().map(|y| y.0).collect::<Vec<_>>();
    assert_eq!(first(&a), first(&b), "(engine, store) commits per node's first start at n and 10n");
    let quiet: Vec<Commits> = a.iter().chain(&b).map(|y| y.2).collect();
    assert!(quiet.iter().all(|x| *x == (0, 0)), "(engine, store) commits per node's quiet start: {quiet:?}");
}



// spec/sync-judgement.md §2 (required set: a copy is in it by the deltas it holds, a header-only
// copy of a rotation while its account's chain is), spec/permissions.md §4 (Evidence of a commit:
// an account's rotations go as header-only copies): a certificate copy
// logged while S named its part stays while the body is must-hold as a header alone, until a
// complete pass after the move; then it leaves the own store with no tombstone, a header-only
// copy is logged in its place, and the old copy is deleted at K only once K holds another entry
// of it (never neither there).
#[test]
fn a_copy_holding_no_named_delta_leaves_for_a_header_copy_spec_sync_judgement_2() {
    let mut w = W::new();
    w.g.done.insert(S, 0);
    let c = cid(44);
    let mut f = uncovered();
    f.body.closure = false;
    let cert = BodyMeta { parts: [0].into(), copy: true, certificate: true, ..meta() };
    w.g.facts.insert((S, c), f);
    w.g.bodies.insert(c, Arc::new([(S, cert.clone())].into()));
    w.g.added.push(c);
    w.exchange();
    let old = w.g.logged.iter().find(|(s, x, _)| *s == S && *x == c).expect("logged").2;
    w.g.blobs.insert(old, Some(BlobInfo { parts: [0].into(), sealed: Default::default(), copy: true }));
    assert!(w.g.k.held.contains_key(&(S, old)), "K took it");
    // S names its header alone from place 5 on
    w.g.place = 5;
    w.g.bodies.insert(c, Arc::new([(S, BodyMeta { parts: BTreeSet::new(), header_only: true, ..cert })].into()));
    w.exchange();
    assert_eq!(w.read.verdict(&S, &c), Some(Verdict::Must));
    assert_eq!(w.logs(S, c), 1, "the copy stands while no pass ended");
    assert_eq!(w.read.passes_wanted().get(&S), Some(&5));
    assert_eq!(w.deletes(), 0);
    w.pass(6);
    assert_eq!(w.g.unlogged, vec![(S, old)], "the copy left with no tombstone");
    assert_eq!(w.logs(S, c), 2, "a header-only copy logged in its place");
    let new = w.g.logged.last().unwrap().2;
    w.g.blobs.insert(new, Some(BlobInfo { parts: BTreeSet::new(), sealed: Default::default(), copy: true }));
    // K holding the old copy alone keeps it: never neither the old copy nor its replacement there
    w.pulls = false;
    w.exchange();
    assert!(!w.sent().any(|m| *m == Sent::Delete(KC, old)), "the copy deleted at K before K holds the header-only copy");
    w.pulls = true;
    w.exchange();
    w.exchange();
    assert!(w.g.k.held.contains_key(&(S, new)), "K took the header-only copy");
    assert!(w.sent().any(|m| *m == Sent::Delete(KC, old)), "the copy deleted at K");
    assert!(!w.sent().any(|m| *m == Sent::Delete(KC, new)), "the header-only copy deleted at K");
}

// spec/permissions.md §3 (deposit-only): a step due by a newer role is issued at once; a
// deposit-only one only past a complete pass of S begun after it came due (status runs it), so a
// co-admin's newer seed logged under S is opened first and the node never steps back to a key a
// departed party knows. Its seed refreshed again while it waits (a co-admin refreshing at will)
// keeps the place it came due at, so one pass bounds the wait.
#[test]
fn a_deposit_only_step_waits_a_complete_pass_spec_permissions_3() {
    let mut w = W::new();
    w.g.done.insert(S, 0);
    w.g.step.insert(S, StepReady::Now);
    w.hold(cid(60), &[S], uncovered());
    assert_eq!(w.g.issued, vec![S], "due by a newer role: issued at once");
    w.g.place = 5;
    w.g.step.insert(S, StepReady::AfterPass);
    w.hold(cid(61), &[S], uncovered());
    assert_eq!(w.g.issued, vec![S], "deposit-only: waits");
    assert_eq!(w.read.passes_wanted().get(&S), Some(&5), "a pass of S begun after place 5 is wanted");
    for place in 6..40 {
        w.g.place = place;
        w.g.step.insert(S, StepReady::AfterPass);
        w.hold(cid(place as u8 + 100), &[S], uncovered());
    }
    assert_eq!(w.g.issued, vec![S], "refreshed again while it waits: still waiting");
    assert_eq!(w.read.passes_wanted().get(&S), Some(&5), "for the pass it first came due before");
    w.pass(5);
    assert_eq!(w.g.issued, vec![S], "a pass begun at its place counts not");
    w.pass(6);
    assert_eq!(w.g.issued, vec![S, S], "issued once the pass ended");
}
