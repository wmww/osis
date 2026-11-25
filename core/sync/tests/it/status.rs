//! Status (spec/sync-status.md) on a fake ground: streams' caught up, full and refusals, opens'
//! reported positions and records, read's verdicts, the store's own entries and the engine's
//! own commits, self-removals and wanted passes, each a stamped value, so `Status` follows them
//! as in a node. Sources come and go as opens' `Moved` would bring them (`joined`, `left`).

use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_engine::sync::{Holding, Stranding, SyncSet};
use osis_proto::limits::PASS_WAIT_MS;
use osis_sync::Result;
use osis_sync::read::Verdict;
use osis_sync::status::{Ground, Net, Src, Status, Up};
use osis_sync::store::Source;
use osis_sync::types::{ConnId, Position, RecordId, Scope, SourceClass, Waiting};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const S: SyncId = SyncId([1; 16]);
const A: ConnId = ConnId(1);
const B: ConnId = ConnId(2);
const RA: RecordId = [0xa; 16];
const RB: RecordId = [0xb; 16];

fn blob(i: u8) -> BlobId {
    BlobId([i; 32])
}

fn cid(i: u8) -> CommitId {
    CommitId([i; 32])
}

fn sid(i: u32) -> SyncId {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&i.to_le_bytes());
    b[15] = 0x77;
    SyncId(b)
}

fn tid(i: u8) -> Tid {
    Tid::from_bytes([i; 15])
}

fn reader(r: RecordId, account: u8) -> Src {
    Src { class: SourceClass::Reader, at: Source::Record(r), node: Some(tid(account)) }
}

fn store(r: RecordId) -> Src {
    Src { class: SourceClass::Store, at: Source::Record(r), node: None }
}

#[derive(Default)]
struct Fake {
    /// The monotonic clock, and the wall clock but where `wall` reads otherwise.
    now: u64,
    /// The wall clock where it is not `now` (frozen, set back).
    wall: Option<u64>,
    set: Stamped<(), Arc<SyncSet>>,
    caught: Stamped<(ConnId, SyncId), WallMs>,
    full: StampedSet<(ConnId, SyncId)>,
    refused: StampedSet<(Source, SyncId, BlobId)>,
    stranded: StampedSet<SyncId>,
    stamped: Stamped<SyncId, Vec<BlobId>>,
    knows: StampedSet<(Source, SyncId, BlobId)>,
    reported: Stamped<(ConnId, SyncId), Position>,
    until: Stamped<(ConnId, SyncId), Position>,
    records: Stamped<SyncId, BTreeSet<RecordId>>,
    own: StampedSet<(SyncId, CommitId)>,
    removals: Stamped<(), Arc<BTreeSet<CommitId>>>,
    verdicts: Stamped<(SyncId, CommitId), Verdict>,
    entries: Stamped<(SyncId, CommitId), Vec<BlobId>>,
    first: Stamped<(SyncId, BlobId), Position>,
    elsewhere: StampedSet<(SyncId, BlobId)>,
    /// Sync IDs some peer other than this account's own nodes is to be waited for on (opens'
    /// `waited`).
    shared: StampedSet<SyncId>,
    /// Sync IDs only this account's own nodes are to be waited for on.
    own_shared: StampedSet<SyncId>,
    told_held: Vec<CommitId>,
    /// (self-removal, node): a peer proving the node holds no role on what the leave left
    /// (`counts_for`).
    leaving: BTreeSet<(CommitId, Tid)>,
    /// The engine's wants, by pass place; the fake's places are its ms (`begin_pass`).
    wanted: Stamped<(), Arc<BTreeMap<SyncId, u64>>>,
    /// Leave's waits, by pass place (`leave_passes`).
    leave: Stamped<(), Arc<BTreeMap<SyncId, u64>>>,
    passes: Vec<(SyncId, u64)>,
    /// The pass starts kept durably (`set_pass_begun`): what a restart keeps.
    begun: BTreeMap<SyncId, WallMs>,
    /// Calls to `stamped` (lacking counts taken).
    stamped_reads: u64,
    /// The engine's `stranded` per read S.
    strandings: Stamped<SyncId, Arc<Stranding>>,
    /// Opens' walk stops per S.
    stops: Stamped<SyncId, osis_sync::opens::Stop>,
}

impl Net for Fake {
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<u64> {
        self.caught.get(&(conn, *s)).map(|t| t.0)
    }
    /// The fake places a Pull by when it was sent, one per millisecond at most: one sent in the
    /// millisecond a pass begins counts as after it.
    fn pull_seq(&self) -> u64 {
        self.now.saturating_sub(1)
    }
    fn full(&self, conn: ConnId, s: &SyncId) -> bool {
        self.full.contains(&(conn, *s))
    }
    fn refusing(&self, at: Source, s: &SyncId) -> bool {
        self.refused.iter().any(|(a, x, _)| *a == at && x == s)
    }
    fn stranded(&self, s: &SyncId) -> bool {
        self.stranded.contains(s)
    }
}

impl Ground for Fake {
    fn mono(&self) -> osis_base::Mono {
        osis_base::Mono(self.now)
    }
    fn now(&self) -> WallMs {
        WallMs(self.wall.unwrap_or(self.now))
    }
    fn passes_begun(&mut self) -> Result<BTreeMap<SyncId, WallMs>> {
        Ok(self.begun.clone())
    }
    fn set_pass_begun(&mut self, s: &SyncId, at: Option<WallMs>) -> Result<()> {
        match at {
            Some(at) => self.begun.insert(*s, at),
            None => self.begun.remove(s),
        };
        Ok(())
    }
    fn syncs(&mut self) -> Arc<SyncSet> {
        self.set.get(&()).cloned().unwrap_or_default()
    }
    fn stamped(&mut self, s: &SyncId) -> Result<Vec<BlobId>> {
        self.stamped_reads += 1;
        Ok(self.stamped.get(s).cloned().unwrap_or_default())
    }
    fn knows(&self, at: Source, _conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.knows.contains(&(at, *s, *b))
    }
    fn knows_now(&self, at: Source, s: &SyncId, b: &BlobId) -> bool {
        self.knows.contains(&(at, *s, *b))
    }
    fn until(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.until.get(&(conn, *s)).copied()
    }
    fn reported(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.reported.get(&(conn, *s)).copied()
    }
    fn records_holding(&mut self, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        Ok(self.records.get(s).cloned().unwrap_or_default())
    }
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(Arc::new(self.own.iter().filter(|x| x.0 == *s).map(|x| x.1).collect()))
    }
    fn own_feed(&mut self) -> osis_engine::sync::OwnFeed {
        (self.own.feed(), self.own.removals())
    }
    fn follow_own(&mut self) -> Result<()> {
        Ok(())
    }
    fn own_has(&mut self, s: &SyncId, c: &CommitId) -> bool {
        self.own.contains(&(*s, *c))
    }
    fn self_removals(&mut self) -> Arc<BTreeSet<CommitId>> {
        self.removals.get(&()).cloned().unwrap_or_default()
    }
    fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict> {
        self.verdicts.get(&(*s, *c)).cloned()
    }
    fn commit_entries(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>> {
        Ok(self.entries.get(&(*s, *c)).cloned().unwrap_or_default())
    }
    fn first_logged(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<Position>> {
        Ok(self.first.get(&(*s, *b)).copied())
    }
    fn elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<bool> {
        Ok(self.elsewhere.contains(&(*s, *b)))
    }
    fn set_elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<()> {
        self.elsewhere.insert((*s, *b));
        Ok(())
    }
    fn waited(&mut self, s: &SyncId, own: bool) -> Result<bool> {
        Ok(self.shared.contains(s) || (own && self.own_shared.contains(s)))
    }
    fn counts_for(&mut self, c: &CommitId, node: Option<Tid>) -> bool {
        node.is_none_or(|n| !self.leaving.contains(&(*c, n)))
    }
    fn removal_done(&mut self, c: &CommitId) -> Result<()> {
        self.told_held.push(*c);
        let mut r = self.removals.get(&()).map(|x| (**x).clone()).unwrap_or_default();
        r.remove(c);
        self.removals.insert((), Arc::new(r));
        Ok(())
    }
    fn pass_wanted(&mut self, s: &SyncId) -> Result<Option<u64>> {
        Ok(self.wanted.get(&()).and_then(|m| m.get(s).copied()))
    }
    fn begin_pass(&mut self) -> u64 {
        self.now
    }
    fn leave_passes(&mut self) -> Arc<BTreeMap<SyncId, u64>> {
        self.leave.get(&()).cloned().unwrap_or_default()
    }
    fn stranding(&mut self, s: &SyncId) -> Result<Option<Arc<Stranding>>> {
        Ok(self.strandings.get(s).cloned())
    }
    fn walk_stop(&self, s: &SyncId) -> Option<osis_sync::opens::Stop> {
        self.stops.get(s).copied()
    }
    fn walk_stranding(&mut self, _s: &SyncId, step: osis_sync::opens::Stop) -> Result<Option<Arc<Stranding>>> {
        Ok(Some(Arc::new(Stranding { step: step.unwrap_or([7; 32]), ..(*stranding()).clone() })))
    }
    fn note_complete_pass(&mut self, s: &SyncId, began: u64) -> Result<()> {
        self.passes.push((*s, began));
        let mut w = self.wanted.get(&()).map(|x| (**x).clone()).unwrap_or_default();
        if w.get(s).is_some_and(|t| *t < began) {
            w.remove(s);
            self.wanted.insert((), Arc::new(w));
        }
        Ok(())
    }
}

struct T {
    st: Status,
    g: Fake,
    pulls: Vec<ConnId>,
    /// The record each connection holds.
    on: BTreeMap<ConnId, Source>,
}

impl T {
    /// A node holding `ids` (read, or kept unread).
    fn new(ids: &[(SyncId, Holding)]) -> T {
        let mut g = Fake::default();
        g.set.insert((), Arc::new(SyncSet { ids: ids.iter().map(|(s, h)| (*s, ([tid(9)].into(), *h))).collect(), unsyncable: BTreeSet::new() }));
        let mut t = T { st: Status::default(), g, pulls: Vec::new(), on: BTreeMap::new() };
        t.settle();
        t
    }

    fn settle(&mut self) {
        for _ in 0..16 {
            if !self.st.settle_on(&mut self.g, &mut self.pulls).unwrap() {
                return;
            }
        }
        panic!("status's settle does not end");
    }

    fn at(&mut self, now: u64) {
        self.g.now = now;
        self.settle();
    }

    /// `conn` holds `src`'s record (as `Moved::Taken`) and S is a member of it (as a member
    /// opening).
    fn join(&mut self, s: SyncId, conn: ConnId, src: Src) {
        self.st.taken(src.at, Up { conn, node: src.node });
        self.on.insert(conn, src.at);
        self.st.opened(s, src.at, src.class);
        self.settle();
    }

    /// `conn` lets its record go (as `Moved::Released`): it keeps its members.
    fn release(&mut self, conn: ConnId) {
        if let Some(src) = self.on.remove(&conn) {
            self.st.released(src);
        }
    }

    fn caught(&mut self, conn: ConnId, s: SyncId, since: u64) {
        self.g.caught.insert((conn, s), WallMs(since));
        self.settle();
    }

    fn heard_out(&self, s: SyncId) -> bool {
        self.st.heard_out(&s, &self.g)
    }

    fn wait(&self, s: SyncId) -> bool {
        self.st.of(&s, &self.g).is_some_and(|x| x.synced())
    }

    /// Own commit `c` under S, must-hold, logged as `b` first at position `pos`.
    fn own(&mut self, s: SyncId, c: CommitId, b: BlobId, pos: Position) {
        self.g.verdicts.insert((s, c), Verdict::Must);
        self.g.entries.insert((s, c), vec![b]);
        self.g.first.insert((s, b), pos);
        self.g.own.insert((s, c));
        self.settle();
    }
}

// spec/sync-status.md §1 (unconnected): with no source S is unconnected, one state, never synced;
// a kept-unread sync ID has its row too (§3).
#[test]
fn unconnected_is_never_synced() {
    let u = sid(2);
    let t = T::new(&[(S, Holding::Read), (u, Holding::Unread)]);
    let st = t.st.of(&S, &t.g).unwrap();
    assert!(st.sources.is_empty() && !st.heard_out() && !st.synced());
    let ku = t.st.of(&u, &t.g).unwrap();
    assert_eq!(ku.holding, Some(Holding::Unread));
    assert!(ku.sources.is_empty() && !ku.synced());
    assert_eq!(t.st.all(&t.g).len(), 2);
}

// spec/sync-status.md §1 (heard out): S is heard out when every source is caught up; readers are
// counted by identity, never by connection.
#[test]
fn heard_out_when_every_source_caught_up() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.join(S, B, reader(RB, 1));
    assert!(!t.heard_out(S));
    t.caught(A, S, 0);
    assert!(!t.heard_out(S), "one source not caught up");
    t.caught(B, S, 0);
    assert!(t.heard_out(S));
    let st = t.st.of(&S, &t.g).unwrap();
    assert_eq!(st.readers(), [tid(1)].into(), "two connections of one account: one reader");
    t.release(A);
    t.release(B);
    t.settle();
    assert!(!t.heard_out(S), "nobody connected: not heard out");
}

// spec/sync-status.md §1 (full or refusing): a full or refusing source is named and not waited
// on; it counts as lacking what it lacks.
#[test]
fn full_or_refusing_source_named_not_waited_on() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.join(S, B, store(RB));
    t.caught(A, S, 0);
    assert!(!t.heard_out(S));
    t.g.full.insert((B, S));
    t.settle();
    assert!(t.heard_out(S), "a full source is not waited on");
    let st = t.st.of(&S, &t.g).unwrap();
    assert!(st.sources[&B].full && !st.sources[&B].caught_up);
    t.g.full.remove(&(B, S));
    t.g.refused.insert((Source::Record(RB), S, blob(1)));
    t.settle();
    assert!(t.heard_out(S) && t.st.of(&S, &t.g).unwrap().sources[&B].refusing);
    // with only sources that do not take S, nothing is heard out
    t.release(A);
    t.settle();
    assert!(!t.heard_out(S), "only a refusing source");
}

// spec/sync-status.md §1 (lacks): a source lacks an entry only for what it would pull: a source
// keeping S unread the stamped entries here its stream did not show; a reader nothing. The count
// follows what the source shows.
#[test]
fn lacking_counted_by_what_a_source_pulls() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.stamped.insert(S, vec![blob(1), blob(2), blob(3)]);
    t.join(S, A, reader(RA, 1));
    t.join(S, B, store(RB));
    t.g.knows.insert((Source::Record(RB), S, blob(1)));
    t.settle();
    let st = t.st.of(&S, &t.g).unwrap();
    assert_eq!((st.sources[&A].lacking, st.sources[&B].lacking), (0, 2));
    t.g.knows.insert((Source::Record(RB), S, blob(2)));
    t.settle();
    assert_eq!(t.st.of(&S, &t.g).unwrap().sources[&B].lacking, 1);
    let reads = t.g.stamped_reads;
    t.settle();
    t.at(5);
    assert_eq!(t.g.stamped_reads, reads, "nothing taken again while nothing moved");
}

// spec/sync-status.md §1 (lacks), spec/sync.md §2 (work in proportion to change): a store
// source's lacking count is kept per record: its connection letting the record go and another
// taking it count nothing again; S leaving the record (also while no connection holds it), or the
// record going, lets it go.
#[test]
fn lacking_is_kept_per_record_across_connections_spec_sync_status_1() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.stamped.insert(S, vec![blob(1), blob(2)]);
    t.join(S, B, store(RB));
    t.settle();
    let reads = t.g.stamped_reads;
    t.release(B);
    t.join(S, ConnId(3), store(RB));
    t.settle();
    assert_eq!(t.g.stamped_reads, reads, "a reconnect counts nothing again");
    assert_eq!(t.st.of(&S, &t.g).unwrap().sources[&ConnId(3)].lacking, 2);
    t.st.record_gone(RB);
    t.g.stamped.insert(S, vec![blob(1)]);
    t.settle();
    assert_eq!(t.g.stamped_reads, reads, "the record gone: counted no more");
    // S leaves the record while no connection holds it
    t.join(S, ConnId(4), store(RB));
    t.settle();
    let reads = t.g.stamped_reads;
    t.release(ConnId(4));
    t.st.gone(RB, S);
    t.g.stamped.insert(S, vec![blob(2)]);
    t.settle();
    assert_eq!(t.g.stamped_reads, reads, "S gone from the record: counted no more");
}

// spec/sync-status.md §2 (held elsewhere: a report from a source): a reader's report and the
// close that follows it in one step (a peer that judges this node departed by the self-removal it
// just applied closes S at once) still count: the source's position as it left is judged at the
// next settle, then nothing of it is kept.
#[test]
fn a_report_counts_when_its_source_leaves_in_the_same_step() {
    use osis_sync::opens::LeftAt;
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.own(S, cid(1), blob(1), 5);
    t.own(S, cid(2), blob(2), 7);
    t.st.left(S, A, LeftAt { src: Source::Record(RA), reported: Some(6), until: None, how: osis_sync::opens::Leaving::Kept });
    t.settle();
    assert!(t.st.held(&cid(1)), "reported at 6 as it left");
    assert!(!t.st.held(&cid(2)), "first logged at 7, past the report");
    t.st.left(S, B, LeftAt { src: Source::Record(RB), reported: Some(9), until: None, how: osis_sync::opens::Leaving::Kept });
    t.settle();
    assert!(!t.st.held(&cid(2)), "a leave of no source counts for nothing");
}

// spec/sync-status.md §2 (held elsewhere): an own commit is held elsewhere once a source's stream
// showed its entry or a source reported a position at or past where this node's log first held
// it (shown: `store_source_counts_by_its_stream`); the report is recorded on the entry and
// outlives the source's connection.
#[test]
fn own_commit_held_elsewhere_by_report() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 0);
    t.own(S, cid(1), blob(1), 5);
    assert_eq!(t.st.of(&S, &t.g).unwrap().unheld, Some(1));
    assert!(!t.wait(S) && !t.st.held(&cid(1)), "heard out, but its own commit is only here");
    t.g.reported.insert((A, S), 4);
    t.settle();
    assert!(!t.st.held(&cid(1)), "a report below where the log first held it");
    t.g.reported.insert((A, S), 5);
    t.settle();
    assert!(t.st.held(&cid(1)) && t.wait(S));
    assert!(t.g.elsewhere.contains(&(S, blob(1))), "recorded on the entry");
    t.release(A);
    t.g.reported.remove(&(A, S));
    t.settle();
    assert!(t.st.held(&cid(1)), "the record outlives the source");
}

// spec/sync-status.md §2 (never one keeping S unread): a store source: a source keeping S unread holds a writer's entry once
// its stream shows it; its reported position says nothing (it applies past what it refused for
// room or does not pull), so a writer's wait ends on its stream alone.
#[test]
fn store_source_counts_by_its_stream() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, B, store(RB));
    t.caught(B, S, 0);
    t.own(S, cid(1), blob(1), 3);
    t.g.full.insert((B, S));
    t.g.reported.insert((B, S), 10);
    t.settle();
    assert!(!t.st.held(&cid(1)), "a full store applied past it");
    t.g.full.remove(&(B, S));
    t.settle();
    assert!(!t.st.held(&cid(1)) && !t.wait(S), "its position alone");
    t.g.knows.insert((Source::Record(RB), S, blob(1)));
    t.settle();
    assert!(t.st.held(&cid(1)) && t.wait(S), "its stream shows it");
}

// spec/sync-status.md §2 (until): a reader's member being ended counts only the entries first
// logged at or below its `until`.
#[test]
fn ending_member_counts_up_to_its_until() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 0);
    t.g.until.insert((A, S), 4);
    t.own(S, cid(1), blob(1), 5);
    t.g.reported.insert((A, S), 10);
    t.settle();
    assert!(!t.st.held(&cid(1)), "logged past its until: never served it");
    t.own(S, cid(2), blob(2), 4);
    assert!(t.st.held(&cid(2)), "logged at its until");
}

// spec/sync-status.md §2 (must hold): only what S must hold of the commit waits.
#[test]
fn nothing_to_hold_is_held() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.own(S, cid(1), blob(1), 1);
    assert!(!t.st.held(&cid(1)));
    t.g.verdicts.insert((S, cid(1)), Verdict::May);
    t.settle();
    assert!(t.st.held(&cid(1)));
}

// spec/sync-status.md §2 (By a source's report: recorded whatever it judges the commit must hold
// now): a may-hold or must-not-hold own commit counts held for status at once, but its entry is
// recorded held elsewhere, which a leave and a loss by an `until` read, by the same evidence as a
// must-hold one: a store's position, a report below where the log first held it and one past an
// ending member's `until` record nothing; a reader's report at or past it, or a stream showing
// it, does.
#[test]
fn may_hold_commit_recorded_only_by_a_source_holding_it_spec_sync_status_2() {
    for v in [Verdict::May, Verdict::MustNot(osis_sync::read::Why::OutsideRequired)] {
        let mut t = T::new(&[(S, Holding::Read)]);
        t.join(S, A, reader(RA, 1));
        t.join(S, B, store(RB));
        t.caught(A, S, 0);
        t.caught(B, S, 0);
        t.g.until.insert((A, S), 6);
        t.own(S, cid(1), blob(1), 5);
        t.own(S, cid(2), blob(2), 7);
        for c in [1, 2] {
            t.g.verdicts.insert((S, cid(c)), v.clone());
        }
        t.g.reported.insert((A, S), 4);
        t.g.reported.insert((B, S), 9);
        t.settle();
        assert!(t.st.held(&cid(1)) && t.st.held(&cid(2)), "{v:?}: nothing S must hold");
        assert!(t.g.elsewhere.is_empty(), "{v:?}: recorded with no source holding it");
        t.g.reported.insert((A, S), 9);
        t.settle();
        assert!(t.g.elsewhere.contains(&(S, blob(1))), "{v:?}: a reader reported past it");
        assert!(!t.g.elsewhere.contains(&(S, blob(2))), "{v:?}: logged past the ending member's until");
        t.g.knows.insert((Source::Record(RB), S, blob(2)));
        t.settle();
        assert!(t.g.elsewhere.contains(&(S, blob(2))), "{v:?}: a stream shows it");
    }
}

/// The engine wants a pass of S begun at or after ms `since` (after place `since - 1`: what it
/// waits on arrived before a pass begun in that ms).
fn want(t: &mut T, s: SyncId, since: u64) {
    let mut w = t.g.wanted.get(&()).map(|x| (**x).clone()).unwrap_or_default();
    w.insert(s, since.saturating_sub(1));
    t.g.wanted.insert((), Arc::new(w));
    t.settle();
}

// spec/sync-status.md §1 (complete pass): a pass ends once every source's stream was read to its
// end from a Pull sent after it began (one is asked at each), and each peer whose record holds
// S was read at its next connection; caught up from an earlier Pull counts for nothing.
#[test]
fn complete_pass_needs_fresh_pulls_and_recorded_peers() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 0);
    t.g.records.insert(S, [RA, RB].into());
    t.at(100);
    want(&mut t, S, 100);
    assert_eq!(t.pulls, vec![A], "a fresh Pull at each source");
    assert_eq!(t.st.of(&S, &t.g).unwrap().pass_waits, Some([RA, RB].into()));
    assert!(t.g.passes.is_empty(), "caught up from a Pull before the pass");
    t.caught(A, S, 100);
    assert_eq!(t.st.of(&S, &t.g).unwrap().pass_waits, Some([RB].into()), "RA read since");
    assert!(t.g.passes.is_empty(), "RB not read since");
    t.join(S, B, reader(RB, 2));
    t.caught(B, S, 120);
    assert_eq!(t.g.passes, vec![(S, 100)]);
    assert_eq!(t.st.of(&S, &t.g).unwrap().pass_waits, None);
}

// spec/sync-set.md §3 (Release): a leave waits for the pass in flight with the connected sources
// only: a fresh Pull at each, ended once each is caught up from it, while a complete pass of S
// begun before the leave still waits for a recorded peer that is not connected (it would hold
// the leave for PASS_WAIT_MS, then for another pass after it).
#[test]
fn a_leave_waits_for_the_connected_sources_only_spec_sync_set_3() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 0);
    t.g.records.insert(S, [RA, RB].into());
    t.at(100);
    want(&mut t, S, 100);
    t.pulls.clear();
    t.at(200);
    t.g.leave.insert((), Arc::new(BTreeMap::from([(S, 150)])));
    t.settle();
    assert_eq!(t.pulls, vec![A], "a fresh Pull at the connected source");
    assert!(!t.st.heard_since(&S, 150), "caught up from a Pull before the leave");
    t.caught(A, S, 200);
    assert!(t.st.heard_since(&S, 150), "the connected source caught up since: RB not waited for");
    assert_eq!(t.st.of(&S, &t.g).unwrap().pass_waits, Some([RB].into()), "the complete pass still waits for RB");
    assert!(!t.st.passed_since(&S, 150));
}

// spec/sync-status.md §1 (complete pass): with no source and no peer to be waited for on S, a pass ends at once.
#[test]
fn complete_pass_with_nobody_ends_at_once() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.at(7);
    want(&mut t, S, 7);
    assert_eq!(t.g.passes, vec![(S, 7)]);
}

// spec/sync-status.md §1 (complete pass): with no source, a
// peer to be waited for (an own node counts) holds the pass until it is no more, or a source
// catches up, or PASS_WAIT_MS.
#[test]
fn complete_pass_with_no_source_waits_for_a_peer_to_be_waited_for() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.own_shared.insert(S);
    t.at(7);
    want(&mut t, S, 7);
    assert!(t.g.passes.is_empty(), "an own node to be waited for");
    t.g.own_shared.remove(&S);
    t.settle();
    assert_eq!(t.g.passes, vec![(S, 7)], "none left to wait for");
    t.g.shared.insert(S);
    t.at(20);
    want(&mut t, S, 20);
    assert!(t.g.passes[1..].is_empty());
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 20);
    assert_eq!(t.g.passes, vec![(S, 7), (S, 20)], "a source caught up since");
    t.release(A);
    t.at(30);
    want(&mut t, S, 30);
    t.at(30 + PASS_WAIT_MS);
    assert_eq!(t.g.passes, vec![(S, 7), (S, 20), (S, 30)], "PASS_WAIT_MS");
}

/// S read, its record of peer B away, a pass wanted at monotonic 10 (the wall clock at `wall`).
fn away_pass(wall: Option<u64>) -> T {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.records.insert(S, [RB].into());
    t.g.wall = wall;
    t.at(10);
    want(&mut t, S, 10);
    t
}

// spec/sync-status.md §1 (PASS_WAIT_MS; the wait runs on the monotonic clock): a recorded peer
// away holds a pass no longer than PASS_WAIT_MS, a wall clock frozen while the node runs
// included; the node wakes for it.
#[test]
fn complete_pass_gives_up_on_away_peer() {
    let mut t = away_pass(Some(10));
    assert!(t.g.passes.is_empty());
    assert_eq!(t.st.next_wake(), Some(osis_base::Mono(10 + PASS_WAIT_MS)));
    t.at(10 + PASS_WAIT_MS - 1);
    assert!(t.g.passes.is_empty());
    t.at(10 + PASS_WAIT_MS);
    assert_eq!(t.g.passes, vec![(S, 10)]);
}

// spec/sync-status.md §1 (PASS_WAIT_MS: a pass's start is dated durably, outliving a restart): a
// node restarting more often than PASS_WAIT_MS with a recorded peer away begins the pass under way
// at the stop again from when it began, so it ends PASS_WAIT_MS after that, and its row goes.
// Fails with a pass's deadline counted from each start.
#[test]
fn a_pass_under_way_at_a_restart_ends_by_its_first_start_spec_sync_status_1() {
    let mut t = away_pass(None);
    assert_eq!(t.g.begun, [(S, WallMs(10))].into(), "its start is kept");
    for k in 1..4 {
        t.st = Status::default();
        t.at(10 + k * PASS_WAIT_MS / 4);
        assert!(t.g.passes.is_empty(), "restart {k}: under way");
        assert_eq!(t.st.of(&S, &t.g).unwrap().pass_waits, Some([RB].into()), "restart {k}: begun again");
        assert_eq!(t.st.next_wake(), Some(osis_base::Mono(10 + PASS_WAIT_MS)), "restart {k}");
    }
    t.at(10 + PASS_WAIT_MS);
    assert_eq!(t.g.passes.len(), 1, "ended at its first start's deadline");
    assert!(t.g.begun.is_empty(), "its row goes with it");
}

// spec/sync-status.md §1 (PASS_WAIT_MS: a pass's start is dated durably): a sync ID leaving the
// sync set takes its pass under way and its start row with it, at once (none left: no row left).
#[test]
fn a_sync_id_leaving_takes_its_pass_and_row_spec_sync_status_1() {
    let mut t = away_pass(None);
    assert!(t.st.of(&S, &t.g).unwrap().pass_waits.is_some());
    t.g.set.insert((), Arc::new(SyncSet::default()));
    t.settle();
    assert!(t.g.begun.is_empty(), "no row left");
    t.at(10 + PASS_WAIT_MS);
    assert!(t.g.passes.is_empty() && t.g.begun.is_empty(), "no pass left to end");
}

// spec/sync-status.md §1 (PASS_WAIT_MS: a pass begun again having waited what the wall clock
// shows): the wall clock set back at every restart, a quarter of PASS_WAIT_MS apart. Set back past
// the row, it counts as now and the row is rewritten so; set back by less than a run, the wait
// credited adds up, and the run after the restart crediting 3/4 of PASS_WAIT_MS ends the pass.
// Each run waits at most PASS_WAIT_MS on the monotonic clock. Fails with the row not rewritten.
#[test]
fn a_wall_clock_set_back_at_each_restart_still_ends_a_pass_spec_sync_status_1() {
    const Q: u64 = PASS_WAIT_MS / 4;
    let w0 = 10 * PASS_WAIT_MS;
    let mut t = away_pass(Some(w0));
    assert_eq!(t.g.begun, [(S, WallMs(w0))].into());
    // the run waits a quarter; the clock is set back a half across the restart: ahead of the row
    let mut wall = w0 + Q - 2 * Q;
    let mut mono = 10 + Q;
    t.st = Status::default();
    t.g.wall = Some(wall);
    t.at(mono);
    assert_eq!(t.g.begun, [(S, WallMs(wall))].into(), "a row ahead of the wall clock counts as now");
    assert_eq!(t.st.next_wake(), Some(osis_base::Mono(mono + PASS_WAIT_MS)), "nothing credited");
    // then each run a quarter on both clocks, the clock set back an eighth at each restart: an
    // eighth more credited per restart, so the run after the 6th ends it
    for k in 1..=7u64 {
        mono += Q;
        wall += Q;
        t.g.wall = Some(wall);
        t.at(mono);
        assert_eq!(t.g.passes.len(), usize::from(k == 7), "run {k}");
        if k == 7 {
            break;
        }
        wall -= Q / 2;
        t.st = Status::default();
        t.g.wall = Some(wall);
        t.at(mono);
        assert_eq!(t.st.next_wake(), Some(osis_base::Mono(mono + PASS_WAIT_MS - k * Q / 2)), "restart {k}: credited");
    }
    assert!(t.g.begun.is_empty(), "its row goes with it");
}

// spec/sync-status.md §1 (complete pass, spec/permissions.md §3 Complete pass): a pass under way
// that began before the moment the engine wants one after ends nothing for it: another begins
// when it ends.
#[test]
fn pass_begun_before_the_moment_counts_for_nothing() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.at(10);
    want(&mut t, S, 10);
    t.at(20);
    want(&mut t, S, 20);
    t.pulls.clear();
    t.caught(A, S, 10);
    assert_eq!(t.g.passes, vec![(S, 10)]);
    assert_eq!(t.pulls, vec![A], "the next pass asks again");
    // a third moment while the second pass is under way queues one pass, not one per moment
    t.at(30);
    want(&mut t, S, 30);
    t.at(40);
    want(&mut t, S, 40);
    t.caught(A, S, 20);
    assert_eq!(t.g.passes, vec![(S, 10), (S, 20)]);
    t.caught(A, S, 40);
    assert_eq!(t.g.passes, vec![(S, 10), (S, 20), (S, 40)], "one pass for both");
    assert!(t.g.wanted.get(&()).unwrap().is_empty());
}

// spec/sync-status.md §2 (held elsewhere): a peer counts for a self-removal only where a thing it proved holds a role on
// the thing left with the leave applied. The account's other node, leaving by the same commit,
// reports past it and counts nothing; a staying reader's report does. Roles-model leave, control
// `-any-source`.
#[test]
fn a_leave_reported_only_by_a_leaving_peer_is_not_held_elsewhere_spec_sync_status_2() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.leaving.insert((cid(1), tid(1)));
    t.join(S, A, reader(RA, 1));
    t.join(S, B, reader(RB, 2));
    t.caught(A, S, 0);
    t.caught(B, S, 0);
    t.own(S, cid(1), blob(1), 5);
    t.g.reported.insert((A, S), 9);
    t.settle();
    assert!(!t.st.held(&cid(1)), "the leaving peer's report holds nothing");
    t.g.reported.insert((B, S), 9);
    t.settle();
    assert!(t.st.held(&cid(1)), "a staying peer's does");
}
// spec/sync-status.md §3 (wait): `wait` ends when every sync ID in scope is heard out with its own
// commits held elsewhere, or shared by no peer; never while one a peer shares is unconnected.
#[test]
fn wait_all_follows_every_sync_id_spec_sync_status_3() {
    let mut t = T::new(&[(S, Holding::Read), (sid(3), Holding::Unread)]);
    let wait = |t: &T| t.st.wait(&t.g, Scope::All, |_| unreachable!(), |s| t.g.shared.contains(s));
    assert_eq!(wait(&t), Waiting::Done, "nobody else holds either: nothing to wait for");
    t.g.shared.insert(S);
    t.g.shared.insert(sid(3));
    assert_eq!(wait(&t), Waiting::Pending);
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 0);
    assert_eq!(wait(&t), Waiting::Pending, "the unread one is unconnected");
    t.join(sid(3), B, store(RB));
    t.caught(B, sid(3), 0);
    assert_eq!(wait(&t), Waiting::Done);
}

// spec/sync-status.md §3 (stranded), notes/api-design.md (a wait on Stranded fails, though it is
// not sure never to finish): a node keeping S unread reports S like any sync ID, stranded
// included; a wait whose scope holds a stranded sync ID fails naming it; one on a thing carried
// elsewhere only does not.
#[test]
fn a_wait_on_a_stranded_sync_id_fails_spec_sync_status_3() {
    let u = sid(2);
    let mut t = T::new(&[(S, Holding::Unread), (u, Holding::Read)]);
    t.g.stranded.insert(S);
    t.g.shared.insert(u);
    t.settle();
    assert!(t.st.of(&S, &t.g).unwrap().stranded);
    assert_eq!(t.st.wait(&t.g, Scope::All, |_| unreachable!(), |s| t.g.shared.contains(s)), Waiting::Stranded(vec![S]));
    assert_eq!(t.st.wait(&t.g, Scope::Thing(tid(1)), |_| Ok(vec![S]), |s| t.g.shared.contains(s)), Waiting::Stranded(vec![S]));
    assert_eq!(t.st.wait(&t.g, Scope::Thing(tid(1)), |_| Ok(vec![u]), |s| t.g.shared.contains(s)), Waiting::Pending, "not stranded: unconnected");
}

/// Work for one source's report on one own commit, at `n` sync IDs each with a source and an
/// own commit not held.
fn work_for_one_report(n: u32) -> (u64, u64) {
    let ids: Vec<(SyncId, Holding)> = (0..n).map(|i| (sid(i), Holding::Read)).collect();
    let mut t = T::new(&ids);
    for (i, (s, _)) in ids.iter().enumerate() {
        let mut r = [0x50; 16];
        r[..8].copy_from_slice(&(i as u64).to_le_bytes());
        t.join(*s, ConnId(100 + i as u64), reader(r, 1));
        t.own(*s, cid(1 + (i % 200) as u8), blob(i as u8), 3);
    }
    let before = t.st.work();
    let reads = t.g.stamped_reads;
    t.at(50);
    assert_eq!(t.st.work(), before, "nothing per sync ID while idle");
    t.g.reported.insert((ConnId(100), sid(0)), 9);
    t.settle();
    let after = t.st.work();
    (after.commits - before.commits, t.g.stamped_reads - reads)
}

// spec/sync-status.md §2: work follows change: one report judges the commits that read it, at n
// and at 10n sync IDs alike, and nothing moves while idle.
#[test]
fn work_follows_change() {
    let (c1, l1) = work_for_one_report(10);
    let (c10, l10) = work_for_one_report(100);
    assert_eq!((c1, l1), (c10, l10));
    assert!((1..=2).contains(&c1), "{c1}");
}

/// Own commits judged for held elsewhere when a second source of S joins and leaves, with `n`
/// own commits under S held elsewhere and one not.
fn work_for_a_source_flip(n: u8) -> u64 {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    for i in 0..n {
        t.own(S, cid(1 + i), blob(1 + i), 1);
        t.g.elsewhere.insert((S, blob(1 + i)));
    }
    t.own(S, cid(200), blob(200), 1);
    t.settle();
    assert_eq!(t.st.of(&S, &t.g).unwrap().unheld, Some(1));
    let before = t.st.work().commits;
    t.join(S, ConnId(7), reader(RB, 2));
    t.release(ConnId(7));
    t.settle();
    t.st.work().commits - before
}

// spec/sync-status.md §2, spec/sync.md §2 (work in proportion to change): a source joining or
// leaving judges again only the own commits not recorded held elsewhere: at n and 10n held ones
// alike.
#[test]
fn a_source_flip_judges_only_the_unheld() {
    let (a, b) = (work_for_a_source_flip(10), work_for_a_source_flip(100));
    assert_eq!(a, b, "own commits judged per source flip grow with those held elsewhere");
    assert!(a >= 1, "the unheld commit is judged again");
}

/// A node reading `ids` with self-removal `c` under each, logged as blob 1 at position 1.
fn removal_under(ids: &[SyncId], c: CommitId) -> T {
    let mut t = T::new(&ids.iter().map(|s| (*s, Holding::Read)).collect::<Vec<_>>());
    t.g.removals.insert((), Arc::new([c].into()));
    for s in ids {
        t.g.verdicts.insert((*s, c), Verdict::Must);
        t.g.entries.insert((*s, c), vec![blob(1)]);
        t.g.first.insert((*s, blob(1)), 1);
        t.g.own.insert((*s, c));
    }
    t
}

// spec/permissions.md §3 (Lost access): a self-removal waits only while a peer shares it; with no
// peer sharing S, the engine is told at once, whatever is held elsewhere.
#[test]
fn self_removal_no_peer_shares_done_at_once_spec_perm_3() {
    let mut t = removal_under(&[S], cid(1));
    t.settle();
    assert!(!t.st.held(&cid(1)), "held nowhere");
    assert_eq!(t.g.told_held, vec![cid(1)]);
}

// spec/permissions.md §3 (Lost access): a self-removal with a body under
// no read sync ID here is done at once: nothing here could hand it to a peer.
#[test]
fn self_removal_under_no_sync_id_done_at_once_spec_perm_3() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.shared.insert(S);
    t.g.removals.insert((), Arc::new([cid(1)].into()));
    t.settle();
    assert_eq!(t.g.told_held, vec![cid(1)]);
}

// spec/permissions.md §3 (Lost access): a kept record of another
// account holding S keeps the self-removal waiting until that peer takes it, or the record goes.
#[test]
fn self_removal_waits_while_a_peer_shares_spec_perm_3() {
    // the peer connects and takes it
    let mut t = removal_under(&[S], cid(1));
    t.g.shared.insert(S);
    t.settle();
    t.at(1_000_000);
    assert!(t.g.told_held.is_empty(), "waits for the away peer, however long");
    t.join(S, B, reader(RB, 2));
    t.g.reported.insert((B, S), 1);
    t.settle();
    assert_eq!(t.g.told_held, vec![cid(1)]);
    // the record goes: nobody left to take it
    let mut t = removal_under(&[S], cid(1));
    t.g.shared.insert(S);
    t.settle();
    assert!(t.g.told_held.is_empty());
    t.g.shared.remove(&S);
    t.settle();
    assert_eq!(t.g.told_held, vec![cid(1)]);
}

// spec/permissions.md §3 (Lost access): done once, under each, it is
// held elsewhere or no peer shares that sync ID; one shared and not held keeps it waiting.
#[test]
fn self_removal_judged_per_sync_id_spec_perm_3() {
    let u = sid(2);
    let mut t = removal_under(&[S, u], cid(1));
    t.g.shared.insert(S);
    t.g.shared.insert(u);
    t.join(S, A, reader(RA, 2));
    t.g.reported.insert((A, S), 1);
    t.settle();
    assert!(t.g.told_held.is_empty(), "held under S, u shared and not held");
    t.g.shared.remove(&u);
    t.settle();
    assert_eq!(t.g.told_held, vec![cid(1)], "u shared by nobody");
}

// spec/permissions.md §3 (Lost access): a self-removal is judged when what it reads moves, never
// on an idle settle.
#[test]
fn self_removal_judged_only_on_change() {
    let mut t = removal_under(&[S], cid(1));
    t.g.shared.insert(S);
    t.settle();
    let n = t.st.work().removals;
    t.at(5);
    t.at(10);
    assert_eq!(t.st.work().removals, n, "nothing moved");
    t.g.shared.remove(&S);
    t.settle();
    assert_eq!(t.st.work().removals, n + 1);
}

fn stranding() -> Arc<Stranding> {
    Arc::new(Stranding { actor: tid(5), holder: tid(6), step: [7; 32], keys: BTreeSet::new(), admins: vec![tid(8)] })
}

// spec/permissions.md §4 (stranded), spec/sync-status.md §3 (Stranded): after a complete pass
// there it cannot open the current epoch, and reports itself stranded. A read S whose engine
// holds no current read secret is stranded only once heard out (the reading of a complete pass
// there), and a wait on it fails so; a secret arriving ends it, and a kept-unread S is never
// judged so.
#[test]
fn a_read_sync_id_is_stranded_once_heard_out_spec_permissions_4() {
    let u = sid(2);
    let mut t = T::new(&[(S, Holding::Read), (u, Holding::Unread)]);
    t.g.strandings.insert(S, stranding());
    t.g.strandings.insert(u, stranding());
    t.join(S, A, reader(RA, 1));
    assert!(!t.st.of(&S, &t.g).unwrap().stranded && t.st.strandings().is_empty(), "not heard out yet");
    t.caught(A, S, 0);
    assert!(t.st.of(&S, &t.g).unwrap().stranded);
    assert_eq!(t.st.strandings().keys().copied().collect::<Vec<_>>(), vec![S], "only the read S");
    assert_eq!(t.st.wait(&t.g, Scope::All, |_| Ok(Vec::new()), |s| t.g.shared.contains(s)), Waiting::Stranded(vec![S]));
    t.g.strandings.remove(&S);
    t.settle();
    assert!(!t.st.of(&S, &t.g).unwrap().stranded && t.st.strandings().is_empty(), "a current secret held");
}

// spec/permissions.md §4 (stranded: every source refused every open it had to try, wherever its
// walk stopped), spec/sync-ids.md §6 (Walk: Stranded there): a read S its walk stopped at a
// source with no source open is stranded, naming the step it stopped at; a source opening S
// (then judged by heard out) or the stop going ends it.
#[test]
fn a_walk_stopped_with_no_source_is_stranded_spec_sync_ids_6() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.stops.insert(S, Some([3; 32]));
    t.settle();
    assert!(t.st.of(&S, &t.g).unwrap().stranded, "stopped, no source");
    assert_eq!(t.st.strandings().get(&S).map(|x| x.step), Some([3; 32]), "naming the step it stopped at");
    t.join(S, A, reader(RA, 1));
    assert!(t.st.strandings().is_empty(), "a source has S open: not heard out");
    t.release(A);
    t.settle();
    assert!(t.st.of(&S, &t.g).unwrap().stranded, "no source again");
    t.g.stops.remove(&S);
    t.settle();
    assert!(!t.st.of(&S, &t.g).unwrap().stranded && t.st.strandings().is_empty(), "the stop gone");
}

/// What one reconnect of a record holding `n` sync IDs moves in status: members moved (the
/// named counter) and lacking counts taken again.
fn reconnect_of(n: u32) -> (u64, u64) {
    let ids: Vec<(SyncId, Holding)> = (0..n).map(|i| (sid(i), Holding::Read)).collect();
    let mut t = T::new(&ids);
    for (s, _) in &ids {
        t.g.stamped.insert(*s, vec![blob(1)]);
        t.join(*s, B, store(RB));
    }
    t.release(B);
    t.settle();
    osis_base::costs::take();
    let lacking = t.st.work().lacking;
    t.st.taken(Source::Record(RB), Up { conn: ConnId(3), node: None });
    t.on.insert(ConnId(3), Source::Record(RB));
    t.settle();
    let moved = osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "status: members moved").map(|(.., v)| v).sum();
    for (s, _) in &ids {
        let st = t.st.of(s, &t.g).unwrap();
        assert_eq!(st.sources.keys().copied().collect::<Vec<_>>(), vec![ConnId(3)], "the record's members are sources on the new connection");
        assert_eq!(st.sources[&ConnId(3)].lacking, 1, "its lacking count kept");
    }
    (moved, t.st.work().lacking - lacking)
}

// spec/sync-status.md §1 (sources: the peers with S open on a connection up now), spec/sync.md §2
// (work in proportion to change): a kept record's members are followed per record; a connection
// taking it makes each a source on that connection by one fact (the record's connection), moving
// no member and counting no lacking again, at n and 10n sync IDs.
#[test]
fn a_reconnect_moves_no_member_spec_sync_status_1() {
    assert_eq!(reconnect_of(3), (0, 0));
    assert_eq!(reconnect_of(30), (0, 0));
}

// spec/sync-status.md §1 (caught up): on the connection S is open on, caught up stays per
// connection: a record taken by a new connection is no source caught up until that connection's
// stream says so, whatever the last one did.
#[test]
fn a_taken_record_is_caught_up_per_connection_spec_sync_status_1() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, B, reader(RB, 1));
    t.caught(B, S, 0);
    assert!(t.heard_out(S));
    t.release(B);
    t.st.taken(Source::Record(RB), Up { conn: ConnId(3), node: Some(tid(1)) });
    t.settle();
    assert!(!t.heard_out(S), "the new connection's stream has said nothing yet");
    t.caught(ConnId(3), S, 0);
    assert!(t.heard_out(S));
}

// spec/sync-status.md §2 (held elsewhere: reported by a source): a member closing counts where
// its peer stood as it closed (its report and close come in one step); a connection letting the
// record go keeps nothing of its reports: the next connection's Pull reports again.
#[test]
fn a_release_keeps_no_report_spec_sync_status_2() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.join(S, A, reader(RA, 1));
    t.own(S, cid(1), blob(1), 5);
    t.g.reported.insert((A, S), 6);
    t.release(A);
    t.g.reported.remove(&(A, S));
    t.settle();
    assert!(!t.st.held(&cid(1)), "a release keeps no report");
    t.st.taken(Source::Record(RA), Up { conn: ConnId(3), node: Some(tid(1)) });
    t.g.reported.insert((ConnId(3), S), 6);
    t.settle();
    assert!(t.st.held(&cid(1)), "reported again on the next connection");
}
