//! Status (spec/sync-status.md) on a fake ground: streams' caught up, full and refusals, opens'
//! reported positions and records, read's verdicts, the store's own entries and the engine's
//! own commits, self-removals and wanted passes, each a stamped value, so `Status` follows them
//! as in a node. Sources come and go as opens' `Moved` would bring them (`joined`, `left`).

use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_engine::sync::{Holding, SyncSet};
use osis_proto::limits::PASS_WAIT_MS;
use osis_sync::Result;
use osis_sync::read::Verdict;
use osis_sync::status::{Ground, Net, Src, Status};
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
    Src { class: SourceClass::Reader, at: Source::Record(r), account: Some(tid(account)), own_node: false }
}

fn store(r: RecordId) -> Src {
    Src { class: SourceClass::Store, at: Source::Record(r), account: None, own_node: false }
}

#[derive(Default)]
struct Fake {
    now: u64,
    set: Stamped<(), Arc<SyncSet>>,
    caught: Stamped<(ConnId, SyncId), WallMs>,
    full: StampedSet<(Source, SyncId)>,
    refused: StampedSet<(Source, SyncId, BlobId)>,
    stranded: StampedSet<SyncId>,
    stamped: Stamped<SyncId, Vec<BlobId>>,
    knows: StampedSet<(Source, SyncId, BlobId)>,
    reported: Stamped<(ConnId, SyncId), Position>,
    until: Stamped<(ConnId, SyncId), Position>,
    records: Stamped<SyncId, BTreeSet<RecordId>>,
    own: Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    removals: Stamped<(), Arc<BTreeSet<CommitId>>>,
    verdicts: Stamped<(SyncId, CommitId), Verdict>,
    entries: Stamped<(SyncId, CommitId), Vec<BlobId>>,
    first: Stamped<(SyncId, BlobId), Position>,
    elsewhere: StampedSet<(SyncId, BlobId)>,
    told_held: Vec<CommitId>,
    wanted: Stamped<(), Arc<BTreeMap<SyncId, WallMs>>>,
    passes: Vec<(SyncId, WallMs)>,
    /// Calls to `stamped` (lacking counts taken).
    stamped_reads: u64,
}

impl Net for Fake {
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<WallMs> {
        self.caught.get(&(conn, *s)).copied()
    }
    fn full(&self, at: Source, s: &SyncId) -> bool {
        self.full.contains(&(at, *s))
    }
    fn refusing(&self, at: Source, s: &SyncId) -> bool {
        self.refused.iter().any(|(a, x, _)| *a == at && x == s)
    }
    fn stranded(&self, s: &SyncId) -> bool {
        self.stranded.contains(s)
    }
}

impl Ground for Fake {
    fn now(&self) -> WallMs {
        WallMs(self.now)
    }
    fn syncs(&mut self) -> Result<Arc<SyncSet>> {
        Ok(self.set.get(&()).cloned().unwrap_or_default())
    }
    fn stamped(&mut self, s: &SyncId) -> Result<Vec<BlobId>> {
        self.stamped_reads += 1;
        Ok(self.stamped.get(s).cloned().unwrap_or_default())
    }
    fn knows(&self, at: Source, _conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.knows.contains(&(at, *s, *b))
    }
    fn until(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.until.get(&(conn, *s)).copied()
    }
    fn reported(&self, conn: ConnId, s: &SyncId) -> Option<Position> {
        self.reported.get(&(conn, *s)).copied()
    }
    fn records_holding(&self, s: &SyncId) -> Result<BTreeSet<RecordId>> {
        Ok(self.records.get(s).cloned().unwrap_or_default())
    }
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.own.get(s).cloned().unwrap_or_default())
    }
    fn self_removals(&mut self) -> Result<Arc<BTreeSet<CommitId>>> {
        Ok(self.removals.get(&()).cloned().unwrap_or_default())
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
    fn held_elsewhere(&mut self, c: &CommitId) -> Result<()> {
        self.told_held.push(*c);
        let mut r = self.removals.get(&()).map(|x| (**x).clone()).unwrap_or_default();
        r.remove(c);
        self.removals.insert((), Arc::new(r));
        Ok(())
    }
    fn passes_wanted(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>> {
        Ok(self.wanted.get(&()).cloned().unwrap_or_default())
    }
    fn pass_clock(&mut self) -> WallMs {
        self.now()
    }
    fn note_complete_pass(&mut self, s: &SyncId, began: WallMs) -> Result<()> {
        self.passes.push((*s, began));
        let mut w = self.wanted.get(&()).map(|x| (**x).clone()).unwrap_or_default();
        if w.get(s).is_some_and(|t| *t <= began) {
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
}

impl T {
    /// A node holding `ids` (read, or kept unread).
    fn new(ids: &[(SyncId, Holding)]) -> T {
        let mut g = Fake::default();
        g.set.insert((), Arc::new(SyncSet { ids: ids.iter().map(|(s, h)| (*s, (tid(9), *h))).collect(), unsyncable: BTreeSet::new() }));
        let mut t = T { st: Status::default(), g, pulls: Vec::new() };
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

    fn join(&mut self, s: SyncId, conn: ConnId, src: Src) {
        self.st.joined(s, conn, src);
        self.settle();
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
        let mut now = self.g.own.get(&s).map(|x| (**x).clone()).unwrap_or_default();
        now.insert(c);
        self.g.own.insert(s, Arc::new(now));
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
    t.st.left(S, A, Default::default());
    t.st.left(S, B, Default::default());
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
    t.g.full.insert((Source::Record(RB), S));
    t.settle();
    assert!(t.heard_out(S), "a full source is not waited on");
    let st = t.st.of(&S, &t.g).unwrap();
    assert!(st.sources[&B].full && !st.sources[&B].caught_up);
    t.g.full.remove(&(Source::Record(RB), S));
    t.g.refused.insert((Source::Record(RB), S, blob(1)));
    t.settle();
    assert!(t.heard_out(S) && t.st.of(&S, &t.g).unwrap().sources[&B].refusing);
    // with only sources that do not take S, nothing is heard out
    t.st.left(S, A, Default::default());
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
    t.st.left(S, A, LeftAt { reported: Some(6), until: None });
    t.settle();
    assert!(t.st.held(&cid(1)), "reported at 6 as it left");
    assert!(!t.st.held(&cid(2)), "first logged at 7, past the report");
    t.st.left(S, B, LeftAt { reported: Some(9), until: None });
    t.settle();
    assert!(!t.st.held(&cid(2)), "a leave of no source counts for nothing");
}

// spec/sync-status.md §2 (held elsewhere): an own commit is held elsewhere once a source's stream
// showed its entry or a source reported a position at or past where this node's log first held
// it; the report is recorded on the entry and outlives the source's connection.
#[test]
fn own_commit_held_elsewhere_by_report_or_presence() {
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
    t.st.left(S, A, Default::default());
    t.g.reported.remove(&(A, S));
    t.settle();
    assert!(t.st.held(&cid(1)), "the record outlives the source");
    // presence by a source's stream counts too
    t.join(S, B, store(RB));
    t.own(S, cid(2), blob(2), 9);
    assert!(!t.st.held(&cid(2)));
    t.g.knows.insert((Source::Record(RB), S, blob(2)));
    t.settle();
    assert!(t.st.held(&cid(2)));
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
    t.g.full.insert((Source::Record(RB), S));
    t.g.reported.insert((B, S), 10);
    t.settle();
    assert!(!t.st.held(&cid(1)), "a full store applied past it");
    t.g.full.remove(&(Source::Record(RB), S));
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

// spec/sync-status.md §2 (self-removal): this account's own other nodes never count for its
// self-removal; once it is held elsewhere the engine is told, once.
#[test]
fn self_removal_not_held_at_own_nodes() {
    let mut t = T::new(&[(S, Holding::Read)]);
    let own = Src { own_node: true, ..reader(RA, 1) };
    t.join(S, A, own);
    t.g.removals.insert((), Arc::new([cid(1)].into()));
    t.own(S, cid(1), blob(1), 1);
    t.g.knows.insert((Source::Record(RA), S, blob(1)));
    t.g.reported.insert((A, S), 9);
    t.settle();
    assert!(!t.st.held(&cid(1)) && t.g.told_held.is_empty());
    t.join(S, B, reader(RB, 2));
    t.g.reported.insert((B, S), 1);
    t.settle();
    assert!(t.st.held(&cid(1)));
    assert_eq!(t.g.told_held, vec![cid(1)]);
    t.at(10);
    assert_eq!(t.g.told_held, vec![cid(1)], "told once");
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

/// The engine wants a pass of S begun at or after `since`.
fn want(t: &mut T, s: SyncId, since: u64) {
    let mut w = t.g.wanted.get(&()).map(|x| (**x).clone()).unwrap_or_default();
    w.insert(s, WallMs(since));
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
    assert_eq!(t.g.passes, vec![(S, WallMs(100))]);
    assert_eq!(t.st.of(&S, &t.g).unwrap().pass_waits, None);
}

// spec/sync-status.md §1 (with no source and no such record it ends at once): with neither, a pass ends at once.
#[test]
fn complete_pass_with_nobody_ends_at_once() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.at(7);
    want(&mut t, S, 7);
    assert_eq!(t.g.passes, vec![(S, WallMs(7))]);
}

// spec/sync-status.md §1 (PASS_WAIT_MS): a recorded peer away holds a pass no longer than
// PASS_WAIT_MS; the node wakes for it.
#[test]
fn complete_pass_gives_up_on_away_peer() {
    let mut t = T::new(&[(S, Holding::Read)]);
    t.g.records.insert(S, [RB].into());
    t.at(10);
    want(&mut t, S, 10);
    assert!(t.g.passes.is_empty());
    assert_eq!(t.st.next_wake(), Some(WallMs(10 + PASS_WAIT_MS)));
    t.at(10 + PASS_WAIT_MS - 1);
    assert!(t.g.passes.is_empty());
    t.at(10 + PASS_WAIT_MS);
    assert_eq!(t.g.passes, vec![(S, WallMs(10))]);
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
    assert_eq!(t.g.passes, vec![(S, WallMs(10))]);
    assert_eq!(t.pulls, vec![A], "the next pass asks again");
    // a third moment while the second pass is under way queues one pass, not one per moment
    t.at(30);
    want(&mut t, S, 30);
    t.at(40);
    want(&mut t, S, 40);
    t.caught(A, S, 20);
    assert_eq!(t.g.passes, vec![(S, WallMs(10)), (S, WallMs(20))]);
    t.caught(A, S, 40);
    assert_eq!(t.g.passes, vec![(S, WallMs(10)), (S, WallMs(20)), (S, WallMs(40))], "one pass for both");
    assert!(t.g.wanted.get(&()).unwrap().is_empty());
}

// spec/sync-status.md §3 (wait): `wait` ends when every sync ID in scope is heard out with its own
// commits held elsewhere; never while one is unconnected.
#[test]
fn wait_all_follows_every_sync_id() {
    let mut t = T::new(&[(S, Holding::Read), (sid(3), Holding::Unread)]);
    assert_eq!(t.st.wait(&t.g, Scope::All, |_| unreachable!()), Waiting::Pending);
    t.join(S, A, reader(RA, 1));
    t.caught(A, S, 0);
    assert_eq!(t.st.wait(&t.g, Scope::All, |_| unreachable!()), Waiting::Pending, "the unread one is unconnected");
    t.join(sid(3), B, store(RB));
    t.caught(B, sid(3), 0);
    assert_eq!(t.st.wait(&t.g, Scope::All, |_| unreachable!()), Waiting::Done);
}

// spec/sync-status.md §3 (stranded): a node keeping S unread reports S like any sync ID, stranded
// included.
#[test]
fn stranded_reported() {
    let mut t = T::new(&[(S, Holding::Unread)]);
    t.g.stranded.insert(S);
    t.settle();
    assert!(t.st.of(&S, &t.g).unwrap().stranded);
}

// spec/sync-status.md §3 (stranded), notes/api-design.md (a wait on Stranded fails, though it is
// not sure never to finish): a wait whose scope holds a stranded sync ID fails naming it; one on
// a thing carried elsewhere only does not.
#[test]
fn a_wait_on_a_stranded_sync_id_fails_spec_sync_status_3() {
    let u = sid(2);
    let mut t = T::new(&[(S, Holding::Unread), (u, Holding::Read)]);
    t.g.stranded.insert(S);
    t.settle();
    assert_eq!(t.st.wait(&t.g, Scope::All, |_| unreachable!()), Waiting::Stranded(vec![S]));
    assert_eq!(t.st.wait(&t.g, Scope::Thing(tid(1)), |_| Ok(vec![S])), Waiting::Stranded(vec![S]));
    assert_eq!(t.st.wait(&t.g, Scope::Thing(tid(1)), |_| Ok(vec![u])), Waiting::Pending, "not stranded: unconnected");
}

/// Work for one source's report on one own commit, at `n` sync IDs each with a source and an
/// own commit not held.
fn work_for_one_report(n: u32) -> (u64, u64) {
    let ids: Vec<(SyncId, Holding)> = (0..n).map(|i| (sid(i), Holding::Read)).collect();
    let mut t = T::new(&ids);
    for (i, (s, _)) in ids.iter().enumerate() {
        t.join(*s, ConnId(100 + i as u64), reader(RA, 1));
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
