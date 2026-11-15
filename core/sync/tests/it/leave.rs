//! Leaving (spec/sync-set.md §3) on a fake ground: the synced group's closure, what this node's
//! keys hold of each sync ID, the store's sync IDs, and whether its own writes under S are
//! elsewhere, each a stamped value, so `Leave` follows them as in a node. What it syncs, shreds
//! and forgets is recorded.

use osis_base::memo::{Stamped, StampedSet};
use osis_base::{SyncId, Tid};
use osis_engine::sync::{Holding, ThingSync};
use osis_sync::Result;
use osis_sync::leave::{Ground, Leave};
use osis_sync::set::{Held, SetGround};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn tid(i: u8) -> Tid {
    let mut b = [0u8; 15];
    b[0] = i;
    b[14] = 0x55;
    Tid::from_bytes(b)
}

fn sid(i: u8) -> SyncId {
    SyncId([i; 16])
}

/// Thing `i` owns sync ID `i`.
#[derive(Default)]
struct Fake {
    closure: Stamped<(), Arc<BTreeSet<Tid>>>,
    /// How this node's keys hold each sync ID (read: a read secret of its thing held).
    holders: Stamped<SyncId, Holding>,
    stored: Stamped<(), BTreeSet<SyncId>>,
    elsewhere: StampedSet<SyncId>,
    present: StampedSet<SyncId>,
    /// Sync IDs no peer shares with this node (no source, no record holding them).
    unshared: StampedSet<SyncId>,
    /// The passes begun so far, and per sync ID the place of its last complete pass.
    clock: u64,
    passes: Stamped<SyncId, u64>,
    /// Sync IDs whose complete passes are not run here: each passes at once unless listed.
    passing: StampedSet<SyncId>,
    /// This node does not know its synced group yet (pairing).
    unrooted: Stamped<(), bool>,
    synced: BTreeMap<SyncId, Held>,
    shredded: Vec<SyncId>,
    forgot: Vec<Tid>,
    /// Calls of `forget_local`.
    forgettings: u64,
}

impl SetGround for Fake {
    /// Every thing of the closure, each read: a superset of what entered.
    fn things_entered(&mut self, _: &mut osis_engine::sync::ThingsFeed) -> Result<Vec<Tid>> {
        Ok(self.closure.get(&()).map(|c| c.iter().copied().collect()).unwrap_or_default())
    }
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        Ok(self.closure.get(&()).is_some_and(|c| c.contains(t)))
    }
    fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        Ok(self.closure.get(&()).cloned().unwrap_or_default())
    }
    fn thing_sync(&mut self, t: &Tid) -> Result<ThingSync> {
        let s = sid(t.as_bytes()[0]);
        Ok(match self.holders.get(&s) {
            Some(Holding::Read) => ThingSync::Read(vec![s]),
            Some(Holding::Unread) => ThingSync::Unread(vec![s]),
            None => ThingSync::Plain,
        })
    }
}

impl Ground for Fake {
    fn synced(&mut self, s: &SyncId) -> Option<Held> {
        self.synced.get(s).copied()
    }
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>) -> Result<()> {
        match now {
            Some(h) => self.synced.insert(*s, h),
            None => self.synced.remove(s),
        };
        Ok(())
    }
    fn stored(&mut self) -> Result<BTreeSet<SyncId>> {
        Ok(self.stored.get(&()).cloned().unwrap_or_default())
    }
    fn holder(&mut self, s: &SyncId) -> Result<Option<Held>> {
        Ok(self.holders.get(s).map(|h| (tid(s.0[0]), *h)))
    }
    fn own_elsewhere(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.elsewhere.contains(s))
    }
    fn own_present(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.present.contains(s))
    }
    fn waited(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unshared.contains(s))
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.shredded.push(*s);
        Ok(())
    }
    fn forget_local(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        self.forgot.extend(ts.iter().copied());
        self.forgettings += 1;
        Ok(())
    }
    fn pass_seq(&mut self) -> u64 {
        self.clock
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> Result<bool> {
        Ok(!self.passing.contains(s) || self.passes.get(s).is_some_and(|b| *b > since))
    }
    fn rooted(&mut self) -> Result<bool> {
        Ok(self.unrooted.get(&()) != Some(&true))
    }
}

impl Fake {
    fn closure(&mut self, things: &[u8]) {
        self.closure.insert((), Arc::new(things.iter().map(|i| tid(*i)).collect()));
    }

    fn syncs(&self, s: u8) -> Option<Holding> {
        self.synced.get(&sid(s)).map(|(_, h)| *h)
    }
}

/// A node with things 1..=3 in its closure, 1 and 2 read, 3 kept unread, each with rows in the
/// store.
fn settled() -> (Fake, Leave) {
    let mut g = Fake::default();
    g.closure(&[1, 2, 3]);
    g.holders.insert(sid(1), Holding::Read);
    g.holders.insert(sid(2), Holding::Read);
    g.holders.insert(sid(3), Holding::Unread);
    g.stored.insert((), [sid(1), sid(2), sid(3)].into());
    let mut l = Leave::default();
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty(), "nothing left");
    assert_eq!((g.syncs(1), g.syncs(3)), (Some(Holding::Read), Some(Holding::Unread)), "the sync set is synced");
    (g, l)
}

// spec/sync-set.md §3 (one rule ends syncing it; while it waits, S stays a member of its shared
// sets; Unsyncing): a read sync ID whose thing left the synced group's closure, still read here,
// stays synced until its own commits are held elsewhere; then its thing's copy is forgotten and
// its store shredded, and it is synced no more.
#[test]
fn unsynced_stays_synced_until_own_writes_are_elsewhere_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.closure(&[2, 3]);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.forgot.is_empty(), "own commits not yet held elsewhere");
    assert_eq!(g.syncs(1), Some(Holding::Read), "still synced while it waits");
    assert!(l.waits(&sid(1)));
    g.elsewhere.insert(sid(1));
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1)]));
    assert_eq!(g.syncs(1), None);
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded.len(), 1, "once");
}

// spec/sync-set.md §3 (one rule ends syncing it: keeping S unread, each entry it logged itself
// present at a source): a kept-unread sync ID whose thing left the closure stays synced (kept
// unread) until its own entries are present at a source; then it is shredded, nothing forgotten.
#[test]
fn kept_unread_stays_synced_until_own_entries_are_present_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.closure(&[1, 2]);
    l.settle(&mut g).unwrap();
    assert_eq!(g.syncs(3), Some(Holding::Unread), "still synced while it waits");
    assert!(g.shredded.is_empty());
    g.present.insert(sid(3));
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(3)]);
    assert!(g.forgot.is_empty(), "nothing read to forget");
    assert_eq!(g.syncs(3), None);
}

// spec/sync-set.md §3 (with none, it stops at once): a sync ID no peer shares (this node's only copy, no
// source, no record holding it) stops at once, read or kept unread, its own writes held nowhere
// else; one waiting whose last peer goes (its record evicted) stops then.
#[test]
fn unshared_stops_at_once_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.unshared.insert(sid(1));
    g.unshared.insert(sid(3));
    g.closure(&[2]);
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1), sid(3)]));
    assert_eq!((g.syncs(1), g.syncs(3)), (None, None));
    g.closure(&[]);
    l.settle(&mut g).unwrap();
    assert!(l.waits(&sid(2)), "a peer shares it: waits");
    g.unshared.insert(sid(2));
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.syncs(2)), (vec![tid(1), tid(2)], None));
}

// spec/sync-set.md §3 (Unsyncing), issues/leave-forget-per-sync-id.md: read sync IDs that stop in
// one settle forget their things' copies in one forgetting (one engine reload), before any of
// them is shredded.
#[test]
fn sync_ids_stopping_together_forget_once_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.unshared.insert(sid(1));
    g.unshared.insert(sid(2));
    g.closure(&[3]);
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone(), g.forgettings), (vec![tid(1), tid(2)], vec![sid(1), sid(2)], 1));
}

// spec/sync-set.md §3 (synced again before then, S is kept as it was): a leaving sync ID listed
// again is neither forgotten nor shredded when its entries are elsewhere later.
#[test]
fn synced_again_before_it_stops_keeps_it_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.closure(&[2, 3]);
    l.settle(&mut g).unwrap();
    g.closure(&[1, 2, 3]);
    l.settle(&mut g).unwrap();
    assert!(!l.waits(&sid(1)));
    g.elsewhere.insert(sid(1));
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.forgot.is_empty());
    assert_eq!(g.syncs(1), Some(Holding::Read));
    assert_eq!(l.judged(), 1, "judged once while it left, not after");
}

// spec/sync-set.md §3 (stops at once; lowering from read to sync is no leaving): a node removed
// by another holds no secret of the thing: a read sync ID that left with no secret of its thing
// held is shredded at once, nothing forgotten; lowered to kept unread it is not shredded.
#[test]
fn removed_stops_at_once_lowered_is_no_leaving_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.holders.remove(&sid(1));
    g.holders.insert(sid(2), Holding::Unread);
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1)]);
    assert!(g.forgot.is_empty());
    assert_eq!((g.syncs(1), g.syncs(2)), (None, Some(Holding::Unread)));
}

// spec/sync-set.md §3 (stops at once): a sync ID waiting to stop whose secrets this node then
// loses (a removal) stops at once, its copy not forgotten by the wait (lost access does that).
#[test]
fn losing_the_secrets_while_waiting_stops_at_once_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.closure(&[2, 3]);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty());
    g.holders.remove(&sid(1));
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1)]);
    assert!(g.forgot.is_empty());
    assert_eq!(g.syncs(1), None);
}

// spec/sync-set.md §3 (on stopping): at a start, a sync ID whose rows the store holds outside the
// sync set, still held by this node's keys, left while the node was down: it is synced and waits
// as any leaving one, read or kept unread; another's rows (an inbox this node deposits to: no key
// of it held) are left alone.
#[test]
fn a_start_finds_what_left_while_down_spec_sync_set_3() {
    let mut g = Fake::default();
    g.closure(&[2]);
    for (i, h) in [(1, Holding::Read), (2, Holding::Read), (8, Holding::Unread)] {
        g.holders.insert(sid(i), h);
    }
    g.stored.insert((), [sid(1), sid(2), sid(7), sid(8)].into());
    g.elsewhere.insert(sid(1));
    let mut l = Leave::default();
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1)]));
    assert_eq!((g.syncs(7), g.syncs(8)), (None, Some(Holding::Unread)), "8 waits, synced");
    g.present.insert(sid(8));
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1), sid(8)]);
}

// spec/sync-set.md §3 (One rule ends syncing it: a complete pass after it left first): a read sync ID that left because
// this node's keys lost it (a loss a later arrival may undo: a rotation's thing list after the
// rotation) stays synced until a complete pass begun after it left ends; a pass begun before
// counts for nothing; synced again meanwhile, it is kept; once the pass ends and the loss stands,
// it stops at once, nothing forgotten. Leave wants that pass (`passes_wanted`) only while it waits.
#[test]
fn a_leaving_sync_id_waits_for_a_complete_pass_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.passing.insert(sid(1));
    g.passes.insert(sid(1), 5);
    g.clock = 10;
    g.holders.remove(&sid(1));
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.syncs(1) == Some(Holding::Read), "waits for a pass");
    assert_eq!(l.passes_wanted(), BTreeMap::from([(sid(1), 10)]));
    // the loss undone by what the pass brings: kept as it was
    g.holders.insert(sid(1), Holding::Read);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && !l.waits(&sid(1)) && l.passes_wanted().is_empty());
    // lost again; a pass begun since ends with the loss standing
    g.clock = 20;
    g.holders.remove(&sid(1));
    l.settle(&mut g).unwrap();
    g.passes.insert(sid(1), 20);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty(), "a pass begun before it left counts for nothing");
    g.passes.insert(sid(1), 21);
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1)]);
    assert!(g.forgot.is_empty() && g.syncs(1).is_none() && l.passes_wanted().is_empty());
}

// spec/sync-set.md §3 (Before the group is known: nothing counts as having left): a node pairing, its sync set empty for want of its synced group, starts with rows of a sync
// ID its keys hold and leaves none; once it knows the group and the closure lacks it, it leaves.
#[test]
fn nothing_leaves_before_the_synced_group_is_known_spec_sync_set_3() {
    let mut g = Fake::default();
    g.unrooted.insert((), true);
    g.holders.insert(sid(1), Holding::Read);
    g.stored.insert((), [sid(1)].into());
    let mut l = Leave::default();
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && !l.waits(&sid(1)) && l.passes_wanted().is_empty(), "nothing left, no pass wanted");
    g.unrooted.insert((), false);
    l.settle(&mut g).unwrap();
    assert!(l.waits(&sid(1)) && g.syncs(1) == Some(Holding::Read), "known: S left, synced while it waits");
}

/// One node, alone: `k` things of its own, each with secrets (and so a sync ID) of its own, filed
/// in its D, each written once more, and a thing under D's sync ID written `n` times; then the `k` things unfiled at once
/// (no peer shares them: each stops at once). The costs of the leave: engine reloads, own entries
/// unlogged, commits the engine's forgetting scanned.
fn leave_costs(k: usize, n: usize) -> (u64, u64, u64) {
    use crate::harness::World;
    use crate::harness::history::{file, value_ak};
    use osis_base::Value;
    use osis_engine::Mutation;
    let mut w = World::new(0);
    w.add_node();
    let a = w.node(0).account.unwrap();
    let new = |w: &mut World| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            m.set(t, &value_ak(), &Value::Int(0)).unwrap();
            e.commit(m).unwrap();
            t
        })
    };
    let things: Vec<Tid> = (0..k).map(|_| new(&mut w)).collect();
    for t in &things {
        w.write(0, |e| e.give_own_secrets(t)).unwrap();
        // a commit of content alone: forgotten whole, its own entry unlogged
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(*t, &value_ak(), &Value::Int(1)).unwrap();
            e.commit(m).unwrap();
        });
    }
    let keep = new(&mut w);
    file(&mut w, 0, things.iter().copied().chain([keep]).collect(), Vec::new());
    for i in 0..n {
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(keep, &value_ak(), &Value::Int(i as i64 + 1)).unwrap();
            e.commit(m).unwrap();
        });
    }
    w.run();
    let ids = |w: &mut World| w.store(0).syncs().len();
    let before = ids(&mut w);
    osis_base::costs::take();
    w.write(0, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let mut g = e.get_typed(&d, &osis_schema::core_types::GROUP).unwrap().unwrap_or_default();
        for t in &things {
            g.items.remove(t);
        }
        let mut m = Mutation::new();
        m.set(d, &osis_schema::core_types::GROUP, &g).unwrap();
        e.write(m).unwrap();
    });
    w.run();
    let costs = osis_base::costs::take();
    assert_eq!(ids(&mut w), before - k, "the {k} sync IDs stopped");
    let sum = |name: &str| costs.iter().filter(|(x, _, _)| *x == name).map(|(_, _, n)| n).sum::<u64>();
    (sum("engine: forget reload"), sum("leave: own entries unlogged"), sum("forget: commits scanned"))
}

// spec/sync-set.md §3 (Unsyncing), issues/leave-forget-per-sync-id.md: leaving k separately
// synced things at once forgets them in one engine reload, and unlogs only the own entries of
// what forgot, at n and 10n own entries elsewhere. The engine's forgetting itself still scans
// every held commit (issues/leave-forget-per-sync-id.md).
#[test]
fn leaving_several_reloads_once_and_unlogs_what_left_at_n_and_10n_spec_sync_set_3() {
    let (one, three, three_10n) = (leave_costs(1, 2), leave_costs(3, 2), leave_costs(3, 20));
    assert_eq!((one.0, three.0, three_10n.0), (1, 1, 1), "one reload per leave");
    assert!(one.1 > 0);
    assert_eq!((three.1, three_10n.1), (3 * one.1, 3 * one.1), "own entries unlogged: what left, not what stays");
}

/// A node with an account of its own whose synced group lists `n` plain things (one write), its
/// sync set followed and settled: (engine, follower, account, synced group).
fn synced_of(n: usize) -> (osis_engine::Engine, osis_sync::set::SetFollow, Tid, Tid) {
    use osis_crypto::SeededRng;
    use osis_store::{MemoryBackend, MemoryRoot};
    let clock: Arc<dyn osis_base::Clock> = Arc::new(osis_base::ManualClock::new(osis_base::WallMs(1_700_000_000_000)));
    let store = osis_sync::Store::open(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Box::new(SeededRng::from_u64(2))).unwrap();
    let mut e = osis_engine::Engine::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), store.cipher(), osis_engine::Config::default(), clock, Box::new(SeededRng::from_u64(1))).unwrap();
    e.create_account().unwrap();
    let (p, d) = e.account().unwrap().unwrap();
    let g = *e.get_typed(&d, &osis_schema::core_types::SYNCED).unwrap().unwrap().values().next().unwrap();
    let mut m = osis_engine::Mutation::new();
    for _ in 0..n {
        let x = e.new_thing(&mut m, p);
        list(&mut m, g, x, true);
    }
    e.commit(m).unwrap();
    let mut f = osis_sync::set::SetFollow::new("test: sync set");
    f.settle(&mut e).unwrap();
    assert!(e.sync_things().unwrap().len() > n, "the synced group's things are in the sync set");
    (e, f, p, g)
}

/// Lists (`on`) or unlists `x` as an item of group `g`.
fn list(m: &mut osis_engine::Mutation, g: Tid, x: Tid, on: bool) {
    let v = osis_base::Value::Tid(x);
    let op = if on { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
    m.op(g, &osis_schema::core_types::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op }).unwrap();
}

/// The closure work counted since the last `take`: the group index's walks and the sync set's
/// things entered, walked and settled.
fn closure_work() -> BTreeMap<&'static str, u64> {
    osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("group index") || k.starts_with("sync set") || k.starts_with("sync: things")).map(|(k, _, n)| (k, n)).collect()
}

// spec/sync-set.md §2 (Cost): a `group.0` change that adds a thing to the synced group costs
// work in proportion to what it adds, and one that removes it likewise here (the spec allows up
// to N's closure): the same closure work at n and 10n things, the engine's closure maintenance
// and the followed sync set together.
#[test]
fn adding_or_removing_a_thing_costs_the_same_at_any_closure_size_spec_sync_set_2() {
    let mut work = Vec::new();
    for n in [20, 200] {
        let (mut e, mut f, p, g) = synced_of(n);
        osis_base::costs::take();
        let mut m = osis_engine::Mutation::new();
        let x = e.new_thing(&mut m, p);
        list(&mut m, g, x, true);
        e.commit(m).unwrap();
        f.settle(&mut e).unwrap();
        let added = closure_work();
        assert!(e.in_sync_things(&x).unwrap(), "the thing added is in the sync set");
        let mut m = osis_engine::Mutation::new();
        list(&mut m, g, x, false);
        e.commit(m).unwrap();
        f.settle(&mut e).unwrap();
        let removed = closure_work();
        assert!(!e.in_sync_things(&x).unwrap(), "the thing removed left the sync set");
        assert!(added.get("sync set: settled").is_some_and(|n| *n > 0) && removed.get("sync set: settled").is_some_and(|n| *n > 0), "counted: {added:?} {removed:?}");
        work.push((added, removed));
    }
    assert_eq!(work[0], work[1], "closure work at n and 10n things (add, remove)");
}
