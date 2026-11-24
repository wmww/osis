//! Leaving (spec/sync-set.md §3) on a fake ground: the node closure, what this node's
//! keys hold of each sync ID, the store's sync IDs, its sources and passes, and what left the
//! node closure, each a stamped value, so `Leave` follows them as in a node. What it syncs,
//! shreds and releases is recorded.

use osis_base::memo::{Stamped, StampedSet};
use osis_base::{SyncId, Tid};
use osis_base::memo::Feed;
use osis_engine::sync::Holding;
use osis_sync::Result;
use osis_sync::leave::{Ground, Leave};
use osis_sync::set::Held;
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
    /// Sync IDs with no source now.
    unsourced: StampedSet<SyncId>,
    /// What left the node closure, with the sync units that held it.
    left: BTreeMap<Tid, BTreeSet<Tid>>,
    /// The passes begun so far, and per sync ID the place of its last complete pass.
    clock: u64,
    passes: Stamped<SyncId, u64>,
    /// Sync IDs whose complete passes are not run here: each passes at once unless listed.
    passing: StampedSet<SyncId>,
    /// This node has joined no account yet (pairing).
    synced: BTreeMap<SyncId, Held>,
    shredded: Vec<SyncId>,
    forgot: Vec<Tid>,
    /// Calls of `release`.
    forgettings: u64,
}

impl Ground for Fake {
    /// Every sync ID of the closure's things and every one this node's keys hold, at each read:
    /// a superset of what entered (one out of the sync set too, as a feed lists one that entered
    /// and left between two reads).
    fn held_added(&mut self, _: &mut Option<Feed<SyncId>>) -> Result<Vec<SyncId>> {
        let mut ids: BTreeSet<SyncId> = self.closure.get(&()).map(|c| c.iter().map(|t| sid(t.as_bytes()[0])).collect()).unwrap_or_default();
        ids.extend(self.holders.keys().copied());
        Ok(ids.into_iter().collect())
    }
    fn sync_held(&mut self, s: &SyncId) -> Result<Option<Held>> {
        let t = tid(s.0[0]);
        Ok(self.holders.get(s).filter(|_| self.closure.get(&()).is_some_and(|c| c.contains(&t))).map(|h| ([t].into(), *h)))
    }
    fn synced(&mut self, s: &SyncId) -> Option<Held> {
        self.synced.get(s).cloned()
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
        Ok(self.holders.get(s).map(|h| ([tid(s.0[0])].into(), *h)))
    }
    fn sourced(&mut self, s: &SyncId) -> bool {
        !self.unsourced.contains(s)
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.shredded.push(*s);
        Ok(())
    }
    fn left(&mut self) -> Result<BTreeMap<Tid, BTreeSet<Tid>>> {
        Ok(self.left.clone())
    }
    fn unit_ids(&mut self, u: &Tid) -> Result<Vec<SyncId>> {
        Ok(vec![sid(u.as_bytes()[0])])
    }
    fn release(&mut self, ts: &BTreeSet<Tid>) -> Result<()> {
        self.forgot.extend(ts.iter().copied());
        for t in ts {
            self.left.remove(t);
        }
        self.forgettings += 1;
        Ok(())
    }
    fn pass_seq(&mut self) -> u64 {
        self.clock
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> bool {
        !self.passing.contains(s) || self.passes.get(s).is_some_and(|b| *b > since)
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

// spec/sync-set.md §3 (Release; Stopping): a sync ID whose thing left the node closure stays
// synced until a complete pass begun after it left ends; then its thing is released and its store
// shredded, read or kept unread (nothing to release). With no source it stops at once.
#[test]
fn a_left_sync_id_stops_after_the_pass_in_flight_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.passing.insert(sid(1));
    g.passing.insert(sid(3));
    g.clock = 10;
    g.closure(&[2]);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.forgot.is_empty(), "the pass in flight first");
    assert_eq!((g.syncs(1), g.syncs(3)), (Some(Holding::Read), Some(Holding::Unread)), "still synced while it waits");
    g.passes.insert(sid(1), 11);
    g.unsourced.insert(sid(3));
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1), sid(3)]));
    assert_eq!((g.syncs(1), g.syncs(3)), (None, None));
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded.len(), 2, "once");
}

// spec/sync-set.md §3 (Release): a thing that left the node closure is released once a complete
// pass begun after it left ended for each sync ID that carried it, at once for one with no
// source; one that left the local part (no sync unit) at once.
#[test]
fn a_thing_is_released_after_the_pass_in_flight_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.passing.insert(sid(1));
    g.passing.insert(sid(2));
    g.clock = 10;
    g.left.insert(tid(9), [tid(1), tid(2)].into());
    g.left.insert(tid(8), BTreeSet::new());
    l.settle(&mut g).unwrap();
    assert_eq!(g.forgot, vec![tid(8)], "the local part's at once");
    assert_eq!(l.passes_wanted(), BTreeMap::from([(sid(1), 10), (sid(2), 10)]));
    g.passes.insert(sid(1), 11);
    l.settle(&mut g).unwrap();
    assert_eq!(g.forgot, vec![tid(8)], "2's pass in flight still");
    g.unsourced.insert(sid(2));
    l.settle(&mut g).unwrap();
    assert_eq!(g.forgot, vec![tid(8), tid(9)], "no source of 2: no wait");
    assert!(l.passes_wanted().is_empty());
}

// spec/sync-set.md §3 (Release: R back in the node closure before then is kept as it was): a leaving sync ID listed
// again is neither forgotten nor shredded.
#[test]
fn synced_again_before_it_stops_keeps_it_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.passing.insert(sid(1));
    g.closure(&[2, 3]);
    l.settle(&mut g).unwrap();
    g.closure(&[1, 2, 3]);
    l.settle(&mut g).unwrap();
    assert!(!l.waits(&sid(1)));
    g.passes.insert(sid(1), 1);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.forgot.is_empty());
    assert_eq!(g.syncs(1), Some(Holding::Read));
    assert_eq!(l.judged(), 1, "judged once while it left, not after");
}

// spec/sync-set.md §3 (Stopping; lowering from read to sync is no release): a node removed
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
    g.passing.insert(sid(8));
    let mut l = Leave::default();
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1)]));
    assert_eq!((g.syncs(7), g.syncs(8)), (None, Some(Holding::Unread)), "8 waits, synced");
    g.passes.insert(sid(8), 1);
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1), sid(8)]);
}

// spec/sync-set.md §3 (Stopping): a read sync ID whose holder went (its secrets lost, or a role
// commit on its thing uncounted for want of its lists) waits only for the pass in flight, then
// stops, nothing released; with no source, at once. A holder back before then keeps it.
#[test]
fn a_lost_holder_waits_only_for_the_pass_in_flight_spec_sync_set_3() {
    for case in ["pass", "no source", "back"] {
        let (mut g, mut l) = settled();
        g.passing.insert(sid(1));
        g.clock = 10;
        g.holders.remove(&sid(1));
        l.settle(&mut g).unwrap();
        assert!(g.shredded.is_empty() && g.syncs(1) == Some(Holding::Read), "{case}: the pass in flight first");
        match case {
            "pass" => _ = g.passes.insert(sid(1), 11),
            "no source" => _ = g.unsourced.insert(sid(1)),
            _ => _ = g.holders.insert(sid(1), Holding::Read),
        }
        l.settle(&mut g).unwrap();
        if case == "back" {
            assert!(g.shredded.is_empty() && !l.waits(&sid(1)), "{case}: kept as it was");
            continue;
        }
        assert_eq!(g.shredded, vec![sid(1)], "{case}: lost, no further wait");
        assert!(g.forgot.is_empty() && g.syncs(1).is_none(), "{case}");
    }
}
