//! Leaving (spec/sync-set.md §3) on a fake ground: the synced group's closure, what this node's
//! keys hold of each sync ID, the store's sync IDs, and whether its own writes under S are
//! elsewhere, each a stamped value, so `Leave` follows them as in a node. What it syncs, shreds
//! and forgets is recorded.

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
    elsewhere: StampedSet<SyncId>,
    present: StampedSet<SyncId>,
    /// Sync IDs no peer shares with this node (no source, no record holding them).
    unshared: StampedSet<SyncId>,
    /// The passes begun so far, and per sync ID the place of its last complete pass.
    clock: u64,
    passes: Stamped<SyncId, u64>,
    /// Sync IDs whose complete passes are not run here: each passes at once unless listed.
    passing: StampedSet<SyncId>,
    /// Things with a role commit held but uncounted for want of its lists.
    uncounted: StampedSet<Tid>,
    /// This node does not know its synced group yet (pairing).
    unrooted: Stamped<(), bool>,
    synced: BTreeMap<SyncId, Held>,
    shredded: Vec<SyncId>,
    forgot: Vec<Tid>,
    /// Calls of `forget_local`.
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
        Ok(self.holders.get(s).filter(|_| self.closure.get(&()).is_some_and(|c| c.contains(&t))).map(|h| (t, *h)))
    }
    fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        Ok(self.closure.get(&()).is_some_and(|c| c.contains(t)))
    }
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
    fn uncounted_role(&mut self, t: &Tid) -> bool {
        self.uncounted.contains(t)
    }
    fn pass_seq(&mut self) -> u64 {
        self.clock
    }
    fn passed(&mut self, s: &SyncId, since: u64) -> bool {
        !self.passing.contains(s) || self.passes.get(s).is_some_and(|b| *b > since)
    }
    fn rooted(&mut self) -> bool {
        self.unrooted.get(&()) != Some(&true)
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

// spec/sync-set.md §3 (its list may still come): a read sync ID whose holder went because a
// role commit on its thing is uncounted for want of its lists (a revocation taken before them)
// is not judged lost by the pass that saw it go: it waits for one more complete pass, begun at
// that judgement, that ends only with a source (`pass_sourced`); the lists arriving give S back,
// kept as it was; with the role commit still uncounted after that pass, it stops. Without an
// uncounted role commit the loss stands after the first pass.
#[test]
fn a_loss_waiting_for_lists_waits_for_a_pass_with_a_source_spec_sync_set_3() {
    for given_back in [true, false] {
        let (mut g, mut l) = settled();
        g.passing.insert(sid(1));
        g.clock = 10;
        g.holders.remove(&sid(1));
        g.uncounted.insert(tid(1));
        l.settle(&mut g).unwrap();
        assert!(!l.pass_sourced(&sid(1)), "the first pass needs no source");
        g.clock = 12;
        g.passes.insert(sid(1), 11);
        l.settle(&mut g).unwrap();
        assert!(g.shredded.is_empty() && g.syncs(1) == Some(Holding::Read), "a role commit waits for its lists: kept");
        assert!(l.pass_sourced(&sid(1)), "the next pass needs a source");
        assert_eq!(l.passes_wanted(), BTreeMap::from([(sid(1), 12)]), "begun after the judgement");
        if given_back {
            g.uncounted.remove(&tid(1));
            g.holders.insert(sid(1), Holding::Read);
            l.settle(&mut g).unwrap();
            assert!(g.shredded.is_empty() && !l.waits(&sid(1)) && !l.pass_sourced(&sid(1)), "the lists gave S back");
            continue;
        }
        g.passes.insert(sid(1), 13);
        l.settle(&mut g).unwrap();
        assert_eq!(g.shredded, vec![sid(1)], "no list came by the pass with a source: lost");
        assert!(g.forgot.is_empty() && g.syncs(1).is_none());
    }
    let (mut g, mut l) = settled();
    g.passing.insert(sid(1));
    g.clock = 10;
    g.holders.remove(&sid(1));
    l.settle(&mut g).unwrap();
    g.passes.insert(sid(1), 11);
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1)], "nothing uncounted: lost after the first pass");
}

// spec/sync-set.md §3 (its list may still come): a sync
// ID waiting for a pass with a source whose thing leaves the closure (the user unsyncs it) stops
// at once, no pass with a source needed; one already out of the closure waits for none.
#[test]
fn an_unsync_ends_a_wait_for_lists_spec_sync_set_3() {
    for unsync_first in [false, true] {
        let (mut g, mut l) = settled();
        g.passing.insert(sid(1));
        g.clock = 10;
        g.holders.remove(&sid(1));
        g.uncounted.insert(tid(1));
        if unsync_first {
            g.closure(&[2, 3]);
        }
        l.settle(&mut g).unwrap();
        g.clock = 12;
        g.passes.insert(sid(1), 11);
        l.settle(&mut g).unwrap();
        if !unsync_first {
            assert!(g.shredded.is_empty() && l.pass_sourced(&sid(1)), "waits for a pass with a source");
            g.closure(&[2, 3]);
            l.settle(&mut g).unwrap();
        }
        assert_eq!(g.shredded, vec![sid(1)], "out of the closure: no list gives S back");
        assert!(!l.pass_sourced(&sid(1)) && g.syncs(1).is_none());
    }
}
