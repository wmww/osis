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
    synced: BTreeMap<SyncId, Held>,
    shredded: Vec<SyncId>,
    forgot: Vec<Tid>,
}

impl SetGround for Fake {
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
    fn set_synced(&mut self, s: &SyncId, now: Option<Held>) {
        match now {
            Some(h) => self.synced.insert(*s, h),
            None => self.synced.remove(s),
        };
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
    fn shared(&mut self, s: &SyncId) -> Result<bool> {
        Ok(!self.unshared.contains(s))
    }
    fn shred(&mut self, s: &SyncId) -> Result<()> {
        self.shredded.push(*s);
        Ok(())
    }
    fn forget_local(&mut self, t: &Tid) -> Result<()> {
        self.forgot.push(*t);
        Ok(())
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

// spec/sync-set.md §3 (it waits only while some peer shares S): a sync ID no peer shares (this node's only copy, no
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
