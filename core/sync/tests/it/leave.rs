//! Leaving, read side (spec/sync-set.md §3) on a fake ground: the sync set, the store's sync IDs,
//! what this node reads, and whether its own commits under S are held elsewhere, each a stamped value, so
//! `Leave` follows them as in a node. What it does (shredding, forgetting) is recorded.

use osis_base::memo::{Stamped, StampedSet};
use osis_base::{SyncId, Tid};
use osis_engine::sync::{Holding, SyncSet};
use osis_sync::Result;
use osis_sync::leave::{Ground, Leave};
use std::collections::BTreeSet;
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

#[derive(Default)]
struct Fake {
    set: Stamped<(), Arc<SyncSet>>,
    stored: Stamped<(), BTreeSet<SyncId>>,
    owners: Stamped<SyncId, Tid>,
    /// Sync IDs whose thing this node still reads (holds a read secret of).
    reads: StampedSet<SyncId>,
    unread: StampedSet<SyncId>,
    elsewhere: StampedSet<SyncId>,
    shredded: Vec<SyncId>,
    forgot: Vec<Tid>,
}

impl Ground for Fake {
    fn sync_set(&mut self) -> Result<Arc<SyncSet>> {
        Ok(self.set.get(&()).cloned().unwrap_or_default())
    }
    fn stored(&mut self) -> Result<BTreeSet<SyncId>> {
        Ok(self.stored.get(&()).cloned().unwrap_or_default())
    }
    fn owner(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        Ok(self.owners.get(s).copied())
    }
    fn reads(&mut self, t: &Tid, s: &SyncId) -> Result<bool> {
        Ok(self.owners.get(s) == Some(t) && self.reads.contains(s))
    }
    fn unread_keeps(&self, s: &SyncId) -> bool {
        self.unread.contains(s)
    }
    fn own_elsewhere(&mut self, s: &SyncId) -> Result<bool> {
        Ok(self.elsewhere.contains(s))
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
    /// The sync set: each (thing, its sync ID) read, still read here.
    fn set(&mut self, read: &[u8]) {
        let ids = read.iter().map(|i| (sid(*i), (tid(*i), Holding::Read))).collect();
        self.set.insert((), Arc::new(SyncSet { ids, ..SyncSet::default() }));
        for i in read {
            self.owners.insert(sid(*i), tid(*i));
            self.reads.insert(sid(*i));
        }
    }
}

/// A node with things 1..=3, each read under its own sync ID with rows in the store.
fn settled() -> (Fake, Leave) {
    let mut g = Fake::default();
    g.set(&[1, 2, 3]);
    g.stored.insert((), [sid(1), sid(2), sid(3)].into());
    let mut l = Leave::default();
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty(), "nothing left");
    (g, l)
}

// spec/sync-set.md §3 (one rule ends syncing it; Unsyncing): a read sync ID whose thing left the
// synced group's closure, still read here, stops once its own commits are held elsewhere:
// its thing's copy forgotten, then its store shredded; not before.
#[test]
fn unsynced_stops_once_own_entries_are_elsewhere_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.set(&[2, 3]);
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.forgot.is_empty(), "own commits not yet held elsewhere");
    g.elsewhere.insert(sid(1));
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1)]));
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded.len(), 1, "once");
}

// spec/sync-set.md §3 (synced again before then, S is kept as it was): a leaving sync ID listed
// again is neither forgotten nor shredded when its entries are elsewhere later.
#[test]
fn synced_again_before_it_stops_keeps_it_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.set(&[2, 3]);
    l.settle(&mut g).unwrap();
    g.set(&[1, 2, 3]);
    l.settle(&mut g).unwrap();
    g.elsewhere.insert(sid(1));
    l.settle(&mut g).unwrap();
    assert!(g.shredded.is_empty() && g.forgot.is_empty());
    assert_eq!(l.judged(), 1, "judged once while it left, not after");
}

// spec/sync-set.md §3 (stops at once; lowering from read to sync is no leaving): a read sync ID
// that left with no secret of its thing held is shredded at once, nothing forgotten; lowered to
// kept unread it is not shredded.
#[test]
fn removed_stops_at_once_lowered_is_no_leaving_spec_sync_set_3() {
    let (mut g, mut l) = settled();
    g.reads.remove(&sid(1));
    let mut set = SyncSet::default();
    set.ids.insert(sid(2), (tid(2), Holding::Read));
    set.ids.insert(sid(3), (tid(3), Holding::Unread));
    g.set.insert((), Arc::new(set));
    l.settle(&mut g).unwrap();
    assert_eq!(g.shredded, vec![sid(1)]);
    assert!(g.forgot.is_empty());
}

// spec/sync-set.md §3 (on stopping): at a start, a read sync ID whose rows the store holds
// outside the sync set left while the node was down: it waits as any leaving one; another's rows
// (an inbox this node deposits to) and one kept unread are left alone.
#[test]
fn a_start_finds_what_left_while_down_spec_sync_set_3() {
    let mut g = Fake::default();
    g.set(&[2]);
    g.owners.insert(sid(1), tid(1));
    g.reads.insert(sid(1));
    g.owners.insert(sid(7), tid(7));
    g.owners.insert(sid(8), tid(8));
    g.unread.insert(sid(8));
    g.reads.insert(sid(8));
    g.stored.insert((), [sid(1), sid(2), sid(7), sid(8)].into());
    g.elsewhere.insert(sid(1));
    g.elsewhere.insert(sid(8));
    let mut l = Leave::default();
    l.settle(&mut g).unwrap();
    assert_eq!((g.forgot.clone(), g.shredded.clone()), (vec![tid(1)], vec![sid(1)]));
}
