#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! spec: none (the record's layout is the store's own; issues/net-reconnect.md The record, and
//! core/test/tla/net/ASSUMPTIONS.md: a record and the log are one durable unit).

use crate::common;

use common::*;
use osis_base::LabelId;
use osis_crypto::SeededRng;
use osis_store::{Fault, Member, MemoryBackend, MemoryRoot, RecordId, Shred, Store};
use std::collections::BTreeSet;

fn l(n: u8) -> LabelId {
    LabelId([n; 16])
}

struct Dev {
    backend: MemoryBackend,
    root: MemoryRoot,
}

impl Dev {
    fn new() -> (Dev, Store, SeededRng) {
        let mut rng = SeededRng::from_u64(9);
        let d = MemDevice::new();
        let s = Store::create(d.backend(), d.root(), cfg(), &mut rng).unwrap();
        (Dev { backend: d.backend, root: d.root }, s, rng)
    }
    fn open(&self) -> Store {
        Store::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), cfg()).unwrap()
    }
    fn copy(&self) -> Dev {
        Dev { backend: self.backend.copy(), root: self.root.copy() }
    }
}

fn member() -> Member {
    Member { proved: (1, 2), until: None, lag: None }
}

fn create(s: &mut Store, rng: &mut SeededRng, r: u8, actor: u8) -> RecordId {
    let mut t = s.transaction(rng).unwrap();
    let id = t.record_create([r; 32], &[tid(actor)]).unwrap();
    t.commit().unwrap();
    id
}

// a record is one atomic unit (issues/net-reconnect.md, Restart and loss): a crash at any write
// of its creation, a member's open and its close leaves it whole or absent
#[test]
fn crash_at_any_write_leaves_a_record_whole_or_absent() {
    let run = |k: u64| {
        let (d, mut s, mut rng) = Dev::new();
        d.backend.faults().at(k, Fault::Crash);
        let mut t = s.transaction(&mut rng).unwrap();
        let id = t.record_create([7; 32], &[tid(1), tid(2)]).unwrap();
        t.record_open(&id, l(1), &member()).unwrap();
        t.record_set_cursor(&id, Some(b"cur".to_vec())).unwrap();
        let _ = t.commit();
        drop(s);
        d.backend.faults().revive();
        let mut s = d.open();
        let mut t = s.transaction(&mut rng).unwrap();
        let found = t.records_of_actors(&[tid(1)]).unwrap();
        match found.as_slice() {
            [] => {
                assert!(t.records_of_actors(&[tid(2)]).unwrap().is_empty(), "crash at write {k}: an actor index row outlived its record");
                assert_eq!(t.records_total().unwrap(), 0, "crash at write {k}: a total without a record");
                false
            }
            [r] => {
                assert_eq!(r.cursor.as_deref(), Some(b"cur".as_slice()), "crash at write {k}: a record without its cursor");
                assert_eq!(t.record_members(&r.id).unwrap().len(), 1, "crash at write {k}: a record without its member");
                assert!(t.records_total().unwrap() > 0);
                true
            }
            more => panic!("crash at write {k}: {} records", more.len()),
        }
    };
    let (mut gone, mut whole) = (false, false);
    for k in 0..40 {
        if run(k) {
            whole = true;
        } else {
            gone = true;
        }
    }
    assert!(gone && whole, "the crash points reach both outcomes");
}

// a cursor is stored only by the transaction applying what it covers (issues/net-reconnect.md,
// Restart and loss): data and cursor cannot split at any write of that transaction
#[test]
fn crash_at_any_write_keeps_a_cursor_with_its_applied_data() {
    let (mut seen_none, mut seen_both) = (false, false);
    for k in 0..24 {
        let (d, mut s, mut rng) = Dev::new();
        let id = create(&mut s, &mut rng, 7, 1);
        d.backend.faults().at(k, Fault::Crash);
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"applied", b"1", Shred::Yes).unwrap();
        t.record_set_cursor(&id, Some(b"cur".to_vec())).unwrap();
        let _ = t.commit();
        drop(s);
        d.backend.faults().revive();
        let mut s = d.open();
        let mut t = s.transaction(&mut rng).unwrap();
        let applied = t.get_local(b"applied").unwrap().is_some();
        let cursor = t.record(&id).unwrap().unwrap().cursor;
        assert_eq!(applied, cursor.is_some(), "crash at write {k}: a cursor and its data split");
        seen_none |= !applied;
        seen_both |= applied;
    }
    assert!(seen_none && seen_both, "the crash points reach both outcomes");
}

// issues/net-shared-set.md, Re-marking: every close sets `acked_pos` to min(self, changed_at - 1),
// whether or not the record held the member, and touches no other record
#[test]
fn a_close_remarks_this_record_alone_to_below_the_changed_at() {
    let (_d, mut s, mut rng) = Dev::new();
    let a = create(&mut s, &mut rng, 1, 1);
    let b = create(&mut s, &mut rng, 2, 2);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_open(&a, l(1), &member()).unwrap();
    assert_eq!(t.record_rise_acked(&a, 100).unwrap(), 100);
    assert_eq!(t.record_rise_acked(&b, 100).unwrap(), 100);
    assert_eq!(t.record_close(&a, &l(1), 40, None).unwrap(), 39, "below changed_at");
    assert!(t.record_members(&a).unwrap().is_empty());
    assert_eq!(t.record(&b).unwrap().unwrap().acked_pos, 100, "another peer's record is untouched");
    assert_eq!(t.record_close(&a, &l(1), 90, None).unwrap(), 39, "a later changed_at leaves it");
    assert_eq!(t.record_close(&a, &l(9), 10, None).unwrap(), 9, "a member the record did not hold is re-marked too");
    assert_eq!(t.record_rise_acked(&a, 5).unwrap(), 9, "only re-marking lowers it");
}

// issues/net-reconnect.md, Lost and rejoin: an older lag is kept, and a rejoin spends it
#[test]
fn a_stop_keeps_the_older_lag_until_a_rejoin_spends_it() {
    let (_d, mut s, mut rng) = Dev::new();
    let a = create(&mut s, &mut rng, 1, 1);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_close(&a, &l(1), 1, Some(b"old".to_vec())).unwrap();
    t.record_close(&a, &l(1), 1, Some(b"new".to_vec())).unwrap();
    assert_eq!(t.record_lag(&a, &l(1)).unwrap().as_deref(), Some(b"old".as_slice()));
    assert_eq!(t.record_take_lag(&a, &l(1)).unwrap().as_deref(), Some(b"old".as_slice()));
    assert_eq!(t.record_lag(&a, &l(1)).unwrap(), None);
    t.record_close(&a, &l(1), 1, Some(b"new".to_vec())).unwrap();
    assert_eq!(t.record_lag(&a, &l(1)).unwrap().as_deref(), Some(b"new".as_slice()));
}

// issues/net-reconnect.md, Changes: a node that stops holding L drops it from every record's S and
// every lag of it, in that same transaction; `log_forget` is that transaction
#[test]
fn forgetting_a_sync_id_drops_it_from_every_record_in_one_step() {
    let (_d, mut s, mut rng) = Dev::new();
    let a = create(&mut s, &mut rng, 1, 1);
    let b = create(&mut s, &mut rng, 2, 2);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_open(&a, l(1), &member()).unwrap();
    t.record_open(&b, l(1), &member()).unwrap();
    t.record_open(&b, l(2), &member()).unwrap();
    t.record_close(&a, &l(1), 1, Some(b"lag".to_vec())).unwrap();
    t.record_open(&a, l(1), &member()).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    t.log_forget(l(1)).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.record_members(&a).unwrap().is_empty());
    assert_eq!(t.record_members(&b).unwrap().iter().map(|(x, _)| *x).collect::<Vec<_>>(), [l(2)]);
    assert_eq!(t.record_lag(&a, &l(1)).unwrap(), None, "its lag goes too");
}

// issues/net-reconnect.md, RECORD_BUDGET: past the budget the least recently used record not in
// use goes, whole, and its bytes come back to the count; a record in use is not dropped
#[test]
fn eviction_drops_the_least_recently_used_not_in_use_whole() {
    let (_d, mut s, mut rng) = Dev::new();
    let a = create(&mut s, &mut rng, 1, 1);
    let b = create(&mut s, &mut rng, 2, 2);
    let c = create(&mut s, &mut rng, 3, 3);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_open(&a, l(1), &member()).unwrap();
    // b most recent, a next, c least
    t.record_used(&a, &[tid(1)]).unwrap();
    t.record_used(&b, &[tid(2)]).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let total = t.records_total().unwrap();
    let in_use: BTreeSet<RecordId> = [c].into();
    assert_eq!(t.records_evict(total - 1, &in_use).unwrap(), 1);
    assert!(t.record(&a).unwrap().is_none(), "the least recently used not in use goes");
    assert!(t.record(&c).unwrap().is_some(), "a record in use stays");
    assert!(t.record(&b).unwrap().is_some());
    assert!(t.records_of_actors(&[tid(1)]).unwrap().is_empty(), "with its actor rows");
    assert!(t.record_members(&a).unwrap().is_empty(), "and its members");
    assert!(t.records_total().unwrap() < total);
    // 0: only what is in use is left (a resource bound, a defined outcome)
    t.records_evict(0, &in_use).unwrap();
    assert!(t.record(&b).unwrap().is_none());
    assert!(t.record(&c).unwrap().is_some());
}

// a restored or copied store holds its records as they stood (the model's restore and copy): the
// same pair key, the state of that moment, nothing shared with the original afterwards
#[test]
fn a_copied_or_restored_store_keeps_its_records_as_of_the_copy() {
    let (d, mut s, mut rng) = Dev::new();
    let a = create(&mut s, &mut rng, 1, 1);
    let copy = d.copy();
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_set_cursor(&a, Some(b"later".to_vec())).unwrap();
    let b = t.record_create([2; 32], &[tid(1)]).unwrap();
    t.commit().unwrap();
    let mut c = copy.open();
    let mut t = c.transaction(&mut rng).unwrap();
    let held = t.records_of_actors(&[tid(1)]).unwrap();
    assert_eq!(held.len(), 1, "the record made after the copy is not in it");
    assert_eq!(held[0].r, [1; 32], "the pair key is the copy's own, as it was");
    assert_eq!(held[0].cursor, None, "and the cursor as of the copy");
    assert!(t.record(&b).unwrap().is_none());
}

// the lookup reads the records of the proven actors, however many others the node keeps
#[test]
fn a_lookup_reads_only_the_records_of_the_proven_actors() {
    for n in [10u32, 100] {
        let (_d, mut s, mut rng) = Dev::new();
        let mut t = s.transaction(&mut rng).unwrap();
        for i in 0..n {
            let mut a = [0u8; 15];
            a[..4].copy_from_slice(&i.to_be_bytes());
            t.record_create([1; 32], &[osis_base::Tid::from_bytes(a)]).unwrap();
        }
        t.record_create([2; 32], &[tid(0xfe)]).unwrap();
        assert_eq!(t.records_of_actors(&[tid(0xfe)]).unwrap().len(), 1, "at n = {n}");
    }
}
