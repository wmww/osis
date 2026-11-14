#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! spec: none (the record's layout is the store's own; spec/sync-opens.md §3 and
//! core/test/tla/net/ASSUMPTIONS.md: a record and the log are one durable unit).

use crate::common;

use common::*;
use osis_base::SyncId;
use osis_crypto::SeededRng;
use osis_store::{Fault, RecordId, Shred, Store};
use std::collections::BTreeSet;

fn l(n: u8) -> SyncId {
    SyncId([n; 16])
}

fn create(s: &mut Store, rng: &mut SeededRng, r: u8, actor: u8) -> RecordId {
    let mut t = s.transaction(rng).unwrap();
    let id = t.record_create([r; 32], &[tid(actor)]).unwrap();
    t.commit().unwrap();
    id
}

// a record is one atomic unit: a crash at any write of its creation with its first rows leaves
// it whole or absent
#[test]
fn crash_at_any_write_leaves_a_record_whole_or_absent() {
    let run = |k: u64| {
        let (d, mut rng, mut s) = fresh(cfg());
        d.backend.faults().at(k, Fault::Crash);
        let mut t = s.transaction(&mut rng).unwrap();
        let id = t.record_create([7; 32], &[tid(1), tid(2)]).unwrap();
        t.record_put_row(&id, b'm', &l(1), b"", b"member".to_vec()).unwrap();
        t.record_put_wide_row(&id, b'c', b"", b"cur".to_vec()).unwrap();
        let _ = t.commit();
        drop(s);
        d.backend.faults().revive();
        let mut s = reopen(&d);
        let mut t = s.transaction(&mut rng).unwrap();
        let found = t.records_of_actors(&[tid(1)]).unwrap();
        match found.as_slice() {
            [] => {
                assert!(t.records_of_actors(&[tid(2)]).unwrap().is_empty(), "crash at write {k}: an actor index row outlived its record");
                assert_eq!(t.records_total().unwrap(), 0, "crash at write {k}: a total without a record");
                assert!(t.records_with_row(&l(1), b'm', b"", 10).unwrap().is_empty(), "crash at write {k}: an index row without its record");
                false
            }
            [r] => {
                assert_eq!(t.record_get_wide_row(&r.id, b'c', b"").unwrap().as_deref(), Some(b"cur".as_slice()), "crash at write {k}: a record without its row");
                assert_eq!(t.records_with_row(&l(1), b'm', b"", 10).unwrap(), [r.id], "crash at write {k}: a row without its index");
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

// a cursor row is written by the transaction applying what it covers (spec/sync-streams.md §3
// Durability): data and cursor cannot split at any write of that transaction
#[test]
fn crash_at_any_write_keeps_a_row_with_its_applied_data() {
    let (mut seen_none, mut seen_both) = (false, false);
    for k in 0..24 {
        let (d, mut rng, mut s) = fresh(cfg());
        let id = create(&mut s, &mut rng, 7, 1);
        d.backend.faults().at(k, Fault::Crash);
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"applied", b"1", Shred::Yes).unwrap();
        t.log_added(l(3), osis_base::BlobId([1; 32])).unwrap();
        t.record_put_wide_row(&id, b'c', b"", b"cur".to_vec()).unwrap();
        let _ = t.commit();
        drop(s);
        d.backend.faults().revive();
        let mut s = reopen(&d);
        let mut t = s.transaction(&mut rng).unwrap();
        let applied = t.get_local(b"applied").unwrap().is_some();
        let cursor = t.record_get_wide_row(&id, b'c', b"").unwrap();
        assert_eq!(applied, cursor.is_some(), "crash at write {k}: a cursor and its data split");
        assert_eq!(applied, t.log_end().unwrap() > 0, "crash at write {k}: a cursor and the log's event split");
        seen_none |= !applied;
        seen_both |= applied;
    }
    assert!(seen_none && seen_both, "the crash points reach both outcomes");
}

// spec/sync-opens.md §3: a node that stops holding S drops it from every record, every module's
// rows of it, in that same transaction; `changed_forget` is that transaction
#[test]
fn forgetting_a_sync_id_drops_it_from_every_record_in_one_step() {
    let (_d, mut rng, mut s) = fresh(cfg());
    let a = create(&mut s, &mut rng, 1, 1);
    let b = create(&mut s, &mut rng, 2, 2);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_put_row(&a, b'm', &l(1), b"", vec![1]).unwrap();
    t.record_put_row(&a, b'k', &l(1), &[7; 32], vec![]).unwrap();
    t.record_put_row(&b, b'm', &l(1), b"", vec![1]).unwrap();
    t.record_put_row(&b, b'm', &l(2), b"", vec![1]).unwrap();
    t.record_put_wide_row(&b, b'c', b"", vec![1]).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    t.changed_forget(&l(1)).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.record_tag_rows(&a, b'm').unwrap().is_empty() && t.record_tag_rows(&a, b'k').unwrap().is_empty());
    assert_eq!(t.record_tag_rows(&b, b'm').unwrap().iter().map(|(x, ..)| *x).collect::<Vec<_>>(), [l(2)]);
    assert!(t.record_get_wide_row(&b, b'c', b"").unwrap().is_some(), "a record-wide row stays");
    assert!(t.records_with_row(&l(1), b'm', b"", 10).unwrap().is_empty());
    // a record-wide row is about no sync ID: no sync ID's leaving takes it, the all-zero one's
    // neither
    t.changed_forget(&l(0)).unwrap();
    assert!(t.record_get_wide_row(&b, b'c', b"").unwrap().is_some());
}

// spec/sync-opens.md §3, RECORD_BUDGET: past the budget the least recently used record not in
// use goes, whole, with every module's rows, and its bytes come back to the count; a record in
// use is not dropped
#[test]
fn eviction_drops_the_least_recently_used_not_in_use_whole() {
    let (_d, mut rng, mut s) = fresh(cfg());
    let a = create(&mut s, &mut rng, 1, 1);
    let b = create(&mut s, &mut rng, 2, 2);
    let c = create(&mut s, &mut rng, 3, 3);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_put_row(&a, b'm', &l(1), b"", vec![1; 10]).unwrap();
    t.record_put_wide_row(&a, b'F', &1u64.to_be_bytes(), vec![0; 1000]).unwrap();
    // b most recent, a next, c least
    t.record_used(&a, &[tid(1)]).unwrap();
    t.record_used(&b, &[tid(2)]).unwrap();
    t.commit().unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    let total = t.records_total().unwrap();
    assert!(total > 1000, "every row counts");
    let in_use: BTreeSet<RecordId> = [c].into();
    assert_eq!(t.records_evict(total - 1, &in_use).unwrap(), [a]);
    assert!(t.record(&a).unwrap().is_none(), "the least recently used not in use goes");
    assert!(t.record(&c).unwrap().is_some(), "a record in use stays");
    assert!(t.record(&b).unwrap().is_some());
    assert!(t.records_of_actors(&[tid(1)]).unwrap().is_empty(), "with its actor rows");
    assert!(t.record_tag_rows(&a, b'm').unwrap().is_empty() && t.record_wide_rows(&a, b'F').unwrap().is_empty(), "and its rows");
    assert!(t.records_with_row(&l(1), b'm', b"", 10).unwrap().is_empty(), "and their index");
    assert!(t.records_total().unwrap() < total - 1000);
    // 0: only what is in use is left (a resource bound, a defined outcome)
    t.records_evict(0, &in_use).unwrap();
    assert!(t.record(&b).unwrap().is_none());
    assert!(t.record(&c).unwrap().is_some());
}

// a restored or copied store holds its records as they stood (the model's restore and copy): the
// same pair key, the state of that moment, nothing shared with the original afterwards
#[test]
fn a_copied_or_restored_store_keeps_its_records_as_of_the_copy() {
    let (d, mut rng, mut s) = fresh(cfg());
    let a = create(&mut s, &mut rng, 1, 1);
    let copy = d.copy();
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_put_wide_row(&a, b'c', b"", b"later".to_vec()).unwrap();
    let b = t.record_create([2; 32], &[tid(1)]).unwrap();
    t.commit().unwrap();
    let mut c = reopen(&copy);
    let mut t = c.transaction(&mut rng).unwrap();
    let held = t.records_of_actors(&[tid(1)]).unwrap();
    assert_eq!(held.len(), 1, "the record made after the copy is not in it");
    assert_eq!(held[0].r, [1; 32], "the pair key is the copy's own, as it was");
    assert_eq!(t.record_get_wide_row(&a, b'c', b"").unwrap(), None, "and its rows as of the copy");
    assert!(t.record(&b).unwrap().is_none());
}

// the index finds the records holding one row by its sync ID, tag and exact key: a longer key
// under the same prefix is another row
#[test]
fn the_index_finds_records_by_exact_row() {
    let (_d, mut rng, mut s) = fresh(cfg());
    let a = create(&mut s, &mut rng, 1, 1);
    let b = create(&mut s, &mut rng, 2, 2);
    let mut t = s.transaction(&mut rng).unwrap();
    t.record_put_row(&a, b'k', &l(1), &[5; 32], vec![]).unwrap();
    t.record_put_row(&b, b'k', &l(1), &[5; 32], vec![]).unwrap();
    t.record_put_row(&b, b'k', &l(1), &[6; 32], vec![]).unwrap();
    t.record_put_row(&a, b'm', &l(1), b"x", vec![]).unwrap();
    let mut both = t.records_with_row(&l(1), b'k', &[5; 32], 10).unwrap();
    both.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(both, want);
    assert_eq!(t.records_with_row(&l(1), b'k', &[6; 32], 10).unwrap(), [b]);
    assert_eq!(t.records_with_row(&l(1), b'k', &[5; 32], 1).unwrap().len(), 1, "at most the limit");
    assert!(t.records_with_row(&l(1), b'm', b"", 10).unwrap().is_empty(), "a longer key is another row");
    assert!(t.record_remove_row(&b, b'k', &l(1), &[6; 32]).unwrap());
    assert!(t.records_with_row(&l(1), b'k', &[6; 32], 10).unwrap().is_empty());
}

// the lookup reads the records of the proven actors, however many others the node keeps
#[test]
fn a_lookup_reads_only_the_records_of_the_proven_actors() {
    for n in [10u32, 100] {
        let (_d, mut rng, mut s) = fresh(cfg());
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



// a module's rows in a record (notes/sync-boundary.md U3): counted in the record's bytes, gone
// with the record (eviction) and with their sync ID (`changed_forget`), never written into a
// record that is gone
#[test]
fn owned_rows_go_with_the_record_and_the_sync_id() {
    let (_d, mut rng, mut s) = fresh(cfg());
    let a = create(&mut s, &mut rng, 1, 1);
    let mut t = s.transaction(&mut rng).unwrap();
    let before = t.records_total().unwrap();
    t.record_put_row(&a, b's', &l(1), b"k1", vec![1; 10]).unwrap();
    t.record_put_row(&a, b's', &l(2), b"k2", vec![2; 10]).unwrap();
    t.record_put_row(&a, b'd', &l(1), b"k3", vec![3; 10]).unwrap();
    assert!(t.records_total().unwrap() > before);
    assert_eq!(t.record_rows(&a, b's', &l(1), b"", 10).unwrap(), [(b"k1".to_vec(), vec![1; 10])]);
    t.changed_forget(&l(1)).unwrap();
    assert!(t.record_get_row(&a, b's', &l(1), b"k1").unwrap().is_none() && t.record_get_row(&a, b'd', &l(1), b"k3").unwrap().is_none());
    assert_eq!(t.record_get_row(&a, b's', &l(2), b"k2").unwrap(), Some(vec![2; 10]));
    assert!(t.record_remove_row(&a, b's', &l(2), b"k2").unwrap());
    assert_eq!(t.records_total().unwrap(), before, "every row's bytes went with it");
    t.record_put_row(&a, b's', &l(2), b"k2", vec![2; 10]).unwrap();
    t.records_evict(0, &BTreeSet::new()).unwrap();
    assert!(t.record_get_row(&a, b's', &l(2), b"k2").unwrap().is_none(), "evicted with the record");
    t.record_put_row(&a, b's', &l(2), b"k2", vec![2; 10]).unwrap();
    assert!(t.record_get_row(&a, b's', &l(2), b"k2").unwrap().is_none(), "a gone record takes nothing");
    assert_eq!(t.records_total().unwrap(), 0);
}
