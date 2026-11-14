//! Linked blobs (pieces) end to end: chunk and tree-node blobs of large values go under the sync
//! IDs their commit goes under, freed ones are deleted at peers, and a reused chunk a purger
//! deleted is repaired by the node whose own commit links it.

use crate::harness::Step::*;
use crate::harness::history::{Gives, world};
use crate::harness::{World, play};
use osis_base::{Ak, BlobId, CommitId, SyncId, Tid, Value};
use osis_engine::Mutation;
use std::collections::BTreeSet;

fn big_ak() -> Ak {
    Ak::new("u:big.0").unwrap()
}

/// 256 KiB of seeded bytes: a value chunked into a tree of several chunks.
fn big(seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; 256 << 10];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(seed), &mut v);
    v
}

/// Node 0 makes thing 0 and grants node 1's account sync (it keeps the thing unread) and node 2's
/// `gives`.
fn three(gives: Gives) -> (World, Tid, SyncId) {
    let mut w = world(0, 3);
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, gives), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    (w, t, s)
}

fn write_big(w: &mut World, i: usize, t: Tid, v: Vec<u8>) -> CommitId {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &big_ak(), &Value::Bytes(v)).unwrap();
        e.commit(m).unwrap().unwrap()
    })
}

/// Node `i`'s value of `t`'s large aspect, read whole (`None`: none, or a piece not held).
fn read_big(w: &mut World, i: usize, t: &Tid) -> Option<Value> {
    match w.engine(i).get(t, &big_ak()).unwrap()? {
        Value::Link(l) => w.engine(i).read_large(t, &l).ok(),
        v => Some(v),
    }
}

/// A purge of `c`'s large write by node `i` (beside a small write: a commit needs a part).
fn purge(w: &mut World, i: usize, t: Tid, c: CommitId) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &crate::harness::history::value_ak(), &Value::Str("purged".into())).unwrap();
        m.purge_commit(c, t, big_ak());
        e.commit(m).unwrap();
    });
}

/// The chunk and node blobs `i`'s live states of `t` link.
fn live(w: &mut World, i: usize, t: &Tid) -> BTreeSet<BlobId> {
    w.engine(i).live_trees(t).unwrap().blobs
}

fn entries(w: &World, i: usize, s: &SyncId) -> BTreeSet<BlobId> {
    w.store(i).entries(s).unwrap().into_iter().map(|e| e.blob).collect()
}

// spec/sync-judgement.md §1 (chunk and tree-node blobs): they go under S too, as the same blobs
// with a filler wrap. Node 0 writes a large value while node 2 reaches only node 1, which keeps the
// thing unread; node 2 reads it whole through node 1 alone.
#[test]
fn a_large_value_reads_whole_through_a_node_keeping_it_unread_spec_sync_judgement_1() {
    let (mut w, t, s) = three(Gives::Reads);
    w.partition(0, 2);
    let v = big(1);
    write_big(&mut w, 0, t, v.clone());
    w.run();
    let pieces = live(&mut w, 0, &t);
    assert!(pieces.len() > 2, "chunked: {}", pieces.len());
    assert!(pieces.is_subset(&entries(&w, 1, &s)), "every piece kept unread at node 1");
    assert_eq!(read_big(&mut w, 2, &t), Some(Value::Bytes(v)), "read whole at node 2");
    assert!(pieces.is_subset(&entries(&w, 2, &s)), "node 2 logs the pieces it took");
}

// spec/sync-compaction.md §1 (freed links): deleted at each peer keeping S unread holding an entry
// of it, its bytes dropped. Node 0 purges its large write; its pieces leave its own store, node
// 1's and the engine's.
#[test]
fn a_purge_deletes_the_pieces_it_frees_at_peers_spec_sync_compaction_1() {
    let (mut w, t, s) = three(Gives::Reads);
    let c = write_big(&mut w, 0, t, big(2));
    w.run();
    let pieces = live(&mut w, 0, &t);
    assert!(pieces.is_subset(&entries(&w, 1, &s)));
    purge(&mut w, 0, t, c);
    w.run();
    for i in 0..3 {
        assert!(pieces.is_disjoint(&entries(&w, i, &s)), "node {i}: no piece left under S");
    }
    assert!(w.engine(0).freed_rows().is_empty(), "the freed set emptied once no entry is known");
    assert!(pieces.iter().all(|b| w.store(0).bytes(b).unwrap().is_none()), "their bytes gone at the purger");
}

// spec/sync-ids.md §1 (Repair): node 2 edits node 0's large value, reusing most of its chunks,
// while cut off; node 0, not having seen the reuse, purges its write, freeing those chunks, and
// deletes them at node 1. Node 2 comes back, finds the reused chunks deleted at every source, and
// writes the value again with them re-encrypted; node 0, reaching only node 1, reads it whole.
#[test]
fn a_reused_chunk_a_purger_deleted_is_repaired_spec_sync_ids_1() {
    let (mut w, t, s) = three(Gives::Writes);
    let mut v = big(3);
    let c = write_big(&mut w, 0, t, v.clone());
    w.run();
    assert_eq!(read_big(&mut w, 2, &t), Some(Value::Bytes(v.clone())));
    let first = live(&mut w, 0, &t);
    w.partition(0, 2);
    w.partition(1, 2);
    let n = v.len();
    v[n - 10..].copy_from_slice(b"node 2 was");
    write_big(&mut w, 2, t, v.clone());
    let reused: BTreeSet<BlobId> = live(&mut w, 2, &t).intersection(&first).copied().collect();
    assert!(!reused.is_empty(), "the edit reuses chunks");
    purge(&mut w, 0, t, c);
    w.run();
    assert!(reused.is_disjoint(&entries(&w, 1, &s)), "the purger deleted them at node 1");
    w.heal();
    w.partition(0, 2);
    w.run();
    assert_eq!(read_big(&mut w, 0, &t), Some(Value::Bytes(v)), "node 0 reads the repaired value whole");
    assert!(reused.is_disjoint(&live(&mut w, 2, &t)), "node 2's value links no deleted chunk");
}
