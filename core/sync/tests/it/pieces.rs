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
    let edited = live(&mut w, 2, &t);
    let reused: BTreeSet<BlobId> = edited.intersection(&first).copied().collect();
    assert!(!reused.is_empty(), "the edit reuses chunks");
    purge(&mut w, 0, t, c);
    w.run();
    assert!(reused.is_disjoint(&entries(&w, 1, &s)), "the purger deleted them at node 1");
    w.heal();
    w.partition(0, 2);
    w.run();
    assert_eq!(read_big(&mut w, 0, &t), Some(Value::Bytes(v)), "node 0 reads the repaired value whole");
    assert!(reused.is_disjoint(&live(&mut w, 2, &t)), "node 2's value links no deleted chunk");
    let own: Vec<CommitId> = w.engine(2).own_commits(&s).unwrap().iter().copied().collect();
    let repairs: Vec<_> = own.iter().map(|c| w.engine(2).read_facts(&s, c).unwrap().repair_fresh).filter(|f| !f.is_empty()).collect();
    assert_eq!(repairs.len(), 1, "one commit, marked a repair");
    // marked with what it encrypted afresh alone: the chunks it reused stay repairable through it
    let now = live(&mut w, 2, &t);
    assert!(repairs[0].is_subset(&now) && repairs[0].is_disjoint(&edited), "{:?}", repairs[0]);
    assert!(now.iter().any(|b| edited.contains(b) && !repairs[0].contains(b)), "the repair reuses chunks");
}

/// Pieces judged (`read: piece judged`) and nodes decoded across the three nodes for a 4-byte edit
/// to a value of `kib` KiB node 0 wrote, and the pieces of the edited value.
fn edit_costs(kib: usize) -> (u64, u64, usize) {
    let (mut w, t, _) = three(Gives::Reads);
    let mut v = vec![0u8; kib << 10];
    osis_crypto::RngCore::fill_bytes(&mut osis_crypto::SeededRng::from_u64(5), &mut v);
    write_big(&mut w, 0, t, v.clone());
    w.run();
    let n = v.len();
    v[n - 4..].copy_from_slice(b"edit");
    osis_base::costs::take();
    write_big(&mut w, 0, t, v.clone());
    w.run();
    let taken = osis_base::costs::take();
    let count = |name: &str| taken.iter().filter(|(k, _, _)| *k == name).map(|(_, _, n)| n).sum::<u64>();
    assert_eq!(read_big(&mut w, 2, &t), Some(Value::Bytes(v)), "the edit read whole at node 2");
    (count("read: piece judged"), count("pieces: nodes decoded"), live(&mut w, 0, &t).len())
}

// spec/sync.md §2 (work in proportion to change): a small edit to a large value judges and
// decodes the pieces it wrote, not the value's tree: about the same at n and 10n pieces (an
// absent store row a piece reads shares its stamp with a 64th of the others, so a removal
// re-judges a few).
#[test]
fn a_small_edit_to_a_large_value_costs_its_new_pieces() {
    let (small, large) = (edit_costs(256), edit_costs(2560));
    assert!(large.2 >= 8 * small.2, "{small:?} {large:?}");
    assert_eq!(small.1, large.1, "nodes decoded: {small:?} {large:?}");
    assert!(large.0 < 2 * small.0, "pieces judged grow with the tree: {small:?} {large:?}");
}

/// After `three(gives)`, node 0 writes thing 0 once: per commit it added with a body under S, the
/// entries at node 1 and at node 2 of its blobs (any opened or sealed at nodes 0 and 2), and of
/// those, the writer's (node 0's own entries).
fn one_write_entries(gives: Gives) -> Vec<[usize; 4]> {
    let (mut w, t, s) = three(gives);
    let before: BTreeSet<CommitId> = w.engine(0).commit_ids().into_iter().collect();
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &crate::harness::history::value_ak(), &Value::Str("one".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    let mut out = Vec::new();
    for c in w.engine(0).commit_ids() {
        if before.contains(&c) || w.engine(0).sync_bodies(&c).unwrap().get(&s).is_none() {
            continue;
        }
        let blobs: BTreeSet<BlobId> = [0, 2].iter().flat_map(|i| w.engine(*i).commit_blobs(&c).unwrap().to_vec()).collect();
        let writers: BTreeSet<BlobId> = w.store(0).entries(&s).unwrap().iter().filter(|e| e.own && blobs.contains(&e.blob)).map(|e| e.blob).collect();
        let at = |i: usize, of: &BTreeSet<BlobId>| w.store(i).entries(&s).unwrap().iter().filter(|e| of.contains(&e.blob)).count();
        out.push([at(1, &blobs), at(1, &writers), at(2, &blobs), at(2, &writers)]);
    }
    out
}

// spec/sync-judgement.md §3 (Own store: a held blob of the commit goes on verbatim), spec/crypto.md
// §5 (Passing on: a fresh encryption only where required): a reader keeps the writer's blob of a
// write as its own store's entry and makes none of its own, so a node keeping S unread stores one
// blob of the write, not one per reader; a reader that writes too likewise.
#[test]
fn a_write_is_one_blob_however_many_read_it_spec_sync_judgement_3() {
    for gives in [Gives::Reads, Gives::Writes] {
        let got = one_write_entries(gives);
        assert_eq!(got, vec![[1; 4]], "{gives:?}: the write's blobs at the store, the writer's of them, at the reader, the writer's of them");
    }
}
