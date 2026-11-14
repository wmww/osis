//! The judgement facts per blob and per card (spec/sync-judgement.md §2-§3), each against a
//! party that would make an honest node drop data: what a blob carries is what this node opened
//! or sealed of it (`note_blob`, here standing in for an entry opened), never a peer's word.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::bodies::note_blob;
use super::{MustNot, PartSet};
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, BlobId, CommitId, SyncId, Tid, Value};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
    for id in ids {
        let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
        lp.deliver(to, &pk).unwrap();
    }
}

/// Peer `i` notes blob `b` of `c` holding `parts` as opened (a shared blob unless `copy`).
fn opened(lp: &mut LocalPeer, i: usize, b: u8, c: &CommitId, parts: &[usize], copy: bool) -> BlobId {
    let (id, c, ps) = (BlobId([b; 32]), *c, parts.iter().copied().collect::<PartSet>());
    lp.peers[i].engine.run(|tx| note_blob(tx, &id, &c, &ps, copy)).unwrap();
    id
}

/// One node of an account; its home sync ID and a commit writing two aspects of a thing in D:
/// the commit's two parts under home and whether its body there is a copy.
fn two_parts() -> (LocalPeer, (SyncId, CommitId, [usize; 2], bool)) {
    LocalPeer::cached("sync::tests_facts::two_parts", || {
        let mut lp = LocalPeer::new_bare(1, 0, T0).unwrap();
        let d = lp.peers[0].engine.create_account().unwrap().0.devices;
        let e = &mut lp.peers[0].engine;
        let home = e.home_sync_id(&d).unwrap().unwrap();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, d);
        e.commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(Value::Tid(t)) }).unwrap();
        e.commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.set(t, &ak("x:a.0"), &Value::Int(1)).unwrap();
        m.set(t, &ak("x:b.0"), &Value::Int(1)).unwrap();
        let c = e.commit(m).unwrap().unwrap();
        let meta = e.sync_bodies(&c).unwrap().get(&home).cloned().expect("a body under home");
        let ps: Vec<usize> = meta.parts.iter().copied().collect();
        (lp, (home, c, [ps[0], ps[1]], meta.copy))
    })
}

// spec/sync-judgement.md §2 must-not-hold (a blob of commit C whose delta set is a strict subset
// of another held blob of C under that sync ID that is not itself must-not-hold and whose extra
// deltas include one only a blob carries): the smaller blob goes, the larger stays.
#[test]
fn a_strict_subset_goes_beside_its_superset_spec_sync_judgement_2() {
    let (mut lp, (home, c, [p0, p1], copy)) = two_parts();
    let small = opened(&mut lp, 0, 1, &c, &[p0], copy);
    let big = opened(&mut lp, 0, 2, &c, &[p0, p1], copy);
    let e = &mut lp.peers[0].engine;
    let held = BTreeSet::from([small, big]);
    assert!(e.strict_subset(&home, &small, &held).unwrap());
    assert!(!e.strict_subset(&home, &big, &held).unwrap(), "the larger one stays");
    assert!(!e.strict_subset(&home, &small, &BTreeSet::from([small])).unwrap(), "alone: kept");
}

// spec/sync-judgement.md §2 strict subset, against a fake delta set: a blob a peer shows that
// this node never opened, or one of another commit, makes no honest blob a strict subset; nor
// does a larger blob of the other kind (a copy beside a shared blob carries nothing of it).
#[test]
fn a_fake_superset_drops_nothing_spec_sync_judgement_2() {
    let (mut lp, (home, c, [p0, p1], copy)) = two_parts();
    let small = opened(&mut lp, 0, 1, &c, &[p0], copy);
    let claimed = BlobId([3; 32]);
    let other = lp.peers[0].engine.commit_ids().into_iter().find(|x| *x != c).unwrap();
    let elsewhere = opened(&mut lp, 0, 4, &other, &[p0, p1], copy);
    let kind = opened(&mut lp, 0, 5, &c, &[p0, p1], !copy);
    let e = &mut lp.peers[0].engine;
    for x in [claimed, elsewhere, kind] {
        assert!(!e.strict_subset(&home, &small, &BTreeSet::from([small, x])).unwrap(), "{x:?} carries nothing of it");
    }
}

// spec/sync-judgement.md §2 strict subset, §1 Certificate blobs: a blob of the other kind than
// the body (a certificate copy of parts the shared blob also holds, sealed there under a secret
// S's readers may lack) is no strict subset of the shared blob, however much of it this node
// opens.
#[test]
fn a_copy_beside_the_shared_blob_stays_spec_sync_judgement_2() {
    let (mut lp, (home, c, [p0, p1], copy)) = two_parts();
    let other = opened(&mut lp, 0, 1, &c, &[p1], !copy);
    let big = opened(&mut lp, 0, 2, &c, &[p0, p1], copy);
    let e = &mut lp.peers[0].engine;
    assert!(!e.strict_subset(&home, &other, &BTreeSet::from([other, big])).unwrap());
}

// spec/sync-judgement.md §2 strict subset ("whose extra deltas include one only a blob carries:
// kept or holding a live write"): once the extra delta's write is replaced and past its keep
// bound, the two blobs are alike in what only a blob carries: neither is a strict subset.
#[test]
fn a_superset_of_dead_deltas_drops_nothing_spec_sync_judgement_2() {
    let (mut lp, (home, c, [p0, p1], copy)) = two_parts();
    let small = opened(&mut lp, 0, 1, &c, &[p0], copy);
    let big = opened(&mut lp, 0, 2, &c, &[p0, p1], copy);
    let h = lp.peers[0].engine.header(&c).unwrap();
    let a = &h.aspects[p1];
    let (t, extra) = (a.tid, a.ak.clone());
    let mut m = Mutation::new();
    m.set(t, &extra, &Value::Int(2)).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    lp.advance(10 * 366 * 24 * 3600 * 1000);
    let e = &mut lp.peers[0].engine;
    assert!(!e.delta_live(&c, &t, &extra).unwrap());
    assert!(!e.strict_subset(&home, &small, &BTreeSet::from([small, big])).unwrap());
}

// spec/sync-judgement.md §3 Neither (a delete stands while each delta only a blob carries is held
// there by another blob of the commit that is not must-not-hold): it stands beside a blob carrying
// both deltas; a source lying about what it holds (a blob never opened here, or one short of a
// live delta) makes no delete stand, so the body is logged again.
#[test]
fn neither_stands_only_on_what_is_opened_here_spec_sync_judgement_3() {
    let (mut lp, (home, c, [p0, p1], copy)) = two_parts();
    let small = opened(&mut lp, 0, 1, &c, &[p0], copy);
    let big = opened(&mut lp, 0, 2, &c, &[p0, p1], copy);
    let e = &mut lp.peers[0].engine;
    assert!(e.neither(&home, &c, &BTreeSet::from([big])).unwrap());
    assert!(!e.neither(&home, &c, &BTreeSet::from([small])).unwrap(), "short of a live delta");
    assert!(!e.neither(&home, &c, &BTreeSet::from([BlobId([3; 32])])).unwrap(), "a blob only claimed");
    assert!(!e.neither(&home, &c, &BTreeSet::new()).unwrap());
}

/// Peer 0's account with peer 1 paired as its second node; D.
fn two_nodes() -> (LocalPeer, Tid) {
    LocalPeer::cached("sync::tests_facts::two_nodes", || {
        let mut lp = LocalPeer::new_bare(2, 0, T0).unwrap();
        let p = lp.peers[0].engine.create_account().unwrap().0;
        let n = lp.peers[1].engine.tid();
        let card = lp.peers[1].engine.commit_ids();
        send(&mut lp, 1, 0, &card);
        let (_, out) = lp.peers[0].engine.pair(&n).unwrap();
        send(&mut lp, 0, 1, &out);
        lp.peers[1].engine.paired(&p.account).unwrap();
        (lp, p.devices)
    })
}

/// Peer `i`'s node writes its own `reach.0` a second later, sent to the other peer.
fn reach(lp: &mut LocalPeer, i: usize, k: u8) -> CommitId {
    lp.advance(1000);
    let n = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    m.set(n, &ct::REACH, &ct::Reach { dialable: [k; 32], items: Vec::new(), account: None }).unwrap();
    let c = lp.peers[i].engine.commit(m).unwrap().unwrap();
    send(lp, i, 1 - i, &[c]);
    c
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit once a later valid card
// commit of that node writing the same aspect is under the sync ID, an entry of it this node
// opened and checked against its header): it goes once an entry of the later card is opened
// here; a header-only entry of it holds no part of the aspect and supersedes nothing.
#[test]
fn a_card_goes_once_a_later_one_is_opened_spec_sync_judgement_2() {
    let (mut lp, d) = two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let old = reach(&mut lp, 1, 1);
    let new = reach(&mut lp, 1, 2);
    opened(&mut lp, 0, 1, &new, &[], true);
    assert_eq!(lp.peers[0].engine.read_facts(&home, &old).unwrap().must_not, None, "a header only: kept");
    opened(&mut lp, 0, 2, &new, &[0], true);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&home, &old).unwrap().must_not, Some(MustNot::CardSuperseded));
    assert_eq!(e.read_facts(&home, &new).unwrap().must_not, None, "the newest stays");
    let own = reach(&mut lp, 0, 3);
    let later = reach(&mut lp, 0, 4);
    opened(&mut lp, 0, 3, &later, &[0], true);
    assert_eq!(lp.peers[0].engine.read_facts(&home, &own).unwrap().must_not, None, "its own card: never by this rule");
}
