//! The derivation over the engine's held set (`osis_engine::evidence::held`; notes/evidence-
//! derivation.md, The engine's input): the engine side of the joint property (spec/permissions.md §4)
//! (`Engine::check_evidence`: per thing, a reader holding its bodies plus exactly the copies the
//! derivation requires judges them under osis-perm `paths` as the node holding everything), and
//! hand tests reading the engine's own commits (finding 9; steps under role compaction).

/// Every node of the representative role-paths world (grants through one and three holders,
/// removals with rotations, self-removals, may-grant, `until`, finalize, links, addenda, a descent
/// of two steps): the derivation agrees with itself and a reader per thing judges as the node.
// spec/permissions.md §4
#[test]
fn every_node_of_the_role_paths_world_passes_the_evidence_check_spec_permissions_4() {
    let mut w = crate::role_paths::world();
    for (i, p) in w.lp.peers.iter_mut().enumerate() {
        let copies = p.engine.evidence_copies().unwrap();
        assert!(copies.values().flatten().any(|x| matches!(x.kind, osis_engine::evidence::Kind::Write(_))), "node {i} holds edge writes");
        assert_eq!(p.engine.check_evidence().unwrap(), None, "node {i}");
        let things: std::collections::BTreeSet<_> = copies.keys().map(|c| c.1).collect();
        let sids: Vec<_> = things.iter().map(|t| (*t, *t, vec![*t])).collect();
        let ev = p.engine.evidence(&sids).unwrap();
        let with = things.iter().filter(|t| ev.required(t).is_some_and(|r| !r.is_empty())).count();
        assert!(with >= 3, "node {i}: {with} things require copies");
    }
}

use crate::common::{REG, s};
use crate::flows::{edge_of, people, thing_of};
use osis_base::{Ak, CommitId, Role, Tid};
use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;
use std::collections::BTreeSet;

/// Syncs peers `0..n` with each other, never the rest.
fn among(lp: &mut LocalPeer, n: usize) {
    for _ in 0..2 {
        for a in 0..n {
            for b in (0..n).filter(|b| *b != a) {
                lp.sync(a, b).unwrap();
            }
        }
    }
}

fn write(lp: &mut LocalPeer, i: usize, t: Tid, v: &str) -> CommitId {
    lp.advance(1000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

/// Delivers commits `ids`, whole, from peer `from` to peer `to`, in `ids` order, twice (a commit
/// waiting for one later in the list applies on the second pass).
fn hand(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
    for _ in 0..2 {
        for id in ids {
            let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
            lp.deliver(to, &pk).unwrap();
        }
        // the node closure takes in what the records delivered show
        lp.peers[to].engine.settle_needs().unwrap();
        lp.peers[to].reexamine().unwrap();
    }
}

// Finding 9 (spec/permissions.md §2 Edge writes: a removal applies only once the creations of
// the entries it resets are held; §4 Evidence of a commit: a commit's evidence takes the writes on
// each edge its edge writes set): X removes K and Q from A in one commit; K wrote D through [A]
// before it (listed) and after it. Under D (its unit D alone) the evidence holds the removal and
// both creations, X's grant to Q among them, on no path K's writes state. A reader given D's
// writes and exactly those copies judges both of K's writes as X; one given them less X's grant to
// Q holds the removal unresolved, applies none of it and takes K's later write as valid.
#[test]
fn f9_a_removal_of_two_holders_waits_for_both_creations_at_a_reader_spec_permissions_2() {
    let (mut lp, ps) = people(5);
    let (px, pk, pq) = (ps[0], ps[1], ps[2]);
    let a = thing_of(&mut lp, 0, px);
    let d = thing_of(&mut lp, 0, px);
    among(&mut lp, 3);
    let ga = lp.peers[0].engine.grant(&d, &a, &edge_of(Role::Write)).unwrap().commits;
    // the readers read D (their grants are bodies of D)
    for r in [ps[3], ps[4]] {
        lp.peers[0].engine.grant(&d, &r, &edge_of(Role::Read)).unwrap();
    }
    let gk = lp.peers[0].engine.grant(&a, &pk, &edge_of(Role::Write)).unwrap().commits;
    let gq = lp.peers[0].engine.grant(&a, &pq, &edge_of(Role::Write)).unwrap().commits;
    among(&mut lp, 3);
    let k1 = write(&mut lp, 1, d, "k1");
    among(&mut lp, 3);
    lp.advance(1000);
    let rm = lp.peers[0].engine.remove_holders(&a, &pk, &[pq]).unwrap().commits;
    let k2 = write(&mut lp, 1, d, "k2");
    among(&mut lp, 3);
    let reg = Ak::new("t:reg.0").unwrap();
    let x = &mut lp.peers[0].engine;
    assert_eq!((x.body_valid(&k1, &d, &reg), x.body_valid(&k2, &d, &reg)), (Some(true), Some(false)), "X: K's first write listed, its second after the removal");
    assert_eq!(x.check_evidence().unwrap(), None);
    let rm = *rm.last().unwrap();
    let gq = *gq.last().unwrap();
    let ev = x.evidence(&[(d, d, vec![d])]).unwrap();
    let req = ev.required(&d).unwrap();
    let _ = ga;
    assert!(gk.iter().any(|c| req.contains_key(&(*c, a))), "X's grant to K: {req:?}");
    assert!(req.contains_key(&(rm, a)) && req.contains_key(&(gq, a)), "the removal and X's grant to Q: {req:?}");
    // D's bodies: every commit with a part on D; the copies: every required one
    let held = lp.peers[0].engine.evidence_copies().unwrap();
    let mut bodies: Vec<CommitId> = held.keys().filter(|c| c.1 == d).map(|c| c.0).collect();
    bodies.extend(req.keys().map(|c| c.0));
    // and the creation record of A, on K's paths (records ride beside evidence, not in it)
    let mint_a = held.keys().map(|c| c.0).find(|c| lp.peers[0].engine.header(c).unwrap().aspects.iter().any(|x| x.tid == a && x.ak.as_str() == "created.0")).unwrap();
    bodies.push(mint_a);
    let all: BTreeSet<CommitId> = bodies.iter().copied().collect();
    let mut ids: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| all.contains(c)).collect();
    ids.sort_by_key(|c| lp.peers[0].engine.header(c).unwrap().ts);
    hand(&mut lp, 0, 3, &ids);
    let r = &mut lp.peers[3].engine;
    assert_eq!((r.body_valid(&k1, &d, &reg), r.body_valid(&k2, &d, &reg)), (Some(true), Some(false)), "a reader holding D's bodies and the required copies judges as X");
    assert!(!r.unresolved(&rm));
    let less: Vec<CommitId> = ids.iter().copied().filter(|c| *c != gq).collect();
    hand(&mut lp, 0, 4, &less);
    let r = &mut lp.peers[4].engine;
    assert!(r.unresolved(&rm), "without the creation of Q's entry the removal applies nothing");
    assert_eq!(r.body_valid(&k2, &d, &reg), Some(true), "and K's later write stands");
}

// notes/a2-spec/README.md Open 4 (spec/crypto.md §7 Checked keys; spec/permissions.md §4 Evidence
// of a commit): a write on D (delete base G) listing G's second step's keys; G issues a third step
// and its `sync.0` is compacted. The snapshot records every step from the genesis on, each entry
// keeping its recording write's stamp (so "recorded by a write ordered before the commit" reads
// the same), and is a copy D's write requires: with the recording writes forgotten, the snapshot
// alone places the listed keys.
#[test]
fn a_write_listing_an_old_step_after_sync_is_compacted_requires_the_snapshot_spec_crypto_7() {
    use osis_engine::evidence::{Level, Reason};
    let (mut lp, ps) = people(1);
    let g = thing_of(&mut lp, 0, ps[0]);
    let d = thing_of(&mut lp, 0, g);
    let sync = Ak::new("sync.0").unwrap();
    let sid = lp.peers[0].engine.sync_id_of(&g).unwrap().unwrap();
    let issue = |lp: &mut LocalPeer| -> CommitId {
        lp.advance(1000);
        let before: BTreeSet<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
        lp.peers[0].engine.issue_step(&g, &sid, true).unwrap().unwrap();
        let new: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
        assert_eq!(new.len(), 1, "one commit records the step");
        new[0]
    };
    let s2 = issue(&mut lp);
    let w = write(&mut lp, 0, d, "w");
    issue(&mut lp);
    lp.advance(1000);
    let snap = lp.peers[0].engine.snapshot(&g, &sync).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    let mut copies = e.evidence_copies().unwrap();
    let steps = copies[&(snap, g)][0].steps.clone();
    let second = *copies[&(s2, g)][0].steps.first().expect("the second step's write records it");
    assert!(steps.contains(&second) && steps.len() >= 3, "the snapshot records every step: {steps:?}");
    // w lists keys for its delete base G
    let dels = &mut copies.get_mut(&(w, d)).unwrap()[0].dels;
    assert!(!dels.is_empty() && dels.iter().all(|x| x.base == g), "{dels:?}");
    // Interim (issues/delete-key-levels-unchecked.md): the engine lists its newest epoch's
    // `kdf("delete key", s)`, borne by no step, until brief 3 lists step keys; w lists the second
    // step's, as written then
    for x in dels.iter_mut() {
        x.key = if x.level == Level::Admin { second.delete } else { second.write };
    }
    // the step's entry in the snapshot keeps its recording write's stamp
    let key = |f: &osis_crdt::Fragment| f.at(&[osis_crdt::PathSeg::Key(osis_schema::Codec::to_value(&sid)), osis_crdt::PathSeg::Field(0), osis_crdt::PathSeg::Key(osis_base::Value::Bytes(second.id.to_vec())), osis_crdt::PathSeg::Field(0)]).and_then(|x| x.write_stamp().cloned());
    let at_snap = key(&e.body_fragment(&snap, &g, &sync).unwrap().unwrap()).expect("the snapshot carries the step's entry");
    assert_eq!(at_snap.ts, e.header(&s2).unwrap().ts);
    assert!(at_snap.ts < e.header(&snap).unwrap().ts);
    // D's write (unit D alone) requires the steps' copies; forgotten but the snapshot, it alone
    let mut ev = osis_engine::evidence::held::derive(&e.evidence_mint(), &copies, &[(d, d, vec![d])]);
    let req = ev.required(&d).unwrap().clone();
    assert!(req.contains_key(&(snap, g)) && req.contains_key(&(s2, g)), "{req:?}");
    let recording: Vec<_> = req.keys().filter(|c| c.1 == g && c.0 != snap && copies[c].iter().any(|p| !p.steps.is_empty())).copied().collect();
    ev.forget_all(recording);
    assert_eq!(ev.check(), Ok(()));
    let req = ev.required(&d).unwrap();
    assert!(matches!(req.get(&(snap, g)), Some(Reason::Step(b, _)) if *b == g), "{req:?}");
}
