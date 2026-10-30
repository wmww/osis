#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Established epochs at the engine level (spec/crypto.md §4).

use crate::common;
use common::*;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_keys::{MemberKeys, Provenance, Recipient, Rotation, rotate};
use osis_node::Mutation;
use osis_node::local_peer::LocalPeer;
use osis_schema::AspectKey;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn rcpt(lp: &LocalPeer, i: usize, role: Role) -> Recipient {
    let e = &lp.peers[i].engine;
    Recipient { member: e.tid(), role, keys: MemberKeys::KeyActor { kem: e.identity().keys().kem.public().clone(), seed: None } }
}

/// A read rotation of `a` from node 0's view, written as one membership commit.
fn rotation_commit(lp: &mut LocalPeer, a: Tid, seed: u64, roles: BTreeSet<Role>) -> (osis_base::CommitId, Rotation) {
    let members = [rcpt(lp, 0, Role::Admin), rcpt(lp, 1, Role::Read)];
    rotation_commit_to(lp, a, seed, roles, &members)
}

/// A rotation of `a` from node 0's view boxing `members`.
fn rotation_commit_to(lp: &mut LocalPeer, a: Tid, seed: u64, roles: BTreeSet<Role>, members: &[Recipient]) -> (osis_base::CommitId, Rotation) {
    let e = &mut lp.peers[0].engine;
    let view = e.epochs(&a).unwrap();
    let state = e.get(&a, &ak("/secrets")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap_or_default();
    let r = rotate(&a, &roles, &view, &state, members, &|_, _| true, &mut SeededRng::from_u64(seed)).unwrap();
    let mut m = Mutation::new();
    for (k, b) in &r.secrets.boxes {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
    }
    for k in &r.secrets.removed {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) }).unwrap();
    }
    for (k, h) in &r.secrets.history {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) }).unwrap();
    }
    for (role, ks) in &r.keys.keysets {
        let f = match role {
            Role::Read => 0,
            Role::Write => 1,
            Role::Admin => 2,
        };
        m.op(a, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) }).unwrap();
    }
    (e.commit(m).unwrap().unwrap(), r)
}

// spec/crypto.md §4: a rotation commit received before the one it supersedes is not current
// (nor established) until the chain is applied; establishment survives a restart.
#[test]
fn rotation_out_of_order_spec_crypto_4() {
    let mut lp = net(2, 81);
    lp.sync_all().unwrap();
    let a = new_thing(&mut lp, 0);
    let (c1, r1) = rotation_commit(&mut lp, a, 1, BTreeSet::from([Role::Read, Role::Write, Role::Admin]));
    let e1 = r1.rotated.iter().find(|x| x.role == Role::Read).unwrap().epoch;
    let v0 = lp.peers[0].engine.epochs(&a).unwrap();
    assert!(v0.read.is_established(&e1), "{:?}", v0.read);
    let (c2, r2) = rotation_commit(&mut lp, a, 2, BTreeSet::from([Role::Read]));
    let e2 = r2.rotated[0].epoch;
    assert_eq!(lp.peers[0].engine.epochs(&a).unwrap().read.current(), vec![e2]);
    // node 1: the thing, then e2's commit before e1's
    let pks = lp.packages(0).unwrap();
    for p in pks.iter().filter(|p| p.id != c1 && p.id != c2) {
        let _ = lp.deliver(1, p);
    }
    let p2 = pks.iter().find(|p| p.id == c2).unwrap().clone();
    let p1 = pks.iter().find(|p| p.id == c1).unwrap().clone();
    lp.deliver(1, &p2).unwrap();
    let v = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(v.read.secret(&e2).is_some());
    assert!(!v.read.is_established(&e2));
    assert!(!v.read.current().contains(&e2));
    lp.deliver(1, &p1).unwrap();
    let v = lp.peers[1].engine.epochs(&a).unwrap();
    assert_eq!(v.read.provenance(&e1), Some(Provenance::Chain));
    assert_eq!(v.read.provenance(&e2), Some(Provenance::Chain));
    assert_eq!(v.read.current(), vec![e2]);
    lp.peers[1].restart(810).unwrap();
    assert_eq!(lp.peers[1].engine.epochs(&a).unwrap().read.current(), vec![e2]);
}

// spec/crypto.md §4: a node boxed at the newest epoch only opens the earlier ones through the
// history boxes the actor's `/secrets` already holds (written by rotations that did not box it):
// the delta's box, then the chain of held history entries, without reading every box.
#[test]
fn history_chain_from_state_spec_crypto_4() {
    let mut lp = net(2, 84);
    lp.sync_all().unwrap();
    let a = new_thing(&mut lp, 0);
    let roles = BTreeSet::from([Role::Read]);
    let only0 = [rcpt(&lp, 0, Role::Admin)];
    // secrets of its own are all three roles' (spec/crypto.md §3); then two read rotations
    rotation_commit_to(&mut lp, a, 9, BTreeSet::from([Role::Read, Role::Write, Role::Admin]), &only0);
    let (_, r1) = rotation_commit_to(&mut lp, a, 1, roles.clone(), &only0);
    let (_, r2) = rotation_commit_to(&mut lp, a, 2, roles.clone(), &only0);
    sync(&mut lp, 0, 1);
    let (e1, e2) = (r1.rotated[0].epoch, r2.rotated[0].epoch);
    assert!(lp.peers[1].engine.epochs(&a).is_none_or(|v| v.read.secret(&e2).is_none()), "not boxed yet");
    // node 1's box at e2 alone: no history entry in the delta
    let e = &mut lp.peers[0].engine;
    let view = e.epochs(&a).unwrap();
    let state = e.get(&a, &ak("/secrets")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap();
    let w = osis_keys::box_member(&a, &view, &state, &rcpt(&lp, 1, Role::Read), &roles, &mut SeededRng::from_u64(3)).unwrap().unwrap();
    let mut m = Mutation::new();
    for (k, b) in &w.boxes {
        m.op(a, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) }).unwrap();
    }
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    let v1 = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(v1.read.secret(&e2).is_some(), "the box");
    assert!(v1.read.secret(&e1).is_some(), "e2's history box, held in state");
    assert_eq!(v1.read.secret(&e1), lp.peers[0].engine.epochs(&a).unwrap().read.secret(&e1));
}

// spec/crypto.md §3, §4: a key actor taken up (a link's L) opens every box reachable from it,
// however deep the chain of member actors (each box opens with the secrets of the member below
// it). Tids descend along the chain, so a bare sweep over actors in tid order opens one level per sweep.
#[test]
fn key_actor_opens_deep_member_chain_spec_crypto_4() {
    let mut lp = net(2, 85);
    lp.sync_all().unwrap();
    let mut chain: Vec<Tid> = (0..12).map(|_| new_thing(&mut lp, 0)).collect();
    chain.sort_by(|a, b| b.cmp(a));
    let read = edge(Role::Read);
    for w in chain.windows(2) {
        lp.peers[0].engine.grant(&w[1], &w[0], &read).unwrap();
    }
    let sharer = new_thing(&mut lp, 0);
    let spec = osis_node::flows::LinkSpec { target: chain[0], role: Role::Read, until: None, servers: Vec::new(), peers: Vec::new(), single_use: false };
    let (link, _, _) = lp.peers[0].engine.create_link(&sharer, &spec).unwrap();
    sync(&mut lp, 0, 1);
    let held = |lp: &LocalPeer, t: &Tid| lp.peers[1].engine.epochs(t).is_some_and(|e| !e.read.held_newest_first().is_empty());
    assert!(chain.iter().all(|t| !held(&lp, t)), "nothing opens before the key");
    lp.peers[1].engine.hold_key_actor(link.seed.clone()).unwrap();
    assert!(held(&lp, &link.k), "K, boxed to L");
    let missing: Vec<usize> = (0..chain.len()).filter(|i| !held(&lp, &chain[*i])).collect();
    assert!(missing.is_empty(), "levels left unopened: {missing:?}");
}
