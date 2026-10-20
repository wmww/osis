#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Established epochs at the engine level (spec/crypto.md §4).

mod common;
use common::*;
use osis_core::{Role, Tid, Value};
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
fn rotation_commit(lp: &mut LocalPeer, a: Tid, seed: u64, roles: BTreeSet<Role>) -> (osis_core::CommitId, Rotation) {
    let members = [rcpt(lp, 0, Role::Admin), rcpt(lp, 1, Role::Read)];
    let e = &mut lp.peers[0].engine;
    let view = e.epochs(&a).unwrap();
    let state = e.get(&a, &ak("/secrets")).unwrap().map(|v| ct::SECRETS.decode(&v).unwrap()).unwrap_or_default();
    let r = rotate(&a, &roles, &view, &state, &members, &|_, _| true, &mut SeededRng::from_u64(seed)).unwrap();
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
