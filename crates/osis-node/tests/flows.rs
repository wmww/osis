#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Membership flows (plans/membership-flows.md) over `LocalPeer`: commits and inbox blobs are
//! delivered by hand between engines (no labels or servers).

mod common;
use common::*;
use osis_core::{CommitId, Role, Tid, Value};
use osis_label::Address;
use osis_node::flows::{Delivery, Demotion, Done, PreSync};
use osis_node::local_peer::LocalPeer;
use osis_node::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn servers() -> Vec<Address> {
    vec![Address { url: "quic://s1:1".into(), key: [7; 32] }]
}

/// Delivers commits `ids` of peer `from` to peer `to`.
fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
    for id in ids {
        let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
        lp.deliver(to, &pk).unwrap();
    }
}

/// Carries out a flow's deliveries addressed to the peers of `lp` (direct sends and inbox
/// blobs; placement under labels is node-sync's and is skipped here).
fn carry(lp: &mut LocalPeer, from: usize, done: &Done) {
    for d in &done.deliveries {
        match d {
            Delivery::Direct { to, commits } => {
                if let Some(i) = lp.peers.iter().position(|p| p.engine.tid() == *to) {
                    send(lp, from, i, commits);
                }
            }
            Delivery::Inbox { blob, .. } => {
                for i in 0..lp.peers.len() {
                    if i != from {
                        let _ = lp.peers[i].engine.accept_inbox(blob);
                    }
                }
            }
            _ => {}
        }
    }
}

fn admin() -> ct::Edge {
    ct::Edge { role: Role::Admin, until: None, invite: None, since: None }
}

fn tags(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<String> {
    match lp.peers[i].engine.get(&t, &ak("/t/tags")).unwrap() {
        Some(Value::Set(s)) => s.into_iter().map(|v| if let Value::Str(x) = v { x } else { String::new() }).collect(),
        _ => BTreeSet::new(),
    }
}

fn add_tag(lp: &mut LocalPeer, i: usize, t: Tid, tag: &str) {
    let mut m = Mutation::new();
    m.op(t, &TAGS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(s(tag)) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap();
}

/// A thing owned by actor `owner`, written by peer `i`.
fn thing_of(lp: &mut LocalPeer, i: usize, owner: Tid) -> Tid {
    let e = &mut lp.peers[i].engine;
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, owner);
    m.set(t, &REG, &s("new")).unwrap();
    e.commit(m).unwrap().unwrap();
    t
}

/// Peer 0 creates a person; peer 1 is paired as its second device.
fn person_two_devices(seed: u64) -> (LocalPeer, Tid, osis_label::RecoveryCard) {
    let mut lp = net(2, seed);
    let (p, done) = lp.peers[0].engine.create_person(&servers()).unwrap();
    assert_eq!(done.commits.len(), 1);
    // the new device's card over the direct connection
    let n = lp.peers[1].engine.tid();
    let card: Vec<CommitId> = lp.peers[1].engine.commit_ids();
    send(&mut lp, 1, 0, &card);
    let paired = lp.peers[0].engine.pair(&p.person, &n).unwrap();
    carry(&mut lp, 0, &paired);
    let grant = *paired.commits.last().unwrap();
    lp.peers[1].engine.paired(&p.person, &grant).unwrap();
    (lp, p.person, p.card)
}

// spec/permissions.md §1, §9; spec/crypto.md §3: a person actor owned by its recovery key, the
// node its admin, secrets of its own, `/keys` with inbox and deposit seed, home label genesis
// with the key listed by static entry; a paired device opens the person's secrets.
#[test]
fn person_and_pairing_spec_perm_1() {
    let (mut lp, p, card) = person_two_devices(501);
    let e0 = &mut lp.peers[0].engine;
    assert_eq!(e0.role_on(&p), Some(Role::Admin));
    let keys = e0.get_typed(&p, &ct::KEYS).unwrap().unwrap();
    assert!(keys.read.is_some() && keys.admin.is_some() && keys.deposit_seed.is_some());
    assert_eq!(keys.inbox.as_ref().unwrap().label, card.home_label);
    let labels = e0.get_typed(&p, &ct::LABEL).unwrap().unwrap();
    let l = labels.get(&card.home_label).unwrap();
    assert_eq!(l.steps.len(), 1);
    let (step, set) = osis_label::parse_record(l.steps.values().next().unwrap()).unwrap();
    step.verify_genesis().unwrap();
    // the recovery key reads the current step's entry box
    let rk = osis_crypto::KeyActorKeys::from_seed(&card.seed);
    let eb = set.unwrap().entry_box(&card.home_label, &rk.signing.verifying_key()).cloned().unwrap();
    let (_, read) = osis_label::open_entry_box(&eb, &step, osis_label::EntryKey::Kem(&rk.kem)).unwrap();
    let held = e0.epochs(&p).unwrap();
    assert_eq!(held.read.newest_held().unwrap().1, &read);
    // the second device: admin, holds the same secrets
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.role_on(&p), Some(Role::Admin));
    let h1 = e1.epochs(&p).unwrap();
    assert_eq!(h1.read.newest_held().unwrap().1, &read);
    assert!(h1.admin.newest_held().is_some());
}
