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

/// `n` peers, each with its own person actor (no pairing); everyone holds everyone's commits.
fn people(n: usize, seed: u64) -> (LocalPeer, Vec<Tid>) {
    let mut lp = net(n, seed);
    let mut ps = Vec::new();
    for i in 0..n {
        ps.push(lp.peers[i].engine.create_person(&servers()).unwrap().0.person);
    }
    lp.sync_all().unwrap();
    (lp, ps)
}

fn edge_of(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None }
}

fn newest_read(lp: &LocalPeer, i: usize, t: Tid) -> Option<osis_crypto::Epoch> {
    lp.peers[i].engine.epochs(&t).and_then(|e| e.read.newest_held().map(|x| x.0))
}

// spec/permissions.md §2, §3; spec/sync.md §3: a grant gives the thing secrets of its own
// first, carries the grantee's boxes, and reaches the grantee's devices as an inbox blob,
// whose acceptance yields a certificate copy for the grantee's home label.
#[test]
fn grant_by_inbox_spec_perm_2() {
    let (mut lp, ps) = people(2, 502);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    let done = lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    assert_eq!(done.commits.len(), 2, "own secrets, then the grant");
    let inbox: Vec<&Delivery> = done.deliveries.iter().filter(|d| matches!(d, Delivery::Inbox { .. })).collect();
    assert_eq!(inbox.len(), 1);
    let Delivery::Inbox { to, inbox: ib, blob } = inbox[0] else { unreachable!() };
    assert_eq!(*to, pb);
    let home = lp.peers[1].engine.label_of(&pb).unwrap().unwrap().0;
    assert_eq!(ib.label, home);
    // bob's node first lacks the doc's chain: the grant waits; once synced it applies
    let (things, acc) = lp.peers[1].engine.accept_inbox(blob).unwrap();
    assert_eq!(things.len(), 1);
    assert_eq!(things[0].tid, d);
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Write));
    assert_eq!(newest_read(&lp, 1, d), newest_read(&lp, 0, d));
    assert!(acc.deliveries.is_empty() || matches!(acc.deliveries[0], Delivery::Certificate { under, .. } if under == pb));
    add_tag(&mut lp, 1, d, "bob");
    sync(&mut lp, 1, 0);
    assert!(tags(&mut lp, 0, d).contains("bob"));
}

// spec/permissions.md §3; spec/commits.md §2: a removal and the target's rotation are one
// commit; the removed member holds no secret of the new epoch and drops what it lost.
#[test]
fn removal_rotates_spec_perm_3() {
    let (mut lp, ps) = people(3, 503);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&d, &pc, &edge_of(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let e0 = newest_read(&lp, 0, d).unwrap();
    assert_eq!(newest_read(&lp, 1, d), Some(e0));
    let done = lp.peers[0].engine.demote(&d, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(done.commits.len(), 1);
    let c = done.commits[0];
    let h = lp.peers[0].engine.header(&c).unwrap();
    let aks: BTreeSet<&str> = h.aspects.iter().map(|a| a.ak.as_str()).collect();
    assert_eq!(aks, BTreeSet::from(["/members", "/secrets", "/keys"]));
    assert!(h.frontier.is_some());
    assert!(done.deliveries.iter().any(|x| matches!(x, Delivery::First { .. })));
    let e1 = newest_read(&lp, 0, d).unwrap();
    assert_ne!(e0, e1);
    lp.sync_all().unwrap();
    assert_eq!(newest_read(&lp, 2, d), Some(e1), "carol is boxed at the new epoch");
    assert_eq!(lp.peers[1].engine.epochs(&d).unwrap().read.secret(&e1), None, "bob is not");
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    let lost = lp.peers[1].engine.drop_lost_secrets().unwrap();
    assert!(lost.contains(&d));
    assert!(lp.peers[1].engine.epochs(&d).is_none_or(|e| e.read.held().next().is_none()));
}

// spec/permissions.md §2: an invite holder grants a new member up to its invite, and cannot
// change or remove anyone else; a member leaves by self-removal.
#[test]
fn invite_power_spec_perm_2() {
    let (mut lp, ps) = people(3, 504);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &ct::Edge { role: Role::Write, until: None, invite: Some(Role::Read), since: None }).unwrap();
    lp.sync_all().unwrap();
    // bob invites carol with read, not with write
    assert!(lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Write)).is_err());
    let done = lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Read)).unwrap();
    assert!(!done.deliveries.iter().any(|x| matches!(x, Delivery::Deposit { .. })), "a writer stamps its own invite grant");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.roster(&d).get(&pc).map(|e| e.role), Some(Role::Read), "peer {i}");
    }
    assert_eq!(lp.peers[2].engine.role_on(&d), Some(Role::Read));
    // no invite holder removes or demotes another member
    assert!(lp.peers[1].engine.demote(&d, &Demotion { member: pc, new: None, presync: PreSync::Synced }).is_err());
    // an existing member cannot be invite-granted again
    assert!(lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Read)).is_err());
    // carol leaves by herself (a reader: no rotation of d is hers to make)
    lp.peers[2].engine.demote(&d, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(!lp.peers[i].engine.roster(&d).contains_key(&pc), "peer {i}");
    }
    // the next writer to encrypt under d rotates it (carol departed)
    let (rot, still) = lp.peers[1].engine.ensure_rotated(&d).unwrap();
    assert!(still.is_empty());
    assert_eq!(rot.commits.len(), 1);
}

// notes/permissions.md Revocation; spec/permissions.md §5.1, §5.2: the demoter's frontier,
// from its receipt record, keeps the edits it received and drops the demoted member's edits
// it never saw (made before) and those made after.
#[test]
fn demotion_frontier_spec_perm_5_1() {
    const DAY: u64 = 86_400_000;
    let (mut lp, ps) = people(2, 505);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    add_tag(&mut lp, 1, d, "mon");
    sync(&mut lp, 1, 0);
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "x");
    lp.advance(DAY);
    let scope = lp.peers[0].engine.presync_scope(&d, &pb, None);
    assert!(scope.contains(&d));
    // the pre-sync failed: the app chooses; failing stamps nothing
    assert!(lp.peers[0].engine.demote(&d, &Demotion { member: pb, new: None, presync: PreSync::Unsynced { proceed: false } }).is_err());
    lp.peers[0].engine.demote(&d, &Demotion { member: pb, new: None, presync: PreSync::Unsynced { proceed: true } }).unwrap();
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "y");
    lp.sync_all().unwrap();
    for i in [0, 1] {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["mon".to_string()]), "node {i}");
    }
}

// notes/permissions.md (membership model: mutual removal): two admins removing each other
// concurrently resolve to the earlier removal; the later one's author was already out.
#[test]
fn mutual_removal_spec_perm_5_1() {
    let (mut lp, ps) = people(3, 506);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 2, pc);
    lp.peers[2].engine.grant(&t, &pa, &edge_of(Role::Admin)).unwrap();
    lp.peers[2].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1000);
    lp.peers[0].engine.demote(&t, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.demote(&t, &Demotion { member: pa, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    for i in 0..3 {
        let r = lp.peers[i].engine.roster(&t);
        assert!(r.contains_key(&pa) && !r.contains_key(&pb), "peer {i}: {r:?}");
    }
}
