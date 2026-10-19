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

/// Every peer's new commits to every other peer, twice (cheaper than `sync_all`'s n rounds);
/// commits that arrive before their chain wait and apply on the second pass.
fn spread(lp: &mut LocalPeer) {
    let n = lp.peers.len();
    let mut sent: Vec<BTreeSet<CommitId>> = vec![BTreeSet::new(); n];
    for _ in 0..2 {
        #[allow(clippy::needless_range_loop)]
        for a in 0..n {
            let ids: Vec<CommitId> = lp.peers[a].engine.commit_ids().into_iter().filter(|c| !sent[a].contains(c)).collect();
            let pks: Vec<_> = ids.iter().filter_map(|id| lp.peers[a].engine.package(id).unwrap()).collect();
            for b in (0..n).filter(|b| *b != a) {
                for pk in &pks {
                    lp.deliver(b, pk).unwrap();
                }
            }
            sent[a].extend(ids);
        }
    }
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
    spread(&mut lp);
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

// spec/crypto.md §4, spec/permissions.md §3: a grant carries the history boxes of the epochs it
// boxes, so the grantee holds the doc's epochs from before its own secrets (what its earlier
// content is under) already from the pending grant, and after applying it.
#[test]
fn grant_carries_history_spec_crypto_4() {
    let (mut lp, ps) = people(2, 503);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    let done = lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Read)).unwrap();
    let held = |lp: &LocalPeer, i: usize| -> BTreeSet<osis_crypto::Epoch> { lp.peers[i].engine.epochs(&d).map(|e| e.read.held().map(|x| x.0).collect()).unwrap_or_default() };
    let want = held(&lp, 0);
    assert!(want.len() >= 2, "derived epoch and own epoch");
    let Some(Delivery::Inbox { blob, .. }) = done.deliveries.iter().find(|d| matches!(d, Delivery::Inbox { .. })) else { panic!("no inbox blob") };
    lp.peers[1].engine.accept_inbox(blob).unwrap();
    assert_eq!(held(&lp, 1), want, "from the pending grant");
    sync(&mut lp, 0, 1);
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(held(&lp, 1), want);
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
    spread(&mut lp);
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
    spread(&mut lp);
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
    spread(&mut lp);
    // bob invites carol with read, not with write
    assert!(lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Write)).is_err());
    let done = lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Read)).unwrap();
    assert!(!done.deliveries.iter().any(|x| matches!(x, Delivery::Deposit { .. })), "a writer stamps its own invite grant");
    spread(&mut lp);
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
    spread(&mut lp);
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
    spread(&mut lp);
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
    spread(&mut lp);
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
    spread(&mut lp);
    lp.advance(1000);
    lp.peers[0].engine.demote(&t, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.demote(&t, &Demotion { member: pa, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    for i in 0..3 {
        let r = lp.peers[i].engine.roster(&t);
        assert!(r.contains_key(&pa) && !r.contains_key(&pb), "peer {i}: {r:?}");
    }
}

/// Peers 0 and 1 are devices of person P (created on 1, 0 paired); peer 2 is Alice (PA).
fn devices_and_alice(seed: u64) -> (LocalPeer, Tid, Tid, osis_label::RecoveryCard) {
    let mut lp = net(3, seed);
    let (p, _) = lp.peers[1].engine.create_person(&servers()).unwrap();
    let d1 = lp.peers[0].engine.tid();
    let ids = lp.peers[0].engine.commit_ids();
    send(&mut lp, 0, 1, &ids);
    let paired = lp.peers[1].engine.pair(&p.person, &d1).unwrap();
    carry(&mut lp, 1, &paired);
    let pa = lp.peers[2].engine.create_person(&servers()).unwrap().0.person;
    spread(&mut lp);
    assert_eq!(lp.peers[0].engine.role_on(&p.person), Some(Role::Admin));
    (lp, p.person, pa, p.card)
}

// spec/permissions.md §3, spec/crypto.md §4 (recursive covers rule; the TLC two-hop scenario):
// device d1 removed from person P, P a writer of team T, T a writer of doc U. Before P's other
// device encrypts under U it rotates T, then U, top-down; d1 holds neither new secret.
#[test]
fn cascade_two_hops_spec_perm_3() {
    let (mut lp, p, pa, _) = devices_and_alice(507);
    let d1 = lp.peers[0].engine.tid();
    let t = thing_of(&mut lp, 2, pa);
    let u = thing_of(&mut lp, 2, pa);
    lp.peers[2].engine.grant(&t, &p, &edge_of(Role::Write)).unwrap();
    lp.peers[2].engine.grant(&u, &t, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let (t0, u0) = (newest_read(&lp, 1, t).unwrap(), newest_read(&lp, 1, u).unwrap());
    assert_eq!(newest_read(&lp, 0, u), Some(u0), "d1 reads U through P and T");
    // d2 removes d1 from P: P's rotation rides in the removal
    lp.peers[1].engine.demote(&p, &Demotion { member: d1, new: None, presync: PreSync::Synced }).unwrap();
    let deps = lp.peers[1].engine.departures(&u).unwrap();
    assert!(deps.iter().any(|d| d.member == d1 && d.via == vec![t, p]), "{deps:?}");
    // nothing below rotated yet (lazy); before encrypting under U: T, then U
    assert_eq!(newest_read(&lp, 1, t), Some(t0));
    let (done, still) = lp.peers[1].engine.ensure_rotated(&u).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 2, "T then U");
    let ht = lp.peers[1].engine.header(&done.commits[0]).unwrap();
    assert!(ht.aspects.iter().all(|a| a.tid == t));
    let (t1, u1) = (newest_read(&lp, 1, t).unwrap(), newest_read(&lp, 1, u).unwrap());
    assert!(t1 != t0 && u1 != u0);
    assert!(lp.peers[1].engine.departures(&u).unwrap().is_empty() || lp.peers[1].engine.ensure_rotated(&u).unwrap().0.commits.is_empty());
    spread(&mut lp);
    assert_eq!(newest_read(&lp, 2, u), Some(u1), "alice is boxed");
    assert!(lp.peers[0].engine.epochs(&u).unwrap().read.secret(&u1).is_none(), "d1 is not");
    assert!(lp.peers[0].engine.epochs(&t).unwrap().read.secret(&t1).is_none());
}

// spec/permissions.md §9 (recovery card), §5.1: a fresh device holding the card claims the
// person (as the recovery key: grants itself admin) and removes the stolen device with the
// person's rotation; the stolen device's later removal of the honest device is invalid.
#[test]
fn stolen_device_recovery_spec_perm_9() {
    let (mut lp, p, _pa, card) = devices_and_alice(508);
    let (d1, d2) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let mut fresh = net(1, 509);
    lp.peers.push(fresh.peers.remove(0));
    // the fresh device downloaded the home label (here: every commit of the honest device)
    sync(&mut lp, 1, 3);
    lp.advance(1000);
    let done = lp.peers[3].engine.recover(&card, &[d1], PreSync::Synced).unwrap();
    assert_eq!(done.commits.len(), 2, "grant, then the removal");
    let n = lp.peers[3].engine.tid();
    assert_eq!(lp.peers[3].engine.role_on(&p), Some(Role::Admin));
    let pe = newest_read(&lp, 3, p).unwrap();
    // the thief removes the honest device afterwards: too late
    lp.advance(1000);
    lp.peers[0].engine.demote(&p, &Demotion { member: d2, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    for i in [1, 2, 3] {
        let r = lp.peers[i].engine.roster(&p);
        assert!(r.contains_key(&d2) && r.contains_key(&n) && !r.contains_key(&d1), "peer {i}: {r:?}");
    }
    assert_eq!(newest_read(&lp, 1, p), Some(pe), "the honest device holds the new epoch");
    assert!(lp.peers[0].engine.epochs(&p).unwrap().read.secret(&pe).is_none(), "the thief does not");
    assert!(lp.peers[3].engine.departures(&p).unwrap().iter().any(|d| d.member == d1));
}

fn link_spec(target: Tid, role: Role, until: Option<osis_core::WallMs>) -> osis_node::flows::LinkSpec {
    osis_node::flows::LinkSpec { target, role, until, servers: servers(), peers: Vec::new(), single_use: false }
}

// spec/crdt.md §3.2 (commit form: own writes first among commits), spec/commits.md §4: a
// redemption signed as L rewrites K's history boxes (remove + put next to the sharer node's
// entries); its deltas must encode canonically whichever way L's and the sharer's tids sort (the
// writer once encoded own writes under the signer's node source, out of the reader's order).
#[test]
fn commit_form_redemption_canonical_spec_crdt_3_2() {
    for seed in 600..606 {
        let (mut lp, ps) = people(2, seed);
        let (pa, ps1) = (ps[0], ps[1]);
        let d = thing_of(&mut lp, 0, pa);
        let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Write, None)).unwrap();
        sync(&mut lp, 0, 1);
        lp.peers[1].engine.redeem(&link, &ps1, true).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        sync(&mut lp, 1, 0);
        assert_eq!(lp.peers[0].engine.roster(&link.k).get(&ps1).map(|e| e.role), Some(Role::Write), "seed {seed}");
    }
}

// spec/permissions.md §9: a stranger redeems a read link: signing as L it invite-grants its
// own actor to K (deposited: read), single use removes L's edge in the same commit, so a
// second redeemer finds no link; the redeemer reads the target through K.
#[test]
fn link_redeem_single_use_spec_perm_9() {
    let (mut lp, ps) = people(3, 510);
    let (pa, ps1, ps2) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, keep, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Read, None)).unwrap();
    let text = link.to_text().unwrap();
    assert_eq!(osis_label::ShareLink::from_text(&text).unwrap(), link);
    assert_eq!(lp.peers[0].engine.roster(&link.k).get(&lp.peers[0].engine.tid()), None);
    assert!(lp.peers[0].engine.get(&keep, &ak(osis_node::flows::LINK_SEED)).unwrap().is_some());
    // the stranger downloads K's label (here: everything the sharer holds)
    sync(&mut lp, 0, 1);
    let done = lp.peers[1].engine.redeem(&link, &ps1, true).unwrap();
    assert_eq!(done.commits.len(), 1);
    assert!(done.deliveries.iter().any(|x| matches!(x, Delivery::Deposit { under, .. } if *under == link.k)));
    // L's own departure does not hold back the deposit (node-sync's cover check)
    assert_eq!(done.departed, vec![link.k]);
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    sync(&mut lp, 1, 0);
    for i in [0, 1] {
        let r = lp.peers[i].engine.roster(&link.k);
        assert_eq!(r.get(&ps1).map(|e| e.role), Some(Role::Read), "peer {i}");
        assert!(!r.contains_key(&l), "peer {i}: single use");
    }
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Read));
    assert_eq!(newest_read(&lp, 1, d), newest_read(&lp, 0, d));
    // a second redeemer is too late
    spread(&mut lp);
    assert!(lp.peers[2].engine.redeem(&link, &ps2, true).is_err());
    assert_eq!(lp.peers[2].engine.role_on(&d), None);
    // the sharer finalizes the used link: a removal of the absent edge, with its frontier
    // (spec/permissions.md §2, §9)
    let fin = lp.peers[0].engine.finalize_link(&link.k, &l).unwrap();
    assert!(lp.peers[0].engine.header(&fin.commits[0]).unwrap().frontier.is_some());
}

// spec/permissions.md §9, §5.1: a forged redemption by a second seed holder, stamped before the
// one the sharer saw, stands until the sharer finalizes; its frontier does not cover it.
#[test]
fn single_use_finalization_audits_spec_perm_9() {
    let (mut lp, ps) = people(3, 518);
    let (pa, ps1, ps2) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Read, None)).unwrap();
    spread(&mut lp);
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    // the forger redeems first (earlier ts) but the sharer never hears of it before finalizing
    lp.peers[2].engine.redeem(&link, &ps2, true).unwrap();
    lp.peers[1].clock.advance(1000);
    lp.peers[1].engine.redeem(&link, &ps1, true).unwrap();
    sync(&mut lp, 1, 0);
    lp.peers[0].clock.advance(2000);
    lp.peers[0].engine.finalize_link(&link.k, &l).unwrap();
    spread(&mut lp);
    for i in 0..3 {
        let r = lp.peers[i].engine.roster(&link.k);
        assert!(r.contains_key(&ps1) && !r.contains_key(&ps2) && !r.contains_key(&l), "peer {i}: {r:?}");
    }
}

// spec/permissions.md §9: bearer use reads without writing; `until` expires the link.
#[test]
fn link_bearer_and_until_spec_perm_9() {
    let (mut lp, ps) = people(2, 511);
    let (pa, ps1) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    let until = osis_core::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Read, Some(until))).unwrap();
    sync(&mut lp, 0, 1);
    let before = lp.peers[1].engine.commit_ids().len();
    lp.peers[1].engine.bear(&link).unwrap();
    assert_eq!(newest_read(&lp, 1, d), newest_read(&lp, 0, d), "the bearer reads the target");
    assert_eq!(lp.peers[1].engine.commit_ids().len(), before, "and writes nothing");
    lp.advance(2 * 3_600_000);
    assert!(lp.peers[1].engine.redeem(&link, &ps1, false).is_err(), "expired");
    // the sharer finalizes: a plain removal of L (with a frontier); K rotates before the next
    // encryption under it (`until` was the departure)
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    let k0 = newest_read(&lp, 0, link.k).unwrap();
    let fin = lp.peers[0].engine.finalize_link(&link.k, &l).unwrap();
    assert!(lp.peers[0].engine.header(&fin.commits[0]).unwrap().frontier.is_some());
    assert!(!lp.peers[0].engine.roster(&link.k).contains_key(&l));
    let (rot, still) = lp.peers[0].engine.ensure_rotated(&link.k).unwrap();
    assert!(still.is_empty() && rot.commits.len() == 1);
    let k1 = newest_read(&lp, 0, link.k).unwrap();
    assert_ne!(k0, k1);
    sync(&mut lp, 0, 1);
    assert!(lp.peers[1].engine.epochs(&link.k).unwrap().read.secret(&k1).is_none(), "the bearer is out");
}

// spec/permissions.md §3 (re-seal): a grant raced by a rotation leaves the grantee without a
// box at the new epoch; at the end of a complete pass a node that may rotate re-seals it by
// inbox; the removed member is not re-sealed.
#[test]
fn reseal_raced_grant_spec_perm_3() {
    struct Pass;
    impl osis_node::flows::SyncState for Pass {
        fn complete_pass(&self, _: &Tid) -> bool {
            true
        }
    }
    let (mut lp, ps) = people(4, 512);
    let (pa, pb, pc, pd) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pd, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    // concurrently: alice grants carol, bob removes dave
    lp.advance(1000);
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Read)).unwrap();
    lp.peers[1].engine.demote(&t, &Demotion { member: pd, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let e1 = newest_read(&lp, 1, t).unwrap();
    assert_eq!(newest_read(&lp, 0, t), Some(e1));
    assert!(lp.peers[2].engine.epochs(&t).is_none_or(|e| e.read.secret(&e1).is_none()), "carol stranded");
    // no pass, no decision
    struct NoPass;
    impl osis_node::flows::SyncState for NoPass {
        fn complete_pass(&self, _: &Tid) -> bool {
            false
        }
    }
    assert!(lp.peers[0].engine.reseal_due(&t, &NoPass).unwrap().commits.is_empty());
    let done = lp.peers[0].engine.reseal_due(&t, &Pass).unwrap();
    assert_eq!(done.commits.len(), 1, "carol only");
    let inbox: Vec<&Vec<u8>> = done.deliveries.iter().filter_map(|x| if let Delivery::Inbox { to, blob, .. } = x { (*to == pc).then_some(blob) } else { None }).collect();
    assert_eq!(inbox.len(), 1);
    lp.peers[2].engine.accept_inbox(inbox[0]).unwrap();
    assert_eq!(newest_read(&lp, 2, t), Some(e1));
    spread(&mut lp);
    assert!(lp.peers[3].engine.epochs(&t).is_none_or(|e| e.read.secret(&e1).is_none()), "dave stays out");
    assert!(lp.peers[1].engine.reseal_due(&t, &Pass).unwrap().commits.is_empty(), "nothing left");
}

// notes/sync.md Limits (stranded device re-paired), spec/permissions.md §3: a device whose
// grant raced a rotation of its person is re-sealed over the pairing channel.
#[test]
fn stranded_device_repaired_spec_perm_3() {
    let mut lp = net(4, 513);
    let (p, _) = lp.peers[0].engine.create_person(&servers()).unwrap();
    let p = p.person;
    for i in [1, 2] {
        let n = lp.peers[i].engine.tid();
        let ids = lp.peers[i].engine.commit_ids();
        send(&mut lp, i, 0, &ids);
        let done = lp.peers[0].engine.pair(&p, &n).unwrap();
        carry(&mut lp, 0, &done);
    }
    spread(&mut lp);
    // d0 pairs n while d1, unaware, removes d2 (rotating P)
    lp.advance(1000);
    let n = lp.peers[3].engine.tid();
    let ids = lp.peers[3].engine.commit_ids();
    send(&mut lp, 3, 0, &ids);
    let first = lp.peers[0].engine.pair(&p, &n).unwrap();
    carry(&mut lp, 0, &first);
    let d2 = lp.peers[2].engine.tid();
    lp.peers[1].engine.demote(&p, &Demotion { member: d2, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let e1 = newest_read(&lp, 1, p).unwrap();
    assert!(lp.peers[3].engine.epochs(&p).unwrap().read.secret(&e1).is_none(), "n is stranded");
    assert_eq!(lp.peers[3].engine.role_on(&p), Some(Role::Admin));
    // re-pairing an existing member re-seals it
    let again = lp.peers[0].engine.pair(&p, &n).unwrap();
    assert_eq!(again.commits.len(), 1);
    carry(&mut lp, 0, &again);
    assert_eq!(newest_read(&lp, 3, p), Some(e1));
    assert!(lp.peers[2].engine.epochs(&p).unwrap().read.secret(&e1).is_none());
}

// spec/sync.md §2, §5: after a rotation an admin issues a child of the server's head at the
// newest epochs; the removed device has no claim key in it, the remaining one has.
#[test]
fn registration_step_after_rotation_spec_sync_5() {
    let (mut lp, p, _pa, card) = devices_and_alice(514);
    let d1 = lp.peers[0].engine.tid();
    let labels = lp.peers[1].engine.get_typed(&p, &ct::LABEL).unwrap().unwrap();
    let genesis = osis_label::StepId(*labels.get(&card.home_label).unwrap().steps.keys().next().unwrap());
    assert!(lp.peers[1].engine.issue_step(&p, &card.home_label, &genesis, false).unwrap().0.is_none(), "nothing newer");
    lp.peers[1].engine.demote(&p, &Demotion { member: d1, new: None, presync: PreSync::Synced }).unwrap();
    let (step, set) = lp.peers[1].engine.issue_step(&p, &card.home_label, &genesis, false).unwrap().0.unwrap();
    let parent = osis_label::parse_record(&labels.get(&card.home_label).unwrap().steps[&genesis.0]).unwrap().0;
    step.verify_child(&parent).unwrap();
    let claims = |i: usize| step.claim_key(lp.peers[i].engine.identity().keys().kem.x25519()).unwrap().verifying_key().to_bytes();
    assert!(set.contains(&claims(1)));
    assert!(!set.contains(&claims(0)));
    let rk = osis_crypto::KeyActorKeys::from_seed(&card.seed);
    assert!(set.entry_box(&card.home_label, &rk.signing.verifying_key()).is_some(), "the recovery key keeps its entry");
    let now = lp.peers[1].engine.get_typed(&p, &ct::LABEL).unwrap().unwrap();
    assert_eq!(now.get(&card.home_label).unwrap().steps.len(), 2);
}

// spec/permissions.md §6: an owner-chain node's roster snapshot carries the timeline's roster
// with `since` and the tenure ledger (the removed writer's ended tenure with its frontier);
// rosters and content validity are unchanged by it; an edge admin may not write one.
#[test]
fn roster_snapshot_spec_perm_6() {
    let (mut lp, ps) = people(3, 515);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    add_tag(&mut lp, 2, t, "carol");
    spread(&mut lp);
    lp.peers[0].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    assert!(!lp.peers[0].engine.roster_snapshot_due(&t, None), "few deltas: not due");
    assert!(lp.peers[1].engine.roster_snapshot(&t, None).is_err(), "edge admin");
    let before = lp.peers[0].engine.roster(&t);
    let done = lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    let h = lp.peers[0].engine.header(&done.commits[0]).unwrap();
    assert_eq!(h.kind, osis_commit::Kind::RosterSnapshot);
    spread(&mut lp);
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.roster(&t), before, "peer {i}");
        assert_eq!(tags(&mut lp, i, t), BTreeSet::from(["carol".to_string()]), "peer {i}");
    }
    let ledger = lp.peers[1].engine.get_typed(&t, &ct::TENURES).unwrap().unwrap();
    assert!(ledger.0.iter().any(|x| x.member == pc && x.role == Role::Write && x.frontier.is_some()), "{ledger:?}");
    let raw = lp.peers[1].engine.state(&t, &ak("/members")).unwrap().unwrap().read().unwrap();
    let roster = osis_schema::AspectKey::decode(&ct::MEMBERS, &raw).unwrap();
    assert!(roster.get(&pb).unwrap().since.is_some(), "{roster:?}");
    add_tag(&mut lp, 1, t, "bob");
    spread(&mut lp);
    assert!(tags(&mut lp, 0, t).contains("bob"));
}

// spec/permissions.md §7: moving a doc to another owner copies it with its history, re-grants
// its members on the copy and points the old thing at it; a second move is refused.
#[test]
fn move_regrants_spec_perm_7() {
    let (mut lp, ps) = people(2, 516);
    let (pa, pb) = (ps[0], ps[1]);
    let team = thing_of(&mut lp, 0, pa);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    add_tag(&mut lp, 1, d, "bob");
    spread(&mut lp);
    let (copy, done) = lp.peers[0].engine.move_to(&d, &team).unwrap();
    assert!(done.deliveries.iter().any(|x| matches!(x, Delivery::Inbox { to, .. } if *to == pb)));
    assert!(lp.peers[0].engine.move_to(&d, &team).is_err());
    spread(&mut lp);
    for i in [0, 1] {
        assert_eq!(tags(&mut lp, i, copy), BTreeSet::from(["bob".to_string()]), "peer {i}");
        assert_eq!(lp.peers[i].engine.get_typed(&d, &ct::MOVED).unwrap(), Some(copy));
    }
    assert_eq!(lp.peers[1].engine.role_on(&copy), Some(Role::Write));
}

// spec/crypto.md §4 (forks): two admins removing different members concurrently fork the read
// epoch; each fork boxes a member the other removed, so the next node to encrypt under it
// rotates again, and that epoch covers both departures; both admins converge on it.
#[test]
fn fork_from_concurrent_rotations_spec_crypto_4() {
    let (mut lp, ps) = people(4, 517);
    let (pa, pb, pc, pd) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&t, &pd, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    lp.advance(1000);
    lp.peers[0].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    lp.peers[1].engine.demote(&t, &Demotion { member: pd, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let forks = lp.peers[0].engine.epochs(&t).unwrap().read.current();
    assert_eq!(forks.len(), 2, "{forks:?}");
    assert_eq!(lp.peers[1].engine.epochs(&t).unwrap().read.current(), forks);
    let (done, still) = lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty());
    assert_eq!(done.commits.len(), 1);
    let e3 = newest_read(&lp, 0, t).unwrap();
    spread(&mut lp);
    assert_eq!(lp.peers[1].engine.epochs(&t).unwrap().read.current(), vec![e3]);
    for i in [2, 3] {
        assert!(lp.peers[i].engine.epochs(&t).unwrap().read.secret(&e3).is_none(), "peer {i}");
    }
    assert!(lp.peers[1].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "nothing left to rotate");
}

fn aks_of(lp: &LocalPeer, i: usize, c: &CommitId) -> BTreeSet<String> {
    lp.peers[i].engine.header(c).unwrap().aspects.iter().map(|a| a.ak.as_str().to_string()).collect()
}

// spec/permissions.md §2, §3: a writer leaving a doc is a self-removal: no rotation in it, the
// leaver drops what it lost; the next node that may rotate does, and the leaver's old secrets
// open nothing new.
#[test]
fn writer_leaves_spec_perm_3() {
    let (mut lp, ps) = people(2, 519);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let done = lp.peers[1].engine.demote(&d, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(aks_of(&lp, 1, &done.commits[0]), BTreeSet::from(["/members".to_string()]));
    assert!(lp.peers[1].engine.header(&done.commits[0]).unwrap().frontier.is_none());
    // the leaver drops what it lost once its removal is placed (node-sync's carry_out)
    assert!(done.drop_lost);
    lp.peers[1].engine.drop_lost_secrets().unwrap();
    assert!(lp.peers[1].engine.epochs(&d).is_none_or(|e| e.read.held().next().is_none()), "dropped on leaving");
    spread(&mut lp);
    let (rot, still) = lp.peers[0].engine.ensure_rotated(&d).unwrap();
    assert!(still.is_empty() && rot.commits.len() == 1);
    let e1 = newest_read(&lp, 0, d).unwrap();
    spread(&mut lp);
    assert!(lp.peers[1].engine.epochs(&d).is_none_or(|e| e.read.secret(&e1).is_none()));
}

// spec/permissions.md §2, §3: a device removing its person from a team (its only authority
// there comes through the person) is a self-removal; the team's admin rotates later.
#[test]
fn device_removes_person_from_team_spec_perm_3() {
    let (mut lp, p, pa, _) = devices_and_alice(520);
    let t = thing_of(&mut lp, 2, pa);
    lp.peers[2].engine.grant(&t, &p, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let done = lp.peers[1].engine.demote(&t, &Demotion { member: p, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(aks_of(&lp, 1, &done.commits[0]), BTreeSet::from(["/members".to_string()]));
    spread(&mut lp);
    assert!(!lp.peers[2].engine.roster(&t).contains_key(&p));
    let (rot, _) = lp.peers[2].engine.ensure_rotated(&t).unwrap();
    assert_eq!(rot.commits.len(), 1);
    let e1 = newest_read(&lp, 2, t).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.epochs(&t).is_none_or(|e| e.read.secret(&e1).is_none()), "device {i}");
    }
}

// spec/crypto.md §4, spec/permissions.md §6: departures are also read from state (a box at a
// current epoch its holder no longer may hold); a roster snapshot first rotates them away.
#[test]
fn reader_leaves_then_snapshot_spec_perm_6() {
    let (mut lp, ps) = people(3, 521);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    lp.peers[2].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let done = lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    assert_eq!(done.commits.len(), 2, "the rotation, then the snapshot");
    let e1 = newest_read(&lp, 0, t).unwrap();
    spread(&mut lp);
    assert!(lp.peers[2].engine.epochs(&t).is_none_or(|e| e.read.secret(&e1).is_none()));
    assert!(lp.peers[1].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "nothing left");
}

// spec/permissions.md §3 (who rotates): a write-link redemption boxes K under the cascade run
// with L's authority: L rotates away a joiner's departure, signing as L.
#[test]
fn write_link_rotates_as_signer_spec_perm_3() {
    let (mut lp, ps) = people(3, 522);
    let (pa, ps1, ps2) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Write, None)).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.redeem(&link, &ps1, false).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.demote(&link.k, &Demotion { member: ps1, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let e0 = newest_read(&lp, 0, link.k).unwrap();
    let done = lp.peers[2].engine.redeem(&link, &ps2, false).unwrap();
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    assert_eq!(done.commits.len(), 2, "L's rotation, then the grant");
    assert_eq!(lp.peers[2].engine.header(&done.commits[0]).unwrap().author, l);
    let e1 = newest_read(&lp, 2, link.k).unwrap();
    assert_ne!(e0, e1);
    spread(&mut lp);
    assert_eq!(lp.peers[2].engine.role_on(&d), Some(Role::Write));
    assert!(lp.peers[1].engine.epochs(&link.k).is_none_or(|e| e.read.secret(&e1).is_none()));
}

// spec/crypto.md §4, spec/sync.md §2: signing a label's genesis step and sealing its entry
// boxes encrypt under the group's epochs: after a device left the person that administers the
// team, the team rotates before its label is created.
#[test]
fn create_label_after_inside_removal_spec_sync_2() {
    let (mut lp, p, pa, _) = devices_and_alice(523);
    let d1 = lp.peers[0].engine.tid();
    let t = thing_of(&mut lp, 2, pa);
    lp.peers[2].engine.grant(&t, &p, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    let t0 = newest_read(&lp, 1, t).unwrap();
    lp.peers[1].engine.demote(&p, &Demotion { member: d1, new: None, presync: PreSync::Synced }).unwrap();
    let (label, done) = lp.peers[1].engine.create_label(&t, &servers()).unwrap();
    assert_eq!(done.commits.len(), 2, "T's rotation, then the label");
    let t1 = newest_read(&lp, 1, t).unwrap();
    assert_ne!(t0, t1);
    let labels = lp.peers[1].engine.get_typed(&t, &ct::LABEL).unwrap().unwrap();
    let (step, _) = osis_label::parse_record(labels.get(&label).unwrap().steps.values().next().unwrap()).unwrap();
    let read = lp.peers[1].engine.epochs(&t).unwrap().read.secret(&t1).cloned().unwrap();
    assert_eq!(step.keys.sync, osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, &read, 0).verifying_key());
}

// notes/permissions.md Revocation (stolen device): the thief backdates a write; the honest
// device's backdated revoke takes its frontier from its receipts as of the theft, so the
// thief's edits are dropped and the device's earlier ones stay.
#[test]
fn backdated_revoke_spec_perm_5_3() {
    const HOUR: u64 = 3_600_000;
    let (mut lp, p, _pa, _) = devices_and_alice(524);
    let d1 = lp.peers[0].engine.tid();
    let u = thing_of(&mut lp, 1, p);
    spread(&mut lp);
    add_tag(&mut lp, 0, u, "honest");
    spread(&mut lp);
    let theft = lp.peers[0].engine.now();
    lp.advance(2 * HOUR);
    // the thief winds its clock back to just after the theft
    lp.peers[0].clock.set(osis_core::WallMs(theft.0 + 60_000));
    add_tag(&mut lp, 0, u, "forged");
    lp.peers[0].clock.set(osis_core::WallMs(theft.0 + 3 * HOUR));
    sync(&mut lp, 0, 1);
    lp.advance(HOUR);
    let backdated = PreSync::Backdated(osis_core::WallMs(theft.0 + HOUR / 2));
    lp.peers[1].engine.demote(&p, &Demotion { member: d1, new: None, presync: backdated }).unwrap();
    spread(&mut lp);
    for i in [1, 2] {
        assert_eq!(tags(&mut lp, i, u), BTreeSet::from(["honest".to_string()]), "peer {i}");
    }
}

// spec/permissions.md §7, spec/sync.md §2: a labeled doc's copy gets a label of its own at the
// doc's servers before its members are re-granted, so they sync and write it whatever else of
// the new owner they read.
#[test]
fn move_labels_copy_spec_perm_7() {
    let (mut lp, ps) = people(2, 518);
    let (pa, pb) = (ps[0], ps[1]);
    let team = thing_of(&mut lp, 0, pa);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.create_label(&d, &servers()).unwrap();
    spread(&mut lp);
    let (copy, _) = lp.peers[0].engine.move_to(&d, &team).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        let ls = lp.peers[i].engine.group_labels(&copy).unwrap();
        assert_eq!(ls.len(), 1, "peer {i}");
        assert_eq!(ls[0].servers, servers());
    }
    assert_eq!(lp.peers[1].engine.role_on(&copy), Some(Role::Write));
    // an unlabeled doc's copy gets none
    let e = thing_of(&mut lp, 0, pa);
    let (copy, _) = lp.peers[0].engine.move_to(&e, &team).unwrap();
    assert!(lp.peers[0].engine.group_labels(&copy).unwrap().is_empty());
}
