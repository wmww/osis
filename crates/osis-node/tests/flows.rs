#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Membership flows over `LocalPeer`: commits and inbox blobs are
//! delivered by hand between engines (no labels or servers).

mod common;
use common::*;
use osis_core::{Clock, CommitId, Role, Tid, Value};
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
// spec/permissions.md §2 (edge inbox delivery): grants
#[test]
fn grant_by_inbox_spec_perm_2() {
    let (mut lp, ps) = people(2, 502);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    let done = lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    assert_eq!(done.commits.len(), 2, "own secrets, then the grant");
    let inbox: Vec<&Delivery> = done.deliveries.iter().filter(|d| matches!(d, Delivery::Inbox { .. })).collect();
    assert_eq!(inbox.len(), 1);
    let Delivery::Inbox { to, inbox: ib, blob, .. } = inbox[0] else { unreachable!() };
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
    // from the pending grant for reading only (spec/crypto.md §4: never encrypted under until
    // an applied valid box carries it)
    let reading: BTreeSet<osis_crypto::Epoch> = lp.peers[1].engine.epochs(&d).unwrap().read.held_newest_first().into_iter().map(|x| x.0).collect();
    assert_eq!(reading, want, "from the pending grant");
    assert!(held(&lp, 1).is_empty());
    sync(&mut lp, 0, 1);
    assert!(lp.peers[1].engine.pending().is_empty());
    assert_eq!(held(&lp, 1), want);
}

// spec/permissions.md §3; spec/commits.md §2: a removal and the target's rotation are one
// commit; the removed member holds no secret of the new epoch and drops what it lost.
// spec/crypto.md §4 (removed member), spec/permissions.md §3 (drop lost secrets)
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

// spec/permissions.md §5.2 (validity judged alike); notes/local-store.md (a rebuildable index): after grants, a removal with its rotation, content
// by the removed member before and after it (the latter invalid here), the indexes an open reads
// from the persisted index equal those rebuilt from every commit record, and those in memory; a
// tag of other rules or an index that does not decode is rebuilt.
#[test]
fn persisted_index_equals_rebuild_spec_perm_5_2() {
    let (mut lp, ps) = people(3, 509);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&d, &pc, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let write = |lp: &mut LocalPeer, i: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(d, &REG, &s(v)).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    write(&mut lp, 1, "bob before");
    spread(&mut lp);
    lp.advance(10);
    lp.peers[0].engine.demote(&d, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    lp.advance(10);
    let late = write(&mut lp, 1, "bob after");
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let h = e.header(&late).unwrap();
    assert!(h.aspects.iter().any(|a| a.tid == d), "bob's late write is held");
    assert_eq!(e.get(&d, &ak("/t/reg")).unwrap(), Some(s("bob before")), "and invalid here");
    let before = e.index_digest();
    assert!(before.contains("false"), "an invalid part is indexed");
    e.reload_index().unwrap();
    assert_eq!(e.index_digest(), before, "loaded from the persisted index");
    e.rebuild_index().unwrap();
    assert_eq!(e.index_digest(), before, "rebuilt from the commit records");
    e.reload_index().unwrap();
    assert_eq!(e.index_digest(), before, "the rebuilt index persisted");
    // another build's rules (everything valid, states joined so), then a row that does not
    // decode: each open rebuilds, re-tags and re-joins the states judged otherwise
    for garble in [false, true] {
        e.damage_index(garble).unwrap();
        if !garble {
            assert_eq!(e.get(&d, &ak("/t/reg")).unwrap(), Some(s("bob after")), "the old rules' state");
        }
        e.reload_index().unwrap();
        assert_eq!(e.index_digest(), before, "rebuilt after damage (garbled: {garble})");
        assert!(e.index_current().unwrap());
        assert_eq!(e.get(&d, &ak("/t/reg")).unwrap(), Some(s("bob before")), "re-joined (garbled: {garble})");
    }
}

/// A peer for forensic and crash checks: small key tree and pages (a shred elsewhere does not
/// incidentally rotate a leaked copy away), every row recorded, faults injectable.
fn forensic_peer(seed: u64, faults: &osis_store::Faults) -> osis_node::local_peer::Peer {
    let clock = std::sync::Arc::new(osis_core::ManualClock::new(T0));
    let (backend, root) = (osis_store::MemoryBackend::with_faults(faults.clone()), osis_store::MemoryRoot::with_faults(faults.clone()));
    backend.record_history();
    let c: std::sync::Arc<dyn osis_core::Clock> = clock.clone();
    let mut engine = osis_node::Engine::create(Box::new(backend.clone()), Box::new(root.clone()), forensic_cfg(), c, Box::new(osis_crypto::SeededRng::from_u64(seed))).unwrap();
    let events = engine.subscribe();
    osis_node::local_peer::Peer { engine, clock, backend, root, events }
}

fn forensic_cfg() -> osis_node::Config {
    osis_node::Config { store: osis_store::StoreConfig { arity: 4, depth: 8, page_max: 512, ..osis_store::StoreConfig::default() }, ..osis_node::Config::default() }
}

/// Reopens peer `i` over its durable state.
fn reopen(lp: &mut LocalPeer, i: usize, seed: u64) -> osis_node::Result<()> {
    let p = &mut lp.peers[i];
    let c: std::sync::Arc<dyn osis_core::Clock> = p.clock.clone();
    let mut engine = osis_node::Engine::open(Box::new(p.backend.clone()), Box::new(p.root.clone()), forensic_cfg(), c, Box::new(osis_crypto::SeededRng::from_u64(seed)))?;
    p.events = engine.subscribe();
    p.engine = engine;
    Ok(())
}

fn big(marker: &str) -> String {
    format!("{marker}{}", "x".repeat(400))
}

/// Things of a removal: `d` (bob read, removed), `f` (read by bob only through `d`), `e` (read by
/// bob directly and through `d`), `mine` (bob's own).
struct Lost {
    lp: LocalPeer,
    faults: osis_store::Faults,
    d: Tid,
    e: Tid,
    f: Tid,
    mine: Tid,
}

const D_MARK: &str = "LOST-D-MARK-31f0";
const F_MARK: &str = "LOST-F-MARK-9c2a";
const E_MARK: &str = "KEPT-E-MARK-5d17";
const MINE_MARK: &str = "MINE-B-MARK-a40e";

/// Alice shares d, e and f with bob as above and writes a marker on each, bob writes one on his
/// own thing, then alice removes bob from d; bob has applied everything, dropped nothing.
fn lost_setup(seed: u64) -> Lost {
    lost_setup_from(seed, false)
}

/// `lost_setup`, bob removed from e instead of d when `from_e` (he still reads e through d).
fn lost_setup_from(seed: u64, from_e: bool) -> Lost {
    let faults = osis_store::Faults::new();
    let mut lp = LocalPeer { peers: vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &faults)] };
    let pa = lp.peers[0].engine.create_person(&servers()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&servers()).unwrap().0.person;
    spread(&mut lp);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Read)).unwrap();
    let e = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&e, &d, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&e, &pb, &edge_of(Role::Read)).unwrap();
    let f = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&f, &d, &edge_of(Role::Read)).unwrap();
    for (t, mark) in [(d, D_MARK), (e, E_MARK), (f, F_MARK)] {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(&big(mark))).unwrap();
        lp.peers[0].engine.commit(m).unwrap();
    }
    let mine = thing_of(&mut lp, 1, pb);
    let mut m = Mutation::new();
    m.set(mine, &REG, &s(&big(MINE_MARK))).unwrap();
    lp.peers[1].engine.commit(m).unwrap();
    spread(&mut lp);
    for (t, mark) in [(d, D_MARK), (e, E_MARK), (f, F_MARK)] {
        assert_eq!(lp.peers[1].engine.get(&t, &ak("/t/reg")).unwrap(), Some(s(&big(mark))));
        assert!(lp.peers[1].engine.epochs(&t).is_some_and(|x| x.read.held().next().is_some()), "bob holds the secrets");
    }
    let target = if from_e { e } else { d };
    lp.peers[0].engine.demote(&target, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&d), if from_e { Some(Role::Read) } else { None });
    Lost { lp, faults, d, e, f, mine }
}

/// Bob reads only e and his own thing, and an attacker holding his device and every row it
/// ever wrote recovers neither lost marker.
fn assert_forgotten(x: &mut Lost) {
    let b = &mut x.lp.peers[1];
    let reg = ak("/t/reg");
    assert_eq!(b.engine.get(&x.d, &reg).unwrap(), None, "lost content kept");
    assert_eq!(b.engine.get(&x.f, &reg).unwrap(), None, "content lost through d kept");
    assert_eq!(b.engine.get(&x.e, &reg).unwrap(), Some(s(&big(E_MARK))), "content readable by another path forgotten");
    assert_eq!(b.engine.get(&x.mine, &reg).unwrap(), Some(s(&big(MINE_MARK))));
    for t in [x.d, x.f] {
        assert!(b.engine.epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "secrets kept");
    }
    let plain = plaintexts(b);
    for m in [D_MARK, F_MARK] {
        assert!(!plain.iter().any(|p| contains(p, m.as_bytes())), "{m} recovered");
    }
    for m in [E_MARK, MINE_MARK] {
        assert!(plain.iter().any(|p| contains(p, m.as_bytes())), "{m}: the attack finds live content");
    }
}

// spec/permissions.md §3: a node that learns it lost read access to an actor MUST drop those
// role secrets and every local unit it can no longer read by another path; spec/requirements.md,
// Deletion: a node that lost access to data yields nothing it can no longer read.
// spec/permissions.md §3 (drop lost secrets)
#[test]
fn removal_erases_lost_content_spec_perm_3() {
    let mut x = lost_setup(509);
    // the attack finds the lost content while it is held, and after a restart
    assert!(recoverable(&mut x.lp.peers[1], D_MARK.as_bytes()));
    reopen(&mut x.lp, 1, 1).unwrap();
    assert_eq!(x.lp.peers[1].engine.get(&x.d, &ak("/t/reg")).unwrap(), Some(s(&big(D_MARK))));
    let lost: BTreeSet<Tid> = x.lp.peers[1].engine.drop_lost_secrets().unwrap().into_iter().collect();
    assert!(lost.contains(&x.d) && lost.contains(&x.f) && !lost.contains(&x.e), "{lost:?}");
    let ev = x.lp.peers[1].drain_events();
    assert!(ev.iter().any(|e| matches!(e, osis_node::Event::Changed { cause: osis_node::Cause::LostAccess, changed } if changed.contains(&(x.d, ak("/t/reg"))))));
    assert_forgotten(&mut x);
    // forgotten for good: after a restart, and a second drop finds nothing
    reopen(&mut x.lp, 1, 2).unwrap();
    assert!(x.lp.peers[1].engine.drop_lost_secrets().unwrap().is_empty());
    assert_forgotten(&mut x);
    // bob keeps syncing what he reads
    let mut m = Mutation::new();
    m.set(x.e, &REG, &s("later")).unwrap();
    let c = x.lp.peers[0].engine.commit(m).unwrap().unwrap();
    send(&mut x.lp, 0, 1, &[c]);
    assert_eq!(x.lp.peers[1].engine.get(&x.e, &ak("/t/reg")).unwrap(), Some(s("later")));
}

// spec/permissions.md §3 (drop lost secrets); spec/commits.md §4 (a transaction lands whole or
// not at all): a crash at any write of the drop leaves bob, reopened, before it (dropping again
// forgets) or after it, never between
#[test]
fn removal_erasure_crash_safe_spec_perm_3() {
    for n in 0.. {
        let mut x = lost_setup(511);
        x.faults.at(n, osis_store::Fault::Crash);
        let r = x.lp.peers[1].engine.drop_lost_secrets();
        let crashed = x.faults.crashed();
        assert_eq!(r.is_err(), crashed, "write {n}");
        x.faults.revive();
        // a crash during recovery as well
        x.faults.at(0, osis_store::Fault::Crash);
        let _ = reopen(&mut x.lp, 1, 3);
        x.faults.revive();
        reopen(&mut x.lp, 1, 4).unwrap();
        let kept = x.lp.peers[1].engine.get(&x.d, &ak("/t/reg")).unwrap();
        if kept.is_some() {
            assert!(crashed, "write {n}");
            assert_eq!(kept, Some(s(&big(D_MARK))), "torn state after a crash at write {n}");
            assert!(x.lp.peers[1].engine.drop_lost_secrets().unwrap().contains(&x.d));
        }
        assert_forgotten(&mut x);
        if !crashed {
            return;
        }
    }
}

// spec/permissions.md §3: a node that learns it lost read access to an actor MUST drop those
// role secrets and every local unit it can no longer read by another path: the received
// removal's apply leaves the trigger its work, which forgets d and f (not e) with no call by hand
// (node-sync runs it every step), and the attack recovers neither lost marker.
#[test]
fn applied_removal_triggers_forgetting_spec_perm_3() {
    let mut x = lost_setup(513);
    assert!(x.lp.peers[1].engine.lost_due());
    let lost: BTreeSet<Tid> = x.lp.peers[1].engine.drop_lost_due().unwrap().into_iter().collect();
    assert!(lost.contains(&x.d) && lost.contains(&x.f) && !lost.contains(&x.e), "{lost:?}");
    assert!(!x.lp.peers[1].engine.lost_due());
    assert_forgotten(&mut x);
    // idempotent
    assert!(x.lp.peers[1].engine.drop_lost_due().unwrap().is_empty());
    assert_forgotten(&mut x);
}

// spec/permissions.md §3 (a node that learns it lost read access MUST drop): the work list is
// durable, so a restart between the removal's apply and the trigger still forgets.
#[test]
fn lost_access_trigger_survives_restart_spec_perm_3() {
    let mut x = lost_setup(515);
    reopen(&mut x.lp, 1, 5).unwrap();
    assert!(x.lp.peers[1].engine.lost_due());
    assert!(x.lp.peers[1].engine.drop_lost_due().unwrap().contains(&x.d));
    assert_forgotten(&mut x);
    reopen(&mut x.lp, 1, 6).unwrap();
    assert!(!x.lp.peers[1].engine.lost_due());
    assert_forgotten(&mut x);
}

// spec/permissions.md §3: only units the node "can no longer read by another path" go: bob,
// removed from e, still reads e through d and keeps everything.
#[test]
fn removal_with_another_path_keeps_all_spec_perm_3() {
    let mut x = lost_setup_from(517, true);
    assert_eq!(x.lp.peers[1].engine.role_on(&x.e), Some(Role::Read));
    assert!(x.lp.peers[1].engine.drop_lost_due().unwrap().is_empty());
    assert!(x.lp.peers[1].engine.drop_lost_secrets().unwrap().is_empty());
    let reg = ak("/t/reg");
    for (t, mark) in [(x.d, D_MARK), (x.e, E_MARK), (x.f, F_MARK), (x.mine, MINE_MARK)] {
        assert_eq!(x.lp.peers[1].engine.get(&t, &reg).unwrap(), Some(s(&big(mark))));
    }
}

// spec/crypto.md §4 (secrets read from a pending commit's boxes are kept for reading),
// spec/permissions.md §3 (only lost access drops secrets): a grant bob holds but has not applied
// is no loss when an unrelated removal applies, by the trigger or by hand; it applies later.
#[test]
fn pending_grant_survives_unrelated_removal_spec_perm_3() {
    let mut x = lost_setup(519);
    let (pa, pb) = (x.lp.peers[0].engine.owner(&x.d).unwrap(), x.lp.peers[1].engine.owner(&x.mine).unwrap());
    let g = thing_of(&mut x.lp, 0, pa);
    let done = x.lp.peers[0].engine.grant(&g, &pb, &edge_of(Role::Read)).unwrap();
    let Some(Delivery::Inbox { blob, .. }) = done.deliveries.iter().find(|d| matches!(d, Delivery::Inbox { .. })) else { panic!("no inbox blob") };
    x.lp.peers[1].engine.accept_inbox(blob).unwrap();
    assert!(!x.lp.peers[1].engine.pending().is_empty(), "the grant waits for g's chain");
    assert_eq!(x.lp.peers[1].engine.role_on(&g), None);
    let reading = |x: &Lost| x.lp.peers[1].engine.epochs(&g).is_some_and(|e| !e.read.held_newest_first().is_empty());
    assert!(reading(&x), "secrets from the pending grant");
    let lost = x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(lost.contains(&x.d) && !lost.contains(&g), "{lost:?}");
    assert!(!x.lp.peers[1].engine.drop_lost_secrets().unwrap().contains(&g));
    assert!(reading(&x));
    assert_forgotten(&mut x);
    spread(&mut x.lp);
    assert_eq!(x.lp.peers[1].engine.role_on(&g), Some(Role::Read));
    assert_eq!(x.lp.peers[1].engine.get(&g, &ak("/t/reg")).unwrap(), Some(s("new")));
}

// spec/crypto.md §4 (a secret from an unchecked box is kept for reading only),
// spec/permissions.md §3: a planted grant (bad signature, held pending while its author is
// unknown) yields reading-only secrets; once it proves bad and is dropped, they go.
#[test]
fn dropped_pending_grant_drops_reading_secrets_spec_crypto_4() {
    let mut lp = net(2, 521);
    let pa = lp.peers[0].engine.create_person(&servers()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&servers()).unwrap().0.person;
    let bobs: Vec<CommitId> = lp.peers[1].engine.commit_ids();
    send(&mut lp, 1, 0, &bobs);
    let g = thing_of(&mut lp, 0, pa);
    let done = lp.peers[0].engine.grant(&g, &pb, &edge_of(Role::Read)).unwrap();
    let grant = *done.commits.last().unwrap();
    let pk = lp.peers[0].engine.package(&grant).unwrap().unwrap();
    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let Value::Enum(c, Some(p)) = blob.signature.to_value() else { panic!() };
    let Value::Bytes(mut sig) = *p else { panic!() };
    sig[0] ^= 1;
    blob.signature = osis_crypto::Signature::from_value(&Value::Enum(c, Some(Box::new(Value::Bytes(sig))))).unwrap();
    lp.peers[1].engine.ingest(&blob.encode(), pk.blobs.clone()).unwrap();
    assert!(!lp.peers[1].engine.pending().is_empty(), "held pending: its author is unknown");
    assert!(lp.peers[1].engine.epochs(&g).is_some_and(|e| !e.read.held_newest_first().is_empty()), "read from the planted box");
    // everything else of alice's arrives, the trigger running after each: kept while the grant
    // is pending, dropped once it proves bad
    let rest: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| *c != grant).collect();
    let mut dropped = false;
    for c in rest {
        send(&mut lp, 0, 1, &[c]);
        let lost = lp.peers[1].engine.drop_lost_due().unwrap();
        if lp.peers[1].engine.pending().is_empty() {
            dropped |= lost.contains(&g);
        } else {
            assert!(!lost.contains(&g), "dropped while the grant is pending");
        }
    }
    assert!(dropped);
    assert!(lp.peers[1].engine.epochs(&g).is_none_or(|e| e.read.held_newest_first().is_empty()));
}

// spec/permissions.md §2: an invite holder grants a new member up to its invite, and cannot
// change or remove anyone else; a member leaves by self-removal.
// spec/permissions.md §2 (invite scope)
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
// spec/permissions.md §5.1 (frontier received)
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
// spec/permissions.md §5.1
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

// spec/permissions.md §5.1 Frontier: the remover's frontier lists its chain writes by commit
// ID. C grants D (Bob never gets it), then grants Bob admin (Bob gets only that, so C's
// counters are not contiguous at Bob); Bob removes C: his own grant stays covered, so the
// removal stands, while C's grant of D drops.
#[test]
fn remover_lists_chain_writes_spec_perm_5_1() {
    let (mut lp, ps) = people(4, 508);
    let (pa, pb, pc, pd) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    let before: BTreeSet<CommitId> = lp.peers[2].engine.commit_ids().into_iter().collect();
    lp.peers[2].engine.grant(&t, &pd, &edge_of(Role::Write)).unwrap();
    let mid: BTreeSet<CommitId> = lp.peers[2].engine.commit_ids().into_iter().collect();
    lp.peers[2].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    let to_b: Vec<CommitId> = lp.peers[2].engine.commit_ids().into_iter().filter(|c| !mid.contains(c)).collect();
    assert!(mid.len() > before.len() && !to_b.is_empty());
    send(&mut lp, 2, 1, &to_b);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Admin));
    assert!(!lp.peers[1].engine.roster(&t).contains_key(&pd), "Bob never got C's grant of D");
    lp.advance(1000);
    lp.peers[1].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    for i in 0..4 {
        let r = lp.peers[i].engine.roster(&t);
        assert_eq!(r.get(&pb).map(|e| e.role), Some(Role::Admin), "peer {i}");
        assert!(!r.contains_key(&pc) && !r.contains_key(&pd), "peer {i}: {r:?}");
    }
}

/// New commits of peer `i` since `before`.
fn new_ids(lp: &LocalPeer, i: usize, before: &BTreeSet<CommitId>) -> Vec<CommitId> {
    lp.peers[i].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect()
}

fn ids(lp: &LocalPeer, i: usize) -> BTreeSet<CommitId> {
    lp.peers[i].engine.commit_ids().into_iter().collect()
}

/// The frontier commit IDs of membership commit `c`.
fn frontier_ids(lp: &mut LocalPeer, i: usize, c: &CommitId) -> BTreeSet<CommitId> {
    let h = lp.peers[i].engine.header(c).unwrap();
    let v = h.frontier.clone().expect("an inline frontier");
    <ct::Frontier as osis_schema::Codec>::from_value(&v).unwrap().commits
}

// spec/permissions.md §5.1 Frontier (chain-write forgery): C granted Bob admin; Bob removes C
// without having received anything else of C's; C, with a lagging clock, then writes Bob's
// edge with an `until` stamped before the removal. Bob's frontier lists his grant but not the
// forgery: it drops, Bob keeps admin and C stays removed.
#[test]
fn grantor_cannot_backdate_removers_edge_spec_perm_5_1() {
    let (mut lp, ps) = people(3, 509);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    let before = ids(&lp, 2);
    lp.peers[2].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    let g = new_ids(&lp, 2, &before);
    spread(&mut lp);
    // C's clock stays behind from here
    let lag = lp.peers[2].clock.as_ref().now_wall_ms();
    lp.advance(60_000);
    lp.peers[2].clock.set(lag);
    lp.peers[1].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    let r = lp.peers[1].engine.commit_ids().into_iter().find(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_some()).unwrap();
    assert!(g.iter().all(|c| frontier_ids(&mut lp, 1, &r).contains(c)), "Bob lists the grant he holds");
    let until = osis_core::WallMs(lp.peers[0].clock.as_ref().now_wall_ms().0 + 3_600_000);
    let before = ids(&lp, 2);
    lp.peers[2].engine.grant(&t, &pb, &ct::Edge { role: Role::Admin, until: Some(until), invite: None, since: None }).unwrap();
    let forged = new_ids(&lp, 2, &before);
    assert!(lp.peers[2].engine.header(&forged[0]).unwrap().ts < lp.peers[1].engine.header(&r).unwrap().ts, "backdated");
    spread(&mut lp);
    lp.advance(3_700_000);
    for i in 0..3 {
        let ro = lp.peers[i].engine.roster(&t);
        assert_eq!(ro.get(&pb).map(|e| (e.role, e.until)), Some((Role::Admin, None)), "peer {i}");
        assert!(!ro.contains_key(&pc), "peer {i}");
    }
}

// spec/permissions.md §5.1 Frontier (at R's point): C rewrites Bob's admin edge with a ts
// ahead of everyone's clock (within MAX_DRIFT) after granting it; Bob then removes C. His
// frontier lists both writes on his chain, so the removal stands either way.
#[test]
fn future_stamped_setter_spec_perm_5_1() {
    let (mut lp, ps) = people(4, 510);
    let (pa, pb, pc, pd) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    // C grants D (Bob never gets it), then Bob: C's counters at Bob have a gap
    lp.peers[2].engine.grant(&t, &pd, &edge_of(Role::Write)).unwrap();
    let before = ids(&lp, 2);
    lp.peers[2].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    let g = new_ids(&lp, 2, &before);
    send(&mut lp, 2, 1, &g);
    // a rewrite of Bob's edge stamped half an hour ahead
    lp.peers[2].clock.advance(1_800_000);
    let before = ids(&lp, 2);
    lp.peers[2].engine.grant(&t, &pb, &ct::Edge { role: Role::Admin, until: None, invite: Some(Role::Read), since: None }).unwrap();
    let f = new_ids(&lp, 2, &before);
    send(&mut lp, 2, 1, &f);
    lp.peers[1].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    let r = lp.peers[1].engine.commit_ids().into_iter().find(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_some()).unwrap();
    let listed = frontier_ids(&mut lp, 1, &r);
    assert!(g.iter().chain(&f).all(|c| listed.contains(c)), "both writes on Bob's chain are listed");
    lp.advance(1_800_000);
    spread(&mut lp);
    for i in 0..4 {
        let ro = lp.peers[i].engine.roster(&t);
        assert_eq!(ro.get(&pb).map(|e| e.role), Some(Role::Admin), "peer {i}");
        assert!(!ro.contains_key(&pc) && !ro.contains_key(&pd), "peer {i}: {ro:?}");
    }
}

// spec/permissions.md §5.1 Frontier, §4: the frontier lists the remover's whole chain
// certificates, its grantor's grant included. C grants Y admin (W1), Y grants Bob admin; Bob
// holds W1 only as a certificate and never got C's earlier grant of E; Bob removes C: W1 stays
// covered, so Y keeps admin, Bob's grant and the removal stand; C's grant of E drops.
#[test]
fn intermediate_grantor_covered_spec_perm_5_1() {
    let (mut lp, ps) = people(5, 511);
    let (pa, pb, pc, py, pe) = (ps[0], ps[1], ps[2], ps[3], ps[4]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    lp.peers[2].engine.grant(&t, &pe, &edge_of(Role::Write)).unwrap();
    let before = ids(&lp, 2);
    lp.peers[2].engine.grant(&t, &py, &edge_of(Role::Admin)).unwrap();
    let w1 = new_ids(&lp, 2, &before);
    send(&mut lp, 2, 3, &w1);
    let before = ids(&lp, 3);
    lp.peers[3].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    let g = new_ids(&lp, 3, &before);
    send(&mut lp, 2, 1, &w1);
    send(&mut lp, 3, 1, &g);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Admin));
    lp.advance(1000);
    lp.peers[1].engine.demote(&t, &Demotion { member: pc, new: None, presync: PreSync::Synced }).unwrap();
    let r = lp.peers[1].engine.commit_ids().into_iter().find(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_some()).unwrap();
    let listed = frontier_ids(&mut lp, 1, &r);
    assert!(w1.iter().chain(&g).all(|c| listed.contains(c)), "Bob's chain certificates are listed");
    spread(&mut lp);
    for i in 0..5 {
        let ro = lp.peers[i].engine.roster(&t);
        assert_eq!((ro.get(&pb).map(|e| e.role), ro.get(&py).map(|e| e.role)), (Some(Role::Admin), Some(Role::Admin)), "peer {i}");
        assert!(!ro.contains_key(&pc) && !ro.contains_key(&pe), "peer {i}: {ro:?}");
    }
}

// spec/crdt.md §8 (absorbed commits), spec/commits.md §5, spec/permissions.md §5.1: X's
// rotation (commit form) reaches late joiner Bob only through Alice's compaction snapshot of
// `/secrets`, which lists it as absorbed, so Bob counts it received: when Bob removes X, his
// frontier covers it and nobody un-merges X's old rotation.
#[test]
fn late_joiner_covers_compacted_rotation_spec_crdt_8() {
    let (mut lp, ps) = people(4, 512);
    let (pa, pb, px, pm) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &px, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pm, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    // X removes M: its commit carries X's rotation of t
    let before = ids(&lp, 2);
    lp.peers[2].engine.demote(&t, &Demotion { member: pm, new: None, presync: PreSync::Synced }).unwrap();
    let xr = new_ids(&lp, 2, &before);
    send(&mut lp, 2, 0, &xr);
    lp.advance(1000);
    let snap = lp.peers[0].engine.snapshot(&t, &ak("/secrets")).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&snap).unwrap();
    assert_eq!(h.form, osis_commit::Form::Node);
    // Bob joins late: everything Alice holds but X's removal itself
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    let to_b: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !xr.contains(c)).collect();
    send(&mut lp, 0, 1, &to_b);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Admin));
    assert!(xr.iter().all(|c| lp.peers[1].engine.header(c).is_none()), "Bob never got X's rotation");
    lp.advance(1000);
    let before = ids(&lp, 1);
    lp.peers[1].engine.demote(&t, &Demotion { member: px, new: None, presync: PreSync::Synced }).unwrap();
    let br = new_ids(&lp, 1, &before);
    let r = br.iter().copied().find(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_some()).unwrap();
    assert!(xr.iter().all(|c| frontier_ids(&mut lp, 1, &r).contains(c)), "the absorbed rotation is listed");
    lp.peers[0].drain_events();
    send(&mut lp, 1, 0, &br);
    let unmerged = lp.peers[0].drain_events().into_iter().any(|e| matches!(e, osis_node::Event::Changed { cause: osis_node::Cause::Validity, ref changed } if changed.iter().any(|(x, a)| *x == t && (a.as_str() == "/secrets" || a.as_str() == "/keys"))));
    assert!(!unmerged, "X's old rotation stays valid");
    assert!(!lp.peers[0].engine.roster(&t).contains_key(&px));
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

// spec/permissions.md §9, spec/commits.md §2: revoking a joiner of a multi-use link removes it
// and L in one commit with one rotation of K; the other joiner keeps K's new secrets, the
// revoked one and a seed holder acting as L (bearer use) get none; every peer applies the
// two-edge commit.
#[test]
fn revoke_joiner_one_rotation_spec_commits_2() {
    let (mut lp, ps) = people(4, 519);
    let (pa, ps1, ps2) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Write, None)).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.redeem(&link, &ps1, false).unwrap();
    spread(&mut lp);
    lp.peers[2].engine.redeem(&link, &ps2, false).unwrap();
    spread(&mut lp);
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    let k0 = newest_read(&lp, 0, link.k).unwrap();
    // a stranger holding the seed reads as L (bearer use) before the revocation
    lp.peers[3].engine.bear(&link).unwrap();
    assert!(lp.peers[3].engine.epochs(&link.k).unwrap().read.secret(&k0).is_some(), "bearer use works");
    let done = lp.peers[0].engine.revoke_joiner(&link.k, &l, &ps1, PreSync::Synced).unwrap();
    assert_eq!(done.commits.len(), 1, "one commit");
    let h = lp.peers[0].engine.header(&done.commits[0]).unwrap();
    assert!(h.frontier.is_some());
    assert_eq!(h.aspects.iter().filter(|a| a.tid == link.k && a.ak.as_str() == "/secrets").count(), 1, "one rotation");
    carry(&mut lp, 0, &done);
    spread(&mut lp);
    let k1 = newest_read(&lp, 0, link.k).unwrap();
    assert_ne!(k0, k1);
    for i in 0..4 {
        let r = lp.peers[i].engine.roster(&link.k);
        assert!(!r.contains_key(&ps1) && !r.contains_key(&l) && r.contains_key(&ps2), "peer {i}: {r:?}");
    }
    assert!(lp.peers[2].engine.epochs(&link.k).unwrap().read.secret(&k1).is_some(), "the other joiner reads on");
    assert!(lp.peers[1].engine.epochs(&link.k).is_none_or(|e| e.read.secret(&k1).is_none()), "the revoked joiner does not");
    // and after it, bearer use of the seed gives nothing new
    lp.peers[3].engine.bear(&link).unwrap();
    assert!(lp.peers[3].engine.epochs(&link.k).unwrap().read.secret(&k1).is_none(), "the seed reads nothing new");
}

// spec/permissions.md §9, spec/commits.md §2: revoking the joiner of a used single-use link
// (L already gone) is a plain removal of the joiner alone.
#[test]
fn revoke_joiner_after_single_use_spec_commits_2() {
    let (mut lp, ps) = people(2, 521);
    let (pa, ps1) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Write, None)).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.redeem(&link, &ps1, true).unwrap();
    spread(&mut lp);
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    assert!(!lp.peers[0].engine.roster(&link.k).contains_key(&l), "single use removed L");
    let done = lp.peers[0].engine.revoke_joiner(&link.k, &l, &ps1, PreSync::Synced).unwrap();
    // (L's self-removal is first rotated out by the cascade; then the joiner's removal)
    let removal = done.commits.iter().filter(|c| lp.peers[0].engine.header(c).unwrap().frontier.is_some()).count();
    assert_eq!(removal, 1, "one removal");
    carry(&mut lp, 0, &done);
    spread(&mut lp);
    for i in 0..2 {
        assert!(!lp.peers[i].engine.roster(&link.k).contains_key(&ps1), "peer {i}");
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

// spec/permissions.md §3 (re-seal), spec/crypto.md §4: a person actor's members are all key
// actors (its devices, its recovery key), boxed once each keyed at their top role; after a
// device removal rotates every role, the read and write epochs are found introduced by the
// rotation's keysets, so nobody is "seen without a box" and nothing is re-sealed.
#[test]
fn key_actor_members_not_resealed_spec_perm_3() {
    struct Pass;
    impl osis_node::flows::SyncState for Pass {
        fn complete_pass(&self, _: &Tid) -> bool {
            true
        }
    }
    let mut lp = net(3, 533);
    let (p, _) = lp.peers[0].engine.create_person(&servers()).unwrap();
    let p = p.person;
    for i in [1, 2] {
        let n = lp.peers[i].engine.tid();
        let card: Vec<CommitId> = lp.peers[i].engine.commit_ids();
        send(&mut lp, i, 0, &card);
        let paired = lp.peers[0].engine.pair(&p, &n).unwrap();
        carry(&mut lp, 0, &paired);
        let grant = *paired.commits.last().unwrap();
        lp.peers[i].engine.paired(&p, &grant).unwrap();
    }
    spread(&mut lp);
    let n2 = lp.peers[2].engine.tid();
    let done = lp.peers[0].engine.demote(&p, &Demotion { member: n2, new: None, presync: PreSync::Synced }).unwrap();
    carry(&mut lp, 0, &done);
    spread(&mut lp);
    let e = newest_read(&lp, 0, p).unwrap();
    assert_eq!(newest_read(&lp, 1, p), Some(e), "the remaining device follows");
    for i in [0, 1] {
        assert!(lp.peers[i].engine.reseal_due(&p, &Pass).unwrap().commits.is_empty(), "peer {i}: nothing to re-seal");
    }
}

// spec/crypto.md §4 (departure by `until`): the departures known are kept per actor; one that
// starts when an edge's `until` passes is seen once the clock passes it, with nothing applied.
#[test]
fn departures_follow_the_clock_spec_crypto_4() {
    let (mut lp, ps) = people(2, 534);
    let (pa, pb) = (ps[0], ps[1]);
    let t = thing_of(&mut lp, 0, pa);
    let until = osis_core::WallMs(lp.peers[0].engine.now().0 + 5_000);
    lp.peers[0].engine.grant(&t, &pb, &ct::Edge { role: Role::Read, until: Some(until), invite: None, since: None }).unwrap();
    assert!(lp.peers[0].engine.departures(&t).unwrap().is_empty());
    lp.advance(10_000);
    let deps = lp.peers[0].engine.departures(&t).unwrap();
    assert!(deps.iter().any(|d| d.member == pb), "{deps:?}");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty() && done.commits.len() == 1, "rotated away");
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

/// Alice (0) grants carol (2) at e0 while bob (1) removes dave (rotation e1, without carol);
/// carol gets the grant and bob's rotation. Alice then removes eve: e2 boxes carol, who holds no
/// box at e1, the epoch e2's commit is wrapped under. Returns (lp, t, carol, e2's Done).
fn raced_then_rotated(seed: u64) -> (LocalPeer, Tid, Tid, Done) {
    let (mut lp, ps) = people(5, seed);
    let (pa, pb, pc, pd, pe) = (ps[0], ps[1], ps[2], ps[3], ps[4]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pd, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&t, &pe, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    lp.advance(1000);
    let g = lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Read)).unwrap();
    carry(&mut lp, 0, &g);
    let r1 = lp.peers[1].engine.demote(&t, &Demotion { member: pd, new: None, presync: PreSync::Synced }).unwrap();
    send(&mut lp, 1, 0, &r1.commits);
    send(&mut lp, 1, 2, &r1.commits);
    let e1 = newest_read(&lp, 0, t).unwrap();
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.secret(&e1).is_none(), "carol has no box at e1");
    lp.advance(1000);
    let r2 = lp.peers[0].engine.demote(&t, &Demotion { member: pe, new: None, presync: PreSync::Synced }).unwrap();
    (lp, t, pc, r2)
}

// spec/permissions.md §3 (rotation), spec/sync.md §3: a rotation boxing a member that holds no
// box at the current read epoch before it (a grant raced by an earlier rotation; the single-use
// link race's winner) reaches that member by inbox: it could not open the rotation commit from
// the label, which is wrapped under that epoch.
#[test]
fn rotation_reaches_unboxed_member_spec_perm_3() {
    let (mut lp, t, pc, r2) = raced_then_rotated(515);
    let inbox: Vec<&Vec<u8>> = r2.deliveries.iter().filter_map(|x| if let Delivery::Inbox { to, blob, .. } = x { (*to == pc).then_some(blob) } else { None }).collect();
    assert_eq!(inbox.len(), 1, "the rotation goes to carol's inbox");
    lp.peers[2].engine.accept_inbox(inbox[0]).unwrap();
    let e2 = newest_read(&lp, 0, t).unwrap();
    assert_eq!(newest_read(&lp, 2, t), Some(e2));
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.is_established(&e2), "carol holds e2's chain");
    assert!(!r2.deliveries.iter().any(|x| matches!(x, Delivery::Inbox { to, .. } if *to == lp.peers[1].engine.tid())));
}

// spec/permissions.md §3 (re-seal), spec/crypto.md §4: a re-seal of a member whose box at the
// epoch sits in a commit it does not hold still reaches it (the box is re-written, not
// overlaid on an entry the member never got).
#[test]
fn reseal_over_unheld_box_spec_perm_3() {
    let (mut lp, t, pc, _) = raced_then_rotated(516);
    let e2 = newest_read(&lp, 0, t).unwrap();
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.secret(&e2).is_none());
    let done = lp.peers[0].engine.reshare(&t, &pc).unwrap();
    let inbox: Vec<&Vec<u8>> = done.deliveries.iter().filter_map(|x| if let Delivery::Inbox { to, blob, .. } = x { (*to == pc).then_some(blob) } else { None }).collect();
    assert_eq!(inbox.len(), 1);
    lp.peers[2].engine.accept_inbox(inbox[0]).unwrap();
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.secret(&e2).is_some(), "carol reads e2");
}

/// Alice (0) owns C, K1 and K2; K1 and K2 are writers of C; o0 (1) writes K1; late (2)
/// writes K2 (and reads K1 when `late_reads_k1`). Unless late reads K1 it never gets K1's
/// `/secrets` parts (they travel under K1's label only), as with `spread_hiding`. Returns
/// (lp, c, k1, o0).
fn two_links(seed: u64, late_reads_k1: bool) -> (LocalPeer, Tid, Tid, Tid) {
    let (mut lp, ps) = people(3, seed);
    let (pa, po, pl) = (ps[0], ps[1], ps[2]);
    let c = thing_of(&mut lp, 0, pa);
    let k1 = thing_of(&mut lp, 0, pa);
    let k2 = thing_of(&mut lp, 0, pa);
    for k in [k1, k2] {
        lp.peers[0].engine.grant(&c, &k, &edge_of(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&k1, &po, &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&k2, &pl, &edge_of(Role::Write)).unwrap();
    if late_reads_k1 {
        lp.peers[0].engine.grant(&k1, &pl, &edge_of(Role::Read)).unwrap();
        spread(&mut lp);
    } else {
        spread_hiding(&mut lp, 2, k1);
    }
    lp.advance(1000);
    (lp, c, k1, po)
}

/// `spread`, but peer `to` gets every commit without its `/secrets` parts of `hidden`.
fn spread_hiding(lp: &mut LocalPeer, to: usize, hidden: Tid) {
    for _ in 0..2 {
        for a in 0..lp.peers.len() {
            let ids = lp.peers[a].engine.commit_ids();
            let pks: Vec<_> = ids.iter().filter_map(|id| lp.peers[a].engine.package(id).unwrap()).collect();
            for b in (0..lp.peers.len()).filter(|b| *b != a) {
                for pk in &pks {
                    if b != to {
                        lp.deliver(b, pk).unwrap();
                        continue;
                    }
                    let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
                    let hide: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, x)| x.tid == hidden && x.ak.as_str() == "/secrets").map(|(i, _)| i).collect();
                    blob.parts.retain(|p| !hide.contains(&p.ai));
                    let _ = lp.peers[b].engine.ingest(&blob.encode(), pk.blobs.clone());
                }
            }
        }
    }
}

// spec/crypto.md §4 (covers rule; a node holding no secret of M judges by M's newest `/keys`
// keyset), spec/permissions.md §3: after alice removes o0 from K1 and rotates K1 and C, a
// writer of C that never read K1 sees C covered and rotates nothing.
#[test]
fn unheld_member_judged_by_keyset_spec_crypto_4() {
    let (mut lp, c, k1, po) = two_links(517, false);
    lp.peers[0].engine.demote(&k1, &Demotion { member: po, new: None, presync: PreSync::Synced }).unwrap();
    let (rot, still) = lp.peers[0].engine.ensure_rotated(&c).unwrap();
    assert!(still.is_empty() && !rot.commits.is_empty(), "alice rotates C");
    spread_hiding(&mut lp, 2, k1);
    assert!(lp.peers[2].engine.epochs(&k1).is_none_or(|e| e.read.held().next().is_none()), "late holds no K1 secret");
    assert!(!lp.peers[2].engine.departures(&c).unwrap().is_empty(), "late knows the departure inside K1");
    let (rot, still) = lp.peers[2].engine.ensure_rotated(&c).unwrap();
    assert!(rot.commits.is_empty() && still.is_empty(), "late rotates nothing: {still:?}");
}

// spec/permissions.md §3: o0 leaves K1 by self-removal (no rotation); late, a reader of K1, may
// not rotate K1, and a rotation of C would still box K1 at the uncovered epoch: it does not
// rotate C (stranded on C until K1 rotates), however often it is asked.
// spec/permissions.md §3 (required rotation)
#[test]
fn no_rotation_that_cannot_cover_spec_perm_3() {
    let (mut lp, c, k1, po) = two_links(518, true);
    lp.peers[1].engine.demote(&k1, &Demotion { member: po, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    for _ in 0..3 {
        let (rot, still) = lp.peers[2].engine.ensure_rotated(&c).unwrap();
        assert!(rot.commits.is_empty(), "no useless rotation of C");
        assert!(!still.is_empty(), "C stays uncovered for late");
    }
}

// spec/permissions.md §7, spec/crypto.md §3, §4: a doc moved into a team without secrets of
// its own: the copy's own-secrets rotation boxes nobody (the team has no keyset). The writer,
// who does not read the team, gets the re-grant before the rotation commit (wrapped under the
// copy's derived epoch): its history box hands it that epoch, and once the rotation commit is
// opened its write epoch is established.
#[test]
fn move_into_derived_owner_spec_perm_7() {
    let (mut lp, ps) = people(2, 519);
    let (pa, pb) = (ps[0], ps[1]);
    let team = thing_of(&mut lp, 0, pa);
    let doc = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&doc, &pb, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let before: BTreeSet<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    let (copy, done) = lp.peers[0].engine.move_to(&doc, &team).unwrap();
    let new: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    let (own, rest): (Vec<CommitId>, Vec<CommitId>) = new.into_iter().partition(|c| {
        let h = lp.peers[0].engine.header(c).unwrap();
        h.aspects.iter().any(|a| a.tid == copy && a.ak.as_str() == "/keys") && !h.aspects.iter().any(|a| a.ak.as_str() == "/members")
    });
    assert_eq!(own.len(), 1, "the copy's own-secrets rotation");
    send(&mut lp, 0, 1, &rest);
    carry(&mut lp, 0, &done);
    let e = lp.peers[1].engine.epochs(&copy).unwrap();
    let derived = lp.peers[0].engine.epochs(&copy).unwrap().read.epochs().filter(|(_, i)| i.established == Some(osis_keys::Provenance::Derived)).map(|(k, _)| *k).max_by_key(|k| k.n()).unwrap();
    assert!(e.read.secret(&derived).is_some(), "the grant's history box opens the derived epoch");
    send(&mut lp, 0, 1, &own);
    let e = lp.peers[1].engine.epochs(&copy).unwrap();
    assert!(e.write.newest_held().is_some(), "bob holds an established write epoch of the copy");
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
// spec/permissions.md §7 (one import)
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
// spec/permissions.md §5.3
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

// spec/crypto.md §4: "An epoch of role r covers a departure of M if it holds no box for M"; a
// key actor's box keyed at a higher role carries the roles below it. A node granted write with
// `until` while another admin rotated write only (a demotion it had not seen with the grant)
// keeps its box at the superseded write epoch, which still carries the read epoch. Once `until`
// passes, the next writer rotates read before encrypting, and the key actor holds none of it.
#[test]
fn stale_key_actor_box_after_until_spec_crypto_4() {
    let (mut lp, ps) = people(4, 521);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let n3 = lp.peers[3].engine.tid();
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    lp.advance(1000);
    let until = osis_core::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
    lp.peers[0].engine.grant(&t, &n3, &ct::Edge { role: Role::Write, until: Some(until), invite: None, since: None }).unwrap();
    lp.peers[1].engine.demote(&t, &Demotion { member: pc, new: Some(edge_of(Role::Read)), presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let r0 = newest_read(&lp, 1, t).unwrap();
    assert!(!lp.peers[3].engine.epochs(&t).unwrap().read.reading_secrets(&r0).is_empty(), "the key actor holds the read epoch");
    lp.advance(2 * 3_600_000);
    let (done, still) = lp.peers[1].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty());
    let r1 = newest_read(&lp, 1, t).unwrap();
    assert_ne!(r0, r1, "read rotated: {done:?}");
    spread(&mut lp);
    assert!(lp.peers[3].engine.epochs(&t).unwrap().read.reading_secrets(&r1).is_empty(), "the departed key actor is out");
}

// spec/commits.md §3 (shared key commit form): a link key, usable from several devices, signs
// its redemption in commit form.
#[test]
fn link_key_writes_commit_form_spec_commits_3() {
    let (mut lp, ps) = people(2, 512);
    let (pa, ps1) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Write, None)).unwrap();
    sync(&mut lp, 0, 1);
    let done = lp.peers[1].engine.redeem(&link, &ps1, true).unwrap();
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    let by_l: Vec<CommitId> = done.commits.iter().copied().filter(|c| lp.peers[1].engine.header(c).unwrap().author == l).collect();
    assert!(!by_l.is_empty());
    for c in by_l {
        assert_eq!(lp.peers[1].engine.header(&c).unwrap().form, osis_commit::Form::Commit);
    }
}

// spec/permissions.md §2 (edge inbox delivery): a change and a removal of an actor's edge reach
// that actor as inbox blobs, like a grant.
#[test]
fn edge_change_and_removal_by_inbox_spec_perm_2() {
    let (mut lp, ps) = people(2, 521);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let to_pb = |done: &Done| done.deliveries.iter().filter(|x| matches!(x, Delivery::Inbox { to, .. } if *to == pb)).count();
    let down = lp.peers[0].engine.demote(&d, &Demotion { member: pb, new: Some(edge_of(Role::Read)), presync: PreSync::Synced }).unwrap();
    assert_eq!(to_pb(&down), 1, "change");
    spread(&mut lp);
    let gone = lp.peers[0].engine.demote(&d, &Demotion { member: pb, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(to_pb(&gone), 1, "removal");
}

/// The deltas of commit `c` on `(t, a)`, their bytes.
fn aspect_deltas(e: &mut osis_node::Engine, c: &CommitId, t: Tid, a: &str) -> Vec<Vec<u8>> {
    let h = e.header(c).unwrap();
    let ai = h.aspects.iter().position(|x| x.tid == t && x.ak.as_str() == a).unwrap();
    let blob = osis_commit::CommitBlob::decode(&e.commit_bytes(c).unwrap().unwrap()).unwrap();
    blob.parts.into_iter().filter(|p| p.ai == ai).map(|p| p.delta).collect()
}

// spec/permissions.md §6, spec/commits.md §2: a roster snapshot carries one reset-plus-state
// delta per edge (and per ledger entry), each the size of one edge whatever the roster's size,
// so a large roster never approaches `MAX_BLOB` as one delta.
#[test]
fn roster_snapshot_one_delta_per_edge_spec_perm_6() {
    let mut lp = net(2, 530);
    let t = new_thing(&mut lp, 0);
    let n = 200;
    for i in 0..n {
        let m = Tid::from_bytes([u8::try_from(i % 250).unwrap(), 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
        set_edge(&mut lp.peers[0].engine, t, m, Some(edge(Role::Read)), None);
    }
    let done = lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    let c = *done.commits.last().unwrap();
    let members = aspect_deltas(&mut lp.peers[0].engine, &c, t, "/members");
    assert_eq!(members.len(), n + 1, "the reset alone, then one delta per edge");
    assert!(members.iter().all(|d| d.len() < 300), "{:?}", members.iter().map(Vec::len).max());
    assert_eq!(aspect_deltas(&mut lp.peers[0].engine, &c, t, "/tenures").len(), 1, "an empty ledger: the reset alone");
    // a receiver joins the deltas back into the whole roster
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.roster(&t), lp.peers[0].engine.roster(&t));
    assert_eq!(lp.peers[1].engine.roster(&t).len(), n);
}

// spec/permissions.md §4, §6; spec/sync.md §3: a certificate copy of a person actor's roster
// snapshot under a co-reader's label carries only the chain's edge (the device that writes),
// never the person's other devices.
#[test]
fn roster_snapshot_certificate_projected_spec_perm_6() {
    let mut lp = net(3, 531);
    let (p, done) = lp.peers[0].engine.create_person(&servers()).unwrap();
    assert_eq!(done.commits.len(), 1);
    let n1 = lp.peers[1].engine.tid();
    let card1: Vec<CommitId> = lp.peers[1].engine.commit_ids();
    send(&mut lp, 1, 0, &card1);
    let paired = lp.peers[0].engine.pair(&p.person, &n1).unwrap();
    carry(&mut lp, 0, &paired);
    let bob = lp.peers[2].engine.create_person(&servers()).unwrap().0.person;
    spread(&mut lp);
    let g = thing_of(&mut lp, 0, p.person);
    lp.peers[0].engine.grant(&g, &bob, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let r = lp.peers[0].engine.hold_key_actor(p.card.seed.clone()).unwrap();
    let done = lp.peers[0].engine.roster_snapshot(&p.person, Some(&r)).unwrap();
    let s = *done.commits.last().unwrap();
    assert_eq!(aspect_deltas(&mut lp.peers[0].engine, &s, p.person, "/members").len(), 3, "the reset, both devices");
    let certs = lp.peers[0].engine.certificates(&g);
    let parts = certs.get(&s).expect("the snapshot is a chain certificate");
    let h = lp.peers[0].engine.header(&s).unwrap();
    let members_ai = h.aspects.iter().position(|a| a.ak.as_str() == "/members").unwrap();
    assert_eq!(parts.iter().filter(|(ai, _)| *ai == members_ai).count(), 2, "the reset and one edge: {parts:?}");
    let bodies = lp.peers[0].engine.part_bodies(&s, parts).unwrap();
    let carried: BTreeSet<(usize, usize)> = bodies.iter().flat_map(|b| b.parts.iter().copied()).collect();
    assert_eq!(&carried, parts);
    // the copy names this device only
    let me = lp.peers[0].engine.tid();
    let copy = bodies.iter().find(|b| b.parts.iter().any(|(ai, _)| *ai == members_ai)).unwrap();
    assert!(contains(&copy.plaintext, me.as_bytes()) && !contains(&copy.plaintext, n1.as_bytes()));
}

// spec/permissions.md §5.1, §6; spec/data-model.md §6: a demotion's frontier above
// `CHUNK_THRESHOLD` goes by link, the roster snapshot's ledger carries it by link, and a node
// holding only the snapshot waits for the frontier's blobs, then judges the demoted writer's
// covered writes by it (valid, not dropped as by an empty frontier).
#[test]
fn linked_tenure_frontier_spec_perm_6() {
    use std::collections::BTreeMap;
    let mut lp = net(3, 532);
    let t = new_thing(&mut lp, 0);
    let x = lp.peers[1].engine.tid();
    let grant = set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    add_tag(&mut lp, 1, t, "by x");
    sync(&mut lp, 1, 0);
    // the frontier covers x's write, padded past the threshold
    let tags_of = |n: u64| BTreeMap::from([("/t/tags".to_string(), BTreeMap::from([(x, n)]))]);
    let mut writes = BTreeMap::from([(t, tags_of(1))]);
    for i in 0..4000u32 {
        let b = i.to_be_bytes();
        writes.insert(Tid::from_bytes([b[0], b[1], b[2], b[3], 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]), tags_of(5));
    }
    let frontier = osis_schema::Codec::to_value(&ct::Frontier { writes, commits: BTreeSet::new() });
    assert!(osis_core::encode(&frontier).len() > osis_core::format::CHUNK_THRESHOLD);
    let demotion = set_edge(&mut lp.peers[0].engine, t, x, None, Some(frontier));
    assert!(lp.peers[0].engine.header(&demotion).unwrap().links.frontier.is_some(), "the header frontier goes by link");
    let done = lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    let s = *done.commits.last().unwrap();
    let ledger = lp.peers[0].engine.get_typed(&t, &ct::TENURES).unwrap().unwrap();
    assert!(matches!(ledger.0.as_slice(), [ct::Tenure { frontier: Some(osis_schema::Chunked::Link(_)), .. }]), "{ledger:?}");
    // peer 2: everything but the grant and the demotion; the snapshot first without its blobs
    let mut ids = lp.peers[0].engine.commit_ids();
    ids.retain(|c| *c != grant && *c != demotion && *c != s);
    for id in ids {
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        lp.deliver(2, &pk).unwrap();
    }
    let pk = lp.peers[0].engine.package(&s).unwrap().unwrap();
    assert!(!pk.blobs.is_empty());
    let r = lp.peers[2].engine.ingest(&pk.bytes, Vec::new()).unwrap();
    assert_eq!(r, osis_node::Ingested::Pending(s, osis_node::Reason::WaitBlobs));
    lp.deliver(2, &pk).unwrap();
    assert_eq!(lp.peers[2].engine.roster(&t), lp.peers[0].engine.roster(&t));
    assert_eq!(tags(&mut lp, 2, t), BTreeSet::from(["by x".to_string()]), "x's covered write stands");
}
