#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Role flows over `LocalPeer`: commits and inbox blobs are
//! delivered by hand between engines (no labels or hosts).

use crate::common;
use common::*;
use osis_base::{Clock, CommitId, Role, Tid, Value};
use osis_label::Address;
use osis_node::flows::{Delivery, Demotion, Done, PreSync};
use osis_node::local_peer::LocalPeer;
use osis_node::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn hosts() -> Vec<Address> {
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

/// `spread` as labels carry commits (`SealedPackage`): each peer opens only what the read
/// secrets it holds unwrap.
fn spread_sealed(lp: &mut LocalPeer) {
    let n = lp.peers.len();
    for _ in 0..2 {
        for a in 0..n {
            let ids = lp.peers[a].engine.commit_ids();
            let pks = lp.sealed(a, &ids).unwrap();
            for b in (0..n).filter(|b| *b != a) {
                lp.deliver_sealed(b, &pks).unwrap();
            }
        }
    }
}

/// Peer `from` writes `v` on `t` and sends it sealed (`SealedPackage`) to every other peer: the
/// peers that read it then. One that does not read it opened none of its bodies (it lacks the key,
/// not the delivery).
fn sealed_write(lp: &mut LocalPeer, from: usize, t: Tid, v: &str) -> BTreeSet<usize> {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(v)).unwrap();
    let c = lp.peers[from].commit(m).unwrap().unwrap();
    let pks = lp.sealed(from, &[c]).unwrap();
    assert!(!pks.is_empty() && !pks[0].entries.is_empty(), "the writer seals its write");
    let mut out = BTreeSet::new();
    for i in (0..lp.peers.len()).filter(|i| *i != from) {
        let left = lp.deliver_sealed(i, &pks).unwrap();
        let reads = lp.peers[i].engine.get(&t, &ak("t:reg.0")).unwrap() == Some(s(v));
        assert_eq!(left.is_empty(), reads, "peer {i}: opened iff it reads");
        if reads {
            out.insert(i);
        }
    }
    out
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
    match lp.peers[i].engine.get(&t, &ak("t:tags.0")).unwrap() {
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
    let (p, done) = lp.peers[0].engine.create_person(&hosts()).unwrap();
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
// node its admin, secrets of its own, `keys.0` with inbox and deposit seed, home label genesis
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
    let (_, read) = osis_label::open_entry_box(&eb, &step, &rk.kem, &p).unwrap();
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
        ps.push(lp.peers[i].engine.create_person(&hosts()).unwrap().0.person);
    }
    spread(&mut lp);
    (lp, ps)
}

fn edge_of(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None, tied: None, keyset: None }
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
// commit; the removed holder holds no secret of the new epoch and drops what it lost.
// spec/crypto.md §4 (removed holder), spec/permissions.md §3 (drop lost secrets)
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
    let done = lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(done.commits.len(), 1);
    let c = done.commits[0];
    let h = lp.peers[0].engine.header(&c).unwrap();
    let aks: BTreeSet<&str> = h.aspects.iter().map(|a| a.ak.as_str()).collect();
    assert_eq!(aks, BTreeSet::from(["roles.0", "secrets.0", "keys.0"]));
    assert!(h.frontier.is_some());
    assert!(done.deliveries.iter().any(|x| matches!(x, Delivery::First { .. })));
    let e1 = newest_read(&lp, 0, d).unwrap();
    assert_ne!(e0, e1);
    // sealed: the removal is wrapped under the epoch it supersedes, so bob still opens it
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 2, d), Some(e1), "carol is boxed at the new epoch");
    assert_eq!(lp.peers[1].engine.epochs(&d).unwrap().read.secret(&e1), None, "bob is not");
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    assert_eq!(sealed_write(&mut lp, 0, d, "after"), BTreeSet::from([2]), "bob does not read what follows");
    let lost = lp.peers[1].engine.drop_lost_secrets().unwrap();
    assert!(lost.contains(&d));
    assert!(lp.peers[1].engine.epochs(&d).is_none_or(|e| e.read.held().next().is_none()));
}

// spec/permissions.md §5.2 (validity judged alike); notes/local-store.md (a rebuildable index): after grants, a removal with its rotation, content
// by the removed holder before and after it (the latter invalid here), the indexes an open reads
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
    lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
    lp.advance(10);
    let late = write(&mut lp, 1, "bob after");
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let h = e.header(&late).unwrap();
    assert!(h.aspects.iter().any(|a| a.tid == d), "bob's late write is held");
    assert_eq!(e.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob before")), "and invalid here");
    let before = e.index_digest();
    assert!(before.commits.values().any(|c| c.valid.contains(&false)), "an invalid part is indexed");
    e.reload().unwrap();
    assert_eq!(e.index_digest(), before, "loaded from the persisted index");
    e.rebuild_index().unwrap();
    assert_eq!(e.index_digest(), before, "rebuilt from the commit records");
    e.reload().unwrap();
    assert_eq!(e.index_digest(), before, "the rebuilt index persisted");
    // another build's rules (everything valid, states joined so), then a row that does not
    // decode: each open rebuilds, re-tags and re-joins the states judged otherwise
    for garble in [false, true] {
        e.damage_index(garble).unwrap();
        if !garble {
            assert_eq!(e.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob after")), "the old rules' state");
        }
        e.reload().unwrap();
        assert_eq!(e.index_digest(), before, "rebuilt after damage (garbled: {garble})");
        assert!(e.index_current().unwrap());
        assert_eq!(e.get(&d, &ak("t:reg.0")).unwrap(), Some(s("bob before")), "re-joined (garbled: {garble})");
    }
}

/// A peer for forensic and crash checks: small key tree and pages (a shred elsewhere does not
/// incidentally rotate a leaked copy away), every row recorded, faults injectable.
fn forensic_peer(seed: u64, faults: &osis_store::Faults) -> osis_node::local_peer::Peer {
    let clock = std::sync::Arc::new(osis_base::ManualClock::new(T0));
    let (backend, root) = (osis_store::MemoryBackend::with_faults(faults.clone()), osis_store::MemoryRoot::with_faults(faults.clone()));
    backend.record_history();
    let c: std::sync::Arc<dyn osis_base::Clock> = clock.clone();
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
    let c: std::sync::Arc<dyn osis_base::Clock> = p.clock.clone();
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
    let mut lp = LocalPeer::of(vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &faults)], seed);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
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
        assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s(&big(mark))));
        assert!(lp.peers[1].engine.epochs(&t).is_some_and(|x| x.read.held().next().is_some()), "bob holds the secrets");
    }
    let target = if from_e { e } else { d };
    lp.peers[0].engine.demote(&target, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&d), if from_e { Some(Role::Read) } else { None });
    Lost { lp, faults, d, e, f, mine }
}

/// Bob reads only e and his own thing, and an attacker holding his device and every row it
/// ever wrote recovers neither lost marker.
fn assert_forgotten(x: &mut Lost) {
    let b = &mut x.lp.peers[1];
    let reg = ak("t:reg.0");
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
    assert_eq!(x.lp.peers[1].engine.get(&x.d, &ak("t:reg.0")).unwrap(), Some(s(&big(D_MARK))));
    let lost: BTreeSet<Tid> = x.lp.peers[1].engine.drop_lost_secrets().unwrap().into_iter().collect();
    assert!(lost.contains(&x.d) && lost.contains(&x.f) && !lost.contains(&x.e), "{lost:?}");
    let ev = x.lp.peers[1].drain_events();
    assert!(ev.iter().any(|e| matches!(e, osis_node::Event::Changed { cause: osis_node::Cause::LostAccess, changed } if changed.contains(&(x.d, ak("t:reg.0"))))));
    assert_forgotten(&mut x);
    // forgotten for good: after a restart, and a second drop finds nothing
    reopen(&mut x.lp, 1, 2).unwrap();
    assert!(x.lp.peers[1].engine.drop_lost_secrets().unwrap().is_empty());
    assert_forgotten(&mut x);
    // bob keeps syncing what he reads, and only that
    assert_eq!(sealed_write(&mut x.lp, 0, x.e, "later"), BTreeSet::from([1]));
    for t in [x.d, x.f] {
        assert!(sealed_write(&mut x.lp, 0, t, "after").is_empty());
    }
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
        let kept = x.lp.peers[1].engine.get(&x.d, &ak("t:reg.0")).unwrap();
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

// spec/permissions.md §3 (a node that learns it lost read access MUST drop): an admin's re-grant
// bob holds pending keeps d (and f through it) only until it ages out of `PENDING_GRANT_WAIT_MS`;
// it never applies and no other role commit arrives, yet the trigger comes due then and drops
// them. `restart`: bob reopens while waiting (the due time is stored).
fn aged_out_grant(seed: u64, restart: bool) {
    let mut x = lost_setup(seed);
    let rcpt = read_recipient(&x.lp.peers[1].engine);
    let bytes = forge_pending_grant(&mut x.lp.peers[0].engine, rcpt, x.d, seed);
    assert!(matches!(x.lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), osis_node::Ingested::Pending(..)));
    let ts = crate::common::grant_ts(&bytes);
    x.lp.peers[1].clock.set(ts);
    x.lp.peers[1].engine.freeze_pending();
    let lost = x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(!lost.contains(&x.d) && !lost.contains(&x.f), "{lost:?}");
    assert!(!x.lp.peers[1].engine.lost_due());
    let at = x.lp.peers[1].engine.next_lost_due().expect("due when the grant ages out");
    let now = x.lp.peers[1].engine.now().0;
    assert!(at > now && at <= now + osis_node::rotation::PENDING_GRANT_WAIT_MS, "{at} {now}");
    if restart {
        // past the drift bound again while opening examines it
        x.lp.peers[1].clock.set(osis_base::WallMs(ts.0 - 2 * osis_base::format::MAX_DRIFT_MS));
        reopen(&mut x.lp, 1, seed).unwrap();
        x.lp.peers[1].clock.set(ts);
        x.lp.peers[1].engine.freeze_pending();
        assert_eq!(x.lp.peers[1].engine.next_lost_due(), Some(at));
    }
    x.lp.peers[1].clock.advance(at - now);
    assert!(x.lp.peers[1].engine.lost_due());
    let lost = x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(lost.contains(&x.d) && lost.contains(&x.f) && !lost.contains(&x.e), "{lost:?}");
    assert!(!x.lp.peers[1].engine.lost_due() && x.lp.peers[1].engine.next_lost_due().is_none());
    assert!(x.lp.peers[1].engine.pending().is_empty(), "the grant boxed no newer epoch: its only part went with the secrets");
    assert_forgotten(&mut x);
}

// spec/permissions.md §3 (a node that learns it lost read access MUST drop): `aged_out_grant`
#[test]
fn aged_out_pending_grant_drops_spec_perm_3() {
    aged_out_grant(523, false);
}

// spec/permissions.md §3 (a node that learns it lost read access MUST drop): `aged_out_grant`
#[test]
fn aged_out_pending_grant_drops_after_restart_spec_perm_3() {
    aged_out_grant(525, true);
}

// spec/permissions.md §3: only units the node "can no longer read by another path" go: bob,
// removed from e, still reads e through d and keeps everything.
#[test]
fn removal_with_another_path_keeps_all_spec_perm_3() {
    let mut x = lost_setup_from(517, true);
    assert_eq!(x.lp.peers[1].engine.role_on(&x.e), Some(Role::Read));
    assert!(x.lp.peers[1].engine.drop_lost_due().unwrap().is_empty());
    assert!(x.lp.peers[1].engine.drop_lost_secrets().unwrap().is_empty());
    let reg = ak("t:reg.0");
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
    let reading = |x: &Lost| x.lp.peers[1].engine.epochs(&g).is_some_and(|e| e.read.holds_any());
    assert!(reading(&x), "secrets from the pending grant");
    let lost = x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(lost.contains(&x.d) && !lost.contains(&g), "{lost:?}");
    assert!(!x.lp.peers[1].engine.drop_lost_secrets().unwrap().contains(&g));
    assert!(reading(&x));
    assert_forgotten(&mut x);
    spread(&mut x.lp);
    assert_eq!(x.lp.peers[1].engine.role_on(&g), Some(Role::Read));
    assert_eq!(x.lp.peers[1].engine.get(&g, &ak("t:reg.0")).unwrap(), Some(s("new")));
}

// spec/crypto.md §4 (a secret from an unchecked box is kept for reading only),
// spec/permissions.md §3: a planted grant (bad signature, held pending while its author is
// unknown) yields reading-only secrets; once it proves bad and is dropped, they go.
#[test]
fn dropped_pending_grant_drops_reading_secrets_spec_crypto_4() {
    let mut lp = net(2, 521);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
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
    assert!(lp.peers[1].engine.epochs(&g).is_some_and(|e| e.read.holds_any()), "read from the planted box");
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
    assert!(lp.peers[1].engine.epochs(&g).is_none_or(|e| !e.read.holds_any()));
}

// spec/permissions.md §2: an invite holder grants a new holder up to its invite, and cannot
// change or remove anyone else; a holder leaves by self-removal.
// spec/permissions.md §2 (invite scope)
#[test]
fn invite_power_spec_perm_2() {
    let (mut lp, ps) = people(3, 504);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &ct::Edge { role: Role::Write, until: None, invite: Some(Role::Read), since: None, tied: None, keyset: None }).unwrap();
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
    // no invite holder removes or demotes another holder
    assert!(lp.peers[1].engine.demote(&d, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).is_err());
    // an existing holder cannot be invite-granted again
    assert!(lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Read)).is_err());
    // carol leaves by herself (a reader: no rotation of d is hers to make)
    lp.peers[2].engine.demote(&d, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
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
// from its receipt record, keeps the edits it received and drops the demoted holder's edits
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
    assert!(lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Unsynced { proceed: false } }).is_err());
    lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Unsynced { proceed: true } }).unwrap();
    lp.advance(DAY);
    add_tag(&mut lp, 1, d, "y");
    spread(&mut lp);
    for i in [0, 1] {
        assert_eq!(tags(&mut lp, i, d), BTreeSet::from(["mon".to_string()]), "node {i}");
    }
}

// notes/permissions.md (roles model: mutual removal): two admins removing each other
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
    lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.demote(&t, &Demotion { holder: pa, new: None, presync: PreSync::Synced }).unwrap();
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
    lp.peers[1].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
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

/// The frontier commit IDs of role commit `c`.
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
    lp.peers[1].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
    let r = lp.peers[1].engine.commit_ids().into_iter().find(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_some()).unwrap();
    assert!(g.iter().all(|c| frontier_ids(&mut lp, 1, &r).contains(c)), "Bob lists the grant he holds");
    let until = osis_base::WallMs(lp.peers[0].clock.as_ref().now_wall_ms().0 + 3_600_000);
    let before = ids(&lp, 2);
    lp.peers[2].engine.grant(&t, &pb, &ct::Edge { role: Role::Admin, until: Some(until), invite: None, since: None, tied: None, keyset: None }).unwrap();
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
    lp.peers[2].engine.grant(&t, &pb, &ct::Edge { role: Role::Admin, until: None, invite: Some(Role::Read), since: None, tied: None, keyset: None }).unwrap();
    let f = new_ids(&lp, 2, &before);
    send(&mut lp, 2, 1, &f);
    lp.peers[1].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
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
    lp.peers[1].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
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

// spec/crdt.md §8 (absorbed commits count only with a held header), spec/permissions.md §5.1,
// §5.2 (a valid snapshot vouches for what it carries): X's removal of M (with X's rotation) is
// compacted away: Alice snapshots `secrets.0` and `keys.0` and writes a roster snapshot, so hosts
// drop its blobs, header included, and late joiner Bob gets only the snapshots. Bob cannot tell
// the absorbed commit from one X signed ahead, so his removal of X does not list it; Alice, still
// holding it, judges its deltas invalid, but her snapshots vouch for its writes: she, Bob and
// fresh nodes agree, M stays removed.
#[test]
fn late_joiner_after_compaction_agrees_spec_crdt_8() {
    let (mut lp, ps) = people(4, 512);
    let (pa, pb, px, pm) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &px, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pm, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    // X removes M: its commit carries X's rotation of t
    let before = ids(&lp, 2);
    lp.peers[2].engine.demote(&t, &Demotion { holder: pm, new: None, presync: PreSync::Synced }).unwrap();
    let xr = new_ids(&lp, 2, &before);
    send(&mut lp, 2, 0, &xr);
    lp.advance(1000);
    let snap = lp.peers[0].engine.snapshot(&t, &ak("secrets.0")).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.header(&snap).unwrap().form, osis_commit::Form::Node);
    lp.peers[0].engine.snapshot(&t, &ak("keys.0")).unwrap().unwrap();
    lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    // Bob joins late: everything Alice holds but X's removal itself
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    let to_b: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !xr.contains(c)).collect();
    send(&mut lp, 0, 1, &to_b);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Admin));
    assert!(xr.iter().all(|c| lp.peers[1].engine.header(c).is_none()), "Bob never got X's removal");
    assert!(!lp.peers[1].engine.roster(&t).contains_key(&pm));
    lp.advance(1000);
    let before = ids(&lp, 1);
    lp.peers[1].engine.demote(&t, &Demotion { holder: px, new: None, presync: PreSync::Synced }).unwrap();
    let br = new_ids(&lp, 1, &before);
    let r = br.iter().copied().find(|c| lp.peers[1].engine.header(c).unwrap().frontier.is_some()).unwrap();
    assert!(xr.iter().all(|c| !frontier_ids(&mut lp, 1, &r).contains(c)), "the unheld absorbed commit is not listed");
    send(&mut lp, 1, 0, &br);
    let aspects: BTreeSet<_> = xr.iter().flat_map(|c| lp.peers[0].engine.header(c).unwrap().aspects.iter().map(|a| (a.tid, a.ak.clone())).collect::<Vec<_>>()).collect();
    let all = lp.peers[0].engine.commit_ids();
    for reversed in [false, true] {
        let i = lp.peers.len();
        lp.peers.push(osis_node::local_peer::Peer::new(0x7700 + reversed as u64, lp.peers[0].engine.now()).unwrap());
        let mut v = all.clone();
        if reversed {
            v.reverse();
        }
        send(&mut lp, 0, i, &v);
        lp.peers[i].engine.reexamine().unwrap();
        for k in [0, 1, i] {
            for (x, a) in &aspects {
                assert_eq!(lp.peers[k].engine.get(x, a).unwrap(), lp.peers[0].engine.get(x, a).unwrap(), "peer {k} {a:?}, reversed {reversed}");
            }
            let roster = lp.peers[k].engine.roster(&t);
            assert!(!roster.contains_key(&pm) && !roster.contains_key(&px), "peer {k}, reversed {reversed}");
        }
    }
}

/// Peers 0 and 1 are devices of person P (created on 1, 0 paired); peer 2 is Alice (PA).
fn devices_and_alice(seed: u64) -> (LocalPeer, Tid, Tid, osis_label::RecoveryCard) {
    let mut lp = net(3, seed);
    let (p, _) = lp.peers[1].engine.create_person(&hosts()).unwrap();
    let d1 = lp.peers[0].engine.tid();
    let ids = lp.peers[0].engine.commit_ids();
    send(&mut lp, 0, 1, &ids);
    let paired = lp.peers[1].engine.pair(&p.person, &d1).unwrap();
    carry(&mut lp, 1, &paired);
    let pa = lp.peers[2].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut lp);
    assert_eq!(lp.peers[0].engine.role_on(&p.person), Some(Role::Admin));
    (lp, p.person, pa, p.card)
}

// spec/permissions.md §3, spec/crypto.md §4 (covers by names, the recursive box judgement; the TLC two-hop scenario):
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
    lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: PreSync::Synced }).unwrap();
    let deps = lp.peers[1].engine.departures(&u).unwrap();
    assert!(deps.iter().any(|d| d.holder == d1 && d.via == vec![t, p]), "{deps:?}");
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
    assert_eq!(sealed_write(&mut lp, 1, u, "after"), BTreeSet::from([2]), "d1 reads nothing new on U");
    assert_eq!(sealed_write(&mut lp, 1, t, "after"), BTreeSet::from([2]), "nor on T");
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
    lp.peers[0].engine.demote(&p, &Demotion { holder: d2, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    for i in [1, 2, 3] {
        let r = lp.peers[i].engine.roster(&p);
        assert!(r.contains_key(&d2) && r.contains_key(&n) && !r.contains_key(&d1), "peer {i}: {r:?}");
    }
    assert_eq!(newest_read(&lp, 1, p), Some(pe), "the honest device holds the new epoch");
    assert!(lp.peers[0].engine.epochs(&p).unwrap().read.secret(&pe).is_none(), "the thief does not");
    assert_eq!(sealed_write(&mut lp, 3, p, "after"), BTreeSet::from([1]), "the thief reads nothing new");
    assert!(lp.peers[3].engine.departures(&p).unwrap().iter().any(|d| d.holder == d1));
}

fn link_spec(target: Tid, role: Role, until: Option<osis_base::WallMs>) -> osis_node::flows::LinkSpec {
    osis_node::flows::LinkSpec { target, role, until, hosts: hosts(), peers: Vec::new(), single_use: false }
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

// spec/permissions.md §9, §5.1, §3: the race flipped by the finalization. Peer 2 redeems first,
// peer 1 later; peer 1 sees both and loses by its view, but keeps K's and the target's secrets
// (so it keeps following their labels) while L's self-removal is not finalized. The sharer saw
// only peer 1's redemption: its finalization drops peer 2's and peer 1 is in. Peer 2, the loser
// once the finalization arrives, drops them.
#[test]
fn single_use_loser_keeps_secrets_until_finalized_spec_perm_9() {
    let (mut lp, ps) = people(3, 522);
    let (pa, ps1, ps2) = (ps[0], ps[1], ps[2]);
    let d = thing_of(&mut lp, 0, pa);
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &link_spec(d, Role::Read, None)).unwrap();
    spread(&mut lp);
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    let early = lp.peers[2].engine.redeem(&link, &ps2, true).unwrap().commits;
    lp.peers[1].clock.advance(1000);
    let late = lp.peers[1].engine.redeem(&link, &ps1, true).unwrap().commits;
    send(&mut lp, 2, 1, &early);
    assert!(!lp.peers[1].engine.roster(&link.k).contains_key(&ps1), "peer 1 lost by its view");
    lp.peers[1].engine.drop_lost_secrets().unwrap();
    assert!(lp.peers[1].engine.epochs(&link.k).is_some() && lp.peers[1].engine.epochs(&d).is_some(), "kept until finalized");
    send(&mut lp, 1, 0, &late);
    lp.peers[0].clock.advance(2000);
    let fin = lp.peers[0].engine.finalize_link(&link.k, &l).unwrap();
    send(&mut lp, 0, 1, &fin.commits);
    send(&mut lp, 2, 0, &early);
    for i in [0, 1] {
        let r = lp.peers[i].engine.roster(&link.k);
        assert!(r.contains_key(&ps1) && !r.contains_key(&ps2) && !r.contains_key(&l), "peer {i}: {r:?}");
    }
    assert_eq!(lp.peers[1].engine.role_on(&d), Some(Role::Read));
    assert!(lp.peers[1].engine.drop_lost_secrets().unwrap().is_empty());
    // the loser holds its own redemption only until the finalization reaches it
    lp.peers[2].engine.drop_lost_secrets().unwrap();
    assert!(lp.peers[2].engine.epochs(&link.k).is_some(), "peer 2 won by its view");
    send(&mut lp, 1, 2, &late);
    lp.peers[2].engine.drop_lost_secrets().unwrap();
    assert!(lp.peers[2].engine.epochs(&link.k).is_some(), "lost by its view, not finalized");
    send(&mut lp, 0, 2, &fin.commits);
    assert!(!lp.peers[2].engine.roster(&link.k).contains_key(&ps2));
    let dropped = lp.peers[2].engine.drop_lost_secrets().unwrap();
    assert!(dropped.contains(&link.k), "{dropped:?}");
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
    assert_eq!(h.aspects.iter().filter(|a| a.tid == link.k && a.ak.as_str() == "secrets.0").count(), 1, "one rotation");
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
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
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
    assert!(sealed_write(&mut lp, 0, d, "after").is_empty(), "and reads nothing new on the target");
}

// spec/permissions.md §9 (link finalized), §5.1: an expired link is due for finalization on both of the sharer's
// devices (the seed thing is the person's); both finalize concurrently without conflict. A seed
// holder whose clock lags signs an invite grant as L dated before `until`, after both removals:
// their frontiers do not cover it, so it is void at every peer, whether it arrives before or
// after the removals (until they arrive it stands: the window the removal closes); the joiner
// that redeemed while the link worked stays.
#[test]
fn until_link_backdated_grant_void_spec_perm_9() {
    let (mut lp, p, _) = person_two_devices(530);
    let mut more = net(3, 531);
    lp.peers.append(&mut more.peers);
    let ps: Vec<Tid> = (2..5).map(|i| lp.peers[i].engine.create_person(&hosts()).unwrap().0.person).collect();
    let (joiner, forger) = (ps[0], ps[1]);
    spread(&mut lp);
    let d = thing_of(&mut lp, 0, p);
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
    let (link, keep, _) = lp.peers[0].engine.create_link(&p, &link_spec(d, Role::Read, Some(until))).unwrap();
    let l = osis_node::identity::Identity::from_seed(link.seed.clone()).tid();
    spread(&mut lp);
    lp.peers[2].engine.redeem(&link, &joiner, false).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.get(&keep, &ak(osis_node::flows::LINK_SEED)).unwrap().is_some());
        assert_eq!(lp.peers[i].engine.held_links().unwrap().iter().map(|h| (h.k, h.l, h.owner, h.here)).collect::<Vec<_>>(), vec![(link.k, l, p, i == 0)], "peer {i}");
        assert!(lp.peers[i].engine.links_due().unwrap().is_empty(), "peer {i}: not expired yet");
        assert_eq!(lp.peers[i].engine.next_link_expiry().unwrap(), Some(until.0), "peer {i}");
    }
    assert_eq!(lp.peers[2].engine.next_link_expiry().unwrap(), None);
    // the link expires everywhere but at the forger
    for i in [0, 1, 2, 4] {
        lp.peers[i].clock.advance(2 * 3_600_000);
    }
    let mut removals = Vec::new();
    for i in [0, 1] {
        assert_eq!(lp.peers[i].engine.links_due().unwrap().iter().map(|(h, u)| (h.k, h.l, *u)).collect::<Vec<_>>(), vec![(link.k, l, Some(until))], "peer {i}");
        assert_eq!(lp.peers[i].engine.next_link_expiry().unwrap(), None);
        let done = lp.peers[i].engine.finalize_link(&link.k, &l).unwrap();
        assert!(lp.peers[i].engine.links_due().unwrap().is_empty(), "peer {i}: idempotent");
        removals.push((i, done.commits));
    }
    // the forger: L still alive by its clock, a grant dated before `until`
    let forged = lp.peers[3].engine.redeem(&link, &forger, false).unwrap().commits;
    assert!(lp.peers[3].engine.header(&forged[0]).unwrap().ts.wall_ms() < until);
    // (its clock catches up, else it parks the removals as from the future)
    lp.peers[3].clock.advance(2 * 3_600_000);
    // peer 4 gets the forged grant first, peer 2 the removals first
    send(&mut lp, 3, 4, &forged);
    assert!(lp.peers[4].engine.roster(&link.k).contains_key(&forger), "stands until the removal arrives");
    for (i, c) in &removals {
        send(&mut lp, *i, 4, c);
        send(&mut lp, *i, 2, c);
    }
    send(&mut lp, 3, 2, &forged);
    spread(&mut lp);
    for i in 0..5 {
        let r = lp.peers[i].engine.roster(&link.k);
        assert!(r.contains_key(&joiner) && !r.contains_key(&forger) && !r.contains_key(&l), "peer {i}: {r:?}");
        assert_eq!(lp.peers[i].engine.core.role_now(&forger, &d), None, "peer {i}");
    }
    for i in 0..5 {
        assert!(lp.peers[i].engine.links_due().unwrap().is_empty(), "peer {i}: nothing left after both removals");
    }
    // sealed: the joiner reads the target, not the seed thing; the forger neither
    assert_eq!(sealed_write(&mut lp, 0, d, "after"), BTreeSet::from([1, 2]));
    assert_eq!(sealed_write(&mut lp, 0, keep, "after"), BTreeSet::from([1]));
}

// spec/permissions.md §3 (re-seal): a grant raced by a rotation leaves the grantee without a
// box at the new epoch; at the end of a complete pass a node that may rotate re-seals it by
// inbox; the removed holder is not re-sealed.
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
    lp.peers[1].engine.demote(&t, &Demotion { holder: pd, new: None, presync: PreSync::Synced }).unwrap();
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
    assert_eq!(sealed_write(&mut lp, 0, t, "after"), BTreeSet::from([1, 2]), "carol reads, dave does not");
}

// spec/permissions.md §3 (re-seal), spec/crypto.md §4: a person actor's holders are all key
// actors (its devices, its recovery key), boxed per role; after a device removal rotates every
// role, every remaining holder has a box at each new epoch, so nobody is "seen without a box"
// and nothing is re-sealed.
#[test]
fn key_actor_holders_not_resealed_spec_perm_3() {
    struct Pass;
    impl osis_node::flows::SyncState for Pass {
        fn complete_pass(&self, _: &Tid) -> bool {
            true
        }
    }
    let mut lp = net(3, 533);
    let (p, _) = lp.peers[0].engine.create_person(&hosts()).unwrap();
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
    let done = lp.peers[0].engine.demote(&p, &Demotion { holder: n2, new: None, presync: PreSync::Synced }).unwrap();
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
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 5_000);
    lp.peers[0].engine.grant(&t, &pb, &ct::Edge { role: Role::Read, until: Some(until), invite: None, since: None, tied: None, keyset: None }).unwrap();
    assert!(lp.peers[0].engine.departures(&t).unwrap().is_empty());
    lp.advance(10_000);
    let deps = lp.peers[0].engine.departures(&t).unwrap();
    assert!(deps.iter().any(|d| d.holder == pb), "{deps:?}");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty() && done.commits.len() == 1, "rotated away");
}

// notes/sync.md Limits (stranded device re-paired), spec/permissions.md §3: a device whose
// grant raced a rotation of its person is re-sealed over the pairing channel.
#[test]
fn stranded_device_repaired_spec_perm_3() {
    let mut lp = net(4, 513);
    let (p, _) = lp.peers[0].engine.create_person(&hosts()).unwrap();
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
    lp.peers[1].engine.demote(&p, &Demotion { holder: d2, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let e1 = newest_read(&lp, 1, p).unwrap();
    assert!(lp.peers[3].engine.epochs(&p).unwrap().read.secret(&e1).is_none(), "n is stranded");
    assert_eq!(lp.peers[3].engine.role_on(&p), Some(Role::Admin));
    assert_eq!(sealed_write(&mut lp, 1, p, "stranded"), BTreeSet::from([0]), "n reads nothing new");
    // re-pairing an existing holder re-seals it
    let again = lp.peers[0].engine.pair(&p, &n).unwrap();
    assert_eq!(again.commits.len(), 1);
    carry(&mut lp, 0, &again);
    assert_eq!(newest_read(&lp, 3, p), Some(e1));
    assert!(lp.peers[2].engine.epochs(&p).unwrap().read.secret(&e1).is_none());
    assert_eq!(sealed_write(&mut lp, 1, p, "repaired"), BTreeSet::from([0, 3]));
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
    let r1 = lp.peers[1].engine.demote(&t, &Demotion { holder: pd, new: None, presync: PreSync::Synced }).unwrap();
    send(&mut lp, 1, 0, &r1.commits);
    send(&mut lp, 1, 2, &r1.commits);
    let e1 = newest_read(&lp, 0, t).unwrap();
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.secret(&e1).is_none(), "carol has no box at e1");
    lp.advance(1000);
    let r2 = lp.peers[0].engine.demote(&t, &Demotion { holder: pe, new: None, presync: PreSync::Synced }).unwrap();
    (lp, t, pc, r2)
}

// spec/permissions.md §3 (rotation), spec/sync.md §3: a rotation boxing a holder that holds no
// box at the current read epoch before it (a grant raced by an earlier rotation; the single-use
// link race's winner) reaches that holder by inbox: it could not open the rotation commit from
// the label, which is wrapped under that epoch.
#[test]
fn rotation_reaches_unboxed_holder_spec_perm_3() {
    let (mut lp, t, pc, r2) = raced_then_rotated(515);
    let inbox: Vec<&Vec<u8>> = r2.deliveries.iter().filter_map(|x| if let Delivery::Inbox { to, blob, .. } = x { (*to == pc).then_some(blob) } else { None }).collect();
    assert_eq!(inbox.len(), 1, "the rotation goes to carol's inbox");
    lp.peers[2].engine.accept_inbox(inbox[0]).unwrap();
    let e2 = newest_read(&lp, 0, t).unwrap();
    assert_eq!(newest_read(&lp, 2, t), Some(e2));
    assert!(lp.peers[2].engine.epochs(&t).unwrap().read.is_established(&e2), "carol holds e2's chain");
    assert!(!r2.deliveries.iter().any(|x| matches!(x, Delivery::Inbox { to, .. } if *to == lp.peers[1].engine.tid())));
}

// spec/permissions.md §3 (re-seal), spec/crypto.md §4: a re-seal of a holder whose box at the
// epoch sits in a commit it does not hold still reaches it (the box is re-written, not
// overlaid on an entry the holder never got).
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
/// `secrets.0` parts (they travel under K1's label only), as with `spread_hiding`. Returns
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

/// `spread`, but peer `to` gets every commit without its `secrets.0` parts of `hidden`.
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
                    let hide: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, x)| x.tid == hidden && x.ak.as_str() == "secrets.0").map(|(i, _)| i).collect();
                    blob.parts.retain(|p| !hide.contains(&p.ai));
                    let _ = lp.peers[b].engine.ingest(&blob.encode(), pk.blobs.clone());
                }
            }
        }
    }
}

// spec/crypto.md §4 (the box judgement; a node holding no secret of M judges by M's newest
// `keys.0` keyset), spec/permissions.md §3: after alice removes o0 from K1 and rotates K1 and C, a
// writer of C that never read K1 sees C covered and rotates nothing.
#[test]
fn unheld_holder_judged_by_keyset_spec_crypto_4() {
    let (mut lp, c, k1, po) = two_links(517, false);
    lp.peers[0].engine.demote(&k1, &Demotion { holder: po, new: None, presync: PreSync::Synced }).unwrap();
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
    lp.peers[1].engine.demote(&k1, &Demotion { holder: po, new: None, presync: PreSync::Synced }).unwrap();
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
// copy's derived epoch): its history box hands it that epoch's secret (it names its epoch), and
// once the rotation commit is opened its write epoch is established.
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
        h.aspects.iter().any(|a| a.tid == copy && a.ak.as_str() == "keys.0") && !h.aspects.iter().any(|a| a.ak.as_str() == "roles.0")
    });
    assert_eq!(own.len(), 1, "the copy's own-secrets rotation");
    send(&mut lp, 0, 1, &rest);
    carry(&mut lp, 0, &done);
    let e = lp.peers[1].engine.epochs(&copy).unwrap();
    let derived = lp.peers[0].engine.epochs(&copy).unwrap().read.epochs().filter(|(_, i)| i.established == Some(osis_keys::Provenance::Derived)).map(|(k, _)| *k).max_by_key(|k| k.n()).unwrap();
    let genuine = lp.peers[0].engine.epochs(&copy).unwrap().read.secret(&derived).cloned().unwrap();
    assert_eq!(e.read.secret(&derived), Some(&genuine), "the grant's history box opens the derived epoch");
    send(&mut lp, 0, 1, &own);
    let e = lp.peers[1].engine.epochs(&copy).unwrap();
    assert_eq!(e.read.secret(&derived), Some(&genuine));
    assert!(e.write.newest_held().is_some(), "bob holds an established write epoch of the copy");
}

// spec/sync.md §2, §5: after a rotation an admin issues a child of the host's head at the
// newest epochs; the removed device has no claim key in it, the remaining one has.
#[test]
fn registration_step_after_rotation_spec_sync_5() {
    let (mut lp, p, _pa, card) = devices_and_alice(514);
    let d1 = lp.peers[0].engine.tid();
    let labels = lp.peers[1].engine.get_typed(&p, &ct::LABEL).unwrap().unwrap();
    let genesis = osis_label::StepId(*labels.get(&card.home_label).unwrap().steps.keys().next().unwrap());
    assert!(lp.peers[1].engine.issue_step(&p, &card.home_label, &genesis, false).unwrap().0.is_none(), "nothing newer");
    lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: PreSync::Synced }).unwrap();
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

// spec/crypto.md §3 (fresh deposit seed), spec/sync.md §5: an admin's removal that rotates read writes a fresh
// deposit seed in its rotation commit, and the step it issues registers the new deposit key, so
// the removed device can no longer deposit under the actor's labels.
#[test]
fn removal_refreshes_deposit_seed_spec_crypto_3() {
    let (mut lp, p, _pa, card) = devices_and_alice(516);
    let d1 = lp.peers[0].engine.tid();
    let labels = lp.peers[1].engine.get_typed(&p, &ct::LABEL).unwrap().unwrap();
    let genesis = osis_label::StepId(*labels.get(&card.home_label).unwrap().steps.keys().next().unwrap());
    let old = lp.peers[1].engine.deposit_seed(&p).unwrap().unwrap();
    let done = lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: PreSync::Synced }).unwrap();
    let new = lp.peers[1].engine.deposit_seed(&p).unwrap().unwrap();
    assert!(old != new, "refreshed");
    let removal = *done.commits.last().unwrap();
    let h = lp.peers[1].engine.header(&removal).unwrap();
    assert!(h.aspects.iter().any(|a| a.tid == p && a.ak.as_str() == "roles.0") && h.aspects.iter().any(|a| a.tid == p && a.ak.as_str() == "keys.0"), "in the removal's rotation commit");
    let (step, _) = lp.peers[1].engine.issue_step(&p, &card.home_label, &genesis, false).unwrap().0.unwrap();
    assert_eq!(step.keys.deposit, osis_crypto::deposit_key(&new, &card.home_label).verifying_key());
}

// spec/sync.md §5: a refreshed deposit seed alone (no rotation) is registered by the next step
// an admin issues: a child at the same role keys with the new deposit key; then nothing is due.
#[test]
fn refreshed_deposit_seed_issues_step_spec_sync_5() {
    let (mut lp, p, _pa, card) = devices_and_alice(518);
    let labels = lp.peers[1].engine.get_typed(&p, &ct::LABEL).unwrap().unwrap();
    let genesis = osis_label::StepId(*labels.get(&card.home_label).unwrap().steps.keys().next().unwrap());
    let parent = osis_label::parse_record(&labels.get(&card.home_label).unwrap().steps[&genesis.0]).unwrap().0;
    assert!(lp.peers[1].engine.issue_step(&p, &card.home_label, &genesis, false).unwrap().0.is_none(), "nothing newer");
    lp.peers[1].engine.refresh_deposit_seed(&p).unwrap();
    let new = lp.peers[1].engine.deposit_seed(&p).unwrap().unwrap();
    let (step, _) = lp.peers[1].engine.issue_step(&p, &card.home_label, &genesis, false).unwrap().0.unwrap();
    step.verify_child(&parent).unwrap();
    assert_eq!(step.keys.deposit, osis_crypto::deposit_key(&new, &card.home_label).verifying_key());
    assert_ne!(step.keys.deposit, parent.keys.deposit);
    assert_eq!((step.keys.sync, step.keys.write, step.keys.delete), (parent.keys.sync, parent.keys.write, parent.keys.delete));
    assert!(lp.peers[1].engine.issue_step(&p, &card.home_label, &step.id(), false).unwrap().0.is_none(), "registered: nothing due");
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
    lp.peers[0].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
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
    assert!(ledger.0.iter().any(|x| x.holder == pc && x.role == Role::Write && x.frontier.is_some()), "{ledger:?}");
    let raw = lp.peers[1].engine.state(&t, &ak("roles.0")).unwrap().unwrap().read().unwrap();
    let roster = osis_schema::AspectKey::decode(&ct::ROLES, &raw).unwrap();
    assert!(roster.get(&pb).unwrap().since.is_some(), "{roster:?}");
    add_tag(&mut lp, 1, t, "bob");
    spread(&mut lp);
    assert!(tags(&mut lp, 0, t).contains("bob"));
}

// spec/permissions.md §7: moving a doc to another owner copies it with its history, re-grants
// its holders on the copy and points the old thing at it; a second move is refused.
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

// spec/crypto.md §4 (forks): two admins removing different holders concurrently fork the read
// epoch; each fork boxes a holder the other removed, so the next node to encrypt under it
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
    lp.peers[0].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
    lp.peers[1].engine.demote(&t, &Demotion { holder: pd, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let forks = lp.peers[0].engine.epochs(&t).unwrap().read.current();
    assert_eq!(forks.len(), 2, "{forks:?}");
    assert_eq!(forks[0].n(), forks[1].n(), "one n: each counts from the epoch it supersedes");
    assert_eq!(lp.peers[1].engine.epochs(&t).unwrap().read.current(), forks);
    assert_eq!(newest_read(&lp, 0, t), newest_read(&lp, 1, t), "ties broken alike");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty());
    assert_eq!(done.commits.len(), 1);
    let e3 = newest_read(&lp, 0, t).unwrap();
    assert_eq!(e3.n(), forks[0].n() + 1);
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
    let done = lp.peers[1].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(aks_of(&lp, 1, &done.commits[0]), BTreeSet::from(["roles.0".to_string()]));
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
    assert!(sealed_write(&mut lp, 0, d, "after").is_empty(), "the leaver's old secrets open nothing new");
}

// spec/permissions.md §2, §3: a device removing its person from a team (its only authority
// there comes through the person) is a self-removal; the team's admin rotates later.
#[test]
fn device_removes_person_from_team_spec_perm_3() {
    let (mut lp, p, pa, _) = devices_and_alice(520);
    let t = thing_of(&mut lp, 2, pa);
    lp.peers[2].engine.grant(&t, &p, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let done = lp.peers[1].engine.demote(&t, &Demotion { holder: p, new: None, presync: PreSync::Synced }).unwrap();
    assert_eq!(aks_of(&lp, 1, &done.commits[0]), BTreeSet::from(["roles.0".to_string()]));
    spread(&mut lp);
    assert!(!lp.peers[2].engine.roster(&t).contains_key(&p));
    let (rot, _) = lp.peers[2].engine.ensure_rotated(&t).unwrap();
    assert_eq!(rot.commits.len(), 1);
    let e1 = newest_read(&lp, 2, t).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.epochs(&t).is_none_or(|e| e.read.secret(&e1).is_none()), "device {i}");
    }
    assert!(sealed_write(&mut lp, 2, t, "after").is_empty(), "neither device reads what follows");
}

// spec/permissions.md §2, §5.1: a self-removal is audited like any write. Device d1 removes
// its person P from alice's doc, unseen; d2 then removes d1 from P with a frontier that misses
// it (d1's backdated forgery, in effect): every reader drops it and P keeps its role. Had d2
// received it first, its frontier covers it and the leave stands.
#[test]
fn removed_device_backdated_leave_dropped_spec_perm_5_1() {
    for seen in [false, true] {
        let (mut lp, p, pa, _) = devices_and_alice(523);
        let d1 = lp.peers[0].engine.tid();
        let t = thing_of(&mut lp, 2, pa);
        lp.peers[2].engine.grant(&t, &p, &edge_of(Role::Write)).unwrap();
        spread(&mut lp);
        let leave = lp.peers[0].engine.demote(&t, &Demotion { holder: p, new: None, presync: PreSync::Synced }).unwrap();
        if seen {
            send(&mut lp, 0, 1, &leave.commits);
        }
        lp.advance(1000);
        lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: PreSync::Synced }).unwrap();
        spread(&mut lp);
        for i in 0..3 {
            let role = lp.peers[i].engine.roster(&t).get(&p).map(|e| e.role);
            assert_eq!(role, if seen { None } else { Some(Role::Write) }, "seen {seen}, peer {i}");
        }
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
    lp.peers[2].engine.demote(&t, &Demotion { holder: pc, new: None, presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let done = lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    assert_eq!(done.commits.len(), 2, "the rotation, then the snapshot");
    let e1 = newest_read(&lp, 0, t).unwrap();
    spread(&mut lp);
    assert!(lp.peers[2].engine.epochs(&t).is_none_or(|e| e.read.secret(&e1).is_none()));
    assert!(lp.peers[1].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "nothing left");
    assert_eq!(sealed_write(&mut lp, 0, t, "after"), BTreeSet::from([1]), "carol reads nothing new");
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
    lp.peers[1].engine.demote(&link.k, &Demotion { holder: ps1, new: None, presync: PreSync::Synced }).unwrap();
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
    assert_eq!(sealed_write(&mut lp, 0, d, "after"), BTreeSet::from([2]), "the removed joiner reads nothing new");
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
    lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: PreSync::Synced }).unwrap();
    let (label, done) = lp.peers[1].engine.create_label(&t, &hosts()).unwrap();
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
    lp.peers[0].clock.set(osis_base::WallMs(theft.0 + 60_000));
    add_tag(&mut lp, 0, u, "forged");
    lp.peers[0].clock.set(osis_base::WallMs(theft.0 + 3 * HOUR));
    sync(&mut lp, 0, 1);
    lp.advance(HOUR);
    let backdated = PreSync::Backdated(osis_base::WallMs(theft.0 + HOUR / 2));
    lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: backdated }).unwrap();
    spread(&mut lp);
    for i in [1, 2] {
        assert_eq!(tags(&mut lp, i, u), BTreeSet::from(["honest".to_string()]), "peer {i}");
    }
}

// spec/permissions.md §5.1 (frontier: chain certificates as of T): a backdated revoke lists
// only the certificate commits its author had received by its cutoff. The thief's write on an
// edge of the demoter's own chain (d1 re-grants d2 on P), received after the cutoff, is
// dropped.
#[test]
fn backdated_revoke_lists_certs_as_of_cutoff_spec_perm_5_1() {
    const HOUR: u64 = 3_600_000;
    let (mut lp, p, _pa, _) = devices_and_alice(525);
    let (d1, d2) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let theft = lp.peers[0].engine.now();
    lp.advance(2 * HOUR);
    let done = lp.peers[0].engine.grant(&p, &d2, &edge_of(Role::Admin)).unwrap();
    let forged: Vec<CommitId> = done.commits.iter().copied().filter(|c| lp.peers[0].engine.edge_applied(&p, c)).collect();
    assert_eq!(forged.len(), 1);
    spread(&mut lp);
    assert!(lp.peers[1].engine.edge_applied(&p, &forged[0]));
    lp.advance(HOUR);
    let backdated = PreSync::Backdated(osis_base::WallMs(theft.0 + HOUR / 2));
    lp.peers[1].engine.demote(&p, &Demotion { holder: d1, new: None, presync: backdated }).unwrap();
    spread(&mut lp);
    for i in [1, 2] {
        assert!(!lp.peers[i].engine.edge_applied(&p, &forged[0]), "peer {i}");
    }
}

// spec/permissions.md §7, spec/sync.md §2: a labeled doc's copy gets a label of its own at the
// doc's hosts before its holders are re-granted, so they sync and write it whatever else of
// the new owner they read.
#[test]
fn move_labels_copy_spec_perm_7() {
    let (mut lp, ps) = people(2, 518);
    let (pa, pb) = (ps[0], ps[1]);
    let team = thing_of(&mut lp, 0, pa);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Write)).unwrap();
    lp.peers[0].engine.create_label(&d, &hosts()).unwrap();
    spread(&mut lp);
    let (copy, _) = lp.peers[0].engine.move_to(&d, &team).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        let ls = lp.peers[i].engine.group_labels(&copy).unwrap();
        assert_eq!(ls.len(), 1, "peer {i}");
        assert_eq!(ls[0].hosts, hosts());
    }
    assert_eq!(lp.peers[1].engine.role_on(&copy), Some(Role::Write));
    // an unlabeled doc's copy gets none
    let e = thing_of(&mut lp, 0, pa);
    let (copy, _) = lp.peers[0].engine.move_to(&e, &team).unwrap();
    assert!(lp.peers[0].engine.group_labels(&copy).unwrap().is_empty());
}

// spec/crypto.md §4 (covers by names; a departure past its `until` is named by its expiry). A
// node granted write with `until` while another admin rotated write only (a demotion it had not
// seen with the grant) keeps its box at the current read epoch. Once `until` passes, the next
// writer rotates read before encrypting, and the key actor holds none of it.
#[test]
fn raced_grant_read_box_after_until_spec_crypto_4() {
    let (mut lp, ps) = people(4, 521);
    let (pa, pb, pc) = (ps[0], ps[1], ps[2]);
    let n3 = lp.peers[3].engine.tid();
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    lp.advance(1000);
    let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 3_600_000);
    lp.peers[0].engine.grant(&t, &n3, &ct::Edge { role: Role::Write, until: Some(until), invite: None, since: None, tied: None, keyset: None }).unwrap();
    lp.peers[1].engine.demote(&t, &Demotion { holder: pc, new: Some(edge_of(Role::Read)), presync: PreSync::Synced }).unwrap();
    spread(&mut lp);
    let r0 = newest_read(&lp, 1, t).unwrap();
    assert!(!lp.peers[3].engine.epochs(&t).unwrap().read.reading_secret(&r0).is_none(), "the key actor holds the read epoch");
    lp.advance(2 * 3_600_000);
    let (done, still) = lp.peers[1].engine.ensure_rotated(&t).unwrap();
    assert!(still.is_empty());
    let r1 = newest_read(&lp, 1, t).unwrap();
    assert_ne!(r0, r1, "read rotated: {done:?}");
    spread(&mut lp);
    assert!(lp.peers[3].engine.epochs(&t).unwrap().read.reading_secret(&r1).is_none(), "the departed key actor is out");
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
    let down = lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: Some(edge_of(Role::Read)), presync: PreSync::Synced }).unwrap();
    assert_eq!(to_pb(&down), 1, "change");
    spread(&mut lp);
    let gone = lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
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
    let n = 60;
    for i in 0..n {
        let m = Tid::from_bytes([u8::try_from(i % 250).unwrap(), 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9]);
        set_edge(&mut lp.peers[0].engine, t, m, Some(edge(Role::Read)), None);
    }
    let done = lp.peers[0].engine.roster_snapshot(&t, None).unwrap();
    let c = *done.commits.last().unwrap();
    let holders = aspect_deltas(&mut lp.peers[0].engine, &c, t, "roles.0");
    assert_eq!(holders.len(), n + 1, "the reset alone, then one delta per edge");
    assert!(holders.iter().all(|d| d.len() < 300), "{:?}", holders.iter().map(Vec::len).max());
    assert_eq!(aspect_deltas(&mut lp.peers[0].engine, &c, t, "tenures.0").len(), 1, "an empty ledger: the reset alone");
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
    let (p, done) = lp.peers[0].engine.create_person(&hosts()).unwrap();
    assert_eq!(done.commits.len(), 1);
    let n1 = lp.peers[1].engine.tid();
    let card1: Vec<CommitId> = lp.peers[1].engine.commit_ids();
    send(&mut lp, 1, 0, &card1);
    let paired = lp.peers[0].engine.pair(&p.person, &n1).unwrap();
    carry(&mut lp, 0, &paired);
    let bob = lp.peers[2].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut lp);
    let g = thing_of(&mut lp, 0, p.person);
    lp.peers[0].engine.grant(&g, &bob, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let r = lp.peers[0].engine.hold_key_actor(p.card.seed.clone()).unwrap();
    let done = lp.peers[0].engine.roster_snapshot(&p.person, Some(&r)).unwrap();
    let s = *done.commits.last().unwrap();
    assert_eq!(aspect_deltas(&mut lp.peers[0].engine, &s, p.person, "roles.0").len(), 3, "the reset, both devices");
    let certs = lp.peers[0].engine.certificates(&g);
    let parts = certs.get(&s).expect("the snapshot is a chain certificate");
    let h = lp.peers[0].engine.header(&s).unwrap();
    let holders_ai = h.aspects.iter().position(|a| a.ak.as_str() == "roles.0").unwrap();
    assert_eq!(parts.iter().filter(|(ai, _)| *ai == holders_ai).count(), 2, "the reset and one edge: {parts:?}");
    let bodies = lp.peers[0].engine.part_bodies(&s, parts).unwrap();
    let carried: BTreeSet<(usize, usize)> = bodies.iter().flat_map(|b| b.parts.iter().copied()).collect();
    assert_eq!(&carried, parts);
    // the copy names this device only
    let me = lp.peers[0].engine.tid();
    let copy = bodies.iter().find(|b| b.parts.iter().any(|(ai, _)| *ai == holders_ai)).unwrap();
    assert!(contains(&copy.plaintext, me.as_bytes()) && !contains(&copy.plaintext, n1.as_bytes()));
}

// spec/permissions.md §5.1, §6; spec/data-model.md §6: a demotion's frontier above
// `CHUNK_THRESHOLD` goes by link, the roster snapshot's ledger carries it by link, and a node
// holding only the snapshot waits for the frontier's blobs, then judges the demoted writer's
// covered writes by it (valid, not dropped as by an empty frontier).
#[test]
fn linked_tenure_frontier_spec_perm_6() {
    let mut lp = net(3, 532);
    let t = new_thing(&mut lp, 0);
    let x = lp.peers[1].engine.tid();
    let grant = set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    add_tag(&mut lp, 1, t, "by x");
    sync(&mut lp, 1, 0);
    let by_x = lp.peers[0].engine.commit_ids().into_iter().find(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.author == x && h.aspects.iter().any(|a| a.ak.as_str() == "t:tags.0"))).unwrap();
    // the frontier lists x's write, padded past the threshold
    let mut commits = BTreeSet::from([by_x]);
    for i in 0..4000u32 {
        let b = i.to_be_bytes();
        commits.insert(osis_base::CommitId([b[0], b[1], b[2], b[3], 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]));
    }
    let frontier = osis_schema::Codec::to_value(&ct::Frontier { commits });
    assert!(osis_base::encode(&frontier).len() > osis_base::format::CHUNK_THRESHOLD);
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
    let before = lp.peers[2].engine.roster(&t);
    lp.peers[2].engine.ingest(&pk.bytes, Vec::new()).unwrap();
    assert_eq!(lp.peers[2].engine.pending(), vec![(s, osis_node::Reason::WaitBlobs)]);
    assert_eq!(lp.peers[2].engine.roster(&t), before, "out of the walk while its frontier is away");
    lp.deliver(2, &pk).unwrap();
    assert!(lp.peers[2].engine.pending().is_empty());
    assert_eq!(lp.peers[2].engine.roster(&t), lp.peers[0].engine.roster(&t));
    assert_eq!(tags(&mut lp, 2, t), BTreeSet::from(["by x".to_string()]), "x's covered write stands");
}

/// A role commit by a made-up node (its chain unknown everywhere, so held pending forever)
/// writing `secrets` as `secrets.0` on `t`.
fn stranger_secrets(lp: &mut LocalPeer, t: Tid, secrets: &ct::Secrets) -> Vec<u8> {
    use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
    use osis_crdt::{Delta, Source, Writer, create, encode_delta};
    use osis_schema::Codec;
    let keys = osis_crypto::KeyActorKeys::from_seed(&osis_crypto::Secret32::from_bytes([0x55; 32]));
    let author = Tid::from_bytes([0x77; 15]);
    let ts = osis_base::Ts::make(lp.peers[0].engine.now(), 0).unwrap();
    let a = ak("secrets.0");
    let view = osis_schema::core_schema().view(a.as_str()).unwrap();
    let own = Source::commit(CommitId([0; 32]));
    let mut w = Writer::new(ts, own.clone(), 1);
    let f = create(&mut w, &view, &secrets.to_value()).unwrap();
    let r = w.range();
    let mut cx = writer_ctx(Kind::Role, ts, author, r.lo, r.hi);
    cx.own = own;
    // small enough to stay inline: no page blobs to deliver
    let mut pages = osis_crdt::MemoryPages::default();
    let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, Some(&mut pages)).unwrap();
    assert!(pages.is_empty());
    let mut aw = AspectWrite::new(t, a.clone(), r.lo, r.hi, bytes);
    aw.retention = osis_commit::retention::write_retention(a.as_str(), None, None).unwrap();
    let mut cb = CommitBuilder::new(Kind::Role, ts, author, author, Form::Commit);
    cb.aspects.push(aw);
    let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
    cb.build(&keys.signing, &Keys(rec), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
}

// spec/crypto.md §4 (a rotation's n is 1 + the greatest n it supersedes; a pending commit's
// secrets are kept for reading only): a stranger's pending commit boxing alice's actor at the top
// of the int range, plus a hundred unopenable boxes at huge epochs, neither grows alice's
// epoch records nor stops her removing bob (the removal's rotation counts up from her own
// established epoch), across a restart.
#[test]
fn planted_epoch_blocks_no_removal_spec_crypto_4() {
    let (mut lp, ps) = people(2, 523);
    let (pa, pb) = (ps[0], ps[1]);
    let d = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let before = lp.peers[0].engine.epochs(&d).unwrap();
    let n0 = before.read.newest().unwrap().n();
    // an openable box to pa at the top, and unopenable ones (keyed to bob) at huge epochs
    let top_secret = osis_crypto::Secret32::from_bytes([0xee; 32]);
    let top = osis_crypto::Epoch::derive(&d, Role::Read, i64::MAX as u64, &top_secret).unwrap();
    let mut v = osis_keys::ActorEpochs::default();
    v.read.set_secret(top, top_secret);
    v.read.set_established(top, osis_keys::Provenance::Fixed);
    let pk = lp.peers[0].engine.get_typed(&pa, &ct::KEYS).unwrap().unwrap();
    let rc = osis_keys::Recipient { holder: pa, role: Role::Admin, keys: osis_keys::HolderKeys::from_keys(&pk).unwrap() };
    let w = osis_keys::box_holder(&d, &v, &ct::Secrets::default(), &rc, &BTreeSet::from([Role::Read]), &mut osis_crypto::SeededRng::from_u64(5)).unwrap().unwrap();
    let mut s = ct::Secrets::default();
    w.apply(&mut s);
    let junk = ct::SecretBox::Symmetric(ct::SymmetricBox { epoch: osis_keys::aspects::to_schema(&top), wrap: vec![0; 49], names: None });
    for i in 0..100u64 {
        let e = osis_crypto::Epoch::new(i64::MAX as u64 - 1 - i, [2; 32]).unwrap();
        s.boxes.insert(osis_keys::aspects::box_key(pb, Role::Read, &e), junk.clone());
    }
    let forged = stranger_secrets(&mut lp, d, &s);
    lp.peers[0].engine.ingest(&forged, Vec::new()).unwrap();
    assert!(!lp.peers[0].engine.pending().is_empty(), "held pending: its author is unknown");
    let held = lp.peers[0].engine.epochs(&d).unwrap();
    assert!(held.read.is_reading_only(&top), "the openable box: reading-only");
    assert_eq!(held.read.epochs().count(), before.read.epochs().count() + 1, "no entry for the unopenable boxes");
    let done = lp.peers[0].engine.demote(&d, &Demotion { holder: pb, new: None, presync: PreSync::Synced }).unwrap();
    assert!(!done.commits.is_empty());
    let after = lp.peers[0].engine.epochs(&d).unwrap();
    assert_eq!(after.read.newest().unwrap().n(), n0 + 1);
    assert!(!lp.peers[0].engine.roster(&d).contains_key(&pb));
    lp.peers[0].restart(5231).unwrap();
    let after = lp.peers[0].engine.epochs(&d).unwrap();
    assert_eq!(after.read.newest().unwrap().n(), n0 + 1);
    assert!(after.read.epochs().all(|(e, _)| e.n() <= n0 + 1 || *e == top));
}

// spec/permissions.md §5.1 Frontier (commit IDs only, never counters): a demoter lists C's held
// edit by its commit ID, whatever group it is under.
#[test]
fn frontier_lists_commit_ids_spec_perm_5_1() {
    let (mut lp, ps) = people(3, 511);
    let (pa, pc) = (ps[0], ps[2]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &pc, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let before = ids(&lp, 2);
    add_tag(&mut lp, 2, t, "c");
    let e = new_ids(&lp, 2, &before);
    spread(&mut lp);
    let nc = lp.peers[2].engine.tid();
    let scope = osis_perm::DemotionScope { roles: [(nc, [t].into())].into(), content: [(nc, [t].into())].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    assert!(!e.is_empty() && e.iter().all(|c| f.commits.contains(c)), "by ID: {f:?}");
}

// spec/permissions.md §5.1 (frontier: chain certificates as of T): the demoter's own grant by
// X, stamped before the cutoff but received after it, is not listed, so a revoke of X cut off
// before that receipt would drop the grant its own authority rests on: refused here. Cut off
// after the receipt, it removes X and keeps the grant.
#[test]
fn backdated_revoke_before_own_grant_received_spec_perm_5_1() {
    const HOUR: u64 = 3_600_000;
    let mut lp = net(3, 526);
    let (x, a) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let pa = lp.peers[2].engine.create_person(&hosts()).unwrap().0.person;
    let t = thing_of(&mut lp, 2, pa);
    spread(&mut lp);
    lp.peers[2].engine.grant(&t, &x, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    lp.peers[0].engine.grant(&t, &a, &edge_of(Role::Admin)).unwrap();
    lp.advance(HOUR);
    let early = lp.peers[0].engine.now();
    lp.advance(HOUR);
    spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Admin));
    lp.advance(HOUR);
    let late = osis_base::WallMs(lp.peers[1].engine.now().0 - HOUR / 2);
    let cut = |w| Demotion { holder: x, new: None, presync: PreSync::Backdated(w) };
    assert!(lp.peers[1].engine.demote(&t, &cut(early)).is_err());
    lp.peers[1].engine.demote(&t, &cut(late)).unwrap();
    spread(&mut lp);
    for i in 0..3 {
        let r = lp.peers[i].engine.roster(&t);
        assert!(!r.contains_key(&x) && r.get(&a).is_some_and(|e| e.role == Role::Admin), "peer {i}");
    }
}

// spec/permissions.md §5.1 Frontier, §5.2 Acting; issues/frontier-clobbers-history.md (a kick
// never scales with history): device 1 writes doc X many times as its person P, compacted, and
// once as P on its own thing Y. Removing it from P lists only what no snapshot covers: Y's write
// (it would go invalid unlisted, though the device's own right on Y never fell), not every
// commit it made as P; X keeps its last value.
#[test]
fn removed_device_frontier_lists_uncovered_acting_spec_perm_5_1() {
    let (mut lp, p, _) = person_two_devices(902);
    let x = thing_of(&mut lp, 0, p);
    let d = lp.peers[1].engine.tid();
    let y = thing_of(&mut lp, 1, d);
    spread(&mut lp);
    let reg = ak("t:reg.0");
    let write = |lp: &mut LocalPeer, t: Tid, v: &str| {
        let mut m = Mutation::new();
        m.set(t, &REG, &s(v)).unwrap();
        m.act_as(p);
        lp.peers[1].commit(m).unwrap().unwrap()
    };
    let mut on_x = Vec::new();
    for i in 0..30 {
        on_x.push(write(&mut lp, x, &format!("v{i}")));
    }
    lp.peers[1].engine.snapshot(&x, &reg).unwrap().unwrap();
    let on_y = write(&mut lp, y, "as p");
    spread(&mut lp);
    let ds = BTreeSet::from([p, x]);
    let scope = osis_perm::DemotionScope { roles: [(d, ds.clone())].into(), content: [(d, ds)].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    assert!(f.commits.contains(&on_y), "an uncovered write as P on a thing outside the scope");
    assert!(on_x.iter().all(|c| !f.commits.contains(c)), "covered writes as P listed: {} commits", f.commits.len());
    lp.peers[0].engine.demote(&p, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    assert!(!lp.peers[0].engine.roster(&p).contains_key(&d));
    assert_eq!(lp.peers[0].engine.get(&x, &reg).unwrap(), Some(s("v29")));
    assert_eq!(lp.peers[0].engine.get(&y, &reg).unwrap(), Some(s("as p")));
}

// spec/permissions.md §5.1 (a frontier leaves out only what the demoter's compaction could drop
// now), spec/commits.md §5 (role-class deltas kept `ROLE_KEEP` after replaced): M leaves t twice
// by self-removal, and admin X rotates t after each. Alice snapshots `secrets.0` and `keys.0`,
// covering both rotations. Removing X, she lists X's first rotation (its keysets replaced inside
// `ROLE_KEEP`), so it stays valid; the second, live and covered, is left out.
#[test]
fn rotation_within_role_keep_listed_spec_perm_5_1() {
    let (mut lp, ps) = people(3, 0x7190);
    let (pa, px, pm) = (ps[0], ps[1], ps[2]);
    let t = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&t, &px, &edge_of(Role::Admin)).unwrap();
    let mut rotations = Vec::new();
    for _ in 0..2 {
        lp.peers[0].engine.grant(&t, &pm, &edge_of(Role::Read)).unwrap();
        spread(&mut lp);
        lp.advance(1_000);
        lp.peers[2].engine.demote(&t, &Demotion { holder: pm, new: None, presync: PreSync::Synced }).unwrap();
        spread(&mut lp);
        lp.advance(1_000);
        let (rot, still) = lp.peers[1].engine.ensure_rotated(&t).unwrap();
        assert!(still.is_empty() && rot.commits.len() == 1);
        assert_eq!(aks_of(&lp, 1, &rot.commits[0]), BTreeSet::from(["keys.0".to_string(), "secrets.0".to_string()]));
        rotations.push(rot.commits[0]);
        spread(&mut lp);
        lp.advance(1_000);
    }
    let keys = ak("keys.0");
    let snaps = [lp.peers[0].engine.snapshot(&t, &ak("secrets.0")).unwrap().unwrap(), lp.peers[0].engine.snapshot(&t, &keys).unwrap().unwrap()];
    for (s, a) in snaps.iter().zip(["secrets.0", "keys.0"]) {
        for r in &rotations {
            assert_eq!(lp.peers[0].engine.covered(s, r, &t, &ak(a)).unwrap(), Some(true), "{a}");
        }
    }
    lp.advance(1_000);
    let x = lp.peers[1].engine.tid();
    let things = BTreeSet::from([t]);
    let scope = osis_perm::DemotionScope { roles: [(x, things.clone())].into(), content: [(x, things)].into() };
    let now = lp.peers[0].engine.now();
    let f = lp.peers[0].engine.frontier(&scope, now).unwrap();
    assert!(f.commits.contains(&rotations[0]), "a rotation replaced inside ROLE_KEEP is listed");
    assert!(!f.commits.contains(&rotations[1]), "the live covered rotation is left out");
    lp.peers[0].engine.demote(&t, &Demotion { holder: px, new: None, presync: PreSync::Synced }).unwrap();
    assert!(!lp.peers[0].engine.roster(&t).contains_key(&px));
    assert_eq!(lp.peers[0].engine.body_valid(&rotations[0], &t, &keys), Some(true));
}

/// Peers 0 (admin, owner) and the people `ps`; `d` of person 0 with person 1 (the vandal) and
/// person 2 writers; person 1's node rotates read and write of `d` boxing person 1 alone
/// (spec/permissions.md §3, Lockout recovery), `times` times. Returns `d`, the epoch before and the
/// vandal's rotation commits.
fn locked_out(lp: &mut LocalPeer, ps: &[Tid], times: usize) -> (Tid, osis_crypto::Epoch, Vec<CommitId>) {
    let d = thing_of(lp, 0, ps[0]);
    for p in &ps[1..] {
        lp.peers[0].engine.grant(&d, p, &edge_of(Role::Write)).unwrap();
    }
    spread(lp);
    let e0 = newest_read(lp, 0, d).unwrap();
    let rv: Vec<CommitId> = (0..times).map(|_| lp.peers[1].engine.rotate_boxing_only(&[d], &[Role::Read, Role::Write], &[ps[1]]).unwrap().unwrap()).collect();
    (d, e0, rv)
}

fn remove(holder: Tid) -> Demotion {
    Demotion { holder, new: None, presync: PreSync::Synced }
}

// spec/permissions.md §3 (lockout recovery), §5.1 (deliberate omission): a writer rotates `d`
// to itself; no other node holds a current secret and a plain removal fails. The admin removes
// it repudiating that rotation: the frontier leaves it out, the rotation goes from the epoch
// before it, the other member reads and writes again and the vandal reads nothing new.
#[test]
fn writer_rotating_to_itself_recovered_spec_perm_3() {
    let (mut lp, ps) = people(3, 571);
    let (d, e0, rv) = locked_out(&mut lp, &ps, 1);
    // labels carry the rotation wrapped under e0: everyone opens it
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 0, d), None, "the admin is locked out");
    assert_eq!(newest_read(&lp, 2, d), None, "the member is locked out");
    assert!(sealed_write(&mut lp, 1, d, "vandal").is_empty(), "nobody reads the vandal's epoch");
    let err = lp.peers[0].engine.demote(&d, &remove(ps[1])).unwrap_err();
    assert!(err.to_string().contains("repudiating"), "{err}");
    let done = lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    let h = lp.peers[0].engine.header(&done.commits[0]).unwrap();
    let f: ct::Frontier = osis_schema::Codec::from_value(h.frontier.as_ref().unwrap()).unwrap();
    assert!(!f.commits.contains(&rv[0]), "the frontier leaves the rotation out");
    let e1 = newest_read(&lp, 0, d).unwrap();
    assert_eq!(e1.n(), e0.n() + 1, "rotated from the epoch before the vandal's");
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 2, d), Some(e1), "the member holds the new epoch");
    assert_eq!(lp.peers[1].engine.role_on(&d), None, "the vandal is out");
    assert!(lp.peers[1].engine.epochs(&d).is_none_or(|e| e.read.reading_secret(&e1).is_none()), "and not boxed");
    assert_eq!(sealed_write(&mut lp, 0, d, "after"), BTreeSet::from([2]));
    assert_eq!(sealed_write(&mut lp, 2, d, "member"), BTreeSet::from([0]));
}

// spec/permissions.md §3, §5.1: a vandal rotating twice (the second from its own epoch): the
// admin received both; repudiating the second makes the first current again, so both are left
// out and the rotation goes from the epoch before them.
#[test]
fn vandal_rotating_twice_both_repudiated_spec_perm_3() {
    let (mut lp, ps) = people(3, 572);
    let (d, e0, rv) = locked_out(&mut lp, &ps, 2);
    spread(&mut lp);
    let done = lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    let h = lp.peers[0].engine.header(&done.commits[0]).unwrap();
    let f: ct::Frontier = osis_schema::Codec::from_value(h.frontier.as_ref().unwrap()).unwrap();
    assert!(rv.iter().all(|c| !f.commits.contains(c)), "both rotations left out");
    let e1 = newest_read(&lp, 0, d).unwrap();
    assert_eq!(e1.n(), e0.n() + 1);
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 2, d), Some(e1));
    assert_eq!(sealed_write(&mut lp, 2, d, "member"), BTreeSet::from([0]));
}

// spec/permissions.md §3, spec/crypto.md §4 (forks): two admins recover concurrently; each
// rotation goes from the epoch before the vandal's, the two fork, and every remaining holder
// reads both.
#[test]
fn concurrent_recoveries_fork_spec_perm_3() {
    let (mut lp, ps) = people(4, 573);
    let (d, e0, _) = locked_out(&mut lp, &ps[..3], 0);
    lp.peers[0].engine.grant(&d, &ps[3], &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    assert_eq!(newest_read(&lp, 3, d), Some(e0));
    lp.peers[1].engine.rotate_boxing_only(&[d], &[Role::Read, Role::Write], &[ps[1]]).unwrap().unwrap();
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 3, d), None, "the second admin is locked out too");
    lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    lp.peers[3].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    let (ea, eb) = (newest_read(&lp, 0, d).unwrap(), newest_read(&lp, 3, d).unwrap());
    assert_ne!(ea, eb);
    assert_eq!((ea.n(), eb.n()), (e0.n() + 1, e0.n() + 1));
    spread_sealed(&mut lp);
    // a later rotation may merge the forks (an admin sealing after both): every remaining
    // holder agrees on the current epochs and holds them all
    let cur = lp.peers[0].engine.epochs(&d).unwrap().read.current();
    assert!(cur.iter().all(|e| e.n() > e0.n()));
    for i in [0, 2, 3] {
        let e = lp.peers[i].engine.epochs(&d).unwrap();
        assert_eq!(e.read.current(), cur, "peer {i}");
        assert!(cur.iter().all(|x| e.read.secret(x).is_some()), "peer {i}: all held");
    }
    assert_eq!(lp.peers[1].engine.role_on(&d), None);
    assert_eq!(sealed_write(&mut lp, 2, d, "member"), BTreeSet::from([0, 3]));
}

// spec/permissions.md §5.1, §3: a repudiation counts only where the demotion audits the
// rotation's author: a vandal that keeps write through its own actor holding write on `d` is
// not demoted by losing its direct edge, so nothing is written.
#[test]
fn repudiation_without_audit_refused_spec_perm_3() {
    let (mut lp, ps) = people(3, 574);
    let d = thing_of(&mut lp, 0, ps[0]);
    let t = thing_of(&mut lp, 1, ps[1]);
    lp.peers[1].engine.give_own_secrets(&t).unwrap();
    spread(&mut lp);
    for p in [ps[1], ps[2], t] {
        lp.peers[0].engine.grant(&d, &p, &edge_of(Role::Write)).unwrap();
    }
    spread(&mut lp);
    lp.peers[1].engine.rotate_boxing_only(&[d], &[Role::Read, Role::Write], &[ps[1]]).unwrap().unwrap();
    spread(&mut lp);
    let (before, epochs) = (lp.peers[0].engine.commit_ids().len(), lp.peers[0].engine.epochs(&d));
    let err = lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap_err();
    assert!(err.to_string().contains("repudiat"), "{err}");
    assert_eq!(lp.peers[0].engine.commit_ids().len(), before, "nothing written");
    assert_eq!(lp.peers[0].engine.epochs(&d), epochs, "nor any rotation invalidated");
    assert!(lp.peers[0].engine.roster(&d).contains_key(&ps[1]), "the vandal stays");
}

// spec/permissions.md §3, spec/crypto.md §4 (sealing a holder actor): a team actor holding
// read on `d` is locked out with the rest; the recovery's rotation seals it again from the
// epoch before the vandal's, so the team's owner reads the new epoch through it.
#[test]
fn recovery_reseals_holder_actor_spec_perm_3() {
    let (mut lp, ps) = people(4, 575);
    let t = thing_of(&mut lp, 3, ps[3]);
    lp.peers[3].engine.give_own_secrets(&t).unwrap();
    spread(&mut lp);
    let (d, e0, _) = locked_out(&mut lp, &ps[..3], 0);
    lp.peers[0].engine.grant(&d, &t, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    assert_eq!(newest_read(&lp, 3, d), Some(e0), "the team's owner reads through it");
    lp.peers[1].engine.rotate_boxing_only(&[d], &[Role::Read, Role::Write], &[ps[1]]).unwrap().unwrap();
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 3, d), None, "the team is locked out too");
    lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    let e1 = newest_read(&lp, 0, d).unwrap();
    assert_eq!(e1.n(), e0.n() + 1);
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 3, d), Some(e1), "sealed to the team again");
    assert_eq!(sealed_write(&mut lp, 0, d, "after"), BTreeSet::from([2, 3]));
}

// spec/permissions.md §3, §5.1; requirements Decentralization (validity a function of the
// held set): a member that receives the recovery before the vandal's rotation, one that held
// the rotation first and the admin end on the same current epochs.
#[test]
fn recovery_alike_in_either_order_spec_perm_3() {
    let (mut lp, ps) = people(4, 576);
    let (d, e0, _) = locked_out(&mut lp, &ps, 0);
    let rv = lp.peers[1].engine.rotate_boxing_only(&[d], &[Role::Read, Role::Write], &[ps[1]]).unwrap().unwrap();
    let pv = lp.peers[1].engine.package(&rv).unwrap().unwrap();
    for i in [0, 2] {
        lp.deliver(i, &pv).unwrap();
    }
    assert_eq!(newest_read(&lp, 2, d), None);
    let done = lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    let pd: Vec<_> = done.commits.iter().map(|c| lp.peers[0].engine.package(c).unwrap().unwrap()).collect();
    for i in [2, 3] {
        for p in &pd {
            lp.deliver(i, p).unwrap();
        }
    }
    lp.deliver(3, &pv).unwrap();
    let cur = lp.peers[0].engine.epochs(&d).unwrap().read.current();
    assert_eq!(cur.len(), 1);
    assert!(cur[0].n() == e0.n() + 1);
    for i in [2, 3] {
        assert_eq!(lp.peers[i].engine.epochs(&d).unwrap().read.current(), cur, "peer {i}");
        assert_eq!(newest_read(&lp, i, d), Some(cur[0]), "peer {i} holds it");
        assert_eq!(lp.peers[i].engine.body_valid(&rv, &d, &ak("secrets.0")), Some(false), "peer {i}");
    }
}

// spec/permissions.md §3, §5.1: the vandal's lockout commit also rotates a thing of its own,
// which the demotion leaves in place; only the part on `d` turns invalid, and the recovery
// does not wait on the other.
#[test]
fn lockout_bundled_with_own_rotation_recovered_spec_perm_3() {
    let (mut lp, ps) = people(3, 577);
    let t = thing_of(&mut lp, 1, ps[1]);
    lp.peers[1].engine.give_own_secrets(&t).unwrap();
    let (d, e0, _) = locked_out(&mut lp, &ps, 0);
    let rv = lp.peers[1].engine.rotate_boxing_only(&[d, t], &[Role::Read, Role::Write], &[ps[1]]).unwrap().unwrap();
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 0, d), None, "the admin is locked out");
    lp.peers[0].engine.demote_repudiating(&d, &remove(ps[1])).unwrap();
    let e1 = newest_read(&lp, 0, d).unwrap();
    assert_eq!(e1.n(), e0.n() + 1);
    assert_eq!(lp.peers[0].engine.body_valid(&rv, &d, &ak("secrets.0")), Some(false));
    assert_eq!(lp.peers[0].engine.body_valid(&rv, &t, &ak("secrets.0")), Some(true), "the vandal's own thing keeps it");
    spread_sealed(&mut lp);
    assert_eq!(newest_read(&lp, 2, d), Some(e1));
    assert_eq!(sealed_write(&mut lp, 2, d, "member"), BTreeSet::from([0]));
}
