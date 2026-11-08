#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A thing's required retention (spec/commits.md §5, spec/permissions.md §5.2, §6): judged at the
//! delta's key on the role timeline, in any arrival order; broken deltas stay held, invalid.

use crate::common;
use crate::net;
use common::*;
use net::Net;
use osis_base::{CommitId, PurgeBy, Role, Tid};
use osis_commit::retention::fixed_retention;
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_node::Mutation;
use osis_schema::core_types::{self as ct, Required, RequiredRules};
use osis_schema::{History, Codec, Retention};
use osis_base::{Value, WallMs};
use std::collections::{BTreeMap, BTreeSet};

fn permanent() -> Retention {
    Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::FOREVER) }
}
fn junk() -> Retention {
    Retention { by: PurgeBy::Nobody, history: Some(History::FOREVER) }
}
const MSGS: &str = "t:msgs.0";

/// Alice (0) is first admin of D, Bob (1) writes, Carol (2) is an admin.
fn setup(seed: u64) -> (LocalPeer, Tid) {
    let mut lp = net(3, seed);
    let mut m = Mutation::new();
    let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(d, &REG, &s("d")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    (lp, d)
}

/// `r` required of each AK named.
fn rules(entries: &[(&str, Retention)]) -> RequiredRules {
    entries.iter().map(|(a, r)| (ak(a), Required::new(*r, None))).collect()
}

/// `r` required of every aspect.
fn all(r: Retention) -> RequiredRules {
    RequiredRules { default: Some(Required::new(r, None)), ..RequiredRules::default() }
}

fn require(lp: &mut LocalPeer, i: usize, d: Tid, r: &RequiredRules) -> CommitId {
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, r).unwrap();
    let c = lp.peers[i].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    c
}

/// A write of `a` with retention `r`, its author's node not stopping it.
fn hostile(lp: &mut LocalPeer, i: usize, d: Tid, a: &str, r: Retention, v: &str) -> CommitId {
    let k = ak(a);
    let mut m = Mutation::new();
    m.set(d, &k, &s(v)).unwrap();
    m.retention(d, &k, r).unwrap();
    let c = lp.peers[i].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    c
}

fn read(p: &mut Peer, d: Tid, a: &str) -> Option<Value> {
    p.engine.get(&d, &ak(a)).unwrap()
}

fn valid(p: &Peer, c: &CommitId, d: &Tid, a: &str) -> bool {
    p.engine.body_valid(c, d, &ak(a)).unwrap()
}

/// Demotes `holder` to write on `d` with a frontier listing `listed`.
fn demote_to_write(lp: &mut LocalPeer, d: Tid, holder: Tid, listed: &[CommitId]) -> CommitId {
    let f = ct::Frontier { commits: listed.iter().copied().collect() };
    let c = set_edge(&mut lp.peers[0].engine, d, holder, Some(edge(Role::Write)), Some(f.to_value()));
    lp.advance(1_000);
    c
}

fn pack(p: &mut Peer, c: &CommitId) -> Package {
    p.engine.package(c).unwrap().unwrap()
}

/// A node holding only the setup, then `order`.
fn fresh(lp: &mut LocalPeer, base: &[Package], order: &[&Package]) -> Peer {
    let now = lp.peers[0].engine.now();
    let mut p = Peer::new(977, now).unwrap();
    for x in base.iter().chain(order.iter().copied()) {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    p
}

fn base_of(lp: &mut LocalPeer) -> Vec<Package> {
    let ids: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    let mut with_ts: Vec<(osis_base::Ts, Package)> = ids.iter().map(|c| (lp.peers[0].engine.header(c).unwrap().ts, pack(&mut lp.peers[0], c))).collect();
    with_ts.sort_by_key(|x| x.0);
    with_ts.into_iter().map(|x| x.1).collect()
}

// spec/commits.md §5: a writer's node fills the required retention over the schema's or untyped
// default, refuses another, and an AK's own entry governs over the default; a delta past that is
// invalid at every node, its author's included, and the same write with the required retention
// or under no entry applies
#[test]
fn delta_with_other_retention_invalid_spec_commits_5() {
    let (mut lp, d) = setup(301);
    let mut r = rules(&[(MSGS, permanent()), ("t:free.0", Retention::default())]);
    require(&mut lp, 0, d, &r);
    lp.sync_all().unwrap();
    // the default governs what has no entry
    r.default = Some(Required::new(junk(), None));
    require(&mut lp, 0, d, &r);
    lp.sync_all().unwrap();
    // filled
    let mut m = Mutation::new();
    m.set(d, &ak(MSGS), &s("filled")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&c).unwrap();
    assert_eq!(h.aspects.iter().find(|a| a.ak.as_str() == MSGS).unwrap().retention, permanent());
    lp.advance(1_000);
    // refused: another retention, an expiry
    let mut m = Mutation::new();
    m.set(d, &ak(MSGS), &s("refused")).unwrap();
    m.retention(d, &ak(MSGS), junk()).unwrap();
    assert!(lp.peers[1].commit(m).is_err());
    let mut m = Mutation::new();
    m.set(d, &ak(MSGS), &s("refused")).unwrap();
    m.expires(d, &ak(MSGS), WallMs(lp.peers[1].engine.now().0 + 60_000)).unwrap();
    assert!(lp.peers[1].commit(m).is_err());
    lp.sync_all().unwrap();
    // past the writer's check
    let bad = hostile(&mut lp, 1, d, MSGS, junk(), "bad");
    // an expiry the rule does not name breaks it too
    let k = ak(MSGS);
    let mut m = Mutation::new();
    m.set(d, &k, &s("expiring")).unwrap();
    m.retention(d, &k, permanent()).unwrap();
    m.expires(d, &k, WallMs(lp.peers[1].engine.now().0 + 3_600_000)).unwrap();
    let exp = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    // its own entry over the default; the default
    let free = hostile(&mut lp, 1, d, "t:free.0", Retention::default(), "free");
    let other = hostile(&mut lp, 1, d, "t:other.0", junk(), "other");
    let off = hostile(&mut lp, 1, d, "t:off.0", permanent(), "off");
    lp.sync_all().unwrap();
    for i in 0..3 {
        let p = &mut lp.peers[i];
        assert!(!valid(p, &bad, &d, MSGS), "{i}");
        assert!(!valid(p, &exp, &d, MSGS), "{i}");
        assert_eq!(read(p, d, MSGS), Some(s("filled")), "{i}");
        assert_eq!(read(p, d, "t:free.0"), Some(s("free")), "{i}: {free:?}");
        assert_eq!(read(p, d, "t:other.0"), Some(s("other")), "{i}: {other:?}");
        assert!(!valid(p, &off, &d, "t:off.0"), "{i}: under the default");
    }
}

// spec/commits.md §5: the default governs every aspect the rule can govern; compaction
// snapshots, fixed-retention aspects and non-durable aspects answer to none
#[test]
fn exempt_deltas_spec_commits_5() {
    let (mut lp, d) = setup(303);
    let bob = lp.peers[1].engine.tid();
    let a = ak("t:kept.0");
    let mut m = Mutation::new();
    m.set(d, &a, &s("before")).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    require(&mut lp, 0, d, &all(permanent()));
    lp.sync_all().unwrap();
    // a compaction snapshot is `writer` whatever is required
    let snap = lp.peers[0].engine.snapshot(&d, &a).unwrap().unwrap();
    lp.advance(1_000);
    assert_eq!(lp.peers[0].engine.header(&snap).unwrap().aspects[0].retention.by, PurgeBy::Writer);
    // role-class: a grant and its boxes
    set_edge(&mut lp.peers[0].engine, d, bob, Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    // created.0: a new thing under D carries it under D's rule? its own thing has no rule
    let eph = ak("t:typing.0~");
    let mut m = Mutation::new();
    m.set(d, &eph, &s("typing")).unwrap();
    lp.peers[0].engine.write(m).unwrap();
    lp.sync_all().unwrap();
    for i in 0..3 {
        let p = &mut lp.peers[i];
        assert!(valid(p, &snap, &d, "t:kept.0"), "{i}: the snapshot");
        assert_eq!(read(p, d, "t:kept.0"), Some(s("before")), "{i}");
        assert_eq!(p.engine.roster(&d).get(&bob).map(|e| e.role), Some(Role::Admin), "{i}");
    }
    assert_eq!(read(&mut lp.peers[0], d, "t:typing.0~"), Some(s("typing")));
    // role-class outside an edge write: a `keys.0` write alone (a deposit-seed refresh)
    let c = *lp.peers[0].engine.refresh_deposit_seed(&d).unwrap().commits.last().unwrap();
    lp.advance(1_000);
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(valid(&lp.peers[i], &c, &d, "keys.0"), "{i}");
        assert!(lp.peers[i].engine.body_not_dropped(&c, &d, &ak("keys.0")), "{i}");
    }
    // `created.0` of a thing whose first admin's rule says otherwise: it has its own fixed retention
    let mut m = Mutation::new();
    let child = lp.peers[0].engine.new_thing(&mut m, d);
    m.set(child, &REG, &s("child")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.body_valid(&c, &child, &ak("created.0")), Some(true));
}

// spec/commits.md §5: `required.0^` has `created.0`'s fixed retention, is never snapshotted or
// undone, and is written whole
#[test]
fn setting_itself_fixed_spec_commits_5() {
    assert_eq!(fixed_retention("required.0^"), fixed_retention("created.0"));
    let (mut lp, d) = setup(305);
    let c = require(&mut lp, 0, d, &all(permanent()));
    let h = lp.peers[0].engine.header(&c).unwrap();
    assert_eq!(Some(h.aspects.iter().find(|a| a.ak.as_str() == "required.0^").unwrap().retention), fixed_retention("created.0"));
    let a = ak("required.0^");
    assert!(lp.peers[0].engine.snapshot(&d, &a).is_err(), "never compacted");
    // a partial write would say something else alone
    let mut m = Mutation::new();
    m.op(d, &ct::REQUIRED, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s("t:x"))], op: osis_crdt::Op::Set(Required::new(permanent(), None).to_value()) }).unwrap();
    assert!(lp.peers[0].commit(m).is_err(), "a partial write refused");
    // `set` writes the whole value, so the delta alone reads it
    let c2 = require(&mut lp, 0, d, &rules(&[("t:x.0", permanent()), ("t:y.0", Retention::default())]));
    let sets = lp.peers[0].engine.core.ix.required.get(&d).unwrap();
    assert_eq!(sets.iter().find(|x| x.0.commit == c2).unwrap().1.rules.len(), 2);
    // an undo of it writes nothing on it
    let mut m = Mutation::new();
    m.undo(c2);
    if let Ok(Some(u)) = lp.peers[0].commit(m) {
        let h = lp.peers[0].engine.header(&u).unwrap();
        assert!(h.aspects.iter().all(|a| a.ak.as_str() != "required.0^"));
    }
}

// spec/permissions.md §5.2: a writer's `required.0^` is no setting: it binds nothing
#[test]
fn writers_setting_binds_nothing_spec_perm_5_2() {
    let (mut lp, d) = setup(307);
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &all(permanent())).unwrap();
    assert!(matches!(lp.peers[1].commit(m), Err(osis_node::Error::Permission { .. })));
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &all(permanent())).unwrap();
    lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    hostile(&mut lp, 2, d, MSGS, junk(), "fine");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(read(&mut lp.peers[i], d, MSGS), Some(s("fine")), "{i}");
    }
}

// spec/permissions.md §5.2: a delta is judged by the setting in force at its key whichever
// arrives first: a change arriving after the delta un-merges it; a write before the change (a
// backdated one too) stands; a change after it re-judges nothing earlier
#[test]
fn judged_at_key_any_order_spec_perm_5_2() {
    let (mut lp, d) = setup(311);
    let base = base_of(&mut lp);
    let before = hostile(&mut lp, 1, d, MSGS, junk(), "before");
    // Alice's clock runs ahead, so a write Bob makes after her change is ordered before it: its
    // key is what counts
    let t = lp.peers[0].engine.now();
    lp.peers[0].clock.set(WallMs(t.0 + 20_000));
    let s1 = require(&mut lp, 0, d, &all(permanent()));
    let back = hostile(&mut lp, 1, d, "t:back.0", junk(), "back");
    lp.advance(30_000);
    let broke = hostile(&mut lp, 1, d, "t:after.0", junk(), "after");
    let good = hostile(&mut lp, 1, d, "t:good.0", permanent(), "good");
    let packs: Vec<Package> = [before, s1, back, broke, good].iter().map(|c| pack(&mut lp.peers[if *c == s1 { 0 } else { 1 }], c)).collect::<Vec<_>>();
    let mut orders: Vec<Vec<usize>> = vec![vec![0, 1, 2, 3, 4], vec![4, 3, 2, 1, 0], vec![3, 0, 4, 1, 2], vec![2, 3, 1, 4, 0]];
    orders.push(vec![1, 3, 0, 2, 4]);
    let mut seen = BTreeSet::new();
    for o in orders {
        let order: Vec<&Package> = o.iter().map(|i| &packs[*i]).collect();
        let mut p = fresh(&mut lp, &base, &order);
        assert_eq!(read(&mut p, d, MSGS), Some(s("before")), "{o:?}");
        assert_eq!(read(&mut p, d, "t:back.0"), Some(s("back")), "{o:?}");
        assert_eq!(read(&mut p, d, "t:after.0"), None, "{o:?}");
        assert_eq!(read(&mut p, d, "t:good.0"), Some(s("good")), "{o:?}");
        seen.insert(valid(&p, &broke, &d, "t:after.0"));
    }
    assert_eq!(seen, BTreeSet::from([false]));
}

// A later change judges only later keys: raising to a stricter rule leaves earlier deltas; a
// rule cleared frees later ones (spec/commits.md §5: immutable retention, nothing rewritten)
#[test]
fn change_judges_later_keys_only_spec_commits_5() {
    let (mut lp, d) = setup(313);
    require(&mut lp, 0, d, &all(Retention::default()));
    let a = hostile(&mut lp, 1, d, "t:a.0", Retention::default(), "a");
    let bad = hostile(&mut lp, 1, d, "t:bad.0", junk(), "bad");
    require(&mut lp, 2, d, &all(permanent()));
    let b = hostile(&mut lp, 1, d, "t:b.0", Retention::default(), "b");
    require(&mut lp, 0, d, &RequiredRules::new());
    let c = hostile(&mut lp, 1, d, "t:c.0", junk(), "c");
    lp.sync_all().unwrap();
    for i in 0..3 {
        let p = &lp.peers[i];
        assert!(valid(p, &a, &d, "t:a.0") && valid(p, &c, &d, "t:c.0"), "{i}");
        assert!(!valid(p, &bad, &d, "t:bad.0") && !valid(p, &b, &d, "t:b.0"), "{i}");
    }
}

// spec/permissions.md §5.1, §5.2, §6: a demoted admin's change the frontier does not list falls, and
// what it invalidated comes back (in an order where it went while invalid, once fetched again), in
// either order; one the frontier lists stands
#[test]
fn demoted_admins_change_falls_unmerge_spec_perm_5_2() {
    let (mut lp, d) = setup(317);
    let carol = lp.peers[2].engine.tid();
    let base = base_of(&mut lp);
    // received by Alice: stands
    let listed = require(&mut lp, 2, d, &rules(&[("t:listed.0", permanent())]));
    sync(&mut lp, 2, 0);
    // Alice has not received this one
    let unseen = require(&mut lp, 2, d, &rules(&[("t:listed.0", permanent()), ("t:unseen.0", permanent())]));
    let under_unseen = hostile(&mut lp, 1, d, "t:unseen.0", junk(), "kept");
    let under_listed = hostile(&mut lp, 1, d, "t:listed.0", junk(), "gone?");
    let demote = demote_to_write(&mut lp, d, carol, &[listed]);
    // the newest valid setting is `listed` once `unseen` falls, so `t:listed` stays required
    let packs: Vec<Package> = [listed, unseen, under_unseen, under_listed, demote].iter().map(|c| {
        let from = if *c == listed || *c == unseen { 2 } else if *c == demote { 0 } else { 1 };
        pack(&mut lp.peers[from], c)
    }).collect();
    for o in [vec![0usize, 1, 2, 3, 4], vec![4, 3, 2, 1, 0], vec![2, 3, 0, 4, 1], vec![1, 4, 0, 3, 2]] {
        let order: Vec<&Package> = o.iter().map(|i| &packs[*i]).collect();
        let mut p = fresh(&mut lp, &base, &order);
        // what went while invalid and turned valid is missing: node-sync fetches it again
        for pk in &order {
            let _ = p.engine.ingest(&pk.bytes, pk.blobs.clone());
        }
        assert!(!valid(&p, &unseen, &d, "required.0^"), "{o:?}: the unlisted change falls");
        assert!(valid(&p, &listed, &d, "required.0^"), "{o:?}: the listed one stands");
        assert_eq!(read(&mut p, d, "t:unseen.0"), Some(s("kept")), "{o:?}: back with the fallen rule");
        assert_eq!(read(&mut p, d, "t:listed.0"), None, "{o:?}: still broken under the listed one");
    }
    // while the change stands the write is out (gone), then missing on the demotion's arrival and
    // back once fetched
    let order = [&packs[1], &packs[0], &packs[2]];
    let mut p = fresh(&mut lp, &base, &order);
    assert_eq!(read(&mut p, d, "t:unseen.0"), None);
    p.engine.ingest(&packs[4].bytes, packs[4].blobs.clone()).unwrap();
    assert_eq!(read(&mut p, d, "t:unseen.0"), None);
    p.engine.ingest(&packs[2].bytes, packs[2].blobs.clone()).unwrap();
    assert_eq!(read(&mut p, d, "t:unseen.0"), Some(s("kept")));
}

// spec/permissions.md §6, spec/commits.md §5: a `required.0^` setting by a writer, not an admin,
// is invalid and goes at every node but its author's: it binds nothing and is not kept
#[test]
fn junk_setting_goes_spec_permissions_6() {
    let (mut lp, d) = setup(333);
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &all(permanent())).unwrap();
    let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in [0, 2] {
        assert!(!valid(&lp.peers[i], &c, &d, "required.0^"), "peer {i}");
        assert!(!lp.peers[i].engine.body_not_dropped(&c, &d, &ak("required.0^")), "peer {i}: gone");
        assert!(lp.peers[i].engine.core.ix.required.get(&d).is_none(), "peer {i}: no setting kept");
    }
}

// The whole judgment survives an open and a rebuild (`ix.required` persisted and re-derived)
#[test]
fn required_after_reopen_spec_commits_5() {
    let (mut lp, d) = setup(319);
    let c = require(&mut lp, 0, d, &all(permanent()));
    let bad = hostile(&mut lp, 1, d, MSGS, junk(), "bad");
    lp.sync_all().unwrap();
    let want = format!("{:?}", lp.peers[2].engine.core.ix.required.get(&d));
    assert!(want.contains(&format!("{:?}", c)) || !want.is_empty());
    lp.peers[2].restart(321).unwrap();
    assert_eq!(format!("{:?}", lp.peers[2].engine.core.ix.required.get(&d)), want);
    assert!(!valid(&lp.peers[2], &bad, &d, MSGS));
    lp.peers[2].engine.rebuild_index().unwrap();
    assert_eq!(format!("{:?}", lp.peers[2].engine.core.ix.required.get(&d)), want);
    assert!(!valid(&lp.peers[2], &bad, &d, MSGS));
}

// spec/commits.md §5 Required retention, spec/permissions.md §6: a delta breaking the setting in
// force at its key is invalid and goes, received before a (backdated) change or after it; when the
// setting falls it is missing and reads again once fetched from a holder (its author)
#[test]
fn broken_bodies_go_and_return_when_the_setting_falls_spec_commits_5() {
    let (mut lp, d) = setup(323);
    let carol = lp.peers[2].engine.tid();
    // Bob's clock runs ahead, so Carol's change, made after his write reached Alice and stamped
    // below it, stands in for a backdated one: `old` breaks it, and Alice holds it already
    let t = lp.peers[1].engine.now();
    lp.peers[1].clock.set(WallMs(t.0 + 20_000));
    let old = hostile(&mut lp, 1, d, "t:old.0", junk(), "old");
    sync(&mut lp, 1, 0);
    lp.advance(1_000);
    require(&mut lp, 2, d, &all(permanent()));
    lp.sync_all().unwrap();
    lp.advance(30_000);
    let bad = hostile(&mut lp, 1, d, "t:bad.0", junk(), "bad");
    lp.sync_all().unwrap();
    for (c, k) in [(old, "t:old.0"), (bad, "t:bad.0")] {
        assert!(!valid(&lp.peers[0], &c, &d, k), "{k}: invalid under the setting");
        assert!(!lp.peers[0].engine.body_not_dropped(&c, &d, &ak(k)), "{k}: dropped");
        assert_eq!(read(&mut lp.peers[0], d, k), None);
    }
    demote_to_write(&mut lp, d, carol, &[]);
    assert_eq!(read(&mut lp.peers[0], d, "t:bad.0"), None, "missing until fetched");
    sync(&mut lp, 1, 0);
    assert_eq!(read(&mut lp.peers[0], d, "t:bad.0"), Some(s("bad")));
    assert_eq!(read(&mut lp.peers[0], d, "t:old.0"), Some(s("old")));
}

// spec/crdt.md §4.6, spec/commits.md §5: Bob, not holding Carol's setting, inserts "x" into a text,
// breaking it; Alice, not holding it either, inserts "y" after "x" with the required retention.
// Once all hold the setting "x" is invalid and goes but at its author; "y", anchored at its
// element, reads at every node (spec/crdt.md §6.1 virtual anchor).
#[test]
fn broken_element_anchors_valid_insert_spec_crdt_4_6() {
    let (mut lp, d) = setup(325);
    let text = ak("t:text.0");
    require(&mut lp, 2, d, &rules(&[("t:text.0", permanent())]));
    let ins = |lp: &mut LocalPeer, i: usize, at: usize, v: &str, r: Option<Retention>| {
        let mut m = Mutation::new();
        m.op(d, &TEXT, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Insert { at, items: vec![s(v)] } }).unwrap();
        if let Some(r) = r {
            m.retention(d, &text, r).unwrap();
        }
        let c = lp.peers[i].commit(m).unwrap().unwrap();
        lp.advance(1_000);
        c
    };
    let x = ins(&mut lp, 1, 0, "x", None);
    sync(&mut lp, 1, 0);
    assert_eq!(read(&mut lp.peers[0], d, "t:text.0"), Some(s("x")));
    let y = ins(&mut lp, 0, 1, "y", Some(permanent()));
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert!(!valid(&lp.peers[i], &x, &d, "t:text.0") && valid(&lp.peers[i], &y, &d, "t:text.0"), "peer {i}");
        assert_eq!(lp.peers[i].engine.body_not_dropped(&x, &d, &text), i == 1, "peer {i}: held only by its author");
        assert_eq!(read(&mut lp.peers[i], d, "t:text.0"), Some(s("y")), "peer {i}");
    }
}

// spec/commits.md §5, spec/permissions.md §6: a junk `nobody` body under a required retention
// reads nothing at every node and goes but at its author
#[test]
fn junk_reads_nothing_and_goes_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.run();
    let mut m = Mutation::new();
    m.set(t, &ct::REQUIRED, &all(permanent())).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.advance(1_000);
    // an ephemeral write carries no retention: it answers to no rule
    net.eph_write(a, t, &ak("t:typing.0~"), s("typing"));
    net.run();
    assert_eq!(net.eph_read(b, t, "t:typing.0~"), Some(s("typing")));
    let k = ak("t:junk.0");
    let mut m = Mutation::new();
    m.set(t, &k, &s("junk")).unwrap();
    m.retention(t, &k, junk()).unwrap();
    let c = net.engine(b).commit_hostile(m).unwrap().unwrap();
    net.run();
    net.advance(10_000);
    net.run();
    let k = ak("t:junk.0");
    for n in [a, b] {
        assert_eq!(net.engine(n).body_not_dropped(&c, &t, &k), n == b, "{n}: held only by its author");
        assert_eq!(net.engine(n).get(&t, &k).unwrap(), None, "{n}");
    }
}

// spec/permissions.md §5.2 (Acting): a setting by a node acting for another actor falls when its
// author loses write on that actor, and every later delta on the thing is judged again, though
// the thing's own timeline did not change
#[test]
fn setting_falls_through_acting_spec_perm_5_2() {
    let (mut lp, d) = setup(331);
    let (alice, carol) = (lp.peers[0].engine.tid(), lp.peers[2].engine.tid());
    let mut m = Mutation::new();
    let p = lp.peers[0].engine.new_thing(&mut m, alice);
    m.set(p, &REG, &s("p")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, p, carol, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.act_as(p);
    m.set(d, &ct::REQUIRED, &all(permanent())).unwrap();
    let setting = lp.peers[2].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let bad = hostile(&mut lp, 1, d, MSGS, junk(), "junk");
    lp.sync_all().unwrap();
    assert!(!valid(&lp.peers[1], &bad, &d, MSGS), "broken while the setting stands");
    // Alice has not listed it: Carol's standing on P goes, and the commit acting for P with it
    set_edge(&mut lp.peers[0].engine, p, carol, None, Some(ct::Frontier::default().to_value()));
    lp.sync_all().unwrap();
    assert!(!valid(&lp.peers[1], &setting, &d, "required.0^"));
    assert!(valid(&lp.peers[1], &bad, &d, MSGS), "back with the fallen setting");
    assert_eq!(read(&mut lp.peers[1], d, MSGS), Some(s("junk")));
}

// spec/permissions.md §5.2: a `required.0^` delta arriving as a late part of a commit on two things
// binds as one arriving whole: a part on another thing applied first, a part on this one later
#[test]
fn setting_as_late_part_spec_perm_5_2() {
    let (mut lp, d) = setup(341);
    let alice = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let other = lp.peers[0].engine.new_thing(&mut m, alice);
    m.set(other, &REG, &s("other")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let base = base_of(&mut lp);
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &all(permanent())).unwrap();
    m.set(other, &REG, &s("beside")).unwrap();
    let setting = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let whole = pack(&mut lp.peers[0], &setting);
    let bad = hostile(&mut lp, 1, d, MSGS, junk(), "junk");
    let broke = pack(&mut lp.peers[1], &bad);
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let ai = part.header.aspects.iter().position(|a| a.ak.as_str() == "required.0^").unwrap();
    part.parts.retain(|x| x.ai != ai);
    let mut p = fresh(&mut lp, &base, &[]);
    assert!(matches!(p.engine.ingest(&part.encode(), whole.blobs.clone()).unwrap(), osis_node::Ingested::Applied(_)), "applied without the part");
    p.engine.ingest(&broke.bytes, broke.blobs.clone()).unwrap();
    assert_eq!(read(&mut p, d, MSGS), Some(s("junk")), "no setting held yet");
    p.engine.ingest(&whole.bytes, whole.blobs.clone()).unwrap();
    assert_eq!(read(&mut p, d, MSGS), None, "bound once the part is held");
    assert!(!valid(&p, &bad, &d, MSGS));
}

// Alice (0) is first admin of the group and of D's first admin, Bob (1) writes, Carol (2) is an admin, Dan (3) reads.
fn on_host(net: &mut Net, host: usize) -> (usize, usize, usize, usize, Tid, Tid) {
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let d = net.node(4, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Admin), (d, Role::Read)], &[host]);
    let t = net.item(a, g, g, "v1");
    net.run();
    (a, b, c, d, g, t)
}

fn settle(net: &mut Net) {
    net.run();
    net.advance(10_000);
    net.run();
}

// spec/permissions.md §5.2: a `required.0^` delta by a node that never held admin binds nothing,
// whatever its size, and stays so once its writer turns admin (stamped before that)
#[test]
fn writers_big_setting_binds_nothing_spec_perm_5_2() {
    let (mut lp, d) = setup(401);
    let big: RequiredRules = (0..2_000).map(|i| (ak(&format!("t:n{i:0>40}.0")), Required::new(permanent(), None))).chain([(ak("t:x.0"), Required::new(permanent(), None))]).collect();
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &big).unwrap();
    let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let k = "t:x.0";
    let w = hostile(&mut lp, 1, d, k, Retention::default(), "w");
    lp.sync_all().unwrap();
    assert!(!valid(&lp.peers[0], &c, &d, "required.0^"));
    assert!(valid(&lp.peers[0], &w, &d, k), "bound by nothing");
    let bob = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, d, bob, Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    lp.sync_all().unwrap();
    assert!(!valid(&lp.peers[0], &c, &d, "required.0^"));
    assert!(valid(&lp.peers[0], &w, &d, k));
}

// spec/commits.md §5: past `MAX_REQUIRED_ENTRIES` or with a key that is no AK a delta requires
// nothing, and a writer refuses it
#[test]
fn setting_over_its_bounds_requires_nothing_spec_commits_5() {
    let n = osis_base::format::MAX_REQUIRED_ENTRIES;
    let many: RequiredRules = (0..=n).map(|i| (ak(&format!("t:n{i}.0")), Required::new(permanent(), None))).collect();
    let fits: RequiredRules = (0..n).map(|i| (ak(&format!("t:n{i}.0")), Required::new(permanent(), None))).collect();
    assert!(ct::required_fits(&fits) && !ct::required_fits(&many));
    // what `all(permanent())` writes, its one entry keyed by text that is no AK
    let Value::Map(mut no_ak) = all(permanent()).to_value() else { panic!() };
    no_ak.insert(Value::Int(0), Value::Map([(s("t:n0"), Required::new(permanent(), None).to_value())].into_iter().collect()));
    // `required.0^` typed by the core schema, its value raw: fits the core type, as a hostile
    // writer's must to be applied anywhere
    let raw = osis_schema::Aspect::<Value>::new("required.0^", &osis_schema::CORE);
    for over in [many.to_value(), Value::Map(no_ak)] {
        assert!(RequiredRules::from_value(&over).is_ok_and(|r| !ct::required_fits(&r)) || RequiredRules::from_value(&over).is_err());
        let (mut lp, d) = setup(407);
        let mut m = Mutation::new();
        m.set(d, &raw, &over).unwrap();
        assert!(lp.peers[0].commit(m).is_err(), "refused");
        let mut m = Mutation::new();
        m.set(d, &raw, &over).unwrap();
        lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
        lp.advance(1_000);
        let w = hostile(&mut lp, 1, d, "t:n0.0", junk(), "fine");
        lp.sync_all().unwrap();
        // the setting is held and read, so it is the bounds that make it require nothing
        assert_eq!(read(&mut lp.peers[2], d, "required.0^"), Some(over.clone()));
        for i in 0..3 {
            assert!(valid(&lp.peers[i], &w, &d, "t:n0.0"), "{i}");
        }
    }
}

// spec/commits.md §7, §5: an undo of a write valid before a change writes under the change
#[test]
fn undo_after_change_fills_spec_commits_5() {
    let (mut lp, d) = setup(403);
    let mut m = Mutation::new();
    m.set(d, &ak("t:a.0"), &s("one")).unwrap();
    let w = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1000);
    require(&mut lp, 0, d, &all(permanent()));
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.undo(w);
    let u = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.header(&u).unwrap().aspects[0].retention, permanent());
    assert!(valid(&lp.peers[0], &u, &d, "t:a.0"));
}

// spec/commits.md §5, spec/permissions.md §6: a setting with a key below a body already written.
// The body is invalid and goes but at its author, a new node's too; all read alike. When the
// setting falls everyone reads it again, the body fetched from the host, which kept it.
#[test]
fn setting_below_a_body_goes_and_comes_back_spec_perm_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b, c, d, g, t) = on_host(&mut net, host);
    net.set_online(d, false);
    net.set_online(c, false);
    let mut m = Mutation::new();
    m.set(t, &ct::REQUIRED, &all(permanent())).unwrap();
    let st = net.engine(c).commit(m).unwrap().unwrap();
    net.advance(5_000);
    let k = ak("t:msg.0");
    let mut m = Mutation::new();
    m.set(t, &k, &s("msg")).unwrap();
    m.retention(t, &k, junk()).unwrap();
    let body = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.engine(a).get(&t, &k).unwrap(), Some(s("msg")));
    net.set_online(c, true);
    settle(&mut net);
    for n in [a, b, c] {
        assert_eq!(net.engine(n).body_valid(&body, &t, &k), Some(false), "{n}");
        assert_eq!(net.engine(n).get(&t, &k).unwrap(), None, "{n}");
    }
    net.set_online(d, true);
    settle(&mut net);
    for n in [a, b, c, d] {
        assert_eq!(net.engine(n).body_not_dropped(&body, &t, &k), n == b, "{n}: held only by its author");
    }
    assert_eq!(net.engine(d).get(&t, &k).unwrap(), None);
    // its author away, the host is the only holder
    net.set_online(b, false);
    // Alice takes Carol's admin, no frontier: the setting falls
    let carol = net.tid(c);
    {
        use osis_crdt::{Op, PathOp, PathSeg};
        let mut m = Mutation::new();
        m.op(g, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(carol)) }).unwrap();
        m.op(g, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(carol))], op: Op::Set(edge(Role::Write).to_value()) }).unwrap();
        m.frontier(ct::Frontier::default().to_value());
        net.engine(a).commit_hostile(m).unwrap().unwrap();
    }
    settle(&mut net);
    settle(&mut net);
    assert_eq!(net.engine(a).body_valid(&st, &t, &ak("required.0^")), Some(false));
    for n in [a, c, d] {
        assert_eq!(net.engine(n).get(&t, &k).unwrap(), Some(s("msg")), "{n}");
    }
}

// spec/commits.md §5: a writer that has not seen the change: a commit's delta breaking a setting
// falls alone, in one blob with the others or not, and goes but at its author; the others stand
// on this thing and another, at a new node too. When the setting falls the delta reads again,
// fetched from the host.
#[test]
fn broken_delta_falls_alone_spec_commits_5() {
    for same_class in [true, false] {
        let mut net = Net::new();
        let host = net.add_host();
        let (a, b, c, d, g, t) = on_host(&mut net, host);
        let u = net.item(a, g, g, "u");
        net.run();
        net.set_online(d, false);
        net.set_online(b, false);
        let setter = if same_class { c } else { a };
        let mut m = Mutation::new();
        m.set(t, &ct::REQUIRED, &rules(&[("t:bad.0", permanent())])).unwrap();
        let st = net.engine(setter).commit(m).unwrap().unwrap();
        settle(&mut net);
        let (bad, good) = (ak("t:bad.0"), ak("t:good.0"));
        // a `nobody` delta shares a commit only with `nobody` ones (spec/commits.md §5): in
        // another blob, the broken delta is `writer`
        let mut m = Mutation::new();
        m.set(t, &bad, &s("bad")).unwrap();
        m.set(t, &good, &s("good")).unwrap();
        m.set(u, &good, &s("other")).unwrap();
        if same_class {
            m.retention(t, &bad, junk()).unwrap();
            m.retention(t, &good, junk()).unwrap();
            m.retention(u, &good, junk()).unwrap();
        } else {
            m.retention(t, &bad, Retention { by: PurgeBy::Writer, ..Retention::default() }).unwrap();
        }
        let cm = net.engine(b).commit(m).unwrap().unwrap();
        net.advance(1_000);
        net.set_online(b, true);
        settle(&mut net);
        settle(&mut net);
        net.set_online(d, true);
        settle(&mut net);
        settle(&mut net);
        for n in [a, b, c, d] {
            assert_eq!(net.engine(n).get(&t, &bad).unwrap(), None, "{same_class} {n}");
            assert_eq!(net.engine(n).get(&t, &good).unwrap(), Some(s("good")), "{same_class} {n}");
            assert_eq!(net.engine(n).get(&u, &good).unwrap(), Some(s("other")), "{same_class} {n}");
        }
        for n in [a, b, d] {
            assert_eq!(net.engine(n).body_not_dropped(&cm, &t, &bad), n == b, "{same_class} {n}: held only by its author");
        }
        if same_class {
            // the setting falls with Carol's admin; everyone reads it
            let carol = net.tid(c);
            use osis_crdt::{Op, PathOp, PathSeg};
            let mut m = Mutation::new();
            m.op(g, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(carol)) }).unwrap();
            m.op(g, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(carol))], op: Op::Set(edge(Role::Write).to_value()) }).unwrap();
            m.frontier(ct::Frontier::default().to_value());
            net.engine(a).commit_hostile(m).unwrap().unwrap();
            settle(&mut net);
            settle(&mut net);
            assert_eq!(net.engine(a).body_valid(&st, &t, &ak("required.0^")), Some(false));
            for n in [a, b, c, d] {
                assert_eq!(net.engine(n).get(&t, &good).unwrap(), Some(s("good")), "{n}");
                assert_eq!(net.engine(n).get(&t, &bad).unwrap(), Some(s("bad")), "{n}");
                assert_eq!(net.engine(n).get(&u, &good).unwrap(), Some(s("other")), "{n}");
            }
        }
    }
}

// spec/commits.md §4: a broken delta a node never gets holds nothing back: a new node reads the
// commit's other delta once it holds it, in any order of the setting, the part and the setting's
// fall, and the broken one once it comes
#[test]
fn missing_broken_part_holds_nothing_back_spec_commits_4() {
    let (mut lp, d) = setup(411);
    let carol = lp.peers[2].engine.tid();
    let base = base_of(&mut lp);
    let (bad, good) = (ak("t:bad.0"), ak("t:good.0"));
    let s1 = require(&mut lp, 2, d, &rules(&[("t:bad.0", permanent())]));
    let mut m = Mutation::new();
    m.set(d, &bad, &s("bad")).unwrap();
    m.retention(d, &bad, junk()).unwrap();
    m.set(d, &good, &s("good")).unwrap();
    // `nobody` beside `nobody` only (spec/commits.md §5)
    m.retention(d, &good, junk()).unwrap();
    let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let setting = pack(&mut lp.peers[2], &s1);
    let whole = pack(&mut lp.peers[1], &c);
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let ai = part.header.aspects.iter().position(|a| a.ak == bad).unwrap();
    part.parts.retain(|x| x.ai != ai);
    let part = part.encode();
    let dem = demote_to_write(&mut lp, d, carol, &[]);
    let demotion = pack(&mut lp.peers[0], &dem);
    let items = [(setting.bytes.clone(), setting.blobs.clone()), (part, whole.blobs.clone()), (demotion.bytes.clone(), demotion.blobs.clone())];
    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let mut p = fresh(&mut lp, &base, &[]);
        p.engine.set_syncing(d, true).unwrap();
        for (n, i) in order.iter().enumerate() {
            let (x, b) = &items[*i];
            p.engine.ingest(x, b.clone()).unwrap();
            let done = &order[..=n];
            let want = done.contains(&1).then(|| s("good"));
            assert_eq!(read(&mut p, d, "t:good.0"), want, "{order:?} after {n}");
        }
        assert_eq!(read(&mut p, d, "t:bad.0"), None, "{order:?}");
        p.engine.ingest(&whole.bytes, whole.blobs.clone()).unwrap();
        assert_eq!(read(&mut p, d, "t:good.0"), Some(s("good")));
        assert_eq!(read(&mut p, d, "t:bad.0"), Some(s("bad")), "the setting fell");
    }
}

// spec/commits.md §5: a commit's delta breaking a setting of one thing says nothing of its delta on
// another. A member of the other thing alone never holds that setting: all its members read alike
// and its bodies stay, whatever an admin of the first thing does.
#[test]
fn commit_across_things_reads_alike_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let (oc, od, b, x) = (net.node(1, &[host]), net.node(2, &[host]), net.node(3, &[host]), net.node(4, &[host]));
    let gc = net.group(oc, &[(b, Role::Write), (od, Role::Read)], &[host]);
    let gd = net.group_seeded(od, &[(b, Role::Write), (x, Role::Read)], vec![net.address(host)], 7);
    let tc = net.item(oc, gc, gc, "c");
    let td = net.item(od, gd, gd, "d");
    net.run();
    net.set_online(b, false);
    let mut m = Mutation::new();
    m.set(tc, &ct::REQUIRED, &all(permanent())).unwrap();
    net.engine(oc).commit(m).unwrap().unwrap();
    settle(&mut net);
    let (msg, card) = (ak("t:msg.0"), ak("t:card.0"));
    let mut m = Mutation::new();
    m.set(tc, &msg, &s("msg")).unwrap();
    m.set(td, &card, &s("card")).unwrap();
    let k = net.engine(b).commit(m).unwrap().unwrap();
    net.advance(1_000);
    net.set_online(b, true);
    settle(&mut net);
    settle(&mut net);
    for n in [od, x, b] {
        assert_eq!(net.engine(n).get(&td, &card).unwrap(), Some(s("card")), "node {n}");
        assert!(net.engine(n).body_not_dropped(&k, &td, &card), "node {n}");
    }
    assert_eq!(net.engine(oc).get(&tc, &msg).unwrap(), None);
}

// A writer that had not seen a setting: its write falls when the setting arrives, and its node
// says so; another's does not
#[test]
fn stale_writer_is_told_spec_commits_5() {
    let (mut lp, d) = setup(431);
    require(&mut lp, 2, d, &all(permanent()));
    let mut m = Mutation::new();
    m.set(d, &ak(MSGS), &s("late")).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    for i in 0..3 {
        lp.peers[i].drain_events();
    }
    lp.sync_all().unwrap();
    assert_eq!(read(&mut lp.peers[1], d, MSGS), None);
    let told = |p: &mut Peer| p.drain_events().iter().any(|e| matches!(e, osis_node::Event::Diagnostic(x) if x.kind == osis_node::DiagnosticKind::OwnWriteInvalid && x.commit == Some(c) && x.tids == [d]));
    assert!(told(&mut lp.peers[1]), "its author's node");
    assert!(!told(&mut lp.peers[0]));
}

// spec/crdt.md §5.7: a reopen forgets a deleted text element's char; the delete falling brings it
// back from its creation's body, and a late part of an invalid body joins without a false alarm
#[test]
fn delete_falls_after_reopen_reads_text_spec_crdt_5_7() {
    for reopen in [false, true] {
        let (mut lp, d) = setup(433);
        let carol = lp.peers[2].engine.tid();
        let mut m = Mutation::new();
        m.set(d, &TEXT, &s("abc")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        lp.advance(1_000);
        let mut m = Mutation::new();
        m.op(d, &TEXT, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Delete { at: 1, len: 1 } }).unwrap();
        lp.peers[2].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        lp.advance(1_000);
        assert_eq!(read(&mut lp.peers[0], d, "t:text.0"), Some(s("ac")));
        if reopen {
            lp.peers[0].engine.reload().unwrap();
            assert_eq!(read(&mut lp.peers[0], d, "t:text.0"), Some(s("ac")));
        }
        set_edge(&mut lp.peers[0].engine, d, carol, Some(edge(Role::Read)), Some(ct::Frontier::default().to_value()));
        assert_eq!(read(&mut lp.peers[0], d, "t:text.0"), Some(s("abc")), "reopen {reopen}");
    }
}

// spec/permissions.md §5.2: a setting signed by one not a possible admin binds nothing, nor does
// naming an admin as actor make it; a commit beside it shows what is held, the rest when it comes.
#[test]
fn writers_setting_as_admin_binds_nothing_spec_perm_5_2() {
    let (mut lp, d) = setup(433);
    let alice = lp.peers[0].engine.tid();
    let base = base_of(&mut lp);
    let (bad, good) = (ak("t:bad.0"), ak("t:good.0"));
    let plain = rules(&[("t:bad.0", permanent())]);
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &plain).unwrap();
    let s1 = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.act_as(alice);
    m.set(d, &ct::REQUIRED, &plain).unwrap();
    let s2 = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &bad, &s("bad")).unwrap();
    m.set(d, &good, &s("good")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(1_000);
    let settings = [pack(&mut lp.peers[1], &s1), pack(&mut lp.peers[1], &s2)];
    let whole = pack(&mut lp.peers[0], &c);
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let ai = part.header.aspects.iter().position(|a| a.ak == bad).unwrap();
    part.parts.retain(|x| x.ai != ai);
    let part = part.encode();
    let mut p = fresh(&mut lp, &base, &[]);
    p.engine.set_syncing(d, true).unwrap();
    for x in &settings {
        p.engine.ingest(&x.bytes, x.blobs.clone()).unwrap();
    }
    p.engine.ingest(&part, whole.blobs.clone()).unwrap();
    assert_eq!(read(&mut p, d, "t:good.0"), Some(s("good")), "waits for nothing the host hides");
    assert!(!valid(&p, &s1, &d, "required.0^") && !valid(&p, &s2, &d, "required.0^"));
    p.engine.ingest(&whole.bytes, whole.blobs.clone()).unwrap();
    assert_eq!(read(&mut p, d, "t:good.0"), Some(s("good")));
    assert_eq!(read(&mut p, d, "t:bad.0"), Some(s("bad")));
}

// spec/commits.md §4: a setting's signer whose grant falls is still a possible admin. Which parts
// show is a function of what is held in every order, a late grant included.
#[test]
fn signer_whose_grant_fell_alike_in_every_order_spec_commits_4() {
    let (mut lp, d) = setup(437);
    let (bob, carol) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let base = base_of(&mut lp);
    let (bad, good) = (ak("t:bad.0"), ak("t:good.0"));
    let g = set_edge(&mut lp.peers[2].engine, d, bob, Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    lp.sync_all().unwrap();
    let s1 = require(&mut lp, 1, d, &rules(&[("t:bad.0", permanent())]));
    let mut m = Mutation::new();
    m.set(d, &bad, &s("bad")).unwrap();
    m.retention(d, &bad, junk()).unwrap();
    m.set(d, &good, &s("good")).unwrap();
    // `nobody` beside `nobody` only (spec/commits.md §5)
    m.retention(d, &good, junk()).unwrap();
    let c = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let dem = demote_to_write(&mut lp, d, carol, &[]);
    let (grant, setting, whole, demotion) = (pack(&mut lp.peers[2], &g), pack(&mut lp.peers[1], &s1), pack(&mut lp.peers[0], &c), pack(&mut lp.peers[0], &dem));
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let ai = part.header.aspects.iter().position(|a| a.ak == bad).unwrap();
    part.parts.retain(|x| x.ai != ai);
    let part = part.encode();
    let items = [(grant.bytes.clone(), grant.blobs.clone()), (setting.bytes.clone(), setting.blobs.clone()), (part, whole.blobs.clone()), (demotion.bytes.clone(), demotion.blobs.clone())];
    let mut orders = Vec::new();
    for a in 0..4 {
        for b in (0..4).filter(|b| *b != a) {
            for x in (0..4).filter(|x| *x != a && *x != b) {
                orders.push([a, b, x, 6 - a - b - x]);
            }
        }
    }
    assert_eq!(orders.len(), 24);
    for order in &orders {
        let mut p = fresh(&mut lp, &base, &[]);
        p.engine.set_syncing(d, true).unwrap();
        for (n, i) in order.iter().enumerate() {
            let (x, b) = &items[*i];
            p.engine.ingest(x, b.clone()).unwrap();
            let done = &order[..=n];
            let want = done.contains(&2).then(|| s("good"));
            assert_eq!(read(&mut p, d, "t:good.0"), want, "{order:?} after {n}");
        }
        assert_eq!(read(&mut p, d, "t:bad.0"), None, "{order:?}");
        p.engine.ingest(&whole.bytes, whole.blobs.clone()).unwrap();
        assert_eq!(read(&mut p, d, "t:good.0"), Some(s("good")));
        assert_eq!(read(&mut p, d, "t:bad.0"), Some(s("bad")), "the setting fell, {order:?}");
    }
}

// spec/commits.md §5: a writer refuses an entry no write could meet
#[test]
fn unmeetable_entry_refused_spec_commits_5() {
    let (mut lp, d) = setup(439);
    let keep = Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::PurgeOnReplace) };
    let purge_by_others: RequiredRules = BTreeMap::from([(ak("t:x.0"), Required::new(keep, None))]).into();
    let nobody = Retention { by: PurgeBy::Nobody, history: Some(History::Keep { until: None, after: Some(1_000) }) };
    let nobody_for_d = RequiredRules { default: Some(Required::new(nobody, None)), ..RequiredRules::default() };
    let at_once: RequiredRules = BTreeMap::from([(ak("t:x.0"), Required::new(permanent(), Some(0)))]).into();
    let beyond = RequiredRules { default: Some(Required::new(permanent(), Some(osis_commit::FOREVER))), ..RequiredRules::default() };
    for r in [purge_by_others, nobody_for_d, at_once, beyond] {
        let mut m = Mutation::new();
        m.set(d, &ct::REQUIRED, &r).unwrap();
        assert!(lp.peers[0].commit(m).is_err(), "{r:?}");
    }
    let writer = Retention { by: PurgeBy::Writer, history: Some(History::PurgeOnReplace) };
    let fine = RequiredRules { default: Some(Required::new(writer, Some(60_000))), ..RequiredRules::default() };
    require(&mut lp, 0, d, &fine);
    let mut m = Mutation::new();
    m.set(d, &ak("t:x.0"), &s("x")).unwrap();
    assert!(lp.peers[0].commit(m).unwrap().is_some());
}

// spec/commits.md §4, spec/permissions.md §5.2: a setting by one not a possible admin reads as never
// seen: in every order of the other inputs a node holding it reads as one that never saw it, and
// alike once the rest arrives
#[test]
fn writers_setting_reads_as_never_seen_spec_commits_4() {
    let mut lp = net(4, 441);
    let ids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(d, &REG, &s("d")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[2], Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, d, ids[3], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let base = base_of(&mut lp);
    let (bad, good) = (ak("t:bad.0"), ak("t:good.0"));
    let plain = rules(&[("t:bad.0", permanent())]);
    let g = set_edge(&mut lp.peers[2].engine, d, ids[1], Some(edge(Role::Admin)), None);
    lp.advance(1_000);
    lp.sync_all().unwrap();
    let s1 = require(&mut lp, 1, d, &plain);
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &plain).unwrap();
    let junk_setting = lp.peers[3].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let mut m = Mutation::new();
    m.set(d, &bad, &s("bad")).unwrap();
    m.retention(d, &bad, junk()).unwrap();
    m.set(d, &good, &s("good")).unwrap();
    // `nobody` beside `nobody` only (spec/commits.md §5)
    m.retention(d, &good, junk()).unwrap();
    let c = lp.peers[0].engine.commit_hostile(m).unwrap().unwrap();
    lp.advance(1_000);
    let dem = demote_to_write(&mut lp, d, ids[2], &[]);
    let (grant, setting, writers, whole, demotion) = (pack(&mut lp.peers[2], &g), pack(&mut lp.peers[1], &s1), pack(&mut lp.peers[3], &junk_setting), pack(&mut lp.peers[0], &c), pack(&mut lp.peers[0], &dem));
    let mut part = osis_commit::CommitBlob::decode(&whole.bytes).unwrap();
    let ai = part.header.aspects.iter().position(|a| a.ak == bad).unwrap();
    part.parts.retain(|x| x.ai != ai);
    let part = part.encode();
    let (wr, pa) = (2, 3);
    let items = [(grant.bytes.clone(), grant.blobs.clone()), (setting.bytes.clone(), setting.blobs.clone()), (writers.bytes.clone(), writers.blobs.clone()), (part, whole.blobs.clone()), (demotion.bytes.clone(), demotion.blobs.clone())];
    let mut orders = vec![Vec::new()];
    for _ in 0..items.len() {
        orders = orders.iter().flat_map(|o: &Vec<usize>| (0..items.len()).filter(|i| !o.contains(i)).map(|i| [o.clone(), vec![i]].concat()).collect::<Vec<_>>()).collect();
    }
    assert_eq!(orders.len(), 120);
    for order in &orders {
        let (mut x, mut y) = (fresh(&mut lp, &base, &[]), fresh(&mut lp, &base, &[]));
        x.engine.set_syncing(d, true).unwrap();
        y.engine.set_syncing(d, true).unwrap();
        for (n, i) in order.iter().enumerate() {
            let (bytes, blobs) = &items[*i];
            x.engine.ingest(bytes, blobs.clone()).unwrap();
            if *i != wr {
                y.engine.ingest(bytes, blobs.clone()).unwrap();
            }
            let (gx, gy) = (read(&mut x, d, "t:good.0"), read(&mut y, d, "t:good.0"));
            assert_eq!(gx, gy, "{order:?} after {n}");
            assert_eq!(read(&mut x, d, "t:bad.0"), read(&mut y, d, "t:bad.0"), "{order:?} after {n}");
            let done = &order[..=n];
            assert_eq!(gy, done.contains(&pa).then(|| s("good")), "{order:?} after {n}, the node that saw no drop");
        }
        for (bytes, blobs) in [(&whole.bytes, &whole.blobs), (&setting.bytes, &setting.blobs)] {
            x.engine.ingest(bytes, blobs.clone()).unwrap();
            y.engine.ingest(bytes, blobs.clone()).unwrap();
            assert_eq!(read(&mut x, d, "t:good.0"), Some(s("good")), "{order:?}");
            assert_eq!(read(&mut y, d, "t:good.0"), Some(s("good")), "{order:?}");
        }
        assert_eq!(read(&mut x, d, "t:bad.0"), read(&mut y, d, "t:bad.0"), "{order:?}");
        assert_eq!(read(&mut y, d, "t:bad.0"), Some(s("bad")), "the setting fell, {order:?}");
    }
}

// spec/permissions.md §5.2: an honest late grant. Bob, granted by Carol at one host, sets at both; an
// admin on the other host holds the setting first, unreadable and judged by nothing; the grant comes
// and it stands everywhere, at both hosts
#[test]
fn setting_before_its_grant_comes_back_spec_perm_6() {
    let mut net = Net::new();
    let (h1, h2) = (net.add_host(), net.add_host());
    let a = net.node(1, &[h1, h2]);
    let b = net.node(2, &[h1, h2]);
    let c = net.node(3, &[h1, h2]);
    let d = net.node(4, &[h1, h2]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Admin), (d, Role::Admin)], &[h1, h2]);
    let t = net.item(a, g, g, "v1");
    settle(&mut net);
    let (l, bob, ra) = (net.label(b), net.tid(b), ak("required.0^"));
    net.set_online(a, false);
    net.drop_link(c, h2);
    net.drop_link(d, h1);
    let grant = set_edge(net.engine(c), t, bob, Some(edge(Role::Admin)), None);
    net.run();
    assert!(net.engine(b).core.ix.commits.get(&grant).is_some());
    let at_host = net.host_ids(h2, &l).len();
    let mut m = Mutation::new();
    m.set(t, &ct::REQUIRED, &all(permanent())).unwrap();
    let st = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    assert!(net.engine(d).core.ix.commits.get(&grant).is_none());
    // the grant gave `t` secrets of its own: the setting's section is under them, so the admin
    // on the other host cannot read the setting before the grant reaches it (spec/wire.md §4);
    // it holds the blob sealed, the setting's part missing, and judges nothing
    assert!(net.engine(d).core.ix.commits.get(&st).is_none_or(|m| !m.missing.is_empty()), "unreadable before the grant");
    assert!(net.engine(d).core.ix.required.get(&t).is_none_or(|v| !v.iter().any(|x| x.0.commit == st)));
    assert!(net.host_ids(h2, &l).len() >= at_host, "nothing deleted from the host");
    net.set_online(a, true);
    for _ in 0..10 {
        net.advance(1_000);
    }
    for n in [a, b, c, d] {
        assert_eq!(net.engine(n).body_valid(&st, &t, &ra), Some(true), "{n}");
        assert!(net.engine(n).body_not_dropped(&st, &t, &ra), "{n}");
    }
    let (x, y): (BTreeSet<_>, BTreeSet<_>) = (net.host_ids(h1, &l).into_iter().collect(), net.host_ids(h2, &l).into_iter().collect());
    assert!(net.engine(d).core.ix.required.get(&t).is_some_and(|v| v.iter().any(|x| x.0.commit == st)), "binding there again");
    // each its own placement of the commit, with its own salt
    let ours: Vec<_> = net.sync(b).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == st)).map(|e| e.0).collect();
    assert!(ours.iter().any(|b| x.contains(b)) && ours.iter().any(|b| y.contains(b)), "both hosts have it");
}

// spec/permissions.md §6, spec/sync.md §6: a purge of a valid delta takes its blob off the host
// though the blob also holds a delta the purger dropped as invalid
#[test]
fn purge_beside_invalid_delta_leaves_host_spec_perm_6() {
    for with_bad in [false, true] {
        let mut net = Net::new();
        let host = net.add_host();
        let (a, b, c, d, _g, t) = on_host(&mut net, host);
        net.set_online(d, false);
        let l = net.label(a);
        let (bad, good) = (ak("t:bad.0"), ak("t:good.0"));
        let mut m = Mutation::new();
        m.set(t, &ct::REQUIRED, &rules(&[("t:bad.0", junk())])).unwrap();
        net.engine(c).commit(m).unwrap().unwrap();
        settle(&mut net);
        let before: BTreeSet<_> = net.host_ids(host, &l).into_iter().collect();
        let mut m = Mutation::new();
        m.set(t, &good, &s("good")).unwrap();
        if with_bad {
            m.set(t, &bad, &s("bad")).unwrap();
        }
        let cm = net.engine(b).commit_hostile(m).unwrap().unwrap();
        settle(&mut net);
        let new: BTreeSet<_> = net.host_ids(host, &l).into_iter().filter(|x| !before.contains(x)).collect();
        assert!(!new.is_empty());
        assert_eq!(net.engine(a).get(&t, &good).unwrap(), Some(s("good")));
        net.set_online(b, false);
        let mut m = Mutation::new();
        m.purge(osis_commit::PurgeItem::Commit { commit: cm, tid: t, ak: good.clone() });
        m.remove_aspect(t, &good).unwrap();
        net.engine(a).commit(m).unwrap().unwrap();
        settle(&mut net);
        settle(&mut net);
        assert!(!net.engine(a).body_not_dropped(&cm, &t, &good));
        let left: Vec<_> = net.host_ids(host, &l).into_iter().filter(|x| new.contains(x)).collect();
        assert!(left.is_empty(), "with_bad {with_bad}: the purged blob stays at the host: {left:?}");
    }
}
