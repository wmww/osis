//! The node closure (spec/sync-set.md §1-§3): what the node root reaches by strongs, sync unit
//! by sync unit, what left it, and what its changes cost.

use crate::common::pass_end;
use crate::flows::people;
use osis_base::{Tid, Value};
use std::collections::{BTreeMap, BTreeSet};
use osis_crdt::{Op, PathOp};
use osis_engine::local_peer::LocalPeer;
use osis_engine::{Engine, Mutation};
use osis_schema::core_types as ct;

/// Writes (`on`) or removes a strong from `from`'s `holds.0` to `to`.
/// One person's node (`people(1)`) and its node root D.
fn alone() -> (LocalPeer, Tid) {
    let (lp, _) = people(1);
    let d = lp.peers[0].engine.node_root().unwrap();
    (lp, d)
}

fn strong(e: &mut Engine, from: Tid, to: Tid, on: bool) {
    let v = Value::Strong(to);
    let mut m = Mutation::new();
    m.op(from, &ct::HOLDS, PathOp { path: vec![], op: if on { Op::Add(v) } else { Op::Remove(v) } }).unwrap();
    e.commit(m).unwrap();
    e.check_closure();
}

/// A dependent thing minted with admin `admin`, strongly referenced from `from` in the same transaction.
fn make(e: &mut Engine, admin: Tid, from: Tid) -> Tid {
    let (t, _) = crate::common::mint_from(e, admin, from, &[]);
    e.check_closure();
    t
}

// spec/sync-set.md §1, §2: a new account's node holds its node root, its node thing (by the node
// root's strong), the account, the profile and the inbox. A dependent thing minted with the
// account as admin and referenced from it is held in its sync unit; removing the strong takes it out and
// notes it as left with the sync unit it was in.
#[test]
fn the_node_closure_follows_strongs_spec_sync_set_2() {
    let (mut lp, ps) = crate::flows::accounts(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), ps[0]);
    let inbox = e.inbox_of(&d).unwrap().unwrap();
    for t in [root, d, inbox] {
        assert!(e.closure_holds(&t), "{t:?}");
    }
    assert!(e.closure_holds(&e.tid()), "the node root holds the node thing");
    let x = make(e, d, d);
    assert!(e.closure_holds(&x));
    assert!(e.sync_unit(&d).contains(&x) && e.units_holding(&x).contains(&d));
    strong(e, d, x, false);
    assert!(!e.closure_holds(&x));
    assert_eq!(e.left_closure().get(&x), Some(&[d].into()));
    strong(e, d, x, true);
    assert!(e.closure_holds(&x) && !e.left_closure().contains_key(&x), "back before release: kept");
}

/// The removal work (`closure:` counts) of `edit` after `setup`, both given `n`.
fn work(n: usize, setup: impl Fn(&mut Engine, Tid, usize) -> (Tid, Tid)) -> u64 {
    let (mut lp, d) = alone();
    let e = &mut lp.peers[0].engine;
    let (from, to) = setup(e, d, n);
    osis_base::costs::take();
    strong(e, from, to, false);
    osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("closure:")).map(|(_, _, c)| c).sum()
}

// spec/sync-set.md §2 Cost (notes/closure-model.md P5 counts): removing a strong costs at most
// the part of the node closure it held, never its target's other referrers; checked at n and
// 10n. A non-tree referrer of a target with fan-in n, the target's tree grant with referrers
// outside, a tree grant whose target has a shallow alternative over a subtree of n, and one whose
// alternative is n deep: each the same at both sizes. A subtree of n released: n.
#[test]
fn removal_costs_what_it_held_spec_sync_set_2() {
    // D -> x1..xn, each xi -> t: the tree grant of t is x1's, made first
    let fan = |e: &mut Engine, d: Tid, n: usize| {
        let xs: Vec<Tid> = (0..n).map(|_| make(e, d, d)).collect();
        let t = make(e, d, xs[0]);
        for x in &xs[1..] {
            strong(e, *x, t, true);
        }
        (xs, t)
    };
    let non_tree = |e: &mut Engine, d: Tid, n: usize| {
        let (xs, t) = fan(e, d, n);
        (xs[n - 1], t)
    };
    let tree = |e: &mut Engine, d: Tid, n: usize| {
        let (xs, t) = fan(e, d, n);
        (xs[0], t)
    };
    // D -> v -> chain of n, and D -> u -> v made after
    let shallow = |e: &mut Engine, d: Tid, n: usize| {
        let v = make(e, d, d);
        let mut at = v;
        for _ in 0..n {
            at = make(e, d, at);
        }
        let u = make(e, d, d);
        strong(e, u, v, true);
        (d, v)
    };
    // D -> t first, then D -> c1 -> .. -> cn -> t
    let deep = |e: &mut Engine, d: Tid, n: usize| {
        let t = make(e, d, d);
        let mut at = d;
        for _ in 0..n {
            at = make(e, d, at);
        }
        strong(e, at, t, true);
        (d, t)
    };
    // D -> c1 -> .. -> cn
    let subtree = |e: &mut Engine, d: Tid, n: usize| {
        let c = make(e, d, d);
        let mut at = c;
        for _ in 1..n {
            at = make(e, d, at);
        }
        (d, c)
    };
    let (n, m) = (6, 60);
    for (name, setup) in [("non-tree", &non_tree as &dyn Fn(&mut Engine, Tid, usize) -> (Tid, Tid)), ("tree", &tree), ("shallow", &shallow), ("deep", &deep)] {
        let (a, b) = (work(n, setup), work(m, setup));
        assert!(b <= a + 2, "{name}: {a} at {n}, {b} at {m}");
    }
    let (a, b) = (work(n, subtree), work(m, subtree));
    assert!(b >= 9 * a && b <= 11 * a, "subtree: {a} at {n}, {b} at {m}");
}

// spec/sync-set.md §3 Release: a thing that leaves waits for each sync ID that carried it when it
// left. G and A are independent, A minted with admin G and held by G; X is dependent, minted with
// admin A and held by A, so in G's and A's sync units; one write removing A -> X takes it out of
// both, and both are noted, whatever order the walk drops them in.
#[test]
fn a_thing_leaving_two_units_at_once_notes_both_spec_sync_set_3() {
    let (mut lp, d) = alone();
    let e = &mut lp.peers[0].engine;
    let me = e.tid();
    let g = make(e, me, d);
    e.make_independent(&g).unwrap();
    let a = make(e, g, g);
    e.make_independent(&a).unwrap();
    let x = make(e, a, a);
    assert_eq!(e.units_holding(&x), [g, a].into());
    strong(e, a, x, false);
    assert_eq!(e.left_closure().get(&x), Some(&[g, a].into()));
}

// spec/sync-set.md §2 Not carried: X in D's sync unit strongly references Y, a thing this node
// never got, so D's keys do not open it and nothing else holds it: the strong is named, from X's
// written strongs and in the whole list; a strong to a held thing is not. So is the node root's
// strong to a thing never got: the local part holds only dependent things the node opens.
#[test]
fn a_strong_nothing_carries_is_named_spec_sync_set_2() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), e.node_root().unwrap());
    let x = make(e, d, d);
    let y = Tid::from_bytes([7; 15]);
    let mut m = Mutation::new();
    m.op(x, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(y)) }).unwrap();
    e.commit(m).unwrap();
    let z = make(e, d, x);
    assert!(!e.closure_holds(&y) && e.closure_holds(&z));
    assert_eq!(e.not_carried_among(&x, &[y, z].into()).unwrap(), vec![y]);
    assert_eq!(e.not_carried().unwrap(), vec![(x, y)]);
    let u = Tid::from_bytes([8; 15]);
    strong(e, root, u, true);
    assert!(!e.closure_holds(&u), "a thing never got is held nowhere");
    assert_eq!(e.not_carried_among(&root, &[u].into()).unwrap(), vec![u]);
    let mut all = e.not_carried().unwrap();
    all.sort();
    let mut want = vec![(x, y), (root, u)];
    want.sort();
    assert_eq!(all, want);
}

/// The `closure:` and sync set work of `edit` on a closure of `n` dependent things minted with admin D beside A
/// (independent, minted with admin D) holding `m` dependent things, A sourced at another node, the sync set followed
/// before and after.
fn cut_work(n: usize, m: usize, edit: impl Fn(&mut Engine, Tid, Tid)) -> u64 {
    let (mut lp, d) = alone();
    let e = &mut lp.peers[0].engine;
    for _ in 0..n {
        make(e, d, d);
    }
    // minted with the node thing: the node enters it by its record grant's piece (a thing
    // minted with the local node root would have no carrier, spec/sync-set.md §2 First entry)
    let me = e.tid();
    let a = make(e, me, d);
    e.make_independent(&a).unwrap();
    for _ in 0..m {
        make(e, a, a);
    }
    e.set_sourced([a].into(), &Default::default()).unwrap();
    e.check_closure();
    let mut f = None;
    e.sync_held_added(&mut f).unwrap();
    osis_base::costs::take();
    edit(e, d, a);
    e.check_closure();
    e.sync_held_added(&mut f).unwrap();
    osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("closure:") || k.starts_with("sync set:") || k.starts_with("sync: things")).map(|(_, _, c)| c).sum()
}

// spec/sync-set.md §5 Sourced away, Cost: while A is sourced elsewhere, a thing entering or
// leaving the node closure costs the same at a closure of n and of 10n; moving A away or back
// costs what is below A (n and 10n), not the rest of the node closure. The sync set leaves A and
// what is below it only, and takes them back.
#[test]
fn a_sourced_thing_costs_what_is_below_it_spec_sync_set_5() {
    let (n, m) = (6, 60);
    let enter = |e: &mut Engine, d: Tid, _: Tid| {
        make(e, d, d);
    };
    let leave = |e: &mut Engine, d: Tid, _: Tid| {
        let x = make(e, d, d);
        osis_base::costs::take();
        strong(e, d, x, false);
    };
    for (name, edit) in [("enter", &enter as &dyn Fn(&mut Engine, Tid, Tid)), ("leave", &leave)] {
        let (a, b) = (cut_work(n, 3, edit), cut_work(m, 3, edit));
        assert!(b <= a + 2, "{name}: {a} at {n}, {b} at {m}");
    }
    let away = |e: &mut Engine, _: Tid, a: Tid| {
        e.set_sourced(Default::default(), &Default::default()).unwrap();
        e.check_closure();
        osis_base::costs::take();
        e.set_sourced([a].into(), &Default::default()).unwrap();
    };
    let back = |e: &mut Engine, _: Tid, _: Tid| {
        e.set_sourced(Default::default(), &Default::default()).unwrap();
    };
    for (name, edit) in [("away", &away as &dyn Fn(&mut Engine, Tid, Tid)), ("back", &back)] {
        let (a, b) = (cut_work(n, 3, edit), cut_work(m, 3, edit));
        assert!(b <= a + 2, "{name}: {a} with n = {n}, {b} with n = {m}");
        let (a, b) = (cut_work(3, n, edit), cut_work(3, m, edit));
        assert!(b >= 8 * a && b <= 12 * a, "{name}: {a} below A at {n}, {b} at {m}");
    }
    // what leaves and comes back
    let (mut lp, d) = alone();
    let e = &mut lp.peers[0].engine;
    let x = make(e, d, d);
    let me = e.tid();
    let a = make(e, me, d);
    e.make_independent(&a).unwrap();
    let y = make(e, a, a);
    e.set_sourced([a].into(), &Default::default()).unwrap();
    e.check_closure();
    let things = e.sync_things().unwrap();
    assert!(things.contains(&x) && !things.contains(&a) && !things.contains(&y), "{things:?}");
    assert!(e.closure_holds(&a) && e.closure_holds(&y), "sourced away, still held");
    e.set_sourced(Default::default(), &Default::default()).unwrap();
    e.check_closure();
    let things = e.sync_things().unwrap();
    assert!(things.contains(&a) && things.contains(&y));
}

// spec/sync-set.md §2 Sync units, Not carried: T's sync unit is T and what it
// reaches by strongs through things T's keys open, chains of grants giving the lowest role and the
// best chain counting; NotCarried names exactly the strongs in the node closure to a thing it does
// not hold. A random walk of edits (strongs added and removed, grants made, lowered and revoked
// between things) over 3 independent things and 4 dependent ones on one node; after each, every
// sync unit and the NotCarried list equal held-model `closure`'s on the world rebuilt from the
// edits.
#[test]
#[ignore = "property"]
fn sync_units_are_the_models_plain_spec_sync_set_2() {
    use held_model::closure as hc;
    use osis_base::Role;
    osis_base::testenv::Seeds::from_env("OSIS_UNITS_START", "OSIS_UNITS_SEEDS", 1..4).run(
        "closure::sync_units_are_the_models_plain_spec_sync_set_2",
        |s| format!("OSIS_UNITS_START={s} OSIS_UNITS_SEEDS=1 cargo test -p osis-engine --test it -- --ignored --exact closure::sync_units_are_the_models_plain_spec_sync_set_2"),
        |seed| {
        let mut rng = crate::order::Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let (mut lp, _) = people(1);
        let e = &mut lp.peers[0].engine;
        let (d, p) = (e.node_root().unwrap(), e.tid());
        // model things 0..3 independent (minted with the node thing as admin and made independent, held by D), 3..7 dependent, minted with admin independent i % 3
        let mut tids: Vec<Tid> = (0..3).map(|_| make(e, p, d)).collect();
        for t in &tids {
            e.make_independent(t).unwrap();
        }
        let mut kinds = vec![hc::Kind::Independent; 3];
        let mut edges = hc::Edges::new();
        for i in 0..4 {
            let k = i % 3;
            tids.push(make(e, tids[k], tids[k]));
            kinds.push(hc::Kind::Dependent(k));
            edges.insert((k, 3 + i));
        }
        let mut grants = BTreeMap::new();
        // each standing grant (holder, target) in the order its standing began (key access)
        let mut order: Vec<(usize, usize)> = Vec::new();
        let ix = |t: &Tid| tids.iter().position(|x| x == t);
        for step in 0..40 {
            let (x, y) = (rng.below(7) as usize, rng.below(7) as usize);
            let (g, t) = (rng.below(3) as usize, rng.below(3) as usize);
            match rng.below(6) {
                0..=1 if x != y && e.closure_holds(&tids[x]) => {
                    strong(e, tids[x], tids[y], true);
                    edges.insert((x, y));
                }
                2 if !edges.is_empty() => {
                    let (x, y) = *edges.iter().nth(rng.below(edges.len() as u64) as usize).unwrap();
                    // a node writes only what it holds
                    if !e.closure_holds(&tids[x]) {
                        continue;
                    }
                    strong(e, tids[x], tids[y], false);
                    edges.remove(&(x, y));
                }
                3..=4 if g != t => {
                    let r = [Role::Sync, Role::Read, Role::Write][rng.below(3) as usize];
                    let grant = ct::Grant { role: r, until: None, may_grant: false, retain: false, floor: None };
                    let had: Option<hc::Role> = grants.get(&(g, t)).copied();
                    let m = match r { Role::Sync => hc::Role::Sync, Role::Read => hc::Role::Read, _ => hc::Role::Write };
                    if had == Some(m) {
                        continue;
                    }
                    if had.is_some_and(|h| h > m) {
                        e.demote(&tids[t], &osis_engine::flows::Demotion { holder: tids[g], new: Some(grant), retain: None }).unwrap();
                    } else {
                        e.grant(&tids[t], &tids[g], &grant).unwrap();
                    }
                    if had.is_none() {
                        order.push((g, t));
                    }
                    grants.insert((g, t), m);
                }
                5 if grants.contains_key(&(g, t)) => {
                    e.demote(&tids[t], &osis_engine::flows::Demotion { holder: tids[g], new: None, retain: None }).unwrap();
                    grants.remove(&(g, t));
                    order.retain(|x| *x != (g, t));
                }
                _ => continue,
            }
            e.check_closure();
            let w = hc::World { kinds: kinds.clone(), grants: grants.clone(), keyless: hc::keyless_of(&order), ..hc::World::default() };
            for (k, kt) in tids.iter().enumerate().take(3) {
                let got: BTreeSet<usize> = e.sync_unit(kt).iter().filter_map(ix).collect();
                assert_eq!(got, hc::unit(&w, k, &edges), "seed {seed} step {step}: the sync unit of {k}");
            }
            // the node reads every independent thing (it made them): roots D's strongs to them
            // (the model's last thing is its node thing, admin of each by its record grant)
            let me = kinds.len();
            let mut mine = w.clone();
            mine.kinds.push(hc::Kind::Independent);
            mine.grants.extend((0..3).map(|k| ((me, k), hc::Role::Admin)));
            let n = hc::NodeView { roots: [0, 1, 2].into(), own: [me].into() };
            let held = hc::closure(&mine, &edges, &n, hc::Walk::Units).held;
            let want: BTreeSet<(usize, usize)> = edges.iter().copied().filter(|(x, y)| held.contains(x) && !held.contains(y)).collect();
            let got: BTreeSet<(usize, usize)> = e.not_carried().unwrap().iter().filter_map(|(x, y)| Some((ix(x)?, ix(y)?))).collect();
            assert_eq!(got, want, "seed {seed} step {step}: not carried");
        }
    },
    );
}

/// `make` refused or not: a thing minted with admin `admin`, strongly referenced from `from` (none: from
/// nothing) in the same commit.
fn try_make(e: &mut Engine, admin: Tid, from: Option<Tid>) -> osis_engine::Result<Tid> {
    let rec = e.thing_record(admin, None);
    let mut m = Mutation::new();
    let t = m.create(rec);
    if let Some(f) = from {
        m.op(f, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    }
    e.commit(m).map(|_| t)
}

// spec/sync-set.md §2 Minting a thing: the commits of one storage transaction must
// leave every thing they make in the node closure at its end, or nothing
// applies. X and U are independent: a dependent thing minted with admin X referenced by X is made; one nothing
// references, or one from U referenced only by X (X's keys do not open it), is refused and
// leaves no commit; a thing minted in one commit and held by the next of its transaction is made,
// and refused with that commit holding nothing, its record alone held by nothing and a holder of
// nothing; a link is made, its link key held by no strong, as K's holder (made with its role
// entries alone).
#[test]
fn a_thing_is_made_only_where_it_is_held_spec_sync_set_2() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (d, p) = (e.node_root().unwrap(), e.tid());
    assert!(e.closure_holds(&d), "the node root");
    let (x, u) = (make(e, p, d), make(e, p, d));
    for t in [x, u] {
        e.make_independent(&t).unwrap();
    }
    let made = try_make(e, x, Some(x)).unwrap();
    assert!(e.closure_holds(&made));
    let before = e.commit_ids().len();
    for (name, admin, from) in [("held by nothing", x, None), ("dependent on U, referenced by X", u, Some(x))] {
        let r = try_make(e, admin, from);
        assert!(matches!(r, Err(osis_engine::Error::NotHeld(_))), "{name}: {r:?}");
        assert_eq!(e.commit_ids().len(), before, "{name}: nothing applies");
    }
    let hold = |a: Tid| {
        let mut m = Mutation::new();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(a)) }).unwrap();
        Ok::<_, osis_engine::Error>(m)
    };
    let a = e.mint_independent(&[osis_engine::MintAdmin::Thing(p)], |ts| Ok(vec![hold(ts[0])?])).unwrap().0[0];
    assert!(e.closure_holds(&a), "held by the transaction's next commit");
    let r = e.mint_independent(&[osis_engine::MintAdmin::Thing(p)], |_| Ok(vec![Mutation::new()]));
    assert!(matches!(r, Err(osis_engine::Error::NotHeld(_))), "{r:?}");
    let spec = osis_engine::flows::LinkSpec { target: x, role: osis_base::Role::Read, until: None, peers: vec![], single_use: false };
    e.create_link(&p, &spec).unwrap();
}

// spec/sync-set.md §2 (Sync unit; T's keys open): nested sharing. X and Y are independent, X is granted read on Y,
// and X -> Y -> B with B dependent on Y. A reader of X (account 1, holding X by a strong) holds Y and
// B in X's sync unit, and has Y's sync ID in its sync set.
#[test]
fn nested_sharing_holds_what_the_shared_thing_reads_spec_sync_set_2() {
    let (mut lp, ps) = people(2);
    let e = &mut lp.peers[0].engine;
    let (d, p) = (e.node_root().unwrap(), e.tid());
    let x = make(e, p, d);
    let y = make(e, p, x);
    let b = make(e, y, y);
    e.grant(&y, &x, &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    e.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.node_root().unwrap();
    strong(e1, d1, x, true);
    lp.sync_all().unwrap();
    let e1 = &mut lp.peers[1].engine;
    for t in [x, y, b] {
        assert!(e1.closure_holds(&t) && e1.sync_unit(&x).contains(&t), "{t:?}");
    }
    assert!(e1.in_sync_things(&y).unwrap(), "Y's sync ID synced");
}

// spec/sync-set.md §2 Cost: adding a thing costs the same whatever else the node
// root holds (n and 10n things beside it), and a cycle cut off from the node closure is released
// whole.
#[test]
fn adding_costs_what_it_adds_and_a_cycle_goes_whole_spec_sync_set_2() {
    let add = |n: usize| {
        let (mut lp, d) = alone();
        let e = &mut lp.peers[0].engine;
        for _ in 0..n {
            make(e, d, d);
        }
        osis_base::costs::take();
        make(e, d, d);
        osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("closure:")).map(|(_, _, c)| c).sum::<u64>()
    };
    assert_eq!(add(6), add(60));
    let (mut lp, d) = alone();
    let e = &mut lp.peers[0].engine;
    let c1 = make(e, d, d);
    let c2 = make(e, d, c1);
    strong(e, c2, c1, true);
    strong(e, d, c1, false);
    assert!(!e.closure_holds(&c1) && !e.closure_holds(&c2));
    assert_eq!(e.left_closure().keys().copied().collect::<BTreeSet<_>>(), [c1, c2].into());
}

// spec/sync-set.md §3 Release: a thing that left the node closure and is
// released is dropped with its writes, durable and ephemeral, and reads as not held; one back in
// the node closure before its release is kept as it was, and its release drops nothing.
#[test]
fn a_released_thing_goes_with_its_writes_spec_sync_set_3() {
    let (mut lp, d) = alone();
    let e = &mut lp.peers[0].engine;
    let reg = crate::common::REG;
    let log = crate::common::LOG;
    let (x, y) = (make(e, d, d), make(e, d, d));
    for t in [x, y] {
        let mut m = Mutation::new();
        m.set(t, &reg, &Value::Str("v".into())).unwrap();
        e.commit(m).unwrap();
        let mut m = Mutation::new();
        m.set(t, &log, &Value::List(vec![Value::Str("e".into())])).unwrap();
        e.write(m).unwrap();
        strong(e, d, t, false);
    }
    strong(e, d, y, true);
    let left: BTreeSet<Tid> = e.left_closure().keys().copied().collect();
    assert_eq!(left, [x].into(), "back before its release: not leaving");
    e.released(&[x, y].into()).unwrap();
    assert!(!e.closure_holds(&x) && e.left_closure().is_empty());
    assert_eq!((e.get(&x, &crate::common::ak("t:reg.0")).unwrap(), e.get(&x, &crate::common::ak("t:log+.0")).unwrap()), (None, None), "released with its writes");
    assert_eq!(e.get(&y, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("v".into())), "kept as it was");
    assert!(e.get(&y, &crate::common::ak("t:log+.0")).unwrap().is_some(), "its ephemeral state too");
}

// spec/sync-set.md §3 (lowering from read to sync is no release): lowering a reader to sync is no release: account 1, holding X
// read, is lowered to sync; X stays in its node closure, kept unread (its sync ID in the sync
// set, nothing noted as left), and what is written after, sealed as sync IDs carry it, opens
// nothing there.
#[test]
fn lowered_to_sync_a_thing_is_kept_unread_spec_sync_set_3() {
    let (mut lp, ps) = people(2);
    let e = &mut lp.peers[0].engine;
    let (d, p) = (e.node_root().unwrap(), e.tid());
    let x = make(e, p, d);
    let reg = crate::common::REG;
    let put = |e: &mut Engine, v: &str| {
        let mut m = Mutation::new();
        m.set(x, &reg, &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap();
    };
    put(e, "before");
    e.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.node_root().unwrap();
    strong(e1, d1, x, true);
    lp.sync_all().unwrap();
    let read = |lp: &mut LocalPeer| lp.peers[1].engine.get(&x, &crate::common::ak("t:reg.0")).unwrap();
    assert_eq!(read(&mut lp), Some(Value::Str("before".into())));
    let e = &mut lp.peers[0].engine;
    let lowering = e.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: Some(crate::flows::grant_of(osis_base::Role::Sync)), retain: None }).unwrap();
    // the lowering's role commits reach account 1, as its sync role keeps them coming
    for c in &lowering.commits {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
    }
    assert_eq!(lp.peers[1].engine.roster(&x).get(&ps[1]).map(|e| e.role), Some(osis_base::Role::Sync), "lowered, as account 1 reads its roster");
    // as sync's Life drops what a lowering lost (spec/permissions.md §3 Lost access)
    lp.peers[1].engine.drop_lost_secrets().unwrap();
    let seen: BTreeSet<osis_base::CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    put(&mut lp.peers[0].engine, "after");
    let ids: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !seen.contains(c)).collect();
    let pks = lp.sealed(0, &ids).unwrap();
    lp.deliver_sealed(1, &pks).unwrap();
    let e1 = &mut lp.peers[1].engine;
    e1.check_closure();
    assert!(e1.closure_holds(&x) && !e1.left_closure().contains_key(&x), "kept");
    assert!(e1.in_sync_things(&x).unwrap(), "its sync ID kept");
    assert_ne!(read(&mut lp), Some(Value::Str("after".into())), "unread");
}

// spec/sync-set.md §2 Cost: taking up an opener (a link key, as a bearer does) and making a
// link cost what the new opener can open, never the node closure or every held actor: counted
// (`closure:` and `reopen:`) with n and 10n independent things held.
#[test]
fn a_take_up_costs_what_the_opener_opens_spec_sync_set_2() {
    let work = |n: usize| {
        let (mut lp, _) = people(1);
        let e = &mut lp.peers[0].engine;
        let (d, p) = (e.node_root().unwrap(), e.tid());
        let things: Vec<Tid> = (0..n).map(|_| make(e, p, d)).collect();
        let counted = |e: &mut Engine, f: &dyn Fn(&mut Engine)| {
            osis_base::costs::take();
            f(e);
            // the totals alone: a split by cause (` <- `) recounts a judgement per read it finds
            // moved, a diagnostic and no count of work
            let counted = |k: &str| (k.starts_with("closure:") || k.starts_with("reopen:")) && !k.contains(" <- ");
            osis_base::costs::take().into_iter().filter(|(k, _, _)| counted(k)).map(|(_, _, c)| c).sum::<u64>()
        };
        let take_up = counted(e, &|e| { e.hold_link_key(osis_crypto::Secret32::from_bytes([0x5a; 32]), things[0]).unwrap(); });
        let spec = osis_engine::flows::LinkSpec { target: things[0], role: osis_base::Role::Read, until: None, peers: vec![], single_use: false };
        let link = counted(e, &|e| drop(e.create_link(&p, &spec).unwrap()));
        e.check_closure();
        (take_up, link)
    };
    let (small, large) = (work(5), work(50));
    eprintln!("take-up and create_link work at n, 10n: {small:?} {large:?}");
    // the work does not grow with n (it moves by a few edges woken either way)
    assert!(large.0 <= small.0 && large.1 <= small.1, "{small:?} at n, {large:?} at 10n");
}

// spec/commits.md §5 What a held thing needs (dropped when the pass that brought it ends): what a
// node holds outside its node closure at quiet does not depend on arrival order. Account Q (peer
// 1, never met by peer 0) makes T and grants peer 0's account read; peer 0 holds T, takes Q's
// commits, then releases T. Q's write on its own profile arrives before the release, or after
// it; Q ends the grant and its fire leaves peer 0's inbox (the held signal keeps T's stub until
// then, released after): either way, at the pass's end nothing held needs Q's chain or that
// write, and peer 0 holds the same.
#[test]
fn what_nothing_needs_goes_whatever_the_arrival_order_spec_commits_5() {
    let mut lp = LocalPeer::new_apart(2, 0, crate::common::T0).unwrap();
    let p0 = osis_engine::local_peer::make_account(&mut lp.peers[0].engine).unwrap().0.thing;
    let (qa, _) = osis_engine::local_peer::make_account(&mut lp.peers[1].engine).unwrap();
    let (q, profile) = (qa.thing, qa.profile);
    let mut end = |late: bool| {
        let mut lp = lp.copy().unwrap();
        // Q keeps peer 0's account, which it grants
        lp.peers[1].know(&[p0]).unwrap();
        let mine: Vec<_> = lp.peers[0].engine.commit_ids();
        crate::flows::send_carried(&mut lp, 0, 1, &mine);
        let e1 = &mut lp.peers[1].engine;
        let mut m = Mutation::new();
        let t = e1.new_thing(&mut m, q);
        m.set(t, &crate::common::REG, &Value::Str("t".into())).unwrap();
        e1.commit(m).unwrap();
        e1.grant(&t, &p0, &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
        let mut m = Mutation::new();
        m.set(profile, &crate::common::REG, &Value::Str("q".into())).unwrap();
        let x = e1.commit(m).unwrap().unwrap();
        let rest: Vec<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|c| *c != x).collect();
        let e0 = &mut lp.peers[0].engine;
        e0.hold(osis_base::Strong(t)).unwrap();
        crate::flows::send_carried(&mut lp, 1, 0, &rest);
        if !late {
            crate::flows::send_carried(&mut lp, 1, 0, &[x]);
        }
        let e0 = &mut lp.peers[0].engine;
        assert!(e0.closure_holds(&t), "late {late}: peer 0 holds T");
        e0.unhold(osis_base::Strong(t)).unwrap();
        e0.released(&[t].into()).unwrap();
        if late {
            crate::flows::send_carried(&mut lp, 1, 0, &[x]);
        }
        // the grant ends and its last fire leaves the inbox: nothing of T's grant is held
        let removal = lp.peers[1].engine.demote(&t, &osis_engine::flows::Demotion { holder: p0, new: None, retain: Some(false) }).unwrap().commits;
        crate::flows::send_carried(&mut lp, 1, 0, &removal);
        lp.advance(osis_base::format::INBOX_LIFETIME_MS + 3_600_000);
        lp.peers[0].tick().unwrap();
        let e0 = &mut lp.peers[0].engine;
        // T's stub, which the grant's signal held, went with the fire: released now
        e0.released(&[t].into()).unwrap();
        e0.settle_needs().unwrap();
        // of Q's commits (peer 0's own hold and unhold differ by their stamps)
        let qs: BTreeSet<_> = rest.iter().copied().chain([x]).collect();
        let held: BTreeSet<_> = e0.commit_ids().into_iter().filter(|c| qs.contains(c)).collect();
        let pending: BTreeSet<_> = e0.pending().into_iter().map(|p| p.0).collect();
        assert!(e0.core.created(&q).is_none(), "late {late}: nothing held needs Q's chain: {}", e0.why_kept(&q));
        (held, pending)
    };
    let (a, b) = (end(false), end(true));
    let only = |x: &BTreeSet<osis_base::CommitId>, y: &BTreeSet<osis_base::CommitId>| x.difference(y).copied().collect::<Vec<_>>();
    assert_eq!(a, b, "held only early {:?}, only late {:?}; pending only early {:?}, only late {:?}", only(&a.0, &b.0), only(&b.0, &a.0), only(&a.1, &b.1), only(&b.1, &a.1));
}

// spec/commits.md §5 What a held thing needs: a held commit waiting for a part keeps what it is on.
// Peer 0 mints U with admin G (read by a fresh observer) in one commit, U's record with G's strong to
// it; the observer gets the commit without its part on G, which it then counts missing. At the
// pass's end U stays (the commit waits for that part, which may reference U), so the part, fetched
// again as counted missing, shows G's strong to U and U's record.
#[test]
fn a_commit_waiting_for_a_part_keeps_what_it_is_on_spec_commits_5() {
    let mut lp = crate::common::net(1, 0);
    let g = crate::common::new_thing(&mut lp, 0);
    let mut r = crate::common::reader(&mut lp, 0, g, 1);
    let (u, done) = lp.peers[0].engine.create_with_admin(&g).unwrap();
    let c = *done.commits.last().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let on_g = b.header.aspects.iter().position(|a| a.tid == g).expect("the commit writes G's strong");
    b.parts.retain(|p| p.ai != on_g);
    r.receive(&b.encode(), pk.blobs.clone()).unwrap();
    r.engine.settle_needs().unwrap();
    // the sync exchange: what it counts missing is fetched again
    if r.engine.commit_parts_missing().get(&c).is_some_and(|m| m.contains(&on_g)) {
        r.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    r.engine.settle_needs().unwrap();
    let holds = r.engine.get(&g, &osis_base::Ak::new("holds.0").unwrap()).unwrap();
    assert!(matches!(&holds, Some(Value::Set(s)) if s.contains(&Value::Strong(u))), "G's strong to U: {holds:?}");
    assert!(r.engine.core.created(&u).is_some(), "U's record");
}

/// Peer 1 reads and holds X, made by peer 0 with mint admin its account D (outside peer 1's node
/// closure, needed as X's mint admin), once a pass brought what peer 0 holds: the world and D.
fn held_minted_with_d() -> (LocalPeer, Tid) {
    let (mut lp, ps) = crate::flows::accounts(2);
    let d = ps[0];
    let x = make(&mut lp.peers[0].engine, d, d);
    lp.peers[0].engine.grant(&x, &ps[1], &crate::common::grant(osis_base::Role::Read)).unwrap();
    lp.hold_at(1, x);
    lp.sync(0, 1).unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.closure_holds(&x) && !e1.closure_holds(&d) && e1.core.created(&d).is_some(), "D held as X's mint admin, outside the node closure");
    (lp, d)
}

// spec/commits.md §5 What a held thing needs: a strong needs its target only from a thing in the
// node closure. D, kept at peer 1 for X alone, holds a strong to B; at the pass's end B goes, as
// would everything D holds.
#[test]
fn a_strong_from_outside_the_node_closure_needs_nothing_spec_commits_5() {
    let (mut lp, d) = held_minted_with_d();
    let b = make(&mut lp.peers[0].engine, d, d);
    lp.sync(0, 1).unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.core.created(&b).is_none(), "{}", e1.why_kept(&b));
}

// spec/commits.md §5 What a held thing needs: a part missing keeps what its commit is on only on a
// thing in the node closure (one the node fetches again). Peer 0 mints T with admin D with D's strong to
// it in one commit; peer 1, holding D outside its node closure, gets the commit without its part
// on D: at the pass's end T goes.
#[test]
fn a_part_missing_outside_the_node_closure_keeps_nothing_spec_commits_5() {
    let (mut lp, d) = held_minted_with_d();
    let t = make(&mut lp.peers[0].engine, d, d);
    let c = *lp.peers[0].engine.commit_ids().last().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let on_d = b.header.aspects.iter().position(|a| a.tid == d).expect("the commit writes D's strong");
    b.parts.retain(|p| p.ai != on_d);
    let r = &mut lp.peers[1];
    r.receive(&b.encode(), pk.blobs.clone()).unwrap();
    assert!(r.engine.commit_parts_missing().get(&c).is_some_and(|m| m.contains(&on_d)), "its part on D counts missing");
    r.engine.settle_needs().unwrap();
    assert!(r.engine.core.created(&t).is_none(), "{}", r.engine.why_kept(&t));
}

// spec/commits.md §5 What a held thing needs, §4 Unjudgeable: a commit needs the things its path
// lists, whose records judge it. Peer 0 writes X acting as T, a thing of its own outside peer 1's
// node closure, holding no role on X: the commit pends at peer 1 until T's chain is known;
// nothing else needs T there, and its record stays past the pass's end with the commit.
#[test]
fn a_commit_needs_the_thing_it_acts_as_spec_commits_5() {
    let mut lp = crate::common::net(2, 0);
    let d = lp.peers[0].engine.node_root().unwrap();
    let x = crate::common::new_shared(&mut lp, 0);
    let e0 = &mut lp.peers[0].engine;
    let me = e0.tid();
    let t = make(e0, me, d);
    let mut m = Mutation::new();
    m.set(x, &crate::common::REG, &crate::common::s("as t")).unwrap();
    m.act_as(t);
    let c = e0.commit_hostile(m).unwrap().unwrap();
    lp.sync(0, 1).unwrap();
    let e1 = &mut lp.peers[1].engine;
    e1.settle_needs().unwrap();
    assert!(e1.pending().iter().any(|(id, r)| *id == c && matches!(r, osis_engine::Reason::MissingChain(_))), "the commit acting as T pends: {:?}", e1.pending());
    assert!(e1.core.created(&t).is_some(), "T's record stays with the commit acting as it: {}", e1.why_kept(&t));
}

// spec/sync-set.md §2 (Writing): a node writes only what it holds. Bob, granted write on Alice's
// T and holding its commits, writes it unaccepted: refused, nothing applies. Accepting T and
// writing it in one commit passes: what it writes is held at the transaction's end.
#[test]
fn a_node_writes_only_what_it_holds_spec_sync_set_2() {
    let (mut lp, ps) = people(2);
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.node_root().unwrap();
    let t = make(e0, d0, d0);
    e0.grant(&t, &ps[1], &crate::flows::grant_of(osis_base::Role::Write)).unwrap();
    let ids = lp.peers[0].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 0, 1, &ids);
    let e1 = &mut lp.peers[1].engine;
    let before = e1.commit_ids().len();
    let v = osis_base::Ak::new("x:v.0").unwrap();
    let mut m = Mutation::new();
    m.set(t, &v, &Value::Str("unaccepted".into())).unwrap();
    assert!(matches!(e1.commit(m), Err(osis_engine::Error::NotHeld(x)) if x == t), "not held: refused");
    assert_eq!(e1.commit_ids().len(), before, "nothing applied");
    let d1 = e1.node_root().unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    m.set(t, &v, &Value::Str("held".into())).unwrap();
    e1.commit(m).unwrap();
    assert_eq!(e1.get(&t, &v).unwrap(), Some(Value::Str("held".into())));
}

// spec/sync-set.md §3 (Nothing of R stays), spec/commits.md §5 (What a held thing needs): a node's
// own things are released whole as another's are. Dependent things minted with the node thing and
// with the node root as admin, each written and then released, keep no
// record, secret or part here: their record chains topping at this node keep nothing of them.
#[test]
fn own_things_are_released_whole_spec_sync_set_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let root = e.node_root().unwrap();
    let p = e.tid();
    let c = make(e, root, root);
    let b = e.create_with_admin(&p).unwrap().0;
    for t in [b, c] {
        let mut m = Mutation::new();
        m.set(t, &crate::common::REG, &crate::common::s("new")).unwrap();
        e.commit(m).unwrap();
    }
    strong(e, root, b, false);
    strong(e, root, c, false);
    e.released(&[b, c].into()).unwrap();
    for t in [b, c] {
        assert!(e.core.created(&t).is_none(), "{t:?}: its record");
        assert!(!e.held_actors_has(&t), "{t:?}: its secrets");
        // a commit with a part held elsewhere (the strong's, on the node root) keeps its header alone
        let held = e.core.on_thing(&t).filter(|c| e.core.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().enumerate().any(|(i, x)| x.tid == t && m.holds(i)))).count();
        assert_eq!(held, 0, "{t:?}: its parts");
    }
}

// spec/data-model.md §8 Held history: on a thing whose setting has `history_holds_targets`, a
// strong in a held body of its history holds its target as a current one does, a fire's as a
// replaced write's (a fire is history once written); without the flag neither holds. X is held by
// D's strong; T's body names X (a fire on T's signal, or a write on T's `holds.0` removed again);
// D's strong removed, X stays iff the flag is set, and goes once the body does (purged; covered
// past the bound: a fire is never covered) or the flag is turned off.
#[test]
fn a_strong_in_held_history_holds_its_target_while_the_body_is_held_spec_data_model_8() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum End {
        FlagOff,
        Purged,
        Covered,
    }
    let sig = crate::common::ak("t:f~0");
    let holds_ak = crate::common::ak("holds.0");
    let keep = osis_schema::History::Keep { until: None, after: Some(10 * 60_000) };
    let setting = |holds| ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(keep), ..Default::default() }), history_holds_targets: holds, ..Default::default() };
    for fire in [false, true] {
        for (holds, end) in [(false, End::FlagOff), (true, End::FlagOff), (true, End::Purged), (true, End::Covered)] {
            if fire && end == End::Covered {
                continue;
            }
            let at = format!("fire {fire}, flag {holds}, {end:?}");
            let (mut lp, d) = alone();
            let e = &mut lp.peers[0].engine;
            let t = make(e, d, d);
            let x = make(e, d, d);
            let mut m = Mutation::new();
            m.set(t, &ct::RETENTION, &setting(holds)).unwrap();
            e.commit(m).unwrap();
            let mut m = Mutation::new();
            if fire {
                m.set(t, &sig, &Value::Strong(x)).unwrap();
            } else {
                m.op(t, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(x)) }).unwrap();
            }
            let body = e.commit(m).unwrap().unwrap();
            if !fire {
                strong(e, t, x, false);
            }
            strong(e, d, x, false);
            assert_eq!(e.closure_holds(&x), holds, "{at}: held by T's body iff the flag is set");
            if !holds {
                continue;
            }
            let on = if fire { sig.clone() } else { holds_ak.clone() };
            match end {
                End::FlagOff => {
                    let mut m = Mutation::new();
                    m.set(t, &ct::RETENTION, &setting(false)).unwrap();
                    e.commit(m).unwrap();
                }
                End::Purged => {
                    let mut m = Mutation::new();
                    m.set(t, &ct::PURGE, &e.now()).unwrap();
                    m.purge_commit(body, t, on.clone());
                    e.commit(m).unwrap();
                    assert!(!e.body_not_dropped(&body, &t, &on), "{at}: the body purged");
                }
                End::Covered => {
                    lp.advance(11 * 60_000);
                    lp.peers[0].tick().unwrap();
                    let e = &mut lp.peers[0].engine;
                    assert!(e.closure_holds(&x), "{at}: past the bound the body is still held: so is X");
                    e.snapshot(&t, &on).unwrap().unwrap();
                    if e.body_not_dropped(&body, &t, &on) {
                        e.drop_body(&body, &t, &on).unwrap();
                    }
                }
            }
            let e = &mut lp.peers[0].engine;
            e.check_closure();
            assert!(!e.closure_holds(&x), "{at}: the body gone or the flag off, X goes");
        }
    }
}

// spec/commits.md §5 What a held thing needs: a strong in an ephemeral aspect needs its target as a
// durable one does, and going loses that need alike. Peer 0 keeps account Q (peer 1) by such a
// strong on its node root alone; the aspect removed, Q's chain goes at the pass's end.
#[test]
fn an_ephemeral_strong_going_lets_its_target_go_spec_commits_5() {
    let mut lp = LocalPeer::new_apart(2, 0, crate::common::T0).unwrap();
    let q = lp.peers[1].engine.tid();
    let theirs: Vec<_> = lp.peers[1].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 1, 0, &theirs);
    let e0 = &mut lp.peers[0].engine;
    let (d0, a) = (e0.node_root().unwrap(), osis_base::Ak::new("t:keep+.0").unwrap());
    let mut m = Mutation::new();
    m.set(d0, &a, &Value::Strong(q)).unwrap();
    e0.write(m).unwrap();
    // twice: the first pass end's drops leave what they named to the next
    e0.settle_needs().unwrap();
    e0.settle_needs().unwrap();
    assert!(e0.core.created(&q).is_some(), "the ephemeral strong keeps Q's chain");
    let mut m = Mutation::new();
    m.remove_aspect(d0, &a).unwrap();
    e0.write(m).unwrap();
    e0.settle_needs().unwrap();
    assert!(e0.core.created(&q).is_none(), "nothing held needs Q's chain");
}

// spec/data-model.md §8 What counts (an ephemeral aspect's references while the node holds its
// value), spec/sync-set.md §3: peers 0 and 1, one account's nodes, hold X by an ephemeral strong
// on their account D alone. Peer 0 restarts and loses the value, so X is released there, until peer 1, still
// holding the value, gives it back (as a connected peer's join lists its live ephemeral
// entries); once both have restarted with nobody holding it, X is released at both.
#[test]
fn an_ephemeral_strong_holds_while_a_peer_holds_its_value_spec_data_model_8() {
    let mut lp = crate::common::net_one(2);
    let d = crate::common::account_of(&mut lp);
    let a = osis_base::Ak::new("t:keep+.0").unwrap();
    let x = make(&mut lp.peers[0].engine, d, d);
    let mut m = Mutation::new();
    m.set(d, &a, &Value::Strong(x)).unwrap();
    let eph = lp.peers[0].engine.write(m).unwrap().unwrap().id;
    strong(&mut lp.peers[0].engine, d, x, false);
    lp.sync_all().unwrap();
    let give = |lp: &mut LocalPeer, from: usize, to: usize| {
        let b = lp.peers[from].engine.memory_blob(&eph).unwrap().expect("held in memory");
        lp.peers[to].engine.ingest_memory(&b.encode(), u64::MAX).unwrap();
    };
    give(&mut lp, 0, 1);
    let held = |lp: &mut LocalPeer, i: usize| {
        let e = &mut lp.peers[i].engine;
        e.settle_needs().unwrap();
        e.settle_needs().unwrap();
        e.closure_holds(&x)
    };
    assert!(held(&mut lp, 0), "the ephemeral strong holds X");
    assert!(held(&mut lp, 1), "and at peer 1");
    lp.peers[0].restart(1).unwrap();
    assert!(!held(&mut lp, 0), "the value lost at a restart: X released");
    give(&mut lp, 1, 0);
    lp.sync(1, 0).unwrap();
    assert!(held(&mut lp, 0), "peer 1 gives the value back: X held again");
    lp.peers[0].restart(2).unwrap();
    lp.peers[1].restart(3).unwrap();
    lp.sync_all().unwrap();
    assert!(!held(&mut lp, 0) && !held(&mut lp, 1), "every holder restarted: X released at both");
}

// spec/commits.md §5 What a held thing needs, spec/data-model.md §8 Held history: a strong in
// held history needs its target as a current one does. Peer 0's T keeps history holding its
// targets; its strong to account Q (peer 1, never entered) removed, Q's chain stays while the
// adding body is held.
#[test]
fn a_strong_in_held_history_needs_its_target_spec_commits_5() {
    let mut lp = LocalPeer::new_apart(2, 0, crate::common::T0).unwrap();
    let q = lp.peers[1].engine.tid();
    let theirs: Vec<_> = lp.peers[1].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 1, 0, &theirs);
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.node_root().unwrap();
    let t = make(e0, d0, d0);
    let keep = osis_schema::History::Keep { until: None, after: Some(10 * 60_000) };
    let mut m = Mutation::new();
    m.set(t, &ct::RETENTION, &ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(keep), ..Default::default() }), history_holds_targets: true, ..Default::default() }).unwrap();
    e0.commit(m).unwrap();
    strong(e0, t, q, true);
    strong(e0, t, q, false);
    e0.settle_needs().unwrap();
    e0.settle_needs().unwrap();
    assert!(e0.core.created(&q).is_some(), "the strong in T's history keeps Q's chain");
}

// spec/sync-set.md §3 Release, spec/commits.md §5 (any other commit keeps its header: a held leftover is a part): one
// commit writes X's register and puts an element on held T's list, expiring; past its expiry
// both parts are leftovers (T's list without the element). X leaves the node
// closure and is released: the commit loses X's part only, so T reads as its held bodies give
// (the debug rebuild check of the release's transaction). Fails when a commit whose blob keeps
// no part is forgotten whole (a leftover is held outside the blob's parts).
#[test]
fn a_release_keeps_the_leftover_of_a_commit_on_a_thing_still_held_spec_sync_set_3() {
    let (mut lp, _) = people(1);
    let d = lp.peers[0].engine.node_root().unwrap();
    let (x, t) = (make(&mut lp.peers[0].engine, d, d), make(&mut lp.peers[0].engine, d, d));
    let now = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.set(x, &crate::common::REG, &Value::Str("v".into())).unwrap();
    m.set(t, &crate::common::LIST, &Value::List(vec![Value::Str("e".into())])).unwrap();
    m.expires_all(osis_base::Time(now + 1_000));
    lp.peers[0].engine.commit(m).unwrap();
    lp.advance(2_000);
    lp.peers[0].tick().unwrap();
    let e = &mut lp.peers[0].engine;
    strong(e, d, x, false);
    e.released(&[x].into()).unwrap();
    assert!(!e.closure_holds(&x));
    e.check_index();
}

// spec/commits.md §5 What a held thing needs (held for itself: a retained copy), spec/sync-set.md
// §3 Release: a retained copy stays once released. Peer 0 makes X, and Y with admin X (X's strong to
// it), and grants peer 1 read on X, which peer 1 holds. Peer 0 removes peer 1 saying retain: peer
// 1 drops X's secrets and keeps a copy, X leaves its node closure and is released; at the pass's
// end X and Y still read as they did.
#[test]
fn a_retained_copy_stays_once_released_spec_commits_5() {
    let (mut lp, ps) = people(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    let e0 = &mut lp.peers[0].engine;
    let y = make(e0, x, x);
    let mut m = Mutation::new();
    m.set(y, &crate::common::REG, &Value::Str("y".into())).unwrap();
    e0.commit(m).unwrap();
    e0.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    crate::flows::spread(&mut lp);
    let reg = crate::common::ak("t:reg.0");
    let before = [x, y].map(|t| lp.peers[1].engine.get(&t, &reg).unwrap());
    assert!(before.iter().all(Option::is_some), "peer 1 reads X and Y");
    lp.peers[0].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: Some(true) }).unwrap();
    crate::flows::spread(&mut lp);
    let e1 = &mut lp.peers[1].engine;
    e1.role_duties().unwrap();
    assert_eq!(e1.kept_copies(), vec![x], "a copy of X kept");
    let left: BTreeSet<Tid> = e1.left_closure().into_keys().collect();
    assert!(left.contains(&x), "X left the node closure");
    e1.released(&left).unwrap();
    e1.settle_needs().unwrap();
    assert_eq!([x, y].map(|t| e1.get(&t, &reg).unwrap()), before, "the copy reads as it did: {}", e1.why_kept(&y));
}

// spec/sync-set.md §3 Release, spec/commits.md §5 (a released thing; Covered): a release judges
// each commit it reaches on the held set as it stood, never on what forgetting another changed.
// Peer 1 keeps a retained copy of X and releases Y: its writes on Y alone go whole, and one
// writing Y and X (its X part dropped as covered, so judged by whether X's copy would take it
// back) is judged though others went first. Failed reading the walk behind the held set (an
// engine assert).
#[test]
fn a_release_judges_every_commit_on_the_held_set_before_it_spec_sync_set_3() {
    let (mut lp, ps) = people(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    let y = crate::flows::thing_of(&mut lp, 0, ps[0]);
    let e0 = &mut lp.peers[0].engine;
    for t in [x, y] {
        e0.grant(&t, &ps[1], &crate::flows::grant_of(osis_base::Role::Write)).unwrap();
    }
    crate::flows::spread(&mut lp);
    let reg = crate::common::ak("t:reg.0");
    let e1 = &mut lp.peers[1].engine;
    let mut m = Mutation::new();
    m.set(y, &crate::common::REG, &Value::Str("y".into())).unwrap();
    m.set(x, &crate::common::REG, &Value::Str("x".into())).unwrap();
    let both = e1.commit(m).unwrap().unwrap();
    // writes on Y alone, one ordered before it (forgotten first)
    let mut n = 0;
    while !e1.commit_ids().iter().any(|c| *c < both && e1.header(c).is_some_and(|h| h.signer == ps[1] && h.aspects.iter().all(|a| a.tid == y))) {
        let mut m = Mutation::new();
        m.set(y, &crate::common::REG, &Value::Str(format!("y{n}"))).unwrap();
        e1.commit(m).unwrap();
        n += 1;
    }
    crate::flows::spread(&mut lp);
    lp.peers[0].engine.snapshot(&x, &reg).unwrap().unwrap();
    lp.peers[0].engine.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: Some(true) }).unwrap();
    crate::flows::spread(&mut lp);
    let e1 = &mut lp.peers[1].engine;
    e1.drop_body(&both, &x, &reg).unwrap();
    e1.role_duties().unwrap();
    assert_eq!(e1.kept_copies(), vec![x], "a copy of X kept");
    e1.unhold(osis_base::Strong(y)).unwrap();
    let left: BTreeSet<Tid> = e1.left_closure().into_keys().collect();
    assert!(left.contains(&x) && left.contains(&y), "X and Y left the node closure");
    e1.released(&left).unwrap();
    e1.settle_needs().unwrap();
    assert!(e1.get(&y, &reg).unwrap().is_none(), "Y released: {}", e1.why_kept(&y));
}

// spec/commits.md §5 What a held thing needs (held for itself: under an own self-removal still to
// be sealed), spec/permissions.md §3 Lost access: a thing released while the node's own leave from
// it waits to be held elsewhere keeps that leave, so it still reaches the others. Peer 1 reads and
// holds peer 0's X, leaves it and stops holding it; X is released before the leave is held
// elsewhere. At the pass's end peer 1 still holds the leave, and peer 0 applies it once it arrives.
#[test]
fn a_release_keeps_an_own_leave_still_waiting_spec_commits_5() {
    let (mut lp, ps) = people(2);
    let x = crate::flows::thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    crate::flows::spread(&mut lp);
    let e1 = &mut lp.peers[1].engine;
    let c = e1.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    assert!(e1.waiting_removals().contains(&c), "the leave waits");
    e1.unhold(osis_base::Strong(x)).unwrap();
    let left: BTreeSet<Tid> = e1.left_closure().into_keys().collect();
    assert!(left.contains(&x), "X left the node closure");
    e1.released(&left).unwrap();
    e1.settle_needs().unwrap();
    assert!(e1.commit_ids().contains(&c), "the leave stays: {}", e1.why_kept(&x));
    crate::flows::send_carried(&mut lp, 1, 0, &[c]);
    assert!(!lp.peers[0].engine.roster(&x).contains_key(&ps[1]), "peer 0 applies the leave");
}

/// Peer 0's thing X (minted by its account), read by peer 1's account, which holds it from its
/// root and took what X's sync IDs carry: built once (`LocalPeer::cached`).
fn x_read_at_1() -> (LocalPeer, Tid) {
    LocalPeer::cached("closure::x_read_at_1", || {
        let (mut lp, ps) = people(2);
        let e0 = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let x = e0.new_thing(&mut m, ps[0]);
        e0.commit(m).unwrap();
        e0.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
        let d1 = lp.peers[1].engine.node_root().unwrap();
        strong(&mut lp.peers[1].engine, d1, x, true);
        let all = lp.peers[0].engine.commit_ids();
        crate::flows::send_carried(&mut lp, 0, 1, &all);
        crate::flows::send_carried(&mut lp, 0, 1, &all);
        pass_end(&mut lp.peers[1].engine);
        assert!(lp.peers[1].engine.closure_holds(&x));
        (lp, x)
    })
}

/// Peer 0's commits, all sent to peer 1 again (a pull from the start), when peer 1 pulled a sync
/// ID anew or a sync ID joined its sync set since `before`: what node-sync would fetch.
fn pull_again(lp: &mut LocalPeer, before: &BTreeSet<osis_base::SyncId>) -> bool {
    lp.peers[1].reexamine().unwrap();
    let now = synced(lp);
    let pulled = !std::mem::take(&mut lp.peers[1].pulled_anew).is_empty() || now.difference(before).next().is_some();
    if pulled {
        let all = lp.peers[0].engine.commit_ids();
        crate::flows::send_carried(lp, 0, 1, &all);
    }
    pulled
}

fn synced(lp: &mut LocalPeer) -> BTreeSet<osis_base::SyncId> {
    lp.peers[1].engine.sync_set().unwrap().ids.keys().copied().collect()
}

/// Of `ids`, what peer `e` holds: each held header with the parts it holds.
fn parts_held(e: &Engine, ids: &BTreeSet<osis_base::CommitId>) -> BTreeMap<osis_base::CommitId, Vec<bool>> {
    ids.iter().filter_map(|c| e.core.ix.commits.get(c).map(|m| (*c, (0..m.view.aspects.len()).map(|ai| m.holds(ai)).collect()))).collect()
}

/// Peer 0 makes Y (register "y") and X with mint admin Y (register "x"), and grants peer 1 read on
/// both; every commit reaches peer 1 (`n` things of its own held first), which holds X by its
/// node root's strong, and Y too when `y_too`; the pass ends. Y outside peer 1's node closure
/// is needed as X's mint admin.
fn minted_with_y(n: usize, y_too: bool) -> (LocalPeer, Tid, Tid) {
    let (mut lp, ps) = people(2);
    let d1 = lp.peers[1].engine.node_root().unwrap();
    for _ in 0..n {
        make(&mut lp.peers[1].engine, d1, d1);
    }
    let e0 = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let y = e0.new_thing(&mut m, ps[0]);
    m.set(y, &crate::common::REG, &Value::Str("y".into())).unwrap();
    e0.commit(m).unwrap();
    let mut m = Mutation::new();
    let x = e0.new_thing(&mut m, y);
    m.set(x, &crate::common::REG, &Value::Str("x".into())).unwrap();
    e0.commit(m).unwrap();
    for t in [y, x] {
        e0.grant(&t, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    }
    let e1 = &mut lp.peers[1].engine;
    strong(e1, d1, x, true);
    if y_too {
        strong(e1, d1, y, true);
    }
    // what the sync IDs it comes to sync carry: twice, as the grants move them
    let all = lp.peers[0].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    lp.peers[1].pulled_anew.clear();
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.closure_holds(&x) && e1.closure_holds(&y) == y_too, "{}", e1.why_kept(&y));
    (lp, x, y)
}

// spec/commits.md §5 What a held thing needs (never its content, whether or not it was ever in the
// node closure): Y, outside peer 1's node closure and needed as X's mint admin, shows and holds the
// same whether peer 1 held it for a while first or never: its record and role commits, no content.
#[test]
fn a_thing_once_in_the_node_closure_holds_as_one_never_in_it_spec_commits_5() {
    let reg = crate::common::ak("t:reg.0");
    let (mut never, _, y) = minted_with_y(0, false);
    let (mut once, _, _) = minted_with_y(0, true);
    assert_eq!(once.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "held, Y reads");
    let d1 = once.peers[1].engine.node_root().unwrap();
    strong(&mut once.peers[1].engine, d1, y, false);
    pass_end(&mut once.peers[1].engine);
    let ids: BTreeSet<osis_base::CommitId> = never.peers[0].engine.commit_ids().into_iter().collect();
    let [a, b] = [&mut never, &mut once].map(|lp| {
        let e = &mut lp.peers[1].engine;
        assert!(!e.closure_holds(&y) && e.core.created(&y).is_some(), "Y's record kept: {}", e.why_kept(&y));
        assert_eq!(e.get(&y, &reg).unwrap(), None, "no content of Y");
        (crate::judgment::observe(e, &ids), parts_held(e, &ids))
    });
    assert_eq!(a, b, "never in the node closure, then once in it");
}

// spec/sync-judgement.md §3 Dropped bodies: a thing whose record stays held outside the node
// closure, entering it again, is pulled anew and its content comes back. Peer 0 makes X, and Y and
// Z dependent in X's sync unit (X's strongs hold both; Y is Z's mint admin, Y's X's), and grants
// peer 1 read on X, which it holds. Peer 0 removes X's strong to Y: Y, still needed as Z's mint
// admin, is released to its certificates. Peer 0 adds the strong back: no sync ID joins (Y's
// bodies go under X's), so X's sync IDs are pulled anew, and Y reads again.
#[test]
fn a_thing_entering_again_with_its_record_held_is_pulled_anew_spec_sync_judgement_3() {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, ps) = people(2);
    let e0 = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let x = e0.new_thing(&mut m, ps[0]);
    m.set(x, &crate::common::REG, &Value::Str("x".into())).unwrap();
    e0.commit(m).unwrap();
    let y = make(e0, x, x);
    let z = make(e0, y, x);
    let mut m = Mutation::new();
    m.set(y, &crate::common::REG, &Value::Str("y".into())).unwrap();
    e0.commit(m).unwrap();
    e0.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    let d1 = lp.peers[1].engine.node_root().unwrap();
    strong(&mut lp.peers[1].engine, d1, x, true);
    let all = lp.peers[0].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    pass_end(&mut lp.peers[1].engine);
    assert!(lp.peers[1].engine.closure_holds(&z), "Z in X's sync unit");
    assert_eq!(lp.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "Y in X's sync unit reads");
    let before = lp.peers[0].engine.commit_ids();
    strong(&mut lp.peers[0].engine, x, y, false);
    let cut: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    crate::flows::send_carried(&mut lp, 0, 1, &cut);
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.closure_holds(&y) && e1.core.created(&y).is_some(), "Y outside, its record kept: {}", e1.why_kept(&y));
    assert_eq!(e1.get(&y, &reg).unwrap(), None, "Y's content went at the release");
    lp.peers[1].pulled_anew.clear();
    let was = synced(&mut lp);
    let before = lp.peers[0].engine.commit_ids();
    strong(&mut lp.peers[0].engine, x, y, true);
    let back: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    crate::flows::send_carried(&mut lp, 0, 1, &back);
    assert!(lp.peers[1].engine.closure_holds(&y), "Y back in X's sync unit");
    assert_eq!(synced(&mut lp), was, "no sync ID joins");
    assert!(pull_again(&mut lp, &was), "Y's entry pulls anew");
    pass_end(&mut lp.peers[1].engine);
    assert_eq!(lp.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "Y's content back");
}

// spec/sync-judgement.md §3 Dropped bodies (the exemption is a minting held nothing of, not a commit
// held nothing of): as `a_thing_entering_again_with_its_record_held_is_pulled_anew`, but the commit
// adding X's strong back mints Y again (a minting needs no authority, spec/commits.md §5). Peer 1
// held nothing of that commit, but held Y's first minting while Y's content went: Y is pulled anew
// and its content comes back. Fails where any commit held nothing of exempts the things it mints.
#[test]
fn a_thing_minted_again_with_the_strong_back_is_pulled_anew_spec_sync_judgement_3() {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, ps) = people(2);
    let e0 = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let x = e0.new_thing(&mut m, ps[0]);
    m.set(x, &crate::common::REG, &Value::Str("x".into())).unwrap();
    e0.commit(m).unwrap();
    let y = make(e0, x, x);
    make(e0, y, x);
    let mut m = Mutation::new();
    m.set(y, &crate::common::REG, &Value::Str("y".into())).unwrap();
    e0.commit(m).unwrap();
    e0.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
    let d1 = lp.peers[1].engine.node_root().unwrap();
    strong(&mut lp.peers[1].engine, d1, x, true);
    let all = lp.peers[0].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    pass_end(&mut lp.peers[1].engine);
    assert_eq!(lp.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "Y in X's sync unit reads");
    let before = lp.peers[0].engine.commit_ids();
    strong(&mut lp.peers[0].engine, x, y, false);
    let cut: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    crate::flows::send_carried(&mut lp, 0, 1, &cut);
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.closure_holds(&y) && !e1.mintings_of(&y).is_empty(), "Y outside, its minting held: {}", e1.why_kept(&y));
    assert_eq!(e1.get(&y, &reg).unwrap(), None, "Y's content went at the release");
    lp.peers[1].pulled_anew.clear();
    let was = synced(&mut lp);
    let before = lp.peers[0].engine.commit_ids();
    let e0 = &mut lp.peers[0].engine;
    let rec = e0.core.created(&y).unwrap().clone();
    let mut m = Mutation::new();
    m.create(rec);
    m.op(x, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(y)) }).unwrap();
    // peer 0 holds Y: it mints again only past its writer rules, as a hostile writer would
    e0.core.skip_writer_rules = true;
    e0.commit(m).unwrap().unwrap();
    e0.core.skip_writer_rules = false;
    let back: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    assert_eq!(back.len(), 1, "one commit mints Y again and adds the strong");
    assert_eq!(lp.peers[0].engine.mintings_of(&y).len(), 2, "Y minted twice");
    crate::flows::send_carried(&mut lp, 0, 1, &back);
    assert!(lp.peers[1].engine.closure_holds(&y), "Y back in X's sync unit");
    assert!(pull_again(&mut lp, &was), "Y's entry pulls anew");
    pass_end(&mut lp.peers[1].engine);
    assert_eq!(lp.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "Y's content back");
}

// spec/sync-judgement.md §3 Dropped bodies (nothing of the thing forgotten since): a release ends
// the exemption of the pass that brought a thing's minting. Peer 1 holds X; peer 0 makes Y in X's
// sync unit with a value and Z with mint admin Y (Y stays needed outside the node closure), then
// removes X's strong to Y and adds it back. In one pass peer 1 takes Y's making, the removal,
// releases Y (its content goes) and takes the strong back: Y is pulled anew and its content comes
// back. Fails where the exemption outlives a release within the pass.
#[test]
fn a_thing_released_in_the_pass_that_brought_it_is_pulled_anew_spec_sync_judgement_3() {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, x) = x_read_at_1();
    let since = |lp: &LocalPeer, seen: &[osis_base::CommitId]| -> Vec<osis_base::CommitId> { lp.peers[0].engine.commit_ids().into_iter().filter(|c| !seen.contains(c)).collect() };
    let seen = lp.peers[0].engine.commit_ids();
    let (y, _) = crate::common::mint_from(&mut lp.peers[0].engine, x, x, &[(&crate::common::REG, "y")]);
    make(&mut lp.peers[0].engine, y, x);
    let made = since(&lp, &seen);
    let seen = lp.peers[0].engine.commit_ids();
    strong(&mut lp.peers[0].engine, x, y, false);
    let removal = since(&lp, &seen);
    let seen = lp.peers[0].engine.commit_ids();
    strong(&mut lp.peers[0].engine, x, y, true);
    let back = since(&lp, &seen);
    lp.peers[1].pulled_anew.clear();
    let was = synced(&mut lp);
    crate::flows::send_carried(&mut lp, 0, 1, &made);
    assert_eq!(lp.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "Y in X's sync unit reads");
    assert!(lp.peers[1].pulled_anew.is_empty(), "Y's minting came with the strong");
    crate::flows::send_carried(&mut lp, 0, 1, &removal);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.closure_holds(&y), "Y left X's sync unit");
    e1.released(&[y].into()).unwrap();
    assert!(!e1.mintings_of(&y).is_empty(), "Y's minting kept: {}", e1.why_kept(&y));
    assert_eq!(e1.get(&y, &reg).unwrap(), None, "Y's content went at the release");
    crate::flows::send_carried(&mut lp, 0, 1, &back);
    assert!(lp.peers[1].engine.closure_holds(&y), "Y back in X's sync unit");
    assert!(pull_again(&mut lp, &was), "Y's entry pulls anew");
    pass_end(&mut lp.peers[1].engine);
    assert_eq!(lp.peers[1].engine.get(&y, &reg).unwrap(), Some(Value::Str("y".into())), "Y's content back");
}

// spec/sync-judgement.md §3 Dropped bodies (nothing of the thing forgotten since): a part waiting on
// a thing outside the node closure that goes with its commit, forgotten whole at another thing's
// release, ends the exemption too. Peer 1 holds X and V in X's sync unit; peer 0 mints W with X's
// strong (C), writes V and W in one commit (D) and removes X's strong to V. In one pass peer 1 takes
// C's part on W (W minted, outside the node closure), D (its part on V applies, on W waits), the
// removal and V's release (D forgotten whole, its part on W with it), then C's part on X: W enters,
// is pulled anew, and D's write on W comes back. Fails where only the released things leave the
// exemption.
#[test]
fn a_part_waiting_on_a_thing_that_goes_with_its_commit_is_pulled_anew_spec_sync_judgement_3() {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, x) = x_read_at_1();
    let (v, mv) = crate::common::mint_from(&mut lp.peers[0].engine, x, x, &[(&crate::common::REG, "v")]);
    crate::flows::send_carried(&mut lp, 0, 1, &[mv]);
    pass_end(&mut lp.peers[1].engine);
    assert!(lp.peers[1].engine.closure_holds(&v), "V in X's sync unit");
    let e0 = &mut lp.peers[0].engine;
    let (w, c) = crate::common::mint_from(e0, x, x, &[(&crate::common::REG, "w")]);
    let mut m = Mutation::new();
    m.set(v, &crate::common::REG, &Value::Str("v2".into())).unwrap();
    m.set(w, &crate::common::REG, &Value::Str("w2".into())).unwrap();
    let d = e0.commit(m).unwrap().unwrap();
    let seen = lp.peers[0].engine.commit_ids();
    strong(&mut lp.peers[0].engine, x, v, false);
    let removal: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|id| !seen.contains(id)).collect();
    let cp = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let c_blob = osis_commit::CommitBlob::decode(&cp.bytes).unwrap();
    let on = |t: Tid| osis_commit::rewrite(&c_blob, |ai| c_blob.header.aspects[ai].tid != t).encode();
    lp.peers[1].pulled_anew.clear();
    let was = synced(&mut lp);
    drop(lp.peers[1].receive(&on(w), cp.blobs.clone()));
    assert!(!lp.peers[1].engine.closure_holds(&w), "W minted outside the node closure");
    let dp = lp.peers[0].engine.package(&d).unwrap().unwrap();
    drop(lp.peers[1].receive(&dp.bytes, dp.blobs.clone()));
    assert!(lp.peers[1].engine.pends(&d), "D's part on W waits");
    assert_eq!(lp.peers[1].engine.get(&v, &reg).unwrap(), Some(Value::Str("v2".into())), "D's part on V applies");
    crate::flows::send_carried(&mut lp, 0, 1, &removal);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.closure_holds(&v), "V left X's sync unit");
    e1.released(&[v].into()).unwrap();
    assert!(e1.header(&d).is_none() && !e1.pends(&d), "D forgotten whole with V's release");
    drop(lp.peers[1].receive(&on(x), cp.blobs.clone()));
    assert!(lp.peers[1].engine.closure_holds(&w), "W in X's sync unit");
    assert!(pull_again(&mut lp, &was), "W's entry pulls anew");
    pass_end(&mut lp.peers[1].engine);
    assert_eq!(lp.peers[1].engine.get(&w, &reg).unwrap(), Some(Value::Str("w2".into())), "D's write on W back");
}

// spec/commits.md §4 Outside the node closure, Pending storage: one commit of peer 0 writes Y,
// outside peer 1's node closure, and X, in it; peer 1 gets its part on Y alone: that part waits for
// Y to enter, so the commit pends whole (its every held part waits) and Y reads nothing. Peer 1
// holds Y's minting commit, so it judges Y in no sync unit it syncs: at the pass end the part is
// not carried and counts as never received. The whole copy then applies its part on X; the part
// on Y waits again and goes again.
#[test]
fn a_part_outside_the_node_closure_waits_beside_one_in_it_spec_commits_4() {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, x, y) = minted_with_y(0, false);
    let mut m = Mutation::new();
    m.set(y, &crate::common::REG, &Value::Str("y2".into())).unwrap();
    m.set(x, &crate::common::REG, &Value::Str("x2".into())).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let mut b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let on_x = b.header.aspects.iter().position(|a| a.tid == x).unwrap();
    b.parts.retain(|p| p.ai != on_x);
    let r = &mut lp.peers[1];
    r.receive(&b.encode(), pk.blobs.clone()).unwrap();
    assert_eq!(r.engine.get(&y, &reg).unwrap(), None, "the part on Y waits");
    assert!(r.engine.pending().iter().any(|p| p.0 == c), "the commit pends: its every held part waits");
    pass_end(&mut r.engine);
    assert!(!r.engine.pends(&c) && r.engine.header(&c).is_none(), "not carried: never received");
    r.receive(&pk.bytes, pk.blobs.clone()).unwrap();
    assert!(r.engine.pends(&c), "the part on Y waits");
    pass_end(&mut r.engine);
    assert_eq!(r.engine.get(&x, &reg).unwrap(), Some(Value::Str("x2".into())), "X reads the commit");
    assert_eq!(r.engine.get(&y, &reg).unwrap(), None, "Y still none");
    assert!(!r.engine.pends(&c), "the part on Y not carried");
}

// spec/sync-set.md §2 Cost, spec/commits.md §4 Outside the node closure, Pending storage, §5 What
// a held thing needs: the pass end judges the things due alone, a wake examines what waits on the
// thing entering alone. With n and 10n things of its own held, peer 1 takes a write on Y (outside
// its node closure, from a source whose view puts Y in a sync unit peer 1 syncs: it waits), then holds Y (pulled anew; the write woken and applied) and
// releases it; a second write on Y then waits until the pass end, which judges Y in no sync unit
// peer 1 syncs (it holds Y's minting commit): not carried, it goes. Each step counts the same work.
#[test]
#[ignore = "issues/node-root-independent.md"]
fn waiting_and_pulling_anew_cost_the_thing_not_the_node_closure_spec_commits_5() {
    let work = |n: usize| {
        let (mut lp, _, y) = minted_with_y(n, false);
        let d1 = lp.peers[1].engine.node_root().unwrap();
        // a source whose view puts Y in a sync unit peer 1 syncs sends its writes whole
        let give = |lp: &mut LocalPeer, c: &osis_base::CommitId| {
            let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        };
        let write = |lp: &mut LocalPeer, v: &str| {
            let mut m = Mutation::new();
            m.set(y, &crate::common::REG, &Value::Str(v.into())).unwrap();
            lp.peers[0].engine.commit(m).unwrap().unwrap()
        };
        let c = write(&mut lp, "y2");
        let counted = |lp: &mut LocalPeer, f: &dyn Fn(&mut LocalPeer)| {
            osis_base::costs::take();
            f(lp);
            osis_base::costs::take().into_iter().map(|(k, _, c)| (k, c)).collect::<BTreeMap<_, _>>()
        };
        let wait = counted(&mut lp, &|lp| give(lp, &c));
        assert_eq!(lp.peers[1].engine.get(&y, &crate::common::ak("t:reg.0")).unwrap(), None, "n {n}: it waits");
        assert!(lp.peers[1].engine.pends(&c), "n {n}: it waits");
        let enter = counted(&mut lp, &|lp| {
            let e1 = &mut lp.peers[1].engine;
            let mut m = Mutation::new();
            m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(y)) }).unwrap();
            e1.commit(m).unwrap();
        });
        assert!(lp.peers[1].engine.closure_holds(&y), "n {n}: entered");
        assert_eq!(lp.peers[1].engine.get(&y, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("y2".into())), "n {n}: the write joins as Y enters");
        let release = counted(&mut lp, &|lp| {
            let e1 = &mut lp.peers[1].engine;
            let mut m = Mutation::new();
            m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Remove(Value::Strong(y)) }).unwrap();
            e1.commit(m).unwrap();
            e1.released(&[y].into()).unwrap();
            e1.settle_needs().unwrap();
        });
        let c2 = write(&mut lp, "y3");
        let gone = counted(&mut lp, &|lp| {
            give(lp, &c2);
            lp.peers[1].engine.settle_needs().unwrap();
        });
        assert!(!lp.peers[1].engine.pends(&c2) && lp.peers[1].engine.header(&c2).is_none(), "n {n}: not carried, never received");
        (wait, enter, release, gone)
    };
    let (small, large) = (work(5), work(50));
    eprintln!("wait, enter, release, gone at n, 10n:\n{small:?}\n{large:?}");
    assert!(small.3.get("needed: things due").is_some_and(|c| *c > 0), "a thing judged");
    assert!(small.1.get("sync IDs pulled anew").is_some_and(|c| *c > 0), "pulled anew on entry");
    assert_eq!(small, large);
}

/// An order's end (`record_with_strong`): its name, its pulls anew, what it shows and holds.
type End = (String, usize, Vec<(String, String)>, BTreeMap<osis_base::CommitId, Vec<bool>>);

/// Peer 0's commit C mints W (a register on it) with X's strong to it, and a later commit D
/// writes W again; peer 1 holds X. Peer 1 takes C and D in each of `orders` (a step: C whole, C's
/// part on W, C's part on X, D, a restart, or a pass end), and once what it pulled anew is given
/// again, what it holds and shows of C and D, with how many pulls each took.
fn record_with_strong(orders: &[&[&str]]) -> Vec<End> {
    let (mut lp, (w, d, steps, blobs, ids, sx, record)) = LocalPeer::cached("closure::record_with_strong", || {
        let (mut lp, ps) = people(2);
        let e0 = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let x = e0.new_thing(&mut m, ps[0]);
        m.set(x, &crate::common::REG, &Value::Str("x".into())).unwrap();
        e0.commit(m).unwrap();
        e0.grant(&x, &ps[1], &crate::flows::grant_of(osis_base::Role::Read)).unwrap();
        let all = lp.peers[0].engine.commit_ids();
        crate::flows::send_carried(&mut lp, 0, 1, &all);
        let d1 = lp.peers[1].engine.node_root().unwrap();
        strong(&mut lp.peers[1].engine, d1, x, true);
        pass_end(&mut lp.peers[1].engine);
        let e0 = &mut lp.peers[0].engine;
        let (w, c) = crate::common::mint_from(e0, x, x, &[(&crate::common::REG, "w")]);
        let mut m = Mutation::new();
        m.set(w, &crate::common::LIST, &Value::List(vec![Value::Str("d".into())])).unwrap();
        let d = e0.commit(m).unwrap().unwrap();
        let pk = |lp: &mut LocalPeer, id| lp.peers[0].engine.package(&id).unwrap().unwrap();
        let (cp, dp) = (pk(&mut lp, c), pk(&mut lp, d));
        let c_blob = osis_commit::CommitBlob::decode(&cp.bytes).unwrap();
        let on = |t: Tid| osis_commit::rewrite(&c_blob, |ai| c_blob.header.aspects[ai].tid != t).encode();
        let steps: BTreeMap<&str, Vec<u8>> = [("C", cp.bytes.clone()), ("C on W", on(w)), ("C on X", on(x)), ("D", dp.bytes.clone())].into();
        let blobs: Vec<_> = cp.blobs.iter().chain(&dp.blobs).cloned().collect();
        let ids: BTreeSet<osis_base::CommitId> = [c, d].into();
        // W's record alone, as a record blob under X's sync ID (spec/wire.md §3)
        let rec_w = lp.peers[0].engine.core.created(&w).cloned().unwrap();
        let sx = lp.peers[0].engine.sync_id_of(&x).unwrap().unwrap();
        let record = crate::facade::record_blob_by_hand(&mut lp, 0, &x, &[rec_w]);
        (lp, (w, d, steps, blobs, ids, sx, record))
    });
    let mut ends = Vec::new();
    for order in orders {
        let name = order.join(", ");
        let mut lp = lp.copy().unwrap();
        lp.peers[1].reexamine().unwrap();
        lp.peers[1].pulled_anew.clear();
        let was = synced(&mut lp);
        for s in *order {
            match (steps.get(s), *s) {
                (Some(b), _) => drop(lp.peers[1].receive(b, blobs.clone())),
                (None, "restart") => lp.peers[1].restart(0).unwrap(),
                (None, "D gone") => assert!(lp.peers[1].engine.release_entry(&d).unwrap(), "{name}: D pends"),
                (None, "W's record") => drop(lp.peers[1].engine.open_entry(&sx, &record.0, &record.2, &record.1, &[], u64::MAX).unwrap()),
                (None, _) => pass_end(&mut lp.peers[1].engine),
            }
        }
        pass_end(&mut lp.peers[1].engine);
        let mut pulls = 0;
        while pull_again(&mut lp, &was) {
            pulls += 1;
            assert!(pulls < 4, "{name}: still pulling");
            pass_end(&mut lp.peers[1].engine);
        }
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.get(&w, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("w".into())), "{name}: W reads C");
        ends.push((name, pulls, crate::judgment::observe(e, &ids), parts_held(e, &ids)));
    }
    ends
}

// spec/sync-judgement.md §3 Dropped bodies (unless a minting arrived, while none was held, in the
// pass in flight, nothing of the thing forgotten since): a strong newly reaching a thing pulls
// nothing anew when the commit minting it arrives in the same pass, and that changes nothing the
// node ends up holding: C whole, or its part on W in a transaction (or a pass) before its part on
// X, D before or after, end alike. D taken between C's part on W and its part on X waits outside
// the node closure and is still held when the strong comes; once the pass ends or D's last
// carrier goes, it counts as never received and the strong pulls anew. D first
// pends for W's record (spec/commits.md §4 Unjudgeable) and is kept across pass ends and a
// restart while carried (§4 Pending storage, §5 What a held thing needs: W held for itself while
// awaited), so C bringing W's record with the strong, pulling nothing, still finds it.
// spec/commits.md §4 Outside the node closure (carried while the node cannot judge the thing's
// sync units): D, pending, makes W's record learned from a record blob; W is outside the node
// closure, so D's part on W waits, and peer 1, not holding the commit minting W, cannot judge W in
// no sync unit it syncs: D stays across the pass end, and C, bringing W's record again with the
// strong in one transaction and pulling nothing, finds it (the last order).
#[test]
fn a_record_arriving_with_the_strong_pulls_nothing_and_ends_alike_spec_sync_judgement_3() {
    let ends = record_with_strong(&[
        &["C", "D"],
        &["C on W", "C on X", "D"],
        &["C on W", "pass end", "C on X", "D"],
        &["D", "C"],
        &["D", "pass end", "C"],
        &["D", "pass end", "restart", "pass end", "C"],
        &["D", "pass end", "C on W", "pass end", "C on X"],
        &["D", "pass end", "D gone", "pass end", "D", "pass end", "C"],
        &["D", "restart", "C"],
        &["D", "pass end", "C on X", "pass end", "C on W"],
        &["D", "W's record", "C"],
        &["D", "W's record", "pass end", "C"],
        &["C on W", "D", "C on X"],
        &["C on W", "D", "pass end", "C on X"],
        &["C on W", "D", "D gone", "C on X"],
    ]);
    for e in &ends[1..] {
        assert_eq!((&e.2, &e.3), (&ends[0].2, &ends[0].3), "{} ends as {}", e.0, ends[0].0);
    }
    let pulls = |i: usize| ends[i].1;
    assert_eq!((pulls(0), pulls(1), pulls(12)), (0, 0, 0), "C's minting in the pass the strong came in: nothing pulled anew");
    assert!(pulls(2) > 0 && pulls(13) > 0, "the pass that brought C's minting ended first: pulled anew");
    assert!(pulls(14) > 0, "D forgotten within the pass (its carrier gone): pulled anew");
    assert_eq!((pulls(4), pulls(5)), (0, 0), "D first, C whole: nothing pulled anew, D kept pending");
}

// spec/commits.md §4 Pending storage, §5 What a held thing needs (held for itself while awaited):
// peer 0 mints n things W, each with X's strong to it (C), and writes each again (D); peer 1, which
// holds X, is given only the Ds. Each pends for its W's record across pass ends; once the last
// entry carrying one goes (`release_entry`, as sync calls it), the pass end leaves nothing of it
// or its W: what pends is bounded by what is carried (and that, from unvouched input, by the
// sync store's budget per source, osis-sync `a_flood_of_pending_commits_is_bounded_per_peer`).
// The one still carried applies once its C comes.
#[test]
fn a_commit_awaiting_its_record_is_kept_while_carried_and_no_longer_spec_commits_5() {
    let n = 20;
    // what X's sync IDs carry: nothing else waits there (spec/commits.md §4 Outside the node closure)
    let (mut lp, x) = x_read_at_1();
    let mut made = Vec::new();
    for _ in 0..n {
        let e0 = &mut lp.peers[0].engine;
        let (w, c) = crate::common::mint_from(e0, x, x, &[]);
        let mut m = Mutation::new();
        m.set(w, &crate::common::REG, &Value::Str("d".into())).unwrap();
        let d = e0.commit(m).unwrap().unwrap();
        made.push((w, c, d));
    }
    let ds: Vec<_> = made.iter().map(|m| m.2).collect();
    crate::flows::send_carried(&mut lp, 0, 1, &ds);
    pass_end(&mut lp.peers[1].engine);
    lp.peers[1].restart(0).unwrap();
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(ds.iter().all(|d| e1.pends(d)), "each D pends while carried");
    let (kept, gone) = made.split_last().unwrap();
    for (_, _, d) in gone {
        assert!(e1.release_entry(d).unwrap());
    }
    pass_end(e1);
    let awaited = |e: &Engine, w: &Tid| e.core.ix.pend_on.contains_key(&osis_engine::apply::Wake::Record(*w));
    for (w, _, d) in gone {
        assert!(!e1.pends(d) && e1.header(d).is_none(), "an uncarried D goes");
        assert!(!awaited(e1, w) && e1.core.created(w).is_none(), "nothing of its W is kept");
    }
    assert_eq!(e1.pending().len(), 1, "only the carried D pends");
    assert!(awaited(e1, &kept.0));
    crate::flows::send_carried(&mut lp, 0, 1, &[kept.1]);
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pends(&kept.2));
    assert_eq!(e1.get(&kept.0, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("d".into())), "the carried D applies with its record");
}

// spec/commits.md §5 What a held thing needs (certificates: its record, its role-class parts):
// peer 0's account D, kept at peer 1 as X's mint admin outside its node closure, keeps its
// role-class parts (`keys.0`) and none of its content (`holds.0`).
#[test]
fn a_needed_account_keeps_its_role_class_parts_alone_spec_commits_5() {
    let (mut lp, d) = held_minted_with_d();
    let [keys, holds] = ["keys.0", "holds.0"].map(|a| osis_base::Ak::new(a).unwrap());
    let theirs = lp.peers[0].engine.get(&d, &keys).unwrap();
    assert!(theirs.is_some(), "D carries keys.0");
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.get(&d, &keys).unwrap(), theirs, "keys.0 kept");
    assert_eq!(e1.get(&d, &holds).unwrap(), None, "no content of D");
}

// spec/commits.md §4 Outside the node closure (the node closure judged as the transaction leaves
// it): peer 0's C mints W with X's strong to it and a write on W; peer 1, holding X, takes C in one
// transaction: the part on W waits at examination, W enters at the settle, and the part joins in
// that transaction, so C applies whole before any pass end, nothing of it pending, examined once
// more.
#[test]
fn a_commit_minting_with_the_strong_applies_whole_in_its_transaction_spec_commits_4() {
    let (mut lp, x) = x_read_at_1();
    let (w, c) = crate::common::mint_from(&mut lp.peers[0].engine, x, x, &[(&crate::common::REG, "w")]);
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let before = lp.peers[1].engine.examined();
    lp.peers[1].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.closure_holds(&w), "W entered");
    assert!(!e1.pends(&c), "nothing of C waits");
    assert_eq!(e1.get(&w, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("w".into())), "C's part on W joined in its transaction");
    assert_eq!(e1.examined() - before, 1, "the waiting part examined once more");
}

// spec/commits.md §4 Pending storage, Outside the node closure, spec/sync-judgement.md §3: every
// order of D, W's record blob and C (whole, or its part on W before its part on X), a pass end
// between steps and a restart after the first, ends as C then D: W shows C and D, the same parts held
// (`record_with_strong`). Orders with no step between: `a_record_arriving_with_the_strong_*`.
#[test]
fn every_order_of_a_commit_its_record_and_its_minting_ends_alike_spec_commits_4() {
    let cs: [&[&str]; 2] = [&["C"], &["C on W", "C on X"]];
    let mut orders: Vec<Vec<&str>> = vec![vec!["C", "D"]];
    for c in cs {
        let items: [&[&str]; 3] = [&["D"], &["W's record"], c];
        for p in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let mut o: Vec<&str> = Vec::new();
            for s in p.iter().flat_map(|i| items[*i].iter()) {
                match o.len() {
                    0 => {}
                    1 => o.extend(["restart", "pass end"]),
                    _ => o.push("pass end"),
                }
                o.push(s);
            }
            orders.push(o);
        }
    }
    let refs: Vec<&[&str]> = orders.iter().map(|o| o.as_slice()).collect();
    let ends = record_with_strong(&refs);
    let first = &ends[0];
    for e in &ends[1..] {
        assert_eq!((&e.2, &e.3), (&first.2, &first.3), "{} ends as {}", e.0, first.0);
    }
}

// spec/sync-set.md §2 (The local part's log; First entry): a signal then a reference. Peer 0
// makes T and grants peer 1's node thing read, signalling it; peer 1 follows the signal (T's
// stub), then its node root strongs T: the local part carries T, logged there while the signal
// gave T's role entries. The signal then goes (its fire past the inbox's lifetime): T stays held,
// the log carrying it, and stays so across a restart (held-model
// `entry_a_signal_then_a_reference_outlives_the_signal`). Fails with the log kept nowhere: T
// leaves with the signal.
#[test]
fn a_signal_then_a_reference_outlives_the_signal_spec_sync_set_2() {
    let mut lp = LocalPeer::fresh(2, crate::common::T0);
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &crate::common::REG, &Value::Str("new".into())).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.hold_at(0, t);
    let who = lp.peers[1].engine.tid();
    lp.peers[0].engine.grant(&t, &who, &crate::common::grant(osis_base::Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert!(!lp.peers[1].engine.closure_holds(&t), "the signal alone: a stub");
    lp.hold_at(1, t);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.closure_holds(&t), "the signal and the reference: T");
    lp.advance(osis_base::format::INBOX_LIFETIME_MS + 3_600_000);
    lp.peers[1].tick().unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.closure_holds(&t), "the signal gone: T held, logged");
    lp.peers[1].restart(7).unwrap();
    lp.peers[1].engine.check_closure();
    assert!(lp.peers[1].engine.closure_holds(&t), "and after a restart");
    assert_eq!(lp.peers[1].engine.get(&t, &crate::common::REG.name()).unwrap(), Some(Value::Str("new".into())));
}
