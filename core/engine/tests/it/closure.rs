//! The node closure (spec/sync-set.md §1-§3): what the node root reaches by strongs, sync unit
//! by sync unit, what left it, and what its changes cost.

use crate::flows::people;
use osis_base::{Tid, Value};
use std::collections::{BTreeMap, BTreeSet};
use osis_crdt::{Op, PathOp};
use osis_engine::{Engine, Mutation};
use osis_schema::core_types as ct;

/// Writes (`on`) or removes a strong from `from`'s `holds.0` to `to`.
fn strong(e: &mut Engine, from: Tid, to: Tid, on: bool) {
    let v = Value::Strong(to);
    let mut m = Mutation::new();
    m.op(from, &ct::HOLDS, PathOp { path: vec![], op: if on { Op::Add(v) } else { Op::Remove(v) } }).unwrap();
    e.commit(m).unwrap();
    e.check_closure();
}

/// A plain thing made under `admin`, strongly referenced from `from` in the same transaction.
fn make(e: &mut Engine, admin: Tid, from: Tid) -> Tid {
    let rec = e.thing_record(admin);
    let mut m = Mutation::new();
    let t = m.create(rec);
    m.op(from, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    e.commit(m).unwrap();
    e.check_closure();
    t
}

// spec/sync-set.md §1, §2: a new account's node holds its node root, the account root, the
// profile and the inbox; the node thing is a key actor, never entered. A plain thing under the
// account root referenced from it is held in its sync unit; removing the strong takes it out and
// notes it as left with the sync unit it was in.
#[test]
fn the_node_closure_follows_strongs_spec_sync_set_2() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), e.account_root().unwrap());
    let p = e.account().unwrap().unwrap().0;
    let inbox = e.inbox_thing(&p).unwrap();
    for t in [root, d, inbox] {
        assert!(e.closure_holds(&t), "{t:?}");
    }
    assert!(!e.closure_holds(&e.tid()), "a key actor is never entered");
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
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let (from, to) = setup(e, d, n);
    osis_base::costs::take();
    strong(e, from, to, false);
    osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("closure:")).map(|(_, _, c)| c).sum()
}

// spec/sync-set.md §2 Cost (notes/closure-model.md P5 counts): removing a strong costs at most
// the part of the node closure it held, never its target's other referrers; checked at n and
// 10n. A non-tree referrer of a target with fan-in n, the target's tree edge with referrers
// outside, a tree edge whose target has a shallow alternative over a subtree of n, and one whose
// alternative is n deep: each the same at both sizes. A subtree of n released: n.
#[test]
fn removal_costs_what_it_held_spec_sync_set_2() {
    // D -> x1..xn, each xi -> t: the tree edge of t is x1's, made first
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
// left. X is plain under A (own keys, under D), so in D's and A's sync units; one write removing
// A -> X takes it out of both, and both are noted, whatever order the walk drops them in.
#[test]
fn a_thing_leaving_two_units_at_once_notes_both_spec_sync_set_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let a = make(e, d, d);
    e.give_own_secrets(&a).unwrap();
    let x = make(e, a, a);
    assert_eq!(e.units_holding(&x), [d, a].into());
    strong(e, a, x, false);
    assert_eq!(e.left_closure().get(&x), Some(&[d, a].into()));
}

// spec/sync-set.md §1 (refgraph H2): a local write that would take away a strong the roots keep
// is refused, however it is written (a removal, a whole-aspect removal): the node root's to the
// account root, and the account root's to the profile and the inbox.
#[test]
fn the_roots_kept_strongs_stay_spec_sync_set_1() {
    let (mut lp, ps) = people(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), e.account_root().unwrap());
    let (profile, inbox) = (e.profile_of(&ps[0]).unwrap(), e.inbox_thing(&ps[0]).unwrap());
    for (from, to) in [(root, d), (d, profile), (d, inbox)] {
        let removal = |m: &mut Mutation| {
            m.op(from, &ct::HOLDS, PathOp { path: vec![], op: Op::Remove(Value::Strong(to)) }).unwrap();
        };
        let whole = |m: &mut Mutation| {
            m.remove_aspect(from, &ct::HOLDS).unwrap();
        };
        for (name, w) in [("removal", &removal as &dyn Fn(&mut Mutation)), ("whole aspect", &whole)] {
            let mut m = Mutation::new();
            w(&mut m);
            assert!(e.commit(m).is_err(), "{name} of {to:?}");
            assert!(e.closure_holds(&to), "{name} of {to:?}");
        }
    }
}

// spec/sync-set.md §2 Not carried: X in D's sync unit strongly references Y, a thing this node
// never got, so D's keys do not open it and nothing else holds it: the strong is named, from X's
// written strongs and in the whole list; a strong to a held thing is not. So is the node root's
// strong to a thing never got: the local part holds only plain things the node opens.
#[test]
fn a_strong_nothing_carries_is_named_spec_sync_set_2() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), e.account_root().unwrap());
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

/// The `closure:` and sync set work of `edit` on a closure of `n` plain things under D beside A
/// (own keys, under D) holding `m` plain things, A sourced at another node, the sync set followed
/// before and after.
fn cut_work(n: usize, m: usize, edit: impl Fn(&mut Engine, Tid, Tid)) -> u64 {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    for _ in 0..n {
        make(e, d, d);
    }
    let a = make(e, d, d);
    e.give_own_secrets(&a).unwrap();
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
// leaving the node closure costs the same at a closure of n and of 10n; moving A away or home
// costs what is below A (n and 10n), not the rest of the node closure. The sync set leaves A and
// what is below it only, and takes them back home.
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
    let home = |e: &mut Engine, _: Tid, _: Tid| {
        e.set_sourced(Default::default(), &Default::default()).unwrap();
    };
    for (name, edit) in [("away", &away as &dyn Fn(&mut Engine, Tid, Tid)), ("home", &home)] {
        let (a, b) = (cut_work(n, 3, edit), cut_work(m, 3, edit));
        assert!(b <= a + 2, "{name}: {a} with n = {n}, {b} with n = {m}");
        let (a, b) = (cut_work(3, n, edit), cut_work(3, m, edit));
        assert!(b >= 8 * a && b <= 12 * a, "{name}: {a} below A at {n}, {b} at {m}");
    }
    // what leaves and comes back
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let x = make(e, d, d);
    let a = make(e, d, d);
    e.give_own_secrets(&a).unwrap();
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

// spec/sync-set.md §2 Sync units, Not carried (refgraph U1, U2): T's sync unit is T and what it
// reaches by strongs through things T's keys open, chains of grants giving the lowest role and the
// best chain counting; NotCarried names exactly the strongs in the node closure to a thing it does
// not hold. A random walk of edits (strongs added and removed, grants made, lowered and revoked
// between things) over 3 things with own keys and 4 plain ones on one node; after each, every
// sync unit and the NotCarried list equal held-model `closure`'s on the world rebuilt from the
// edits.
#[test]
fn sync_units_are_the_models_spec_sync_set_2() {
    use held_model::closure as hc;
    use osis_base::Role;
    for seed in 1..=3u64 {
        let mut rng = crate::order::Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let (mut lp, _) = people(1);
        let e = &mut lp.peers[0].engine;
        let (d, p) = (e.account_root().unwrap(), e.me());
        // model things 0..3 keyed (under the account, held by D), 3..7 plain under keyed i % 3
        let mut tids: Vec<Tid> = (0..3).map(|_| make(e, p, d)).collect();
        let mut kinds = vec![hc::Kind::Keyed; 3];
        let mut edges = hc::Edges::new();
        for i in 0..4 {
            let k = i % 3;
            tids.push(make(e, tids[k], tids[k]));
            kinds.push(hc::Kind::Plain(k));
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
                    let edge = ct::Edge { role: r, until: None, invite: None, floor: None };
                    let had: Option<hc::Role> = grants.get(&(g, t)).copied();
                    let m = match r { Role::Sync => hc::Role::Sync, Role::Read => hc::Role::Read, _ => hc::Role::Write };
                    if had == Some(m) {
                        continue;
                    }
                    if had.is_some_and(|h| h > m) {
                        e.demote(&tids[t], &osis_engine::flows::Demotion { holder: tids[g], new: Some(edge), retain: None }).unwrap();
                    } else {
                        e.grant(&tids[t], &tids[g], &edge).unwrap();
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
            let w = hc::World { kinds: kinds.clone(), grants: grants.clone(), keyless: hc::keyless_of(&order) };
            for (k, kt) in tids.iter().enumerate().take(3) {
                let got: BTreeSet<usize> = e.sync_unit(kt).iter().filter_map(ix).collect();
                assert_eq!(got, hc::unit(&w, k, &edges), "seed {seed} step {step}: the sync unit of {k}");
            }
            // the node reads every thing with own keys (it made them): roots D's strongs to them
            let n = hc::NodeView { roots: [0, 1, 2].into(), tickets: (0..3).map(|k| (k, hc::Ticket::Open)).collect() };
            let held = hc::closure(&w, &edges, &n, hc::Walk::Units).held;
            let want: BTreeSet<(usize, usize)> = edges.iter().copied().filter(|(x, y)| held.contains(x) && !held.contains(y)).collect();
            let got: BTreeSet<(usize, usize)> = e.not_carried().unwrap().iter().filter_map(|(x, y)| Some((ix(x)?, ix(y)?))).collect();
            assert_eq!(got, want, "seed {seed} step {step}: not carried");
        }
    }
}

/// `make` refused or not: a thing under `admin`, strongly referenced from `from` (none: from
/// nothing) in the same commit.
fn try_make(e: &mut Engine, admin: Tid, from: Option<Tid>) -> osis_engine::Result<Tid> {
    let rec = e.thing_record(admin);
    let mut m = Mutation::new();
    let t = m.create(rec);
    if let Some(f) = from {
        m.op(f, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    }
    e.commit(m).map(|_| t)
}

// spec/sync-set.md §2 Making a thing (refgraph U3): the commits of one storage transaction must
// leave every thing they make, but a key actor, in the node closure at its end, or nothing
// applies. X and U have own keys: a plain thing under X referenced by X is made; one nothing
// references, or one from U referenced only by X (X's keys do not open it), is refused and
// leaves no commit; a thing made in one commit and held by the next of its transaction is made,
// and refused with that commit holding nothing; a link (its key actor held by nothing, its seed
// thing under the account root with its strong) is made; the account's creation was.
#[test]
fn a_thing_is_made_only_where_it_is_held_spec_sync_set_2() {
    let (mut lp, ps) = people(1);
    let e = &mut lp.peers[0].engine;
    let (d, p) = (e.account_root().unwrap(), e.me());
    for t in [d, e.profile_of(&ps[0]).unwrap(), e.inbox_thing(&ps[0]).unwrap()] {
        assert!(e.closure_holds(&t), "the account's creation: {t:?}");
    }
    let (x, u) = (make(e, p, d), make(e, p, d));
    let made = try_make(e, x, Some(x)).unwrap();
    assert!(e.closure_holds(&made));
    let before = e.commit_ids().len();
    for (name, admin, from) in [("held by nothing", x, None), ("plain from U, referenced by X", u, Some(x))] {
        let r = try_make(e, admin, from);
        assert!(matches!(r, Err(osis_engine::Error::NotHeld(_))), "{name}: {r:?}");
        assert_eq!(e.commit_ids().len(), before, "{name}: nothing applies");
    }
    let hold = |a: Tid| {
        let mut m = Mutation::new();
        m.op(d, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(a)) }).unwrap();
        Ok(m)
    };
    let (a, _) = e.mint_actor(&p, hold).unwrap();
    assert!(e.closure_holds(&a), "held by the transaction's next commit");
    let r = e.mint_actor(&p, |_| Ok(Mutation::new()));
    assert!(matches!(r, Err(osis_engine::Error::NotHeld(_))), "{r:?}");
    let spec = osis_engine::flows::LinkSpec { target: x, role: osis_base::Role::Read, until: None, peers: vec![], single_use: false };
    e.create_link(&p, &spec).unwrap();
}

// spec/sync-set.md §2 (refgraph U5): nested sharing. X and Y have own keys, X is granted read on Y,
// and X -> Y -> B with B plain from Y. A reader of X (account 1, holding X by a strong) holds Y and
// B, with no ticket for Y, in X's sync unit, and has Y's sync ID in its sync set.
#[test]
fn nested_sharing_holds_what_the_shared_thing_reads_spec_sync_set_2() {
    let (mut lp, ps) = people(2);
    let e = &mut lp.peers[0].engine;
    let (d, p) = (e.account_root().unwrap(), e.me());
    let x = make(e, p, d);
    let y = make(e, p, x);
    let b = make(e, y, y);
    e.grant(&y, &x, &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    e.grant(&x, &ps[1], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.account_root().unwrap();
    strong(e1, d1, x, true);
    lp.sync_all().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.held_tickets(&y).unwrap().is_empty(), "no ticket for Y");
    for t in [x, y, b] {
        assert!(e1.closure_holds(&t) && e1.sync_unit(&x).contains(&t), "{t:?}");
    }
    assert!(e1.in_sync_things(&y).unwrap(), "Y's sync ID synced");
}

// spec/sync-set.md §2 Cost (refgraph H4): adding a thing costs the same whatever else the account
// root holds (n and 10n things beside it), and a cycle cut off from the node closure is released
// whole.
#[test]
fn adding_costs_what_it_adds_and_a_cycle_goes_whole_spec_sync_set_2() {
    let add = |n: usize| {
        let (mut lp, _) = people(1);
        let e = &mut lp.peers[0].engine;
        let d = e.account_root().unwrap();
        for _ in 0..n {
            make(e, d, d);
        }
        osis_base::costs::take();
        make(e, d, d);
        osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("closure:")).map(|(_, _, c)| c).sum::<u64>()
    };
    assert_eq!(add(6), add(60));
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let c1 = make(e, d, d);
    let c2 = make(e, d, c1);
    strong(e, c2, c1, true);
    strong(e, d, c1, false);
    assert!(!e.closure_holds(&c1) && !e.closure_holds(&c2));
    assert_eq!(e.left_closure().keys().copied().collect::<BTreeSet<_>>(), [c1, c2].into());
}

// spec/sync-set.md §3 Release (refgraph L1, L10, L3): a thing that left the node closure and is
// released is dropped with its writes, durable and ephemeral, and reads as not held; one back in
// the node closure before its release is kept as it was, and its release drops nothing.
#[test]
fn a_released_thing_goes_with_its_writes_spec_sync_set_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
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

// spec/sync-set.md §3 (refgraph L9): lowering a reader to sync is no release: account 1, holding X
// read, is lowered to sync; X stays in its node closure, kept unread (its sync ID in the sync
// set, nothing noted as left), and what is written after, sealed as sync IDs carry it, opens
// nothing there.
#[test]
fn lowered_to_sync_a_thing_is_kept_unread_spec_sync_set_3() {
    let (mut lp, ps) = people(2);
    let e = &mut lp.peers[0].engine;
    let (d, p) = (e.account_root().unwrap(), e.me());
    let x = make(e, p, d);
    let reg = crate::common::REG;
    let put = |e: &mut Engine, v: &str| {
        let mut m = Mutation::new();
        m.set(x, &reg, &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap();
    };
    put(e, "before");
    e.grant(&x, &ps[1], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.account_root().unwrap();
    strong(e1, d1, x, true);
    lp.sync_all().unwrap();
    let read = |lp: &mut osis_engine::local_peer::LocalPeer| lp.peers[1].engine.get(&x, &crate::common::ak("t:reg.0")).unwrap();
    assert_eq!(read(&mut lp), Some(Value::Str("before".into())));
    let e = &mut lp.peers[0].engine;
    let lowering = e.demote(&x, &osis_engine::flows::Demotion { holder: ps[1], new: Some(crate::flows::edge_of(osis_base::Role::Sync)), retain: None }).unwrap();
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

/// Whether peer `i` holds anything of account `a`'s chain: its record, its inbox's, or a
/// commit it authored.
fn knows(lp: &mut osis_engine::local_peer::LocalPeer, i: usize, a: Tid) -> bool {
    let e = &mut lp.peers[i].engine;
    let inbox = e.inbox_thing(&a);
    let commits = e.commit_ids();
    e.core.created(&a).is_some() || inbox.is_some_and(|x| e.core.created(&x).is_some()) || commits.iter().any(|c| e.header(c).is_some_and(|h| h.author == a))
}

// spec/commits.md §5 What a held thing needs, spec/sync-set.md §3 Release: another account's
// chain stays while a held thing needs it and goes with the last. Peer 0 makes T (peer 1 a
// writer who writes there, peer 2 a reader) and U (peer 2 a reader); peer 2 holds both and of
// peer 1 only what certifies it (its role commits). Released, T goes whole, and peer 1's chain
// with it; peer 0's stays, U needing it.
#[test]
fn another_accounts_chain_goes_with_the_last_held_thing_needing_it_spec_commits_5() {
    let mut lp = crate::common::net_bare(3, 0);
    let ps: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.create_account().unwrap().0.account).collect();
    // each peer's commits to the others, twice (chains first); of peer 1 only role commits
    let pass = |lp: &mut osis_engine::local_peer::LocalPeer| {
        for _ in 0..2 {
            for from in 0..3 {
                let ids: Vec<_> = lp.peers[from].engine.commit_ids().into_iter().filter(|c| from != 1 || crate::common::is_role(&lp.peers[from].engine, c)).collect();
                for to in (0..3).filter(|to| *to != from) {
                    crate::flows::send(lp, from, to, &ids);
                }
            }
        }
    };
    pass(&mut lp);
    let d0 = lp.peers[0].engine.account_root().unwrap();
    let (t, u) = (make(&mut lp.peers[0].engine, d0, d0), make(&mut lp.peers[0].engine, d0, d0));
    let e0 = &mut lp.peers[0].engine;
    e0.grant(&t, &ps[1], &crate::flows::edge_of(osis_base::Role::Write)).unwrap();
    e0.grant(&t, &ps[2], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    e0.grant(&u, &ps[2], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    pass(&mut lp);
    // peer 1 holds what it writes
    let d1 = lp.peers[1].engine.account_root().unwrap();
    strong(&mut lp.peers[1].engine, d1, t, true);
    let mut m = Mutation::new();
    m.set(t, &osis_base::Ak::new("x:v.0").unwrap(), &Value::Str("by 1".into())).unwrap();
    let w = lp.peers[1].engine.commit(m).unwrap().unwrap();
    pass(&mut lp);
    crate::flows::send(&mut lp, 1, 2, &[w]);
    let e2 = &mut lp.peers[2].engine;
    assert!(e2.commit_ids().contains(&w), "peer 2 holds peer 1's write");
    let d2 = e2.account_root().unwrap();
    strong(e2, d2, t, true);
    strong(e2, d2, u, true);
    assert!(e2.closure_holds(&t) && e2.closure_holds(&u), "peer 2 holds T and U");
    assert!(knows(&mut lp, 2, ps[1]) && knows(&mut lp, 2, ps[0]), "peer 2 met both");
    let e2 = &mut lp.peers[2].engine;
    strong(e2, d2, t, false);
    assert!(knows(&mut lp, 2, ps[1]), "T, left but not released, still needs peer 1's chain");
    let e2 = &mut lp.peers[2].engine;
    e2.released(&[t].into()).unwrap();
    // the pass ends: what T's commits needed goes
    e2.settle_needs().unwrap();
    e2.check_index();
    assert!(e2.core.created(&t).is_none(), "T released whole");
    assert!(!knows(&mut lp, 2, ps[1]), "nothing held needs peer 1's chain");
    assert!(knows(&mut lp, 2, ps[0]), "U needs peer 0's chain");
    assert!(lp.peers[2].engine.closure_holds(&u));
}

// spec/sync-set.md §2 Cost: taking up an opener (a key actor, as a bearer does) and making a
// link cost what the new opener can open, never the node closure or every held actor: counted
// (`closure:` and `reopen:`) with n and 10n things with own keys held.
#[test]
fn a_take_up_costs_what_the_opener_opens_spec_sync_set_2() {
    let work = |n: usize| {
        let (mut lp, _) = people(1);
        let e = &mut lp.peers[0].engine;
        let (d, p) = (e.account_root().unwrap(), e.me());
        let things: Vec<Tid> = (0..n).map(|_| make(e, p, d)).collect();
        let counted = |e: &mut Engine, f: &dyn Fn(&mut Engine)| {
            osis_base::costs::take();
            f(e);
            osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("closure:") || k.starts_with("reopen:")).map(|(_, _, c)| c).sum::<u64>()
        };
        let take_up = counted(e, &|e| { e.hold_key_actor(osis_crypto::Secret32::from_bytes([0x5a; 32])).unwrap(); });
        let spec = osis_engine::flows::LinkSpec { target: things[0], role: osis_base::Role::Read, until: None, peers: vec![], single_use: false };
        let link = counted(e, &|e| drop(e.create_link(&p, &spec).unwrap()));
        e.check_closure();
        (take_up, link)
    };
    let (small, large) = (work(5), work(50));
    eprintln!("take-up and create_link work at n, 10n: {small:?} {large:?}");
    assert_eq!(small, large);
}

// spec/commits.md §5 What a held thing needs (dropped when the pass that brought it ends): what a
// node holds outside its node closure at quiet does not depend on arrival order. Account Q (peer
// 1, never met by peer 0) makes T and grants peer 0's account read; peer 0 holds T, takes Q's
// commits, then releases T. Q's write on its own profile arrives before the release, or after
// it: either way, at the pass's end nothing held needs Q's chain or that write, and peer 0 holds
// the same.
#[test]
fn what_nothing_needs_goes_whatever_the_arrival_order_spec_commits_5() {
    let mut lp = osis_engine::local_peer::LocalPeer::new_apart(2, 0, crate::common::T0).unwrap();
    let (p0, q) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
    let mut end = |late: bool| {
        let mut lp = lp.copy().unwrap();
        // Q keeps peer 0's account, which it grants
        lp.peers[1].know(&[p0]).unwrap();
        let mine: Vec<_> = lp.peers[0].engine.commit_ids();
        crate::flows::send(&mut lp, 0, 1, &mine);
        let e1 = &mut lp.peers[1].engine;
        let mut m = Mutation::new();
        let t = e1.new_thing(&mut m, q);
        m.set(t, &crate::common::REG, &Value::Str("t".into())).unwrap();
        e1.commit(m).unwrap();
        e1.grant(&t, &p0, &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
        let profile = e1.profile_of(&q).unwrap();
        let mut m = Mutation::new();
        m.set(profile, &crate::common::REG, &Value::Str("q".into())).unwrap();
        let x = e1.commit(m).unwrap().unwrap();
        let rest: Vec<_> = lp.peers[1].engine.commit_ids().into_iter().filter(|c| *c != x).collect();
        let e0 = &mut lp.peers[0].engine;
        e0.hold(osis_base::Strong(t)).unwrap();
        crate::flows::send(&mut lp, 1, 0, &rest);
        if !late {
            crate::flows::send(&mut lp, 1, 0, &[x]);
        }
        let e0 = &mut lp.peers[0].engine;
        assert!(e0.closure_holds(&t), "late {late}: peer 0 holds T");
        e0.unhold(osis_base::Strong(t)).unwrap();
        e0.released(&[t].into()).unwrap();
        if late {
            crate::flows::send(&mut lp, 1, 0, &[x]);
        }
        let e0 = &mut lp.peers[0].engine;
        e0.settle_needs().unwrap();
        // of Q's commits (peer 0's own hold and unhold differ by their stamps)
        let qs: BTreeSet<_> = rest.iter().copied().chain([x]).collect();
        let held: BTreeSet<_> = e0.commit_ids().into_iter().filter(|c| qs.contains(c)).collect();
        let pending: BTreeSet<_> = e0.pending().into_iter().map(|p| p.0).collect();
        assert!(e0.core.created(&q).is_none(), "late {late}: nothing held needs Q's chain");
        (held, pending)
    };
    let (a, b) = (end(false), end(true));
    let only = |x: &BTreeSet<osis_base::CommitId>, y: &BTreeSet<osis_base::CommitId>| x.difference(y).copied().collect::<Vec<_>>();
    assert_eq!(a, b, "held only early {:?}, only late {:?}; pending only early {:?}, only late {:?}", only(&a.0, &b.0), only(&b.0, &a.0), only(&a.1, &b.1), only(&b.1, &a.1));
}

// spec/commits.md §5 What a held thing needs: a held commit waiting for a part keeps what it is on.
// Peer 0 makes U under G (read by a fresh observer) in one commit, U's record with G's strong to
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

// spec/sync-set.md §2 (Writing): a node writes only what it holds. Bob, granted write on Alice's
// T and holding its commits, writes it unaccepted: refused, nothing applies. Accepting T and
// writing it in one commit passes: what it writes is held at the transaction's end.
#[test]
fn a_node_writes_only_what_it_holds_spec_sync_set_2() {
    let (mut lp, ps) = people(2);
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.account_root().unwrap();
    let t = make(e0, d0, d0);
    e0.grant(&t, &ps[1], &crate::flows::edge_of(osis_base::Role::Write)).unwrap();
    let ids = lp.peers[0].engine.commit_ids();
    crate::flows::send(&mut lp, 0, 1, &ids);
    let e1 = &mut lp.peers[1].engine;
    let before = e1.commit_ids().len();
    let v = osis_base::Ak::new("x:v.0").unwrap();
    let mut m = Mutation::new();
    m.set(t, &v, &Value::Str("unaccepted".into())).unwrap();
    assert!(matches!(e1.commit(m), Err(osis_engine::Error::NotHeld(x)) if x == t), "not held: refused");
    assert_eq!(e1.commit_ids().len(), before, "nothing applied");
    let d1 = e1.account_root().unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    m.set(t, &v, &Value::Str("held".into())).unwrap();
    e1.commit(m).unwrap();
    assert_eq!(e1.get(&t, &v).unwrap(), Some(Value::Str("held".into())));
}

// spec/commits.md §5 What a held thing needs: a weak only points and keeps nothing; a strong
// keeps. Peer 0 (never met Q) refers to Q from its account root and takes Q's commits: by a weak
// to Q, nothing needs Q's chain at the pass's end and it goes; by a strong to Q's profile (a
// contact), the profile needs Q (its first admin) and Q's chain stays.
#[test]
fn a_weak_to_an_account_keeps_nothing_a_strong_to_its_profile_keeps_its_chain_spec_commits_5() {
    let mut lp = osis_engine::local_peer::LocalPeer::new_apart(2, 0, crate::common::T0).unwrap();
    let q = lp.peers[1].engine.me();
    let profile = lp.peers[1].engine.profile_of(&q).unwrap();
    let mut kept = |v: Value| {
        let mut lp = lp.copy().unwrap();
        let e0 = &mut lp.peers[0].engine;
        let d0 = e0.account_root().unwrap();
        let mut m = Mutation::new();
        m.op(d0, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(v) }).unwrap();
        e0.commit(m).unwrap();
        let qs = lp.peers[1].engine.commit_ids();
        crate::flows::send(&mut lp, 1, 0, &qs);
        crate::flows::send(&mut lp, 1, 0, &qs);
        let e0 = &mut lp.peers[0].engine;
        e0.settle_needs().unwrap();
        e0.check_index();
        e0.core.created(&q).is_some()
    };
    assert!(!kept(Value::Weak(q)), "a weak to Q keeps nothing of it");
    assert!(kept(Value::Strong(profile)), "a strong to Q's profile keeps Q's chain");
}

// spec/sync-set.md §3 (Nothing of R stays), spec/commits.md §5 (What a held thing needs): a node's
// own things are released whole as another's are. A plain thing under the account root, a thing
// with own keys under the account and a plain thing under the node root, each written and then
// released, keep no record, secret or part here: their record chains topping at this node or
// its account keep nothing of them.
#[test]
fn own_things_are_released_whole_spec_sync_set_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), e.account_root().unwrap());
    let p = e.account().unwrap().unwrap().0;
    let (a, c) = (make(e, d, d), make(e, root, root));
    let b = e.create_with_admin(&p).unwrap().0;
    for t in [a, b, c] {
        let mut m = Mutation::new();
        m.set(t, &crate::common::REG, &crate::common::s("new")).unwrap();
        e.commit(m).unwrap();
    }
    strong(e, d, a, false);
    strong(e, d, b, false);
    strong(e, root, c, false);
    e.released(&[a, b, c].into()).unwrap();
    for t in [a, b, c] {
        assert!(e.core.created(&t).is_none(), "{t:?}: its record");
        assert!(!e.held_actors_has(&t), "{t:?}: its secrets");
        // a commit with a part held elsewhere (the strong's, on D) keeps its header alone
        let held = e.core.on_thing(&t).filter(|c| e.core.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().enumerate().any(|(i, x)| x.tid == t && m.holds(i)))).count();
        assert_eq!(held, 0, "{t:?}: its parts");
    }
}
