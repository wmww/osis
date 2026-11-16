//! The node closure (spec/sync-set.md §1-§3): what the node root reaches by strongs, sync unit
//! by sync unit, what left it, and what its changes cost.

use crate::flows::people;
use osis_base::{Tid, Value};
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

// spec/sync-set.md §1: a local write that would leave the node root without its strong to the
// account root is refused, however it is written: a removal, a whole-aspect removal, a purge.
#[test]
fn the_node_roots_strong_to_the_account_root_stays_spec_sync_set_1() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (root, d) = (e.node_root().unwrap(), e.account_root().unwrap());
    let removal = |m: &mut Mutation| {
        m.op(root, &ct::HOLDS, PathOp { path: vec![], op: Op::Remove(Value::Strong(d)) }).unwrap();
    };
    let whole = |m: &mut Mutation| {
        m.remove_aspect(root, &ct::HOLDS).unwrap();
    };
    for (name, w) in [("removal", &removal as &dyn Fn(&mut Mutation)), ("whole aspect", &whole)] {
        let mut m = Mutation::new();
        w(&mut m);
        assert!(e.commit(m).is_err(), "{name}");
        assert!(e.closure_holds(&d), "{name}");
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
