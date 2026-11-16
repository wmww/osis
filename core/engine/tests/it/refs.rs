//! Known references (spec/data-model.md §8): the index holds every reference in held readable
//! values and held valid fires, each with its kind; a fire's leave with it.

use crate::common::*;
use osis_base::{PurgeBy, RefKind, Tid, Value};
use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_schema::core_types as ct;
use osis_schema::{History, Retention};

fn rows(lp: &mut LocalPeer, i: usize, target: &Tid) -> Vec<(Tid, String, RefKind, u64)> {
    lp.peers[i].engine.references_to(target).unwrap().into_iter().map(|r| (r.source, r.ak.as_str().to_string(), r.kind, r.count)).collect()
}

// spec/data-model.md §8 What counts: a strong and a weak to one target in one value are two rows,
// each with its kind; a core aspect's names are weaks
#[test]
fn rows_carry_the_kind_spec_data_model_8() {
    let mut lp = net(1, 0);
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let (t, x) = (lp.peers[0].engine.new_thing(&mut m, me), lp.peers[0].engine.new_thing(&mut m, me));
    m.set(t, &REFS, &Value::Set([Value::Strong(x), Value::Weak(x)].into_iter().collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let got: Vec<_> = rows(&mut lp, 0, &x).into_iter().filter(|r| r.0 == t).collect();
    assert_eq!(got, vec![(t, "t:refs.0".into(), RefKind::Strong, 1), (t, "t:refs.0".into(), RefKind::Weak, 1)]);
    // the account is named by each creation record's `admin`, a weak
    assert!(rows(&mut lp, 0, &me).iter().any(|r| r.0 == t && r.1 == "created.0" && r.2 == RefKind::Weak));
}

// spec/data-model.md §8 Known references: a held valid fire's references count at every holder
// and go with the fire
#[test]
fn a_fires_references_go_with_it_spec_data_model_8() {
    let mut lp = net(2, 0);
    let ids: Vec<Tid> = (0..2).map(|i| lp.peers[i].engine.me()).collect();
    let log = ak("t:log~0");
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    let x = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(d, &ct::RETENTION, &setting(&[(log.as_str(), History::FOREVER)])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(osis_base::Role::Write)), None);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.retention(d, &log, Retention { by: PurgeBy::AuthorOrAdmin }).unwrap();
    m.set(d, &log, &Value::List(vec![Value::Weak(x), Value::Weak(x)])).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(rows(&mut lp, i, &x).into_iter().filter(|r| r.0 == d).collect::<Vec<_>>(), vec![(d, "t:log~0".into(), RefKind::Weak, 2)], "peer {i}");
    }
    let item = lp.peers[0].engine.purge_item(&c, d, log.clone()).unwrap();
    let mut m = Mutation::new();
    m.set(d, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
    m.purge(item);
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert!(rows(&mut lp, i, &x).iter().all(|r| r.0 != d), "peer {i}: purged");
    }
}

/// Every reference at any depth of `v` (map keys and payloads too), counted by (target, kind).
fn scan(v: &Value, out: &mut std::collections::BTreeMap<(Tid, RefKind), u64>) {
    let mut one = |t: Tid, k: RefKind| *out.entry((t, k)).or_default() += 1;
    match v {
        Value::Strong(t) => one(*t, RefKind::Strong),
        Value::Weak(t) => one(*t, RefKind::Weak),
        Value::Ticket(k) => one(k.target, RefKind::Ticket),
        Value::Enum(_, Some(p)) => scan(p, out),
        Value::Map(m) => m.iter().for_each(|(k, x)| {
            scan(k, out);
            scan(x, out);
        }),
        Value::List(x) => x.iter().for_each(|x| scan(x, out)),
        Value::Set(x) => x.iter().for_each(|x| scan(x, out)),
        _ => {}
    }
}

type Rows = std::collections::BTreeSet<(Tid, Tid, String, RefKind, u64)>;

/// The app aspects' rows (source, target, AK, kind, count) of `sources` two ways: the reference
/// index (by source and by target) and a scan of every aspect each source reads now.
fn index_and_scan(e: &mut osis_engine::Engine, sources: &[Tid], targets: &[Tid]) -> (Rows, Rows, Rows) {
    let app = |ak: &str| ak.starts_with("x:") || ak.starts_with("t:");
    let (mut by_source, mut by_target, mut scanned) = (Rows::new(), Rows::new(), Rows::new());
    for s in sources {
        by_source.extend(e.references_from(s).unwrap().into_iter().filter(|r| app(r.ak.as_str())).map(|r| (r.source, r.target, r.ak.as_str().to_string(), r.kind, r.count)));
        for a in e.aspects(s).unwrap().into_iter().filter(|a| app(a.as_str())) {
            let mut c = std::collections::BTreeMap::new();
            if let Some(v) = e.get(s, &a).unwrap() {
                scan(&v, &mut c);
            }
            scanned.extend(c.into_iter().map(|((t, k), n)| (*s, t, a.as_str().to_string(), k, n)));
        }
    }
    for t in targets {
        by_target.extend(e.references_to(t).unwrap().into_iter().filter(|r| app(r.ak.as_str()) && sources.contains(&r.source)).map(|r| (r.source, r.target, r.ak.as_str().to_string(), r.kind, r.count)));
    }
    scanned.retain(|r| targets.contains(&r.1));
    by_source.retain(|r| targets.contains(&r.1));
    (by_source, by_target, scanned)
}

// spec/data-model.md §8 Known references (refgraph R2): after every commit the known references,
// with kind, equal a scan of the current values of every held aspect: at any depth (map keys,
// enum payloads, sets in lists), a large value, an expiring write while it lasts, a removed
// aspect's and a replaced value's gone, whatever shape replaced it (never history). Random
// nested writes on one node.
#[test]
fn known_references_are_a_scan_of_held_values_spec_data_model_8() {
    for seed in 1..=4u64 {
        let mut rng = crate::order::Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut lp = net(1, 0);
        let things: Vec<Tid> = (0..3).map(|_| new_thing(&mut lp, 0)).collect();
        let d = lp.peers[0].engine.account_root().unwrap();
        // targets: the things, the account root, one tid never got
        let mut targets = things.clone();
        targets.extend([d, Tid::from_bytes([3; 15])]);
        let aks = [ak("x:a.0"), ak("x:b.0")];
        let reference = |rng: &mut crate::order::Rng| {
            let t = targets[rng.below(targets.len() as u64) as usize];
            if rng.below(2) == 0 { Value::Strong(t) } else { Value::Weak(t) }
        };
        // any shape at any position, so a value of one shape replaces one of another
        let nested = |rng: &mut crate::order::Rng, depth: u32| -> Value {
            fn go(rng: &mut crate::order::Rng, depth: u32, r: &dyn Fn(&mut crate::order::Rng) -> Value) -> Value {
                match if depth == 0 { 4 } else { rng.below(5) } {
                    0 => Value::List((0..rng.below(3)).map(|_| go(rng, depth - 1, r)).collect()),
                    1 => Value::Set((0..rng.below(3)).map(|_| r(rng)).collect()),
                    2 => Value::Map((0..rng.below(3)).map(|i| (if rng.below(2) == 0 { r(rng) } else { Value::Int(i as i64) }, go(rng, depth - 1, r))).collect()),
                    3 => Value::Enum(1, Some(Box::new(go(rng, depth - 1, r)))),
                    _ => r(rng),
                }
            }
            go(rng, depth, &reference)
        };
        for step in 0..30 {
            let t = things[rng.below(3) as usize];
            let a = &aks[rng.below(2) as usize];
            let mut m = Mutation::new();
            let expiring = match rng.below(7) {
                0..=2 => {
                    m.set(t, a, &nested(&mut rng, 3)).unwrap();
                    false
                }
                3 => {
                    m.remove_aspect(t, a).unwrap();
                    false
                }
                4 => {
                    // a large value: paged in the store
                    let pad = Value::Str("p".repeat(70_000));
                    m.set(t, &ak("x:big.0"), &Value::List(vec![pad, nested(&mut rng, 2), reference(&mut rng)])).unwrap();
                    false
                }
                5 => {
                    let x = reference(&mut rng);
                    m.op(t, &REFS, osis_crdt::PathOp { path: vec![], op: if rng.below(3) == 0 { osis_crdt::Op::Remove(x) } else { osis_crdt::Op::Add(x) } }).unwrap();
                    false
                }
                _ => {
                    let now = lp.peers[0].engine.now();
                    m.set(t, &ak("x:e.0"), &nested(&mut rng, 2)).unwrap();
                    m.expires(t, &ak("x:e.0"), osis_base::WallMs(now.0 + 1_000)).unwrap();
                    true
                }
            };
            lp.peers[0].commit(m).unwrap();
            if expiring || rng.below(4) == 0 {
                lp.advance(1_500);
                lp.peers[0].tick().unwrap();
            }
            let (by_source, by_target, scanned) = index_and_scan(&mut lp.peers[0].engine, &things, &targets);
            assert_eq!(by_source, scanned, "seed {seed} step {step}: rows by source");
            assert_eq!(by_target, scanned, "seed {seed} step {step}: rows by target");
        }
    }
}

// spec/data-model.md §8 What counts (refgraph R3): core aspects name things by weaks, so none of
// them holds anything. Y is made under X and both are held by the account root; G, a thing with
// own keys nothing holds, is granted read on X. Every reference a core aspect holds is a weak, and
// removing the strong to X takes X out of the node closure though Y's `created.0` names it, and G
// is held by none though X's roster and boxes name it.
#[test]
fn core_aspects_hold_nothing_spec_data_model_8() {
    let mut lp = net(1, 0);
    let e = &mut lp.peers[0].engine;
    let d = e.account_root().unwrap();
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, d);
    let y = e.new_thing(&mut m, x);
    m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(y)) }).unwrap();
    let g = e.new_thing(&mut m, e.me());
    e.commit(m).unwrap();
    e.give_own_secrets(&x).unwrap();
    e.grant(&x, &g, &ct::Edge { role: osis_base::Role::Read, until: None, invite: None, floor: None }).unwrap();
    let mut m = Mutation::new();
    m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(Value::Strong(g)) }).unwrap();
    e.commit(m).unwrap();
    let core = |a: &str| !(a.starts_with("x:") || a.starts_with("t:") || a == "holds.0" || a == "tickets.0");
    for t in [x, y, g, d, e.me()] {
        for r in e.references_to(&t).unwrap().into_iter().filter(|r| core(r.ak.as_str())) {
            assert_eq!(r.kind, RefKind::Weak, "{r:?}");
        }
    }
    assert!(e.references_to(&g).unwrap().iter().any(|r| r.source == x), "X's roster names G");
    assert!(!e.closure_holds(&g), "the roster holds nothing");
    let mut m = Mutation::new();
    m.op(d, &ct::HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(Value::Strong(x)) }).unwrap();
    e.commit(m).unwrap();
    assert!(e.closure_holds(&y) && !e.closure_holds(&x), "Y's record holds nothing");
}

// spec/data-model.md §8 What counts: a value of another shape set over an untyped aspect (a map
// over a list, a set or a reference) reads as the new value alone, and so do its references.
#[test]
fn a_value_of_another_shape_leaves_no_references_spec_data_model_8() {
    let x = Value::Weak(Tid::from_bytes([3; 15]));
    for first in [Value::List(vec![x.clone()]), Value::Set([x.clone()].into_iter().collect()), x.clone()] {
        let mut lp = net(1, 0);
        let t = new_thing(&mut lp, 0);
        for v in [&first, &Value::Map(Default::default())] {
            let mut m = Mutation::new();
            m.set(t, &ak("x:a.0"), v).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.get(&t, &ak("x:a.0")).unwrap(), Some(Value::Map(Default::default())));
        assert_eq!(rows(&mut lp, 0, &Tid::from_bytes([3; 15])), vec![], "{first:?}");
    }
}
