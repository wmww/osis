//! Known references (spec/data-model.md §8): the index holds every reference in held readable
//! values and held valid fires, each with its kind; a fire's leave with it.

use crate::common::*;
use osis_base::{CommitId, RefKind, Tid, Value, WallMs};
use osis_engine::local_peer::{LocalPeer, Package};
use osis_engine::{Engine, Mutation};
use std::collections::{BTreeMap, BTreeSet};
use osis_schema::core_types as ct;
use osis_schema::History;

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

/// Every reference at any depth of `v` (map keys and payloads too), counted by (target, kind).
fn scan(v: &Value, out: &mut BTreeMap<(Tid, RefKind), u64>) {
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

type Rows = BTreeSet<(Tid, Tid, String, RefKind, u64)>;

/// R2's signal: its held valid fires' references are known references.
const SIG: &str = "x:f~0";
/// R2's state aspects, each counted in held history (`history_holds_targets`).
const HELD: [&str; 6] = ["x:a.0", "x:b.0", "x:big.0", "x:e.0", "t:refs.0", "x:m.0"];
/// R2's paged map: past a page, its few live keys put again and written into by every writer.
const MAP: &str = "x:m.0";

fn app(ak: &str) -> bool {
    ak.starts_with("x:") || ak.starts_with("t:")
}

/// Every reference in the held valid bodies of `(s, a)` (a history read), by (target, kind): in
/// what each reads as, or, `written`, in every value it writes (its writes inside another's
/// elements included).
fn scan_bodies(e: &mut Engine, s: &Tid, a: &str, written: bool, out: &mut BTreeMap<(Tid, RefKind), u64>) {
    let a = ak(a);
    for b in e.body_page(s, &a, true, 0, usize::MAX).unwrap() {
        match b.valid.then(|| e.body_fragment(&b.id, s, &a).unwrap()).flatten() {
            Some(f) if written => f.each_value(&mut |v| scan(v, out)),
            Some(f) => f.read().iter().for_each(|v| scan(v, out)),
            None => {}
        }
    }
}

/// The app aspects' rows (source, target, AK, kind, count) of `sources` naming `targets` two
/// ways: the reference index (by source and by target) and a scan of every aspect each source
/// reads now and of the held valid fires of `SIG`.
fn index_and_scan(e: &mut Engine, sources: &[Tid], targets: &[Tid]) -> (Rows, Rows, Rows) {
    let (mut by_source, mut by_target, mut scanned) = (Rows::new(), Rows::new(), Rows::new());
    for s in sources {
        by_source.extend(e.references_from(s).unwrap().into_iter().filter(|r| app(r.ak.as_str())).map(|r| (r.source, r.target, r.ak.as_str().to_string(), r.kind, r.count)));
        for a in e.aspects(s).unwrap().into_iter().filter(|a| app(a.as_str())) {
            let mut c = BTreeMap::new();
            if let Some(v) = e.get(s, &a).unwrap() {
                scan(&v, &mut c);
            }
            scanned.extend(c.into_iter().map(|((t, k), n)| (*s, t, a.as_str().to_string(), k, n)));
        }
        let mut c = BTreeMap::new();
        scan_bodies(e, s, SIG, false, &mut c);
        scanned.extend(c.into_iter().map(|((t, k), n)| (*s, t, SIG.to_string(), k, n)));
    }
    for t in targets {
        by_target.extend(e.references_to(t).unwrap().into_iter().filter(|r| app(r.ak.as_str()) && sources.contains(&r.source)).map(|r| (r.source, r.target, r.ak.as_str().to_string(), r.kind, r.count)));
    }
    scanned.retain(|r| targets.contains(&r.1));
    by_source.retain(|r| targets.contains(&r.1));
    (by_source, by_target, scanned)
}

/// History rows: (source, target, AK).
type Kept = BTreeSet<(Tid, Tid, String)>;

/// The strongs held history holds (source, target, AK) two ways: the index and a scan of the
/// held valid bodies of `HELD` on each source whose setting says its history holds them.
fn history_two_ways(e: &mut Engine, sources: &[Tid], targets: &[Tid]) -> (Kept, Kept) {
    let (mut index, mut scanned) = (BTreeSet::new(), BTreeSet::new());
    for s in sources {
        index.extend(e.history_strongs_from(s).unwrap().into_iter().filter(|(t, a)| targets.contains(t) && app(a.as_str())).map(|(t, a)| (*s, t, a.as_str().to_string())));
        if !e.get_typed(s, &ct::RETENTION).unwrap().is_some_and(|x| x.history_holds_targets) {
            continue;
        }
        for a in HELD {
            let mut c = BTreeMap::new();
            scan_bodies(e, s, a, true, &mut c);
            scanned.extend(c.into_keys().filter(|(t, k)| *k == RefKind::Strong && targets.contains(t)).map(|(t, _)| (*s, t, a.to_string())));
        }
    }
    (index, scanned)
}

const HOUR: u64 = 3_600_000;

/// R2's setting: replaced writes kept an hour, replaced fires a second, history holding its
/// strongs' targets where `holds`.
fn r2_setting(holds: bool) -> ct::RetentionSetting {
    let keep = |ms| ct::RetentionEntry { history: Some(History::Keep { until: None, after: Some(ms) }), ..Default::default() };
    ct::RetentionSetting { default: Some(keep(HOUR)), rules: [(ak(SIG), keep(1_000))].into_iter().collect(), history_holds_targets: holds, ..Default::default() }
}

/// R2's paged map: 200 padding entries (past a page, notes/engine-paged.md) and keys 0 to 2
/// naming `targets`.
fn r2_map(targets: &[Tid]) -> Value {
    let pad = (0..200).map(|i| (Value::Int(100 + i), Value::Str("p".repeat(60))));
    Value::Map(pad.chain((0..3).map(|i| (Value::Int(i), Value::Strong(targets[i as usize % targets.len()])))).collect())
}

/// R2's world: three nodes of their own accounts; node 0 makes two things under `r2_setting`
/// (the first's history holding its targets) and grants nodes 1 and 2 write on the first (each
/// holds both). Built once (`LocalPeer::cached`).
fn r2_world() -> (LocalPeer, Vec<Tid>) {
    LocalPeer::cached("refs::r2_world", || {
        let mut lp = net(3, 0);
        let things: Vec<Tid> = (0..2).map(|_| new_thing(&mut lp, 0)).collect();
        for (i, t) in things.iter().enumerate() {
            let mut m = Mutation::new();
            m.set(*t, &ct::RETENTION, &r2_setting(i == 0)).unwrap();
            m.set(*t, &ak(MAP), &r2_map(&things)).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
        for j in 1..3 {
            let who = lp.peers[j].engine.me();
            lp.peers[0].engine.grant(&things[0], &who, &edge(osis_base::Role::Write)).unwrap();
        }
        lp.sync_all().unwrap();
        (lp, things)
    })
}

// spec/data-model.md §8 Known references, Held history (refgraph R2): after every step, at every
// node, the known references with kind equal a scan of the current values of every held aspect
// and of the held valid fires, and the strongs held history holds equal a scan of the held valid
// bodies where the setting says so. Three authors (an admin, two writers) on two things:
// nested values of any shape at any position (map keys, enum payloads, sets in lists), a large
// value, expiring writes and fires, removed aspects, replaced fires, purges of any held body,
// compactions, history bounds passing, the setting's flag turned on and off, and the writers
// removed and granted again; every commit reaches each other node in a random order, so writes
// arrive before or after the grants and removals judging them (valid, then invalid, or back).
#[test]
fn known_references_are_a_scan_of_held_values_spec_data_model_8() {
    use osis_base::Role;
    for seed in 1..=2u64 {
        let mut rng = crate::order::Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let (mut lp, things) = r2_world();
        let ids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        // targets: the things, an account root, one tid never got
        let mut targets = things.clone();
        targets.extend([lp.peers[0].engine.account_root().unwrap(), Tid::from_bytes([3; 15])]);
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
        // what each node is still to receive, taken in a random order
        let mut known: BTreeSet<CommitId> = (0..3).flat_map(|i| lp.peers[i].engine.commit_ids()).collect();
        let mut pending: [Vec<Package>; 3] = Default::default();
        let mut fires: Vec<(usize, Tid, CommitId)> = Vec::new();
        let sig = ak(SIG);
        const STEPS: u64 = 30;
        for step in 0..=STEPS {
            let t = things[rng.below(2) as usize];
            let (kind, mut by) = (rng.below(20), rng.below(3) as usize);
            if (10..16).contains(&kind) {
                by = 0;
            }
            let now = lp.peers[by].engine.now();
            let mut m = Mutation::new();
            let a = ak(HELD[rng.below(2) as usize]);
            let mut expiring = false;
            let writes = lp.peers[by].engine.role_on(&t).is_some_and(|r| r >= Role::Write);
            match kind {
                // the last step only delivers
                _ if step == STEPS || !writes => {}
                0..=2 | 13..=14 => drop(m.set(t, &a, &nested(&mut rng, 3)).unwrap()),
                3 => drop(m.remove_aspect(t, &a).unwrap()),
                4 => {
                    // a large value: paged in the store
                    let pad = Value::Str("p".repeat(70_000));
                    m.set(t, &ak("x:big.0"), &Value::List(vec![pad, nested(&mut rng, 2), reference(&mut rng)])).unwrap();
                }
                5 => {
                    let x = reference(&mut rng);
                    m.op(t, &REFS, osis_crdt::PathOp { path: vec![], op: if rng.below(3) == 0 { osis_crdt::Op::Remove(x) } else { osis_crdt::Op::Add(x) } }).unwrap();
                }
                6 => {
                    m.set(t, &ak("x:e.0"), &nested(&mut rng, 2)).unwrap();
                    m.expires(t, &ak("x:e.0"), WallMs(now.0 + 1_000)).unwrap();
                    expiring = true;
                }
                7..=8 => {
                    m.set(t, &sig, &nested(&mut rng, 2)).unwrap();
                    if rng.below(3) == 0 {
                        m.expires(t, &sig, WallMs(now.0 + 1_000)).unwrap();
                        expiring = true;
                    }
                    let own: Vec<CommitId> = fires.iter().filter(|f| f.0 == by && f.1 == t).map(|f| f.2).collect();
                    if !own.is_empty() && rng.below(3) > 0 {
                        m.replaces(t, &sig, own[rng.below(own.len() as u64) as usize]).unwrap();
                    }
                }
                9 => {
                    // a compaction: what it covers past its keep bound goes
                    let a = ak(HELD[rng.below(HELD.len() as u64) as usize]);
                    lp.peers[by].engine.snapshot(&t, &a).unwrap();
                }
                10..=11 => {
                    // the admin purges any held body, a fire's too
                    let mut held = Vec::new();
                    for a in HELD.iter().chain([&SIG]) {
                        held.extend(lp.peers[0].engine.body_page(&t, &ak(a), true, 0, usize::MAX).unwrap().into_iter().map(|b| (b.id, ak(a))));
                    }
                    if let Some(item) = held.get(rng.below(held.len() as u64) as usize).and_then(|(c, a)| lp.peers[0].engine.purge_item(c, t, a.clone())) {
                        // a purge request writes the purge time, new each time
                        lp.advance(1);
                        m.set(t, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
                        m.purge(item);
                    }
                }
                12 => drop(m.set(t, &ct::RETENTION, &r2_setting(rng.below(2) == 0)).unwrap()),
                16..=19 => {
                    // R2's paged map: a key put again whatever is live there, written into or
                    // removed (the records its writer holds), so one key holds several records,
                    // on different pages
                    let map = ak(MAP);
                    let k = Value::Int(rng.below(3) as i64);
                    if matches!(lp.peers[by].engine.get(&t, &map).unwrap(), Some(Value::Map(_))) {
                        let (path, op) = match kind {
                            16..=17 => (vec![osis_crdt::PathSeg::Key(k)], osis_crdt::Op::Put(nested(&mut rng, 2))),
                            18 => (vec![osis_crdt::PathSeg::Key(k)], osis_crdt::Op::Set(nested(&mut rng, 2))),
                            _ => (vec![], osis_crdt::Op::Remove(k)),
                        };
                        m.op(t, &map, osis_crdt::PathOp { path, op }).unwrap();
                    } else {
                        m.set(t, &map, &r2_map(&targets)).unwrap();
                    }
                }
                _ => {
                    // a writer removed (its writes the admin has not seen go invalid) and granted
                    // again: a node given the removal before the grant holds its later writes
                    // invalid until the grant comes
                    let (wi, t) = (1 + rng.below(2) as usize, things[0]);
                    let e = &mut lp.peers[0].engine;
                    let had: BTreeSet<CommitId> = e.commit_ids().into_iter().collect();
                    e.demote(&t, &osis_engine::flows::Demotion { holder: ids[wi], new: None, retain: None }).unwrap();
                    e.grant(&t, &ids[wi], &edge(Role::Write)).unwrap();
                    // the writer takes both and writes at once
                    for c in lp.peers[0].engine.commit_ids().into_iter().filter(|c| !had.contains(c)) {
                        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
                        lp.deliver(wi, &pk).unwrap();
                    }
                    by = wi;
                    m.set(t, &a, &nested(&mut rng, 3)).unwrap();
                }
            }
            // the nodes whose index may have moved this step
            let mut moved = [false; 3];
            moved[by] = true;
            moved[0] |= kind == 15;
            if !m.is_empty() {
                let c = lp.peers[by].commit(m).unwrap();
                if let Some(c) = c.filter(|_| (7..=8).contains(&kind)) {
                    fires.push((by, t, c));
                }
            }
            // every new commit (a node's own, its answers) goes to each other node
            for i in 0..3 {
                let root = lp.peers[i].engine.node_root();
                for id in lp.peers[i].engine.commit_ids() {
                    if !known.insert(id) || lp.peers[i].engine.header(&id).is_some_and(|h| h.aspects.iter().all(|a| Some(a.tid) == root)) {
                        continue;
                    }
                    let pk = lp.peers[i].engine.package(&id).unwrap().unwrap();
                    for j in (0..3).filter(|j| *j != i) {
                        pending[j].push(pk.clone());
                    }
                }
            }
            for (j, q) in pending.iter_mut().enumerate() {
                let n = if step == STEPS { q.len() } else { rng.below(q.len() as u64 + 1) as usize };
                moved[j] |= n > 0;
                for _ in 0..n {
                    let pk = q.swap_remove(rng.below(q.len() as u64) as usize);
                    lp.deliver(j, &pk).unwrap();
                }
            }
            if expiring || rng.below(4) == 0 {
                // past the history bound now and then
                lp.advance(if rng.below(5) == 0 { 2 * HOUR } else { 1_500 });
                for p in &mut lp.peers {
                    p.tick().unwrap();
                }
                moved = [true; 3];
            }
            for i in (0..3).filter(|i| moved[*i]) {
                let e = &mut lp.peers[i].engine;
                let (by_source, by_target, scanned) = index_and_scan(e, &things, &targets);
                assert_eq!(by_source, scanned, "seed {seed} step {step} node {i}: rows by source");
                assert_eq!(by_target, scanned, "seed {seed} step {step} node {i}: rows by target");
                let (index, scanned) = history_two_ways(e, &things, &targets);
                assert_eq!(index, scanned, "seed {seed} step {step} node {i}: held history's strongs");
                // the scan read each state whole: the next join meets it cold, its pages unloaded
                e.run(|tx| {
                    for (t, a) in things.iter().flat_map(|t| HELD.iter().map(move |a| (t, ak(a)))) {
                        tx.evict_pages(t, &a);
                    }
                    Ok(())
                })
                .unwrap();
            }
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

// spec/data-model.md §8 Known references: a fire's references go when it expires (held as its
// value-less leftover, with no state to strip)
#[test]
fn an_expired_fires_references_go_spec_data_model_8() {
    let mut lp = net(1, 0);
    let t = new_thing(&mut lp, 0);
    set_setting(&mut lp, 0, t, &r2_setting(false));
    let now = lp.peers[0].engine.now();
    let mut m = Mutation::new();
    m.set(t, &ak(SIG), &Value::Weak(t)).unwrap();
    m.expires(t, &ak(SIG), WallMs(now.0 + 1_000)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    assert_eq!(rows(&mut lp, 0, &t).into_iter().filter(|r| r.1 == SIG).count(), 1, "the fire's weak");
    lp.advance(1_500);
    lp.peers[0].tick().unwrap();
    assert_eq!(rows(&mut lp, 0, &t).into_iter().filter(|r| r.1 == SIG).collect::<Vec<_>>(), vec![], "expired");
}

// spec/data-model.md §8 What counts: a write the read hides (inside a map entry removed
// concurrently; inside the payload of an enum whose case a concurrent write of another shape
// reset; inside a list element deleted concurrently) holds no reference. Node 0 hides the position, node 1 writes a strong inside it unseen,
// node 0 takes it: the value reads without it, so no row names T (`Fragment::each_read_value`).
#[test]
fn a_hidden_write_holds_no_reference_spec_data_model_8() {
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut lp = net(2, 0);
    let t = new_thing(&mut lp, 0);
    let w = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&t, &w, &edge(osis_base::Role::Write)).unwrap();
    // a map entry, an enum and a list element, each with a strong written inside it later, unseen
    let (map, en, list) = (ak("x:a.0"), ak("x:b.0"), ak("x:c.0"));
    let mut m = Mutation::new();
    m.set(t, &map, &Value::Map([(Value::Int(1), Value::Int(0))].into_iter().collect())).unwrap();
    m.set(t, &en, &Value::Enum(1, Some(Box::new(Value::Int(0))))).unwrap();
    m.set(t, &list, &Value::List(vec![Value::List(vec![Value::Int(0)])])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.op(t, &map, PathOp { path: vec![], op: Op::Remove(Value::Int(1)) }).unwrap();
    m.set(t, &en, &Value::Int(1)).unwrap();
    m.set(t, &list, &Value::List(vec![])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    // later than the hiding writes: they survive the resets, hidden
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &map, PathOp { path: vec![PathSeg::Key(Value::Int(1))], op: Op::Set(Value::Strong(t)) }).unwrap();
    m.set(t, &en, &Value::Enum(1, Some(Box::new(Value::Strong(t))))).unwrap();
    m.set(t, &list, &Value::List(vec![Value::List(vec![Value::Int(0), Value::Strong(t)])])).unwrap();
    let c = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&c).unwrap().unwrap();
    lp.deliver(0, &pk).unwrap();
    let e = &mut lp.peers[0].engine;
    for a in [&map, &en, &list] {
        let read = e.get(&t, a).unwrap();
        let mut c = BTreeMap::new();
        if let Some(v) = &read {
            scan(v, &mut c);
        }
        assert!(c.is_empty(), "{a:?}: the read shows no strong: {read:?}");
    }
    assert_eq!(e.references_from(&t).unwrap().into_iter().filter(|r| [&map, &en, &list].contains(&&r.ak)).collect::<Vec<_>>(), vec![]);
}
