//! Growth with the number of writes (notes/growth.md): counts stored bytes and rows, never time.

use crate::net::hosted;
use crate::net::*;
use osis_base::Role;
use std::collections::BTreeMap;

// spec/commits.md §5 (Own replaces, Forgetting), notes/growth.md row 1: one writer replacing
// one small register n and 10n times, no membership change, stores the same bytes and rows at
// the writer, a reader and their host once tombstones have aged out; the writer keeps its newest
// body and the one before. Each step ends with a month of no writes. A further month with no
// writes at all holds steady too.
#[test]
fn single_writer_replace_grows_nothing() {
    let (mut net, h, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["first"], true);
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    let census = |net: &mut Net, n: usize| net.engine(n).local_census().unwrap();
    let host = |net: &mut Net| {
        let mut c: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (k, v) in net.hosts[h].hub.store().all_rows().unwrap() {
            let e = c.entry(String::from_utf8_lossy(&k[..1.min(k.len())]).into_owned()).or_default();
            e.0 += 1;
            e.1 += k.len() + v.len();
        }
        c
    };
    let at = |net: &mut Net, from: usize, to: usize| {
        for i in from..to {
            net.write(a, t, &format!("v{i:08}"));
            net.advance(1_000);
        }
        net.advance(32 * 24 * 3600 * 1000);
        (census(net, a), census(net, b), host(net), net.engine(a).held_bodies(&t, &reg))
    };
    // what setting up left settles first
    at(&mut net, 0, 0);
    at(&mut net, 0, 0);
    let (a1, b1, h1, _) = at(&mut net, 0, 20);
    let (a2, b2, h2, held) = at(&mut net, 20, 200);
    // a month settles the last write's deletes at the host, then a month alone adds nothing
    let (a2b, b2b, h2b, _) = at(&mut net, 200, 200);
    let (a3, b3, h3, _) = at(&mut net, 200, 200);
    assert_eq!(held, 3, "the newest body, the writer's previous and the creating commit, whole");
    assert_eq!(net.read(a, t), Some(s("v00000199")), "writer reads the newest");
    assert_eq!(net.read(b, t), Some(s("v00000199")), "reader reads the newest");
    for (who, x1, x2, x2b, x3) in [("writer", &a1, &a2, &a2b, &a3), ("reader", &b1, &b2, &b2b, &b3), ("host", &h1, &h2, &h2b, &h3)] {
        flat(who, "n to 10n writes", x1, x2);
        flat(who, "a month with no writes", x2b, x3);
    }
}

/// Rows and bytes of every row kind, equal between two censuses (a few bytes for a row whose
/// counters widened).
fn flat(who: &str, step: &str, a: &BTreeMap<String, (usize, usize)>, b: &BTreeMap<String, (usize, usize)>) {
    let grew: Vec<_> = a.keys().chain(b.keys()).collect::<std::collections::BTreeSet<_>>().into_iter().map(|k| (k, a.get(k).copied().unwrap_or_default(), b.get(k).copied().unwrap_or_default())).filter(|(_, x, y)| y.0 > x.0 || y.1 > x.1 + 32).collect();
    assert!(grew.is_empty(), "{who}: {step} grew: {grew:?}");
}

// spec: none (notes/growth.md). Probe: what grows with n, row kind by row kind. Run by hand with --ignored --nocapture.
#[test]
#[ignore = "probe"]
fn replace_census_probe() {
    let (mut net, h, [a], _g, [t]) = hosted::<1, 1>(&[], ["first"], true);
    let run = |net: &mut Net, from: usize, to: usize| {
        for i in from..to {
            net.write(a, t, &format!("v{i:08}"));
            net.run();
            net.advance(1_000);
        }
    };
    let snap = |net: &mut Net| {
        let n = net.engine(a).local_census().unwrap();
        let hr = net.hosts[h].hub.store().all_rows().unwrap();
        let mut hc: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (k, v) in &hr {
            let e = hc.entry(format!("{:?}", String::from_utf8_lossy(&k[..1.min(k.len())]))).or_default();
            e.0 += 1;
            e.1 += k.len() + v.len();
        }
        (n, hc)
    };
    run(&mut net, 0, 50);
    net.advance(32 * 24 * 3600 * 1000);
    let (n1, h1) = snap(&mut net);
    run(&mut net, 50, 500);
    net.advance(32 * 24 * 3600 * 1000);
    let (n2, h2) = snap(&mut net);
    for (label, a, b) in [("node", &n1, &n2), ("host", &h1, &h2)] {
        for k in a.keys().chain(b.keys()).collect::<std::collections::BTreeSet<_>>() {
            let (x, y) = (a.get(k).copied().unwrap_or_default(), b.get(k).copied().unwrap_or_default());
            eprintln!("{label} {k:?}: {x:?} -> {y:?}");
        }
    }
}

// spec/commits.md §5 (Own replaces): a writer's path write does not replace the aspect, so it covers
// nothing and every body stays; another writer's whole replace covers none of a first's bodies.
#[test]
fn only_a_whole_own_replace_covers() {
    let (mut net, _h, [a, b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["first"], true);
    let bag = osis_base::Ak::new("t:big.0").unwrap();
    for i in 0..4 {
        let mut m = osis_node::Mutation::new();
        m.op(t, &bag, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(s(&format!("k{i}")))], op: osis_crdt::Op::Put(s("x")) }).unwrap();
        net.engine(a).commit(m).unwrap();
        net.advance(1_000);
    }
    assert_eq!(net.engine(a).held_bodies(&t, &bag), 4, "path writes replace nothing");
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    for i in 0..4 {
        let n = if i % 2 == 0 { a } else { b };
        net.write(n, t, &format!("v{i}"));
        net.advance(1_000);
        net.run();
    }
    // the creating commit stays whole; a's first write goes (two newer own replaces cover it);
    // a's two newest and b's two stay: an own replace covers nothing of the other writer's
    assert_eq!(net.engine(a).held_bodies(&t, &reg), 5);
}


// spec/commits.md §5 (Own replaces), spec/sync.md §6: a commit with a part own replaces cover and
// a part they do not stays whole: nothing the host holds is judged must-not, and every node
// can still relay its other part.
#[test]
fn own_replace_of_one_part_keeps_the_other() {
    let (mut net, h, [a, _b], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["first"], true);
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    let other = osis_base::Ak::new("t:other.0").unwrap();
    let mut m = osis_node::Mutation::new();
    m.set(t, &reg, &s("v0")).unwrap();
    m.set(t, &other, &s("o")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    for i in 1..=3 {
        net.write(a, t, &format!("v{i}"));
        net.advance(1_000);
        net.run();
    }
    assert_eq!(net.engine(a).held_bodies(&t, &reg), 4, "the creating and mixed commits stay whole, then the two newest");
    assert_eq!(net.engine(a).get(&t, &other).unwrap(), Some(s("o")), "the other part stays");
    net.settle(5);
    let key = net.address(h).key;
    let l = net.label(a);
    let v = net.sync(a).verdicts(&key, &l).unwrap().unwrap();
    assert!(v.must_not.is_empty(), "nothing must-not at the host: {:?}", v.must_not);
}

// spec/commits.md §5 (Own replaces, Forgetting), spec/sync.md §6: a reader offline through the
// writes (a late joiner), and a copy of the writer's store taken early and offline since (a
// restored device, holding replaces the writer later forgot), catch up: each reads the newest,
// holds no more bodies than the writer, and judges nothing the host holds must-not.
#[test]
fn late_reader_and_restored_device_catch_up() {
    let (mut net, h, [a, late], _g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["first"], true);
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    net.set_online(late, false);
    for i in 0..10 {
        net.write(a, t, &format!("v{i}"));
        net.advance(1_000);
        net.run();
    }
    let dev = net.copy_node(a, 9);
    net.set_online(dev, false);
    for i in 10..40 {
        net.write(a, t, &format!("v{i}"));
        net.advance(1_000);
        net.run();
    }
    net.advance(32 * 24 * 3600 * 1000);
    net.run();
    net.set_online(late, true);
    net.set_online(dev, true);
    net.run();
    net.advance(32 * 24 * 3600 * 1000);
    net.run();
    let writer = net.engine(a).held_bodies(&t, &reg);
    let key = net.address(h).key;
    let l = net.label(a);
    for (who, n) in [("writer", a), ("late reader", late), ("restored device", dev)] {
        assert_eq!(net.read(n, t), Some(s("v39")), "{who} reads the newest");
        assert!(net.engine(n).held_bodies(&t, &reg) <= writer, "{who} holds no more than the writer");
        let v = net.sync(n).verdicts(&key, &l).unwrap().unwrap();
        assert!(v.must_not.is_empty(), "{who}: must-not at the host: {:?}", v.must_not);
    }
}

// spec/commits.md §5 (Own replaces, Forgetting), notes/coordination.md (count work): three writers
// replacing one register in turn do the same cover joins and forgetting checks per write after
// n and 10n writes, whatever the history held or forgotten.
#[test]
fn own_cover_work_per_write_is_flat() {
    let mut net = Net::new();
    let h = net.add_host();
    let ws: Vec<usize> = (1..=3).map(|i| net.node(i, &[h])).collect();
    let g = net.group(ws[0], &[(ws[1], Role::Write), (ws[2], Role::Write)], &[h]);
    let t = net.item(ws[0], g, g, "first");
    net.run();
    let count = |net: &mut Net, from: usize, to: usize| {
        osis_node::costs::take();
        for i in from..to {
            net.write(ws[i % 3], t, &format!("v{i:08}"));
            net.advance(1_000);
            net.run();
        }
        let c = osis_node::costs::take();
        let n = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
        (n("covered: join"), n("forgettable"))
    };
    count(&mut net, 0, 6);
    let (j1, f1) = count(&mut net, 6, 12);
    count(&mut net, 12, 120);
    let (j2, f2) = count(&mut net, 120, 126);
    assert!(j1 > 0, "covers are judged");
    assert!(j2 <= j1 + j1 / 2 && f2 <= f1 + f1 / 2 + 3, "work per write grew with history: joins {j1} -> {j2}, forget checks {f1} -> {f2}");
}

// spec/commits.md §5 (Own replaces, Between the bounds): a commit goes only whole, so a part its
// author's replaces cover but its author may not purge (the aspect's purge right is the admin's)
// keeps every other part of the commit too, at the writer and a reader.
#[test]
fn a_part_without_the_right_keeps_its_commit_whole() {
    let (mut net, _h, [_a, b, r], _g, [t]) = hosted::<3, 1>(&[(1, Role::Write), (2, Role::Read)], ["first"], true);
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    let kept = osis_base::Ak::new("t:kept.0").unwrap();
    for i in 0..3 {
        let mut m = osis_node::Mutation::new();
        m.set(t, &reg, &s(&format!("v{i}"))).unwrap();
        m.retention(t, &kept, osis_schema::Retention { by: osis_schema::PurgeBy::Admin, history: None }).unwrap();
        m.set(t, &kept, &s(&format!("k{i}"))).unwrap();
        net.engine(b).commit(m).unwrap().unwrap();
        net.advance(1_000);
        net.run();
    }
    net.advance(2 * 3_600_000);
    net.settle(5);
    for n in [b, r] {
        assert_eq!(net.engine(n).held_bodies(&t, &kept), 3, "node {n}: the admin's right");
        assert_eq!(net.engine(n).held_bodies(&t, &reg), 4, "node {n}: the creating commit and b's three, whole");
    }
}
