//! Growth with the number of writes (notes/growth.md): counts stored bytes and rows, never time.

use crate::net::*;
use osis_base::Role;
use std::collections::BTreeMap;

// spec/commits.md §5 (Own replaces, Forgetting), notes/growth.md rows 1 and 3: one writer replacing
// one small register n and 10n times, no membership change, stores the same bytes and rows at
// the writer, a reader and their host once tombstones have aged out; the writer keeps its newest
// body and the one before. Each step ends with a month of no writes, whose own small expiry
// and log noise is told apart by a control step of a month alone.
#[test]
fn single_writer_replace_grows_nothing() {
    let mut net = Net::new();
    let h = net.add_host();
    let a = net.node(1, &[h]);
    let b = net.node(2, &[h]);
    let g = net.group(a, &[(b, Role::Read)], &[h]);
    let t = net.item(a, g, g, "first");
    net.run();
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    let totals = |c: BTreeMap<String, (usize, usize)>| c.values().fold((0usize, 0usize), |x, v| (x.0 + v.0, x.1 + v.1));
    let at = |net: &mut Net, from: usize, to: usize| {
        for i in from..to {
            net.write(a, t, &format!("v{i:08}"));
            net.advance(1_000);
        }
        net.advance(32 * 24 * 3600 * 1000);
        let rows = net.hosts[h].hub.store().all_rows().unwrap();
        let host = (rows.len(), rows.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>());
        (totals(net.engine(a).local_census().unwrap()), totals(net.engine(b).local_census().unwrap()), host, net.engine(a).held_bodies(&t, &reg))
    };
    let (a1, b1, h1, _) = at(&mut net, 0, 50);
    let (a2, b2, h2, held) = at(&mut net, 50, 500);
    let (a3, b3, h3, _) = at(&mut net, 500, 500);
    assert_eq!(held, 2, "the newest body and the writer's previous");
    assert_eq!(net.read(a, t), Some(s("v00000499")), "writer reads the newest");
    assert_eq!(net.read(b, t), Some(s("v00000499")), "reader reads the newest");
    for (who, x1, x2, x3) in [("writer", a1, a2, a3), ("reader", b1, b2, b3), ("host", h1, h2, h3)] {
        // writes add no more than a month alone adds (expiry and log noise): a small constant
        let grew = |a: usize, b: usize, c: usize, eps: usize| b.saturating_sub(a) <= c.saturating_sub(b) + eps;
        assert!(grew(x1.0, x2.0, x3.0, 1) && grew(x1.1, x2.1, x3.1, 128), "{who} grew with writes: {x1:?} -> {x2:?}, a month alone -> {x3:?}");
    }
}

// spec: none (notes/growth.md). Probe: what grows with n, row kind by row kind. Run by hand with --ignored --nocapture.
#[test]
#[ignore = "probe"]
fn replace_census_probe() {
    let mut net = Net::new();
    let h = net.add_host();
    let a = net.node(1, &[h]);
    let g = net.group(a, &[], &[h]);
    let t = net.item(a, g, g, "first");
    net.run();
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
    let mut net = Net::new();
    let h = net.add_host();
    let a = net.node(1, &[h]);
    let b = net.node(2, &[h]);
    let g = net.group(a, &[(b, Role::Write)], &[h]);
    let t = net.item(a, g, g, "first");
    net.run();
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
    // a's first write goes (two newer own replaces cover it); a's two newest and b's two stay: an
    // own replace covers nothing of the other writer's
    assert_eq!(net.engine(a).held_bodies(&t, &reg), 4);
}
