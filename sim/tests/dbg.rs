#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
use osis_core::Role;
use osis_sim::harness::ClockSpec;
use osis_sim::net::{NetConfig, NetSim};

#[test]
fn dbg() {
    let mut sim = NetSim::new("dbg", 1, NetConfig::default());
    let s = sim.add_server().unwrap();
    let a = sim.add_node(&[s], ClockSpec::default()).unwrap();
    let b = sim.add_node(&[s], ClockSpec::default()).unwrap();
    let pa = sim.person(a, &[s]).unwrap().person;
    let pb = sim.person(b, &[s]).unwrap().person;
    sim.direct(b, a).unwrap();
    if std::env::var_os("WA").is_some() { sim.direct(a, b).unwrap(); }
    sim.run_until_quiescent(40).unwrap();
    let g = sim.group_with(a, pa, &[s], std::env::var_os("OWN").is_some()).unwrap();
    sim.grant(a, g, pb, Role::Write).unwrap();
    let r = sim.run_until_quiescent(40);
    r.unwrap();
    let t = sim.item(a, g).unwrap();
    sim.run_until_quiescent(40).unwrap();
    let mut m = osis_node::Mutation::new();
    m.set(t, &osis_sim::workload::REG, &osis_core::Value::Str("from b".into())).unwrap();
    let c = sim.commit(b, m).unwrap();
    eprintln!("b wrote {c:?}; role {:?}", sim.engine(b).unwrap().role_on(&t));
    sim.settle().unwrap();
    let gl = sim.sync(a).unwrap().labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    let key = sim.servers[0].key;
    eprintln!("b labels {:?}", sim.sync(b).unwrap().labels().iter().map(|(g, l)| (*g, l.id)).collect::<Vec<_>>());
    eprintln!("b verdicts {:?}", sim.sync(b).unwrap().verdicts(&key, &gl));
    for n in [a, b] { eprintln!("{n} epochs of g {:?}", sim.engine(n).unwrap().epochs(&g).map(|e| [&e.read, &e.write].iter().map(|r| r.epochs().map(|(x, i)| (x.n(), i.secret.is_some(), i.established)).collect::<Vec<_>>()).collect::<Vec<_>>())); }
    let r = sim.run_until_quiescent(40);
    eprintln!("pa {pa} pb {pb} g {g} a {} b {}", sim.tid(a).unwrap(), sim.tid(b).unwrap());
    let gl = sim.sync(a).unwrap().labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    for (bl, k) in sim.sync(b).unwrap().entries(&gl) {
        let h = if let osis_node::sync::EntryKind::Commit { commit, .. } = &k { sim.engine(b).unwrap().header(commit).map(|h| h.aspects.iter().map(|x| (x.tid, x.ak.as_str().to_string())).collect::<Vec<_>>()) } else { None };
        eprintln!("b knows under g's label: {bl:?} {k:?} {h:?}");
    }
    eprintln!("b roster of pa: {:?}", sim.engine(b).unwrap().roster(&pa));
    sim.engine(b).unwrap().reexamine().unwrap();
    eprintln!("b pending after reexamine: {:?}", sim.engine(b).unwrap().pending());
    for n in [a, b] {
        let sy = sim.sync(n).unwrap();
        eprintln!("node {n} labels {:?}", sy.labels().iter().map(|(g, l)| (*g, l.id)).collect::<Vec<_>>());
        eprintln!("node {n} describe {:?}", sy.describe());
        for (gg, l) in sy.labels() {
            eprintln!(" label of {gg}:");
            for (b, k) in sy.entries(&l.id) {
                if let osis_node::sync::EntryKind::Commit { commit, parts } = k {
                    let h = sy.engine().header(&commit);
                    eprintln!("   {b:?} {commit:?} {parts:?} {:?}", h.map(|h| (h.author, h.aspects.iter().map(|x| (x.tid, x.ak.as_str().to_string())).collect::<Vec<_>>())));
                } else {
                    eprintln!("   {b:?} {k:?}");
                }
            }
        }
        eprintln!("node {n} pending {:?}", sy.engine().pending());
        for (c, _) in sy.engine().pending() {
            let h = sy.engine_mut().commit_bytes(&c).unwrap().map(|b| osis_commit::CommitBlob::decode(&b).unwrap().header);
            if let Some(h) = h {
                eprintln!("   {c:?} author {} kind {:?} aspects {:?}", h.author, h.kind, h.aspects.iter().map(|x| (x.tid, x.ak.as_str().to_string())).collect::<Vec<_>>());
            }
        }
    }
    r.unwrap();
}
