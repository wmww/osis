#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Revokes about authors seen under a label (spec/permissions.md §4): a holder that syncs the
//! label and holds the revoke places it there, so verifiers judge the author's writes alike.

use crate::net;
use net::*;
use osis_base::Role;
use osis_node::flows::{Demotion, PreSync};
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

// spec/permissions.md §4 (chain certificates: current `keys.0` of the actors on a path): W writes
// in G through team X; X's admin B, who does not sync G, removes W from X (the commit writes X's
// new keyset); R, a holder of X that syncs G through it, places it under G's label as X's current
// keys, and G's admin, finding its box to X stale, rotates: W reads nothing new.
#[test]
fn revoke_about_author_placed_spec_permissions_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let r = net.node(4, &[host]);
    let x = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(host)], 1);
    net.name_inbox_elsewhere(b, x);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(host)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &x, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.pair(a, w);
    net.pair(a, r);
    net.run();
    assert_eq!(net.engine(w).role_on(&g), Some(Role::Write));
    let t = net.item(w, g, g, "by w");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("by w")));
    let lg = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(net.sync(b).labels().iter().all(|(x, _)| *x != g), "B does not sync G");
    let wt = net.tid(w);
    let done = net.engine(b).demote(&x, &Demotion { holder: wt, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    let removal = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&removal).is_some(), "R holds the revoke");
    let ids = net.host_ids(host, &lg);
    let placed = net.sync(r).entries(&lg).into_iter().any(|(id, k)| ids.contains(&id) && matches!(k, EntryKind::Commit { commit, .. } if commit == removal));
    assert!(placed, "the revoke of W on X is under G's label");
    // G's admin learns of it there and rotates G: W reads nothing new
    let u = net.item(a, g, g, "after w left");
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(a).header(&removal).is_some(), "the admin holds the revoke");
    assert_eq!(net.read(r, u), Some(s("after w left")));
    assert_eq!(net.read(w, u), None);
}

// spec/permissions.md §4 (chain certificates: current `keys.0` of the actors on a path),
// spec/crypto.md §4 (holder actors: stale): G <- X1 <- X2 <- {W, R}; X2's admin B, who does not
// sync G, removes W from X2 (rotating X2), then rotates X1 (its box to X2 stale); R reads G
// through two levels, may not rotate it, and is not held back by the stale box: it places X1's new
// keys under G's label. W, still a writer of G through X1 in its own view and in that of G's admin
// (who never learns W left X2), finds G's box to X1 stale too but holds no secret of X1's new
// keyset, so it may not rotate G (spec/crypto.md §4, Possession): it waits, and G's admin rotates.
#[test]
fn nested_departure_removed_writer_waits_spec_crypto_4() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let r = net.node(4, &[host]);
    let x2 = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(host)], 1);
    let x1 = net.group_seeded(b, &[], vec![net.address(host)], 2);
    net.name_inbox_elsewhere(b, x2);
    net.name_inbox_elsewhere(b, x1);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
    let done = net.engine(b).grant(&x1, &x2, &edge).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(host)], 3);
    let done = net.engine(a).grant(&g, &x1, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.pair(a, w);
    net.pair(a, r);
    net.run();
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.engine(w).role_on(&g), Some(Role::Write));
    assert_eq!(net.engine(r).role_on(&g), Some(Role::Read));
    let t = net.item(a, g, g, "before");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("before")));
    assert_eq!(net.read(w, t), Some(s("before")));
    let lg = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(net.sync(b).labels().iter().all(|(x, _)| *x != g), "B does not sync G");
    let wt = net.tid(w);
    let done = net.engine(b).demote(&x2, &Demotion { holder: wt, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    let removal = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&removal).is_some(), "R holds the revoke");
    // X1's new keys (B rotated X1: its box to X2 stale) reach G's label as R's chain certificate
    let ids = net.host_ids(host, &lg);
    let placed: BTreeSet<_> = net.sync(r).entries(&lg).into_iter().filter(|(id, _)| ids.contains(id)).filter_map(|(_, k)| if let EntryKind::Commit { commit, .. } = k { Some(commit) } else { None }).collect();
    let x1k = net.engine(r).current_keys(&x1);
    assert!(x1k.iter().any(|c| placed.contains(c)), "X1's current keys.0 under G's label");
    let u = net.item(a, g, g, "after w left");
    for _ in 0..4 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, u), Some(s("after w left")));
    assert_eq!(net.read(w, u), None, "W reads nothing written after it left");
}

// spec/permissions.md §4: a revoke on a thing the label's actor has no holder path from carries no keyset: W's removal from M, a stranger to G, has M's fresh deposit seed
#[test]
fn revoke_on_an_unrelated_thing_brings_no_keys() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let w = net.node(3, &[host]);
    let r = net.node(4, &[host]);
    let x = net.group_seeded(b, &[(w, Role::Write), (r, Role::Read)], vec![net.address(host)], 1);
    net.name_inbox_elsewhere(b, x);
    let m = net.group_seeded(b, &[(w, Role::Read), (r, Role::Read)], vec![net.address(host)], 3);
    net.pair(b, a);
    let g = net.group_seeded(a, &[], vec![net.address(host)], 2);
    let edge = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &x, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.pair(a, w);
    net.pair(a, r);
    net.run();
    let t = net.item(w, g, g, "by w");
    for _ in 0..2 {
        net.advance(31_000);
    }
    assert_eq!(net.read(r, t), Some(s("by w")));
    let lg = net.sync(a).labels().into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    assert!(net.sync(b).labels().iter().all(|(x, _)| *x != g), "B does not sync G");
    let wt = net.tid(w);
    let done = net.engine(b).demote(&m, &Demotion { holder: wt, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    let rm = *done.commits.first().unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    let done = net.engine(b).demote(&x, &Demotion { holder: wt, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(r).header(&rm).is_some(), "R holds the revoke");
    let ids = net.host_ids(host, &lg);
    let h = net.engine(r).header(&rm).unwrap();
    let placed: Vec<Vec<usize>> = net.sync(r).entries(&lg).into_iter().filter(|(id, _)| ids.contains(id)).filter_map(|(_, k)| match k {
        EntryKind::Commit { commit, parts, .. } if commit == rm => Some(parts),
        _ => None,
    }).collect();
    assert!(!placed.is_empty(), "the revoke is under G's label");
    assert!(placed.iter().flatten().all(|ai| h.aspects[*ai].ak.as_str() != "keys.0"), "no keyset of M");
}

fn carry(net: &mut Net, n: usize, done: osis_node::flows::Done) {
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
}

fn brief(net: &mut Net, name: &str, n: usize, c: osis_base::Tid, k: osis_base::Tid) {
    let mut line = String::new();
    for (lbl, t) in [("C", c), ("K", k)] {
        if let Some(ep) = net.engine(n).epochs(&t) {
            let re = ep.role(Role::Read);
            let cur: Vec<String> = re.epochs().map(|(e, i)| format!("{}.{}{}{}", e.n(), e.nonce()[0], if i.secret.is_some() { "+" } else { "-" }, if re.is_current(e) { "*" } else { "" })).collect();
            line.push_str(&format!(" {lbl}:{cur:?}"));
        }
    }
    let rc: Vec<String> = net.engine(n).core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role() && m.view.aspects.iter().any(|a| a.tid == c)).map(|(id, m)| format!("{}@{}", &format!("{id:?}")[9..13], m.view.ts.to_u64() % 1000)).collect();
    let me = net.tid(n);
    let deps = net.engine(n).departures(&c).unwrap();
    let blocked = net.engine(n).run(|tx| osis_node::rotation::blocked_roles_of(tx, &me, &c, &deps)).unwrap();
    let st: Vec<String> = net.sync(n).label_status().into_iter().filter(|s| s.group == c).map(|s| format!("open={} idle={} stranded={} refused={}", s.open, s.idle, s.stranded, s.refused)).collect();
    let diags = net.diagnostics(n);
    eprintln!("[{name}] node {n}{line} C-role-commits={rc:?} deps={} blocked={blocked:?} st={st:?} diags={diags:?}", deps.len());
}

/// TEMP probe
fn probe_c(net: &mut Net, name: &str, n: usize, c: osis_base::Tid, host: usize) {
    let ep = net.engine(n).epochs(&c);
    eprintln!("[{name}] node {n} C: roster={:?}", net.engine(n).roster(&c).iter().map(|(h, e)| format!("{h}:{:?}", e.role)).collect::<Vec<_>>());
    if let Some(ep) = ep {
        for r in [Role::Read, Role::Write, Role::Admin] {
            let re = ep.role(r);
            for (e, info) in re.epochs() {
                let rots: Vec<String> = info.rotations.iter().map(|(id, l)| format!("{:?}->{:?}", id, l.iter().map(|x| (x.n(), x.nonce()[0])).collect::<Vec<_>>())).collect();
                eprintln!("    {r:?} n={} nonce={} secret={} est={:?} cur={} sup={:?} rots={rots:?}", e.n(), e.nonce()[0], info.secret.is_some(), info.established.is_some(), re.is_current(e), info.supersedes.iter().map(|x| (x.n(), x.nonce()[0])).collect::<Vec<_>>());
            }
        }
    }
    if let Some(sec) = net.engine(n).get_typed(&c, &ct::SECRETS).unwrap() {
        for (k, b) in &sec.boxes {
            let form = match b {
                ct::SecretBox::Sealed(b) => format!("sealed at keyset {:?}", b.keyset.as_ref().map(|e| (e.n, e.nonce[0]))),
                ct::SecretBox::Symmetric(b) => format!("symmetric at {:?}", (b.epoch.n, b.epoch.nonce[0])),
            };
            eprintln!("    box {} {:?} ({}, {}) {form}", k.holder, k.role, k.epoch.n, k.epoch.nonce[0]);
        }
    }
    let commits: Vec<String> = net.engine(n).core.ix.commits.iter().filter(|(_, m)| m.view.aspects.iter().any(|a| a.tid == c)).map(|(id, m)| {
        let aks: Vec<String> = m.view.aspects.iter().enumerate().filter(|(_, a)| a.tid == c).map(|(i, a)| format!("{}{}", a.ak.as_str(), if m.valid.get(i).copied().unwrap_or(false) { "" } else { "!" })).collect();
        format!("{:?}@{:?} by {} {:?} {:?}", m.view.kind, m.view.ts, m.view.author, aks, id)
    }).collect();
    for x in commits { eprintln!("    {x}"); }
    let labels: Vec<(osis_base::Tid, osis_base::LabelId)> = net.sync(n).labels().into_iter().filter(|(g, _)| *g == c).map(|(g, l)| (g, l.id)).collect();
    for (_, l) in labels {
        let at_host = net.host_ids(host, &l);
        let mine: Vec<String> = net.sync(n).entries(&l).into_iter().map(|(id, k)| format!("{:?} {}", id, match k { EntryKind::Commit { commit, .. } => format!("commit {commit:?}"), EntryKind::Unknown => "unknown".into(), other => format!("{other:?}") })).collect();
        eprintln!("    label {l:?}: host has {} entries; node knows {}:", at_host.len(), mine.len());
        for m in mine { eprintln!("        {m}"); }
        for h in at_host { eprintln!("        host: {h:?}"); }
    }
    let d = net.diagnostics(n);
    if !d.is_empty() { eprintln!("    diags: {d:?}"); }
}

// TEMP repro of issues/link-leave-splits-thing.md at the node level
#[test]
fn tmp_link_leave_node_repro() {
    use osis_node::Mutation;
    let mut net = Net::new();
    let host = net.add_host();
    let home = vec![net.address(host)];
    let a = net.node(40, &[host]);
    let b = net.node(41, &[host]);
    let d = net.node(42, &[host]);
    let (pa, done) = net.engine(a).create_person(&home).unwrap();
    carry(&mut net, a, done);
    let (pb, done) = net.engine(b).create_person(&home).unwrap();
    carry(&mut net, b, done);
    let (pd, done) = net.engine(d).create_person(&home).unwrap();
    carry(&mut net, d, done);
    net.run();
    eprintln!("A node {} B node {} D node {}; pa {} pb {} pd {}", net.tid(a), net.tid(b), net.tid(d), pa.person, pb.person, pd.person);
    // a plain thing with content, then synced as a group of itself (`Osis::sync`: own secrets, then a label)
    let e = net.engine(a);
    let mut m = Mutation::new();
    let c = e.new_thing(&mut m, pa.person);
    m.set(c, &REG, &s("hi")).unwrap();
    e.commit(m).unwrap();
    let done = net.engine(a).give_own_secrets(&c).unwrap();
    carry(&mut net, a, done);
    let (_, acts) = net.sync(a).create_label(&c, home.clone()).unwrap();
    net.actions(a, acts);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: c, role: Role::Write, until: None, hosts: home.clone(), peers: Vec::new(), single_use: false };
    let (link, _, done) = net.engine(a).create_link(&pa.person, &spec).unwrap();
    carry(&mut net, a, done);
    net.run();
    eprintln!("C {c} K {}", link.k);
    for (x, px) in [(b, pb.person), (d, pd.person)] {
        let held = net.engine(x).hold_key_actor(link.seed.clone()).unwrap();
        let acts = net.sync(x).follow(held, link.k, link.k_label, link.hosts.clone());
        net.actions(x, acts);
        net.run();
        let done = net.engine(x).redeem(&link, &px, false).unwrap();
        net.engine(x).drop_key_actor(&held);
        carry(&mut net, x, done);
        net.run();
    }
    assert_eq!(net.read(d, c), Some(s("hi")));
    probe_c(&mut net, "before leave", a, c, host);
    probe_c(&mut net, "before leave", d, c, host);
    // B leaves: its own grant is on K
    let done = net.engine(b).demote(&link.k, &Demotion { holder: pb.person, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    carry(&mut net, b, done);
    for n in 0..net.nodes.len() {
        net.feed(n, osis_node::sync::Event::Local);
    }
    let mut r = 0;
    while net.queue_len() > 0 && r < 400 {
        net.round();
        r += 1;
        for n in [a, d] {
            brief(&mut net, &format!("round {r}"), n, c, link.k);
        }
    }
    net.run();
    probe_c(&mut net, "after leave", a, c, host);
    probe_c(&mut net, "after leave", d, c, host);
    probe_c(&mut net, "after leave K", a, link.k, host);
    probe_c(&mut net, "after leave K", d, link.k, host);
    net.write(d, c, "still here");
    net.run();
    probe_c(&mut net, "after write", a, c, host);
    probe_c(&mut net, "after write", d, c, host);
    assert_eq!(net.read(a, c), Some(s("still here")));
}
