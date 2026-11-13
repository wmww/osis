#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Destroying a thing at the node level (spec/commits.md §5 Destruction, spec/permissions.md §6): what
//! outlasts it, restarts, stale copies, a fall, and its cost.

use crate::net::hosted;
use crate::net;
use net::*;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_node::{Ingested, Mutation};
use osis_schema::core_types as ct;
use osis_schema::{Codec, RawKey};
use osis_crdt::{Op, PathOp};

/// Node indices and the group of `setup`.
struct Setup {
    net: Net,
    a: usize,
    b: usize,
    c: usize,
    g: Tid,
}

/// A group on one host: a its admin, b a writer, c an admin too.
fn setup() -> Setup {
    let (net, _host, [a, b, c], g, []) = hosted::<3, 0>(&[(1, Role::Write), (2, Role::Admin)], [], true);
    Setup { net, a, b, c, g }
}

/// A thing in `g`, first admin `g`, valued "x" in the commit that creates it (returned).
fn made(net: &mut Net, n: usize, g: Tid) -> (Tid, CommitId) {
    let mut m = Mutation::new();
    let t = net.engine(n).new_thing(&mut m, g);
    m.set(t, &REG, &s("x")).unwrap();
    let mut items = net.engine(n).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(t);
    m.set(g, &ct::GROUP, &items).unwrap();
    let c = net.engine(n).commit(m).unwrap().unwrap();
    net.run();
    (t, c)
}

/// A demotion of `holder` on `thing` written by node `n` (an explicit write naming what it audited).
fn demote(net: &mut Net, n: usize, thing: Tid, holder: Tid, role: Role) {
    let mut m = Mutation::new();
    let edge = ct::Edge { role, until: None, invite: None, tied: None };
    m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
    m.op(thing, &ct::ROLES, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(holder))], op: Op::Set(edge.to_value()) }).unwrap();
    m.frontier(ct::Frontier::default().to_value());
    net.engine(n).commit(m).unwrap().unwrap();
}

fn purge_thing(net: &mut Net, by: usize, t: Tid) -> CommitId {
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(net.now())).unwrap();
    m.purge(PurgeItem::Aspect { tid: t, ak: Ak::new(ct::CREATED.ak()).unwrap() });
    net.engine(by).commit(m).unwrap().unwrap()
}

/// Nothing of `t` reads as existing at node `n`.
#[track_caller]
fn gone(net: &mut Net, n: usize, t: Tid) {
    assert_eq!(net.read(n, t), None, "node {n}: its value");
    let e = net.engine(n);
    assert!(!e.knows(&t), "node {n}: known");
    assert!(!e.has_content(&t).unwrap(), "node {n}: content");
    assert!(e.roster(&t).is_empty(), "node {n}: roster");
    for ak in ["tid.0", "aspects.0", "groups.0", "roles.0", ct::PURGE.ak(), ct::RELEASED.ak(), ct::CREATED.ak()] {
        assert_eq!(e.get(&t, &Ak::new(ak).unwrap()).unwrap(), None, "node {n}: {ak}");
    }
    let mut m = Mutation::new();
    m.set(t, &REG, &s("late")).unwrap();
    assert!(matches!(e.commit(m), Err(osis_node::Error::UnknownThing(_))), "node {n}: a write refused as unknown");
}

// spec/commits.md §5 (Destruction): a destruction holds over a restart, and nothing of the thing reads as
// existing
#[test]
fn destroyed_stays_destroyed_over_a_restart_spec_commits_5() {
    let Setup { mut net, a, b, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    net.write(b, t, "y");
    net.run();
    purge_thing(&mut net, a, t);
    net.run();
    for n in [a, b] {
        gone(&mut net, n, t);
    }
    net.restart(b, 77);
    net.run();
    gone(&mut net, b, t);
    assert!(net.read(b, g).is_some() || net.read(a, g) == net.read(b, g));
}

// spec/permissions.md §6 (Destruction), spec/commits.md §5: an admin by a grant on the thing alone may
// destroy it, and the verdict reads the edges the destruction keeps: a stale copy of the creation arriving
// while the request is held destroys the thing again, also after a restart
#[test]
fn a_grant_holder_destroys_and_a_stale_copy_is_destroyed_again_spec_permissions_6() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, creation) = made(&mut net, a, g);
    let tc = net.tid(c);
    net.grant(a, t, tc, Role::Admin);
    demote(&mut net, a, g, tc, Role::Read);
    net.run();
    let stale = net.engine(a).package(&creation).unwrap().unwrap();
    purge_thing(&mut net, c, t);
    net.run();
    gone(&mut net, b, t);
    let _ = net.engine(b).ingest(&stale.bytes, Vec::new());
    gone(&mut net, b, t);
    net.restart(b, 78);
    let _ = net.engine(b).ingest(&stale.bytes, Vec::new());
    gone(&mut net, b, t);
    net.run();
    for n in [a, b, c] {
        gone(&mut net, n, t);
    }
}

// spec/requirements.md Deletion; Tess's ruling on a fallen destruction: a demotion ordered before the
// request makes the destruction fall where it is held; the thing comes back from a node holding a copy
#[test]
fn a_destruction_that_falls_comes_back_from_a_copy_spec_commits_5() {
    let Setup { mut net, a, b, c, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    let tb = net.tid(b);
    net.grant(a, g, tb, Role::Admin);
    net.run();
    // c demotes b concurrently: its demotion is earlier than b's request, and b has not seen it
    net.set_online(c, false);
    demote(&mut net, c, g, tb, Role::Read);
    net.advance(10);
    purge_thing(&mut net, b, t);
    net.run();
    gone(&mut net, a, t);
    assert_eq!(net.read(c, t), Some(s("x")), "c never heard");
    net.set_online(c, true);
    net.run();
    net.advance(120_000);
    net.advance(120_000);
    assert_eq!(net.read(c, t), Some(s("x")), "the destruction fell at c, which holds a copy");
    assert_eq!(net.read(a, t), Some(s("x")), "the destruction fell at a: the copy comes back");
    assert_eq!(net.read(b, t), Some(s("x")), "and at the demoted b");
}

// spec/commits.md §4 (Unjudgeable), §5 (Destruction): a late write on a destroyed thing is a write on an
// unknown thing: nothing of it is kept, and it does not come back while the destruction stands
#[test]
fn a_late_write_awaits_a_destroyed_thing_spec_commits_5() {
    let Setup { mut net, a, b, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    net.set_online(b, false);
    let late = net.write(b, t, "late");
    let pk = net.engine(b).package(&late).unwrap().unwrap();
    purge_thing(&mut net, a, t);
    net.run();
    assert!(matches!(net.engine(a).ingest(&pk.bytes, Vec::new()).unwrap(), Ingested::Awaits(..)));
    assert!(!net.engine(a).commit_ids().contains(&late));
    gone(&mut net, a, t);
    net.set_online(b, true);
    net.run();
    net.advance(120_000);
    net.advance(120_000);
    gone(&mut net, a, t);
    gone(&mut net, b, t);
    assert!(!net.engine(a).commit_ids().contains(&late));
}

// spec/commits.md §4, §5 (Destruction): a destruction arriving while a write awaits the unknown thing: the
// write comes back to nothing, and its parts are not held
#[test]
fn a_destruction_while_a_write_awaits_the_thing_spec_commits_5() {
    let mut lp = crate::common::net(2, 0);
    lp.sync_all().unwrap();
    let before: std::collections::BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
    let t = crate::common::new_thing(&mut lp, 0);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &crate::common::REG, &Value::Str("v".into())).unwrap();
    let w = lp.peers[0].commit(m).unwrap().unwrap();
    let pw = lp.peers[0].engine.package(&w).unwrap().unwrap();
    let made_ = lp.packages(0).unwrap().into_iter().find(|p| !before.contains(&p.id) && p.id != w).unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(lp.peers[0].engine.now().0)).unwrap();
    m.purge(PurgeItem::Aspect { tid: t, ak: Ak::new(ct::CREATED.ak()).unwrap() });
    let q = lp.peers[0].commit(m).unwrap().unwrap();
    let pq = lp.peers[0].engine.package(&q).unwrap().unwrap();
    assert!(matches!(lp.deliver(1, &pw).unwrap(), Ingested::Awaits(..)));
    let _ = lp.deliver(1, &pq);
    lp.deliver(1, &made_).unwrap();
    let _ = lp.deliver(1, &pq);
    assert!(matches!(lp.deliver(1, &pw).unwrap(), Ingested::Awaits(..)), "still a write on an unknown thing");
    assert_eq!(lp.peers[1].engine.get(&t, &Ak::new(crate::common::REG.ak()).unwrap()).unwrap(), None);
    assert!(!lp.peers[1].engine.knows(&t));
}

/// The work of destroying one thing holding `parts` writes on a node holding `others` other things.
fn destruction_work(parts: usize, others: usize) -> (crate::scale::Work, crate::scale::Work) {
    let mut lp = crate::common::net(1, 0);
    let b = lp.peers[0].backend.clone();
    let mut other = crate::common::new_thing(&mut lp, 0);
    for _ in 0..others {
        other = crate::common::new_thing(&mut lp, 0);
    }
    let t = crate::common::new_thing(&mut lp, 0);
    for i in 0..parts {
        let mut m = Mutation::new();
        m.set(t, &crate::common::REG, &Value::Str(format!("v{i}"))).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(lp.peers[0].engine.now().0)).unwrap();
    m.purge(PurgeItem::Aspect { tid: t, ak: Ak::new(ct::CREATED.ak()).unwrap() });
    // what any purge costs at this size: the baseline
    let mut one = Mutation::new();
    one.set(other, &crate::common::REG, &Value::Str("v".into())).unwrap();
    lp.peers[0].commit(one).unwrap().unwrap();
    let mut plain = Mutation::new();
    plain.set(other, &ct::PURGE, &osis_base::WallMs(lp.peers[0].engine.now().0)).unwrap();
    plain.purge(PurgeItem::Aspect { tid: other, ak: Ak::new(crate::common::REG.ak()).unwrap() });
    let (_, base) = crate::scale::measured(&b, || lp.peers[0].commit(plain).unwrap().unwrap());
    let (_, w) = crate::scale::measured(&b, || lp.peers[0].commit(m).unwrap().unwrap());
    assert!(!lp.peers[0].engine.knows(&t));
    (w, base)
}

// spec/requirements.md Scale, spec/commits.md §5 (Destruction): a destruction costs the thing's own parts,
// not their square and not the things beside it: it rewrites only the store pages its own rows
// sit on, however many other things the node holds (bytes follow the page size, so writes are
// what is counted)
#[test]
fn destruction_costs_the_things_parts_spec_commits_5() {
    let (a, b) = (destruction_work(20, 5), destruction_work(200, 5));
    crate::scale::linear("rebuilds by parts", a.0.n("rebuild"), b.0.n("rebuild"));
    crate::scale::linear("bytes written by parts", a.0.io.written_bytes, b.0.io.written_bytes);
    let (a, b) = (destruction_work(5, 20), destruction_work(5, 200));
    crate::scale::flat("rebuilds by other things", a.0.n("rebuild"), b.0.n("rebuild"));
    crate::scale::flat("store writes by other things", a.0.io.writes, b.0.io.writes);
}

// spec/commits.md §5 (Destruction): the first admin's removal is authorised by a grant the destruction keeps,
// so a removal arriving after the destruction makes it fall and a copy brings the thing back
#[test]
fn repro_first_admin_removal_after_destruction() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, creation) = made(&mut net, a, g);
    let tc = net.tid(c);
    net.grant(a, t, tc, Role::Admin);
    net.run();
    let copy = net.engine(a).package(&creation).unwrap().unwrap();
    net.set_online(c, false);
    let done = net.engine(c).demote(&t, &osis_node::flows::Demotion { holder: g, new: None, retain: None }).unwrap();
    let removal: Vec<_> = done.commits.iter().map(|x| net.engine(c).package(x).unwrap().unwrap()).collect();
    net.advance(10);
    purge_thing(&mut net, a, t);
    net.run();
    gone(&mut net, b, t);
    for p in &removal {
        let _ = net.engine(b).ingest(&p.bytes, Vec::new());
    }
    let _ = net.engine(b).ingest(&copy.bytes, Vec::new());
    assert_eq!(net.read(b, t), Some(s("x")));
}

// spec/commits.md §5 (Destruction), spec/sync.md §5: a removal of the first admin racing a destruction, in
// both arrival orders: the nodes agree the destruction fell, and then nothing is logged or deleted at
// hosts over and over
#[test]
fn removal_racing_a_destruction_converges_in_both_orders_spec_commits_5() {
    for destruction_first in [true, false] {
        let (mut net, (a, b, c, g, t)) = Net::cached("destruction::removal_racing", || {
            let Setup { mut net, a, b, c, g } = setup();
            let (t, _) = made(&mut net, a, g);
            let (tc, tb) = (net.tid(c), net.tid(b));
            net.grant(a, t, tc, Role::Admin);
            net.grant(a, t, tb, Role::Read);
            net.run();
            (net, (a, b, c, g, t))
        });
        // who is cut off until both are written: the side that took the other first
        let off = if destruction_first { c } else { a };
        net.set_online(off, false);
        net.engine(c).demote(&t, &osis_node::flows::Demotion { holder: g, new: None, retain: None }).unwrap();
        net.run();
        net.advance(10);
        purge_thing(&mut net, a, t);
        net.run();
        net.set_online(off, true);
        net.run();
        for _ in 0..4 {
            net.advance(120_000);
        }
        // a lost its way in with the first admin's edge; b and c hold their own
        for n in [b, c] {
            assert_eq!(net.read(n, t), Some(s("x")), "destruction first {destruction_first}: node {n}");
        }
        assert!(!net.engine(a).core.destroyed(&t), "destruction first {destruction_first}: it fell at a too");
        let churn = |net: &Net| net.shown.values().sum::<usize>() + net.sent_kinds.get(&14).copied().unwrap_or(0);
        let settled = churn(&net);
        for _ in 0..4 {
            net.advance(120_000);
        }
        assert_eq!(churn(&net), settled, "destruction first {destruction_first}: entries shown and deletes go on");
    }
}

/// Whether a commit on `t` held at node `n` has a part on `t` waiting.
fn waiting_on(net: &mut Net, n: usize, t: Tid) -> bool {
    let core = &net.engine(n).core;
    core.on_thing(&t).any(|c| core.ix.commits.get(&c).is_some_and(|m| m.missing_parts().any(|ai| m.header.aspects.get(ai).is_some_and(|a| a.tid == t))))
}

// spec/commits.md §4, §5 (Destruction): a fall judges again what waited on the destroyed thing (a late write
// awaiting it, the falling removal's own key rotation), and observers of its roles hear it come back
#[test]
fn a_fall_judges_again_what_waited_on_the_destroyed_thing_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, _) = made(&mut net, a, g);
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.run();
    net.set_online(c, false);
    let done = net.engine(c).demote(&t, &osis_node::flows::Demotion { holder: tb, new: None, retain: None }).unwrap();
    let removal: Vec<_> = done.commits.iter().map(|x| net.engine(c).package(x).unwrap().unwrap()).collect();
    let late = net.write(c, t, "late");
    let pk = net.engine(c).package(&late).unwrap().unwrap();
    net.advance(10);
    purge_thing(&mut net, b, t);
    net.run();
    gone(&mut net, a, t);
    net.engine(a).take_wakes();
    assert!(matches!(net.engine(a).ingest(&pk.bytes, Vec::new()).unwrap(), Ingested::Awaits(..)));
    let heard = net.engine(a).subscribe_durable();
    for p in &removal {
        let _ = net.engine(a).ingest(&p.bytes, Vec::new());
    }
    assert!(net.engine(a).knows(&t), "it fell");
    net.engine(a).reexamine().unwrap();
    assert!(net.engine(a).take_wakes().records.contains(&t), "what awaits the thing wakes");
    let roles = Ak::new(ct::ROLES.ak()).unwrap();
    assert!(heard.try_iter().any(|e| matches!(e, osis_node::Event::Changed { changed, .. } if changed.contains(&(t, roles.clone())))), "observers of its roles hear it");
    net.set_online(c, true);
    net.run();
    net.advance(120_000);
    net.advance(120_000);
    assert!(!waiting_on(&mut net, a, t), "nothing of it is left waiting");
    assert_eq!(net.read(a, t), Some(s("late")));
}

// spec/commits.md §5 (Destruction): a destruction by expiry keeps nothing, even where the thing held a purge
// request of something else
#[test]
fn a_destruction_by_expiry_keeps_nothing_beside_a_purge_spec_commits_5() {
    let mut lp = crate::common::net(1, 0);
    let at = osis_base::WallMs(lp.peers[0].engine.now().0 + 1_000);
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &crate::common::REG, &Value::Str("v".into())).unwrap();
    m.expires_all(at);
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(lp.peers[0].engine.now().0)).unwrap();
    m.purge(PurgeItem::Aspect { tid: t, ak: Ak::new(crate::common::REG.ak()).unwrap() });
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(2_000);
    lp.peers[0].tick().unwrap();
    assert!(!lp.peers[0].engine.knows(&t));
    assert!(lp.peers[0].engine.core.created(&t).is_none(), "no record kept");
    assert!(lp.peers[0].engine.core.timelines.get(&t).is_none_or(|tl| tl.roster(&t, osis_perm::At::END).is_empty()), "no edges kept");
}

// spec/commits.md §5 (Destruction), spec/permissions.md §6: a removal of the destruction's author and its
// re-grant, ordered before the request, arriving in any order around it: the verdict is a
// function of what is held
#[test]
fn removal_and_regrant_around_a_destruction_converge_in_any_order_spec_commits_5() {
    // the destruction first (it stands, falls, stands again), between the two, and last
    for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0]] {
        let (mut net, (a, b, c, _, t, tb)) = Net::cached("destruction::removal_and_regrant", || {
            let Setup { mut net, a, b, c, g } = setup();
            let (t, _) = made(&mut net, a, g);
            let tb = net.tid(b);
            net.grant(a, t, tb, Role::Admin);
            net.run();
            (net, (a, b, c, g, t, tb))
        });
        // a takes all three in turn: c's removal of b, c's re-grant of b, and b's request after them
        net.set_online(a, false);
        net.advance(10);
        let done = net.engine(c).demote(&t, &osis_node::flows::Demotion { holder: tb, new: None, retain: None }).unwrap();
        let removal: Vec<_> = done.commits.iter().map(|x| net.engine(c).package(x).unwrap().unwrap()).collect();
        net.advance(10);
        let re = net.grant(c, t, tb, Role::Admin);
        let regrant = vec![net.engine(c).package(&re).unwrap().unwrap()];
        net.advance(10);
        let destruction = purge_thing(&mut net, b, t);
        let destruction = vec![net.engine(b).package(&destruction).unwrap().unwrap()];
        let lots = [destruction, removal, regrant];
        for lot in order {
            for p in &lots[lot] {
                let _ = net.engine(a).ingest(&p.bytes, Vec::new());
            }
        }
        net.engine(a).reexamine().unwrap();
        assert!(net.engine(a).core.destroyed(&t), "order {order:?}: the re-grant gives the right back");
        gone(&mut net, a, t);
    }
}

// spec/commits.md §5 (Destruction: dependents): a destroyed thing others name first admin keeps its record
// and edges while one of them is held, so the dependent reads and is written through the destroyed
// thing's standing edges; once its last dependent is destroyed too, neither leaves anything
#[test]
fn a_destroyed_first_admin_stays_a_chain_proof_until_its_last_dependent_goes_spec_commits_5() {
    let mut lp = crate::common::net(2, 0);
    lp.sync_all().unwrap();
    let now = lp.peers[0].engine.now().0;
    let me = lp.peers[0].engine.me();
    let made = |lp: &mut osis_node::local_peer::LocalPeer, admin: Tid, v: &str, at: u64| {
        let mut m = Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, admin);
        m.set(x, &crate::common::REG, &s(v)).unwrap();
        m.expires_all(osis_base::WallMs(at));
        lp.peers[0].commit(m).unwrap().unwrap();
        x
    };
    let t = made(&mut lp, me, "t", now + 1_000);
    let x = made(&mut lp, t, "x", now + 5_000);
    lp.sync_all().unwrap();
    lp.advance(2_000);
    for i in 0..2 {
        lp.peers[i].tick().unwrap();
        let e = &mut lp.peers[i].engine;
        assert!(!e.knows(&t), "peer {i}: t was destroyed");
        assert!(e.core.created(&t).is_some(), "peer {i}: t's record kept as x's chain proof");
        assert_eq!(e.get(&x, &Ak::new(crate::common::REG.ak()).unwrap()).unwrap(), Some(s("x")), "peer {i}: x lives on");
    }
    let mut m = Mutation::new();
    m.set(x, &crate::common::REG, &s("y")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.get(&x, &Ak::new(crate::common::REG.ak()).unwrap()).unwrap(), Some(s("y")), "written through t's standing edges");
    lp.advance(4_000);
    for i in 0..2 {
        lp.peers[i].tick().unwrap();
        let e = &mut lp.peers[i].engine;
        assert!(!e.knows(&x), "peer {i}: x was destroyed");
        assert!(e.core.created(&x).is_none() && e.core.created(&t).is_none(), "peer {i}: neither leaves a record");
    }
}

// spec/commits.md §5 (Destruction: dependents): a destroyed actor a held edge names holder on another
// thing is on that thing's authority paths and keeps its record and edges, as a first admin does;
// once that thing is destroyed too, nothing of either is left
#[test]
fn a_destroyed_holder_stays_until_what_names_it_goes_spec_commits_5() {
    let mut lp = crate::common::net(2, 0);
    lp.sync_all().unwrap();
    let now = lp.peers[0].engine.now().0;
    let me = lp.peers[0].engine.me();
    let made = |lp: &mut osis_node::local_peer::LocalPeer, v: &str, at: u64| {
        let mut m = Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(x, &crate::common::REG, &s(v)).unwrap();
        m.expires_all(osis_base::WallMs(at));
        lp.peers[0].commit(m).unwrap().unwrap();
        x
    };
    let t = made(&mut lp, "t", now + 1_000);
    let x = made(&mut lp, "x", now + 5_000);
    let admin = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
    crate::common::set_edge(&mut lp.peers[0].engine, x, t, Some(admin), None);
    lp.sync_all().unwrap();
    lp.advance(2_000);
    for i in 0..2 {
        lp.peers[i].tick().unwrap();
        let e = &mut lp.peers[i].engine;
        assert!(!e.knows(&t), "peer {i}: t was destroyed");
        assert!(e.core.created(&t).is_some(), "peer {i}: t's record kept, x names it holder");
        assert!(e.roster(&x).contains_key(&t), "peer {i}: t's edge on x stands");
    }
    lp.advance(4_000);
    for i in 0..2 {
        lp.peers[i].tick().unwrap();
        let e = &mut lp.peers[i].engine;
        assert!(!e.knows(&x), "peer {i}: x was destroyed");
        assert!(e.core.created(&x).is_none() && e.core.created(&t).is_none(), "peer {i}: neither leaves a record");
        assert!(e.core.timelines.get(&t).is_none_or(|tl| tl.roster(&t, osis_perm::At::END).is_empty()), "peer {i}: no edges of t kept");
    }
}

// spec/commits.md §5 (Destruction: dependents), spec/permissions.md §4 (records travel raw): an account
// that destroys itself leaves the group it created running under its other admins. Its own data is
// gone; what it wrote there still reads and verifies, the other admin writes on, and a node
// granted afterwards learns the account's record from the group's label alone
#[test]
fn a_destroyed_account_leaves_what_it_created_running_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let p = net.engine(a).me();
    let t = net.item(a, g, g, "from a");
    let mut m = Mutation::new();
    m.set(p, &REG, &s("mine")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.read(a, p), Some(s("mine")));
    purge_thing(&mut net, a, p);
    net.run();
    gone(&mut net, a, p);
    assert!(net.engine(a).core.created(&p).is_some(), "its record stays: the group names it first admin");
    for n in [a, b, c] {
        assert_eq!(net.read(n, t), Some(s("from a")), "node {n}: what the account wrote verifies");
    }
    let t2 = net.item(c, g, g, "from c");
    net.run();
    assert_eq!(net.read(b, t2), Some(s("from c")), "the other admin runs the group");
    // a node granted now opens the group's label: the account's record comes raw from there
    let d = net.joining_node(net.nodes.len() as u64 + 1, &[0]);
    let addr = net.address(0);
    let (made, done) = net.engine(d).create_account(std::slice::from_ref(&addr)).unwrap();
    let dt = made.account;
    let acts = net.sync(d).carry_out(done).unwrap();
    net.actions(d, acts);
    net.run();
    net.pair(d, c);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(c).grant(&g, &dt, &edge).unwrap();
    let acts = net.sync(c).carry_out(done).unwrap();
    net.actions(c, acts);
    net.run();
    let acts = net.accept_invites(d);
    net.actions(d, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.engine(d).core.created(&p).is_some(), "the account's record, from the group's label");
    assert_eq!(net.read(d, t), Some(s("from a")));
    assert_eq!(net.read(d, t2), Some(s("from c")));
}

// spec/commits.md §5 (Destruction: dependents), spec/permissions.md §4 (Placing): a thing whose first
// admin destroyed by expiry before a node joined the group reads at that node, which learns the destroyed
// first admin's record from the group's label (no body there carries it once it was destroyed), and takes
// no write on that record alone: it cannot tell the thing was destroyed
#[test]
fn a_node_joining_after_a_first_admin_was_destroyed_reads_its_dependents_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let at = net.now() + 1_000;
    let mut m = Mutation::new();
    let t = net.engine(a).new_thing(&mut m, g);
    m.set(t, &REG, &s("t")).unwrap();
    let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(t);
    m.set(g, &ct::GROUP, &items).unwrap();
    m.expires_all(osis_base::WallMs(at));
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let x = net.item(a, g, t, "x");
    net.run();
    for _ in 0..2 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert!(!net.engine(n).knows(&t), "node {n}: t was destroyed");
        assert_eq!(net.read(n, x), Some(s("x")), "node {n}: x lives on");
    }
    let d = net.joining_node(4, &[0]);
    let addr = net.address(0);
    let (made, done) = net.engine(d).create_account(std::slice::from_ref(&addr)).unwrap();
    let dt = made.account;
    let acts = net.sync(d).carry_out(done).unwrap();
    net.actions(d, acts);
    net.run();
    net.pair(d, c);
    let edge = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
    let done = net.engine(c).grant(&g, &dt, &edge).unwrap();
    let acts = net.sync(c).carry_out(done).unwrap();
    net.actions(c, acts);
    net.run();
    let acts = net.accept_invites(d);
    net.actions(d, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.engine(d).core.created(&t).is_some(), "t's record, from g's label");
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert_eq!(net.read(d, t), None, "d: nothing of t");
    let mut m = Mutation::new();
    m.set(t, &REG, &s("late")).unwrap();
    assert!(matches!(net.engine(d).commit(m), Err(osis_node::Error::UnknownThing(_))), "d: a write to t refused, as at a node that saw it destroyed");
    let mut m = Mutation::new();
    m.set(x, &REG, &s("x2")).unwrap();
    net.engine(d).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.read(a, x), Some(s("x2")), "d, an admin of g, writes x through t's standing edges");
}

/// A node granted read on `g` by node `by` after the fact, synced a while: its index.
fn granted_later(net: &mut Net, by: usize, g: Tid) -> usize {
    granted_later_as(net, by, g, Role::Read)
}

/// `granted_later` at `role`.
fn granted_later_as(net: &mut Net, by: usize, g: Tid, role: Role) -> usize {
    let d = net.joining_node(4, &[0]);
    let addr = net.address(0);
    let (made, done) = net.engine(d).create_account(std::slice::from_ref(&addr)).unwrap();
    let dt = made.account;
    let acts = net.sync(d).carry_out(done).unwrap();
    net.actions(d, acts);
    net.run();
    net.pair(d, by);
    let edge = ct::Edge { role, until: None, invite: None, tied: None };
    let done = net.engine(by).grant(&g, &dt, &edge).unwrap();
    let acts = net.sync(by).carry_out(done).unwrap();
    net.actions(by, acts);
    net.run();
    let acts = net.accept_invites(d);
    net.actions(d, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    d
}

/// A thing `t` in `g` (first admin `g`) that is destroyed by expiry in 5 s, with b granted admin on it.
/// `listed`: `g` lists it in a durable commit of its own, so the destroyed thing stays in `g`'s
/// closure; else in its expiring creation commit, so it leaves the closure as it is destroyed.
fn destroyed_actor_of(net: &mut Net, a: usize, b: usize, g: Tid, listed: bool) -> Tid {
    let at = net.now() + 5_000;
    let mut m = Mutation::new();
    let t = net.engine(a).new_thing(&mut m, g);
    m.set(t, &REG, &s("t")).unwrap();
    if listed {
        m.expires_all(osis_base::WallMs(at));
        net.engine(a).commit(m).unwrap().unwrap();
        m = Mutation::new();
    }
    let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(t);
    m.set(g, &ct::GROUP, &items).unwrap();
    if !listed {
        m.expires_all(osis_base::WallMs(at));
    }
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.run();
    t
}

/// Lets `t` be destroyed (`destroyed_actor_of`) with c offline through it, then brings c back.
fn destroy_with_c_away(net: &mut Net, c: usize) {
    for _ in 0..2 {
        net.advance(70_000);
    }
    net.set_online(c, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
}

// spec/commits.md §5 (Destruction: dependents), spec/permissions.md §4 (Placing): b is admin of x only
// by its edge on x's first admin t. t is destroyed by expiry while c holds no dependent of it (x reaches c
// after the destruction), so c keeps nothing of t and its destruction deletes t's bodies at the host; the
// holders of x place t's frozen edges under the label again (as closure bodies while g lists t,
// else as certificate copies), so c judges b's grant on x as a and b do
#[test]
fn a_destroyed_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5() {
    for listed in [false, true] {
        let Setup { mut net, a, b, c, g } = setup();
        let t = destroyed_actor_of(&mut net, a, b, g, listed);
        net.set_online(c, false);
        let x = net.item(a, g, t, "x");
        net.run();
        let ta = net.tid(a);
        net.grant(b, x, ta, Role::Read);
        net.run();
        let ra = net.engine(a).roster(&x);
        assert!(ra.contains_key(&ta), "listed {listed}: a: b's grant on x by its admin on t");
        destroy_with_c_away(&mut net, c);
        for n in [a, b, c] {
            assert!(!net.engine(n).knows(&t), "listed {listed}: node {n}: t was destroyed");
            assert_eq!(net.read(n, x), Some(s("x")), "listed {listed}: node {n}: x lives on");
            assert_eq!(net.engine(n).roster(&x), ra, "listed {listed}: node {n}: x's roster");
        }
    }
}

// spec/commits.md §5 (Destruction): as
// `a_destroyed_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5`, with a durable
// write on t before its destruction. c keeps nothing of t, then takes its record again with x; a late
// copy of that write is a part on a destroyed thing there, never content
#[test]
fn a_late_content_copy_after_the_record_comes_back_stays_destroyed_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = destroyed_actor_of(&mut net, a, b, g, false);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("y")).unwrap();
    let late = net.engine(a).commit(m).unwrap().unwrap();
    let late = net.engine(a).package(&late).unwrap().unwrap().bytes;
    net.run();
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    destroy_with_c_away(&mut net, c);
    assert!(net.engine(c).core.created(&t).is_some(), "c: t's record back with x");
    let _ = net.engine(c).ingest(&late, Vec::new());
    net.engine(c).reexamine().unwrap();
    for _ in 0..2 {
        net.advance(70_000);
    }
    assert!(!net.engine(c).knows(&t), "c: t was destroyed");
    assert_eq!(net.read(c, t), None, "c: nothing of t");
    assert!(!net.engine(c).has_content(&t).unwrap(), "c: no content on t");
    assert_eq!(net.read(c, x), Some(s("x")), "c: x lives on");
}

// spec/commits.md §5 (Destruction: dependents), spec/permissions.md §1 (the first admin is history): t,
// granted admin on x by an edge (x's first admin is g), is destroyed by expiry; b, admin of x only through
// t, granted on x before the destruction and grants again after it through t's frozen edges. Every node
// agrees on x's roster: those that held x at the destruction, c which got the destruction first, and a node
// granted afterwards
#[test]
fn authority_through_a_destroyed_granted_admin_stands_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = destroyed_actor_of(&mut net, a, b, g, true);
    net.set_online(c, false);
    let x = net.item(a, g, g, "x");
    net.run();
    net.grant(a, x, t, Role::Admin);
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    destroy_with_c_away(&mut net, c);
    let tc = net.tid(c);
    net.grant(b, x, tc, Role::Write);
    net.run();
    for _ in 0..2 {
        net.advance(70_000);
    }
    let ra = net.engine(a).roster(&x);
    assert!(ra.get(&ta).is_some_and(|e| e.role == Role::Read), "a: b's grant before the destruction");
    assert!(ra.get(&tc).is_some_and(|e| e.role == Role::Write), "a: b's grant after it");
    for n in [a, b, c] {
        assert!(!net.engine(n).knows(&t), "node {n}: t was destroyed");
        assert!(net.engine(n).core.created(&t).is_some(), "node {n}: t's record stays, x names it holder");
        assert_eq!(net.engine(n).roster(&x), ra, "node {n}: x's roster");
    }
    let d = granted_later(&mut net, a, g);
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert_eq!(net.engine(d).roster(&x), ra, "d: x's roster");
    assert!(!net.engine(d).knows(&t), "d: t was destroyed, learned with its frozen history");
    assert!(net.engine(d).roster(&t).is_empty(), "d: t's roster reads empty as at a");
}

// spec/crypto.md §4 (Holder actors, Destroyed): as
// `a_destroyed_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5`, then a node
// granted g afterwards: x has secrets of its own, boxed to its holder actor t, whose own secrets
// nobody boxes once t was destroyed; x's admins box t's frozen holders (g, b's account) in its place, so
// the newcomer reads x through g
#[test]
fn newcomer_reads_a_dependent_keyed_by_a_destroyed_actor_spec_crypto_4() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = destroyed_actor_of(&mut net, a, b, g, false);
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    let ra = net.engine(a).roster(&x);
    destroy_with_c_away(&mut net, c);
    let d = granted_later(&mut net, a, g);
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert_eq!(net.engine(d).roster(&x), ra, "d: x's roster");
}

// spec/crypto.md §4 (Holder actors, Destroyed), spec/commits.md §5 (Destruction): as
// `newcomer_reads_a_dependent_keyed_by_a_destroyed_actor_spec_crypto_4` with d an admin of g. t's
// destruction travels with its frozen history (its minting's header), so d reads t as destroyed as the
// others do: t's frozen holders hold x's keys in its place, x's current epochs agree, and what d
// writes to x the others read
#[test]
fn a_newcomer_admin_keys_a_dependent_by_a_destroyed_actors_frozen_holders_spec_crypto_4() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = destroyed_actor_of(&mut net, a, b, g, false);
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    destroy_with_c_away(&mut net, c);
    let d = granted_later_as(&mut net, a, g, Role::Admin);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let cur = |net: &mut Net, n: usize| net.engine(n).epochs(&x).map(|e| e.read.current());
    let holders = |net: &mut Net, n: usize| net.engine(n).core.key_holders(&x).into_iter().collect::<std::collections::BTreeSet<_>>();
    let ha = holders(&mut net, a);
    assert!(!ha.iter().any(|h| h.0 == t) && ha.iter().any(|h| h.0 == g), "a: t's frozen holders hold x's keys: {ha:?}");
    for n in [b, c, d] {
        assert!(!net.engine(n).knows(&t), "node {n}: t was destroyed");
        assert_eq!(holders(&mut net, n), ha, "node {n}: x's holders for keys");
        assert_eq!(cur(&mut net, n), cur(&mut net, a), "node {n}: x's current epochs");
    }
    let mut m = Mutation::new();
    m.set(x, &REG, &s("x2")).unwrap();
    net.engine(d).commit(m).unwrap().unwrap();
    for _ in 0..2 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert_eq!(net.read(n, x), Some(s("x2")), "node {n}: d's write");
    }
}

/// A commit of node `n` minting `t`'s record again, durable, past the writer's rules: what anyone
/// holding the record can sign. Its bytes as sent.
fn remint(net: &mut Net, n: usize, t: Tid) -> Vec<u8> {
    let rec = net.engine(n).core.created(&t).cloned().expect("t's record");
    let mut m = Mutation::new();
    m.create(rec);
    let c = net.engine(n).commit_hostile(m).unwrap().unwrap();
    net.engine(n).take_forged().unwrap_or_else(|| net.engine(n).package(&c).unwrap().unwrap().bytes)
}

/// `setup` with a fourth node, r, a reader of `g`: it holds the records of `g`'s things.
fn setup_reader() -> (Setup, usize) {
    let (net, _host, [a, b, c, r], g, []) = hosted::<4, 0>(&[(1, Role::Write), (2, Role::Admin), (3, Role::Read)], [], true);
    (Setup { net, a, b, c, g }, r)
}

// spec/commits.md §5 (Destruction): a request names every minting. A reader of `g` (it holds t's record)
// mints t again before and after an admin purges t's creation, and a writer of t mints it again
// after the destruction, each with the default retention: c takes the three and the destruction in every
// order, and t reads gone everywhere
#[test]
fn a_minting_again_the_request_can_drop_never_brings_back_a_purged_thing_spec_commits_5() {
    for order in [[0, 1, 2, 3], [1, 0, 2, 3], [2, 3, 1, 0], [3, 2, 0, 1]] {
        let (mut net, (a, b, c, _, r, t)) = Net::cached("destruction::minting_again_can_drop", || {
            let (Setup { mut net, a, b, c, g }, r) = setup_reader();
            let (t, _) = made(&mut net, a, g);
            net.run();
            (net, (a, b, c, g, r, t))
        });
        assert!(net.engine(r).core.created(&t).is_some(), "order {order:?}: r holds t's record");
        net.set_online(c, false);
        for n in [a, b, r] {
            net.set_online(n, false);
        }
        net.advance(10);
        let before = remint(&mut net, r, t);
        net.advance(10);
        let destruction = purge_thing(&mut net, a, t);
        let destruction = net.engine(a).package(&destruction).unwrap().unwrap().bytes;
        net.advance(10);
        let after = remint(&mut net, r, t);
        let by_writer = remint(&mut net, b, t);
        let lots = [&before, &destruction, &after, &by_writer];
        for i in order {
            let _ = net.engine(c).ingest(lots[i], Vec::new());
            net.engine(c).reexamine().unwrap();
        }
        gone(&mut net, c, t);
        for n in [a, b, c, r] {
            net.set_online(n, true);
        }
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c, r] {
            gone(&mut net, n, t);
        }
    }
}

// spec/commits.md §5 (Destruction, Limit): a reader holding an expiring thing's record mints it again
// durable, before its expiry and after it. Wherever the mintings arrive before or after the thing
// destroyed there, it exists past its expiry, but its content still expired
#[test]
fn a_durable_minting_again_keeps_an_expiring_thing_but_not_its_content_spec_commits_5() {
    for remint_first in [true, false] {
        let (Setup { mut net, a, c, g, .. }, r) = setup_reader();
        let at = net.now() + 5_000;
        let mut m = Mutation::new();
        let t = net.engine(a).new_thing(&mut m, g);
        m.set(t, &REG, &s("x")).unwrap();
        m.expires_all(osis_base::WallMs(at));
        net.engine(a).commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        items.items.insert(t);
        m.set(g, &ct::GROUP, &items).unwrap();
        net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        net.set_online(c, false);
        net.set_online(r, false);
        let before = remint(&mut net, r, t);
        if remint_first {
            let _ = net.engine(c).ingest(&before, Vec::new());
        }
        net.advance(10_000);
        // c is offline: its expiry runs by its own clock
        net.engine(c).tick().unwrap();
        assert_eq!(net.engine(c).core.destroyed(&t), !remint_first, "first {remint_first}: t was destroyed at c only without the minting");
        let after = remint(&mut net, r, t);
        if !remint_first {
            let _ = net.engine(c).ingest(&before, Vec::new());
        }
        let _ = net.engine(c).ingest(&after, Vec::new());
        net.engine(c).reexamine().unwrap();
        assert!(net.engine(c).knows(&t), "first {remint_first}: t exists at c");
        assert_eq!(net.read(c, t), None, "first {remint_first}: its content expired");
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record, Limit): t, durable, made by a under
// its account, is first admin of x, an item of g that g reads, so r, a reader of g, knows t by its
// record alone. c, a reader of t, mints t again expiring and hands r the commit, before and after
// its expiry: r holds t's own minting too (it travels with the record), so t lives at r past the
// forged expiry, and a's admin on x through t stands there
#[test]
fn a_forged_expiring_minting_destroys_no_live_thing_known_by_its_record_spec_commits_5() {
    for late in [false, true] {
        let (Setup { mut net, a, b, c, g }, r) = setup_reader();
        let mut m = Mutation::new();
        let ta = net.tid(a);
        let t = net.engine(a).new_thing(&mut m, ta);
        m.set(t, &REG, &s("t")).unwrap();
        net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        let x = net.item(a, g, t, "x");
        net.run();
        net.grant(a, x, g, Role::Read);
        for _ in 0..3 {
            net.advance(70_000);
        }
        assert_eq!(net.read(r, x), Some(s("x")), "late {late}: r reads x");
        assert!(net.engine(r).core.created(&t).is_some(), "late {late}: r holds t's record");
        assert_eq!(net.read(r, t), None, "late {late}: r reads nothing of t");
        let a_on_x = |net: &mut Net, n: usize| {
            let ts = osis_base::Ts::make(osis_base::WallMs(net.now()), 0).unwrap();
            osis_engine::engine::write::role_of(&net.engine(n).core, &ta, &x, ts)
        };
        assert_eq!(a_on_x(&mut net, r), Some(Role::Admin), "late {late}: a administers x through t");
        // c, a reader of t, mints it again expiring (any edge leading to t's record chain lets a
        // minting apply), and hands r the commit with c's grant on t as its chain
        let tc = net.tid(c);
        let grant = net.grant(a, t, tc, Role::Read);
        let grant = net.engine(a).package(&grant).unwrap().unwrap().bytes;
        for n in [c, r] {
            let _ = net.engine(n).ingest(&grant, Vec::new());
            net.engine(n).reexamine().unwrap();
        }
        let rec = net.engine(c).core.created(&t).cloned().unwrap();
        let mut m = Mutation::new();
        m.create(rec);
        m.expires(t, &ct::CREATED, osis_base::WallMs(net.now() + 5_000)).unwrap();
        let fid = net.engine(c).commit_hostile(m).unwrap().unwrap();
        let forged = net.engine(c).take_forged().unwrap_or_else(|| net.engine(c).package(&fid).unwrap().unwrap().bytes);
        if !late {
            let _ = net.engine(r).ingest(&forged, Vec::new());
            net.engine(r).reexamine().unwrap();
        }
        for _ in 0..2 {
            net.advance(70_000);
        }
        if late {
            let _ = net.engine(r).ingest(&forged, Vec::new());
            net.engine(r).reexamine().unwrap();
        }
        net.engine(r).tick().unwrap();
        for n in [a, b, r] {
            assert!(!net.engine(n).core.destroyed(&t), "late {late}: node {n}: t lives");
            assert_eq!(a_on_x(&mut net, n), Some(Role::Admin), "late {late}: node {n}: a administers x through t");
        }
    }
}

/// `setup_reader` with t, a thing of a's account (its first admin), first admin of x, an item
/// of g that g reads, so r knows t by its record alone; c reads t. `expires_in`: t's creation's
/// expiry, from now. Returns (setup, r, t, t's creation commit, x).
fn reader_knows_by_record(expires_in: Option<u64>) -> (Setup, usize, Tid, CommitId, Tid) {
    let (Setup { mut net, a, b, c, g }, r) = setup_reader();
    let mut m = Mutation::new();
    let ta = net.tid(a);
    let t = net.engine(a).new_thing(&mut m, ta);
    m.set(t, &REG, &s("t")).unwrap();
    if let Some(x) = expires_in {
        m.expires_all(osis_base::WallMs(net.now() + x));
    }
    let w = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let x = net.item(a, g, t, "x");
    net.run();
    net.grant(a, x, g, Role::Read);
    // c, a reader of t, takes its grant directly (any edge leading to t's record chain lets a minting apply)
    for _ in 0..3 {
        net.advance(70_000);
    }
    let tc = net.tid(c);
    let grant = net.grant(a, t, tc, Role::Read);
    let grant = net.engine(a).package(&grant).unwrap().unwrap().bytes;
    let _ = net.engine(c).ingest(&grant, Vec::new());
    net.engine(c).reexamine().unwrap();
    net.run();
    assert!(net.engine(r).core.created(&t).is_some(), "r holds t's record");
    assert_eq!(net.read(r, t), None, "r reads nothing of t");
    (Setup { net, a, b, c, g }, r, t, w, x)
}

/// `who`'s role on `x` at node `at`, now.
fn role_on(net: &mut Net, at: usize, who: usize, x: Tid) -> Option<Role> {
    let who = net.tid(who);
    let ts = osis_base::Ts::make(osis_base::WallMs(net.now()), 0).unwrap();
    osis_engine::engine::write::role_of(&net.engine(at).core, &who, &x, ts)
}

/// a, an admin of t (first admin of x), grants b admin on t, then the net runs until past `end`:
/// at each of `nodes` t lives before and is destroyed after, and b's grant, stamped before `end`,
/// stands on x (the destruction is dated at `end` alike everywhere, record-only nodes included).
fn destroyed_at_alike(net: &mut Net, (a, b): (usize, usize), t: Tid, x: Tid, end: u64, nodes: &[usize]) {
    for &at in nodes {
        assert!(!net.engine(at).core.destroyed(&t), "node {at}: t lives");
        assert_eq!(role_on(net, at, a, x), Some(Role::Admin), "node {at}: a administers x through t");
    }
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.run();
    assert!(net.now() < end, "the grant is stamped before the destruction");
    while net.now() <= end + 70_000 {
        net.advance(70_000);
    }
    for _ in 0..3 {
        net.advance(70_000);
    }
    for &at in nodes {
        assert!(net.engine(at).core.destroyed(&t), "node {at}: t destroyed");
        assert_eq!(role_on(net, at, b, x), Some(Role::Admin), "node {at}: b's grant, before the destruction, stands");
    }
}

/// A minting again of `t` by node `n` (`expires`, `retention` on it), ingested at node `at`.
fn mint_at(net: &mut Net, n: usize, at: usize, t: Tid, expires: Option<u64>, retention: Option<osis_schema::Retention>) -> CommitId {
    let rec = net.engine(n).core.created(&t).cloned().unwrap();
    let mut m = Mutation::new();
    m.create(rec);
    if let Some(x) = expires {
        m.expires(t, &ct::CREATED, osis_base::WallMs(x)).unwrap();
    }
    if let Some(r) = retention {
        m.retention(t, &ct::CREATED, r).unwrap();
    }
    let id = net.engine(n).commit_hostile(m).unwrap().unwrap();
    let bytes = net.engine(n).take_forged().unwrap_or_else(|| net.engine(n).package(&id).unwrap().unwrap().bytes);
    let _ = net.engine(at).ingest(&bytes, Vec::new());
    net.engine(at).reexamine().unwrap();
    id
}

/// The entries at the host under `l` carrying a minting of `t`, as node `n` knows them.
fn minting_copies(net: &mut Net, n: usize, l: &osis_base::LabelId, t: Tid) -> Vec<CommitId> {
    let host = net.host_ids(0, l);
    let entries = net.sync(n).entries(l);
    let mut out = Vec::new();
    for (id, k) in entries {
        if let osis_node::sync::EntryKind::Commit { commit, .. } = k
            && host.contains(&id)
            && net.engine(n).header(&commit).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t && a.ak.as_str() == ct::CREATED.ak()))
        {
            out.push(commit);
        }
    }
    out
}

// spec/commits.md §5 (A thing's mintings travel with its record): c, a reader of t, mints it again k
// times, each handed to a, which places t's record under g's label. Only t's witness goes with it, so
// the label carries as many copies of t's mintings at k = 10 as at k = 1. Durable: c's mintings tie
// t's own, which stays the one copy. Expiring: each of c's, expiring later than all before it, is the
// witness in turn, placed, and the one before it deleted (the witness may go up twice: a and c place
// it in the same round)
#[test]
fn a_minting_again_adds_no_copy_under_a_label_carrying_the_record_spec_commits_5() {
    for expiring in [false, true] {
        let mut counts = Vec::new();
        for k in [1u64, 10] {
            let day = 86_400_000;
            let (Setup { mut net, a, c, g, .. }, r, t, w, _) = reader_knows_by_record(expiring.then_some(day));
            let now = net.now();
            let l = net.group_labels(a).into_iter().find(|(x, _)| *x == g).unwrap().1.id;
            assert_eq!(minting_copies(&mut net, a, &l, t), vec![w], "expiring {expiring}, k {k}: t's own minting under g's label");
            let mut last = w;
            for i in 0..k {
                last = mint_at(&mut net, c, a, t, expiring.then_some(now + 2 * day + i * 1_000), None);
                net.run();
            }
            for _ in 0..3 {
                net.advance(70_000);
            }
            let copies = minting_copies(&mut net, a, &l, t);
            let distinct: std::collections::BTreeSet<CommitId> = copies.iter().copied().collect();
            assert_eq!(distinct, [if expiring { last } else { w }].into(), "expiring {expiring}, k {k}: the witness alone");
            assert!(!net.engine(r).core.destroyed(&t), "expiring {expiring}, k {k}: t lives at r");
            counts.push(copies.len());
        }
        assert_eq!(counts[0], counts[1], "expiring {expiring}");
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record): t's own minting W (durable) is its
// witness; c, a reader of t, mints it again N, `nobody` and expiring. a purges t: the request drops W
// but not N, so N is the witness now. b, a writer of g that does not read t, lacks the request and
// deletes N's copy under g's label as lower than W. t lives at every node, r (which holds W alone of
// what was placed) and a node granted g afterwards included; once N expires, a, which may place N
// again now that t is destroyed, does, with the request, so t is destroyed at N's expiry everywhere,
// not at the purge
#[test]
fn a_witness_deleted_by_a_node_lacking_the_request_comes_back_once_destroyed_spec_commits_5() {
    let (Setup { mut net, a, b, c, g }, r, t, w, x) = reader_knows_by_record(None);
    let l = net.group_labels(a).into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    let expiry = net.now() + 30 * 60_000;
    let n = mint_at(&mut net, c, a, t, Some(expiry), Some(osis_commit::retention::KEPT_RETENTION));
    for _ in 0..2 {
        net.advance(70_000);
    }
    assert_eq!(minting_copies(&mut net, a, &l, t), vec![w], "W, durable, is the witness");
    assert!(net.engine(r).header(&w).is_some() && net.engine(r).header(&n).is_none(), "r holds W alone");
    purge_thing(&mut net, a, t);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let copies: std::collections::BTreeSet<CommitId> = minting_copies(&mut net, a, &l, t).into_iter().collect();
    assert_eq!(copies, [w].into(), "b deleted N's copy");
    let d = granted_later(&mut net, a, g);
    assert!(net.engine(d).core.created(&t).is_some(), "d holds t's record");
    destroyed_at_alike(&mut net, (a, b), t, x, expiry, &[a, b, r, d]);
}

// spec/commits.md §5 (A thing's mintings travel with its record): t's creation C expires at T. a, the
// one node online that places under g's label (b, c and r, which could place C there for the first
// time, are away), mints t again, Y, expiring later, so Y is the witness and a deletes its copy of
// C; then a purges Y alone (a hostile writer's own minting goes the same way): C is the witness
// again, live until T, its copy gone. Once T passes a places C again with the request, so t is
// destroyed at T at a node granted g after T (knowing t by its record) as at a, and at every node
// once all are back: an edge write between the purge and T stands everywhere. Y's copy, expiring
// later than C, stays beside it
#[test]
fn a_purged_later_minting_leaves_the_destruction_at_the_creations_expiry_spec_commits_5() {
    let life = 30 * 60_000;
    let (Setup { mut net, a, b, c, g }, r, t, w, x) = reader_knows_by_record(Some(life));
    for n in [b, c, r] {
        net.set_online(n, false);
    }
    let end = net.now() + life;
    let l = net.group_labels(a).into_iter().find(|(x, _)| *x == g).unwrap().1.id;
    let y = mint_at(&mut net, a, a, t, Some(end + 86_400_000), None);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let copies: std::collections::BTreeSet<CommitId> = minting_copies(&mut net, a, &l, t).into_iter().collect();
    assert_eq!(copies, [y].into(), "Y is the witness, C's copy gone");
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &osis_base::WallMs(net.now())).unwrap();
    m.purge_commit(y, t, Ak::new(ct::CREATED.ak()).unwrap());
    net.engine(a).commit(m).unwrap().unwrap();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(!minting_copies(&mut net, a, &l, t).contains(&w), "C, the witness again, has no copy");
    destroyed_at_alike(&mut net, (a, b), t, x, end, &[a]);
    // Y stands lower than C at a but expires later, so its copy stays: a node lacking the purge
    // ranks Y higher, and deleting by expiry alone keeps the two from deleting both copies at once
    let copies: std::collections::BTreeSet<CommitId> = minting_copies(&mut net, a, &l, t).into_iter().collect();
    assert_eq!(copies, [w, y].into(), "C placed again beside Y");
    let d = granted_later(&mut net, a, g);
    for n in [b, c, r] {
        net.set_online(n, true);
    }
    for _ in 0..3 {
        net.advance(70_000);
    }
    for at in [a, b, r, d] {
        assert!(net.engine(at).core.destroyed(&t), "node {at}: t destroyed");
        assert_eq!(role_on(&mut net, at, b, x), Some(Role::Admin), "node {at}: b's grant, before the destruction, stands");
    }
}

// spec/commits.md §5 (Destruction: nobody writes a thing after its destruction): t, first admin of x, is
// purged; c, an admin of t that has not heard of it, grants r admin on t afterwards. r gains nothing on x through t at b whether the grant reaches it before or after the
// destruction, nor anywhere once all have synced
#[test]
fn an_edge_write_after_a_destruction_counts_nowhere_spec_commits_5() {
    for grant_first in [true, false] {
        let (mut net, (a, b, c, _, r, t, x)) = Net::cached("destruction::edge_write_after", || {
            let (Setup { mut net, a, b, c, g }, r) = setup_reader();
            let (t, _) = made(&mut net, a, g);
            let x = net.item(a, g, t, "x");
            net.run();
            (net, (a, b, c, g, r, t, x))
        });
        let tr = net.tid(r);
        assert_eq!(net.engine(r).role_on(&x), Some(Role::Read), "grant first {grant_first}: r reads x through g");
        // c, offline, has not heard of the destruction: its grant is a writer's, stamped after it
        net.set_online(b, false);
        net.set_online(c, false);
        net.advance(10);
        let destruction = purge_thing(&mut net, a, t);
        let destruction = net.engine(a).package(&destruction).unwrap().unwrap().bytes;
        net.run();
        net.advance(10);
        let grant = set_edge(net.engine(c), t, tr, Role::Admin);
        let grant = net.engine(c).package(&grant).unwrap().unwrap().bytes;
        let lots = if grant_first { [&grant, &destruction] } else { [&destruction, &grant] };
        for p in lots {
            let _ = net.engine(b).ingest(p, Vec::new());
            net.engine(b).reexamine().unwrap();
        }
        assert!(net.engine(b).core.destroyed(&t), "grant first {grant_first}: t was destroyed at b");
        assert!(!net.engine(b).roster(&x).is_empty(), "grant first {grant_first}: x lives at b");
        net.set_online(b, true);
        net.set_online(c, true);
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c, r] {
            assert_eq!(net.read(n, x), Some(s("x")), "grant first {grant_first}: node {n}: x lives on");
        }
        assert_eq!(net.engine(r).role_on(&x), Some(Role::Read), "grant first {grant_first}: r: nothing through t's late edge");
        let rb = net.engine(b).roster(&x);
        for n in [a, c, r] {
            assert_eq!(net.engine(n).roster(&x), rb, "grant first {grant_first}: node {n}: x's roster");
        }
    }
}

// spec/commits.md §5 (Destruction: nobody writes a thing after its destruction), spec/permissions.md §4: t,
// first admin of x, is purged; a node granted g afterwards learns t's record, frozen edges and the
// request with them, so it reads t as destroyed, and a grant on t that c, not having heard, wrote
// after the destruction gives r nothing there, as at b
#[test]
fn a_newcomer_refuses_an_edge_write_after_a_destruction_spec_commits_5() {
    let (Setup { mut net, a, b, c, g }, r) = setup_reader();
    let (t, _) = made(&mut net, a, g);
    let x = net.item(a, g, t, "x");
    net.run();
    let tr = net.tid(r);
    net.set_online(c, false);
    net.advance(10);
    purge_thing(&mut net, a, t);
    net.run();
    net.advance(10);
    let grant = set_edge(net.engine(c), t, tr, Role::Admin);
    let grant = net.engine(c).package(&grant).unwrap().unwrap().bytes;
    let d = granted_later(&mut net, a, g);
    assert!(!net.engine(d).knows(&t), "d: t was destroyed");
    assert!(net.engine(d).core.created(&t).is_some(), "d: t's record, x names it");
    let _ = net.engine(d).ingest(&grant, Vec::new());
    net.engine(d).reexamine().unwrap();
    let _ = net.engine(b).ingest(&grant, Vec::new());
    net.engine(b).reexamine().unwrap();
    let ts = osis_base::Ts::make(osis_base::WallMs(net.now()), 0).unwrap();
    for n in [b, d] {
        assert!(net.engine(n).roster(&t).is_empty(), "node {n}: t's roster reads empty");
        assert_eq!(osis_engine::engine::write::role_of(&net.engine(n).core, &tr, &x, ts), Some(Role::Read), "node {n}: r reads x through g, nothing through t's late edge");
    }
    assert_eq!(net.engine(d).roster(&x), net.engine(b).roster(&x), "d: x's roster as at b");
}

// spec/commits.md §5 (Destruction is judged by the history before it), spec/permissions.md §6: c, admin
// of t by its own grant on t alone, destroys t; a, not having heard, demotes c on t afterwards with a
// frontier that omits the request. The demotion is a write after the destruction: whether b takes it
// before or after the request, the destruction stands at every node
#[test]
fn a_demotion_after_a_destruction_does_not_undo_it_spec_commits_5() {
    for demotion_first in [true, false] {
        let (mut net, (a, b, c, _, t, tc)) = Net::cached("destruction::demotion_after", || {
            let Setup { mut net, a, b, c, g } = setup();
            let (t, _) = made(&mut net, a, g);
            let tc = net.tid(c);
            set_edge(net.engine(a), t, tc, Role::Admin);
            demote(&mut net, a, g, tc, Role::Read);
            net.run();
            (net, (a, b, c, g, t, tc))
        });
        net.set_online(a, false);
        net.set_online(b, false);
        net.advance(10);
        let destruction = purge_thing(&mut net, c, t);
        let destruction = net.engine(c).package(&destruction).unwrap().unwrap().bytes;
        net.advance(10);
        let mut m = Mutation::new();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(tc)) }).unwrap();
        m.op(t, &ct::ROLES, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(tc))], op: Op::Set(edge.to_value()) }).unwrap();
        m.frontier(ct::Frontier::default().to_value());
        let d = net.engine(a).commit(m).unwrap().unwrap();
        let demotion = net.engine(a).package(&d).unwrap().unwrap().bytes;
        let lots = if demotion_first { [&demotion, &destruction] } else { [&destruction, &demotion] };
        for p in lots {
            let _ = net.engine(b).ingest(p, Vec::new());
            net.engine(b).reexamine().unwrap();
        }
        assert!(net.engine(b).core.destroyed(&t), "demotion first {demotion_first}: the destruction stands at b");
        net.set_online(a, true);
        net.set_online(b, true);
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c] {
            gone(&mut net, n, t);
        }
    }
}

/// The things node a's cut walks count for one role change on t, while c's destroying request on t
/// stands nowhere (a demoted c on t first) and a later edge write on t is held, beside `others`
/// other things in t's group.
fn fallen_request_work(others: usize) -> u64 {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, _) = made(&mut net, a, g);
    for _ in 0..others {
        made(&mut net, a, g);
    }
    let (tb, tc) = (net.tid(b), net.tid(c));
    set_edge(net.engine(a), t, tc, Role::Admin);
    demote(&mut net, a, g, tc, Role::Read);
    net.run();
    net.set_online(c, false);
    demote(&mut net, a, t, tc, Role::Read);
    net.advance(10);
    let destruction = purge_thing(&mut net, c, t);
    let destruction = net.engine(c).package(&destruction).unwrap().unwrap().bytes;
    net.advance(10);
    set_edge(net.engine(a), t, tb, Role::Write);
    let _ = net.engine(a).ingest(&destruction, Vec::new());
    net.engine(a).reexamine().unwrap();
    assert!(!net.engine(a).core.destroyed(&t), "others {others}: the request stands nowhere");
    osis_node::costs::take();
    set_edge(net.engine(a), t, tb, Role::Admin);
    osis_node::costs::take().into_iter().find(|x| x.0 == "destruction: cut walk things").map_or(0, |x| x.2)
}

// spec/requirements.md Scale, spec/permissions.md §6 (Destruction): a request that destroyed nothing, with
// later edge writes on its thing held, costs each role change on the thing what the thing's
// authority comes from, not the node's other things
#[test]
fn a_fallen_destruction_walks_only_the_things_authority_spec_permissions_6() {
    let (small, big) = (fallen_request_work(3), fallen_request_work(30));
    assert!(small > 0, "the cut walk runs");
    crate::scale::flat("cut walk things by other things", small, big);
}

// spec/commits.md §5 (Destruction, Limit): a reader of g mints a purged t again `nobody`, which the
// request has no right over; b, not having heard of the destruction, writes t after it, and its write
// reaches the peer before b hears of the destruction (brought back is only what a copy is still held
// of). Brought back, t is live again: its roster stands and b's late write shows, at every node
// whatever the order c took the three in
#[test]
fn a_minting_again_the_request_cannot_drop_brings_back_a_live_thing_alike_spec_commits_5() {
    for order in [[0, 2, 1], [1, 0, 2]] {
        let (Setup { mut net, a, b, c, g }, r) = setup_reader();
        let (t, _) = made(&mut net, a, g);
        let roster = net.engine(a).roster(&t);
        for n in [a, b, c, r] {
            net.set_online(n, false);
        }
        net.advance(10);
        let destruction = purge_thing(&mut net, a, t);
        let destruction = net.engine(a).package(&destruction).unwrap().unwrap().bytes;
        net.advance(10);
        let rec = net.engine(r).core.created(&t).cloned().unwrap();
        let mut m = Mutation::new();
        m.create(rec);
        m.retention(t, &ct::CREATED, osis_commit::retention::KEPT_RETENTION).unwrap();
        let rc = net.engine(r).commit_hostile(m).unwrap().unwrap();
        let remint = net.engine(r).take_forged().unwrap_or_else(|| net.engine(r).package(&rc).unwrap().unwrap().bytes);
        net.advance(10);
        let w = net.write(b, t, "late");
        let late = net.engine(b).package(&w).unwrap().unwrap().bytes;
        let lots = [&destruction, &remint, &late];
        for i in order {
            let _ = net.engine(c).ingest(lots[i], Vec::new());
            net.engine(c).reexamine().unwrap();
        }
        // b's write reaches the peer before b hears of the destruction: a destruction drops what
        // was written after it, and brought back is only what a copy is still held of (Limit)
        net.set_online(b, true);
        net.advance(70_000);
        for n in [a, c, r] {
            net.set_online(n, true);
        }
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c, r] {
            assert!(net.engine(n).knows(&t), "order {order:?}: node {n}: t back");
            assert_eq!(net.engine(n).roster(&t), roster, "order {order:?}: node {n}: its roster");
            assert_eq!(net.read(n, t), Some(s("late")), "order {order:?}: node {n}: b's late write");
        }
    }
}

// spec/commits.md §5 (Destruction), spec/permissions.md §6: b's destruction R1 falls by c's concurrent
// demotion of b on g; a destroys t after R1. A node taking R2 while R1 still stands drops it as written
// after the destruction, and fetches it again once R1 falls: t is destroyed at every node whatever the order
#[test]
fn a_second_destruction_after_one_that_falls_destroys_the_thing_spec_commits_5() {
    for order in [[1, 2, 0], [0, 1, 2]] {
        let (mut net, (a, b, c, g, r, t, tb)) = Net::cached("destruction::second", || {
            let (Setup { mut net, a, b, c, g }, r) = setup_reader();
            let (t, _) = made(&mut net, a, g);
            let tb = net.tid(b);
            set_edge(net.engine(a), g, tb, Role::Admin);
            net.run();
            (net, (a, b, c, g, r, t, tb))
        });
        for n in [a, b, c, r] {
            net.set_online(n, false);
        }
        let mut m = Mutation::new();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        m.op(g, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(tb)) }).unwrap();
        m.op(g, &ct::ROLES, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(tb))], op: Op::Set(edge.to_value()) }).unwrap();
        m.frontier(ct::Frontier::default().to_value());
        let d = net.engine(c).commit(m).unwrap().unwrap();
        let dem = net.engine(c).package(&d).unwrap().unwrap().bytes;
        net.advance(10);
        let r1 = purge_thing(&mut net, b, t);
        let r1 = net.engine(b).package(&r1).unwrap().unwrap().bytes;
        net.advance(10);
        let r2 = purge_thing(&mut net, a, t);
        let r2 = net.engine(a).package(&r2).unwrap().unwrap().bytes;
        let lots = [&dem, &r1, &r2];
        for i in order {
            let _ = net.engine(r).ingest(lots[i], Vec::new());
            net.engine(r).reexamine().unwrap();
        }
        for n in [a, b, c, r] {
            net.set_online(n, true);
        }
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c, r] {
            gone(&mut net, n, t);
        }
    }
}

// spec/permissions.md §1, spec/commits.md §5 (Destruction: authority through a destroyed actor stands):
// b administers plain x only through x's first admin t; once t was destroyed, removing t from x would
// leave x no admin (t's frozen admins administer x through t's edge alone), so it is refused
#[test]
fn removing_a_destroyed_only_admin_of_a_plain_thing_is_refused_spec_permissions_1() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = destroyed_actor_of(&mut net, a, b, g, false);
    let x = net.item(a, g, t, "x");
    net.run();
    destroy_with_c_away(&mut net, c);
    assert!(!net.engine(b).knows(&t), "t was destroyed");
    let d = osis_node::flows::Demotion { holder: t, new: None, retain: None };
    let err = net.engine(b).demote(&x, &d).err();
    assert!(matches!(err, Some(osis_node::Error::Misuse(m)) if m.contains("no admin")), "refused: {err:?}");
}

// spec/commits.md §5 (A thing's mintings travel with its record), spec/permissions.md §4, spec/sync.md
// §3 (Per-label copies): t, first admin of x (b granted admin on t, so t has secrets of its own), is
// purged, outside g's closure or listed in g; time passes, so every node judges what sits under g's
// label, and then a node is granted g. The request destroying t stays there for x's sake (every node
// holding x needs it), so the newcomer reads t as destroyed as the others do; x's body, sealed under
// t's secrets whose boxes went with t, goes there as a per-label copy, so the newcomer reads x, and
// the shared blob placed before the destruction goes as the copy's duplicate (spec/sync.md §7)
#[test]
fn a_destruction_by_purge_stays_under_a_dependents_label_for_a_newcomer_spec_commits_5() {
    for listed in [false, true] {
        let (mut net, host, [a, b, c], g, []) = hosted::<3, 0>(&[(1, Role::Write), (2, Role::Admin)], [], true);
        let mut m = Mutation::new();
        let t = net.engine(a).new_thing(&mut m, g);
        m.set(t, &REG, &s("t")).unwrap();
        if listed {
            let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
            items.items.insert(t);
            m.set(g, &ct::GROUP, &items).unwrap();
        }
        net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        let tb = net.tid(b);
        net.grant(a, t, tb, Role::Admin);
        net.run();
        let x = net.item(a, g, t, "x");
        net.run();
        net.advance(10);
        purge_thing(&mut net, a, t);
        net.run();
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c] {
            assert!(!net.engine(n).knows(&t), "listed {listed}, node {n}: t was destroyed");
            assert_eq!(net.read(n, x), Some(s("x")), "listed {listed}, node {n}: x reads");
        }
        let d = granted_later(&mut net, a, g);
        assert_eq!(net.read(d, x), Some(s("x")), "listed {listed}, d: x reads");
        assert!(net.engine(d).core.created(&t).is_some(), "listed {listed}, d: t's record, x names it");
        assert!(!net.engine(d).knows(&t), "listed {listed}, d: t was destroyed");
        assert_eq!(net.engine(d).roster(&x), net.engine(a).roster(&x), "listed {listed}, d: x's roster as at a");
        // no shared blob stays beside a copy: one entry per commit of x under g at the host
        let l = net.group_labels(a).into_iter().find(|(y, _)| *y == g).unwrap().1.id;
        let ids = net.host_ids(host, &l);
        let mut per: std::collections::BTreeMap<CommitId, usize> = Default::default();
        for (id, k) in net.sync(a).entries(&l) {
            if let osis_node::sync::EntryKind::Commit { commit, .. } = k
                && ids.contains(&id)
                && net.engine(a).header(&commit).is_some_and(|h| h.aspects.iter().any(|y| y.tid == x))
            {
                *per.entry(commit).or_default() += 1;
            }
        }
        assert!(!per.is_empty() && per.values().all(|n| *n == 1), "listed {listed}: one entry per commit of x: {per:?}");
    }
}

// spec/commits.md §5 (A thing's mintings travel with its record), spec/permissions.md §4, notes/growth.md:
// the certificates of a destroyed thing outside the closure (its minting's header, the request destroying
// it) stay under g's label while x, a dependent of it, is in the closure, and go once x is destroyed: no
// node finds a dependent there any more
#[test]
fn a_destroyed_things_certificates_leave_the_label_with_its_last_dependent_spec_commits_5() {
    let Setup { mut net, a, b, g, .. } = setup();
    let l = net.label(a);
    let mut m = Mutation::new();
    let t = net.engine(a).new_thing(&mut m, g);
    m.set(t, &REG, &s("t")).unwrap();
    let mint = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.run();
    let x = net.item(a, g, t, "x");
    net.run();
    net.advance(10);
    let req = purge_thing(&mut net, a, t);
    net.run();
    let at_the_peer = |net: &mut Net, c: CommitId| {
        let host = net.host_ids(0, &l);
        net.sync(a).entries(&l).into_iter().any(|(id, k)| host.contains(&id) && matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c))
    };
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(at_the_peer(&mut net, mint) && at_the_peer(&mut net, req), "t's minting and destruction under g's label for x");
    net.advance(10);
    purge_thing(&mut net, a, x);
    net.run();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(!net.engine(a).knows(&x), "x was destroyed");
    assert!(!at_the_peer(&mut net, mint), "t's minting header gone with its last dependent");
    assert!(!at_the_peer(&mut net, req), "the request destroying t gone with its last dependent");
}

// spec/commits.md §5 (Destruction: a release request): an admin's release of t is one commit of
// `released.0` deltas expiring `ROLE_KEEP` after it; every node receiving it destroys t as a purge of
// its creation does (t reads absent, a write on t is refused), a stale copy of the creation is destroyed
// again, and nothing of it is erasure's (its header lasts nowhere)
#[test]
fn a_released_thing_reads_absent_at_every_node_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, creation) = made(&mut net, a, g);
    net.write(b, t, "y");
    net.run();
    let stale = net.engine(a).package(&creation).unwrap().unwrap();
    let r = net.engine(c).release(&[t]).unwrap().unwrap();
    let h = net.engine(c).header(&r).unwrap();
    assert!(h.is_release() && h.purge.is_empty(), "a release, no purge field");
    assert_eq!(h.expires, Some(osis_commit::retention::release_expires(h.ts)), "it expires ROLE_KEEP after it");
    net.run();
    for n in [a, b, c] {
        gone(&mut net, n, t);
        assert!(net.engine(n).header(&r).is_some(), "node {n}: holds the request");
    }
    let _ = net.engine(b).ingest(&stale.bytes, Vec::new());
    gone(&mut net, b, t);
    net.restart(b, 79);
    net.run();
    gone(&mut net, b, t);
}

// spec/permissions.md §6 (Destruction), spec/commits.md §5: a release needs the right to destroy the thing
// (by default its admins): a writer's is refused at the writer, and one written past the writer's
// rules destroys nothing where it arrives
#[test]
fn a_release_without_the_right_destroys_nothing_spec_permissions_6() {
    let Setup { mut net, a, b, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    net.run();
    assert!(matches!(net.engine(b).release(&[t]), Err(osis_node::Error::Permission { .. })), "refused at the writer");
    let mut m = Mutation::new();
    m.set(t, &ct::RELEASED, &osis_base::WallMs(net.now())).unwrap();
    let id = net.engine(b).commit_hostile(m).unwrap().unwrap();
    let forged = net.engine(b).take_forged().unwrap();
    let _ = net.engine(a).ingest(&forged, Vec::new());
    net.run();
    assert!(net.engine(a).header(&id).is_some(), "a holds the forged request");
    for n in [a, b] {
        assert!(net.engine(n).knows(&t), "node {n}: t lives");
        assert_eq!(net.read(n, t), Some(s("x")), "node {n}: its value");
    }
    // a release request is a content commit of its own: its aspect is never compacted
    assert!(matches!(net.engine(a).snapshot(&t, &Ak::new(ct::RELEASED.ak()).unwrap()), Err(osis_node::Error::Misuse(_))));
}

// spec/commits.md §5 (Destruction: dependents), spec/crypto.md §4 (Holder actors, Destroyed): as
// `a_newcomer_admin_keys_a_dependent_by_a_destroyed_actors_frozen_holders_spec_crypto_4`, with t
// released instead of expired: x's admins box t's frozen holders in its place, every node judges
// x's roster and keys alike, and a node granted afterwards learns t was destroyed with its frozen history
// (the request's `released.0` part travels with t's record)
#[test]
fn a_released_actors_dependents_see_it_destroyed_spec_crypto_4() {
    let Setup { mut net, a, b, c, g } = setup();
    let mut m = Mutation::new();
    let t = net.engine(a).new_thing(&mut m, g);
    m.set(t, &REG, &s("t")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.run();
    let x = net.item(a, g, t, "x");
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    let ra = net.engine(a).roster(&x);
    net.engine(a).release(&[t]).unwrap().unwrap();
    for _ in 0..3 {
        net.advance(70_000);
    }
    let d = granted_later_as(&mut net, a, g, Role::Admin);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let cur = |net: &mut Net, n: usize| net.engine(n).epochs(&x).map(|e| e.read.current());
    let holders = |net: &mut Net, n: usize| net.engine(n).core.key_holders(&x).into_iter().collect::<std::collections::BTreeSet<_>>();
    let ha = holders(&mut net, a);
    assert!(!ha.iter().any(|h| h.0 == t) && ha.iter().any(|h| h.0 == g), "a: t's frozen holders hold x's keys: {ha:?}");
    for n in [a, b, c, d] {
        assert!(!net.engine(n).knows(&t), "node {n}: t was destroyed");
        assert!(net.engine(n).core.created(&t).is_some(), "node {n}: t's record kept for x");
        assert_eq!(net.read(n, x), Some(s("x")), "node {n}: x lives on");
        assert_eq!(net.engine(n).roster(&x), ra, "node {n}: x's roster");
        assert_eq!(holders(&mut net, n), ha, "node {n}: x's holders for keys");
        assert_eq!(cur(&mut net, n), cur(&mut net, a), "node {n}: x's current epochs");
    }
    let mut m = Mutation::new();
    m.set(x, &REG, &s("x2")).unwrap();
    net.engine(d).commit(m).unwrap().unwrap();
    for _ in 0..2 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert_eq!(net.read(n, x), Some(s("x2")), "node {n}: d's write");
    }
}

/// Whether host 0 holds an entry of commit `c` under label `l`, as node `n` knows the entries.
fn at_host_of(net: &mut Net, n: usize, l: &osis_base::LabelId, c: CommitId) -> bool {
    let host = net.host_ids(0, l);
    net.sync(n).entries(l).into_iter().any(|(id, k)| host.contains(&id) && matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c))
}

/// `r`, an item of `g` (first admin `g`), referencing `x`, made in the same commit listing `r` as
/// its retainer: that commit.
fn retained(net: &mut Net, n: usize, g: Tid) -> (Tid, Tid, CommitId) {
    let e = net.engine(n);
    let mut m = Mutation::new();
    let r = e.new_thing(&mut m, g);
    let x = e.new_thing(&mut m, g);
    m.set(x, &ct::RETAINERS, &std::collections::BTreeSet::from([r])).unwrap();
    m.set(r, &Ak::new("t:refs.0").unwrap(), &Value::Set([Value::Tid(x)].into())).unwrap();
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.extend([r, x]);
    m.set(g, &ct::GROUP, &items).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    net.run();
    (r, x, c)
}

// notes/lifetimes.md (What is kept; The release: Final while held), spec/commits.md §5
// (Destruction, Forgetting): x, listing r and referenced by it, is released on purpose. Past its
// request's expiry every node still holds that x was destroyed (r references it), and a node granted g
// afterwards gets that evidence under g's label: it reads x destroyed, not unknown, and a stale copy
// of x's creation is destroyed again on arrival. No header of x lasts meanwhile
#[test]
fn a_referenced_released_thing_stays_destroyed_past_its_expiry_and_for_a_newcomer_spec_commits_5() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(a);
    let (_r, x, made) = retained(&mut net, a, g);
    let w = net.write(b, x, "y");
    net.run();
    let stale = net.engine(a).package(&made).unwrap().unwrap();
    net.engine(a).release(&[x]).unwrap().unwrap();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(!at_host_of(&mut net, a, &l, w), "x's write left the host whole: a release leaves no lasting header");
    net.advance(osis_base::format::ROLE_KEEP_MS + 1_000);
    for _ in 0..2 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert_eq!(net.engine(n).lifetime_status(&x), Status::Destroyed, "node {n}: x stays destroyed past the request's expiry");
    }
    let d = granted_later(&mut net, a, g);
    assert_eq!(net.engine(d).lifetime_status(&x), Status::Destroyed, "d: told x destroyed under g's label");
    let _ = net.engine(d).ingest(&stale.bytes, stale.blobs);
    net.run();
    assert_eq!(net.engine(d).lifetime_status(&x), Status::Destroyed, "d: a stale copy is destroyed again");
    assert!(!net.engine(d).knows(&x));
}

// notes/lifetimes.md (What is kept; Interactions: Expiry): rr, an expiring retainer,
// references cx, which lists it. rr expires while its admins are offline (not heard out: cx
// stays). A node granted g afterwards receives cx with rr's destruction under g's label (cx lists rr),
// so it reads rr destroyed, judges cx unreachable and releases it, rather than reading rr unknown and
// keeping cx for good
#[test]
fn an_expired_retainers_child_is_judged_and_released_at_a_later_node_spec_commits_5() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, a, b, c, g } = setup();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let rr = e.new_thing(&mut m, g);
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(rr);
    m.set(g, &ct::GROUP, &items).unwrap();
    m.expires_all(osis_base::WallMs(net.now() + 5_000));
    net.engine(a).commit(m).unwrap().unwrap();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let cx = e.new_thing(&mut m, g);
    m.set(cx, &ct::RETAINERS, &std::collections::BTreeSet::from([rr])).unwrap();
    m.set(rr, &Ak::new("t:refs.0").unwrap(), &Value::Set([Value::Tid(cx)].into())).unwrap();
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(cx);
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap().unwrap();
    net.run();
    // d is granted admin of g now, and takes it up (receives g) only after rr expired
    let d = net.joining_node(4, &[0]);
    let addr = net.address(0);
    let (made, done) = net.engine(d).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(d).carry_out(done).unwrap();
    net.actions(d, acts);
    net.run();
    net.pair(d, a);
    net.nodes[d].accepts = false;
    let edge = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &made.account, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    // g's other admins are offline: nobody who may destroy cx judges it at rr's expiry
    net.set_online(a, false);
    net.set_online(c, false);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).lifetime_status(&rr), Status::Destroyed, "rr expired");
    assert_eq!(net.engine(b).lifetime_status(&cx), Status::Known, "b may not destroy cx");
    assert_eq!(net.engine(b).lifetimes_pending().unwrap(), vec![cx], "b: unreachable, pending");
    assert_eq!(net.engine(a).lifetime_status(&cx), Status::Known, "a offline: nothing judged");
    net.nodes[d].accepts = true;
    let acts = net.accept_invites(d);
    net.actions(d, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(d).lifetime_status(&rr), Status::Destroyed, "d: told rr destroyed under g's label");
    assert_eq!(net.engine(d).lifetime_status(&cx), Status::Destroyed, "d: cx judged unreachable and released once heard out");
    assert_eq!(net.engine(b).lifetime_status(&cx), Status::Destroyed, "b: by d's request");
    net.set_online(a, true);
    net.run();
    assert_eq!(net.engine(a).lifetime_status(&cx), Status::Destroyed, "a: released");
}

// notes/lifetimes.md (The release: Applying; Limits 5), spec/sync.md §6: a right holder
// places the release request at a host before any of the released thing's blobs is deleted
// there, so no host holds neither (else a holder that missed the request logs the thing
// again and right holders release it again, round for good): checked after every message
#[test]
fn a_release_request_is_at_the_host_before_the_things_blobs_leave_spec_sync_6() {
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(a);
    let (t, _) = made(&mut net, a, g);
    let w = net.write(b, t, "y");
    net.run();
    assert!(at_host_of(&mut net, a, &l, w), "t's write at the host");
    let req = net.engine(c).release(&[t]).unwrap().unwrap();
    for n in [a, b, c] {
        net.feed(n, osis_node::sync::Event::Local);
    }
    loop {
        let (w_at, req_at) = (at_host_of(&mut net, c, &l, w), at_host_of(&mut net, c, &l, req));
        assert!(w_at || req_at, "neither t's write nor the request at the host");
        if !net.step() {
            break;
        }
    }
    net.run();
    assert!(!at_host_of(&mut net, c, &l, w) && at_host_of(&mut net, c, &l, req), "t's write deleted at the host, the request there");
}

// notes/lifetimes.md (Cost; The release: Not erasure, Forgotten), spec/commits.md §5
// (Lasting, Forgetting), spec/sync.md §6: t is released and g's list lets go of it, so nothing
// held lists or references it. No header of t lasts (its write leaves the host whole), and past
// the request's expiry nothing of t is held anywhere: no node holds the request or t's write, and
// the host holds no entry of either
#[test]
fn nothing_of_a_released_thing_nothing_needs_outlasts_its_request_spec_commits_5() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(a);
    let (t, _) = made(&mut net, a, g);
    let w = net.write(b, t, "y");
    net.run();
    let req = net.engine(c).release(&[t]).unwrap().unwrap();
    net.run();
    let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.remove(&t);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &items).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(!at_host_of(&mut net, a, &l, w), "t's write left the host whole: no lasting header");
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        let e = net.engine(n);
        assert_eq!(e.lifetime_status(&t), Status::Unknown, "node {n}: t forgotten");
        assert!(e.header(&req).is_none() && e.header(&w).is_none(), "node {n}: no header of t's commits");
        assert!(!at_host_of(&mut net, n, &l, req) && !at_host_of(&mut net, n, &l, w), "node {n}: nothing of t at the host");
        assert!(!net.sync(n).entries(&l).iter().any(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == req || *commit == w)), "node {n}: no entry of t's commits known");
    }
}

// notes/lifetimes.md (What is kept), spec/commits.md §5 (Destruction, Forgetting): a group
// contains its members, it does not need them told destroyed. t, released while still listed in g's
// `group.0`, is forgotten at its request's expiry at every node: no record, no header of a commit
// only on it, nothing of them at the host
#[test]
fn a_released_group_member_is_forgotten_while_still_listed_spec_commits_5() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(a);
    let (t, _) = made(&mut net, a, g);
    let w = net.write(b, t, "y");
    net.run();
    let req = net.engine(c).release(&[t]).unwrap().unwrap();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default().items.contains(&t), "t still listed");
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        let e = net.engine(n);
        assert_eq!(e.lifetime_status(&t), Status::Unknown, "node {n}: t forgotten");
        assert!(e.core.created(&t).is_none() && e.header(&req).is_none() && e.header(&w).is_none(), "node {n}: no record, no header of t's commits");
        assert!(!at_host_of(&mut net, n, &l, req) && !at_host_of(&mut net, n, &l, w), "node {n}: nothing of t's commits at the host");
    }
}

// spec/sync.md §6 (Dropped bodies: a commit forgotten with a released thing), spec/commits.md §5
// (Forgetting): a node forgets a released thing (r lets go of t past its request's expiry) and
// restarts before deleting its commits' entries at the host, alone on the network: it still
// deletes them, and keeps nothing of them past their tombstones
#[test]
fn a_forgotten_commits_entries_are_deleted_after_a_restart_spec_sync_6() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(a);
    let (r, t, _) = retained(&mut net, a, g);
    let req = net.engine(c).release(&[t]).unwrap().unwrap();
    net.run();
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(at_host_of(&mut net, a, &l, req), "the request's copy at the host while r references t");
    net.set_online(b, false);
    net.set_online(c, false);
    let mut m = Mutation::new();
    m.set(r, &Ak::new("t:refs.0").unwrap(), &Value::Set(Default::default())).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    assert_eq!(net.engine(a).lifetime_status(&t), Status::Unknown, "forgotten");
    let ids: Vec<_> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == req)).map(|(id, _)| id).collect();
    assert!(!ids.is_empty());
    net.restart(a, 50);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(!net.host_ids(0, &l).iter().any(|x| ids.contains(x)), "deleted at the host");
    assert!(!net.sync(a).entries(&l).iter().any(|(id, _)| ids.contains(id)), "no entry of it known");
    net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS + 1_000);
    net.restart(a, 51);
    assert!(net.engine(a).local_rows_naming(&req.0).unwrap().is_empty(), "nothing names it past its tombstones");
}

// spec/commits.md §5 (Forgetting), spec/sync.md §6: w writes x, an item of g, and y, a thing of
// g's no closure holds yet, so y's record is not held at b. b forgets x at its release's expiry
// and w with it, here alone: its entries stay at the host, skipped at b as awaiting y's record,
// not fetched again over later syncs. y then joins g: its record reaches b, w is fetched again
// and y's part of it applies
#[test]
fn a_commit_on_a_forgotten_thing_and_an_unknown_one_awaits_its_record_spec_commits_5() {
    forgotten_and_unknown(false);
}

// as above, b restarting while w's entries await: a start fetches them again, and an entry
// judged then awaits every record its commit lacks (x's, which never comes, and y's), so y's
// record arriving still wakes it
#[test]
fn a_commit_on_a_forgotten_thing_and_an_unknown_one_awaits_its_record_over_a_restart_spec_commits_5() {
    forgotten_and_unknown(true);
}

fn forgotten_and_unknown(restart: bool) {
    use osis_node::retention::lifetimes::Status;
    use osis_node::sync::EntryKind;
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(b);
    // x made apart from its listing in g: no commit carrying x's record has a part elsewhere
    let e = net.engine(c);
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, g);
    m.set(x, &REG, &s("x")).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(x);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap().unwrap();
    net.run();
    let e = net.engine(c);
    let mut m = Mutation::new();
    let y = e.new_thing(&mut m, g);
    m.set(y, &REG, &s("y")).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(x, &REG, &s("x2")).unwrap();
    m.set(y, &REG, &s("y2")).unwrap();
    let w = net.engine(c).commit(m).unwrap().unwrap();
    net.run();
    assert!(!net.engine(b).knows(&y) && net.engine(b).header(&w).is_some(), "b holds w, not y's record");
    let of_w = |net: &mut Net| -> Vec<(osis_base::BlobId, EntryKind)> { net.sync(b).entries(&l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } | EntryKind::Awaits { commit, .. } if *commit == w)).collect() };
    let ids: Vec<osis_base::BlobId> = of_w(&mut net).into_iter().map(|(id, _)| id).collect();
    assert!(!ids.is_empty());
    // the admins away (they would delete w's entries once x is released), c's release reaches b
    net.set_online(a, false);
    net.set_online(c, false);
    let req = net.engine(c).release(&[x]).unwrap().unwrap();
    let p = net.engine(c).package(&req).unwrap().unwrap();
    let _ = net.engine(b).ingest(&p.bytes, p.blobs);
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).lifetime_status(&x), Status::Unknown, "x forgotten");
    assert!(net.engine(b).header(&w).is_none(), "w forgotten here");
    assert!(of_w(&mut net).iter().all(|(_, k)| matches!(k, EntryKind::Awaits { things, .. } if things.contains(&y))), "its entries skipped, awaiting y's record");
    assert!(ids.iter().all(|i| net.host_ids(0, &l).contains(i)), "and kept at the host");
    if restart {
        net.restart(b, 61);
        for _ in 0..3 {
            net.advance(70_000);
        }
        assert!(net.engine(b).header(&w).is_none());
        assert!(of_w(&mut net).iter().all(|(_, k)| matches!(k, EntryKind::Awaits { things, .. } if things.contains(&y))), "judged again at the start: awaiting y's record too");
    }
    net.fetched.insert(b, Vec::new());
    for _ in 0..5 {
        net.advance(70_000);
    }
    assert_eq!(net.fetched[&b].iter().filter(|i| ids.contains(i)).count(), 0, "not fetched again over later syncs");
    let e = net.engine(c);
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(y);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap().unwrap();
    net.set_online(c, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(b, y), Some(s("y2")), "y's part of w applies at b");
}

// spec/commits.md §5 (Forgetting): x and y released together at c, b never having held y's
// record. b forgets w (on both) here alone as x goes; c forgets it whole and deletes its entries,
// so b keeps nothing of w: no header, no entry. The request goes at b too (its part on y dropped,
// not held), and with it every row naming y
#[test]
fn a_commit_on_a_forgotten_thing_and_a_never_held_one_leaves_nothing_spec_commits_5() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, b, c, g, .. } = setup();
    let l = net.label(b);
    let (x, _) = made(&mut net, c, g);
    let e = net.engine(c);
    let mut m = Mutation::new();
    let y = e.new_thing(&mut m, g);
    m.set(y, &REG, &s("y")).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(x, &REG, &s("x2")).unwrap();
    m.set(y, &REG, &s("y2")).unwrap();
    let w = net.engine(c).commit(m).unwrap().unwrap();
    net.run();
    let req = net.engine(c).release(&[x, y]).unwrap().unwrap();
    net.run();
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..5 {
        net.advance(70_000);
    }
    assert_eq!(net.engine(b).lifetime_status(&x), Status::Unknown);
    assert!(net.engine(c).header(&w).is_none() && net.engine(b).header(&w).is_none(), "w forgotten at c and b");
    let known = net.sync(b).entries(&l).into_iter().any(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } | osis_node::sync::EntryKind::Awaits { commit, .. } if commit == w));
    assert!(!known, "no entry of w known at b");
    // the request on x and y went too, its purge items with it: no engine row names y
    let rows: Vec<Vec<u8>> = net.engine(b).local_rows_naming(y.as_bytes()).unwrap().into_iter().map(|(k, _)| k).filter(|k| !k.starts_with(b"y/")).collect();
    assert!(rows.is_empty(), "no row names y at b");
    assert!(net.engine(b).header(&req).is_none(), "the request gone at b");
}

// spec/commits.md §5 (Forgetting): b forgets x (made with g's listing: its commit keeps its
// header, x's parts marked) and z (made alone: its commit goes whole) while their entries stay at
// the host, the admins away; a restart of b ingests neither again from what it holds, so both
// stay unknown
#[test]
fn released_things_stay_forgotten_over_a_restart_spec_commits_5() {
    use osis_node::retention::lifetimes::Status;
    let Setup { mut net, a, b, c, g } = setup();
    let (x, _) = made(&mut net, c, g);
    let e = net.engine(c);
    let mut m = Mutation::new();
    let z = e.new_thing(&mut m, g);
    m.set(z, &REG, &s("z")).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut items = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(z);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &items).unwrap();
    e.commit(m).unwrap().unwrap();
    net.run();
    assert!(net.engine(b).knows(&x) && net.engine(b).knows(&z));
    net.set_online(a, false);
    net.set_online(c, false);
    let req = net.engine(c).release(&[x, z]).unwrap().unwrap();
    let p = net.engine(c).package(&req).unwrap().unwrap();
    let _ = net.engine(b).ingest(&p.bytes, p.blobs);
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for t in [x, z] {
        assert_eq!(net.engine(b).lifetime_status(&t), Status::Unknown, "forgotten");
    }
    net.restart(b, 63);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for t in [x, z] {
        assert_eq!(net.engine(b).lifetime_status(&t), Status::Unknown, "still forgotten after a restart");
    }
}

// spec/commits.md §5 (a release request expires at ts + ROLE_KEEP), spec/sync.md §5 (an entry
// goes at its prefix expiry): x and y released together, b never having held y's record (its
// entry of the request awaits it). At the expiry every node forgets the request and its entry
// goes there too, whatever is known of its commit: no entry, no row in the node's own hub (it
// serves what it reads), no bytes; past the tombstones nothing names it (the forgotten header
// included)
#[test]
fn a_release_requests_entry_goes_everywhere_at_its_expiry_spec_sync_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let l = net.label(b);
    let (x, _) = made(&mut net, c, g);
    let e = net.engine(c);
    let mut m = Mutation::new();
    let y = e.new_thing(&mut m, g);
    m.set(y, &REG, &s("y")).unwrap();
    e.commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(x, &REG, &s("x2")).unwrap();
    m.set(y, &REG, &s("y2")).unwrap();
    net.engine(c).commit(m).unwrap().unwrap();
    net.run();
    let req = net.engine(c).release(&[x, y]).unwrap().unwrap();
    net.run();
    let of_req = |net: &mut Net, n: usize| -> Vec<osis_base::BlobId> { net.sync(n).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } | osis_node::sync::EntryKind::Awaits { commit, .. } if *commit == req)).map(|(id, _)| id).collect() };
    let ids = of_req(&mut net, c);
    assert!(!ids.is_empty(), "the request placed");
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert!(of_req(&mut net, n).is_empty(), "node {n}: no entry of the request");
        let rows = osis_proto::LabelStore::live_ids(&*net.sync(n).hub_store().lock().unwrap(), &l).unwrap();
        assert!(!ids.iter().any(|i| rows.contains(i) || net.sync(n).holds_blob(i)), "node {n}: no row, no bytes of it");
    }
    net.advance(osis_base::format::TOMBSTONE_LIFETIME_MS + 1_000);
    for n in [a, b, c] {
        assert!(net.engine(n).local_rows_naming(&req.0).unwrap().is_empty(), "node {n}: nothing names it past the tombstones");
    }
}

// spec/sync.md §5 (an entry goes at its prefix expiry, at any host), spec/commits.md §5
// (Forgetting): b stops syncing g's label L (handed off), its rows there kept unread. A writer's
// release request under L reaches b. Nothing at b reads L, yet the entry goes there at the
// request's expiry, with every reader having forgotten it, as it goes at the host that never
// read L
#[test]
fn a_release_requests_entry_goes_where_it_is_held_unread_spec_sync_5() {
    let (net, host, [a, b, c], g, []) = hosted::<3, 0>(&[(1, Role::Write), (2, Role::Admin)], [], true);
    let mut net = net;
    let old = net.label(b);
    let acts = net.sync(b).set_handed_off(g, true);
    net.actions(b, acts);
    net.run();
    assert!(net.group_labels(b).into_iter().all(|(x, _)| x != g), "b syncs no label of g");
    let rows = |net: &mut Net, n: usize, l: &osis_base::LabelId| osis_proto::LabelStore::live_ids(&*net.sync(n).hub_store().lock().unwrap(), l).unwrap();
    assert!(!rows(&mut net, b, &old).is_empty(), "b keeps rows of L, unread");
    // b's connections forget L too
    net.restart(b, 31);
    net.run();
    let (x, _) = made(&mut net, c, g);
    let req = net.engine(c).release(&[x]).unwrap().unwrap();
    net.run();
    let ids: Vec<osis_base::BlobId> = net.sync(c).entries(&old).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == req)).map(|(id, _)| id).collect();
    assert!(!ids.is_empty() && ids.iter().all(|i| net.host_ids(host, &old).contains(i)), "the request placed");
    // the entry reaches b under L by its store's rules (as a pull from a writer: the blob's prefix expiry)
    for id in &ids {
        let bytes = osis_proto::LabelStore::blob(&*net.sync(c).hub_store().lock().unwrap(), id).unwrap().unwrap();
        let expiry = osis_label::host_prefix(&bytes).unwrap().and_then(|p| p.expiry()).map(|t| t.0);
        assert!(expiry.is_some(), "the request's blob carries its expiry");
        let put = osis_proto::Put { blob_id: *id, blob: &bytes, wrap: [7; osis_crypto::WRAP_LEN], stamp: None, expiry, ephemeral: false, now: net.now(), role: false };
        assert_eq!(osis_proto::LabelStore::put(&mut *net.sync(b).hub_store().lock().unwrap(), &old, put).unwrap(), osis_proto::Code::OK);
    }
    net.run();
    assert!(ids.iter().all(|i| rows(&mut net, b, &old).contains(i)), "b holds it under L");
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert!(net.engine(n).header(&req).is_none(), "node {n} forgot the request");
    }
    assert!(!ids.iter().any(|i| net.host_ids(host, &old).contains(i)), "gone at the host");
    let held = rows(&mut net, b, &old);
    assert!(!ids.iter().any(|i| held.contains(i) || net.sync(b).holds_blob(i)), "gone at b: no row, no bytes");
}

/// What node `n` keeps of destroyed `t`: its record, the edge commits on it, and its parts held
/// (the value-less creation, `roles.0`, the destroying requests' parts).
fn leftovers(net: &mut Net, n: usize, t: Tid) -> usize {
    let e = net.engine(n);
    let commits: Vec<CommitId> = e.core.on_thing(&t).collect();
    let parts: usize = commits.iter().map(|c| e.header(c).map_or(0, |h| h.aspects.iter().enumerate().filter(|(ai, a)| a.tid == t && e.part_held(c, *ai)).count())).sum();
    usize::from(e.core.created(&t).is_some()) + e.core.ix.held.commits_on(&t).len() + parts
}

// spec/commits.md §5 (Destruction: kept while a request destroying it is in force): a thing destroyed
// by purge that nothing needs keeps what judges its destruction for `ROLE_KEEP` after the request, then
// nothing, at every node; a stale copy of its creation arriving later, before or after a restart,
// brings nothing back
#[test]
fn a_purged_thing_nothing_needs_keeps_nothing_past_its_requests_window_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, creation) = made(&mut net, a, g);
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.write(b, t, "y");
    net.run();
    let stale = net.engine(a).package(&creation).unwrap().unwrap();
    purge_thing(&mut net, a, t);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        gone(&mut net, n, t);
        // the record, the grant's edge commit, the value-less creation, its `roles.0` parts and the
        // request's part
        assert!(leftovers(&mut net, n, t) >= 4, "node {n}: what judges the destruction is kept in its window");
    }
    net.advance(osis_base::format::ROLE_KEEP_MS);
    for n in [a, b, c] {
        gone(&mut net, n, t);
        assert_eq!(leftovers(&mut net, n, t), 0, "node {n}: nothing kept past the window");
    }
    let _ = net.engine(b).ingest(&stale.bytes, stale.blobs.clone());
    net.run();
    gone(&mut net, b, t);
    assert_eq!(leftovers(&mut net, b, t), 0, "a stale copy brings nothing back");
    net.restart(b, 79);
    let _ = net.engine(b).ingest(&stale.bytes, stale.blobs);
    net.advance(70_000);
    for n in [a, b, c] {
        gone(&mut net, n, t);
        assert_eq!(leftovers(&mut net, n, t), 0, "node {n}: nothing back after a restart");
    }
}

/// How the last dependent of a destroyed thing lets go of it.
#[derive(Clone, Copy, Debug)]
enum LetGo {
    Expiry,
    Purge,
    /// The node loses read access to the dependent's group.
    LostAccess,
}

// spec/commits.md §5 (Destruction: kept while a held thing needs it): t, purged, is referenced by x.
// Past the request's window every node keeps what tells t was destroyed while x references it; once
// that reference goes (it expires, is purged, or the node loses read access to x) nothing of t is left
// there, and the same entries coming round again bring nothing back
#[test]
fn a_destroyed_thing_leaves_nothing_once_its_last_dependent_lets_go_spec_commits_5() {
    let refs = Ak::new("t:refs.0").unwrap();
    for how in [LetGo::Expiry, LetGo::Purge, LetGo::LostAccess] {
        let Setup { mut net, a, b, c, g } = setup();
        let (t, _) = made(&mut net, a, g);
        let x = net.item(a, g, g, "x");
        let mut m = Mutation::new();
        m.set(x, &refs, &Value::Set([Value::Tid(t)].into())).unwrap();
        if matches!(how, LetGo::Expiry) {
            m.expires_all(osis_base::WallMs(net.now() + osis_base::format::ROLE_KEEP_MS + 600_000));
        }
        net.engine(a).commit(m).unwrap().unwrap();
        net.run();
        purge_thing(&mut net, a, t);
        for _ in 0..3 {
            net.advance(70_000);
        }
        net.advance(osis_base::format::ROLE_KEEP_MS);
        for n in [a, b, c] {
            gone(&mut net, n, t);
            assert!(net.engine(n).core.created(&t).is_some(), "{how:?} node {n}: t's record kept while x references it");
            assert!(leftovers(&mut net, n, t) >= 3, "{how:?} node {n}: its record, value-less creation and request part");
        }
        let at: Vec<usize> = match how {
            LetGo::Expiry => {
                net.advance(700_000);
                vec![a, b, c]
            }
            LetGo::Purge => {
                let mut m = Mutation::new();
                m.set(x, &ct::PURGE, &osis_base::WallMs(net.now())).unwrap();
                m.purge(PurgeItem::Aspect { tid: x, ak: refs.clone() });
                net.engine(a).commit(m).unwrap().unwrap();
                for _ in 0..3 {
                    net.advance(70_000);
                }
                vec![a, b, c]
            }
            LetGo::LostAccess => {
                let tb = net.tid(b);
                net.engine(a).demote(&g, &osis_node::flows::Demotion { holder: tb, new: None, retain: Some(false) }).unwrap();
                for _ in 0..3 {
                    net.advance(70_000);
                }
                assert_eq!(net.engine(b).get(&x, &refs).unwrap(), None, "b forgot x's content");
                vec![b]
            }
        };
        for n in at {
            gone(&mut net, n, t);
            assert_eq!(leftovers(&mut net, n, t), 0, "{how:?} node {n}: nothing of t once x lets go");
        }
        for _ in 0..3 {
            net.advance(70_000);
        }
        for n in [a, b, c] {
            assert_eq!(net.engine(n).core.created(&t).is_some(), matches!(how, LetGo::LostAccess) && n != b, "{how:?} node {n}: nothing comes back");
        }
    }
}

/// How a minting of a thing destroyed for good comes back.
#[derive(Clone, Copy, Debug)]
enum Minted {
    /// A copy of its creation, held from before the purge.
    Stale,
    /// A new minting by a node that holds its record.
    Fresh,
}

// spec/commits.md §5 (Destruction: destroyed for good), spec/requirements.md (a destroyed thing's later
// writes are ignored): past a purge request's window every node keeps only the verdict, so a minting
// arriving later, a stale copy of the creation or a new one by a node holding the record, is dropped
// everywhere, a newcomer granted the group after the window included, before and after a restart.
// `by_grant`: the purger's right came from a grant on t itself (else from g, t's first admin), which
// no node holds past the window
#[test]
fn a_minting_of_a_thing_purged_past_its_window_is_dropped_everywhere_spec_commits_5() {
    for by_grant in [true, false] {
        for how in [Minted::Stale, Minted::Fresh] {
            let Setup { mut net, a, b, c, g } = setup();
            let (t, creation) = made(&mut net, a, g);
            let tb = net.tid(b);
            net.grant(a, t, tb, Role::Admin);
            net.run();
            let stale = net.engine(a).package(&creation).unwrap().unwrap();
            let rec = net.engine(c).core.created(&t).cloned().unwrap();
            purge_thing(&mut net, if by_grant { b } else { a }, t);
            for _ in 0..3 {
                net.advance(70_000);
            }
            net.advance(osis_base::format::ROLE_KEEP_MS);
            let d = granted_later(&mut net, a, g);
            for n in [a, b, c, d] {
                gone(&mut net, n, t);
                assert_eq!(leftovers(&mut net, n, t), 0, "{by_grant} {how:?} node {n}: nothing kept past the window");
            }
            match how {
                Minted::Stale => {
                    let _ = net.engine(c).ingest(&stale.bytes, stale.blobs.clone());
                }
                Minted::Fresh => {
                    let mut m = Mutation::new();
                    m.create(rec);
                    let _ = net.engine(c).commit_hostile(m);
                }
            }
            for _ in 0..3 {
                net.advance(70_000);
            }
            for n in [a, b, c, d] {
                gone(&mut net, n, t);
                assert_eq!(leftovers(&mut net, n, t), 0, "{by_grant} {how:?} node {n}: the minting is dropped");
            }
            net.restart(b, 79);
            let _ = net.engine(b).ingest(&stale.bytes, stale.blobs);
            for _ in 0..3 {
                net.advance(70_000);
            }
            for n in [a, b, c, d] {
                gone(&mut net, n, t);
                assert_eq!(leftovers(&mut net, n, t), 0, "{by_grant} {how:?} node {n}: dropped after a restart");
            }
        }
    }
}
