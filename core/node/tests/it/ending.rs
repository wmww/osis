#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Ending a thing at the node level (spec/commits.md §5 Ending, spec/permissions.md §6): what
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

fn end(net: &mut Net, by: usize, t: Tid) -> CommitId {
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

// spec/commits.md §5 (Ending): an ending holds over a restart, and nothing of the thing reads as
// existing
#[test]
fn ended_stays_ended_over_a_restart_spec_commits_5() {
    let Setup { mut net, a, b, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    net.write(b, t, "y");
    net.run();
    end(&mut net, a, t);
    net.run();
    for n in [a, b] {
        gone(&mut net, n, t);
    }
    net.restart(b, 77);
    net.run();
    gone(&mut net, b, t);
    assert!(net.read(b, g).is_some() || net.read(a, g) == net.read(b, g));
}

// spec/permissions.md §6 (Ending), spec/commits.md §5: an admin by a grant on the thing alone may
// end it, and the verdict reads the edges the ending keeps: a stale copy of the creation arriving
// while the request is held ends the thing again, also after a restart
#[test]
fn a_grant_holder_ends_and_a_stale_copy_ends_again_spec_permissions_6() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, creation) = made(&mut net, a, g);
    let tc = net.tid(c);
    net.grant(a, t, tc, Role::Admin);
    demote(&mut net, a, g, tc, Role::Read);
    net.run();
    let stale = net.engine(a).package(&creation).unwrap().unwrap();
    end(&mut net, c, t);
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

// spec/requirements.md Deletion; Tess's ruling on a fallen ending: a demotion ordered before the
// request makes the ending fall where it is held; the thing comes back from a node holding a copy
#[test]
fn an_ending_that_falls_comes_back_from_a_copy_spec_commits_5() {
    let Setup { mut net, a, b, c, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    let tb = net.tid(b);
    net.grant(a, g, tb, Role::Admin);
    net.run();
    // c demotes b concurrently: its demotion is earlier than b's request, and b has not seen it
    net.set_online(c, false);
    demote(&mut net, c, g, tb, Role::Read);
    net.advance(10);
    end(&mut net, b, t);
    net.run();
    gone(&mut net, a, t);
    assert_eq!(net.read(c, t), Some(s("x")), "c never heard");
    net.set_online(c, true);
    net.run();
    net.advance(120_000);
    net.advance(120_000);
    assert_eq!(net.read(c, t), Some(s("x")), "the ending fell at c, which holds a copy");
    assert_eq!(net.read(a, t), Some(s("x")), "the ending fell at a: the copy comes back");
    assert_eq!(net.read(b, t), Some(s("x")), "and at the demoted b");
}

// spec/commits.md §4 (Unjudgeable), §5 (Ending): a late write on an ended thing is a write on an
// unknown thing: nothing of it is kept, and it does not come back while the ending stands
#[test]
fn a_late_write_awaits_an_ended_thing_spec_commits_5() {
    let Setup { mut net, a, b, g, .. } = setup();
    let (t, _) = made(&mut net, a, g);
    net.set_online(b, false);
    let late = net.write(b, t, "late");
    let pk = net.engine(b).package(&late).unwrap().unwrap();
    end(&mut net, a, t);
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

// spec/commits.md §4, §5 (Ending): an ending arriving while a write awaits the unknown thing: the
// write comes back to nothing, and its parts are not held
#[test]
fn an_ending_while_a_write_awaits_the_thing_spec_commits_5() {
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

/// The work of ending one thing holding `parts` writes on a node holding `others` other things.
fn ending_work(parts: usize, others: usize) -> (crate::scale::Work, crate::scale::Work) {
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

// spec/requirements.md Scale, spec/commits.md §5 (Ending): an ending costs the thing's own parts,
// not their square and not the things beside it: it rewrites only the store pages its own rows
// sit on, however many other things the node holds (bytes follow the page size, so writes are
// what is counted)
#[test]
fn ending_costs_the_things_parts_spec_commits_5() {
    let (a, b) = (ending_work(20, 5), ending_work(200, 5));
    crate::scale::linear("rebuilds by parts", a.0.n("rebuild"), b.0.n("rebuild"));
    crate::scale::linear("bytes written by parts", a.0.io.written_bytes, b.0.io.written_bytes);
    let (a, b) = (ending_work(5, 20), ending_work(5, 200));
    crate::scale::flat("rebuilds by other things", a.0.n("rebuild"), b.0.n("rebuild"));
    crate::scale::flat("store writes by other things", a.0.io.writes, b.0.io.writes);
}

// spec/commits.md §5 (Ending): the first admin's removal is authorised by a grant the ending keeps,
// so a removal arriving after the ending makes it fall and a copy brings the thing back
#[test]
fn repro_first_admin_removal_after_ending() {
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
    end(&mut net, a, t);
    net.run();
    gone(&mut net, b, t);
    for p in &removal {
        let _ = net.engine(b).ingest(&p.bytes, Vec::new());
    }
    let _ = net.engine(b).ingest(&copy.bytes, Vec::new());
    assert_eq!(net.read(b, t), Some(s("x")));
}

// spec/commits.md §5 (Ending), spec/sync.md §5: a removal of the first admin racing an ending, in
// both arrival orders: the nodes agree the ending fell, and then nothing is uploaded or deleted at
// hosts over and over
#[test]
fn removal_racing_an_ending_converges_in_both_orders_spec_commits_5() {
    for ending_first in [true, false] {
        let (mut net, (a, b, c, g, t)) = Net::cached("ending::removal_racing", || {
            let Setup { mut net, a, b, c, g } = setup();
            let (t, _) = made(&mut net, a, g);
            let (tc, tb) = (net.tid(c), net.tid(b));
            net.grant(a, t, tc, Role::Admin);
            net.grant(a, t, tb, Role::Read);
            net.run();
            (net, (a, b, c, g, t))
        });
        // who is cut off until both are written: the side that took the other first
        let off = if ending_first { c } else { a };
        net.set_online(off, false);
        net.engine(c).demote(&t, &osis_node::flows::Demotion { holder: g, new: None, retain: None }).unwrap();
        net.run();
        net.advance(10);
        end(&mut net, a, t);
        net.run();
        net.set_online(off, true);
        net.run();
        for _ in 0..4 {
            net.advance(120_000);
        }
        // a lost its way in with the first admin's edge; b and c hold their own
        for n in [b, c] {
            assert_eq!(net.read(n, t), Some(s("x")), "ending first {ending_first}: node {n}");
        }
        assert!(!net.engine(a).core.ended(&t), "ending first {ending_first}: it fell at a too");
        let churn = |net: &Net| net.sent_kinds.get(&10).copied().unwrap_or(0) + net.sent_kinds.get(&14).copied().unwrap_or(0);
        let settled = churn(&net);
        for _ in 0..4 {
            net.advance(120_000);
        }
        assert_eq!(churn(&net), settled, "ending first {ending_first}: uploads and deletes go on");
    }
}

/// Whether a commit on `t` held at node `n` has a part on `t` waiting.
fn waiting_on(net: &mut Net, n: usize, t: Tid) -> bool {
    let core = &net.engine(n).core;
    core.on_thing(&t).any(|c| core.ix.commits.get(&c).is_some_and(|m| m.missing.iter().any(|ai| m.header.aspects.get(*ai).is_some_and(|a| a.tid == t))))
}

// spec/commits.md §4, §5 (Ending): a fall judges again what waited on the ended thing (a late write
// awaiting it, the falling removal's own key rotation), and observers of its roles hear it come back
#[test]
fn a_fall_judges_again_what_waited_on_the_ended_thing_spec_commits_5() {
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
    end(&mut net, b, t);
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

// spec/commits.md §5 (Ending): an ending by expiry keeps nothing, even where the thing held a purge
// request of something else
#[test]
fn an_expiry_ending_keeps_nothing_beside_a_purge_spec_commits_5() {
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

// spec/commits.md §5 (Ending), spec/permissions.md §6: a removal of the ending's author and its
// re-grant, ordered before the request, arriving in any order around it: the verdict is a
// function of what is held
#[test]
fn removal_and_regrant_around_an_ending_converge_in_any_order_spec_commits_5() {
    // the ending first (it stands, falls, stands again), between the two, and last
    for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0]] {
        let (mut net, (a, b, c, _, t, tb)) = Net::cached("ending::removal_and_regrant", || {
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
        let ending = end(&mut net, b, t);
        let ending = vec![net.engine(b).package(&ending).unwrap().unwrap()];
        let lots = [ending, removal, regrant];
        for lot in order {
            for p in &lots[lot] {
                let _ = net.engine(a).ingest(&p.bytes, Vec::new());
            }
        }
        net.engine(a).reexamine().unwrap();
        assert!(net.engine(a).core.ended(&t), "order {order:?}: the re-grant gives the right back");
        gone(&mut net, a, t);
    }
}

// spec/commits.md §5 (Ending: dependents): an ended thing others name first admin keeps its record
// and edges while one of them is held, so the dependent reads and is written through the ended
// thing's standing edges; once its last dependent ends too, neither leaves anything
#[test]
fn an_ended_first_admin_stays_a_chain_proof_until_its_last_dependent_goes_spec_commits_5() {
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
        assert!(!e.knows(&t), "peer {i}: t ended");
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
        assert!(!e.knows(&x), "peer {i}: x ended");
        assert!(e.core.created(&x).is_none() && e.core.created(&t).is_none(), "peer {i}: neither leaves a record");
    }
}

// spec/commits.md §5 (Ending: dependents): an ended actor a held edge names holder on another
// thing is on that thing's authority paths and keeps its record and edges, as a first admin does;
// once that thing ends too, nothing of either is left
#[test]
fn an_ended_holder_stays_until_what_names_it_goes_spec_commits_5() {
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
        assert!(!e.knows(&t), "peer {i}: t ended");
        assert!(e.core.created(&t).is_some(), "peer {i}: t's record kept, x names it holder");
        assert!(e.roster(&x).contains_key(&t), "peer {i}: t's edge on x stands");
    }
    lp.advance(4_000);
    for i in 0..2 {
        lp.peers[i].tick().unwrap();
        let e = &mut lp.peers[i].engine;
        assert!(!e.knows(&x), "peer {i}: x ended");
        assert!(e.core.created(&x).is_none() && e.core.created(&t).is_none(), "peer {i}: neither leaves a record");
        assert!(e.core.timelines.get(&t).is_none_or(|tl| tl.roster(&t, osis_perm::At::END).is_empty()), "peer {i}: no edges of t kept");
    }
}

// spec/commits.md §5 (Ending: dependents), spec/permissions.md §4 (records travel raw): an account
// that ends itself leaves the group it created running under its other admins. Its own data is
// gone; what it wrote there still reads and verifies, the other admin writes on, and a node
// granted afterwards learns the account's record from the group's label alone
#[test]
fn an_ended_account_leaves_what_it_created_running_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let p = net.engine(a).me();
    let t = net.item(a, g, g, "from a");
    let mut m = Mutation::new();
    m.set(p, &REG, &s("mine")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert_eq!(net.read(a, p), Some(s("mine")));
    end(&mut net, a, p);
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
    let d = net.joining_node(4, &[0]);
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

// spec/commits.md §5 (Ending: dependents), spec/permissions.md §4 (Placing): a thing whose first
// admin ended by expiry before a node joined the group reads at that node, which learns the ended
// first admin's record from the group's label (no body there carries it once it ended), and takes
// no write on that record alone: it cannot tell the thing ended
#[test]
fn a_node_joining_after_a_first_admin_ended_reads_its_dependents_spec_commits_5() {
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
        assert!(!net.engine(n).knows(&t), "node {n}: t ended");
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
    assert!(matches!(net.engine(d).commit(m), Err(osis_node::Error::UnknownThing(_))), "d: a write to t refused, as at a node that saw it end");
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

/// A thing `t` in `g` (first admin `g`) that ends by expiry in 5 s, with b granted admin on it.
/// `listed`: `g` lists it in a durable commit of its own, so the ended thing stays in `g`'s
/// closure; else in its expiring creation commit, so it leaves the closure as it ends.
fn ending_actor(net: &mut Net, a: usize, b: usize, g: Tid, listed: bool) -> Tid {
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

/// Lets `t` end (`ending_actor`) with c offline through it, then brings c back.
fn end_with_c_away(net: &mut Net, c: usize) {
    for _ in 0..2 {
        net.advance(70_000);
    }
    net.set_online(c, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
}

// spec/commits.md §5 (Ending: dependents), spec/permissions.md §4 (Placing): b is admin of x only
// by its edge on x's first admin t. t ends by expiry while c holds no dependent of it (x reaches c
// after the ending), so c keeps nothing of t and its ending deletes t's bodies at the host; the
// holders of x place t's frozen edges under the label again (as closure bodies while g lists t,
// else as certificate copies), so c judges b's grant on x as a and b do
#[test]
fn an_ended_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5() {
    for listed in [false, true] {
        let Setup { mut net, a, b, c, g } = setup();
        let t = ending_actor(&mut net, a, b, g, listed);
        net.set_online(c, false);
        let x = net.item(a, g, t, "x");
        net.run();
        let ta = net.tid(a);
        net.grant(b, x, ta, Role::Read);
        net.run();
        let ra = net.engine(a).roster(&x);
        assert!(ra.contains_key(&ta), "listed {listed}: a: b's grant on x by its admin on t");
        end_with_c_away(&mut net, c);
        for n in [a, b, c] {
            assert!(!net.engine(n).knows(&t), "listed {listed}: node {n}: t ended");
            assert_eq!(net.read(n, x), Some(s("x")), "listed {listed}: node {n}: x lives on");
            assert_eq!(net.engine(n).roster(&x), ra, "listed {listed}: node {n}: x's roster");
        }
    }
}

// spec/commits.md §5 (Ending): as
// `an_ended_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5`, with a durable
// write on t before its ending. c keeps nothing of t, then takes its record again with x; a late
// copy of that write is a part on an ended thing there, never content
#[test]
fn a_late_content_copy_after_the_record_comes_back_stays_ended_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = ending_actor(&mut net, a, b, g, false);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("y")).unwrap();
    let late = net.engine(a).commit(m).unwrap().unwrap();
    let late = net.engine(a).package(&late).unwrap().unwrap().bytes;
    net.run();
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    end_with_c_away(&mut net, c);
    assert!(net.engine(c).core.created(&t).is_some(), "c: t's record back with x");
    let _ = net.engine(c).ingest(&late, Vec::new());
    net.engine(c).reexamine().unwrap();
    for _ in 0..2 {
        net.advance(70_000);
    }
    assert!(!net.engine(c).knows(&t), "c: t ended");
    assert_eq!(net.read(c, t), None, "c: nothing of t");
    assert!(!net.engine(c).has_content(&t).unwrap(), "c: no content on t");
    assert_eq!(net.read(c, x), Some(s("x")), "c: x lives on");
}

// spec/commits.md §5 (Ending: dependents), spec/permissions.md §1 (the first admin is history): t,
// granted admin on x by an edge (x's first admin is g), ends by expiry; b, admin of x only through
// t, granted on x before the ending and grants again after it through t's frozen edges. Every node
// agrees on x's roster: those that held x at the ending, c which got the ending first, and a node
// granted afterwards
#[test]
fn authority_through_an_ended_granted_admin_stands_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = ending_actor(&mut net, a, b, g, true);
    net.set_online(c, false);
    let x = net.item(a, g, g, "x");
    net.run();
    net.grant(a, x, t, Role::Admin);
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    end_with_c_away(&mut net, c);
    let tc = net.tid(c);
    net.grant(b, x, tc, Role::Write);
    net.run();
    for _ in 0..2 {
        net.advance(70_000);
    }
    let ra = net.engine(a).roster(&x);
    assert!(ra.get(&ta).is_some_and(|e| e.role == Role::Read), "a: b's grant before the ending");
    assert!(ra.get(&tc).is_some_and(|e| e.role == Role::Write), "a: b's grant after it");
    for n in [a, b, c] {
        assert!(!net.engine(n).knows(&t), "node {n}: t ended");
        assert!(net.engine(n).core.created(&t).is_some(), "node {n}: t's record stays, x names it holder");
        assert_eq!(net.engine(n).roster(&x), ra, "node {n}: x's roster");
    }
    let d = granted_later(&mut net, a, g);
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert_eq!(net.engine(d).roster(&x), ra, "d: x's roster");
    assert!(!net.engine(d).knows(&t), "d: t ended, learned with its frozen history");
    assert!(net.engine(d).roster(&t).is_empty(), "d: t's roster reads empty as at a");
}

// spec/crypto.md §4 (Holder actors, Ended): as
// `an_ended_first_admins_edges_reach_a_node_that_held_no_dependent_spec_commits_5`, then a node
// granted g afterwards: x has secrets of its own, boxed to its holder actor t, whose own secrets
// nobody boxes once t ended; x's admins box t's frozen holders (g, b's account) in its place, so
// the newcomer reads x through g
#[test]
fn newcomer_reads_a_dependent_keyed_by_an_ended_actor_spec_crypto_4() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = ending_actor(&mut net, a, b, g, false);
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    let ra = net.engine(a).roster(&x);
    end_with_c_away(&mut net, c);
    let d = granted_later(&mut net, a, g);
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert_eq!(net.engine(d).roster(&x), ra, "d: x's roster");
}

// spec/crypto.md §4 (Holder actors, Ended), spec/commits.md §5 (Ending): as
// `newcomer_reads_a_dependent_keyed_by_an_ended_actor_spec_crypto_4` with d an admin of g. t's
// ending travels with its frozen history (its minting's header), so d reads t as ended as the
// others do: t's frozen holders hold x's keys in its place, x's current epochs agree, and what d
// writes to x the others read
#[test]
fn a_newcomer_admin_keys_a_dependent_by_an_ended_actors_frozen_holders_spec_crypto_4() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = ending_actor(&mut net, a, b, g, false);
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    let ta = net.tid(a);
    net.grant(b, x, ta, Role::Read);
    net.run();
    end_with_c_away(&mut net, c);
    let d = granted_later_as(&mut net, a, g, Role::Admin);
    for _ in 0..3 {
        net.advance(70_000);
    }
    let cur = |net: &mut Net, n: usize| net.engine(n).epochs(&x).map(|e| e.read.current());
    let holders = |net: &mut Net, n: usize| net.engine(n).core.key_holders(&x).into_iter().collect::<std::collections::BTreeSet<_>>();
    let ha = holders(&mut net, a);
    assert!(!ha.iter().any(|h| h.0 == t) && ha.iter().any(|h| h.0 == g), "a: t's frozen holders hold x's keys: {ha:?}");
    for n in [b, c, d] {
        assert!(!net.engine(n).knows(&t), "node {n}: t ended");
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

// spec/commits.md §5 (Ending): a request names every minting. A reader of `g` (it holds t's record)
// mints t again before and after an admin purges t's creation, and a writer of t mints it again
// after the ending, each with the default retention: c takes the three and the ending in every
// order, and t reads gone everywhere
#[test]
fn a_minting_again_the_request_can_drop_never_brings_back_a_purged_thing_spec_commits_5() {
    for order in [[0, 1, 2, 3], [1, 0, 2, 3], [2, 3, 1, 0], [3, 2, 0, 1]] {
        let (mut net, (a, b, c, _, r, t)) = Net::cached("ending::minting_again_can_drop", || {
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
        let ending = end(&mut net, a, t);
        let ending = net.engine(a).package(&ending).unwrap().unwrap().bytes;
        net.advance(10);
        let after = remint(&mut net, r, t);
        let by_writer = remint(&mut net, b, t);
        let lots = [&before, &ending, &after, &by_writer];
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

// spec/commits.md §5 (Ending, Limit): a reader holding an expiring thing's record mints it again
// durable, before its expiry and after it. Wherever the mintings arrive before or after the thing
// ended there, it exists past its expiry, but its content still expired
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
        assert_eq!(net.engine(c).core.ended(&t), !remint_first, "first {remint_first}: t ended at c only without the minting");
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

// spec/commits.md §5 (Ending: nobody writes a thing after its ending): t, first admin of x, is
// purged; c, an admin of t that has not heard of it, grants r admin on t afterwards. r gains nothing on x through t at b whether the grant reaches it before or after the
// ending, nor anywhere once all have synced
#[test]
fn an_edge_write_after_an_ending_counts_nowhere_spec_commits_5() {
    for grant_first in [true, false] {
        let (mut net, (a, b, c, _, r, t, x)) = Net::cached("ending::edge_write_after", || {
            let (Setup { mut net, a, b, c, g }, r) = setup_reader();
            let (t, _) = made(&mut net, a, g);
            let x = net.item(a, g, t, "x");
            net.run();
            (net, (a, b, c, g, r, t, x))
        });
        let tr = net.tid(r);
        assert_eq!(net.engine(r).role_on(&x), Some(Role::Read), "grant first {grant_first}: r reads x through g");
        // c, offline, has not heard of the ending: its grant is a writer's, stamped after it
        net.set_online(b, false);
        net.set_online(c, false);
        net.advance(10);
        let ending = end(&mut net, a, t);
        let ending = net.engine(a).package(&ending).unwrap().unwrap().bytes;
        net.run();
        net.advance(10);
        let grant = set_edge(net.engine(c), t, tr, Role::Admin);
        let grant = net.engine(c).package(&grant).unwrap().unwrap().bytes;
        let lots = if grant_first { [&grant, &ending] } else { [&ending, &grant] };
        for p in lots {
            let _ = net.engine(b).ingest(p, Vec::new());
            net.engine(b).reexamine().unwrap();
        }
        assert!(net.engine(b).core.ended(&t), "grant first {grant_first}: t ended at b");
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

// spec/commits.md §5 (Ending: nobody writes a thing after its ending), spec/permissions.md §4: t,
// first admin of x, is purged; a node granted g afterwards learns t's record, frozen edges and the
// request with them, so it reads t as ended, and a grant on t that c, not having heard, wrote
// after the ending gives r nothing there, as at b
#[test]
fn a_newcomer_refuses_an_edge_write_after_an_ending_spec_commits_5() {
    let (Setup { mut net, a, b, c, g }, r) = setup_reader();
    let (t, _) = made(&mut net, a, g);
    let x = net.item(a, g, t, "x");
    net.run();
    let tr = net.tid(r);
    net.set_online(c, false);
    net.advance(10);
    end(&mut net, a, t);
    net.run();
    net.advance(10);
    let grant = set_edge(net.engine(c), t, tr, Role::Admin);
    let grant = net.engine(c).package(&grant).unwrap().unwrap().bytes;
    let d = granted_later(&mut net, a, g);
    assert!(!net.engine(d).knows(&t), "d: t ended");
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

// spec/commits.md §5 (Ending is judged by the history before it), spec/permissions.md §6: c, admin
// of t by its own grant on t alone, ends t; a, not having heard, demotes c on t afterwards with a
// frontier that omits the request. The demotion is a write after the ending: whether b takes it
// before or after the request, the ending stands at every node
#[test]
fn a_demotion_after_an_ending_does_not_undo_it_spec_commits_5() {
    for demotion_first in [true, false] {
        let (mut net, (a, b, c, _, t, tc)) = Net::cached("ending::demotion_after", || {
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
        let ending = end(&mut net, c, t);
        let ending = net.engine(c).package(&ending).unwrap().unwrap().bytes;
        net.advance(10);
        let mut m = Mutation::new();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        m.op(t, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(tc)) }).unwrap();
        m.op(t, &ct::ROLES, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(tc))], op: Op::Set(edge.to_value()) }).unwrap();
        m.frontier(ct::Frontier::default().to_value());
        let d = net.engine(a).commit(m).unwrap().unwrap();
        let demotion = net.engine(a).package(&d).unwrap().unwrap().bytes;
        let lots = if demotion_first { [&demotion, &ending] } else { [&ending, &demotion] };
        for p in lots {
            let _ = net.engine(b).ingest(p, Vec::new());
            net.engine(b).reexamine().unwrap();
        }
        assert!(net.engine(b).core.ended(&t), "demotion first {demotion_first}: the ending stands at b");
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

/// The things node a's cut walks count for one role change on t, while c's ending request on t
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
    let ending = end(&mut net, c, t);
    let ending = net.engine(c).package(&ending).unwrap().unwrap().bytes;
    net.advance(10);
    set_edge(net.engine(a), t, tb, Role::Write);
    let _ = net.engine(a).ingest(&ending, Vec::new());
    net.engine(a).reexamine().unwrap();
    assert!(!net.engine(a).core.ended(&t), "others {others}: the request stands nowhere");
    osis_node::costs::take();
    set_edge(net.engine(a), t, tb, Role::Admin);
    osis_node::costs::take().into_iter().find(|x| x.0 == "ending: cut walk things").map_or(0, |x| x.2)
}

// spec/requirements.md Scale, spec/permissions.md §6 (Ending): a request that ended nothing, with
// later edge writes on its thing held, costs each role change on the thing what the thing's
// authority comes from, not the node's other things
#[test]
fn a_fallen_ending_walks_only_the_things_authority_spec_permissions_6() {
    let (small, big) = (fallen_request_work(3), fallen_request_work(30));
    assert!(small > 0, "the cut walk runs");
    crate::scale::flat("cut walk things by other things", small, big);
}

// spec/commits.md §5 (Ending, Limit): a reader of g mints a purged t again `nobody`, which the
// request has no right over; b, not having heard of the ending, writes t after it. Brought back, t
// is live again: its roster stands and b's late write shows, at every node whatever the order c
// took the three in
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
        let ending = end(&mut net, a, t);
        let ending = net.engine(a).package(&ending).unwrap().unwrap().bytes;
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
        let lots = [&ending, &remint, &late];
        for i in order {
            let _ = net.engine(c).ingest(lots[i], Vec::new());
            net.engine(c).reexamine().unwrap();
        }
        for n in [a, b, c, r] {
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

// spec/commits.md §5 (Ending), spec/permissions.md §6: b's ending R1 falls by c's concurrent
// demotion of b on g; a ends t after R1. A node taking R2 while R1 still stands drops it as written
// after the ending, and fetches it again once R1 falls: t ends at every node whatever the order
#[test]
fn a_second_ending_after_one_that_falls_ends_the_thing_spec_commits_5() {
    for order in [[1, 2, 0], [0, 1, 2]] {
        let (mut net, (a, b, c, g, r, t, tb)) = Net::cached("ending::second_ending", || {
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
        let r1 = end(&mut net, b, t);
        let r1 = net.engine(b).package(&r1).unwrap().unwrap().bytes;
        net.advance(10);
        let r2 = end(&mut net, a, t);
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

// spec/permissions.md §1, spec/commits.md §5 (Ending: authority through an ended actor stands):
// b administers plain x only through x's first admin t; once t ended, removing t from x would
// leave x no admin (t's frozen admins administer x through t's edge alone), so it is refused
#[test]
fn removing_an_ended_only_admin_of_a_plain_thing_is_refused_spec_permissions_1() {
    let Setup { mut net, a, b, c, g } = setup();
    let t = ending_actor(&mut net, a, b, g, false);
    let x = net.item(a, g, t, "x");
    net.run();
    end_with_c_away(&mut net, c);
    assert!(!net.engine(b).knows(&t), "t ended");
    let d = osis_node::flows::Demotion { holder: t, new: None, retain: None };
    let err = net.engine(b).demote(&x, &d).err();
    assert!(matches!(err, Some(osis_node::Error::Misuse(m)) if m.contains("no admin")), "refused: {err:?}");
}

// spec/commits.md §5 (The ending travels with the record), spec/permissions.md §4: t, first admin
// of x and outside g's closure, is purged; time passes, so every node judges what sits under g's
// label, and then a node is granted g. The request ending t stays there for x's sake (every node
// holding x needs it), so the newcomer reads t as ended as the others do
#[test]
fn a_purge_ending_stays_under_a_dependents_label_for_a_newcomer_spec_commits_5() {
    let Setup { mut net, a, b, c, g } = setup();
    let mut m = Mutation::new();
    let t = net.engine(a).new_thing(&mut m, g);
    m.set(t, &REG, &s("t")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let tb = net.tid(b);
    net.grant(a, t, tb, Role::Admin);
    net.run();
    let x = net.item(a, g, t, "x");
    net.run();
    net.advance(10);
    end(&mut net, a, t);
    net.run();
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert!(!net.engine(n).knows(&t), "node {n}: t ended");
    }
    let d = granted_later(&mut net, a, g);
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert!(net.engine(d).core.created(&t).is_some(), "d: t's record, x names it");
    assert!(!net.engine(d).knows(&t), "d: t ended");
    assert_eq!(net.engine(d).roster(&x), net.engine(a).roster(&x), "d: x's roster as at a");
}

// spec/commits.md §5 (The ending travels with the record), spec/permissions.md §4, notes/growth.md:
// the certificates of an ended thing outside the closure (its minting's header, the request ending
// it) stay under g's label while x, a dependent of it, is in the closure, and go once x ends: no
// node finds a dependent there any more
#[test]
fn an_ended_things_certificates_leave_the_label_with_its_last_dependent_spec_commits_5() {
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
    let req = end(&mut net, a, t);
    net.run();
    let at_host = |net: &mut Net, c: CommitId| {
        let host = net.host_ids(0, &l);
        net.sync(a).entries(&l).into_iter().any(|(id, k)| host.contains(&id) && matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == c))
    };
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(at_host(&mut net, mint) && at_host(&mut net, req), "t's minting and ending under g's label for x");
    net.advance(10);
    end(&mut net, a, x);
    net.run();
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert!(!net.engine(a).knows(&x), "x ended");
    assert!(!at_host(&mut net, mint), "t's minting header gone with its last dependent");
    assert!(!at_host(&mut net, req), "the request ending t gone with its last dependent");
}

// spec/commits.md §5 (Ending: a release request): an admin's release of t is one commit of
// `released.0` deltas expiring `ROLE_KEEP` after it; every node receiving it ends t as a purge of
// its creation does (t reads absent, a write on t is refused), a stale copy of the creation ends
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

// spec/permissions.md §6 (Ending), spec/commits.md §5: a release needs the right to end the thing
// (by default its admins): a writer's is refused at the writer, and one written past the writer's
// rules ends nothing where it arrives
#[test]
fn a_release_without_the_right_ends_nothing_spec_permissions_6() {
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

// spec/commits.md §5 (Ending: dependents), spec/crypto.md §4 (Holder actors, Ended): as
// `a_newcomer_admin_keys_a_dependent_by_an_ended_actors_frozen_holders_spec_crypto_4`, with t
// released instead of expired: x's admins box t's frozen holders in its place, every node judges
// x's roster and keys alike, and a node granted afterwards learns t ended with its frozen history
// (the request's `released.0` part travels with t's record)
#[test]
fn a_released_actors_dependents_see_it_ended_spec_crypto_4() {
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
        assert!(!net.engine(n).knows(&t), "node {n}: t ended");
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
