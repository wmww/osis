#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Ending a thing at the node level (spec/commits.md §5 Ending, spec/permissions.md §6): what
//! outlasts it, restarts, stale copies, a fall, and its cost.

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
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, Role::Write), (c, Role::Admin)], &[host]);
    net.run();
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
    for ak in ["tid.0", "aspects.0", "groups.0", "roles.0", ct::PURGE.ak(), ct::CREATED.ak()] {
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
    set_edge(net.engine(a), t, tc, Role::Admin);
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
    set_edge(net.engine(a), g, tb, Role::Admin);
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
    let mut lp = crate::common::net(2, 0x7e2);
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
    let mut lp = crate::common::net(1, 0x7e3);
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
// not their square and not the things beside it
#[test]
fn ending_costs_the_things_parts_spec_commits_5() {
    let (a, b) = (ending_work(20, 5), ending_work(200, 5));
    crate::scale::linear("rebuilds by parts", a.0.n("rebuild"), b.0.n("rebuild"));
    crate::scale::linear("bytes written by parts", a.0.io.written_bytes, b.0.io.written_bytes);
    let (a, b) = (ending_work(5, 20), ending_work(5, 200));
    crate::scale::flat("rebuilds by other things", a.0.n("rebuild"), b.0.n("rebuild"));
}

// spec/commits.md §5 (Ending): the first admin's removal is authorised by a grant the ending keeps,
// so a removal arriving after the ending makes it fall and a copy brings the thing back
#[test]
fn repro_first_admin_removal_after_ending() {
    let Setup { mut net, a, b, c, g } = setup();
    let (t, creation) = made(&mut net, a, g);
    let tc = net.tid(c);
    set_edge(net.engine(a), t, tc, Role::Admin);
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
        let Setup { mut net, a, b, c, g } = setup();
        let (t, _) = made(&mut net, a, g);
        let (tc, tb) = (net.tid(c), net.tid(b));
        set_edge(net.engine(a), t, tc, Role::Admin);
        set_edge(net.engine(a), t, tb, Role::Read);
        net.run();
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

// spec/requirements.md Scale: an ending rewrites only the store pages its own rows sit on, however
// many other things the node holds (bytes follow the page size, so writes are what is counted)
#[test]
fn ending_writes_flat_in_other_things_spec_commits_5() {
    let (a, b) = (ending_work(5, 20), ending_work(5, 200));
    crate::scale::flat("store writes by other things", a.0.io.writes, b.0.io.writes);
}
