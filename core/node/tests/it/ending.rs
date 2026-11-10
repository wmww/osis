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
    set_edge(net.engine(a), t, tb, Role::Admin);
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
    let mut lp = crate::common::net(1, 0x7e4);
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
    lp.peers[0].engine.tick().unwrap();
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
        let Setup { mut net, a, b, c, g } = setup();
        let (t, _) = made(&mut net, a, g);
        let tb = net.tid(b);
        set_edge(net.engine(a), t, tb, Role::Admin);
        net.run();
        // a takes all three in turn: c's removal of b, c's re-grant of b, and b's request after them
        net.set_online(a, false);
        net.advance(10);
        let done = net.engine(c).demote(&t, &osis_node::flows::Demotion { holder: tb, new: None, retain: None }).unwrap();
        let removal: Vec<_> = done.commits.iter().map(|x| net.engine(c).package(x).unwrap().unwrap()).collect();
        net.advance(10);
        let re = set_edge(net.engine(c), t, tb, Role::Admin);
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
    let mut lp = crate::common::net(2, 0x7e5);
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
        let e = &mut lp.peers[i].engine;
        e.tick().unwrap();
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
        let e = &mut lp.peers[i].engine;
        e.tick().unwrap();
        assert!(!e.knows(&x), "peer {i}: x ended");
        assert!(e.core.created(&x).is_none() && e.core.created(&t).is_none(), "peer {i}: neither leaves a record");
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

// spec/commits.md §5 (Ending: dependents), issues/ended-first-admin-keep-is-local.md: b is admin of
// x only by its edge on x's first admin t. t ends by expiry while c holds no dependent of it, so c
// keeps nothing of t, its edges included; once x reaches c, c's roster of x lacks b's grant that a
// and b show. A node granted afterwards does not read x at all (cause not yet split out: t's own
// secrets, or c's deletes at the host). Fails: the keep rule is per node
#[test]
#[ignore]
fn repro_ended_first_admin_edges_lost_where_no_dependent_was_held() {
    let Setup { mut net, a, b, c, g } = setup();
    let at = net.now() + 5_000;
    let mut m = Mutation::new();
    let t = net.engine(a).new_thing(&mut m, g);
    m.set(t, &REG, &s("t")).unwrap();
    let mut items = net.engine(a).get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
    items.items.insert(t);
    m.set(g, &ct::GROUP, &items).unwrap();
    m.expires_all(osis_base::WallMs(at));
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let tb = net.tid(b);
    set_edge(net.engine(a), t, tb, Role::Admin);
    net.run();
    net.set_online(c, false);
    let x = net.item(a, g, t, "x");
    net.run();
    let ta = net.tid(a);
    set_edge(net.engine(b), x, ta, Role::Read);
    net.run();
    let ra = net.engine(a).roster(&x);
    assert!(ra.contains_key(&ta), "a: b's grant on x by its admin on t");
    for _ in 0..2 {
        net.advance(70_000);
    }
    net.set_online(c, true);
    for _ in 0..3 {
        net.advance(70_000);
    }
    for n in [a, b, c] {
        assert!(!net.engine(n).knows(&t), "node {n}: t ended");
        assert_eq!(net.read(n, x), Some(s("x")), "node {n}: x lives on");
        assert_eq!(net.engine(n).roster(&x), ra, "node {n}: x's roster");
    }
    let d = net.joining_node(4, &[0]);
    let addr = net.address(0);
    let (made, done) = net.engine(d).create_account(std::slice::from_ref(&addr)).unwrap();
    let dt = made.account;
    let acts = net.sync(d).carry_out(done).unwrap();
    net.actions(d, acts);
    net.run();
    net.pair(d, a);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let done = net.engine(a).grant(&g, &dt, &edge).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let acts = net.accept_invites(d);
    net.actions(d, acts);
    for _ in 0..3 {
        net.advance(70_000);
    }
    assert_eq!(net.read(d, x), Some(s("x")), "d: x reads");
    assert_eq!(net.engine(d).roster(&x), ra, "d: x's roster");
}
