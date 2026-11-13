#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A node holds no secret of an actor it cannot read (spec/permissions.md §3, Lost access): no
//! box it opens later, from any source, gives a lost actor's secrets back; a re-grant does.

use crate::net;
use net::*;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::sync::Event;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

fn local(net: &mut Net, n: usize) {
    let acts = net.sync(n).handle(Event::Local);
    net.actions(n, acts);
}

/// Node `n` makes a thing under `admin`, an item of `group`.
fn made(net: &mut Net, n: usize, admin: Tid, group: Tid) -> Tid {
    let e = net.engine(n);
    let mut m = Mutation::new();
    let w = e.new_thing(&mut m, admin);
    m.op(group, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) }).unwrap();
    e.write(m).unwrap();
    local(net, n);
    w
}

fn carry(net: &mut Net, n: usize, done: osis_node::flows::Done) {
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
}

struct Lost {
    net: Net,
    a: usize,
    r: usize,
    g: Tid,
    x: Tid,
    w2: Tid,
    /// The blob under g's label holding w2's part.
    b: osis_base::BlobId,
}

/// a grants x read to g, which r and o read; one commit writes w1 (g's) and w2 (x's, an item of
/// g), placed under g's label as one blob; a demotes g on x, and r loses x: its secrets, w2's
/// content and the blob's bytes go.
fn lost_x() -> Lost {
    let mut net = Net::new();
    let (h1, h2) = (net.add_host(), net.add_host());
    let a = net.node(1, &[h1, h2]);
    let r = net.node(2, &[h1, h2]);
    let o = net.node(3, &[h1, h2]);
    let g = net.group(a, &[(r, Role::Read), (o, Role::Read)], &[h1]);
    let addr = net.hosts[h2].address.clone();
    let x = net.group_at(a, &[], vec![addr]);
    let done = net.engine(a).grant(&x, &g, &crate::common::edge(Role::Read)).unwrap();
    carry(&mut net, a, done);
    net.run();
    let w1 = made(&mut net, a, g, g);
    let w2 = made(&mut net, a, x, g);
    net.run();
    let lg = net.group_labels(r).into_iter().find(|(t, _)| *t == g).unwrap().1.id;
    let before: BTreeSet<_> = net.sync(r).entries(&lg).into_iter().map(|e| e.0).collect();
    let mut m = Mutation::new();
    m.set(w1, &crate::common::REG, &s("v")).unwrap();
    m.set(w2, &crate::common::REG, &s("x")).unwrap();
    net.engine(a).write(m).unwrap();
    local(&mut net, a);
    net.run();
    assert_eq!((net.read(r, w1), net.read(r, w2)), (Some(s("v")), Some(s("x"))));
    let new: Vec<_> = net.sync(r).entries(&lg).into_iter().map(|e| e.0).filter(|b| !before.contains(b)).collect();
    assert_eq!(new.len(), 1, "one blob of both parts under g's label");
    let done = net.engine(a).demote(&x, &osis_node::flows::Demotion { holder: g, new: None, retain: None }).unwrap();
    carry(&mut net, a, done);
    for _ in 0..3 {
        net.advance(31_000);
    }
    let rt = net.tid(r);
    assert!(!net.engine(r).may_read(&rt, &w2), "the reader lost x");
    assert_eq!(net.read(r, w1), Some(s("v")));
    let mut l = Lost { net, a, r, g, x, w2, b: new[0] };
    holds_nothing(&mut l);
    l
}

/// r holds no secret of x, nothing of w2's content, and not the blob holding its part.
fn holds_nothing(l: &mut Lost) {
    let (r, x, w2, b) = (l.r, l.x, l.w2, l.b);
    assert!(l.net.engine(r).read_secrets(&x).is_empty(), "no secret of the lost actor");
    assert_eq!(l.net.read(r, w2), None, "nor its content");
    assert!(l.net.engine(r).blob(&b).unwrap().is_none(), "nor the bytes of the blob holding it");
}

/// The node removes g's other reader: g's next epoch reaches r, which reopens the boxes sealed to g.
fn rotate_g(l: &mut Lost) {
    let o = l.net.tid(2);
    let done = l.net.engine(l.a).demote(&l.g, &osis_node::flows::Demotion { holder: o, new: None, retain: None }).unwrap();
    carry(&mut l.net, l.a, done);
}

// The forgotten `secrets.0` part of x's grant to g rejoins from its copy under g's label, which r
// still reads; reopening the store opens its box to g: x's old secrets do not come back
#[test]
fn a_rejoined_box_after_restart_gives_no_lost_secret_spec_permissions_3() {
    let mut l = lost_x();
    for _ in 0..3 {
        l.net.advance(31_000);
    }
    l.net.restart(l.r, 21);
    for _ in 0..3 {
        l.net.advance(31_000);
    }
    holds_nothing(&mut l);
}

// The same with no restart: g's next epoch reopens the boxes sealed to g at runtime, the rejoined
// one among them, and r walks g's label again, where the blob holding w2's part (a copy under the
// label's key, which r reads) still is: neither gives anything of x back
#[test]
fn a_rejoined_box_at_runtime_gives_no_lost_secret_spec_permissions_3() {
    let mut l = lost_x();
    for _ in 0..3 {
        l.net.advance(31_000);
    }
    rotate_g(&mut l);
    for _ in 0..3 {
        l.net.advance(31_000);
    }
    holds_nothing(&mut l);
}

// An entry box (spec/sync.md §2: anyone holding the label's step key can write one, a removed
// admin among them) gives no secret of an actor whose held roles give the node none
#[test]
fn an_entry_box_gives_no_lost_secret_spec_permissions_3() {
    let mut l = lost_x();
    let held: Vec<_> = l.net.engine(l.a).epochs(&l.x).unwrap().read.held().map(|(e, s)| (e, s.clone())).collect();
    assert!(!held.is_empty());
    for (e, s) in held {
        assert!(!l.net.engine(l.r).learn_secret(&l.x, Role::Read, e, s).unwrap());
    }
    holds_nothing(&mut l);
}

// A re-grant of x to g brings x's secrets and content back after the box rejoined
#[test]
fn a_re_grant_after_a_rejoined_box_reads_again_spec_permissions_3() {
    let mut l = lost_x();
    for _ in 0..3 {
        l.net.advance(31_000);
    }
    rotate_g(&mut l);
    l.net.restart(l.r, 21);
    l.net.advance(31_000);
    let done = l.net.engine(l.a).grant(&l.x, &l.g, &crate::common::edge(Role::Read)).unwrap();
    carry(&mut l.net, l.a, done);
    for _ in 0..5 {
        l.net.advance(31_000);
    }
    assert!(!l.net.engine(l.r).read_secrets(&l.x).is_empty(), "x's secrets again");
    assert_eq!(l.net.read(l.r, l.w2), Some(s("x")), "and its content");
}

// A rotation an admin made before it saw the node's removal, boxing the node, arrives after the
// removal applied there: its box gives nothing (no role commit of it lists the actor for the
// lost-access trigger, so only the box's opening can refuse it)
#[test]
fn a_concurrent_rotation_gives_no_lost_secret_spec_permissions_3() {
    use crate::common::{edge, new_thing};
    let mut lp = crate::common::net(3, 0);
    lp.sync_all().unwrap();
    let x = new_thing(&mut lp, 0);
    let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
    lp.peers[0].engine.grant(&x, &b, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &c, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let held = |lp: &osis_node::local_peer::LocalPeer| lp.peers[1].engine.epochs(&x).is_some_and(|e| e.read.holds_any());
    assert!(held(&lp));
    lp.peers[2].engine.rotate_boxing_only(&[x], &[Role::Read], &[a, b, c]).unwrap().unwrap();
    lp.peers[0].engine.demote(&x, &osis_node::flows::Demotion { holder: b, new: None, retain: None }).unwrap();
    lp.sync(0, 1).unwrap();
    lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(!held(&lp), "the removal dropped x's secrets");
    lp.sync(2, 1).unwrap();
    lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(!held(&lp), "the concurrent rotation's box gives none back");
}
