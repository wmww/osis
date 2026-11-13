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

/// x made by node 0, node 2 its admin, node 1 reading it; then node 1 removed (its trigger
/// run) when `removed`. Node 0 then grants node 1 read (`g`); node 2, having seen the grant,
/// rotates x boxing every holder (`r`), and writes `w` under the new epoch: none reach node 1.
struct Granted {
    lp: osis_node::local_peer::LocalPeer,
    x: Tid,
    g: Vec<osis_base::CommitId>,
    r: osis_base::CommitId,
    w: osis_base::CommitId,
}

fn granted_then_rotated(removed: bool) -> Granted {
    use crate::common::{edge, new_thing};
    let mut lp = crate::common::net(3, 0);
    lp.sync_all().unwrap();
    let x = new_thing(&mut lp, 0);
    let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
    lp.peers[0].engine.grant(&x, &c, &edge(Role::Admin)).unwrap();
    if removed {
        lp.peers[0].engine.grant(&x, &b, &edge(Role::Read)).unwrap();
    }
    lp.sync_all().unwrap();
    if removed {
        lp.peers[0].engine.demote(&x, &osis_node::flows::Demotion { holder: b, new: None, retain: None }).unwrap();
        lp.sync_all().unwrap();
        lp.peers[1].engine.drop_lost_due().unwrap();
        assert!(lp.peers[1].engine.read_secrets(&x).is_empty(), "the removal dropped x's secrets");
    }
    let g = lp.peers[0].engine.grant(&x, &b, &edge(Role::Read)).unwrap().commits;
    lp.sync(0, 2).unwrap();
    let r = lp.peers[2].engine.rotate_boxing_only(&[x], &[Role::Read], &[a, b, c]).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(x, &crate::common::REG, &s("after")).unwrap();
    let w = lp.peers[2].engine.commit(m).unwrap().unwrap();
    Granted { lp, x, g, r, w }
}

/// Node 1 holds node 2's newest read epoch of x and reads its write under it.
fn reads_newest(gr: &mut Granted) {
    let newest = gr.lp.peers[2].engine.epochs(&gr.x).unwrap().read.newest_held().unwrap().0;
    let at1 = gr.lp.peers[1].engine.epochs(&gr.x).unwrap();
    assert!(at1.read.secret(&newest).is_some(), "the rotation's epoch reached the grantee");
    assert_eq!(gr.lp.peers[1].engine.get(&gr.x, &crate::common::ak("t:reg.0")).unwrap(), Some(s("after")));
}

// A grant (first or after a removal) and a rotation boxing the grantee, in either order: the
// grantee takes the rotation's box (a box applied before its grant is opened once the grant
// applies, never lost)
#[test]
fn a_grant_and_a_rotation_in_either_order_give_the_newest_epoch_spec_permissions_3() {
    for removed in [false, true] {
        for grant_first in [true, false] {
            let mut gr = granted_then_rotated(removed);
            let (g, rw) = (gr.g.clone(), [gr.r, gr.w]);
            if grant_first {
                crate::flows::send(&mut gr.lp, 0, 1, &g);
                crate::flows::send(&mut gr.lp, 2, 1, &rw);
            } else {
                crate::flows::send(&mut gr.lp, 2, 1, &rw);
                crate::flows::send(&mut gr.lp, 0, 1, &g);
            }
            gr.lp.peers[1].engine.drop_lost_due().unwrap();
            reads_newest(&mut gr);
        }
    }
}

// A box kept out for want of a role, then a restart, then the grant: the open lists it again
// (`take_account`'s `reopen_all`)
#[test]
fn a_box_kept_out_across_a_restart_opens_once_the_grant_applies_spec_permissions_3() {
    let mut gr = granted_then_rotated(true);
    let (g, rw) = (gr.g.clone(), [gr.r, gr.w]);
    crate::flows::send(&mut gr.lp, 2, 1, &rw);
    gr.lp.peers[1].restart(7).unwrap();
    crate::flows::send(&mut gr.lp, 0, 1, &g);
    gr.lp.peers[1].engine.drop_lost_due().unwrap();
    reads_newest(&mut gr);
}

// What a role-changing apply costs `flows::retake` is one judgment per listed actor's role,
// whatever else the node holds: 30 things of its own and other accounts' actors it cannot read
// (epochs observed without a secret list nothing), one actor listed (x)
#[test]
fn retake_judges_only_listed_actors_spec_permissions_3() {
    let mut gr = granted_then_rotated(true);
    for _ in 0..30 {
        crate::common::new_thing(&mut gr.lp, 1);
    }
    let (g, rw) = (gr.g.clone(), [gr.r, gr.w]);
    crate::flows::send(&mut gr.lp, 2, 1, &rw);
    osis_node::costs::take();
    crate::flows::send(&mut gr.lp, 0, 1, &g);
    let c = osis_node::costs::take();
    let n = |k: &str| c.iter().find(|x| x.0 == k).map_or(0, |x| x.2);
    assert!(n("retake: calls") > 0);
    assert!(n("retake: judged") <= n("retake: calls"), "{c:?}");
    gr.lp.peers[1].engine.drop_lost_due().unwrap();
    reads_newest(&mut gr);
}

// After a removal, an entry box of x's current epoch (a link's label, spec/sync.md §2) is taken
// once the re-grant applied; one opened before the re-grant applies is refused, and the re-grant
// gives that secret anyway
#[test]
fn an_entry_box_around_a_re_grant_spec_permissions_3() {
    for grant_first in [true, false] {
        let mut gr = granted_then_rotated(true);
        let g = gr.g.clone();
        let (e, sec) = {
            let ep = gr.lp.peers[0].engine.epochs(&gr.x).unwrap();
            let (e, s) = ep.read.newest_held().unwrap();
            (e, s.clone())
        };
        if grant_first {
            crate::flows::send(&mut gr.lp, 0, 1, &g);
            gr.lp.peers[1].engine.learn_secret(&gr.x, Role::Read, e, sec).unwrap();
        } else {
            assert!(!gr.lp.peers[1].engine.learn_secret(&gr.x, Role::Read, e, sec).unwrap(), "lost: refused");
            crate::flows::send(&mut gr.lp, 0, 1, &g);
        }
        gr.lp.peers[1].engine.drop_lost_due().unwrap();
        assert!(gr.lp.peers[1].engine.epochs(&gr.x).unwrap().read.secret(&e).is_some(), "the re-granted epoch is held");
    }
}

/// Node `x`'s account joins by `link`: follows K's label by the link key, redeems, drops the key.
fn join(net: &mut Net, x: usize, px: Tid, link: &osis_label::ShareLink) {
    let held = net.engine(x).hold_key_actor(link.seed.clone()).unwrap();
    let acts = net.sync(x).follow(held, link.k, link.k_label, link.hosts.clone());
    net.actions(x, acts);
    net.run();
    let done = net.engine(x).redeem(link, &px, false).unwrap();
    net.engine(x).drop_key_actor(&held);
    carry(net, x, done);
    net.run();
}

// A member removed after joining by a link joins again by a new link (spec/permissions.md §7):
// the ended edge it holds refuses no box of the re-grant, entry box or grant, and it reads again
#[test]
fn a_removed_member_rejoins_by_a_new_link_spec_permissions_3() {
    let mut net = Net::bare();
    let host = net.add_host();
    let home = vec![net.address(host)];
    let (a, b) = (net.node(40, &[host]), net.node(41, &[host]));
    let account = |net: &mut Net, n: usize| {
        let (p, done) = net.engine(n).create_account(&home).unwrap();
        carry(net, n, done);
        p.account
    };
    let (pa, pb) = (account(&mut net, a), account(&mut net, b));
    net.run();
    let e = net.engine(a);
    let mut m = Mutation::new();
    let c = e.new_thing(&mut m, pa);
    m.set(c, &crate::common::REG, &s("hi")).unwrap();
    e.commit(m).unwrap();
    let done = net.engine(a).give_own_secrets_on(&c, &home).unwrap();
    carry(&mut net, a, done);
    net.run();
    let spec = osis_node::flows::LinkSpec { target: c, role: Role::Read, until: None, hosts: home.clone(), peers: Vec::new(), single_use: false };
    let (link, _, done) = net.engine(a).create_link(&pa, &spec).unwrap();
    carry(&mut net, a, done);
    net.run();
    join(&mut net, b, pb, &link);
    assert_eq!(net.read(b, c), Some(s("hi")));
    let done = net.engine(a).demote(&link.k, &osis_node::flows::Demotion { holder: pb, new: None, retain: None }).unwrap();
    carry(&mut net, a, done);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(net.engine(b).read_secrets(&c).is_empty(), "removed: c's secrets dropped");
    let (link2, _, done) = net.engine(a).create_link(&pa, &spec).unwrap();
    carry(&mut net, a, done);
    net.run();
    join(&mut net, b, pb, &link2);
    for _ in 0..3 {
        net.advance(31_000);
    }
    net.write(a, c, "again");
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert_eq!(net.read(b, c), Some(s("again")), "the rejoined member reads c");
}

// A role-class part in a copy on a thing the group cannot read (here an account's `account.0`,
// as a relay may place any commit whole) is no stale content and is taken: each such part is
// judged as it is used (`Engine::copy_stale`), and one left out would strand its slot
#[test]
fn a_copys_role_class_parts_are_never_stale_spec_permissions_3() {
    let mut lp = crate::common::net(2, 0);
    lp.peers[0].engine.create_account(&[]).unwrap();
    lp.sync_all().unwrap();
    let g = crate::common::new_thing(&mut lp, 1);
    let mut accounts = 0;
    for c in lp.peers[0].engine.commit_ids() {
        let Some(body) = lp.peers[0].engine.body(&c).unwrap() else { continue };
        let blob = osis_commit::CommitBlob::decode(&body.plaintext).unwrap();
        let stale = lp.peers[1].engine.copy_stale(&g, &blob);
        for p in &blob.parts {
            let ak = blob.header.aspects[p.ai].ak.as_str();
            if osis_schema::core_types::is_role_class(ak) {
                accounts += usize::from(ak == "account.0");
                assert!(!stale.contains(&p.ai), "{ak} is no stale content");
            }
        }
    }
    assert!(accounts > 0);
}
