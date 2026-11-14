//! A thing getting secrets of its own changes in no way who reaches it
//! (spec/permissions.md §3, Own secrets add only).

use crate::flows::{edge_of, people, sealed_write, spread, thing_of};
use osis_base::{Role, SyncId, Tid};
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::{Holding, ThingSync};
use osis_engine::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn add_item(lp: &mut LocalPeer, i: usize, g: Tid, t: Tid) {
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap();
}

fn devices(lp: &mut LocalPeer, i: usize) -> Tid {
    lp.peers[i].engine.account().unwrap().unwrap().1
}

/// Peer `from` grants `role` on `a` to `to`'s account; `to` takes its inbox blobs, and accepts a
/// sync grant (spec/sync.md §3: kept only by an accept).
fn grant(lp: &mut LocalPeer, ps: &[Tid], from: usize, a: Tid, to: usize, role: Role) {
    let done = lp.peers[from].engine.grant(&a, &ps[to], &edge_of(role)).unwrap();
    for (h, b) in lp.inbox_blobs(from, &done).unwrap() {
        if h == ps[to] {
            lp.peers[to].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    if role == Role::Sync {
        crate::facade::accept(lp, to, a);
    }
}

/// What node `i` syncs: each sync ID of its sync set with the things it carries, as reader `judge`
/// judges them (a node keeping S unread judges nothing; what it keeps is what S's readers log).
fn synced(lp: &mut LocalPeer, i: usize, judge: usize) -> BTreeSet<(SyncId, Tid)> {
    let set = lp.peers[i].engine.sync_set().unwrap();
    let mut out = BTreeSet::new();
    for (s, (owner, _)) in set.ids.iter() {
        let e = &mut lp.peers[judge].engine;
        for t in e.closure(owner).iter() {
            if e.reads_in(owner, t) {
                out.insert((*s, *t));
            }
        }
    }
    out
}

/// No node syncs less than `before` (per node, `synced`).
fn kept(lp: &mut LocalPeer, before: &[BTreeSet<(SyncId, Tid)>]) {
    for (i, b) in before.iter().enumerate() {
        let after = synced(lp, i, 0);
        let lost: Vec<_> = b.difference(&after).collect();
        assert!(lost.is_empty(), "peer {i} lost {lost:?}");
    }
}

/// G: a group with secrets of its own, peer 0 its admin; T: a plain thing whose first admin is G,
/// an item of G. Peer 1 reads G, peer 2 holds sync on G; peers 0..=3 list G in their synced
/// closure (peer 3 is granted later).
fn setup() -> (LocalPeer, Vec<Tid>, Tid, Tid) {
    let (mut lp, ps) = people(6);
    let g = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&g).unwrap();
    let t = thing_of(&mut lp, 0, g);
    add_item(&mut lp, 0, g, t);
    for i in 0..4 {
        let d = devices(&mut lp, i);
        add_item(&mut lp, i, d, g);
    }
    grant(&mut lp, &ps, 0, g, 1, Role::Read);
    grant(&mut lp, &ps, 0, g, 2, Role::Sync);
    spread(&mut lp);
    (lp, ps, g, t)
}

// spec/permissions.md §3 (Own secrets add only): a plain thing T derived from group G gets secrets
// of its own; G keeps its role on T (the record edge), so G's sync ID keeps carrying T at every
// node: G's reader reads T's new content, G's sync-only holder keeps G's sync ID, and a reader
// of G added later reads T.
#[test]
fn own_secrets_change_no_sync_set_but_to_add_spec_permissions_3() {
    let (mut lp, ps, g, t) = setup();
    let sg = lp.peers[0].engine.home_sync_id(&g).unwrap().unwrap();
    let before: Vec<_> = (0..3).map(|i| synced(&mut lp, i, 0)).collect();
    assert!(before[1].contains(&(sg, t)) && before[2].contains(&(sg, t)), "T rides under G's sync ID before");
    assert_eq!(lp.peers[2].engine.sync_set().unwrap().ids.get(&sg), Some(&(g, Holding::Unread)));
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    spread(&mut lp);
    kept(&mut lp, &before);
    assert!(matches!(lp.peers[1].engine.thing_sync(&t).unwrap(), ThingSync::Read(_)), "G's reader syncs T's own sync ID too");
    let readers = sealed_write(&mut lp, 0, t, "after");
    assert!(readers.contains(&1), "G's reader reads T's new content");
    // a reader of G added later
    grant(&mut lp, &ps, 0, g, 3, Role::Read);
    spread(&mut lp);
    let readers = sealed_write(&mut lp, 0, t, "later");
    assert!(readers.contains(&3), "a reader of G added later reads T");
}

// spec/permissions.md §3 (Own secrets add only): the admin giving T secrets of its own does not
// sync G (peer 4: admin of G by grant, G in no synced group of its account) and holds G's keyset
// from before a rotation of G (peer 5's removal). Its rotation goes to G's inbox like any holder's
// that held no box before it, so G's readers and sync-only holder learn T's secrets and keep T
// under G's sync ID; G's box at the superseded keyset is stale where G's newer keyset is held, and
// G's admin re-keys T before it next writes there, so peer 5 (removed from G) reads nothing new.
#[test]
fn own_secrets_by_an_admin_not_syncing_the_base_reach_its_holders_spec_permissions_3() {
    let (mut lp, ps, g, t) = setup();
    grant(&mut lp, &ps, 0, g, 4, Role::Admin);
    grant(&mut lp, &ps, 0, g, 5, Role::Read);
    // peer 4 holds G and T as they stand now, then nothing more of G
    let ids: Vec<_> = lp.peers[0].engine.commit_ids();
    crate::flows::send(&mut lp, 0, 4, &ids);
    lp.peers[0].engine.demote(&g, &Demotion { holder: ps[5], new: None, retain: None }).unwrap();
    let held: Vec<_> = lp.peers[0].engine.commit_ids();
    for i in 1..4 {
        crate::flows::send(&mut lp, 0, i, &held);
    }
    let before: Vec<_> = (0..4).map(|i| synced(&mut lp, i, 0)).collect();
    lp.peers[4].engine.give_own_secrets(&t).unwrap();
    lp.carry_deliveries(4).unwrap();
    kept(&mut lp, &before);
    for i in [0, 1] {
        assert!(matches!(lp.peers[i].engine.thing_sync(&t).unwrap(), ThingSync::Read(_)), "peer {i} learns T's secrets through G");
    }
    // the window: peer 5, which has not heard of its removal, opens G's box at the keyset peer 4
    // knew, and so T's first own epoch (spec/crypto.md §4, Holder actors, the stated limit)
    assert!(matches!(lp.peers[5].engine.thing_sync(&t).unwrap(), ThingSync::Read(_)), "peer 5 opens the box at G's superseded keyset");
    let readers = sealed_write(&mut lp, 0, t, "after");
    assert!(readers.contains(&1) && !readers.contains(&5), "G's reader reads T's new content, the party removed from G does not: {readers:?}");
}

/// Peer `i`'s view of thing `x`: whether it syncs it under G's sync ID, and how it syncs `x` itself.
fn view(lp: &mut LocalPeer, i: usize, sg: SyncId, x: Tid) -> (bool, bool) {
    let under_g = synced(lp, i, 0).contains(&(sg, x));
    let own = !matches!(lp.peers[i].engine.thing_sync(&x).unwrap(), ThingSync::Plain | ThingSync::Unsyncable);
    (under_g, own)
}

// spec/permissions.md §3 (Own secrets add only): a thing made under G and given secrets of its own
// reaches exactly whom a thing made under another admin and handed to G (G granted admin, the
// first admin leaving) reaches: the first admin is an ordinary holder.
#[test]
fn made_under_g_or_handed_to_g_reach_alike_spec_permissions_3() {
    let (mut lp, ps, g, t1) = setup();
    let sg = lp.peers[0].engine.home_sync_id(&g).unwrap().unwrap();
    lp.peers[0].engine.give_own_secrets(&t1).unwrap();
    let t2 = thing_of(&mut lp, 0, ps[0]);
    add_item(&mut lp, 0, g, t2);
    lp.peers[0].engine.grant(&t2, &g, &edge_of(Role::Admin)).unwrap();
    lp.peers[0].engine.demote(&t2, &Demotion { holder: ps[0], new: None, retain: None }).unwrap();
    grant(&mut lp, &ps, 0, g, 3, Role::Read);
    spread(&mut lp);
    for i in 0..4 {
        assert_eq!(view(&mut lp, i, sg, t1), view(&mut lp, i, sg, t2), "peer {i}");
    }
    let r1 = sealed_write(&mut lp, 0, t1, "a");
    let r2 = sealed_write(&mut lp, 0, t2, "a");
    assert_eq!(r1, r2);
    assert!(r1.contains(&1) && r1.contains(&3), "G's readers: {r1:?}");
}

// spec/sync-set.md §2 (key home), spec/permissions.md §3 (Own secrets add only): X, made under G
// and listed nowhere, and C, made under X, go under G's sync ID to G's reader and to its
// sync-only holder (kept unread: what G's readers log there). X given secrets of its own stays
// there (its key home is still G); C moves to X's own sync ID, which a node syncs once G is
// walked in its synced closure (a subgroup), not while G is reached only as an item.
#[test]
fn dependants_go_under_their_key_home_spec_sync_set_2() {
    let (mut lp, _, g, _) = setup();
    let sg = lp.peers[0].engine.home_sync_id(&g).unwrap().unwrap();
    let x = thing_of(&mut lp, 0, g);
    let c = thing_of(&mut lp, 0, x);
    spread(&mut lp);
    for i in [1, 2] {
        let s = synced(&mut lp, i, 0);
        assert!(s.contains(&(sg, x)) && s.contains(&(sg, c)), "peer {i}: X and C under G's sync ID");
    }
    lp.peers[0].engine.give_own_secrets(&x).unwrap();
    lp.carry_deliveries(0).unwrap();
    spread(&mut lp);
    let sx = lp.peers[0].engine.home_sync_id(&x).unwrap().unwrap();
    let s = synced(&mut lp, 1, 0);
    assert!(s.contains(&(sg, x)) && !s.contains(&(sg, c)), "X stays under G's sync ID, C leaves it");
    assert!(!lp.peers[1].engine.sync_set().unwrap().ids.contains_key(&sx), "G an item: X's own sync ID is not walked");
    crate::facade::accept(&mut lp, 1, g);
    assert_eq!(lp.peers[1].engine.sync_set().unwrap().ids.get(&sx), Some(&(x, Holding::Read)), "G a subgroup: X's own sync ID synced");
    assert!(synced(&mut lp, 1, 0).contains(&(sx, c)), "C under X's sync ID");
}

// spec/sync-set.md §2 Cost: a thing given secrets of its own moves the key homes of the things
// below it alone, whatever its key home holds besides (n and 10n dependants of G).
#[test]
fn a_key_home_moves_with_its_subtree_alone_spec_sync_set_2() {
    fn cost(n: usize) -> (u64, u64) {
        let (mut lp, ps) = people(1);
        let g = thing_of(&mut lp, 0, ps[0]);
        let e = &mut lp.peers[0].engine;
        e.give_own_secrets(&g).unwrap();
        let mut m = Mutation::new();
        for _ in 0..n {
            e.new_thing(&mut m, g);
        }
        e.commit(m).unwrap().unwrap();
        let x = thing_of(&mut lp, 0, g);
        let c = thing_of(&mut lp, 0, x);
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.closure(&g).len(), n + 3);
        osis_base::costs::take();
        e.give_own_secrets(&x).unwrap();
        let k = osis_base::costs::take();
        assert!(e.closure(&x).contains(&c) && !e.closure(&g).contains(&c) && e.closure(&g).contains(&x));
        let count = |name: &str| k.iter().find(|r| r.0 == name).map_or(0, |r| r.2);
        (count("group index: rehome"), count("group index"))
    }
    let small = cost(20);
    assert_eq!(small, cost(200));
    assert_eq!(small.0, 2, "X and C rehomed");
}
