//! Two nodes of one account (siblings, paired by the product's pairing: `World::pair`) and a
//! node of another: what a sibling changes and what it does not.

use crate::harness::history::file;
use crate::harness::{World, siblings, stranger_siblings};
use osis_base::{Ak, Role, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// Node `i`'s synced group (`synced^.0` on its account's D).
fn synced_group(w: &mut World, i: usize) -> Tid {
    let me = w.engine(i).tid();
    let d = w.engine(i).account().unwrap().unwrap().1;
    *w.engine(i).get_typed(&d, &ct::SYNCED).unwrap().unwrap().get(&me).expect("node i's synced group")
}

/// Node `i` lists `t` as a subgroup of its own synced group (`add`) or takes it out.
fn list_own(w: &mut World, i: usize, t: Tid, add: bool) {
    let g = synced_group(w, i);
    w.write(i, |e| {
        let mut x = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        if add {
            x.subgroups.insert(t);
        } else {
            x.subgroups.retain(|y| *y != t);
        }
        let mut m = Mutation::new();
        m.set(g, &ct::GROUP, &x).unwrap();
        e.commit(m).unwrap();
    });
}

/// Node 0 makes a thing with a value, files it in its D and grants account 1 `role` on it.
fn granted(w: &mut World, role: Role) -> (Tid, Ak) {
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(w, 0, vec![t], Vec::new());
    w.write(0, |e| e.grant(&t, &a1, &edge(role))).unwrap();
    w.run();
    (t, ak)
}

/// `granted(Write)`, accepted in account 1's D (every synced group's closure): both siblings
/// read it.
fn both_read() -> (World, Tid, Ak) {
    let mut w = siblings();
    let (t, ak) = granted(&mut w, Role::Write);
    file(&mut w, 1, Vec::new(), vec![t]);
    w.run();
    for i in [1, 2] {
        assert_eq!(w.engine(i).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "node {i} reads it");
    }
    (w, t, ak)
}

// spec/sync-set.md §1 (in the pairing reply): a later node's synced group holds a copy of the
// pairing node's synced group's items and subgroups: node 2's synced group is its own, listed in
// `synced^.0`, holding node 1's items and subgroups and D.
#[test]
fn pairing_gives_the_new_node_a_synced_group_of_its_own_spec_sync_set_1() {
    let mut w = siblings();
    let (g1, g2) = (synced_group(&mut w, 1), synced_group(&mut w, 2));
    assert_ne!(g1, g2);
    let d = w.engine(1).account().unwrap().unwrap().1;
    for i in [1, 2] {
        let (x1, x2) = (w.engine(i).get_typed(&g1, &ct::GROUP).unwrap().unwrap(), w.engine(i).get_typed(&g2, &ct::GROUP).unwrap().unwrap());
        assert!(x2.subgroups.contains(&d) && x1.subgroups.is_subset(&x2.subgroups) && x1.items.is_subset(&x2.items), "node {i}: {x1:?} {x2:?}");
    }
}

// spec/permissions.md §3 (Lost access: a self-remover keeps the secrets until its self-removal is
// held elsewhere, or no peer but its account's nodes shares where it goes): node 0 unsyncs a thing
// both siblings write; node 1 leaves it while node 2, away, still shares it (node 1's record of
// it holds S), and drops its secrets at once. (A sibling holding the removal never counts as held
// elsewhere: status::self_removal_not_held_at_own_nodes.)
#[test]
fn a_self_removal_shared_only_with_a_sibling_drops_at_once_spec_perm_3() {
    let (mut w, t, _) = both_read();
    let a1 = w.node(1).account.unwrap();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    w.write(0, |e| {
        let d = e.account().unwrap().unwrap().1;
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        g.items.retain(|x| *x != t);
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(w.store(0).synced(&s).is_none(), "node 0 stopped syncing it");
    assert!(w.store(2).synced(&s).is_some(), "node 2 shares it");
    w.partition(1, 2);
    w.run();
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.run();
    assert!(!w.engine(1).waiting_removals().unwrap().contains(&c), "only a sibling shares it: done");
    assert!(w.engine(1).epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "dropped");
}

// spec/sync-inbox.md §2 (Taking: a boxes payload, for each thing it boxes the recipient on that
// is in a synced group's closure, a sibling node that accepted it listing the thing there, that
// thing's boxes alone): a stranger grants account 1 sync on a thing; neither sibling takes it
// (an invite request) until node 1's user accepts it in node 1's synced group; then node 2, whose
// own synced group does not list it, takes its boxes too.
#[test]
fn a_siblings_accept_makes_the_other_take_a_boxes_payload_spec_sync_inbox_2() {
    let mut w = stranger_siblings();
    let (t, _) = granted(&mut w, Role::Sync);
    for i in [1, 2] {
        let inv = w.engine(i).invitations().unwrap();
        assert!(inv.iter().any(|x| x.thing == t && !x.taken), "node {i}: an invite request: {inv:?}");
        assert!(w.engine(i).sync_record(&t).unwrap().is_none(), "node {i} took nothing");
    }
    list_own(&mut w, 1, t, true);
    w.run();
    assert!(w.engine(1).sync_record(&t).unwrap().is_some(), "node 1 took it");
    let g2 = synced_group(&mut w, 2);
    assert!(!w.engine(2).get_typed(&g2, &ct::GROUP).unwrap().unwrap().subgroups.contains(&t), "node 2's own group lists it not");
    assert!(w.engine(2).sync_record(&t).unwrap().is_some(), "node 2 took it by node 1's accept");
}

// spec/sync-set.md §3 (Unsyncing: whoever holds it elsewhere): each sibling lists a thing in its
// own synced group; node 1 takes it out of its own, stops syncing it and forgets its copy, while
// node 2 keeps it and reads a later write.
#[test]
fn unsyncing_on_one_sibling_leaves_the_other_its_copy_spec_sync_set_3() {
    let mut w = siblings();
    let (t, ak) = granted(&mut w, Role::Read);
    list_own(&mut w, 1, t, true);
    list_own(&mut w, 2, t, true);
    w.run();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    for i in [1, 2] {
        assert_eq!(w.engine(i).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "node {i} reads it");
    }
    list_own(&mut w, 1, t, false);
    w.run();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "node 1 forgot it");
    assert!(w.store(1).synced(&s).is_none() && !w.store(1).held_ids().unwrap().contains(&s), "node 1 stopped and shredded");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("y".into())), "node 2 keeps it");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "node 1 still not");
}
