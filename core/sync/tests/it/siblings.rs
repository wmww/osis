//! Two nodes of one account (siblings, paired by the product's pairing: `World::pair`) and a
//! node of another: what a sibling changes and what it does not.

use crate::harness::history::file;
use crate::harness::{World, fixture_with, siblings, stranger_siblings};
use osis_base::{Ak, Role, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
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

/// `siblings` with `granted(Write)` listed in each sibling's own synced group: both read it.
/// Built once (`fixture_with`).
fn listed() -> (World, Tid, Ak) {
    let (w, (t, ak)) = fixture_with("siblings listed", || {
        let mut w = siblings();
        let (t, ak) = granted(&mut w, Role::Write);
        list_own(&mut w, 1, t, true);
        list_own(&mut w, 2, t, true);
        w.run();
        for i in [1, 2] {
            assert_eq!(w.engine(i).get(&t, &ak).unwrap(), Some(Value::Str("x".into())), "node {i} reads it");
        }
        (w, (t, ak))
    });
    (w, t, ak)
}

// spec/permissions.md §3 (Lost access: a self-remover keeps the secrets until its self-removal is
// held elsewhere, or no peer but its account's nodes shares where it goes): node 0 unsyncs a thing
// both siblings list in their own synced groups and write; node 1 leaves it while node 2, away, still shares it (node 1's record of
// it holds S), and drops its secrets at once. (A sibling holding the removal never counts as held
// elsewhere: status::self_removal_not_held_at_own_nodes.)
#[test]
fn a_self_removal_shared_only_with_a_sibling_drops_at_once_spec_perm_3() {
    let (mut w, t, _) = listed();
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
    w.flush();
    assert!(w.store(0).synced(&s).is_none(), "node 0 stopped syncing it");
    assert!(w.store(2).synced(&s).is_some(), "node 2 shares it");
    // node 1 told its connection to node 2 closed before it writes (else the removal reaches node
    // 2 and is held elsewhere: the test proves nothing)
    w.partition(1, 2);
    w.flush();
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.flush();
    assert!(!w.engine(1).waiting_removals().unwrap().contains(&c), "only a sibling shares it: done");
    assert!(w.engine(1).epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "dropped");
}

// spec/sync-inbox.md §2 (Taking: its sender is connected, a taken boxes payload gives its sync IDs):
// the stranger redeemed account 1's contact card, so it
// holds read on the profile both siblings sync and is connected at each: a grant of sync to
// account 1 is no invite request at either node, and node 2 takes it with its own synced group
// not listing the thing. (An accept on one sibling taking at the other:
// `flows::a_sync_grant_accepted_on_one_node_is_taken_at_its_sibling_spec_sync_inbox_2`.)
#[test]
fn a_contacts_boxes_payload_is_taken_at_both_siblings_spec_sync_inbox_2() {
    let mut w = stranger_siblings();
    let (t, _) = granted(&mut w, Role::Sync);
    for i in [1, 2] {
        let inv = w.engine(i).invitations().unwrap();
        assert!(!inv.iter().any(|x| x.thing == t && !x.taken), "node {i}: no invite request: {inv:?}");
        assert!(w.engine(i).sync_record(&t).unwrap().is_some(), "node {i} took it");
    }
    let g2 = synced_group(&mut w, 2);
    assert!(!w.engine(2).get_typed(&g2, &ct::GROUP).unwrap().unwrap().subgroups.contains(&t), "node 2's own group lists it not");
}

// spec/sync-set.md §3 (Unsyncing: whoever holds it elsewhere): each sibling lists a thing in its
// own synced group; node 1 takes it out of its own, stops syncing it and forgets its copy, while
// node 2 keeps it and reads a later write.
#[test]
fn unsyncing_on_one_sibling_leaves_the_other_its_copy_spec_sync_set_3() {
    let (mut w, t, ak) = listed();
    let s = w.engine(1).sync_ids(&t).unwrap()[0].id;
    list_own(&mut w, 1, t, false);
    w.flush();
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "node 1 forgot it");
    assert!(w.store(1).synced(&s).is_none() && !w.store(1).held_ids().unwrap().contains(&s), "node 1 stopped and shredded");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("y".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.flush();
    assert_eq!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("y".into())), "node 2 keeps it");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "node 1 still not");
}

// spec/permissions.md §3 (Lost access: whichever node of the account made it), spec/sync-status.md
// §2: node 1 leaves a thing both siblings read while node 0, which shares it, is away; node 2
// applies the removal from node 1 and waits as node 1 does (node 0's record holds S: a peer away),
// through a restart, then drops its secrets and stops syncing S once node 0 holds the removal,
// so node 0's later write never reaches it.
#[test]
fn a_siblings_self_removal_waits_and_drops_at_both_siblings_spec_perm_3() {
    let (mut w, t, ak) = listed();
    let a1 = w.node(1).account.unwrap();
    let s = w.engine(2).sync_ids(&t).unwrap()[0].id;
    w.partition(0, 1);
    w.partition(0, 2);
    w.flush();
    let c = w.write(1, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.flush();
    assert!(w.engine(2).commit_ids().contains(&c), "node 2 holds the removal");
    w.power_off(2);
    w.power_on(2);
    w.run();
    for i in [1, 2] {
        assert!(w.engine(i).waiting_removals().unwrap().contains(&c), "node {i} waits: node 0 shares S, away");
        assert!(w.engine(i).epochs(&t).is_some_and(|x| x.read.holds_any()), "node {i} keeps its secrets while it waits");
    }
    w.heal();
    w.run();
    for i in [1, 2] {
        assert!(!w.engine(i).waiting_removals().unwrap().contains(&c), "node {i}: node 0 holds it");
        assert!(w.engine(i).epochs(&t).is_none_or(|x| x.read.held().next().is_none()), "node {i} dropped");
        assert!(w.store(i).synced(&s).is_none(), "node {i} stopped syncing S");
    }
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Str("after".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_ne!(w.engine(2).get(&t, &ak).unwrap(), Some(Value::Str("after".into())), "node 2 reads nothing after");
}
