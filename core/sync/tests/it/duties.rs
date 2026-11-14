//! Engine duties a node runs through sync, end to end: what the spec makes due by a change (a
//! complete pass ending, a role commit applied, a report received) is done by the product's own
//! step, nothing called by hand.

use crate::flows::granted_and_read;
use crate::harness::World;
use osis_base::Role;
use osis_engine::flows::Demotion;

/// Four nodes of one account (node 0 made it, the others paired), settled.
fn four_siblings() -> World {
    crate::harness::fixture("four siblings", || {
        let mut w = World::new(0);
        w.add_node();
        w.pair(0);
        w.pair(0);
        w.pair(0);
        w.run();
        w
    })
}

/// Node `by` removes node `node` from its account's devices actor.
fn remove_node(w: &mut World, by: usize, node: usize) -> Vec<osis_base::CommitId> {
    let n = w.engine(node).tid();
    w.write(by, |e| {
        let d = e.account().unwrap().unwrap().1;
        e.demote(&d, &Demotion { holder: n, new: None, retain: None }).unwrap().commits
    })
}

// spec/permissions.md §3 (a node's removal from D: any node of P holding a removal no counting
// rotation on its line names makes that rotation, deciding at the end of a complete pass of D's
// sync IDs), §5.4, spec/crypto.md §9: nodes 0 and 1 remove nodes 2 and 3 apart, each with its
// rotation; node 1's pair reaches node 0 (handed over: issues/sync-sibling-rotation-unopened.md),
// so node 0 holds a fork whose every line lacks a removal (blocked), and owes a rotation
// superseding both heads: its step makes it at the end of the pass of D the commits made due
#[test]
fn a_rotation_owed_by_the_account_is_made_at_a_pass_end_spec_permissions_3() {
    let mut w = four_siblings();
    w.cap = 6_000;
    w.power_off(2);
    w.power_off(3);
    w.partition(0, 1);
    w.run();
    remove_node(&mut w, 0, 2);
    let d1 = remove_node(&mut w, 1, 3);
    // a pass begun at the same ms as the commits' arrival ends no pass after it
    w.advance(1);
    let pks: Vec<_> = d1.iter().map(|c| w.engine(1).package(c).unwrap().unwrap()).collect();
    w.write(0, |e| {
        for pk in &pks {
            e.ingest_with_lists(&pk.bytes, pk.blobs.clone(), None, &pk.lists).unwrap();
        }
    });
    w.heal();
    w.run();
    let owed = w.write(0, |e| e.signing_due()).unwrap();
    assert!(owed.commits.is_empty(), "the merge rotation was made at the pass end, nothing owed: {owed:?}");
}

// spec/permissions.md §3 (Lost access: a node that learns it lost read access to an actor MUST drop
// those role secrets and every local unit it can no longer read by another path): node 0 removes
// node 1's account from a thing node 1 read; once node 1 holds the removal it holds no read secret
// of the thing and shows none of its content
#[test]
fn a_node_removed_by_another_drops_what_it_lost_spec_permissions_3() {
    let (mut w, t, ak) = granted_and_read(Role::Read);
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: None, retain: None })).unwrap();
    w.run();
    assert!(w.engine(1).epochs(&t).is_none_or(|e| e.read.held().next().is_none()), "node 1 dropped the thing's read secrets");
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), None, "and its content");
}

// spec/permissions.md §3 (Required rotation: whoever may rotate does so before it next encrypts
// under the actor), spec/crypto.md §4 (Encrypting under): node 1 makes thing t (its account A
// the first admin, t shared with node 0's account) and removes its sibling node 2 from A's
// devices actor. The rotations that removal makes due on t are this node's own to write with
// nothing else arriving (also when written with its sync down: its start finds them owed): a later write to t is
// sealed and logged under t's sync IDs.
#[test]
fn an_own_removal_makes_its_rotations_due_with_nothing_arriving_spec_permissions_3() {
    use osis_base::{Ak, Value};
    use osis_engine::Mutation;
    for restart in [false, true] {
        let mut w = crate::harness::siblings();
        let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
        let ak = Ak::new("u:v.0").unwrap();
        let t = w.write(1, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a1);
            m.set(t, &ak, &Value::Str("x".into())).unwrap();
            e.commit(m).unwrap();
            t
        });
        crate::harness::history::file(&mut w, 1, vec![t], Vec::new());
        w.write(1, |e| e.grant(&t, &a0, &crate::flows::edge(Role::Read))).unwrap();
        w.run();
        if restart {
            // written with its sync down, so only a start finds the rotations owed
            w.power_off(1);
            let n2 = w.engine(2).tid();
            let d = w.engine(1).account().unwrap().unwrap().1;
            w.engine(1).demote(&d, &Demotion { holder: n2, new: None, retain: None }).unwrap();
            w.power_on(1);
        } else {
            remove_node(&mut w, 1, 2);
        }
        w.run();
        assert!(w.engine(1).wrap_secret(&t, None).unwrap().is_some(), "restart {restart}: t's epoch open to encrypt under");
        let c = w.write(1, |e| {
            let mut m = Mutation::new();
            m.set(t, &ak, &Value::Str("y".into())).unwrap();
            e.commit(m).unwrap().unwrap()
        });
        w.run();
        let homes: Vec<_> = w.engine(1).sync_bodies(&c).unwrap().keys().copied().collect();
        let blobs = w.engine(1).commit_blobs(&c).unwrap();
        assert!(!homes.is_empty() && homes.iter().all(|s| blobs.iter().any(|b| w.store(1).entry(s, b).ok().flatten().is_some())), "restart {restart}: the write logged under every sync ID of t");
    }
}

/// With `n` things of their own secrets made by node 0: the role duties judged (one per held
/// actor, `Life`'s settles) in a quiet run and in the run after a restart, and the actors held.
fn role_duties_judged(n: usize) -> (u64, u64, u64) {
    let mut w = World::new(0);
    w.add_node();
    w.run();
    let a = w.node(0).account.unwrap();
    for _ in 0..n {
        w.write(0, |e| {
            let mut m = osis_engine::Mutation::new();
            let t = e.new_thing(&mut m, a);
            e.commit(m).unwrap();
            e.give_own_secrets(&t).unwrap();
        });
    }
    w.run();
    let held = w.engine(0).held_actors().len() as u64;
    let judged = || osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "life: role duty owed").map(|(.., n)| n).sum::<u64>();
    judged();
    w.run();
    let quiet = judged();
    w.power_off(0);
    judged();
    w.power_on(0);
    w.run();
    (quiet, judged(), held)
}

// spec/permissions.md §3 (Required rotation), notes/engine-lost-access.md (Owed role commits):
// what a node owes is judged once per held actor at a start (no transaction: `role_duty_due`)
// and not again while nothing it read moves, at n and 10n actors held.
#[test]
fn role_duties_are_judged_once_per_held_actor_at_a_start_spec_permissions_3() {
    for n in [2, 20] {
        let (quiet, start, held) = role_duties_judged(n);
        assert!(held > n as u64, "every thing held, the account too: {held}");
        assert_eq!((quiet, start), (0, held), "n = {n}");
    }
}
