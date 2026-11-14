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
