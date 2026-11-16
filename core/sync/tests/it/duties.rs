//! Engine duties a node runs through sync, end to end: what the spec makes due by a change (a
//! complete pass ending, a role commit applied, a report received) is done by the product's own
//! step, nothing called by hand.

use crate::harness::World;
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

// spec/permissions.md §3 (Required rotation: a node's removal from D: any node of P holding a
// removal no counting rotation on its line names makes that rotation, at the end of a complete
// pass of D's sync IDs), §5.4, spec/crypto.md §4 (Established and current), §5 (Who wraps under
// what: an account's rotation and its list blobs under the pre-removal D epoch), §9,
// spec/sync-streams.md §4 (Fill order: an entry with a section not opened while a part of its
// commit counts missing opens again as read secrets gain an epoch): nodes 0 and 1 remove nodes 2
// and 3 apart, each with its rotations, and sync alone carries them across the heal: each node
// then holds the other's removal (the other's removed node holds nothing on D there) and every D
// epoch the other holds, and owes no merge rotation: its step made it at the end of the pass of D
// the commits made due (that pass waits for nodes 2 and 3's records until its deadline)
#[test]
fn sibling_removals_apart_both_hold_through_sync_spec_permissions_3() {
    let mut w = four_siblings();
    w.cap = 6_000;
    w.power_off(2);
    w.power_off(3);
    w.partition(0, 1);
    w.run();
    remove_node(&mut w, 0, 2);
    remove_node(&mut w, 1, 3);
    w.heal();
    w.run();
    w.advance(osis_proto::limits::PASS_WAIT_MS + 1);
    w.run();
    let d = w.engine(0).account().unwrap().unwrap().1;
    let gone: Vec<_> = [2, 3].map(|i| w.engine(i).tid()).into();
    for (i, j) in [(0, 1), (1, 0)] {
        let roster = w.engine(i).roster(&d);
        assert!(gone.iter().all(|n| !roster.contains_key(n)), "node {i}: neither removed node holds D: {roster:?}");
        let held: Vec<_> = w.engine(i).epochs(&d).unwrap().read.held().map(|(_, s)| s.clone()).collect();
        let newest: Vec<_> = w.engine(j).epochs(&d).unwrap().read.held().map(|(_, s)| s.clone()).collect();
        assert!(newest.iter().all(|s| held.contains(s)), "node {i}: holds every D epoch node {j} holds, its removal's included");
        let owed = w.write(i, |e| e.signing_due()).unwrap();
        assert!(owed.commits.is_empty(), "node {i}: the merge rotation made, nothing owed: {owed:?}");
    }
}
