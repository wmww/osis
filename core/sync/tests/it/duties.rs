//! Engine duties a node runs through sync, end to end: what the spec makes due by a change (a
//! complete pass ending, a role commit applied, a report received) is done by the product's own
//! step, nothing called by hand.

use crate::harness::World;

/// Node 0 makes `n` more things of their own secrets; run.
fn things(w: &mut World, n: usize) {
    let a = w.node(0).account.unwrap();
    for _ in 0..n {
        w.write(0, |e| {
            let mut m = osis_engine::Mutation::new();
            let t = e.new_thing(&mut m, a);
            e.commit(m).unwrap();
            e.make_independent(&t).unwrap();
        });
    }
    w.run();
}

/// The role duties node 0 judges (one per held actor, `Life`'s settles) in a quiet run and in the
/// run after a restart, and the actors it holds.
fn role_duties_judged(mut w: World) -> (u64, u64, u64) {
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
    let mut w = World::new(0);
    w.add_node();
    w.run();
    // 2 things, then 18 more on the same world
    for (n, more) in [(2, 2), (20, 18)] {
        things(&mut w, more);
        let (quiet, start, held) = role_duties_judged(w.copy());
        assert!(held > n as u64, "every thing held, the account too: {held}");
        assert_eq!((quiet, start), (0, held), "n = {n}");
    }
}
