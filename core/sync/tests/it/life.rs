//! Lifecycle duties the engine judges and sync drives (notes/sync-driver.md, Duties).

use crate::harness::history::file;
use crate::harness::lies::Lie;
use crate::harness::{World, fixture_with, siblings};
use osis_base::{Ak, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn v() -> Ak {
    Ak::new("u:v.0").unwrap()
}

/// `siblings` with node 1 having filed in D a root R whose value references X, and X retained
/// by R (`retainers^.0` {R}), both read at node 2: (world, R, X). Built once.
fn retained() -> (World, Tid, Tid) {
    let (w, (r, x)) = fixture_with("life retained", || {
        let mut w = siblings();
        let a1 = w.node(1).account.unwrap();
        let (r, x) = w.write(1, |e| {
            let mut m = Mutation::new();
            let r = e.new_thing(&mut m, a1);
            let x = e.new_thing(&mut m, a1);
            m.set(r, &v(), &Value::Tid(x)).unwrap();
            m.set(x, &v(), &Value::Str("x".into())).unwrap();
            m.set(x, &ct::RETAINERS, &BTreeSet::from([r])).unwrap();
            e.commit(m).unwrap();
            (r, x)
        });
        file(&mut w, 1, vec![r, x], Vec::new());
        w.run();
        assert_eq!(w.engine(2).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "node 2 reads X");
        (w, (r, x))
    });
    (w, r, x)
}

/// Node `i` drops R's reference to X.
fn unreference(w: &mut World, i: usize, r: Tid) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(r, &v(), &Value::Str("none".into())).unwrap();
        e.commit(m).unwrap();
    });
}

// spec/commits.md §5 (Lifetimes: judged once a source of each sync ID is connected and read to its
// end, nothing released under one while a peer sharing it is away): X,
// under D's sync ID, is unreachable once R stops referencing it; cut off from its sibling node 1
// keeps it, and releases it once D is heard out again, which node 2 then holds. Node 2 shows none
// of its own new entries meanwhile (`Lie::Withhold`), so the release is node 1's judgment of the
// thing it held, not node 2's of the write reaching it.
#[test]
fn an_unreachable_thing_is_released_once_heard_out_spec_commits_5() {
    let (mut w, r, x) = retained();
    w.partition(1, 2);
    w.partition(0, 1);
    unreference(&mut w, 1, r);
    w.flush();
    assert_eq!(w.engine(1).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "released offline");
    w.lie(2, Some(Lie::Withhold));
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&x, &v()).unwrap(), None, "not released once heard out");
    assert_eq!(w.engine(2).get(&x, &v()).unwrap(), None, "the release did not reach node 2");
}

// spec/commits.md §5 (Lifetimes: a sync ID no peer shares with it needs no source): a single-device
// account, no peer sharing D's sync ID, releases X as soon as R stops referencing it. (A peer
// that shares it but is away is waited on: `an_unreachable_thing_is_released_once_heard_out`.)
#[test]
fn a_node_alone_releases_at_once_spec_commits_5() {
    let mut w = World::new(0);
    w.add_node();
    w.run();
    let a = w.node(0).account.unwrap();
    let (r, x) = w.write(0, |e| {
        let mut m = Mutation::new();
        let r = e.new_thing(&mut m, a);
        let x = e.new_thing(&mut m, a);
        m.set(r, &v(), &Value::Tid(x)).unwrap();
        m.set(x, &v(), &Value::Str("x".into())).unwrap();
        m.set(x, &ct::RETAINERS, &BTreeSet::from([r])).unwrap();
        e.commit(m).unwrap();
        (r, x)
    });
    file(&mut w, 0, vec![r, x], Vec::new());
    w.run();
    assert_eq!(w.engine(0).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "kept while referenced");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(r, &v(), &Value::Str("none".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(0).get(&x, &v()).unwrap(), None, "a node alone releases");
}

// spec/commits.md §5 (Lifetimes: while a peer sharing a sync ID is away nothing under it is
// released), spec/sync-set.md §3 (it waits only while some peer is to be waited for on S: one the rosters name, never told of S): node 1
// makes R retaining and referencing X outside its synced group and grants node 0's account write
// on R, which node 0 accepts; apart from node 0, node 1 files both and drops R's reference. R's
// sync ID joined node 1's sync set after the two parted, so no record holds it, yet node 1
// releases nothing until node 0's record has been told of it.
#[test]
fn nothing_is_released_under_a_sync_id_just_joined_before_the_peer_is_told_spec_commits_5() {
    let mut w = crate::harness::contacts();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let (r, x) = w.write(1, |e| {
        let mut m = Mutation::new();
        let r = e.new_thing(&mut m, a1);
        let x = e.new_thing(&mut m, a1);
        m.set(r, &v(), &Value::Tid(x)).unwrap();
        m.set(x, &v(), &Value::Str("x".into())).unwrap();
        m.set(x, &ct::RETAINERS, &BTreeSet::from([r])).unwrap();
        e.commit(m).unwrap();
        (r, x)
    });
    w.write(1, |e| e.grant(&r, &a0, &crate::flows::edge(osis_base::Role::Write))).unwrap();
    w.run();
    file(&mut w, 0, Vec::new(), vec![r]);
    w.run();
    w.partition(0, 1);
    w.run();
    file(&mut w, 1, vec![r, x], Vec::new());
    w.run();
    unreference(&mut w, 1, r);
    w.run();
    assert_eq!(w.engine(1).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "released before node 0 was told of R's sync ID");
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&x, &v()).unwrap(), None, "released once heard out");
}

// spec/permissions.md §2 (Tied grants), §7 (Joiner's leave): the holder duties' state, one value
// per thing named a holder: a thing is followed while named a holder here and no longer. A node alone releases X; once X is
// destroyed (its record and role commits gone), no holder duty follows it.
#[test]
fn a_destroyed_thing_is_followed_by_no_holder_duty_spec_permissions_2() {
    let mut w = World::new(0);
    w.add_node();
    w.run();
    let a = w.node(0).account.unwrap();
    let (r, x) = w.write(0, |e| {
        let mut m = Mutation::new();
        let r = e.new_thing(&mut m, a);
        let x = e.new_thing(&mut m, a);
        m.set(r, &v(), &Value::Tid(x)).unwrap();
        m.set(x, &ct::RETAINERS, &BTreeSet::from([r])).unwrap();
        e.commit(m).unwrap();
        (r, x)
    });
    file(&mut w, 0, vec![r, x], Vec::new());
    w.run();
    assert!(w.node(0).node.life().holder_duties_follow(&x), "followed while held");
    unreference(&mut w, 0, r);
    w.run();
    w.advance(osis_base::format::ROLE_KEEP_MS + 1);
    w.run();
    assert!(!w.engine(0).named_a_holder(&x), "X destroyed");
    assert!(!w.node(0).node.life().holder_duties_follow(&x), "still followed once destroyed");
}

/// How long node 1's grant in `read_until` lasts: past what a run's dial timers move the clock.
const UNTIL_MS: u64 = 10 * 86_400_000;

/// `contacts` with node 0's thing t (value "x") granted to node 1's account for reading for
/// `UNTIL_MS`, filed and read there: (world, t).
fn read_until() -> (World, Tid) {
    let (w, t) = fixture_with("life read until", || {
        let mut w = crate::harness::contacts();
        let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
        let until = osis_base::WallMs(w.now().0 + UNTIL_MS);
        let t = w.write(0, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a0);
            m.set(t, &v(), &Value::Str("x".into())).unwrap();
            e.commit(m).unwrap();
            t
        });
        file(&mut w, 0, vec![t], Vec::new());
        w.write(0, |e| e.grant(&t, &a1, &ct::Edge { role: osis_base::Role::Read, until: Some(until), invite: None, tied: None, floor: None })).unwrap();
        w.run();
        file(&mut w, 1, Vec::new(), vec![t]);
        w.run();
        assert_eq!(w.engine(1).get(&t, &v()).unwrap(), Some(Value::Str("x".into())), "node 1 reads t");
        (w, t)
    });
    (w, t)
}

/// Whether node `i` still holds secrets of `t`.
fn holds(w: &mut World, i: usize, t: &Tid) -> bool {
    w.engine(i).held_actors().contains(t)
}

// spec/permissions.md §2 (an `until` passing: the node hears out the sync IDs of what it lost,
// then drops): node 1's read of t ends by its `until` alone while connected to node 0; node 0
// finalizes it and shares nothing with node 1 from then (it judges it departed), which refuses
// node 1's ByRole: heard out, node 1 drops t's secrets and forgets t, long before
// `LOST_HEARD_WAIT_MS`.
#[test]
fn a_loss_by_an_until_drops_once_heard_out_spec_permissions_2() {
    let (mut w, t) = read_until();
    w.advance(UNTIL_MS);
    w.run();
    assert!(!holds(&mut w, 1, &t), "node 1 dropped t");
    assert_eq!(w.engine(1).get(&t, &v()).unwrap(), None, "and forgot it");
}

// spec/permissions.md §2 (It drops anyway `LOST_HEARD_WAIT_MS` after it first found the role
// gone): node 1, cut off from every peer when its `until` passes, hears nothing out and keeps t
// meanwhile; at the wait's end it drops t. Node 1's clock moves alone (`skew`): the world's dial
// ticks over the wait would cost minutes.
#[test]
fn a_loss_by_an_until_cut_off_drops_at_the_waits_end_spec_permissions_2() {
    let (mut w, t) = read_until();
    w.partition(0, 1);
    w.skew(1, UNTIL_MS as i64);
    w.run();
    assert!(holds(&mut w, 1, &t), "kept while not heard out");
    w.skew(1, (UNTIL_MS + osis_engine::rotation::LOST_HEARD_WAIT_MS / 2) as i64);
    w.run();
    assert!(holds(&mut w, 1, &t), "kept within the wait");
    w.skew(1, (UNTIL_MS + osis_engine::rotation::LOST_HEARD_WAIT_MS) as i64 + 3_600_000);
    w.run();
    assert!(!holds(&mut w, 1, &t), "dropped at the wait's end");
}
