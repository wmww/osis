//! A demotion reaching every sync ID that carries the demoted writer's writes (spec/permissions.md
//! §4 Chain certificates: every held edge write on a path into a thing, removals and lowerings
//! included, goes with each author's chain there, and with the demoted actor's keysets, spec/
//! crypto.md §4 Carried demotions; spec/sync-judgement.md §2 required set), end to
//! end through the product's sync: the demotion is written under another sync ID than the one a
//! node syncs, and that node judges the demoted writer's writes as the demoter does.

use crate::harness::history::{file, world};
use crate::harness::{World, fixture_with};
use osis_base::{Ak, CommitId, Role, SyncId, Tid, Value};
use osis_sync::types::Entry;
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}

fn ak() -> Ak {
    Ak::new("u:v.0").unwrap()
}

/// Node `i` writes `v` on `t`.
fn set(w: &mut World, i: usize, t: Tid, v: &str) -> CommitId {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &ak(), &Value::Str(v.into())).unwrap();
        e.commit(m).unwrap().unwrap()
    })
}

fn reads(w: &mut World, i: usize, t: Tid) -> Option<Value> {
    w.engine(i).get(&t, &ak()).unwrap()
}

fn s(v: &str) -> Option<Value> {
    Some(Value::Str(v.into()))
}


#[derive(Clone)]
struct Shape {
    t: Tid,
    g: Tid,
    /// G2's sync ID, the only one carrying `t` that nodes 2 and 3 sync.
    s2: SyncId,
}

/// Four accounts. Node 0 (admin of everything) makes t (secrets of its own), group G2 holding t
/// and reading it, and actor g holding write on t. Node 1's account W holds write on g (so on t)
/// and read on G2, where it logs its writes; node 2's holds read on G2, node 3's sync on G2 (kept
/// unread). Node 3 syncs S2 (G2's sync ID) alone of what carries t or g. Node 2 also syncs t's
/// own sync ID (it keeps up with t's rotations there), whose own certificates carry every edge
/// write into t; the tests cut node 2 off from all but node 3, so S2 is its one way in.
fn shape() -> (World, Shape) {
    fixture_with("demotions shape", || {
        let mut w = world(0, 4);
        let a: Vec<Tid> = (0..4).map(|i| w.node(i).account.unwrap()).collect();
        let (t, g, g2) = w.write(0, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a[0]);
            m.set(t, &ak(), &Value::Str("x".into())).unwrap();
            let g = e.new_thing(&mut m, a[0]);
            let g2 = e.new_thing(&mut m, a[0]);
            e.commit(m).unwrap();
            for x in [t, g, g2] {
                e.give_own_secrets(&x).unwrap();
            }
            e.grant(&t, &g, &edge(Role::Write)).unwrap();
            e.grant(&t, &g2, &edge(Role::Read)).unwrap();
            let mut m = Mutation::new();
            m.set(g2, &ct::GROUP, &ct::Group { items: [t].into(), ..Default::default() }).unwrap();
            e.commit(m).unwrap();
            e.grant(&g, &a[1], &edge(Role::Write)).unwrap();
            e.grant(&g2, &a[1], &edge(Role::Read)).unwrap();
            e.grant(&g2, &a[2], &edge(Role::Read)).unwrap();
            e.grant(&g2, &a[3], &edge(Role::Sync)).unwrap();
            (t, g, g2)
        });
        file(&mut w, 0, Vec::new(), vec![g, g2]);
        w.run();
        for (i, x) in [(1, g), (1, g2), (2, g2), (3, g2)] {
            let invited = w.engine(i).invitations().unwrap().iter().any(|v| v.thing == x && !v.taken);
            if invited {
                let (_, d) = w.engine(i).account().unwrap().unwrap();
                w.write(i, |e| e.accept_invite(&x, &d)).unwrap();
            } else {
                file(&mut w, i, Vec::new(), vec![x]);
            }
            w.run();
        }
        let s2 = w.engine(0).home_sync_id(&g2).unwrap().unwrap();
        let sg = w.engine(0).home_sync_id(&g).unwrap().unwrap();
        let st = w.engine(0).home_sync_id(&t).unwrap().unwrap();
        let ids = w.engine(3).sync_set().unwrap().ids.clone();
        assert!(ids.contains_key(&s2) && !ids.contains_key(&sg) && !ids.contains_key(&st), "node 3 syncs S2, neither g's nor t's sync ID");
        assert!(!w.engine(2).sync_set().unwrap().ids.contains_key(&sg), "node 2 does not sync g's sync ID");
        assert_eq!(reads(&mut w, 2, t), s("x"), "node 2 reads t through G2");
        // the partitions and arrival orders below cost dial ticks toward cut-off peers
        w.cap = u64::MAX;
        (w, Shape { t, g, s2 })
    })
}

/// Node 0 removes W from g, under g's sync ID, while W is cut off from every other node (so it
/// writes on as before).
fn demote(w: &mut World, sh: &Shape) -> CommitId {
    let a1 = w.node(1).account.unwrap();
    for j in [0, 2, 3] {
        w.partition(1, j);
    }
    let c = w.write(0, |e| e.demote(&sh.g, &Demotion { holder: a1, new: None, retain: None })).unwrap().commits[0];
    w.run();
    c
}

/// Commit `c`'s entries (its blobs as node 0 names them) under S2 in node `i`'s store.
fn entries_of(w: &mut World, i: usize, sh: &Shape, c: &CommitId) -> usize {
    let blobs = w.engine(0).commit_blobs(c).unwrap();
    w.store(i).entries(&sh.s2).unwrap().iter().filter(|e| blobs.contains(&e.blob)).count()
}

/// W's own deposits under S2.
fn own_deposits(w: &World, sh: &Shape) -> Vec<Entry> {
    w.store(1).entries(&sh.s2).unwrap().into_iter().filter(|e| e.own && e.deposited).collect()
}

/// W writes `v` on t (cut off): the deposits under S2 it made.
fn deposited_write(w: &mut World, sh: &Shape, v: &str) -> Vec<Entry> {
    let had = own_deposits(w, sh);
    set(w, 1, sh.t, v);
    w.run();
    let new: Vec<Entry> = own_deposits(w, sh).into_iter().filter(|x| !had.contains(x)).collect();
    assert!(!new.is_empty(), "W deposits its write under S2");
    new
}

/// Whether node `i`'s store holds any of `deps` under S2.
fn holds_any(w: &World, i: usize, sh: &Shape, deps: &[Entry]) -> bool {
    w.store(i).entries(&sh.s2).unwrap().iter().any(|e| deps.iter().any(|d| d.blob == e.blob))
}

/// `shape` with node 2 reaching nothing but node 3, and W's w1 written and at the store.
fn cut_off_reader() -> (World, Shape) {
    let (mut w, sh) = shape();
    w.partition(0, 2);
    w.partition(1, 2);
    set(&mut w, 1, sh.t, "w1");
    w.run();
    assert_eq!(reads(&mut w, 2, sh.t), s("w1"), "w1 reached node 2 through the store");
    (w, sh)
}

/// Node 2 restarts and settles: what it reads.
fn restarted(w: &mut World, sh: &Shape) -> Option<Value> {
    w.power_off(2);
    w.power_on(2);
    w.run();
    reads(w, 2, sh.t)
}

// spec/permissions.md §4 (Chain certificates: the demotion lies on W's path into t, so it goes
// with W's chain under S2), spec/sync-judgement.md §2 (required set) and §6 (a node keeping S2
// unread serves what it holds), spec/permissions.md §5.2 (a write after an explicit demotion is
// invalid; one its frontier lists stays): node 0 removes W from g under g's sync ID, which
// neither node 2 nor the store syncs; the demotion reaches the store under S2, once, and node 2
// from it. W, cut off and not knowing, writes w2 and pushes its deposit to node 2 (by hand: an
// honest W that reaches S2 learns of the demotion and logs w2 nowhere). Node 2 reads w1, never
// w2, also after a restart.
#[test]
fn a_demotion_under_another_sync_id_reaches_a_reader_through_s2_alone_spec_permissions_4() {
    let (mut w, sh) = cut_off_reader();
    let r = demote(&mut w, &sh);
    assert_eq!(entries_of(&mut w, 3, &sh, &r), 1, "the store keeps the demotion under S2, once");
    assert_eq!(entries_of(&mut w, 0, &sh, &r), 1, "one entry of the demotion under S2 at node 0");
    let deps = deposited_write(&mut w, &sh, "w2");
    let store = w.store(2).clone();
    for e in &deps {
        let bytes = w.store(1).bytes(&e.blob).unwrap().unwrap();
        let o = osis_sync::streams::opening(w.engine(2), &store, &sh.s2, e, &bytes).unwrap();
        assert_eq!(o, osis_sync::streams::Opening::Held { gave: true }, "node 2 opens W's deposit of w2");
    }
    w.run();
    assert_eq!(reads(&mut w, 2, sh.t), s("w1"), "node 2 reads w1, not w2");
    assert_eq!(restarted(&mut w, &sh), s("w1"), "after a restart");
}

// As above, the other arrival order: W's w2, written after the demotion, reaches the store and
// node 2 first and counts there (nothing node 2 holds says otherwise); node 0 then logs the
// demotion under S2 at the store, and node 2 reads w1 again. W never held the demotion: nothing
// it logs carries it, and nothing it does keeps it from S2.
#[test]
fn a_demotion_arriving_after_the_demoted_write_takes_it_back_spec_permissions_4() {
    let (mut w, sh) = cut_off_reader();
    w.partition(0, 3);
    let r = demote(&mut w, &sh);
    let deps = deposited_write(&mut w, &sh, "w2");
    w.rejoin(1, 3);
    w.run();
    assert!(holds_any(&w, 3, &sh, &deps), "the store took w2");
    assert_eq!(reads(&mut w, 2, sh.t), s("w2"), "before the demotion arrives, w2 counts");
    w.partition(1, 3);
    w.rejoin(0, 3);
    w.run();
    assert!(!w.engine(1).holds_commit(&r), "W never held the demotion");
    assert_eq!(entries_of(&mut w, 3, &sh, &r), 1, "the store keeps the demotion under S2");
    assert_eq!(reads(&mut w, 2, sh.t), s("w1"), "node 2 reads w1 again");
    assert_eq!(restarted(&mut w, &sh), s("w1"), "after a restart");
}
