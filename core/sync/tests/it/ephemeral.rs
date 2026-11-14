//! Ephemeral commits through sync (spec/sync-compaction.md §2): logged and pulled as durable
//! bodies are, held in memory only at every node, relayed by a node that cannot read them, gone
//! at their expiry and with every holder's restart.

use crate::harness::history::file;
use crate::harness::{World, fixture_with, contacts};
use osis_base::{Ak, Role, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_label::Class;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None, floor: None }
}

fn cursor() -> Ak {
    Ak::new("u:c+.0").unwrap()
}

/// Node 0 and node 2 (paired to node 0's account) read thing t; node 1 (another account) keeps
/// it unread by a sync grant it accepted. Quiet; t and its sync ID.
fn three() -> (World, (Tid, SyncId)) {
    fixture_with("ephemeral three", || {
        let mut w = contacts();
        w.pair(0);
        w.run();
        let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
        let t = w.write(0, |e| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a0);
            m.set(t, &Ak::new("u:v.0").unwrap(), &Value::Str("x".into())).unwrap();
            e.commit(m).unwrap();
            t
        });
        file(&mut w, 0, vec![t], Vec::new());
        w.write(0, |e| e.grant(&t, &a1, &edge(Role::Sync))).unwrap();
        w.run();
        file(&mut w, 1, Vec::new(), vec![t]);
        w.run();
        assert_eq!(w.engine(2).get(&t, &Ak::new("u:v.0").unwrap()).unwrap(), Some(Value::Str("x".into())), "node 2 reads t");
        let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
        (w, (t, s))
    })
}

/// Node `i` sets t's cursor to `v` (an ephemeral write), expiring `expires` ms from now.
fn eph_write(w: &mut World, i: usize, t: Tid, v: &str, expires: Option<u64>) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &cursor(), &Value::Str(v.into())).unwrap();
        if let Some(ms) = expires {
            let at = osis_base::WallMs(e.now().0 + ms);
            m.expires(t, &cursor(), at).unwrap();
        }
        e.write(m).unwrap();
    });
}

fn reads(w: &mut World, i: usize, t: Tid) -> Option<Value> {
    w.engine(i).get(&t, &cursor()).unwrap()
}

fn val(v: &str) -> Option<Value> {
    Some(Value::Str(v.into()))
}

/// Node `i`'s ephemeral entries of S.
fn eph_entries(w: &World, i: usize, s: &SyncId) -> usize {
    w.store(i).entries(s).unwrap().iter().filter(|e| e.class == Class::Ephemeral).count()
}

// spec/sync-compaction.md §2 (As durable bodies), spec/sync-ids.md §5 (Ephemeral entries):
// logged and relayed as durable bodies, held in memory only: node 0's ephemeral write reaches
// node 2 through node 1, which keeps S unread and cannot read it; it is no durable commit
// anywhere.
#[test]
fn an_ephemeral_write_reaches_a_reader_through_a_node_that_cannot_read_it_spec_sync_compaction_2() {
    let (mut w, (t, s)) = three();
    w.partition(0, 2);
    eph_write(&mut w, 0, t, "here", None);
    w.flush();
    assert_eq!(reads(&mut w, 2, t), val("here"), "node 2 reads it through node 1");
    assert!(eph_entries(&w, 1, &s) > 0, "node 1 relays it as an ephemeral entry");
    assert_eq!(reads(&mut w, 1, t), None, "node 1 cannot read it");
    let c = w.engine(0).memory_commits().into_iter().find(|x| x.2).map(|x| x.0).unwrap();
    for i in [0, 2] {
        assert!(w.engine(i).holds_memory(&c), "node {i} holds it in memory");
        assert!(!w.engine(i).commit_ids().contains(&c), "node {i}: no durable commit");
    }
}

// spec/sync-compaction.md §2 (Verification), spec/sync-ids.md §6 (Expiry): a part past its
// `expires` is held value-less, and at the prefix's `T` every node deletes the entry: an
// expiring ephemeral write is read at node 2 through node 1 before its expiry; at it the value
// is gone at nodes 0 and 2 and the entry from every node's store, by their own wakes.
#[test]
fn an_expiring_ephemeral_write_goes_everywhere_at_its_expiry_spec_sync_compaction_2() {
    let (mut w, (t, s)) = three();
    w.partition(0, 2);
    eph_write(&mut w, 0, t, "here", Some(60_000));
    w.flush();
    assert_eq!(reads(&mut w, 2, t), val("here"), "read before its expiry");
    assert!(eph_entries(&w, 1, &s) > 0);
    w.advance(61_000);
    w.flush();
    for i in 0..3 {
        assert_eq!(reads(&mut w, i, t), None, "node {i}: gone at its expiry");
        assert_eq!(eph_entries(&w, i, &s), 0, "node {i}: its entry gone");
    }
}

// spec/sync-compaction.md §2 (Holding), spec/crdt.md §2.1 (Start): node 0 restarts, gets its
// own ephemeral write back from the nodes holding it, and its next write, under a new session,
// reaches node 2 and wins there.
#[test]
fn a_restart_gets_ephemeral_state_back_and_writes_under_a_new_session_spec_sync_compaction_2() {
    let (mut w, (t, _)) = three();
    eph_write(&mut w, 0, t, "one", None);
    w.run();
    assert_eq!(reads(&mut w, 2, t), val("one"));
    w.power_off(0);
    w.power_on(0);
    assert_eq!(reads(&mut w, 0, t), None, "lost at the restart");
    w.run();
    assert_eq!(reads(&mut w, 0, t), val("one"), "back from the holders");
    eph_write(&mut w, 0, t, "two", None);
    w.run();
    for i in [0, 2] {
        assert_eq!(reads(&mut w, i, t), val("two"), "node {i} reads the new session's write");
    }
}

// spec/sync-compaction.md §2 (Holding), spec/sync-ids.md §5 (Ephemeral entries): in memory only,
// never in a store, until a restart: with node 0 away, nodes 1 and 2 restart, and none holds the
// ephemeral write any more.
#[test]
fn ephemeral_state_is_lost_once_every_holder_restarted_spec_sync_ids_5() {
    let (mut w, (t, s)) = three();
    eph_write(&mut w, 0, t, "here", None);
    w.run();
    assert_eq!(reads(&mut w, 2, t), val("here"));
    w.power_off(0);
    for i in [1, 2] {
        w.power_off(i);
    }
    for i in [1, 2] {
        w.power_on(i);
    }
    w.run();
    assert_eq!(reads(&mut w, 2, t), None, "no holder left");
    assert_eq!(eph_entries(&w, 1, &s), 0);
    assert_eq!(eph_entries(&w, 2, &s), 0);
}

// spec/sync-compaction.md §2 (Verification): an ephemeral commit more than `MAX_DRIFT` ahead of
// the wall clock waits as a durable one does, and applies within the room then: node 0's clock
// runs two hours ahead; its ephemeral write waits at node 2 until node 2's clock comes within
// `MAX_DRIFT` of it, then applies.
#[test]
fn an_ephemeral_commit_ahead_of_the_clock_applies_once_its_wait_is_over_spec_sync_compaction_2() {
    let (mut w, (t, _)) = three();
    let hour = osis_base::format::MAX_DRIFT_MS;
    w.skew(0, 2 * hour as i64);
    eph_write(&mut w, 0, t, "early", None);
    w.flush();
    assert_eq!(reads(&mut w, 2, t), None, "it waits");
    w.advance(hour + 60_000);
    w.flush();
    assert_eq!(reads(&mut w, 2, t), val("early"), "applied once within MAX_DRIFT");
}


/// Node `i` fires t's ring signal with `v`.
fn ring(w: &mut World, i: usize, t: Tid, v: &str) {
    w.write(i, |e| {
        let mut m = Mutation::new();
        m.set(t, &Ak::new("u:ring+~0").unwrap(), &Value::Str(v.into())).unwrap();
        e.write(m).unwrap();
    });
}

/// The signals fired on t's ring that `rx` heard so far.
fn heard(rx: &std::sync::mpsc::Receiver<osis_engine::Event>) -> usize {
    rx.try_iter().filter_map(|ev| match ev {
        osis_engine::Event::Commits(cs) => Some(cs.iter().filter(|c| c.fired.is_some() && c.ak.as_str() == "u:ring+~0").count()),
        _ => None,
    }).sum()
}

// spec/sync-compaction.md §2 (Delivery), spec/sync-ids.md §6 (Relay-only),
// spec/sync-streams.md §4 (Relay-only entries): node 0's ephemeral signal reaches node 2 through
// node 1, which keeps S unread, and is told to node 2's listeners once; it goes as a Stream with
// no cursor and no node holds an entry of it.
#[test]
fn an_ephemeral_signal_is_relayed_to_a_reader_once_and_held_nowhere_spec_sync_compaction_2() {
    let (mut w, (t, s)) = three();
    w.engine(2).watch_commits();
    let rx = w.engine(2).subscribe();
    w.partition(0, 2);
    let before: Vec<usize> = (0..3).map(|i| w.store(i).entries(&s).unwrap().len()).collect();
    ring(&mut w, 0, t, "hi");
    w.flush();
    assert_eq!(heard(&rx), 1, "node 2 hears it once, through node 1");
    for (i, n) in before.into_iter().enumerate() {
        assert_eq!(w.store(i).entries(&s).unwrap().len(), n, "node {i} holds no entry of it");
    }
}

// spec/sync-ids.md §6 (Taken once), spec/sync-compaction.md §2 (Replay): node 0's signal
// reaches node 2 directly and through node 1; node 2 tells its listeners once.
#[test]
fn an_ephemeral_signal_by_two_routes_is_delivered_once_spec_sync_ids_6() {
    let (mut w, (t, _)) = three();
    w.engine(2).watch_commits();
    let rx = w.engine(2).subscribe();
    ring(&mut w, 0, t, "hi");
    w.run();
    assert_eq!(heard(&rx), 1);
}

// spec/sync-compaction.md §2 (At a node, for what it reads): each ephemeral body from others
// counts at an estimate of the memory it takes held, and one whose bound does not fit the room
// left is not applied: node 2's memory cap holds one of two like ephemeral writes as held,
// though their bytes alone would fit twice; it applies one.
#[test]
fn a_reader_holds_ephemeral_commits_from_others_within_its_cap_as_held_spec_sync_compaction_2() {
    let (mut w, (t, s)) = three();
    w.partition(0, 1);
    w.partition(0, 2);
    let d = Ak::new("u:d+.0").unwrap();
    eph_write(&mut w, 0, t, "v", None);
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &d, &Value::Str("v".into())).unwrap();
        e.write(m).unwrap();
    });
    let own: Vec<_> = w.engine(0).memory_commits().into_iter().filter(|x| x.2).map(|x| x.0).collect();
    assert_eq!(own.len(), 2);
    let charge = own.iter().map(|c| w.engine(0).memory_charge(c).unwrap()).min().unwrap();
    let bound = own.iter().map(|c| osis_engine::Engine::memory_bound(&w.engine(0).memory_blob(c).unwrap().unwrap()).0).max().unwrap();
    let cap = charge + 256 + bound - 1;
    let mut st = w.store(2).clone();
    st.set_caps(&osis_engine::sync::Caps { policy: [("memory_bytes".to_string(), cap)].into(), ..Default::default() });
    w.heal();
    w.run();
    let held = [reads(&mut w, 2, t).is_some(), w.engine(2).get(&t, &d).unwrap().is_some()];
    assert_eq!(held.iter().filter(|x| **x).count(), 1, "one held within the cap: {held:?}");
    assert!(eph_entries(&w, 1, &s) >= 2, "node 1 relays both");
}
