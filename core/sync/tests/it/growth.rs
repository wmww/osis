//! Growth with the number of writes (spec/requirements.md Scale; notes/growth.md): what a
//! writer, a reader and a node keeping S unread store, counted at n and 10n writes, never timed. Node 0 makes thing 0; node 1's account syncs it (kept unread), node 2's
//! reads it (`writers`: writes it too).

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_engine::Mutation;
use osis_engine::flows::Demotion;
use osis_schema::core_types::Edge;
use std::collections::BTreeMap;

const DAY_MS: u64 = 86_400_000;

fn setup(gives: Gives) -> (World, Tid) {
    let mut w = world(0, 3);
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, gives), Run], String::new());
    let t = w.history.things[0].0;
    (w, t)
}

/// Rows by kind (a key up to its first `/`): count and key plus value bytes.
type Census = BTreeMap<String, (usize, usize)>;

fn census(rows: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Census {
    let mut out = Census::new();
    for (k, v) in rows {
        let end = k.iter().position(|b| *b == b'/').map_or(k.len().min(3), |p| p + 1);
        let e = out.entry(String::from_utf8_lossy(k.get(..end).unwrap_or(&k)).into_owned()).or_default();
        e.0 += 1;
        e.1 += k.len() + v.len();
    }
    out
}

/// What a node holds: its engine's and its sync store's rows by kind, and the blobs on its disks
/// (count, bytes). Pages are not counted: their layout follows the history of writes within a
/// bound, not the data.
type Held = (Census, Census, [(u64, u64); 2]);

/// What node `i` holds (`Held`).
fn held(w: &mut World, i: usize) -> Held {
    let engine = w.engine(i).local_census().expect("census");
    let store = census(w.store(i).with_read(|t| t.scan_local(b"", b"", usize::MAX)).expect("scan").into_iter().map(|kv| (kv.0, kv.1)));
    let d = w.disk_use(i);
    (engine, store, [(d[0].2, d[0].3), (d[1].2, d[1].3)])
}

/// Writes `from..to` by the nodes `by` in turn, each a whole replace of t's value, a second
/// apart, then a snapshot by the last writer (what the compaction trigger leaves held moves in a
/// cycle of writes; a snapshot ends it at the same place), a run and the tombstone lifetime plus
/// two days with no writes: what each node holds then.
fn at(w: &mut World, t: Tid, by: &[usize], from: usize, to: usize) -> Vec<Held> {
    for i in from..to {
        let n = by[i % by.len()];
        w.write(n, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(format!("v{i:08}"))).unwrap();
            e.commit(m).unwrap();
        });
        w.run();
        w.advance(1_000);
    }
    if to > from {
        w.write(by[(to - 1) % by.len()], |e| e.snapshot(&t, &value_ak())).unwrap();
        w.run();
    }
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    (0..3).map(|i| held(w, i)).collect()
}

/// A store's per-entry attribution rows: who brought an entry uncharged (`B/`), who it is charged
/// to (`W/`). One per entry at most, and which peer's copy came first is the run's order, not the
/// number of writes (an author whose own entry went and came back holds a peer's copy, or logs
/// its own, by which arrives first): each is bounded by the entries (`E/`), not compared.
const ATTRIBUTION: [&str; 2] = ["B/", "W/"];

/// No more rows of any kind at 10n than at n, nor blobs (a few bytes for a counter that
/// widened); a store's attribution rows at most one per entry.
#[track_caller]
fn flat(a: &[Held], b: &[Held]) {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        for (d, p, q) in [("engine", &x.0, &y.0), ("store", &x.1, &y.1)] {
            let compared = |k: &String| d == "engine" || !ATTRIBUTION.contains(&k.as_str());
            let bytes = |c: &Census| c.iter().filter(|(k, _)| compared(k)).map(|(_, v)| v.1).sum::<usize>();
            let fewer = q.iter().filter(|(k, _)| compared(k)).all(|(k, v)| v.0 <= p.get(k).map_or(0, |x| x.0));
            let entries = q.get("E/").map_or(0, |e| e.0);
            let bounded = q.iter().filter(|(k, _)| !compared(k)).all(|(_, v)| v.0 <= entries);
            assert!(fewer && bounded && bytes(q) <= bytes(p) + 64, "node {i} {d}: rows by kind (count, bytes) {p:?} at n, {q:?} at 10n");
        }
        for (d, p, q) in [("engine", x.2[0], y.2[0]), ("store", x.2[1], y.2[1])] {
            assert!(q.0 <= p.0 && q.1 <= p.1 + 64, "node {i} {d} disk: blobs (count, bytes) {p:?} at n, {q:?} at 10n");
        }
    }
}

fn grows_nothing(gives: Gives, by: &[usize]) {
    let (mut w, t) = setup(gives);
    // a warm-up: each aspect's history cursor settles with time alone
    at(&mut w, t, by, 0, 0);
    at(&mut w, t, by, 0, 2);
    let n = at(&mut w, t, by, 2, 8);
    let n10 = at(&mut w, t, by, 8, 68);
    for i in [0, 2] {
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("v00000067".into())), "node {i} reads the newest");
    }
    flat(&n, &n10);
}

// spec/commits.md §5 Own replaces and Forgetting, spec/requirements.md Scale: one writer replacing
// one register 6 and 60 more times stores the same rows and blobs at the writer, a reader and a node
// keeping S unread once tombstones have aged out.
#[test]
fn single_writer_replace_grows_nothing_spec_commits_5() {
    grows_nothing(Gives::Reads, &[0]);
}

// spec/commits.md §5 Covered and Forgetting, spec/sync-compaction.md §1 (trigger): two writers
// replacing one register in turn store the same at 6 and 60 more writes (automatic compaction covers
// the other's writes).
#[test]
fn several_writers_grow_nothing_spec_commits_5() {
    grows_nothing(Gives::Writes, &[0, 2]);
}

// spec/sync-opens.md §1 (One connection per pair; Twin): the differential's nodes dial each other at
// once at first contact, yet each pair keeps one connection, so each write crosses each pair on one
// stream: deliveries per write are the same at n and 10n writes, all on one connection per pair.
#[test]
fn each_write_crosses_each_pair_on_one_connection_spec_sync_opens_1() {
    let (mut w, _) = setup(Gives::Writes);
    for i in 0..3 {
        let mut peers: Vec<usize> = w.links_of(i).into_iter().map(|(_, j)| j).collect();
        peers.sort();
        assert_eq!(peers, (0..3).filter(|j| *j != i).collect::<Vec<_>>(), "node {i}: one connection per peer");
    }
    let writes = |w: &mut World, n: usize| {
        let d = w.deliveries;
        for _ in 0..n {
            let _ = play(w, &[Write(0, 0), Run], String::new());
        }
        w.deliveries - d
    };
    // the first two writes after setup carry the grants' tail; after them deliveries repeat every
    // 3 writes (the writer node 2 deletes some replaced bodies at node 1 beside the admin)
    writes(&mut w, 2);
    w.trace = true;
    let (a, b) = (writes(&mut w, 3), writes(&mut w, 30));
    assert_eq!(b, 10 * a, "deliveries per write at n and 10n");
    let ends: std::collections::BTreeSet<_> = w.seen.iter().filter_map(|s| match s {
        crate::harness::Seen::Bytes { node, conn, .. } => Some((*node, *conn)),
        _ => None,
    }).collect();
    assert!(ends.len() <= 6, "bytes on one connection per pair: {ends:?}");
}

/// Node 0 makes thing 0 and grants node 1's account write and node 2's read (no node keeps it
/// unread: a store keeps what it holds of an invalid body until its expiry,
/// issues/invalid-junk-kept.md). Cut off from node 0, node 1 is lowered to read there and writes
/// `n` values it still believes valid, the first purging its own earlier write (`writer`
/// retention, so it may as a writer); node 2, cut off from node 0 too, takes them; then nodes 0
/// and 2 meet, then all: every node judges them invalid. Then a restart of every node and the
/// tombstone lifetime: the world, the thing, the invalid commits and what each node holds
/// (`Held`).
fn lowered_writes(n: usize) -> (World, Tid, Vec<CommitId>, Vec<Held>) {
    let mut w = world(0, 3);
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let note = Ak::new("u:n.0").unwrap();
    let mine = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &note, &Value::Str("mine".into())).unwrap().retention(t, &note, osis_schema::Retention { by: osis_schema::PurgeBy::Writer }).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.partition(0, 1);
    w.partition(0, 2);
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: Some(Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None }), retain: None })).unwrap();
    w.run();
    let mut bad = Vec::new();
    for i in 0..n {
        w.advance(1_000);
        bad.push(w.write(1, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(format!("w{i:04}"))).unwrap();
            if i == 0 {
                m.purge_commit(mine, t, note.clone());
            }
            e.commit(m).unwrap().unwrap()
        }));
    }
    // node 2 holds them (valid as it judges), then meets node 0 alone: each holds an invalid body
    // the other's stream shows
    w.run();
    let (first, last) = (bad[0], bad[n - 1]);
    assert!(w.engine(2).holds_commit(&first) && w.engine(2).holds_commit(&last), "node 2 took the writes");
    w.heal();
    w.partition(0, 1);
    w.partition(1, 2);
    w.run();
    // known while node 1's stream, as node 2 last heard it, shows them: valid again, they are
    // fetched there
    assert!(w.engine(2).kept_invalid(&first) && w.engine(2).kept_invalid(&last), "node 2 dropped them as invalid, their headers kept");
    w.heal();
    w.run();
    for i in 0..3 {
        w.power_off(i);
        w.power_on(i);
    }
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    let held = (0..3).map(|i| held(&mut w, i)).collect();
    (w, t, bad, held)
}

// spec/commits.md §5 (Forgetting: a commit judged invalid goes once no entry of it is known),
// spec/sync-judgement.md §3 (Own store: a body judged invalid leaves it with no tombstone),
// spec/permissions.md §6 (A purge request: an invalid one purges nothing): a lowered writer's invalid writes,
// one carrying a purge request, leave no header at the other nodes, nor a store entry anywhere,
// the author included (it keeps its own commits for its user): every node's store and the
// others' engines hold the same at 10 and 20 such writes (both past what arms a compaction of the value), the purge took nothing, and nothing of
// them is held at nodes 0 and 2. Then a re-grant makes them valid again: the author logs them
// again and every node reads its last write. Fails if a node keeps its entry of a body judged
// invalid, the author included, or the engine keeps a commit known only for invalid parts.
#[test]
fn a_lowered_writers_invalid_writes_leave_nothing_and_return_on_regrant_spec_commits_5() {
    let (_, _, _, few) = lowered_writes(10);
    let (mut w, t, bad, many) = lowered_writes(20);
    // the author keeps its own commits for its user: its engine is not compared
    let mut few = few;
    few[1].0 = many[1].0.clone();
    flat(&few, &many);
    let note = Ak::new("u:n.0").unwrap();
    for i in [0, 2] {
        assert!(bad.iter().all(|c| !w.engine(i).holds_commit(c)), "node {i} forgot every invalid write");
        assert_eq!(w.engine(i).get(&t, &note).unwrap(), Some(Value::Str("mine".into())), "node {i}: the invalid request purged nothing");
        assert_ne!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("w0019".into())));
    }
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.grant(&t, &a1, &Edge { role: Role::Write, until: None, invite: None, retain: false, floor: None })).unwrap();
    w.run();
    for i in 0..3 {
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("w0019".into())), "node {i} reads the re-granted writer's last write");
    }
    for i in [0, 2] {
        // the author's own replaces cover the rest: never sent again
        assert!(w.engine(i).holds_commit(&bad[0]) && w.engine(i).holds_commit(&bad[19]), "node {i} holds the writes valid again");
        assert_eq!(w.engine(i).get(&t, &note).unwrap(), None, "node {i}: the request valid again purges");
    }
}

// spec/permissions.md §6 (Invalid deltas: valid again, fetched from any holder), spec/commits.md
// §5 (Forgetting: no entry of a blob of it is known): node 2 judges a lowered writer's write invalid, its
// author never having heard of the demotion, and the re-grant reaches node 2 while the author is
// away: node 2 reads the write from node 3, which keeps S unread and holds it. Fails if node 2
// forgets the write while node 3 shows it and nothing brings it back.
#[test]
fn a_write_valid_again_before_its_author_hears_comes_from_a_store_spec_permissions_6() {
    eprintln!("start {:?}", std::time::Instant::now());
    let mut w = world(0, 4);
    eprintln!("world {:?}", std::time::Instant::now());
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 2, Gives::Reads), Grant(0, 0, 3, Gives::Syncs), Run], String::new());
    let t = w.history.things[0].0;
    // two islands: {0, 2} hear the demotion, {1, 3} the write
    for (a, b) in [(0, 1), (0, 3), (1, 2), (2, 3)] {
        w.partition(a, b);
    }
    let a1 = w.node(1).account.unwrap();
    w.write(0, |e| e.demote(&t, &Demotion { holder: a1, new: Some(Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None }), retain: None })).unwrap();
    w.run();
    let key = Ak::new("u:k.0").unwrap();
    let x = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &key, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let blobs = w.engine(1).commit_blobs(&x).unwrap();
    let at_store = |w: &mut World| w.store(3).entries(&s).unwrap().iter().any(|e| blobs.contains(&e.blob));
    assert!(at_store(&mut w), "node 3 holds the write");
    // the author goes away before hearing of the demotion; node 2 meets node 3
    w.heal();
    for b in [0, 2, 3] {
        w.partition(1, b);
    }
    w.run();
    assert_ne!(w.engine(2).get(&t, &key).unwrap(), Some(Value::Str("x".into())), "node 2 judges the write invalid");
    assert!(at_store(&mut w), "node 3 keeps its entry (none deleted for being invalid)");
    w.write(0, |e| e.grant(&t, &a1, &Edge { role: Role::Write, until: None, invite: None, retain: false, floor: None })).unwrap();
    w.run();
    assert_eq!(w.engine(2).get(&t, &key).unwrap(), Some(Value::Str("x".into())), "node 2 reads the write valid again, from node 3");
}

/// Node 0 makes `n` things, each kept unread by node 1 and read by node 2; every node then
/// restarts once (what a start finds owed is done), then once more cut off from its peers: the
/// durable commits (engine store, sync store) each node's second start makes, run to quiet.
fn quiet_starts(n: usize) -> Vec<(u64, u64)> {
    let mut w = world(0, 3);
    w.cap = 2_000_000;
    let mut steps = Vec::new();
    for k in 0..n {
        steps.extend([New(0), Grant(0, k, 1, Gives::Syncs), Grant(0, k, 2, Gives::Reads)]);
    }
    steps.push(Run);
    let _ = play(&mut w, &steps, String::new());
    for i in 0..3 {
        w.power_off(i);
        w.power_on(i);
        w.run();
    }
    let mut out = Vec::new();
    for i in 0..3 {
        w.power_off(i);
        for j in (0..3).filter(|j| *j != i) {
            w.partition(i, j);
        }
        w.power_on(i);
        w.run();
        out.push((w.engine(i).store_writes().committed, w.store(i).committed()));
        w.heal();
        w.run();
    }
    out
}

// spec: none (property: notes/growth.md, no per-session growth; spec/sync-set.md §3, a start
// judges what left the sync set by the whole set): a start with nothing new commits nothing, at
// n and 10n things shared with a reader and a node keeping them unread.
#[test]
fn a_quiet_start_commits_nothing_at_n_and_10n() {
    let (a, b) = (quiet_starts(1), quiet_starts(10));
    assert!(a.iter().chain(&b).all(|x| *x == (0, 0)), "(engine, store) commits per node's start: {a:?} at n, {b:?} at 10n");
}

// spec/permissions.md §6 (Invalid deltas: valid again, received again from any holder),
// spec/commits.md §5 (Forgetting: an invalid commit carrying a request goes only where the
// request holds the right over nothing): node 1's account, lowered to read on things 0 and 1,
// writes on thing 0 and purges its own write on thing 1. Node 0 judges it invalid and its request
// void, and forgets it; a re-grant of write on thing 1 alone gives the request force while the
// commit's part on thing 0 stays invalid: every node reads the purge.
#[test]
fn a_request_given_force_again_reaches_a_node_that_forgot_it_spec_perm_6() {
    let mut w = world(0, 2);
    let _ = play(&mut w, &[New(0), New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 1, 1, Gives::Writes), Run], String::new());
    let (t, u) = (w.history.things[0].0, w.history.things[1].0);
    let y = Ak::new("u:y.0").unwrap();
    let mine = Some(Value::Str("mine".into()));
    let own = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(u, &y, &Value::Str("mine".into())).unwrap().retention(u, &y, osis_schema::Retention { by: osis_schema::PurgeBy::Writer }).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    w.partition(0, 1);
    let a1 = w.node(1).account.unwrap();
    let read = || Some(Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None });
    for x in [t, u] {
        w.write(0, |e| e.demote(&x, &Demotion { holder: a1, new: read(), retain: None })).unwrap();
    }
    w.run();
    w.advance(1_000);
    let q = w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("late".into())).unwrap();
        m.purge_commit(own, u, y.clone());
        e.commit(m).unwrap().unwrap()
    });
    w.heal();
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    assert!(!w.engine(0).holds_commit(&q), "node 0 forgot the invalid commit");
    assert_eq!(w.engine(0).get(&u, &y).unwrap(), mine, "its request void at node 0");
    w.write(0, |e| e.grant(&u, &a1, &Edge { role: Role::Write, until: None, invite: None, retain: false, floor: None })).unwrap();
    w.run();
    for i in 0..2 {
        assert_eq!(w.engine(i).get(&u, &y).unwrap(), None, "node {i} reads the purge given force");
    }
}

// spec/sync-opens.md §6 (Where it stopped; Lost: each Lost for a member open at its receiver is
// answered), spec/sync-streams.md §4 (Joining): a head move at a node keeping S unread ends the
// readers' opens by the old sync key, and each reader opens S again by the new one: both sides
// rejoin from where they stopped, so what a reader and the store send each other per head move
// does not grow with the n entries of S (no listing from the start either way), at n and 10n.
// Node 0 makes thing 0, node 1's account syncs it (kept unread), nodes 2 and 3 read it; each
// removal of node 3's account rotates read and sync (node 1's head moves); counted between node 1
// and node 2 (a reader, no writer), each way, after n entries and again after 10n.
#[test]
fn a_head_move_relists_nothing_between_a_reader_and_a_store_at_n_and_10n() {
    eprintln!("start {:?}", std::time::Instant::now());
    let mut w = world(0, 4);
    eprintln!("world {:?}", std::time::Instant::now());
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let mut written = 0;
    let mut head_move = |w: &mut World, n: usize| {
        for i in written..n {
            w.write(0, |e| {
                let mut m = Mutation::new();
                m.set(t, &Ak::new(format!("u:e{i}.0")).unwrap(), &Value::Int(i as i64)).unwrap();
                e.commit(m).unwrap();
            });
        }
        written = n;
        let _ = play(w, &[Grant(0, 0, 3, Gives::Reads), Run], String::new());
        assert!(w.store(1).entries(&s).unwrap().len() >= n, "the store holds every entry");
        let steps = |w: &World| w.store(1).path(&s).unwrap().map_or(0, |p| p.steps.len());
        let sent = |w: &World| (w.net.between.get(&(1, 2)).copied().unwrap_or(0), w.net.between.get(&(2, 1)).copied().unwrap_or(0));
        let (before, head) = (sent(w), steps(w));
        let _ = play(w, &[Remove(0, 0, 3), Run], String::new());
        assert_eq!(steps(w), head + 1, "the store's head moved");
        let after = sent(w);
        (after.0 - before.0, after.1 - before.1)
    };
    let (a, b) = (head_move(&mut w, 3), head_move(&mut w, 30));
    assert!(b.0 <= a.0 + 64 && b.1 <= a.1 + 64, "bytes (store to reader, reader to store) across a head move: {a:?} at n, {b:?} at 10n");
}

/// Node 0 makes a plain thing under its account root D held from D, a thing with own keys under
/// its account (held from D), and a plain thing under its node root held from it, writes each,
/// removes every strong to them and runs (a pass releases them), `rounds` times; then snapshots
/// the roots' `holds.0` and D's `tickets.0` (what the trigger leaves held moves in a cycle; a
/// snapshot ends it at the same place) and lets the tombstone lifetime and two days pass. What
/// it holds then.
fn own_rounds(w: &mut World, rounds: usize) -> Held {
    use osis_schema::core_types::{HOLDS, TICKETS};
    let (root, d) = (w.engine(0).node_root().unwrap(), w.engine(0).account_root().unwrap());
    let p = w.engine(0).account().unwrap().unwrap().0;
    let strong = |m: &mut Mutation, from: Tid, to: Tid, on: bool| {
        let v = Value::Strong(to);
        let op = if on { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
        m.op(from, &HOLDS, osis_crdt::PathOp { path: vec![], op }).unwrap();
    };
    for _ in 0..rounds {
        let ts = w.write(0, |e| {
            let mut ts = Vec::new();
            for from in [d, root] {
                let mut m = Mutation::new();
                let t = m.create(e.thing_record(from, None));
                strong(&mut m, from, t, true);
                e.commit(m).unwrap();
                ts.push((t, from));
            }
            ts.push((e.create_with_admin(&p).unwrap().0, d));
            for (t, _) in &ts {
                let mut m = Mutation::new();
                m.set(*t, &value_ak(), &Value::Str("new".into())).unwrap();
                e.commit(m).unwrap();
            }
            ts
        });
        w.run();
        w.write(0, |e| {
            for (t, from) in &ts {
                let mut m = Mutation::new();
                strong(&mut m, *from, *t, false);
                e.commit(m).unwrap();
            }
        });
        w.run();
        for (t, _) in &ts {
            if w.engine(0).core.created(t).is_some() {
                panic!("released: {t:?} keeps its record\n{}", why_kept(w, 0, t));
            }
        }
        w.advance(1_000);
    }
    w.write(0, |e| {
        for (t, ak) in [(d, HOLDS.name()), (d, TICKETS.name()), (root, HOLDS.name())] {
            e.snapshot(&t, &ak).unwrap();
        }
    });
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    held(w, 0)
}

/// What a set removal's tombstone may add to the roots' snapshots, in their records (`c/`) and
/// in their blobs: spec/requirements.md Scale, a few bytes per removal (issues/storage-owners.md
/// 12: no cover can drop one).
const TOMBSTONE_BYTES: usize = 32;

/// `h` holds what a fresh node of the same account holds (`fresh`), after `removals` set
/// removals in the roots: every family's rows, but the schemas it learned (`d/`, the node's
/// own) and `cv/` (`handed`), the same count of blobs, and no more bytes than the removals'
/// tombstones add to the snapshot records (`c/`) and blobs. `cv/` holds at most one row per
/// held commit (one per held part dropped as covered whose coverer went: the trigger's
/// snapshots a fresh node never took); the caller checks it flat. On a mismatch the message
/// adds `explain` of the families that differ (`leaked`).
#[track_caller]
fn as_fresh(h: &Held, fresh: &Held, removals: usize, what: &str, explain: &mut dyn FnMut(&[String]) -> String) {
    let rest = |c: &Census| {
        let mut c = c.clone();
        c.remove("d/");
        c.remove("cv/");
        if let Some(x) = c.get_mut("c/") {
            x.1 = 0;
        }
        c
    };
    let snap = |c: &Census| c.get("c/").copied().unwrap_or_default();
    let tombs = removals * TOMBSTONE_BYTES;
    let differ = |side: &str, a: &Census, b: &Census| -> Vec<String> { a.keys().chain(b.keys()).filter(|k| a.get(*k) != b.get(*k)).map(|k| format!("{side} {k}")).collect() };
    if (rest(&h.0), &h.1) != (rest(&fresh.0), &fresh.1) {
        let fams: Vec<String> = differ("engine", &rest(&h.0), &rest(&fresh.0)).into_iter().chain(differ("store", &h.1, &fresh.1)).collect();
        assert_eq!((rest(&h.0), &h.1), (rest(&fresh.0), &fresh.1), "{what}: rows by family{}", explain(&fams));
    }
    if !(snap(&h.0).0 == snap(&fresh.0).0 && snap(&h.0).1 <= snap(&fresh.0).1 + tombs) {
        panic!("{what}: c/ {:?}, a fresh node's {:?}, {removals} removals{}", snap(&h.0), snap(&fresh.0), explain(&["engine c/".into()]));
    }
    if h.0.get("cv/").map_or(0, |x| x.0) > snap(&fresh.0).0 {
        panic!("{what}: cv/ {:?}{}", h.0.get("cv/"), explain(&["engine cv/".into()]));
    }
    for (d, (a, b)) in ["engine", "store"].iter().zip(h.2.iter().zip(&fresh.2)) {
        if !(a.0 == b.0 && a.1 <= b.1 + tombs as u64) {
            panic!("{what}: {d} blobs (count, bytes) {a:?}, a fresh node's {b:?}{}", explain(&["engine c/".into(), "engine bp/".into()]));
        }
    }
}

/// Debug builds: the rows of `families` (`"engine c/"`, `"store E/"`) node `i` of `w` holds and
/// node `j` of `base` (a fresh world's, same seed: the same roots) does not, each with its
/// decoded key, then why node `i` keeps each thing those rows name that no row of `base` names
/// (`World::rows`, `World::why_kept`; notes/test-harnesses.md, Why kept and row dumps).
#[cfg(debug_assertions)]
fn leaked(w: &mut World, i: usize, base: &mut World, j: usize, families: &[String]) -> String {
    use std::fmt::Write;
    let base_rows = base.rows(j, "", None);
    let keys: std::collections::BTreeSet<(&str, &[u8])> = base_rows.iter().map(|(d, r)| (*d, r.raw.as_slice())).collect();
    let base_tids: std::collections::BTreeSet<Tid> = base_rows.iter().flat_map(|(_, r)| r.tids.iter().copied()).collect();
    // rows of the families that differ and no row of `base` has, those naming a thing `base`
    // has no row naming first (commit IDs differ between the worlds: a row of a root's commit
    // has its own key at each)
    let (mut fresh_named, mut other) = (Vec::new(), Vec::new());
    for (d, r) in w.rows(i, "", None) {
        if families.contains(&format!("{d} {}", r.family)) && !keys.contains(&(d, r.raw.as_slice())) {
            match r.tids.iter().any(|t| !base_tids.contains(t)) {
                true => fresh_named.push((d, r)),
                false => other.push((d, r)),
            }
        }
    }
    let shown = if fresh_named.is_empty() { &other } else { &fresh_named };
    let mut out = format!("\nrows a fresh node lacks ({} naming a thing it has no row of, {} others):", fresh_named.len(), other.len());
    for (d, r) in shown.iter().take(60) {
        let names: Vec<String> = r.tids.iter().map(|t| t.to_string()).collect();
        let _ = write!(out, "\n  {d} {}{} ({} bytes), names [{}]", r.family, r.key, r.bytes, names.join(" "));
    }
    if shown.len() > 60 {
        let _ = write!(out, "\n  ... {} more", shown.len() - 60);
    }
    let tids: std::collections::BTreeSet<Tid> = shown.iter().flat_map(|(_, r)| r.tids.iter()).filter(|t| !base_tids.contains(t)).copied().collect();
    let _ = write!(out, "\nwhy kept:");
    for t in tids.iter().take(20) {
        let _ = write!(out, "\n{}", why_kept(w, i, t));
    }
    out
}

/// Debug builds: why node `i` keeps `t` (`World::why_kept`).
fn why_kept(w: &mut World, i: usize, t: &Tid) -> String {
    #[cfg(debug_assertions)]
    {
        w.why_kept(i, t)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = (w, i, t);
        String::new()
    }
}

#[cfg(not(debug_assertions))]
fn leaked(_: &mut World, _: usize, _: &mut World, _: usize, _: &[String]) -> String {
    String::new()
}

// Releasing everything, its own-things arm (issues/storage-owners.md), spec/sync-set.md §3 (Nothing of R stays): what a node makes under its account root, its account
// and its node root, written and then released, leaves its rows and blobs as a fresh node's of the
// same account once tombstones have aged out, at 2 and 20 rounds: but the roots' set tombstones,
// a few bytes per removal (three strongs and the keyed thing's ticket a round), and `cv/` (flat).
// A mismatch prints the rows a fresh node lacks and why each thing they name is kept (`leaked`:
// notes/test-harnesses.md, Why kept and row dumps).
#[test]
fn releasing_own_things_returns_storage_to_a_fresh_nodes_spec_sync_set_3() {
    let (mut wf, mut wa, mut wb) = (world(0, 1), world(0, 1), world(0, 1));
    let fresh = own_rounds(&mut wf, 0);
    let (a, b) = (own_rounds(&mut wa, 2), own_rounds(&mut wb, 20));
    as_fresh(&a, &fresh, 2 * 4, "2 rounds", &mut |f| leaked(&mut wa, 0, &mut wf, 0, f));
    as_fresh(&b, &fresh, 20 * 4, "20 rounds", &mut |f| leaked(&mut wb, 0, &mut wf, 0, f));
    assert_eq!(a.0.get("cv/"), b.0.get("cv/"), "cv/ flat");
}

/// Node 0 makes a thing under its account root D expiring a second later, held from D and
/// written in the same commit (a disappearing message), and lets it expire, `rounds` times; then
/// as `own_rounds` ends.
fn expiry_rounds(w: &mut World, rounds: usize) -> Held {
    use osis_schema::core_types::{HOLDS, TICKETS};
    let (root, d) = (w.engine(0).node_root().unwrap(), w.engine(0).account_root().unwrap());
    for _ in 0..rounds {
        let t = w.write(0, |e| {
            let at = osis_base::WallMs(e.now().0 + 1_000);
            let mut m = Mutation::new();
            let t = m.create(e.thing_record(d, Some(at)));
            m.op(d, &HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::Strong(t)) }).unwrap();
            m.set(t, &value_ak(), &Value::Str("brief".into())).unwrap();
            m.expires_all(at);
            e.commit(m).unwrap();
            t
        });
        w.run();
        w.advance(2_000);
        w.run();
        assert!(!w.engine(0).knows(&t), "expired");
    }
    w.write(0, |e| {
        for (t, ak) in [(d, HOLDS.name()), (d, TICKETS.name()), (root, HOLDS.name())] {
            e.snapshot(&t, &ak).unwrap();
        }
    });
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    held(w, 0)
}

// S1, its expiry arm, spec/commits.md §5 (Destruction: a thing goes by ordinary expiry at its
// record's; Forgetting: a part not held on a thing whose record is not held, a forgotten name
// past its expiry), spec/requirements.md (data may carry an expiry at which every node drops it):
// a thing made to expire with its holding strong, written and expired, leaves its rows and blobs
// as a fresh node's of the same account, at 2 and 20 rounds: but the expired strongs in D's
// snapshot, a few bytes each.
#[test]
fn expired_things_return_storage_to_a_fresh_nodes_spec_commits_5() {
    let (mut wf, mut wa, mut wb) = (world(0, 1), world(0, 1), world(0, 1));
    let fresh = expiry_rounds(&mut wf, 0);
    let (a, b) = (expiry_rounds(&mut wa, 2), expiry_rounds(&mut wb, 20));
    // each expired strong stays in D's holds.0 snapshot as its value-less record (notes/crdt.md,
    // An expired set element keeps its record), about two removals' tombstones of bytes
    as_fresh(&a, &fresh, 2 * 2, "2 rounds", &mut |f| leaked(&mut wa, 0, &mut wf, 0, f));
    as_fresh(&b, &fresh, 2 * 20, "20 rounds", &mut |f| leaked(&mut wb, 0, &mut wf, 0, f));
}

/// Node 0 makes A under its account root, keeping 10 minutes of history whose strongs hold
/// their targets (`history_holds_targets`), and B, held by A alone: A's strong to B is removed
/// (B held by A's history), then the root's to A. `rounds` times; then as `own_rounds` ends.
fn history_rounds(w: &mut World, rounds: usize) -> Held {
    use osis_schema::core_types::{self as ct, HOLDS, TICKETS};
    let (root, d) = (w.engine(0).node_root().unwrap(), w.engine(0).account_root().unwrap());
    let strong = |m: &mut Mutation, from: Tid, to: Tid, on: bool| {
        let v = Value::Strong(to);
        let op = if on { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
        m.op(from, &HOLDS, osis_crdt::PathOp { path: vec![], op }).unwrap();
    };
    let keep = osis_schema::History::Keep { until: None, after: Some(10 * 60_000) };
    let setting = ct::RetentionSetting { default: Some(ct::RetentionEntry { history: Some(keep), ..Default::default() }), history_holds_targets: true, ..Default::default() };
    for _ in 0..rounds {
        let (a, b) = w.write(0, |e| {
            let mut m = Mutation::new();
            let a = m.create(e.thing_record(d, None));
            strong(&mut m, d, a, true);
            e.commit(m).unwrap();
            let mut m = Mutation::new();
            m.set(a, &ct::RETENTION, &setting).unwrap();
            e.commit(m).unwrap();
            let mut m = Mutation::new();
            let b = m.create(e.thing_record(d, None));
            strong(&mut m, a, b, true);
            e.commit(m).unwrap();
            let mut m = Mutation::new();
            m.set(b, &value_ak(), &Value::Str("new".into())).unwrap();
            e.commit(m).unwrap();
            let mut m = Mutation::new();
            strong(&mut m, a, b, false);
            e.commit(m).unwrap();
            (a, b)
        });
        w.run();
        assert!(w.engine(0).closure_holds(&b), "B held by A's history");
        w.write(0, |e| {
            let mut m = Mutation::new();
            strong(&mut m, d, a, false);
            e.commit(m).unwrap();
        });
        w.run();
        for t in [a, b] {
            if w.engine(0).core.created(&t).is_some() {
                panic!("released: {t:?} keeps its record\n{}", why_kept(w, 0, &t));
            }
        }
        w.advance(1_000);
    }
    w.write(0, |e| {
        for (t, ak) in [(d, HOLDS.name()), (d, TICKETS.name()), (root, HOLDS.name())] {
            e.snapshot(&t, &ak).unwrap();
        }
    });
    w.run();
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    held(w, 0)
}

// Releasing everything, its history arm, spec/data-model.md §8 What counts, spec/sync-set.md
// §3: a thing whose history holds its strongs' targets, released with what only its history
// held, leaves its rows and blobs as a fresh node's, at 2 and 20 rounds: but the root's set
// tombstones (one removal a round).
#[test]
fn releasing_held_history_returns_storage_to_a_fresh_nodes_spec_data_model_8() {
    let (mut wf, mut wa, mut wb) = (world(0, 1), world(0, 1), world(0, 1));
    let fresh = own_rounds(&mut wf, 0);
    let (a, b) = (history_rounds(&mut wa, 2), history_rounds(&mut wb, 20));
    as_fresh(&a, &fresh, 2, "2 rounds", &mut |f| leaked(&mut wa, 0, &mut wf, 0, f));
    as_fresh(&b, &fresh, 20, "20 rounds", &mut |f| leaked(&mut wb, 0, &mut wf, 0, f));
    assert_eq!(a.0.get("cv/"), b.0.get("cv/"), "cv/ flat");
}

/// Each node's roots snapshotted (`own_rounds`), then the inbox lifetime, the role keep and the
/// tombstone lifetime and two days: what each node holds.
fn settled(w: &mut World) -> Vec<Held> {
    use osis_base::format::{INBOX_LIFETIME_MS, ROLE_KEEP_MS};
    use osis_schema::core_types::{HOLDS, TICKETS};
    for i in 0..w.len() {
        let (root, d) = (w.engine(i).node_root().unwrap(), w.engine(i).account_root().unwrap());
        w.write(i, |e| {
            for (t, ak) in [(d, HOLDS.name()), (d, TICKETS.name()), (root, HOLDS.name())] {
                e.snapshot(&t, &ak).unwrap();
            }
        });
    }
    w.run();
    w.advance(INBOX_LIFETIME_MS.max(ROLE_KEEP_MS) + TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    (0..w.len()).map(|i| held(w, i)).collect()
}

/// Node 0 makes a thing under its account root, writes it, and gives node 1's account read on
/// it: node 1 accepts (`accept`, a strong from its account root) or declines (no accept, the
/// fire left in its inbox); node 0 writes again, removes node 1's account, and both let the thing
/// go (node 0 its strong, node 1 its accept). `rounds` times; then `settled`.
fn grant_rounds(rounds: usize, accept: bool) -> (World, Vec<Held>) {
    use crate::harness::history::Holder;
    let mut w = world(0, 2);
    w.cap = 2_000_000;
    for k in 0..rounds {
        let give = if accept { Grant(0, k, 1, Gives::Reads) } else { Give(0, k, Holder::Node(1), Gives::Reads) };
        let mut steps = vec![New(0), Write(0, k), give, Run, Write(0, k), Run, Remove(0, k, 1), Run];
        if accept {
            steps.push(Unstrong(1, None, k));
        }
        steps.extend([Unstrong(0, None, k), Run]);
        let _ = play(&mut w, &steps, String::new());
        w.advance(1_000);
    }
    let held = settled(&mut w);
    (w, held)
}

/// `grant_rounds` at 2 and 20 rounds: each node as a fresh world's (`as_fresh`), each round's
/// set removals at most `removals` a node.
fn grants_as_fresh(accept: bool, removals: usize) {
    let (mut wf, fresh) = grant_rounds(0, accept);
    let ((mut wa, a), (mut wb, b)) = (grant_rounds(2, accept), grant_rounds(20, accept));
    for (i, who) in ["the maker", "the grantee"].iter().enumerate() {
        as_fresh(&a[i], &fresh[i], 2 * removals, &format!("{who}, 2 rounds"), &mut |f| leaked(&mut wa, i, &mut wf, i, f));
        as_fresh(&b[i], &fresh[i], 20 * removals, &format!("{who}, 20 rounds"), &mut |f| leaked(&mut wb, i, &mut wf, i, f));
        assert_eq!(a[i].0.get("cv/"), b[i].0.get("cv/"), "{who}: cv/ flat");
    }
}

// Releasing everything, its grant, fire, accept and revoke arm (issues/storage-owners.md),
// spec/sync-set.md §3: a thing granted to another account, its fire accepted, written,
// the grantee removed and both sides letting it go, leaves each node as a fresh world's once the
// inbox lifetime, the role keep and tombstones have passed, at 2 and 20 rounds.
#[test]
fn a_granted_and_revoked_thing_returns_storage_to_a_fresh_worlds_spec_sync_set_3() {
    grants_as_fresh(true, 4);
}

// S1, its decline arm (spec/sync-set.md §4 (Declining)): as the grant arm, the fire never accepted.
#[test]
fn a_declined_grant_returns_storage_to_a_fresh_worlds_spec_sync_set_3() {
    grants_as_fresh(false, 4);
}

// spec/sync-judgement.md §3 (Restart and forgetting: an own entry logs a commit held here),
// spec/sync-set.md §3 (Nothing of R stays): node 0 makes a thing with own keys under its
// account, held from D, and releases it; no own entry of a commit forgotten then stays under any
// sync ID, D's included (its creation commit's and role commit's certificate copies there, which
// go once nothing held needs the thing).
#[test]
fn a_released_things_forgotten_commits_leave_no_own_entry_spec_sync_judgement_3() {
    use osis_schema::core_types::HOLDS;
    let mut w = world(0, 1);
    let d = w.engine(0).account_root().unwrap();
    let p = w.engine(0).account().unwrap().unwrap().0;
    let t = w.write(0, |e| {
        let t = e.create_with_admin(&p).unwrap().0;
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    w.run();
    let ds = w.engine(0).sync_id_of(&d).unwrap().unwrap();
    // the own entries of commits with a part on t, under every sync ID
    let mut logged = Vec::new();
    for (s, _) in w.store(0).syncs() {
        for e in w.store(0).entries(&s).unwrap() {
            let on_t = w.engine(0).blob_of(&e.blob).and_then(|x| w.engine(0).header(&x.commit)).is_some_and(|h| h.aspects.iter().any(|a| a.tid == t));
            if e.own && on_t {
                logged.push((s, e.blob));
            }
        }
    }
    assert!(logged.iter().any(|(s, _)| *s == ds), "a commit on the thing is logged under D's sync ID");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.op(d, &HOLDS, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Remove(Value::Strong(t)) }).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert!(w.engine(0).core.created(&t).is_none(), "released");
    let forgotten: Vec<_> = logged.iter().filter(|(_, b)| w.engine(0).blob_of(b).is_none()).collect();
    assert!(forgotten.iter().any(|(s, _)| *s == ds), "a commit logged under D's sync ID is forgotten");
    for (s, b) in forgotten {
        assert!(w.store(0).entry(s, b).unwrap().is_none(), "an own entry of a forgotten commit under {s:?}");
    }
}



/// Nodes 0, 1 and 2 write thing 0, node 3 keeps its sync ID S unread; S and the records it
/// carries.
fn record_world() -> (World, osis_base::SyncId, std::collections::BTreeSet<Tid>) {
    let mut w = world(0, 4);
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Writes), Grant(0, 0, 2, Gives::Writes), Grant(0, 0, 3, Gives::Syncs), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let records: std::collections::BTreeSet<Tid> = w.engine(0).certificate_records(&s).unwrap().iter().copied().collect();
    assert!(!records.is_empty(), "S carries records");
    (w, s, records)
}

/// `rounds` rounds of nodes 0, 1 and 2, the writers of thing 0, each sealing a record blob of
/// S's records at once, its own store holding no other (as each logs one before it holds
/// another's); then node 3's entries under S, which it keeps unread.
fn record_rounds(rounds: usize) -> usize {
    let (mut w, s, records) = record_world();
    for round in 0..rounds {
        for i in 0..3 {
            let noted = w.engine(i).cert_blobs(&s, None);
            for b in noted.keys() {
                w.store(i).clone().unlog_entry(&s, b).unwrap();
            }
            let mut rng = osis_crypto::SeededRng::from_u64((round * 3 + i) as u64);
            let (blob, bytes, wrap) = w.engine(i).seal_records(&s, &records, &mut rng).unwrap().expect("sealed");
            let e = osis_sync::types::Entry { blob, wrap, stamp: None, deposited: false, own: true, role: false, class: osis_blob::Class::Durable, expires: None };
            w.store(i).clone().log(&s, e, Some(bytes), None).unwrap();
        }
        for i in 0..3 {
            w.deliver(i, osis_sync::Input::Tick);
        }
        w.run();
    }
    w.store(3).entries(&s).unwrap().len()
}

// spec/sync-ids.md §6 (Delete: a record or list blob losing to another there is deleted at a
// store once it shows the winner), spec/permissions.md §4 (Logging certificates): writers each
// logging a record blob of the same records every round leave a store keeping S unread holding
// as many entries at n rounds as at 10n.
#[test]
fn record_blobs_at_a_store_stay_flat_spec_sync_ids_6() {
    let (n, ten_n) = (record_rounds(1), record_rounds(10));
    assert_eq!(n, ten_n, "store entries at 1 and 10 rounds");
}
