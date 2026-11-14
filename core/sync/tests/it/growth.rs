//! Growth with the number of writes (spec/requirements.md Scale; notes/growth.md): what a
//! writer, a reader and a node keeping S unread store, counted at n and 10n writes, never timed. Node 0 makes thing 0; node 1's account syncs it (kept unread), node 2's
//! reads it (`writers`: writes it too).

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{Tid, Value};
use osis_engine::Mutation;
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

/// No more rows of any kind at 10n than at n, nor blobs (a few bytes for a counter that
/// widened).
#[track_caller]
fn flat(a: &[Held], b: &[Held]) {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        for (d, p, q) in [("engine", &x.0, &y.0), ("store", &x.1, &y.1)] {
            let bytes = |c: &Census| c.values().map(|v| v.1).sum::<usize>();
            let fewer = q.iter().all(|(k, v)| v.0 <= p.get(k).map_or(0, |x| x.0));
            assert!(fewer && bytes(q) <= bytes(p) + 64, "node {i} {d}: rows by kind (count, bytes) {p:?} at n, {q:?} at 10n");
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
