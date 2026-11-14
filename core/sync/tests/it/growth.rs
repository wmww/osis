//! Growth with the number of writes (spec/requirements.md Scale; notes/growth.md; issues/zero-growth.md):
//! stored rows and bytes at a writer, a reader and a node keeping S unread, counted at n and 10n
//! writes, never timed. Node 0 makes thing 0; node 1's account syncs it (kept unread), node 2's
//! reads it (`writers`: writes it too).

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{Tid, Value};
use osis_engine::Mutation;

const DAY_MS: u64 = 86_400_000;

fn setup(gives: Gives) -> (World, Tid) {
    let mut w = world(0, 3);
    w.cap = 200_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, gives), Run], String::new());
    let t = w.history.things[0].0;
    (w, t)
}

/// Writes `from..to` by the nodes `by` in turn, each a whole replace of t's value, a second
/// apart, then a run and the tombstone lifetime plus two days with no writes: what each node's
/// disks hold then.
fn at(w: &mut World, t: Tid, by: &[usize], from: usize, to: usize) -> Vec<[(u64, u64, u64, u64); 2]> {
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
    w.advance(TOMBSTONE_LIFETIME_MS + 2 * DAY_MS);
    w.run();
    (0..3).map(|i| w.disk_use(i)).collect()
}

/// Rows and bytes equal at n and 10n (a few bytes for a counter that widened).
#[track_caller]
fn flat(a: &[[(u64, u64, u64, u64); 2]], b: &[[(u64, u64, u64, u64); 2]]) {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        for (d, (p, q)) in ["engine", "store"].iter().zip(x.iter().zip(y)) {
            assert!(q.0 <= p.0 && q.1 <= p.1 + 64 && q.2 <= p.2 && q.3 <= p.3 + 64, "node {i} {d}: (rows, row bytes, blobs, blob bytes) {p:?} at n, {q:?} at 10n");
        }
    }
}

fn grows_nothing(gives: Gives, by: &[usize]) {
    let (mut w, t) = setup(gives);
    at(&mut w, t, by, 0, 0);
    let n = at(&mut w, t, by, 0, 6);
    let n10 = at(&mut w, t, by, 6, 60);
    for i in [0, 2] {
        assert_eq!(w.engine(i).get(&t, &value_ak()).unwrap(), Some(Value::Str("v00000059".into())), "node {i} reads the newest");
    }
    flat(&n, &n10);
}

// spec/commits.md §5 Own replaces and Forgetting, spec/requirements.md Scale: one writer replacing
// one register 6 and 60 times stores the same rows and bytes at the writer, a reader and a node
// keeping S unread once tombstones have aged out.
#[test]
#[ignore = "issues/zero-growth.md"]
fn repro_single_writer_replace_grows_nothing_spec_commits_5() {
    grows_nothing(Gives::Reads, &[0]);
}

// spec/commits.md §5 Covered and Forgetting, spec/sync-compaction.md §1 (trigger): two writers
// replacing one register in turn store the same at 6 and 60 writes (automatic compaction covers
// the other's writes).
#[test]
#[ignore = "issues/zero-growth.md"]
fn repro_several_writers_grow_nothing_spec_commits_5() {
    grows_nothing(Gives::Writes, &[0, 2]);
}
