//! Retention across nodes (spec/commits.md §5 Keep at least): a body in history leaves no node by
//! compaction, and right holders delete it at a node keeping S unread only `MAX_DRIFT` after it
//! left history. Node 0 (admin) keeps thing 0's value an hour after replaced; node 1's account
//! syncs it (kept unread), node 2's reads.

use crate::harness::Step::*;
use crate::harness::history::{Gives, value_ak, world};
use crate::harness::{World, play};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{BlobId, CommitId, SyncId, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

const HOUR_MS: u64 = 3_600_000;

/// Thing 0 with its value kept an hour after replaced, written ("one", returned), replaced and
/// covered by node 0's snapshot, synced.
fn covered_in_history() -> (World, Tid, SyncId, CommitId) {
    let mut w = world(0, 3);
    w.cap = 20_000;
    // `run` looks a minute ahead, never to the keep bound: only `advance` passes it
    w.horizon_ms = 60_000;
    let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    let keep: ct::RetentionSetting = [(value_ak(), ct::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() })].into_iter().collect();
    let set = |w: &mut World, v: &str| {
        w.write(0, |e| {
            let mut m = Mutation::new();
            m.set(t, &value_ak(), &Value::Str(v.into())).unwrap();
            e.commit(m).unwrap().unwrap()
        })
    };
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(t, &ct::RETENTION, &keep).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    let one = set(&mut w, "one");
    w.run();
    w.advance(10);
    set(&mut w, "two");
    w.write(0, |e| e.snapshot(&t, &value_ak())).unwrap().expect("a snapshot");
    w.run();
    (w, t, s, one)
}

fn entries_of(w: &mut World, i: usize, s: &SyncId, c: &CommitId) -> Vec<BlobId> {
    let es = w.store(i).entries(s).unwrap();
    es.into_iter().filter(|e| w.engine(0).blob_commit(&e.blob).ok().flatten() == Some(*c)).map(|e| e.blob).collect()
}

// spec/commits.md §5 (keep at least): before a body leaves history it leaves a node only by purge
// request, expiry or as invalid: compaction does not drop it. A replaced value kept an hour, under
// a snapshot covering it, is still held at the writer, a reader and the node keeping S unread
// half an hour on.
#[test]
fn a_covered_body_in_history_stays_everywhere_spec_commits_5() {
    let (mut w, t, s, one) = covered_in_history();
    w.advance(HOUR_MS / 2);
    w.run();
    for i in [0, 2] {
        assert!(w.engine(i).body_not_dropped(&one, &t, &value_ak()), "node {i} dropped a body in history");
    }
    assert!(!entries_of(&mut w, 1, &s, &one).is_empty(), "node 1 lost a body in history");
}

// spec/commits.md §5 (unread delete margin): right holders do not delete a body at a peer keeping
// it unread before `MAX_DRIFT` past its leaving history, on their clock. Past the hour (out of
// history) and within the margin, node 1 still holds it, while the writer and the reader, whose
// own entries follow the keep bound alone, dropped theirs.
#[test]
fn a_body_out_of_history_stays_at_a_node_keeping_it_unread_for_the_margin_spec_commits_5() {
    let (mut w, _, s, one) = covered_in_history();
    w.advance(HOUR_MS + MAX_DRIFT_MS / 2);
    w.run();
    for i in [0, 2] {
        assert!(entries_of(&mut w, i, &s, &one).is_empty(), "node {i}: its entry outlived the keep bound");
    }
    assert!(!entries_of(&mut w, 1, &s, &one).is_empty(), "deleted at node 1 within MAX_DRIFT of leaving history");
}

// spec/commits.md §5 (Keep bounds; Covered), spec/sync-judgement.md §3 (covered and dropped), spec/sync.md §2:
// a covered body leaves the stores once out of history and past the margin, by time alone: no
// later write moves it.
#[test]
fn repro_a_covered_body_leaves_by_time_alone_spec_commits_5() {
    let (mut w, _, s, one) = covered_in_history();
    w.advance(HOUR_MS + MAX_DRIFT_MS + 60_000);
    w.run();
    for i in 0..3 {
        assert!(entries_of(&mut w, i, &s, &one).is_empty(), "node {i} still holds the covered body's entry");
    }
}

