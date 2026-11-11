#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention bounds a compactor must not cross (spec/commits.md §5), through a host.

use crate::net::{hosted, hosted_nodes};
use crate::net;
use net::*;
use osis_base::{Ak, Value};
use osis_node::Mutation;
use osis_schema::RawKey;

static KEEP: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "keep.osis",
    r#"
revision 1;
purgeable_by(writer) aspect k:kept.0: string;
"#,
);
const KEPT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("k:kept.0", &KEEP);
/// What the tests' things keep (their setting): a day after replaced.
const DAY: osis_schema::History = crate::common::DAY;

// spec/commits.md §5 (keep at least): a compaction before the bound neither drops the covered
// bodies nor deletes them at the host; once the bound has passed it drops them, and deletes them
// at the host once it is MAX_DRIFT past (host delete margin).
#[test]
fn compaction_keeps_bodies_until_keep_at_least_spec_commits_5() {
    let (mut net, host, [a], _g, [t]) = hosted::<1, 1>(&[], ["x"], false);
    net.keep(a, t, &[("k:kept.0", DAY)]);
    let mut bodies = Vec::new();
    for v in ["v1", "v2", "v3"] {
        let mut m = Mutation::new();
        m.set(t, &KEPT, &s(v)).unwrap();
        bodies.push(net.engine(a).commit(m).unwrap().unwrap());
        net.advance(1_000);
    }
    net.run();
    let l = net.label(a);
    let ak = Ak::new(KEPT.ak()).unwrap();
    // the blobs carrying the two dead bodies
    let dead: Vec<osis_base::BlobId> = net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
        osis_node::sync::EntryKind::Commit { commit, .. } if bodies[..2].contains(&commit) => Some(id),
        _ => None,
    }).collect();
    assert!(dead.len() >= 2);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    for c in &bodies[..2] {
        assert!(net.engine(a).body_not_dropped(c, &t, &ak), "dead body dropped before its keep-at-least bound");
    }
    let at = net.host_ids(host, &l);
    assert!(dead.iter().all(|id| at.contains(id)), "deleted at the host before the bound");
    // the host delete waits MAX_DRIFT past the bound (spec/sync.md §7)
    net.advance(86_400_000 + osis_base::format::MAX_DRIFT_MS);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    for c in &bodies[..2] {
        assert!(!net.engine(a).body_not_dropped(c, &t, &ak), "covered body past its bound kept");
    }
    let at = net.host_ids(host, &l);
    assert!(dead.iter().all(|id| !at.contains(id)), "covered bodies past the bound left at the host");
    assert_eq!(net.engine(a).get(&t, &ak).unwrap(), Some(s("v3")));
}

/// Deletions in host `host`'s log of label `l`.
fn deletions(net: &Net, host: usize, l: &osis_base::LabelId) -> usize {
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.hosts[host].hub.store().log_after(l, 0, 1 << 20).unwrap().unwrap_or_default();
    recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(_))).count()
}

/// Two writers, one with its clock `MAX_DRIFT` ahead, compact two dead bodies and pass their
/// keep-at-least bound. Returns the host's log deletions over the crossing and how many blobs of
/// those bodies either node knew.
fn compact_across_skew(a_ahead: bool) -> (usize, usize) {
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    net.set_skew(if a_ahead { a } else { b }, osis_base::format::MAX_DRIFT_MS as i64);
    let g = net.group(a, &[(b, osis_base::Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[("k:kept.0", DAY)]);
    let mut bodies = Vec::new();
    for v in ["v1", "v2", "v3"] {
        let mut m = Mutation::new();
        m.set(t, &KEPT, &s(v)).unwrap();
        bodies.push(net.engine(a).commit(m).unwrap().unwrap());
        net.advance(1_000);
    }
    net.run();
    let ak = Ak::new(KEPT.ak()).unwrap();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    let l = net.label(a);
    let before = deletions(&net, host, &l);
    let mut seen = std::collections::BTreeSet::new();
    net.advance(86_400_000 - 3 * 3_600_000);
    // 5 min steps from 3 h before the bound to 3 h after it
    for _ in 0..72 {
        net.advance(5 * 60_000);
        for n in [a, b] {
            for (id, k) in net.sync(n).entries(&l) {
                if matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if bodies[..2].contains(&commit)) {
                    seen.insert(id);
                }
            }
        }
    }
    for n in [a, b] {
        for c in &bodies[..2] {
            assert!(!net.engine(n).body_not_dropped(c, &t, &ak), "node {n}: covered body past its bound kept");
        }
        assert_eq!(net.engine(n).get(&t, &ak).unwrap(), Some(s("v3")));
    }
    // the dead bodies' blobs only
    let _ = before;
    (deletions_of(&net, host, &l, &seen), seen.len())
}

// spec/sync.md §7, spec/commits.md §5 (host delete margin): two right holders whose
// clocks differ by MAX_DRIFT, either way, cross a keep-at-least bound: the two dead
// bodies are deleted at the host once each and nobody places them again (the node past the
// bound used to delete what the other, still before it, placed again as must-hold).
#[test]
fn compaction_across_skew_no_churn_spec_sync_7() {
    for a_ahead in [true, false] {
        assert_eq!(compact_across_skew(a_ahead), (2, 2), "a ahead {a_ahead}: deletions, blobs of the dead bodies");
    }
}

/// Deletions in host `host`'s log of label `l` of the blobs in `of`.
fn deletions_of(net: &Net, host: usize, l: &osis_base::LabelId, of: &std::collections::BTreeSet<osis_base::BlobId>) -> usize {
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.hosts[host].hub.store().log_after(l, 0, 1 << 20).unwrap().unwrap_or_default();
    recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(id) if of.contains(id))).count()
}

// spec/commits.md §5 (replaced, from the held set), spec/sync.md §6: X < Y < Z on a kept
// register; right holder A held Y before Z, B held Z before Y: both date X at Y (arrival order
// does not matter). Once the bound has passed A deletes X at the host (covered by its
// compaction); B does not place it again (A's snapshot covers it): one deletion, no fresh
// encryption, and B drops it by its bound.
#[test]
fn deletion_across_local_dating_no_churn_spec_sync_6() {
    assert_eq!(local_dating_churn(), (1, 1), "deletions, blobs of X");
}

/// The scenario of `deletion_across_local_dating_no_churn_*`: the host's deletions of X's
/// blobs and how many blobs of X either node knew.
fn local_dating_churn() -> (usize, usize) {
    let (mut net, host, [a, b, c]) = hosted_nodes::<3>();
    let g = net.group(a, &[(b, osis_base::Role::Write), (c, osis_base::Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[("k:kept.0", DAY)]);
    let k = &KEPT;
    let set = |net: &mut Net, n: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(t, k, &s(v)).unwrap();
        net.engine(n).commit(m).unwrap().unwrap()
    };
    let x = set(&mut net, a, "x");
    net.run();
    let l = net.label(a);
    let mut seen = std::collections::BTreeSet::new();
    let look = |net: &mut Net, seen: &mut std::collections::BTreeSet<osis_base::BlobId>| {
        for n in [a, b] {
            for (id, k) in net.sync(n).entries(&l) {
                if matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == x) {
                    seen.insert(id);
                }
            }
        }
    };
    look(&mut net, &mut seen);
    for n in [a, b, c] {
        net.set_online(n, false);
    }
    net.advance(1_000);
    let y = set(&mut net, c, "y");
    let py = net.engine(c).package(&y).unwrap().unwrap();
    net.engine(a).ingest(&py.bytes, py.blobs.clone()).unwrap();
    net.advance(2 * 3_600_000);
    let z = set(&mut net, a, "z");
    let pz = net.engine(a).package(&z).unwrap().unwrap();
    net.engine(b).ingest(&pz.bytes, pz.blobs.clone()).unwrap();
    net.engine(b).ingest(&py.bytes, py.blobs.clone()).unwrap();
    let ak = Ak::new(k.ak()).unwrap();
    let ts = |net: &mut Net, c: &osis_base::CommitId| net.engine(a).header(c).unwrap().ts;
    let ty = ts(&mut net, &y);
    assert_eq!(net.engine(a).replaced_at(&x, &t, &ak).unwrap(), Some(ty));
    assert_eq!(net.engine(b).replaced_at(&x, &t, &ak).unwrap(), Some(ty));
    for n in [a, b, c] {
        net.set_online(n, true);
    }
    net.run();
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    // 5 min steps from before A's bound to past B's
    let bound = ty.wall_ms().0 + 86_400_000 + osis_base::format::MAX_DRIFT_MS - 10 * 60_000;
    net.advance(bound.saturating_sub(net.now()));
    for _ in 0..30 {
        look(&mut net, &mut seen);
        net.advance(5 * 60_000);
    }
    assert!(!net.engine(a).body_not_dropped(&x, &t, &ak), "A past its bound");
    assert!(!net.engine(b).body_not_dropped(&x, &t, &ak), "B past its bound");
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.hosts[host].hub.store().log_after(&l, 0, 1 << 20).unwrap().unwrap_or_default();
    let of_x = recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(id) if seen.contains(id))).count();
    (of_x, seen.len())
}

