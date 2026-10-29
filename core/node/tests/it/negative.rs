#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention bounds a compactor must not cross (spec/commits.md §5), through a blind node.

use crate::net;
use net::*;
use osis_base::{Ak, Value};
use osis_node::Mutation;
use osis_schema::AspectKey;

static KEEP: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "keep.osis",
    r#"
schema 0x0123456789abcdef0123456789abcd01;
revision 1;
aspect /k/kept: string [by: writer, keep_at_least: 1d];
aspect /k/short: string [by: writer, keep_at_most: 10m];
"#,
);
const KEPT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/k/kept", &KEEP);
const SHORT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/k/short", &KEEP);

// spec/commits.md §5 (keep at least): a compaction before the bound neither drops the covered
// bodies nor deletes them at the blind node; once the bound has passed (by MAX_DRIFT) it does both.
#[test]
fn compaction_keeps_bodies_until_keep_at_least_spec_commits_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let g = net.group(a, &[], &[sv]);
    let t = net.item(a, g, g, "x");
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
    let at = net.server_ids(sv, &l);
    assert!(dead.iter().all(|id| at.contains(id)), "deleted at the blind node before the bound");
    // compaction waits MAX_DRIFT past the bound (spec/sync.md §7)
    net.advance(86_400_000 + osis_base::format::MAX_DRIFT_MS);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    for c in &bodies[..2] {
        assert!(!net.engine(a).body_not_dropped(c, &t, &ak), "covered body past its bound kept");
    }
    let at = net.server_ids(sv, &l);
    assert!(dead.iter().all(|id| !at.contains(id)), "covered bodies past the bound left at the blind node");
    assert_eq!(net.engine(a).get(&t, &ak).unwrap(), Some(s("v3")));
}

/// Deletions in server `sv`'s log of label `l`.
fn deletions(net: &Net, sv: usize, l: &osis_base::LabelId) -> usize {
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.servers[sv].hub.store().log_after(l, 0, 1 << 20).unwrap().unwrap_or_default();
    recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(_))).count()
}

/// Two writers, one with its corrected clock `MAX_DRIFT` ahead (its median offset counts a
/// second server that far ahead), compact two dead bodies and pass their keep-at-least bound.
/// Returns the server's log deletions over the crossing and how many blobs of those bodies
/// either node knew.
fn compact_across_skew(a_ahead: bool) -> (usize, usize) {
    let mut net = Net::new();
    let sv = net.add_server();
    let sk = net.add_server();
    net.servers[sk].skew = osis_base::format::MAX_DRIFT_MS as i64;
    let (fast, slow): (&[usize], &[usize]) = (&[sv, sk], &[sv]);
    let a = net.node(1, if a_ahead { fast } else { slow });
    let b = net.node(2, if a_ahead { slow } else { fast });
    let g = net.group(a, &[(b, osis_base::Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
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
    let before = deletions(&net, sv, &l);
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
    (deletions(&net, sv, &l) - before, seen.len())
}

// spec/sync.md §7 (compaction waits MAX_DRIFT past keep-at-least): two right holders whose
// corrected clocks differ by MAX_DRIFT, either way, cross a keep-at-least bound: the two dead
// bodies are deleted at the server once each and nobody places them again (the node past the
// bound used to delete what the other, still before it, placed again as must-hold).
#[test]
fn compaction_across_skew_no_churn_spec_sync_7() {
    for a_ahead in [true, false] {
        assert_eq!(compact_across_skew(a_ahead), (2, 2), "a ahead {a_ahead}: deletions, blobs of the dead bodies");
    }
}

// spec/commits.md §5 (deaths dated per node), spec/sync.md §6: X < Y < Z on a kept register
// and on a keep-at-most-10m one; right holder A held Y before Z (X dies at Y), B held Z before Y
// (X dies at Z, two hours later). Once A's bound has passed it deletes X at the blind node
// (kept: covered by its compaction; at most: a timed delete); B, still before its own bound,
// does not place it again (it has no live write): one deletion, no fresh encryption, and B
// drops it by its own bound.
#[test]
fn deletion_across_local_dating_no_churn_spec_sync_6() {
    for at_most in [false, true] {
        assert_eq!(local_dating_churn(at_most), (1, 1), "at most {at_most}: deletions, blobs of X");
    }
}

/// The scenario of `deletion_across_local_dating_no_churn_*`: the server's deletions of X's
/// blobs and how many blobs of X either node knew.
fn local_dating_churn(at_most: bool) -> (usize, usize) {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    let g = net.group(a, &[(b, osis_base::Role::Write), (c, osis_base::Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    let k = if at_most { &SHORT } else { &KEPT };
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
    let (ty, tz) = (ts(&mut net, &y), ts(&mut net, &z));
    assert_eq!(net.engine(a).deaths(&x, &t, &ak).unwrap(), Some((ty, ty)));
    assert_eq!(net.engine(b).deaths(&x, &t, &ak).unwrap(), Some((tz, tz)));
    for n in [a, b, c] {
        net.set_online(n, true);
    }
    net.run();
    if !at_most {
        let acts = net.sync(a).compact(&t, &ak).unwrap();
        net.actions(a, acts);
        net.run();
    }
    // 5 min steps from before A's bound (at most: passed offline) to past B's
    let bound = if at_most { net.now() } else { ty.wall_ms().0 + 86_400_000 + osis_base::format::MAX_DRIFT_MS - 10 * 60_000 };
    net.advance(bound.saturating_sub(net.now()));
    for _ in 0..30 {
        look(&mut net, &mut seen);
        net.advance(5 * 60_000);
    }
    assert!(!net.engine(a).body_not_dropped(&x, &t, &ak), "A past its bound");
    assert!(!net.engine(b).body_not_dropped(&x, &t, &ak), "B past its bound");
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.servers[sv].hub.store().log_after(&l, 0, 1 << 20).unwrap().unwrap_or_default();
    let of_x = recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(id) if seen.contains(id))).count();
    (of_x, seen.len())
}
