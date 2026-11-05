#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention bounds a compactor must not cross (spec/commits.md §5), through a host.

use crate::net;
use net::*;
use osis_base::{Ak, Value};
use osis_node::Mutation;
use osis_schema::AspectKey;

static KEEP: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "keep.osis",
    r#"
version 1;
aspect k:kept.0: string [by: writer, keep_at_least: 1d];
aspect k:admin.0: string [by: admin, keep_at_least: 1d];
"#,
);
const KEPT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("k:kept.0", &KEEP);
const ADMIN_KEPT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("k:admin.0", &KEEP);

// spec/commits.md §5 (keep at least): a compaction before the bound neither drops the covered
// bodies nor deletes them at the host; once the bound has passed (by MAX_DRIFT) it does both.
#[test]
fn compaction_keeps_bodies_until_keep_at_least_spec_commits_5() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
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
    let at = net.host_ids(host, &l);
    assert!(dead.iter().all(|id| at.contains(id)), "deleted at the host before the bound");
    // compaction waits MAX_DRIFT past the bound (spec/sync.md §7)
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

/// Two writers, one with its corrected clock `MAX_DRIFT` ahead (its median offset counts a
/// second host that far ahead), compact two dead bodies and pass their keep-at-least bound.
/// Returns the host's log deletions over the crossing and how many blobs of those bodies
/// either node knew.
fn compact_across_skew(a_ahead: bool) -> (usize, usize) {
    let mut net = Net::new();
    let host = net.add_host();
    let sk = net.add_host();
    net.hosts[sk].skew = osis_base::format::MAX_DRIFT_MS as i64;
    let (fast, slow): (&[usize], &[usize]) = (&[host, sk], &[host]);
    let a = net.node(1, if a_ahead { fast } else { slow });
    let b = net.node(2, if a_ahead { slow } else { fast });
    let g = net.group(a, &[(b, osis_base::Role::Write)], &[host]);
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
    (deletions(&net, host, &l) - before, seen.len())
}

// spec/sync.md §7 (compaction waits MAX_DRIFT past keep-at-least): two right holders whose
// corrected clocks differ by MAX_DRIFT, either way, cross a keep-at-least bound: the two dead
// bodies are deleted at the host once each and nobody places them again (the node past the
// bound used to delete what the other, still before it, placed again as must-hold).
#[test]
fn compaction_across_skew_no_churn_spec_sync_7() {
    for a_ahead in [true, false] {
        assert_eq!(compact_across_skew(a_ahead), (2, 2), "a ahead {a_ahead}: deletions, blobs of the dead bodies");
    }
}

/// X, a dead write of the slow node `b` (its corrected clock `MAX_DRIFT` behind `a`'s) whose
/// keep-at-least and keep-at-most bounds are one absolute time (or under `nobody`, with that
/// keep-at-most), crosses it. Returns the host's deletions of X's blobs over the crossing and
/// how many blobs of X either node knew.
fn at_most_across_skew(by: osis_schema::PurgeBy) -> (usize, usize) {
    use osis_schema::{Bound, Retention};
    let mut net = Net::new();
    let host = net.add_host();
    let sk = net.add_host();
    net.hosts[sk].skew = osis_base::format::MAX_DRIFT_MS as i64;
    let a = net.node(1, &[host, sk]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, osis_base::Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let bound = net.now() + 86_400_000;
    let at = Bound { abs: Some(bound), rel: None };
    let mut m = Mutation::new();
    m.set(t, &REG, &s("kept")).unwrap();
    m.retention(t, &REG, Retention { by, at_least: at, at_most: at }).unwrap();
    let x = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.advance(1_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("y")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let l = net.label(a);
    let mut seen = std::collections::BTreeSet::new();
    net.advance(bound - 3 * 3_600_000 - net.now());
    let before = deletions_of(&net, host, &l, &seen);
    // 5 min steps from 3 h before the bound to 3 h after it
    for _ in 0..72 {
        net.advance(5 * 60_000);
        for n in [a, b] {
            for (id, k) in net.sync(n).entries(&l) {
                if matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if commit == x) {
                    seen.insert(id);
                }
            }
        }
    }
    let ak = Ak::new(REG.ak()).unwrap();
    for n in [a, b] {
        assert!(!net.engine(n).body_not_dropped(&x, &t, &ak), "node {n}: X past its keep-at-most kept");
    }
    (deletions_of(&net, host, &l, &seen) - before, seen.len())
}

/// Deletions in host `host`'s log of label `l` of the blobs in `of`.
fn deletions_of(net: &Net, host: usize, l: &osis_base::LabelId, of: &std::collections::BTreeSet<osis_base::BlobId>) -> usize {
    use osis_proto::{LabelStore, LogRecord};
    let recs = net.hosts[host].hub.store().log_after(l, 0, 1 << 20).unwrap().unwrap_or_default();
    recs.iter().filter(|(_, r)| matches!(r, LogRecord::Deleted(id) if of.contains(id))).count()
}

// spec/sync.md §6 (keep-at-least is must-carry), spec/commits.md §5 (keep at most wins): a dead
// write whose two bounds are one time, crossed by two right holders whose clocks differ by
// MAX_DRIFT: the fast one drops and deletes it; the slow one, still before its keep-at-least,
// must not place it again each pass until its own clock passes (one deletion, one blob). The
// same for a `nobody` write with that keep-at-most.
#[test]
fn at_most_across_skew_no_churn_spec_sync_6() {
    for by in [osis_schema::PurgeBy::Writer, osis_schema::PurgeBy::Nobody] {
        assert_eq!(at_most_across_skew(by), (1, 1), "{by:?}: deletions, blobs of X");
    }
}

// spec/commits.md §5 (deaths dated per node), spec/sync.md §6: X < Y < Z on a kept register;
// right holder A held Y before Z (X dies at Y), B held Z before Y (X dies at Z, two hours later).
// Once A's bound has passed it deletes X at the host (covered by its compaction); B, still before
// its own bound, does not place it again (A's snapshot covers it): one deletion, no fresh
// encryption, and B drops it by its own bound. Both end up dating X at Y here; dates still apart
// at the delete: `covered_drop_stays_out_across_local_dating_*`.
#[test]
fn deletion_across_local_dating_no_churn_spec_sync_6() {
    assert_eq!(local_dating_churn(), (1, 1), "deletions, blobs of X");
}

/// The scenario of `deletion_across_local_dating_no_churn_*`: the host's deletions of X's
/// blobs and how many blobs of X either node knew.
fn local_dating_churn() -> (usize, usize) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, osis_base::Role::Write), (c, osis_base::Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
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
    let (ty, tz) = (ts(&mut net, &y), ts(&mut net, &z));
    assert_eq!(net.engine(a).deaths(&x, &t, &ak).unwrap(), Some((ty, ty)));
    assert_eq!(net.engine(b).deaths(&x, &t, &ak).unwrap(), Some((tz, tz)));
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

// spec/sync.md §6 (a covered delta is no blob's alone), spec/commits.md §5 (deaths dated per
// node): admin A compacts a register while X, B's write, is live (no death: past its relative
// keep-at-least), drops X and deletes it at the host. Then C overwrites X: B, still holding X,
// dates its death now and judges it kept. X is covered by A's snapshot under the label, so B
// does not place it again; else A deletes each fresh encryption and B uploads another, for a
// day (sim `snapshot_rights` seed 9317).
#[test]
fn covered_drop_stays_out_across_local_dating_spec_sync_6() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(b, osis_base::Role::Write), (c, osis_base::Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    net.run();
    let k = &ADMIN_KEPT;
    let set = |net: &mut Net, n: usize, v: &str| {
        let mut m = Mutation::new();
        m.set(t, k, &s(v)).unwrap();
        net.engine(n).commit(m).unwrap().unwrap()
    };
    let x = set(&mut net, b, "x");
    net.run();
    let l = net.label(a);
    let ak = Ak::new(k.ak()).unwrap();
    // past MAX_DRIFT since X: a node's compaction may drop a body with no death then
    net.advance(osis_base::format::MAX_DRIFT_MS + 60_000);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&x, &t, &ak), "A dropped X as covered");
    let x_ids = |net: &mut Net| -> std::collections::BTreeSet<osis_base::BlobId> {
        let mut out = std::collections::BTreeSet::new();
        for n in [a, b, c] {
            for (id, e) in net.sync(n).entries(&l) {
                if matches!(e, osis_node::sync::EntryKind::Commit { commit, .. } if commit == x) {
                    out.insert(id);
                }
            }
        }
        out
    };
    let before = x_ids(&mut net);
    assert!(net.host_ids(host, &l).iter().all(|id| !before.contains(id)), "X deleted at the host");
    set(&mut net, c, "y");
    net.run();
    assert!(net.engine(b).deaths(&x, &t, &ak).unwrap().is_some(), "B dated X's death");
    assert!(net.engine(b).body_not_dropped(&x, &t, &ak), "B still holds X, kept");
    let after = x_ids(&mut net);
    assert_eq!(after, before, "no fresh encryption of X");
    assert_eq!(deletions_of(&net, host, &l, &after), before.len(), "one deletion per blob of X");
    assert!(net.host_ids(host, &l).iter().all(|id| !after.contains(id)), "X stays out of the host");
}
