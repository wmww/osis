#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention bounds a compactor must not cross (spec/commits.md §5), through a blind node.

mod net;
use net::*;
use osis_core::{Ak, Value};
use osis_node::Mutation;
use osis_schema::AspectKey;

static KEEP: osis_schema::StaticSchema = osis_schema::StaticSchema::new(
    "keep.osis",
    r#"
schema 0x0123456789abcdef0123456789abcd01;
revision 1;
aspect /k/kept: string [by: writer, keep_at_least: 1d];
"#,
);
const KEPT: osis_schema::Aspect<Value> = osis_schema::Aspect::new("/k/kept", &KEEP);

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
    let dead: Vec<osis_core::BlobId> = net.sync(a).entries(&l).into_iter().filter_map(|(id, k)| match k {
        osis_node::sync::EntryKind::Commit { commit, .. } if bodies[..2].contains(&commit) => Some(id),
        _ => None,
    }).collect();
    assert!(dead.len() >= 2);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    for c in &bodies[..2] {
        assert!(net.engine(a).holds_body(c, &t, &ak), "dead body dropped before its keep-at-least bound");
    }
    let at = net.server_ids(sv, &l);
    assert!(dead.iter().all(|id| at.contains(id)), "deleted at the blind node before the bound");
    // compaction waits MAX_DRIFT past the bound (spec/sync.md §7)
    net.advance(86_400_000 + osis_core::format::MAX_DRIFT_MS);
    let acts = net.sync(a).compact(&t, &ak).unwrap();
    net.actions(a, acts);
    net.run();
    for c in &bodies[..2] {
        assert!(!net.engine(a).holds_body(c, &t, &ak), "covered body past its bound kept");
    }
    let at = net.server_ids(sv, &l);
    assert!(dead.iter().all(|id| !at.contains(id)), "covered bodies past the bound left at the blind node");
    assert_eq!(net.engine(a).get(&t, &ak).unwrap(), Some(s("v3")));
}

/// Deletions in server `sv`'s log of label `l`.
fn deletions(net: &Net, sv: usize, l: &osis_core::LabelId) -> usize {
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
    net.servers[sk].skew = osis_core::format::MAX_DRIFT_MS as i64;
    let (fast, slow): (&[usize], &[usize]) = (&[sv, sk], &[sv]);
    let a = net.node(1, if a_ahead { fast } else { slow });
    let b = net.node(2, if a_ahead { slow } else { fast });
    let g = net.group(a, &[(b, osis_core::Role::Write)], &[sv]);
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
            assert!(!net.engine(n).holds_body(c, &t, &ak), "node {n}: covered body past its bound kept");
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
