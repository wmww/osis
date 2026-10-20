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
// bodies nor deletes them at the blind node; once the bound has passed it does both.
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
    net.advance(86_400_000);
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
