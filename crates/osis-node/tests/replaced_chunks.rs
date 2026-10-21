#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A replaced label keeps membership-class commits and certificates only (spec/sync.md §2): the
//! chunk and page entries of its content commits go with them.

mod net;
use net::*;
use osis_core::{Role, Value};
use osis_node::Mutation;
use osis_node::sync::EntryKind;

// spec/sync.md §2 (replacement: the admin deletes the old label's content entries): the chunks
// of a large value written under the old label go too, and the admin then retires the label.
#[test]
fn replaced_label_chunks_deleted_spec_sync_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let g = net.group(a, &[(b, Role::Write)], &[sv]);
    let t = net.item(a, g, g, "x");
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(big)).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let old = net.label(a);
    let chunks = net.sync(a).entries(&old).into_iter().filter(|(_, k)| *k == EntryKind::Unknown).count();
    assert!(chunks > 1, "the value went up in chunks");
    let (new, _) = net.sync(a).replace_label(&g, &old).unwrap();
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(!net.server_ids(sv, &new).is_empty());
    let known = net.sync(a).entries(&old);
    let left: Vec<_> = net.server_ids(sv, &old).into_iter().filter(|id| known.iter().any(|(x, k)| x == id && *k == EntryKind::Unknown)).collect();
    assert!(left.is_empty(), "no chunk of the content commit is left: {left:?}");
    let labels: Vec<_> = net.sync(a).labels().into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, vec![new], "the admin is done with the old label");
}
