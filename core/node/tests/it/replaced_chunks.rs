#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A replaced label keeps role-class commits and certificates only (spec/sync.md §2): every
//! entry holding content goes, a creation record's commit included, and the chunk and page
//! entries of content commits with them.

use crate::net::hosted;
use crate::net;
use net::*;
use osis_base::{Role, Value};
use osis_node::Mutation;
use osis_node::sync::EntryKind;

// spec/sync.md §2 (replacement: the admin deletes the old label's content entries): the chunks
// of a large value written under the old label go too, and the admin then retires the label.
#[test]
fn replaced_label_chunks_deleted_spec_sync_2() {
    let (mut net, host, [a, _b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["x"], false);
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut m = Mutation::new();
    m.set(t, &BLOB, &Value::Bytes(big)).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let old = net.label(a);
    let chunks = net.sync(a).entries(&old).into_iter().filter(|(_, k)| *k == EntryKind::Unknown).count();
    assert!(chunks > 1, "the value went up in chunks");
    let (new, acts) = net.sync(a).replace_label(&g, &old).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert!(!net.host_ids(host, &new).is_empty());
    let known = net.sync(a).entries(&old);
    let left: Vec<_> = net.host_ids(host, &old).into_iter().filter(|id| known.iter().any(|(x, k)| x == id && *k == EntryKind::Unknown)).collect();
    assert!(left.is_empty(), "no chunk of the content commit is left: {left:?}");
    let labels: Vec<_> = net.group_labels(a).into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, vec![new], "the admin is done with the old label");
}

// spec/sync.md §2 (replacement: the old label's content entries go, carried under it or not): a
// thing's first commit holds its creation record, its first value and its group's membership.
// The admin replaces the label while offline and meanwhile overwrites the value and drops that
// body; online again, the entry still goes from the old label (its creation record and
// membership write do not make it a kept one) and the admin retires the label.
#[test]
fn replaced_label_first_commit_deleted_after_its_value_dropped_spec_sync_2() {
    let (mut net, host, [a, _b], g, [t]) = hosted::<2, 1>(&[(1, Role::Write)], ["first"], true);
    let old = net.label(a);
    let commits: Vec<_> = net.sync(a).entries(&old).into_iter().filter_map(|(_, k)| match k {
        EntryKind::Commit { commit, .. } => Some(commit),
        _ => None,
    }).collect();
    let first = commits.into_iter().find(|c| net.engine(a).header(c).is_some_and(|h| h.aspects.iter().any(|x| x.tid == t && x.ak.as_str() == "created.0"))).unwrap();
    let entries_of_first = |net: &mut Net| {
        let live = net.host_ids(host, &old);
        net.sync(a).entries(&old).into_iter().filter(|(id, k)| live.contains(id) && matches!(k, EntryKind::Commit { commit, .. } if *commit == first)).count()
    };
    assert_eq!(entries_of_first(&mut net), 1);
    net.set_online(a, false);
    let (new, acts) = net.sync(a).replace_label(&g, &old).unwrap();
    net.actions(a, acts);
    net.write(a, t, "second");
    let acts = net.sync(a).compact_now(&t, &REG.name()).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(!net.engine(a).body_not_dropped(&first, &t, &REG.name()), "the first value's body dropped");
    net.set_online(a, true);
    for _ in 0..3 {
        net.advance(31_000);
    }
    assert_eq!(entries_of_first(&mut net), 0, "the first commit's entry left under the replaced label");
    let labels: Vec<_> = net.group_labels(a).into_iter().map(|(_, l)| l.id).collect();
    assert_eq!(labels, vec![new], "the admin is done with the old label");
}
