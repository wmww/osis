//! The group index (`groups.0`, spec/data-model.md §8) of a paged group: each join refreshes it
//! from the tids the join touches, and in debug builds the engine checks every such refresh
//! against the group's whole state (`groups::refresh`).

use crate::common::{DAY, edge, new_thing_keeping, net, set_edge};
use osis_base::Role;
use osis_base::{Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::local_peer::LocalPeer;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn t(i: usize) -> Tid {
    let mut b = [0u8; 15];
    b[7..].copy_from_slice(&(i as u64).to_be_bytes());
    Tid::from_bytes(b)
}

fn op(lp: &mut LocalPeer, i: usize, g: Tid, ops: Vec<Op>) -> osis_base::CommitId {
    let mut m = Mutation::new();
    for o in ops {
        m.op(g, &ct::GROUP, PathOp { path: vec![PathSeg::Field(0)], op: o }).unwrap();
    }
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// At every peer the index lists `g` for exactly the items its state reads, of `probe`.
fn agrees(lp: &mut LocalPeer, g: Tid, probe: &[usize]) -> BTreeSet<usize> {
    let mut seen = None;
    for p in &mut lp.peers {
        let items = p.engine.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default().items;
        let listed: BTreeSet<usize> = probe.iter().copied().filter(|i| p.engine.groups_of(&t(*i)).contains(&g)).collect();
        let read: BTreeSet<usize> = probe.iter().copied().filter(|i| items.contains(&t(*i))).collect();
        assert_eq!(listed, read, "the group index differs from the group's state");
        assert!(seen.is_none_or(|s| s == listed), "peers differ");
        seen = Some(listed);
    }
    seen.unwrap_or_default()
}

// spec/data-model.md §8, spec/crdt.md §5.5: in a paged group, concurrent changes of one item (a
// removal at one node, an add at the other), undoing an add (an element reset) and a removal,
// and replacing the whole definition (a reset) leave `groups.0` what the state lists at both.
#[test]
fn group_index_follows_concurrent_changes_spec_data_model_8() {
    let n = 4000;
    let mut lp = net(2, 0);
    let g = new_thing_keeping(&mut lp, 0, &[("group.0", DAY)]);
    let b = lp.peers[1].engine.me();
    set_edge(&mut lp.peers[0].engine, g, b, Some(edge(Role::Write)), None);
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &ct::Group { items: (0..n).map(t).collect(), subgroups: Default::default() }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let probe = [1, 2, 3, 5, n];
    // concurrent: 0 removes 1 and 2; 1 removes 1, then adds it again (an element 0 did not see)
    // and removes 3
    op(&mut lp, 0, g, vec![Op::Remove(Value::Tid(t(1))), Op::Remove(Value::Tid(t(2)))]);
    op(&mut lp, 1, g, vec![Op::Remove(Value::Tid(t(1)))]);
    let add = op(&mut lp, 1, g, vec![Op::Add(Value::Tid(t(1))), Op::Remove(Value::Tid(t(3)))]);
    lp.sync_all().unwrap();
    assert_eq!(agrees(&mut lp, g, &probe), BTreeSet::from([1, 5]));
    // undoing the add resets its element: 1 goes; adding n, then undoing that
    lp.peers[1].engine.revert(&add).unwrap().unwrap();
    let new = op(&mut lp, 0, g, vec![Op::Add(Value::Tid(t(n)))]);
    lp.sync_all().unwrap();
    assert_eq!(agrees(&mut lp, g, &probe), BTreeSet::from([3, 5, n]));
    lp.peers[0].engine.revert(&new).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(agrees(&mut lp, g, &probe), BTreeSet::from([3, 5]));
    // the definition written whole (a removal and an add per changed item), then the items reset
    let mut m = Mutation::new();
    m.set(g, &ct::GROUP, &ct::Group { items: [2, 5].map(t).into(), subgroups: Default::default() }).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(agrees(&mut lp, g, &probe), BTreeSet::from([2, 5]));
    op(&mut lp, 0, g, vec![Op::Replace(Value::Set([Value::Tid(t(1))].into()))]);
    lp.sync_all().unwrap();
    assert_eq!(agrees(&mut lp, g, &probe), BTreeSet::from([1]));
}

// spec/data-model.md §8: a group written only by item ops (no definition write) lists its one
// item, and removing it unlists it (the refresh of a group whose state is present only through
// its items).
#[test]
fn group_index_follows_item_ops_alone_spec_data_model_8() {
    let mut lp = net(1, 0);
    let g = crate::common::new_thing(&mut lp, 0);
    op(&mut lp, 0, g, vec![Op::Add(Value::Tid(t(1)))]);
    assert!(lp.peers[0].engine.groups_of(&t(1)).contains(&g));
    op(&mut lp, 0, g, vec![Op::Remove(Value::Tid(t(1)))]);
    assert!(!lp.peers[0].engine.groups_of(&t(1)).contains(&g));
}
