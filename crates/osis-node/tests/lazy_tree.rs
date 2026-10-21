#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Lazy chunks (spec/sync.md §6): a read that misses a chunk fetches that value's tree only.

mod net;
use net::*;
use osis_core::{Ak, Role, Value};
use osis_node::Mutation;
use osis_node::sync::SyncConfig;
use osis_schema::AspectKey;

// spec/sync.md §6 (chunk and tree-node blobs of large atomic values may be fetched lazily): a
// lazy reader fetches the tree of the value it reads, node by node, and nothing of another
// large value.
#[test]
fn read_fetches_its_tree_only_spec_sync_6() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.add_node(2, SyncConfig { servers: vec![net.address(sv)], inline_limit: 0, ..SyncConfig::default() });
    let g = net.group(a, &[(b, Role::Read)], &[sv]);
    let t = net.item(a, g, g, "x");
    let u = net.item(a, g, g, "y");
    let one: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
    let two: Vec<u8> = (0..700_000u32).map(|i| (i % 241) as u8).collect();
    for (x, v) in [(t, &one), (u, &two)] {
        let mut m = Mutation::new();
        m.set(x, &BLOB, &Value::Bytes(v.clone())).unwrap();
        net.engine(a).commit(m).unwrap();
    }
    net.run();
    let ak = Ak::new(BLOB.ak()).unwrap();
    assert!(net.engine(b).get_full(&t, &ak).is_err(), "not fetched yet");
    let Some(Value::Link(link)) = net.engine(b).get(&t, &ak).unwrap() else { panic!("a link") };
    for _ in 0..8 {
        let acts = net.sync(b).fetch_tree(&t, &link).unwrap();
        if acts.is_empty() {
            break;
        }
        net.actions(b, acts);
        net.settle(100_000);
    }
    assert_eq!(net.engine(b).get_full(&t, &ak).unwrap(), Some(Value::Bytes(one)));
    assert!(net.engine(b).get_full(&u, &ak).is_err(), "the other value stays lazy");
}
