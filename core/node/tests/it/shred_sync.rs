#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Forensic deletion at a node that syncs: node-sync's records (blob keys `y/b`, entry wraps
//! `y/e`) and the sealed body blobs it fetched are on the device too, and the attack
//! (`Engine::forensic`) opens them (spec/commits.md §5: dropping a body destroys every local
//! copy; spec/requirements.md, Deletion: forward secure).

use crate::net::hosted_nodes;
use crate::net;
use net::*;
use osis_base::{Ak, Role};
use osis_node::Mutation;
use osis_schema::RawKey;
use osis_node::sync::Event;
use osis_store::{Fault, Faults, Source};

fn gone() -> Ak {
    Ak::new(GONE.ak()).unwrap()
}

const MARK: &str = "SYNCED-PURGE-MARK-6b2d";

/// Two blob shapes (spec/sync.md §3): one commit on items of two groups, its one blob held under
/// both groups' labels, and one on an item of one group, under one label.
const TWO_LABELS: &[usize] = &[0, 1];
const ONE_LABEL: &[usize] = &[0];

/// The (commit, item) parts of `MARK` that node b holds.
type Parts = Vec<(osis_base::CommitId, osis_base::Tid)>;

/// Node b (forensic, faults `f`) holds a's writes of `MARK` synced through a host: one commit
/// per entry of `shape`, on one item of each group it names (`TWO_LABELS`, `ONE_LABEL`):
/// (net, b, parts).
fn synced(f: &Faults, shape: &[&[usize]]) -> (Net, usize, Parts) {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let b = net.forensic_node(2, &[host], f);
    let n = shape.iter().flat_map(|c| c.iter()).max().map_or(0, |g| g + 1);
    let gs: Vec<_> = (0..n).map(|_| net.group(a, &[(b, Role::Write)], &[host])).collect();
    let mut parts = Vec::new();
    for groups in shape {
        let ts: Vec<_> = groups.iter().map(|g| {
            let t = net.item(a, gs[*g], gs[*g], "x");
            net.keep(a, t, &[("t:gone.0", PURGE)]);
            t
        }).collect();
        let mut m = Mutation::new();
        for t in &ts {
            m.set(*t, &GONE, &s(&format!("{MARK}{t:?}{}", "x".repeat(400)))).unwrap();
        }
        let c = net.engine(a).commit(m).unwrap().unwrap();
        parts.extend(ts.into_iter().map(|t| (c, t)));
    }
    net.run();
    assert_eq!(holds(&mut net, b, &parts), parts.len(), "b holds the bodies");
    let found = net.forensic(b, MARK.as_bytes());
    assert!(found.iter().any(|f| matches!(f, Source::Blob { .. })), "the attack opens the sealed body: {found:?}");
    (net, b, parts)
}

fn purge(net: &mut Net, b: usize, parts: &Parts) -> osis_node::Result<()> {
    let mut m = Mutation::new();
    for (c, t) in parts {
        m.purge_commit(*c, *t, gone());
        m.remove_aspect(*t, &GONE).unwrap();
    }
    net.engine(b).commit(m).map(|_| ())
}

/// How many of the bodies `b` holds.
fn holds(net: &mut Net, b: usize, parts: &Parts) -> usize {
    parts.iter().filter(|(c, t)| net.engine(b).body_not_dropped(c, t, &gone())).count()
}

/// Node-sync's work at `b` offline, stopping at a crash of its device (`f`): the process is gone.
fn settle_offline(net: &mut Net, b: usize, f: &Faults) {
    for _ in 0..3 {
        for ev in [Event::Local, Event::Tick] {
            if f.crashed() {
                return;
            }
            net.sync(b).handle(ev);
        }
    }
}

/// `b` holds none of the bodies, and the attack recovers nothing of them.
fn purged(net: &mut Net, b: usize, parts: &Parts, at: &str) {
    assert_eq!(holds(net, b, parts), 0, "{at}");
    let found = net.forensic(b, MARK.as_bytes());
    assert!(found.is_empty(), "{at}: purged content recovered from {found:?}");
}

// spec/commits.md §5 (a purge drops every local copy), spec/requirements.md Deletion: at a node
// that synced the bodies (each sealed blob, blob key and wrap under each label held by
// node-sync), a purge leaves nothing of them in rows, blobs, wraps or keys, online (syncing on)
#[test]
fn purged_synced_body_unrecoverable_spec_commits_5() {
    let f = Faults::new();
    let (mut net, b, parts) = synced(&f, &[TWO_LABELS, ONE_LABEL]);
    purge(&mut net, b, &parts).unwrap();
    net.feed(b, Event::Local);
    net.run();
    purged(&mut net, b, &parts, "online");
}

// spec/commits.md §5, spec/requirements.md Deletion: as above with the node offline from the
// purge on: node-sync's entries of the dropped blobs stay while a host may hold the blob, so
// each label's wrap of each blob must be zeroed in its row (online the entries go: no kept wrap
// shows there)
#[test]
fn purged_synced_body_unrecoverable_offline_spec_commits_5() {
    let f = Faults::new();
    let (mut net, b, parts) = synced(&f, &[TWO_LABELS, ONE_LABEL]);
    net.set_online(b, false);
    purge(&mut net, b, &parts).unwrap();
    settle_offline(&mut net, b, &f);
    purged(&mut net, b, &parts, "offline");
}

// spec/commits.md §5, §4 (a transaction lands whole or not at all): a crash at any write of the
// purge or of node-sync's forgetting after it leaves nothing of the body once the node restarts
// and settles offline (the store-audit window: a crash after the purging commit and before
// node-sync forgot the body's key and ciphertext). One label: node-sync writes every label's
// entries of a blob in one write (a blob under two labels takes the writes of one under one
// label with as many parts), so no crash falls between them; the offline test covers both shapes.
#[test]
fn purged_synced_body_crash_safe_spec_commits_5() {
    let f = Faults::new();
    let (mut net, b, parts) = synced(&f, &[ONE_LABEL]);
    net.set_online(b, false);
    // the synced node's device (the engine's store and the hub's), run down each crash path
    // from a fresh copy
    let (backend, root) = (net.nodes[b].backend.copy(), net.nodes[b].root.copy());
    let hub = (net.nodes[b].hub_disk.0.copy(), net.nodes[b].hub_disk.1.copy());
    for n in 0.. {
        net.nodes[b].backend = backend.copy();
        net.nodes[b].root = root.copy();
        net.nodes[b].hub_disk = (hub.0.copy(), hub.1.copy());
        net.restart(b, 70);
        f.at(n, Fault::Crash);
        if purge(&mut net, b, &parts).is_ok() {
            settle_offline(&mut net, b, &f);
        }
        let crashed = f.crashed();
        f.revive();
        net.restart(b, 77);
        if holds(&mut net, b, &parts) > 0 {
            assert!(crashed, "write {n}");
            purge(&mut net, b, &parts).unwrap();
        }
        settle_offline(&mut net, b, &f);
        purged(&mut net, b, &parts, &format!("crash at write {n}"));
        if !crashed {
            return;
        }
    }
}

/// Admin `a` (forensic), writer `b`, new node `n` (forensic, offline from the start) of a group
/// on one host, and an item `t` of it: built once (`Net::cached`).
fn carrier_chat() -> (Net, usize, usize, usize, osis_base::Tid) {
    let (net, (a, b, n, t)) = Net::cached("shred_sync::carrier_chat", || {
        let (net, a, b, n, t) = carrier_chat_built();
        (net, (a, b, n, t))
    });
    (net, a, b, n, t)
}

fn carrier_chat_built() -> (Net, usize, usize, usize, osis_base::Tid) {
    let f = Faults::new();
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.forensic_node(1, &[host], &f);
    let b = net.node(2, &[host]);
    let n = net.forensic_node(3, &[host], &f);
    let g = net.group(a, &[(b, Role::Write), (n, Role::Read)], &[host]);
    net.set_online(n, false);
    let t = net.item(a, g, g, "x");
    net.run();
    (net, a, b, n, t)
}

/// `a` reacts to entry `key` and posts entry `m2` in one write (one delta: a carrier of `key`),
/// then edits `m2`: the carrier's own values.
fn react_and_post(net: &mut Net, a: usize, t: osis_base::Tid, key: &str) {
    use crate::common::{MAP, item};
    use osis_crdt::{Op, PathOp, PathSeg};
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(key)), PathSeg::Field(1)], op: Op::Set(osis_base::Value::Int(2)) }).unwrap();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2"))], op: Op::Set(item("M2-MARK", 7)) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("m2")), PathSeg::Field(1)], op: Op::Set(osis_base::Value::Int(9)) }).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
}

/// Every node reads `m2` whole and at `key` the reaction alone (`a`'s own copy of the key keeps
/// the entry, spec/crdt.md §5.6); no forensic node recovers the gone message's value `gone`.
fn reaction_kept_value_gone(net: &mut Net, nodes: &[usize], forensic: &[usize], t: osis_base::Tid, key: &str, gone: &str) {
    use crate::common::{MAP, item};
    use osis_crdt::PathSeg;
    let k = Ak::new(MAP.ak()).unwrap();
    for &x in nodes {
        assert_eq!(net.engine(x).get_at(&t, &k, &[PathSeg::Key(s(key))]).unwrap(), Some(osis_base::Value::Map([(osis_base::Value::Int(1), osis_base::Value::Int(2))].into_iter().collect())), "node {x}: the reaction alone");
        assert_eq!(net.engine(x).get_at(&t, &k, &[PathSeg::Key(s("m2"))]).unwrap(), Some(item("M2-MARK", 9)), "node {x}: the carrier's own values");
    }
    for &x in forensic {
        let found = net.forensic(x, gone.as_bytes());
        assert!(found.is_empty(), "node {x}: the gone value recovered from {found:?}");
    }
}

// spec/crdt.md §4.7, spec/commits.md §5, spec/sync.md §7: `b` purges its message; `a`'s reaction to it
// (with `a`'s own message in one delta) keeps the entry under its own key, at `a`, at `b` and at a
// new node fetching after the purge once a writer compacts (the entry's creation reaches it only
// in a snapshot, spec/commits.md §5), and the message's value is gone everywhere.
#[test]
fn purge_leaves_reaction_through_hosts_spec_crdt_4_7() {
    use crate::common::{MAP, item};
    use osis_crdt::{Op, PathOp, PathSeg};
    let (mut net, a, b, n, t) = carrier_chat();
    let (key, value) = ("e", "PURGED-VALUE-MARK-5e17");
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(key))], op: Op::Set(item(value, 1)) }).unwrap();
    // its author purges it below
    m.retention(t, &MAP, crate::common::purgeable_by(osis_base::PurgeBy::AuthorOrAdmin)).unwrap();
    let e = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.advance(5);
    react_and_post(&mut net, a, t, key);
    net.run();
    assert!(!net.forensic(a, value.as_bytes()).is_empty(), "the attack finds the live value");
    net.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("other"))], op: Op::Set(item("w", 3)) }).unwrap();
    m.purge_commit(e, t, Ak::new(MAP.ak()).unwrap());
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.engine(a).snapshot(&t, &Ak::new(MAP.ak()).unwrap()).unwrap();
    net.run();
    net.set_online(n, true);
    net.run();
    reaction_kept_value_gone(&mut net, &[a, b, n], &[a, n], t, key, value);
    for x in [a, n] {
        net.restart(x, 600 + x as u64);
    }
    net.run();
    reaction_kept_value_gone(&mut net, &[a, b, n], &[a, n], t, key, value);
}

// spec/crdt.md §4.7: as above for an expiring message: the reaction keeps its own expiry (none) and
// past T the entry at every node, a new node fetching after T and a compaction included, and no
// node keeps the message's value.
#[test]
fn expiry_leaves_reaction_through_hosts_spec_crdt_4_7() {
    use crate::common::{MAP, item};
    use osis_crdt::{Op, PathOp, PathSeg};
    let (mut net, a, b, n, t) = carrier_chat();
    let (key, value) = ("e", "EXPIRED-VALUE-MARK-2c90");
    let t_end = net.now() + 60_000;
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(key))], op: Op::Set(item(value, 1)) }).unwrap();
    m.expires(t, &MAP, osis_base::WallMs(t_end)).unwrap();
    net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.advance(5);
    react_and_post(&mut net, a, t, key);
    net.run();
    net.advance(60_001);
    net.run();
    net.engine(a).snapshot(&t, &Ak::new(MAP.ak()).unwrap()).unwrap();
    net.run();
    net.set_online(n, true);
    net.run();
    reaction_kept_value_gone(&mut net, &[a, b, n], &[a, n], t, key, value);
}
