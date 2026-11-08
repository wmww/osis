#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Forensic deletion at a node that syncs: node-sync's records (blob keys `y/b`, entry wraps
//! `y/e`) and the sealed body blobs it fetched are on the device too, and the attack
//! (`Engine::forensic`) opens them (spec/commits.md §5: dropping a body destroys every local
//! copy; spec/requirements.md, Deletion: forward secure).

use crate::net;
use net::*;
use osis_base::{Ak, Role};
use osis_commit::PurgeItem;
use osis_node::Mutation;
use osis_schema::RawKey;
use osis_node::sync::Event;
use osis_store::{Fault, Faults, Source};

fn gone() -> Ak {
    Ak::new(GONE.ak()).unwrap()
}

const MARK: &str = "SYNCED-PURGE-MARK-6b2d";

/// Node b (forensic, faults `f`) holds a's write of `MARK` to `t`, synced through a host under
/// a group label: (net, b, t, commit).
fn synced(f: &Faults) -> (Net, usize, osis_base::Tid, osis_base::CommitId) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.forensic_node(2, &[host], f);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    let t = net.item(a, g, g, "x");
    let mut m = Mutation::new();
    m.set(t, &GONE, &s(&format!("{MARK}{}", "x".repeat(400)))).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    assert!(net.engine(b).body_not_dropped(&c, &t, &gone()), "b holds the body");
    let found = net.forensic(b, MARK.as_bytes());
    assert!(found.iter().any(|f| matches!(f, Source::Blob { .. })), "the attack opens the sealed body: {found:?}");
    (net, b, t, c)
}

fn purge(net: &mut Net, b: usize, t: osis_base::Tid, c: osis_base::CommitId) -> osis_node::Result<()> {
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: gone() });
    m.remove_aspect(t, &GONE).unwrap();
    net.engine(b).commit(m).map(|_| ())
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

// spec/commits.md §5 (a purge drops every local copy), spec/requirements.md Deletion: at a node
// that synced the body (its sealed blob, blob key and wrap held by node-sync), a purge leaves
// nothing of it in rows, blobs, wraps or keys, online (syncing on) or offline
#[test]
fn purged_synced_body_unrecoverable_spec_commits_5() {
    for online in [true, false] {
        let f = Faults::new();
        let (mut net, b, t, c) = synced(&f);
        net.set_online(b, online);
        purge(&mut net, b, t, c).unwrap();
        if online {
            net.feed(b, Event::Local);
            net.run();
        } else {
            settle_offline(&mut net, b, &f);
        }
        assert!(!net.engine(b).body_not_dropped(&c, &t, &gone()));
        let found = net.forensic(b, MARK.as_bytes());
        assert!(found.is_empty(), "online {online}: purged content recovered from {found:?}");
    }
}

// spec/commits.md §5, §4 (a transaction lands whole or not at all): a crash at any write of the
// purge or of node-sync's forgetting after it leaves nothing of the body once the node restarts
// and settles offline (the store-audit window: a crash after the purging commit and before
// node-sync forgot the body's key and ciphertext)
#[test]
fn purged_synced_body_crash_safe_spec_commits_5() {
    let f = Faults::new();
    let (mut net, b, t, c) = synced(&f);
    net.set_online(b, false);
    // the synced node, run down each crash path from a fresh copy
    let (backend, root) = (net.nodes[b].backend.fork(), net.nodes[b].root.copy());
    for n in 0.. {
        net.nodes[b].backend = backend.fork();
        net.nodes[b].root = root.copy();
        net.restart(b, 70);
        f.at(n, Fault::Crash);
        let r = purge(&mut net, b, t, c);
        if r.is_ok() {
            settle_offline(&mut net, b, &f);
        }
        let crashed = f.crashed();
        f.revive();
        net.restart(b, 77);
        if net.engine(b).body_not_dropped(&c, &t, &gone()) {
            assert!(crashed, "write {n}");
            purge(&mut net, b, t, c).unwrap();
        }
        settle_offline(&mut net, b, &f);
        assert!(!net.engine(b).body_not_dropped(&c, &t, &gone()), "write {n}");
        let found = net.forensic(b, MARK.as_bytes());
        assert!(found.is_empty(), "crash at write {n}: purged content recovered from {found:?}");
        if !crashed {
            return;
        }
    }
}

/// Admin `a` (forensic), writer `b`, new node `n` (forensic, offline from the start) of a group
/// on one host, and an item `t` of it.
fn carrier_chat() -> (Net, usize, usize, usize, osis_base::Tid) {
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
    let e = net.engine(b).commit(m).unwrap().unwrap();
    net.run();
    net.advance(5);
    react_and_post(&mut net, a, t, key);
    net.run();
    assert!(!net.forensic(a, value.as_bytes()).is_empty(), "the attack finds the live value");
    net.advance(5);
    let mut m = Mutation::new();
    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s("other"))], op: Op::Set(item("w", 3)) }).unwrap();
    m.purge(PurgeItem::Commit { commit: e, tid: t, ak: Ak::new(MAP.ak()).unwrap() });
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
