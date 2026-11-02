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
use osis_schema::AspectKey;
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
    // the synced device, run down each crash path from a fresh copy
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
