#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Forensic deletion at node level: after a purge, an expiry or a keep-at-most drop, an attacker
//! holding the device (every key the current root yields) and every row ever written (freed
//! pages, old versions) recovers nothing of the dropped body (spec/commits.md §5: dropping a
//! body destroys every local copy so that later compromise of the node recovers nothing;
//! spec/requirements.md, Deletion: forward secure).

mod common;
use common::*;
use osis_commit::PurgeItem;
use osis_core::{Clock, ManualClock, Tid, Value};
use osis_crypto::SeededRng;
use osis_node::local_peer::{LocalPeer, Peer};
use osis_node::{Config, Engine, Mutation};
use osis_store::{MemoryBackend, MemoryRoot, StoreConfig, forensic_node_keys, forensic_open};
use std::collections::HashSet;
use std::sync::Arc;

/// A peer over a small key tree (arity 4: few units share a leaf, so a shred elsewhere does
/// not incidentally rotate a leaked copy away) and small pages, recording every row written.
fn peer(seed: u64) -> Peer {
    let clock = Arc::new(ManualClock::new(T0));
    let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
    backend.record_history();
    let cfg = Config { store: StoreConfig { arity: 4, depth: 8, page_max: 512, ..StoreConfig::default() }, ..Config::default() };
    let c: Arc<dyn Clock> = clock.clone();
    let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), cfg, c, Box::new(SeededRng::from_u64(seed))).unwrap();
    let events = engine.subscribe();
    Peer { engine, clock, backend, root, events }
}

fn net2(seed: u64) -> LocalPeer {
    LocalPeer { peers: vec![peer(seed), peer(seed + 1)] }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether an attacker decrypts `marker` from the rows ever written, starting from the keys the
/// current tree yields and harvesting keys from opened tree nodes.
fn recoverable(p: &mut Peer, marker: &[u8]) -> bool {
    let history = p.backend.history();
    let mut keys = p.engine.forensic_keys().unwrap();
    let mut known: HashSet<[u8; 32]> = keys.iter().copied().collect();
    let mut opened = vec![false; history.len()];
    let mut tried = 0;
    let mut found = false;
    while tried < keys.len() {
        let batch: Vec<[u8; 32]> = keys[tried..].to_vec();
        tried = keys.len();
        for (i, (row, value)) in history.iter().enumerate() {
            if opened[i] {
                continue;
            }
            for k in &batch {
                if let Some(plain) = forensic_open(row, value, k) {
                    for nk in forensic_node_keys(row, &plain) {
                        if known.insert(nk) {
                            keys.push(nk);
                        }
                    }
                    found |= contains(&plain, marker);
                    opened[i] = true;
                    break;
                }
            }
        }
    }
    found
}

fn big(marker: &str) -> String {
    format!("{marker}{}", "x".repeat(400))
}

fn set(lp: &mut LocalPeer, i: usize, t: Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_core::CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

/// Unrelated writes so the store grows past one leaf of the key tree.
fn filler(lp: &mut LocalPeer, i: usize, n: usize) {
    for k in 0..n {
        let t = new_thing(lp, i);
        set(lp, i, t, &REG, &format!("filler {k}"));
    }
}

// spec/commits.md §5: a purge drops every local copy (the commit record, state, undo buffer)
// so that later compromise recovers nothing
#[test]
fn purged_body_unrecoverable_spec_commits_5() {
    let mut lp = net2(71);
    let t = new_thing(&mut lp, 0);
    let marker = "PURGED-MARK-41c9";
    let secret = set(&mut lp, 0, t, &REG, &big(marker));
    filler(&mut lp, 0, 6);
    assert!(recoverable(&mut lp.peers[0], marker.as_bytes()), "the attack finds live content");
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[0].commit(m).unwrap();
    assert!(!lp.peers[0].engine.holds_body(&secret, &t, &ak("/t/reg")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "purged content recovered");
}

// spec/commits.md §5: a commit held pending before it applied leaves no copy once its body is
// purged
#[test]
fn purged_after_pending_unrecoverable_spec_commits_5() {
    let mut lp = net2(72);
    let t = new_thing(&mut lp, 0);
    let marker = "PENDING-MARK-8d2e";
    let secret = set(&mut lp, 0, t, &REG, &big(marker));
    // node 1 gets the marker commit before the thing's creation: held pending
    let pks = lp.packages(0).unwrap();
    let pk = pks.iter().find(|p| p.id == secret).unwrap().clone();
    assert!(matches!(lp.deliver(1, &pk).unwrap(), osis_node::Ingested::Pending(..)));
    filler(&mut lp, 1, 6);
    lp.sync(0, 1).unwrap();
    assert!(lp.peers[1].engine.holds_body(&secret, &t, &ak("/t/reg")));
    filler(&mut lp, 1, 6);
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("/t/reg") });
    lp.peers[0].commit(m).unwrap();
    lp.sync(0, 1).unwrap();
    assert!(!lp.peers[1].engine.holds_body(&secret, &t, &ak("/t/reg")));
    assert!(!recoverable(&mut lp.peers[1], marker.as_bytes()), "purged content recovered from the pending copy");
}

// spec/commits.md §6: at T the body is dropped; spec/commits.md §5: no local copy survives
#[test]
fn expired_body_unrecoverable_spec_commits_6() {
    let mut lp = net2(73);
    let t = new_thing(&mut lp, 0);
    let marker = "EXPIRED-MARK-77aa";
    let c = set(&mut lp, 0, t, &BRIEF, &big(marker));
    filler(&mut lp, 0, 6);
    lp.advance(3_600_001);
    lp.peers[0].engine.tick().unwrap();
    assert!(!lp.peers[0].engine.holds_body(&c, &t, &ak("/t/brief")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "expired content recovered");
}

// spec/commits.md §5 (keep at most 0): the replacing node drops the body in the killing
// transaction; no local copy survives
#[test]
fn kept_at_most_zero_unrecoverable_spec_commits_5() {
    let mut lp = net2(74);
    let t = new_thing(&mut lp, 0);
    let marker = "ATMOST-MARK-5b01";
    let c = set(&mut lp, 0, t, &GONE, &big(marker));
    filler(&mut lp, 0, 6);
    lp.advance(5);
    set(&mut lp, 0, t, &GONE, "final");
    assert!(!lp.peers[0].engine.holds_body(&c, &t, &ak("/t/gone")));
    assert!(!recoverable(&mut lp.peers[0], marker.as_bytes()), "dropped content recovered");
}
