//! The background runtime (notes/api.md Design rules: async only where another node is waited
//! on; sync runs on the handle's tokio runtime): two nodes on `Runtime::Tokio` reach a
//! third that peers (one on the app's runtime, one on `Runtime::Own`) over in-process sessions
//! (tier 1, a guard timeout against a hang) and over localhost QUIC (tier 2, ignored).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use osis::internals::Internals as _;
use crate::common;
use common::ak;
use crate::common::CreateIn;
use osis::{SetRoleOpts, SyncFirst, MemStore, Osis, Runtime, Address, Store, SyncScope, Value};
use osis_transport::Transport as _;
use std::time::Duration;

const GUARD: Duration = Duration::from_secs(30);

fn cfg(seed: u64, hosts: Vec<Address>, t: Option<osis::internals::InProcess>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.app.internals.seed = Some(seed);
    c.runtime = Runtime::Tokio(tokio::runtime::Handle::current());
    c.app.internals.transport = t;
    c.hosts = hosts;
    c
}

/// A node serving any label (`set_hosting`, open admission) on `t` at `url`, and its peer
/// address once it listens.
async fn host_node(t: Option<osis::internals::InProcess>, url: &str) -> (Option<Osis>, Address) {
    let mut c = cfg(90, vec![], t);
    c.direct_sync = false;
    let db = osis::internals::create(c).unwrap().0;
    db.set_serving(Some(osis::Serving { listen: vec![url.parse().unwrap()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    let a = tokio::time::timeout(GUARD, async {
        loop {
            if let Some(a) = db.serving_address().unwrap() {
                return a;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    (Some(db), a)
}

/// An account writes into its home group and waits until it is at the peer; a fresh node
/// restores the account from the card and reads it. `p2p`: the peer then stops, and a write
/// reaches the other node directly (each listens with its dialable key, spec/sync.md §5, §10).
async fn round_trip(host_ep: Option<osis::internals::InProcess>, url: &str, a: Option<osis::internals::InProcess>, b: Option<osis::internals::InProcess>, p2p: bool) {
    let (mut host_db, host) = host_node(host_ep, url).await;

    let (da, card) = osis::internals::create(cfg(1, vec![host.clone()], a)).unwrap();
    let mut w = da.write();
    let t = w.create_in(da.me(), &[da.me()]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("over the wire".into())).unwrap();
    w.commit().unwrap();
    tokio::time::timeout(GUARD, da.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();

    // the fresh node syncs on a runtime of osis's own (`Runtime::Own`)
    let mut own = cfg(2, vec![], b);
    own.runtime = Runtime::Own;
    let db = tokio::time::timeout(GUARD, osis::internals::restore(own, &card.unwrap())).await.unwrap().unwrap();
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), Some(Value::Str("over the wire".into())));
    // the peer, and the first node as a co-reader once its connection is up
    assert!(db.status().unwrap().connected >= 1);
    if p2p {
        drop(host_db.take());
        let mut w = da.write();
        w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("peer to peer".into())).unwrap();
        w.commit().unwrap();
        let want = Some(Value::Str("peer to peer".into()));
        tokio::time::timeout(GUARD, async {
            while db.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != want {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    // close() returns once the node is closed (the driver held only a weak reference)
    let weak = da.downgrade();
    assert_eq!(da.close().unwrap(), osis::Close::Closed);
    assert!(weak.upgrade().is_none());
    drop(db);
    drop(host_db);
}

// notes/api.md Handle (Config.runtime), spec/sync.md §10: the tokio driver under the handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_in_process_spec_sync_10() {
    let net = osis_transport::Net::new(3);
    round_trip(Some(net.endpoint("s")), "mem://s", Some(net.endpoint("a")), Some(net.endpoint("b")), false).await;
}

// spec/sync.md §5 (co-reader peer), §10, notes/api.md (Config.peers): two nodes under the
// handle's driver keep syncing peer to peer once their peer is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_peers_in_process_spec_sync_5() {
    let net = osis_transport::Net::new(5);
    round_trip(Some(net.endpoint("s")), "mem://s", Some(net.endpoint("a")), Some(net.endpoint("b")), true).await;
}

// spec/sync.md §10: the same over localhost QUIC (tier 2: touches the network).
// Run: `cargo test --workspace --test it runtime:: -- --ignored`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn runtime_quic_localhost_spec_sync_10() {
    round_trip(None, "quic://127.0.0.1:0", None, None, false).await;
}

/// Bob redeems Alice's write link to a synced group, both on the tokio driver.
async fn redeem_over(host_ep: Option<osis::internals::InProcess>, url: &str, a: Option<osis::internals::InProcess>, b: Option<osis::internals::InProcess>) {
    let (host_db, host) = host_node(host_ep, url).await;
    let alice = osis::internals::create(cfg(1, vec![host.clone()], a)).unwrap().0;
    let bob = osis::internals::create(cfg(2, vec![host.clone()], b)).unwrap().0;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.me()]).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let link = alice.make_link(g, osis::Role::Write, Default::default()).unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(90), bob.redeem(&link)).await.unwrap().unwrap(), g);
    // spec/permissions.md §4, notes/sync.md: `reach.0` under the home group, not under a group
    // shared with a non-contact, until the policy says so
    let home = alice.me();
    assert!(alice.sync_engine(|s| s.publishes_reach(&home)));
    assert!(!alice.sync_engine(|s| s.publishes_reach(&g)));
    alice.set_sync_options(g, osis::SyncOptions { share_address: osis::ShareAddress::Always, ..Default::default() }).unwrap();
    assert!(alice.sync_engine(|s| s.publishes_reach(&g)));
    drop((alice, bob));
    drop(host_db);
}

// spec/permissions.md §8 (links), spec/sync.md §10: a link redeemed over the tokio driver.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeem_in_process_spec_permissions_8() {
    let net = osis_transport::Net::new(4);
    redeem_over(Some(net.endpoint("s")), "mem://s", Some(net.endpoint("a")), Some(net.endpoint("b"))).await;
}

// spec/permissions.md §8, spec/sync.md §10: the same over localhost QUIC (tier 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn redeem_quic_localhost_spec_permissions_8() {
    redeem_over(None, "quic://127.0.0.1:0", None, None).await;
}

// notes/api.md Text editing sessions, spec/requirements.md (Generality: one commit per editing
// pause): with a runtime, a session commits after `idle_commit` without edits, with no further
// edit or call. Tier 2: it waits on a real 20 ms timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "tier 2"]
async fn text_idle_commit_api_text_sessions() {
    let net = osis_transport::Net::new(4);
    let mut c = cfg(1, vec![], Some(net.endpoint("a")));
    c.app.idle_commit = Duration::from_millis(20);
    let db = osis::internals::create(c).unwrap().0;
    let k = ak("t:body.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let s = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).edit_text().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let _watch = db.at(t, osis::DynamicAspectKey::untyped(k.clone())).on_change(move |_, c| tx.send(c.value.unwrap()).unwrap()).unwrap();
    assert_eq!(tokio::time::timeout(GUARD, rx.recv()).await.unwrap(), Some(None), "the current value first");
    s.splice(0..0, "hi").unwrap();
    assert_eq!(tokio::time::timeout(GUARD, rx.recv()).await.unwrap(), Some(Some(Value::Str("hi".into()))));
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(k)).get().unwrap(), Some(Value::Str("hi".into())));
    assert_eq!(s.commit().unwrap(), None, "already committed");
}

// notes/ephemeral.md Values that live while their author is there: a kept-alive cursor (a map
// entry under the node's key, expiring 60 ms after each write) is rewritten every half
// expiry while the `KeepAlive` lives, takes a new value at once, and is gone by its expiry once
// dropped; a key without a default expiry is refused
#[tokio::test]
async fn keep_alive_rewrites_until_dropped() {
    let net = osis_transport::Net::new(4);
    let db = osis::internals::create(cfg(1, vec![], Some(net.endpoint("a")))).unwrap().0;
    db.register_schema("c.osis", "version 1;\naspect c:cursor.0~: map<tid, int> [expires: 60ms];\naspect c:flag.0~: map<tid, int>;\naspect c:on.0~: int [expires: 60ms];\n").unwrap();
    let k = db.aspect_key("c:cursor.0~").unwrap();
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let me = osis::Path(vec![osis::Step::Key(Value::Tid(db.node()))]);
    let mine = |db: &Osis| db.at(t, k.clone()).get().unwrap().and_then(|v| if let Value::Map(m) = v { m.get(&Value::Tid(db.node())).cloned() } else { None });
    assert!(db.at(t, db.aspect_key("c:flag.0~").unwrap()).path(me.clone()).keep_alive(&Value::Int(1)).is_err(), "no default expiry");
    let on = db.aspect_key("c:on.0~").unwrap();
    let whole = db.at(t, on.clone()).keep_alive(&Value::Int(7)).unwrap();
    assert_eq!(db.at(t, on.clone()).get().unwrap(), Some(Value::Int(7)), "the whole aspect");
    drop(whole);
    let ka = db.at(t, k.clone()).path(me).keep_alive(&Value::Int(1)).unwrap();
    assert_eq!(mine(&db), Some(Value::Int(1)));
    // rewritten every 30 ms: four writes besides the first come (GUARD only against a hang: no
    // wall-time assertion; expiry runs on the sync engine's ticks, so the gap is not watched)
    tokio::time::timeout(GUARD, async {
        while osis::internals::kept_writes(&ka) < 5 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(mine(&db), Some(Value::Int(1)));
    ka.set(&Value::Int(2)).unwrap();
    assert_eq!(mine(&db), Some(Value::Int(2)));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let _watch = db.at(t, k.clone()).on_change(move |_, _| tx.send(()).unwrap()).unwrap();
    drop(ka);
    tokio::time::timeout(GUARD, async {
        while mine(&db).is_some() {
            rx.recv().await;
        }
    })
    .await
    .unwrap();
}

/// Waits until `db` published its `reach.0` (the driver listens with its dialable key).
async fn reach_of(db: &Osis) -> osis::internals::node::sync::peers::Peer {
    tokio::time::timeout(GUARD, async {
        loop {
            if let Some(r) = db.sync_engine(|s| s.own_reach()) {
                return osis::internals::node::sync::peers::Peer { node: db.node(), reach: r, labels: Default::default() };
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

// spec/permissions.md §8 (first contact: the link carries the sharer's dialable key and relays),
// spec/sync.md §5 (co-reader peer): Bob cannot reach Alice's peer; he redeems her direct link at
// her node, opening the link's label there by the link key, and then syncs the target with
// her node though neither publishes `reach.0` to the other's groups by default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeem_direct_in_process_spec_permissions_8() {
    let net = osis_transport::Net::new(6);
    let host_ep = Some(net.endpoint("s"));
    let (host_db, host) = host_node(host_ep, "mem://s").await;
    net.partition("b", "s");
    let alice = osis::internals::create(cfg(1, vec![host], Some(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Some(net.endpoint("b")));
    c.app.internals.connection_wait = Some(GUARD);
    let bob = osis::internals::create(c).unwrap().0;
    let me = reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.me()]).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let mut w = alice.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("first contact".into())).unwrap();
    w.commit().unwrap();
    // `reach.0` went under g (only Alice reads it); the link's K joining g makes g stop
    // qualifying, so the key rotates, and the link carries the new one, listened on
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    let now = alice.sync_engine(|s| s.own_reach()).unwrap();
    assert_ne!(now.dialable, me.reach.dialable, "rotated: g no longer qualifies");
    let parsed = osis_label::ShareLink::from_text(&link.to_string()).unwrap();
    assert_eq!(parsed.peers, vec![osis_label::Peer { dialable: now.dialable, relays: vec![] }]);
    let probe = net.endpoint("probe");
    tokio::time::timeout(GUARD, async {
        while probe.dial(&osis_transport::Address { url: osis_transport::peer_url(&[]), key: now.dialable }).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap(), g);
    let want = Some(Value::Str("first contact".into()));
    tokio::time::timeout(GUARD, async {
        while bob.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Bob's writes reach Alice the same way
    let mut w = bob.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("back".into())).unwrap();
    w.commit().unwrap();
    let back = Some(Value::Str("back".into()));
    tokio::time::timeout(GUARD, async {
        while alice.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != back {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Bob keeps the sharer from the link; Alice never saw his dialable key (no co-reader proof)
    assert_eq!(bob.sync_engine(|s| s.link_peer_keys()), [now.dialable].into());
    let bob_key = bob.sync_engine(|s| s.own_reach()).unwrap().dialable;
    assert!(!alice.sync_engine(|s| s.served_co_readers()).contains(&bob_key));
    // the link ends (revoked): the key it carried rotates
    let k = alice.links_of(g).unwrap()[0].id.actor();
    tokio::time::timeout(GUARD, alice.revoke_link(crate::common::link_id(k), SyncFirst::Skip)).await.unwrap().unwrap();
    tokio::time::timeout(GUARD, async {
        while alice.sync_engine(|s| s.own_reach()).unwrap().dialable == now.dialable {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // a later holder of the link reaches nothing, and its follow is forgotten
    let mut c = cfg(3, vec![], Some(net.endpoint("c")));
    c.app.internals.connection_wait = Some(Duration::from_secs(2));
    let carol = osis::internals::create(c).unwrap().0;
    net.partition("c", "s");
    assert!(tokio::time::timeout(Duration::from_secs(2), carol.redeem(&link)).await.is_err());
    assert!(carol.sync_engine(|s| s.link_peer_keys()).is_empty());
    assert_eq!(carol.role_on(g).unwrap(), None);
    // even at the sharer's current key, K refuses the revoked link's key: the open fails there.
    // Erin is told at once; the new key is listened on first (a dial before that pauses the peer)
    let nk = alice.sync_engine(|s| s.own_reach()).unwrap().dialable;
    tokio::time::timeout(GUARD, async {
        while probe.dial(&osis_transport::Address { url: osis_transport::peer_url(&[]), key: nk }).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut patched = parsed.clone();
    patched.peers = vec![osis_label::Peer { dialable: nk, relays: vec![] }];
    // the sharer's node is its only route: a peer not answering would keep the verdict open
    patched.hosts = vec![];
    let patched: osis::ShareLink = patched.to_text().unwrap().parse().unwrap();
    let mut e = cfg(5, vec![], Some(net.endpoint("e")));
    e.app.internals.connection_wait = Some(GUARD);
    let erin = osis::internals::create(e).unwrap().0;
    assert!(matches!(tokio::time::timeout(GUARD, erin.redeem(&patched)).await.unwrap(), Err(osis::Error::Invalid(_))), "K's open was refused at the sharer");
    assert!(erin.sync_engine(|s| s.link_peer_keys()).is_empty());
    assert_eq!(erin.role_on(g).unwrap(), None);
    // a redemption dropped while it waits forgets its follow too (the key guard)
    net.partition("d", "s");
    let dave = osis::internals::create(cfg(4, vec![], Some(net.endpoint("d")))).unwrap().0;
    assert!(tokio::time::timeout(Duration::from_millis(300), dave.redeem(&link)).await.is_err());
    assert!(dave.sync_engine(|s| s.link_peer_keys()).is_empty());
    drop((alice, bob, carol, dave, erin));
    drop(host_db);
}

// spec/permissions.md §8 (a node without peers makes only direct links), spec/sync.md §5
// (co-reader peer: a label synced with nobody is served complete): Alice has no peer and no
// other node; Bob redeems her direct link at her node and the two sync the target there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redeem_direct_no_peer_in_process_spec_permissions_8() {
    let net = osis_transport::Net::new(9);
    let alice = osis::internals::create(cfg(1, vec![], Some(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Some(net.endpoint("b")));
    c.app.internals.connection_wait = Some(GUARD);
    let bob = osis::internals::create(c).unwrap().0;
    reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.me()]).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let mut w = alice.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("no host".into())).unwrap();
    w.commit().unwrap();
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    assert_eq!(tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap(), g);
    let want = Some(Value::Str("no host".into()));
    tokio::time::timeout(GUARD, async {
        while bob.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut w = bob.write();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("back".into())).unwrap();
    w.commit().unwrap();
    let back = Some(Value::Str("back".into()));
    tokio::time::timeout(GUARD, async {
        while alice.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != back {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Bob leaves, K rotates: the link goes on for a next redeemer at her node (spec/sync.md §2)
    let k = alice.links_of(g).unwrap()[0].id.actor();
    let before = alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap());
    tokio::time::timeout(GUARD, bob.set_role(k, bob.me(), None, SetRoleOpts { sync: SyncFirst::Skip, retain_copy: None })).await.unwrap().unwrap();
    tokio::time::timeout(GUARD, async {
        while alice.engine(|e| e.epochs(&k).unwrap().read.newest().unwrap()) == before {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut c = cfg(3, vec![], Some(net.endpoint("c")));
    c.app.internals.connection_wait = Some(GUARD);
    let carol = osis::internals::create(c).unwrap().0;
    assert_eq!(tokio::time::timeout(GUARD, carol.redeem(&link)).await.unwrap().unwrap(), g);
    tokio::time::timeout(GUARD, async {
        while carol.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != back {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

// spec/requirements.md Offline and network, notes/api.md Sync configuration: status never says a
// group has nobody while a node is connected on it, whichever side dialed: Alice shows `NoPeers`, and
// `Connected` once Bob dialed her by her direct link; he shows it too, and `peers` names her to him.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_says_connected_with_a_direct_peer() {
    let net = osis_transport::Net::new(9);
    let alice = osis::internals::create(cfg(1, vec![], Some(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Some(net.endpoint("b")));
    c.app.internals.connection_wait = Some(GUARD);
    let bob = osis::internals::create(c).unwrap().0;
    reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.me()]).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    assert_eq!(alice.status().unwrap().groups[&g].state, osis::SyncState::NoPeers);
    assert_eq!(alice.status().unwrap().connected, 0);
    assert!(alice.peers(g).unwrap().is_empty(), "nobody known");
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap();
    tokio::time::timeout(GUARD, async {
        while alice.status().unwrap().groups[&g].state != osis::SyncState::Connected || bob.status().unwrap().groups.get(&g).map(|x| x.state) != Some(osis::SyncState::Connected) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(alice.status().unwrap().connected > 0, "a connection she was dialed on counts");
    assert!(!bob.peers(g).unwrap().is_empty(), "she is known to him");
}

// notes/api.md Sync configuration: `peers` starts from the peers saved on the group, and `saved_peers`
// is the node's own list, which a group's naming others does not touch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peers_lists_what_a_group_saved() {
    let db = osis::internals::create(cfg(1, vec![], None)).unwrap().0;
    let there = Address::new(&"quic://192.0.2.1:9".parse().unwrap(), [7; 32]);
    let mut w = db.write();
    let g = w.create_in(db.me(), &[db.me()]).unwrap();
    w.commit().unwrap();
    assert!(db.peers(g).unwrap().is_empty(), "not synced");
    db.sync(g, std::slice::from_ref(&there)).unwrap();
    assert_eq!(db.peers(g).unwrap(), vec![there]);
    assert!(db.saved_peers().unwrap().is_empty());
}

// spec/permissions.md §8 (a single-use link finalized by its redemption does not rotate): Bob
// redeems Alice's single-use direct link with no peer between them; once Alice finalizes it,
// her key is the one the link carried and Bob's writes still reach her directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_use_direct_keeps_key_in_process_spec_permissions_8() {
    let net = osis_transport::Net::new(8);
    let host_ep = Some(net.endpoint("s"));
    let (host_db, host) = host_node(host_ep, "mem://s").await;
    net.partition("b", "s");
    let alice = osis::internals::create(cfg(1, vec![host.clone()], Some(net.endpoint("a")))).unwrap().0;
    let mut c = cfg(2, vec![], Some(net.endpoint("b")));
    c.app.internals.connection_wait = Some(GUARD);
    let bob = osis::internals::create(c).unwrap().0;
    reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.me()]).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let link = alice.make_link(g, osis::Role::Write, osis::LinkOpts { direct: true, single_use: true, ..Default::default() }).unwrap();
    let key = alice.sync_engine(|s| s.own_reach()).unwrap().dialable;
    assert_eq!(osis_label::ShareLink::from_text(&link.to_string()).unwrap().peers[0].dialable, key);
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();
    assert_eq!(tokio::time::timeout(GUARD, bob.redeem(&link)).await.unwrap().unwrap(), g);
    tokio::time::timeout(GUARD, async {
        while !alice.links_of(g).unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(alice.sync_engine(|s| s.own_reach()).unwrap().dialable, key, "finalized by redemption: kept");
    let mut w = bob.write();
    let t = w.create_in(g, &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("still direct".into())).unwrap();
    w.commit().unwrap();
    let want = Some(Value::Str("still direct".into()));
    tokio::time::timeout(GUARD, async {
        while alice.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap() != want {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    drop((alice, bob));
    drop(host_db);
}

// spec/sync.md §10, notes/api.md (`rotate_reach`): a rotated dialable key is listened on at once,
// without a restart, and the old one no longer answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotate_reach_relistens_in_process_spec_sync_10() {
    let net = osis_transport::Net::new(7);
    let db = osis::internals::create(cfg(1, vec![], Some(net.endpoint("a")))).unwrap().0;
    let old = reach_of(&db).await.reach;
    // spec/permissions.md §8: direct is opt-in; without peers a link must be direct
    assert!(matches!(db.make_link(db.me(), osis::Role::Read, Default::default()), Err(osis::Error::Invalid(_))));
    let probe = net.endpoint("probe");
    let dial = |key: [u8; 32]| {
        let probe = probe.clone();
        async move { osis_transport::Transport::dial(&probe, &osis_transport::Address { url: osis_transport::peer_url(&[]), key }).await.is_ok() }
    };
    assert!(dial(old.dialable).await);
    db.rotate_peer_address().unwrap();
    let new = db.sync_engine(|s| s.own_reach()).unwrap();
    assert_ne!(new.dialable, old.dialable);
    assert_ne!(new.lan_secret, old.lan_secret);
    tokio::time::timeout(GUARD, async {
        while !dial(new.dialable).await || dial(old.dialable).await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

// notes/api.md Handle and sync: closing a node whose own runtime's driver is inside an
// engine call (its `block_in_place`) must not let the driver poll a timer of the shut-down
// runtime (tokio panics "... it is being shutdown" on an `osis-sync` thread). spec: none (an API property)
#[test]
fn close_while_driver_runs_no_timer_panic() {
    count_shutdown_panics();
    let net = osis_transport::Net::new(9);
    std::thread::scope(|sc| {
        for t in 0..8u64 {
            let net = net.clone();
            sc.spawn(move || {
                for i in 0..40 {
                    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
                    c.app.internals.seed = Some(t * 1000 + i);
                    c.runtime = Runtime::Own;
                    c.app.internals.transport = Some(net.endpoint(&format!("c{t}-{i}")));
                    let (db, _) = osis::internals::create(c).unwrap();
                    let _ = common::block_on(db.wait_synced(osis::SyncScope::AllWithPeers));
                    assert_eq!(db.close().unwrap(), osis::Close::Closed);
                }
            });
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(shutdown_panics("osis-sync"), 0);
}

/// Names of the threads that panicked on a timer of a shut-down tokio runtime.
static SHUTDOWN_PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Installs (once) a panic hook recording `SHUTDOWN_PANICS`.
fn count_shutdown_panics() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |i| {
            if i.to_string().contains("being shutdown") {
                let name = std::thread::current().name().unwrap_or("").to_string();
                SHUTDOWN_PANICS.lock().unwrap_or_else(|p| p.into_inner()).push(name);
            }
            prev(i);
        }));
    });
}

/// How many threads named `prefix...` panicked on a timer of a shut-down runtime.
fn shutdown_panics(prefix: &str) -> usize {
    SHUTDOWN_PANICS.lock().unwrap_or_else(|p| p.into_inner()).iter().filter(|n| n.starts_with(prefix)).count()
}

// notes/api.md Handle and sync: `close` returns once the store is closed, also with
// `Runtime::Own` (whose runtime stops in the background): the store opens again at once and
// holds every write. spec: none (an API property)
#[test]
fn own_runtime_reopen_right_after_close() {
    let dir = std::env::temp_dir().join(format!("osis-reopen-{}-{}", std::process::id(), rand_suffix()));
    let net = osis_transport::Net::new(10);
    let at = |i: u64| {
        let mut c = osis::internals::Opening::at(Store::Dir(dir.clone()));
        c.app.internals.seed = Some(i);
        c.runtime = Runtime::Own;
        c.app.internals.transport = Some(net.endpoint(&format!("r{i}")));
        c
    };
    let (db, _) = osis::internals::create(at(0)).unwrap();
    let mut w = db.write();
    let t = w.create_durable(db.me()).unwrap();
    w.commit().unwrap();
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    for i in 1..12u64 {
        let db = osis::internals::open(at(i)).unwrap();
        assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(ak("n:v.0"))).get().unwrap(), (i > 1).then(|| Value::Int(i as i64 - 1)));
        db.commit_set(t, osis::DynamicAspectKey::untyped(ak("n:v.0")), &Value::Int(i as i64)).unwrap();
        assert_eq!(db.close().unwrap(), osis::Close::Closed);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0);
    h.finish()
}

// notes/api.md Handle and sync: closing a node on the app's runtime (`Runtime::Tokio`)
// and then shutting that runtime down must not let the driver poll a timer of the shut-down
// runtime. spec: none (an API property)
#[test]
fn tokio_runtime_close_then_shutdown_no_timer_panic() {
    count_shutdown_panics();
    let net = osis_transport::Net::new(11);
    std::thread::scope(|sc| {
        for t in 0..8u64 {
            let net = net.clone();
            sc.spawn(move || {
                for i in 0..40 {
                    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("tk-close").enable_all().build().unwrap();
                    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
                    c.app.internals.seed = Some(t * 1000 + i);
                    c.runtime = Runtime::Tokio(rt.handle().clone());
                    c.app.internals.transport = Some(net.endpoint(&format!("k{t}-{i}")));
                    let (db, _) = osis::internals::create(c).unwrap();
                    let _ = common::block_on(db.wait_synced(osis::SyncScope::AllWithPeers));
                    assert_eq!(db.close().unwrap(), osis::Close::Closed);
                    drop(rt);
                }
            });
        }
    });
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(shutdown_panics("tk-close"), 0);
}

// spec/data-model.md §9 (`host.0^` `own`), notes/cli.md Serving (a dedicated peer node): a
// node paired to Alice's account peers under `own` on the handle's driver (the account set
// before the driver starts), the only peer either node knows: her home, a group she makes
// afterwards and a link to it all reach it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_serving_node_in_process_spec_data_model_9() {
    let net = osis_transport::Net::new(6);
    let alice = osis::internals::create(cfg(1, vec![], Some(net.endpoint("a")))).unwrap().0;
    let j = osis::internals::pair(cfg(2, vec![], Some(net.endpoint("h"))), &alice.pair_offer().unwrap()).unwrap();
    let (_, reply) = alice.pair_accept(j.request()).unwrap();
    let dev = j.finish(&reply).unwrap();
    assert_eq!(dev.me(), alice.me());
    // the refused-for-now back-off (5 s) shortened: the test waits it once per new label
    alice.sync_engine(|s| s.config_mut().retry_ms = 100);
    dev.set_serving(Some(osis::Serving { listen: vec!["mem://h".parse().unwrap()], admit: osis::Admit::Own, ..Default::default() })).unwrap();
    let ha = tokio::time::timeout(GUARD, async {
        loop {
            if let Some(a) = dev.serving_address().unwrap() {
                return a;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    dev.add_peer(&ha).unwrap();
    alice.add_peer(&ha).unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();

    let mut w = alice.write();
    let g = w.create_in(alice.me(), &[alice.me()]).unwrap();
    w.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();
    alice.make_link(g, osis::Role::Write, Default::default()).unwrap();
    tokio::time::timeout(GUARD, alice.wait_synced(SyncScope::AllWithPeers)).await.unwrap().unwrap();
}

// notes/api.md Handle and sync: a sync driver that panics (inside an engine call, under the lock)
// fails the waits pending on it and every later one with `Network` naming the panic, at once
// rather than at their deadline (a dead driver fires no timer), and reports `SyncStopped`.
// spec: none (an API property)
#[test]
fn driver_panic_fails_waiters() {
    let net = osis_transport::Net::new(12);
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.app.internals.seed = Some(3);
    c.runtime = Runtime::Own;
    c.app.internals.transport = Some(net.endpoint("dp"));
    // a peer nobody answers at: `wait_synced(All)` waits
    c.hosts = vec![Address::new(&"mem://nobody".parse().unwrap(), [7; 32])];
    let (db, _) = osis::internals::create(c).unwrap();
    let (dtx, drx) = std::sync::mpsc::channel();
    let _sub = db.on_diagnostic(move |_, d| {
        let _ = dtx.send(d);
    }).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let d2 = db.clone();
    let waiter = std::thread::spawn(move || {
        let _ = tx.send(common::block_on(d2.wait_synced(SyncScope::AllWithPeers)));
    });
    let t0 = std::time::Instant::now();
    while db.waiting() == 0 {
        assert!(t0.elapsed() < GUARD, "the wait never registered");
        std::thread::sleep(Duration::from_millis(5));
    }
    db.panic_driver();
    let r = rx.recv_timeout(GUARD).expect("a wait hung on a dead driver");
    // its handle goes with the thread: `close` below refuses while one is open
    waiter.join().unwrap();
    let died = |r: osis::Result<()>| match r {
        Err(osis::Error::Network(m)) => assert!(m.contains("sync driver panicked: test: the sync driver panics"), "{m}"),
        r => panic!("{r:?}"),
    };
    died(r);
    // a later wait fails at once too
    died(common::block_on(db.wait_synced(SyncScope::AllWithPeers)));
    let d = loop {
        let d = drx.recv_timeout(GUARD).expect("no SyncStopped diagnostic");
        if let osis::Diagnostic::SyncStopped { detail } = d {
            break detail;
        }
    };
    assert!(d.contains("test: the sync driver panics"), "{d}");
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
}

// spec: none (API surface, notes/api.md Futures): a wait known never to finish fails: a link naming no peer, on a node that dials nobody directly
#[tokio::test]
async fn direct_link_with_peers_off_fails_at_once() {
    let net = osis_transport::Net::new(2);
    let alice = osis::internals::create(cfg(1, vec![], Some(net.endpoint("a")))).unwrap().0;
    let _ = reach_of(&alice).await;
    let mut w = alice.write();
    let g = w.create().unwrap();
    w.commit().unwrap();
    let link = alice.make_link(g, osis::Role::Read, osis::LinkOpts { direct: true, ..Default::default() }).unwrap();
    let mut c = cfg(2, vec![], Some(net.endpoint("b")));
    c.direct_sync = false;
    let bob = osis::internals::create(c).unwrap().0;
    let r = tokio::time::timeout(GUARD, bob.redeem(&link)).await.expect("waits for what can never come");
    assert!(matches!(r, Err(osis::Error::Network(_))), "{r:?}");
}

// spec: none (API surface, notes/api.md Futures): a wait holding no handle (the client port's) hears when the node goes
#[tokio::test]
async fn database_going_answers_a_wait_with_no_handle() {
    let net = osis_transport::Net::new(2);
    // a peer nobody answers at: `wait_synced(All)` waits
    let nobody = Address::new(&"mem://nobody".parse().unwrap(), [7; 32]);
    let db = osis::internals::create(cfg(1, vec![nobody], Some(net.endpoint("a")))).unwrap().0;
    let f = db.wait_synced_no_handle(SyncScope::AllWithPeers);
    assert_eq!(db.waiting(), 1);
    drop(db);
    let r = tokio::time::timeout(GUARD, f).await.expect("nothing answers it");
    assert!(matches!(r, Err(osis::Error::Closed)), "{r:?}");
}
