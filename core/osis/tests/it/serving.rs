//! A node that serves (notes/api.md Serving, notes/serving.md), in process: its `host^.0`
//! runs a hub the world steps; the node's own dials of its peer address reach it like anyone's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;
use common::*;
use crate::common::CreateIn;
use osis::internals::Internals as _;
use osis::{Admit, Address, Serving, Osis, Role, Tid, Value};
use osis::internals::{LabelId};
use osis_sim::world::World;

fn item(db: &Osis, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(db.me(), &[g]).unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str(v.into())).unwrap();
    w.commit().unwrap();
    t
}

fn home_label(db: &Osis) -> LabelId {
    let home = db.home();
    db.sync_engine(|s| s.labels().into_iter().find(|(g, _)| *g == home).map(|(_, l)| l.id)).unwrap()
}

fn hosted(w: &World, s: usize) -> Vec<LabelId> {
    w.hosts[s].hub.store().labels_after(None, 1000).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|x| x == needle)
}

// spec/wire.md §11.2 (an unadmitted genesis step gets code 14), notes/serving.md, spec/requirements.md
// Data a node cannot read, issues/net-one-peer.md step 4: Alice serves admitting nothing for others: her
// home label, which she reads, is in her one store with no setup (no saved peer of her own); Bob's is
// refused until she opens admission (his status names her peer, his home synced at his other peer;
// Carol's, at her peer only, `Refused`, and `wait_synced` waits: it may yet be admitted), then
// served unread (she holds none of its keys) and served to Bob's paired node. Her store holds no
// tid or AK of either label in any row it ever wrote.
#[test]
fn serving_listed_then_open_spec_sync_5() {
    let mut w = World::new();
    let base = w.add_host();
    // Alice's one store records every write (the hygiene check below)
    let mut c = w.cfg(1, &[base]);
    let mem = osis::MemStore::new();
    let hub_rows = osis::internals::MemStoreMeasures::hub_backend(&mem);
    hub_rows.record_history();
    c.store = osis::Store::Memory(mem);
    let alice = osis::internals::create(c).unwrap();
    let bob = w.account(2, &[base]);
    let carol = w.account(3, &[base]);
    w.run();
    alice.set_serving(Some(Serving { admit: Admit::Listed, ..Default::default() })).unwrap();
    let ha = alice.listen(&["quic://alice:1".parse().unwrap()]).unwrap().remove(0);
    w.run();
    assert_eq!(alice.serving().unwrap().unwrap().admit, Admit::Listed);
    let ai = w.index(&alice).unwrap();
    let s = w.host_of(ai).unwrap();

    // Bob's home label names her peer: refused; hers is in her store, read
    bob.add_peer(&ha).unwrap();
    carol.add_peer(&ha).unwrap();
    carol.remove_peer(&w.addr(base).unwrap()).unwrap();
    let ta = item(&alice, alice.home(), "alice's");
    let tb = item(&bob, bob.home(), "bob's");
    w.run();
    w.advance(120_000);
    let (la, lb) = (home_label(&alice), home_label(&bob));
    assert!(hosted(&w, s).contains(&la), "a label she reads");
    assert!(!hosted(&w, s).contains(&lb), "another account's label refused");
    let st = bob.status().unwrap().groups[&bob.home()].clone();
    assert_eq!((st.state, st.refused_by), (osis::SyncState::Synced, vec![ha.clone()]), "not admitted, not full; synced at base");
    w.until(bob.wait_synced(osis::SyncScope::Thing(bob.home())), 1000, 10).unwrap();
    let st = carol.status().unwrap().groups[&carol.home()].clone();
    assert_eq!((st.state, st.refused_by), (osis::SyncState::Refused, vec![ha.clone()]), "at no other host");
    assert!(w.try_until(carol.wait_synced(osis::SyncScope::Thing(carol.home())), 1000, 10).is_none());

    // open: Bob's label is taken at his next registration
    alice.set_serving(Some(Serving { admit: Admit::Open, ..alice.serving().unwrap().unwrap() })).unwrap();
    w.run();
    for _ in 0..5 {
        w.advance(120_000);
    }
    assert!(hosted(&w, s).contains(&lb), "open: admitted");

    // Bob's new node, paired, given Alice's peer: his label is served from her store, unread by her
    let mut cfg = w.cfg(3, &[]);
    cfg.hosts = vec![ha];
    let join = osis::internals::pair(cfg, &bob.pair_offer().unwrap()).unwrap();
    let (_, reply) = bob.pair_accept(join.request()).unwrap();
    let paired = join.finish(&reply).unwrap();
    w.until(paired.wait_synced(osis::SyncScope::Thing(bob.home())), 1000, 30).unwrap();
    assert_eq!(paired.at(tb, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), Some(Value::Str("bob's".into())));

    // hygiene: no tid or AK of the label Alice reads or the one she does not
    let mut history = hub_rows.history();
    assert!(!history.is_empty());
    let keys = w.hosts[s].hub.store().store_mut().unwrap().forensic_keys().unwrap();
    let plain = osis_store::attack(&osis_store::Evidence { store_keys: keys, rows: history.clone(), ..Default::default() }, None).into_iter().map(|r| r.plain).collect::<Vec<_>>();
    history.extend(plain.into_iter().map(|p| (Vec::new(), p)));
    for needle in [ta.as_bytes().as_slice(), tb.as_bytes(), alice.me().as_bytes(), bob.me().as_bytes(), alice.node().as_bytes(), bob.node().as_bytes(), b"t:x.0"] {
        for (k, v) in &history {
            assert!(!contains(k, needle) && !contains(v, needle));
        }
    }

    // stopping: what was stored for others goes, what she reads stays
    alice.set_serving(None).unwrap();
    w.run();
    assert!(!alice.sync_engine(|e| e.hosts()));
    assert_eq!(hosted(&w, s), vec![la]);
}

// notes/api.md Serving, issues/net-one-peer.md step 4: a node serves the groups it reads from its one
// store with no setup and no peer of its own: Alice, not serving for others, listens; her group
// names her address alone; Bob, granted it, syncs it there and reads it.
#[test]
fn a_reader_serves_what_it_reads_with_no_setup_spec_data_model_9() {
    let mut w = World::new();
    let base = w.add_host();
    let alice = w.account(1, &[base]);
    let bob = w.account(2, &[base]);
    let ha = alice.listen(&["quic://alice:1".parse().unwrap()]).unwrap().remove(0);
    w.run();
    let b = w.until(alice.import_contact(&bob.contact_card().unwrap()), 1000, 10).unwrap();
    let g = group_of(&alice, alice.me(), alice.home(), &[ha]);
    let mut tx = alice.write();
    let t = tx.create_in(g, &[g]).unwrap();
    tx.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).set(&Value::Str("x".into())).unwrap();
    tx.commit().unwrap();
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    w.run();
    w.until(bob.wait_synced(osis::SyncScope::Thing(g)), 1000, 30).unwrap();
    assert_eq!(bob.at(t, osis::DynamicAspectKey::untyped(ak("t:x.0"))).get().unwrap(), Some(Value::Str("x".into())));
    let ai = w.index(&alice).unwrap();
    let s = w.host_of(ai).unwrap();
    assert!(hosted(&w, s).contains(&label_of(&alice, g)), "served from her own store");
}

/// A group whose first admin is `admin` (held by `db`), added to `within`, synced on `hosts`.
fn group_of(db: &Osis, admin: Tid, within: Tid, hosts: &[Address]) -> Tid {
    let mut w = db.write();
    let g = w.create_in(admin, &[within]).unwrap();
    w.commit().unwrap();
    db.sync(g, hosts).unwrap();
    g
}

fn label_of(db: &Osis, g: Tid) -> LabelId {
    db.sync_engine(|s| s.labels().into_iter().find(|(x, _)| *x == g).map(|(_, l)| l.id)).expect("Alice reads it")
}

/// Alice (listening on a test peer) and Bob, contacts both ways: (world, alice, bob, base peer,
/// Alice's peer address, Alice's account as Bob knows it, Bob's as Alice knows it).
fn pair(seed: u64) -> (World, Osis, Osis, usize, Address, Tid, Tid) {
    let mut w = World::new();
    let base = w.add_host();
    let alice = w.account(seed * 2 + 1, &[base]);
    let bob = w.account(seed * 2 + 2, &[base]);
    w.run();
    let ha = alice.listen(&["quic://alice:1".parse().unwrap()]).unwrap().remove(0);
    w.run();
    let (ca, cb) = (alice.contact_card().unwrap(), bob.contact_card().unwrap());
    w.run();
    let a = w.until(bob.import_contact(&ca), 1000, 10).unwrap();
    let b = w.until(alice.import_contact(&cb), 1000, 10).unwrap();
    (w, alice, bob, base, ha, a, b)
}

// spec/sync.md §3 (the nearest home label up a group's chain carries its `label.0` and
// `created.0`), spec/commits.md §4: Bob, granted a parent group after a labeled child group was made
// under it, has neither the child's record nor its label's key. The copy under the parent's label,
// opened with the box of the grant's chain, makes the child's records and keys reachable: he holds
// its role with no direct grant.
#[test]
fn home_label_copy_reaches_the_labeled_child_spec_sync_3() {
    let (mut w, alice, bob, base, ha, _a, b) = pair(6);
    let hosts = [w.addr(base).unwrap(), ha.clone()];
    let y = group_of(&alice, alice.me(), alice.me(), &[]);
    let g = group_of(&alice, y, y, &hosts);
    alice.grant(y, b, Role::Admin, Default::default()).unwrap();
    w.run();
    assert_eq!(bob.role_on(g).unwrap(), Some(Role::Admin));
}

/// Waits (up to 30 s) for `f` to hold.
fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !f() {
        assert!(std::time::Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The labels the store at `dir` keeps for others (the node closed): not those it reads.
fn host_store_labels(dir: &std::path::Path) -> Vec<LabelId> {
    let b = osis_store::RedbBackend::open(&dir.join("host.redb")).unwrap();
    let r = osis_store::FileRoot::new(dir.join("host.root"));
    let s = osis_store::Store::open(Box::new(b), Box::new(r), osis_store::StoreConfig::default()).unwrap();
    let clock: std::sync::Arc<dyn osis::internals::Clock> = std::sync::Arc::new(osis_base::SystemClock);
    let h = osis_host::HostStore::open(s, clock, osis_host::HostPolicy::default(), Box::new(osis_crypto::OsRng)).unwrap();
    h.labels_after(None, 1000).unwrap().into_iter().filter(|l| !h.reads(l)).collect()
}

// spec/data-model.md §9 (`host^.0` absent: it does not serve), spec/requirements.md Deletion,
// issues/net-one-peer.md step 4: stopping serving drops what the node kept for others from its
// one store (shredded), not the store: on a running driver, or at the next driver start when it
// stopped while none ran.
#[test]
fn stop_serving_drops_what_it_kept_spec_data_model_9() {
    let dir = std::env::temp_dir().join(format!("osis-host-drop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let net = osis_transport::Net::new(41);
    let at = |i: u64, run: bool| {
        let mut c = osis::internals::Opening::at(osis::Store::Dir(dir.clone()));
        c.app.internals.seed = Some(i);
        c.direct_sync = false;
        if run {
            c.runtime = osis::Runtime::Own;
            c.app.internals.transport = Some(net.endpoint(&format!("e{i}")));
        }
        c
    };
    let kept = |db: &Osis| {
        db.sync_engine(|s| {
            let h = s.hub_store();
            let h = h.lock().unwrap();
            h.labels_after(None, 1000).unwrap().into_iter().filter(|l| !h.reads(l)).collect::<Vec<_>>()
        })
    };
    let hosting = || Some(Serving { admit: Admit::Open, ..Default::default() });
    let listen = |db: &Osis| db.listen(&["mem://e".parse().unwrap()]).unwrap().remove(0);

    // another node's home label, registered at `addr`
    let theirs = |seed: u64, addr: &Address| {
        let mut c = osis::internals::Opening::at(osis::Store::Memory(osis::MemStore::new()));
        c.app.internals.seed = Some(seed);
        c.direct_sync = false;
        c.runtime = osis::Runtime::Own;
        c.app.internals.transport = Some(net.endpoint(&format!("other{seed}")));
        let other = osis::internals::create(c).unwrap();
        other.add_peer(addr).unwrap();
        common::block_on(other.wait_synced(osis::SyncScope::All)).unwrap();
        let l = home_label(&other);
        assert_eq!(other.close().unwrap(), osis::Close::Closed);
        l
    };

    // serving, with another node's label registered there (its own home label it reads: never
    // kept for others)
    let db = osis::internals::create(at(1, true)).unwrap();
    db.set_serving(hosting()).unwrap();
    let addr = listen(&db);
    let l = theirs(100, &addr);
    assert_eq!(kept(&db), vec![l]);
    let home = home_label(&db);
    assert!(db.sync_engine(|s| s.hub_store().lock().unwrap().labels_after(None, 1000).unwrap()).contains(&home));

    // stopped on a running driver: what it kept goes, the store stays
    db.set_serving(None).unwrap();
    wait_for("what it kept dropped", || kept(&db).is_empty());
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    assert!(dir.join("host.redb").exists() && dir.join("host.root").exists());
    assert!(host_store_labels(&dir).is_empty());

    // stopped with no driver running: the next driver start drops it
    let db = osis::internals::open(at(5, true)).unwrap();
    db.set_serving(hosting()).unwrap();
    let addr = listen(&db);
    let l = theirs(101, &addr);
    wait_for("their label kept", || kept(&db) == vec![l]);
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let db = osis::internals::open(at(6, false)).unwrap();
    db.set_serving(None).unwrap();
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    assert_eq!(host_store_labels(&dir), vec![l]);
    let db = osis::internals::open(at(7, true)).unwrap();
    wait_for("what it kept dropped", || kept(&db).is_empty());
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    let _ = std::fs::remove_dir_all(&dir);
}

// notes/api.md Handle and sync: `close` with `Runtime::Own` returns once the driver, and with it
// the peer, is gone, so the serving store is free: reopening at once serves again (not "Database
// already open"). spec: none (an API property)
#[test]
fn own_runtime_close_frees_serving_store() {
    let dir = std::env::temp_dir().join(format!("osis-host-reopen-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let net = osis_transport::Net::new(42);
    let at = |i: u64| {
        let mut c = osis::internals::Opening::at(osis::Store::Dir(dir.clone()));
        c.app.internals.seed = Some(i);
        c.direct_sync = false;
        c.runtime = osis::Runtime::Own;
        c.app.internals.transport = Some(net.endpoint(&format!("o{i}")));
        c
    };
    // its own home served from its own store, open
    let served = |db: &Osis| {
        db.listen(&["mem://o".parse().unwrap()]).unwrap();
        let home = home_label(db);
        wait_for("served", || db.sync_engine(|s| s.hub_store().lock().unwrap().labels_after(None, 1000).unwrap()).contains(&home));
    };
    let db = osis::internals::create(at(0)).unwrap();
    db.set_serving(Some(Serving { admit: Admit::Open, ..Default::default() })).unwrap();
    served(&db);
    assert_eq!(db.close().unwrap(), osis::Close::Closed);
    for i in 1..6 {
        let db = osis::internals::open(at(i)).unwrap();
        served(&db);
        assert_eq!(db.close().unwrap(), osis::Close::Closed);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// spec: none (notes/api.md Serving): a stored limit this build does not know (another node's newer one) hides none
// of the others from `hosting`, and a read-then-set keeps them all.
#[test]
fn an_unknown_stored_limit_loses_nothing() {
    let db = osis::internals::create(cfg(1, osis::MemStore::new(), &clock())).unwrap();
    db.set_serving(Some(osis::Serving { policy: osis::ServingPolicy { groups: 7, ..Default::default() }, ..Default::default() })).unwrap();
    let node = db.node();
    let mut stored = db.at(node, osis::internals::core_types::HOST).get().unwrap().unwrap();
    stored.policy.insert("a_later_limit".into(), 9);
    let mut w = db.write();
    w.at(node, osis::internals::core_types::HOST).overwrite(&stored).unwrap();
    w.commit().unwrap();
    let mut read = db.serving().unwrap().unwrap();
    assert_eq!(read.policy.groups, 7, "the limits it knows");
    read.policy.entries = 11;
    db.set_serving(Some(read)).unwrap();
    let p = db.at(node, osis::internals::core_types::HOST).get().unwrap().unwrap().policy;
    assert_eq!((p.get("max_labels"), p.get("max_entries"), p.get("a_later_limit")), (Some(&7), Some(&11), Some(&9)));
    assert_eq!(db.serving().unwrap().unwrap().policy.groups, 7);
}

// spec: none (notes/api.md Serving): a stored value out of a known limit's range runs as the default, is
// kept like an unknown name, and gives way when that limit is set: it must not win over it.
#[test]
fn a_stored_limit_out_of_range_gives_way() {
    let db = osis::internals::create(cfg(1, osis::MemStore::new(), &clock())).unwrap();
    db.set_serving(Some(osis::Serving::default())).unwrap();
    let node = db.node();
    let mut stored = db.at(node, osis::internals::core_types::HOST).get().unwrap().unwrap();
    stored.policy.insert("max_queued_bytes".into(), 1);
    let mut w = db.write();
    w.at(node, osis::internals::core_types::HOST).overwrite(&stored).unwrap();
    w.commit().unwrap();
    let mut read = db.serving().unwrap().unwrap();
    osis::internals::host_limit(&mut read.policy, "max_queued_bytes", 1 << 30).unwrap();
    db.set_serving(Some(read)).unwrap();
    let p = db.at(node, osis::internals::core_types::HOST).get().unwrap().unwrap().policy;
    assert_eq!(p.get("max_queued_bytes"), Some(&(1 << 30)), "what was set");
}
