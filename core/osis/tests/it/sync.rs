//! The osis API over the new sync: status, waits, listening, links and cards,
//! `keep_alive`, and the client port's node side; nodes on one in-process test network
//! (`internals::ManualNet`) with one manual clock, or with no network at all.

use crate::common::{T0, cfg, clock, db};
use osis::internals::proto::Msg;
use osis::internals::proto::api::{ApiCode, Outcome};
use osis::internals::{ManualClock, ManualNet};
use osis::{Error, LinkOpts, MemStore, Osis, Role, SyncScope, Time, Value};
use std::sync::Arc;

/// Node `seed` on `net`, at `clock`.
fn on(net: &ManualNet, seed: u64, clock: &Arc<ManualClock>) -> Osis {
    let mut c = cfg(seed, MemStore::new(), clock);
    c.app.internals.net = Some(net.clone());
    osis::internals::create(c).unwrap()
}

/// Polls `f` once with a no-op waker: what a wait says at once.
fn now<T>(f: impl std::future::Future<Output = T>) -> std::task::Poll<T> {
    let mut f = std::pin::pin!(f);
    f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
}

// spec/sync-status.md §3 (status): a node connected to nobody says so, and lists only what its
// sync set holds.
#[test]
fn status_with_nobody_connected_spec_sync_status_3() {
    let db = db(1);
    let s = db.status().unwrap();
    assert_eq!(s.connected, 0);
    assert!(s.groups.values().all(|g| g.state == osis::SyncState::NotConnected || g.state == osis::SyncState::Stranded));
}

// spec/sync-status.md §3 (waits): with no network a wait not done at once can never end, so it
// fails `Network` at once (notes/api-design.md: a wait sure never to finish fails); a node alone
// is done at once.
#[test]
fn wait_synced_with_no_network_fails_network_spec_sync_status_3() {
    let db = db(2);
    for scope in [SyncScope::All, SyncScope::Thing(db.home()), SyncScope::Deliveries] {
        match now(db.wait_synced(scope)) {
            std::task::Poll::Ready(Err(Error::Network(_))) | std::task::Poll::Ready(Ok(())) => {}
            r => panic!("{scope:?}: {r:?}"),
        }
    }
}

// spec/sync-status.md §3 (waits): a sync ID no peer shares holds no wait: a node alone (a
// one-node account) ends a wait on all, on home and on a thing filed under home at once,
// connected to nobody; a wait on a thing never known here runs on (to the caller's timeout);
// a wait on deliveries with none owed ends at once.
#[test]
fn a_node_alone_waits_on_nothing_spec_sync_status_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 5, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.commit().unwrap();
    net.run();
    for scope in [SyncScope::All, SyncScope::Thing(a.home()), SyncScope::Thing(t), SyncScope::Deliveries] {
        assert!(matches!(now(a.wait_synced(scope)), std::task::Poll::Ready(Ok(()))), "{scope:?}");
    }
    let mut w = a.write();
    let never = w.create().unwrap();
    drop(w);
    net.advance(60_000);
    assert!(now(a.wait_synced(SyncScope::Thing(never))).is_pending(), "never known here");
}

// spec/sync-transport.md §5 (One key): a node listens under its one key; with no network it
// cannot, and a store in memory has no client socket.
#[test]
fn listening_needs_a_network_and_a_socket_a_directory_spec_sync_transport_5() {
    let db = db(4);
    let url: osis::Url = "quic://127.0.0.1:4040".parse().unwrap();
    assert!(matches!(db.listen(&[url]), Err(Error::Network(_))));
    assert!(matches!(db.listen_socket(), Err(Error::Invalid(_))));
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 5, &c);
    let url: osis::Url = "peer://127.0.0.1:1".parse().unwrap();
    let addrs = a.listen(std::slice::from_ref(&url)).unwrap();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].url(), url);
    // a new key: a new address, the old one dialed no more
    a.rotate_peer_address().unwrap();
    let again = a.listen(&[url]).unwrap();
    assert_ne!(again[0].key(), addrs[0].key());
}

// spec/sync-transport.md §3 (`reach.0` lists; each time it starts listening),
// §5 (key change), spec/sync-set.md §1 (dial list: each node keeping its own entry): listening
// publishes the node's global addresses in `reach.0` and its profile's dial list under its key;
// a new key replaces its entry.
#[test]
fn listening_publishes_where_the_node_is_dialed_spec_sync_transport_3() {
    use osis::internals::Internals;
    use osis::internals::schema::core_types as ct;
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 9, &c);
    let key = a.listen(&["peer://203.0.113.5:4040".parse().unwrap(), "peer://127.0.0.1:1".parse().unwrap()]).unwrap()[0].key();
    let (node, profile) = (a.node(), a.profile().unwrap());
    let (reach, list) = a.engine(|e| (e.get_typed(&node, &ct::REACH).unwrap(), e.get_typed(&profile, &ct::DIAL).unwrap()));
    let reach = reach.expect("reach.0 written");
    assert_eq!((reach.dialable, reach.items.clone(), reach.account), (key, vec!["203.0.113.5:4040".to_string()], Some(a.me())), "global addresses only");
    assert_eq!(list.unwrap(), [(key.to_vec(), vec!["peer://203.0.113.5:4040".to_string()])].into());
    a.rotate_peer_address().unwrap();
    let list = a.engine(|e| e.get_typed(&profile, &ct::DIAL).unwrap()).unwrap();
    assert_eq!(list.len(), 1);
    assert!(!list.contains_key(key.as_slice()), "the old key's entry gone");
}

// spec/sync-opens.md §1 (where to dial): a configured address is dialed; the connection comes up
// at both ends, and once it shares nothing it closes.
#[test]
fn a_dial_address_is_dialed_spec_sync_opens_1() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let b = on(&net, 6, &c);
    let addr = b.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let mut o = cfg(7, MemStore::new(), &c);
    o.app.internals.net = Some(net.clone());
    o.cfg.dial = vec![addr];
    let a = osis::internals::create(o).unwrap();
    net.run();
    assert_eq!((net.ups(0), net.ups(1)), (1, 1), "up at both ends");
    assert_eq!(a.status().unwrap().connected, 0, "closed sharing nothing");
    assert_eq!(b.status().unwrap().connected, 0);
}

// spec: none (notes/sync-driver.md, Connection diagnostics: for a log, `osis serve`, `diag
// --follow`): a node reports each connection up and closed, at both ends, and each failed dial
// with its address and why.
#[test]
fn connections_and_failed_dials_are_diagnostics() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let b = on(&net, 6, &c);
    let addr = b.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let gone = osis::Address::new(&"peer://127.0.0.1:2".parse().unwrap(), [9; 32]);
    let mut o = cfg(7, MemStore::new(), &c);
    o.app.internals.net = Some(net.clone());
    o.cfg.dial = vec![addr.clone(), gone.clone()];
    let a = osis::internals::create(o).unwrap();
    let lines = |db: &Osis| {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let s = seen.clone();
        let sub = db
            .on_diagnostic(move |_, d| {
                if let osis::Diagnostic::Connection { detail } = d {
                    s.lock().unwrap().push(detail);
                }
            })
            .unwrap();
        (seen, sub)
    };
    let ((at_a, _sa), (at_b, _sb)) = (lines(&a), lines(&b));
    net.run();
    a.settle();
    b.settle();
    let (at_a, at_b) = (at_a.lock().unwrap().clone(), at_b.lock().unwrap().clone());
    let has = |v: &[String], parts: &[&str]| v.iter().any(|l| parts.iter().all(|p| l.contains(p)));
    assert!(has(&at_a, &["up: dialed", &addr.to_string()]), "{at_a:?}");
    assert!(has(&at_a, &["closed: shares nothing"]), "{at_a:?}");
    assert!(has(&at_a, &["dial to", &gone.to_string(), "failed: unreachable"]), "{at_a:?}");
    assert!(has(&at_b, &["up: accepted"]) && has(&at_b, &["closed: ended"]), "{at_b:?}");
}

// spec/sync-opens.md §1 (where to dial), notes/api-design.md (explicit where a wrong default is
// silent): configured dial candidates with no runtime would never be reached.
#[test]
fn dial_without_a_network_is_invalid_notes_api() {
    let mut o = cfg(8, MemStore::new(), &clock());
    o.cfg.dial = vec![format!("peer://127.0.0.1:1#{}", osis_key()).parse().unwrap()];
    assert!(matches!(osis::internals::create(o), Err(Error::Invalid(_))));
}

fn osis_key() -> String {
    osis::Address::new(&"peer://127.0.0.1:1".parse().unwrap(), [9; 32]).to_string().rsplit('#').next().unwrap().to_string()
}

// spec/wire.md §10 (the target tid): a link names its target, K and the sharer node's dialable key; it
// gives read or above.
#[test]
fn a_link_names_its_target_and_this_node_spec_wire_10() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 10, &c);
    let addr = a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let l = a.make_link(t, Role::Read, LinkOpts::default()).unwrap();
    assert_eq!(l.target().unwrap(), t);
    let text = l.to_string();
    let parsed = osis::internals::blob::ShareLink::from_text(&text).unwrap();
    assert_eq!(parsed.peers.first().map(|p| p.dialable), Some(addr.key()));
    assert!(a.links().unwrap().iter().any(|x| x.target == t && x.role == Role::Read));
    assert!(matches!(a.make_link(t, Role::Sync, LinkOpts::default()), Err(Error::Invalid(_))));
}

// spec/sync-inbox.md §5 (contact card): a read link to the account's profile, made once.
#[test]
fn the_contact_card_is_a_read_link_to_the_profile_spec_sync_inbox_5() {
    let db = db(11);
    let card = db.contact_card().unwrap();
    assert_eq!(db.contact_card().unwrap().to_string(), card.to_string());
    let p = db.profile().unwrap();
    let link: osis::ShareLink = card.to_string().parse().unwrap();
    assert_eq!(link.target().unwrap(), p);
    assert!(db.links().unwrap().iter().any(|x| x.target == p && x.role == Role::Read));
}

// spec/sync-set.md §1 (dial list; a node learns P's profile): from pairing: every node of the account knows the profile
// (each writes its own `dial^.0` entry there), a paired node from its offer,
// before any sync; reading it there before it arrives reads nothing, and its card works.
#[test]
fn a_paired_node_knows_the_accounts_profile_spec_sync_set_1() {
    let a = db(12);
    let join = osis::internals::pair(cfg(13, MemStore::new(), &clock()), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(join.request()).unwrap();
    let b = join.finish(&reply).unwrap();
    assert_eq!(b.profile().unwrap(), a.profile().unwrap());
    assert_eq!(b.at(b.profile().unwrap(), osis::core::NAME).get().unwrap(), None);
    let card: osis::ShareLink = b.contact_card().unwrap().to_string().parse().unwrap();
    assert_eq!(card.target().unwrap(), a.profile().unwrap());
}

// spec/sync-set.md §4 (accepting): an accept goes into a synced group only.
#[test]
fn accepting_into_a_group_not_synced_is_invalid_spec_sync_set_4() {
    let db = db(12);
    let mut w = db.write();
    let g = w.create().unwrap();
    let t = w.create().unwrap();
    w.commit().unwrap();
    assert!(db.accept_invite(t, g).is_err());
}

// spec/commits.md §6 (expiry), spec/requirements.md (Ephemeral data: a value that lives while its author is there):
// `keep_alive` renews an ephemeral value with a default expiry; any other key is refused.
#[test]
fn keep_alive_needs_an_ephemeral_key_and_a_runtime_notes_ephemeral() {
    let db = db(13);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    assert!(matches!(db.at(t, osis::core::NAME).keep_alive(&"x".to_string()), Err(Error::Invalid(_))));
}

// ---- the client port (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6) ----

fn auth(secret: Option<[u8; 32]>) -> Msg {
    Msg::Auth { id: 1, secret: secret.map(osis::internals::Secret32::from_bytes), session_id: [7; 16] }
}

fn get(t: osis::Tid, ak: &str) -> Msg {
    Msg::Call { id: 2, max_reply: 65_536, method: osis::internals::port_method::GET, args: vec![Value::Tid(t), Value::Str(ak.into()), Value::List(Vec::new())] }
}

fn ok_reply(m: &Msg) -> bool {
    matches!(m, Msg::Reply { outcome: Outcome::Ok { .. }, .. })
}

fn refused(m: &Msg) -> bool {
    matches!(m, Msg::Error { code, .. } if code.0 == 1)
}

/// A node with a thing `t` holding `x:v.0` = 5, and a client registered with no grant.
fn port_node() -> (Osis, osis::Tid, osis::Tid, [u8; 32]) {
    let db = db(20);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(crate::common::ak("x:v.0"))).set(&Value::Int(5)).unwrap();
    w.commit().unwrap();
    let (actor, secret) = db.add_client(None).unwrap();
    (db, t, actor, *secret.expose())
}

// spec/wire.md §11.2 (Auth): a main session on the unix transport sends no secret, and then
// reads as the node's main actor.
#[test]
fn a_main_session_authenticates_without_a_secret_spec_wire_11() {
    let (db, t, _, _) = port_node();
    let r = osis::internals::port_answers(&db, 1, true, vec![auth(None), get(t, "x:v.0")]);
    assert!(ok_reply(&r[0]), "{r:?}");
    assert!(matches!(&r[1], Msg::Reply { outcome: Outcome::Ok { value: Value::List(v) }, .. } if v == &vec![Value::uint(0), Value::List(vec![Value::Int(5)])]), "{r:?}");
}

// spec/wire.md §11.2 (Auth): any other Auth is Error 1: no secret on a keyed transport, a secret
// on the unix transport, a secret matching no entry, a second Auth of a client-actor session;
// and a Call before an Auth answered by Reply is Error 1.
#[test]
fn other_auths_and_calls_before_auth_are_refused_spec_wire_11() {
    let (db, t, _, secret) = port_node();
    assert!(refused(&osis::internals::port_answers(&db, 1, false, vec![get(t, "x:v.0")])[0]));
    assert!(refused(&osis::internals::port_answers(&db, 2, false, vec![auth(None)])[0]));
    assert!(refused(&osis::internals::port_answers(&db, 3, true, vec![auth(Some(secret))])[0]));
    assert!(refused(&osis::internals::port_answers(&db, 4, false, vec![auth(Some([1; 32]))])[0]));
    let r = osis::internals::port_answers(&db, 5, false, vec![auth(Some(secret)), auth(Some(secret))]);
    assert!(ok_reply(&r[0]) && refused(&r[1]), "{r:?}");
}

// spec/wire.md §11.2 (A client actor's rights): a thing the actor may not read answers as a
// thing the node does not know (a GET of an unknown tid reads absent); an unknown method is
// `[1, 11, text]`.
#[test]
fn a_client_actor_reads_only_what_it_may_spec_wire_11() {
    let (db, t, actor, secret) = port_node();
    let unknown = osis::Tid::from_bytes([3; 15]);
    let r = osis::internals::port_answers(&db, 1, false, vec![auth(Some(secret)), get(t, "x:v.0"), get(unknown, "x:v.0"), Msg::Call { id: 3, max_reply: 4096, method: 999, args: vec![] }]);
    assert!(ok_reply(&r[0]));
    assert_eq!(r[1], r[2], "as unknown");
    assert!(matches!(&r[3], Msg::Reply { outcome: Outcome::Err { code, .. }, .. } if *code == ApiCode::UNSUPPORTED), "{r:?}");
    db.grant(t, actor, Role::Read, osis::GrantOpts::default()).unwrap();
    let r = osis::internals::port_answers(&db, 1, false, vec![get(t, "x:v.0")]);
    assert!(matches!(&r[0], Msg::Reply { outcome: Outcome::Ok { value: Value::List(v) }, .. } if v == &vec![Value::uint(0), Value::List(vec![Value::Int(5)])]), "granted: {r:?}");
}

// spec/wire.md §11.2 (End of a client-actor session): it ends when the entry goes, its secret
// hash changes or its `until` passes; each request is checked as it runs.
#[test]
fn a_client_session_ends_with_its_entry_spec_wire_11() {
    let (db, t, actor, secret) = port_node();
    db.grant(t, actor, Role::Read, osis::GrantOpts::default()).unwrap();
    assert!(ok_reply(&osis::internals::port_answers(&db, 1, false, vec![auth(Some(secret))])[0]));
    db.rotate_client_secret(actor).unwrap();
    assert!(refused(&osis::internals::port_answers(&db, 1, false, vec![get(t, "x:v.0")])[0]), "rotated");
    let c = clock();
    let db = osis::internals::create(cfg(21, MemStore::new(), &c)).unwrap();
    let (_, secret) = db.add_client(Some(Time(T0 + 1_000))).unwrap();
    assert!(ok_reply(&osis::internals::port_answers(&db, 1, false, vec![auth(Some(*secret.expose()))])[0]));
    c.advance(1_000);
    assert!(refused(&osis::internals::port_answers(&db, 1, false, vec![get(db.home(), "x:v.0")])[0]), "until passed");
}

// spec/wire.md §11.2 (Auth): past `MAX_CONNS_PER_CLIENT` authenticated sessions of one client,
// Error 4.
#[test]
fn a_client_has_a_bounded_number_of_sessions_spec_wire_11() {
    let (db, _, _, secret) = port_node();
    let max = osis::internals::proto::limits::MAX_CONNS_PER_CLIENT as u64;
    for c in 0..max {
        assert!(ok_reply(&osis::internals::port_answers(&db, c, false, vec![auth(Some(secret))])[0]));
    }
    assert!(matches!(&osis::internals::port_answers(&db, max, false, vec![auth(Some(secret))])[0], Msg::Error { code, .. } if code.0 == 4));
}

// ---- two nodes syncing (spec/sync.md): each waits on the engine facade (branch sync-facade) ----

/// Drives `f` on `net` until it resolves (at most 20 rounds of `run`).
fn drive<T>(net: &ManualNet, f: impl std::future::Future<Output = T>) -> T {
    let mut f = std::pin::pin!(f);
    for _ in 0..20 {
        if let std::task::Poll::Ready(r) = f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
            return r;
        }
        net.run();
    }
    panic!("did not resolve");
}

/// Two paired nodes of one account on `net`, the second dialing the first, with the first's
/// address.
fn paired(net: &ManualNet, c: &Arc<ManualClock>) -> (Osis, Osis, osis::Address) {
    let a = on(net, 30, c);
    let addr = a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let mut o = cfg(31, MemStore::new(), c);
    o.app.internals.net = Some(net.clone());
    o.cfg.dial = vec![addr.clone()];
    let join = osis::internals::pair(o, &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(join.request()).unwrap();
    (a, join.finish(&reply).unwrap(), addr)
}

// spec/sync-set.md §1 (home under synced group): what one node of an account writes in its
// home reaches its other nodes; `wait_synced` on a thing in home (carried by home's sync ID)
// ends once the other node holds it.
#[test]
fn a_write_reaches_the_accounts_other_node_spec_sync_set_1() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Item(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"x".to_string()).unwrap();
    w.commit().unwrap();
    drive(&net, a.wait_synced(SyncScope::Thing(t))).unwrap();
    net.run();
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("x"));
    assert_eq!(a.status().unwrap().groups.get(&a.home()).map(|g| g.state), Some(osis::SyncState::Synced));
}

// spec/sync-set.md §2 (a thing made under an account itself, listed nowhere a node syncs, stays
// on the nodes holding it): a created thing the write lists nowhere stays off the account's other
// node while one listed in home reaches it; listed in home later, it reaches it, its creation
// included.
#[test]
fn a_thing_listed_nowhere_stays_on_its_node_spec_sync_set_2() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::core::NAME).set(&"t".to_string()).unwrap();
    w.commit().unwrap();
    assert!(!a.members(a.home()).unwrap().iter().any(|m| matches!(m, osis::Member::Item(x) | osis::Member::Subgroup(x) if *x == t)), "listed nowhere");
    let mut w = a.write();
    let f = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Item(f)).unwrap();
    w.at(f, osis::core::NAME).set(&"f".to_string()).unwrap();
    w.commit().unwrap();
    drive(&net, a.wait_synced(SyncScope::Thing(f))).unwrap();
    net.run();
    assert_eq!(b.at(f, osis::core::NAME).get().unwrap().as_deref(), Some("f"), "listed in home: reaches b");
    assert!(b.created(t).unwrap().is_none() && b.at(t, osis::core::NAME).get().unwrap().is_none(), "listed nowhere: stays on a");
    let mut w = a.write();
    w.group(a.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.commit().unwrap();
    drive(&net, a.wait_synced(SyncScope::Thing(t))).unwrap();
    net.run();
    assert!(b.created(t).unwrap().is_some());
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("t"), "listed in home later: reaches b");
}

// spec/sync-set.md §2 (Shared here), §3 (Unsyncing): a thing listed nowhere, granted
// to another account, syncs at the granting node: the grantee accepts and gets it from there,
// and its writes come back; the account's other node does not sync it. Unsynced at the granting
// node, once its writes are held elsewhere it leaves there and its copy goes; the grantee keeps
// it, and what it writes later stays off that node.
#[test]
fn a_shared_thing_syncs_at_the_sharing_node_spec_sync_set_2() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, a2, _) = paired(&net, &c);
    let o = on(&net, 56, &c);
    drive(&net, o.import_contact(&a.contact_card().unwrap())).unwrap();
    drive(&net, a.import_contact(&o.contact_card().unwrap())).unwrap();
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::core::NAME).set(&"shared".to_string()).unwrap();
    w.commit().unwrap();
    a.grant(t, o.me(), Role::Write, osis::GrantOpts::default()).unwrap();
    for _ in 0..5 {
        net.run();
    }
    o.accept_invite(t, o.home()).unwrap();
    drive(&net, o.wait_synced(SyncScope::Thing(t))).unwrap();
    assert_eq!(name(&o, t).as_deref(), Some("shared"), "the grantee got it from the sharing node");
    let mut w = o.write();
    w.at(t, osis::core::NAME).set(&"from o".to_string()).unwrap();
    w.commit().unwrap();
    drive(&net, o.wait_synced(SyncScope::Thing(t))).unwrap();
    net.run();
    assert_eq!(name(&a, t).as_deref(), Some("from o"), "and its writes came back");
    assert!(a.status().unwrap().groups.contains_key(&t));
    assert!(!a2.status().unwrap().groups.contains_key(&t), "the account's other node does not sync it");
    assert_eq!(name(&a2, t), None);
    a.unsync(t).unwrap();
    for _ in 0..5 {
        net.run();
    }
    assert!(!a.status().unwrap().groups.contains_key(&t), "left the sharing node");
    assert_eq!(name(&a, t), None, "its copy went");
    let mut w = o.write();
    w.at(t, osis::core::NAME).set(&"later".to_string()).unwrap();
    w.commit().unwrap();
    for _ in 0..5 {
        net.run();
    }
    assert_eq!(name(&o, t).as_deref(), Some("later"));
    assert_eq!(name(&a, t), None, "what it writes later stays off it");
}

// spec/sync-set.md §2 (Shared here), spec/sync-inbox.md §6: a link to a thing listed nowhere
// shares it at the node making it: a redeemer joins through that node and gets the thing.
#[test]
fn a_link_to_a_thing_listed_nowhere_is_served_spec_sync_set_2() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 57, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 58, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::core::NAME).set(&"linked".to_string()).unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Read, LinkOpts::default()).unwrap();
    assert_eq!(drive(&net, b.redeem(&link)).unwrap(), t);
    drive(&net, b.wait_synced(SyncScope::Thing(t))).unwrap();
    assert_eq!(name(&b, t).as_deref(), Some("linked"));
}

// spec/sync-inbox.md §6 (first contact), spec/sync-set.md §4 (A redeem is an accept): a redeemer reaches the
// sharer node by the link and joins; the redeem files the thing under its home, so it syncs both
// ways after the join with no other write.
#[test]
fn redeeming_a_link_joins_and_files_its_thing_spec_sync_set_4() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 40, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 41, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"shared".to_string()).unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Write, LinkOpts::default()).unwrap();
    assert_eq!(drive(&net, b.redeem(&link)).unwrap(), t);
    assert_eq!(b.role_on(t).unwrap(), Some(Role::Write));
    assert!(b.invitations().unwrap().iter().all(|i| i.thing != t), "filed: no invitation");
    drive(&net, b.wait_synced(SyncScope::Thing(t))).unwrap();
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("shared"));
    let mut w = b.write();
    w.at(t, osis::core::NAME).set(&"from b".to_string()).unwrap();
    w.commit().unwrap();
    drive(&net, b.wait_synced(SyncScope::Thing(t))).unwrap();
    net.run();
    assert_eq!(a.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("from b"));
}

// spec/sync-inbox.md §6 (First contact: a node may stop following a link after a time of its
// choosing), notes/api-design.md (a wait sure never to finish fails): with the sharer away the
// whole follow time, `redeem` fails `Network` at it, and nothing is held.
#[test]
fn a_redeem_whose_sharer_never_answers_fails_at_the_follow_time_spec_sync_inbox_6() {
    use osis::internals::FOLLOW_LINK_MS;
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 44, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 45, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Read, LinkOpts::default()).unwrap();
    net.set_online(0, false);
    let mut f = std::pin::pin!(b.redeem(&link));
    let mut poll = || f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
    assert!(poll().is_pending());
    net.advance(FOLLOW_LINK_MS - 60_000);
    assert!(poll().is_pending(), "waits within the follow time");
    net.advance(120_000);
    assert!(matches!(poll(), std::task::Poll::Ready(Err(Error::Network(_)))), "fails once given up");
    assert!(!matches!(b.role_on(t), Ok(Some(_))), "joined nothing");
}

// spec/sync-status.md §3 (waits), spec/sync-inbox.md §6: a redeemer (the redeem files the thing
// under its home) waits on the thing (its home carrying it, shared by no peer) until the thing's data
// is here; the sharer away (its record holding the thing's sync ID), a wait there runs on.
#[test]
fn a_redeemers_wait_on_the_thing_ends_spec_sync_status_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 42, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 43, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"shared".to_string()).unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Write, LinkOpts::default()).unwrap();
    assert_eq!(drive(&net, b.redeem(&link)).unwrap(), t);
    drive(&net, b.wait_synced(SyncScope::Thing(t))).unwrap();
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("shared"));
    drive(&net, a.wait_synced(SyncScope::Thing(t))).unwrap();
    net.set_online(0, false);
    net.run();
    let mut w = b.write();
    w.at(t, osis::core::NAME).set(&"from b".to_string()).unwrap();
    w.commit().unwrap();
    net.run();
    net.advance(60_000);
    assert!(now(b.wait_synced(SyncScope::Thing(t))).is_pending(), "the sharer away");
}

// spec/sync-status.md §3 (waits), spec/sync-set.md §4: an account accepting another's grant into
// its home waits on the thing until the thing's data is here, its home shared by no peer.
#[test]
fn an_accepters_wait_on_the_thing_ends_spec_sync_status_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 54, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 55, &c);
    drive(&net, b.import_contact(&a.contact_card().unwrap())).unwrap();
    let mut w = b.write();
    let t = w.create().unwrap();
    w.group(b.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"granted".to_string()).unwrap();
    w.commit().unwrap();
    b.grant(t, a.me(), Role::Read, osis::GrantOpts::default()).unwrap();
    net.run();
    assert!(now(b.wait_synced(SyncScope::Deliveries)).is_pending(), "not taken until accepted");
    a.accept_invite(t, a.home()).unwrap();
    drive(&net, a.wait_synced(SyncScope::Thing(t))).unwrap();
    assert_eq!(a.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("granted"));
    drive(&net, b.wait_synced(SyncScope::Deliveries)).unwrap();
}

// spec/sync-inbox.md §5 (contact card), spec/sync-set.md §4: importing a card gives the account,
// whose keys are then here (a grant to it goes through).
#[test]
fn importing_a_card_gives_the_account_spec_sync_inbox_5() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 50, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 51, &c);
    let who = drive(&net, b.import_contact(&a.contact_card().unwrap())).unwrap();
    assert_eq!(who, a.me());
    assert_eq!(b.profile_of(a.me()).unwrap(), Some(a.profile().unwrap()));
    let mut w = b.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    b.grant(t, a.me(), Role::Read, osis::GrantOpts::default()).unwrap();
}

// spec/sync-set.md §4 (Acted): a new grant is an invitation not acted on; accepted, it is no
// invitation; unsynced, it is one again, acted on.
#[test]
fn an_unsynced_invitation_is_acted_on_spec_sync_set_4() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 52, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 53, &c);
    drive(&net, b.import_contact(&a.contact_card().unwrap())).unwrap();
    let mut w = b.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    b.grant(t, a.me(), Role::Read, osis::GrantOpts::default()).unwrap();
    for _ in 0..5 {
        net.run();
    }
    let acted = |db: &Osis| db.invitations().unwrap().iter().find(|i| i.thing == t).map(|i| i.acted);
    assert_eq!(acted(&a), Some(false), "a new grant: {:?}", a.invitations().unwrap());
    a.accept_invite(t, a.home()).unwrap();
    assert_eq!(acted(&a), None, "accepted");
    let mut w = a.write();
    w.group(a.home()).remove(osis::Member::Subgroup(t)).unwrap();
    w.commit().unwrap();
    assert_eq!(acted(&a), Some(true), "unsynced");
}

// ---- leaving (spec/sync-set.md §3) ----

/// A thing with a sync ID of its own (its first link), named `name`, an item of `g`.
fn shared_in(db: &Osis, g: osis::Tid, name: &str) -> osis::Tid {
    let mut w = db.write();
    let t = w.create().unwrap();
    w.group(g).add(osis::Member::Item(t)).unwrap();
    w.at(t, osis::core::NAME).set(&name.to_string()).unwrap();
    w.commit().unwrap();
    db.make_link(t, Role::Read, LinkOpts::default()).unwrap();
    t
}

fn name(db: &Osis, t: osis::Tid) -> Option<String> {
    db.at(t, osis::core::NAME).get().unwrap()
}

/// `db`'s own synced group (under home as every synced group) lists `t` too.
fn keep_at(db: &Osis, t: osis::Tid) {
    let synced = db.aspect_key("synced^.0").unwrap();
    let Some(Value::Map(mut m)) = db.at(db.home(), synced.clone()).get().unwrap() else { panic!("synced^.0") };
    let mut w = db.write();
    let g = w.create().unwrap();
    w.group(g).add(osis::Member::Subgroup(db.home())).unwrap();
    w.group(g).add(osis::Member::Item(t)).unwrap();
    w.group(db.home()).add(osis::Member::Item(g)).unwrap();
    m.insert(Value::Tid(db.node()), Value::Tid(g));
    w.at(db.home(), synced).set(&Value::Map(m)).unwrap();
    w.commit().unwrap();
}

// spec/sync-set.md §3 (Unsyncing): a thing leaving this node's synced group, its own entries held
// at the account's other node, is forgotten here; the other node, whose own synced group lists
// it, keeps it.
#[test]
fn an_unsynced_thing_is_forgotten_here_spec_sync_set_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    let t = shared_in(&a, a.home(), "moved");
    drive(&net, a.wait_synced(SyncScope::Thing(t))).unwrap();
    net.run();
    keep_at(&b, t);
    net.run();
    let mut w = a.write();
    w.group(a.home()).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    // the link `shared_in` made here shared it here too
    a.unsync(t).unwrap();
    for _ in 0..5 {
        net.run();
    }
    assert_eq!(name(&a, t), None, "forgotten here");
    assert_eq!(name(&b, t).as_deref(), Some("moved"));
}

// spec/sync-set.md §3 (with none, it stops at once): a node alone, no peer ever sharing the thing, unsyncing
// it drops its only copy at once (the user's choice), its own writes held nowhere else.
#[test]
fn an_unsynced_thing_no_peer_shares_goes_at_once_spec_sync_set_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 30, &c);
    let t = shared_in(&a, a.home(), "alone");
    let mut w = a.write();
    w.at(t, osis::core::NAME).set(&"edited".to_string()).unwrap();
    w.commit().unwrap();
    net.run();
    let mut w = a.write();
    w.group(a.home()).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    // the link `shared_in` made here shared it here too
    a.unsync(t).unwrap();
    net.run();
    assert_eq!(name(&a, t), None, "forgotten here");
    assert!(!a.status().unwrap().groups.contains_key(&t), "synced no more");
}

// spec/sync-set.md §3 (one rule ends syncing it; while it waits, S stays a member of its shared
// sets): a write made while the other node was away, its thing then taken out of this node's
// synced groups, stays here (the thing still synced) while no other node holds it, reaches the
// other node, whose own synced group lists the thing, once it is back, and only then goes here.
#[test]
fn an_unsynced_write_goes_out_before_the_copy_goes_spec_sync_set_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    let t = shared_in(&a, a.home(), "first");
    drive(&net, a.wait_synced(SyncScope::Thing(t))).unwrap();
    net.run();
    keep_at(&b, t);
    net.run();
    net.set_online(1, false);
    net.run();
    let mut w = a.write();
    w.at(t, osis::core::NAME).set(&"away".to_string()).unwrap();
    w.commit().unwrap();
    net.run();
    let mut w = a.write();
    w.group(a.home()).remove(osis::Member::Item(t)).unwrap();
    w.commit().unwrap();
    // the link `shared_in` made here shared it here too
    a.unsync(t).unwrap();
    for _ in 0..5 {
        net.advance(60_000);
    }
    assert_eq!(name(&a, t).as_deref(), Some("away"), "its own write held nowhere else: kept");
    assert!(a.status().unwrap().groups.get(&t).is_some_and(|g| g.leaving), "shown leaving");
    net.set_online(1, true);
    for _ in 0..5 {
        net.advance(60_000);
    }
    assert_eq!(name(&b, t).as_deref(), Some("away"));
    // its creation commit also wrote home, so that commit stays and its name part may join again
    // under home's sync ID (notes/sync-leave.md, forget_local): what only t's sync ID carried goes
    assert!(matches!(name(&a, t).as_deref(), None | Some("first")), "then forgotten here");
    assert!(!a.status().unwrap().groups.contains_key(&t), "synced no more");
}

// spec/permissions.md §3, spec/sync-inbox.md §2: removing a node is a departure rotating its
// account's roles; an outside reader of a group the account writes reads the account's writes from before and
// after one of the account's nodes is removed (Fathom's report on main: it read none of them).
#[test]
fn an_outsider_reads_the_accounts_writes_across_a_node_removal_spec_permissions_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    let o = on(&net, 32, &c);
    o.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    drive(&net, a.import_contact(&o.contact_card().unwrap())).unwrap();
    drive(&net, o.import_contact(&a.contact_card().unwrap())).unwrap();
    let mut w = a.write();
    let g = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(g)).unwrap();
    w.at(g, osis::core::NAME).set(&"before".to_string()).unwrap();
    w.commit().unwrap();
    a.grant(g, o.me(), Role::Read, osis::GrantOpts::default()).unwrap();
    for _ in 0..5 {
        net.run();
    }
    o.accept_invite(g, o.home()).unwrap();
    for _ in 0..5 {
        net.run();
    }
    assert_eq!(name(&o, g).as_deref(), Some("before"), "the outsider reads the group");
    a.remove_node(b.node(), osis::SetRoleOpts::default()).unwrap();
    for _ in 0..5 {
        net.run();
    }
    assert_eq!(name(&o, g).as_deref(), Some("before"), "the write before the removal still read");
    let mut w = a.write();
    w.at(g, osis::core::NAME).set(&"after".to_string()).unwrap();
    w.commit().unwrap();
    for _ in 0..5 {
        net.run();
    }
    assert_eq!(name(&o, g).as_deref(), Some("after"), "the write after the removal read");
}

// spec/permissions.md §7 (removed node's links): a removed node keeps the seeds of the account's
// links, so `remove_node` lists the links still working, one made on the removed node included;
// none for a node not of this account.
#[test]
fn removing_a_node_lists_the_accounts_links_spec_permissions_7() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    let mut w = a.write();
    let g = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(g)).unwrap();
    w.commit().unwrap();
    for _ in 0..3 {
        net.run();
    }
    a.make_link(g, Role::Read, LinkOpts::default()).unwrap();
    b.make_link(g, Role::Write, LinkOpts::default()).unwrap();
    for _ in 0..3 {
        net.run();
    }
    assert_eq!(a.links().unwrap().len(), 2, "every node lists the account's links");
    let stranger = on(&net, 33, &c);
    assert!(a.remove_node(stranger.node(), osis::SetRoleOpts::default()).unwrap().is_empty(), "no node of this account");
    let open = a.remove_node(b.node(), osis::SetRoleOpts::default()).unwrap();
    let mut roles: Vec<Role> = open.iter().filter(|l| l.target == g).map(|l| l.role).collect();
    roles.sort();
    assert_eq!(roles, vec![Role::Read, Role::Write], "both links still work: {open:?}");
}

// spec/sync.md §3 (kept unread), spec/sync-set.md §4 (accepting), spec/permissions.md §7 (first
// contact: a link reaches the redeemer through peers it shares K with): a node of a third account, granted
// sync on a group and on its link's K and accepting both, relays the group between two accounts
// that never connect to each other (the dogfood channel, notes/dogfood.md).
#[test]
fn a_third_accounts_node_relays_a_group_it_keeps_unread_spec_sync_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let h = on(&net, 60, &c);
    let addr = h.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let via = |seed| {
        let mut o = cfg(seed, MemStore::new(), &c);
        o.app.internals.net = Some(net.clone());
        o.cfg.dial = vec![addr.clone()];
        o.cfg.direct_sync = false;
        osis::internals::create(o).unwrap()
    };
    let (a, b) = (via(61), via(62));
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"first".to_string()).unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Write, LinkOpts::default()).unwrap();
    drive(&net, a.import_contact(&h.contact_card().unwrap())).unwrap();
    a.grant(t, h.me(), Role::Sync, osis::GrantOpts::default()).unwrap();
    let k = a.links().unwrap().iter().find(|l| l.target == t).unwrap().id.actor();
    a.grant(k, h.me(), Role::Sync, osis::GrantOpts::default()).unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    let inv = h.invitations().unwrap();
    assert!(inv.iter().any(|i| i.thing == t && i.role == Role::Sync), "{inv:?}");
    h.accept_invite(t, h.home()).unwrap();
    h.accept_invite(k, h.home()).unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    assert!(h.status().unwrap().groups.contains_key(&t), "kept unread at h");
    assert_eq!(drive(&net, b.redeem(&link)).unwrap(), t);
    for _ in 0..5 {
        net.advance(1_000);
    }
    assert_eq!(name(&b, t).as_deref(), Some("first"));
    let mut w = a.write();
    w.at(t, osis::core::NAME).set(&"from a".to_string()).unwrap();
    w.commit().unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    assert_eq!(name(&b, t).as_deref(), Some("from a"));
    let mut w = b.write();
    w.at(t, osis::core::NAME).set(&"from b".to_string()).unwrap();
    w.commit().unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    assert_eq!(name(&a, t).as_deref(), Some("from b"));
    assert_eq!((a.status().unwrap().connected, b.status().unwrap().connected), (1, 1), "each connected to h alone");
}

// spec/wire.md §10 (the nodes to dial for first contact), spec/permissions.md §7 (First contact): a link lists the nodes its sharer dials by configured address,
// so a fresh node with no address of its own joins from the link alone through a third account's
// node keeping the thing unread (the sharer reachable by nobody), receives the sharer's writes
// there, and dials that node again after a restart (spec/permissions.md §7: the link's peers stay
// addresses to dial while the target is held).
#[test]
fn a_link_reaches_a_node_its_sharer_dials_spec_wire_10() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let h = on(&net, 70, &c);
    let addr = h.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let node = |seed, store: MemStore, dial: Vec<osis::Address>, open: bool| {
        let mut o = cfg(seed, store, &c);
        o.app.internals.net = Some(net.clone());
        o.cfg.dial = dial;
        o.cfg.direct_sync = false;
        if open { osis::internals::open(o) } else { osis::internals::create(o) }.unwrap()
    };
    let a = node(71, MemStore::new(), vec![addr.clone()], false);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"first".to_string()).unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Write, LinkOpts::default()).unwrap();
    let peers = osis::internals::blob::ShareLink::from_text(&link.to_string()).unwrap().peers;
    assert_eq!(peers.iter().map(|p| p.dialable).collect::<Vec<_>>()[1..], [addr.key()], "the sharer, then its configured node");
    drive(&net, a.import_contact(&h.contact_card().unwrap())).unwrap();
    a.grant(t, h.me(), Role::Sync, osis::GrantOpts::default()).unwrap();
    let k = a.links().unwrap().iter().find(|l| l.target == t).unwrap().id.actor();
    a.grant(k, h.me(), Role::Sync, osis::GrantOpts::default()).unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    h.accept_invite(t, h.home()).unwrap();
    h.accept_invite(k, h.home()).unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    let store = MemStore::new();
    let b = node(72, store.clone(), Vec::new(), false);
    assert_eq!(drive(&net, b.redeem(&link)).unwrap(), t);
    for _ in 0..5 {
        net.advance(1_000);
    }
    assert_eq!(name(&b, t).as_deref(), Some("first"));
    let mut w = a.write();
    w.at(t, osis::core::NAME).set(&"from a".to_string()).unwrap();
    w.commit().unwrap();
    for _ in 0..5 {
        net.advance(1_000);
    }
    assert_eq!(name(&b, t).as_deref(), Some("from a"));
    drop(b);
    let b = node(72, store, Vec::new(), true);
    let mut w = a.write();
    w.at(t, osis::core::NAME).set(&"after b's restart".to_string()).unwrap();
    w.commit().unwrap();
    for _ in 0..40 {
        net.advance(1_000);
    }
    assert_eq!(name(&b, t).as_deref(), Some("after b's restart"));
    assert_eq!((a.status().unwrap().connected, b.status().unwrap().connected), (1, 1), "each connected to h alone");
}

// ---- group sources: the hand-off (spec/sync-set.md §5) ----

/// Paired nodes a (place 0) and b; g in a's home with `x:v.0` = 1, granted to a client of a's,
/// which b is connected as; b holds g, and sources it at a, run to quiet: (a, b, g, a's address).
fn sourced_at_a(net: &ManualNet, c: &Arc<ManualClock>) -> (Osis, Osis, osis::Tid, osis::Address) {
    let (a, b, addr) = paired(net, c);
    let mut w = a.write();
    let g = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Item(g)).unwrap();
    w.at(g, v()).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let (actor, secret) = a.add_client(None).unwrap();
    a.grant(g, actor, Role::Write, osis::GrantOpts::default()).unwrap();
    drive(net, a.wait_synced(SyncScope::Thing(g))).unwrap();
    net.run();
    assert_eq!(b.at(g, v()).get().unwrap(), Some(Value::Int(1)), "b holds g");
    drive(net, b.connect_node(&osis::NodeLogin { addr: addr.clone(), secret })).unwrap();
    drive(net, b.group_source(g, osis::GroupSource::Node(addr.clone()))).unwrap();
    net.run();
    (a, b, g, addr)
}

fn v() -> osis::DynamicAspectKey {
    osis::DynamicAspectKey::untyped(crate::common::ak("x:v.0"))
}

// spec/sync-set.md §5 (Sourced away; Moving home): b, with g sourced at a, stops syncing it;
// moved home while a wrote g meanwhile, the move answers only once b's copy caught up, and then
// b reads a's write here.
#[test]
fn moving_home_answers_once_caught_up_spec_sync_set_5() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, g, _) = sourced_at_a(&net, &c);
    assert!(!b.status().unwrap().groups.contains_key(&g), "away: b syncs g no more");
    let mut w = a.write();
    w.at(g, v()).set(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    net.run();
    let mut home = std::pin::pin!(b.group_source(g, osis::GroupSource::Local));
    assert!(now(home.as_mut()).is_pending(), "not caught up yet");
    assert!(b.group_sources().contains_key(&g), "read at a meanwhile");
    drive(&net, home).unwrap();
    assert!(b.group_sources().is_empty());
    assert_eq!(b.at(g, v()).get().unwrap(), Some(Value::Int(2)), "caught up: a's write here");
}

// spec/sync-set.md §5 (Moving home: a complete pass ends by `PASS_WAIT_MS`): with a gone, b's move
// home still answers, once `PASS_WAIT_MS` passed.
#[test]
fn moving_home_with_the_source_gone_answers_spec_sync_set_5() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (_a, b, g, _) = sourced_at_a(&net, &c);
    net.set_online(0, false);
    let mut home = std::pin::pin!(b.group_source(g, osis::GroupSource::Local));
    assert!(now(home.as_mut()).is_pending(), "a is recorded: the pass waits for it");
    net.advance(osis::internals::proto::limits::PASS_WAIT_MS + 1);
    drive(&net, home).unwrap();
    assert!(b.group_sources().is_empty());
    assert_eq!(b.at(g, v()).get().unwrap(), Some(Value::Int(1)));
}

// spec/commits.md §5 (Waiting for it), spec/sync-status.md §1 (complete pass: it ends by
// `PASS_WAIT_MS` at the latest): b holds a thing's creating commit with its setting's part left
// out, the only holder of the body away: b writes nothing there (`role_on` reads `Read`) until a
// complete pass of home, begun after it started waiting, ends without the body; then it writes as
// with no setting. The body arriving later applies. (The pass's exact bar: osis-engine
// `facade::a_setting_never_received_is_waited_for_one_pass_spec_commits_5`.)
#[test]
fn a_setting_no_one_serves_is_waited_for_one_complete_pass_spec_commits_5() {
    use crate::common::TestWrites as _;
    use osis::internals::Internals;
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, _) = paired(&net, &c);
    drive(&net, a.wait_synced(SyncScope::All)).unwrap();
    drive(&net, b.wait_synced(SyncScope::All)).unwrap();
    net.set_online(0, false);
    net.run();
    assert_eq!(b.status().unwrap().connected, 0, "a away");
    let x = crate::common::setting(&[("t:log~0", osis::History::FOREVER)]);
    let t = a.commit_with(|w| {
        let t = w.create()?;
        w.group(a.home()).add(osis::Member::Item(t))?;
        w.at(t, osis::core::RETENTION).set(&x)?;
        Ok(t)
    }).unwrap();
    let pks = a.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in &pks {
        let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let bare = osis_commit::rewrite(&blob, |ai| blob.header.aspects[ai].tid == t && blob.header.aspects[ai].ak.as_str() == osis_commit::retention::RETENTION);
        b.engine(|e| e.ingest(&bare.encode(), pk.blobs.clone()).unwrap());
    }
    let name = |db: &Osis| db.commit_with(|w| w.at(t, osis::core::NAME).set(&"b".to_string()));
    assert!(matches!(name(&b), Err(Error::Permission { tid, .. }) if tid == t), "waits for the setting");
    assert_eq!(b.role_on(t).unwrap(), Some(Role::Read), "a role of no use yet");
    net.advance(osis::internals::proto::limits::PASS_WAIT_MS + 1);
    net.run();
    name(&b).expect("a complete pass brought no setting: written as with none");
    assert_eq!(b.at(t, osis::core::RETENTION).get().unwrap(), None);
    for pk in &pks {
        b.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    }
    assert_eq!(b.at(t, osis::core::RETENTION).get().unwrap(), Some(x), "arrived later: it applies");
}

// spec/sync-set.md §5 (Moving home): a move home dropped before it answers leaves g read at a
// (syncing here too); moving it home again answers once caught up, as a restart's retry would.
#[test]
fn a_dropped_move_home_leaves_it_at_its_node_until_moved_again_spec_sync_set_5() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b, g, _) = sourced_at_a(&net, &c);
    let mut w = a.write();
    w.at(g, v()).set(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    net.run();
    {
        let mut home = std::pin::pin!(b.group_source(g, osis::GroupSource::Local));
        assert!(now(home.as_mut()).is_pending(), "not caught up yet");
    }
    net.run();
    assert!(b.group_sources().contains_key(&g), "dropped: still read at a");
    drive(&net, b.group_source(g, osis::GroupSource::Local)).unwrap();
    assert!(b.group_sources().is_empty());
    assert_eq!(b.at(g, v()).get().unwrap(), Some(Value::Int(2)));
}

// spec/sync-set.md §2-3 (Shared here; Unsyncing: a share that ended keeps the copy, shared with
// no one, until the user unsyncs it), issues/storage-follows-groups.md (unsync everything gives
// zero): a thing listed nowhere, granted to another account, stays here once the grant is
// revoked, synced no more and listed as kept; unsyncing it then forgets it.
#[test]
fn a_thing_whose_share_ended_is_kept_until_unsynced_spec_sync_set_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 31, &c);
    let o = on(&net, 57, &c);
    drive(&net, o.import_contact(&a.contact_card().unwrap())).unwrap();
    drive(&net, a.import_contact(&o.contact_card().unwrap())).unwrap();
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::core::NAME).set(&"kept".to_string()).unwrap();
    w.commit().unwrap();
    a.grant(t, o.me(), Role::Read, osis::GrantOpts::default()).unwrap();
    net.run();
    assert!(a.status().unwrap().groups.contains_key(&t), "shared: synced here");
    a.set_role(t, o.me(), None, osis::SetRoleOpts::default()).unwrap();
    for _ in 0..5 {
        net.run();
    }
    let st = a.status().unwrap();
    assert!(!st.groups.contains_key(&t), "the share ended: synced no more");
    assert_eq!(name(&a, t).as_deref(), Some("kept"), "its copy stays");
    assert!(st.kept.contains(&t), "listed as kept");
    a.unsync(t).unwrap();
    net.run();
    assert_eq!(name(&a, t), None, "unsynced: forgotten");
    assert!(!a.status().unwrap().kept.contains(&t));
}
