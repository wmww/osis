//! The osis API over the new sync: status, waits, listening, links and cards, bundles,
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

// spec/sync-status.md §3 (waits): a wait never ends while nothing is connected; with no network
// at all it can never end, so it fails `Network` at once (notes/api-design.md: a wait sure never
// to finish fails).
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

// spec/sync-status.md §3 (waits): on a network with nobody connected no wait on sync IDs ends,
// however long (never an `Unsynced` it did not find, notes/api-design.md: never faked); a wait on
// deliveries with none owed ends at once.
#[test]
fn on_a_network_no_wait_ends_unconnected_spec_sync_status_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 5, &c);
    net.run();
    net.advance(60_000);
    for scope in [SyncScope::All, SyncScope::Thing(a.home())] {
        assert!(now(a.wait_synced(scope)).is_pending(), "{scope:?}");
    }
    assert!(matches!(now(a.wait_synced(SyncScope::Deliveries)), std::task::Poll::Ready(Ok(()))));
}

// spec/sync-status.md §3 (waits): on a network, a wait on a thing whose sync IDs no node has
// open stays pending (it runs to the caller's timeout), whatever time passes.
#[test]
fn wait_on_a_thing_nobody_has_open_stays_pending_spec_sync_status_3() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 3, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    net.run();
    assert!(now(a.wait_synced(SyncScope::Thing(t))).is_pending());
    net.advance(60_000);
    assert!(now(a.wait_synced(SyncScope::Thing(t))).is_pending());
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

// spec/wire.md §10 (the sharer node's P2P reach): a link names its target, K and the sharer node's dialable key; it
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
    let parsed = osis::internals::label::ShareLink::from_text(&text).unwrap();
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

/// Two paired nodes of one account on `net`, the second dialing the first.
fn paired(net: &ManualNet, c: &Arc<ManualClock>) -> (Osis, Osis) {
    let a = on(net, 30, c);
    let addr = a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap().remove(0);
    let mut o = cfg(31, MemStore::new(), c);
    o.app.internals.net = Some(net.clone());
    o.cfg.dial = vec![addr];
    let join = osis::internals::pair(o, &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(join.request()).unwrap();
    (a, join.finish(&reply).unwrap())
}

// spec/sync-set.md §1 (home under synced group): what one node of an account writes in its
// home reaches its other nodes; `wait_synced` on a thing in home (carried by home's sync ID)
// ends once the other node holds it.
#[test]
fn a_write_reaches_the_accounts_other_node_spec_sync_set_1() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b) = paired(&net, &c);
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

// spec/sync-inbox.md §6 (first contact): a redeemer reaches the sharer node by the link and
// joins; the thing is read there.
#[test]
#[ignore = "the join holds, but the redeemed thing is filed nowhere so it is not synced after (issues/sync-link-first-contact.md)"]
fn redeeming_a_link_joins_its_thing_spec_sync_inbox_6() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 40, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 41, &c);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.at(t, osis::core::NAME).set(&"shared".to_string()).unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Read, LinkOpts::default()).unwrap();
    assert_eq!(drive(&net, b.redeem(&link)).unwrap(), t);
    assert_eq!(b.role_on(t).unwrap(), Some(Role::Read));
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("shared"));
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

// spec/sync-streams.md §6 (a bundle is a one-way log replay): a bundle carries what a node holds of a group to another
// node of the account by hand.
#[test]
#[ignore = "sync rewrite: bundle import (streams::import) and the engine facade are not built here"]
fn a_bundle_carries_a_group_by_hand_spec_sync_streams_6() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let (a, b) = paired(&net, &c);
    net.set_online(0, false);
    let mut w = a.write();
    let t = w.create().unwrap();
    w.group(a.home()).add(osis::Member::Item(t)).unwrap();
    w.at(t, osis::core::NAME).set(&"by hand".to_string()).unwrap();
    w.commit().unwrap();
    let mut bytes = Vec::new();
    a.export_bundle(&[a.home()], &mut bytes).unwrap();
    b.import_bundle(bytes.as_slice()).unwrap();
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("by hand"));
}
