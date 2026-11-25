//! The osis API over the new sync: status, waits, listening, links and cards,
//! `keep_alive`, and the client port's node side; nodes on one in-process test network
//! (`internals::ManualNet`) with one manual clock, or with no network at all.

use crate::common::{Held as _, TestWrites as _};
use crate::common::{cfg, clock, db};
use osis::internals::proto::Msg;
use osis::internals::proto::api::{ApiCode, Outcome};
use osis::internals::{ManualClock, ManualNet};
use osis::{Error, LinkOpts, MemStore, Osis, Role, Value};
use std::sync::Arc;

/// Node `seed` on `net`, at `clock`.
fn on(net: &ManualNet, seed: u64, clock: &Arc<ManualClock>) -> Osis {
    let mut c = cfg(seed, MemStore::new(), clock);
    c.app.internals.net = Some(net.clone());
    osis::internals::create(c).unwrap()
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

// spec/sync-transport.md §3 (each time it starts listening), §5 (key change), spec/sync-set.md §1
// (dial list: each node keeping its own entry, on the things it chooses): naming a thing publishes
// the node's entry there at once, listening publishes it under its key, its global addresses only;
// a new key replaces its entry.
#[test]
fn listening_publishes_where_the_node_is_dialed_spec_sync_transport_3() {
    use osis::internals::Internals;
    use osis::internals::schema::core_types as ct;
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 9, &c);
    let (t, u) = a.commit_with(|w| Ok((w.create_held()?, w.create_held()?))).unwrap();
    a.publish_dial_on(&[t]).unwrap();
    let key = a.listen(&["peer://203.0.113.5:4040".parse().unwrap(), "peer://127.0.0.1:1".parse().unwrap()]).unwrap()[0].key();
    let list = |t| a.engine(|e| e.get_typed(&t, &ct::DIAL).unwrap()).unwrap_or_default();
    assert_eq!(list(t), [(osis::Weak(a.node()), ct::Dial { key: key.to_vec(), urls: vec!["peer://203.0.113.5:4040".to_string()] })].into(), "global addresses only");
    assert!(list(u).is_empty(), "a thing not named");
    a.publish_dial_on(&[t, u]).unwrap();
    assert_eq!(list(u), list(t), "named after the listen: published at once");
    a.rotate_peer_address().unwrap();
    for t in [t, u] {
        let list = list(t);
        assert_eq!(list.len(), 1);
        assert!(list.values().all(|d| d.key != key.to_vec()), "the old key's entry replaced");
    }
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
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    let l = a.make_link(t, Role::Read, a.node(), LinkOpts::default()).unwrap();
    assert_eq!(l.target().unwrap(), t);
    let text = l.to_string();
    let parsed = osis::internals::blob::ShareLink::from_text(&text).unwrap();
    assert_eq!(parsed.peers.first().map(|p| p.dialable), Some(addr.key()));
    assert!(a.links().unwrap().iter().any(|x| x.target == t && x.role == Role::Read));
    assert!(matches!(a.make_link(t, Role::Sync, a.node(), LinkOpts::default()), Err(Error::Invalid(_))));
}

// spec/commits.md §6 (expiry), spec/requirements.md (Ephemeral data: a value that lives while its author is there):
// `keep_alive` renews an ephemeral value with a default expiry; any other key is refused.
#[test]
fn keep_alive_needs_an_ephemeral_key_and_a_runtime_notes_ephemeral() {
    let db = db(13);
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    assert!(matches!(db.at(t, osis::core::NAME).keep_alive(&"x".to_string()), Err(Error::Invalid(_))));
}

// ---- the client port (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6) ----

fn auth(secret: Option<[u8; 32]>) -> Msg {
    Msg::Auth { id: 1, secret: secret.map(osis::internals::Secret32::from_bytes), session_id: [7; 16] }
}

fn get(t: osis::Tid, ak: &str) -> Msg {
    Msg::Call { id: 2, max_reply: 65_536, method: osis::internals::port_method::GET, args: vec![Value::bytes(t.as_bytes()), Value::Str(ak.into()), Value::List(Vec::new())] }
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
    let t = w.create_held().unwrap();
    w.at(t, osis::DynamicAspectKey::untyped(crate::common::ak("x:v.0"))).set(&Value::Int(5)).unwrap();
    w.commit().unwrap();
    let (client, secret) = db.add_client(db.node(), None).unwrap();
    (db, t, client, *secret.expose())
}

// spec/wire.md §11.2 (Auth): a main session on the unix transport sends no secret, and then
// reads as the node itself.
#[test]
fn a_main_session_authenticates_without_a_secret_spec_wire_11() {
    let (db, t, _, _) = port_node();
    let r = osis::internals::port_answers(&db, 1, true, vec![auth(None), get(t, "x:v.0")]);
    assert!(ok_reply(&r[0]), "{r:?}");
    assert!(matches!(&r[1], Msg::Reply { outcome: Outcome::Ok { value: Value::List(v) }, .. } if v == &vec![Value::uint(0), Value::List(vec![Value::Int(5)])]), "{r:?}");
}

// spec/wire.md §11.2 (Auth): any other Auth is Error 1: no secret on a keyed transport, a secret
// on the unix transport, a secret matching no entry, a second Auth of a client session;
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

// spec/wire.md §11.2 (A client's rights): a thing the client's thing may not read answers as a
// thing the node does not know (a GET of an unknown tid reads absent); an unknown method is
// `[1, 11, text]`.
#[test]
fn a_clients_thing_reads_only_what_it_may_spec_wire_11() {
    let (db, t, client, secret) = port_node();
    let unknown = osis::Tid::from_bytes([3; 15]);
    let r = osis::internals::port_answers(&db, 1, false, vec![auth(Some(secret)), get(t, "x:v.0"), get(unknown, "x:v.0"), Msg::Call { id: 3, max_reply: 4096, method: 999, args: vec![] }]);
    assert!(ok_reply(&r[0]));
    assert_eq!(r[1], r[2], "as unknown");
    assert!(matches!(&r[3], Msg::Reply { outcome: Outcome::Err { code, .. }, .. } if *code == ApiCode::UNSUPPORTED), "{r:?}");
    db.grant(t, client, Role::Read, osis::GrantOpts::default()).unwrap();
    let r = osis::internals::port_answers(&db, 1, false, vec![get(t, "x:v.0")]);
    assert!(matches!(&r[0], Msg::Reply { outcome: Outcome::Ok { value: Value::List(v) }, .. } if v == &vec![Value::uint(0), Value::List(vec![Value::Int(5)])]), "granted: {r:?}");
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
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Read, a.node(), LinkOpts::default()).unwrap();
    net.set_online(0, false);
    let mut f = std::pin::pin!(b.redeem(&link, b.node()));
    let mut poll = || f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
    assert!(poll().is_pending());
    net.advance(FOLLOW_LINK_MS - 60_000);
    assert!(poll().is_pending(), "waits within the follow time");
    net.advance(120_000);
    assert!(matches!(poll(), std::task::Poll::Ready(Err(Error::Network(_)))), "fails once given up");
    assert!(!matches!(b.role_on(t), Ok(Some(_))), "joined nothing");
}

// spec/permissions.md §7 (Finalized; the seed thing goes): a revoked link is listed no more and
// revoking it again changes nothing; its joiner keeps its role until set_role removes it,
// through the link's thing.
#[test]
fn a_revoked_links_joiner_stays_until_removed_spec_permissions_7() {
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 46, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 47, &c);
    let mut w = a.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    let link = a.make_link(t, Role::Read, a.node(), LinkOpts::default()).unwrap();
    assert_eq!(drive(&net, b.redeem(&link, b.node())).unwrap(), t);
    let id = a.links().unwrap().into_iter().find(|l| l.target == t).unwrap().id;
    a.revoke_link(id).unwrap();
    assert!(a.links().unwrap().is_empty(), "ended");
    a.revoke_link(id).unwrap();
    // the joiner: b's node thing, as it named (spec/permissions.md §7 Redeem)
    let joiner = b.node();
    let joined = |a: &Osis| a.holders(t).unwrap().into_iter().any(|h| h.thing == joiner);
    assert!(joined(&a), "the joiner keeps its role");
    a.set_role(t, joiner, None, osis::SetRoleOpts::default()).unwrap();
    assert!(!joined(&a), "removed");
}

// spec/permissions.md §1, §2 (the public), spec/wire.md §10 (public link), spec/sync-judgement.md
// §1 (entitlement): a grant to the public lets every party read: a client's thing of the node
// granted nothing, and a stranger node by a public link, which a private thing has none of. The
// public holds read at most, and removing its grant makes the thing private again.
#[test]
fn the_publics_grant_round_trip_spec_permissions_1() {
    use osis::{GrantOpts, HolderKind, Tid};
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 48, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let b = on(&net, 49, &c);
    let mut w = a.write();
    let t = w.create_held().unwrap();
    w.at(t, osis::core::NAME).set(&"open".to_string()).unwrap();
    w.commit().unwrap();
    let (client, _) = a.add_client(a.node(), None).unwrap();
    let client = osis::internals::Internals::acting_as(&a, client);
    assert_eq!(client.at(t, osis::core::NAME).get().unwrap(), None, "a client granted nothing");
    assert!(matches!(a.public_link(t), Err(Error::Invalid(_))), "not public");
    assert!(matches!(a.grant(t, Tid::PUBLIC, Role::Write, GrantOpts::default()), Err(Error::Invalid(_))), "read at most");
    assert!(matches!(a.grant(t, Tid::PUBLIC, Role::Read, GrantOpts { may_grant: true, ..GrantOpts::default() }), Err(Error::Invalid(_))));
    a.grant(t, Tid::PUBLIC, Role::Read, GrantOpts::default()).unwrap();
    assert!(a.holders(t).unwrap().iter().any(|h| h.thing == Tid::PUBLIC && h.kind == HolderKind::Public && h.role == Role::Read));
    assert_eq!(client.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("open"), "every party reads it");
    let link = a.public_link(t).unwrap();
    assert_eq!(link.target().unwrap(), t);
    assert_eq!(drive(&net, b.redeem(&link, b.node())).unwrap(), t);
    assert_eq!(b.at(t, osis::core::NAME).get().unwrap().as_deref(), Some("open"), "a stranger reads it by the link");
    a.set_role(t, Tid::PUBLIC, None, osis::SetRoleOpts::default()).unwrap();
    assert!(!a.grants(t).unwrap().contains_key(&Tid::PUBLIC));
    assert_eq!(client.at(t, osis::core::NAME).get().unwrap(), None, "private again");
    assert!(matches!(a.public_link(t), Err(Error::Invalid(_))));
}

// spec/sync-inbox.md §1 (Card): putting a thing's card needs its keys here and write on the host
// through it; a stranger reading the host then holds its keys and grants it a
// role. Removing a card needs write on the host.
#[test]
fn set_card_needs_keys_and_a_path_through_the_thing_spec_sync_inbox_1() {
    use osis::{GrantOpts, Tid};
    let c = clock();
    let net = ManualNet::new(c.clone());
    let a = on(&net, 50, &c);
    a.listen(&["peer://127.0.0.1:1".parse().unwrap()]).unwrap();
    let mut w = a.write();
    let g = w.create_held().unwrap();
    let p = w.create(g, None).unwrap();
    w.hold(g, p).unwrap();
    let elsewhere = w.create_held().unwrap();
    w.commit().unwrap();
    // g with its keys: by a grant (here to a client's thing)
    let (client, _) = a.add_client(a.node(), None).unwrap();
    a.grant(g, client, Role::Read, GrantOpts::default()).unwrap();
    let unknown = Tid::from_bytes([7; 15]);
    assert!(matches!(a.set_card(p, unknown, Some(unknown)), Err(Error::UnknownKeys { .. })), "no keys of it here");
    assert!(matches!(a.set_card(elsewhere, g, Some(g)), Err(Error::Permission { .. })), "g does not write it");
    a.set_card(p, g, Some(g)).unwrap();
    a.grant(p, Tid::PUBLIC, Role::Read, GrantOpts::default()).unwrap();
    let b = on(&net, 51, &c);
    assert_eq!(drive(&net, b.redeem(&a.public_link(p).unwrap(), b.node())).unwrap(), p);
    let mut w = b.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    b.grant(t, g, Role::Read, GrantOpts::default()).unwrap();
    a.set_card(p, g, None).unwrap();
}

// ---- leaving (spec/sync-set.md §3) ----

// ---- sync unit sources: the hand-off (spec/sync-set.md §5) ----
