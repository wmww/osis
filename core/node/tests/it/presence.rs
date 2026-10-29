//! Presence (notes/ephemeral.md step 4, spec/sync.md §5, §9): ephemeral values tied to their
//! author's connection. A server deletes a presence entry when the connection that uploaded it
//! closes; a node drops a presence commit once no server or peer it syncs the label with holds
//! it; leases (`MAX_LEASE`) and keep-alives (`KEEPALIVE`) are the backstop for a departure nobody
//! noticed.

use crate::ephemeral::{push, rows, sealed, write_key};
use crate::net;
use net::*;
use osis_base::format::{KEEPALIVE_MS, MAX_LEASE_MS};
use osis_base::{Role, Tid, Value};
use osis_node::Mutation;
use osis_schema::Lifetime;

const CURSOR: &str = "/doc/cursor";

fn cursor() -> osis_schema::Untyped {
    ukey(CURSOR, Lifetime::Presence)
}

/// A group of `members` (node, role) administered by `admin` at `servers`, with a durable item
/// `t` in it.
fn setup(net: &mut Net, admin: usize, members: &[(usize, Role)], servers: &[usize]) -> (Tid, Tid) {
    let g = net.group(admin, members, servers);
    let t = net.item(admin, g, g, "doc");
    net.run();
    (g, t)
}

/// Node `n`'s cursor on `t`.
fn at(net: &mut Net, n: usize, t: Tid) -> Option<Value> {
    net.eph_read(n, t, CURSOR)
}

/// Remote ephemeral changes of `(t, ak)` among the events `rx` got.
fn remote_changes(rx: &std::sync::mpsc::Receiver<osis_node::Event>, t: Tid, ak: &str) -> usize {
    rx.try_iter()
        .filter(|e| matches!(e, osis_node::Event::Ephemeral { changed, origin: osis_node::Origin::Remote, .. } if changed.iter().any(|(x, a)| *x == t && a.as_str() == ak)))
        .count()
}

/// Live entries server `sv` holds under `l`.
fn live(net: &Net, sv: usize, l: &osis_base::LabelId) -> usize {
    osis_proto::LabelStore::live_ids(net.servers[sv].hub.store(), l).unwrap().len()
}

/// Presence commits node `n` holds.
fn presence_held(net: &mut Net, n: usize) -> usize {
    let e = net.engine(n);
    e.held_ephemeral().into_iter().filter(|(id, _, _)| e.ephemeral_is_presence(id)).count()
}

// spec/sync.md §5 (a presence entry goes when its uploading connection closes), §9 (a node drops a
// presence commit no server holds): the cursor vanishes at B the moment A's connection closes,
// with no clock advance; A reconnecting brings it back
#[test]
fn author_disconnects_presence_gone_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    let (rb, rs) = (rows(&net.nodes[b].backend), rows(&net.servers[sv].backend));
    let l = net.label(a);
    let n0 = live(&net, sv, &l);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")));
    assert_eq!(rows(&net.nodes[b].backend), rb, "presence is never stored at a member");
    assert_eq!(rows(&net.servers[sv].backend), rs, "nor at the server");
    assert_eq!(live(&net, sv, &l), n0 + 1);
    let rx = net.listen(b);
    let now = net.now();
    net.set_online(a, false);
    net.run();
    assert_eq!(net.now(), now);
    assert_eq!(at(&mut net, b, t), None, "gone at once");
    assert!(remote_changes(&rx, t, CURSOR) >= 1, "a remote change fired");
    assert_eq!(live(&net, sv, &l), n0, "the server holds nothing of it");
    assert_eq!(at(&mut net, a, t), Some(s("a@1")), "the author keeps its own value");
    assert_eq!(presence_held(&mut net, b), 0);
    net.set_online(a, true);
    net.advance(10_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "back with its author");
}

// spec/sync.md §9: with A and B both on two servers the cursor stays until A has left both
#[test]
fn presence_stays_while_any_server_holds_it_spec_sync_9() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s1, s2]);
    let b = net.node(2, &[s1, s2]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[s1, s2]);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")));
    // A loses server 1 only
    net.blocked.insert((a, s1));
    net.set_online(a, false);
    net.set_online(a, true);
    net.advance(10_000);
    assert!(net.conn_to(a, s1).is_none() && net.conn_to(a, s2).is_some());
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "server 2 still holds it");
    net.blocked.insert((a, s2));
    net.set_online(a, false);
    net.run();
    assert_eq!(at(&mut net, b, t), None, "gone once A left both");
}

// spec/sync.md §9: B losing its own connection drops A's cursor at once (no source holds it for
// B); on reconnect B reconciles the label and gets it back while A is still there
#[test]
fn holder_disconnect_drops_and_recovers_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")));
    net.set_online(b, false);
    net.run();
    assert_eq!(at(&mut net, b, t), None, "dropped with B's connection");
    net.set_online(b, true);
    net.advance(10_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "back on reconnect");
    // and again after an update made while B was away
    net.set_online(b, false);
    net.eph_write(a, t, &cursor(), s("a@2"));
    net.run();
    net.set_online(b, true);
    net.advance(10_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@2")));
}

// spec/sync.md §5 (a member peer serving a label applies the same rule), §9: a device reachable
// only through a member peer sees a server device's cursor and loses it when that device leaves
// the server; its own cursor reaches the peer and goes when it leaves the peer
#[test]
fn member_peer_carries_presence_spec_sync_5() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let c = net.node(3, &[sv]);
    for (n, k) in [(b, 0xb5), (c, 0xc5)] {
        let acts = net.sync(n).publish_reach([k; 32], vec!["https://relay.example".into()]).unwrap();
        net.actions(n, acts);
    }
    let (_, t) = setup(&mut net, a, &[(b, Role::Write), (c, Role::Write)], &[sv]);
    // c loses the server: only b's peer link is left
    net.blocked.insert((c, sv));
    net.restart(c, 33);
    net.advance(10_000);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")));
    assert_eq!(at(&mut net, c, t), Some(s("a@1")), "through the member peer");
    net.set_online(a, false);
    net.run();
    assert_eq!(at(&mut net, b, t), None);
    assert_eq!(at(&mut net, c, t), None, "gone through the member peer too");
    let k = ukey("/doc/peer", Lifetime::Presence);
    net.eph_write(c, t, &k, s("c@1"));
    net.run();
    assert_eq!(net.eph_read(b, t, "/doc/peer"), Some(s("c@1")));
    net.set_online(c, false);
    net.run();
    assert_eq!(net.eph_read(b, t, "/doc/peer"), None, "gone when C leaves the peer");
}

// spec/sync.md §9 (presence over a direct peer link, no server): the cursor goes with the link
#[test]
fn peer_link_presence_spec_sync_9() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    for (n, k) in [(a, 0xa7), (b, 0xb7)] {
        let acts = net.sync(n).publish_reach([k; 32], vec!["https://relay.example".into()]).unwrap();
        net.actions(n, acts);
    }
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    let t = net.item(a, g, g, "doc");
    net.run();
    net.advance(70_000);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.eph_write(b, t, &ukey("/doc/peer", Lifetime::Presence), s("b@1"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")));
    assert_eq!(net.eph_read(a, t, "/doc/peer"), Some(s("b@1")));
    net.set_online(a, false);
    net.run();
    assert_eq!(at(&mut net, b, t), None);
    net.set_online(a, true);
    net.advance(70_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "back with the link");
    net.set_online(b, false);
    net.run();
    assert_eq!(net.eph_read(a, t, "/doc/peer"), None);
}

// spec/sync.md §9 (lease): an author gone behind a half-open connection keeps its cursor up only
// until `ts + MAX_LEASE`, at the server and at every holder
#[test]
fn half_open_author_gone_by_lease_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    let l = net.label(a);
    let n1 = live(&net, sv, &l);
    net.vanish(a);
    net.advance(MAX_LEASE_MS - 60_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "the server never saw A go");
    net.advance(61_000);
    assert_eq!(at(&mut net, b, t), None, "past the lease");
    assert_eq!(live(&net, sv, &l), n1 - 1, "the server dropped it unattended");
    // a holder arriving now never gets it
    net.restart(b, 22);
    net.advance(10_000);
    assert_eq!(at(&mut net, b, t), None);
}

// spec/sync.md §9 (keep-alive): a connected author refreshes its presence every KEEPALIVE, so it
// outlives the lease; each fresh commit covers the last (one held per author); no traffic between
// refreshes while idle
#[test]
fn keepalive_outlives_lease_no_idle_traffic_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    assert_eq!(presence_held(&mut net, b), 1);
    let kinds = |net: &Net| net.sent_kinds.iter().filter(|(k, _)| ![2, 3].contains(*k)).map(|(_, n)| *n).sum::<usize>();
    let before = kinds(&net);
    // idle, short of the keep-alive
    for _ in 0..14 {
        net.advance(60_000);
    }
    assert_eq!(kinds(&net), before, "nothing but pings while idle: {:?}", net.sent_kinds);
    net.advance(KEEPALIVE_MS - 14 * 60_000 + 1_000);
    assert!(kinds(&net) > before, "a keep-alive went");
    net.advance(MAX_LEASE_MS - KEEPALIVE_MS + 60_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "kept past the first commit's lease");
    assert_eq!(presence_held(&mut net, b), 1, "the fresh commit covers the old one");
    assert_eq!(presence_held(&mut net, a), 1);
    let l = net.label(a);
    assert!(net.servers[sv].hub.store().ephemeral_bytes(&l) > 0);
}

// spec/sync.md §9 (presence travels from its author only): a holder bridging two servers does not
// carry another's presence across (it carries plain ephemeral state), and a forged presence commit
// carrying another node's writes does not count at receivers
#[test]
fn non_author_cannot_carry_presence_spec_sync_9() {
    let mut net = Net::new();
    let (s1, s2) = (net.add_server(), net.add_server());
    let a = net.node(1, &[s1]);
    let b = net.node(2, &[s1, s2]);
    let c = net.node(3, &[s2]);
    net.blocked.insert((a, s2));
    net.blocked.insert((c, s1));
    let g = net.group(a, &[(b, Role::Write), (c, Role::Write)], &[s1, s2]);
    net.run();
    // made by b, on both servers: every node holds it
    let t = net.item(b, g, g, "doc");
    net.run();
    assert!(net.read(c, t).is_some() && net.read(a, t).is_some());
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.eph_write(a, t, &ukey("/doc/plain", Lifetime::Ephemeral), s("plain"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")));
    assert_eq!(net.eph_read(c, t, "/doc/plain"), Some(s("plain")), "plain state is bridged");
    assert_eq!(at(&mut net, c, t), None, "presence is not");
    // b forges a presence commit of its own carrying a's cursor writes, uploaded to server 2
    let ak = osis_base::Ak::new(CURSOR).unwrap();
    let forged = net.engine(b).forge_presence_carrying(t, &ak).unwrap().unwrap();
    let wk = write_key(&mut net, b, g);
    let (_, ev) = sealed(&mut net, b, g, &forged.blob, Some(&wk), 5);
    let l = net.label(b);
    let acts = push(&mut net, c, s2, l, vec![ev]);
    net.actions(c, acts);
    net.run();
    assert_eq!(at(&mut net, c, t), None, "another node's writes in a presence commit do not count");
    assert!(net.engine(c).holds_ephemeral(&forged.id), "the commit itself is held (its own writes would count)");
}

// spec/sync.md §9 (lease): a captured presence entry replayed after its author left (a hostile
// writer or server pushing it again) stays up at most until the original lease ends
#[test]
fn replayed_presence_dies_at_lease_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    let id = net.engine(b).held_ephemeral().into_iter().map(|(id, _, _)| id).find(|id| net.engine(b).ephemeral_is_presence(id)).unwrap();
    let captured = net.sync(b).ephemeral_entry_events(&id);
    assert!(!captured.is_empty());
    net.vanish(a);
    net.restart_server(sv);
    net.run();
    net.advance(10 * 60_000);
    assert_eq!(at(&mut net, b, t), None, "gone with the server's restart");
    for (l, ev) in captured {
        let acts = push(&mut net, b, sv, l, vec![ev]);
        net.actions(b, acts);
    }
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "the replay counts while its lease runs");
    net.advance(MAX_LEASE_MS - 10 * 60_000);
    assert_eq!(at(&mut net, b, t), None, "but not past it");
    assert_eq!(presence_held(&mut net, b), 0);
}

// spec/sync.md §9 (restart): an author's restart ends its presence everywhere (its connection
// closed; its new session has no presence); a holder's restart gets the live presence back
#[test]
fn restart_behavior_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    net.eph_write(a, t, &cursor(), s("a@1"));
    net.run();
    net.restart(b, 22);
    net.advance(10_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@1")), "a restarted holder gets it back");
    net.restart(a, 21);
    net.advance(10_000);
    assert_eq!(at(&mut net, a, t), None, "forgotten by its author's restart");
    assert_eq!(at(&mut net, b, t), None, "and gone at the holder");
    net.eph_write(a, t, &cursor(), s("a@2"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@2")));
    // a server restart: the author uploads it again
    net.restart_server(sv);
    net.run();
    net.advance(10_000);
    assert_eq!(at(&mut net, b, t), Some(s("a@2")), "back after the server restarted");
}

// spec/data-model.md §2 (presence values live while their author is connected): a presence write
// with an expiry is refused
#[test]
fn presence_write_takes_no_expiry_spec_data_model_2() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let (_, t) = setup(&mut net, a, &[], &[sv]);
    let mut m = Mutation::new();
    m.set(t, &cursor(), &s("x")).unwrap();
    m.expires(t, &cursor(), osis_base::WallMs(net.now() + 5_000)).unwrap();
    assert!(net.engine(a).write(m).is_err());
}

// spec/sync.md §9 (each presence commit covers its author's last): an update replaces the cursor
// at a holder in one change, never dropping it in between (the author deletes the covered entry
// before uploading the cover, so the holder sees the deletion first)
#[test]
fn update_never_flaps_spec_sync_9() {
    let mut net = Net::new();
    let sv = net.add_server();
    let a = net.node(1, &[sv]);
    let b = net.node(2, &[sv]);
    let (_, t) = setup(&mut net, a, &[(b, Role::Write)], &[sv]);
    net.eph_write(a, t, &cursor(), s("a@0"));
    net.run();
    assert_eq!(at(&mut net, b, t), Some(s("a@0")));
    let rx = net.listen(b);
    for i in 1..=5 {
        net.eph_write(a, t, &cursor(), s(&format!("a@{i}")));
        net.run();
        assert_eq!(at(&mut net, b, t), Some(s(&format!("a@{i}"))));
    }
    assert_eq!(remote_changes(&rx, t, CURSOR), 5, "one change per update");
}
