#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Co-reader-peer serving limits and LAN routes (spec/sync.md §5, §10): tombstones, budgets,
//! session caps, refused strangers and removed holders, LAN candidates, co-reader caps.

use crate::net::{hosted_nodes, local_nodes};
use crate::net;
use net::*;
use osis_base::{LabelId, Role};
use osis_crypto::{Secret32, SigningSecret};
use osis_label::Address;
use osis_node::sync::{Action, ConnId, EntryKind, Event, SyncConfig};
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command, OpenKey};

const LOCAL: [u8; 32] = [0x42; 32];

/// A hand-driven peer session into node `n`: its served session there and its hub connection.
struct Dialer {
    conn: ConnId,
    hc: ConnId,
    cs: ClientSession,
}

fn exchange(net: &mut Net, n: usize, p: &mut Dialer, acts: Vec<Action>, outs: Vec<ClientOutput>) -> Vec<ClientEvent> {
    net.hand_exchange(n, p.hc, &mut p.cs, acts, outs, true)
}

fn dial_in(net: &mut Net, n: usize) -> (Dialer, Vec<ClientEvent>) {
    let (hc, sent) = net.hand_accept(n, LOCAL, osis_transport::Peer::Key([0x43; 32]));
    let mut p = Dialer { conn: 0, hc, cs: ClientSession::new(ClientConfig { peer_static_key: LOCAL, challenge: [7; 32] }) };
    let now = net.now();
    let mut outs = p.cs.handle(now, ClientInput::Start);
    for f in sent {
        outs.extend(p.cs.handle(now, ClientInput::Bytes(f)));
    }
    let evs = exchange(net, n, &mut p, Vec::new(), outs);
    p.conn = net.served(n, hc);
    (p, evs)
}

fn command(net: &mut Net, n: usize, p: &mut Dialer, cmd: Command) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(cmd));
    exchange(net, n, p, Vec::new(), outs)
}

/// A hand dialer of node `n` that proved `proven_as`'s node key and is a member of `l` here.
fn member_session(net: &mut Net, n: usize, proven_as: usize, l: LabelId) -> Dialer {
    member_pulled(net, n, proven_as, l).0
}

/// `member_session`, with what `n` sent it once `l` joined (its Pull).
fn member_pulled(net: &mut Net, n: usize, proven_as: usize, l: LabelId) -> (Dialer, Vec<ClientEvent>) {
    let (mut p, _) = dial_in(net, n);
    let own = net.engine(proven_as).account_tid().is_some_and(|x| net.engine(n).account_tid() == Some(x));
    let provers = net.sync(proven_as).provers(own).unwrap();
    command(net, n, &mut p, Command::Prove(provers));
    let mut out = Vec::new();
    net.sync(n).shared_admit(p.conn, l, &mut out).unwrap();
    let evs = exchange(net, n, &mut p, out, Vec::new());
    (p, evs)
}

fn reach(net: &mut Net, n: usize, key: u8) {
    let acts = net.sync(n).publish_reach([key; 32], vec![]).unwrap();
    net.actions(n, acts);
}

/// Whether node `b`, with `peer_bytes`, keeps an unstamped entry no key here opens, 1000 bytes,
/// that a reader sharing L brings in reply to `b`'s Pull.
fn kept_from_reader(peer_bytes: u64) -> bool {
    let (mut net, [a]) = local_nodes::<1>();
    let cfg = SyncConfig { peers: false, peer_bytes, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let l = net.label(b);
    let (mut p, evs) = member_pulled(&mut net, b, a, l);
    let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
    let blob = vec![0x5a; 1000];
    let blob_id = osis_label::blob_id(&blob);
    let ev = osis_proto::Event::Added { blob_id, blob: Some(blob), wrap: [0x11; osis_crypto::WRAP_LEN], stamp: None };
    let reply = osis_proto::msg::PullReply { id, events: vec![(l, ev)], cursor: Some(vec![1; 8]), whole: false, more: false, report: false, joins: Vec::new() };
    command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    net.sync(b).entries(&l).iter().any(|(x, _)| *x == blob_id)
}

// spec/sync.md §5 (hosts cap storage per label; co-reader peer applies the same rule), spec/requirements.md
// (peer input never grows storage unbounded): unopened, unstamped entries a reader's stream brings
// count against the peer budget, and past it are not kept.
#[test]
fn peer_budget_refuses_spec_sync_5() {
    assert!(kept_from_reader(SyncConfig::default().peer_bytes), "within the budget, kept");
    assert!(!kept_from_reader(64), "past it, not kept");
}

/// Whether node `b`, with `peer_bytes`, keeps a commit that opens and pends here (drift: its
/// author's clock two hours ahead) that a reader sharing L brings, unstamped, in reply to `b`'s
/// Pull; and whether `b` then holds it pending.
fn pending_kept_from_reader(peer_bytes: u64) -> (bool, bool) {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let cfg = SyncConfig { peers: false, peer_bytes, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.set_skew(a, 2 * 3_600_000);
    let c = net.write(a, g, "ahead");
    let acts = net.sync(a).handle(Event::Local);
    net.actions(a, acts);
    net.run();
    net.set_skew(a, 0);
    let l = net.label(b);
    let la = net.label(a);
    let blob_id = net.sync(a).entries(&la).into_iter().find(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).expect("a placed it").0;
    let (wrap, _) = net.sync(a).entry_meta(&la, &blob_id).unwrap();
    let blob = net.engine(a).blob(&blob_id).unwrap().unwrap();
    let (mut p, evs) = member_pulled(&mut net, b, a, l);
    let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
    let ev = osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None };
    let reply = osis_proto::msg::PullReply { id, events: vec![(l, ev)], cursor: Some(vec![1; 8]), whole: false, more: false, report: false, joins: Vec::new() };
    command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
    let kept = net.sync(b).entries(&l).iter().any(|(x, _)| *x == blob_id);
    let pending = net.engine(b).pending().iter().any(|(x, _)| *x == c);
    (kept, pending)
}

// notes/node-sync.md (Unjudged input), spec/requirements.md (peer input never grows storage
// unbounded): an entry from a reader that opens to a commit pending here counts against the peer
// budget as an unopened one does; past it neither the entry nor the pending commit is kept.
#[test]
fn pending_from_reader_counts_against_peer_budget_spec_sync_5() {
    assert_eq!(pending_kept_from_reader(SyncConfig::default().peer_bytes), (true, true), "within the budget, kept pending");
    assert_eq!(pending_kept_from_reader(64), (false, false), "past it, neither kept");
}

/// Whether node `b` (`peer_bytes` 1500) keeps the second of two unopened 1000-byte entries that
/// reader `a` brings over two sessions, each proving `a`'s account and, with `fresh`, also an
/// account known by nothing at `b`, below `a`'s in tid order (anyone can make one per session).
fn second_kept(fresh: bool) -> bool {
    let (mut net, [a]) = local_nodes::<1>();
    let cfg = SyncConfig { peers: false, peer_bytes: 1500, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let l = net.label(b);
    let pa = net.tid(a);
    let mut strangers = Vec::new();
    for seed in 10.. {
        let s = net.node(seed, &[]);
        if net.tid(s) < pa {
            strangers.push(s);
        }
        if strangers.len() == 2 {
            break;
        }
    }
    let mut kept = false;
    for (i, s) in strangers.into_iter().enumerate() {
        let (mut p, _) = dial_in(&mut net, b);
        let mut provers = net.sync(a).provers(false).unwrap();
        if fresh {
            provers.extend(net.sync(s).provers(false).unwrap());
        }
        command(&mut net, b, &mut p, Command::Prove(provers));
        let mut out = Vec::new();
        net.sync(b).shared_admit(p.conn, l, &mut out).unwrap();
        let evs = exchange(&mut net, b, &mut p, out, Vec::new());
        let id = evs.iter().find_map(|e| if let ClientEvent::Peer(m) = e { if let osis_proto::Message::Pull(x) = &**m { Some(x.id) } else { None } } else { None }).expect("b pulls its member");
        let blob = vec![0x5a + i as u8; 1000];
        let blob_id = osis_label::blob_id(&blob);
        let ev = osis_proto::Event::Added { blob_id, blob: Some(blob), wrap: [0x11; osis_crypto::WRAP_LEN], stamp: None };
        let reply = osis_proto::msg::PullReply { id, events: vec![(l, ev)], cursor: Some(vec![1; 8]), whole: false, more: false, report: false, joins: Vec::new() };
        command(&mut net, b, &mut p, Command::Peer(Box::new(osis_proto::Message::PullReply(Box::new(reply)))));
        kept = net.sync(b).entries(&l).iter().any(|(x, _)| *x == blob_id);
    }
    kept
}

// spec/sync.md §5 (co-reader peer budgets), notes/peers.md Source: a peer's bytes count against
// the account it proved, not one known by nothing here: proving a fresh account beside its own
// gives a session no budget of its own.
#[test]
fn a_fresh_account_splits_no_budget_spec_sync_5() {
    assert!(!second_kept(false), "one account, one budget");
    assert!(!second_kept(true), "a fresh account beside it adds none");
}

// spec/sync.md §5: served connections are capped by one rule over all (the node's
// `max_connections`): at the cap a new one takes the slot of one sharing nothing (a stranger's
// idle connection) before a co-reader's, and once every other shares something, of the source
// holding the most; one sharing nothing is closed `serve_open_ms` after it started, one sharing
// a sync ID stays while up, however quiet its stream.
#[test]
fn at_the_cap_a_stranger_goes_before_a_co_reader_spec_sync_5() {
    let (mut net, [a]) = local_nodes::<1>();
    let cfg = SyncConfig { serve_open_ms: 1_000, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Read)], vec![]);
    let me = net.node_tid(b);
    let mut m = osis_engine::Mutation::new();
    let policy = std::collections::BTreeMap::from([("max_connections".to_string(), 2)]);
    m.replace(me, &osis_schema::core_types::HOST, &osis_schema::core_types::Host { policy, ..Default::default() }).unwrap();
    net.engine(b).commit(m).unwrap();
    net.run();
    let l = net.label(b);
    let (s1, _) = dial_in(&mut net, b);
    let co = member_session(&mut net, b, a, l);
    assert!(net.sync(b).served_opened()[&co.conn].contains(&l), "a member of its shared set");
    let (s2, _) = dial_in(&mut net, b);
    assert!(net.hand_closed(b, s1.hc), "the stranger's idle connection made room");
    assert!(!net.hand_closed(b, co.hc) && !net.hand_closed(b, s2.hc));
    let (s3, _) = dial_in(&mut net, b);
    assert!(net.hand_closed(b, s2.hc), "the next idle one goes");
    assert!(!net.hand_closed(b, co.hc), "the co-reader stays");
    net.clock.advance(1_001);
    let acts = net.sync(b).handle(Event::Tick);
    net.actions(b, acts);
    assert!(net.hand_closed(b, s3.hc), "sharing nothing past serve_open_ms");
    assert!(!net.hand_closed(b, co.hc), "a session sharing a sync ID stays while up, however quiet its stream");
}

// spec/sync.md §5: a stranger without the label's sync key opens nothing.
// spec/sync.md §5 (co-reader peer)
#[test]
fn stranger_refused_spec_sync_5() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let l: LabelId = net.label(b);
    let (mut p, _) = dial_in(&mut net, b);
    let key = SigningSecret::from_seed(&Secret32::from_bytes([0x99; 32]));
    let evs = command(&mut net, b, &mut p, Command::Open { label: l, key: OpenKey::Sync { step: None, key } });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { .. })), "{evs:?}");
    assert!(!evs.iter().any(|e| matches!(e, ClientEvent::Opened { .. })));
    assert!(net.sync(b).served_opened()[&p.conn].is_empty());
}

// spec/sync.md §5, spec/permissions.md §3: a removed holder's node is not dialed (its old
// `reach.0` is held, it may not read now) and, once the label has a new step, opens nothing
// served.
// spec/sync.md §5 (co-reader peer)
#[test]
fn removed_holder_not_dialed_nor_served_spec_sync_5() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let r = net.node(2, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, r, 0xb1);
    let g = net.group(a, &[(r, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(r, t), Some(s("before")));
    assert!(net.sync(a).peers().contains_key(&[0xb1; 32]));
    let (ta, tr) = (net.tid(a), net.tid(r));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_holder(e, g, tr, &rec, 77);
    net.set_online(r, false);
    net.run();
    let la = net.label(a);
    assert!(net.host_path(host, &la).len() >= 2, "a registered a new step");
    assert!(!net.sync(a).peers().contains_key(&[0xb1; 32]), "not dialed");
    net.write(a, t, "after");
    net.set_online(r, true);
    net.advance(61_000);
    let served = net.sync(a).served_opened();
    assert!(!served.is_empty(), "r dialed a");
    assert!(served.values().all(|o| o.is_empty()), "served nothing");
    assert_eq!(net.read(r, t), Some(s("before")));
}

fn net_label(net: &mut Net, n: usize, g: osis_base::Tid) -> LabelId {
    net.engine(n).group_labels(&g).unwrap()[0].id
}

fn reach_ed(net: &mut Net, n: usize) -> [u8; 32] {
    let secret = net.sync(n).dialable_secret();
    let k = SigningSecret::from_seed(&secret).verifying_key().to_bytes();
    let acts = net.sync(n).publish_reach(k, vec![]).unwrap();
    net.actions(n, acts);
    k
}

fn dials(acts: &[Action]) -> Vec<Address> {
    acts.iter().filter_map(|x| if let Action::Dial { address, .. } = x { Some(address.clone()) } else { None }).collect()
}

const IP: &str = "192.168.7.7";

/// A LAN source at `ip`.
fn src(ip: &str) -> std::net::SocketAddr {
    (ip.parse::<std::net::IpAddr>().unwrap(), 47380).into()
}

// spec/sync.md §10: a LAN address is only a candidate; one whose connection fails before coming
// up is backed off without pausing the peer, which is reached by its `peer://` route at once,
// and a repeat of its announcement is not dialed while backed off.
#[test]
fn lan_candidate_failure_keeps_route_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    net.clock.advance(60_001);
    // b announces a key nobody listens with
    let ann = net.sync(b).lan_announcement([0x77; 32], 9).unwrap();
    let (hit, acts) = net.sync(a).lan_seen(&ann, src(IP));
    assert_eq!(hit, Some(kb));
    let bogus = Address { url: format!("peer://{IP}:9"), key: [0x77; 32] };
    assert_eq!(dials(&acts), vec![bogus.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "via peer route");
    net.run();
    assert_eq!(net.read(b, t), Some(s("via peer route")));
    let (_, acts) = net.sync(a).lan_seen(&ann, src(IP));
    assert!(dials(&acts).is_empty());
}

// spec/sync.md §10: a candidate that fails falls back to the most heard verified source (a
// rejoin's announcement from a second address that is not reachable, then the first again).
#[test]
fn lan_candidate_falls_back_to_most_heard_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    // the peer:// route failed (paused): the first real announcement cuts the pause and is
    // dialed; repeats and the second address meanwhile dial nothing
    net.clock.advance(60_001);
    net.feed(a, Event::Tick);
    net.settle(100_000);
    let real = IP;
    let spoof = "192.168.7.66";
    let lk2 = [0x55; 32];
    let ann2 = net.sync(b).lan_announcement(lk2, 5000).unwrap();
    let (_, first) = net.sync(a).lan_seen(&ann, src(real));
    let real_addr = Address { url: format!("peer://{real}:5000"), key: lk };
    assert_eq!(dials(&first), vec![real_addr.clone()]);
    for _ in 0..2 {
        assert!(dials(&net.sync(a).lan_seen(&ann, src(real)).1).is_empty());
    }
    net.clock.advance(osis_node::sync::peers::LAN_CHANGE_MS);
    assert!(dials(&net.sync(a).lan_seen(&ann2, src(spoof)).1).is_empty());
    // that first dial got nowhere; the second candidate is dialed after the pause and fails:
    // the first one takes over
    let conn = first.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).unwrap();
    net.sync(a).handle(Event::Down { conn });
    let spoofed = Address { url: format!("peer://{spoof}:5000"), key: lk2 };
    net.blocked_peers.clear();
    net.clock.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert_eq!(dials(&acts), vec![spoofed.clone()]);
    let conn = acts.iter().find_map(|x| if let Action::Dial { conn, .. } = x { Some(*conn) } else { None }).unwrap();
    let acts = net.sync(a).handle(Event::Down { conn });
    assert_eq!(dials(&acts), vec![real_addr]);
}

// spec/sync.md §10: a connection through a LAN address that comes up proves the route (the
// signature bound the key to the node): it is dialed first from then on; a newer candidate
// does not displace a running connection.
#[test]
fn lan_route_proven_by_up_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.blocked_peers.insert((a, b));
    let g = net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    net.blocked_peers.clear();
    net.clock.advance(60_001);
    // b listens on the LAN with a fresh key
    let lk = SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    let (_, acts) = net.sync(a).lan_seen(&ann, src(IP));
    let route = Address { url: format!("peer://{IP}:5000"), key: lk };
    assert_eq!(dials(&acts), vec![route.clone()]);
    net.actions(a, acts);
    net.settle(100_000);
    let t = net.item(a, g, g, "over the LAN");
    net.run();
    assert_eq!(net.read(b, t), Some(s("over the LAN")));
    // another address while connected: no dial
    let (_, acts) = net.sync(a).lan_seen(&ann, src("192.168.7.8"));
    assert!(dials(&acts).is_empty(), "{acts:?}");
    // the connection drops: after the pause the proven route is dialed, not the candidate
    net.set_online(b, false);
    net.set_online(b, true);
    net.advance(61_000);
    let acts = net.sync(a).handle(Event::Tick);
    assert!(dials(&acts).iter().all(|d| *d != Address { url: "peer://192.168.7.8:5000".into(), key: lk }), "{acts:?}");
}

// spec/sync.md §10 (Shared set): what a session serves is its shared set's, and once the proved
// node is removed from the group its member closes (issues/net-shared-set.md, Opens); a session
// with no member opens nothing by a key it does not hold
#[test]
fn a_member_closes_with_the_right_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    let g = net.group_at(a, &[(b, Role::Read)], vec![]);
    net.run();
    let l: LabelId = net.label(a);
    let p = member_session(&mut net, a, b, l);
    assert!(net.sync(a).served_opened()[&p.conn].contains(&l));
    let (mut q, _) = dial_in(&mut net, a);
    let stranger = SigningSecret::from_seed(&Secret32::from_bytes([0x99; 32]));
    let evs = command(&mut net, a, &mut q, Command::Open { label: l, key: OpenKey::Sync { step: None, key: stranger } });
    assert!(evs.iter().any(|e| matches!(e, ClientEvent::Refused { .. })), "{evs:?}");
    // b removed from g
    let (ta, tb) = (net.tid(a), net.tid(b));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_holder(e, g, tb, &rec, 79);
    let acts = net.sync(a).handle(Event::Local);
    net.actions(a, acts);
    assert_eq!(net.sync(a).shared_members(p.conn), std::collections::BTreeSet::new(), "the member closed");
    assert!(net.sync(a).served_opened()[&p.conn].is_empty(), "serves nothing");
}

// spec: none (notes/api.md Sync configuration and status): sources count per proven source
// (`pass_source`); a served session with none is its own source, never caught up, so it cannot
// make the count read caught up.
#[test]
fn a_session_of_a_node_not_dialed_is_a_source_not_caught_up() {
    let (mut net, [a, b, c]) = local_nodes::<3>();
    for n in [a, b, c] {
        reach_ed(&mut net, n);
    }
    let g = net.group_at(a, &[(b, Role::Read), (c, Role::Read)], vec![]);
    net.run();
    net.set_online(c, false);
    net.run();
    let status = |net: &mut Net| net.sync(a).label_status().into_iter().find(|s| s.group == g).unwrap();
    let before = status(&mut net);
    assert_eq!(before.idle, before.sources, "caught up with the connection it dialed: {before:?}");
    let l: LabelId = net.label(a);
    let _p = member_session(&mut net, a, c, l);
    let after = status(&mut net);
    assert_eq!(after.sources, before.sources + 1, "its own source: {after:?}");
    assert_eq!(after.idle, before.idle, "not caught up: {after:?}");
}

// spec/sync.md §5: a served session that opens nothing is closed after `serve_open_ms`, even
// while it keeps sending.
#[test]
fn silent_session_closed_spec_sync_5() {
    let mut net = Net::new();
    let cfg = SyncConfig { serve_open_ms: 1_000, ..SyncConfig::default() };
    let b = net.add_node(2, cfg);
    let (mut p, _) = dial_in(&mut net, b);
    net.clock.advance(1_001);
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Open { label: LabelId([1; 16]), key: OpenKey::Sync { step: None, key: SigningSecret::from_seed(&Secret32::from_bytes([3; 32])) } }));
    exchange(&mut net, b, &mut p, Vec::new(), outs);
    let acts = net.sync(b).handle(Event::Tick);
    net.actions(b, acts);
    assert!(net.hand_closed(b, p.hc));
}

// spec/permissions.md §3: a complete pass also waits for every co-reader the node received the
// label from and can reach: with that peer's replies held back, the host's pass alone is not
// enough; a node that is no co-reader is never waited for. `a` never stops waiting for peers, so
// only b's own passes complete it.
#[test]
fn complete_pass_counts_peers_spec_permissions_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let cfg = SyncConfig { hosts: vec![net.address(host)], peer_pass_wait_ms: u64::MAX, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[host]);
    let c = net.node(3, &[host]);
    let x = net.node(4, &[host]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    reach_ed(&mut net, x);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read)], &[host]);
    net.item(b, g, g, "from b");
    net.run();
    assert!(net.sync(a).complete_pass(&g));
    // x shares nothing with a: its replies held back change nothing
    net.held.insert((x, a));
    net.held.insert((b, a));
    let (tb, tc) = (net.tid(b), net.tid(c));
    let e = net.engine(b);
    let rec = recipients_of(e, &[(tb, Role::Admin)]);
    remove_holder(e, g, tc, &rec, 78);
    net.run();
    assert!(!net.sync(a).complete_pass(&g), "b's pass is held back");
    net.release();
    // b's rotation boxed only b: its re-seal of a comes by a's inbox over b's link once released,
    // a role change after a's last pass at the host, which a then asks the host for
    net.run();
    assert!(net.sync(a).complete_pass(&g));
}

// spec/permissions.md §3: a co-reader removed from G while still sharing another label with the
// node no longer holds G's complete pass, even with its replies held back; nor does one that
// stays silent past `peer_pass_wait_ms`.
#[test]
fn complete_pass_drops_removed_coreader_spec_permissions_3() {
    let (mut net, host, [a, x, b]) = hosted_nodes::<3>();
    reach_ed(&mut net, a);
    reach_ed(&mut net, x);
    let g = net.group(a, &[(x, Role::Write), (b, Role::Read)], &[host]);
    let g2 = net.group_seeded(a, &[(x, Role::Read)], vec![net.address(host)], 2);
    net.item(x, g, g, "from x");
    net.run();
    assert!(net.sync(a).complete_pass(&g) && net.sync(a).complete_pass(&g2));
    net.held.insert((x, a));
    let (ta, tx) = (net.tid(a), net.tid(x));
    let e = net.engine(a);
    let rec = recipients_of(e, &[(ta, Role::Admin)]);
    remove_holder(e, g, tx, &rec, 81);
    // a role change of g from elsewhere: b's grant
    let tb = net.tid(b);
    net.grant(a, g, tb, Role::Write);
    net.run();
    assert!(net.sync(a).peers().get(&net.sync(x).own_reach().unwrap().dialable).is_some_and(|p| !p.labels.contains(&net_label(&mut net, a, g))), "x still shares g2 only");
    assert!(net.sync(a).complete_pass(&g), "x no longer counts for g");
}

// spec/permissions.md §4: `reach.0` goes under every label: two nodes of other accounts sharing
// a group at a host learn each other's dialable key there and dial each other.
#[test]
fn reach_under_every_label_spec_permissions_4() {
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    net.group(a, &[(b, Role::Read)], &[host]);
    let ka = reach_ed(&mut net, a);
    let kb = reach_ed(&mut net, b);
    net.run();
    assert!(net.sync(b).peers().contains_key(&ka));
    assert!(net.sync(a).peers().contains_key(&kb));
}

// spec/sync.md §5: co-readers dialed per label are capped.
#[test]
fn co_readers_capped_spec_sync_5() {
    let mut net = Net::new();
    let cfg = SyncConfig { max_peers_per_label: 1, ..SyncConfig::default() };
    let a = net.add_node(1, cfg);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach(&mut net, a, 0xa1);
    reach(&mut net, b, 0xb1);
    reach(&mut net, c, 0xc1);
    net.group_at(a, &[(b, Role::Read), (c, Role::Read)], vec![]);
    assert_eq!(net.sync(a).peers().len(), 1);
}
