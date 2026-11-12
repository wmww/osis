#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The shared set over real sessions (issues/net-shared-set.md, spec/wire.md §11.2 Beacons, Offer,
//! Lost): a hand dialer that is `a` in everything but the code, against a real node `b`.

use crate::net::local_nodes;
use crate::connection_proofs::{CHALLENGE, Dialer, LISTENER, dial_with, prove, pump};
use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{LabelId, Role};
use osis_crypto::kdf::{beacon, beacon_hit, beacon_reply, connection_order, resume_tag};
use osis_node::sync::credentials::Credential;
use osis_node::sync::ConnId;
use osis_proto::filter::{beacon_value, encode_gcs, filter_width};
use osis_proto::msg::OfferItem;
use osis_proto::{ClientEvent, ClientInput, Code, Command, Message};

/// Two holders of one group with a record, only `b` dialable (`net_records::dialed`); `a`
/// offline, so the only connection using their record is the hand dialer's: built once
/// (`Net::cached`).
fn paired() -> (Net, usize, usize, LabelId, [u8; 32]) {
    let (net, (a, b, l, r)) = Net::cached("shared::paired", || {
        let (mut net, a, b) = crate::net_records::dialed();
        let ta = net.tid(a);
        let r = net.engine(b).run(|tx| Ok(tx.txn.records_of_actors(&[ta])?)).unwrap()[0].r;
        let l = net.label(a);
        net.set_online(a, false);
        net.run();
        (net, (a, b, l, r))
    });
    (net, a, b, l, r)
}

pub(crate) fn dial_as(net: &mut Net, a: usize, b: usize, challenge: [u8; 32]) -> Dialer {
    let mut p = dial_with(net, b, challenge);
    let own = net.engine(a).account_tid().is_some_and(|x| net.engine(b).account_tid() == Some(x));
    let provers = net.sync(a).provers(own).unwrap();
    prove(net, b, &mut p, provers);
    p
}

/// A hand dialer that proved `a` and resumed the record whose key is `r`, holding an empty S: its
/// digest and empty list close what `b`'s record held (issues/net-reconnect.md, Agreement), and
/// `b`'s first filter comes back.
fn resumed(net: &mut Net, a: usize, b: usize, r: &[u8; 32], challenge: [u8; 32]) -> (Dialer, Vec<ClientEvent>) {
    let mut p = dial_as(net, a, b, challenge);
    let tag = resume_tag(r, &LISTENER, &challenge, &p.hello);
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Resume { nonce: [5; 32], tags: vec![tag] }));
    let mut evs = pump(net, b, &mut p, outs);
    assert!(net.sync(b).connection_record(p.conn).is_some(), "the record is bound");
    let theirs = shared_of(&evs).into_iter().find_map(|m| if let Message::Digest { digest } = m { Some(digest) } else { None }).expect("b's digest first");
    let empty = osis_crypto::kdf::members_digest(r, []);
    evs.extend(send(net, b, &mut p, Message::Digest { digest: empty }));
    if theirs != empty {
        evs.extend(send(net, b, &mut p, Message::Members { labels: vec![], more: false }));
    }
    assert!(net.sync(b).shared_members(p.conn).is_empty(), "S agreed empty");
    (p, evs)
}

pub(crate) fn send(net: &mut Net, b: usize, p: &mut Dialer, m: Message) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Peer(Box::new(m))));
    pump(net, b, p, outs)
}

pub(crate) fn shared_of(evs: &[ClientEvent]) -> Vec<Message> {
    evs.iter().filter_map(|e| if let ClientEvent::Peer(m) = e { Some((**m).clone()) } else { None }).collect()
}

/// `a`'s read-secret match value for L (it holds L's read role).
pub(crate) fn read_value(net: &mut Net, a: usize, l: LabelId) -> [u8; 32] {
    let creds = net.sync(a).credentials(&[l]).unwrap();
    creds[&l].iter().find_map(|c| matches!(c, Credential::ReadSecret(_)).then(|| c.match_value())).expect("a holds L")
}

/// Hit of a dialer-side `a` (its beacon, its side, this connection).
pub(crate) fn dialer_hit(value: &[u8; 32], l: LabelId, r: &[u8; 32], p: &Dialer, challenge: [u8; 32]) -> [u8; 32] {
    beacon_hit(value, &l.0, &beacon(value, &l.0, r), (false, &LISTENER, &challenge, &p.hello))
}

fn answer(m: &Message) -> Vec<(Code, Option<[u8; 32]>)> {
    match m {
        Message::Shared { codes, .. } => codes.iter().map(|(c, t, _)| (*c, *t)).collect(),
        o => panic!("{o:?}"),
    }
}

pub(crate) fn offer(net: &mut Net, b: usize, p: &mut Dialer, items: Vec<OfferItem>) -> Vec<(Code, Option<[u8; 32]>)> {
    let msgs = shared_of(&send(net, b, p, Message::Offer { id: 77, items }));
    answer(msgs.iter().find(|m| m.id() == 77).expect("answered"))
}

// spec/wire.md §11.2 Offer: a Hit proving the shared credential opens L on the connection and is
// answered with the tag only the credential's holder computes (the tester's own check)
#[test]
fn a_valid_hit_opens_and_is_tagged_spec_wire_11_2() {
    let (mut net, a, b, l, r) = paired();
    let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
    let v = read_value(&mut net, a, l);
    let hit = dialer_hit(&v, l, &r, &p, CHALLENGE);
    let ans = offer(&mut net, b, &mut p, vec![OfferItem::Hit(hit, None)]);
    let expect = beacon_reply(&v, &l.0, &beacon(&v, &l.0, &r), (true, &LISTENER, &CHALLENGE, &p.hello));
    assert_eq!(ans, vec![(Code::OK, Some(expect))]);
    assert!(net.sync(b).shared_members(p.conn).contains(&l));
}

// the reflection a symmetric beacon invites (issues/net-shared-set.md, Adversaries): a peer sending
// back the digest of its own sender's side, or a digest for another connection or listener, shows
// nothing, for every way the binding differs
#[test]
fn a_reflected_or_carried_hit_opens_nothing_spec_wire_11_2() {
    let (mut net, a, b, l, r) = paired();
    let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
    let v = read_value(&mut net, a, l);
    let bcn = beacon(&v, &l.0, &r);
    let other = [0x33; 32];
    let hello = p.hello;
    for (what, side) in [
        ("the listener's own side", (true, &LISTENER, &CHALLENGE, &hello)),
        ("another listener key", (false, &other, &CHALLENGE, &hello)),
        ("another dialer challenge", (false, &LISTENER, &other, &hello)),
        ("another listener challenge", (false, &LISTENER, &CHALLENGE, &other)),
    ] {
        let hit = beacon_hit(&v, &l.0, &bcn, side);
        let ans = offer(&mut net, b, &mut p, vec![OfferItem::Hit(hit, None)]);
        assert_eq!(ans, vec![(Code::NOT_ADMITTED, None)], "{what}");
    }
    assert!(net.sync(b).shared_members(p.conn).is_empty(), "nothing opened");
}

// issues/net-shared-set.md, Reply: a tester opens L only on an answer carrying the tag: a peer
// answering 0 to its Hit, without one, serves it nothing and is served nothing
#[test]
fn a_hit_answered_without_a_tag_opens_nothing_spec_wire_11_2() {
    let (mut net, a, b, l, r) = paired();
    let (mut p, first) = resumed(&mut net, a, b, &r, CHALLENGE);
    let v = read_value(&mut net, a, l);
    let bcn = beacon(&v, &l.0, &r);
    let f = filter_width(1);
    let gcs = encode_gcs(&[beacon_value(&bcn, f)], 0);
    // b tests L, re-marked pending by the agreement, against the filter its record stored or this one
    let mut msgs = shared_of(&first);
    msgs.extend(shared_of(&send(&mut net, b, &mut p, Message::Beacons { id: 40, generation: 1, base: None, f, lo: 0, hi: 1 << f, gcs, more: false })));
    let Some(Message::Offer { id, items }) = msgs.iter().find(|m| matches!(m, Message::Offer { .. })) else { panic!("no Offer: {msgs:?}") };
    assert!(matches!(items[0], OfferItem::Hit(..)), "{items:?}");
    send(&mut net, b, &mut p, Message::Shared { id: *id, codes: vec![(Code::OK, None, None)] });
    assert!(net.sync(b).shared_members(p.conn).is_empty(), "no tag, no open");
}

// issues/net-shared-set.md, Adversaries: a filter breaking a page, ordering or width rule closes
// the connection before it costs anything but a pass
#[test]
fn bad_filters_close_the_connection_spec_wire_11_2() {
    let (mut net, a, b, _, r) = paired();
    for bad in [
        Message::Beacons { id: 1, generation: 1, base: None, f: 8, lo: 256, hi: 256, gcs: vec![], more: false },
        Message::Beacons { id: 2, generation: 1, base: None, f: 8, lo: 100, hi: 256, gcs: vec![], more: false },
        Message::Beacons { id: 3, generation: 1, base: None, f: 40, lo: 0, hi: 1 << 40, gcs: vec![], more: false },
        Message::Beacons { id: 4, generation: 1, base: None, f: 9, lo: 0, hi: 512, gcs: vec![0xff], more: false },
    ] {
        let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
        send(&mut net, b, &mut p, bad);
        assert!(net.sync(b).proven(p.conn).is_none(), "closed");
    }
}

// issues/net-shared-set.md, Lost: a Lost changes only a member of this connection's S: a peer naming
// something it does not share here changes nothing, and is idempotent
#[test]
fn a_lost_touches_only_members_spec_wire_11_2() {
    let (mut net, a, b, l, r) = paired();
    let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
    let v = read_value(&mut net, a, l);
    let hit = dialer_hit(&v, l, &r, &p, CHALLENGE);
    offer(&mut net, b, &mut p, vec![OfferItem::Hit(hit, None)]);
    let other = LabelId([0x77; 16]);
    send(&mut net, b, &mut p, Message::Lost { id: 8, items: vec![(other, None)] });
    assert!(net.sync(b).shared_members(p.conn).contains(&l), "not a member's Lost");
    send(&mut net, b, &mut p, Message::Lost { id: 9, items: vec![(l, None)] });
    assert!(net.sync(b).shared_members(p.conn).is_empty());
    send(&mut net, b, &mut p, Message::Lost { id: 10, items: vec![(l, None)] });
    assert!(net.sync(b).shared_members(p.conn).is_empty(), "idempotent");
}

// issues/net-reconnect.md Costs (a Lost costs other peers nothing): a Lost for what is not shared
// here re-tests nothing: a refused Hit stays refused
#[test]
fn a_lost_for_what_is_not_shared_costs_no_test() {
    let (mut net, a, b, l, r) = paired();
    let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
    let v = read_value(&mut net, a, l);
    let f = filter_width(1);
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::Beacons { id: 40, generation: 1, base: None, f, lo: 0, hi: 1 << f, gcs: encode_gcs(&[beacon_value(&beacon(&v, &l.0, &r), f)], 0), more: false }));
    let mut msgs = msgs;
    while let Some(Message::Offer { id, items }) = msgs.iter().find(|m| matches!(m, Message::Offer { .. })).cloned() {
        msgs = shared_of(&send(&mut net, b, &mut p, Message::Shared { id, codes: items.iter().map(|_| (Code::NOT_ADMITTED, None, None)).collect() }));
    }
    let hits = net.sync(b).pass_stats().hits_sent;
    send(&mut net, b, &mut p, Message::Lost { id: 8, items: vec![(LabelId([0x77; 16]), None)] });
    assert_eq!(net.sync(b).pass_stats().hits_sent, hits, "not offered again");
}

// issues/net-shared-set.md, Words: what a node reads goes in a filter only to a peer that proved
// a known actor: a dialer knowing nothing of the listener shows no credential and tests the
// listener's
#[test]
fn a_redeemer_knowing_nothing_shows_no_credential_spec_sync_10() {
    let (mut net, _, a, _, (k, _, _, seed)) = crate::net_judgment::linked();
    let key = reach_ed(&mut net, a);
    let c = net.node(2, &[]);
    let held = net.engine(c).hold_key_actor(seed).unwrap();
    // the sharer is dialed while a label is followed through the link: here one it does not
    // serve, so `c` comes to know nothing there
    net.sync(c).follow_link_peer(k, k, vec![osis_label::Address { url: osis_transport::peer_url(&[]), key }]);
    let acts = net.sync(c).follow(held, k, LabelId([0x99; 16]), vec![]);
    net.actions(c, acts);
    net.run();
    assert_eq!(net.sync(c).pass_stats().beacons_sent, 0, "knows no actor of the listener");
    assert!(net.sync(c).pass_stats().filters_received >= 1, "and tests the listener's");
    assert!(net.sync(a).pass_stats().filters_sent >= 1);
}

// spec/sync.md §10 (Shared set, Offer), spec/wire.md §11.2 (Offer: grant): a link's redeemer
// reads K by the head's box an accepted static-entry Hit's answer carries, with no Open; a
// joiner that read K so grants the next redeemer, who cannot reach the sharer, the same way
#[test]
fn a_link_redeemed_through_a_joiner_gets_the_box_from_the_hit_reply_spec_sync_10() {
    const OPEN: u64 = 4;
    let (mut net, _, a, _, (k, kl, _, seed)) = crate::net_judgment::linked();
    let at = |key| vec![osis_label::Address { url: osis_transport::peer_url(&[]), key }];
    let ka = reach_ed(&mut net, a);
    let j = net.node(2, &[]);
    let kj = reach_ed(&mut net, j);
    let held = net.engine(j).hold_key_actor(seed.clone()).unwrap();
    net.sync(j).follow_link_peer(k, k, at(ka));
    let acts = net.sync(j).follow(held, k, kl, vec![]);
    net.actions(j, acts);
    net.run();
    let reads = |net: &mut Net, n: usize| net.engine(n).epochs(&k).is_some_and(|e| e.read.holds_any());
    assert!(reads(&mut net, j), "the joiner reads K");
    let r = net.node(3, &[]);
    net.blocked_peers.insert((r, a));
    let held = net.engine(r).hold_key_actor(seed).unwrap();
    net.sync(r).follow_link_peer(k, k, at(kj));
    let acts = net.sync(r).follow(held, k, kl, vec![]);
    net.actions(r, acts);
    net.run();
    assert!(reads(&mut net, r), "the redeemer reads K through the joiner");
    assert_eq!(net.peer_sent(j, OPEN) + net.peer_sent(r, OPEN), 0, "no Open between readers");
}

// spec/sync.md §10 (Connection proofs): a connection proves what its node held when it came up;
// a redeemer already connected to a reader of K, a stranger there, holds the link key after its
// proofs went, so the peer's filter never shows K to it. It dials again and reads K there
#[test]
fn a_link_key_held_after_the_connection_is_proved_on_a_new_one_spec_sync_10() {
    let (mut net, _, a, _, (k, kl, _, seed)) = crate::net_judgment::linked();
    let at = vec![osis_label::Address { url: osis_transport::peer_url(&[]), key: reach_ed(&mut net, a) }];
    let c = net.add_node(2, osis_node::sync::SyncConfig { hosts: at.clone(), ..Default::default() });
    net.run();
    let to_a = |net: &Net| net.dialed.iter().filter(|(n, x)| *n == c && x.key == at[0].key).count();
    let before = to_a(&net);
    let held = net.engine(c).hold_key_actor(seed).unwrap();
    let acts = net.sync(c).follow(held, k, kl, at.clone());
    net.actions(c, acts);
    net.run();
    assert!(net.engine(c).epochs(&k).is_some_and(|e| e.read.holds_any()), "the redeemer reads K at the peer it was connected to");
    assert_eq!(to_a(&net), before + 1, "by one new connection to it");
}

// spec/permissions.md §7, spec/sync.md §5: only the link's sharer lacking the key's static entry
// ends a link. A peer holding nothing of K (here a stranger; the redeemer's own other node alike)
// shows no entry of K's label: that says nothing while the sharer is not reached
#[test]
fn a_peer_other_than_the_sharer_does_not_end_a_link_spec_permissions_7() {
    let (mut net, _, a, _, (k, kl, _, seed)) = crate::net_judgment::linked();
    let ka = reach_ed(&mut net, a);
    let d = net.node(3, &[]);
    let kd = reach_ed(&mut net, d);
    let at = |key| vec![osis_label::Address { url: osis_transport::peer_url(&[]), key }];
    let c = net.add_node(2, osis_node::sync::SyncConfig { hosts: at(kd), ..Default::default() });
    net.blocked_peers.insert((c, a));
    let held = net.engine(c).hold_key_actor(seed).unwrap();
    net.sync(c).follow_link_peer(k, k, at(ka));
    let acts = net.sync(c).follow(held, k, kl, vec![]);
    net.actions(c, acts);
    net.run();
    assert!(net.sync(c).pass_stats().filters_received >= 1, "d's filter came");
    assert!(!net.sync(c).static_entry_refused(&kl), "d's filter lacking K's entry ends nothing");
}

// spec/sync.md §10 (Node keys): a node is never its own peer, whatever address names it (its
// account's saved peer, a label's host): no dial to its own key
#[test]
fn a_node_never_dials_its_own_key_spec_sync_10() {
    let (mut net, [a]) = local_nodes::<1>();
    let me = osis_label::Address { url: osis_transport::peer_url(&[]), key: reach_ed(&mut net, a) };
    let t = net.tid(a);
    let acts = net.sync(a).follow(t, t, LabelId([0x42; 16]), vec![me.clone()]);
    net.actions(a, acts);
    net.run();
    assert!(!net.dialed.iter().any(|(n, x)| *n == a && x.key == me.key), "{:?}", net.dialed);
}

// issues/net-shared-set.md, Words and Peers that cannot read: a stranger's NoRecord starts the
// connection's set, whose filter holds none of what the node reads (here nothing else: it keeps
// nothing unread); before it, a shared-set request is refused
#[test]
fn a_strangers_filter_shows_nothing_the_node_reads_spec_sync_10() {
    let (mut net, _a, b, _, _) = paired();
    let stranger = net.node(9, &[]);
    let mut p = dial_as(&mut net, stranger, b, [4; 32]);
    let ids = osis_proto::msg::NODE_IDS;
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::Beacons { id: ids | 5, generation: 1, base: None, f: 8, lo: 0, hi: 256, gcs: vec![], more: false }));
    assert_eq!(msgs[0], Message::Error { id: ids | 5, code: Code::NOT_ADMITTED });
    assert!(net.sync(b).shared_members(p.conn).is_empty());
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::NoRecord { id: ids | 6 }));
    let filter: Vec<u64> = msgs.iter().filter_map(|m| if let Message::Beacons { gcs, lo, hi, .. } = m { Some(osis_proto::filter::decode_gcs(gcs, *lo, *hi).unwrap()) } else { None }).flatten().collect();
    assert!(msgs.iter().any(|m| matches!(m, Message::Beacons { .. })), "a filter");
    assert!(filter.is_empty(), "with no entry: b reads its group and keeps nothing unread");
}

fn the_conn(net: &mut Net, n: usize) -> ConnId {
    net.sync(n).proven_connections().into_iter().find(|(_, p)| !p.is_empty()).map(|(c, _)| c).expect("a connection")
}

// issues/net-shared-set.md, Testing and Opens: a holder gaining a right mid-connection finds it by
// additions and a Hit, and losing it closes the member on both sides and stops the data
#[test]
fn a_right_gained_and_lost_mid_connection_opens_and_closes_spec_sync_5() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, b);
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let g2 = net.group_seeded(a, &[(b, Role::Write)], vec![], 2);
    let t = net.item(a, g2, g2, "gained");
    net.run();
    assert_eq!(net.read(b, t), Some(s("gained")), "the new group opened on the running connection");
    let (ca, cb) = (the_conn(&mut net, a), the_conn(&mut net, b));
    let l2 = net.engine(a).labels_of(&g2)[0].id;
    assert!(net.sync(a).shared_members(ca).contains(&l2) && net.sync(b).shared_members(cb).contains(&l2));
    let (ta, tb) = (net.tid(a), net.tid(b));
    let rec = recipients_of(net.engine(a), &[(ta, Role::Admin)]);
    remove_holder(net.engine(a), g2, tb, &rec, 7);
    net.run();
    assert!(!net.sync(a).shared_members(ca).contains(&l2), "closed at the node that judged it");
    net.run();
    assert!(!net.sync(b).shared_members(cb).contains(&l2), "the Lost closed it at the other side too");
    net.write(a, t, "after");
    net.run();
    assert_ne!(net.read(b, t), Some(s("after")), "nothing more comes");
}

/// Dials node `a` proving only `seed`'s key actor, then NoRecord: a's filter for that actor.
fn proving_key_actor(net: &mut Net, a: usize, carrier: usize, seed: &osis_crypto::Secret32, challenge: [u8; 32]) -> Dialer {
    net.engine(carrier).hold_key_actor(seed.clone()).unwrap();
    let id = osis_engine::Identity::from_seed(seed.clone()).tid();
    let provers: Vec<osis_proto::Prover> = net.sync(carrier).provers(false).unwrap().into_iter().filter(|p| p.record.tid() == id).collect();
    let mut p = dial_with(net, a, challenge);
    prove(net, a, &mut p, provers);
    send(net, a, &mut p, Message::NoRecord { id: 1 << 31 });
    p
}

// issues/net-shared-set.md, Words (static entry) and first contact: a link key proved on this
// connection opens K by its static entry's Hit; the same Hit on a connection that proved another
// actor opens nothing
#[test]
fn a_static_entry_hit_opens_only_for_its_proved_key_actor_spec_wire_11_2() {
    let (mut net, host, a, account, (_k, label, _l1, seed1)) = crate::net_judgment::linked();
    let (_k2, _label2, _l2, seed2) = crate::net_judgment::link(&mut net, a, account);
    let carrier = net.node(2, &[host]);
    let entry = osis_crypto::static_entry(&label, &osis_engine::Identity::from_seed(seed1.clone()).keys().signing.verifying_key());
    let ch = [6; 32];
    let mut wrong = proving_key_actor(&mut net, a, carrier, &seed2, ch);
    let r = *osis_crypto::kdf::pair_key(&ch, &wrong.hello).expose();
    let hit = beacon_hit(&entry, &label.0, &beacon(&entry, &label.0, &r), (false, &LISTENER, &ch, &wrong.hello));
    assert_eq!(offer(&mut net, a, &mut wrong, vec![OfferItem::Hit(hit, None)]), vec![(Code::NOT_ADMITTED, None)], "another key actor proved");
    assert!(net.sync(a).shared_members(wrong.conn).is_empty());
    let ch = [8; 32];
    let mut right = proving_key_actor(&mut net, a, carrier, &seed1, ch);
    let r = *osis_crypto::kdf::pair_key(&ch, &right.hello).expose();
    let hit = beacon_hit(&entry, &label.0, &beacon(&entry, &label.0, &r), (false, &LISTENER, &ch, &right.hello));
    let ans = offer(&mut net, a, &mut right, vec![OfferItem::Hit(hit, None)]);
    assert_eq!(ans[0].0, Code::OK, "its own key actor proved");
    assert!(net.sync(a).shared_members(right.conn).contains(&label));
}

fn first_contact_cost(n: usize) -> (u64, u64, u64) {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, b);
    for i in 0..n {
        net.group_seeded(a, &[(b, Role::Write)], vec![], i as u64 + 1);
    }
    net.run();
    let st = net.sync(a).pass_stats();
    (st.filters_sent, st.beacons_sent, st.hits_sent)
}

// issues/net-shared-set.md, Costs: a first contact sharing n sync IDs sends one filter of about n beacons
// and offers at most n Hits: the count grows with n and no more
#[test]
fn a_first_contact_costs_one_filter_of_n_beacons() {
    let (f1, b1, h1) = first_contact_cost(4);
    let (f2, b2, h2) = first_contact_cost(40);
    assert!(f1 <= 3 && f2 <= f1 + 2, "filters do not grow with n: {f1} {f2}");
    // one beacon for the account itself; the rest are per sync ID
    assert!(b2 > 10 * (b1 - 1) && b2 <= 15 * b1, "beacons {b1} {b2}");
    assert!(h2 <= 15 * h1.max(1), "hits {h1} {h2}");
}

// the keeper of two connections of one record is decided by what the connections showed, not by
// which answer arrived first (spec/sync.md §10, Pair key)
#[test]
fn the_same_connection_survives_whatever_the_order_spec_sync_10() {
    for flip in [false, true] {
        let (mut net, a, b, _, r) = paired();
        let (c1, c2) = ([0x11u8; 32], [0x22u8; 32]);
        let (mut p1, mut p2) = (dial_as(&mut net, a, b, c1), dial_as(&mut net, a, b, c2));
        let cost = |c: [u8; 32], h: [u8; 32]| connection_order(&r, &c, &h);
        let (o1, o2) = (cost(c1, p1.hello), cost(c2, p2.hello));
        let (first, second, ch1, ch2) = if flip { (&mut p2, &mut p1, c2, c1) } else { (&mut p1, &mut p2, c1, c2) };
        for (p, ch, nonce) in [(first, ch1, [5; 32]), (second, ch2, [6; 32])] {
            let tag = resume_tag(&r, &LISTENER, &ch, &p.hello);
            let now = net.now();
            let outs = p.cs.handle(now, ClientInput::Command(Command::Resume { nonce, tags: vec![tag] }));
            pump(&mut net, b, p, outs);
        }
        let (win, lose) = if o1 < o2 { (&p1, &p2) } else { (&p2, &p1) };
        assert!(net.sync(b).connection_record(win.conn).is_some(), "the smaller keeps the record");
        assert!(net.sync(b).proven(lose.conn).is_none(), "the larger closed ({flip})");
    }
}

// issues/net-shared-set.md, Offer and Adversaries: a ByRole that lists a static entry's public
// value does not open L: only a Hit on a connection that proved the key actor does
#[test]
fn a_by_role_listing_a_static_entry_opens_nothing_spec_wire_11_2() {
    let (mut net, host, a, account, (_k, label, _l1, seed1)) = crate::net_judgment::linked();
    let (_k2, _label2, _l2, seed2) = crate::net_judgment::link(&mut net, a, account);
    let carrier = net.node(2, &[host]);
    let entry = osis_crypto::static_entry(&label, &osis_engine::Identity::from_seed(seed1).keys().signing.verifying_key());
    let ch = [6; 32];
    let mut wrong = proving_key_actor(&mut net, a, carrier, &seed2, ch);
    let r = *osis_crypto::kdf::pair_key(&ch, &wrong.hello).expose();
    let hit = beacon_hit(&entry, &label.0, &beacon(&entry, &label.0, &r), (false, &LISTENER, &ch, &wrong.hello));
    assert_eq!(offer(&mut net, a, &mut wrong, vec![OfferItem::ByRole(label, vec![hit])]), vec![(Code::NOT_ADMITTED, None)]);
    assert!(net.sync(a).shared_members(wrong.conn).is_empty());
}

// issues/net-shared-set.md, Offer: a ByRole the peer accepts opens L at its sender too (a holder a
// rotation apart): the listener serves it and the dialer pulls it
#[test]
fn an_accepted_by_role_opens_at_its_sender_spec_wire_11_2() {
    let (mut net, a, b, l, r) = paired();
    let (mut p, first) = resumed(&mut net, a, b, &r, CHALLENGE);
    // an empty filter: b finds nothing by testing and offers by role
    let mut msgs = shared_of(&first);
    msgs.extend(shared_of(&send(&mut net, b, &mut p, Message::Beacons { id: 40, generation: 1, base: None, f: filter_width(0), lo: 0, hi: 1 << filter_width(0), gcs: vec![], more: false })));
    // a Hit on the filter b's record stored is refused: b finds nothing by testing
    while let Some(Message::Offer { id, items }) = msgs.iter().find(|m| matches!(m, Message::Offer { items, .. } if matches!(items[0], OfferItem::Hit(..)))).cloned() {
        msgs.retain(|m| m.id() != id);
        msgs.extend(shared_of(&send(&mut net, b, &mut p, Message::Shared { id, codes: vec![(Code::NOT_ADMITTED, None, None); items.len()] })));
    }
    let Some(Message::Offer { id, items }) = msgs.iter().find(|m| matches!(m, Message::Offer { .. })) else { panic!("no Offer: {msgs:?}") };
    assert!(matches!(&items[0], OfferItem::ByRole(x, _) if *x == l), "{items:?}");
    send(&mut net, b, &mut p, Message::Shared { id: *id, codes: vec![(Code::OK, None, None)] });
    assert!(net.sync(b).shared_members(p.conn).contains(&l), "the sender serves what its peer accepted");
}

// issues/net-shared-set.md, The rule: a peer whose only tie here ended still shares what it showed
// an admissible credential of; only the filter stops
#[test]
fn a_credential_open_outlasts_the_peers_being_known_spec_sync_10() {
    let (mut net, [a, b]) = local_nodes::<2>();
    reach_ed(&mut net, b);
    let g1 = net.group_at(b, &[(a, Role::Read)], vec![]);
    let g2 = net.group_seeded(b, &[], vec![], 2);
    let l2 = net.engine(b).labels_of(&g2)[0].id;
    net.run();
    let ta = net.tid(a);
    let r = net.engine(b).run(|tx| Ok(tx.txn.records_of_actors(&[ta])?)).unwrap()[0].r;
    net.set_online(a, false);
    net.run();
    let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
    let v = read_value(&mut net, b, l2);
    let hit = dialer_hit(&v, l2, &r, &p, CHALLENGE);
    assert_eq!(offer(&mut net, b, &mut p, vec![OfferItem::Hit(hit, None)])[0].0, Code::OK);
    let tb = net.tid(b);
    let rec = recipients_of(net.engine(b), &[(tb, Role::Admin)]);
    remove_holder(net.engine(b), g1, ta, &rec, 7);
    net.run();
    assert!(net.sync(b).shared_members(p.conn).contains(&l2), "the credential is still admissible");
}

// spec/wire.md §11.2 Beacons, notes/arbitrary-values-table.md: a filter past MAX_FILTER_ENTRIES closes
// the connection
#[test]
fn a_filter_past_the_entry_cap_closes_the_connection_spec_wire_11_2() {
    let (mut net, a, b, _, r) = paired();
    let (mut p, _) = resumed(&mut net, a, b, &r, CHALLENGE);
    // every gap 0: 9 bits an entry
    let n = (1usize << 22) + 1;
    let gcs = vec![0u8; (n * 9).div_ceil(8)];
    send(&mut net, b, &mut p, Message::Beacons { id: 1, generation: 1, base: None, f: 8, lo: 0, hi: 256, gcs, more: false });
    assert!(net.sync(b).proven(p.conn).is_none(), "closed");
}

// spec/sync.md §10: a node proving an account at an epoch open here is judged as that account: the
// shared set finds its way in by the account's role
#[test]
fn an_account_proved_at_an_open_epoch_gets_a_shared_set_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, _) = crate::net_judgment::account_node(&mut net, 1, host);
    let (s, account) = crate::net_judgment::account_node(&mut net, 3, host);
    let g = net.group_at(a, &[], vec![]);
    // bare: the account's keys are not held here; the roster entry alone is judged
    set_edge(net.engine(a), g, account, Role::Read);
    assert_eq!(net.engine(a).core.judge([account]).of(&g), osis_node::sync::credentials::Judgment::Holder, "the account holds g here");
    let mut p = dial_as(&mut net, s, a, [7; 32]);
    let msgs = shared_of(&send(&mut net, a, &mut p, Message::NoRecord { id: 1 << 31 }));
    assert!(msgs.iter().any(|m| matches!(m, Message::Beacons { .. })), "a filter goes out: {msgs:?}");
}

// spec/sync.md §10 Shared set, Re-marking: a Lost sent re-marks L, so a sync-key Hit the host
// accepted after this node stopped syncing L (handed off) opens L again once it syncs L again,
// at whatever point of its opening the hand-off fell (every interleaving, one message at a time)
#[test]
fn a_hit_declined_after_its_answer_opens_again_spec_sync_10() {
    let (mut net, host, [a]) = hosted_nodes::<1>();
    let g = net.group(a, &[], &[host]);
    net.run();
    let synced = |net: &mut Net| net.sync(a).label_status().iter().any(|s| s.group == g && s.sources == 1 && s.idle == 1);
    assert!(synced(&mut net));
    let hand = |net: &mut Net, on: bool| {
        let acts = net.sync(a).set_handed_off(g, on);
        net.actions(a, acts);
    };
    hand(&mut net, true);
    net.run();
    for k in 0.. {
        let mut x = net.copy();
        hand(&mut x, false);
        let mut stepped = 0;
        while stepped < k && x.step() {
            stepped += 1;
        }
        if stepped < k {
            break;
        }
        hand(&mut x, true);
        x.run();
        hand(&mut x, false);
        x.run();
        assert!(synced(&mut x), "taken back after {k} messages: {:?}", x.sync(a).label_status());
    }
}

// issues/net-shared-set.md, Reply and Divergence: a peer answering a static entry's Hit with a
// grant that does not verify is told Lost, and the Hit is not sent again on that connection
// until something else re-marks it: a forged grant buys no loop
#[test]
fn a_forged_grant_is_not_offered_again_spec_sync_10() {
    let (mut net, _, a, _, (k, kl, _, seed)) = crate::net_judgment::linked();
    let t = net.node(3, &[]);
    let held = net.engine(t).hold_key_actor(seed.clone()).unwrap();
    let acts = net.sync(t).follow(held, k, kl, vec![]);
    net.actions(t, acts);
    net.run();
    let ch = [9; 32];
    let mut p = dial_as(&mut net, a, t, ch);
    let mut msgs = shared_of(&send(&mut net, t, &mut p, Message::NoRecord { id: 1 << 31 }));
    let pair = *osis_crypto::kdf::pair_key(&ch, &p.hello).expose();
    let entry = osis_crypto::static_entry(&kl, &osis_engine::Identity::from_seed(seed).keys().signing.verifying_key());
    let bcn = beacon(&entry, &kl.0, &pair);
    let f = filter_width(1);
    msgs.extend(shared_of(&send(&mut net, t, &mut p, Message::Beacons { id: 40, generation: 1, base: None, f, lo: 0, hi: 1 << f, gcs: encode_gcs(&[beacon_value(&bcn, f)], 0), more: false })));
    let tag = beacon_reply(&entry, &kl.0, &bcn, (false, &LISTENER, &ch, &p.hello));
    let forged = osis_proto::msg::Grant {
        entry_box: Some(osis_proto::msg::SecretBox::Symmetric(osis_schema::core_types::SymmetricBox { epoch: osis_schema::core_types::Epoch { n: 1, nonce: [8; 32] }, wrap: vec![1; 48], possession: None })),
        steps: vec![crate::hostile_host::foreign_step(3)],
    };
    let mut hits = 0;
    let mut losts = 0;
    for _ in 0..8 {
        let Some(Message::Offer { id, items }) = msgs.iter().find(|m| matches!(m, Message::Offer { .. })).cloned() else { break };
        msgs.retain(|m| m.id() != id);
        hits += items.iter().filter(|i| matches!(i, OfferItem::Hit(..) | OfferItem::Static { .. })).count();
        let codes = items.iter().map(|_| (Code::OK, Some(tag), Some(Box::new(forged.clone())))).collect();
        let back = shared_of(&send(&mut net, t, &mut p, Message::Shared { id, codes }));
        losts += back.iter().filter(|m| matches!(m, Message::Lost { .. })).count();
        msgs.extend(back);
    }
    assert_eq!((hits, losts), (1, 1), "{msgs:?}");
    assert!(net.sync(t).shared_members(p.conn).is_empty());
}

/// Node `t` follows the link of `linked()` by its key actor; a scripted peer proving `a` shows the
/// key actor's static entry in its filter and answers `t`'s Hit with `grant` (made from `a`, the
/// label, its thing and the key actor's seed), tagged. The
/// diagnostics `t` logged, and the read secrets of the link's thing it held before and after.
fn answer_static_hit(grant: impl FnOnce(&mut Net, usize, LabelId, osis_base::Tid, &osis_crypto::Secret32) -> osis_proto::msg::Grant) -> (Vec<String>, usize, usize) {
    let (mut net, _, a, _, (k, kl, _, seed)) = crate::net_judgment::linked();
    let t = net.node(3, &[]);
    let ka = net.engine(t).hold_key_actor(seed.clone()).unwrap();
    let held = |net: &mut Net| net.engine(t).epochs(&k).map_or(0, |e| e.read.held_newest_first().len());
    let before = held(&mut net);
    let acts = net.sync(t).follow(ka, k, kl, vec![]);
    net.actions(t, acts);
    net.run();
    let ch = [9; 32];
    let mut p = dial_as(&mut net, a, t, ch);
    let mut msgs = shared_of(&send(&mut net, t, &mut p, Message::NoRecord { id: 1 << 31 }));
    let pair = *osis_crypto::kdf::pair_key(&ch, &p.hello).expose();
    let entry = osis_crypto::static_entry(&kl, &osis_engine::Identity::from_seed(seed.clone()).keys().signing.verifying_key());
    let bcn = beacon(&entry, &kl.0, &pair);
    let f = filter_width(1);
    msgs.extend(shared_of(&send(&mut net, t, &mut p, Message::Beacons { id: 40, generation: 1, base: None, f, lo: 0, hi: 1 << f, gcs: encode_gcs(&[beacon_value(&bcn, f)], 0), more: false })));
    let tag = beacon_reply(&entry, &kl.0, &bcn, (false, &LISTENER, &ch, &p.hello));
    let grant = grant(&mut net, a, kl, k, &seed);
    let Some(Message::Offer { id, items }) = msgs.iter().find(|m| matches!(m, Message::Offer { .. })).cloned() else { panic!("t Hits its static entry: {msgs:?}") };
    net.sync(t).take_diagnostics();
    let codes = items.iter().map(|_| (Code::OK, Some(tag), Some(Box::new(grant.clone())))).collect();
    send(&mut net, t, &mut p, Message::Shared { id, codes });
    let diags = net.sync(t).take_diagnostics();
    let after = held(&mut net);
    (diags, before, after)
}

// spec/sync.md §10 Shared set (a static entry's grant: the path verified from its genesis step),
// spec/crypto.md §4 (sealed boxes are unauthenticated): a peer's forged head and entry box, its
// path not the label's, teach the key actor no secret.
#[test]
fn a_forged_head_and_box_teach_nothing_spec_sync_10() {
    let (diags, before, after) = answer_static_hit(|_, _, _, _, _| osis_proto::msg::Grant {
        entry_box: Some(osis_proto::msg::SecretBox::Symmetric(osis_schema::core_types::SymmetricBox { epoch: osis_schema::core_types::Epoch { n: 1, nonce: [8; 32] }, wrap: vec![1; 48], possession: None })),
        steps: vec![crate::hostile_host::foreign_step(3)],
    });
    assert!(diags.iter().any(|x| x.contains("granted path does not verify")), "{diags:?}");
    assert_eq!(after, before, "a forged head's box teaches nothing");
}

// spec/sync.md §2 (a step's entry box carries the read secret of its epoch and the sync secret
// whose key the step registers), spec/crypto.md §4 (sealed boxes are unauthenticated): the
// label's genuine path with a substituted entry box (sealed by the peer to the key actor's public
// KEM key) teaches no secret: its sync secret does not derive the head's sync key.
#[test]
fn a_substituted_box_teaches_nothing_spec_sync_2() {
    let (diags, before, after) = answer_static_hit(|net, a, kl, group, seed| {
        // the link's label as its holder `a` records it, genesis first
        let gl = net.group_labels(a).into_iter().find(|(_, x)| x.id == kl).expect("a records the link's label").1;
        let mut steps: Vec<osis_label::Step> = Vec::new();
        while let Some(next) = gl.steps.values().map(|x| &x.0).find(|s| s.prev == steps.last().map(|p| p.id())) {
            steps.push(next.clone());
        }
        let head = steps.last().expect("the label's head").clone();
        let keys = osis_crypto::KeyActorKeys::from_seed(seed);
        let slot = osis_crypto::BoxSlot::Entry { label: kl, step_key: head.step_key, group };
        let other = osis_crypto::Secret32::from_bytes([0x99; 32]);
        let item = osis_crypto::EntryItem { epoch: osis_crypto::Epoch::derive(&group, Role::Read, 1, &other).unwrap(), secret: other.clone(), earlier: None, sync: (osis_crypto::Epoch::derive(&group, Role::Sync, 1, &other).unwrap(), other) };
        let sealed = osis_crypto::seal_entry(keys.kem.public(), &slot, &item, &mut osis_crypto::SeededRng::from_u64(1)).unwrap();
        use osis_schema::core_types as ct;
        let entry_box = ct::SecretBox::Sealed(ct::SealedBox { keyset: None, suite: u64::from(osis_crypto::SUITE_1), sealed: ct::Sealed::X25519MlKem768(sealed) });
        osis_proto::msg::Grant { entry_box: Some(entry_box), steps }
    });
    assert!(diags.iter().any(|x| x.contains("does not derive the head's sync key")), "{diags:?}");
    assert_eq!(after, before, "a substituted box teaches nothing");
}
