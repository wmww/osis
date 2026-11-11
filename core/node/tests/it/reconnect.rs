#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Reconnects (issues/net-reconnect.md; spec/sync.md §10, Agreement): a record's shared set is
//! restored, the two records are compared by one digest each way, and a reconnect sends what
//! changed: counted, at n and 10n sync IDs.

use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{LabelId, Role, Tid};
use osis_proto::Message;
use std::cell::RefCell;
use std::rc::Rc;

/// Nodes `a` and `b` holding `n` groups together, `b` dialable: `a` dials `b`.
fn pair(net: &mut Net, n: usize) -> (usize, usize, Vec<Tid>) {
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(net, b);
    let gs = (0..n).map(|i| net.group_seeded(b, &[(a, Role::Write)], vec![], 10 + i as u64)).collect();
    net.run();
    (a, b, gs)
}

/// Every message the nodes send on peer links from now on: its kind, encoded size and the message.
fn record_messages(net: &mut Net) -> Rc<RefCell<Vec<(u64, usize, Message)>>> {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let s = seen.clone();
    net.tamper = Some(Box::new(move |m| {
        s.borrow_mut().push((m.kind(), m.encode().len(), m.clone()));
        None
    }));
    seen
}

/// `a` goes off and comes back: the connection ends and `a` dials again.
fn reconnect(net: &mut Net, a: usize) {
    net.set_online(a, false);
    net.run();
    net.set_online(a, true);
    net.advance(120_000);
}

fn label_of(net: &mut Net, n: usize, g: Tid) -> LabelId {
    net.engine(n).labels_of(&g)[0].id
}

fn count(seen: &[(u64, usize, Message)], kind: u64) -> usize {
    seen.iter().filter(|(k, ..)| *k == kind).count()
}

const BEACONS: u64 = 36;
const OFFER: u64 = 37;
const LOST: u64 = 38;
const PULL: u64 = 41;
const DIGEST: u64 = 45;
const MEMBERS: u64 = 46;

/// What an idle reconnect of a pair sharing `n` groups sends: per kind, the count, and the bytes of
/// every message but the stream's events.
fn idle_reconnect(n: usize) -> (std::collections::BTreeMap<u64, usize>, usize, Vec<[u8; 32]>) {
    let mut net = Net::new();
    let (a, _b, _gs) = pair(&mut net, n);
    let seen = record_messages(&mut net);
    reconnect(&mut net, a);
    let seen = seen.borrow();
    let mut kinds = std::collections::BTreeMap::new();
    for (k, ..) in seen.iter() {
        *kinds.entry(*k).or_insert(0) += 1;
    }
    let bytes = seen.iter().map(|(_, n, _)| n).sum();
    let digests = seen.iter().filter_map(|(_, _, m)| if let Message::Digest { digest } = m { Some(*digest) } else { None }).collect();
    let joins: usize = seen.iter().map(|(_, _, m)| if let Message::Pull(p) = m { p.joins.len() } else { 0 }).sum();
    assert_eq!(joins, 0, "no member joins again: S is the record's");
    (kinds, bytes, digests)
}

// issues/net-reconnect.md (What a reconnect sends): an idle reconnect, nothing changed on either
// side, sends no message per sync ID: no Offer, Lost or Members, no join, and the same messages
// and about the same bytes at n and 10n. spec/sync.md §10 (Agreement): the digests of two equal
// records match at any size: one 32-byte Digest each way, no list
#[test]
fn an_idle_reconnect_sends_no_per_sync_id_message_spec_sync_10() {
    let (k1, b1, d1) = idle_reconnect(3);
    let (k10, b10, d10) = idle_reconnect(30);
    for (n, kinds, digests) in [(3, &k1, d1), (30, &k10, d10)] {
        assert_eq!(kinds.get(&DIGEST), Some(&2), "one each way at {n}");
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0], digests[1], "equal records, equal digests at {n}");
        assert_ne!(digests[0], [0; 32], "a digest of a non-empty S");
    }
    for k in [OFFER, LOST, MEMBERS] {
        assert_eq!((k1.get(&k), k10.get(&k)), (None, None), "kind {k}: {k1:?} {k10:?}");
    }
    assert_eq!(k1, k10, "the same messages at n and 10n");
    assert!(b10 <= b1 + 64, "bytes {b1} at n, {b10} at 10n");
    assert!(b10 < 4096, "an idle reconnect is small: {b10} bytes");
}

/// The record node `n` keeps for `peer`'s account.
fn record_of(net: &mut Net, n: usize, peer: usize) -> osis_store::Record {
    let t = net.tid(peer);
    net.engine(n).run(|tx| Ok(tx.txn.records_of_actors(&[t])?)).unwrap().remove(0)
}

// issues/net-reconnect.md (Agreement): a record restored so that S differs (here: `a`'s record
// lost a member while apart, as a store restored from a backup taken before it opened) shows as a
// digest difference; the member only one side holds is closed on both and reopened by the shared
// set's own rule, rejoining from the start, and what was written meanwhile arrives. A stopped
// member's lag beside S is not in the digest
#[test]
fn a_record_restored_so_s_differs_is_repaired_by_the_shared_set_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 2);
    let l0 = label_of(&mut net, a, gs[0]);
    net.set_online(a, false);
    net.run();
    let t = net.item(b, gs[0], gs[0], "apart");
    net.run();
    let (ra, rb) = (record_of(&mut net, a, b), record_of(&mut net, b, a));
    // a stopped lag of a sync ID beside S, at one side only: no difference
    net.engine(b).run(|tx| Ok(tx.txn.record_close(&rb.id, &LabelId([0x77; 16]), 0, Some(vec![1; 8]))?)).unwrap();
    let seen = record_messages(&mut net);
    net.set_online(a, true);
    net.advance(120_000);
    assert_eq!(count(&seen.borrow(), MEMBERS), 0, "a lag beside S changes no digest");
    assert_eq!(net.read(a, t), Some(s("apart")));
    // the record loses L0 while apart
    net.set_online(a, false);
    net.run();
    let changed = net.engine(a).run(|tx| Ok(tx.txn.changed_at(&l0)?)).unwrap().unwrap();
    net.engine(a).run(|tx| Ok(tx.txn.record_drop(&ra.id, &l0, changed)?)).unwrap();
    let t2 = net.item(b, gs[0], gs[0], "apart again");
    net.run();
    seen.borrow_mut().clear();
    net.set_online(a, true);
    net.advance(120_000);
    let seen = seen.borrow();
    assert_eq!(count(&seen, MEMBERS), 2, "one list each way");
    assert_eq!(net.read(a, t2), Some(s("apart again")), "L0 reopened and what was written apart arrived");
    let joined_from_start = seen.iter().any(|(_, _, m)| matches!(m, Message::Pull(p) if p.joins.iter().any(|(l, c)| *l == l0 && c.is_none())));
    assert!(joined_from_start, "the rejoin of a member the records disagreed on is a listing");
    for (x, y) in [(a, b), (b, a)] {
        let conn = net.peer_conns(x).into_iter().find(|(_, m, _)| *m == y).map(|(c, ..)| c).unwrap();
        assert!(net.sync(x).shared_members(conn).contains(&l0), "{x}: L0 open again");
    }
    let rb = record_of(&mut net, b, a);
    let members = net.engine(b).run(|tx| Ok(tx.txn.record_members(&rb.id)?)).unwrap();
    assert!(members.iter().any(|(l, _)| *l == l0), "and kept in b's record");
}

// issues/net-shared-set.md (Re-marking): a Lost re-marks the member for its own record only: the
// node receiving it sends nothing and tests nothing on its connection to another peer
#[test]
fn a_lost_costs_other_peers_nothing_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let c = net.node(3, &[]);
    reach_ed(&mut net, b);
    let g = net.group_seeded(b, &[(a, Role::Write), (c, Role::Write)], vec![], 10);
    net.run();
    net.advance(120_000);
    let l = label_of(&mut net, b, g);
    let to = |net: &Net, x: usize, y: usize| net.peer_conns(x).into_iter().find(|(_, m, _)| *m == y).map(|(cn, ..)| cn).unwrap();
    let (ba, bc, ab) = (to(&net, b, a), to(&net, b, c), to(&net, a, b));
    assert!(net.sync(b).shared_members(ba).contains(&l) && net.sync(b).shared_members(bc).contains(&l));
    let (work_c, work_a) = (net.sync(b).shared_work(bc), net.sync(b).shared_work(ba));
    let beacons = net.peer_sent(b, BEACONS);
    net.inject(a, ab, &Message::Lost { id: 1 << 31 | 99, items: vec![(l, None)] });
    net.run();
    assert_eq!(net.sync(b).shared_work(bc), work_c, "no test and no generation on the other peer's connection");
    assert_eq!(net.peer_sent(b, BEACONS), beacons, "no additions to anyone");
    assert!(net.sync(b).shared_work(ba).0 > work_a.0, "the record it closed for is tested again");
    assert!(net.sync(b).shared_members(ba).contains(&l), "and reopens L");
    let t = net.item(a, g, g, "after");
    net.run();
    assert_eq!(net.read(b, t), Some(s("after")));
}

// issues/net-reconnect.md (Restart and loss): a restarted node resumes: its S, filters and
// cursor are the record's, so nothing is offered or joined again
#[test]
fn a_restarted_node_resumes_its_shared_set_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 3);
    let seen = record_messages(&mut net);
    net.restart(a, 21);
    net.run();
    net.advance(120_000);
    let t = net.item(b, gs[1], gs[1], "after");
    net.run();
    assert_eq!(net.read(a, t), Some(s("after")));
    let seen = seen.borrow();
    for k in [OFFER, LOST, MEMBERS] {
        assert_eq!(count(&seen, k), 0, "kind {k}");
    }
    let joins: usize = seen.iter().map(|(_, _, m)| if let Message::Pull(p) = m { p.joins.len() } else { 0 }).sum();
    assert_eq!(joins, 0, "nothing joins again");
    assert!(count(&seen, PULL) >= 1);
}

// issues/net-reconnect.md (Agreement): a `Lost` lost with its connection is never resent: the
// next connection's digest finds the member only one side holds and closes it there, so the node
// that missed the `Lost` no longer counts the peer a source of what the peer stopped sharing
#[test]
fn a_lost_lost_with_its_connection_is_found_by_the_digest_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 2);
    let l0 = label_of(&mut net, a, gs[0]);
    net.tamper = Some(Box::new(|m| matches!(m, Message::Lost { .. }).then(|| Message::Applied { cursor: vec![0; 72] })));
    let (ta, tb) = (net.tid(a), net.tid(b));
    let rec = recipients_of(net.engine(b), &[(tb, Role::Admin)]);
    remove_holder(net.engine(b), gs[0], ta, &rec, 7);
    net.run();
    let sources = |net: &mut Net| net.sync(a).label_status().into_iter().find(|s| s.label == l0).map(|s| s.sources);
    assert_eq!(sources(&mut net), Some(1), "the Lost was lost: a still counts b a source");
    net.tamper = None;
    reconnect(&mut net, a);
    assert_eq!(sources(&mut net), Some(0), "the digest closed it at a");
    let t = net.item(b, gs[1], gs[1], "still shared");
    net.run();
    assert_eq!(net.read(a, t), Some(s("still shared")), "the other member goes on");
}

// spec/sync.md §10 (filter): a generation lost with its connection is not one the peer holds, so
// the next connection's first generation does not build on it. Here `a`'s whole filter at a new
// width (its credentials grew past doubling) never reaches `b`: additions at that width on `b`'s
// older generation would break `b`'s width rule and close every connection that follows
#[test]
fn a_generation_lost_with_its_connection_is_not_built_on_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, _) = pair(&mut net, 1);
    net.advance(120_000);
    net.tamper_link = Some((a, b));
    net.tamper = Some(Box::new(|m| matches!(m, Message::Beacons { .. }).then(|| Message::Applied { cursor: vec![0; 72] })));
    let more: Vec<Tid> = (0..20).map(|i| net.group_seeded(b, &[(a, Role::Write)], vec![], 40 + i)).collect();
    net.run();
    net.set_online(a, false);
    net.run();
    net.tamper = None;
    net.tamper_link = None;
    let closes = net.peer_closes;
    net.set_online(a, true);
    net.advance(120_000);
    let t = net.item(b, more[3], more[3], "after");
    net.run();
    assert_eq!(net.read(a, t), Some(s("after")));
    assert_eq!(net.peer_closes, closes, "no connection closed");
}

// spec/sync.md §10 (Lost): a Lost names a position the receiver reported storing, which it keeps.
// A push it did not take (`MAX_WAITING`) is received and not applied: the sender's last cursor is
// then past a write this node lacks, so the Lost names an older one, and the rejoin from it brings
// that write
#[test]
fn a_lost_after_a_dropped_push_names_a_reported_position_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, gs) = pair(&mut net, 1);
    net.item(b, gs[0], gs[0], "x");
    net.run();
    let l = label_of(&mut net, b, gs[0]);
    let (c, pc) = net.peer_conns(a).into_iter().find(|(_, m, _)| *m == b).map(|(c, _, pc)| (c, pc)).unwrap();
    // b's fetch answers and pull replies to a are lost: a stays full; the last cursor b pushed
    let pushed = Rc::new(RefCell::new(None));
    let p2 = pushed.clone();
    net.tamper_link = Some((b, a));
    net.tamper = Some(Box::new(move |m| match m {
        Message::FetchReply { .. } | Message::PullReply(_) => Some(Message::Applied { cursor: vec![] }),
        Message::Stream(st) if st.cursor.is_some() => {
            *p2.borrow_mut() = st.cursor.clone();
            None
        }
        _ => None,
    }));
    let cursor = net.sync(a).stream_cursor(c);
    for i in 0..20 {
        let events = (0..100).map(|j| (l, osis_proto::Event::Added { blob_id: osis_label::blob_id(format!("unserved {i} {j}").as_bytes()), blob: None, wrap: [0; osis_crypto::WRAP_LEN], stamp: None })).collect();
        net.inject(b, pc, &Message::Stream(Box::new(osis_proto::msg::Stream { events, cursor: cursor.clone(), report: false })));
    }
    net.run();
    assert!(net.sync(a).stream_waiting(c).1 >= 1024, "a waits on bodies");
    let t = net.item(b, gs[0], gs[0], "pushed while full");
    net.run();
    let at = pushed.borrow().clone();
    assert!(at.is_some() && at != cursor, "b pushed t");
    // b says it holds none of what a waits on: a settles, the dropped push still unread
    for i in 0..20 {
        let events = (0..100).map(|j| (l, osis_proto::Event::Deleted(osis_label::blob_id(format!("unserved {i} {j}").as_bytes())))).collect();
        net.inject(b, pc, &Message::Stream(Box::new(osis_proto::msg::Stream { events, cursor: None, report: false })));
    }
    net.run();
    assert_eq!(net.sync(a).stream_waiting(c), (0, 0), "settled");
    // b's Lost names what a reported storing: not the dropped push's cursor
    let lost = net.sync(b).shared_lost_cursor(pc, &l).unwrap();
    assert!(lost.is_some() && lost != at, "a reported position, not the last one served");
    net.inject(b, pc, &Message::Lost { id: 1 << 31 | 99, items: vec![(l, lost)] });
    net.run();
    net.tamper = None;
    net.tamper_link = None;
    net.restart(a, 21);
    net.run();
    net.advance(120_000);
    assert_eq!(net.read(a, t), Some(s("pushed while full")));
}

// spec/sync.md §10 (Agreement): no Offer before the peer's Digest is read and no Pull before the
// records agree. Here `a`'s Digest never reaches `b`: `b`, with a group new to `a` to offer and a
// filter of `a`'s to test it against, offers and pulls nothing on that connection
#[test]
fn nothing_is_offered_or_pulled_before_the_peers_digest_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, _) = pair(&mut net, 1);
    net.set_online(a, false);
    net.run();
    net.group_seeded(b, &[(a, Role::Write)], vec![], 40);
    net.run();
    net.tamper_link = Some((a, b));
    net.tamper = Some(Box::new(|m| matches!(m, Message::Digest { .. }).then(|| Message::Applied { cursor: vec![0; 72] })));
    let (offers, pulls, filters) = (net.peer_sent(b, OFFER), net.peer_sent(b, PULL), net.peer_sent(a, BEACONS));
    net.set_online(a, true);
    net.advance(120_000);
    assert!(net.peer_sent(a, BEACONS) > filters, "a's filter reached b");
    assert_eq!(net.peer_sent(b, OFFER), offers, "no Offer");
    assert_eq!(net.peer_sent(b, PULL), pulls, "no Pull");
}

// issues/net-reconnect.md (Adversaries): a peer's `Members` list keeps only what can matter here
// (a member of S, or a sync ID this node holds), so a peer listing sync IDs this node never held
// page after page makes it keep nothing
#[test]
fn a_members_list_keeps_only_what_this_node_holds_spec_sync_10() {
    let mut net = Net::new();
    let (a, b, _) = pair(&mut net, 1);
    net.set_online(a, false);
    net.run();
    // b reads a digest that differs and waits for a's list
    net.tamper_link = Some((a, b));
    net.tamper = Some(Box::new(|m| matches!(m, Message::Digest { .. }).then(|| Message::Digest { digest: [9; 32] })));
    net.set_online(a, true);
    net.advance(120_000);
    net.tamper = None;
    net.tamper_link = None;
    let (ca, cb) = net.peer_conns(a).into_iter().find(|(_, m, _)| *m == b).map(|(c, _, pc)| (c, pc)).unwrap();
    for i in 0..10u8 {
        let labels = (0..100u8).map(|j| LabelId([i, j, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee])).collect();
        net.inject(a, ca, &Message::Members { labels, more: true });
    }
    net.run();
    assert_eq!(net.sync(b).shared_listed(cb), 0, "nothing kept of sync IDs b never held");
}
