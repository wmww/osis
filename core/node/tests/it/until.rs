#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! A rotation ends an open (issues/net-reconnect.md, Joining and rejoining; spec/sync.md §10
//! Shared set, Lost): a member opened by a credential the rotation made stale, its peer not judged
//! a holder, is served through the rotation (`until`) and closes with a `Lost` once the requester
//! reported a position past it, by the per-message reports or a Pull's cursor. A hand dialer is
//! the requester: it proves `a`, which holds no role on the group, and shows its read secret.

use crate::connection_proofs::{CHALLENGE, Dialer, LISTENER, pump};
use crate::net;
use crate::peers::reach_ed;
use crate::shared::{dial_as, dialer_hit, offer, read_value, send, shared_of};
use net::*;
use osis_base::{BlobId, LabelId, Role, Tid};
use osis_crypto::kdf::{beacon, members_digest, resume_tag};
use osis_proto::filter::{beacon_value, decode_gcs};
use osis_proto::msg::{OfferItem, Pull, PullReply};
use osis_proto::{ClientInput, Code, Command, Event as Ev, Message};
use std::collections::BTreeSet;

const PULL_ID: u32 = 1 << 31 | 1 << 30 | 7;

struct Setup {
    net: Net,
    b: usize,
    a: usize,
    g: Tid,
    l: LabelId,
    r: [u8; 32],
    p: Dialer,
    /// The dialer's stream position: what it applied and reported.
    cursor: Vec<u8>,
}

/// Node `b` holds group `g` alone; `a` is on another group of `b`'s (so a record), not on `g`. A
/// hand dialer proving `a` resumes the record, opens `g`'s label by a Hit on its read secret (J
/// unknown: an open by a credential), pulls it with `follow` and reports the reply.
fn opened() -> Setup {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, b);
    net.group_at(b, &[(a, Role::Read)], vec![]);
    let g = net.group_seeded(b, &[], vec![], 2);
    let l = net.engine(b).labels_of(&g)[0].id;
    net.item(b, g, g, "before");
    net.run();
    let ta = net.tid(a);
    let r = net.engine(b).run(|tx| Ok(tx.txn.records_of_actors(&[ta])?)).unwrap()[0].r;
    net.set_online(a, false);
    net.run();
    let (mut p, _) = resume(&mut net, a, b, &r, CHALLENGE, &[]);
    let v = read_value(&mut net, b, l);
    let hit = dialer_hit(&v, l, &r, &p, CHALLENGE);
    assert_eq!(offer(&mut net, b, &mut p, vec![OfferItem::Hit(hit)])[0].0, Code::OK);
    let reply = pull(&mut net, b, &mut p, None, vec![(l, None)]);
    assert!(reply.report && events_of(&reply.events, l) > 0, "the listing carries g and asks its report");
    let cursor = reply.cursor.clone().unwrap();
    send(&mut net, b, &mut p, Message::Applied { cursor: cursor.clone() });
    Setup { net, b, a, g, l, r, p, cursor }
}

/// A hand dialer proving `a` that resumes the record keyed `r` holding `members` (its digest
/// matches `b`'s when `b` holds the same S), and what `b` sent it.
fn resume(net: &mut Net, a: usize, b: usize, r: &[u8; 32], challenge: [u8; 32], members: &[LabelId]) -> (Dialer, Vec<Message>) {
    let mut p = dial_as(net, a, b, challenge);
    let tag = resume_tag(r, &LISTENER, &challenge, &p.hello);
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Resume { nonce: [5; 32], tags: vec![tag] }));
    let mut msgs = shared_of(&pump(net, b, &mut p, Vec::new(), outs));
    let theirs = msgs.iter().find_map(|m| if let Message::Digest { digest } = m { Some(*digest) } else { None }).expect("b's digest first");
    let mine = members_digest(r, members.iter().map(|l| &l.0));
    msgs.extend(shared_of(&send(net, b, &mut p, Message::Digest { digest: mine })));
    if theirs != mine {
        msgs.extend(shared_of(&send(net, b, &mut p, Message::Members { labels: members.to_vec(), more: false })));
    }
    (p, msgs)
}

fn pull(net: &mut Net, b: usize, p: &mut Dialer, cursor: Option<Vec<u8>>, joins: Vec<(LabelId, Option<Vec<u8>>)>) -> PullReply {
    pull_all(net, b, p, cursor, joins).1
}

/// A Pull and everything `b` sent back: its messages, and the reply.
fn pull_all(net: &mut Net, b: usize, p: &mut Dialer, cursor: Option<Vec<u8>>, joins: Vec<(LabelId, Option<Vec<u8>>)>) -> (Vec<Message>, PullReply) {
    let m = Message::Pull(Box::new(Pull { id: PULL_ID, cursor, joins, inline_limit: 1 << 20, max_reply: 1 << 20, follow: true, ephemeral: true }));
    let msgs = shared_of(&send(net, b, p, m));
    let reply = msgs.iter().find_map(|m| if let Message::PullReply(r) = m { Some((**r).clone()) } else { None }).expect("a reply");
    (msgs, reply)
}

/// `b` runs a step on its own; what it sent the dialer.
fn step(net: &mut Net, b: usize, p: &mut Dialer) -> Vec<Message> {
    let mut msgs = Vec::new();
    for _ in 0..3 {
        let acts = net.sync(b).handle(osis_node::sync::Event::Local);
        msgs.extend(shared_of(&pump(net, b, p, acts, Vec::new())));
    }
    msgs
}

fn events_of(events: &[(LabelId, Ev)], l: LabelId) -> usize {
    events.iter().filter(|(x, _)| *x == l).count()
}

fn added_of(events: &[(LabelId, Ev)], l: LabelId) -> BTreeSet<BlobId> {
    events.iter().filter_map(|(x, e)| if let Ev::Added { blob_id, .. } = e { (*x == l).then_some(*blob_id) } else { None }).collect()
}

fn pushes(msgs: &[Message]) -> Vec<osis_proto::msg::Stream> {
    msgs.iter().filter_map(|m| if let Message::Stream(s) = m { Some((**s).clone()) } else { None }).collect()
}

fn losts(msgs: &[Message]) -> Vec<(LabelId, Option<Vec<u8>>)> {
    msgs.iter().filter_map(|m| if let Message::Lost { items, .. } = m { Some(items.clone()) } else { None }).flatten().collect()
}

/// `b` rotates `g`, boxing only itself: `a`'s shown credential is stale, and `a` is no holder.
fn rotate(net: &mut Net, b: usize, g: Tid) {
    let tb = net.tid(b);
    let rec = recipients_of(net.engine(b), &[(tb, Role::Admin)]);
    rotation(net.engine(b), g, &rec, 9, false);
}

fn position(net: &mut Net, b: usize, c: &[u8]) -> u64 {
    net.engine(b).run(|tx| Ok(tx.txn.log_position(c)?)).unwrap().expect("a cursor of b's")
}

// issues/net-reconnect.md (Reported position): a followed member whose credential a rotation made
// stale is pushed through the rotation and gets `Lost` only once the requester reported that push:
// its `Applied` is what ends the wait. The rotation asks no report beyond the per-message ones:
// every push asking one carries events
#[test]
fn a_followed_member_gets_lost_after_its_rotation_spec_sync_10() {
    let Setup { mut net, b, g, l, mut p, cursor, .. } = opened();
    let before = position(&mut net, b, &cursor);
    rotate(&mut net, b, g);
    let msgs = step(&mut net, b, &mut p);
    let ps = pushes(&msgs);
    let rot = ps.iter().find(|s| s.report && events_of(&s.events, l) > 0).expect("the rotation is pushed, asking its report");
    assert!(ps.iter().all(|s| !s.report || !s.events.is_empty()), "no report asked of a push without events");
    assert!(losts(&msgs).is_empty(), "no Lost before the requester reported the rotation");
    // more of g after the rotation: not pushed, and still no Lost
    net.item(b, g, g, "after");
    let msgs = step(&mut net, b, &mut p);
    assert!(pushes(&msgs).iter().all(|s| events_of(&s.events, l) == 0), "nothing of g past the rotation");
    assert!(losts(&msgs).is_empty(), "still no Lost");
    let at = rot.cursor.clone().unwrap();
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::Applied { cursor: at.clone() }));
    let lost = losts(&msgs);
    assert_eq!(lost.len(), 1, "the Applied ends the wait: {msgs:?}");
    let (x, c) = &lost[0];
    assert_eq!(*x, l);
    let stop = position(&mut net, b, c.as_ref().expect("where it stopped"));
    assert!(stop > before && stop <= position(&mut net, b, &at), "it stopped at the rotation");
    assert!(net.sync(b).shared_members(p.conn).is_empty());
}

// issues/net-reconnect.md (Joining and rejoining): nothing past `until` reaches a requester whose
// proof went stale, by push, by a Pull from its position, or by a Fetch
#[test]
fn nothing_is_served_past_until_to_a_peer_that_lost_the_right_spec_sync_10() {
    let Setup { mut net, b, g, l, mut p, cursor, .. } = opened();
    rotate(&mut net, b, g);
    let msgs = step(&mut net, b, &mut p);
    let rotated = pushes(&msgs).iter().flat_map(|s| added_of(&s.events, l)).collect::<BTreeSet<_>>();
    assert!(!rotated.is_empty(), "the rotation is served");
    let held: BTreeSet<BlobId> = net.sync(b).entries(&l).into_iter().map(|(id, _)| id).collect();
    net.item(b, g, g, "after");
    step(&mut net, b, &mut p);
    let after: BTreeSet<BlobId> = net.sync(b).entries(&l).into_iter().map(|(id, _)| id).filter(|id| !held.contains(id)).collect();
    assert!(!after.is_empty());
    // the requester asks again from before the rotation: the rotation, nothing after it
    let reply = pull(&mut net, b, &mut p, Some(cursor), vec![]);
    let served = added_of(&reply.events, l);
    assert!(rotated.is_subset(&served), "the rotation again");
    assert!(served.is_disjoint(&after), "nothing written after it");
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::Fetch { id: PULL_ID + 1, label: l, max_reply: 1 << 20, ids: after.iter().copied().collect() }));
    let fetched = msgs.iter().find_map(|m| if let Message::FetchReply { items, .. } = m { Some(items.clone()) } else { None }).expect("answered");
    assert!(fetched.iter().all(|f| f.entry.is_none()), "a Fetch past until is answered with nothing");
}

// issues/net-reconnect.md (Hard cases, Lost and rejoin): a rotation while apart ends the member at
// the rotation, not at the reconnect. On the next connection the requester's Pull from its
// position gets the rotation, its report brings the `Lost` naming where L stopped, the holder
// finds L again by `b`'s added beacon (the new epoch's), and its rejoin from that position
// carries only what it missed: what came after the rotation, nothing served before
#[test]
fn a_rotation_while_apart_rejoins_from_its_lag_spec_sync_10() {
    let Setup { mut net, b, a, g, l, r, p, cursor } = opened();
    let acts = net.sync(b).handle(osis_node::sync::Event::Down { conn: p.conn });
    net.actions(b, acts);
    rotate(&mut net, b, g);
    net.run();
    let held: BTreeSet<BlobId> = net.sync(b).entries(&l).into_iter().map(|(id, _)| id).collect();
    net.item(b, g, g, "apart");
    net.run();
    let missed: BTreeSet<BlobId> = net.sync(b).entries(&l).into_iter().map(|(id, _)| id).filter(|id| !held.contains(id)).collect();
    assert!(!missed.is_empty());
    let (mut p, mut sent) = resume(&mut net, a, b, &r, [8; 32], &[l]);
    assert!(net.sync(b).shared_members(p.conn).contains(&l), "the records agree: L is in S");
    let (msgs, reply) = pull_all(&mut net, b, &mut p, Some(cursor), vec![]);
    sent.extend(msgs.iter().cloned());
    assert!(losts(&msgs).is_empty(), "the Pull's position is before the rotation");
    let first = added_of(&reply.events, l);
    assert!(!first.is_empty() && first.is_disjoint(&missed), "the rotation, nothing written after it");
    assert!(reply.report);
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::Applied { cursor: reply.cursor.clone().unwrap() }));
    let lost = losts(&msgs);
    assert_eq!(lost.len(), 1, "{msgs:?}");
    sent.extend(msgs);
    let lag = lost[0].1.clone().expect("where L stopped");
    // b's filter of this connection carries the new epoch's beacon: an added one
    let v = read_value(&mut net, b, l);
    let want = beacon(&v, &l.0, &r);
    let found = sent.iter().any(|m| matches!(m, Message::Beacons { f, gcs, lo, hi, .. } if decode_gcs(gcs, *lo, *hi).unwrap().contains(&beacon_value(&want, *f))));
    assert!(found, "b sent the new epoch's beacon");
    let hit = dialer_hit(&v, l, &r, &p, [8; 32]);
    assert_eq!(offer(&mut net, b, &mut p, vec![OfferItem::Hit(hit)])[0].0, Code::OK, "the holder reopens L");
    let rejoin = pull(&mut net, b, &mut p, reply.cursor.clone(), vec![(l, Some(lag))]);
    let again = added_of(&rejoin.events, l);
    assert!(missed.is_subset(&again), "what it missed arrives");
    assert!(again.is_disjoint(&first) && again.iter().all(|id| !held.contains(id)), "nothing served before comes again");
    assert!(!rejoin.whole);
}

// issues/net-reconnect.md (Reported position): a report lost with its connection needs no repair of
// its own: the next connection's Pull carries the requester's cursor, past the rotation, and that
// ends the wait with no Applied
#[test]
fn a_report_lost_with_its_connection_is_repaired_by_the_next_pull_spec_sync_10() {
    let Setup { mut net, b, a, g, l, r, mut p, .. } = opened();
    rotate(&mut net, b, g);
    let msgs = step(&mut net, b, &mut p);
    let at = pushes(&msgs).into_iter().find(|s| s.report && events_of(&s.events, l) > 0).and_then(|s| s.cursor).expect("the rotation pushed");
    let acts = net.sync(b).handle(osis_node::sync::Event::Down { conn: p.conn });
    net.actions(b, acts);
    let (mut p, _) = resume(&mut net, a, b, &r, [8; 32], &[l]);
    let (msgs, reply) = pull_all(&mut net, b, &mut p, Some(at), vec![]);
    assert_eq!(losts(&msgs).iter().map(|(x, _)| *x).collect::<Vec<_>>(), vec![l], "the Pull's cursor reported the rotation");
    assert_eq!(events_of(&reply.events, l), 0);
}
