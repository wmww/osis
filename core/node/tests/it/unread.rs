#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The serving side for sync IDs a node keeps and cannot read (issues/net-one-peer.md build 3g;
//! issues/net-shared-set.md, Peers that cannot read; spec/sync.md §10 Shared set): their head's
//! sync-key, deposit-key and static entries go in the filter to every connection; a Hit on the
//! sync key with its open signature opens the sync ID, which is then served by the stream from the
//! hub's store; a head with another sync key ends it through its event. A hand dialer proving
//! nothing plays the reader: it registers and uploads by the host protocol and holds the label's
//! keys (examples::Label), node `b` reads a group of its own.

use crate::connection_proofs::{CHALLENGE, Dialer, LISTENER, dial_with, pump};
use crate::net;
use crate::shared::{offer, send, shared_of};
use net::*;
use osis_base::{BlobId, LabelId, Role, Tid};
use osis_node::Mutation;
use osis_crypto::kdf::{beacon, beacon_hit, pair_key};
use osis_proto::examples::{Label, blob};
use osis_proto::filter::{beacon_value, decode_gcs};
use osis_proto::msg::{DeleteItem, OfferItem, Pull, PullReply};
use osis_proto::{ClientEvent, ClientInput, Code, Command, Event as Ev, Message};
use std::collections::BTreeSet;

const PULL_ID: u32 = 1 << 31 | 1 << 30 | 9;

struct Setup {
    net: Net,
    b: usize,
    l: Label,
    p: Dialer,
    /// The peer's filter on the hand connection: its width and values.
    filter: (u8, Vec<u64>),
    /// b's read group's label.
    read: LabelId,
}

/// Node `b` reading a group of its own, keeping everything for others (`open` admission); a hand
/// dialer registers label `l` there, uploads two entries, and sends NoRecord.
fn setup() -> Setup {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    let g = net.group_at(b, &[(a, Role::Read)], vec![]);
    net.run();
    let read = net.engine(b).labels_of(&g)[0].id;
    net.sync(b).hub_store().lock().unwrap().set_admission(osis_host::Admission::Open, Default::default());
    let mut p = dial_with(&mut net, b, CHALLENGE);
    let l = Label::new(0x51);
    command(&mut net, b, &mut p, l.register_cmd(0));
    command(&mut net, b, &mut p, Command::Upload { label: l.id, entries: vec![l.entry(blob(1)), l.entry(blob(2))] });
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::NoRecord { id: 1 << 31 }));
    let mut filter = (0, Vec::new());
    for m in &msgs {
        if let Message::Beacons { f, lo, hi, gcs, .. } = m {
            filter.0 = *f;
            filter.1.extend(decode_gcs(gcs, *lo, *hi).unwrap());
        }
    }
    assert!(filter.0 > 0, "a filter: {msgs:?}");
    Setup { net, b, l, p, filter, read }
}

fn command(net: &mut Net, b: usize, p: &mut Dialer, c: Command) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(c));
    pump(net, b, p, outs)
}

/// The connection's pair key: it keeps no record.
fn r_of(p: &Dialer) -> [u8; 32] {
    *pair_key(&CHALLENGE, &p.hello).expose()
}

/// The dialer's Hit on match value `v` of `l`.
fn hit(p: &Dialer, v: &[u8; 32], l: &LabelId) -> [u8; 32] {
    beacon_hit(v, &l.0, &beacon(v, &l.0, &r_of(p)), (false, &LISTENER, &CHALLENGE, &p.hello))
}

/// An open signature by `l`'s head sync key over the listener's challenge and key.
fn open_sig(p: &Dialer, l: &Label) -> osis_crypto::Signature {
    osis_crypto::sign_open(&l.head_keys().sync, &l.id, &p.hello, &LISTENER)
}

fn sync_value(l: &Label) -> [u8; 32] {
    l.head_keys().sync.verifying_key().to_bytes()
}

fn in_filter(s: &Setup, v: &[u8; 32], l: &LabelId) -> bool {
    s.filter.1.binary_search(&beacon_value(&beacon(v, &l.0, &r_of(&s.p)), s.filter.0)).is_ok()
}

fn pull(net: &mut Net, b: usize, p: &mut Dialer, joins: Vec<(LabelId, Option<Vec<u8>>)>) -> (Vec<Message>, PullReply) {
    let m = Message::Pull(Box::new(Pull { id: PULL_ID, cursor: None, joins, inline_limit: 1 << 20, max_reply: 1 << 20, follow: true, ephemeral: true }));
    let msgs = shared_of(&send(net, b, p, m));
    let reply = msgs.iter().find_map(|m| if let Message::PullReply(r) = m { Some((**r).clone()) } else { None }).expect("a reply");
    (msgs, reply)
}

fn added(events: &[(LabelId, Ev)], l: LabelId) -> BTreeSet<BlobId> {
    events.iter().filter_map(|(x, e)| if let Ev::Added { blob_id, .. } = e { (*x == l).then_some(*blob_id) } else { None }).collect()
}

fn pushed(msgs: &[Message]) -> Vec<(LabelId, Ev)> {
    msgs.iter().filter_map(|m| if let Message::Stream(s) = m { Some(s.events.clone()) } else { None }).flatten().collect()
}

/// Opens `s.l` by a Hit on its sync key and pulls it from the start.
fn opened(s: &mut Setup) -> PullReply {
    let h = hit(&s.p, &sync_value(&s.l), &s.l.id);
    let sig = open_sig(&s.p, &s.l);
    let ans = offer(&mut s.net, s.b, &mut s.p, vec![OfferItem::Hit(h, Some(sig))]);
    assert_eq!(ans[0].0, Code::OK, "the sync key's Hit with its open signature opens L");
    pull(&mut s.net, s.b, &mut s.p, vec![(s.l.id, None)]).1
}

// spec/sync.md §10 Shared set (a peer that cannot read): a stranger's filter holds the head
// credentials of what the node keeps unread (sync key, deposit key, the claim set's entries)
// and none of what it reads
#[test]
fn a_strangers_filter_holds_only_unread_entries_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    assert!(in_filter(&s, &sync_value(&s.l), &l), "the sync key's entry");
    assert!(in_filter(&s, &s.l.head_keys().deposit.verifying_key().to_bytes(), &l), "the deposit key's");
    let entry = osis_crypto::static_entry(&l, &s.l.key_actor.verifying_key());
    assert!(in_filter(&s, &entry, &l), "the key actor's static entry");
    let claims = s.l.sets[0].claims.len();
    assert_eq!(s.filter.1.len(), 2 + claims, "nothing more: b's own group shows nothing here");
    let read = s.read;
    let secrets = s.net.sync(s.b).credentials(&[read]).unwrap();
    for c in &secrets[&read] {
        assert!(!in_filter(&s, &c.match_value(), &read), "none of what b reads");
    }
}

// issues/net-shared-set.md, The rule (unknown actors see nothing of what a node reads): a
// stranger holding a read secret of what the node reads opens nothing by a Hit on it, though
// it never saw its entry
#[test]
fn a_strangers_hit_on_a_read_secret_opens_nothing_spec_sync_10() {
    let mut s = setup();
    let read = s.read;
    let secrets = s.net.sync(s.b).credentials(&[read]).unwrap();
    let items: Vec<OfferItem> = secrets[&read].iter().map(|c| OfferItem::Hit(hit(&s.p, &c.match_value(), &read), None)).collect();
    assert!(!items.is_empty());
    let ans = offer(&mut s.net, s.b, &mut s.p, items);
    assert!(ans.iter().all(|(c, t)| *c == Code::NOT_ADMITTED && t.is_none()), "{ans:?}");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).is_empty());
}

// spec/sync.md §10 Shared set, Stream: a reader opens an unread L by its sync key, pulls what the
// node keeps of it, and its uploads and deletes there reach its stream
#[test]
fn a_reader_opens_an_unread_label_by_sync_key_pulls_uploads_and_deletes_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let reply = opened(&mut s);
    let want: BTreeSet<BlobId> = [blob(1), blob(2)].iter().map(|b| osis_label::blob_id(b)).collect();
    assert_eq!(added(&reply.events, l), want, "the listing from the hub's store");
    assert!(reply.events.iter().any(|(x, e)| *x == l && matches!(e, Ev::Head(h) if h.id() == s.l.steps[0].id())), "and its head");
    send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: reply.cursor.clone().unwrap() });
    let third = s.l.entry(blob(3));
    let evs = command(&mut s.net, s.b, &mut s.p, Command::Upload { label: l, entries: vec![third.clone()] });
    let third_id = osis_label::blob_id(&third.blob);
    assert!(added(&pushed(&shared_of(&evs)), l).contains(&third_id), "an upload is pushed to the follower: {evs:?}");
    let item = DeleteItem::sign(&s.l.head_keys().delete, &l, third_id).unwrap();
    let evs = command(&mut s.net, s.b, &mut s.p, Command::Delete { label: l, items: vec![item] });
    assert!(pushed(&shared_of(&evs)).iter().any(|(x, e)| *x == l && *e == Ev::Deleted(third_id)), "and its deletion: {evs:?}");
}

// issues/net-shared-set.md, Offer: of an unread L's entries only the sync key with its open
// signature opens: no signature, another's, the deposit key's or the static entry's without its
// key actor proved open nothing
#[test]
fn nothing_else_of_an_unread_filter_opens_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let sync = sync_value(&s.l);
    let other = osis_crypto::sign_open(&s.l.head_keys().write, &l, &s.p.hello, &LISTENER);
    let elsewhere = osis_crypto::sign_open(&s.l.head_keys().sync, &l, &[1; 32], &LISTENER);
    let deposit = s.l.head_keys().deposit.verifying_key().to_bytes();
    let entry = osis_crypto::static_entry(&l, &s.l.key_actor.verifying_key());
    let sig = open_sig(&s.p, &s.l);
    let items = vec![
        OfferItem::Hit(hit(&s.p, &sync, &l), None),
        OfferItem::Hit(hit(&s.p, &sync, &l), Some(other)),
        OfferItem::Hit(hit(&s.p, &sync, &l), Some(elsewhere)),
        OfferItem::Hit(hit(&s.p, &deposit, &l), Some(sig)),
        OfferItem::Hit(hit(&s.p, &entry, &l), None),
        OfferItem::ByRole(l, vec![hit(&s.p, &sync, &l)]),
    ];
    let ans = offer(&mut s.net, s.b, &mut s.p, items);
    assert!(ans.iter().all(|(c, t)| *c == Code::NOT_ADMITTED && t.is_none()), "{ans:?}");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).is_empty());
}

// issues/net-shared-set.md, Opens: an open by sync key ends when the head's sync key changes: the
// reader is served through the new head's event, and Lost once it reported past it
#[test]
fn a_head_change_ends_the_open_after_its_event_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let reply = opened(&mut s);
    send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: reply.cursor.clone().unwrap() });
    s.l.rotate(0x61);
    let evs = command(&mut s.net, s.b, &mut s.p, s.l.register_cmd(1));
    let msgs = shared_of(&evs);
    let streams: Vec<osis_proto::msg::Stream> = msgs.iter().filter_map(|m| if let Message::Stream(x) = m { Some((**x).clone()) } else { None }).collect();
    let last = streams.iter().rev().find(|x| x.cursor.is_some()).expect("a push");
    assert!(last.events.iter().any(|(x, e)| *x == l && matches!(e, Ev::Head(h) if h.id() == s.l.steps[1].id())), "the new head's event is served: {msgs:?}");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).contains(&l), "still a member until reported");
    // an upload under the new keys, logged past the head's event, is not served
    let evs = command(&mut s.net, s.b, &mut s.p, Command::Upload { label: l, entries: vec![s.l.entry(blob(4))] });
    assert!(added(&pushed(&shared_of(&evs)), l).is_empty(), "nothing past the head's event");
    let msgs = shared_of(&send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: last.cursor.clone().unwrap() }));
    assert!(msgs.iter().any(|m| matches!(m, Message::Lost { items, .. } if items.iter().any(|(x, _)| *x == l))), "Lost once reported past it: {msgs:?}");
    assert!(!s.net.sync(s.b).shared_members(s.p.conn).contains(&l));
    // the new head's sync key opens it again
    let h = hit(&s.p, &sync_value(&s.l), &l);
    let sig = open_sig(&s.p, &s.l);
    let ans = offer(&mut s.net, s.b, &mut s.p, vec![OfferItem::Hit(h, Some(sig))]);
    assert_eq!(ans[0].0, Code::OK, "the current sync key reopens");
}

// spec/sync.md §10 Shared set (Lost): a head the hub's store moved ends an open by its old sync
// key before node sync answers anything after it: a Pull handled in the step that takes the move
// in is served nothing past the new head's event
#[test]
fn a_pull_after_a_head_change_gets_nothing_past_its_event_spec_sync_10() {
    use osis_proto::LabelStore;
    let mut s = setup();
    let l = s.l.id;
    let reply = opened(&mut s);
    send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: reply.cursor.clone().unwrap() });
    let (step, set) = s.l.rotate(0x61);
    let e4 = s.l.entry(blob(4));
    let now = s.net.now();
    {
        // another connection's register and upload, in the hub before node sync's next step
        let hub = s.net.sync(s.b).hub_store();
        let mut hub = hub.lock().unwrap();
        assert_eq!(hub.push_step(&l, step, Some(set)).unwrap(), Code::OK);
        let put = osis_proto::Put { blob_id: osis_label::blob_id(&e4.blob), blob: &e4.blob, wrap: e4.wrap, stamp: Some(e4.stamp), expiry: None, ephemeral: false, replaces: &[], now, role: false };
        assert_eq!(hub.put(&l, put).unwrap(), Code::OK);
    }
    let m = Message::Pull(Box::new(Pull { id: PULL_ID, cursor: reply.cursor.clone(), joins: vec![], inline_limit: 1 << 20, max_reply: 1 << 20, follow: true, ephemeral: false }));
    let msgs = shared_of(&send(&mut s.net, s.b, &mut s.p, m));
    let mut events: Vec<(LabelId, Ev)> = pushed(&msgs);
    events.extend(msgs.iter().filter_map(|m| if let Message::PullReply(r) = m { Some(r.events.clone()) } else { None }).flatten());
    assert!(!added(&events, l).contains(&osis_label::blob_id(&e4.blob)), "nothing past the head's event: {msgs:?}");
}

// issues/net-shared-set.md, Deposits: a depositor's Deposit item at a node keeping the inbox
// unread is taken by the hub's store's deposit rules; a bad signature is 14
#[test]
fn a_deposit_at_an_unread_inbox_is_taken_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let b5 = blob(5);
    let wrap = [7; osis_crypto::WRAP_LEN];
    let id = osis_label::blob_id(&b5);
    let good = osis_label::sign_deposit(&s.l.head_keys().deposit, &l, &id, &wrap, false);
    let bad = osis_label::sign_deposit(&s.l.head_keys().write, &l, &id, &wrap, false);
    let ans = offer(&mut s.net, s.b, &mut s.p, vec![OfferItem::Deposit { label: l, blob: b5.clone(), wrap, sig: bad }, OfferItem::Deposit { label: l, blob: b5, wrap, sig: good }]);
    assert_eq!(ans, vec![(Code::NOT_ADMITTED, None), (Code::OK, None)]);
    use osis_proto::LabelStore;
    let held = s.net.sync(s.b).hub_store().lock().unwrap().entry(&l, &id).unwrap();
    assert!(held.is_some_and(|m| m.stamp.is_none()), "kept unstamped (deposited)");
}

// spec/sync.md §10 Stream (ephemeral, relay-only): an unread L's ephemeral entries are listed from
// the hub's memory and follow on; a relay-only upload past the hub's gate reaches the reader on
// its stream as a Stream with no cursor
#[test]
fn an_unread_labels_memory_and_relay_entries_reach_the_reader_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let soon = s.net.now() + osis_base::format::MAX_DRIFT_MS;
    let eph = |n: u8| classed(n, osis_label::Class::Ephemeral, soon);
    command(&mut s.net, s.b, &mut s.p, Command::Upload { label: l, entries: vec![s.l.entry(eph(6))] });
    let reply = opened(&mut s);
    let e6 = osis_label::blob_id(&eph(6));
    assert!(added(&reply.events, l).contains(&e6), "a live memory entry is listed");
    send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: reply.cursor.clone().unwrap() });
    let evs = command(&mut s.net, s.b, &mut s.p, Command::Upload { label: l, entries: vec![s.l.entry(eph(7))] });
    assert!(added(&pushed(&shared_of(&evs)), l).contains(&osis_label::blob_id(&eph(7))), "a new one follows: {evs:?}");
    // a relay-only entry from another connection goes on the reader's stream
    let mut q = dial_with(&mut s.net, s.b, [8; 32]);
    let relay = classed(8, osis_label::Class::Relay, soon);
    command(&mut s.net, s.b, &mut q, Command::Upload { label: l, entries: vec![s.l.entry(relay.clone())] });
    let now = s.net.now();
    let frames = s.net.hand_sent(s.b, s.p.hc);
    let outs: Vec<_> = frames.into_iter().flat_map(|f| s.p.cs.handle(now, ClientInput::Bytes(f))).collect();
    let msgs = shared_of(&pump(&mut s.net, s.b, &mut s.p, outs));
    let rid = osis_label::blob_id(&relay);
    assert!(msgs.iter().any(|m| matches!(m, Message::Stream(x) if x.cursor.is_none() && added(&x.events, l).contains(&rid))), "{msgs:?}");
}

/// A blob of class `c` expiring at `t` (wall ms).
fn classed(n: u8, c: osis_label::Class, t: u64) -> Vec<u8> {
    let p = osis_label::Prefix::new([n; 16], Some(osis_base::WallMs(t)), vec![]).unwrap().with_class(c);
    osis_label::frame(&p, &[n; 20], &mut osis_crypto::SeededRng::from_seed([n; 32])).unwrap().1
}

// spec/sync.md §10 Shared set (static entry), spec/wire.md §11.2 Offer: a key actor listed in an
// unread L's head claim set, proved on the connection, opens L by a Hit on its static entry and
// gets the head's entry box for it with the path from the genesis step, from the hub's store
#[test]
fn a_key_actors_static_entry_opens_an_unread_label_with_its_grant_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let ka = s.l.key_actor.clone();
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: ka.verifying_key().to_bytes().to_vec(), nonce: [3; 32], account: false };
    let mut q = dial_with(&mut s.net, s.b, [8; 32]);
    crate::connection_proofs::prove(&mut s.net, s.b, &mut q, vec![osis_proto::Prover { key: ka.clone(), record }]);
    send(&mut s.net, s.b, &mut q, Message::NoRecord { id: 1 << 31 });
    let entry = osis_crypto::static_entry(&l, &ka.verifying_key());
    let r = *pair_key(&[8; 32], &q.hello).expose();
    let h = beacon_hit(&entry, &l.0, &beacon(&entry, &l.0, &r), (false, &LISTENER, &[8; 32], &q.hello));
    let msgs = shared_of(&send(&mut s.net, s.b, &mut q, Message::Offer { id: 77, items: vec![OfferItem::Hit(h, None)] }));
    let Some(Message::Shared { codes, .. }) = msgs.iter().find(|m| m.id() == 77) else { panic!("{msgs:?}") };
    let (code, tag, grant) = &codes[0];
    assert_eq!((*code, tag.is_some()), (Code::OK, true));
    let grant = grant.as_ref().expect("a grant");
    assert_eq!(grant.path, s.l.steps, "the path from genesis");
    assert_eq!(Some(&grant.entry_box), s.l.sets[0].entries.get(&entry), "the head's box for the entry");
    assert!(s.net.sync(s.b).shared_members(q.conn).contains(&l));
}

// spec/sync.md §10 (Stream: a node that cannot read L pulls it from every reader that opened it
// there): a write reaches the peer that cannot read its group by the peer's pull alone (no
// Upload is sent), and a second reader reads it through that peer with the writer offline.
#[test]
fn a_write_reaches_a_peer_that_cannot_read_by_its_pull_spec_sync_10() {
    let (mut net, host, [a, b], g, []) = hosted::<2, 0>(&[(1, Role::Read)], [], true);
    net.set_online(b, false);
    net.sent_kinds.clear();
    let t = net.item(a, g, g, "pulled");
    net.run();
    let l = net.label(a);
    let mine: BTreeSet<BlobId> = net.sync(a).entries(&l).into_iter().map(|x| x.0).collect();
    let held: BTreeSet<BlobId> = net.host_ids(host, &l).into_iter().collect();
    assert!(mine.is_subset(&held), "the peer holds every entry of the writer's store");
    assert_eq!(net.sent_kinds.get(&10).copied().unwrap_or(0), 0, "no Upload");
    net.set_online(a, false);
    net.set_online(b, true);
    net.advance(61_000);
    assert_eq!(net.read(b, t), Some(osis_base::Value::Str("pulled".into())));
}

// spec/sync.md §10 (Stream): a peer that cannot read L, restored from a backup taken before a
// write, pulls it again from a reader at the next connection, and a second reader gets it from
// that peer with the writer offline.
#[test]
fn a_peer_restored_from_a_backup_pulls_again_spec_sync_10() {
    let (mut net, host, [a, b], g, []) = hosted::<2, 0>(&[(1, Role::Read)], [], true);
    net.set_online(b, false);
    let backup = net.backup_store(host);
    let t = net.item(a, g, g, "again");
    net.run();
    let l = net.label(a);
    let before = net.host_ids(host, &l).len();
    // the peer's store as it was before the write
    net.restore_store(host, backup);
    assert!(net.host_ids(host, &l).len() < before, "rolled back");
    for _ in 0..3 {
        net.advance(61_000);
    }
    net.set_online(a, false);
    net.set_online(b, true);
    net.advance(61_000);
    assert_eq!(net.read(b, t), Some(osis_base::Value::Str("again".into())));
}

// spec/sync.md §10 (Stream: bytes cross once): an edit of a thing two groups read and list is
// one blob under both sync IDs; a peer that cannot read them, its bytes fetched under one, takes
// it under both.
#[test]
fn a_blob_under_two_sync_ids_is_taken_under_both_spec_sync_10() {
    use osis_schema::core_types as ct;
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    let g1 = net.group(a, &[(b, Role::Read)], &[host]);
    let g2 = net.group(a, &[(b, Role::Read)], &[host]);
    net.run();
    // a thing with secrets of its own, read by both groups and listed in both
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = osis_engine::Mutation::new();
    let t = e.new_thing(&mut m, me);
    m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let done = net.engine(a).give_own_secrets(&t).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    for g in [g1, g2] {
        let done = net.engine(a).grant(&t, &g, &edge).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        let e = net.engine(a);
        let mut x = e.get_typed(&g, &ct::GROUP).unwrap().unwrap_or_default();
        x.items.insert(t);
        let mut m = osis_engine::Mutation::new();
        m.set(g, &ct::GROUP, &x).unwrap();
        e.commit(m).unwrap();
    }
    net.run();
    net.advance(61_000);
    let c = net.write(a, t, "under both");
    net.run();
    net.advance(61_000);
    net.run();
    let mut ids = BTreeSet::new();
    for g in [g1, g2] {
        let l = net.engine(a).labels_of(&g)[0].id;
        let mine: Vec<BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
        assert!(!mine.is_empty(), "the write is under {l:?}");
        let held = net.host_ids(host, &l);
        assert!(mine.iter().all(|id| held.contains(id)), "the peer holds it under {l:?}");
        ids.extend(mine);
    }
    assert_eq!(ids.len(), 1, "one blob under both");
}

// spec/sync.md §10 (Bodies): a body a peer that cannot read L answered a Fetch with nothing is not
// asked there again on that connection (no Fetch storm while it lacks it), and is fetched once the
// peer announces it again (here, its listing on the next connection)
#[test]
fn undelivered_blob_fetched_again_once_announced_spec_sync_6() {
    use std::cell::Cell;
    use std::rc::Rc;
    let (mut net, _host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["x"], true);
    net.set_online(b, false);
    let c = net.write(a, t, "y");
    net.run();
    let l = net.label(a);
    let body = net.sync(a).entries(&l).into_iter().find(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).unwrap().0;
    let asked = Rc::new(Cell::new(0));
    let n = asked.clone();
    net.host_tamper = Some(Box::new(move |m| match m {
        Message::FetchReply { id, items } if items.iter().any(|i| i.blob_id == body) => {
            n.set(n.get() + 1);
            let items = items.iter().cloned().map(|mut i| {
                if i.blob_id == body {
                    i.entry = None;
                }
                i
            });
            Some(Message::FetchReply { id: *id, items: items.collect() })
        }
        // announced without its bytes: fetched
        Message::Stream(x) if x.events.iter().any(|(_, e)| matches!(e, Ev::Added { blob_id, blob: Some(_), .. } if *blob_id == body)) => {
            let mut x = x.clone();
            for (_, e) in &mut x.events {
                if let Ev::Added { blob_id, blob, .. } = e
                    && *blob_id == body
                {
                    *blob = None;
                }
            }
            Some(Message::Stream(x))
        }
        Message::PullReply(r) if r.events.iter().any(|(_, e)| matches!(e, Ev::Added { blob_id, blob: Some(_), .. } if *blob_id == body)) => {
            let mut r = r.clone();
            for (_, e) in &mut r.events {
                if let Ev::Added { blob_id, blob, .. } = e
                    && *blob_id == body
                {
                    *blob = None;
                }
            }
            Some(Message::PullReply(r))
        }
        _ => None,
    }));
    net.set_online(b, true);
    for _ in 0..4 {
        net.run();
        net.advance(61_000);
    }
    // another write passes the label at b: what the peer lacks is not asked there again
    let t2 = net.item(a, g, g, "other");
    for _ in 0..2 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.read(b, t2), Some(s("other")));
    assert_eq!(asked.get(), 1, "asked once on the connection");
    assert_eq!(net.read(b, t), Some(s("x")));
    net.host_tamper = None;
    net.set_online(b, false);
    net.set_online(b, true);
    for _ in 0..2 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.read(b, t), Some(s("y")), "fetched once announced again");
}

// spec/sync.md §10 (Shared set: a reader opens a peer that cannot read L by a Hit on its head's
// credential; Open only walks a head off the recorded path): readers whose recorded path ends at
// the peer's head reconnect, write and read through it with no Open sent.
#[test]
fn no_open_reaches_a_peer_on_the_newest_head_spec_sync_10() {
    let (mut net, _host, [a, b], g, [t]) = hosted::<2, 1>(&[(1, Role::Read)], ["x"], true);
    net.advance(61_000);
    net.sent_kinds.clear();
    for n in [a, b] {
        net.set_online(n, false);
    }
    net.run();
    for n in [a, b] {
        net.set_online(n, true);
    }
    net.advance(61_000);
    let t2 = net.item(a, g, g, "after");
    net.write(a, t, "y");
    net.run();
    net.advance(61_000);
    net.set_online(a, false);
    net.set_online(b, false);
    net.set_online(b, true);
    net.advance(61_000);
    assert_eq!(net.read(b, t2), Some(s("after")));
    assert_eq!(net.read(b, t), Some(s("y")));
    assert_eq!(net.sent_kinds.get(&4).copied().unwrap_or(0), 0, "no Open");
}

// spec/sync.md §5 (Delete: signed by the head's delete key or level keys), §10 (a reader acts
// on a peer that cannot read L by deletes alone): a writer's purge-on-replace write reaches the
// peer through a reader while the writer cannot reach it; the reader, holding no delete key,
// sends no Delete and the purged body stays there; once the writer (its level-3 key) reaches
// the peer, the body goes, and the admin, back alone, reads the new value through the peer.
#[test]
fn deletes_reach_a_peer_only_from_a_delete_key_holder_spec_sync_5() {
    use crate::common::GONE;
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let w = net.node(2, &[host]);
    let r = net.node(3, &[host]);
    // r dials w directly
    let acts = net.sync(w).publish_reach([0xb2; 32], Vec::new()).unwrap();
    net.actions(w, acts);
    let g = net.group(a, &[(w, Role::Write), (r, Role::Read)], &[host]);
    let t = net.item(a, g, g, "x");
    net.keep(a, t, &[("t:gone.0", PURGE)]);
    net.run();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("old")).unwrap();
    let old = net.engine(w).commit(m).unwrap().unwrap();
    net.feed(w, osis_node::sync::Event::Local);
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let purged: Vec<BlobId> = net.sync(w).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == old)).map(|(id, _)| id).collect();
    assert!(!purged.is_empty() && purged.iter().all(|id| net.host_ids(host, &l).contains(id)), "the old value at the peer");
    assert_eq!(net.engine(r).get_typed(&t, &GONE).unwrap(), Some(s("old")));
    // the admin away, the writer reaching the peer through r alone
    net.set_online(a, false);
    net.blocked.insert((w, host));
    net.drop_link(w, host);
    net.run();
    let before: BTreeSet<BlobId> = net.host_ids(host, &l).into_iter().collect();
    let mut m = Mutation::new();
    m.set(t, &GONE, &s("new")).unwrap();
    net.engine(w).commit(m).unwrap().unwrap();
    net.feed(w, osis_node::sync::Event::Local);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.engine(r).get_typed(&t, &GONE).unwrap(), Some(s("new")), "r read the new value from w");
    let held = net.host_ids(host, &l);
    assert!(held.iter().any(|id| !before.contains(id)), "what carries the new value reached the peer through r");
    assert!(purged.iter().all(|id| held.contains(id)), "the purged body stays: r holds no key");
    assert!(net.deleted.keys().all(|(n, x, _)| *n != r || *x != l), "r sent no Delete under L");
    // the writer reaches the peer: its level-3 key deletes the purged body
    net.blocked.remove(&(w, host));
    net.set_online(w, false);
    net.set_online(w, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let held = net.host_ids(host, &l);
    assert!(purged.iter().all(|id| !held.contains(id)), "the purged body went");
    assert!(net.deleted.keys().any(|(n, x, b)| *n == w && *x == l && purged.contains(b)), "by w's Delete");
    net.set_online(w, false);
    net.set_online(r, false);
    net.set_online(a, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.engine(a).get_typed(&t, &GONE).unwrap(), Some(s("new")), "the admin reads the new value through the peer");
}

// spec/sync.md §5 (Sending: every deposit a Deposit item), §10: A grants B while B is offline;
// A's grant lands as a Deposit item in B's inbox at the peer that keeps it, and B, connecting
// only to that peer with A offline, sees the grant and reads the group.
#[test]
fn a_deposit_for_an_offline_recipient_lands_where_its_inbox_is_kept_spec_sync_10() {
    let mut net = Net::new();
    net.home_at_hosts = true;
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    net.run();
    // A knows B's account (a contact)
    net.pair(b, a);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "for b");
    net.run();
    net.set_online(b, false);
    net.sent_kinds.clear();
    let bt = net.tid(b);
    net.grant(a, g, bt, Role::Read);
    for _ in 0..2 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.sent_kinds.get(&12).copied().unwrap_or(0), 0, "no Deposit message: a Deposit item");
    net.set_online(a, false);
    net.set_online(b, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert!(net.engine(b).roster(&g).contains_key(&bt), "B sees the grant");
    assert_eq!(net.read(b, t), Some(s("for b")), "and reads the group through the peer");
}

/// A writer `a` and a reader at one peer that cannot read; a thing with secrets of its own, read
/// by `k` groups of a's (the reader holding each) and listed in them; one edit of it with a 16 KB
/// value: the bytes of the edit's blobs nodes sent the peer.
fn edit_bytes(k: usize) -> usize {
    use osis_schema::core_types as ct;
    let (mut net, host, [a, b]) = hosted_nodes::<2>();
    let gs: Vec<Tid> = (0..k).map(|_| net.group(a, &[(b, Role::Read)], &[host])).collect();
    net.run();
    let me = net.tid(a);
    let e = net.engine(a);
    let mut m = osis_engine::Mutation::new();
    let t = e.new_thing(&mut m, me);
    m.set(t, &ct::GROUP, &ct::Group::default()).unwrap();
    e.commit(m).unwrap();
    let done = net.engine(a).give_own_secrets(&t).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    for g in &gs {
        let done = net.engine(a).grant(&t, g, &edge).unwrap();
        let acts = net.sync(a).carry_out(done).unwrap();
        net.actions(a, acts);
        let e = net.engine(a);
        let mut x = e.get_typed(g, &ct::GROUP).unwrap().unwrap_or_default();
        x.items.insert(t);
        let mut m = osis_engine::Mutation::new();
        m.set(*g, &ct::GROUP, &x).unwrap();
        e.commit(m).unwrap();
    }
    net.run();
    net.advance(61_000);
    net.run();
    net.crossed.clear();
    let big = "e".repeat(16 * 1024);
    let c = net.write(a, t, &big);
    net.run();
    net.advance(61_000);
    net.run();
    assert_eq!(net.read(b, t), Some(s(&big)));
    let mut blobs = BTreeSet::new();
    for g in &gs {
        let l = net.engine(a).labels_of(g)[0].id;
        let mine: Vec<BlobId> = net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect();
        assert!(!mine.is_empty(), "the edit is under {l:?}");
        let held = net.host_ids(host, &l);
        assert!(mine.iter().all(|id| held.contains(id)), "the peer holds it under {l:?}");
        blobs.extend(mine);
    }
    assert_eq!(blobs.len(), 1, "one blob under every group");
    // the edit's commit blob and the chunks it lists
    let l0 = net.engine(a).labels_of(&gs[0])[0].id;
    let listed: BTreeSet<BlobId> = net.sync(a).entries(&l0).into_iter().map(|(id, _)| id).collect();
    net.crossed.iter().filter(|(id, _)| listed.contains(id)).map(|(_, n)| *n).sum()
}

// spec/sync.md §3 (bytes cross once), §10 (Bodies: only blob IDs the store lacks are fetched):
// an edit of a thing listed in three groups a peer that cannot read them keeps crosses to it
// as many bytes as in one.
#[test]
fn an_edit_in_a_group_nested_in_three_crosses_its_bytes_once_spec_sync_3() {
    let (one, three) = (edit_bytes(1), edit_bytes(3));
    println!("bytes crossed at 1 and 3 groups: {one} / {three}");
    assert!(one >= 16 * 1024, "the edit's bytes crossed: {one}");
    assert_eq!(one, three, "bytes at 1 and 3 enclosing groups");
}

// spec/sync.md §5 (Deletes wait while a source lacks a body it takes now), §10 (Stream: a body a
// peer that cannot read L refuses for its tombstone is told deleted there): the peer dropped a
// writer's kept body on its own and the writer never read that deletion in the peer's log
// (its events of it lost on the way), so the writer, listing the peer from the start after a
// restart, judges the peer lacking a body it takes;
// the peer, pulling the writer from the start, refuses that body for its tombstone and says
// so, the writer places it anew, and its deletes (a purged body) go there instead of waiting
// for good.
#[test]
fn a_body_refused_for_a_tombstone_holds_no_delete_back_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    let t = net.item(a, g, g, "t");
    let u = net.item(a, g, g, "u");
    net.keep(a, u, &[("t:gone.0", PURGE)]);
    net.run();
    let kept = net.write(a, t, "kept");
    let mut m = Mutation::new();
    m.set(u, &GONE, &s("old")).unwrap();
    let old = net.engine(a).commit(m).unwrap().unwrap();
    net.feed(a, osis_node::sync::Event::Local);
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let of = |net: &mut Net, c: osis_base::CommitId| -> Vec<BlobId> { net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect() };
    let (x, purged) = (of(&mut net, kept), of(&mut net, old));
    assert!(!x.is_empty() && x.iter().chain(&purged).all(|id| net.host_ids(host, &l).contains(id)), "both at the peer");
    // the peer's log events deleting the kept body never reach a (a peer's own tell, a Stream
    // with no cursor, does)
    let lost: BTreeSet<BlobId> = x.iter().copied().collect();
    let strip = move |evs: &[(LabelId, Ev)]| -> Vec<(LabelId, Ev)> { evs.iter().filter(|(_, e)| !matches!(e, Ev::Deleted(b) if lost.contains(b))).cloned().collect() };
    net.host_tamper = Some(Box::new(move |m| match m {
        Message::Stream(st) if st.cursor.is_some() => Some(Message::Stream(Box::new(osis_proto::msg::Stream { events: strip(&st.events), ..(**st).clone() }))),
        Message::PullReply(r) => Some(Message::PullReply(Box::new(PullReply { events: strip(&r.events), ..(**r).clone() }))),
        _ => None,
    }));
    let now = net.now();
    for id in &x {
        osis_proto::LabelStore::delete(&mut *net.hosts[host].hub.store(), &l, id, now).unwrap();
    }
    let mut m = Mutation::new();
    m.set(u, &GONE, &s("new")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    // a restarts: it lists the peer from the start, which shows the kept body nowhere
    net.restart(a, 9);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    net.host_tamper = None;
    let held = net.host_ids(host, &l);
    assert!(purged.iter().all(|id| !held.contains(id)), "the purged body went from the peer");
    assert!(of(&mut net, kept).iter().any(|id| held.contains(id)), "the kept body is at the peer again, under a new encryption");
}
