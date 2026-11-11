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
use osis_base::{BlobId, LabelId, Role};
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

// issues/net-shared-set.md, Deposits: a depositor's Deposit item at a node keeping the inbox
// unread is taken by the hub's store's deposit rules; a bad signature is 14
#[test]
fn a_deposit_at_an_unread_inbox_is_taken_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let b5 = blob(5);
    let wrap = [7; osis_crypto::WRAP_LEN];
    let id = osis_label::blob_id(&b5);
    let good = osis_label::sign_deposit(&s.l.head_keys().deposit, &l, &id, &wrap);
    let bad = osis_label::sign_deposit(&s.l.head_keys().write, &l, &id, &wrap);
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
