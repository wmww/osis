#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The serving side for sync IDs a node keeps and cannot read (issues/sync-rewrite.md build 3g;
//! issues/net-shared-set.md, Peers that cannot read; spec/sync.md §10 Shared set): their head's
//! sync-key, deposit-key and static entries go in the filter to every connection; a Hit on the
//! sync key with its open signature opens the sync ID, which is then served by the stream from the
//! hub's store; a head with another sync key ends it through its event. A hand dialer proving
//! nothing plays the reader: it registers the label and holds its keys (examples::Label); entries
//! reach node `b`'s store by its store's rules as if pulled from a reader (`take`); node `b`
//! reads a group of its own.

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
use osis_proto::{Code, Event as Ev, Message};
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
/// dialer registers label `l` there, two entries reach b's store, and the dialer sends NoRecord.
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
    request(&mut net, b, &mut p, |id| l.register(id, 0));
    for n in [1, 2] {
        put(&mut net, b, &l, l.entry(blob(n)));
    }
    net.run();
    let msgs = shared_of(&send(&mut net, b, &mut p, Message::NoRecord { id: 1 << 31 }));
    let filter = filter_of(&msgs);
    Setup { net, b, l, p, filter, read }
}

/// The filter among `msgs`: its width and values.
fn filter_of(msgs: &[Message]) -> (u8, Vec<u64>) {
    let mut filter = (0, Vec::new());
    for m in msgs {
        if let Message::Beacons { f, lo, hi, gcs, .. } = m {
            filter.0 = *f;
            filter.1.extend(decode_gcs(gcs, *lo, *hi).unwrap());
        }
    }
    assert!(filter.0 > 0, "a filter: {msgs:?}");
    filter
}

/// Stamped entry `e` of `l` taken into node `b`'s store by its rules, as pulled from a reader
/// (spec/sync.md §5, Taking a stamped entry).
fn put(net: &mut Net, b: usize, l: &Label, e: osis_proto::examples::Stamped) {
    let now = net.now();
    let hub = net.sync(b).hub_store();
    let mut hub = hub.lock().unwrap();
    let k = osis_proto::LabelStore::head_keys(&*hub, &l.id).unwrap().unwrap();
    let taken = osis_proto::session::pulled(&mut *hub, now, &l.id, &k, &e.blob, e.wrap, e.stamp, &mut false).unwrap();
    assert!(matches!(taken, osis_proto::session::Taken::Code(Code::OK)), "taken");
}

/// `put`, then what node `b` sent the hand dialer since, as messages.
fn take(s: &mut Setup, e: osis_proto::examples::Stamped) -> Vec<Message> {
    put(&mut s.net, s.b, &s.l, e);
    s.net.run();
    let now = s.net.now();
    let frames = s.net.hand_sent(s.b, s.p.hc);
    let outs: Vec<_> = frames.into_iter().flat_map(|f| s.p.cs.bytes(now, f)).collect();
    shared_of(&pump(&mut s.net, s.b, &mut s.p, outs))
}

/// The hand dialer's request `m` (under an id it picks) and the exchange: what came back.
fn request(net: &mut Net, b: usize, p: &mut Dialer, m: impl FnOnce(u32) -> Message) -> Vec<Message> {
    let now = net.now();
    let (_, outs) = p.cs.request(now, m);
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
    osis_crypto::sign_open(&l.head_keys().sync, false, &l.id, &p.hello, &LISTENER)
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
// node keeps of it, and what the node takes later and deletes there reach its stream
#[test]
fn a_reader_opens_an_unread_label_by_sync_key_pulls_takes_and_deletes_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let reply = opened(&mut s);
    let want: BTreeSet<BlobId> = [blob(1), blob(2)].iter().map(|b| osis_label::blob_id(b)).collect();
    assert_eq!(added(&reply.events, l), want, "the listing from the hub's store");
    assert!(reply.events.iter().any(|(x, e)| *x == l && matches!(e, Ev::Head(h) if h.id() == s.l.steps[0].id())), "and its head");
    send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: reply.cursor.clone().unwrap() });
    let third_id = osis_label::blob_id(&blob(3));
    let e = s.l.entry(blob(3));
    let msgs = take(&mut s, e);
    assert!(added(&pushed(&msgs), l).contains(&third_id), "an entry taken is pushed to the follower: {msgs:?}");
    let item = DeleteItem::sign(&s.l.head_keys().delete, &l, third_id);
    let evs = request(&mut s.net, s.b, &mut s.p, |id| Message::Delete { id, label: l, items: vec![item] });
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
    let other = osis_crypto::sign_open(&s.l.head_keys().write, false, &l, &s.p.hello, &LISTENER);
    let elsewhere = osis_crypto::sign_open(&s.l.head_keys().sync, false, &l, &[1; 32], &LISTENER);
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
    let evs = request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, 1));
    let msgs = shared_of(&evs);
    let streams: Vec<osis_proto::msg::Stream> = msgs.iter().filter_map(|m| if let Message::Stream(x) = m { Some((**x).clone()) } else { None }).collect();
    let last = streams.iter().rev().find(|x| x.cursor.is_some()).expect("a push");
    assert!(last.events.iter().any(|(x, e)| *x == l && matches!(e, Ev::Head(h) if h.id() == s.l.steps[1].id())), "the new head's event is served: {msgs:?}");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).contains(&l), "still a member until reported");
    // an entry under the new keys, logged past the head's event, is not served
    let e = s.l.entry(blob(4));
    let msgs = take(&mut s, e);
    assert!(added(&pushed(&msgs), l).is_empty(), "nothing past the head's event");
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
        // a register on another connection and an entry taken, in the hub before node sync's next step
        let hub = s.net.sync(s.b).hub_store();
        let mut hub = hub.lock().unwrap();
        assert_eq!(hub.push_step(&l, step, Some(set)).unwrap(), Code::OK);
        let put = osis_proto::Put { blob_id: osis_label::blob_id(&e4.blob), blob: &e4.blob, wrap: e4.wrap, stamp: Some(e4.stamp), expiry: None, ephemeral: false, now, role: false };
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

// spec/sync.md §10 Stream (ephemeral): an unread L's ephemeral entries are listed from the hub's
// memory and follow on
#[test]
fn an_unread_labels_memory_entries_reach_the_reader_spec_sync_10() {
    let mut s = setup();
    let l = s.l.id;
    let soon = s.net.now() + osis_base::format::MAX_DRIFT_MS;
    let eph = |n: u8| classed(n, osis_label::Class::Ephemeral, soon);
    put(&mut s.net, s.b, &s.l, s.l.entry(eph(6)));
    s.net.run();
    let reply = opened(&mut s);
    let e6 = osis_label::blob_id(&eph(6));
    assert!(added(&reply.events, l).contains(&e6), "a live memory entry is listed");
    send(&mut s.net, s.b, &mut s.p, Message::Applied { cursor: reply.cursor.clone().unwrap() });
    let e = s.l.entry(eph(7));
    let msgs = take(&mut s, e);
    assert!(added(&pushed(&msgs), l).contains(&osis_label::blob_id(&eph(7))), "a new one follows: {msgs:?}");
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
    assert_eq!(grant.steps, s.l.steps, "the path from genesis");
    assert_eq!(grant.entry_box.as_ref(), s.l.sets[0].entries.get(&entry), "the head's box for the entry");
    assert!(s.net.sync(s.b).shared_members(q.conn).contains(&l));
}

// spec/sync.md §10 (Stream: a node that cannot read L pulls it from every reader that opened it
// there): a write reaches the peer that cannot read its group by the peer's pull alone, and a second reader reads it through that peer with the writer offline.
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
    net.set_online(a, false);
    net.set_online(b, true);
    net.advance(61_000);
    assert_eq!(net.read(b, t), Some(osis_base::Value::Str("pulled".into())));
}

/// Reader `a` of L (listing the host) and node `p` that cannot read L, keeping it unread (its
/// hub holds L's path, copied from the host) and dialing `a`, never reaching the host. `p`
/// proves an actor `a` knows: holding Sync on L's group when `sync` (and so its sync secret),
/// else Read on another group of `a`'s. (net, a, p, g, L).
fn dialing_node(sync: bool) -> (Net, usize, usize, Tid, LabelId) {
    let holders: &[(usize, Role)] = if sync { &[(1, Role::Sync)] } else { &[] };
    let (mut net, host, [a, p], g, []) = hosted::<2, 0>(holders, [], true);
    if !sync {
        net.group(a, &[(p, Role::Read)], &[]);
    }
    let l = net.label(a);
    net.blocked.insert((p, host));
    net.drop_link(p, host);
    let path = net.host_path(host, &l);
    {
        let hub = net.sync(p).hub_store();
        let mut hub = hub.lock().unwrap();
        hub.set_admission(osis_host::Admission::Open, Default::default());
        for st in path {
            assert_eq!(osis_proto::LabelStore::push_step(&mut *hub, &l, st, None).unwrap(), Code::OK);
        }
    }
    let key = crate::peers::reach_ed(&mut net, a);
    net.sync(p).set_hosts(vec![osis_label::Address { url: "peer://reader".into(), key }]);
    net.run();
    (net, a, p, g, l)
}

/// What node `p`'s store keeps of `l`.
fn kept(net: &mut Net, p: usize, l: &LabelId) -> BTreeSet<BlobId> {
    let hub = net.sync(p).hub_store();
    let hub = hub.lock().unwrap();
    osis_proto::LabelStore::live_ids(&*hub, l).unwrap().into_iter().collect()
}

// spec/sync.md §10 (Offer, Stream: each side pulls, whoever dialed), §5 Opens: a node that
// cannot read L, holding L's sync secret (Sync on its group), dials a reader of L and pulls L
// from it: its own Hit on L's sync key, signed by it, opens L on the connection; the reader holds
// per-label state there only for what the dialer proved, and shares only that.
#[test]
fn a_peer_that_cannot_read_pulls_from_a_reader_it_dialed_spec_sync_10() {
    let (mut net, a, p, g, l) = dialing_node(true);
    assert!(!net.engine(p).epochs(&g).unwrap().read.holds_any(), "p cannot read L");
    let before = kept(&mut net, p, &l).len();
    net.item(a, g, g, "pulled by its dialer");
    net.advance(61_000);
    let mine: BTreeSet<BlobId> = net.sync(a).entries(&l).into_iter().map(|x| x.0).collect();
    let held = kept(&mut net, p, &l);
    assert!(held.len() > before, "the dialer pulled the new write");
    assert!(mine.is_subset(&held), "the dialer holds every entry of the reader's store");
    let opened = net.sync(a).served_opened();
    assert!(opened.values().any(|m| m.contains(&l)), "L open on the connection p dialed: {opened:?}");
    assert!(opened.values().all(|m| m.iter().all(|x| *x == l)), "only what p proved: {opened:?}");
    let states = net.sync(a).served_label_states();
    assert!(opened.iter().all(|(c, m)| states.get(c) == Some(&m.len())), "per-label state for what p proved alone: {states:?}");
}

// spec/sync.md §5 Opens (one sync-key run per proof): a dialer's proof of L's sync secret opens
// L only while the newest step the reader records bears that sync key: a rotation closes L
// there, and while the dialer's head bears the old key (no reader moved it) nothing written
// after it reaches the dialer.
#[test]
fn a_dialers_proof_ends_at_the_next_sync_key_spec_sync_5() {
    let (mut net, a, p, g, l) = dialing_node(true);
    net.item(a, g, g, "before");
    net.advance(61_000);
    assert!(net.sync(a).served_opened().values().any(|m| m.contains(&l)), "open by p's proof");
    let at = net.tid(a);
    let rs = recipients_of(net.engine(a), &[(at, Role::Admin)]);
    rotation(net.engine(a), g, &rs, 61, false);
    net.run();
    net.advance(61_000);
    assert_eq!(net.group_labels(a).into_iter().find(|(_, x)| x.id == l).unwrap().1.steps.len(), 2, "a step under the new sync key");
    assert!(net.sync(a).served_opened().values().all(|m| !m.contains(&l)), "closed at the new sync key");
    let held = kept(&mut net, p, &l);
    net.item(a, g, g, "after");
    net.advance(61_000);
    assert_eq!(kept(&mut net, p, &l), held, "nothing after the rotation reaches p");
}

// spec/sync.md §10 (Admissible: the proof of the newest step `label.0` records), §5 Opens: after a rotation the reader's filter shows the new step's proof and no older step's,
// though the dialer holds both secrets; a sync holder then removed keeps its sync secrets, and
// the filter to it, a known actor still, shows no proof of any.
#[test]
fn only_the_newest_steps_proof_is_in_a_readers_filter_spec_sync_10() {
    let (mut net, a, p, g, l) = dialing_node(true);
    net.group(a, &[(p, Role::Read)], &[]);
    net.run();
    let at = net.tid(a);
    let rs = recipients_of(net.engine(a), &[(at, Role::Admin)]);
    rotation(net.engine(a), g, &rs, 61, false);
    net.run();
    net.advance(61_000);
    assert_eq!(net.group_labels(a).into_iter().find(|(_, x)| x.id == l).unwrap().1.steps.len(), 2, "a step under the new sync key");
    let proofs = |net: &mut Net, n: usize| -> Vec<[u8; 32]> {
        let held = net.engine(n).epochs(&g).map(|e| e.sync.held_newest_first().into_iter().map(|(_, s)| osis_crypto::label_role_seed(osis_crypto::LabelRole::Sync, s)).collect::<Vec<_>>()).unwrap_or_default();
        held.iter().map(osis_crypto::kdf::sync_proof).collect()
    };
    let shown = |net: &mut Net, v: &[[u8; 32]]| -> Vec<bool> {
        let mut q = crate::shared::dial_as(net, p, a, CHALLENGE);
        let filter = filter_of(&shared_of(&send(net, a, &mut q, Message::NoRecord { id: 1 << 31 })));
        v.iter().map(|v| filter.1.binary_search(&beacon_value(&beacon(v, &l.0, &r_of(&q)), filter.0)).is_ok()).collect()
    };
    let (held, new) = (proofs(&mut net, p), proofs(&mut net, a)[0]);
    assert!(held.len() > 1 && held.contains(&new), "p holds the new sync secret and an older one");
    let old: Vec<[u8; 32]> = held.into_iter().filter(|v| *v != new).collect();
    let mut all = vec![new];
    all.extend(&old);
    let got = shown(&mut net, &all);
    assert!(got[0], "the filter shows the newest step's proof");
    assert!(!got[1..].iter().any(|x| *x), "and no older step's: {got:?}");
    let pt = net.tid(p);
    remove_holder(net.engine(a), g, pt, &rs, 62);
    net.run();
    net.advance(61_000);
    let got = shown(&mut net, &all);
    assert!(!got.iter().any(|x| *x), "no proof to a removed sync holder: {got:?}");
}

// spec/sync.md §10 (Stream, a store's presence), §6: a reader judges a peer that cannot read L
// and dialed it as a source of L, as one it dialed: what it must not hold there is deleted there
// (a purge's deletes reach the dialer's store).
#[test]
fn a_reader_deletes_at_a_peer_that_dialed_it_spec_sync_10() {
    let (mut net, a, p, g, l) = dialing_node(true);
    let before = kept(&mut net, p, &l);
    let t = net.item(a, g, g, "doomed");
    net.advance(61_000);
    let doomed: BTreeSet<BlobId> = kept(&mut net, p, &l).difference(&before).copied().collect();
    assert!(!doomed.is_empty(), "the dialer pulled the write");
    use osis_schema::RawKey;
    let mut m = Mutation::new();
    m.set(t, &osis_schema::core_types::PURGE, &osis_base::WallMs(net.now())).unwrap();
    m.purge(osis_commit::PurgeItem::Aspect { tid: t, ak: osis_base::Ak::new(osis_schema::core_types::CREATED.ak()).unwrap() });
    net.engine(a).commit(m).unwrap().unwrap();
    net.feed(a, osis_node::sync::Event::Local);
    net.advance(61_000);
    let after = kept(&mut net, p, &l);
    assert!(!doomed.is_subset(&after), "the purged write left the dialer's store");
}

// spec/sync.md §10 (Pair key, Stream: a store's presence kept by the record): what a reader keeps
// of a peer that cannot read L and dialed it is kept by their record, so a reconnect resumes
// where it left: the dialer's store is not listed to the reader again.
#[test]
fn a_dialer_reconnecting_is_not_listed_again_spec_sync_10() {
    let (mut net, a, p, g, l) = dialing_node(true);
    net.item(a, g, g, "before");
    net.advance(61_000);
    assert!(net.sync(a).served_opened().values().any(|m| m.contains(&l)));
    net.tamper_link = Some((p, a));
    let seen = crate::reconnect::record_messages(&mut net);
    net.set_online(p, false);
    net.run();
    net.set_online(p, true);
    net.advance(120_000);
    assert!(net.sync(a).served_opened().values().any(|m| m.contains(&l)), "open again");
    let listed: usize = seen.borrow().iter().map(|(_, _, m)| match m {
        Message::PullReply(r) => r.events.iter().filter(|(x, e)| *x == l && matches!(e, Ev::Added { .. })).count(),
        Message::Stream(r) => r.events.iter().filter(|(x, e)| *x == l && matches!(e, Ev::Added { .. })).count(),
        _ => 0,
    }).sum();
    assert_eq!(listed, 0, "nothing the dialer holds is shown to the reader again");
    net.tamper = None;
    net.item(a, g, g, "after");
    net.advance(61_000);
    let mine: BTreeSet<BlobId> = net.sync(a).entries(&l).into_iter().map(|x| x.0).collect();
    assert!(mine.is_subset(&kept(&mut net, p, &l)), "and it pulls on");
}

// spec/sync.md §10 (Offer), §5 (Opens): a node that keeps L unread and holds only L's public
// sync key (no secret), proving an actor the reader knows, dials a reader of L and gets nothing
// of L: no open, no stream, no Hit of the reader's (its filter shows the key's beacon).
#[test]
fn a_dialer_holding_only_the_public_sync_key_pulls_nothing_spec_sync_10() {
    let (mut net, a, p, g, l) = dialing_node(false);
    let before = kept(&mut net, p, &l);
    let hits = net.sync(a).pass_stats().hits_sent;
    net.item(a, g, g, "not for the dialer");
    net.advance(61_000);
    assert!(!net.sync(a).served_opened().is_empty(), "p dialed a");
    assert!(net.sync(a).served_opened().values().all(|m| !m.contains(&l)), "L never opens where p dialed");
    assert_eq!(kept(&mut net, p, &l), before, "the dialer pulled nothing");
    assert_eq!(net.sync(a).pass_stats().hits_sent, hits, "the reader sent no Hit");
}

// spec/sync.md §10 (Admissible: a proof derives from its sync key's seed; Filter), model NetOpen
// `ON_proofpub`: a peer holding every public value of L (each step's keys and claim set) and
// proving an actor the reader knows dials a reader of L: no beacon those values give, the proof a
// public sync key would derive included, is in the reader's filter, which shows L's proof (to a
// holder of the sync secret). With the proof from the public key, it finds that proof.
#[test]
fn a_node_holding_only_the_public_keys_finds_no_proof_in_a_readers_filter_spec_sync_10() {
    let (mut net, a, p, g, l) = dialing_node(false);
    let mut q = crate::shared::dial_as(&mut net, p, a, CHALLENGE);
    let filter = filter_of(&shared_of(&send(&mut net, a, &mut q, Message::NoRecord { id: 1 << 31 })));
    let r = r_of(&q);
    let shows = |v: &[u8; 32]| filter.1.binary_search(&beacon_value(&beacon(v, &l.0, &r), filter.0)).is_ok();
    let gl = net.group_labels(a).into_iter().find(|(_, x)| x.id == l).unwrap().1;
    let mut public: Vec<[u8; 32]> = Vec::new();
    for (step, set) in gl.steps.values() {
        let k = &step.keys;
        let sync = k.sync.to_bytes();
        public.extend([sync, *osis_crypto::kdf::kdf(osis_crypto::kdf::SYNC_PROOF, &sync, b"").expose(), k.write.to_bytes(), k.delete.to_bytes(), k.deposit.to_bytes()]);
        public.extend(set.iter().flat_map(|s| s.claims.iter().copied()));
    }
    let found: Vec<&[u8; 32]> = public.iter().filter(|v| shows(v)).collect();
    assert!(found.is_empty(), "{} of {} public values found", found.len(), public.len());
    let seeds: Vec<osis_crypto::Secret32> = net.engine(a).epochs(&g).unwrap().sync.held_newest_first().into_iter().map(|(_, s)| osis_crypto::label_role_seed(osis_crypto::LabelRole::Sync, s)).collect();
    let proof = gl.steps.values().flat_map(|(st, _)| seeds.iter().filter(move |x| osis_crypto::SigningSecret::from_seed(x).verifying_key() == st.keys.sync)).map(osis_crypto::kdf::sync_proof).next().expect("a holds L's sync secret");
    assert!(shows(&proof), "the filter shows L's proof");
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

// spec/sync.md §7 (Role view first), §10 (Refused): a peer that cannot read L refuses an entry a
// writer logs for it under the peer's head (as it answers a stamp under keys it does not hold
// yet, code 1) and says so. The writer's deletes there wait on it no more, the claim deletes
// nothing of the writer's and status names the peer; once the peer's head moves (it gets the
// keys) the entry is offered again and taken.
#[test]
fn a_refused_entry_holds_no_delete_back_and_comes_again_once_the_head_moves_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "t");
    let u = net.item(a, g, g, "u");
    net.keep(a, u, &[("t:gone.0", PURGE)]);
    net.run();
    let l = net.label(a);
    let mut m = Mutation::new();
    m.set(u, &GONE, &s("old")).unwrap();
    let old = net.engine(a).commit(m).unwrap().unwrap();
    net.feed(a, osis_node::sync::Event::Local);
    net.run();
    net.advance(61_000);
    let of = |net: &mut Net, c: osis_base::CommitId| -> Vec<BlobId> { net.sync(a).entries(&l).into_iter().filter(|(_, k)| matches!(k, osis_node::sync::EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect() };
    let purged = of(&mut net, old);
    assert!(!purged.is_empty() && purged.iter().all(|id| net.host_ids(host, &l).contains(id)), "at the peer");
    // a's write never reaches the peer, which says it refused it
    let e = net.write(a, t, "e");
    net.lose_deposits.insert(e);
    net.feed(a, osis_node::sync::Event::Local);
    net.run();
    let refused = of(&mut net, e);
    assert!(!refused.is_empty() && refused.iter().all(|id| !net.host_ids(host, &l).contains(id)), "not at the peer");
    let events = refused.iter().map(|id| (l, Ev::Refused(*id, Code::REFUSED))).collect();
    net.host_inject(host, a, &Message::Stream(Box::new(osis_proto::msg::Stream { events, cursor: None, report: false, seq: 0 })));
    net.run();
    assert!(net.refused_at(a, &l), "status names the peer");
    net.restart(a, 9);
    net.run();
    assert!(net.refused_at(a, &l), "a restart keeps the refusal");
    // the purge's deletes go there
    let mut m = Mutation::new();
    m.set(u, &GONE, &s("new")).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.feed(a, osis_node::sync::Event::Local);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let held = net.host_ids(host, &l);
    assert!(purged.iter().all(|id| !held.contains(id)), "the purged body went from the peer");
    assert!(refused.iter().all(|id| !held.contains(id)), "the refused entry is not there");
    assert_eq!(of(&mut net, e), refused, "a keeps what the peer refused");
    assert_eq!(net.read(a, t), Some(s("e")));
    // the peer gets the keys: its head moves (a removal's rotation), and the entry comes again
    net.lose_deposits.clear();
    let tb = net.tid(b);
    let done = net.engine(a).demote(&g, &osis_node::flows::Demotion { holder: tb, new: None, retain: None }).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    assert_eq!(net.host_path(host, &l).len(), 2, "the peer's head moved");
    let held = net.host_ids(host, &l);
    assert!(refused.iter().all(|id| held.contains(id)), "the entry is taken there");
    assert!(!net.refused_at(a, &l), "status names the peer no more");
}

/// A Behind item on `l` by step `i`'s sync key, naming that step or (`named` false) none, signed
/// over the listener's challenge and key (or `sig` given).
fn behind_item(p: &Dialer, l: &Label, i: usize, named: bool) -> OfferItem {
    let k = &l.keys[i].sync;
    OfferItem::Behind { label: l.id, step: named.then(|| l.steps[i].id()), key: k.verifying_key().to_bytes(), sig: osis_crypto::sign_open(k, false, &l.id, &p.hello, &LISTENER) }
}

/// The answers to an Offer of `items`: each code and the grant carried, if any.
fn offer_answers(s: &mut Setup, items: Vec<OfferItem>) -> Vec<(Code, Option<osis_proto::msg::Grant>)> {
    let msgs = shared_of(&send(&mut s.net, s.b, &mut s.p, Message::Offer { id: 77, items }));
    let Some(Message::Shared { codes, .. }) = msgs.iter().find(|m| m.id() == 77) else { panic!("{msgs:?}") };
    codes.iter().map(|(c, _, g)| (*c, g.as_deref().cloned())).collect()
}

/// The answers to an Offer of `items`: each code and the steps carried, if any.
fn behind_answers(s: &mut Setup, items: Vec<OfferItem>) -> Vec<(Code, Option<Vec<osis_label::Step>>)> {
    offer_answers(s, items).into_iter().map(|(c, g)| (c, g.map(|g| { assert!(g.entry_box.is_none(), "steps alone"); g.steps }))).collect()
}

// spec/sync.md §5 (Behind), spec/wire.md §11.2 (Offer): a node keeping L unread answers a Behind
// item by a credential of a step on its path other than its head (its sync key, a claim of its
// held set) with the steps after it through the first under another sync key, each verifying
// under the one before; naming no step, the step after the newest bearing the sync key. One on the head, by a key that is no credential of the step
// (a claim naming no step), or with a signature over another connection's challenge is refused
// (14), one on a label not kept here answered 13, carrying nothing; nothing opens.
// spec/sync.md §5 (behind)
#[test]
fn a_behind_item_gets_its_steps_child_spec_sync_5() {
    let mut s = setup();
    for b in [0x61, 0x62] {
        s.l.rotate(b);
        let i = s.l.steps.len() - 1;
        request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, i));
    }
    let (p, l) = (&s.p, &s.l);
    let mut wrong_key = behind_item(p, l, 0, true);
    if let OfferItem::Behind { key, .. } = &mut wrong_key {
        *key = l.keys[2].sync.verifying_key().to_bytes();
    }
    let mut elsewhere = behind_item(p, l, 0, true);
    if let OfferItem::Behind { sig, .. } = &mut elsewhere {
        *sig = osis_crypto::sign_open(&l.keys[0].sync, false, &l.id, &[1; 32], &LISTENER);
    }
    let unknown = Label::new(0x52);
    // step 1's claim key of the reader its set lists
    let claim = l.steps[1].claim_key(&l.reader).unwrap();
    let by_claim = |step: Option<osis_label::StepId>| OfferItem::Behind { label: l.id, step, key: claim.verifying_key().to_bytes(), sig: osis_crypto::sign_open(&claim, false, &l.id, &p.hello, &LISTENER) };
    let items = vec![behind_item(p, l, 0, true), behind_item(p, l, 1, false), behind_item(p, l, 2, true), wrong_key, elsewhere, behind_item(p, &unknown, 0, true), by_claim(Some(l.steps[1].id())), by_claim(None)];
    let steps = l.steps.clone();
    let ans = behind_answers(&mut s, items);
    let l = &s.l;
    assert_eq!(ans[0], (Code::OK, Some(steps[1..2].to_vec())), "the step after step 0, the first under another sync key");
    steps[1].verify_child(&l.steps[0]).unwrap();
    steps[2].verify_child(&l.steps[1]).unwrap();
    assert_eq!(ans[1], (Code::OK, Some(steps[2..].to_vec())), "naming none: after the newest step bearing the key");
    for (i, a) in ans.iter().enumerate().take(5).skip(2) {
        assert_eq!(*a, (Code::NOT_ADMITTED, None), "item {i}");
    }
    assert_eq!(ans[5], (Code::UNKNOWN_LABEL, None), "a label not kept here");
    assert_eq!(ans[6], (Code::OK, Some(steps[2..].to_vec())), "by a claim of the named step's set");
    assert_eq!(ans[7], (Code::NOT_ADMITTED, None), "a claim names its step");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).is_empty(), "nothing opens");
    assert_eq!(s.net.sync(s.b).pass_stats().behind_answered, 3);
}

/// Dials node `b` again as the hand dialer, its shared set started (NoRecord).
fn redial(s: &mut Setup) {
    s.p = dial_with(&mut s.net, s.b, CHALLENGE);
    shared_of(&send(&mut s.net, s.b, &mut s.p, Message::NoRecord { id: 1 << 31 }));
}

// spec/sync.md §5 (Behind), notes/label-access.md (One sync key at a time): a reader removed at a
// rotation keeps its old sync secret, and no time ends a sync key as a credential: long past
// `ROLE_KEEP` (claim sets dropped), its Behind items, naming its step or none, learn the steps
// under its own sync key and the first rotation past them, and nothing after: not how many
// rotations followed, nor the head's sync key.
#[test]
fn a_removed_reader_learns_at_most_the_next_rotation_spec_sync_5() {
    let mut s = setup();
    // step 1 keeps step 0's sync key; steps 2-4 each rotate it (step 2 removes the reader)
    s.l.rotate_keeping_sync(0x41);
    request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, 1));
    for b in [0x61, 0x63, 0x65] {
        s.l.rotate(b);
        let i = s.l.steps.len() - 1;
        request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, i));
    }
    assert_eq!(s.l.steps[1].keys.sync, s.l.steps[0].keys.sync);
    s.net.advance(osis_base::format::ROLE_KEEP_MS + 61_000);
    redial(&mut s);
    let (p, l) = (&s.p, &s.l);
    let items = vec![behind_item(p, l, 0, true), behind_item(p, l, 0, false), behind_item(p, l, 1, true)];
    let steps = l.steps.clone();
    let ans = behind_answers(&mut s, items);
    assert_eq!(ans[0], (Code::OK, Some(steps[1..3].to_vec())), "naming step 0: its sync key's run and the first rotation");
    assert_eq!(ans[1], (Code::OK, Some(steps[2..3].to_vec())), "naming none: the first rotation alone");
    assert_eq!(ans[2], (Code::OK, Some(steps[2..3].to_vec())), "naming step 1: the first rotation alone");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).is_empty(), "nothing opens");
}

// spec/sync.md §5 (Behind), spec/permissions.md §7: a used or revoked link's key actor, named by
// the static entry of an old step's claim set, asking by a Behind item on that step learns the
// steps through the first rotation past it and nothing after; naming no step it is refused where
// the head does not list it (a Static item's grant), and once the old step's claim set is
// dropped (`ROLE_KEEP`) it is refused on the step too.
#[test]
fn a_revoked_link_learns_at_most_the_next_rotation_spec_sync_5() {
    let mut s = setup();
    for b in [0x61, 0x63, 0x65] {
        s.l.rotate(b);
        let i = s.l.steps.len() - 1;
        request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, i));
    }
    let by = |p: &Dialer, l: &Label, step: Option<osis_label::StepId>| OfferItem::Behind { label: l.id, step, key: l.key_actor.verifying_key().to_bytes(), sig: osis_crypto::sign_open(&l.key_actor, false, &l.id, &p.hello, &LISTENER) };
    let (p, l) = (&s.p, &s.l);
    let items = vec![by(p, l, Some(l.steps[0].id())), by(p, l, Some(l.steps[1].id()))];
    let steps = l.steps.clone();
    let ans = offer_answers(&mut s, items);
    let got = |a: &(Code, Option<osis_proto::msg::Grant>)| (a.0, a.1.as_ref().map(|g| (g.entry_box.is_none(), g.steps.clone())));
    assert_eq!(got(&ans[0]), (Code::OK, Some((true, steps[1..2].to_vec()))), "on step 0: step 1 alone");
    assert_eq!(got(&ans[1]), (Code::OK, Some((true, steps[2..3].to_vec()))), "on step 1: step 2 alone");
    s.net.advance(osis_base::format::ROLE_KEEP_MS + 61_000);
    redial(&mut s);
    let (p, l) = (&s.p, &s.l);
    let items = vec![by(p, l, Some(l.steps[0].id()))];
    let ans = offer_answers(&mut s, items);
    assert_eq!(got(&ans[0]), (Code::NOT_ADMITTED, None), "its claim set dropped: nothing");
}

// spec/sync.md §5 (Behind), notes/flow-control.md (Hub stall bounds): an Offer of 1024 Behind
// items each naming the genesis step by its sync key reads one step per item (the first under
// another sync key) whatever the number of steps after it, and every item is answered.
#[test]
fn behind_items_on_genesis_read_a_step_each_spec_sync_5() {
    let reads = |rotations: u8| {
        let mut s = setup();
        for k in 0..rotations {
            s.l.rotate(0x61 + 2 * k);
            let i = s.l.steps.len() - 1;
            request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, i));
        }
        let items = (0..1024).map(|_| behind_item(&s.p, &s.l, 0, true)).collect();
        let before = s.net.sync(s.b).pass_stats();
        let ans = behind_answers(&mut s, items);
        let after = s.net.sync(s.b).pass_stats();
        assert!(ans.iter().all(|a| a.0 == Code::OK && a.1.as_ref().is_some_and(|x| x.len() == 1)), "{rotations} rotations: one step each");
        (after.behind_steps - before.behind_steps, after.behind_answered - before.behind_answered)
    };
    assert_eq!(reads(2), (1024, 1024));
    assert_eq!(reads(12), (1024, 1024), "flat in the steps past genesis");
}

// spec/sync.md §5 (Behind), spec/wire.md §11.2 (Offer): the Behind answers of one Offer carry at
// most ⌊REPLY_BUDGET / 326⌋ steps: the item reaching the bound gets the steps it read, the items
// after it 4 (refused for now), and a later Offer is answered.
#[test]
fn an_offers_behind_answers_stop_at_the_step_bound_spec_sync_5() {
    let mut s = setup();
    // 29 steps under the genesis sync key: 1024 items on genesis would read 29 696
    for k in 0..29u8 {
        s.l.rotate_keeping_sync(0x61 + 2 * k);
        let i = s.l.steps.len() - 1;
        request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, i));
    }
    let run = s.l.steps.len() - 1;
    let bound = osis_proto::session::REPLY_BUDGET / osis_proto::msg::MAX_STEP_WIRE;
    assert!(1024 * run > bound, "past the bound");
    let items = (0..1024).map(|_| behind_item(&s.p, &s.l, 0, true)).collect();
    let before = s.net.sync(s.b).pass_stats().behind_steps;
    let ans = behind_answers(&mut s, items);
    assert_eq!(s.net.sync(s.b).pass_stats().behind_steps - before, bound as u64, "the bound read");
    let (whole, part) = (bound / run, bound % run);
    assert!(part > 0, "an item reaches the bound part way");
    let steps = s.l.steps.clone();
    for (i, a) in ans.iter().enumerate() {
        match i {
            i if i < whole => assert_eq!(a, &(Code::OK, Some(steps[1..].to_vec())), "item {i}: the run"),
            i if i == whole => assert_eq!(a, &(Code::OK, Some(steps[1..=part].to_vec())), "item {i}: the steps read"),
            i => assert_eq!(a, &(Code::RATE_LIMITED, None), "item {i}: refused for now"),
        }
    }
    let item = behind_item(&s.p, &s.l, 0, true);
    let ans = behind_answers(&mut s, vec![item]);
    assert_eq!(ans, vec![(Code::OK, Some(steps[1..].to_vec()))], "a later Offer is answered");
}

// spec/sync.md §5 (Behind), spec/wire.md §11.2 (Offer): a Behind item by a key actor's signing
// key, naming no step, at a node keeping L unread is answered with the head's entry box for its
// static entry and the path, as a Static item's Hit is, when the head's claim set lists the
// entry; naming a step whose set lists it, with the steps after it alone; a key actor the head
// does not list is refused (14); nothing opens.
// spec/sync.md §5 (behind static)
#[test]
fn a_behind_item_by_a_static_entry_gets_the_heads_box_spec_sync_5() {
    let mut s = setup();
    s.l.rotate(0x61);
    request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, 1));
    let by = |p: &Dialer, l: &Label, k: &osis_crypto::SigningSecret, step: Option<osis_label::StepId>| OfferItem::Behind { label: l.id, step, key: k.verifying_key().to_bytes(), sig: osis_crypto::sign_open(k, false, &l.id, &p.hello, &LISTENER) };
    let stranger = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([0x77; 32]));
    let (p, l) = (&s.p, &s.l);
    let items = vec![by(p, l, &l.key_actor, None), by(p, l, &stranger, None), by(p, l, &l.key_actor, Some(l.steps[0].id()))];
    let (steps, set) = (l.steps.clone(), l.sets[1].clone());
    let ans = offer_answers(&mut s, items);
    let entry = osis_crypto::static_entry(&s.l.id, &s.l.key_actor.verifying_key());
    let g = ans[0].1.as_ref().expect("a grant");
    assert_eq!((ans[0].0, g.steps.clone(), g.entry_box.as_ref()), (Code::OK, steps, set.entries.get(&entry)), "the head's box and the path");
    assert_eq!(ans[1], (Code::NOT_ADMITTED, None), "not listed");
    let child = ans[2].1.as_ref().expect("a child");
    assert_eq!((ans[2].0, child.entry_box.is_none(), child.steps.clone()), (Code::OK, true, vec![s.l.steps[1].clone()]), "naming a step it lists: the steps after it");
    assert!(s.net.sync(s.b).shared_members(s.p.conn).is_empty(), "nothing opens");
}

// spec/sync.md §5 (Delete): a node keeping L unread takes a Delete of it only on a connection
// where L opened by a Hit on its head's sync key (or a static entry), and while the head bears
// that key: before the open, and after a step with another sync key, it is refused whole (8)
// spec/sync.md §5 (delete opened)
#[test]
fn a_delete_is_taken_only_under_an_open_spec_sync_5() {
    let mut s = setup();
    let l = s.l.id;
    let delete = |s: &mut Setup, n: u64| {
        let item = DeleteItem::sign(&s.l.head_keys().delete, &l, osis_label::blob_id(&blob(n)));
        request(&mut s.net, s.b, &mut s.p, |id| Message::Delete { id, label: l, items: vec![item] })
    };
    let refused = |ev: &[Message]| ev.iter().any(|e| matches!(e, Message::Error { code: Code::NOT_OPENED, .. }));
    let ev = delete(&mut s, 1);
    assert!(refused(&ev), "not opened: {ev:?}");
    let held = |s: &mut Setup, n: u64| osis_proto::LabelStore::entry(&*s.net.sync(s.b).hub_store().lock().unwrap(), &l, &osis_label::blob_id(&blob(n))).unwrap().is_some();
    assert!(held(&mut s, 1), "kept");
    opened(&mut s);
    let ev = delete(&mut s, 1);
    assert!(ev.iter().any(|e| matches!(e, Message::Status { codes, .. } if codes == &[Code::OK])), "{ev:?}");
    assert!(!held(&mut s, 1), "deleted");
    // a step with another sync key ends the open
    s.l.rotate(0x61);
    request(&mut s.net, s.b, &mut s.p, |id| s.l.register(id, 1));
    let ev = delete(&mut s, 2);
    assert!(refused(&ev), "the open ended with the head's sync key: {ev:?}");
}

/// Cuts node `n` off peer `s` (no dial reaches it) until `rejoin`.
fn cut(net: &mut Net, n: usize, s: usize) {
    net.blocked.insert((n, s));
    net.drop_link(n, s);
}

fn rejoin(net: &mut Net, n: usize, s: usize) {
    net.blocked.remove(&(n, s));
}

// spec/sync.md §5 (Register: relayable by any node), issues/sync-rewrite.md 3h2 (Stale head): a
// rotation while a peer that cannot read L is away leaves it on the old head (the child step
// registered at another); a reader that is no admin, holding the recorded child, moves it there
// by its walk (L opens at the old step it still shows) and registration; a reader added after
// the rotation, holding the new epoch alone, then reads L through that peer with every other
// node offline.
#[test]
fn a_peer_on_an_older_head_is_moved_by_any_reader_spec_sync_5() {
    let mut net = Net::new();
    let s = net.add_host();
    let s2 = net.add_host();
    let a = net.node(1, &[s2]);
    let b = net.node(2, &[s2]);
    let x = net.node(3, &[s2]);
    // c reaches no peer until the end (no link of it is ever dropped)
    let c = net.node(4, &[]);
    net.blocked.extend([(c, s), (c, s2)]);
    let g = net.group(a, &[(b, Role::Write), (x, Role::Read)], &[s, s2]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(b, t), Some(net::s("before")));
    let l = net.label(a);
    assert_eq!(net.host_path(s, &l).len(), 1);
    for n in [a, b] {
        cut(&mut net, n, s);
    }
    // the rotation's step registered at s2 alone; c granted after it
    let (at, bt, xt, ct_) = (net.tid(a), net.tid(b), net.tid(x), net.tid(c));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Write)]);
    remove_holder(e, g, xt, &rs, 45);
    net.run();
    net.advance(61_000);
    assert_eq!(net.host_path(s2, &l).len(), 2, "a child registered at s2");
    // c granted after the rotation, the grant handed over directly, then a's write
    net.pair(c, a);
    net.grant(a, g, ct_, Role::Read);
    net.run();
    net.pair(a, c);
    assert!(net.engine(c).role_on(&g).is_some(), "c holds g");
    net.write(a, t, "after");
    net.run();
    net.advance(61_000);
    assert_eq!(net.read(b, t), Some(net::s("after")));
    assert_eq!(net.host_path(s, &l).len(), 1, "s missed the step");
    net.set_online(a, false);
    // b, a writer and no admin, moves s to the recorded child
    assert!(net.engine(b).role_on(&g) < Some(Role::Admin));
    cut(&mut net, b, s2);
    rejoin(&mut net, b, s);
    for _ in 0..3 {
        net.advance(61_000);
    }
    assert_eq!(net.host_path(s, &l).len(), 2, "b registered the recorded child");
    net.set_online(b, false);
    assert_ne!(net.read(c, t), Some(net::s("after")), "c has not read it yet");
    net.blocked.remove(&(c, s));
    for _ in 0..3 {
        net.advance(61_000);
    }
    assert_eq!(net.read(c, t), Some(net::s("after")), "c reads through s alone: {:?}", net.sync(c).label_status());
}

// spec/sync.md §5 (Opens, Behind), notes/node-sync.md (Label states): two admins' sibling steps
// share their keys, so a reader's Hit by that sync key opens at the sibling the peer holds while
// its walk found its own branch's step, which has a recorded child. The open head is doubted and
// walked back to the peer's path by Behind items: the reader sends at most the one refused
// Register, then settles open at the peer's step, sending nothing more.
#[test]
fn a_reader_opened_at_a_sibling_registers_once_spec_sync_5() {
    let mut net = Net::new();
    let s = net.add_host();
    let s2 = net.add_host();
    let a = net.node(1, &[s, s2]);
    let b = net.node(2, &[s, s2]);
    let c = net.node(3, &[s, s2]);
    let x = net.node(4, &[s2]);
    // c knows no head of s: it opens where its walk finds a credential shown; x relays nothing
    // between s and s2
    net.blocked.extend([(c, s), (x, s)]);
    let g = net.group(a, &[(b, Role::Admin), (c, Role::Read), (x, Role::Read)], &[s, s2]);
    let t = net.item(a, g, g, "item");
    net.run();
    assert_eq!(net.read(c, t), Some(net::s("item")));
    let l = net.label(a);
    let genesis = net.host_path(s, &l);
    assert_eq!(genesis.len(), 1);
    // b reaches s alone, a and c s2 alone: each admin's child of the genesis, same keys
    cut(&mut net, b, s2);
    cut(&mut net, a, s);
    let g0 = genesis[0].id();
    let theirs = net.engine(b).issue_step(&g, &l, &g0, true).unwrap().0.unwrap().0;
    let ours = net.engine(a).issue_step(&g, &l, &g0, true).unwrap().0.unwrap().0;
    assert_eq!((theirs.keys, theirs.prev), (ours.keys, ours.prev), "siblings sharing their keys");
    assert_ne!(theirs.id(), ours.id());
    net.run();
    net.advance(61_000);
    assert_eq!(net.host_path(s, &l).last().map(|x| x.id()), Some(theirs.id()));
    assert_eq!(net.host_path(s2, &l).last().map(|x| x.id()), Some(ours.id()));
    // b away: no admin moves s past `theirs`
    net.set_online(b, false);
    // a rotation on a's branch: c records its child of `ours`, under another sync key
    let (at, bt, ct_, xt) = (net.tid(a), net.tid(b), net.tid(c), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Admin), (ct_, Role::Read)]);
    remove_holder(e, g, xt, &rs, 45);
    net.run();
    net.advance(61_000);
    let path = net.host_path(s2, &l);
    assert_eq!(path.len(), 3, "the child registered at s2");
    assert_ne!(path[2].keys.sync, ours.keys.sync);
    // c moves to s: its walk shows `ours` by the shared sync key, and s holds `theirs`
    cut(&mut net, c, s2);
    rejoin(&mut net, c, s);
    net.diagnostics(c);
    for _ in 0..3 {
        net.advance(61_000);
    }
    let refused = |d: &[String]| d.iter().filter(|x| x.contains("step refused")).count();
    let d = net.diagnostics(c);
    assert!(refused(&d) <= 1, "one Register at most: {d:?}");
    let conn = net.conn_to(c, s).expect("connected");
    assert!(net.sync(c).shared_members(conn).contains(&l), "L open at s");
    assert_eq!(net.host_path(s, &l).last().map(|x| x.id()), Some(theirs.id()), "s keeps its branch");
    // settled: nothing more goes
    let behind = net.sync(c).pass_stats().behind_sent;
    for _ in 0..3 {
        net.advance(61_000);
    }
    let d = net.diagnostics(c);
    assert_eq!(refused(&d), 0, "{d:?}");
    assert_eq!(net.sync(c).pass_stats().behind_sent, behind, "no Behind item");
    assert!(net.sync(c).shared_members(conn).contains(&l));
}

// spec/sync.md §5 (Walk): a node holding the sync key of the peer's head opens L there whatever
// steps it recorded. While reader c is away it is removed (a step under a sync key it never
// gets), the label rotates again, and c is granted anew; it learns the newest epoch's sync and
// read secrets alone (as an inbox grant would bring them). Its `label.0` ends before both steps (it comes only by L),
// and a Behind walk from its newest step stops at the removal's step, which it holds no
// credential of: its walk tests the held sync key no recorded step bears, L opens, and c reads.
#[test]
fn a_node_holding_the_heads_sync_key_opens_past_steps_it_lacks_spec_sync_5() {
    let (mut net, s, [a, c]) = hosted_nodes::<2>();
    let g = net.group(a, &[(c, Role::Read)], &[s]);
    net.item(a, g, g, "item");
    net.run();
    let l = net.label(a);
    let recorded = net.host_path(s, &l).len();
    net.set_online(c, false);
    let (at, ct_) = (net.tid(a), net.tid(c));
    let rs = recipients_of(net.engine(a), &[(at, Role::Admin)]);
    remove_holder(net.engine(a), g, ct_, &rs, 51);
    net.run();
    net.advance(61_000);
    rotation(net.engine(a), g, &rs, 52, false);
    net.run();
    net.advance(61_000);
    net.grant(a, g, ct_, Role::Read);
    let t = net.item(a, g, g, "after");
    net.run();
    net.advance(61_000);
    assert_eq!(net.host_path(s, &l).len(), recorded + 2, "two steps c never recorded");
    for r in [Role::Sync, Role::Read] {
        let ep = net.engine(a).epochs(&g).unwrap();
        let ep = if r == Role::Sync { &ep.sync } else { &ep.read };
        let (e, secret) = ep.held_newest_first().into_iter().next().map(|(e, x)| (e, x.clone())).unwrap();
        net.engine(c).learn_secret(&g, r, e, secret).unwrap();
    }
    net.set_online(c, true);
    for _ in 0..3 {
        net.run();
        net.advance(61_000);
    }
    let conn = net.conn_to(c, s).expect("connected");
    assert!(net.sync(c).shared_members(conn).contains(&l), "L open at s: {:?}", net.sync(c).describe());
    assert_eq!(net.read(c, t), Some(net::s("after")));
}

// spec/sync.md §5 (Register: relayable by any node), issues/sync-rewrite.md 3h2 (Stale head): a
// peer listed for L (in `label.0`) that lacks L entirely gets the recorded path, genesis first,
// from a reader that is no admin: its walk finds no credential shown, a Behind item on its
// newest step is refused there, and it registers the path; L then opens there at its head.
#[test]
fn a_listed_peer_without_l_gets_the_recorded_path_spec_sync_5() {
    let mut net = Net::new();
    let s = net.add_host();
    let s2 = net.add_host();
    let a = net.node(1, &[s]);
    let b = net.node(2, &[s]);
    let x = net.node(3, &[s]);
    // nobody reaches s2 yet
    for n in [a, b, x] {
        net.blocked.insert((n, s2));
    }
    let g = net.group(a, &[(b, Role::Read), (x, Role::Read)], &[s, s2]);
    let t = net.item(a, g, g, "item");
    let (at, bt, xt) = (net.tid(a), net.tid(b), net.tid(x));
    let e = net.engine(a);
    let rs = recipients_of(e, &[(at, Role::Admin), (bt, Role::Read)]);
    remove_holder(e, g, xt, &rs, 45);
    net.run();
    net.advance(61_000);
    let l = net.label(a);
    let path = net.host_path(s, &l);
    assert_eq!(path.len(), 2, "two steps recorded and registered at s");
    assert!(net.host_path(s2, &l).is_empty(), "s2 lacks L");
    assert_eq!(net.read(b, t), Some(net::s("item")));
    assert!(net.engine(b).role_on(&g) < Some(Role::Admin));
    net.set_online(a, false);
    let behind = net.sync(b).pass_stats().behind_sent;
    net.blocked.remove(&(b, s2));
    for _ in 0..3 {
        net.advance(61_000);
    }
    assert_eq!(net.host_path(s2, &l), path, "b registered the recorded path at s2");
    assert_eq!(net.sync(b).pass_stats().behind_sent - behind, 1, "one Behind item, refused");
    let conn = net.conn_to(b, s2).expect("connected");
    assert!(net.sync(b).shared_members(conn).contains(&l), "L open at s2");
}

// spec/sync.md §10 (Shared set), issues/sync-rewrite.md 3h2 (Stale head: found only at a peer
// listed for L): a reader connected to a peer that keeps nothing of L and is not listed for it
// registers nothing of L there, sends it no Behind item, and opens nothing.
#[test]
fn an_unlisted_peer_gets_no_register_spec_sync_10() {
    let mut net = Net::new();
    let s = net.add_host();
    let s2 = net.add_host();
    let a = net.node(1, &[s]);
    let b = net.node(2, &[s, s2]);
    let g = net.group(a, &[(b, Role::Read)], &[s]);
    let t = net.item(a, g, g, "item");
    net.run();
    let behind = net.sync(b).pass_stats().behind_sent;
    for _ in 0..3 {
        net.advance(61_000);
    }
    assert_eq!(net.read(b, t), Some(net::s("item")));
    let l = net.label(a);
    let conn = net.conn_to(b, s2).expect("b keeps a connection to s2");
    assert!(net.host_path(s2, &l).is_empty(), "no Register of L reached s2");
    assert_eq!(net.sync(b).pass_stats().behind_sent, behind, "no Behind item");
    assert!(!net.sync(b).shared_members(conn).contains(&l));
}
