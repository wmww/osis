#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! The engine's facade for sync (`osis_engine::sync`, notes/sync-facade.md): each call against
//! the spec rule it serves, over `LocalPeer` (commits and inbox blobs carried by hand).

use crate::common::{REG, s};
use crate::flows::{edge_of, people, spread, spread_sealed, thing_of};
use osis_base::{Ak, Role, Tid};
use osis_crypto::SeededRng;
use osis_engine::flows::Demotion;
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::{Holding, Taken, ThingSync};
use osis_engine::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Peer 0 grants peer 1's account `role` on a new thing of its own; the inbox blob of the grant.
fn granted(role: Role) -> (LocalPeer, Tid, Tid, osis_base::CommitId, Vec<u8>) {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(role)).unwrap();
    let g = *done.commits.last().unwrap();
    let blob = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).expect("an inbox blob to peer 1").1;
    (lp, t, ps[1], g, blob)
}

// spec/sync-set.md §1 (the first node: the commit creating D carries the synced group and the
// `synced^.0` entry), §2 (sync set: D read, a plain item of the closure has no sync ID of its own).
#[test]
fn account_has_a_synced_group_and_reads_home_spec_sync_set_1() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let synced = e.get_typed(&d, &ct::SYNCED).unwrap().expect("synced^.0 on D");
    let g = *synced.get(&e.tid()).expect("this node's synced group");
    assert!(e.closure(&g).contains(&d), "D under the synced group");
    let home = e.home_sync_id(&d).unwrap().unwrap();
    assert_eq!(e.thing_sync(&d).unwrap(), ThingSync::Read(vec![home]));
    assert_eq!(e.sync_set().unwrap().ids.get(&home), Some(&(d, Holding::Read)));
    assert_eq!(e.thing_sync(&g).unwrap(), ThingSync::Plain, "the synced group is plain");
    assert_eq!(e.sync_owner(&home).unwrap(), Some(d));
}

// spec/sync-ids.md §3 (claim key: a listed reader derives it from its own key and the step key),
// §4 (owner), spec/sync-opens.md §4 (admissible: read secrets at a current epoch, the head's sync
// proof).
#[test]
fn read_credentials_and_claim_key_spec_sync_ids_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let home = e.home_sync_id(&d).unwrap().unwrap();
    let ids = e.sync_ids(&d).unwrap();
    assert_eq!(ids.len(), 1);
    assert!(!ids[0].hint);
    let head = ids[0].path.steps.last().unwrap().0.clone();
    head.verify_genesis().unwrap();
    let rc = e.read_credentials(&home).unwrap().expect("a reader of home");
    assert_eq!(rc.head.as_ref().map(|s| s.id()), Some(head.id()));
    assert!(!rc.read_secrets.is_empty(), "a current read secret");
    assert_eq!(rc.proofs.first().map(|p| p.0), Some(head.id()), "the head's sync proof first");
    assert_ne!(rc.roster, [0; 32]);
    let ck = e.claim_key(&home, &head.id()).unwrap().expect("this node is listed at genesis");
    let (_, Some(claims)) = &ids[0].path.steps[0] else { panic!("claim set held") };
    assert!(claims.claims.contains(&ck.verifying_key().to_bytes()));
}

// spec/sync-opens.md §4: the roster digest moves with a grant (no rotation needed).
#[test]
fn roster_digest_moves_with_a_grant_spec_sync_opens_4() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    // the thing in the synced group's closure: read here
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let before = lp.peers[0].engine.read_credentials(&s).unwrap().expect("read").roster;
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let after = lp.peers[0].engine.read_credentials(&s).unwrap().unwrap().roster;
    assert_ne!(before, after);
}

fn add_item(lp: &mut LocalPeer, i: usize, g: Tid, t: Tid) {
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap();
}

// spec/data-model.md §9 (`caps^.0`: on the node thing), spec/sync-ids.md §5 (caps).
#[test]
fn caps_read_from_the_node_spec_sync_ids_5() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    assert!(e.caps().unwrap().things.is_empty(), "absent: the defaults");
    let me = e.tid();
    let t = Tid::from_bytes([9; 15]);
    let mut m = Mutation::new();
    m.set(me, &ct::CAPS, &ct::Caps { policy: [("entries".to_string(), 7)].into(), things: [(t, ct::ThingCaps { entries: 3, bytes: 4 })].into() }).unwrap();
    e.commit(m).unwrap().unwrap();
    let c = e.caps().unwrap();
    assert_eq!(c.policy.get("entries"), Some(&7));
    assert_eq!(c.things.get(&t).map(|x| (x.entries, x.bytes)), Some((3, 4)));
}

// spec/sync-inbox.md §2 Taking (a boxes payload is never taken and applies nothing), spec/sync.md
// §3 (Sync record: a sync ID kept only by an accept): a sync grant is held as an offer, with no
// sync record and no engine state of the thing, and is an invitation.
#[test]
fn a_sync_grant_is_held_as_an_offer_spec_sync_inbox_2() {
    let (mut lp, t, _, g, blob) = granted(Role::Sync);
    let e = &mut lp.peers[1].engine;
    let o = e.take_inbox_blob(&blob, false).unwrap().expect("opens");
    assert_eq!((o.commit, o.taken), (None, Taken::Offered));
    assert!(o.hints.is_empty() && o.dial.is_none());
    assert!(e.sync_record(&t).unwrap().is_none(), "nothing kept before an accept");
    assert!(e.core.ix.commits.get(&g).is_none(), "the grant is not applied");
    assert!(e.epochs(&t).is_none(), "no engine state of the thing");
    let inv = e.invitations().unwrap();
    assert!(inv.iter().any(|i| i.thing == t && i.role == Role::Sync && !i.taken), "an invitation: {inv:?}");
    assert_eq!(e.take_inbox_blob(&blob, true).unwrap().unwrap().taken, Taken::Offered, "a stamp vouches for no boxes payload");
}

/// The aspects of the parts an inbox blob's commit carries to peer `to`, with the header's
/// things and the payload's chain and records counts.
fn inbox_parts(lp: &mut LocalPeer, to: usize, blob: &[u8]) -> (BTreeSet<String>, BTreeSet<Tid>, usize) {
    let Some(osis_label::Inbox::Payload(p)) = lp.peers[to].engine.open_inbox_blob(blob) else { panic!("an inbox payload") };
    let (plain, rest) = p.split();
    let c = osis_commit::CommitBlob::decode(&plain).unwrap();
    let aks = c.parts.iter().map(|p| c.header.aspects[p.ai].ak.as_str().to_string()).collect();
    let tids = c.header.aspects.iter().map(|a| a.tid).collect();
    (aks, tids, rest.chain.len() + rest.records.len())
}

/// The boxes payload of an inbox blob to peer `to`, and its canonical bytes.
fn boxes_of(lp: &mut LocalPeer, to: usize, blob: &[u8]) -> (osis_label::BoxesPayload, Vec<u8>) {
    let Some(osis_label::Inbox::Boxes(p)) = lp.peers[to].engine.open_inbox_blob(blob) else { panic!("a boxes payload") };
    let bytes = osis_base::encode(&p.to_value());
    (p, bytes)
}

fn names(bytes: &[u8], t: &Tid) -> bool {
    bytes.windows(15).any(|w| w == t.as_bytes())
}

/// The inbox blob `done` owes `h`.
fn blob_to(lp: &mut LocalPeer, done: &osis_engine::flows::Done, h: Tid) -> Vec<u8> {
    lp.inbox_blobs(0, done).unwrap().into_iter().find(|(x, _)| *x == h).expect("an inbox blob").1
}

// spec/sync-inbox.md §2 (What it carries about G: to a holder of sync alone, a boxes payload),
// spec/wire.md §9 (boxes payload: signed only on a grant), spec/sync-ids.md §2 (What a sync holder
// learns: of the thing its tid alone, never its roster, no rotator): a grant carries the holder's
// own boxes, signed by its granter; a rotation carries the holder's boxes, no author; neither names
// another holder; a grant sent after its holder was removed carries no more.
#[test]
fn a_sync_holder_is_sent_its_boxes_only_spec_sync_inbox_2() {
    let (mut lp, ps) = people(6);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[3], &edge_of(Role::Sync)).unwrap();
    lp.peers[0].engine.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    let blob = blob_to(&mut lp, &done, ps[1]);
    let (p, bytes) = boxes_of(&mut lp, 1, &blob);
    assert_eq!(p.things.iter().map(|x| x.tid).collect::<Vec<_>>(), vec![t], "the thing's tid alone");
    assert!(p.things[0].boxes.iter().all(|(r, _, _)| *r == Role::Sync));
    assert_eq!(p.grant.as_ref().map(|g| g.author), Some(ps[0]), "a grant names its granter");
    assert!(!names(&bytes, &ps[2]) && !names(&bytes, &ps[3]), "no other holder");
    // a rotation (removing a reader) boxing every holder at the new sync epoch
    let done = lp.peers[0].engine.grant(&t, &ps[4], &edge_of(Role::Read)).unwrap();
    let to_reader = blob_to(&mut lp, &done, ps[4]);
    assert!(inbox_parts(&mut lp, 4, &to_reader).0.contains("roles.0"), "a reader gets the commit");
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: ps[4], new: None, retain: None }).unwrap();
    let rot = blob_to(&mut lp, &done, ps[1]);
    let (p, bytes) = boxes_of(&mut lp, 1, &rot);
    assert!(p.grant.is_none(), "a rotation names no author");
    assert!(![ps[0], ps[2], ps[3], ps[4]].iter().any(|x| names(&bytes, x)), "the rotation names nobody");
    // removed before its grant went: still its boxes alone
    let done = lp.peers[0].engine.grant(&t, &ps[5], &edge_of(Role::Sync)).unwrap();
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[5], new: None, retain: None }).unwrap();
    let late = blob_to(&mut lp, &done, ps[5]);
    let (_, bytes) = boxes_of(&mut lp, 5, &late);
    assert!(![ps[1], ps[2], ps[3]].iter().any(|x| names(&bytes, x)));
}

/// `p` sealed to peer `to`'s account by hand.
fn boxes_by_hand(lp: &mut LocalPeer, to: usize, p: &osis_label::BoxesPayload) -> Vec<u8> {
    let e = &mut lp.peers[to].engine;
    let a = e.me();
    let Some(ct::KemKey::X25519MlKem768(k)) = e.get_typed(&a, &ct::KEYS).unwrap().and_then(|k| k.key) else { panic!("the account's KEM key") };
    let kem = osis_crypto::KemPublicKey::from_slice(&k).unwrap();
    let now = e.now();
    osis_label::seal_boxes_payload(&a, &kem, p, now, &mut SeededRng::from_u64(12)).unwrap()
}

/// The user's accept of `t` as the product writes it (`Engine::write`): filed in D, the synced
/// group's closure, as a subgroup.
pub(crate) fn accept(lp: &mut LocalPeer, i: usize, t: Tid) {
    let (_, d) = lp.peers[i].engine.account().unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[i].engine.write(m).unwrap().unwrap();
}

/// The sync keys of `r`'s held secrets.
fn keys_of(r: &osis_engine::sync::SyncRecord) -> BTreeSet<[u8; 32]> {
    r.secrets.values().map(|x| osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, x).verifying_key().to_bytes()).collect()
}

/// Peer 1 offered a sync grant on a thing of peer 0's and accepted it, its secret recorded as a
/// step bearing it would: (peers, thing, peer 1's account, the thing's sync ID).
fn kept() -> (LocalPeer, Vec<Tid>, Tid, osis_base::SyncId) {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let blob = blob_to(&mut lp, &done, ps[1]);
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap();
    accept(&mut lp, 1, t);
    let e = &mut lp.peers[1].engine;
    let r = e.sync_record(&t).unwrap().expect("kept");
    assert!(e.record_borne(&t, &keys_of(&r)).unwrap());
    (lp, ps, t, s)
}

// spec/sync.md §3 (A kept sync ID: added by an accept, the sync IDs every held boxes payload
// offering the thing names), spec/sync-set.md §4 (Accepting), spec/sync-inbox.md §2 (Taking: a
// boxes payload's dial hint dialed once its sync IDs are kept): once accepted, the offered sync
// ID is kept, its dial hint given, the thing kept unread under it with the offer's secret held
// (not recorded), and it is no invitation; the record lasts the offer's expiry and a restart.
#[test]
fn an_accept_keeps_the_offered_sync_id_spec_sync_3() {
    let (mut lp, t, _, _, blob) = granted(Role::Sync);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    // the sender's dial hint: dialed only once its sync ID is kept (spec/sync-inbox.md §2)
    let (mut p, _) = boxes_of(&mut lp, 1, &blob);
    p.dial = Some(osis_label::DialHint { dialable: [0x44; 32], urls: vec!["quic://granter".into()] });
    let blob = boxes_by_hand(&mut lp, 1, &p);
    assert!(lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap().unwrap().dial.is_none(), "not kept: no dial hint");
    accept(&mut lp, 1, t);
    assert_eq!(lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap().unwrap().dial, p.dial, "kept: its dial hint");
    let e = &mut lp.peers[1].engine;
    let r = e.sync_record(&t).unwrap().expect("kept");
    assert_eq!(r.sync_ids, vec![s]);
    assert!(!r.secrets.is_empty() && r.recorded.is_empty(), "held from the offer, not recorded yet");
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Unread(vec![s]));
    assert!(!e.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken), "no longer an invitation");
    let (_, d) = e.account().unwrap().unwrap();
    assert!(e.get_typed(&d, &ct::KEPT).unwrap().is_some_and(|k| k.get(&t).is_some_and(|x| x.ids.contains(&s))), "in kept^.0 on D");
    lp.advance(osis_base::format::INBOX_LIFETIME_MS + 1);
    lp.peers[1].tick().unwrap();
    let r = lp.peers[1].engine.sync_record(&t).unwrap().expect("the record outlives the offer");
    assert!(r.secrets.is_empty(), "the offer's secret went with it: never recorded");
    lp.peers[1].restart(5).unwrap();
    assert_eq!(lp.peers[1].engine.sync_record(&t).unwrap().unwrap().sync_ids, vec![s], "a restart changes nothing");
}

// spec/sync.md §3 (A recorded secret: only once a step on the node's own path bears its sync key):
// a held secret is recorded by a borne key and only so; a key no held secret derives records
// nothing; with no kept sync ID nothing is recorded. NetTrust `UN_any` (unconfirmed) fails this.
#[test]
fn a_secret_is_recorded_only_borne_spec_sync_3() {
    let (mut lp, t, _, _, blob) = granted(Role::Sync);
    let e = &mut lp.peers[1].engine;
    e.take_inbox_blob(&blob, false).unwrap();
    let junk: BTreeSet<[u8; 32]> = [[7; 32]].into();
    assert!(!e.record_borne(&t, &junk).unwrap(), "not kept: nothing recorded");
    accept(&mut lp, 1, t);
    let e = &mut lp.peers[1].engine;
    assert!(!e.record_borne(&t, &junk).unwrap(), "a key no held secret derives");
    assert!(e.sync_record(&t).unwrap().unwrap().recorded.is_empty());
    let r = e.sync_record(&t).unwrap().unwrap();
    assert!(e.record_borne(&t, &keys_of(&r)).unwrap());
    let r2 = e.sync_record(&t).unwrap().unwrap();
    assert_eq!(r2.recorded, r.secrets.keys().copied().collect(), "recorded");
    assert!(!e.record_borne(&t, &keys_of(&r)).unwrap(), "recorded once");
}

/// A key actor of seed byte `n` no node holds, signing as `as_author`.
fn stranger_key(n: u8) -> osis_crypto::SigningSecret {
    osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([n; 32]))
}

// spec/sync.md §3 (A kept sync ID: only by an accept), spec/sync-inbox.md §2 (Following a payload
// sync ID: the sender's word), spec/sync-hostile.md §1: once the
// thing is kept, a forger (unsigned, or signing in the granter's name) naming its own sync ID or
// the genuine one, with a box of another thing, attaches nothing: the kept sync IDs, recorded
// secrets and dial hint stay, and nothing new is recorded. NetTrust `UN_vouch` (taken on the
// sender's word) fails this.
#[test]
fn an_offer_after_the_accept_attaches_nothing_spec_sync_3() {
    let (mut lp, ps, t, s) = kept();
    let before = lp.peers[1].engine.sync_record(&t).unwrap().unwrap();
    let blob = {
        let u = thing_of(&mut lp, 0, ps[0]);
        let done = lp.peers[0].engine.grant(&u, &ps[1], &edge_of(Role::Sync)).unwrap();
        blob_to(&mut lp, &done, ps[1])
    };
    let (real, _) = boxes_of(&mut lp, 1, &blob);
    let dial = Some(osis_label::DialHint { dialable: [0x66; 32], urls: vec!["quic://forger".into()] });
    // another thing's genuine box relabelled t, under the forger's sync ID or the genuine one
    let relabel = |sid: osis_base::SyncId| vec![osis_label::BoxedThing::new(t, Some(sid), real.things[0].boxes.clone())];
    let forger = osis_base::SyncId([0x66; 16]);
    let k = stranger_key(6);
    let offers = [
        osis_label::BoxesPayload::new(&ps[1], relabel(forger), dial.clone(), None),
        osis_label::BoxesPayload::new(&ps[1], relabel(forger), dial.clone(), Some((ps[0], real.grant.as_ref().unwrap().epoch, &k))),
        osis_label::BoxesPayload::new(&ps[1], relabel(s), dial.clone(), None),
    ];
    for p in offers {
        let b = boxes_by_hand(&mut lp, 1, &p);
        let o = lp.peers[1].engine.take_inbox_blob(&b, true).unwrap().unwrap();
        // a box of another thing opens to no secret of t: refused or offered, never more
        assert!(matches!(o.taken, Taken::Refused | Taken::Offered) && o.dial.is_none(), "{o:?}");
        let e = &mut lp.peers[1].engine;
        let r = e.sync_record(&t).unwrap().unwrap();
        assert_eq!((r.sync_ids.clone(), r.recorded.clone(), r.dials.clone()), (before.sync_ids.clone(), before.recorded.clone(), Vec::new()));
        assert!(!e.record_borne(&t, &keys_of(&r)).unwrap(), "nothing new recorded");
    }
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.sync_record(&t).unwrap().unwrap().sync_ids, vec![s], "only the accepted sync ID");
}

// spec/sync.md §3 (A recorded secret: from any box that opens here, no accept), spec/wire.md §9
// (GrantSig: a rotation's payload is unsigned): a rotation's boxes payload
// to a kept holder is unsigned and no invitation; its secret is held at once and recorded once a
// step bears it.
#[test]
fn a_rotation_needs_no_accept_spec_sync_3() {
    let (mut lp, ps, t, s) = kept();
    let first = lp.peers[1].engine.sync_record(&t).unwrap().unwrap();
    lp.peers[0].engine.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    // removing peer 2 rotates read and sync: the rotation boxes peer 1 at the new sync epoch
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap();
    let rot = blob_to(&mut lp, &done, ps[1]);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.take_inbox_blob(&rot, false).unwrap().unwrap().taken, Taken::Offered);
    assert!(!e.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken), "no accept asked");
    let r = e.sync_record(&t).unwrap().unwrap();
    assert_eq!(r.sync_ids, vec![s]);
    assert!(r.secrets.len() > first.secrets.len() && first.secrets.keys().all(|x| r.secrets.contains_key(x)), "the new epoch held, nothing lost");
    assert!(e.record_borne(&t, &keys_of(&r)).unwrap());
    assert_eq!(e.sync_record(&t).unwrap().unwrap().recorded.len(), r.secrets.len());
}

// spec/sync-inbox.md §2 Taking (a grant's payload names its granting account only when its
// signature verifies under a key of its author held here, at an epoch open here), spec/wire.md §9
// (`GrantSig`: no creation record or rotation carried): a grant by an account at a rotated epoch
// names nobody to a node holding nothing of it, and its granter once that node holds the author's
// chain; a signature by another key, or by the removed node's key at the closed first epoch,
// names nobody.
#[test]
fn a_grant_names_its_granter_only_where_its_key_is_held_spec_sync_inbox_2() {
    let (mut lp, a, b, old) = rotated_author();
    let t = thing_of(&mut lp, 0, a);
    let done = lp.peers[0].engine.grant(&t, &b, &edge_of(Role::Sync)).unwrap();
    let blob = blob_to(&mut lp, &done, b);
    assert!(lp.peers[2].engine.core.created(&a).is_none(), "the recipient holds nothing of the author");
    let from = |lp: &mut LocalPeer, blob: &[u8]| {
        lp.peers[2].engine.take_inbox_blob(blob, false).unwrap();
        lp.peers[2].engine.invitations().unwrap().iter().find(|i| i.thing == t).expect("an invitation").from
    };
    assert_eq!(from(&mut lp, &blob), None, "unknown");
    let (p, _) = boxes_of(&mut lp, 2, &blob);
    let mut resigned = p.clone();
    resigned.grant = osis_label::BoxesPayload::new(&b, p.things.clone(), None, Some((a, p.grant.as_ref().unwrap().epoch, &stranger_key(7)))).grant;
    let resigned = boxes_by_hand(&mut lp, 2, &resigned);
    let ids = lp.peers[0].engine.commit_ids();
    crate::flows::send(&mut lp, 0, 2, &ids);
    assert_eq!(from(&mut lp, &resigned), None, "another key's signature");
    let closed = boxes_by_hand(&mut lp, 2, &osis_label::BoxesPayload::new(&b, p.things.clone(), None, Some((a, Some(osis_commit::FIRST_EPOCH), &old))));
    assert_eq!(from(&mut lp, &closed), None, "a removed node's key at the closed epoch");
    assert_eq!(from(&mut lp, &blob), Some(a), "the author's chain held: verified");
}

/// An account (peer 0) that rotated once (removing its second node, peer 1, whose key of the
/// first epoch is returned), and a stranger account (peer 2) holding nothing of it, whose own
/// commits peer 0 holds.
fn rotated_author() -> (LocalPeer, Tid, Tid, osis_crypto::SigningSecret) {
    let mut lp = crate::common::net_bare(3, 0);
    let (a, _) = lp.peers[0].engine.create_account().unwrap();
    let n = lp.peers[1].engine.tid();
    let card = lp.peers[1].engine.commit_ids();
    crate::flows::send(&mut lp, 1, 0, &card);
    let (_, sent) = lp.peers[0].engine.pair(&n).unwrap();
    crate::flows::send(&mut lp, 0, 1, &sent);
    lp.peers[1].engine.paired(&a.account).unwrap();
    let old = lp.peers[1].engine.provers(false).unwrap().into_iter().find(|(_, r)| r.tid() == a.account).expect("the account's key").0;
    let done = lp.peers[0].engine.demote(&a.devices, &Demotion { holder: n, new: None, retain: None }).unwrap();
    assert!(done.commits.iter().any(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.rotation.is_some())), "the account rotated");
    let (b, _) = lp.peers[2].engine.create_account().unwrap();
    let ids = lp.peers[2].engine.commit_ids();
    crate::flows::send(&mut lp, 2, 0, &ids);
    (lp, a.account, b.account, old)
}

// spec/sync-set.md §4 (invitations: a thing a held boxes payload offers under a sync ID not kept,
// wherever listed; accepting: listing it again), spec/sync.md §3: a sync grant on a thing a group
// the account reads already lists is unsyncable and an invitation until the user accepts it.
#[test]
fn a_listed_thing_offered_waits_for_an_accept_spec_sync_set_4() {
    let (mut lp, t, _, _, blob) = granted(Role::Sync);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let (_, d) = lp.peers[1].engine.account().unwrap().unwrap();
    add_item(&mut lp, 1, d, t);
    let e = &mut lp.peers[1].engine;
    e.take_inbox_blob(&blob, false).unwrap();
    assert!(e.sync_record(&t).unwrap().is_none());
    assert!(!matches!(e.thing_sync(&t).unwrap(), ThingSync::Unread(_)), "listed, no kept sync ID: not kept");
    assert!(e.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken), "an invitation though listed");
    accept(&mut lp, 1, t);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Unread(vec![s]));
}

// spec/sync-inbox.md §2 Taking (the user accepted it), spec/sync-set.md §4 (accepting): a read
// invite request is taken whole once the user accepts its thing here, and stays taken as judged
// again; a sync one keeps its sync ID; an offer of another sync ID arriving after the accept is
// an invitation again and keeps nothing.
#[test]
fn an_accept_takes_the_waiting_blob_spec_sync_set_4() {
    let (mut lp, t, _, g, blob) = granted(Role::Read);
    assert_eq!(lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap().unwrap().taken, Taken::Waiting);
    accept(&mut lp, 1, t);
    for _ in 0..2 {
        assert_eq!(lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap().unwrap().taken, Taken::Applied);
    }
    assert!(lp.peers[1].engine.core.ix.commits.contains_key(&g));
    let (mut lp, t, b, _, blob) = granted(Role::Sync);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let (real, _) = boxes_of(&mut lp, 1, &blob);
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap();
    accept(&mut lp, 1, t);
    assert_eq!(lp.peers[1].engine.sync_record(&t).unwrap().unwrap().sync_ids, vec![s]);
    let mut things = real.things.clone();
    things[0].sync_id = Some(osis_base::SyncId([0x77; 16]));
    let late = boxes_by_hand(&mut lp, 1, &osis_label::BoxesPayload::new(&b, things, None, None));
    assert_eq!(lp.peers[1].engine.take_inbox_blob(&late, false).unwrap().unwrap().taken, Taken::Offered);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.sync_record(&t).unwrap().unwrap().sync_ids, vec![s]);
    assert!(e.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken), "the user decides again");
}

// spec/sync-inbox.md §2 (invite request: an untaken blob, not applied, nothing followed),
// spec/sync-set.md §4 (invitations: listed untaken; accepting: takes it).
#[test]
fn an_untaken_grant_is_an_invitation_spec_sync_set_4() {
    let (mut lp, t, _, g, blob) = granted(Role::Read);
    let from = lp.peers[0].engine.me();
    let e = &mut lp.peers[1].engine;
    let o = e.take_inbox_blob(&blob, false).unwrap().expect("opens");
    assert_eq!(o.taken, Taken::Waiting, "the sender is not connected");
    assert!(e.core.ix.commits.get(&g).is_none());
    let inv = e.invitations().unwrap();
    let i = inv.iter().find(|i| i.thing == t).expect("listed");
    assert_eq!((i.role, i.from, i.taken), (Role::Read, Some(from), false));
    let o = e.take_inbox_blob(&blob, true).unwrap().unwrap();
    assert_eq!(o.taken, Taken::Applied);
    assert!(!e.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken));
}

// spec/sync-ids.md §6 (Steps: an admin issues a step when it holds an epoch newer than its
// recorded head registers, a child of that head, after logging the rotation commits it registers):
// nothing is due until a removal rotates; then the step is due, naming the removal's rotation
// among what it registers, and its issue records a child of the recorded head at the new sync
// epoch, after which nothing is due; a fresh step is a further child. A refreshed deposit seed
// makes a step due, and `issue_due_step` issues it (both read the head and seed one way).
#[test]
fn a_step_is_due_after_a_rotation_spec_sync_ids_6() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let head = |lp: &mut LocalPeer| lp.peers[0].engine.sync_ids(&t).unwrap().iter().find(|o| o.id == s).unwrap().path.steps.last().unwrap().0.clone();
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_none(), "nothing newer");
    let before = head(&mut lp);
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    let needs = lp.peers[0].engine.due_step(&s).unwrap().expect("the rotation's step is due");
    assert!(needs.contains(done.commits.last().unwrap()), "it registers the removal's rotation");
    let step = lp.peers[0].engine.issue_due_step(&s).unwrap().expect("issued");
    assert_eq!((step.prev, head(&mut lp).id()), (Some(before.id()), step.id()), "a child of the recorded head, recorded");
    let sync = lp.peers[0].engine.epochs(&t).unwrap().sync.newest_held().map(|(_, x)| x.clone()).unwrap();
    assert_eq!(step.keys.sync, osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, &sync).verifying_key(), "at the new sync epoch");
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_none(), "nothing due after it");
    let (fresh, _) = lp.peers[0].engine.issue_step(&t, &s, true).unwrap().expect("a fresh step");
    assert_eq!((fresh.prev, head(&mut lp).id()), (Some(step.id()), fresh.id()));
    // a refreshed deposit seed: due by the seed `issue_due_step` reads, and issued from it
    lp.peers[0].engine.refresh_deposit_seed(&t).unwrap();
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_some(), "a new deposit key is due");
    let seeded = lp.peers[0].engine.issue_due_step(&s).unwrap().expect("issued by the same reading");
    assert_eq!(seeded.prev, Some(fresh.id()));
    assert!(lp.peers[0].engine.due_step(&s).unwrap().is_none(), "nothing due after it");
}

// spec/sync-inbox.md §2 (Re-send: until the sender has seen the recipient take it, a commit by
// the recipient writing a thing the blob names, opened under a current read epoch).
#[test]
fn a_delivery_is_owed_until_taken_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, blob) = granted(Role::Write);
    assert!(lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)));
    assert!(!lp.peers[0].engine.delivery_taken(&g, &pb).unwrap());
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    write_reg(&mut lp, 1, t, 1);
    spread_sealed(&mut lp);
    assert!(lp.peers[0].engine.delivery_taken(&g, &pb).unwrap());
    assert!(!lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)));
}

// spec/sync-inbox.md §2 (What it carries about G): a removal of a grant of read or above; G
// holding sync alone is sent none. Removing a sync holder owes it nothing, a reader is owed.
#[test]
fn a_removal_is_owed_to_a_reader_not_a_sync_holder_spec_sync_inbox_2() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Sync)).unwrap();
    lp.peers[0].engine.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    let owed = |lp: &mut LocalPeer, c: osis_base::CommitId, h: Tid| lp.peers[0].engine.deliveries().unwrap().contains(&(c, h));
    let c = *lp.peers[0].engine.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits.last().unwrap();
    assert!(!owed(&mut lp, c, ps[1]), "a sync holder's removal");
    let c = *lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap().commits.last().unwrap();
    assert!(owed(&mut lp, c, ps[2]), "a reader's removal");
}

// spec/sync-inbox.md §2 (What it carries about G: a removal of G's grant of read or above, its
// `roles.0` parts; Taking: its sender connected): the removed reader applies it, though it boxes
// nothing.
#[test]
fn a_readers_removal_is_taken_spec_sync_inbox_2() {
    let (mut lp, t, pb, _, blob) = granted(Role::Read);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    let (_, d) = lp.peers[1].engine.account().unwrap().unwrap();
    add_item(&mut lp, 1, d, t);
    spread(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Read));
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let c = *done.commits.last().unwrap();
    let removal = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == pb).expect("a reader's removal is owed").1;
    assert!(!lp.peers[1].engine.holds_commit(&c));
    let o = lp.peers[1].engine.take_inbox_blob(&removal, false).unwrap().expect("opens");
    assert_eq!(o.taken, Taken::Applied);
    assert!(lp.peers[1].engine.holds_commit(&c));
    assert_eq!(lp.peers[1].engine.role_on(&t), None);
}

// spec/sync-inbox.md §2 (Re-send: a commit sealed under an older epoch shows nothing): a writer
// removed and granted write again, holding neither yet, writes under the epoch from before its
// removal; that write, stamped after the grant, leaves the grant owed; one written once it holds
// both, under the grant's epoch, shows it taken.
#[test]
fn a_write_under_an_older_epoch_shows_no_grant_again_taken_spec_sync_inbox_2() {
    let (mut lp, t, pb, _, blob) = granted(Role::Write);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let g = *lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Write)).unwrap().commits.last().unwrap();
    lp.advance(1_000);
    let stale = write_reg(&mut lp, 1, t, 2);
    let pks = lp.sealed(1, &[stale]).unwrap();
    lp.deliver_sealed(0, &pks).unwrap();
    assert!(lp.peers[0].engine.commit_bytes(&stale).unwrap().is_some(), "the stale write is held at the granter");
    assert!(!lp.peers[0].engine.delivery_taken(&g, &pb).unwrap(), "a write under the old epoch shows nothing");
    spread(&mut lp);
    let fresh = write_reg(&mut lp, 1, t, 3);
    let pks = lp.sealed(1, &[fresh]).unwrap();
    lp.deliver_sealed(0, &pks).unwrap();
    assert!(lp.peers[0].engine.delivery_taken(&g, &pb).unwrap(), "a write under the grant's epoch shows it taken");
}

/// Peer `i` writes `v` on `t`'s `t:reg.0`: the commit.
fn write_reg(lp: &mut LocalPeer, i: usize, t: Tid, v: i64) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(v)).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

// spec/permissions.md §3 (Lost access: a self-remover keeps its secrets until sync is done with
// the removal), spec/sync-status.md §2.
#[test]
fn a_self_removal_waits_for_sync_spec_perm_3() {
    let (mut lp, t, pb, _, blob) = granted(Role::Write);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    let done = lp.peers[1].engine.demote(&t, &Demotion { holder: pb, new: None, retain: None }).unwrap();
    let c = done.commits[0];
    let e = &mut lp.peers[1].engine;
    assert!(e.waiting_removals().unwrap().contains(&c));
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "kept while it waits");
    e.removal_done(&c).unwrap();
    assert!(e.waiting_removals().unwrap().is_empty());
}

/// Peers 0 and 1 nodes of one account (paired), peer 2 of another, which makes a thing and
/// grants the first account write on it; everyone holds everything. The account and the thing.
fn siblings_granted() -> (LocalPeer, Tid, Tid) {
    let (lp, (a, t)) = LocalPeer::cached("facade::siblings_granted", || {
        let mut lp = crate::common::net_bare(3, 0);
        let a = lp.peers[0].engine.create_account().unwrap().0.account;
        let n = lp.peers[1].engine.tid();
        let card = lp.peers[1].engine.commit_ids();
        crate::flows::send(&mut lp, 1, 0, &card);
        let (_, sent) = lp.peers[0].engine.pair(&n).unwrap();
        crate::flows::send(&mut lp, 0, 1, &sent);
        lp.peers[1].engine.paired(&a).unwrap();
        let b = lp.peers[2].engine.create_account().unwrap().0.account;
        spread(&mut lp);
        let t = thing_of(&mut lp, 2, b);
        lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Write)).unwrap();
        spread(&mut lp);
        for i in [0, 1] {
            assert!(lp.peers[i].engine.epochs(&t).is_some_and(|x| x.read.holds_any()), "node {i} reads it");
        }
        (lp, (a, t))
    });
    (lp, a, t)
}

// spec/permissions.md §3 (Lost access: whichever node of the account made it), spec/sync-status.md
// §2: node 0 removes its account from a thing; node 1, its sibling, applies the removal and waits
// for sync as the writer does (through a restart and the lost-access trigger), then drops; the
// other account's node waits on nothing.
#[test]
fn a_siblings_self_removal_waits_and_drops_alike_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let c = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    assert!(lp.peers[0].engine.waiting_removals().unwrap().contains(&c), "the writer waits");
    assert!(lp.peers[2].engine.waiting_removals().unwrap().is_empty(), "another account's node waits on nothing");
    lp.peers[1].restart(1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.waiting_removals().unwrap().contains(&c), "the sibling waits too, through a restart");
    e.drop_lost_due().unwrap();
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "kept while it waits");
    e.removal_done(&c).unwrap();
    assert!(e.waiting_removals().unwrap().is_empty());
    assert!(e.epochs(&t).is_none_or(|x| x.read.held().next().is_none()), "dropped");
}

// spec/permissions.md §3 (Lost access): each lost actor drops once the own self-removals behind
// it are done; one still waiting holds back nothing else.
#[test]
fn a_self_removal_done_drops_its_own_loss_alone_spec_perm_3() {
    let (mut lp, ps) = people(2);
    let (t1, t2) = (thing_of(&mut lp, 0, ps[0]), thing_of(&mut lp, 0, ps[0]));
    for t in [t1, t2] {
        lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Write)).unwrap();
    }
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    let c1 = e.demote(&t1, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    let c2 = e.demote(&t2, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    assert_eq!(*e.waiting_removals().unwrap(), BTreeSet::from([c1, c2]));
    e.removal_done(&c1).unwrap();
    assert!(e.epochs(&t1).is_none_or(|x| x.read.held().next().is_none()), "t1 dropped");
    assert!(e.epochs(&t2).is_some_and(|x| x.read.holds_any()), "t2 waits on its own removal");
    e.removal_done(&c2).unwrap();
    assert!(e.epochs(&t2).is_none_or(|x| x.read.held().next().is_none()), "t2 dropped");
}

// spec/permissions.md §3 (Lost access): a self-removal sync is done with leaves no wait behind:
// peer 1 leaves a thing it still reads through a group, then is removed from the group; the
// lost-access trigger drops the thing.
#[test]
fn a_loss_behind_a_done_self_removal_drops_at_the_trigger_spec_perm_3() {
    let (mut lp, ps) = people(2);
    let (g, t) = (thing_of(&mut lp, 0, ps[0]), thing_of(&mut lp, 0, ps[0]));
    let e = &mut lp.peers[0].engine;
    e.grant(&g, &ps[1], &edge_of(Role::Read)).unwrap();
    e.grant(&t, &g, &edge_of(Role::Read)).unwrap();
    e.grant(&t, &ps[1], &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    let c = e.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits[0];
    e.removal_done(&c).unwrap();
    assert!(e.waiting_removals().unwrap().is_empty());
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "read through the group");
    spread(&mut lp);
    lp.peers[0].engine.demote(&g, &Demotion { holder: ps[1], new: None, retain: None }).unwrap();
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    e.drop_lost_due().unwrap();
    assert!(e.epochs(&t).is_none_or(|x| x.read.held().next().is_none()), "dropped");
}

/// Whether node `i` holds a read secret of `t`.
fn reads(lp: &LocalPeer, i: usize, t: &Tid) -> bool {
    lp.peers[i].engine.epochs(t).is_some_and(|x| x.read.holds_any())
}

/// Tells node `i` sync is done with every removal it waits on.
fn all_done(lp: &mut LocalPeer, i: usize) {
    let e = &mut lp.peers[i].engine;
    for c in e.waiting_removals().unwrap().iter() {
        e.removal_done(c).unwrap();
    }
    assert!(e.waiting_removals().unwrap().is_empty(), "node {i}");
}

// spec/permissions.md §3 (Lost access: a self-removal by itself, its account or a key actor it
// holds): another account's removal of this account is no wait of its; an own removal that
// leaves a path drops nothing when done; a done told for a commit not waited on drops nothing.
#[test]
fn only_an_own_self_removal_waits_and_done_drops_only_the_lost_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let b = lp.peers[2].engine.account().unwrap().unwrap().0;
    let g = thing_of(&mut lp, 2, b);
    lp.peers[2].engine.grant(&g, &a, &edge_of(Role::Read)).unwrap();
    lp.peers[2].engine.grant(&t, &g, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let other = lp.peers[2].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.waiting_removals().unwrap().is_empty(), "node {i}: another account's removal is no wait");
        lp.peers[i].engine.removal_done(&other).unwrap();
        assert!(reads(&lp, i, &t), "node {i}: a done not waited on drops nothing");
    }
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    let own = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    for i in [0, 1] {
        assert!(lp.peers[i].engine.waiting_removals().unwrap().contains(&own), "node {i} waits on the own removal");
        all_done(&mut lp, i);
        assert!(reads(&lp, i, &t), "node {i} still reads through the group: nothing dropped");
    }
}

// spec/permissions.md §3 (Lost access): both siblings remove their account from a thing while
// apart; once each holds both removals and sync is done with what it waits on, each drops.
#[test]
fn siblings_removing_at_once_both_drop_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    for i in [0, 1] {
        lp.peers[i].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap();
        lp.advance(10);
    }
    spread(&mut lp);
    for i in [0, 1] {
        assert!(!lp.peers[i].engine.waiting_removals().unwrap().is_empty(), "node {i} waits");
        assert!(reads(&lp, i, &t), "node {i} keeps it while it waits");
        all_done(&mut lp, i);
        assert!(!reads(&lp, i, &t), "node {i} dropped");
    }
}

// spec/permissions.md §3 (Lost access): a re-grant applied while a sibling's removal waits
// keeps the secrets when the removal is done.
#[test]
fn a_regrant_during_the_wait_keeps_the_secrets_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let c = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    assert!(lp.peers[1].engine.waiting_removals().unwrap().contains(&c));
    lp.advance(10);
    lp.peers[2].engine.grant(&t, &a, &edge_of(Role::Write)).unwrap();
    spread(&mut lp);
    for i in [0, 1] {
        all_done(&mut lp, i);
        lp.peers[i].engine.drop_lost_due().unwrap();
        assert!(reads(&lp, i, &t), "node {i} re-granted: kept");
    }
}

// spec/permissions.md §3 (Lost access): a crash after the drop and before the removal leaves
// the wait (`removal_done`'s order) finds it waiting after a restart; done again clears it.
#[test]
fn a_crash_between_drop_and_clear_is_done_again_spec_perm_3() {
    let (mut lp, a, t) = siblings_granted();
    let c = lp.peers[0].engine.demote(&t, &Demotion { holder: a, new: None, retain: None }).unwrap().commits[0];
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    let lost: Vec<Tid> = e.lost_leaving().unwrap().actors.into_keys().collect();
    assert!(lost.contains(&t), "t lost behind the removal");
    e.forget_lost(osis_engine::rotation::LostScope::Only(&lost)).unwrap();
    lp.peers[1].restart(1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert_eq!(*e.waiting_removals().unwrap(), BTreeSet::from([c]), "still waiting after the restart");
    assert!(!reads(&lp, 1, &t));
    all_done(&mut lp, 1);
}

// spec/sync-judgement.md §1-§2: a commit's body under each read sync ID whose closure holds it,
// with its facts; this node's own commits under it.
#[test]
fn bodies_and_facts_under_home_spec_sync_judgement_1() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let home = e.home_sync_id(&d).unwrap().unwrap();
    let t = thing_of(&mut lp, 0, d);
    add_item(&mut lp, 0, d, t);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let b = e.sync_bodies(&c).unwrap();
    let meta = b.get(&home).expect("a body under home");
    assert!(!meta.parts.is_empty() && !meta.header_only && !meta.certificate);
    let f = e.body_facts(&home, &c).unwrap();
    assert!(f.required && f.closure && f.dropped.is_none());
    assert!(e.own_commits(&home).unwrap().contains(&c));
}

// spec/crypto.md §5 (who wraps under what: a node logging an entry of its own commit wraps under
// the newest current read epoch): the blob opens under home's read secret; its parts are noted.
#[test]
fn seal_body_seals_an_own_commit_spec_crypto_5() {
    let (mut lp, _) = people(2);
    let (_, d0) = lp.peers[0].engine.account().unwrap().unwrap();
    let home = lp.peers[0].engine.home_sync_id(&d0).unwrap().unwrap();
    let t = thing_of(&mut lp, 0, d0);
    add_item(&mut lp, 0, d0, t);
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let mut rng = SeededRng::from_u64(3);
    let (sealed, wrap) = lp.peers[0].engine.seal_body(&home, &c, &[], &mut rng).unwrap().expect("an own commit seals");
    assert_eq!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().map(|p| p.into_iter().collect::<Vec<_>>()), Some(sealed.parts.clone()));
    let rc = lp.peers[0].engine.read_credentials(&home).unwrap().unwrap();
    assert!(osis_label::unwrap_any(rc.read_secrets.iter().map(|x| &x.1), &sealed.id, &wrap).is_some(), "the wrap opens under home's read secret");
}

/// The parts of `bytes` (blob `id`, `wrap` under a sync ID of `t`) that open at peer `i`.
fn parts_opened(lp: &mut LocalPeer, i: usize, t: &Tid, id: &osis_base::BlobId, bytes: &[u8], wrap: &[u8]) -> Vec<usize> {
    let e = &mut lp.peers[i].engine;
    let key = osis_label::unwrap_any(e.read_secrets(t).iter(), id, wrap).expect("the wrap opens").1;
    let o = e.open_commit(bytes, &key).unwrap();
    let c = o.commit.id();
    e.openings_done(&c);
    o.commit.parts.iter().map(|p| p.ai).collect()
}

// spec/sync-judgement.md §1 (a section the node cannot open it copies verbatim when it encrypts
// the commit again), spec/crypto.md §5 (Passing on: a held section of the commit, opened or not):
// peer 0 writes c on t (peer 1 reads it) and u (peer 1 does not). Peer 1's fresh encryption of
// c under t's sync ID, given the blob it took (`HeldBlob`), carries u's section as it came;
// given none, it has nothing of u.
#[test]
fn seal_body_carries_held_sections_verbatim_spec_crypto_5() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    let u = thing_of(&mut lp, 0, ps[0]);
    for x in [t, u] {
        lp.peers[0].engine.give_own_secrets(&x).unwrap();
    }
    let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == ps[1] {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    for i in 0..2 {
        let (_, d) = lp.peers[i].engine.account().unwrap().unwrap();
        add_item(&mut lp, i, d, t);
    }
    spread(&mut lp);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let mut m = Mutation::new();
    for x in [t, u] {
        m.set(x, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(7)).unwrap();
    }
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let ais = |x: Tid, e: &mut osis_engine::Engine| e.header(&c).unwrap().aspects.iter().position(|a| a.tid == x).unwrap();
    let (at, au) = (ais(t, &mut lp.peers[0].engine), ais(u, &mut lp.peers[0].engine));
    let mut rng = SeededRng::from_u64(5);
    let (sealed, wrap) = lp.peers[0].engine.seal_body(&s, &c, &[], &mut rng).unwrap().expect("peer 0 seals its own");
    assert!(sealed.parts.contains(&au), "peer 0's blob carries u's part");
    assert!(matches!(lp.peers[1].engine.open_entry(&s, &sealed.id, &wrap, &sealed.blob).unwrap(), osis_engine::sync::Opened::Commit(x, _) if x == c));
    let held = osis_engine::sync::HeldBlob { sync_id: s, wrap, bytes: sealed.blob.clone() };
    let (again, w) = lp.peers[1].engine.seal_body(&s, &c, &[held], &mut rng).unwrap().expect("peer 1 seals c again");
    assert_ne!(again.id, sealed.id, "a fresh blob");
    let got = parts_opened(&mut lp, 0, &t, &again.id, &again.blob, &w);
    assert!(got.contains(&at) && got.contains(&au), "u's section copied as it came: {got:?}");
    let (bare, w) = lp.peers[1].engine.seal_body(&s, &c, &[], &mut rng).unwrap().expect("peer 1 seals its part of c");
    assert!(!parts_opened(&mut lp, 0, &t, &bare.id, &bare.blob, &w).contains(&au), "with no held blob given, nothing of u");
}

/// Commit `c` as peer `i` stores it.
fn commit_of(lp: &mut LocalPeer, i: usize, c: &osis_base::CommitId) -> osis_commit::CommitBlob {
    let pk = lp.peers[i].engine.package(c).unwrap().expect("held");
    osis_commit::CommitBlob::decode_stored(&pk.bytes).unwrap()
}

/// An inbox blob to peer `to`'s account carrying `commit` with `things`, sealed by hand (a
/// sender's own payload: its sync IDs and its commit's header are its word).
fn inbox_by_hand(lp: &mut LocalPeer, to: usize, commit: &osis_commit::CommitBlob, things: Vec<osis_label::InboxThing>) -> Vec<u8> {
    let e = &mut lp.peers[to].engine;
    let a = e.me();
    let Some(ct::KemKey::X25519MlKem768(k)) = e.get_typed(&a, &ct::KEYS).unwrap().and_then(|k| k.key) else { panic!("the account's KEM key") };
    let kem = osis_crypto::KemPublicKey::from_slice(&k).unwrap();
    let v = osis_base::decode(&commit.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB }).unwrap();
    let payload = osis_label::InboxPayload { commit: v, things, chain: Vec::new(), records: Vec::new(), dial: None };
    let now = e.now();
    osis_label::seal_inbox_blob(&a, &kem, &payload, now, &mut SeededRng::from_u64(11)).unwrap()
}

// spec/sync-inbox.md §2 Taking, spec/sync.md §3: a commit blob boxing sync alone is held as an
// offer like a boxes payload: one whose header names an author it was not signed by names no
// granting account and keeps nothing.
#[test]
fn a_forged_author_names_nobody_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, _) = granted(Role::Sync);
    let mut forged = commit_of(&mut lp, 0, &g);
    forged.header.author = pb;
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap();
    let blob = inbox_by_hand(&mut lp, 1, &forged, vec![osis_label::InboxThing { tid: t, sync_id: s, delete_keys: None }]);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.take_inbox_blob(&blob, false).unwrap().expect("opens").taken, Taken::Offered);
    assert!(e.sync_record(&t).unwrap().is_none());
    assert_eq!(e.invitations().unwrap().iter().find(|i| i.thing == t).expect("an invitation").from, None);
}

// spec/sync-inbox.md §2 (sync ID hints), spec/sync-set.md §2: an accepted sync grant naming a
// sync ID that a held `sync.0` gives another thing keeps nothing unread under it; that sync ID
// stays its owner's.
#[test]
fn a_payload_sync_id_of_another_thing_is_not_kept_unread_spec_sync_inbox_2() {
    let (mut lp, t, _, g, _) = granted(Role::Sync);
    let (_, d1) = lp.peers[1].engine.account().unwrap().unwrap();
    let home1 = lp.peers[1].engine.home_sync_id(&d1).unwrap().unwrap();
    let commit = commit_of(&mut lp, 0, &g);
    let blob = inbox_by_hand(&mut lp, 1, &commit, vec![osis_label::InboxThing { tid: t, sync_id: Some(home1), delete_keys: None }]);
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap();
    accept(&mut lp, 1, t);
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.sync_record(&t).unwrap().expect("kept").sync_ids, vec![home1], "kept as the payload named it");
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Unread(Vec::new()), "home1 is D's");
    assert_eq!(e.sync_set().unwrap().ids.get(&home1), Some(&(d1, Holding::Read)));
}

// spec/sync-inbox.md §2 Re-send (until the sender has seen the recipient take it, an open by
// the recipient among the signs: sync's to see): `delivered` ends a delivery, durably; a sync
// holder writes nothing, so the engine alone never sees it taken.
#[test]
fn delivered_ends_a_delivery_spec_sync_inbox_2() {
    let (mut lp, _, pb, g, _) = granted(Role::Sync);
    let e = &mut lp.peers[0].engine;
    assert!(e.deliveries().unwrap().contains(&(g, pb)));
    e.delivered(&g, &pb).unwrap();
    assert!(!e.deliveries().unwrap().contains(&(g, pb)));
    lp.peers[0].restart(7).unwrap();
    assert!(!lp.peers[0].engine.deliveries().unwrap().contains(&(g, pb)), "gone for good");
}

// spec/crypto.md §5 (passing on: needs the epoch each section was written under, so what was
// opened or sealed is kept): what this node keeps of a blob it sealed or opened
// lasts across a restart and goes with its commit when that is forgotten.
#[test]
fn blob_rows_go_with_their_commit() {
    let (mut lp, _) = people(1);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let t = thing_of(&mut lp, 0, d);
    add_item(&mut lp, 0, d, t);
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let (sealed, _) = lp.peers[0].engine.seal_body(&home, &c, &[], &mut SeededRng::from_u64(3)).unwrap().unwrap();
    lp.peers[0].restart(8).unwrap();
    assert!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().is_some(), "durable");
    lp.peers[0].engine.forget_commits(&[c]).unwrap();
    assert!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().is_none());
    lp.peers[0].restart(9).unwrap();
    assert!(lp.peers[0].engine.blob_parts(&sealed.id).unwrap().is_none(), "its row gone too");
}


/// Whether `wrap` of blob `b` opens under peer `i`'s secret of read epoch `e` of `t`.
fn wrap_opens_under(lp: &LocalPeer, i: usize, t: &Tid, e: &osis_crypto::Epoch, b: &osis_base::BlobId, wrap: &[u8]) -> bool {
    let ep = lp.peers[i].engine.epochs(t).unwrap();
    ep.read.secret(e).is_some_and(|x| osis_crypto::unwrap(x, b, wrap).is_ok())
}

// spec/crypto.md §5 (who wraps under what; Passing on), spec/sync-judgement.md §1: a reader that
// is no writer of S makes a fresh encryption of a shared blob and of a per-sync-ID copy after a
// rotation that removed peer 2, and logs the held shared blob verbatim (`rewrap`): each wrap is
// `wrap_secret`'s, under the newest epoch, which the removed peer lacks (a copy's wrap is its only
// key).
#[test]
fn a_fresh_encryption_wraps_beyond_the_removed_spec_crypto_5() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    for p in [ps[1], ps[2]] {
        let done = lp.peers[0].engine.grant(&t, &p, &edge_of(Role::Read)).unwrap();
        for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
            if let Some(i) = ps.iter().position(|x| *x == h) {
                lp.peers[i].engine.take_inbox_blob(&b, true).unwrap();
            }
        }
    }
    // u: a thing t administers, with secrets of its own; a grant on it travels under t's sync ID
    // as a copy (a role commit on another thing)
    let u = thing_of(&mut lp, 0, t);
    lp.peers[0].engine.give_own_secrets(&u).unwrap();
    add_item(&mut lp, 0, t, u);
    for i in 0..2 {
        let (_, d) = lp.peers[i].engine.account().unwrap().unwrap();
        add_item(&mut lp, i, d, t);
    }
    spread(&mut lp);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let done = lp.peers[0].engine.grant(&u, &ps[1], &edge_of(Role::Read)).unwrap();
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(7)).unwrap();
    let plain = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let copy = *done.commits.iter().find(|c| lp.peers[0].engine.sync_bodies(c).unwrap().get(&s).is_some_and(|b| b.copy)).expect("the grant on u is a copy under t's sync ID");
    let e1 = crate::flows::newest_read(&lp, 0, t).unwrap();
    // peer 1 opens both from the blobs peer 0 logged under S
    let mut rng = SeededRng::from_u64(5);
    let mut held = Vec::new();
    for c in [plain, copy] {
        let (sealed, wrap) = lp.peers[0].engine.seal_body(&s, &c, &[], &mut rng).unwrap().expect("peer 0 seals its own");
        assert!(matches!(lp.peers[1].engine.open_entry(&s, &sealed.id, &wrap, &sealed.blob).unwrap(), osis_engine::sync::Opened::Commit(x, _) if x == c));
        held.push((sealed.id, wrap));
    }
    // removing peer 2 rotates read: peer 1 holds a newer epoch
    lp.peers[0].engine.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap();
    spread(&mut lp);
    let e2 = crate::flows::newest_read(&lp, 1, t).unwrap();
    assert_ne!(e1, e2, "peer 1 holds the rotation's epoch");
    for (name, c) in [("shared blob", plain), ("copy", copy)] {
        let (again, wrap) = lp.peers[1].engine.seal_body(&s, &c, &[], &mut rng).unwrap().unwrap_or_else(|| panic!("{name}: sealed"));
        assert!(wrap_opens_under(&lp, 1, &t, &e2, &again.id, &wrap), "{name}: wrapped under the newest epoch");
        assert!(!wrap_opens_under(&lp, 1, &t, &e1, &again.id, &wrap), "{name}: not under one the removed peer holds");
    }
    // the held shared blob logged verbatim again (`rewrap`): its wrap by the same rule
    let (b, w) = &held[0];
    let again = lp.peers[1].engine.rewrap(&plain, b, &s, w, &s).unwrap().expect("rewrapped");
    assert!(wrap_opens_under(&lp, 1, &t, &e2, b, &again) && !wrap_opens_under(&lp, 1, &t, &e1, b, &again), "rewrapped under the newest epoch");
}

// spec/sync-inbox.md §2 (logging: a sender that does not write the inbox deposits under the
// recipient's deposit key; Re-send: the sync IDs the blob names, whose open by the recipient
// shows it took the delivery).
#[test]
fn a_delivery_names_and_signs_for_the_recipients_inbox_spec_sync_inbox_2() {
    let (mut lp, t, pb, g, _) = granted(Role::Sync);
    let e = &mut lp.peers[0].engine;
    let home = e.home_sync_id(&t).unwrap().unwrap();
    assert_eq!(*e.delivery_names(&g, &pb).unwrap(), vec![home]);
    let inbox = e.inbox_of(&pb).expect("the recipient's inbox");
    let sg = e.signers(&inbox, Some(&pb)).unwrap();
    assert!(sg.stamp.is_none() && sg.delete.is_none(), "no head of another's inbox recorded here");
    let seed = e.deposit_seed(&pb).unwrap().expect("the recipient's deposit seed");
    assert_eq!(sg.deposit.map(|k| k.verifying_key()), Some(osis_crypto::deposit_key(&seed, &inbox).verifying_key()));
    // its own thing: the head's keys
    let own = e.signers(&home, None).unwrap();
    assert!(own.stamp.is_some() && own.delete.is_some() && own.deposit.is_some());
}

// spec/sync-ids.md §6 (steps: registered only once the source holds the role commits its epochs
// depend on): the genesis step's needs are the rotations of its epochs, held here.
#[test]
fn a_step_needs_its_epochs_rotations_spec_sync_ids_6() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let ids = e.sync_ids(&d).unwrap();
    let step = ids[0].path.steps[0].0.id();
    let needs = e.step_needs(&ids[0].id, &step).unwrap();
    assert!(!needs.is_empty());
    assert!(needs.iter().all(|c| e.core.ix.commits.contains_key(c)));
}

// spec/sync-judgement.md §2, §3 (own store; role entries first), §4 (falls of held parts: the
// mark a stand compares), §1 (per-sync-ID copies: known as one).
#[test]
fn read_facts_of_own_and_role_commits_spec_sync_judgement_3() {
    let (mut lp, t, _, g, _) = granted(Role::Write);
    let e = &mut lp.peers[0].engine;
    let s = e.home_sync_id(&t).unwrap().unwrap();
    let (_, d) = e.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    m.set(t, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(5)).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let f = e.read_facts(&s, &c).unwrap();
    assert!(f.own && !f.role && f.must_not.is_none() && !f.missing);
    let r = e.read_facts(&s, &g).unwrap();
    assert!(r.own && r.role, "the grant is an own role commit");
    assert_eq!(e.body_fall_mark(&c).unwrap(), 0, "nothing fell yet");
    let (sealed, wrap) = e.seal_body(&s, &c, &[], &mut SeededRng::from_u64(4)).unwrap().unwrap();
    assert_eq!(e.blob_copy(&sealed.id).unwrap(), Some(false));
    // the held blob logged verbatim under the same sync ID: a wrap of the same key
    let again = e.rewrap(&c, &sealed.id, &s, &wrap, &s).unwrap().expect("its epoch is held");
    let rc = e.read_credentials(&s).unwrap().unwrap();
    let key = |w: &[u8]| osis_label::unwrap_any(rc.read_secrets.iter().map(|x| &x.1), &sealed.id, w).map(|x| *x.1.expose());
    assert_eq!(key(&again), key(&wrap));
}

// spec/sync-judgement.md §6 (Read and unread move: a node lowered to sync writes its account's
// sync record from its own reading, spec/sync.md §3, and drops its engine state of S, which
// becomes kept unread).
#[test]
fn a_lowering_to_sync_writes_a_sync_record_spec_sync_judgement_6() {
    let (mut lp, t, pb, _, blob) = granted(Role::Read);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    assert!(lp.peers[1].engine.sync_record(&t).unwrap().is_none(), "a reader keeps no record");
    let held: Vec<_> = lp.peers[1].engine.epochs(&t).unwrap().sync.held().map(|(e, _)| e).collect();
    assert!(!held.is_empty());
    let done = lp.peers[0].engine.demote(&t, &Demotion { holder: pb, new: Some(edge_of(Role::Sync)), retain: None }).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == pb {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    spread(&mut lp);
    let e = &mut lp.peers[1].engine;
    e.forget_lost(osis_engine::rotation::LostScope::All).unwrap();
    assert!(e.epochs(&t).is_none_or(|x| !x.read.holds_any()), "read secrets gone");
    let r = e.sync_record(&t).unwrap().expect("lowered: a sync record");
    assert!(held.iter().all(|x| r.recorded.contains(x)), "the sync secrets it held, recorded");
    assert_eq!(r.sync_ids, vec![lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap()]);
}

// spec/sync-judgement.md §1 Per-sync-ID copies (never shared with another sync ID; only a copy
// holds a copy's body): a held blob is logged verbatim under another sync ID only as a shared
// blob for a shared body. A grant on u travels under t's sync ID as a copy and under u's own as
// the shared blob; neither is rewrapped for the other.
#[test]
fn a_copy_is_never_logged_verbatim_elsewhere_spec_sync_judgement_1() {
    let (mut lp, ps) = people(2);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let u = thing_of(&mut lp, 0, t);
    lp.peers[0].engine.give_own_secrets(&u).unwrap();
    add_item(&mut lp, 0, t, u);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let e = &mut lp.peers[0].engine;
    let (s, su) = (e.home_sync_id(&t).unwrap().unwrap(), e.home_sync_id(&u).unwrap().unwrap());
    let done = e.grant(&u, &ps[1], &edge_of(Role::Read)).unwrap();
    let c = *done.commits.iter().find(|c| e.sync_bodies(c).unwrap().get(&s).is_some_and(|b| b.copy)).expect("a copy under t's sync ID");
    assert!(e.sync_bodies(&c).unwrap().get(&su).is_some_and(|b| !b.copy), "the shared blob under u's");
    let mut rng = SeededRng::from_u64(9);
    let (copy, copy_wrap) = e.seal_body(&s, &c, &[], &mut rng).unwrap().expect("the copy seals");
    let (shared, shared_wrap) = e.seal_body(&su, &c, &[], &mut rng).unwrap().expect("the shared blob seals");
    assert_eq!((e.blob_copy(&copy.id).unwrap(), e.blob_copy(&shared.id).unwrap()), (Some(true), Some(false)));
    assert!(e.rewrap(&c, &copy.id, &s, &copy_wrap, &su).unwrap().is_none(), "a copy goes under no other sync ID");
    assert!(e.rewrap(&c, &shared.id, &su, &shared_wrap, &s).unwrap().is_none(), "a copy body is held only by a copy");
    assert!(e.rewrap(&c, &shared.id, &su, &shared_wrap, &su).unwrap().is_some(), "a shared blob for a shared body");
}

// spec/sync-inbox.md §2 (following a payload sync ID: one no applied `sync.0` records, only while
// the blob is unexpired): a read grant whose payload names the recipient's own home sync ID
// gives the granted thing no hint, so home stays D's in the sync set; an honest payload's hint
// lasts across a restart until the blob's expiry.
#[test]
fn a_hint_is_no_recorded_sync_id_and_ends_with_its_blob_spec_sync_inbox_2() {
    let (mut lp, t, _, g, blob) = granted(Role::Read);
    let (_, d1) = lp.peers[1].engine.account().unwrap().unwrap();
    let home1 = lp.peers[1].engine.home_sync_id(&d1).unwrap().unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let commit = commit_of(&mut lp, 0, &g);
    let forged = inbox_by_hand(&mut lp, 1, &commit, vec![osis_label::InboxThing { tid: t, sync_id: Some(home1), delete_keys: None }]);
    let o = lp.peers[1].engine.take_inbox_blob(&forged, true).unwrap().expect("opens");
    assert_eq!(o.taken, Taken::Applied);
    assert!(o.hints.is_empty(), "home1 is recorded by D's sync.0: no hint");
    add_item(&mut lp, 1, d1, t);
    let e = &mut lp.peers[1].engine;
    assert!(e.sync_ids(&t).unwrap().iter().all(|o| o.id != home1));
    assert_eq!(e.sync_set().unwrap().ids.get(&home1), Some(&(d1, Holding::Read)));
    // the honest blob names t's own sync ID: followed as a hint
    let o = e.take_inbox_blob(&blob, true).unwrap().expect("opens");
    assert_eq!(o.hints, vec![(t, s)]);
    lp.peers[1].restart(5).unwrap();
    let hinted = |lp: &mut LocalPeer| lp.peers[1].engine.sync_ids(&t).unwrap().iter().any(|o| o.id == s && o.hint);
    assert!(hinted(&mut lp), "durable");
    lp.advance(osis_base::format::INBOX_LIFETIME_MS + 1);
    lp.peers[1].tick().unwrap();
    assert!(!hinted(&mut lp), "the blob expired: no longer followed");
}

/// Peer `i`'s node writes its own `reach.0` a second later; the commit (a card commit, spec/
/// permissions.md §4).
fn reach(lp: &mut LocalPeer, i: usize, k: u8) -> osis_base::CommitId {
    lp.advance(1000);
    let n = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    m.set(n, &ct::REACH, &ct::Reach { dialable: [k; 32], items: Vec::new(), account: None }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit once a later valid card
// commit of that node writing the same aspect is under the sync ID, an entry of it this node
// opened). Hostile: a later card held as a commit with no entry of it opened here (a forged
// supersession) supersedes nothing, and this node's own card never goes by this rule. The rule
// firing: core/engine/src/sync/tests_facts.rs.
#[test]
fn a_card_known_only_as_a_commit_supersedes_nothing_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let old = reach(&mut lp, 1, 1);
    reach(&mut lp, 1, 2);
    let (o1, _) = (reach(&mut lp, 0, 3), reach(&mut lp, 0, 4));
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&home, &old).unwrap().must_not, None, "a later card held but never opened here: kept");
    assert_eq!(e.read_facts(&home, &o1).unwrap().must_not, None, "its own card: never by this rule");
}

// spec/sync-judgement.md §2 must-not-hold (another node's card commit, for `node.0` and `reach.0`,
// once that node is a node of the account no more after an applied edge write on D ended its
// grant). Hostile: a removed node paired again is a node again, its card kept; its `keys.0` card
// never goes by this rule.
#[test]
fn a_card_goes_with_its_nodes_grant_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let n1 = lp.peers[1].engine.tid();
    let r = reach(&mut lp, 1, 1);
    spread(&mut lp);
    let keys = *lp.peers[0].engine.core.ix.by_aspect.get(&(n1, Ak::new("keys.0").unwrap())).unwrap().iter().next().unwrap();
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.read_facts(&home, &r).unwrap().must_not, None, "a node of the account: kept");
    e.demote(&d, &Demotion { holder: n1, new: None, retain: None }).unwrap();
    assert_eq!(e.read_facts(&home, &r).unwrap().must_not, Some(osis_engine::sync::MustNot::CardEnded));
    assert_eq!(e.read_facts(&home, &keys.1).unwrap().must_not, None, "its keys.0 card stays");
    e.pair(&n1).unwrap();
    assert_eq!(e.read_facts(&home, &r).unwrap().must_not, None, "paired again: kept");
}

// spec/sync-judgement.md §2 required set (the certificate blobs of spec/permissions.md §4): the
// other node's `reach.0` card is in D's home sync ID's required set, so read never judges it
// outside it (must-not-hold, deleted at a node keeping the sync ID unread by a delete-key
// holder); sealed as a copy, it opens at the card's own node.
#[test]
fn another_nodes_card_is_in_the_required_set_spec_sync_judgement_2() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let r = reach(&mut lp, 1, 1);
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    let b = e.sync_bodies(&r).unwrap();
    assert!(b.get(&home).is_some_and(|m| m.certificate && m.copy && !m.parts.is_empty()), "the card's certificate body under D's home: {b:?}");
    let f = e.body_facts(&home, &r).unwrap();
    assert!(f.required && !f.closure, "{f:?}");
    let (sealed, wrap) = e.seal_body(&home, &r, &[], &mut SeededRng::from_u64(1)).unwrap().expect("sealed as a certificate copy");
    assert_eq!(e.blob_copy(&sealed.id).unwrap(), Some(true));
    match lp.peers[1].engine.open_entry(&home, &sealed.id, &wrap, &sealed.blob).unwrap() {
        osis_engine::sync::Opened::Commit(c, _) => assert_eq!(c, r),
        o => panic!("{o:?}"),
    }
}

/// Peer 1 takes a write grant on peer 0's thing `t` and syncs it (in its synced group).
fn grantee() -> (LocalPeer, Tid) {
    let (mut lp, t, _, _, blob) = granted(Role::Write);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    spread(&mut lp);
    let (_, d1) = lp.peers[1].engine.account().unwrap().unwrap();
    add_item(&mut lp, 1, d1, t);
    (lp, t)
}

// spec/permissions.md §3 Complete pass (a Pull sent before a role commit of the actor applied
// ends no pass after it): the grant applied at peer 1 from elsewhere wants a pass of the thing's
// sync ID from its arrival, on the engine's clock; a pass begun before it does not count, one
// begun at it does, and the re-seal trigger waits for it.
#[test]
fn a_pass_begun_before_a_role_commit_does_not_count_spec_perm_3() {
    let (mut lp, t) = grantee();
    let e = &mut lp.peers[1].engine;
    let s = e.home_sync_id(&t).unwrap().unwrap();
    let since = *e.passes_wanted().unwrap().get(&s).expect("a pass of the thing's sync ID wanted");
    assert!(since.0 > 0 && since <= e.pass_clock(), "from the grant's arrival, on the engine's clock");
    e.note_complete_pass(&s, osis_base::WallMs(since.0 - 1)).unwrap();
    assert_eq!(e.passes_wanted().unwrap().get(&s), Some(&since), "begun before it: still wanted");
    assert!(e.pass_end(&t).unwrap().commits.is_empty());
    e.note_complete_pass(&s, since).unwrap();
    assert!(!e.passes_wanted().unwrap().contains_key(&s));
}

// spec/permissions.md §3 Complete pass, spec/sync-status.md §1: the want is derived from the role
// commits held and the passes noted, so a crash right after a role commit still wants the pass,
// and a pass noted is kept across a restart.
#[test]
fn a_restart_still_wants_the_pass_spec_perm_3() {
    let (mut lp, t) = grantee();
    let s = lp.peers[1].engine.home_sync_id(&t).unwrap().unwrap();
    let since = *lp.peers[1].engine.passes_wanted().unwrap().get(&s).unwrap();
    lp.peers[1].restart(7).unwrap();
    assert_eq!(lp.peers[1].engine.passes_wanted().unwrap().get(&s), Some(&since), "wanted after the crash");
    lp.peers[1].engine.note_complete_pass(&s, since).unwrap();
    lp.peers[1].restart(8).unwrap();
    assert!(!lp.peers[1].engine.passes_wanted().unwrap().contains_key(&s), "the pass noted survives");
}

// spec/sync-status.md §3 History complete (a complete pass of every sync ID carrying the thing):
// a fresh node wants one pass of its home, whenever begun; history is complete once it is noted.
#[test]
fn history_completes_with_a_pass_spec_sync_status_3() {
    let (mut lp, _) = people(1);
    let e = &mut lp.peers[0].engine;
    let (_, d) = e.account().unwrap().unwrap();
    let home = e.home_sync_id(&d).unwrap().unwrap();
    assert_eq!(e.passes_wanted().unwrap().get(&home), Some(&osis_base::WallMs(0)), "one pass, whenever");
    assert!(!e.history_complete(&d).unwrap());
    let now = e.pass_clock();
    e.note_complete_pass(&home, now).unwrap();
    assert!(e.history_complete(&d).unwrap() && e.passes_wanted().unwrap().is_empty());
}

// spec/sync-status.md §3 History complete: a pass belongs to a sync ID read here, so a sync ID
// left and read again wants a pass of its own (what it missed while away is not here): one that
// leaves loses its noted pass (sync's follow calls `forget_read`; an open drops it too, for one
// left while down), and a pass of a sync ID not read is not kept.
#[test]
fn a_pass_goes_with_its_sync_id_spec_sync_status_3() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let now = lp.peers[0].engine.pass_clock();
    lp.peers[0].engine.note_complete_pass(&home, now).unwrap();
    lp.peers[0].engine.note_complete_pass(&s, now).unwrap();
    add_item(&mut lp, 0, d, t);
    assert!(!lp.peers[0].engine.history_complete(&t).unwrap(), "noted while not read here: not kept");
    lp.peers[0].engine.note_complete_pass(&s, now).unwrap();
    assert!(lp.peers[0].engine.history_complete(&t).unwrap());
    let mut m = Mutation::new();
    m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Remove(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    lp.peers[0].restart(9).unwrap();
    add_item(&mut lp, 0, d, t);
    assert!(!lp.peers[0].engine.history_complete(&t).unwrap(), "left while down: read again, history not complete");
    assert_eq!(lp.peers[0].engine.passes_wanted().unwrap().get(&s), Some(&osis_base::WallMs(0)));
    let now = lp.peers[0].engine.pass_clock();
    lp.peers[0].engine.note_complete_pass(&s, now).unwrap();
    lp.peers[0].engine.forget_read(&s).unwrap();
    assert!(!lp.peers[0].engine.history_complete(&t).unwrap(), "forgotten: wanted again");
}

// spec/permissions.md §3 Complete pass: `passes_wanted` is a memo value over the engine's stamps,
// so an `Effects` key over it is due when a role commit arrives from elsewhere, with no polling
// and no hook, and its new value wants the pass from that arrival.
#[test]
fn passes_wanted_moves_with_a_role_commit_spec_perm_3() {
    let (mut lp, t) = grantee();
    let e = &mut lp.peers[1].engine;
    let s = e.home_sync_id(&t).unwrap().unwrap();
    let now = e.pass_clock();
    for x in e.passes_wanted().unwrap().keys().copied().collect::<Vec<_>>() {
        e.note_complete_pass(&x, now).unwrap();
    }
    let mut fx: osis_base::memo::Effects<(), std::sync::Arc<std::collections::BTreeMap<osis_base::SyncId, osis_base::WallMs>>> = osis_base::memo::Effects::new("test passes");
    fx.want(());
    let (_, first) = fx.settle(&(), || lp.peers[1].engine.passes_wanted().unwrap()).unwrap();
    assert!(first.is_empty() && fx.due().is_empty(), "nothing wanted, nothing due");
    lp.advance(1000);
    let pb = lp.peers[1].engine.me();
    lp.peers[0].engine.grant(&t, &pb, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    assert_eq!(fx.due(), vec![()], "the role commit's arrival moves the wants");
    let (_, now) = fx.settle(&(), || lp.peers[1].engine.passes_wanted().unwrap()).unwrap();
    assert!(now.get(&s).is_some_and(|x| x.0 > 0));
}

// spec/permissions.md §2 Tied grants (an explicit demotion of a tied grant held dead waits for a
// complete pass of every sync ID whose bodies carry a thing of the demotion's pre-sync scope,
// ended after the last role commit of G or T applied from elsewhere): a role commit on G from
// another node wants a pass of T's sync ID, which no other rule wants once passed.
#[test]
fn a_dead_tie_wants_a_pass_of_its_scope_spec_perm_2() {
    let (mut lp, ps) = people(3);
    let g = thing_of(&mut lp, 0, ps[0]);
    let t = thing_of(&mut lp, 0, ps[0]);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    for x in [g, t] {
        lp.peers[0].engine.give_own_secrets(&x).unwrap();
        add_item(&mut lp, 0, d, x);
    }
    add_item(&mut lp, 0, g, t);
    let e = &mut lp.peers[0].engine;
    let tie = e.placement(&t, &g, false).unwrap().unwrap();
    e.grant(&t, &g, &ct::Edge { role: Role::Write, until: None, invite: None, tied: Some(osis_engine::flows::tied::tie_ct(tie)), floor: None }).unwrap();
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Remove(osis_base::Value::Tid(t)) }).unwrap();
    e.commit(m).unwrap().unwrap();
    assert!(e.tied_unplaced(&Default::default(), &Default::default(), true).unwrap().contains(&(t, g)), "the tie is dead");
    let st = e.home_sync_id(&t).unwrap().unwrap();
    let now = e.pass_clock();
    for x in e.passes_wanted().unwrap().keys().copied().collect::<Vec<_>>() {
        e.note_complete_pass(&x, now).unwrap();
    }
    assert!(e.passes_wanted().unwrap().is_empty());
    let done = e.grant(&g, &ps[1], &edge_of(Role::Admin)).unwrap();
    for (h, b) in lp.inbox_blobs(0, &done).unwrap() {
        if h == ps[1] {
            lp.peers[1].engine.take_inbox_blob(&b, true).unwrap();
        }
    }
    spread(&mut lp);
    lp.advance(1000);
    lp.peers[1].engine.grant(&g, &ps[2], &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let w = lp.peers[0].engine.passes_wanted().unwrap();
    assert!(w.get(&st).is_some_and(|x| x.0 > now.0), "T's sync ID, from the role commit on G: {w:?}");
}

// spec/crypto.md §4 (names): a rotation names the edge writes its rotator held that pin a holder
// below a role, and what it names travels with it: a removal's rotation logs with it the earlier
// removal it names.
#[test]
fn a_rotation_logs_with_it_the_commits_it_names_spec_crypto_4() {
    let (mut lp, ps) = people(3);
    let t = thing_of(&mut lp, 0, ps[0]);
    let e = &mut lp.peers[0].engine;
    e.give_own_secrets(&t).unwrap();
    e.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
    e.grant(&t, &ps[2], &edge_of(Role::Read)).unwrap();
    let first = *e.demote(&t, &Demotion { holder: ps[1], new: None, retain: None }).unwrap().commits.last().unwrap();
    let second = *e.demote(&t, &Demotion { holder: ps[2], new: None, retain: None }).unwrap().commits.last().unwrap();
    let with = e.logged_with(&second).unwrap();
    assert!(with.contains(&first), "the earlier removal it names: {with:?}");
}

/// A record blob of `records` under `t`'s current read epoch at peer `i` (spec/wire.md §3), as
/// any reader of the sync ID could frame one: its ID, bytes and wrap.
fn record_blob_by_hand(lp: &mut LocalPeer, i: usize, t: &Tid, records: &[osis_base::CreationRecord]) -> (osis_base::BlobId, Vec<u8>, osis_engine::sync::Wrap) {
    let mut rng = SeededRng::from_u64(17);
    let plain = osis_commit::record_blob::encode_record_blob(records);
    let prefix = osis_label::Prefix::for_groups(osis_label::Prefix::random_salt(&mut rng), &[7; 16], None, &[]).unwrap().with_class(osis_label::Class::Durable);
    let (key, blob) = osis_label::frame(&prefix, &plain, &mut rng).unwrap();
    let id = osis_label::blob_id(&blob);
    let w = lp.peers[i].engine.wrap_secret(t, None).unwrap().expect("a read epoch");
    let wrap = osis_crypto::wrap(&w, &id, &key, 0).unwrap();
    (id, blob, wrap)
}

// spec/wire.md §3 (creation record; Record blob), spec/permissions.md §4 (Chain certificates),
// spec/commits.md §4 (Pending storage): a record's tid is the hash of its encoding, records go raw
// in a record blob. A reader of S framing a record blob cannot plant a false record for a thing it
// names: a record altered to name another first admin is a record of another tid, and the
// receiver learns nothing of the thing; the genuine record, sealed by its holder, is kept loose
// until a commit here awaits it, then learned as it is.
#[test]
fn a_forged_record_in_a_record_blob_names_no_other_thing_spec_wire_3() {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let a = lp.peers[0].engine.account().unwrap().unwrap().0;
    let u = thing_of(&mut lp, 0, a);
    let real = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    assert!(lp.peers[1].engine.core.created(&u).is_none(), "u not spread");
    let osis_base::CreationRecord::Thing { nonce, .. } = real.clone() else { panic!() };
    let forged = osis_base::CreationRecord::Thing { admin: lp.peers[1].engine.tid(), nonce, link: None };
    assert_ne!(forged.tid(), u);
    let (id, blob, wrap) = record_blob_by_hand(&mut lp, 0, &d, std::slice::from_ref(&forged));
    match lp.peers[1].engine.open_entry(&home, &id, &wrap, &blob).unwrap() {
        osis_engine::sync::Opened::Records(tids) => assert_eq!(tids, [forged.tid()].into()),
        o => panic!("{o:?}"),
    }
    assert!(lp.peers[1].engine.core.created(&u).is_none(), "nothing learned of u");
    let (id, bytes, wrap) = lp.peers[0].engine.seal_records(&home, &[u].into(), &mut SeededRng::from_u64(3)).unwrap().expect("sealed");
    assert!(matches!(lp.peers[1].engine.open_entry(&home, &id, &wrap, &bytes).unwrap(), osis_engine::sync::Opened::Records(_)));
    assert!(lp.peers[1].engine.core.created(&u).is_none() && lp.peers[1].engine.carries_loose(&id), "nothing awaits u yet: loose");
    later_write_on(&mut lp, u);
    assert_eq!(lp.peers[1].engine.core.created(&u), Some(&real));
    assert!(!lp.peers[1].engine.carries_loose(&id), "its carrier gives something held");
}

/// Peer 0 writes on `u` and peer 1 ingests that commit alone (`u`'s record not with it): it
/// awaits `u`'s record there.
fn later_write_on(lp: &mut LocalPeer, u: Tid) {
    let mut m = Mutation::new();
    m.set(u, &REG, &s("later")).unwrap();
    let c = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let bytes = lp.peers[0].engine.commit_bytes(&c).unwrap().unwrap();
    lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap();
}

/// `n` junk records (things no commit names) and one genuine one in record blobs a reader of
/// S frames, opened at peer 1, then the junk blob's entry gone: (loose records while carried,
/// records learned, loose left, whether the genuine one was learned once awaited).
fn junk_records(n: usize) -> (usize, usize, usize, bool) {
    let (mut lp, d) = crate::flows::account_two_nodes();
    let home = lp.peers[0].engine.home_sync_id(&d).unwrap().unwrap();
    let a = lp.peers[0].engine.account().unwrap().unwrap().0;
    let u = thing_of(&mut lp, 0, a);
    let real = lp.peers[0].engine.core.created(&u).cloned().unwrap();
    let junk: Vec<osis_base::CreationRecord> = (0..n).map(|i| osis_base::CreationRecord::Thing { admin: a, nonce: { let mut x = [9u8; 32]; x[..8].copy_from_slice(&(i as u64).to_be_bytes()); x }, link: None }).collect();
    let known = |lp: &LocalPeer| junk.iter().filter(|r| lp.peers[1].engine.core.created(&r.tid()).is_some()).count();
    let (jb, jbytes, jwrap) = record_blob_by_hand(&mut lp, 0, &d, &junk);
    let (gb, gbytes, gwrap) = record_blob_by_hand(&mut lp, 0, &d, std::slice::from_ref(&real));
    assert_ne!(jb, gb);
    for (b, bytes, wrap) in [(&jb, &jbytes, &jwrap), (&gb, &gbytes, &gwrap)] {
        assert!(matches!(lp.peers[1].engine.open_entry(&home, b, wrap, bytes).unwrap(), osis_engine::sync::Opened::Records(_)));
    }
    let carried = lp.peers[1].engine.loose_records();
    let learned = known(&lp);
    lp.peers[1].engine.forget_carrier(&jb);
    let left = lp.peers[1].engine.loose_records();
    later_write_on(&mut lp, u);
    (carried, learned + known(&lp), left, lp.peers[1].engine.core.created(&u) == Some(&real))
}

// spec/commits.md §4 (Pending storage), spec/requirements.md (malicious readers only waste
// storage; peer input never causes unbounded storage): records nothing here awaits are kept only
// while their carrier is (its entry charged to the peer that brought it): n and 10n junk records
// are never learned and go with their blob's entry, and they evict nothing another blob carries.
#[test]
fn junk_records_go_with_their_carrier_spec_commits_4() {
    for n in [20, 200] {
        let (carried, learned, left, genuine) = junk_records(n);
        assert_eq!(carried, n + 1, "kept loose while carried");
        assert_eq!(learned, 0, "never learned: nothing names them");
        assert_eq!(left, 1, "gone with their carrier; the other blob's stays");
        assert!(genuine, "the other blob's record, learned once awaited");
    }
}

// spec/permissions.md §4 (Logging certificates: the records missing go as one record blob of the
// logging node's, while held in its own store): what the engine keeps of a record blob it sealed under S lasts across a
// restart, goes when its own entry does (`forget_record_blob`), and goes with S when S is read here
// no more (`forget_read`; an open drops those of every sync ID not read).
#[test]
fn record_blob_rows_go_with_their_sync_id_spec_perm_4() {
    let (mut lp, ps) = people(1);
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    add_item(&mut lp, 0, d, t);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let mut rng = SeededRng::from_u64(4);
    let (b, _, _) = lp.peers[0].engine.seal_records(&s, &[ps[0]].into(), &mut rng).unwrap().expect("sealed");
    let (b2, _, _) = lp.peers[0].engine.seal_records(&s, &[ps[0]].into(), &mut rng).unwrap().expect("sealed");
    lp.peers[0].restart(8).unwrap();
    assert_eq!(lp.peers[0].engine.record_blobs(&s).unwrap().keys().copied().collect::<Vec<_>>().len(), 2, "durable");
    lp.peers[0].engine.forget_record_blob(&s, &b2).unwrap();
    assert_eq!(lp.peers[0].engine.record_blobs(&s).unwrap().keys().copied().collect::<Vec<_>>(), vec![b]);
    lp.peers[0].engine.forget_read(&s).unwrap();
    assert!(lp.peers[0].engine.record_blobs(&s).unwrap().is_empty());
    lp.peers[0].restart(9).unwrap();
    assert!(lp.peers[0].engine.record_blobs(&s).unwrap().is_empty(), "its rows gone too");
    // left while down: an open drops them
    lp.peers[0].engine.seal_records(&s, &[ps[0]].into(), &mut rng).unwrap().expect("sealed");
    let mut m = Mutation::new();
    m.op(d, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Remove(osis_base::Value::Tid(t)) }).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap();
    lp.peers[0].restart(10).unwrap();
    assert!(lp.peers[0].engine.record_blobs(&s).unwrap().is_empty(), "S not read at the open");
}

// spec/permissions.md §4 (Logging certificates: each node logs its account's chain certificates
// for the sync ID's group and for each actor it acted for, and a commit's author's chain goes
// with it), spec/sync-judgement.md §2 (required set: those certificates, nothing more): x is
// an item of t's closure that t reads; a private group h holds write on x, peer 1's account is in
// h. h's roster is no chain into t, and nobody wrote on x through h: its edge write on h is not
// under t's sync ID. Once peer 1 writes on x through h, its author's chain goes there, and a
// follower of the member commit's bodies is due after `Engine::follow` with nothing else asked.
#[test]
fn a_chain_goes_under_a_sync_id_only_for_its_group_or_a_write_there_spec_perm_4() {
    let (mut lp, ps) = people(2);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    add_item(&mut lp, 0, d, t);
    let x = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&x).unwrap();
    add_item(&mut lp, 0, t, x);
    let h = thing_of(&mut lp, 0, ps[0]);
    let e = &mut lp.peers[0].engine;
    e.give_own_secrets(&h).unwrap();
    e.grant(&x, &t, &edge_of(Role::Read)).unwrap();
    e.grant(&x, &h, &edge_of(Role::Write)).unwrap();
    let member = *e.grant(&h, &ps[1], &edge_of(Role::Write)).unwrap().commits.iter().find(|c| e.header(c).is_some_and(|hd| hd.aspects.iter().any(|a| a.tid == h && a.ak.as_str() == "roles.0"))).expect("the edge write on h");
    let s = e.home_sync_id(&t).unwrap().unwrap();
    assert_eq!(e.sync_holder(&s).unwrap(), Some((t, Holding::Read)));
    // (its `keys.0` part, the record of h's box to peer 1's account, goes as h's current `keys.0`)
    let roles = e.header(&member).unwrap().aspect_index(&h, "roles.0").unwrap();
    assert!(e.sync_bodies(&member).unwrap().get(&s).is_none_or(|b| !b.parts.contains(&roles)), "h's roster is nobody's chain into t: {:?}", e.sync_bodies(&member).unwrap());
    spread(&mut lp);
    let mut m = Mutation::new();
    m.set(x, &Ak::new("t:reg.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
    // a follower of the member commit's body under t's sync ID (sync's read): the write on x is
    // another commit, yet it moves this one's certificates, so the key goes due once `follow`ed
    let mut fx: osis_base::memo::Effects<(), bool> = osis_base::memo::Effects::new("test bodies");
    fx.want(());
    let e = &mut lp.peers[0].engine;
    fx.settle(&(), || e.sync_bodies(&member).unwrap().contains_key(&s));
    lp.peers[1].engine.commit(m).unwrap().unwrap();
    spread(&mut lp);
    let e = &mut lp.peers[0].engine;
    e.follow().unwrap();
    assert_eq!(fx.due(), [()], "the member commit's certificates moved");
    assert!(e.sync_bodies(&member).unwrap().get(&s).is_some_and(|b| b.certificate && b.copy && b.parts.contains(&roles)), "the writer's chain to x: {:?}", e.sync_bodies(&member).unwrap());
}

// spec/sync-judgement.md §1 Certificate blobs (a node logging the same parts of a commit under
// several sync IDs logs one blob, wrapped under each): the account's `keys.0` part of its creating
// commit is a certificate under the sync IDs of t and u alike; the copy sealed under one is
// wrapped for the other, under its own thing's epoch. Under D's home the commit is a closure body,
// a per-sync-ID copy of other parts, never shared as either.
#[test]
fn a_certificate_copy_is_one_blob_under_every_sync_id_spec_sync_judgement_1() {
    let (mut lp, ps) = people(1);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let t = thing_of(&mut lp, 0, ps[0]);
    let u = thing_of(&mut lp, 0, ps[0]);
    for x in [t, u] {
        lp.peers[0].engine.give_own_secrets(&x).unwrap();
        add_item(&mut lp, 0, d, x);
    }
    let e = &mut lp.peers[0].engine;
    let ids = [d, t, u].map(|x| e.home_sync_id(&x).unwrap().unwrap());
    let [home, s, su] = ids;
    let keys = e.current_keys(&ps[0]);
    let c = *keys.iter().find(|c| {
        let b = e.sync_bodies(c).unwrap();
        matches!((b.get(&s), b.get(&su)), (Some(x), Some(y)) if x.certificate && y.certificate && x.parts == y.parts)
    }).expect("one certificate body under both");
    let mut rng = SeededRng::from_u64(5);
    let (sealed, wrap) = e.seal_body(&s, &c, &[], &mut rng).unwrap().expect("sealed");
    let to = e.rewrap(&c, &sealed.id, &s, &wrap, &su).unwrap().expect("the same blob under u's sync ID");
    if e.sync_bodies(&c).unwrap().get(&home).is_some_and(|m| !m.certificate) {
        let (copy, copy_wrap) = e.seal_body(&home, &c, &[], &mut rng).unwrap().expect("the closure copy");
        assert!(e.rewrap(&c, &copy.id, &home, &copy_wrap, &s).unwrap().is_none(), "a per-sync-ID copy is no certificate elsewhere");
        assert!(e.rewrap(&c, &sealed.id, &s, &wrap, &home).unwrap().is_none(), "a certificate is no closure body");
    }
    assert!(lp.peers[0].engine.epochs(&u).is_some_and(|ep| ep.read.held().any(|(x, _)| wrap_opens_under(&lp, 0, &u, &x, &sealed.id, &to))), "wrapped under u's epoch");
}

// spec/commits.md §4 (Records: learned once something awaits it): a loose record is learned when
// a commit by its actor arrives, the author's record being what that commit awaits.
#[test]
fn a_loose_author_record_is_learned_when_its_commit_comes_spec_commits_4() {
    let mut lp = crate::common::net_bare(2, 5);
    let a = lp.peers[0].engine.create_account().unwrap().0.account;
    let b = lp.peers[1].engine.create_account().unwrap().0.account;
    let t = thing_of(&mut lp, 0, a);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let s0 = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let rec = lp.peers[1].engine.core.created(&b).cloned().unwrap();
    let (id, bytes, wrap) = record_blob_by_hand(&mut lp, 0, &t, std::slice::from_ref(&rec));
    assert!(matches!(lp.peers[0].engine.open_entry(&s0, &id, &wrap, &bytes).unwrap(), osis_engine::sync::Opened::Records(_)));
    assert!(lp.peers[0].engine.core.created(&b).is_none() && lp.peers[0].engine.carries_loose(&id));
    let u = thing_of(&mut lp, 1, b);
    let mut m = Mutation::new();
    m.set(u, &REG, &s("later")).unwrap();
    let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
    let cb = lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap();
    lp.peers[0].engine.ingest(&cb, Vec::new()).unwrap();
    assert_eq!(lp.peers[0].engine.core.created(&b), Some(&rec), "the author's record, awaited");
}

// spec/sync-set.md §3 (Unsyncing): forgetting an unsynced thing's local copy drops its content
// and that of the things under its secrets but those the synced group's closure holds; its
// role-class aspects and secrets stay (still read here), and its commits arriving again count as
// never received.
#[test]
fn forget_local_drops_content_keeps_secrets_spec_sync_set_3() {
    let (mut lp, ps) = people(1);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let t = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let under = e.new_thing(&mut m, t);
    let listed = e.new_thing(&mut m, t);
    m.set(t, &ct::NAME, &"own".to_string()).unwrap();
    m.set(under, &ct::NAME, &"under".to_string()).unwrap();
    m.set(listed, &ct::NAME, &"listed".to_string()).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let bytes = e.commit_bytes(&c).unwrap().unwrap();
    add_item(&mut lp, 0, d, listed);
    let e = &mut lp.peers[0].engine;
    let s0 = e.home_sync_id(&t).unwrap().unwrap();
    e.forget_local(&t).unwrap();
    assert_eq!(e.get_typed(&t, &ct::NAME).unwrap(), None);
    assert_eq!(e.get_typed(&under, &ct::NAME).unwrap(), None, "under its secrets");
    assert_eq!(e.get_typed(&listed, &ct::NAME).unwrap().as_deref(), Some("listed"), "in the synced group's closure");
    assert_eq!(e.thing_sync(&t).unwrap(), ThingSync::Read(vec![s0]), "secrets kept: still read");
    e.ingest(&bytes, Vec::new()).unwrap();
    assert_eq!(e.get_typed(&t, &ct::NAME).unwrap().as_deref(), Some("own"), "arrived again");
    assert_eq!(e.get_typed(&under, &ct::NAME).unwrap().as_deref(), Some("under"));
}

// spec/sync-set.md §3 (Unsyncing): one commit writing an unsynced thing and a synced one (each
// under its own secrets) keeps the synced thing's part and its own commits under its
// sync ID; the unsynced thing's part joins late when the commit arrives again.
#[test]
fn forget_local_keeps_a_spanning_commits_synced_part_spec_sync_set_3() {
    let (mut lp, ps) = people(1);
    let (_, d) = lp.peers[0].engine.account().unwrap().unwrap();
    let t = thing_of(&mut lp, 0, ps[0]);
    let v = thing_of(&mut lp, 0, ps[0]);
    lp.peers[0].engine.give_own_secrets(&t).unwrap();
    lp.peers[0].engine.give_own_secrets(&v).unwrap();
    add_item(&mut lp, 0, d, v);
    let e = &mut lp.peers[0].engine;
    let sv = e.home_sync_id(&v).unwrap().unwrap();
    let mut m = Mutation::new();
    m.set(t, &ct::NAME, &"dropped".to_string()).unwrap();
    m.set(v, &ct::NAME, &"kept".to_string()).unwrap();
    let c = e.commit(m).unwrap().unwrap();
    let bytes = e.commit_bytes(&c).unwrap().unwrap();
    assert!(e.own_commits(&sv).unwrap().contains(&c));
    e.forget_local(&t).unwrap();
    assert_eq!(e.get_typed(&t, &ct::NAME).unwrap(), None);
    assert_eq!(e.get_typed(&v, &ct::NAME).unwrap().as_deref(), Some("kept"), "the synced thing's part stays");
    assert!(e.commit_bytes(&c).unwrap().is_some(), "the commit stays with its other part");
    assert!(e.own_commits(&sv).unwrap().contains(&c), "still an own commit under the synced thing's sync ID");
    e.ingest(&bytes, Vec::new()).unwrap();
    assert_eq!(e.get_typed(&t, &ct::NAME).unwrap().as_deref(), Some("dropped"), "a late part");
    assert_eq!(e.get_typed(&v, &ct::NAME).unwrap().as_deref(), Some("kept"));
}

/// Peer `i` lists (`on`) or cuts `t` in field `f` of group `g`, as an app writes (`Engine::write`).
fn listing(lp: &mut LocalPeer, i: usize, g: Tid, f: u64, t: Tid, on: bool) {
    let op = if on { osis_crdt::Op::Add(osis_base::Value::Tid(t)) } else { osis_crdt::Op::Remove(osis_base::Value::Tid(t)) };
    let mut m = Mutation::new();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(f)], op }).unwrap();
    lp.peers[i].engine.write(m).unwrap().unwrap();
}

/// Peer `i`'s synced group.
fn synced_group(lp: &mut LocalPeer, i: usize) -> Tid {
    let e = &mut lp.peers[i].engine;
    let (_, d) = e.account().unwrap().unwrap();
    *e.get_typed(&d, &ct::SYNCED).unwrap().unwrap().get(&e.tid()).unwrap()
}

/// Whether peer `i` lists `t` as an invitation, and if so whether as acted on.
fn acted(lp: &mut LocalPeer, i: usize, t: Tid) -> Option<bool> {
    lp.peers[i].engine.invitations().unwrap().iter().find(|x| x.thing == t).map(|x| x.acted)
}

/// `acted^.0` on peer `i`'s D.
fn marks(lp: &mut LocalPeer, i: usize) -> BTreeSet<Tid> {
    let e = &mut lp.peers[i].engine;
    let (_, d) = e.account().unwrap().unwrap();
    e.get_typed(&d, &ct::ACTED).unwrap().unwrap_or_default()
}

// spec/sync-set.md §4 (Acted: a new grant is not acted on, an accept marks it, an unsync lists it
// again, acted on).
#[test]
fn accepting_then_unsyncing_marks_an_invitation_spec_sync_set_4() {
    let (mut lp, t, _, _, blob) = granted(Role::Read);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    assert_eq!(acted(&mut lp, 1, t), Some(false), "a new grant");
    let g = synced_group(&mut lp, 1);
    listing(&mut lp, 1, g, 1, t, true);
    assert_eq!(acted(&mut lp, 1, t), None, "accepted: no invitation");
    assert!(marks(&mut lp, 1).contains(&t), "the accept marks it");
    listing(&mut lp, 1, g, 1, t, false);
    assert_eq!(acted(&mut lp, 1, t), Some(true), "unsynced: an invitation acted on");
    let before = lp.peers[1].engine.core.ix.commits.len();
    listing(&mut lp, 1, g, 1, t, true);
    listing(&mut lp, 1, g, 1, t, false);
    assert_eq!(lp.peers[1].engine.core.ix.commits.len(), before + 2, "marked once: no second mark");
}

// spec/sync-set.md §4 (Acted: declining by filing the thing in a group outside every synced
// group marks it).
#[test]
fn filing_outside_the_synced_groups_marks_spec_sync_set_4() {
    let (mut lp, t, _, _, blob) = granted(Role::Read);
    lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
    let e = &mut lp.peers[1].engine;
    let (p, _) = e.account().unwrap().unwrap();
    let mut m = Mutation::new();
    let x = e.new_thing(&mut m, p);
    m.op(x, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    e.write(m).unwrap().unwrap();
    assert_eq!(acted(&mut lp, 1, t), Some(true));
    assert_eq!(marks(&mut lp, 1), BTreeSet::from([t]), "the new group it was filed in is not marked");
}

// spec/sync-set.md §4 (Acted: what a write creates, or moves inside the synced groups, is not
// marked, and cutting a subgroup marks each thing its closure held that no synced group holds now).
#[test]
fn cutting_a_subgroup_marks_what_it_held_spec_sync_set_4() {
    let (mut lp, ps) = people(1);
    let g = synced_group(&mut lp, 0);
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let sub = e.new_thing(&mut m, ps[0]);
    let t = e.new_thing(&mut m, ps[0]);
    m.set(t, &REG, &s("x")).unwrap();
    m.op(sub, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
    m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Add(osis_base::Value::Tid(sub)) }).unwrap();
    e.write(m).unwrap().unwrap();
    e.give_own_secrets(&t).unwrap();
    // listed again inside the synced groups: no change of what is synced
    listing(&mut lp, 0, g, 0, t, true);
    listing(&mut lp, 0, g, 0, t, false);
    assert!(marks(&mut lp, 0).is_empty(), "created or moved inside the synced groups: nothing marked");
    listing(&mut lp, 0, g, 1, sub, false);
    assert_eq!(acted(&mut lp, 0, t), Some(true), "own thing unsynced: an invitation acted on");
    assert_eq!(marks(&mut lp, 0), BTreeSet::from([t]), "the plain subgroup has no role of its own");
}

// spec/sync-set.md §4 (Invitations: in no synced group closure; Acted: accepting an untaken
// invitation marks it).
#[test]
fn accepting_an_untaken_invitation_marks_it_spec_sync_set_4() {
    let (mut lp, t, _, _, blob) = granted(Role::Read);
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap();
    assert_eq!(acted(&mut lp, 1, t), Some(false));
    let g = synced_group(&mut lp, 1);
    listing(&mut lp, 1, g, 1, t, true);
    assert_eq!(acted(&mut lp, 1, t), None, "listed: no invitation, taken or not");
    assert!(marks(&mut lp, 1).contains(&t));
}

// spec/sync-set.md §2 (Cost: a `group.0` change that adds a subtree costs work in proportion to
// that subtree): marking what a write acted on walks up O(n) for an add of n items.
#[test]
fn marking_an_add_costs_its_size_spec_sync_set_2() {
    let (mut lp, ps) = people(1);
    let g = synced_group(&mut lp, 0);
    let mut cost = |n: usize| -> u64 {
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let sub = e.new_thing(&mut m, ps[0]);
        for _ in 0..n {
            let t = e.new_thing(&mut m, ps[0]);
            m.op(sub, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(osis_base::Value::Tid(t)) }).unwrap();
        }
        m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(1)], op: osis_crdt::Op::Add(osis_base::Value::Tid(sub)) }).unwrap();
        osis_base::costs::take();
        e.write(m).unwrap().unwrap();
        osis_base::costs::take().iter().find(|x| x.0 == "group index: walk up").map_or(0, |x| x.2)
    };
    let (small, big) = (cost(20), cost(200));
    assert!(small > 0 && big <= 11 * small, "walks up {small} at 20, {big} at 200");
}

/// The aspects of the parts `copy` names of commit `c`.
fn copied_aks(lp: &mut LocalPeer, c: &osis_base::CommitId, copy: &osis_engine::labeling::Certs) -> BTreeSet<String> {
    let h = commit_of(lp, 0, c).header;
    copy.commits.get(c).into_iter().flatten().map(|ai| h.aspects[*ai].ak.as_str().to_string()).collect()
}

// spec/sync-inbox.md §5 (Grant copy), spec/sync-judgement.md §2 (required set: under an actor's
// inbox, its grant copies): a reader's grant copy is the grant's `roles.0` and `secrets.0` parts on
// the thing (and its keyset, the first grant's: the thing's current `keys.0`), with the thing's
// `sync.0` commits and record; a node of the grantee that took the grant holds it as a
// certificate body under the grantee's inbox once the account accepted the thing, not before.
#[test]
fn a_readers_grant_copy_carries_the_grant_spec_sync_inbox_5() {
    let (mut lp, t, p1, g, blob) = granted(Role::Read);
    let copy = lp.peers[0].engine.grant_copy(&p1, &t);
    let aks = copied_aks(&mut lp, &g, &copy);
    assert!(aks.contains("roles.0") && aks.contains("secrets.0"), "{aks:?}");
    let sync0 = lp.peers[0].engine.aspect_commits(&t, "sync.0");
    assert!(!sync0.is_empty() && sync0.iter().all(|(c, ais)| copy.commits.get(c).is_some_and(|p| p.is_superset(ais))), "the thing's sync.0 parts");
    assert!(copy.records.contains(&t), "the thing's record");
    let e = &mut lp.peers[1].engine;
    assert_eq!(e.take_inbox_blob(&blob, true).unwrap().map(|o| o.taken), Some(Taken::Applied));
    let inbox = e.inbox_of(&p1).expect("an inbox");
    assert!(!e.sync_bodies(&g).unwrap().contains_key(&inbox), "not accepted: no grant copy");
    let synced = synced_group(&mut lp, 1);
    listing(&mut lp, 1, synced, 1, t, true);
    let body = lp.peers[1].engine.sync_bodies(&g).unwrap().get(&inbox).cloned().expect("accepted: a body under the inbox");
    assert!(body.certificate, "a certificate copy");
}

// spec/sync-inbox.md §5 (Grant copy: kept once `acted^.0` lists the thing), spec/sync-set.md §4:
// peer 1 takes a stranger's grant, then marks the thing in `acted^.0` on D alone (no listing, so
// nothing else moves): the grant copy joins its inbox's required set; unmarked, it leaves again.
#[test]
fn marking_a_grant_acted_on_keeps_its_copy_spec_sync_inbox_5() {
    let (mut lp, t, p1, g, blob) = granted(Role::Read);
    let e = &mut lp.peers[1].engine;
    e.take_inbox_blob(&blob, true).unwrap();
    let inbox = e.inbox_of(&p1).expect("an inbox");
    assert!(!e.sync_bodies(&g).unwrap().contains_key(&inbox), "not accepted");
    let d = e.account().unwrap().unwrap().1;
    let mark = |e: &mut osis_engine::Engine, op| {
        let mut m = Mutation::new();
        m.op(d, &ct::ACTED, osis_crdt::PathOp { path: Vec::new(), op }).unwrap();
        e.write(m).unwrap().unwrap();
    };
    mark(e, osis_crdt::Op::Add(osis_base::Value::Tid(t)));
    assert!(e.sync_bodies(&g).unwrap().contains_key(&inbox), "accepted: a grant copy");
    mark(e, osis_crdt::Op::Remove(osis_base::Value::Tid(t)));
    assert!(!e.sync_bodies(&g).unwrap().contains_key(&inbox), "unmarked: none");
}

// spec/sync-inbox.md §5 (Grant copy: only one its author held write on the actor for, or the
// account accepted), spec/requirements.md (a node that cannot read stores content only with a
// writer's signature, beyond a small budget): peer 0 grants peer 1's account read on n things it
// mints, and peer 1 takes every grant. None is a grant copy under peer 1's inbox, at n and at 10n.
#[test]
fn a_strangers_grants_add_nothing_to_the_accounts_inbox_spec_sync_inbox_5() {
    let (mut lp, ps) = people(2);
    let mut kept = |n: usize| -> usize {
        let grants: Vec<_> = (0..n)
            .map(|_| {
                let t = thing_of(&mut lp, 0, ps[0]);
                let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
                let blob = lp.inbox_blobs(0, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).unwrap().1;
                lp.peers[1].engine.take_inbox_blob(&blob, true).unwrap();
                *done.commits.last().unwrap()
            })
            .collect();
        let e = &mut lp.peers[1].engine;
        let inbox = e.inbox_of(&ps[1]).expect("an inbox");
        grants.iter().filter(|c| e.sync_bodies(c).unwrap().contains_key(&inbox)).count()
    };
    assert_eq!((kept(4), kept(40)), (0, 0));
}

// spec/sync-inbox.md §5 (Grant copy: none for an actor holding sync alone after the edge write:
// its account's sync record holds what it keeps), spec/sync-ids.md §2 (What a sync holder
// learns: never the roster a `secrets.0` part would show): a sync holder's grant and removal copy
// nothing.
#[test]
fn a_sync_holder_has_no_grant_copy_spec_sync_inbox_5() {
    let (mut lp, t, p1, _, _) = granted(Role::Sync);
    assert!(lp.peers[0].engine.grant_copy(&p1, &t).is_empty(), "a sync grant");
    lp.peers[0].engine.demote(&t, &Demotion { holder: p1, new: None, retain: None }).unwrap();
    assert!(lp.peers[0].engine.grant_copy(&p1, &t).is_empty(), "a sync holder's removal");
}

// spec/sync-inbox.md §5 (Grant copy: a newer edge write replaces it): a reader's removal is its
// copy, the removal's `roles.0` part; the grant's leaves.
#[test]
fn a_removal_replaces_the_grant_copy_spec_sync_inbox_5() {
    let (mut lp, t, p1, g, _) = granted(Role::Read);
    let r = *lp.peers[0].engine.demote(&t, &Demotion { holder: p1, new: None, retain: None }).unwrap().commits.last().unwrap();
    let copy = lp.peers[0].engine.grant_copy(&p1, &t);
    assert!(!copy.commits.contains_key(&g), "the grant left");
    assert_eq!(copied_aks(&mut lp, &r, &copy), BTreeSet::from(["roles.0".to_string()]));
}

/// The certificate pieces `follow` derives (`sync::certified`) after `change`, on peer 0 of
/// `lp`, once everything before it is followed.
fn pieces_derived(lp: &mut LocalPeer, change: impl FnOnce(&mut LocalPeer)) -> u64 {
    lp.peers[0].engine.follow().unwrap();
    change(lp);
    osis_base::costs::take();
    lp.peers[0].engine.follow().unwrap();
    osis_base::costs::take().iter().find(|x| x.0 == "sync: certificate pieces derived").map_or(0, |x| x.2)
}

// spec/sync-inbox.md §5 (Grant copy: one per thing an edge write names the actor on): a new
// thing the actor is named on adds its own copy under the actor's inbox and derives no other;
// counted at n and 10n things.
#[test]
fn a_new_grant_copy_lists_in_proportion_to_change_spec_sync_inbox_5() {
    let derived = |n: usize| {
        let (mut lp, ps) = people(1);
        for _ in 0..n {
            thing_of(&mut lp, 0, ps[0]);
        }
        pieces_derived(&mut lp, |lp| {
            thing_of(lp, 0, ps[0]);
        })
    };
    crate::scale::flat("certificate pieces derived", derived(3), derived(30));
}

// spec/sync-inbox.md §5 (Grant copy), spec/permissions.md §4: an account granted read on n
// things (each grant copy carries the thing's keys and chains) re-derives, for a grant on one
// more and for a rotation of one of them, the pieces that thing's paths and keys make, not one
// per thing; counted at n and 10n things.
#[test]
fn an_account_named_on_many_things_derives_in_proportion_to_change_spec_sync_inbox_5() {
    let derived = |n: usize| {
        let (mut lp, ps) = people(2);
        let grant = |lp: &mut LocalPeer| {
            let t = thing_of(lp, 1, ps[1]);
            lp.peers[1].engine.grant(&t, &ps[0], &edge_of(Role::Read)).unwrap();
            lp.sync(1, 0).unwrap();
            t
        };
        let things: Vec<Tid> = (0..n).map(|_| grant(&mut lp)).collect();
        let one = pieces_derived(&mut lp, |lp| {
            grant(lp);
        });
        let rotated = pieces_derived(&mut lp, |lp| {
            lp.peers[1].engine.demote(&things[0], &Demotion { holder: ps[0], new: Some(edge_of(Role::Sync)), retain: None }).unwrap();
            lp.sync(1, 0).unwrap();
        });
        one + rotated
    };
    crate::scale::flat("certificate pieces derived", derived(3), derived(30));
}

// spec/commits.md §4 (Records: learned once something awaits it; Examined again): a pending
// commit that, examined again for one record arriving, comes to await a second record kept
// loose learns that one too, in the same `reexamine`, whichever record it awaits first.
#[test]
fn a_loose_record_awaited_after_another_arrives_is_learned_spec_commits_4() {
    for loose_author in [false, true] {
        let mut lp = crate::common::net_bare(2, 5);
        let a = lp.peers[0].engine.create_account().unwrap().0.account;
        let b = lp.peers[1].engine.create_account().unwrap().0.account;
        let t = thing_of(&mut lp, 0, a);
        lp.peers[0].engine.give_own_secrets(&t).unwrap();
        let s0 = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
        let u = thing_of(&mut lp, 1, b);
        let rb = lp.peers[1].engine.core.created(&b).cloned().unwrap();
        let ru = lp.peers[1].engine.core.created(&u).cloned().unwrap();
        let (loose, later) = if loose_author { (rb.clone(), ru.clone()) } else { (ru.clone(), rb.clone()) };
        let mut m = Mutation::new();
        m.set(u, &REG, &s("later")).unwrap();
        let c = lp.peers[1].engine.commit(m).unwrap().unwrap();
        let cb = lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap();
        // the commit first, awaiting `later`'s record (the loose one is not yet known here)
        lp.peers[0].engine.ingest(&cb, Vec::new()).unwrap();
        let first = lp.peers[0].engine.pending().into_iter().find(|(x, _)| *x == c).map(|x| x.1);
        let (id, bytes, wrap) = record_blob_by_hand(&mut lp, 0, &t, std::slice::from_ref(&loose));
        lp.peers[0].engine.open_entry(&s0, &id, &wrap, &bytes).unwrap();
        if lp.peers[0].engine.core.created(&loose.tid()).is_some() {
            continue; // the commit awaited the loose one first: learned at once (the other test)
        }
        assert!(lp.peers[0].engine.carries_loose(&id), "loose: {first:?}");
        lp.peers[0].engine.learn_records(vec![later.clone()]).unwrap();
        assert_eq!(lp.peers[0].engine.core.created(&loose.tid()), Some(&loose), "loose_author {loose_author}: awaited once {:?} arrived, now {:?}", later.tid(), lp.peers[0].engine.pending().into_iter().find(|(x, _)| *x == c));
    }
}

// spec/sync.md §3 (Sync record: a secret only beside a kept sync ID): a genuine sync secret
// learned from an entry box of a thing this node does not read and keeps no sync ID of writes
// nothing to the account's record.
#[test]
fn a_secret_without_a_kept_sync_id_records_nothing_spec_sync_3() {
    let (mut lp, t, _, _, _) = granted(Role::Sync);
    let (e, x) = lp.peers[0].engine.epochs(&t).unwrap().sync.held().map(|(e, x)| (e, x.clone())).next().expect("a sync secret");
    let p1 = &mut lp.peers[1].engine;
    assert!(!p1.learn_secret(&t, Role::Sync, e, x).unwrap());
    let (_, d) = p1.account().unwrap().unwrap();
    assert!(p1.get_typed(&d, &ct::KEPT).unwrap().is_none_or(|k| !k.contains_key(&t)), "no record entry");
}

// spec/sync.md §3 (A kept sync ID: an accept keeps the sync IDs every held boxes payload offering
// the thing names), spec/sync-hostile.md §2 (The user may accept an offer whose sync ID is a
// forger's: the genuine sync ID is kept too): an accept made while a
// forger's offer of another sync ID is held keeps both, so a forger arriving first displaces
// nothing; the forger's secret, which no step of the genuine path bears, is never recorded.
#[test]
fn an_accept_with_a_forgers_offer_held_keeps_the_genuine_too_spec_sync_3() {
    let (mut lp, t, b, _, blob) = granted(Role::Sync);
    let s = lp.peers[0].engine.home_sync_id(&t).unwrap().unwrap();
    let (real, _) = boxes_of(&mut lp, 1, &blob);
    let forger = osis_base::SyncId([0x55; 16]);
    let mut things = real.things.clone();
    things[0].sync_id = Some(forger);
    let forged = boxes_by_hand(&mut lp, 1, &osis_label::BoxesPayload::new(&b, things, None, None));
    lp.peers[1].engine.take_inbox_blob(&forged, false).unwrap();
    lp.peers[1].engine.take_inbox_blob(&blob, false).unwrap();
    accept(&mut lp, 1, t);
    let e = &mut lp.peers[1].engine;
    let r = e.sync_record(&t).unwrap().expect("kept");
    let mut want = vec![s, forger];
    want.sort();
    assert_eq!(r.sync_ids, want, "both offers' sync IDs: the genuine one kept");
}

// spec/sync.md §3 (A kept sync ID: an accept keeps none the record keeps for another thing),
// spec/sync-set.md §4: a forger's offer of its own thing naming the sync ID of a thing the
// account keeps unread is no invitation, and accepted anyway keeps that sync ID for the kept
// thing alone: the forger's thing (its tid sorting first) never holds it.
#[test]
fn an_accepted_offer_takes_no_kept_sync_id_from_another_thing_spec_sync_3() {
    let (mut lp, ps, t, s) = kept();
    let u = (0..64).map(|_| thing_of(&mut lp, 2, ps[2])).find(|u| *u < t).expect("a tid sorting before t");
    let done = lp.peers[2].engine.grant(&u, &ps[1], &edge_of(Role::Sync)).unwrap();
    let blob = lp.inbox_blobs(2, &done).unwrap().into_iter().find(|(h, _)| *h == ps[1]).unwrap().1;
    let (mut p, _) = boxes_of(&mut lp, 1, &blob);
    p.things[0].sync_id = Some(s);
    p.grant = None;
    let b = boxes_by_hand(&mut lp, 1, &p);
    assert_eq!(lp.peers[1].engine.take_inbox_blob(&b, false).unwrap().unwrap().taken, Taken::Offered);
    assert!(!lp.peers[1].engine.invitations().unwrap().iter().any(|i| i.thing == u), "no invitation");
    accept(&mut lp, 1, u);
    let e = &mut lp.peers[1].engine;
    assert!(!matches!(e.thing_sync(&u).unwrap(), ThingSync::Unread(ids) if ids.contains(&s)), "the forger's thing holds no kept sync ID");
    assert_eq!(e.sync_set().unwrap().ids.get(&s), Some(&(t, Holding::Unread)), "t keeps its sync ID");
}

// spec/sync-inbox.md §2 Taking (a boxes payload's dial hint: dialed while it is held and its sync
// IDs are kept), spec/sync-hostile.md §2 (The user may accept an offer whose sync ID is a
// forger's): an insider's offer of the kept thing under its own sync ID with its own dial hint,
// accepted, adds its hint beside the granter's: it hides no granter.
#[test]
fn an_accepted_forgers_dial_hint_hides_no_granter_spec_sync_inbox_2() {
    let (mut lp, t, _, _, blob) = granted(Role::Sync);
    let (mut p, _) = boxes_of(&mut lp, 1, &blob);
    let granter = osis_label::DialHint { dialable: [0x44; 32], urls: vec!["quic://granter".into()] };
    p.dial = Some(granter.clone());
    let genuine = boxes_by_hand(&mut lp, 1, &p);
    lp.peers[1].engine.take_inbox_blob(&genuine, false).unwrap();
    accept(&mut lp, 1, t);
    let forger = osis_label::DialHint { dialable: [0x66; 32], urls: vec!["quic://forger".into()] };
    let f = osis_label::BoxesPayload::new(&lp.peers[1].engine.me(), vec![osis_label::BoxedThing::new(t, Some(osis_base::SyncId([0x66; 16])), p.things[0].boxes.clone())], Some(forger.clone()), None);
    lp.advance(1000);
    let f = boxes_by_hand(&mut lp, 1, &f);
    assert_eq!(lp.peers[1].engine.take_inbox_blob(&f, false).unwrap().unwrap().taken, Taken::Offered);
    assert!(lp.peers[1].engine.invitations().unwrap().iter().any(|i| i.thing == t && !i.taken), "an invitation again");
    let (_, d) = lp.peers[1].engine.account().unwrap().unwrap();
    lp.peers[1].engine.accept_invite(&t, &d).unwrap();
    let r = lp.peers[1].engine.sync_record(&t).unwrap().unwrap();
    assert_eq!(r.sync_ids.len(), 2, "the user accepted the forger's sync ID too");
    assert!(r.dials.contains(&granter) && r.dials.contains(&forger), "{:?}", r.dials);
}

// spec/sync-ids.md §2 (home sync id): a commit that gives a thing role secrets of its own also
// creates its sync ID and records it in `sync.0`, in that one commit. A thing given secrets of its
// own, by `give_own_secrets` or by its first grant, has its home sync ID, and the first commit
// with a `secrets.0` part on it carries a `sync.0` write too.
#[test]
fn own_secrets_and_the_home_sync_id_come_in_one_commit_spec_sync_ids_2() {
    for by_grant in [false, true] {
        let (mut lp, ps) = people(2);
        let t = thing_of(&mut lp, 0, ps[0]);
        let e = &mut lp.peers[0].engine;
        assert_eq!(e.home_sync_id(&t).unwrap(), None, "a plain thing has none");
        let done = if by_grant { e.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap() } else { e.give_own_secrets(&t).unwrap() };
        assert!(e.home_sync_id(&t).unwrap().is_some(), "a home sync ID (by grant: {by_grant})");
        let secrets = Ak::new("secrets.0").unwrap();
        let sync = ct::SYNC.name();
        // the first commit with a secrets.0 part on t gives them (later ones box holders)
        let first = done.commits.iter().map(|c| e.header(c).unwrap()).find(|h| h.aspects.iter().any(|a| a.tid == t && a.ak == secrets)).expect("a commit gives t its secrets");
        assert!(first.aspects.iter().any(|a| a.ak == sync), "the commit giving t secrets writes sync.0 (by grant: {by_grant})");
    }
}
