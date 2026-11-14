//! Opens: records, agreement, the shared set, filters, Offer and ending (spec/sync-opens.md §3-§6),
//! between honest sides and against hostile scripted peers (harness::scripted). Each test named
//! for a NetOpen control (core/test/tla/net/NetOpen.tla, `ON_*`) fails when that control's rule
//! is taken out of `osis_sync::opens`.

use crate::harness::scripted::*;
use osis_base::SyncId;
use osis_engine::sync::J;
use osis_proto::{Code, Msg, OfferItem};
use osis_sync::opens::{Moved, Rejoin};
use osis_sync::session::Proven;
use osis_sync::types::{Credential, SourceClass};

const S: SyncId = SyncId([5; 16]);

/// Two readers of S holding one read secret.
fn readers() -> Pair {
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    a.settle();
    b.settle();
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    p
}

// spec/sync-opens.md §5 (opening): one Hit and its answer open S both ways.
#[test]
fn one_hit_opens_both_ways_spec_sync_opens_5() {
    let p = readers();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    let m = &p.a.opens.members(p.ca)[&S];
    assert_eq!((m.class, m.by), (SourceClass::Reader, Credential::ReadSecret(epoch(0))));
    assert!(p.a.opens.record(p.ca).is_some() && p.b.opens.record(p.cb).is_some());
}

// spec/sync-opens.md §3 (pair key): a second connection resumes the record: its members open
// again without an Offer, the digests match.
#[test]
fn a_record_resumes_its_shared_set_spec_sync_opens_3() {
    let mut p = readers();
    p.close();
    p.a.moved.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    assert!(p.a.moved.iter().any(|m| matches!(m, Moved::Joined(c, s, _) if *c == p.ca && *s == S)));
    assert!(p.a.opens.agreed(p.ca) && p.b.opens.agreed(p.cb));
}

fn sid(n: u8) -> SyncId {
    SyncId([n; 16])
}

/// The Hits of every Offer among `sent`.
fn offered_hits(sent: &[(osis_sync::types::ConnId, Msg)]) -> usize {
    of_kind(sent, 37).iter().map(|m| match m {
        Msg::Offer { items, .. } => items.iter().filter(|i| matches!(i, OfferItem::Hit { .. } | OfferItem::Static { .. })).count(),
        _ => 0,
    }).sum()
}

// spec/sync-opens.md §4 (source): a reader opens a node keeping S unread by a credential of its
// step; the member is a store source at that step. Neither knows the other: no record (§3).
#[test]
fn a_reader_opens_a_store_at_its_step_spec_sync_opens_4() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    let mut k = Side::new(2);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    k.table.set(S, Some(store(&st)));
    let mut p = Pair::new(r, k, Proven::default(), Proven::default());
    p.run();
    assert!(p.a.opens.record(p.ca).is_none() && p.b.opens.record(p.cb).is_none());
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    assert_eq!(p.a.opens.members(p.ca)[&S].class, SourceClass::Store);
}

// spec/sync-opens.md §4 (Admissible: keeping S unread with no head, its step is the newest sync
// secret it holds) and spec/sync-ids.md §6 (Walk): a node granted sync that starts keeping S
// after the reader tested it there (nothing shown then) opens S by its own test when it does:
// the reader tests nothing again. NetOpen `ON_shownkey` (a store with no step shows and tests
// nothing) fails this.
#[test]
fn a_store_granted_later_opens_with_no_head_spec_sync_opens_4() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    let k = Side::new(2);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    r.table.judge_as(S, tid(2), J::SyncHolder);
    r.settle();
    let mut p = Pair::new(r, k, account(1), account(2));
    p.run();
    assert!(!p.a.open(p.ca, &S));
    let tested = p.a.opens.work().tested;
    p.b.table.set(S, Some(store_no_head(&[&st])));
    p.b.settle();
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "open both ways");
    assert_eq!(p.a.opens.members(p.ca)[&S].class, SourceClass::Store);
    assert_eq!(p.a.opens.work().tested, tested, "the reader tested nothing again");
}

// spec/sync-opens.md §4 (Admissible: keeping S unread with no head, each sync secret it holds is
// its step), §5 (Proof an answer carries: a sync key's Hit by that key), spec/sync-hostile.md (a
// box at a self-made epoch blocks no other open): a store with no head holding its grant's secret
// and a newer one (a hostile box's) opens toward a reader of the grant's step that neither knows
// nor shows a proof to it: the reader's sync key Hit is answered by that key, which it verifies.
#[test]
fn a_store_with_no_head_opens_by_its_grant_under_a_newer_box_spec_sync_opens_4() {
    let (st, junk) = (StepKeys::new(1, 0), StepKeys::new(7, 9));
    let mut r = Side::new(1);
    let mut k = Side::new(2);
    let mut rc = reader(&S, &read_secret(1, 0), &st, &[], &[], &[]);
    rc.shows.retain(|(x, _)| !matches!(x, osis_sync::opens::cred::Shown::Proof(_)));
    r.table.set(S, Some(rc));
    k.table.set(S, Some(store_no_head(&[&junk, &st])));
    let mut p = Pair::new(r, k, Proven::default(), Proven::default());
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "open both ways");
    assert_eq!(p.a.opens.members(p.ca)[&S].by, Credential::SyncKey);
}

// spec/sync-ids.md §6 (Walk: a refused Hit counts as none shown): a reader whose walk Hit at a
// sync holder is refused (a false positive of the filter) asks Behind next.
#[test]
fn a_refused_walk_hit_asks_behind_spec_sync_ids_6() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    r.table.judge_as(S, tid(9), J::SyncHolder);
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    adv.filter(&mut r, &[st.pk()], &S);
    let sent = r.sent();
    let Some(Msg::Offer { id, items }) = of_kind(&sent, 37).pop() else { panic!("an Offer") };
    assert!(matches!(items.as_slice(), [OfferItem::Hit { .. }]), "the walk's sync key shown: Hit, {items:?}");
    adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem::code(Code::DECLINED)] });
    let sent = r.sent();
    let Some(Msg::Offer { items, .. }) = of_kind(&sent, 37).pop() else { panic!("a Behind follows") };
    assert!(matches!(items.as_slice(), [OfferItem::Behind(b)] if b.sync_id == S), "{items:?}");
}

// spec/sync-opens.md §5 (Proof an answer carries: its head at a node keeping S unread): a node
// keeping S unread answers a Hit on its head's sync key, so a reader whose filter shows nothing
// the store tests (no sync proof yet) still opens S by its walk's sync key.
#[test]
fn a_store_answers_a_hit_on_its_heads_sync_key_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    let mut k = Side::new(2);
    let mut rc = reader(&S, &read_secret(1, 0), &st, &[], &[], &[]);
    rc.shows.retain(|(x, _)| !matches!(x, osis_sync::opens::cred::Shown::Proof(_)));
    r.table.set(S, Some(rc));
    k.table.set(S, Some(store(&st)));
    let mut p = Pair::new(r, k, Proven::default(), Proven::default());
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    assert_eq!(p.b.opens.members(p.cb)[&S].by, Credential::SyncKey);
}

// spec/sync-opens.md §5 (ByRole): J judging the peer a reader opens S with no credential in
// common.
#[test]
fn byrole_opens_on_j_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &read_secret(9, 0), &StepKeys::new(9, 0), &[], &[], &[])));
    a.table.judge_as(S, tid(2), J::Reader);
    b.table.judge_as(S, tid(1), J::Reader);
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    assert_eq!(p.a.opens.members(p.ca)[&S].by, Credential::J);
}

// spec/sync-opens.md §3 (agreement): a member only one side's record holds closes there, with
// no position kept, and is tested again: the two sides open it again.
#[test]
fn a_digest_difference_closes_one_sided_members_spec_sync_opens_3() {
    let mut p = readers();
    p.close();
    // While apart, `a` stops and starts syncing S: its record drops S.
    let c = p.a.table.creds[&S].as_ref().clone();
    p.a.table.set(S, None);
    p.a.settle();
    p.a.table.set(S, Some(c));
    p.a.settle();
    p.a.sent();
    p.b.moved.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.b.moved.iter().any(|m| matches!(m, Moved::Left(c, S, _) if *c == p.cb)), "the one-sided member closed: {:?}", p.b.moved);
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "tested again and open");
    assert!(p.b.moved.contains(&Moved::Joined(p.cb, S, Rejoin::From(None))), "rejoined from the start: {:?}", p.b.moved);
}

// spec/sync-opens.md §6 (Lost): the receiver keeps the Lost's cursor (where the member stopped for
// it, in the sender's log) and its rejoin reads from there; a member left with its connection
// rejoins from where its own stream holds it.
#[test]
fn a_rejoin_reads_from_the_losts_cursor_spec_sync_opens_6() {
    let mut p = readers();
    // b stored a's log at 7 for S (a learns it from b's Applied)
    p.a.reported(p.ca, S, 7);
    let c = p.a.table.creds[&S].as_ref().clone();
    p.a.table.set(S, None);
    p.a.settle();
    p.run();
    assert!(!p.b.open(p.cb, &S));
    p.b.moved.clear();
    p.a.table.set(S, Some(c));
    p.a.settle();
    p.run();
    assert!(p.b.open(p.cb, &S));
    assert!(p.b.moved.contains(&Moved::Joined(p.cb, S, Rejoin::From(Some(7u64.to_be_bytes().to_vec())))), "{:?}", p.b.moved);
    // a reconnect: the record's members rejoin as their streams hold them
    p.close();
    p.b.moved.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.b.moved.contains(&Moved::Joined(p.cb, S, Rejoin::Held)), "{:?}", p.b.moved);
}

// spec/sync-opens.md §3 (a node that stops holding S drops S from every record in the step that
// stops it): where a peer's Lost said the member stopped goes with S's shred, so a later join
// does not read from that old cursor (the store holds nothing of S any more).
#[test]
fn a_shred_drops_where_a_member_stopped_spec_sync_opens_3() {
    let mut p = readers();
    p.a.reported(p.ca, S, 7);
    let c = p.a.table.creds[&S].as_ref().clone();
    p.a.table.set(S, None);
    p.a.settle();
    p.run();
    assert!(!p.b.open(p.cb, &S));
    p.b.store.shred(&S).unwrap();
    p.b.moved.clear();
    p.a.table.set(S, Some(c));
    p.a.settle();
    p.run();
    assert!(p.b.open(p.cb, &S));
    assert!(p.b.moved.iter().any(|m| matches!(m, Moved::Joined(c, s, r) if *c == p.cb && *s == S && *r != Rejoin::From(Some(7u64.to_be_bytes().to_vec())))), "not from the Lost's cursor: {:?}", p.b.moved);
}

// spec/sync-opens.md §6 (closed here): a member this side closed rejoins from the start unless it
// holds the peer's Lost for it. Here the peer's crossed Lost is lost with the connection (this
// side's own Lost never arrives), so the rejoin reads from the start: nothing the peer logged
// between its `until` and where this side's stream stood is skipped.
#[test]
fn a_member_closed_here_without_the_peers_lost_rejoins_from_the_start_spec_sync_opens_6() {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &read_secret(9, 0), &StepKeys::new(9, 0), &[], &[], &[])));
    a.table.judge_as(S, tid(2), J::Reader);
    b.table.judge_as(S, tid(1), J::Reader);
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    p.a.reported(p.ca, S, 7);
    // a judges b departed: S closes there at once with a Lost, which the connection drops
    p.a.table.judge_as(S, tid(2), J::Departed);
    p.a.settle();
    assert!(!p.a.open(p.ca, &S));
    p.close();
    p.a.table.judge_as(S, tid(2), J::Reader);
    p.a.settle();
    p.a.moved.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    assert!(p.a.moved.contains(&Moved::Joined(p.ca, S, Rejoin::From(None))), "from the start: {:?}", p.a.moved);
}

// spec/sync-opens.md §4 (shared set): a side keeping no shared set yet answers its requests 14.
#[test]
fn no_shared_set_yet_answers_14_spec_sync_opens_4() {
    let mut r = Side::new(1);
    let mut adv = Adv::connect(&mut r, false, [1; 32], [2; 32], Proven::default());
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 1, base: None, f: 8, lo: 0, hi: 256, gcs: Vec::new(), more: false });
    assert!(r.sent().iter().any(|(_, m)| *m == Msg::Error { id, code: Code::DECLINED }));
}

// spec/sync-opens.md §3 (agreement): no Offer goes before the peer's Digest is read.
#[test]
fn no_offer_before_the_peers_digest_spec_sync_opens_3() {
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    r.settle();
    // `r` dials Adv, which it knows: Resume.
    let mut adv = Adv::connect(&mut r, true, [1; 32], [2; 32], account(9));
    let sent = r.sent();
    let Some(Msg::Resume { id, nonce, .. }) = of_kind(&sent, 34).pop() else { panic!("Resume") };
    let an = [3; 32];
    adv.send(&mut r, Msg::Resumed { id, nonce: an, tag: None });
    let rr = *osis_crypto::kdf::pair_key(&nonce, &an).expose();
    let b = osis_crypto::kdf::beacon(rs.1.expose(), &S.0, &rr);
    let f = 8;
    let gcs = osis_proto::filter::encode_gcs(&[osis_proto::filter::beacon_value(&b, f)], 0);
    let fid = adv.id();
    adv.send(&mut r, Msg::Beacons { id: fid, generation: 1, base: None, f, lo: 0, hi: 256, gcs, more: false });
    assert_eq!(offered_hits(&r.sent()), 0, "no Offer before the Digest");
    adv.send(&mut r, Msg::Digest { digest: [0; 32] });
    assert_eq!(offered_hits(&r.sent()), 1, "the Offer follows the Digest");
}

// spec/sync-opens.md §5 (Filter): every shown credential's beacon goes to every connection, one
// whose peer proved no actor included: a read secret's and a sync proof's.
#[test]
fn every_beacon_goes_to_every_peer_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    r.settle();
    let (_adv, sent) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    assert_eq!(filter_values(&sent).0.len(), 2, "the read secret and the proof");
}

// spec/sync-opens.md §5 (filter): additions naming a base the receiver does not hold are
// answered 13; a page breaking the format is answered 2 and closes the connection.
#[test]
fn a_filter_on_an_unheld_base_is_answered_13_spec_sync_opens_5() {
    let mut r = Side::new(1);
    let (mut adv, _) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 2, base: Some(1), f: 8, lo: 0, hi: 256, gcs: Vec::new(), more: false });
    assert_eq!(shared(&r.sent(), id).unwrap()[0].code, Code::UNKNOWN_SYNC_ID);
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 3, base: None, f: 8, lo: 0, hi: 128, gcs: Vec::new(), more: false });
    assert!(r.sent().iter().any(|(_, m)| *m == Msg::Error { id, code: Code::MALFORMED }));
    assert!(!r.pipe.closed.is_empty());
}

// spec/sync-opens.md §3 (records): a connection with an acknowledged record sends additions
// first, not a whole filter.
#[test]
fn a_resumed_record_sends_additions_first_spec_sync_opens_5() {
    let mut p = readers();
    p.close();
    p.log.clear();
    p.connect(2, account(1), account(2));
    p.run();
    let bases: Vec<Option<u64>> = p.log.iter().filter_map(|(from_a, m)| match m {
        Msg::Beacons { base, .. } if *from_a => Some(*base),
        _ => None,
    }).collect();
    assert!(!bases.is_empty() && bases.iter().all(Option::is_some), "{bases:?}");
}

// spec/sync-opens.md §5 (testing): a Hit that opened nothing is tried again on that connection
// only once something re-marks S (here the peer's Lost).
#[test]
fn a_refused_hit_is_tried_again_only_when_remarked_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    r.settle();
    let (mut adv, sent) = Adv::dials(&mut r, account(9), [2; 32]);
    // Adv acknowledges r's filter and shows r's read secret: r Hits, Adv refuses.
    for m in of_kind(&sent, 36) {
        let id = m.id();
        adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem::code(Code::OK)] });
    }
    adv.filter(&mut r, &[*rs.1.expose()], &S);
    let sent = r.sent();
    assert_eq!(offered_hits(&sent), 1);
    let oid = of_kind(&sent, 37)[0].id();
    adv.send(&mut r, Msg::Shared { id: oid, items: vec![osis_proto::SharedItem::code(Code::DECLINED)] });
    r.sent();
    // A later filter arrival tests nothing new.
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 2, base: Some(1), f: 8, lo: 0, hi: 256, gcs: Vec::new(), more: false });
    assert_eq!(offered_hits(&r.sent()), 0, "not tried again without a re-mark");
    let id = adv.id();
    adv.send(&mut r, Msg::Lost { id, items: vec![(S, None)] });
    assert_eq!(offered_hits(&r.sent()), 1, "a Lost re-marks S");
}

// ---- NetOpen controls (core/test/tla/net/NetOpen.tla, ON_*): the hostile cases ----

/// A store K at `head` that Adv dials keeping no record; Adv holds `adv_steps` seeds.
fn store_dialed_by_adv(head: &StepKeys, ch_adv: [u8; 32]) -> (Side, Adv) {
    let mut k = Side::new(3);
    k.table.set(S, Some(store(head)));
    k.settle();
    let (mut adv, _) = Adv::dials(&mut k, Proven::default(), ch_adv);
    hit_once(&mut k, &mut adv);
    (k, adv)
}

/// Adv Hits nothing K shows, so K indexes the Hits its filter makes possible now: what it shows
/// later must not take an entry of that index for proof.
fn hit_once(h: &mut Side, adv: &mut Adv) {
    assert_eq!(adv.offer(h, vec![OfferItem::Hit { hit: [0; 32], sig: None }])[0].code, Code::DECLINED);
}

/// Adv's Hit on a sync key it holds the secret of, with its open signature.
fn sync_key_hit(adv: &Adv, st: &StepKeys) -> OfferItem {
    OfferItem::Hit { hit: adv.hit_on(&st.pk(), &S), sig: Some(adv.bind.sign(&st.sync, &S)) }
}

// ON_old (spec/sync-opens.md §4, shared set): a step older than the newest the judge knows
// proves nothing: after K's head moves, Adv's Hit by the old step's sync key (an entry K's
// stored filter at Adv still holds) opens nothing.
#[test]
fn an_older_steps_sync_key_proves_nothing_spec_sync_opens_4() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    let a = adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    assert_eq!(a[0].code, Code::DECLINED);
    assert!(!k.open(adv.peer, &S));
    // At the newest step it opens (the Hit is Adv's to make while it holds that seed).
    let a = adv.offer(&mut k, vec![sync_key_hit(&adv, &s1)]);
    assert_eq!(a[0].code, Code::OK);
    assert!(k.open(adv.peer, &S));
}

// ON_proofold (spec/sync-opens.md §4): an older step's sync proof proves nothing.
#[test]
fn an_older_steps_proof_proves_nothing_spec_sync_opens_4() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    let a = adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&s0.proof, &S), sig: None }]);
    assert_eq!(a[0].code, Code::DECLINED);
    assert!(!k.open(adv.peer, &S));
}

// ON_proofpub (spec/sync-ids.md §2, spec/sync-opens.md §4): the sync proof derives from the sync
// secret's seed; a node holding only the public sync key computes no proof K accepts.
#[test]
fn a_proof_from_the_public_key_proves_nothing_spec_sync_opens_4() {
    let s0 = StepKeys::new(1, 0);
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    // The proof's derivation applied to the public key in place of the seed.
    let fake = *osis_crypto::kdf::kdf(osis_crypto::kdf::SYNC_PROOF, &s0.pk(), b"").expose();
    let a = adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&fake, &S), sig: None }]);
    assert_eq!(a[0].code, Code::DECLINED);
    assert!(!k.open(adv.peer, &S));
}

// ON_answer (spec/sync-opens.md §4-§5): a tag on a public value proves nothing: K Hits its head's
// sync key in Adv's filter, Adv answers with the tag (computable from the public key) and no
// signature; K opens nothing and ends with Lost.
#[test]
fn an_answer_on_a_public_value_opens_nothing_spec_sync_opens_5() {
    let s0 = StepKeys::new(1, 0);
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.filter(&mut k, &[s0.pk()], &S);
    let sent = k.sent();
    let offer = of_kind(&sent, 37).pop().expect("K Hits the sync key Adv shows");
    let tag = adv.tag_on(&s0.pk(), &S);
    adv.send(&mut k, Msg::Shared { id: offer.id(), items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: None }] });
    assert!(!k.open(adv.peer, &S));
    assert_eq!(of_kind(&k.sent(), 38).len(), 1, "Lost for what Adv accepted");
}

// ON_side (spec/wire.md §11.2): an open signature binds its signer's side: Adv copies K's Hello
// challenge and reflects K's own Hit signature as its answer; K opens nothing.
#[test]
fn a_reflected_open_signature_opens_nothing_spec_wire_11_2() {
    let s0 = StepKeys::new(1, 0);
    let mut k = Side::new(3);
    k.table.set(S, Some(store(&s0)));
    k.settle();
    // K dials Adv, whose challenge is K's own.
    let ch = [0x33; 32];
    let mut adv = Adv::connect(&mut k, true, ch, ch, Proven::default());
    k.sent();
    adv.filter(&mut k, &[s0.pk()], &S);
    let sent = k.sent();
    let Some(Msg::Offer { id, items }) = of_kind(&sent, 37).pop() else { panic!("an Offer") };
    let Some(OfferItem::Hit { sig: Some(reflected), .. }) = items.into_iter().next() else { panic!("a signed Hit") };
    let tag = adv.tag_on(&s0.pk(), &S);
    adv.send(&mut k, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: Some(reflected) }] });
    assert!(!k.open(adv.peer, &S));
}

// ON_endsync (spec/sync-opens.md §6): an open by a sync key is re-judged when the head moves: it
// is ended (`until`) and closes with a Lost once the peer reported it.
#[test]
fn a_sync_key_open_ends_when_the_head_moves_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    assert_eq!(adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)])[0].code, Code::OK);
    assert!(k.open(adv.peer, &S));
    k.table.set(S, Some(store(&s1)));
    k.settle();
    assert_eq!(k.opens.members(adv.peer)[&S].until, Some(k.table.until));
    k.sent();
    k.reported(adv.peer, S, k.table.until);
    assert!(!k.open(adv.peer, &S));
    let lost = of_kind(&k.sent(), 38);
    assert!(matches!(&lost[..], [Msg::Lost { items, .. }] if items[0].0 == S && items[0].1.is_some()));
}

// spec/sync-opens.md §6 (reported positions): an Applied moves every member at the stream; an
// ended member there closes with a Lost naming `until` once the stream passes it, and not before.
#[test]
fn an_ended_member_closes_when_the_stream_passes_until_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    let until = k.table.until;
    assert!(k.moved.contains(&Moved::Until(adv.peer, S)));
    k.reported_stream(adv.peer, until - 1);
    assert!(k.open(adv.peer, &S));
    k.sent();
    // past `until`: the Lost names `until`, the lower (spec/sync-opens.md §6 Lost)
    k.reported_stream(adv.peer, until + 5);
    assert!(!k.open(adv.peer, &S));
    assert!(matches!(&of_kind(&k.sent(), 38)[..], [Msg::Lost { items, .. }] if items[0] == (S, osis_proto::Cursor::new(until.to_be_bytes().to_vec()).ok())));
}

// ON_endproof (spec/sync-opens.md §6): an open by a sync proof is re-judged at a rotation.
#[test]
fn a_proof_open_ends_at_a_rotation_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    assert_eq!(adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&s0.proof, &S), sig: None }])[0].code, Code::OK);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    assert!(k.opens.members(adv.peer)[&S].until.is_some(), "ended");
}

/// A reader R of S whose roster lists Adv's link `l`, dialed by Adv keeping no record.
fn reader_with_link(l: &osis_crypto::SigningSecret) -> (Side, Adv) {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(4);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[l], &[])));
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    hit_once(&mut r, &mut adv);
    (r, adv)
}

fn static_item(adv: &Adv, l: &osis_crypto::SigningSecret) -> OfferItem {
    let e = osis_crypto::static_entry(&S, &l.verifying_key());
    OfferItem::Static { hit: adv.hit_on(&e, &S), signing_pk: l.verifying_key().to_bytes(), sig: adv.bind.sign(l, &S) }
}

// ON_linkold (spec/sync-opens.md §4): a static entry counts only while the roster held now lists
// it: Adv Hits its removed entry, left in R's filter as Adv stored it.
#[test]
fn a_removed_static_entry_proves_nothing_spec_sync_opens_4() {
    let l = link_key(7);
    let (mut r, mut adv) = reader_with_link(&l);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &StepKeys::new(1, 0), &[], &[], &[])));
    r.settle();
    assert_eq!(adv.offer(&mut r, vec![static_item(&adv, &l)])[0].code, Code::DECLINED);
    assert!(!r.open(adv.peer, &S));
}

// ON_endlink (spec/sync-opens.md §6): an open by a static entry is re-judged when the roster
// drops it.
#[test]
fn a_static_open_ends_when_the_roster_drops_it_spec_sync_opens_6() {
    let l = link_key(7);
    let (mut r, mut adv) = reader_with_link(&l);
    assert_eq!(adv.offer(&mut r, vec![static_item(&adv, &l)])[0].code, Code::OK);
    assert!(r.open(adv.peer, &S));
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &StepKeys::new(1, 0), &[], &[], &[])));
    r.settle();
    assert!(r.opens.members(adv.peer)[&S].until.is_some(), "ended");
}

/// A reader R of S knowing Adv's account 9, dialed by Adv keeping no record, J of Adv `j`.
fn reader_judging(j: J) -> (Side, Adv) {
    let mut r = Side::new(4);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &StepKeys::new(1, 0), &[], &[], &[])));
    r.table.judge_as(S, tid(9), j);
    r.settle();
    let (adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    (r, adv)
}

// ON_jnow (spec/sync-opens.md §4 J): J reads the roster held now, not the one the connection
// started with: Adv's ByRole after its removal opens nothing, and a grant made while connected
// opens by J (R itself offers ByRole).
#[test]
fn j_is_judged_on_the_roster_held_now_spec_sync_opens_4() {
    let (mut r, mut adv) = reader_judging(J::Reader);
    r.table.judge_as(S, tid(9), J::Departed);
    r.settle();
    assert_eq!(adv.offer(&mut r, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new() }])[0].code, Code::DECLINED);
    assert!(!r.open(adv.peer, &S));
    let (mut r, mut adv) = reader_judging(J::Unknown);
    adv.filter(&mut r, &[], &S);
    r.sent();
    r.table.judge_as(S, tid(9), J::Reader);
    r.settle();
    let byrole = of_kind(&r.sent(), 37).iter().any(|m| matches!(m, Msg::Offer { items, .. } if items.iter().any(|i| matches!(i, OfferItem::ByRole { sync_id, .. } if *sync_id == S))));
    assert!(byrole, "ByRole once J judges Adv a reader");
    assert_eq!(adv.offer(&mut r, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new() }])[0].code, Code::OK);
    assert!(r.open(adv.peer, &S));
}

// ON_endj (spec/sync-opens.md §6): an open by J closes at once with a Lost when J judges the peer
// departed.
#[test]
fn a_j_open_closes_at_a_removal_spec_sync_opens_6() {
    let (mut r, mut adv) = reader_judging(J::Reader);
    assert_eq!(adv.offer(&mut r, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new() }])[0].code, Code::OK);
    assert!(r.open(adv.peer, &S));
    r.sent();
    r.table.judge_as(S, tid(9), J::Departed);
    r.settle();
    assert!(!r.open(adv.peer, &S));
    assert_eq!(of_kind(&r.sent(), 38).len(), 1, "a Lost");
}

// ON_departed (spec/sync-opens.md §4 (departed)): a side MUST NOT open S toward a peer J judges
// departed by a credential at an epoch not covering every departure: Adv, removed, still holds
// R's current read secret and proof (no rotation yet); R shows it nothing and accepts none of it.
#[test]
fn nothing_opens_toward_a_departed_peer_spec_sync_opens_4() {
    let rs = read_secret(1, 0);
    let st = StepKeys::new(1, 0);
    let (mut r, mut adv) = reader_judging(J::Departed);
    let a = adv.offer(&mut r, vec![OfferItem::Hit { hit: adv.hit_on(rs.1.expose(), &S), sig: None }, OfferItem::Hit { hit: adv.hit_on(&st.proof, &S), sig: None }]);
    assert!(a.iter().all(|x| x.code == Code::DECLINED), "{a:?}");
    adv.filter(&mut r, &[*rs.1.expose(), st.pk()], &S);
    assert_eq!(offered_hits(&r.sent()), 0, "R tests nothing toward Adv");
    assert!(!r.open(adv.peer, &S));
    // At an epoch covering the departure, R's credentials of it count again.
    let rs1 = read_secret(1, 1);
    r.table.covering.insert((S, rs1.0));
    r.table.set(S, Some(reader(&S, &rs1, &st, &[], &[], &[])));
    r.settle();
    assert_eq!(adv.offer(&mut r, vec![OfferItem::Hit { hit: adv.hit_on(rs1.1.expose(), &S), sig: None }])[0].code, Code::OK);
}

// ON_dialer (spec/sync-opens.md §4): which side dialed proves nothing. K dials Adv, which holds
// only S's public values and proves nothing: Adv claiming K reads S (ByRole) opens nothing, and
// K's Hit on the sync key Adv shows, answered with the tag anyone holding the key computes and no
// signature, opens nothing either; K sends Adv the same as when Adv dials it.
#[test]
fn dialing_proves_nothing_spec_sync_opens_4() {
    let s0 = StepKeys::new(1, 0);
    let mut outcome = Vec::new();
    for k_dials in [true, false] {
        let mut k = Side::new(3);
        k.table.set(S, Some(store(&s0)));
        k.settle();
        let mut adv = Adv::connect(&mut k, k_dials, [1; 32], [2; 32], Proven::default());
        if !k_dials {
            let id = osis_proto::limits::NO_RECORD_ID;
            adv.send(&mut k, Msg::NoRecord { id });
        }
        k.sent();
        assert_eq!(adv.offer(&mut k, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new() }])[0].code, Code::DECLINED);
        adv.filter(&mut k, &[s0.pk()], &S);
        let sent = k.sent();
        let Some(Msg::Offer { id, .. }) = of_kind(&sent, 37).pop() else { panic!("K Hits the sync key Adv shows") };
        let tag = adv.tag_on(&s0.pk(), &S);
        adv.send(&mut k, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: None }] });
        assert!(!k.open(adv.peer, &S), "k dials: {k_dials}");
        outcome.push((k.opens.record(adv.peer).is_some(), of_kind(&k.sent(), 38).len()));
    }
    assert_eq!(outcome[0], outcome[1], "the dialer and the dialed act alike");
}

// ON_nolisten (spec/sync-opens.md §5): a listener signs its answer: a link holder X dials reader
// R (the listener); R answers X's static entry Hit with its step's open signature and the grant,
// and both open.
#[test]
fn a_listener_signs_its_answer_spec_sync_opens_5() {
    let l = link_key(7);
    let st = StepKeys::new(1, 0);
    let mut x = Side::new(5);
    x.table.set(S, Some(link_holder(&l)));
    x.table.grants.insert(S, st.pk());
    let mut r = Side::new(4);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[&l], &[])));
    r.table.gives_grant = true;
    let mut p = Pair::new(x, r, Proven::default(), Proven::default());
    p.run();
    assert!(p.b.open(p.cb, &S), "the listener opened");
    assert!(p.a.open(p.ca, &S), "the dialer opened on the listener's signature");
    assert!(p.a.table.taken.contains(&S), "the grant taken once its signature verified");
}

// spec/sync-opens.md §5 (Opening: for a static entry the tester takes the box's secrets, and
// opens, only when `sig` verifies under the head's sync key): the grant's box and path name a
// head sync key the replier's signature is not by; the tester takes nothing and opens nothing.
#[test]
fn a_static_grant_is_taken_only_once_its_signature_verifies_spec_sync_opens_5() {
    let l = link_key(7);
    let st = StepKeys::new(1, 0);
    let mut x = Side::new(5);
    x.table.set(S, Some(link_holder(&l)));
    x.table.grants.insert(S, StepKeys::new(2, 0).pk());
    let mut r = Side::new(4);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[&l], &[])));
    r.table.gives_grant = true;
    let mut p = Pair::new(x, r, Proven::default(), Proven::default());
    p.run();
    assert!(p.a.table.taken.is_empty(), "no secret learned before the signature verifies");
    assert!(!p.a.open(p.ca, &S), "the tester opened nothing");
}

// ---- work in proportion to change (notes/coordination.md, Check scaling) ----

/// Two readers sharing `n` sync IDs, all open; then one sync ID's credentials move on both.
/// The work of that change, at each side.
fn change_one_of(n: u8) -> osis_sync::opens::Work {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 0..n {
        let rs = read_secret(i, 0);
        a.table.set(sid(i), Some(reader(&sid(i), &rs, &st, &[], &[], &[])));
        b.table.set(sid(i), Some(reader(&sid(i), &rs, &st, &[], &[], &[])));
    }
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!((0..n).all(|i| p.a.open(p.ca, &sid(i))));
    let before = p.a.opens.work();
    let rs = read_secret(0, 1);
    p.a.table.set(sid(0), Some(reader(&sid(0), &rs, &st, &[], &[], &[])));
    p.b.table.set(sid(0), Some(reader(&sid(0), &rs, &st, &[], &[], &[])));
    p.settle();
    assert!(p.a.open(p.ca, &sid(0)));
    let w = p.a.opens.work();
    osis_sync::opens::Work { rejudged: w.rejudged - before.rejudged, beacons: w.beacons - before.beacons, tested: w.tested - before.tested, creds: w.creds - before.creds }
}

// spec/sync-opens.md §6: a change of one sync ID's credentials re-judges, tests and filters that
// sync ID alone: the same work at n and 10n sync IDs held.
#[test]
fn a_credential_change_costs_the_same_at_n_and_10n_spec_sync_opens_6() {
    let (small, large) = (change_one_of(10), change_one_of(100));
    assert_eq!(small, large);
    assert!(small.rejudged >= 1 && small.creds == 1, "{small:?}");
}

// A change of one sync ID costs in proportion to the connections, not the sync IDs times them:
// the honest side holds `n` sync IDs and `c` silent connections.
fn change_with_conns(n: u8, c: u64) -> u64 {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    for i in 0..n {
        r.table.set(sid(i), Some(reader(&sid(i), &read_secret(i, 0), &st, &[], &[], &[])));
    }
    r.settle();
    for k in 0..c {
        let peer = osis_sync::types::ConnId(ConnIdBit::ACCEPTED | (100 + k));
        let (_, bb) = binds([k as u8; 32], [0xee; 32], [0x77; 32]);
        r.pipe.binds.insert(peer, (bb, Proven::default()));
        r.take(peer, osis_sync::session::Incoming::Proved);
        r.take(peer, incoming(Msg::NoRecord { id: osis_proto::limits::NO_RECORD_ID }));
    }
    r.sent();
    let before = r.opens.work().beacons;
    r.table.set(sid(0), Some(reader(&sid(0), &read_secret(0, 1), &st, &[], &[], &[])));
    r.settle();
    r.opens.work().beacons - before
}

use osis_sync::types::ConnId as ConnIdBit;

#[test]
fn a_credential_change_costs_per_connection_not_per_sync_id_spec_sync_opens_6() {
    assert_eq!(change_with_conns(10, 2), change_with_conns(100, 2));
    assert_eq!(change_with_conns(10, 20), 10 * change_with_conns(10, 2));
}

// spec/sync-opens.md §6 (Lost): a Lost for a member this side is ending closes it, and is
// answered with this side's own Lost naming where it stopped.
#[test]
fn a_lost_for_an_ending_member_is_answered_with_a_lost_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    k.sent();
    let id = adv.id();
    adv.send(&mut k, Msg::Lost { id, items: vec![(S, None)] });
    let sent = k.sent();
    assert!(!k.open(adv.peer, &S));
    assert_eq!(shared(&sent, id).unwrap()[0].code, Code::OK);
    assert!(matches!(&of_kind(&sent, 38)[..], [Msg::Lost { items, .. }] if items[0].0 == S && items[0].1.is_some()));
}

// spec/sync-opens.md §6: a member ended and then judged admissible again is no longer ended.
#[test]
fn an_ended_member_admissible_again_is_not_ended_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    assert!(k.opens.members(adv.peer)[&S].until.is_some());
    k.table.set(S, Some(store(&s0)));
    k.settle();
    assert_eq!(k.opens.members(adv.peer)[&S].until, None);
}

// spec/sync-opens.md §4 (the rule: a secret credential), §5 (ByRole): a Hit or a ByRole Hit on a
// read secret opens S whoever the peer proved, none at all included.
#[test]
fn a_read_secret_hit_opens_whoever_proved_spec_sync_opens_4() {
    let rs = read_secret(1, 0);
    for byrole in [false, true] {
        let mut r = Side::new(4);
        r.table.set(S, Some(reader(&S, &rs, &StepKeys::new(1, 0), &[], &[], &[])));
        r.settle();
        let (mut adv, _) = Adv::dials(&mut r, Proven::default(), [2; 32]);
        let hit = adv.hit_on(rs.1.expose(), &S);
        let item = if byrole { OfferItem::ByRole { sync_id: S, hits: vec![hit] } } else { OfferItem::Hit { hit, sig: None } };
        assert_eq!(adv.offer(&mut r, vec![item])[0].code, Code::OK, "byrole {byrole}");
        assert!(r.open(adv.peer, &S));
    }
}

// spec/sync-opens.md §5 (opening): a Lost after an Offer names only a sync ID whose Hit the peer
// answered with a valid tag: an OK with no valid tag (a hostile answer to a filter's false
// positive) learns no sync ID.
#[test]
fn no_lost_names_s_without_a_valid_tag_spec_sync_opens_5() {
    let rs = read_secret(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &rs, &StepKeys::new(1, 0), &[], &[], &[])));
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    adv.filter(&mut r, &[*rs.1.expose()], &S);
    let sent = r.sent();
    let Some(Msg::Offer { id, .. }) = of_kind(&sent, 37).pop() else { panic!("an Offer") };
    adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some([0; 32]), grant: None, sig: None }] });
    assert!(!r.open(adv.peer, &S));
    assert!(of_kind(&r.sent(), 38).is_empty(), "no Lost");
}

// spec/wire.md §11.2 (Beacons): a whole filter narrower than its entry count needs (one that
// would make every beacon a Hit), or additions past the whole one's entries, is answered 2 and
// closes the connection.
#[test]
fn a_filter_too_dense_closes_the_connection_spec_wire_11_2() {
    let all: Vec<u64> = (0..256).collect();
    let mut r = Side::new(1);
    let (mut adv, _) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 1, base: None, f: 8, lo: 0, hi: 256, gcs: osis_proto::filter::encode_gcs(&all, 0), more: false });
    assert!(r.sent().iter().any(|(_, m)| *m == Msg::Error { id, code: Code::MALFORMED }));
    assert!(!r.pipe.closed.is_empty());
    let mut r = Side::new(1);
    let (mut adv, _) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 1, base: None, f: 8, lo: 0, hi: 256, gcs: osis_proto::filter::encode_gcs(&[5], 0), more: false });
    let id = adv.id();
    adv.send(&mut r, Msg::Beacons { id, generation: 2, base: Some(1), f: 8, lo: 0, hi: 256, gcs: osis_proto::filter::encode_gcs(&[6, 7], 0), more: false });
    assert!(r.sent().iter().any(|(_, m)| *m == Msg::Error { id, code: Code::MALFORMED }));
    assert!(!r.pipe.closed.is_empty());
}

// spec/sync-opens.md §5 (testing): a refused Hit is not sent again at its answer (here the peer
// acknowledged no generation of the tester's filter), and a Lost naming a sync ID this node does
// not sync re-marks nothing; a Lost naming S re-marks S.
#[test]
fn a_lost_for_an_unheld_sync_id_remarks_nothing_spec_sync_opens_5() {
    let rs = read_secret(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &rs, &StepKeys::new(1, 0), &[], &[], &[])));
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    adv.filter(&mut r, &[*rs.1.expose()], &S);
    let oid = of_kind(&r.sent(), 37)[0].id();
    adv.send(&mut r, Msg::Shared { id: oid, items: vec![osis_proto::SharedItem::code(Code::DECLINED)] });
    // Adv acknowledged no generation of r's filter: still no Hit again at the answer.
    assert_eq!(offered_hits(&r.sent()), 0, "a refused Hit is not sent again at its answer");
    let id = adv.id();
    adv.send(&mut r, Msg::Lost { id, items: vec![(sid(77), None)] });
    assert_eq!(offered_hits(&r.sent()), 0, "not re-marked");
    let id = adv.id();
    adv.send(&mut r, Msg::Lost { id, items: vec![(S, None)] });
    assert_eq!(offered_hits(&r.sent()), 1, "a Lost for S re-marks it");
}

// spec/sync-opens.md §3 (pair key): a dialer the listener proved an actor to sends Resume; a
// listener the dialer proved no actor to (its policy proved none, `Policy::identify`) answers
// Error 1, the dialer sends NoRecord, and the shared set runs keeping no record at either side.
#[test]
fn a_resume_from_a_dialer_proving_nothing_runs_unkept_spec_sync_opens_3() {
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    let mut p = Pair::new(a, b, Proven::default(), account(2));
    p.run();
    let from_b: Vec<&Msg> = p.log.iter().filter(|(a, _)| !a).map(|(_, m)| m).collect();
    assert!(from_b.iter().any(|m| matches!(m, Msg::Error { code: Code::REFUSED, .. })), "Error 1");
    assert!(p.log.iter().any(|(a, m)| *a && matches!(m, Msg::NoRecord { .. })), "then NoRecord");
    assert!(p.a.opens.record(p.ca).is_none() && p.b.opens.record(p.cb).is_none());
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
}

// spec/sync-opens.md §3 (pair key): two nodes that each proved an actor keep one record, whether
// or not either held anything of the other's before.
#[test]
fn strangers_proving_actors_keep_a_record_spec_sync_opens_3() {
    let mut p = Pair::new(Side::new(1), Side::new(2), account(1), account(2));
    p.run();
    assert!(p.a.opens.record(p.ca).is_some() && p.b.opens.record(p.cb).is_some());
}

/// `a` holds `n` sync IDs, `b` one of them; they share it, close and connect again with nothing
/// changed. The work of the reconnect at `a`.
fn reconnect_with(n: u8) -> osis_sync::opens::Work {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 0..n {
        a.table.set(sid(i), Some(reader(&sid(i), &read_secret(i, 0), &st, &[], &[], &[])));
    }
    b.table.set(sid(0), Some(reader(&sid(0), &read_secret(0, 0), &st, &[], &[], &[])));
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &sid(0)));
    p.close();
    let before = p.a.opens.work();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &sid(0)));
    let w = p.a.opens.work();
    osis_sync::opens::Work { rejudged: w.rejudged - before.rejudged, beacons: w.beacons - before.beacons, tested: w.tested - before.tested, creds: w.creds - before.creds }
}

// spec/sync-opens.md §3 (records): a peer with a record reconnecting with nothing changed costs the same
// whatever else this node syncs: no beacon of what the two do not share.
#[test]
fn a_reconnect_costs_the_same_at_n_and_10n_spec_sync_opens_3() {
    assert_eq!(reconnect_with(10), reconnect_with(100));
}

/// Delivers what both sides of `p` sent on every connection between them (a's `n` is b's
/// `ACCEPTED | n` and the other way round), until none flows. A side's last messages before it
/// closed still go; none reach a side that closed its end.
fn route_all(p: &mut Pair) {
    use osis_sync::types::ConnId;
    let peer = |c: ConnId| ConnId(c.0 ^ ConnId::ACCEPTED);
    for _ in 0..500 {
        let (fa, fb) = (p.a.sent(), p.b.sent());
        if fa.is_empty() && fb.is_empty() {
            return;
        }
        for (c, m) in fa {
            if !p.b.pipe.closed.iter().any(|(x, _)| *x == peer(c)) {
                p.b.take(peer(c), incoming(m));
            }
        }
        for (c, m) in fb {
            if !p.a.pipe.closed.iter().any(|(x, _)| *x == peer(c)) {
                p.a.take(peer(c), incoming(m));
            }
        }
    }
    panic!("opens storm");
}

/// A second connection between the readers of `readers()`, `b` dialing `a` at `rank`.
fn second_connection(p: &mut Pair, rank: u8) -> (osis_sync::types::ConnId, osis_sync::types::ConnId) {
    use osis_sync::types::ConnId;
    let (cb, ca) = (ConnId(2), ConnId(ConnId::ACCEPTED | 2));
    let (bb, ba) = binds_at([0x5c; 32], [0x6d; 32], [0x4a; 32], rank);
    p.b.pipe.binds.insert(cb, (bb, account(1)));
    p.a.pipe.binds.insert(ca, (ba, account(2)));
    p.a.take(ca, osis_sync::session::Incoming::Proved);
    p.b.take(cb, osis_sync::session::Incoming::Proved);
    route_all(p);
    (ca, cb)
}

// spec/sync-opens.md §1 (one connection per pair): two connections of one record, whoever dialed
// each: the one of better route rank stays and the other closes at both ends; the shared set is
// the winner's.
#[test]
fn a_better_route_wins_the_pair_spec_sync_opens_1() {
    let mut p = readers();
    let (ca1, cb1) = (p.ca, p.cb);
    let (ca2, cb2) = second_connection(&mut p, 0);
    assert!(p.a.pipe.closed.iter().any(|(c, _)| *c == ca1) && p.b.pipe.closed.iter().any(|(c, _)| *c == cb1), "the direct one closed at both ends");
    assert!(!p.a.pipe.closed.iter().any(|(c, _)| *c == ca2) && !p.b.pipe.closed.iter().any(|(c, _)| *c == cb2));
    assert_eq!((p.a.opens.lost_to(ca1), p.b.opens.lost_to(cb1)), (Some(ca2), Some(cb2)));
    assert!(p.a.open(ca2, &S) && p.b.open(cb2, &S) && !p.a.open(ca1, &S));
    assert!(p.a.moved.iter().any(|m| matches!(m, Moved::Left(c, S, _) if *c == ca1)));
}

// spec/sync-opens.md §1 (one connection per pair): among two of one rank the one with the smaller
// order hash stays, the same one at both ends whatever order they arrived in.
#[test]
fn the_order_hash_breaks_a_tie_alike_at_both_ends_spec_sync_opens_1() {
    let mut p = readers();
    let (ca1, cb1) = (p.ca, p.cb);
    let (ca2, cb2) = second_connection(&mut p, 1);
    let a_lost: Vec<_> = p.a.pipe.closed.iter().map(|(c, _)| *c).collect();
    let b_lost: Vec<_> = p.b.pipe.closed.iter().map(|(c, _)| *c).collect();
    assert_eq!(a_lost.len(), 1, "one closed: {a_lost:?}");
    let pairs = [(ca1, cb1), (ca2, cb2)];
    let lost = pairs.iter().find(|(a, _)| a_lost.contains(a)).unwrap();
    assert_eq!(b_lost, [lost.1], "the same connection at both ends");
}

// spec/sync-opens.md §1 (one connection per pair): two connections on which the peer proved the
// same node of this account are of one pair though each made a record of its own (crossed first
// dials): one closes, the same one at both ends, and the shared set runs on the other.
#[test]
fn crossed_first_dials_between_own_nodes_keep_one_spec_sync_opens_1() {
    use osis_sync::types::ConnId;
    let node = |n: u8, node: u8| Proven { node: Some(tid(node)), ..account(n) };
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    a.settle();
    b.settle();
    // a dials b (connection 1) and b dials a (connection 2) before either answers
    let mut p = Pair::new(a, b, node(1, 11), node(2, 12));
    let (cb2, ca2) = (ConnId(2), ConnId(ConnId::ACCEPTED | 2));
    let (bb, ba) = binds([0x5c; 32], [0x6d; 32], [0x4a; 32]);
    p.b.pipe.binds.insert(cb2, (bb, node(1, 11)));
    p.a.pipe.binds.insert(ca2, (ba, node(2, 12)));
    p.a.take(ca2, osis_sync::session::Incoming::Proved);
    p.b.take(cb2, osis_sync::session::Incoming::Proved);
    route_all(&mut p);
    let a_lost: Vec<_> = p.a.pipe.closed.iter().map(|(c, _)| *c).collect();
    let b_lost: Vec<_> = p.b.pipe.closed.iter().map(|(c, _)| *c).collect();
    let pairs = [(p.ca, p.cb), (ca2, cb2)];
    assert_eq!(a_lost.len(), 1, "one closed: {a_lost:?}");
    let (lost, kept) = if a_lost[0] == pairs[0].0 { (pairs[0], pairs[1]) } else { (pairs[1], pairs[0]) };
    assert_eq!(b_lost, [lost.1], "the same connection at both ends");
    assert!(p.a.open(kept.0, &S) && p.b.open(kept.1, &S));
}

/// `a` and `b` share `n` sync IDs, close, both restart (opens started from their stores) and
/// connect again with nothing changed. The bytes of every message the reconnect sent.
pub(crate) fn restart_reconnect_bytes(n: u8) -> usize {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 1..=n {
        for x in [&mut a, &mut b] {
            x.table.set(sid(i), Some(reader(&sid(i), &read_secret(i, 0), &st, &[], &[], &[])));
        }
    }
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!((1..=n).all(|i| p.a.open(p.ca, &sid(i)) && p.b.open(p.cb, &sid(i))));
    let changed: Vec<u64> = (1..=n).map(|i| p.a.opens.changed_at(&sid(i))).collect();
    p.close();
    p.a.restart();
    p.b.restart();
    assert_eq!((1..=n).map(|i| p.a.opens.changed_at(&sid(i))).collect::<Vec<_>>(), changed, "changed_at is durable: a restart advances nothing");
    p.log.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!((1..=n).all(|i| p.a.open(p.ca, &sid(i)) && p.b.open(p.cb, &sid(i))), "the record's members are open again");
    assert!((1..=n).all(|i| p.a.moved.contains(&Moved::Joined(p.ca, sid(i), Rejoin::Held))), "each rejoins where its stream holds it");
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Resumed { tag: Some(_), .. })), "the record resumed");
    assert!(!p.log.iter().any(|(_, m)| matches!(m, Msg::Members { .. } | Msg::Offer { .. })), "digests match, nothing tested: {:?}", p.log);
    assert!(p.a.opens.agreed(p.ca) && p.b.opens.agreed(p.cb));
    p.log.iter().map(|(_, m)| m.encode().len()).sum()
}

// spec/sync-opens.md §3 (records, `changed_at`; spec/sync-streams.md §3 Durability: the records
// are durable): a restart keeps the record and `changed_at`, so a reconnect after it is no first
// contact and costs the same at n and 10n shared sync IDs (but for the widths of the integers
// it names).
#[test]
fn a_restart_keeps_records_and_changed_at_spec_sync_opens_3() {
    let (small, large) = (restart_reconnect_bytes(10), restart_reconnect_bytes(100));
    assert!(large <= small + 16, "{small} bytes at n, {large} at 10n");
}

// spec/sync-opens.md §3 (RECORD_BUDGET): past the budget the least recently used record no
// connection holds goes with every module's rows; the next connection is a first contact.
#[test]
fn an_evicted_record_goes_whole_and_is_a_first_contact_spec_sync_opens_3() {
    use osis_sync::store::Source;
    let mut p = readers();
    let rid = p.a.opens.record(p.ca).unwrap();
    // rows of other modules in the record: a stand (store), a source's word (streams)
    let stand = osis_sync::store::Stand { at: osis_base::WallMs(1), logged: osis_base::BlobId([1; 32]), head: osis_label::StepId([2; 32]), fall: 0 };
    p.a.store.set_stand(Source::Record(rid), &S, b"body", Some(&stand)).unwrap();
    p.a.store.with_tx(|t| t.record_put_row(&rid, b'k', &S, &[3; 32], Vec::new())).unwrap();
    // in use: kept whatever the budget
    p.a.opens.set_record_budget(0);
    assert!(p.a.flush().is_empty(), "a record a connection holds stays");
    p.close();
    assert_eq!(p.a.flush(), Vec::<osis_sync::types::RecordId>::new(), "gone at the close's own flush");
    p.a.store.with_read(|t| {
        assert!(t.record(&rid)?.is_none());
        assert!(t.records_with_row(&S, b'M', b"", 10)?.is_empty(), "its members");
        assert!(t.record_get_wide_row(&rid, b'R', b"")?.is_none(), "its own state");
        assert!(t.records_with_row(&S, b'k', &[3; 32], 10)?.is_empty(), "streams' rows");
        Ok(())
    }).unwrap();
    assert_eq!(p.a.store.stand(Source::Record(rid), &S, b"body").unwrap(), None, "read's stand");
    p.log.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Resumed { tag: None, .. })), "nothing to resume");
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Offer { .. })), "S is tested again");
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
}

// spec/sync-opens.md §3 (RECORD_BUDGET: a record in use is not dropped): a record a Resume in
// flight lists is in use, so eviction past the budget spares it and the answer finds it; at the
// listener a record evicted while the Resume is on its way matches nothing: a first contact.
#[test]
fn eviction_spares_a_record_a_resume_lists_spec_sync_opens_3() {
    let mut p = readers();
    let rid = p.a.opens.record(p.ca).unwrap();
    p.close();
    p.log.clear();
    // a's Resume naming the record is on its way
    p.connect(2, account(1), account(2));
    p.a.opens.set_record_budget(0);
    assert!(p.a.flush().is_empty(), "listed in a Resume out: in use");
    p.run();
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Resumed { tag: Some(_), .. })), "resumed");
    assert_eq!(p.a.opens.record(p.ca), Some(rid));
    assert!(!p.log.iter().any(|(_, m)| matches!(m, Msg::Offer { .. })), "no first contact");
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    p.close();
    p.log.clear();
    p.connect(3, account(1), account(2));
    p.b.opens.set_record_budget(0);
    assert_eq!(p.b.flush().len(), 1, "the listener's record, no connection holding it, goes");
    p.run();
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Resumed { tag: None, .. })), "nothing to resume");
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Offer { .. })), "S is tested again");
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
}

/// `a` and `b` read S and meet; `a` loses power at the end of the `k`-th step in which it takes a
/// message, before that step's records are written (`crash_taking`); then, with `leave`, `b`
/// stops reading S once the two share it (a Lost naming where S stopped), `a` crashing at that
/// Lost instead. Both connect again twice, `b` reading S again. Whether `a` crashed.
fn crash_before_flush(k: usize, leave: bool) -> bool {
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    a.settle();
    b.settle();
    let mut p = Pair::new(a, b, account(1), account(2));
    let mut n = 0;
    let mut crashed = false;
    let mut left = false;
    'run: loop {
        let (fa, fb) = (p.a.sent(), p.b.sent());
        if fa.is_empty() && fb.is_empty() {
            if !leave || left {
                break;
            }
            // a stored up to position 5 of b's log; b stops reading S
            left = true;
            p.b.reported(p.cb, S, 5);
            p.b.table.set(S, None);
            p.b.settle();
            continue;
        }
        for (c, m) in fa {
            if c == p.ca {
                p.b.take(p.cb, incoming(m));
            }
        }
        for (c, m) in fb {
            if c != p.cb {
                continue;
            }
            if n == k && (!leave || left) {
                p.a.crash_taking(p.ca, incoming(m));
                crashed = true;
                break 'run;
            }
            if !leave || left {
                n += 1;
            }
            p.a.take(p.ca, incoming(m));
        }
    }
    p.b.closed(p.cb);
    p.b.sent();
    p.a.closed(p.ca);
    if leave {
        p.b.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
        p.b.settle();
    }
    for c in [2, 3] {
        p.a.moved.clear();
        p.log.clear();
        p.connect(c, account(1), account(2));
        p.run();
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "crash at step {k}: S open both ways");
        // where a's stream reads S again (its last join: the record's members join as held
        // when a connection takes it, pulled only once the digests agree): never as it held it,
        // once b's Lost (or a digest difference) said where S stopped
        let last = p.a.moved.iter().rev().find_map(|m| match m {
            Moved::Joined(_, s, r) if *s == S => Some(r.clone()),
            _ => None,
        });
        if leave && c == 2 {
            assert_ne!(last, Some(Rejoin::Held), "crash at step {k}: a rejoins S as its stream held it: {:?}", p.a.moved);
        }
        p.a.closed(p.ca);
        p.b.closed(p.cb);
        p.a.sent();
        p.b.sent();
    }
    assert!(!p.log.iter().any(|(_, m)| matches!(m, Msg::Members { .. } | Msg::Offer { .. })), "crash at step {k}: the records agree again");
    crashed
}

// spec/sync-opens.md §3 (records; agreement) and spec/sync-streams.md §3 (Durability: partial
// loss is atomic per record): opens writes a record at its step's end, after what streams wrote
// in the step; a power loss at the end of any step, before that write, leaves an older record
// that the next connection's digest brings back to agreement, and a member the peer closed with
// a Lost rejoins from where that Lost (or the digest) says, never from where the stream held it.
#[test]
fn a_crash_before_a_step_writes_its_records_spec_sync_opens_3() {
    for leave in [false, true] {
        let mut k = 0;
        while crash_before_flush(k, leave) {
            k += 1;
            assert!(k < 50, "the exchange ends");
        }
        assert!(k > 1, "steps crashed: {k}");
    }
}

/// Behind items a reader sends at each of three arrivals of Adv's filter (whole, then empty
/// additions), Adv an account J judges a sync holder of `n` sync IDs it does not keep (each
/// Behind answered 13).
fn behinds_per_arrival(n: u8) -> Vec<usize> {
    let mut r = Side::new(1);
    for i in 0..n {
        let s = SyncId([i; 16]);
        r.table.set(s, Some(reader(&s, &read_secret(i, 0), &StepKeys::new(i, 0), &[], &[], &[])));
        r.table.judge_as(s, tid(9), J::SyncHolder);
    }
    r.settle();
    let (mut adv, sent) = Adv::dials(&mut r, account(9), [2; 32]);
    for m in of_kind(&sent, 36) {
        let id = m.id();
        adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem::code(Code::OK)] });
    }
    let behinds = |sent: &[(osis_sync::types::ConnId, Msg)]| -> Vec<(osis_proto::Id, usize)> {
        of_kind(sent, 37).iter().map(|m| match m {
            Msg::Offer { id, items } => (*id, items.iter().filter(|i| matches!(i, OfferItem::Behind(_))).count()),
            _ => unreachable!(),
        }).collect()
    };
    // Adv's filter arrives (generation 1 whole, then empty additions); r's Offers are each
    // answered 13 (Adv keeps none of them).
    let mut per = Vec::new();
    for g in 1..=3u64 {
        let id = adv.id();
        let base = (g > 1).then_some(g - 1);
        adv.send(&mut r, Msg::Beacons { id, generation: g, base, f: 8, lo: 0, hi: 256, gcs: Vec::new(), more: false });
        let mut count = 0;
        let mut offers = behinds(&r.sent());
        while let Some((oid, k)) = offers.pop() {
            count += k;
            let items = vec![osis_proto::SharedItem::code(Code::UNKNOWN_SYNC_ID); osis_proto::limits::MAX_OFFER_ITEMS];
            adv.send(&mut r, Msg::Shared { id: oid, items });
            offers.extend(behinds(&r.sent()));
        }
        per.push(count);
    }
    per
}

// spec/sync-ids.md §6 (Walk: tested as spec/sync-opens.md §5 Testing says, on this node's own
// changes): a reader asks Behind once per sync ID its own change made due; an arrival of the
// peer's filter asks nothing again, at n and 10n walks alike.
#[test]
fn an_unchanged_filter_asks_behind_on_nothing_spec_sync_ids_6() {
    assert_eq!(behinds_per_arrival(2), vec![2, 0, 0]);
    assert_eq!(behinds_per_arrival(20), vec![20, 0, 0]);
}

// spec/sync-ids.md §6 (Walk: Test): a reader tests its recorded steps' credentials deepest first,
// then the sync key of each sync secret it holds, newest first, each distinct credential once: a
// held sync key no recorded step bears is tested (by no step), one a step bears only at its step.
#[test]
fn a_reader_tests_each_held_sync_key_after_its_steps_spec_sync_ids_6() {
    use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, label_role_key};
    use osis_engine::labeling::HeadKeys;
    use osis_engine::sync::{Path, ReadCredentials};
    use osis_label::{Parent, StepKeys};
    use osis_sync::opens::cred::Tested;
    use osis_sync::opens::holds::walk_tests;
    let thing = osis_base::Tid::from_bytes([3; 15]);
    let admin = Secret32::from_bytes([0xab; 32]);
    let (old, new) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]));
    let id = osis_label::genesis_label(&admin);
    let keys = StepKeys::derive(&old, &old, &admin, &Secret32::from_bytes([9; 32]), &id);
    let read = Epoch::derive(&thing, osis_base::Role::Read, 0, &old).unwrap();
    let se = |n: u64, x: &Secret32| Epoch::derive(&thing, osis_base::Role::Sync, n, x).unwrap();
    let d = label_role_key(LabelRole::Delete, &admin);
    let (genesis, _) = osis_label::register(Parent::Genesis(&d), keys, &[], (&thing, read, &old), (se(0, &old), &old), &mut SeededRng::from_u64(0)).unwrap();
    let k = |x: &Secret32| label_role_key(LabelRole::Sync, x);
    let mut rc = ReadCredentials::default();
    rc.keys.insert(genesis.id(), HeadKeys { sync: Some(k(&old)), epochs: [Some(se(0, &old)), None, None], ..HeadKeys::default() });
    rc.sync_keys = vec![(se(1, &new), k(&new)), (se(0, &old), k(&old))];
    let path = Path { steps: vec![(genesis.clone(), None)] };
    let tests = walk_tests(&rc, &path, &mut |_| None);
    let got: Vec<(Option<osis_label::StepId>, [u8; 32])> = tests
        .iter()
        .map(|(t, _)| match t {
            Tested::SyncKey { step, key } => (*step, key.verifying_key().to_bytes()),
            other => panic!("only sync keys: {other:?}"),
        })
        .collect();
    let pk = |x: &Secret32| k(x).verifying_key().to_bytes();
    assert_eq!(got, vec![(Some(genesis.id()), pk(&old)), (None, pk(&new))]);
    // no recorded path: every held sync key, newest first
    let bare: Vec<_> = walk_tests(&rc, &Path::default(), &mut |_| None).into_iter().map(|(t, _)| t.step()).collect();
    assert_eq!(bare, vec![None, None]);
}
