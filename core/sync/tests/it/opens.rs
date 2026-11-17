//! Opens: records, agreement, the shared set, filters, Offer and ending (spec/sync-opens.md §3-§6),
//! between honest sides and against hostile scripted peers (harness::scripted). Each test named
//! for a NetOpen control (core/test/tla/net/NetOpen.tla, `ON_*`) fails when that control's rule
//! is taken out of `osis_sync::opens`.

use crate::harness::scripted::*;
use osis_base::SyncId;
use osis_engine::sync::J;
use osis_proto::{Code, Msg, OfferItem};
use osis_sync::opens::{Leaving, Moved, Peer, Rejoin};
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

/// S's read secret at `side` moves to epoch `n`, covering every departure: J is read when S's
/// credentials move (spec/sync-opens.md §6), as a removal's rotation moves the remover's and a
/// grant the grantee's.
fn rotated(side: &mut Side, n: u8) {
    let rs = read_secret(1, n);
    side.table.covering.insert((S, rs.0));
    side.table.set(S, Some(reader(&S, &rs, &StepKeys::new(1, 0), &[], &[], &[])));
}

/// `a` removes `b`'s account with its rotation; `b` is granted again later.
fn departs(p: &mut Pair) {
    p.a.table.judge_as(S, tid(2), J::Departed);
    rotated(&mut p.a, 1);
    p.a.settle();
}

/// `a` grants `b`'s account again: `b` takes the box of the current epoch.
fn regranted(p: &mut Pair) {
    p.a.table.judge_as(S, tid(2), J::Reader);
    rotated(&mut p.b, 1);
    p.b.settle();
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

// spec/sync-set.md §3 (it waits only while some peer is to be waited for on S: a source or a record it keeps holding S
// as a member), spec/permissions.md §3 (Lost access: no peer but its account's nodes): S is
// waited on while the connection has it open and, once closed, while the kept record holds it;
// a peer whose proven actors the caller skips (this account's own nodes, for a self-removal)
// holds no wait.
#[test]
fn waited_by_a_connection_or_a_kept_record_spec_sync_set_3() {
    let mut p = readers();
    let other = |a: &osis_store::Named| if a.actors().contains(&tid(2)) { Peer::Skipped } else { Peer::Unlisted };
    let wait = |p: &Pair, s: &SyncId, f: &dyn Fn(&osis_store::Named) -> Peer| p.a.opens.wait_for(&p.a.store, s, f).unwrap();
    assert!(wait(&p, &S, &|_| Peer::Unlisted), "open on a connection");
    assert!(!wait(&p, &S, &other), "only a skipped peer");
    assert!(!wait(&p, &sid(9), &|_| Peer::Unlisted), "held by nobody");
    p.close();
    assert!(wait(&p, &S, &|_| Peer::Unlisted), "the peer away: its record holds S");
    assert!(!wait(&p, &S, &other), "its record names a skipped actor");
}

// spec/sync-set.md §3 (it waits only while some peer is to be waited for on S: one the rosters name
// while no record of it acknowledged S's current credentials), spec/sync-opens.md §5 Testing (`acked_pos`): S joins `a` while
// `b` is away, so no record holds it: `a` waits for `b` when the rosters say `b` may hold S, and
// not for a peer they do not name, nor once `b`'s record acknowledges S with S not a member, nor
// past a restart of what it read; records naming the same actors are one peer; the wait comes
// back when S's credentials move again, and once `b` holds S too it is its member.
#[test]
fn a_sync_id_just_joined_waits_for_a_peer_the_rosters_name_spec_sync_set_3() {
    let s2 = sid(7);
    let mut p = readers();
    p.close();
    let may = |_: &osis_store::Named| Peer::MayHold;
    let wait = |p: &Pair, f: &dyn Fn(&osis_store::Named) -> Peer| p.a.opens.wait_for(&p.a.store, &sid(7), f).unwrap();
    let st = StepKeys::new(2, 0);
    p.a.table.set(s2, Some(reader(&s2, &read_secret(2, 0), &st, &[], &[], &[])));
    p.a.settle();
    assert!(wait(&p, &may), "b away, its record not told of S");
    assert!(!wait(&p, &|_| Peer::Unlisted), "a peer the rosters do not name");
    assert!(!wait(&p, &|_| Peer::Skipped));
    p.a.restart();
    assert!(wait(&p, &may), "a restart reads the same from the record's rows");
    p.connect(2, account(1), account(2));
    p.run();
    assert!(!p.a.open(p.ca, &s2));
    assert!(!wait(&p, &may), "b acknowledged S, not a member: it does not hold S");
    p.close();
    p.a.restart();
    assert!(!wait(&p, &may), "nor after a restart");
    // a second record naming the same actors (both nodes dialed at first contact, §1 Limit) is the
    // same peer: told by one of its records, it is told; one naming other actors is another peer
    p.a.store.with_tx(|t| t.record_create([9; 32], &named(2)).map(drop)).unwrap();
    p.a.restart();
    assert!(!wait(&p, &may), "the same peer, told by its other record");
    // spec/sync-opens.md §3 (a node of another account whose epoch closed by a rotation carrying
    // no removal is still that account): a record at another key of its account acknowledging S
    // tells it
    let other_key = osis_store::Named { account: Some((tid(2), [0x77; 32])), ..osis_store::Named::default() };
    p.a.store.with_tx(|t| t.record_create([7; 32], &other_key).map(drop)).unwrap();
    p.a.restart();
    assert!(!wait(&p, &may), "the same peer at another key of its account, told by its other record");
    p.a.store.with_tx(|t| t.record_create([8; 32], &named(3)).map(drop)).unwrap();
    p.a.restart();
    assert!(wait(&p, &may) && !wait(&p, &|a| if a.actors().contains(&tid(3)) { Peer::Unlisted } else { Peer::MayHold }), "another peer, never told");
    let st3 = StepKeys::new(3, 0);
    p.a.table.set(s2, Some(reader(&s2, &read_secret(3, 0), &st3, &[], &[], &[])));
    p.a.settle();
    assert!(wait(&p, &may), "S's credentials moved: b not told of them");
    p.b.table.set(s2, Some(reader(&s2, &read_secret(3, 0), &st3, &[], &[], &[])));
    p.b.settle();
    p.connect(3, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &s2) && wait(&p, &|_| Peer::Unlisted), "open: a member");
}

// spec/sync-set.md §3 (a peer away keeps it waiting until that peer connects or its record goes),
// spec/sync-opens.md §3 (RECORD_BUDGET): the record of a peer away that was never told of S goes
// past the budget, and the wait with it: nothing stays stuck on a peer that never returns.
#[test]
fn an_evicted_record_ends_its_wait_spec_sync_set_3() {
    let s2 = sid(7);
    let mut p = readers();
    p.close();
    let st = StepKeys::new(2, 0);
    p.a.table.set(s2, Some(reader(&s2, &read_secret(2, 0), &st, &[], &[], &[])));
    p.a.settle();
    let wait = |p: &Pair| p.a.opens.wait_for(&p.a.store, &s2, |_| Peer::MayHold).unwrap();
    assert!(wait(&p) && wait_s(&p), "b's record: not told of s2, holding S");
    p.a.opens.set_record_budget(0);
    assert_eq!(p.a.flush().len(), 1);
    assert!(!wait(&p) && !wait_s(&p), "the record gone, nothing to wait for");
}

fn wait_s(p: &Pair) -> bool {
    p.a.opens.wait_for(&p.a.store, &S, |_| Peer::Unlisted).unwrap()
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

// spec/sync-opens.md §6 (Where it stopped): the receiver keeps the Lost's cursor (where the member
// stopped for it, in the sender's log) and its rejoin on that connection reads from there; a
// member left with its connection rejoins from where its own stream holds it.
#[test]
fn a_rejoin_reads_from_the_losts_cursor_spec_sync_opens_6() {
    let mut p = readers();
    // b stored a's log at 7 for S (a learns it from b's Applied)
    p.a.reported(p.ca, S, 7);
    departs(&mut p);
    p.run();
    assert!(!p.b.open(p.cb, &S));
    assert!(p.b.moved.iter().any(|m| matches!(m, Moved::Left(c, s, at) if *c == p.cb && *s == S && at.how == Leaving::Kept)), "{:?}", p.b.moved);
    p.b.moved.clear();
    regranted(&mut p);
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
// only once something re-marks S or moves `changed_at(S)` (here a credential of S moving).
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
    // `changed_at(S)` moving tries it again
    r.table.set(S, Some(reader(&S, &rs, &StepKeys::new(1, 1), &[], &[], &[])));
    r.settle();
    assert_eq!(offered_hits(&r.sent()), 1, "tried again once changed_at(S) moved");
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
    assert_eq!(adv.offer(h, vec![OfferItem::Hit { hit: [0; 32], sig: None, unread: false }])[0].code, Code::DECLINED);
}

/// Adv's Hit on a sync key it holds the secret of, with its open signature.
fn sync_key_hit(adv: &Adv, st: &StepKeys) -> OfferItem {
    OfferItem::Hit { hit: adv.hit_on(&st.pk(), &S), sig: Some(adv.bind.sign(&st.sync, &S)), unread: false }
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
    let a = adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&s0.proof, &S), sig: None, unread: false }]);
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
    let a = adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&fake, &S), sig: None, unread: false }]);
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
    adv.send(&mut k, Msg::Shared { id: offer.id(), items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: None, unread: false }] });
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
    adv.send(&mut k, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: Some(reflected), unread: false }] });
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
    assert_eq!(adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&s0.proof, &S), sig: None, unread: false }])[0].code, Code::OK);
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
    OfferItem::Static { hit: adv.hit_on(&e, &S), signing_pk: l.verifying_key().to_bytes(), sig: adv.bind.sign(l, &S), unread: false }
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
// started with: Adv's ByRole after its removal opens nothing.
#[test]
fn j_is_judged_on_the_roster_held_now_spec_sync_opens_4() {
    let (mut r, mut adv) = reader_judging(J::Reader);
    r.table.judge_as(S, tid(9), J::Departed);
    assert_eq!(adv.offer(&mut r, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new(), unread: false }])[0].code, Code::DECLINED);
    assert!(!r.open(adv.peer, &S));
}

// ON_endj, ON_peermoves (spec/sync-opens.md §6): an open by J closes at once with a Lost when
// its peer's standing moves, with no credential of S moving: J judging it departed (its removal
// held), or unknown (its account's key revoked); one demoted to sync holder stays.
#[test]
fn a_j_open_closes_when_its_peer_stops_counting_spec_sync_opens_6() {
    for (j, stays) in [(J::Departed, false), (J::Unknown, false), (J::SyncHolder, true)] {
        let (mut r, mut adv) = reader_judging(J::Reader);
        assert_eq!(adv.offer(&mut r, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new(), unread: false }])[0].code, Code::OK);
        assert!(r.open(adv.peer, &S));
        r.sent();
        r.table.judge_as(S, tid(9), j);
        r.settle();
        assert_eq!(r.open(adv.peer, &S), stays, "{j:?}");
        assert_eq!(of_kind(&r.sent(), 38).len(), usize::from(!stays), "{j:?}: a Lost");
    }
}

// ON_peermoves (spec/sync-opens.md §4 Departed, §6): a peer removed while connected, its removal
// held here before any rotation (no credential of S moves), is no longer served S: its open by
// S's read secret, at an epoch not covering its departure, closes at once at both ends. Across a
// restart the record's next connection opens nothing either.
#[test]
fn a_removal_held_here_closes_a_credential_open_at_once_spec_sync_opens_6() {
    let mut p = readers();
    p.a.table.judge_as(S, tid(2), J::Departed);
    p.a.settle();
    assert!(!p.a.open(p.ca, &S), "closed at once, before any rotation");
    p.run();
    assert!(!p.a.open(p.ca, &S) && !p.b.open(p.cb, &S), "b's Hit refused: a judges it departed");
    // held while away (the record keeps the member), then a restart: the reconnect re-judges it
    let mut p = readers();
    p.close();
    p.a.table.judge_as(S, tid(2), J::Departed);
    p.a.restart();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(!p.a.open(p.ca, &S) && !p.b.open(p.cb, &S));
}

// spec/sync-opens.md §6: a move of one peer's standing for one sync ID re-judges that member
// alone: the same work at n and 10n sync IDs open on the connection.
fn standing_moves_one_of(n: u8) -> osis_sync::opens::Work {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 0..n {
        let rs = read_secret(i, 0);
        a.table.set(sid(i), Some(reader(&sid(i), &rs, &st, &[], &[], &[])));
        b.table.set(sid(i), Some(reader(&sid(i), &rs, &st, &[], &[], &[])));
    }
    a.settle();
    b.settle();
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!((0..n).all(|i| p.a.open(p.ca, &sid(i))));
    let before = p.a.opens.work();
    p.a.table.judge_as(sid(0), tid(2), J::SyncHolder);
    p.a.settle();
    let w = p.a.opens.work();
    osis_sync::opens::Work { rejudged: w.rejudged - before.rejudged, standing: w.standing - before.standing, beacons: w.beacons - before.beacons, tested: w.tested - before.tested, creds: w.creds - before.creds }
}

#[test]
fn a_standing_move_costs_the_same_at_n_and_10n_spec_sync_opens_6() {
    let (small, large) = (standing_moves_one_of(10), standing_moves_one_of(100));
    assert_eq!(small, large);
    assert_eq!((small.standing, small.rejudged), (1, 1), "{small:?}");
}

// ON_departed (spec/sync-opens.md §4 (departed)): a side MUST NOT open S toward a peer J judges
// departed by a credential at an epoch not covering every departure: Adv, removed, still holds
// R's current read secret and proof (no rotation yet); R shows it nothing and accepts none of it.
#[test]
fn nothing_opens_toward_a_departed_peer_spec_sync_opens_4() {
    let rs = read_secret(1, 0);
    let st = StepKeys::new(1, 0);
    let (mut r, mut adv) = reader_judging(J::Departed);
    let a = adv.offer(&mut r, vec![OfferItem::Hit { hit: adv.hit_on(rs.1.expose(), &S), sig: None, unread: false }, OfferItem::Hit { hit: adv.hit_on(&st.proof, &S), sig: None, unread: false }]);
    assert!(a.iter().all(|x| x.code == Code::DECLINED), "{a:?}");
    adv.filter(&mut r, &[*rs.1.expose(), st.pk()], &S);
    assert_eq!(offered_hits(&r.sent()), 0, "R tests nothing toward Adv");
    assert!(!r.open(adv.peer, &S));
    // At an epoch covering the departure, R's credentials of it count again.
    let rs1 = read_secret(1, 1);
    r.table.covering.insert((S, rs1.0));
    r.table.set(S, Some(reader(&S, &rs1, &st, &[], &[], &[])));
    r.settle();
    assert_eq!(adv.offer(&mut r, vec![OfferItem::Hit { hit: adv.hit_on(rs1.1.expose(), &S), sig: None, unread: false }])[0].code, Code::OK);
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
        assert_eq!(adv.offer(&mut k, vec![OfferItem::ByRole { sync_id: S, hits: Vec::new(), unread: false }])[0].code, Code::DECLINED);
        adv.filter(&mut k, &[s0.pk()], &S);
        let sent = k.sent();
        let Some(Msg::Offer { id, .. }) = of_kind(&sent, 37).pop() else { panic!("K Hits the sync key Adv shows") };
        let tag = adv.tag_on(&s0.pk(), &S);
        adv.send(&mut k, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: None, unread: false }] });
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

// ---- work in proportion to change (notes/principles.md, Check scaling) ----

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
    osis_sync::opens::Work { rejudged: w.rejudged - before.rejudged, standing: w.standing - before.standing, beacons: w.beacons - before.beacons, tested: w.tested - before.tested, creds: w.creds - before.creds }
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

// spec/sync-opens.md §6 (Lost): a Lost for a member open here closes it, ending or not, and is
// answered with this side's own Lost naming where it stopped for the peer (its reported position,
// or `until` where lower); a Lost naming no member open here is not answered.
#[test]
fn a_lost_for_an_open_member_is_answered_with_a_lost_spec_sync_opens_6() {
    for ending in [false, true] {
        let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
        let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
        adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
        k.reported(adv.peer, S, 3);
        if ending {
            k.table.set(S, Some(store(&s1)));
            k.settle();
        }
        k.sent();
        let id = adv.id();
        adv.send(&mut k, Msg::Lost { id, items: vec![(S, None)] });
        let sent = k.sent();
        assert!(!k.open(adv.peer, &S));
        assert_eq!(shared(&sent, id).unwrap()[0].code, Code::OK);
        assert!(matches!(&of_kind(&sent, 38)[..], [Msg::Lost { items, .. }] if items[0] == (S, osis_proto::Cursor::new(3u64.to_be_bytes().to_vec()).ok())), "ending {ending}: {sent:?}");
        // S closed: the peer's Lost again names no member open here
        let id = adv.id();
        adv.send(&mut k, Msg::Lost { id, items: vec![(S, None)] });
        assert!(of_kind(&k.sent(), 38).is_empty(), "ending {ending}: not answered");
    }
}

// spec/sync-opens.md §6: a member once ended stays ended when judged admissible again: the peer's
// stream may be served past `until` with S's entries there skipped, so it still closes with a Lost
// naming `until` once the stream passes it, the peer rejoining from there.
#[test]
fn an_ended_member_admissible_again_stays_ended_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    let until = k.opens.members(adv.peer)[&S].until.expect("ended");
    k.table.set(S, Some(store(&s0)));
    k.settle();
    assert_eq!(k.opens.members(adv.peer)[&S].until, Some(until), "still ended");
    k.sent();
    k.reported_stream(adv.peer, until + 5);
    assert!(!k.open(adv.peer, &S));
    assert!(matches!(&of_kind(&k.sent(), 38)[..], [Msg::Lost { items, .. }] if items[0] == (S, osis_proto::Cursor::new(until.to_be_bytes().to_vec()).ok())));
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
        let item = if byrole { OfferItem::ByRole { sync_id: S, hits: vec![hit], unread: false } } else { OfferItem::Hit { hit, sig: None, unread: false } };
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
    adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some([0; 32]), grant: None, sig: None, unread: false }] });
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

// notes/decode-bounds.md (spec/wire.md §11.2 Beacons): a stranger's filter, whole, arriving page by
// page, and with additions, is held as coded: about what it sent, never 8 B an entry
#[test]
fn a_peers_filter_is_held_as_sent_spec_wire_11_2() {
    let entries = |n: u64, salt: u64, f: u8| {
        let mut v: Vec<u64> = (0..n).map(|i| osis_proto::filter::beacon_value(&osis_base::hash::hash(&[salt.to_le_bytes(), i.to_le_bytes()].concat()), f)).collect();
        v.sort_unstable();
        v
    };
    let n = 1u64 << 14;
    let f = osis_proto::filter::filter_width(n as usize);
    let mut r = Side::new(1);
    let (mut adv, _) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    let whole = entries(n, 0, f);
    let mut sent = 0;
    let pages = osis_proto::filter::pages(&whole, f, 2048);
    assert!(pages.len() > 2);
    let conn = adv.peer;
    // a generation arriving grows as a vector does (up to twice its bytes, and its index); one
    // arrived is held at its size
    let held = |r: &Side, sent: usize, growing: bool| {
        let (count, bytes) = r.opens.peer_filter_held(conn);
        let bound = if growing { 3 * sent } else { sent * 3 / 2 };
        assert!(bytes <= bound + 64, "{bytes} B held for {count} entries, {sent} B sent");
        count
    };
    let id = adv.id();
    for p in &pages {
        sent += p.gcs.len();
        adv.send(&mut r, Msg::Beacons { id, generation: 1, base: None, f, lo: p.lo, hi: p.hi, gcs: p.gcs.clone(), more: p.more });
        held(&r, sent, p.more);
    }
    assert_eq!(held(&r, sent, false), n);
    for g in 2..4u64 {
        let add = entries(n / 4, g, f);
        let gcs = osis_proto::filter::encode_gcs(&add, 0);
        sent += gcs.len();
        let id = adv.id();
        adv.send(&mut r, Msg::Beacons { id, generation: g, base: Some(g - 1), f, lo: 0, hi: 1 << f, gcs, more: false });
    }
    assert!(r.pipe.closed.is_empty());
    assert_eq!(held(&r, sent, false), n + n / 2);
}

// spec/sync-opens.md §5 (testing): a refused Hit is not sent again at its answer (here the peer
// acknowledged no generation of the tester's filter), and a Lost naming no member open here (a
// sync ID this node does not sync, or S not open) re-marks nothing.
#[test]
fn a_lost_for_no_member_open_here_remarks_nothing_spec_sync_opens_5() {
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
    assert_eq!(offered_hits(&r.sent()), 0, "S not open: not re-marked");
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
    osis_sync::opens::Work { rejudged: w.rejudged - before.rejudged, standing: w.standing - before.standing, beacons: w.beacons - before.beacons, tested: w.tested - before.tested, creds: w.creds - before.creds }
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
    route_with(p, |_, _, m| Some(m));
}

/// `route_all`, each message passed through `f` (whether a sent it, the sender's end of its
/// connection; none: lost).
fn route_with(p: &mut Pair, mut f: impl FnMut(bool, osis_sync::types::ConnId, Msg) -> Option<Msg>) {
    use osis_sync::types::ConnId;
    let peer = |c: ConnId| ConnId(c.0 ^ ConnId::ACCEPTED);
    for _ in 0..500 {
        let (fa, fb) = (p.a.sent(), p.b.sent());
        if fa.is_empty() && fb.is_empty() {
            return;
        }
        for (c, m) in fa {
            if !p.b.pipe.closed.iter().any(|(x, _)| *x == peer(c))
                && let Some(m) = f(true, c, m)
            {
                p.b.take(peer(c), incoming(m));
            }
        }
        for (c, m) in fb {
            if !p.a.pipe.closed.iter().any(|(x, _)| *x == peer(c))
                && let Some(m) = f(false, c, m)
            {
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

// spec/sync-opens.md §1 (one connection per pair): a dialer restarted while its old connection
// still stands at the listener (its close never arrived) dials again: of the two the listener
// holds, both dialed by the peer, the later stays whatever the order hash, and the shared set runs
// on it. Several challenge sets, so the order hash falls both ways.
#[test]
fn a_redial_replaces_the_connection_its_dialer_gave_up_spec_sync_opens_1() {
    for n in 2..10u64 {
        let mut p = readers();
        let old = p.cb;
        p.a.restart();
        p.connect(n, account(1), account(2));
        p.run();
        let b_lost: Vec<_> = p.b.pipe.closed.iter().map(|(c, _)| *c).collect();
        assert_eq!(b_lost, [old], "the old one closed (n {n})");
        assert!(p.a.pipe.closed.is_empty(), "the redial stands (n {n})");
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "open on the redial (n {n})");
    }
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

/// Readers of S under accounts 1 and 2 that dial each other at once: a dials b (connection 1),
/// b dials a (connection 2), both proved, nothing routed yet. b's and a's ends of connection 2.
fn crossed_accounts() -> (Pair, (osis_sync::types::ConnId, osis_sync::types::ConnId)) {
    use osis_sync::types::ConnId;
    let st = StepKeys::new(1, 0);
    let rs = read_secret(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    b.table.set(S, Some(reader(&S, &rs, &st, &[], &[], &[])));
    a.settle();
    b.settle();
    let mut p = Pair::new(a, b, account(1), account(2));
    let (cb2, ca2) = (ConnId(2), ConnId(ConnId::ACCEPTED | 2));
    let (bb, ba) = binds([0x5c; 32], [0x6d; 32], [0x4a; 32]);
    p.b.pipe.binds.insert(cb2, (bb, account(1)));
    p.a.pipe.binds.insert(ca2, (ba, account(2)));
    p.a.take(ca2, osis_sync::session::Incoming::Proved);
    p.b.take(cb2, osis_sync::session::Incoming::Proved);
    (p, (ca2, cb2))
}

// spec/sync-opens.md §1 (Twin): nodes of two accounts that dial each other at once make a record
// on each connection; each dialer's Twin names its new record on the other connection, so the two
// are of one pair: one closes, the same one at both ends, its record goes at both ends, and the
// shared set runs on the other alone.
#[test]
fn crossed_first_dials_between_accounts_twin_spec_sync_opens_1() {
    let (mut p, (ca2, cb2)) = crossed_accounts();
    route_all(&mut p);
    let a_lost: Vec<_> = p.a.pipe.closed.iter().map(|(c, _)| *c).collect();
    let b_lost: Vec<_> = p.b.pipe.closed.iter().map(|(c, _)| *c).collect();
    let pairs = [(p.ca, p.cb), (ca2, cb2)];
    assert_eq!(a_lost.len(), 1, "one closed: {a_lost:?}");
    let (lost, kept) = if a_lost[0] == pairs[0].0 { (pairs[0], pairs[1]) } else { (pairs[1], pairs[0]) };
    assert_eq!(b_lost, [lost.1], "the same connection at both ends");
    assert!(p.a.open(kept.0, &S) && p.b.open(kept.1, &S));
    for (x, conn) in [(&p.a, kept.0), (&p.b, kept.1)] {
        let kept_rec = x.opens.record(conn);
        let all: Vec<_> = x.store.with_read(|t| t.records_all()).unwrap().into_iter().map(|r| r.id).collect();
        assert_eq!(all.iter().map(|id| Some(*id)).collect::<Vec<_>>(), [kept_rec], "one record of the peer, the kept connection's");
    }
}

// spec/sync-opens.md §1 (Twin), §5 Testing (re-marking): a twinned connection's record goes with
// its members re-marked for the one that stays. Each connection in turn has every Hit garbled
// until the Twins land (S tested there, refused, `acked_pos` past it: a Hit that opened nothing
// is not tried again until a re-mark), so S is open on the other alone; whichever stays, S opens
// on it at both ends.
#[test]
fn a_twinned_records_members_are_remarked_on_the_survivor_spec_sync_opens_1() {
    for garbled in [0, 1] {
        let (mut p, (ca2, cb2)) = crossed_accounts();
        let pairs = [(p.ca, p.cb), (ca2, cb2)];
        let ends = pairs[garbled];
        let mut held = Vec::new();
        route_with(&mut p, |from_a, c, m| match m {
            Msg::Twin { .. } => {
                held.push((from_a, c, m));
                None
            }
            Msg::Offer { id, mut items } if c == if from_a { ends.0 } else { ends.1 } => {
                for it in &mut items {
                    match it {
                        OfferItem::Hit { hit, .. } | OfferItem::Static { hit, .. } => hit[0] ^= 1,
                        OfferItem::ByRole { hits, .. } => hits.iter_mut().for_each(|h| h[0] ^= 1),
                        _ => {}
                    }
                }
                Some(Msg::Offer { id, items })
            }
            m => Some(m),
        });
        assert!(!held.is_empty(), "a Twin went");
        let other = pairs[1 - garbled];
        assert!(!p.a.open(ends.0, &S) && !p.b.open(ends.1, &S) && p.a.open(other.0, &S) && p.b.open(other.1, &S), "S open only where Hits passed");
        let peer = |c: osis_sync::types::ConnId| osis_sync::types::ConnId(c.0 ^ osis_sync::types::ConnId::ACCEPTED);
        for (from_a, c, m) in held {
            if from_a { p.b.take(peer(c), incoming(m)) } else { p.a.take(peer(c), incoming(m)) }
        }
        route_all(&mut p);
        let lost: Vec<_> = p.a.pipe.closed.iter().map(|(c, _)| *c).collect();
        assert_eq!(lost.len(), 1, "one closed: {lost:?}");
        let kept = if lost[0] == pairs[0].0 { pairs[1] } else { pairs[0] };
        assert!(p.a.open(kept.0, &S) && p.b.open(kept.1, &S), "S open on the survivor at both ends (garbled {garbled})");
    }
}

// spec/sync-opens.md §1 (Twin): a Twin's sender takes the two connections as twinned only on the
// answer proving the peer holds the record: a forged Twinned closes nothing at the sender.
#[test]
fn a_forged_twinned_twins_nothing_spec_sync_opens_1() {
    let (mut p, _) = crossed_accounts();
    // b's Twins never reach a (a learns only from its own Twin's answer), and b's answers lie
    route_with(&mut p, |from_a, _, m| match m {
        Msg::Twin { .. } if !from_a => None,
        Msg::Twinned { id, tag: Some(_) } if !from_a => Some(Msg::Twinned { id, tag: Some([0x55; 32]) }),
        m => Some(m),
    });
    assert!(p.a.pipe.closed.is_empty(), "a closed {:?} on a forged answer", p.a.pipe.closed);
}

// spec/sync-opens.md §1 (Twin): a Twin whose tag names no record of another connection here (a
// guess, or another node of the peer's account) twins nothing: answered with none, nothing closes.
#[test]
fn a_twin_naming_no_record_here_twins_nothing_spec_sync_opens_1() {
    let (mut p, (ca2, _)) = crossed_accounts();
    // the Twins lost: two connections of account 2, each on a record of its own
    route_with(&mut p, |_, _, m| (!matches!(m, Msg::Twin { .. })).then_some(m));
    p.a.take(ca2, osis_sync::session::Incoming::Request(9, Msg::Twin { id: 9, tag: [0x77; 32] }));
    assert!(p.a.pipe.sent.iter().any(|(c, m)| *c == ca2 && matches!(m, Msg::Twinned { id: 9, tag: None })), "answered with none");
    assert!(p.a.pipe.closed.is_empty() && p.b.pipe.closed.is_empty());
    assert!(p.a.open(p.ca, &S) && p.a.open(ca2, &S));
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
    let stand = osis_sync::store::Stand { at: osis_base::WallMs(1), logged: osis_base::BlobId([1; 32]), head: osis_blob::StepId([2; 32]), fall: 0 };
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
    use osis_crypto::{Epoch, RoleKey, Secret32, SeededRng, role_key};
    use osis_engine::sync_ids::HeadKeys;
    use osis_engine::sync::{Path, ReadCredentials};
    use osis_blob::{Parent, StepKeys};
    use osis_sync::opens::cred::Tested;
    use osis_sync::opens::holds::walk_tests;
    let thing = osis_base::Tid::from_bytes([3; 15]);
    let admin = Secret32::from_bytes([0xab; 32]);
    let (old, new) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]));
    let id = osis_blob::genesis_sync_id(&admin);
    let keys = StepKeys::derive(&old, &old, &admin, &Secret32::from_bytes([9; 32]), &id);
    let read = Epoch::derive(&thing, osis_base::Role::Read, 0, &old).unwrap();
    let se = |n: u64, x: &Secret32| Epoch::derive(&thing, osis_base::Role::Sync, n, x).unwrap();
    let d = role_key(RoleKey::Delete, &admin);
    let (genesis, _) = osis_blob::register(Parent::Genesis(&d), keys, &[], (&thing, read, &old), (se(0, &old), &old), &mut SeededRng::from_u64(0)).unwrap();
    let k = |x: &Secret32| role_key(RoleKey::Sync, x);
    let mut rc = ReadCredentials::default();
    rc.keys.insert(genesis.id(), HeadKeys { sync: Some(k(&old)), epochs: [Some(se(0, &old)), None, None], ..HeadKeys::default() });
    rc.sync_keys = vec![(se(1, &new), k(&new)), (se(0, &old), k(&old))];
    let path = Path { steps: vec![(genesis.clone(), None)] };
    let tests = walk_tests(&rc, &path, &mut |_| None);
    let got: Vec<(Option<osis_blob::StepId>, [u8; 32])> = tests
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

/// S's recorded genesis step (its sync key `st`'s) and a child step under it whose sync key the
/// reader does not hold, signed by the genesis delete key (`bad`: signed by another key).
fn path_past(st: &StepKeys, bad: bool) -> (osis_blob::Step, osis_blob::Step) {
    use osis_crypto::{Domain, Secret32, Signature, SigningSecret};
    let d0 = SigningSecret::from_seed(&Secret32::from_bytes([0xd0; 32]));
    let keys = |sync: osis_crypto::VerifyingKey, d: &SigningSecret| osis_blob::StepKeys { sync, write: d.verifying_key(), delete: d.verifying_key(), deposit: d.verifying_key() };
    let g0 = osis_blob::Step { sync_id: S, prev: None, keys: keys(st.sync.verifying_key(), &d0), step_key: [1; 32], claims_hash: [0; 32], sig: Signature([0; 64]) };
    let d1 = SigningSecret::from_seed(&Secret32::from_bytes([0xd1; 32]));
    let mut g1 = osis_blob::Step { sync_id: S, prev: Some(g0.id()), keys: keys(StepKeys::new(1, 1).sync.verifying_key(), &d1), step_key: [2; 32], claims_hash: [0; 32], sig: Signature([0; 64]) };
    g1.sig = if bad { &d1 } else { &d0 }.sign(Domain::SyncStep, &g1.digest());
    (g0, g1)
}

/// A reader at recorded step `st` whose only peer, Adv, J judges a sync holder, its filter
/// showing nothing of the reader's; Adv answers the reader's first Behind with `answer`.
fn walk_answered(answer: osis_proto::SharedItem, bad: bool) -> (Side, Adv, osis_blob::Step) {
    let st = StepKeys::new(1, 0);
    let (g0, g1) = path_past(&st, bad);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    r.table.recorded.insert(S, vec![g0]);
    r.table.judge_as(S, tid(9), J::SyncHolder);
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    adv.filter(&mut r, &[[0xee; 32]], &S);
    let sent = r.sent();
    let Some(Msg::Offer { id, items }) = of_kind(&sent, 37).pop() else { panic!("an Offer") };
    assert!(matches!(items.as_slice(), [OfferItem::Behind(b)] if b.sync_id == S), "nothing shown: Behind, {items:?}");
    let answer = match answer.code {
        Code::OK => osis_proto::SharedItem { grant: Some(osis_proto::Grant { entry_box: None, steps: vec![g1.clone()] }), ..answer },
        _ => answer,
    };
    adv.send(&mut r, Msg::Shared { id, items: vec![answer] });
    (r, adv, g1)
}

// spec/sync-ids.md §6 (Walk: Known steps, Stranded there), spec/permissions.md §4 (stranded): a
// reader whose Behind is answered with a step verifying under its recorded head, whose
// credential it does not hold, stops there naming that step's sync key; one refused on every
// step it had to try stops at its recorded head; an answer that does not verify teaches no step
// and stops nothing; a source not keeping S (13) stops nothing; the stop goes with the
// connection, and with S opened there by the peer's test.
#[test]
fn a_walk_stops_past_its_keys_or_refused_spec_sync_ids_6() {
    let ok = osis_proto::SharedItem::code(Code::OK);
    let (mut r, adv, g1) = walk_answered(ok.clone(), false);
    assert_eq!(r.opens.walk_stop(&S), Some(Some(g1.keys.sync.to_bytes())), "stopped at the step it learned");
    assert!(of_kind(&r.sent(), 37).is_empty(), "nothing more asked");
    r.closed(adv.peer);
    assert_eq!(r.opens.walk_stop(&S), None, "the stop goes with the connection");
    let (mut r, mut adv, _) = walk_answered(ok.clone(), false);
    let hit = adv.hit_on(read_secret(1, 0).1.expose(), &S);
    assert_eq!(adv.offer(&mut r, vec![OfferItem::Hit { hit, sig: None, unread: false }])[0].code, Code::OK);
    assert!(r.open(adv.peer, &S));
    assert_eq!(r.opens.walk_stop(&S), None, "S opened there by the peer's test: no stop");
    let (mut r, ..) = walk_answered(osis_proto::SharedItem::code(Code::DECLINED), false);
    assert_eq!(r.opens.walk_stop(&S), Some(None), "refused on its only step: stopped at its head");
    assert!(of_kind(&r.sent(), 37).is_empty(), "each step asked once per walk");
    let (r, ..) = walk_answered(ok, true);
    assert_eq!(r.opens.walk_stop(&S), None, "a step that does not verify is not known");
    let (r, ..) = walk_answered(osis_proto::SharedItem::code(Code::UNKNOWN_SYNC_ID), false);
    assert_eq!(r.opens.walk_stop(&S), None, "13: the source does not keep S");
}

// spec/sync-ids.md §6 (Behind: refused for now, code 4: asked again after a back-off): a
// Behind answered 4 is not asked again before its back-off, which wakes the node, stops nothing
// and is not counted off the path; once over it is asked again, and a second 4 backs off longer;
// S opened there meanwhile, the back-off's end leaves no wake due (the node would spin).
#[test]
fn a_behind_refused_for_now_is_asked_again_after_a_back_off_spec_sync_ids_6() {
    use osis_base::Mono;
    use osis_sync::inbox::{BACKOFF_MIN_MS, backoff_ms};
    let behind = |r: &mut Side| of_kind(&r.sent(), 37).into_iter().find_map(|m| match m {
        Msg::Offer { id, items } if matches!(items.as_slice(), [OfferItem::Behind(b)] if b.sync_id == S) => Some(id),
        _ => None,
    });
    let (mut r, mut adv, _) = walk_answered(osis_proto::SharedItem::code(Code::RATE_LIMITED), false);
    assert_eq!(r.opens.walk_stop(&S), None, "refused for now: no stop");
    assert_eq!(r.opens.next_wake(), Some(Mono(r.mono.0 + BACKOFF_MIN_MS)), "its back-off wakes the node");
    r.mono = Mono(r.mono.0 + BACKOFF_MIN_MS - 1);
    r.settle();
    assert_eq!(behind(&mut r), None, "not asked within its back-off");
    r.mono = Mono(r.mono.0 + 1);
    r.settle();
    let Some(id) = behind(&mut r) else { panic!("asked again once its back-off is over") };
    adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem::code(Code::RATE_LIMITED)] });
    assert_eq!(r.opens.next_wake(), Some(Mono(r.mono.0 + backoff_ms(1))), "a second 4: a longer back-off");
    // S opened there meanwhile: its back-off ending asks nothing and leaves no wake past
    let hit = adv.hit_on(read_secret(1, 0).1.expose(), &S);
    assert_eq!(adv.offer(&mut r, vec![OfferItem::Hit { hit, sig: None, unread: false }])[0].code, Code::OK);
    assert!(r.open(adv.peer, &S));
    r.mono = Mono(r.mono.0 + backoff_ms(1));
    r.settle();
    assert_eq!(behind(&mut r), None, "S open: no Behind");
    assert!(r.opens.next_wake().is_none_or(|t| t > r.mono), "no wake left due: {:?} at {:?}", r.opens.next_wake(), r.mono);
}

// spec/sync-ids.md §6 (Walk: Stranded there), spec/sync-opens.md §3 (record: it keeps the
// source's step): where a walk stopped is kept in the peer's record, so after both sides restart
// the record's next connection starts stopped there, testing nothing again; a test there that
// opens S ends the stop.
#[test]
fn a_walk_stop_is_kept_in_the_record_across_a_restart_spec_sync_ids_6() {
    let (st, head) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let mut r = Side::new(1);
    let mut k = Side::new(2);
    r.table.set(S, Some(reader(&S, &read_secret(1, 0), &st, &[], &[], &[])));
    r.table.judge_as(S, tid(2), J::SyncHolder);
    k.table.set(S, Some(store(&head)));
    r.settle();
    k.settle();
    let mut p = Pair::new(r, k, account(1), account(2));
    p.run();
    assert!(!p.a.open(p.ca, &S));
    assert_eq!(p.a.opens.walk_stop(&S), Some(None), "refused (the store's Behind answers 14): stopped");
    p.close();
    assert_eq!(p.a.opens.walk_stop(&S), None);
    p.a.restart();
    p.b.restart();
    p.log.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.log.iter().any(|(_, m)| matches!(m, Msg::Resumed { tag: Some(_), .. })), "the record resumed");
    assert_eq!(p.a.opens.walk_stop(&S), Some(None), "stopped there again");
    assert!(!p.log.iter().any(|(_, m)| matches!(m, Msg::Offer { .. })), "nothing tested: {:?}", p.log);
    p.a.table.set(S, Some(reader(&S, &read_secret(1, 0), &head, &[st], &[], &[])));
    p.settle();
    assert!(p.a.open(p.ca, &S), "granted the head's key: open");
    assert_eq!(p.a.opens.walk_stop(&S), None, "open: no stop");
}

// ---- where a closed member stopped (spec/sync-opens.md §6 Where it stopped) ----

fn left_how(moved: &[Moved], c: osis_sync::types::ConnId, s: SyncId) -> Option<Leaving> {
    moved.iter().rev().find_map(|m| match m {
        Moved::Left(x, y, at) if *x == c && *y == s => Some(at.how),
        _ => None,
    })
}

fn cursor(p: u64) -> Option<osis_proto::Cursor> {
    osis_proto::Cursor::new(p.to_be_bytes().to_vec()).ok()
}

// spec/sync-opens.md §6 (Where it stopped): a side that closed a member at its `until` keeps
// where its own stream holds it until the peer's Lost, then the position that Lost names: opened
// again on that connection, it rejoins from there.
#[test]
fn a_member_closed_at_its_until_rejoins_from_the_peers_lost_spec_sync_opens_6() {
    for answered in [false, true] {
        let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
        let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
        adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
        k.table.set(S, Some(store(&s1)));
        k.settle();
        k.reported(adv.peer, S, k.table.until);
        assert!(!k.open(adv.peer, &S));
        assert_eq!(left_how(&k.moved, adv.peer, S), Some(Leaving::Kept));
        if answered {
            let id = adv.id();
            adv.send(&mut k, Msg::Lost { id, items: vec![(S, cursor(5))] });
        }
        k.moved.clear();
        assert_eq!(adv.offer(&mut k, vec![sync_key_hit(&adv, &s1)])[0].code, Code::OK);
        let want = if answered { Rejoin::From(Some(5u64.to_be_bytes().to_vec())) } else { Rejoin::Held };
        assert!(k.moved.contains(&Moved::Joined(adv.peer, S, want.clone())), "answered {answered}: {want:?} in {:?}", k.moved);
    }
}

// spec/sync-opens.md §6 (Where it stopped): a side that closed a member at once (J departed)
// keeps nothing, whatever Lost follows: what its source showed goes and its rejoin is from the
// start; the side receiving that Lost keeps the position it names.
#[test]
fn a_close_for_a_departure_keeps_nothing_here_spec_sync_opens_6() {
    let mut p = readers();
    p.b.reported(p.cb, S, 4);
    p.a.reported(p.ca, S, 7);
    departs(&mut p);
    p.run();
    assert_eq!(left_how(&p.a.moved, p.ca, S), Some(Leaving::Forgot));
    assert_eq!(left_how(&p.b.moved, p.cb, S), Some(Leaving::Kept));
    // b answered with its own Lost naming 4: a keeps nothing still
    assert!(p.log.iter().any(|(by_a, m)| !*by_a && matches!(m, Msg::Lost { items, .. } if items[0] == (S, cursor(4)))), "b answers");
    // the Lost re-marked S at b: tested again (its Hit refused while a judges b departed)
    let after = p.log.iter().position(|(by_a, m)| *by_a && matches!(m, Msg::Lost { .. })).unwrap();
    assert!(p.log[after..].iter().any(|(by_a, m)| !*by_a && matches!(m, Msg::Offer { .. })), "b tests S again");
    p.a.moved.clear();
    p.b.moved.clear();
    regranted(&mut p);
    p.run();
    assert!(p.a.moved.contains(&Moved::Joined(p.ca, S, Rejoin::From(None))), "{:?}", p.a.moved);
    assert!(p.b.moved.contains(&Moved::Joined(p.cb, S, Rejoin::From(Some(7u64.to_be_bytes().to_vec())))), "{:?}", p.b.moved);
}

// spec/sync-opens.md §6 (Lost; Where it stopped): a Lost for S that left the sender's sync set
// names no position, and its receiver keeps nothing of where S stopped.
#[test]
fn a_lost_for_s_that_left_the_senders_sync_set_names_none_spec_sync_opens_6() {
    let mut p = readers();
    p.a.reported(p.ca, S, 7);
    p.a.table.set(S, None);
    p.a.settle();
    p.run();
    assert!(p.log.iter().any(|(by_a, m)| *by_a && matches!(m, Msg::Lost { items, .. } if items[0] == (S, None))), "{:?}", p.log);
    assert_eq!(left_how(&p.b.moved, p.cb, S), Some(Leaving::Forgot));
}

// spec/sync-opens.md §6 (Where it stopped): a kept stop lasts its connection: when it ends, what
// the source showed goes (`Forgot`) and the next connection's rejoin is from the start.
#[test]
fn a_kept_stop_goes_with_its_connection_spec_sync_opens_6() {
    let mut p = readers();
    p.a.reported(p.ca, S, 7);
    departs(&mut p);
    p.run();
    assert_eq!(left_how(&p.b.moved, p.cb, S), Some(Leaving::Kept));
    p.b.moved.clear();
    p.close();
    assert!(p.b.moved.contains(&Moved::Forgot(p.cb, S)), "{:?}", p.b.moved);
    regranted(&mut p);
    p.b.moved.clear();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.b.open(p.cb, &S));
    assert!(p.b.moved.contains(&Moved::Joined(p.cb, S, Rejoin::From(None))), "{:?}", p.b.moved);
}

// spec/sync-opens.md §6 (Where it stopped): a node that stops holding S sends a Lost naming S and
// none on each connection keeping S's stop, and that Lost makes the peer forget its own.
#[test]
fn a_node_leaving_s_tells_each_connection_keeping_its_stop_spec_sync_opens_6() {
    // b's own stop of S is kept (closed at its until, before any Lost): the Lost naming none
    // forgets it
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    k.reported(adv.peer, S, k.table.until);
    assert_eq!(left_how(&k.moved, adv.peer, S), Some(Leaving::Kept));
    k.moved.clear();
    let id = adv.id();
    adv.send(&mut k, Msg::Lost { id, items: vec![(S, None)] });
    assert!(k.moved.contains(&Moved::Forgot(adv.peer, S)), "{:?}", k.moved);
    // and k, leaving S with a stop kept, tells the peer
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![sync_key_hit(&adv, &s0)]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    k.reported(adv.peer, S, k.table.until);
    k.sent();
    k.table.set(S, None);
    k.settle();
    assert!(of_kind(&k.sent(), 38).iter().any(|m| matches!(m, Msg::Lost { items, .. } if items[0] == (S, None))));
}

// spec/sync-opens.md §4 (Source: a member's class is what its peer declared, whichever side's
// Hit opened S): two nodes keeping S unread at one step, and a reader with a node keeping S
// unread, class each other alike whichever side's Offer arrives first; once the store reads S,
// the member closes and opens again, and both class each other readers.
#[test]
fn a_sources_class_is_its_declaration_whichever_hit_opens_spec_sync_opens_4() {
    use SourceClass::{Reader, Store};
    let st = StepKeys::new(1, 0);
    let rd = || reader(&S, &read_secret(1, 0), &st, &[], &[], &[]);
    let class = |c: &osis_sync::opens::holds::Creds| if c.holding == Some(osis_sync::types::Holding::Unread) { Store } else { Reader };
    for (x, y) in [(store(&st), store(&st)), (rd(), store(&st)), (store(&st), rd())] {
        let mut a = Side::new(1);
        let mut b = Side::new(2);
        let want = (class(&y), class(&x));
        a.table.set(S, Some(x));
        b.table.set(S, Some(y));
        let mut p = Pair::new(a, b, Proven::default(), Proven::default());
        p.run();
        let first = p.log.iter().find(|(_, m)| matches!(m, Msg::Offer { .. })).map(|(by_a, _)| *by_a);
        assert_eq!(first, Some(true), "the dialer's Offer arrives first");
        let (ma, mb) = (&p.a.opens.members(p.ca)[&S], &p.b.opens.members(p.cb)[&S]);
        assert_eq!((ma.class, mb.class), want, "each side's class of the other is the other's own");
        assert_eq!((ma.own, mb.own), (want.1, want.0));
        // the side keeping S unread comes to read it
        if want.0 == Store {
            p.b.table.set(S, Some(rd()));
            p.b.settle();
            p.run();
            let (ma, mb) = (&p.a.opens.members(p.ca)[&S], &p.b.opens.members(p.cb)[&S]);
            assert_eq!((ma.class, mb.own), (Reader, Reader), "reopened at its new class");
        }
    }
}

/// The classes node `i` gives the sources of S proved by node `j`'s account.
fn classes(w: &crate::harness::World, i: usize, j: usize, s: &SyncId) -> Vec<SourceClass> {
    let a = w.node(j).account;
    w.status(i).get(s).map(|st| st.sources.values().filter(|x| x.src.account == a).map(|x| x.src.class).collect()).unwrap_or_default()
}

// spec/sync-opens.md §4 (Source: a source's class is what its peer declared, whether it keeps S
// unread, never which side's Hit opened S), §6 (Lost: a member whose own class moved closes and
// opens again):
// nodes 1 and 2 keep S unread and class each other a store; once node 2 writes S, node 2 classes
// node 1 a store and nodes 0 and 1 class node 2 a reader, after a reconnect and a restart too;
// and node 2's purge of its own write deletes it at node 1.
#[test]
fn a_sources_class_follows_what_the_peer_holds_spec_sync_opens_4() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, value_ak, world};
    use osis_engine::Mutation;
    use SourceClass::{Reader, Store};
    let mut w = world(0, 3);
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Syncs), Run, Run, Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).home_sync_id(&t).unwrap().unwrap();
    let all = |w: &crate::harness::World| [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)].map(|(i, j)| ((i, j), classes(w, i, j, &s)));
    let want = |two: SourceClass| [((0, 1), vec![Store]), ((0, 2), vec![two]), ((1, 0), vec![Reader]), ((1, 2), vec![two]), ((2, 0), vec![Reader]), ((2, 1), vec![Store])];
    assert_eq!(all(&w), want(Store), "both keep S unread");
    let _ = crate::harness::play(&mut w, &[Grant(0, 0, 2, Gives::Writes), Run], String::new());
    assert_eq!(all(&w), want(Reader), "node 2 reads S");
    w.cut(1, 2);
    w.run();
    assert_eq!(all(&w), want(Reader), "after a reconnect");
    w.power_off(2);
    w.power_on(2);
    w.run();
    assert_eq!(all(&w), want(Reader), "after node 2 restarts");
    // node 2's purge of its own write deletes it at node 1, node 0 away
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &osis_base::Value::Str("by 2".into())).unwrap().retention(t, &value_ak(), osis_schema::Retention { by: osis_base::PurgeBy::AuthorOrAdmin }).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let at1 = |w: &mut crate::harness::World| w.store(1).entries(&s).unwrap().into_iter().filter(|e| w.engine(2).blob_commit(&e.blob) == Some(c)).count();
    assert!(at1(&mut w) > 0, "node 1 holds node 2's write");
    w.power_off(0);
    w.write(2, |e| {
        let mut m = Mutation::new();
        let now = e.now();
        m.set(t, &osis_schema::core_types::PURGE, &now).unwrap();
        m.purge_commit(c, t, value_ak());
        e.commit(m).unwrap().unwrap();
    });
    w.run();
    assert_eq!(at1(&mut w), 0, "node 2 deleted its purged write at node 1");
}

// spec/sync-opens.md §4 (Source: a side opens S only while its class is still the one it
// declared in that exchange): store K Hits the sync key Adv shows, declaring it keeps S unread;
// K comes to read S before Adv's valid answer arrives. K opens nothing at the class it declared
// (Adv would class it a store for the member's life): a member there, if any, is at its new class.
#[test]
fn an_answer_after_the_testers_class_moved_opens_nothing_at_the_old_class_spec_sync_opens_4() {
    let s0 = StepKeys::new(1, 0);
    for moved in [false, true] {
        let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
        adv.filter(&mut k, &[s0.pk()], &S);
        let sent = k.sent();
        let Some(Msg::Offer { id, items }) = of_kind(&sent, 37).pop() else { panic!("K Hits the sync key Adv shows") };
        assert!(matches!(items[..], [OfferItem::Hit { unread: true, .. }]), "{items:?}");
        if moved {
            k.table.set(S, Some(reader(&S, &read_secret(1, 0), &s0, &[], &[], &[])));
            k.settle();
            k.sent();
        }
        let tag = adv.tag_on(&s0.pk(), &S);
        adv.send(&mut k, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), grant: None, sig: Some(adv.bind.sign(&s0.sync, &S)), unread: false }] });
        let own = k.opens.members(adv.peer).get(&S).map(|m| m.own);
        let want = if moved { None } else { Some(SourceClass::Store) };
        assert_eq!(own, want, "moved {moved}");
    }
}
