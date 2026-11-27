//! Opens: records, agreement, the shared set, filters, Offer and ending (spec/sync-opens.md §3-§6),
//! between honest sides and against hostile scripted peers (harness::scripted). Each test named
//! for a NetOpen control (core/test/tla/net/NetOpen.tla, `ON_*`) fails when that control's rule
//! is taken out of `osis_sync::opens`.

use crate::harness::scripted::*;
use osis_base::SyncId;
use osis_proto::{Code, Msg, OfferItem};
use osis_sync::opens::{Leaving, Moved, Peer, Rejoin};
use osis_sync::session::Proven;
use osis_sync::types::{Credential, SourceClass};

const S: SyncId = SyncId([5; 16]);

/// Two readers of S at one step, met (`reader_pair`).
fn readers() -> Pair {
    let mut p = reader_pair(account(1), account(2));
    p.run();
    p
}

/// Two readers of S at one step, settled, `a` dialing `b` proving `pa` and `pb`; nothing routed
/// yet.
fn reader_pair(pa: Proven, pb: Proven) -> Pair {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    a.table.set(S, Some(reader(&st, &[])));
    b.table.set(S, Some(reader(&st, &[])));
    a.settle();
    b.settle();
    Pair::new(a, b, pa, pb)
}

/// S's head at `side` moves to step `n`, the sync secret of step 0 held still (spec/sync-opens.md
/// §6), as a removal's rotation moves the remover's and a grant the grantee's.
fn rotated(side: &mut Side, n: u8) {
    side.table.set(S, Some(reader(&StepKeys::new(1, n), &[StepKeys::new(1, 0)])));
}

/// `a`'s head moves past the step `b`'s member opened by: that member is ended at `until`; `b` is
/// granted again later.
fn ends(p: &mut Pair) {
    rotated(&mut p.a, 1);
    p.a.settle();
}

/// `b` takes the sync secret of `a`'s head.
fn regranted(p: &mut Pair) {
    rotated(&mut p.b, 1);
    p.b.settle();
}

// spec/sync-opens.md §5 (opening): one Hit and its answer open S both ways.
#[test]
fn one_hit_opens_both_ways_spec_sync_opens_5() {
    let p = readers();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    let m = &p.a.opens.members(p.ca)[&S];
    assert_eq!((m.class, m.by), (SourceClass::Reader, Credential::SyncProof(StepKeys::new(1, 0).pk())));
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
    assert!(p.a.moved.iter().any(|m| matches!(m, Moved::Taken(c, ..) if *c == p.ca)), "the record taken: its members open on it");
    assert!(p.a.opens.agreed(p.ca) && p.b.opens.agreed(p.cb));
}

// spec/sync-set.md §3 (To be waited for: a source, or a record N keeps holding S as a member), spec/permissions.md §3 (Lost access: no peer but its account's nodes): S is
// waited on while the connection has it open and, once closed, while the kept record holds it;
// a peer whose proven actors the caller skips (this account's own nodes, for a self-removal)
// holds no wait.
#[test]
fn waited_by_a_connection_or_a_kept_record_spec_sync_set_3() {
    let mut p = readers();
    let other = |a: &osis_store::Named| if a.things().contains(&tid(2)) { Peer::Skipped } else { Peer::Unlisted };
    let wait = |p: &Pair, s: &SyncId, f: &dyn Fn(&osis_store::Named) -> Peer| p.a.opens.wait_for(&p.a.store, s, f).unwrap();
    assert!(wait(&p, &S, &|_| Peer::Unlisted), "open on a connection");
    assert!(!wait(&p, &S, &other), "only a skipped peer");
    assert!(!wait(&p, &sid(9), &|_| Peer::Unlisted), "held by nobody");
    p.close();
    assert!(wait(&p, &S, &|_| Peer::Unlisted), "the peer away: its record holds S");
    assert!(!wait(&p, &S, &other), "its record names a skipped actor");
}

// spec/sync-set.md §3 (To be waited for: one the rosters name while no record of it acknowledged
// S's current credentials), spec/sync-opens.md §5 Testing (`acked_pos`): S joins `a` while
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
    p.a.table.set(s2, Some(reader(&st, &[])));
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
    // a second record naming the same actors (a crash's leftover until the pair's next take, §3 One
    // record per pair) is the same peer: told by one of its records, it is told; one naming other actors is another peer
    p.a.store.with_tx(|t| t.record_create([9; 32], &named(2)).map(drop)).unwrap();
    p.a.restart();
    assert!(!wait(&p, &may), "the same peer, told by its other record");
    p.a.store.with_tx(|t| t.record_create([8; 32], &named(3)).map(drop)).unwrap();
    p.a.restart();
    assert!(wait(&p, &may) && !wait(&p, &|a| if a.things().contains(&tid(3)) { Peer::Unlisted } else { Peer::MayHold }), "another peer, never told");
    let st3 = StepKeys::new(3, 0);
    p.a.table.set(s2, Some(reader(&st3, &[])));
    p.a.settle();
    assert!(wait(&p, &may), "S's credentials moved: b not told of them");
    p.b.table.set(s2, Some(reader(&st3, &[])));
    p.b.settle();
    p.connect(3, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &s2) && wait(&p, &|_| Peer::Unlisted), "open: a member");
}

// spec/sync-set.md §3 (To be waited for: not one whose records went),
// spec/sync-opens.md §3 (RECORD_BUDGET): the record of a peer away that was never told of S goes
// past the budget, and the wait with it: nothing stays stuck on a peer that never returns.
#[test]
fn an_evicted_record_ends_its_wait_spec_sync_set_3() {
    let s2 = sid(7);
    let mut p = readers();
    p.close();
    let st = StepKeys::new(2, 0);
    p.a.table.set(s2, Some(reader(&st, &[])));
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
        Msg::Offer { items, .. } => items.iter().filter(|i| matches!(i, OfferItem::Hit { .. })).count(),
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
    r.table.set(S, Some(reader(&st, &[])));
    k.table.set(S, Some(store(&st)));
    let mut p = Pair::new(r, k, Proven::default(), Proven::default());
    p.run();
    assert!(p.a.opens.record(p.ca).is_none() && p.b.opens.record(p.cb).is_none());
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
    assert_eq!(p.a.opens.members(p.ca)[&S].class, SourceClass::Store);
}

// spec/sync-opens.md §4 (Admissible: keeping S unread with no head, its step is the newest sync
// secret it holds) and spec/sync-ids.md §6 (Walk): a node granted sync that starts keeping S
// after the reader tested it there (nothing shown then) opens S by its own test when it does;
// the reader tests S again once, for the store's filter showing a credential of S (§5 Testing),
// and nothing else. A store with no step showing and testing nothing fails this.
#[test]
fn a_store_granted_later_opens_with_no_head_spec_sync_opens_4() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    let k = Side::new(2);
    r.table.set(S, Some(reader(&st, &[])));
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
    assert!(p.a.opens.work().tested <= tested + 1, "the reader tested S again once at most");
}

// spec/sync-opens.md §4 (Source: a class that moves closes the member, and S opens again with
// both classes declared anew): a, open with b on S by J, comes to hold S for keys and back to
// read before its Offer declaring keys is answered; b, told of the close, offers S declaring
// reader as it takes a's Offer. Each side opens S by the other's exchange; at the end b's member
// has a's class as a holds S, a reader (else b serves a S's role entries alone). Control: a
// staying keys.
#[test]
fn crossing_offers_leave_both_sides_one_class_spec_sync_opens_4() {
    use osis_sync::types::Holding;
    for back in [true, false] {
        let st = StepKeys::new(1, 0);
        let creds = |h: Holding| osis_sync::opens::holds::Creds { holding: Some(h), ..reader(&st, &[]) };
        let mut a = Side::new(1);
        let mut b = Side::new(2);
        a.table.set(S, Some(creds(Holding::Read)));
        b.table.set(S, Some(creds(Holding::Read)));
        let mut p = Pair::new(a, b, account(1), account(2));
        p.run();
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
        // a's Lost and its Offer declaring keys go out; a reads again before b takes them
        p.a.table.set(S, Some(creds(Holding::Stub)));
        p.a.settle();
        if back {
            p.a.table.set(S, Some(creds(Holding::Read)));
            p.a.settle();
        }
        p.run();
        let class = if back { SourceClass::Reader } else { SourceClass::Stub };
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "open again");
        assert_eq!(p.b.opens.members(p.cb)[&S].class, class, "b holds a's class as a declares it now");
        assert_eq!(p.a.opens.members(p.ca)[&S].own, class);
    }
}

// spec/sync-opens.md §6 (Where it stopped: a member declared a stub keeps nothing once this side
// holds S otherwise), spec/sync-streams.md §4 (Toward a peer holding S's thing as a stub): a holds S as a
// stub, open with b, b having stored a's log at 7; a comes to read S, with its member open
// (closed as its class moved) or ended by a's head moving (closed at its `until`). Its stream
// stood where b served it role entries alone, so a rejoins from the start, whatever b's Lost
// names (failed while either close kept where the stub's stream stood: content it was never
// served was never pulled).
#[test]
fn a_stub_coming_to_read_rejoins_from_the_start_spec_sync_opens_6() {
    use osis_sync::types::Holding;
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    for ended in [false, true] {
        let creds = |h: Holding, at: &StepKeys, older: &[StepKeys]| osis_sync::opens::holds::Creds { holding: Some(h), ..reader(at, older) };
        let mut a = Side::new(1);
        let mut b = Side::new(2);
        a.table.set(S, Some(creds(Holding::Stub, &s0, &[])));
        b.table.set(S, Some(creds(Holding::Read, &s0, &[])));
        let mut p = Pair::new(a, b, account(1), account(2));
        p.run();
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S));
        assert_eq!(p.a.opens.members(p.ca)[&S].own, SourceClass::Stub);
        p.b.reported(p.cb, S, 7);
        p.a.moved.clear();
        let at = if ended { &s1 } else { &s0 };
        let older: &[StepKeys] = if ended { std::slice::from_ref(&s0) } else { &[] };
        if ended {
            p.a.table.until = 3;
            p.a.table.set(S, Some(creds(Holding::Stub, at, older)));
            p.a.settle();
            assert!(p.a.opens.members(p.ca)[&S].until.is_some(), "ended");
        }
        p.a.table.set(S, Some(creds(Holding::Read, at, older)));
        p.a.settle();
        if ended {
            p.a.reported(p.ca, S, 3);
            p.a.settle();
            p.b.table.set(S, Some(creds(Holding::Read, &s1, std::slice::from_ref(&s0))));
            p.b.settle();
        }
        p.run();
        assert!(p.a.open(p.ca, &S), "ended {ended}: open again as a reader");
        assert!(p.a.moved.contains(&Moved::Joined(p.ca, S, Rejoin::From(None))), "ended {ended}: rejoined from the start: {:?}", p.a.moved);
    }
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
    // b stored a's log at 7 for S (a learns it from b's Applied), its `until`
    p.a.reported(p.ca, S, 7);
    p.a.table.until = 7;
    ends(&mut p);
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
    assert!(p.b.moved.iter().any(|m| matches!(m, Moved::Taken(c, ..) if *c == p.cb)), "{:?}", p.b.moved);
    assert!(!p.b.moved.iter().any(|m| matches!(m, Moved::Joined(..) | Moved::Left(..))), "no member moves: {:?}", p.b.moved);
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
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&st, &[])));
    r.settle();
    // `r` dials Adv, which it knows: Resume.
    let mut adv = Adv::connect(&mut r, true, [1; 32], [2; 32], account(9));
    let sent = r.sent();
    let Some(Msg::Resume { id, nonce, .. }) = of_kind(&sent, 34).pop() else { panic!("Resume") };
    let an = [3; 32];
    adv.send(&mut r, Msg::Resumed { id, nonce: an, tag: None });
    let rr = *osis_crypto::kdf::pair_key(&nonce, &an).expose();
    let b = osis_crypto::kdf::beacon(&st.proof, &S.0, &rr);
    let f = 8;
    let gcs = osis_proto::filter::encode_gcs(&[osis_proto::filter::beacon_value(&b, f)], 0);
    let fid = adv.id();
    adv.send(&mut r, Msg::Beacons { id: fid, generation: 1, base: None, f, lo: 0, hi: 256, gcs, more: false });
    assert_eq!(offered_hits(&r.sent()), 0, "no Offer before the Digest");
    adv.send(&mut r, Msg::Digest { digest: [0; 32] });
    assert_eq!(offered_hits(&r.sent()), 1, "the Offer follows the Digest");
}

// spec/sync-opens.md §5 (Filter): every shown credential's beacon goes to every connection, one
// whose peer proved no actor included: a sync proof's.
#[test]
fn every_beacon_goes_to_every_peer_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&st, &[])));
    r.settle();
    let (_adv, sent) = Adv::dials(&mut r, Proven::default(), [2; 32]);
    assert_eq!(filter_values(&sent).0.len(), 1, "the proof");
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

/// Two readers sharing sync IDs 1 to 4 (room in the whole filter for later additions); `a`
/// comes to hold sync ID 5 and sends its additions, whose answer is lost with the connection
/// (`b` read them when `stored`), closed.
fn answer_lost(stored: bool) -> Pair {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 1..=4 {
        for x in [&mut a, &mut b] {
            x.table.set(sid(i), Some(reader(&st, &[])));
            x.settle();
        }
    }
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    p.a.table.set(sid(5), Some(reader(&st, &[])));
    p.a.settle();
    let sent = p.a.sent();
    assert!(!of_kind(&sent, 36).is_empty(), "a sent additions");
    if stored {
        for (c, m) in sent {
            if c == p.ca {
                p.b.take(p.cb, incoming(m));
            }
        }
    }
    p.close();
    p
}

/// `answer_lost(stored)`, connected again: the bases of `a`'s generations on the new connection,
/// and the codes `b` answered them with.
fn after_a_lost_answer(stored: bool) -> (Vec<Option<u64>>, Vec<Code>) {
    let mut p = answer_lost(stored);
    p.log.clear();
    p.connect(2, account(1), account(2));
    p.run();
    let gens: Vec<(osis_proto::Id, Option<u64>)> = p.log.iter().filter_map(|(from_a, m)| match m {
        Msg::Beacons { id, base, .. } if *from_a => Some((*id, *base)),
        _ => None,
    }).collect();
    let codes = p.log.iter().filter_map(|(from_a, m)| match m {
        Msg::Shared { id, items } if !from_a && gens.iter().any(|(g, _)| g == id) => items.first().map(|i| i.code),
        _ => None,
    }).collect();
    (gens.into_iter().map(|(_, b)| b).collect(), codes)
}

// spec/sync-opens.md §5 (filter: A generation never acknowledged; A receiver takes additions
// on their base or on a later generation): a
// generation whose answer was lost with its connection, read by the peer or not, is followed on
// the next connection by additions on the last acknowledged one, taken: no whole filter.
#[test]
fn a_lost_answer_costs_no_whole_filter_spec_sync_opens_5() {
    for stored in [false, true] {
        let (bases, codes) = after_a_lost_answer(stored);
        assert!(!bases.is_empty() && bases.iter().all(Option::is_some), "read {stored}: additions only: {bases:?}");
        assert!(codes.iter().all(|c| *c == Code::OK), "read {stored}: taken: {codes:?}");
    }
}

// spec/sync-opens.md §5 (filter: A receiver takes additions on a later generation; a whole one
// replaces additions once they pass its entries), spec/wire.md §11.2 (Beacons): after a lost
// answer the peer read, both sides count the additions alike: later additions up to the whole
// one's entries are taken, never closed as breaking the count, and past it a whole one follows.
#[test]
fn additions_after_a_lost_answer_keep_both_counts_alike_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut p = answer_lost(true);
    p.connect(2, account(1), account(2));
    p.run();
    p.log.clear();
    // counted apart, the additions of sync ID 8 fill `a`'s room but pass `b`'s on every
    // connection: never taken
    for i in 6..=12 {
        p.a.table.set(sid(i), Some(reader(&st, &[])));
        p.a.settle();
        p.run();
        if i == 8 {
            p.close();
            p.connect(3, account(1), account(2));
            p.run();
        }
    }
    assert!(p.b.pipe.closed.is_empty(), "b closed: {:?}", p.b.pipe.closed);
    let errors: Vec<_> = p.log.iter().filter(|(from_a, m)| !from_a && matches!(m, Msg::Error { .. })).collect();
    assert!(errors.is_empty(), "{errors:?}");
    assert!(p.log.iter().any(|(from_a, m)| *from_a && matches!(m, Msg::Beacons { base: None, .. })), "a whole one once the additions pass its entries");
}

// spec/sync-opens.md §5 (testing): a Hit that opened nothing is tried again on that connection
// only once something re-marks S or moves `changed_at(S)` (here a credential of S moving).
#[test]
fn a_refused_hit_is_tried_again_only_when_remarked_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&st, &[])));
    r.settle();
    let (mut adv, sent) = Adv::dials(&mut r, account(9), [2; 32]);
    // Adv acknowledges r's filter and shows r's sync proof: r Hits, Adv refuses.
    for m in of_kind(&sent, 36) {
        let id = m.id();
        adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem::code(Code::OK)] });
    }
    adv.filter(&mut r, &[st.proof], &S);
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
    r.table.set(S, Some(reader(&StepKeys::new(1, 1), std::slice::from_ref(&st))));
    r.settle();
    assert_eq!(offered_hits(&r.sent()), 1, "tried again once changed_at(S) moved");
}

// ---- NetOpen controls (core/test/tla/net/NetOpen.tla, ON_*): the hostile cases ----

/// A store K at `head` that Adv dials keeping no record, then Hits once (`hit_once`).
fn store_dialed_by_adv(head: &StepKeys, ch_adv: [u8; 32]) -> (Side, Adv) {
    let mut k = Side::new(3);
    k.table.set(S, Some(store(head)));
    k.settle();
    let (mut adv, _) = Adv::dials(&mut k, Proven::default(), ch_adv);
    hit_once(&mut k, &mut adv);
    (k, adv)
}

/// Adv's Hit on the sync proof of a step it holds the secret of.
fn proof_hit(adv: &Adv, st: &StepKeys) -> OfferItem {
    OfferItem::Hit { hit: adv.hit_on(&st.proof, &S), sig: None, class: osis_proto::SourceClass::Reader }
}

/// Adv Hits nothing K shows, so K indexes the Hits its filter makes possible now: what it shows
/// later must not take an entry of that index for proof.
fn hit_once(h: &mut Side, adv: &mut Adv) {
    assert_eq!(adv.offer(h, vec![OfferItem::Hit { hit: [0; 32], sig: None, class: osis_proto::SourceClass::Reader }])[0].code, Code::DECLINED);
}

// spec/sync-opens.md §4: the sync proof of a step off this side's path proves nothing.
#[test]
fn an_older_steps_proof_proves_nothing_spec_sync_opens_4() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    k.table.set(S, Some(store(&s1)));
    k.settle();
    let a = adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&s0.proof, &S), sig: None, class: osis_proto::SourceClass::Reader }]);
    assert_eq!(a[0].code, Code::DECLINED);
    assert!(!k.open(adv.peer, &S));
}

// spec/sync-opens.md §6 (reported positions): an Applied moves every member at the stream (its
// join merged); an ended member there closes with a Lost naming `until` once the stream passes
// it, and not before.
#[test]
fn an_ended_member_closes_when_the_stream_passes_until_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![proof_hit(&adv, &s0)]);
    k.table.set(S, Some(store_with(&s1, &[&s0])));
    k.settle();
    let until = k.table.until;
    assert!(k.moved.contains(&Moved::Until(adv.peer, S)));
    k.join_merged(adv.peer, S);
    k.reported_stream(adv.peer, until - 1);
    assert!(k.open(adv.peer, &S));
    k.sent();
    // past `until`: the Lost names `until`, the lower (spec/sync-opens.md §6 Lost)
    k.reported_stream(adv.peer, until + 5);
    assert!(!k.open(adv.peer, &S));
    assert!(matches!(&of_kind(&k.sent(), 38)[..], [Msg::Lost { items, .. }] if items[0] == (S, osis_proto::Cursor::new(until.to_be_bytes().to_vec()).ok())));
}

// ON_endhead (spec/sync-opens.md §6): an open by a sync proof is re-judged at a rotation.
#[test]
fn a_proof_open_ends_at_a_rotation_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    assert_eq!(adv.offer(&mut k, vec![OfferItem::Hit { hit: adv.hit_on(&s0.proof, &S), sig: None, class: osis_proto::SourceClass::Reader }])[0].code, Code::OK);
    k.table.set(S, Some(store_with(&s1, &[&s0])));
    k.settle();
    assert!(k.opens.members(adv.peer)[&S].until.is_some(), "ended");
}

// spec/sync-opens.md §6 (judged in the step that applies the change; for every record holding
// the member whether connected or not): b's open by a's read secret ends with a's
// rotation while b is away; its `until` is a's position at the rotation, not at the reconnect,
// though a's log moved on meanwhile.
#[test]
fn an_until_is_the_position_of_the_change_while_away_spec_sync_opens_6() {
    let mut p = readers();
    let at = osis_sync::store::Source::Record(p.a.opens.record(p.ca).unwrap());
    p.close();
    p.a.settle();
    let then = p.a.table.until;
    rotated(&mut p.a, 1);
    p.a.settle();
    assert_eq!(p.a.opens.member_at(at, &S).and_then(|m| m.until), Some(then), "ended in the step of the rotation");
    p.a.table.until = then + 50;
    p.connect(2, account(1), account(2));
    p.run();
    assert_eq!(p.a.opens.member_at(at, &S).and_then(|m| m.until), Some(then), "served up to the rotation's position");
}

// spec/sync-opens.md §3 (`changed_at`: a node that stops holding S drops S from every record in
// the step that stops it), spec/sync-set.md §3 (Stopping): S leaving while no connection holds the
// record drops the member there, and what the other modules keep of it for that record goes
// (`Moved::Gone`), whether its credentials went to none or its rows were shredded while it stays
// synced (left and synced again before a settle saw it go).
#[test]
fn s_leaving_the_sync_set_while_away_drops_it_from_the_record_spec_sync_opens_3() {
    for shred in [false, true] {
        let mut p = readers();
        let rid = p.a.opens.record(p.ca).unwrap();
        p.close();
        p.a.settle();
        p.a.moved.clear();
        if shred {
            p.a.store.shred(&S).unwrap();
        } else {
            p.a.table.set(S, None);
        }
        p.a.settle();
        assert!(p.a.opens.member_at(osis_sync::store::Source::Record(rid), &S).is_none(), "shred {shred}");
        assert!(p.a.moved.contains(&Moved::Gone(rid, S)), "shred {shred}: {:?}", p.a.moved);
    }
}

// spec/sync-set.md §3 (Stopping), spec/sync-opens.md §6 (Where it stopped): S shredded and synced
// again before a settle saw it go rejoins from the start, never at where it stood before the
// shred: connected, the peer hears a Lost naming none; away, the next take opens S afresh.
#[test]
fn s_shredded_and_synced_again_rejoins_from_the_start_spec_sync_set_3() {
    for connected in [true, false] {
        let mut p = readers();
        assert!(p.a.open(p.ca, &S), "connected {connected}");
        p.a.reported(p.ca, S, 7);
        if !connected {
            p.close();
            p.a.settle();
        }
        p.a.store.shred(&S).unwrap();
        p.a.moved.clear();
        p.b.moved.clear();
        p.a.settle();
        if connected {
            p.run();
            assert!(p.log.iter().any(|(by_a, m)| *by_a && matches!(m, Msg::Lost { items, .. } if items[0] == (S, None))), "its Lost names no position: {:?}", p.log);
            assert!(p.b.moved.contains(&Moved::Joined(p.cb, S, Rejoin::From(None))), "b from the start: {:?}", p.b.moved);
        } else {
            p.connect(2, account(1), account(2));
            p.run();
        }
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "connected {connected}: opened again");
        assert!(p.a.moved.contains(&Moved::Joined(p.ca, S, Rejoin::From(None))), "connected {connected}: a from the start: {:?}", p.a.moved);
    }
}

/// The work done at a side since `before`.
fn since(w: osis_sync::opens::Work, before: osis_sync::opens::Work) -> osis_sync::opens::Work {
    osis_sync::opens::Work { rejudged: w.rejudged - before.rejudged, beacons: w.beacons - before.beacons, tested: w.tested - before.tested, creds: w.creds - before.creds }
}

/// Two readers sharing `n` sync IDs at step keys `st`, all open.
fn two_readers(n: u8, st: &StepKeys) -> Pair {
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 0..n {
        a.table.set(sid(i), Some(reader(st, &[])));
        b.table.set(sid(i), Some(reader(st, &[])));
    }
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!((0..n).all(|i| p.a.open(p.ca, &sid(i))));
    p
}

// ---- work in proportion to change (notes/principles.md, Check scaling) ----

/// Two readers sharing `n` sync IDs, all open; then one sync ID's credentials move on both.
/// The work of that change, at each side.
fn change_one_of(n: u8) -> osis_sync::opens::Work {
    let st = StepKeys::new(1, 0);
    let mut p = two_readers(n, &st);
    let before = p.a.opens.work();
    let next = StepKeys::new(1, 1);
    p.a.table.set(sid(0), Some(reader(&next, std::slice::from_ref(&st))));
    p.b.table.set(sid(0), Some(reader(&next, std::slice::from_ref(&st))));
    p.settle();
    assert!(p.a.open(p.ca, &sid(0)));
    since(p.a.opens.work(), before)
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
        r.table.set(sid(i), Some(reader(&st, &[])));
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
    r.table.set(sid(0), Some(reader(&st, &[])));
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
        adv.offer(&mut k, vec![proof_hit(&adv, &s0)]);
        k.reported(adv.peer, S, 3);
        if ending {
            k.table.set(S, Some(store_with(&s1, &[&s0])));
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
    adv.offer(&mut k, vec![proof_hit(&adv, &s0)]);
    k.table.set(S, Some(store_with(&s1, &[&s0])));
    k.settle();
    let until = k.opens.members(adv.peer)[&S].until.expect("ended");
    k.table.set(S, Some(store(&s0)));
    k.settle();
    assert_eq!(k.opens.members(adv.peer)[&S].until, Some(until), "still ended");
    k.sent();
    k.join_merged(adv.peer, S);
    k.reported_stream(adv.peer, until + 5);
    assert!(!k.open(adv.peer, &S));
    assert!(matches!(&of_kind(&k.sent(), 38)[..], [Msg::Lost { items, .. }] if items[0] == (S, osis_proto::Cursor::new(until.to_be_bytes().to_vec()).ok())));
}

// spec/sync-opens.md §5 (opening): a Lost after an Offer names only a sync ID whose Hit the peer
// answered with a valid tag: an OK with no valid tag (a hostile answer to a filter's false
// positive) learns no sync ID.
#[test]
fn no_lost_names_s_without_a_valid_tag_spec_sync_opens_5() {
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&st, &[])));
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    adv.filter(&mut r, &[st.proof], &S);
    let sent = r.sent();
    let Some(Msg::Offer { id, .. }) = of_kind(&sent, 37).pop() else { panic!("an Offer") };
    adv.send(&mut r, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some([0; 32]), sig: None, class: osis_proto::SourceClass::Reader }] });
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
    let st = StepKeys::new(1, 0);
    let mut r = Side::new(1);
    r.table.set(S, Some(reader(&st, &[])));
    r.settle();
    let (mut adv, _) = Adv::dials(&mut r, account(9), [2; 32]);
    adv.filter(&mut r, &[st.proof], &S);
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
    let mut p = reader_pair(Proven::default(), account(2));
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
        a.table.set(sid(i), Some(reader(&st, &[])));
    }
    b.table.set(sid(0), Some(reader(&st, &[])));
    let mut p = Pair::new(a, b, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &sid(0)));
    p.close();
    let before = p.a.opens.work();
    p.connect(2, account(1), account(2));
    p.run();
    assert!(p.a.open(p.ca, &sid(0)));
    since(p.a.opens.work(), before)
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
    assert!(p.a.moved.iter().any(|m| matches!(m, Moved::Released(c, _) if *c == ca1)), "the loser lets the record go");
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

/// Readers of S proving `pa` and `pb` that dial each other at once: a dials b (connection 1),
/// b dials a (connection 2), both proved, nothing routed yet. a's and b's ends of connection 2.
fn crossed(pa: Proven, pb: Proven) -> (Pair, (osis_sync::types::ConnId, osis_sync::types::ConnId)) {
    use osis_sync::types::ConnId;
    let mut p = reader_pair(pa.clone(), pb.clone());
    let (cb2, ca2) = (ConnId(2), ConnId(ConnId::ACCEPTED | 2));
    let (bb, ba) = binds([0x5c; 32], [0x6d; 32], [0x4a; 32]);
    p.b.pipe.binds.insert(cb2, (bb, pa));
    p.a.pipe.binds.insert(ca2, (ba, pb));
    p.a.take(ca2, osis_sync::session::Incoming::Proved);
    p.b.take(cb2, osis_sync::session::Incoming::Proved);
    (p, (ca2, cb2))
}

/// Of the two connections (`crossed`, routed), one closed, the same one at both ends, and S is
/// open on the other at both ends: the other's (a, b) ends.
fn one_closed(p: &Pair, ca2: osis_sync::types::ConnId, cb2: osis_sync::types::ConnId) -> (osis_sync::types::ConnId, osis_sync::types::ConnId) {
    let a_lost: Vec<_> = p.a.pipe.closed.iter().map(|(c, _)| *c).collect();
    let b_lost: Vec<_> = p.b.pipe.closed.iter().map(|(c, _)| *c).collect();
    let pairs = [(p.ca, p.cb), (ca2, cb2)];
    assert_eq!(a_lost.len(), 1, "one closed: {a_lost:?}");
    let (lost, kept) = if a_lost[0] == pairs[0].0 { (pairs[0], pairs[1]) } else { (pairs[1], pairs[0]) };
    assert_eq!(b_lost, [lost.1], "the same connection at both ends");
    assert!(p.a.open(kept.0, &S) && p.b.open(kept.1, &S));
    kept
}

/// The records a side's store holds.
fn records_held(x: &Side) -> Vec<osis_sync::types::RecordId> {
    x.store.with_read(|t| t.records_all()).unwrap().into_iter().map(|r| r.id).collect()
}

// spec/sync-opens.md §1 (one connection per pair), §3 (One record per pair): crossed first dials
// make a record per connection; the closing one's record goes at both ends, so each side keeps
// one record of the other, the kept connection's.
#[test]
fn crossed_first_dials_keep_one_record_spec_sync_opens_3() {
    let (mut p, (ca2, cb2)) = crossed(account(1), account(2));
    route_all(&mut p);
    let kept = one_closed(&p, ca2, cb2);
    for (x, conn) in [(&p.a, kept.0), (&p.b, kept.1)] {
        assert_eq!(records_held(x).into_iter().map(Some).collect::<Vec<_>>(), [x.opens.record(conn)], "one record of the peer, the kept connection's");
    }
}

/// Where a side loses power in the step that settles crossed connections 1 and 2.
#[derive(Clone, Copy, Debug)]
enum PairCrash {
    None,
    /// `a` (true) or `b` before taking the message that settles the pair: as if it never came.
    Before(bool),
    /// `a` or `b` taking it, before the step's end (`crash_taking`): what the step wrote at once
    /// (a new record) stays, its records' writes and what it sent are lost.
    Inside(bool),
}

// spec/sync-opens.md §3 (One record per pair), spec/sync-set.md §3 (To be waited for): crossed
// dials, connection 2 (of worse route rank) running its shared set first, so S is a member of its
// record at both ends; connection 1 then settles the pair and connection 2 closes. A side losing
// power before or inside the step that settles it at its end keeps connection 2's record, and
// one end may hold a record the other dropped; the pair's next connection leaves one record at
// each end. Then b stops reading S: once its Lost closes S, a waits on b for S no more, as with
// one connection all along (a record left holding S would hold that wait until evicted).
#[test]
fn a_crash_settling_crossed_dials_leaves_one_record_spec_sync_opens_3() {
    use osis_sync::types::ConnId;
    for crash in [PairCrash::None, PairCrash::Before(true), PairCrash::Before(false), PairCrash::Inside(true), PairCrash::Inside(false)] {
        let mut p = reader_pair(account(1), account(2));
        let (ca1, cb1) = (p.ca, p.cb);
        let (cb2, ca2) = (ConnId(2), ConnId(ConnId::ACCEPTED | 2));
        let (bb, ba) = binds_at([0x5c; 32], [0x6d; 32], [0x4a; 32], 2);
        p.b.pipe.binds.insert(cb2, (bb, account(1)));
        p.a.pipe.binds.insert(ca2, (ba, account(2)));
        p.a.take(ca2, osis_sync::session::Incoming::Proved);
        p.b.take(cb2, osis_sync::session::Incoming::Proved);
        // connection 2 runs alone (connection 1's Resume held back)
        let held: Vec<(ConnId, Msg)> = p.a.sent().into_iter().filter(|(c, _)| *c == ca1).collect();
        route_all(&mut p);
        assert!(p.a.open(ca2, &S) && p.b.open(cb2, &S), "{crash:?}: S open on connection 2");
        // connection 1's Resume: b settles the pair, answering; then a settles it on the answer
        let settle = |x: &mut Side, conn: ConnId, m: Msg, at: Option<bool>| match at {
            Some(true) => x.restart(),
            Some(false) => x.crash_taking(conn, incoming(m)),
            None => x.take(conn, incoming(m)),
        };
        let at = |side: bool| match crash {
            PairCrash::Before(s) if s == side => Some(true),
            PairCrash::Inside(s) if s == side => Some(false),
            _ => None,
        };
        let crashed = |side: bool| at(side).is_some();
        for (_, m) in held.into_iter().filter(|(_, m)| matches!(m, Msg::Resume { .. })) {
            settle(&mut p.b, cb1, m, at(false));
        }
        if !crashed(false) {
            let answer: Vec<Msg> = p.b.sent().into_iter().filter(|(c, m)| *c == cb1 && matches!(m, Msg::Resumed { .. })).map(|(_, m)| m).collect();
            for m in answer {
                settle(&mut p.a, ca1, m, at(true));
            }
        }
        // every connection ends (a side that lost power has none)
        for (x, ends) in [(&mut p.a, [ca1, ca2]), (&mut p.b, [cb1, cb2])] {
            for c in ends {
                x.closed(c);
            }
            x.sent();
        }
        p.connect(3, account(1), account(2));
        p.run();
        assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "{crash:?}: S open on the next connection");
        for (x, conn) in [(&p.a, p.ca), (&p.b, p.cb)] {
            assert_eq!(records_held(x).into_iter().map(Some).collect::<Vec<_>>(), [x.opens.record(conn)], "{crash:?}: one record of the peer, the connection's");
        }
        p.b.reported(p.cb, S, 5);
        p.b.table.set(S, None);
        p.b.settle();
        p.run();
        assert!(!p.a.open(p.ca, &S), "{crash:?}: b's Lost closed S");
        assert!(!wait_s(&p), "{crash:?}: a waits on b for S no more");
    }
}

/// `a` and `b` share `n` sync IDs, close, both restart (opens started from their stores) and
/// connect again with nothing changed. The bytes of every message the reconnect sent.
pub(crate) fn restart_reconnect_bytes(n: u8) -> usize {
    let st = StepKeys::new(1, 0);
    let mut a = Side::new(1);
    let mut b = Side::new(2);
    for i in 1..=n {
        for x in [&mut a, &mut b] {
            x.table.set(sid(i), Some(reader(&st, &[])));
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
    assert!(p.a.moved.iter().any(|m| matches!(m, Moved::Taken(c, ..) if *c == p.ca)), "the record is taken: each stands where it holds it");
    assert!(!p.a.moved.iter().any(|m| matches!(m, Moved::Joined(..) | Moved::Left(..))), "no member moves: {:?}", p.a.moved);
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
    p.a.settle();
    assert!(p.a.opens.member_at(Source::Record(rid), &S).is_none(), "gone from memory too");
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
    let mut p = reader_pair(account(1), account(2));
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
        p.b.table.set(S, Some(reader(&st, &[])));
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
        adv.offer(&mut k, vec![proof_hit(&adv, &s0)]);
        k.table.set(S, Some(store_with(&s1, &[&s0])));
        k.settle();
        k.reported(adv.peer, S, k.table.until);
        assert!(!k.open(adv.peer, &S));
        assert_eq!(left_how(&k.moved, adv.peer, S), Some(Leaving::Kept));
        if answered {
            let id = adv.id();
            adv.send(&mut k, Msg::Lost { id, items: vec![(S, cursor(5))] });
        }
        k.moved.clear();
        assert_eq!(adv.offer(&mut k, vec![proof_hit(&adv, &s1)])[0].code, Code::OK);
        let want = if answered { Rejoin::From(Some(5u64.to_be_bytes().to_vec())) } else { Rejoin::Held };
        assert!(k.moved.contains(&Moved::Joined(adv.peer, S, want.clone())), "answered {answered}: {want:?} in {:?}", k.moved);
    }
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
    p.a.table.until = 7;
    ends(&mut p);
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
    adv.offer(&mut k, vec![proof_hit(&adv, &s0)]);
    k.table.set(S, Some(store_with(&s1, &[&s0])));
    k.settle();
    k.reported(adv.peer, S, k.table.until);
    assert_eq!(left_how(&k.moved, adv.peer, S), Some(Leaving::Kept));
    k.moved.clear();
    let id = adv.id();
    adv.send(&mut k, Msg::Lost { id, items: vec![(S, None)] });
    assert!(k.moved.contains(&Moved::Forgot(adv.peer, S)), "{:?}", k.moved);
    // and k, leaving S with a stop kept, tells the peer
    let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
    adv.offer(&mut k, vec![proof_hit(&adv, &s0)]);
    k.table.set(S, Some(store_with(&s1, &[&s0])));
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
    let rd = || reader(&st, &[]);
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

/// The classes node `i` gives the sources of S proved by node `j`.
fn classes(w: &mut crate::harness::World, i: usize, j: usize, s: &SyncId) -> Vec<SourceClass> {
    // a source is a node, named by its node thing
    let a = Some(w.engine(j).tid());
    w.status(i).get(s).map(|st| st.sources.values().filter(|x| x.src.node == a).map(|x| x.src.class).collect()).unwrap_or_default()
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
    use crate::harness::history::{Gives, three, value_ak};
    use osis_engine::Mutation;
    use SourceClass::{Reader, Store};
    let (mut w, t, s) = three(Gives::Syncs, 3);
    let all = |w: &mut crate::harness::World| [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)].map(|(i, j)| ((i, j), classes(w, i, j, &s)));
    let want = |two: SourceClass| [((0, 1), vec![Store]), ((0, 2), vec![two]), ((1, 0), vec![Reader]), ((1, 2), vec![two]), ((2, 0), vec![Reader]), ((2, 1), vec![Store])];
    assert_eq!(all(&mut w), want(Store), "both keep S unread");
    let _ = crate::harness::play(&mut w, &[Grant(0, 0, 2, Gives::Writes), Run], String::new());
    assert_eq!(all(&mut w), want(Reader), "node 2 reads S");
    w.cut(1, 2);
    w.run();
    assert_eq!(all(&mut w), want(Reader), "after a reconnect");
    w.power_off(2);
    w.power_on(2);
    w.run();
    assert_eq!(all(&mut w), want(Reader), "after node 2 restarts");
    // node 2's purge of its own write deletes it at node 1, node 0 away
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &osis_base::Value::Str("by 2".into())).unwrap().purge_by(t, &value_ak(), osis_base::PurgeBy::AuthorOrAdmin).unwrap();
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
// declared in that exchange): store K Hits the sync proof Adv shows, declaring it keeps S unread;
// K comes to read S before Adv's valid answer arrives. K opens nothing at the class it declared
// (Adv would class it a store for the member's life): a member there, if any, is at its new class.
#[test]
fn an_answer_after_the_testers_class_moved_opens_nothing_at_the_old_class_spec_sync_opens_4() {
    let s0 = StepKeys::new(1, 0);
    for moved in [false, true] {
        let (mut k, mut adv) = store_dialed_by_adv(&s0, [2; 32]);
        adv.filter(&mut k, &[s0.proof], &S);
        let sent = k.sent();
        let Some(Msg::Offer { id, items }) = of_kind(&sent, 37).pop() else { panic!("K Hits the sync proof Adv shows") };
        assert!(matches!(items[..], [OfferItem::Hit { class: osis_proto::SourceClass::Store, .. }]), "{items:?}");
        if moved {
            k.table.set(S, Some(reader(&s0, &[])));
            k.settle();
            k.sent();
        }
        let tag = adv.tag_on(&s0.proof, &S);
        adv.send(&mut k, Msg::Shared { id, items: vec![osis_proto::SharedItem { code: Code::OK, tag: Some(tag), sig: None, class: osis_proto::SourceClass::Reader }] });
        let own = k.opens.members(adv.peer).get(&S).map(|m| m.own);
        let want = if moved { None } else { Some(SourceClass::Store) };
        assert_eq!(own, want, "moved {moved}");
    }
}

/// The entries of S node `at` holds.
fn held_of(w: &crate::harness::World, at: usize, s: &SyncId) -> std::collections::BTreeSet<osis_base::BlobId> {
    w.store(at).entries(s).unwrap().into_iter().map(|e| e.blob).collect()
}

/// Node 0 writes thing `t` a new value; the entries of S it logged for it.
fn write_value(w: &mut crate::harness::World, t: osis_base::Tid, s: &SyncId, v: i64) -> std::collections::BTreeSet<osis_base::BlobId> {
    let before = held_of(w, 0, s);
    w.write(0, |e| {
        let mut m = osis_engine::Mutation::new();
        m.set(t, &crate::harness::history::value_ak(), &osis_base::Value::Int(v)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.advance(10);
    held_of(w, 0, s).difference(&before).copied().collect()
}

/// Nodes 1 and 2 meet again (node 0 still away from node 2); whether node 2 held any of `blobs`
/// after any delivery until 30 s after they meet (it may drop S's entries later, once it learns
/// it no longer holds S).
fn served_at_reconnect(w: &mut crate::harness::World, s: &SyncId, blobs: &std::collections::BTreeSet<osis_base::BlobId>) -> bool {
    w.rejoin(1, 2);
    let (mut served, mut met) = (false, None);
    let start = w.now().0;
    while met.is_none_or(|t| w.now().0 < t + 30_000) && w.now().0 < start + 3_600_000 && w.step_or_wake() {
        served |= !held_of(w, 2, s).is_disjoint(blobs);
        if met.is_none() && w.links_of(1).iter().any(|(_, j)| *j == 2) {
            met = Some(w.now().0);
        }
    }
    assert!(met.is_some(), "they met again");
    served
}

/// Node 1 holds t (`one`: reads, or keeps it unread), node 2 reads it and node 0 has written it;
/// node 2 has been away from both and back once. Built once per process per `one`
/// (`fixture_with`): the world, t and its sync ID S.
fn away_and_back(one: crate::harness::history::Gives) -> (crate::harness::World, (osis_base::Tid, SyncId)) {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world_of};
    crate::harness::fixture_with(&format!("opens away and back {one:?}"), || {
        let mut w = world_of(0, 3, 3);
        w.cap = crate::harness::WIDE_CAP;
        let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, one), Grant(0, 0, 2, Gives::Reads), Run], String::new());
        let t = w.history.things[0].0;
        let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
        let before = write_value(&mut w, t, &s, 1);
        w.advance(1000);
        assert!(!before.is_empty() && before.is_subset(&held_of(&w, 2, &s)), "node 2 reads t");
        w.partition(0, 2);
        w.partition(1, 2);
        w.advance(1000);
        w.rejoin(0, 2);
        w.rejoin(1, 2);
        w.advance(30_000);
        (w, (t, s))
    })
}

/// Node 1 holds t (`one`: reads, or keeps it unread), node 2 reads it; node 2 goes away from
/// both, `change` ends its right at node 0, node 0 writes t and node 1 takes the write. Whether
/// node 2 is served the write when it meets node 1 again. Node 2 is away and back once first:
/// the first reconnect after first contact names other actors than the record (issues/
/// many-sync-ids-cost.md), and a take naming other actors judges every member. These check the
/// outcome, not which judgement gives it: each change here also moves what node 1 holds of S
/// (the rotation it brings), which judges every record holding S in its step.
fn served_after_a_change_while_away(one: crate::harness::history::Gives, change: impl FnOnce(&mut crate::harness::World, osis_base::Tid)) -> bool {
    let (w, (t, s)) = away_and_back(one);
    served_after_a_change(w, t, s, change)
}

/// `served_after_a_change_while_away` on world `w` where node 2 reads t (its sync ID `s`).
fn served_after_a_change(mut w: crate::harness::World, t: osis_base::Tid, s: SyncId, change: impl FnOnce(&mut crate::harness::World, osis_base::Tid)) -> bool {
    w.partition(0, 2);
    w.partition(1, 2);
    change(&mut w, t);
    let after = write_value(&mut w, t, &s, 2);
    w.run();
    assert!(!after.is_empty() && after.is_subset(&held_of(&w, 1, &s)), "node 1 took the write");
    served_at_reconnect(&mut w, &s, &after)
}

// spec/sync-opens.md §6 (whether or not a connection holds its record): a member is re-judged at
// each change of what this node holds that touches S. In each test below
// node 2's right to t ends while it is away from both other nodes, node 1 hearing of it from node
// 0; meeting node 1 again it is served nothing written after.

/// Node 0 removes node 2's account from t.
fn removed(w: &mut crate::harness::World, _: osis_base::Tid) {
    let _ = crate::harness::play(w, &[crate::harness::Step::Remove(0, 0, 2)], String::new());
    w.run();
}

// Its removal: at a reader by J, at a node keeping S unread by the step registered there.
#[test]
fn a_removal_while_away_serves_nothing_after_it_spec_sync_opens_6() {
    use crate::harness::history::Gives;
    assert!(!served_after_a_change_while_away(Gives::Reads, removed), "at a reader");
    assert!(!served_after_a_change_while_away(Gives::Syncs, removed), "at a node keeping S unread");
}

// Node 1 restarts while node 2 is away and hears of the removal after: the record, read from its
// rows at the take, is judged there.
#[test]
fn a_removal_after_a_restart_serves_nothing_after_it_spec_sync_opens_6() {
    let restarted = |w: &mut crate::harness::World, t: osis_base::Tid| {
        w.power_off(1);
        w.power_on(1);
        w.run();
        removed(w, t);
    };
    assert!(!served_after_a_change_while_away(crate::harness::history::Gives::Reads, restarted));
}

// Its grant's `until` passing (granted while it is away, so it still asks for S), the finalize's
// rotation reaching node 1. Its read secret's sync proof stays of the head until the rotation's
// step (§4 One open rule), so what it is served is what it held the secret for.
#[test]
fn an_until_passing_while_away_serves_nothing_after_it_spec_sync_opens_6() {
    let expire = |w: &mut crate::harness::World, t: osis_base::Tid| {
        let a2 = w.node(2).account.unwrap();
        let until = osis_base::WallMs(w.now().0 + 60_000);
        let edge = osis_schema::core_types::Edge { role: osis_base::Role::Read, until: Some(until), may_grant: false, retain: false, floor: None };
        w.write(0, |e| e.grant(&t, &a2, &edge)).unwrap();
        w.advance(120_000);
        assert!(w.now() >= until);
    };
    assert!(!served_after_a_change_while_away(crate::harness::history::Gives::Reads, expire));
}

// spec/sync-opens.md §3 (a node that stops holding S drops S from every record in the step that
// stops it), §6 Where it stopped, spec/sync-inbox.md §5 (Grant signal: followed while held):
// node 1's grant signal expired, it lets t go (its strong dropped: S shredded there) while node 2,
// which reads S from it, is away; what streams kept of S for node 2's record goes with S's rows
// already gone (`Moved::Gone`), and the two meet again with nothing of S open.
#[test]
fn s_shredded_while_its_reader_is_away_spec_sync_opens_3() {
    use crate::harness::Step::*;
    use crate::harness::history::{Gives, world_of};
    let mut w = world_of(0, 3, 3);
    let _ = crate::harness::play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Reads), Grant(0, 0, 2, Gives::Reads), Run], String::new());
    let t = w.history.things[0].0;
    let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
    let before = write_value(&mut w, t, &s, 1);
    w.advance(1000);
    assert!(!before.is_empty() && before.is_subset(&held_of(&w, 1, &s)) && before.is_subset(&held_of(&w, 2, &s)));
    // the grant signals expire first, while everyone is connected: node 1 then holds t by its
    // strong alone
    w.advance(osis_base::format::INBOX_LIFETIME_MS + 1000);
    w.run();
    w.partition(1, 2);
    let _ = crate::harness::play(&mut w, &[Unstrong(1, None, 0)], String::new());
    w.run();
    assert!(w.store(1).holding(&s).is_none(), "node 1 let S go");
    let _ = served_at_reconnect(&mut w, &s, &Default::default());
    assert!(w.store(1).holding(&s).is_none() && held_of(&w, 1, &s).is_empty());
}

// spec/sync-opens.md §3 (records), notes/sync-opens.md (Durability and eviction): a record no connection holds
// stays in memory only while it has a member: a dialer proving a fresh account each time, with no
// right to S, leaves nothing in memory once gone; a reader of S, its record with its member.
#[test]
fn a_record_with_no_member_leaves_memory_with_its_connection_spec_sync_opens_3() {
    let mut p = readers();
    p.close();
    p.a.settle();
    assert_eq!(p.a.opens.records_in_memory(), 1, "the reader's record, with its member");
    // the dialer holds nothing of S from here
    p.b.table.set(S, None);
    p.b.settle();
    for n in 0..10u8 {
        p.connect(2 + u64::from(n), account(1), account(100 + n));
        p.run();
        assert!(!p.a.open(p.ca, &S), "no right to S");
        p.close();
        p.a.settle();
    }
    assert_eq!(p.a.opens.records_in_memory(), 1, "the strangers' records left memory");
}


/// A store of S at head `head` showing `claims` as its head claims (spec/sync-ids.md §3 Bound).
fn store_claiming(head: &StepKeys, claims: &[[u8; 32]]) -> osis_sync::opens::holds::Creds {
    let mut c = store(head);
    c.shows.extend(claims.iter().map(|k| osis_sync::opens::cred::Shown::Claim(*k)));
    c
}

/// A node holding no secret of S that tests `claim` at the store's head `head` (a grantee).
fn claimant(head: &StepKeys, claim: &osis_crypto::SigningSecret) -> osis_sync::opens::holds::Creds {
    osis_sync::opens::holds::Creds { holding: Some(osis_sync::types::Holding::Read), tests: vec![osis_sync::opens::cred::Tested::Claim { key: claim.clone(), sync: head.pk() }], ..Default::default() }
}

// spec/sync-opens.md §4 (One open rule) and §6 (a claim no longer a head claim): a claim among
// the head claims opens S whole, proven by an open signature by it, its answer by the replier's
// head sync key; one no longer a head claim is ended, served up to its step's end. A grantee holding no secret of S opens a store by its
// claim, whole on both sides; the store's head moves past the claim's epoch and its member is
// ended, not closed at once.
#[test]
fn a_claim_opens_whole_and_ends_at_a_head_move_spec_sync_opens_6() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let claim = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([3; 32]));
    let mut g = Side::new(1);
    let mut k = Side::new(2);
    g.table.set(S, Some(claimant(&s0, &claim)));
    k.table.set(S, Some(store_claiming(&s0, &[claim.verifying_key().to_bytes()])));
    let mut p = Pair::new(g, k, Proven::default(), Proven::default());
    p.run();
    assert!(p.a.open(p.ca, &S) && p.b.open(p.cb, &S), "opened by the claim both ways");
    let at_store = p.b.opens.members(p.cb)[&S].clone();
    assert_eq!((at_store.by, at_store.until), (Credential::Claim(claim.verifying_key().to_bytes()), None), "whole");
    // the head moves: the claim is bound to an older step now
    p.b.table.set(S, Some(store_with(&s1, &[&s0])));
    p.b.settle();
    assert!(p.b.opens.members(p.cb).get(&S).is_some_and(|m| m.until.is_some()), "ended at its step's end");
}

// spec/sync-opens.md §5 (Proof an answer carries: for a claim an open signature by the sync key of
// the replier's head): a claim's Hit answered by a store whose head sync key is not the one the
// claim was computed at opens nothing at the tester.
#[test]
fn a_claims_answer_signed_by_another_head_opens_nothing_spec_sync_opens_5() {
    let (s0, s1) = (StepKeys::new(1, 0), StepKeys::new(1, 1));
    let claim = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([3; 32]));
    let mut g = Side::new(1);
    let mut k = Side::new(2);
    g.table.set(S, Some(claimant(&s0, &claim)));
    k.table.set(S, Some(store_claiming(&s1, &[claim.verifying_key().to_bytes()])));
    let mut p = Pair::new(g, k, Proven::default(), Proven::default());
    p.run();
    assert!(!p.a.open(p.ca, &S), "the tester opens nothing on an answer by another head's key");
}

// spec/sync-ids.md §6 Head: a node following S with no path asks Head; a node holding S answers
// with its path from genesis, whatever the connection proved, and the asker takes the path.
#[test]
fn a_node_with_no_path_asks_head_spec_sync_ids_6() {
    let st = StepKeys::new(1, 0);
    let claim = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([3; 32]));
    let mut g = Side::new(1);
    let k = Side::new(2);
    g.table.set(S, Some(claimant(&st, &claim)));
    let mut p = Pair::new(g, k, Proven::default(), Proven::default());
    p.run();
    let heads = |p: &Pair| p.log.iter().filter(|(by_a, m)| *by_a && matches!(m, Msg::Head { sync_id, after: None, .. } if *sync_id == S)).count();
    assert_eq!(heads(&p), 1, "asked Head once");
    let answered = p.log.iter().any(|(by_a, m)| !*by_a && matches!(m, Msg::Error { code: Code::UNKNOWN_SYNC_ID, .. }));
    assert!(answered, "a node not holding S answers 13");
    p.run();
    assert_eq!(heads(&p), 1, "never again while S stands");
}
