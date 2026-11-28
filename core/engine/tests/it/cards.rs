//! Cards (spec/sync-inbox.md §1 Card, spec/permissions.md §5.2): a card counts only written along
//! a path through its thing; a thing's inbox is its own `keys.0` field, an admin's: a writer
//! cannot move it, an admin's move spreads to every card its thing's nodes may write, a writer's
//! keys refresh keeps it; a party holding nothing of an account but a card of it grants to it and
//! fires at the inbox the account's admins chose.

use crate::common::T0;
use osis_base::{Role, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::flows::cards;
use osis_engine::local_peer::{Account, LocalPeer};
use osis_engine::{Engine, Mutation};
use osis_schema::core_types as ct;
use osis_schema::Codec;

/// A thing minted with admin `admin`, made independent where `independent`, held.
fn thing(lp: &mut LocalPeer, i: usize, admin: Tid, independent: bool) -> Tid {
    let mut m = Mutation::new();
    let t = lp.peers[i].engine.new_thing(&mut m, admin);
    lp.peers[i].commit(m).unwrap();
    if independent {
        lp.peers[i].engine.make_independent(&t).unwrap();
    }
    lp.hold_at(i, t);
    t
}

/// Whether every card of `a` held at `e` carries the current `keys.0` commits of `a` and of its
/// inbox there.
fn cards_current(e: &mut Engine, a: &Tid) -> bool {
    let inbox = e.inbox_of(a).unwrap().unwrap();
    let mut keys = e.current_keys(a).unwrap();
    keys.extend(e.current_keys(&inbox).unwrap());
    let cards = e.cards_of(a).unwrap();
    !cards.is_empty() && cards.iter().all(|(_, card)| keys.is_subset(&carried(card)))
}

/// Write on `accs[0]` for `accs[1]`, `accs[0]` held at node 1.
fn writer(lp: &mut LocalPeer, accs: &[Tid]) {
    lp.peers[0].engine.grant(&accs[0], &accs[1], &ct::Grant { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    lp.sync_all().unwrap();
    lp.hold_at(1, accs[0]);
    lp.sync_all().unwrap();
}

/// One node's account, its card on the profile filled in.
fn one() -> (LocalPeer, Account) {
    let (mut lp, acc) = LocalPeer::one_account(1, 0, T0).unwrap();
    lp.peers[0].engine.refresh_cards().unwrap();
    (lp, acc)
}

// spec/permissions.md §5.2: a card of B written on the profile along a path through A alone (B
// no member of it) is refused by its writer and, written anyway, invalid: it reads nowhere; A's own card there, along a path through A,
// reads and carries A's keys.
#[test]
fn a_card_written_off_its_path_is_invalid_spec_permissions_5_2() {
    let (mut lp, acc) = one();
    let b = thing(&mut lp, 0, acc.thing, true);
    let mut m = Mutation::new();
    m.act_as(acc.thing);
    m.op(acc.profile, &ct::card_ak(&b), PathOp { path: vec![], op: Op::Set(ct::Card::default().to_value()) }).unwrap();
    let node = lp.peers[0].engine.tid();
    assert!(lp.peers[0].commit(m.clone()).is_err(), "refused writer-side");
    lp.peers[0].engine.core.skip_writer_rules = true;
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].engine.core.skip_writer_rules = false;
    let e = &mut lp.peers[0].engine;
    assert!(e.cards_of(&b).unwrap().is_empty(), "off its path: no card of B");
    let a = e.cards_of(&acc.thing).unwrap();
    assert_eq!(a.len(), 1, "A's card on the profile");
    let entry = a[0].1.get(&osis_base::Weak(node)).expect("the node's entry");
    assert!(!entry.keys.is_empty(), "carrying A's keys");
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let values = |l: &[Vec<u8>]| Value::List(l.iter().map(|b| osis_base::decode(b, &limits).unwrap()).collect());
    assert!(osis_blob::Certificates::from_values(&values(&entry.keys), &values(&entry.records), usize::MAX).is_ok(), "in the holder keys form");
    assert_eq!(e.inbox_of(&acc.thing).unwrap(), Some(acc.inbox));
}

// spec/sync-inbox.md §1: an inbox is a thing of its own. A thing naming none has none; naming itself is refused, and a `keys.0` naming it anyway names none.
#[test]
fn an_inbox_is_a_thing_of_its_own_spec_sync_inbox_1() {
    let (mut lp, acc) = one();
    let b = thing(&mut lp, 0, acc.thing, true);
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.inbox_of(&b).unwrap(), None, "naming none: no inbox");
    assert!(matches!(e.set_inbox(b, b), Err(osis_engine::Error::Misuse(_))), "itself refused");
    let mut m = Mutation::new();
    cards::put_inbox(&mut m, b, b).unwrap();
    lp.peers[0].commit(m).unwrap();
    assert_eq!(lp.peers[0].engine.inbox_of(&b).unwrap(), None, "naming itself: no inbox");
}

// spec/sync-inbox.md §1: an admin moves A's inbox; A's cards on the profile and on C are
// rewritten carrying it (A's newest `keys.0` and the new inbox's keys).
#[test]
fn an_inbox_move_spreads_to_every_card_spec_sync_inbox_1() {
    let (mut lp, acc) = one();
    let c = thing(&mut lp, 0, acc.thing, false);
    let i2 = thing(&mut lp, 0, acc.thing, true);
    let e = &mut lp.peers[0].engine;
    assert!(e.write_card(c, acc.thing).unwrap());
    e.set_inbox(acc.thing, i2).unwrap();
    assert_eq!(e.inbox_of(&acc.thing).unwrap(), Some(i2));
    assert_eq!(e.cards_of(&acc.thing).unwrap().len(), 2);
    assert!(cards_current(e, &acc.thing), "every card carries the move");
    assert!(!e.refresh_cards().unwrap(), "nothing left to rewrite");
}

// spec/permissions.md §3 (Who rotates: a `keys.0` delta touching the inbox field needs admin), spec/sync-inbox.md
// §1: node 1, acting for an account holding write on A0, may not move A0's inbox: refused at its
// writer, and a commit writing it anyway (forged) is invalid at both nodes, A0's inbox unmoved.
// Control: node 0, an admin of A0, moves it.
#[test]
fn a_writer_cannot_move_the_inbox_spec_permissions_3() {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    writer(&mut lp, &accs);
    let i2 = thing(&mut lp, 1, accs[1], true);
    let inbox = lp.peers[0].engine.inbox_of(&accs[0]).unwrap().unwrap();
    assert_eq!(lp.peers[1].engine.inbox_of(&accs[0]).unwrap(), Some(inbox));
    assert!(matches!(lp.peers[1].engine.set_inbox(accs[0], i2), Err(osis_engine::Error::Permission { needs: Role::Admin, .. })), "refused writer-side");
    let mut m = Mutation::new();
    cards::put_inbox(&mut m, accs[0], i2).unwrap();
    // the plain write path too: a `keys.0` op outside a writer's keysets needs admin
    assert!(matches!(lp.peers[1].engine.write(m.clone()), Err(osis_engine::Error::Permission { needs: Role::Admin, .. })), "refused writer-side, written plainly");
    lp.peers[1].engine.core.skip_writer_rules = true;
    let forged = lp.peers[1].commit(m).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.part_valid(&forged, 0), Some(false), "node {i}: the forged move is invalid");
        assert_eq!(lp.peers[i].engine.inbox_of(&accs[0]).unwrap(), Some(inbox), "node {i}: the inbox stays");
    }
    let i3 = thing(&mut lp, 0, accs[0], true);
    lp.peers[0].engine.set_inbox(accs[0], i3).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.inbox_of(&accs[0]).unwrap(), Some(i3), "control: an admin's move counts");
}

// spec/sync-inbox.md §1: node 1, a writer of A0 (through its account), refreshes A0's card on C
// after rotating A0, before it sees node 0's move of A0's inbox; once both sync, A0's inbox is the
// moved one everywhere and every card carries A0's newest keys: a writer's refresh carries the admin's inbox, never
// one of its own.
#[test]
fn a_writers_refresh_keeps_the_admins_inbox_spec_sync_inbox_1() {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    let c = thing(&mut lp, 0, accs[0], false);
    lp.peers[0].engine.write_card(c, accs[0]).unwrap();
    writer(&mut lp, &accs);
    lp.hold_at(1, c);
    lp.sync_all().unwrap();
    let i2 = thing(&mut lp, 0, accs[0], true);
    lp.peers[0].engine.set_inbox(accs[0], i2).unwrap();
    lp.advance(1000);
    lp.peers[1].engine.rotate_leaving_out(&accs[0], &[Role::Read], &[]).unwrap();
    lp.peers[1].engine.refresh_cards().unwrap();
    for _ in 0..3 {
        lp.sync_all().unwrap();
        for p in lp.peers.iter_mut() {
            p.engine.refresh_cards().unwrap();
        }
    }
    for i in 0..2 {
        let e = &mut lp.peers[i].engine;
        assert_eq!(e.inbox_of(&accs[0]).unwrap(), Some(i2), "node {i}: the admin's inbox");
        assert!(cards_current(e, &accs[0]), "node {i}: every card carries A0's newest keys and the inbox's");
    }
}

// spec/permissions.md §5.2 (Compaction snapshot; card aspect): node 1, a writer of
// C through its own account alone, holds A0's card on C. Its snapshot of the card aspect carries
// the card off a path through A0: refused writer-side and, written anyway, invalid at node 0.
// Node 0's own snapshot, acting as A0, is valid at node 1; once node 1 removes the card (any
// writer's power), node 1's snapshot of the removed aspect is valid.
#[test]
fn a_card_snapshot_off_its_path_is_invalid_spec_permissions_5_2() {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    let c = thing(&mut lp, 0, accs[0], true);
    let ak = ct::card_ak(&accs[0]);
    lp.peers[0].engine.write_card(c, accs[0]).unwrap();
    lp.peers[0].engine.grant(&c, &accs[1], &ct::Grant { role: Role::Write, until: None, may_grant: false, retain: false, floor: None }).unwrap();
    lp.sync_all().unwrap();
    lp.hold_at(1, c);
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.cards_of(&accs[0]).unwrap().iter().any(|(h, _)| *h == c), "node 1 reads A0's card on C");
    assert!(lp.peers[1].engine.snapshot(&c, &ak).is_err(), "refused writer-side");
    lp.peers[1].engine.core.skip_writer_rules = true;
    let off = lp.peers[1].engine.snapshot(&c, &ak).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    let on = lp.peers[0].engine.snapshot(&c, &ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.part_valid(&off, 0), Some(false), "off its path: invalid");
    assert_eq!(lp.peers[1].engine.part_valid(&on, 0), Some(true), "through A0: valid");
    lp.peers[1].engine.remove_card(c, accs[0]).unwrap();
    let removed = lp.peers[1].engine.snapshot(&c, &ak).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.part_valid(&removed, 0), Some(true), "a removal's snapshot: any writer's");
    assert!(!lp.peers[0].engine.cards_of(&accs[0]).unwrap().iter().any(|(h, _)| *h == c), "the card is gone at node 0");
}

// spec/sync-inbox.md §1 (Card), spec/permissions.md §4 (current `keys.0` commits): a fresh node
// paired into A, A's card on the profile reaching it before the pairing grant (which writes
// nothing in A's `keys.0`), rewrites the card once and settles, not due again each round; the
// grant arriving moves nothing.
#[test]
fn a_card_rewrite_settles_for_a_paired_node_spec_sync_inbox_1() {
    let (mut lp, acc) = LocalPeer::one_account(1, 0, T0).unwrap();
    let mut p = osis_engine::local_peer::Peer::new(7, lp.peers[0].engine.now()).unwrap();
    let (node, keys) = (p.engine.tid(), p.engine.node_keys().unwrap());
    let done = lp.peers[0].engine.pair(&acc.thing, &node, &keys, Role::Admin).unwrap();
    p.engine.take_pairing(&acc.thing).unwrap();
    p.know(&[acc.thing, acc.profile]).unwrap();
    for id in lp.peers[0].engine.commit_ids() {
        if !done.commits.contains(&id) {
            let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
            p.engine.ingest(&pk.bytes, pk.blobs).unwrap();
        }
    }
    p.engine.refresh_cards().unwrap();
    assert!(!p.engine.refresh_cards().unwrap(), "settled: nothing left to rewrite");
    for id in &done.commits {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        p.engine.ingest(&pk.bytes, pk.blobs).unwrap();
    }
    assert!(!p.engine.refresh_cards().unwrap(), "the grant writes no keys.0: nothing to rewrite");
    assert_eq!(p.engine.inbox_of(&acc.thing).unwrap(), Some(acc.inbox));
}

// spec/permissions.md §4 (current `keys.0` commits: every commit with a write live in the
// `keys.0` state), spec/sync-inbox.md §1 (Card), spec/wire.md §9 (Holder keys): every role of
// A0's inbox is rotated after the commit that wrote its sync ID, deposit seed and step. A fresh node
// taking only the inbox's holder keys (what a card of A0 carries of it) rebuilds its `keys.0`
// whole, the step's read key among it, so a read key is in force to seal a fire to. Failed when
// the current commits were the newest rotation commits and the newest `keys.0` commit alone (the
// sync differential's `New(1), Pair(1), Unpair(0, 2), Run, Strong(0, None, 0), Give(3, 0,
// Node(0), Reads)`: a stranger never sealed its grant fire).
#[test]
fn holder_keys_rebuild_the_whole_keys_state_after_a_rotation_spec_permissions_4() {
    let mut lp = LocalPeer::new_apart(1, 0, T0).unwrap();
    let (acc, _) = osis_engine::local_peer::make_account(&mut lp.peers[0].engine).unwrap();
    let e0 = &mut lp.peers[0].engine;
    let made = e0.get_typed(&acc.inbox, &ct::KEYS).unwrap().unwrap();
    e0.rotate_leaving_out(&acc.inbox, &[Role::Sync, Role::Read, Role::Write, Role::Admin], &[]).unwrap().unwrap();
    let want = e0.get_typed(&acc.inbox, &ct::KEYS).unwrap().unwrap();
    assert!(want.read != made.read && want.sync_id.is_some() && want.step.is_some(), "every keyset rotated, the rest kept");
    let keys = e0.holder_keys(&acc.inbox).unwrap();
    let mut q = osis_engine::local_peer::Peer::new(8, T0).unwrap();
    q.engine.take_holder_keys(&acc.inbox, &keys, None).unwrap();
    assert_eq!(q.engine.get_typed(&acc.inbox, &ct::KEYS).unwrap(), Some(want), "the inbox's keys.0 rebuilt whole from its holder keys");
}

/// A card entry carrying `certs` (spec/wire.md §9 Holder keys), as `card_keys` writes one.
fn card_of(certs: &[osis_blob::Certificates]) -> ct::CardEntry {
    let mut card = ct::CardEntry::default();
    let mut recs = std::collections::BTreeMap::new();
    for c in certs {
        card.keys.extend(c.commits.iter().map(osis_base::encode));
        recs.extend(c.records.iter().map(|r| (r.tid(), osis_base::encode(&r.to_value()))));
    }
    card.records = recs.into_values().collect();
    card
}

/// What a party holding only the entry `card` takes as `a`'s holder keys.
fn certs_of(card: &ct::CardEntry) -> osis_blob::Certificates {
    cards::holder_keys_of(&ct::Card::from([(osis_base::Weak(Tid::from_bytes([0; 15])), card.clone())]))
}

/// The commit ID of each commit a card carries, in any entry.
fn carried(card: &ct::Card) -> std::collections::BTreeSet<osis_base::CommitId> {
    card.values().flat_map(|e| &e.keys).filter_map(|b| osis_commit::CommitBlob::decode(b).ok()).map(|b| b.id()).collect()
}

/// Node 1 writes `card` as its entry in `a`'s card on `c` (a writer of `a`: along a path through it).
fn put_card(lp: &mut LocalPeer, c: Tid, a: Tid, card: &ct::CardEntry) -> osis_base::CommitId {
    let node = lp.peers[1].engine.tid();
    lp.peers[1].commit(cards::put_entry(c, a, node, card).unwrap()).unwrap().unwrap()
}

/// Syncs and refreshes every node's cards until quiet (a few rounds).
fn settle(lp: &mut LocalPeer) {
    for _ in 0..3 {
        lp.sync_all().unwrap();
        for p in lp.peers.iter_mut() {
            p.engine.refresh_cards().unwrap();
        }
    }
}

/// Accounts A0 (node 0, its admin) and A1 (node 1, a writer of A0); A0's card on C, held at
/// both; A0's inbox moved by node 0 (to `i2`) and A0 rotated after it. Returns C, A0's first
/// inbox, `i2` and the move's commit.
fn moved_then_rotated() -> (LocalPeer, Vec<Tid>, Tid, Tid, Tid, osis_base::CommitId) {
    let (mut lp, accs) = LocalPeer::accounts(2, 0, T0).unwrap();
    let c = thing(&mut lp, 0, accs[0], false);
    lp.peers[0].engine.write_card(c, accs[0]).unwrap();
    writer(&mut lp, &accs);
    lp.hold_at(1, c);
    lp.sync_all().unwrap();
    let i1 = lp.peers[0].engine.inbox_of(&accs[0]).unwrap().unwrap();
    let i2 = thing(&mut lp, 0, accs[0], true);
    let before = lp.peers[0].engine.current_keys(&accs[0]).unwrap();
    lp.peers[0].engine.set_inbox(accs[0], i2).unwrap();
    let after = lp.peers[0].engine.current_keys(&accs[0]).unwrap();
    let mv: Vec<_> = after.difference(&before).copied().collect();
    assert_eq!(mv.len(), 1, "the move is one commit");
    lp.advance(1000);
    lp.peers[0].engine.rotate_leaving_out(&accs[0], &[Role::Read], &[]).unwrap().unwrap();
    settle(&mut lp);
    (lp, accs, c, i1, i2, mv[0])
}

// spec/sync-inbox.md §1 (Card: an entry per node, its commits read together): node 1, a writer
// of A0, writes its entry in A0's card on C carrying A0's current `keys.0` commits but node 0's
// move of A0's inbox (so the commit naming the first inbox and the newer rotation), with both
// inboxes' keys: a stranger taking that entry alone fires at the first inbox. Node 0's entry
// carries the move, and a stranger taking the card fires at the moved inbox. Failed when one card
// was judged stale per thing by the newest commit carried (the rotation is newer than the move:
// the writer's card was left as written).
#[test]
fn a_writers_card_points_no_stranger_at_an_earlier_inbox_spec_sync_inbox_1() {
    let (mut lp, accs, c, i1, i2, mv) = moved_then_rotated();
    let e1 = &mut lp.peers[1].engine;
    let mut keys = e1.holder_keys(&accs[0]).unwrap();
    keys.commits.retain(|v| osis_commit::CommitBlob::decode(&osis_base::encode(v)).unwrap().id() != mv);
    let old = card_of(&[keys, e1.holder_keys(&i1).unwrap(), e1.holder_keys(&i2).unwrap()]);
    let mut q = osis_engine::local_peer::Peer::new(8, lp.peers[0].engine.now()).unwrap();
    q.engine.take_holder_keys(&accs[0], &certs_of(&old), None).unwrap();
    assert_eq!(q.engine.inbox_of(&accs[0]).unwrap(), Some(i1), "premise: a stranger taking the writer's card fires at the first inbox");
    put_card(&mut lp, c, accs[0], &old);
    settle(&mut lp);
    for i in 0..2 {
        let card = lp.peers[i].engine.cards_of(&accs[0]).unwrap().into_iter().find(|(h, _)| *h == c).unwrap().1;
        assert!(carried(&card).contains(&mv), "node {i}: A0's card on C carries the inbox move");
    }
    let card = lp.peers[0].engine.cards_of(&accs[0]).unwrap().into_iter().find(|(h, _)| *h == c).unwrap().1;
    let mut q = osis_engine::local_peer::Peer::new(9, lp.peers[0].engine.now()).unwrap();
    q.engine.take_holder_keys(&accs[0], &cards::holder_keys_of(&card), None).unwrap();
    assert_eq!(q.engine.inbox_of(&accs[0]).unwrap(), Some(i2), "a stranger taking the card fires at the moved inbox");
}

// spec/sync-inbox.md §1 (Card: an entry is its node's): node 1, a writer of A0, writes its entry
// in A0's card on C carrying A0's current `keys.0` commits and a copy of one of them stamped far
// ahead, its signature no longer its commit's. Node 0 rotates A0 after: the card carries the
// rotation at both nodes. Failed when one card's newest `ts` held back a rewrite (the copy's
// counted: the card newer than anything a rewrite carries, for good).
#[test]
fn an_unverified_card_commit_counts_for_nothing_spec_sync_inbox_1() {
    let (mut lp, accs, c, _, _, _) = moved_then_rotated();
    let e1 = &mut lp.peers[1].engine;
    let mut keys = e1.holder_keys(&accs[0]).unwrap();
    let i2 = e1.inbox_of(&accs[0]).unwrap().unwrap();
    let inbox = e1.holder_keys(&i2).unwrap();
    let on_keys = |b: &osis_commit::CommitBlob| b.header.aspect_index(&accs[0], "keys.0").is_some();
    let mut forged = keys.commits.iter().map(|v| osis_commit::CommitBlob::decode(&osis_base::encode(v)).unwrap()).find(on_keys).unwrap();
    forged.header.ts = osis_base::Ts::from_u64(forged.header.ts.to_u64() + (1 << 50)).unwrap();
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    keys.commits.push(osis_base::decode(&forged.encode(), &limits).unwrap());
    put_card(&mut lp, c, accs[0], &card_of(&[keys, inbox]));
    settle(&mut lp);
    lp.advance(1000);
    let r = lp.peers[0].engine.rotate_leaving_out(&accs[0], &[Role::Read], &[]).unwrap().unwrap();
    settle(&mut lp);
    for i in 0..2 {
        let card = lp.peers[i].engine.cards_of(&accs[0]).unwrap().into_iter().find(|(h, _)| *h == c).unwrap().1;
        assert!(carried(&card).contains(&r), "node {i}: A0's card on C carries the rotation after the forged copy");
    }
}

// spec/sync-inbox.md §1 (Card: an entry is its node's), spec/permissions.md §3 (Who rotates: the
// inbox field needs admin): node 1, a writer of A0, writes its entry in A0's card on C carrying
// A0's current `keys.0` commits and a move of A0's inbox it signs itself, stamped far ahead: a
// stranger taking it fires at the admin's inbox. Node 0, A0's admin, then rotates A0's admin
// keyset: the card at both nodes carries that rotation. Failed when a commit of one card not held
// valid counted for every field whoever signed it (the card newer than any honest commit, for
// good).
#[test]
fn a_writers_own_card_commit_stamped_ahead_holds_back_no_admin_field_spec_sync_inbox_1() {
    let (mut lp, accs, c, i1, i2, _) = moved_then_rotated();
    let mut ahead = lp.peers[1].copy().unwrap();
    ahead.clock.advance(1 << 40);
    let mut m = Mutation::new();
    cards::put_inbox(&mut m, accs[0], i1).unwrap();
    ahead.engine.core.skip_writer_rules = true;
    let f = ahead.commit(m).unwrap().unwrap();
    let pk = ahead.engine.package(&f).unwrap().unwrap();
    let forged = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    assert_eq!(forged.header.signer, lp.peers[1].engine.tid(), "premise: signed by node 1 itself");
    let e1 = &mut lp.peers[1].engine;
    let mut keys = e1.holder_keys(&accs[0]).unwrap();
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    keys.commits.push(osis_base::decode(&forged.encode(), &limits).unwrap());
    let inbox = e1.holder_keys(&i2).unwrap();
    let card = card_of(&[keys, inbox]);
    let mut q = osis_engine::local_peer::Peer::new(8, lp.peers[0].engine.now()).unwrap();
    q.engine.take_holder_keys(&accs[0], &certs_of(&card), None).unwrap();
    assert_eq!(q.engine.inbox_of(&accs[0]).unwrap(), Some(i2), "a stranger taking the card fires at the admin's inbox");
    put_card(&mut lp, c, accs[0], &card);
    settle(&mut lp);
    lp.advance(1000);
    let r = lp.peers[0].engine.rotate_leaving_out(&accs[0], &[Role::Admin], &[]).unwrap().unwrap();
    settle(&mut lp);
    for i in 0..2 {
        let card = lp.peers[i].engine.cards_of(&accs[0]).unwrap().into_iter().find(|(h, _)| *h == c).unwrap().1;
        assert!(carried(&card).contains(&r), "node {i}: A0's card on C carries the admin's rotation after the writer's own far-ahead commit");
    }
}

// spec/sync-inbox.md §1 (Card: Keeping an entry), spec/commits.md §5 (Covered): A rotated, its
// `keys.0` compacted and the covered parts dropped, the rotation still current by its write the
// snapshot holds. A refresh carries the snapshot and settles: the rotation, whose part no card can
// carry, moves no entry again. Failed when every current commit had to be carried itself
// (`refresh_cards` passed its loop bound).
#[test]
fn a_card_settles_once_its_things_keys_are_compacted_spec_sync_inbox_1() {
    let (mut lp, acc) = one();
    let keys = osis_base::Ak::new("keys.0").unwrap();
    let e = &mut lp.peers[0].engine;
    let r = e.rotate_leaving_out(&acc.thing, &[Role::Read], &[]).unwrap().unwrap();
    lp.advance(1000);
    let e = &mut lp.peers[0].engine;
    let s = e.snapshot(&acc.thing, &keys).unwrap().unwrap();
    lp.advance(osis_base::format::ROLE_KEEP_MS + 1);
    let e = &mut lp.peers[0].engine;
    e.drop_body(&r, &acc.thing, &keys).unwrap();
    assert!(!e.body_not_dropped(&r, &acc.thing, &keys) && e.current_keys(&acc.thing).unwrap().contains(&r), "the rotation current, its part dropped");
    e.refresh_cards().unwrap();
    assert!(!e.refresh_cards().unwrap(), "settled: nothing left to rewrite");
    let cards = e.cards_of(&acc.thing).unwrap();
    assert!(cards.iter().all(|(_, card)| carried(card).contains(&s)), "the card carries the snapshot");
}

/// Commit IDs peer `i` holds.
fn ids(lp: &LocalPeer, i: usize) -> std::collections::BTreeSet<osis_base::CommitId> {
    lp.peers[i].engine.commit_ids().into_iter().collect()
}

/// The commits peer `i` made running `f`.
fn made(lp: &mut LocalPeer, i: usize, f: impl FnOnce(&mut LocalPeer)) -> Vec<osis_base::CommitId> {
    let before = ids(lp, i);
    f(lp);
    ids(lp, i).into_iter().filter(|c| !before.contains(c)).collect()
}

/// Syncs and refreshes every node's cards for `n` rounds: whether any node made or took a commit
/// in the last.
fn rounds(lp: &mut LocalPeer, n: usize) -> bool {
    let mut moved = false;
    for _ in 0..n {
        let before: Vec<usize> = (0..lp.peers.len()).map(|i| ids(lp, i).len()).collect();
        lp.sync_all().unwrap();
        for p in lp.peers.iter_mut() {
            p.engine.refresh_cards().unwrap();
        }
        moved = (0..lp.peers.len()).any(|i| ids(lp, i).len() != before[i]);
    }
    moved
}

// spec/sync-inbox.md §1 (Card: each node keeps its own entry), spec/permissions.md §5.1 (Trust set:
// each node keeps the side it took): admins a (peer 0) and b (peer 1) of T remove each
// other; peers 2 (T's mint admin) and 3 (a writer) take a's side, peer 4 (a writer) b's. Each
// side then writes T's `keys.0` alone: a rotates T, then a writer b grants on its side alone
// (peer 5) rotates T's write keyset, stamped after. Peers 2, 3 and 4 may write C (T's child)
// along a path through T on both sides, so each side reads the other's card writes. Once synced,
// a round of sync makes no commit, and each side's stranger taking the card at a node of that
// side reads that side's current keys. Failed when one card held one side's commits and each
// side judged the other's by the roles it applied (the sides rewrote each other's card every
// round).
#[test]
fn a_fork_settles_with_each_sides_card_spec_sync_inbox_1() {
    let (mut lp, ps) = crate::flows::people(6);
    let (a, b, c) = (ps[0], ps[1], ps[2]);
    let mut m = Mutation::new();
    let t = lp.peers[2].engine.new_thing(&mut m, c);
    lp.peers[2].commit(m).unwrap();
    lp.peers[2].engine.make_independent(&t).unwrap();
    lp.hold(t);
    let grant = crate::flows::grant_of;
    for (p, r) in [(a, Role::Admin), (b, Role::Admin), (ps[3], Role::Write), (ps[4], Role::Write)] {
        lp.peers[2].engine.grant(&t, &p, &grant(r)).unwrap();
    }
    let mut m = Mutation::new();
    let child = lp.peers[2].engine.new_thing(&mut m, t);
    lp.peers[2].commit(m).unwrap();
    lp.hold(child);
    lp.peers[2].engine.write_card(child, t).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1000);
    // b's clock runs ahead; a has not seen b's removal when it writes its own
    lp.peers[1].clock.advance(5000);
    let w = made(&mut lp, 1, |lp| drop(lp.peers[1].engine.demote(&t, &osis_engine::flows::Demotion { holder: a, new: None, retain: None }).unwrap()));
    let r = made(&mut lp, 0, |lp| drop(lp.peers[0].engine.demote(&t, &osis_engine::flows::Demotion { holder: b, new: None, retain: None }).unwrap()));
    // each node's side: the removal it received first
    for (to, first, then) in [(2, (0, &r), (1, &w)), (3, (0, &r), (1, &w)), (4, (1, &w), (0, &r)), (5, (1, &w), (0, &r))] {
        crate::flows::send_carried(&mut lp, first.0, to, first.1);
        crate::flows::send_carried(&mut lp, then.0, to, then.1);
    }
    crate::flows::send_carried(&mut lp, 0, 1, &r);
    crate::flows::send_carried(&mut lp, 1, 0, &w);
    lp.sync_all().unwrap();
    let side_a = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&t).contains_key(&a);
    for (i, on_a) in [(0, true), (1, false), (2, true), (3, true), (4, false), (5, false)] {
        assert_eq!(side_a(&lp, i), on_a, "premise: peer {i}'s side");
    }
    // a's side rotates T after both removals; on b's, b grants peer 5 write, which rotates T's
    // write keyset after that
    lp.advance(10_000);
    lp.peers[0].engine.rotate_leaving_out(&t, &[Role::Read], &[]).unwrap().unwrap();
    lp.peers[1].engine.grant(&t, &ps[5], &grant(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.advance(1000);
    lp.peers[5].engine.rotate_leaving_out(&t, &[Role::Write], &[]).unwrap().unwrap();
    rounds(&mut lp, 4);
    assert!(!rounds(&mut lp, 1), "settled: no commit moves");
    assert!(!rounds(&mut lp, 1), "settled: no commit moves, a round on");
    for i in [2, 3, 4] {
        let e = &mut lp.peers[i].engine;
        let want = e.current_keys(&t).unwrap();
        let card = e.cards_of(&t).unwrap().into_iter().find(|(h, _)| *h == child).expect("T's card on its child").1;
        assert!(want.is_subset(&carried(&card)), "peer {i}: the card carries its side's current keys of T");
    }
}

// spec/sync-inbox.md §1 (Card: an entry per node, read together), spec/permissions.md §5.1
// (Frontier): D (peer 1), an admin of T demoted to writer, writes its entry in T's card on C
// carrying T's keys as it held them as admin, the grant that made it admin and a move of T's
// inbox to a thing of its own, signed against those keys and stamped after its demotion: a
// stranger taking that entry alone fires at D's inbox. A stranger taking the card as honest nodes
// hold it fires at T's own inbox: T's admin's entry carries the demotion. Failed when one card
// held whatever its last writer put and honest nodes left it, D having once held admin.
#[test]
fn a_demoted_admins_card_points_no_stranger_at_its_inbox_spec_sync_inbox_1() {
    let (mut lp, ps) = crate::flows::people(2);
    let (c, d) = (ps[0], ps[1]);
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, c);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.make_independent(&t).unwrap();
    lp.hold(t);
    let i1 = thing(&mut lp, 0, c, true);
    lp.peers[0].engine.set_inbox(t, i1).unwrap();
    let g = made(&mut lp, 0, |lp| drop(lp.peers[0].engine.grant(&t, &d, &crate::flows::grant_of(Role::Admin)).unwrap()));
    let mut m = Mutation::new();
    let host = lp.peers[0].engine.new_thing(&mut m, t);
    lp.peers[0].commit(m).unwrap();
    lp.hold(host);
    lp.peers[0].engine.write_card(host, t).unwrap();
    let i2 = thing(&mut lp, 1, d, true);
    settle(&mut lp);
    // what D holds of T's keys as admin, and D's node as it stood then
    let mut keys = lp.peers[1].engine.holder_keys(&t).unwrap();
    let mut was = lp.peers[1].copy().unwrap();
    lp.advance(1000);
    let dm = made(&mut lp, 0, |lp| drop(lp.peers[0].engine.demote(&t, &osis_engine::flows::Demotion { holder: d, new: Some(crate::flows::grant_of(Role::Write)), retain: None }).unwrap()));
    settle(&mut lp);
    assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Write), "premise: D demoted");
    // D's own move of the inbox, signed against the keys it held as admin, stamped after its
    // demotion
    was.clock.advance(10_000);
    let mut m = Mutation::new();
    cards::put_inbox(&mut m, t, i2).unwrap();
    let f = was.commit(m).unwrap().unwrap();
    assert!(dm.iter().all(|x| was.engine.header(&f).unwrap().ts > lp.peers[0].engine.header(x).unwrap().ts), "premise: stamped after the demotion");
    let pk = was.engine.package(&f).unwrap().unwrap();
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let moved = osis_base::decode(&pk.bytes, &limits).unwrap();
    keys.commits.push(moved);
    // the grant that made D admin, and D's record
    for id in &g {
        let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
        keys.commits.push(osis_base::decode(&pk.bytes, &limits).unwrap());
    }
    keys.records.push(lp.peers[1].engine.core.created(&d).unwrap().clone());
    // T's own inbox's keys too, as an honest card carries them: the card looks current
    let own = lp.peers[0].engine.holder_keys(&i1).unwrap();
    let card = card_of(&[keys, own, lp.peers[1].engine.holder_keys(&i2).unwrap()]);
    let mut q = osis_engine::local_peer::Peer::new(8, lp.peers[0].engine.now()).unwrap();
    q.engine.take_holder_keys(&t, &certs_of(&card), None).unwrap();
    assert_eq!(q.engine.inbox_of(&t).unwrap(), Some(i2), "premise: D's card alone points a stranger at D's inbox");
    // D's entry reaches T's admin, D's node keeping it as written
    let w = put_card(&mut lp, host, t, &card);
    crate::flows::send_carried(&mut lp, 1, 0, &[w]);
    lp.peers[0].engine.refresh_cards().unwrap();
    assert!(lp.peers[0].engine.cards_of(&t).unwrap().iter().any(|(h, c)| *h == host && c.contains_key(&osis_base::Weak(d))), "premise: D's entry held at T's admin");
    let held = lp.peers[0].engine.cards_of(&t).unwrap().into_iter().find(|(h, _)| *h == host).unwrap().1;
    let mut q = osis_engine::local_peer::Peer::new(9, lp.peers[0].engine.now()).unwrap();
    q.engine.take_holder_keys(&t, &cards::holder_keys_of(&held), None).unwrap();
    assert_eq!(q.engine.inbox_of(&t).unwrap(), Some(i1), "a stranger taking the card fires at T's own inbox");
}

// spec/permissions.md §5.2 (card aspect: each entry a delta writes into keyed by its signer):
// node 1, a writer of A0, writes into node 0's entry in A0's card on C, and in another commit
// replaces the whole card with one holding an entry keyed by node 0: both invalid at both nodes,
// node 0's entry as it wrote it. Control: node 1's own entry counts.
#[test]
fn a_card_entry_counts_only_written_by_its_node_spec_permissions_5_2() {
    let (mut lp, accs, c, _, _, _) = moved_then_rotated();
    let n0 = osis_base::Weak(lp.peers[0].engine.tid());
    let card = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.cards_of(&accs[0]).unwrap().into_iter().find(|(h, _)| *h == c).unwrap().1;
    let before = card(&mut lp, 0).get(&n0).cloned().expect("node 0's entry");
    let junk = ct::CardEntry::default();
    let mut whole = Mutation::new();
    whole.act_as(accs[0]);
    whole.op(c, &ct::card_ak(&accs[0]), PathOp { path: vec![], op: Op::Replace(ct::Card::from([(n0, junk.clone())]).to_value()) }).unwrap();
    lp.peers[1].engine.core.skip_writer_rules = true;
    let into = lp.peers[1].commit(cards::put_entry(c, accs[0], n0.0, &junk).unwrap()).unwrap().unwrap();
    let replaced = lp.peers[1].commit(whole).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    let own = put_card(&mut lp, c, accs[0], &junk);
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.part_valid(&into, 0), Some(false), "node {i}: a write into another's entry is invalid");
        assert_eq!(lp.peers[i].engine.part_valid(&replaced, 0), Some(false), "node {i}: a whole card holding another's entry is invalid");
        assert_eq!(lp.peers[i].engine.part_valid(&own, 0), Some(true), "node {i}: control: its own entry counts");
        assert_eq!(card(&mut lp, i).get(&n0), Some(&before), "node {i}: node 0's entry as it wrote it");
    }
}
