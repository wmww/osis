//! The public as a holder (spec/permissions.md §1, §2; spec/crypto.md §4 Boxes): open boxes at
//! each epoch of the roles it holds, its removal a departure like any, the writer's check on its
//! grant.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, granted, put_on, reads_key};
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// The epochs (role, epoch) of `g` peer `i` holds an open box to the public at, by `g`'s state;
/// every box to the public is open and every open box is the public's, none recorded in
/// `keys.0`.
fn open_boxes(lp: &mut LocalPeer, i: usize, g: Tid) -> BTreeSet<(Role, osis_crypto::Epoch)> {
    let s = lp.peers[i].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
    for (k, b) in &s.boxes {
        assert_eq!(k.holder.0.is_public(), matches!(b, ct::SecretBox::Open(_)), "the open form is the public's alone");
    }
    let k = lp.peers[i].engine.get_typed(&g, &ct::KEYS).unwrap().unwrap();
    assert!(k.sealed.keys().all(|x| !x.holder.0.is_public()), "the public is no holder actor: no box record");
    s.boxes.keys().filter(|k| k.holder.0.is_public()).map(|k| (k.role, osis_keys::aspects::from_schema(&k.epoch).unwrap())).collect()
}

/// The current epochs of `g`'s read and sync roles at peer `i`.
fn current_read_sync(lp: &LocalPeer, i: usize, g: Tid) -> BTreeSet<(Role, osis_crypto::Epoch)> {
    let e = lp.peers[i].engine.epochs(&g).unwrap();
    [Role::Sync, Role::Read].into_iter().flat_map(|r| e.role(r).current().into_iter().map(move |x| (r, x))).collect()
}

/// What a party holding nothing opens of `g`'s `secrets.0` as peer 0 holds it: the open boxes
/// (and what their secrets' history boxes carry), each checked against peer 0's secret.
fn opened_by_anyone(lp: &mut LocalPeer, g: Tid) -> BTreeSet<(Role, osis_crypto::Epoch)> {
    let s = lp.peers[0].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
    let none = osis_keys::ActorEpochs::default();
    let (opened, failed) = osis_keys::open_boxes(&g, &s, &osis_keys::Opener { holder: Tid::PUBLIC, epochs: &none });
    assert!(failed.is_empty(), "{failed:?}");
    let held = lp.peers[0].engine.epochs(&g).unwrap();
    for o in &opened {
        assert_eq!(held.role(o.role).secret(&o.epoch).map(|s| s.secret()), Some(&o.secret));
    }
    opened.into_iter().map(|o| (o.role, o.epoch)).collect()
}

// Peer 0 grants the public read on g: boxed open at g's current read and sync epochs (nothing
// above), which anyone opens holding nothing; each later rotation (a reader leaving) boxes the
// public open at the new epochs.
#[test]
fn a_public_grant_boxes_open_at_each_rotation() {
    let (mut lp, g, tids) = granted(2, &[(1, Role::Read)]);
    lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Read)).unwrap();
    let first = current_read_sync(&lp, 0, g);
    assert_eq!(open_boxes(&mut lp, 0, g), first, "open at each current read and sync epoch, nothing above");
    assert_eq!(opened_by_anyone(&mut lp, g), first);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    let after = current_read_sync(&lp, 0, g);
    assert!(after.iter().any(|x| x.0 == Role::Read && !first.contains(x)), "the reader's departure rotates read");
    assert_eq!(open_boxes(&mut lp, 0, g), after, "the rotation boxes the public open at the new epochs");
    assert_eq!(opened_by_anyone(&mut lp, g), after);
}

// Removing the public is a departure as any: g's read rotates without it, boxing it nothing at
// the new epochs, and the remaining reader reads on (spec/permissions.md §1: its departures and
// the rotations they force are ordinary).
#[test]
fn removing_the_public_rotates_it_out() {
    let (mut lp, g, _) = granted(2, &[(1, Role::Read)]);
    lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Read)).unwrap();
    let before = current_read_sync(&lp, 0, g);
    lp.peers[0].engine.demote(&g, &Demotion { holder: Tid::PUBLIC, new: None, retain: None }).unwrap();
    let after = current_read_sync(&lp, 0, g);
    assert!(after.iter().any(|x| x.0 == Role::Read && !before.contains(x)), "the public's departure rotates read");
    assert!(opened_by_anyone(&mut lp, g).is_disjoint(&after), "nothing boxed open at the new epochs");
    put_on(&mut lp, 0, g, "private", 2);
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 1, g, "private"), "the remaining reader reads on");
}

// The writer's check (spec/permissions.md §2): the public is granted at most read, never
// may-grant; a grant at sync stands (its sync secret boxed open, nothing to read).
#[test]
fn the_public_is_granted_at_most_read_without_may_grant() {
    let (mut lp, g, _) = granted(2, &[]);
    for e in [edge(Role::Write), edge(Role::Admin), ct::Grant { may_grant: true, ..edge(Role::Read) }] {
        assert!(lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &e).is_err(), "{e:?} refused");
    }
    assert!(open_boxes(&mut lp, 0, g).is_empty());
    lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Sync)).unwrap();
    let sync: BTreeSet<_> = current_read_sync(&lp, 0, g).into_iter().filter(|x| x.0 == Role::Sync).collect();
    assert_eq!(open_boxes(&mut lp, 0, g), sync, "a sync grant boxes the sync secret alone");
}

// A box to the public of another form than open, or an open box whose secret does not name its
// key's epoch, is ignored (spec/crypto.md §4 Boxes), so it is no box to the re-seal trigger
// (spec/permissions.md §3 Re-seal): a writer's junk at the public's keys is re-sealed over and
// anyone opens g's current read and sync epochs again.
#[test]
fn an_ignored_box_to_the_public_is_resealed_over() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::Codec;
    let (mut lp, g, _) = granted(2, &[(1, Role::Write)]);
    lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let current = current_read_sync(&lp, 0, g);
    let mut m = crate::Mutation::new();
    for (r, e) in &current {
        let junk = match r {
            Role::Read => ct::SecretBox::Sealed(ct::SealedBox { keyset: None, suite: 1, sealed: ct::Sealed::X25519MlKem768(vec![0x66; 64]) }),
            _ => ct::SecretBox::Open(vec![0x66; 40]),
        };
        let key = osis_keys::aspects::box_key(Tid::PUBLIC, *r, e);
        m.op(g, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(key.to_value())], op: Op::Set(junk.to_value()) }).unwrap();
    }
    m.unchecked();
    lp.peers[1].engine.core.skip_writer_rules = true;
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    let s = lp.peers[0].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
    assert!(current.iter().all(|(r, e)| !osis_keys::has_box(&g, &s, &osis_keys::aspects::box_key(Tid::PUBLIC, *r, e))), "the junk applied, ignored");
    assert!(!lp.peers[0].engine.reseal_after_pass(&g).unwrap().commits.is_empty(), "the trigger re-seals the public");
    assert_eq!(current_read_sync(&lp, 0, g), current, "a re-seal, no rotation");
    assert_eq!(opened_by_anyone(&mut lp, g), current);
}

// An open box to the public replayed from an earlier epoch: well formed and opening, but its
// secret names the earlier epoch, not its key's (spec/crypto.md §4 Boxes), so the trigger reads it
// as none and re-seals over it once; the re-seal's own box is one, so the trigger then settles
// (no re-seal at every pass end).
#[test]
fn a_replayed_open_box_is_resealed_over_once() {
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::Codec;
    let (mut lp, g, tids) = granted(3, &[(1, Role::Write), (2, Role::Read)]);
    lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let old = current_read_sync(&lp, 0, g);
    let s = lp.peers[0].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
    let (_, eo) = *old.iter().find(|x| x.0 == Role::Read).unwrap();
    let replay = s.boxes[&osis_keys::aspects::box_key(Tid::PUBLIC, Role::Read, &eo)].clone();
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    let current = current_read_sync(&lp, 0, g);
    let (_, en) = *current.iter().find(|x| x.0 == Role::Read && !old.contains(x)).unwrap();
    let key = osis_keys::aspects::box_key(Tid::PUBLIC, Role::Read, &en);
    let mut m = crate::Mutation::new();
    m.op(g, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(key.to_value())], op: Op::Set(replay.to_value()) }).unwrap();
    m.unchecked();
    lp.peers[1].engine.core.skip_writer_rules = true;
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    let s = lp.peers[0].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
    assert_eq!(s.boxes.get(&key), Some(&replay), "the replay applied");
    assert!(!osis_keys::has_box(&g, &s, &key), "a replayed box is ignored");
    assert!(!lp.peers[0].engine.reseal_after_pass(&g).unwrap().commits.is_empty(), "the trigger re-seals the public");
    lp.sync_all().unwrap();
    assert_eq!(opened_by_anyone(&mut lp, g), current, "anyone opens the current epochs again");
    for i in [0, 1] {
        assert!(lp.peers[i].engine.reseal_after_pass(&g).unwrap().commits.is_empty(), "peer {i}: the trigger settles");
    }
}

// spec/permissions.md §2 (May-grant grant; Granting to the public; Finalize): the public is a
// holder as any there. Writer W (1), holding the may-grant flag, makes g public (at most read,
// never the flag: refused above), and stranger S (2), granted nothing, redeems a locator and
// reads g. Holders by may-grant remove no other edge: W cannot take the public's grant away; past
// its `until` a writer finalizes it, and the admin (0) removes W's grant made again.
#[test]
fn a_may_grant_holder_makes_a_thing_public_spec_permissions_2() {
    let (mut lp, g, tids) = granted(3, &[]);
    lp.peers[0].engine.grant(&g, &tids[1], &ct::Grant { may_grant: true, ..edge(Role::Write) }).unwrap();
    put_on(&mut lp, 0, g, "open", 1);
    lp.sync_all().unwrap();
    for e in [edge(Role::Write), ct::Grant { may_grant: true, ..edge(Role::Read) }] {
        assert!(lp.peers[1].engine.grant(&g, &Tid::PUBLIC, &e).is_err(), "{e:?} refused");
    }
    let until = osis_base::Time(lp.peers[1].engine.core.now().0 + 100);
    lp.peers[1].engine.grant(&g, &Tid::PUBLIC, &ct::Grant { until: Some(until), ..edge(Role::Read) }).unwrap();
    lp.sync_all().unwrap();
    let public = |lp: &LocalPeer, i: usize| lp.peers[i].engine.roster(&g).get(&Tid::PUBLIC).map(|e| e.role);
    assert_eq!(public(&lp, 0), Some(Role::Read), "the may-grant grant applies");
    assert!(lp.peers[2].engine.public_reads(&g));
    let link = lp.peers[1].engine.locator(&g, Vec::new()).unwrap().unwrap();
    lp.peers[2].engine.redeem_locator(&link, &tids[2]).unwrap();
    lp.sync_all().unwrap();
    assert!(reads_key(&mut lp, 2, g, "open"), "a stranger reads g by the link");
    assert!(lp.peers[1].engine.demote(&g, &Demotion { holder: Tid::PUBLIC, new: None, retain: None }).is_err(), "W removes no other edge");
    lp.peers[1].clock.advance(1_000);
    lp.peers[1].engine.ensure_rotated(&g).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(public(&lp, 0), None, "W finalizes the ended grant");
    lp.peers[1].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(public(&lp, 0), Some(Role::Read), "granted again by may-grant");
    lp.peers[0].engine.demote(&g, &Demotion { holder: Tid::PUBLIC, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(public(&lp, 1), None, "the admin removes it");
}

// spec/crypto.md §4 (Epochs; Reading-only secrets: a box while the node's roles do not give its
// role gives nothing): what an epoch's history says is what its history box says now, whatever
// the node's roles. G, minted in P after P rotated twice, is dependent, its derived epochs
// superseding one another. P's admin, its clock ahead, makes G independent, then gives the
// public sync on P and on G. Stranger S (1) holds both and gets all three ahead of its clock: it
// reads their boxes for reading only (P's secrets, so G's derived epochs), and the grant on G
// waits for G's keys too. S's clock reaches G's independence alone: G's epochs start again from
// the derived ones (`refresh_independent`), whose history is P's, and S reads G's state with no
// role giving it G's secrets. Its store loaded afresh says the same, rebuilt from the commit
// records too (`check_index`). Fails when the role kept skips the read's clearing: the live
// index keeps the derived history, which a rebuild never records.
#[test]
fn an_epochs_history_is_its_states_whatever_the_roles_spec_crypto_4() {
    let mut lp = super::tests::synced(2);
    let p = super::tests::target_thing(&mut lp, 0);
    let all = [Role::Sync, Role::Read, Role::Write, Role::Admin];
    for _ in 0..2 {
        lp.peers[0].engine.rotate_leaving_out(&p, &all, &[]).unwrap();
    }
    let me = lp.peers[0].engine.tid();
    let mut m = crate::Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, p);
    m.op(me, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(g)) }).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.hold_at(1, g);
    lp.sync_all().unwrap();
    let drift = osis_base::format::MAX_DRIFT_MS;
    lp.peers[0].clock.advance(3 * drift);
    let mut late = lp.peers[0].engine.make_independent(&g).unwrap().commits;
    lp.peers[0].clock.advance(2 * drift);
    late.extend(lp.peers[0].engine.grant(&p, &Tid::PUBLIC, &edge(Role::Sync)).unwrap().commits);
    late.extend(lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Sync)).unwrap().commits);
    for c in &late {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(..)), "each waits");
    }
    // G's independence applies, P's grant still ahead of S's clock: S holds P's secrets for
    // reading only and no role on G
    lp.peers[1].clock.advance(5 * drift / 2);
    lp.peers[1].reexamine().unwrap();
    assert!(lp.peers[1].engine.commit_ids().contains(&late[0]), "G made independent here");
    assert!(!late[1..].iter().any(|c| lp.peers[1].engine.commit_ids().contains(c)), "the grants wait");
    lp.peers[1].engine.check_index();
    lp.peers[1].clock.advance(3 * drift);
    lp.peers[1].reexamine().unwrap();
    assert!(late.iter().all(|c| lp.peers[1].engine.commit_ids().contains(c)), "all applied");
    lp.peers[1].engine.check_index();
}
