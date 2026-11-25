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
        assert_eq!(held.role(o.role).secret(&o.epoch), Some(&o.secret));
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
    for e in [edge(Role::Write), edge(Role::Admin), ct::Edge { may_grant: true, ..edge(Role::Read) }] {
        assert!(lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &e).is_err(), "{e:?} refused");
    }
    assert!(open_boxes(&mut lp, 0, g).is_empty());
    lp.peers[0].engine.grant(&g, &Tid::PUBLIC, &edge(Role::Sync)).unwrap();
    let sync: BTreeSet<_> = current_read_sync(&lp, 0, g).into_iter().filter(|x| x.0 == Role::Sync).collect();
    assert_eq!(open_boxes(&mut lp, 0, g), sync, "a sync grant boxes the sync secret alone");
}
