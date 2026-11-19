#![allow(clippy::unwrap_used)]
//! Hostile tickets (spec/sync-set.md §2, spec/sync-inbox.md §5): a ticket anyone holding the
//! holder's public record can box, for any tid, at an epoch of its own making.

use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Role, SyncId, Tid, Ticket, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_crypto::{Epoch, Secret32};
use osis_schema::core_types as ct;
use osis_schema::Codec;
use std::collections::BTreeSet;

const T0: WallMs = WallMs(1_700_000_000_000);

/// Two accounts, each peer holding the other's records.
fn two() -> (LocalPeer, [Tid; 2]) {
    let mut lp = LocalPeer::new(2, 0, T0).unwrap();
    let a = lp.peers[0].engine.create_account().unwrap().0.account;
    let b = lp.peers[1].engine.create_account().unwrap().0.account;
    for (x, y) in [(0, 1), (1, 0)] {
        for pk in lp.packages_for(x, y).unwrap() {
            lp.deliver(y, &pk).unwrap();
        }
    }
    (lp, [a, b])
}

/// A ticket for `target` boxed to `holder` by peer `i`, of an epoch it makes up with a secret of
/// its choosing: what any holder of `holder`'s public record can make.
fn forged(lp: &mut LocalPeer, i: usize, target: Tid, holder: Tid) -> Ticket {
    lp.peers[i]
        .engine
        .run(|tx| {
            let s = Secret32::from_bytes([9; 32]);
            let e = Epoch::derive(&target, Role::Read, 7, &s).unwrap();
            let mut held = osis_keys::ActorEpochs::default();
            held.role_mut(Role::Read).set_secret(e, s);
            held.role_mut(Role::Read).set_established(e, osis_keys::Provenance::Rotated);
            let rcpt = crate::flows::recipient(tx, holder, Role::Read)?;
            let w = osis_keys::box_holder(&target, &held, &Default::default(), &rcpt, &BTreeSet::from([Role::Read]), &mut *tx.rng)?.unwrap();
            let key = ct::BoxKey { holder: holder.into(), role: Role::Read, epoch: osis_keys::aspects::to_schema(&e) };
            let boxed = w.boxes.get(&key).unwrap().to_value();
            Ok(Ticket { target, sync_id: SyncId([7; 16]), role: Role::Read, epoch: (e.n(), *e.nonce()), boxed, holder, profile: holder })
        })
        .unwrap()
}

// spec/sync-inbox.md §5 Taking its secret, spec/sync-set.md §2: a ticket arriving after the
// strong to its target enters it, and a forged ticket for it held first does not keep the honest
// one's secret out.
#[test]
fn a_ticket_after_the_strong_enters_whatever_was_forged_spec_sync_set_2() {
    for forge in [false, true] {
        ticket_after_strong(forge);
    }
}

fn ticket_after_strong(forge: bool) {
    let (mut lp, [_, bob]) = two();
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.account_root().unwrap();
    let mut m = Mutation::new();
    let t = e0.new_thing(&mut m, d0);
    m.op(d0, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    e0.commit(m).unwrap();
    // Bob accepts T, holding a forged ticket for it or none
    let k = forged(&mut lp, 1, t, bob);
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.account_root().unwrap();
    let mut m = Mutation::new();
    if forge {
        m.op(d1, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(k))) }).unwrap();
    }
    m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    e1.commit(m).unwrap();
    // Alice grants Bob read: her ticket reaches him as a sealed fire
    let e0 = &mut lp.peers[0].engine;
    e0.grant(&t, &bob, &ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None }).unwrap();
    let honest = e0.epochs(&t).unwrap().read.newest_held().unwrap().0;
    let fires = e0.fires_owed();
    let out = e0.sealed_fire(&fires[0]).unwrap().unwrap();
    let e1 = &mut lp.peers[1].engine;
    let b = osis_blob::blob_id(&out.blob);
    e1.open_entry(&out.sync_id, &b, &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(e1.held_tickets(&t).unwrap().iter().any(|x| x.epoch == (honest.n(), *honest.nonce())), "the honest ticket is held");
    assert!(e1.epochs(&t).is_some_and(|x| x.read.secret(&honest).is_some()), "the honest secret is taken (forged first: {forge})");
}

// spec/sync-set.md §2 (counts as independent; a read secret a ticket gives establishes nothing): a forged ticket for a dependent thing P of another account, with a
// strong to P from a thing whose keys do not open it, does not make P independent here: the forged
// secret is taken but P is not entered read, so the node closure does not hold it (nor writes
// D's ticket for it), and with the strong gone nothing of it is left.
#[test]
fn a_forged_ticket_keeps_no_dependent_thing_held_spec_sync_set_2() {
    let (mut lp, [_, bob]) = two();
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.account_root().unwrap();
    let mut m = Mutation::new();
    let p = e0.new_thing(&mut m, d0);
    m.op(d0, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(p)) }).unwrap();
    e0.commit(m).unwrap();
    let k = forged(&mut lp, 1, p, bob);
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.account_root().unwrap();
    let profile = e1.profile_of(&bob).unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(k))) }).unwrap();
    m.op(profile, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(p)) }).unwrap();
    e1.commit(m).unwrap();
    assert!(e1.core.ix.secrets.get(&p).is_some_and(|e| e.holds_any()), "the forged secret is taken at the strong");
    assert!(!e1.closure_holds(&p), "P is not independent here: not held");
    assert_eq!(e1.account_ticket_due(&p).unwrap(), None, "no ticket of D's owed for it");
    let mut m = Mutation::new();
    m.op(profile, &ct::HOLDS, PathOp { path: vec![], op: Op::Remove(Value::Strong(p)) }).unwrap();
    e1.commit(m).unwrap();
    assert!(!e1.closure_holds(&p) && !e1.sync_things().unwrap().contains(&p), "nothing of P left");
}

// spec/permissions.md §3 Lost access (drop those role secrets and every local unit it can no
// longer read), spec/sync-set.md §2 (a read secret a ticket gives establishes nothing; On a
// ticket's word), spec/commits.md §4 (Outside the node closure): Bob holds T's read secret from
// his ticket while T counts as dependent here (he holds no keyset commit of it), so T is held on
// the ticket's word alone, outside the node closure: T's value waits, unread; his timed grant
// ends and its secrets go, the value still unread.
#[test]
fn a_tickets_secret_on_a_dependent_thing_reads_nothing_and_goes_spec_permissions_3() {
    let (mut lp, [_, bob]) = two();
    let ak = osis_base::Ak::new("x:v.0").unwrap();
    let e0 = &mut lp.peers[0].engine;
    let d0 = e0.account_root().unwrap();
    let mut m = Mutation::new();
    let t = e0.new_thing(&mut m, d0);
    m.set(t, &ak, &Value::Str("v".into())).unwrap();
    m.op(d0, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    let made = e0.commit(m).unwrap().unwrap();
    let before: BTreeSet<_> = e0.commit_ids().into_iter().collect();
    let e1 = &mut lp.peers[1].engine;
    let d1 = e1.account_root().unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(t)) }).unwrap();
    e1.commit(m).unwrap();
    // Alice grants Bob read for an hour: her ticket reaches him as a sealed fire
    let e0 = &mut lp.peers[0].engine;
    let hour = 3_600_000;
    e0.grant(&t, &bob, &ct::Edge { role: Role::Read, until: Some(WallMs(T0.0 + hour)), invite: None, retain: false, floor: None }).unwrap();
    let fire = e0.sealed_fire(&e0.fires_owed()[0]).unwrap().unwrap();
    let keysets: BTreeSet<_> = e0.core.ix.keyset_parts.get(&t).into_iter().flatten().copied().collect();
    let grant: Vec<_> = e0.commit_ids().into_iter().filter(|c| !before.contains(c) && !keysets.contains(c)).collect();
    let e1 = &mut lp.peers[1].engine;
    e1.open_entry(&fire.sync_id, &osis_blob::blob_id(&fire.blob), &[0; 57], &fire.blob, u64::MAX).unwrap();
    // Bob gets T's value and the grant, none of T's keysets
    let pks = lp.sealed(0, &[made]).unwrap();
    lp.deliver_sealed(1, &pks).unwrap();
    for c in &grant {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
    }
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.core.is_independent(&t), "T counts as dependent here");
    assert!(!e1.closure_holds(&t), "held on the ticket's word alone");
    assert!(e1.pending().iter().any(|(c, r)| *c == made && *r == crate::Reason::Outside(t)), "T's value waits");
    assert_eq!(e1.get(&t, &ak).unwrap(), None, "unread");
    lp.advance(hour + crate::rotation::LOST_HEARD_WAIT_MS + 1);
    let e1 = &mut lp.peers[1].engine;
    e1.tick().unwrap();
    assert!(e1.forget_lost(crate::rotation::LostScope::All).unwrap().actors.contains(&t), "T's secrets go");
    assert_eq!(e1.get(&t, &ak).unwrap(), None, "still unread");
}
