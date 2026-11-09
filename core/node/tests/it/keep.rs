#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Keep (spec/permissions.md §3): a removed holder's read-only copy.

use crate::common::*;
use crate::flows::{big, edge_of, forensic_peer, hosts, reopen, send, spread, thing_of};
use crate::net::Net;
use osis_base::{Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_node::flows::Demotion;
use osis_node::local_peer::LocalPeer;
use osis_node::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const D_MARK: &str = "KEEP-D-MARK-77a1";
const F_MARK: &str = "KEEP-F-MARK-02bd";
const LATE_MARK: &str = "KEEP-LATE-MARK-4c0e";

/// A holder's edge and the target's default for removals.
type Holding = (ct::Edge, bool);

fn keeping(role: Role) -> Holding {
    (edge_of(role), true)
}

fn erasing(role: Role) -> Holding {
    (edge_of(role), false)
}

/// The removal's word left to the default.
fn remove(holder: Tid) -> Demotion {
    Demotion { holder, new: None, retain: None }
}

fn saying(holder: Tid, keep: bool) -> Demotion {
    Demotion { retain: Some(keep), ..remove(holder) }
}

/// Removes `holder`, the removal saying `keep` whatever the default.
fn remove_saying(lp: &mut LocalPeer, target: Tid, holder: Tid, keep: bool) -> osis_node::flows::Done {
    lp.peers[0].engine.demote(&target, &saying(holder, keep)).unwrap()
}

/// Peer `i` sets `t`'s default for removals.
fn set_default(lp: &mut LocalPeer, i: usize, t: Tid, keep: bool) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &ct::REQUIRED, &ct::RequiredRules { retain: keep, ..Default::default() }).unwrap();
    lp.peers[i].engine.commit(m).unwrap().unwrap()
}

struct Kept {
    lp: LocalPeer,
    /// Bob's account.
    pb: Tid,
    /// Bob holds an edge on it.
    d: Tid,
    /// Read by bob only through `d`.
    f: Tid,
}

/// Alice's d (bob holding `edge`, `keep` its default) and f (d holding read), a marker on each, all
/// at both.
fn setup(seed: u64, (edge, keep): Holding) -> Kept {
    let mut lp = LocalPeer::of(vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &osis_store::Faults::new())], seed);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut lp);
    let d = thing_of(&mut lp, 0, pa);
    if keep {
        set_default(&mut lp, 0, d, true);
    }
    lp.peers[0].engine.grant(&d, &pb, &edge).unwrap();
    let f = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&f, &d, &edge_of(Role::Read)).unwrap();
    for (t, mark) in [(d, D_MARK), (f, F_MARK)] {
        write(&mut lp, t, mark);
    }
    spread(&mut lp);
    assert_eq!(read(&mut lp, d), Some(s(&big(D_MARK))));
    Kept { lp, pb, d, f }
}

fn write(lp: &mut LocalPeer, t: Tid, mark: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, &REG, &s(&big(mark))).unwrap();
    lp.peers[0].engine.commit(m).unwrap().unwrap()
}

fn read(lp: &mut LocalPeer, t: Tid) -> Option<Value> {
    lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap()
}

fn found(lp: &mut LocalPeer, mark: &str) -> bool {
    plaintexts(&mut lp.peers[1]).iter().any(|p| contains(p, mark.as_bytes()))
}

fn no_secret(lp: &LocalPeer, t: Tid) -> bool {
    lp.peers[1].engine.epochs(&t).is_none_or(|e| e.read.held().next().is_none())
}

fn assert_kept(x: &mut Kept) {
    let (d, f) = (x.d, x.f);
    assert_eq!(read(&mut x.lp, d), Some(s(&big(D_MARK))), "the copy reads");
    assert_eq!(read(&mut x.lp, f), Some(s(&big(F_MARK))), "what it read through the removed actor too");
    assert!(no_secret(&x.lp, d) && no_secret(&x.lp, f), "no secret stays");
    let kept: BTreeSet<Tid> = x.lp.peers[1].engine.kept_copies().into_iter().collect();
    assert!(kept.contains(&d) && kept.contains(&f), "{kept:?}");
}

fn assert_erased(x: &mut Kept) {
    let (d, f) = (x.d, x.f);
    assert_eq!(read(&mut x.lp, d), None);
    assert_eq!(read(&mut x.lp, f), None);
    assert!(!found(&mut x.lp, D_MARK) && !found(&mut x.lp, F_MARK), "a marker recovered");
    assert!(x.lp.peers[1].engine.kept_copies().is_empty());
}

/// Bob removed, the removal at both, the trigger run at bob.
fn removed(x: &mut Kept) {
    let (d, pb) = (x.d, x.pb);
    x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap();
    spread(&mut x.lp);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
}

// spec/permissions.md §3, Retain: a removal under a default to keep leaves its holder's node a copy of
// what it read through the edge, an actor below it included, with no secret; it reads and is read-only.
#[test]
fn a_keeping_removal_leaves_a_read_only_copy_spec_perm_3() {
    let mut x = setup(9100, keeping(Role::Write));
    removed(&mut x);
    assert_kept(&mut x);
    assert!(found(&mut x.lp, D_MARK), "held in the store");
    let mut m = Mutation::new();
    m.set(x.d, &REG, &s("no")).unwrap();
    assert!(x.lp.peers[1].engine.commit(m).is_err(), "read-only");
    assert_eq!(read(&mut x.lp, x.d), Some(s(&big(D_MARK))));
}

// spec/permissions.md §3, Retain: no default erases.
#[test]
fn no_default_erases_spec_perm_3() {
    let mut x = setup(9110, erasing(Role::Write));
    removed(&mut x);
    assert_erased(&mut x);
}

// spec/permissions.md §3, Retain: the copy, its marks and its timers survive a restart; open equals
// rebuild; nothing asks for a secret to read it.
#[test]
fn copy_survives_restart_spec_perm_3() {
    let mut x = setup(9120, keeping(Role::Read));
    removed(&mut x);
    reopen(&mut x.lp, 1, 9122).unwrap();
    assert_kept(&mut x);
    x.lp.peers[1].engine.check_index();
    assert_kept(&mut x);
    reopen(&mut x.lp, 1, 9123).unwrap();
    assert_kept(&mut x);
    // still a copy: no write, no late content
    let late = write(&mut x.lp, x.d, LATE_MARK);
    send(&mut x.lp, 0, 1, &[late]);
    assert_eq!(read(&mut x.lp, x.d), Some(s(&big(D_MARK))));
}

// spec/permissions.md §3, Retain: expiry keeps running on a copy, through a restart.
#[test]
fn expiry_runs_on_a_copy_spec_perm_3() {
    let mut x = setup(9130, keeping(Role::Read));
    let now = x.lp.peers[0].engine.now();
    let mut m = Mutation::new();
    m.set(x.d, &REG, &s(&big(LATE_MARK))).unwrap();
    m.expires(x.d, &REG, osis_base::WallMs(now.0 + 60_000)).unwrap();
    x.lp.peers[0].engine.commit(m).unwrap();
    spread(&mut x.lp);
    removed(&mut x);
    assert_eq!(read(&mut x.lp, x.d), Some(s(&big(LATE_MARK))));
    reopen(&mut x.lp, 1, 9132).unwrap();
    x.lp.peers[1].clock.advance(61_000);
    x.lp.peers[1].engine.tick().unwrap();
    assert_ne!(read(&mut x.lp, x.d), Some(s(&big(LATE_MARK))));
    assert!(!found(&mut x.lp, LATE_MARK), "expired");
}

// spec/permissions.md §3, Retain: a body received before the removal is in the copy; one after it is
// not, and stays out through a restart.
#[test]
fn removal_vs_body_every_order_spec_perm_3() {
    for (body_first, seed) in [(true, 9140), (false, 9150)] {
        let mut x = setup(seed, keeping(Role::Read));
        let (d, pb) = (x.d, x.pb);
        let body = write(&mut x.lp, d, LATE_MARK);
        let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
        if body_first {
            send(&mut x.lp, 0, 1, &[body, rm]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            assert_eq!(read(&mut x.lp, d), Some(s(&big(LATE_MARK))), "a body held when it learned");
        } else {
            send(&mut x.lp, 0, 1, &[rm]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            send(&mut x.lp, 0, 1, &[body]);
            assert_eq!(read(&mut x.lp, d), Some(s(&big(D_MARK))), "frozen");
            assert!(!found(&mut x.lp, LATE_MARK));
            reopen(&mut x.lp, 1, seed + 2).unwrap();
            assert_eq!(read(&mut x.lp, d), Some(s(&big(D_MARK))));
        }
    }
}

// spec/permissions.md §3, Retain: another holder's purge held before the removal goes as anywhere; one
// after it stays undone in the copy, even handed over (the limit), through a restart.
#[test]
fn removal_vs_purge_every_order_spec_perm_3() {
    for (purge_first, seed) in [(true, 9160), (false, 9170)] {
        let mut x = setup(seed, keeping(Role::Read));
        let (d, pb) = (x.d, x.pb);
        let body = write(&mut x.lp, d, LATE_MARK);
        send(&mut x.lp, 0, 1, &[body]);
        assert!(found(&mut x.lp, LATE_MARK));
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: body, tid: d, ak: ak("t:reg.0") });
        m.remove_aspect(d, &REG).unwrap();
        let purge = x.lp.peers[0].engine.commit(m).unwrap().unwrap();
        let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
        if purge_first {
            send(&mut x.lp, 0, 1, &[purge, rm]);
        } else {
            send(&mut x.lp, 0, 1, &[rm]);
        }
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        assert!(x.lp.peers[1].engine.kept_copies().contains(&d));
        if !purge_first {
            send(&mut x.lp, 0, 1, &[purge]);
        }
        reopen(&mut x.lp, 1, seed + 2).unwrap();
        assert_eq!(found(&mut x.lp, LATE_MARK), !purge_first);
        assert_eq!(read(&mut x.lp, d) == Some(s(&big(LATE_MARK))), !purge_first);
    }
}

// spec/permissions.md §3, Retain: no content joins a copy, whatever the commit also carries.
#[test]
fn a_purge_carries_no_content_into_a_copy_spec_perm_3() {
    let mut x = setup(9180, keeping(Role::Read));
    let d = x.d;
    removed(&mut x);
    let mut m = Mutation::new();
    m.set(d, &REG, &s(&big(LATE_MARK))).unwrap();
    m.purge(PurgeItem::Commit { commit: osis_base::CommitId([9; 32]), tid: d, ak: ak("t:reg.0") });
    let c = x.lp.peers[0].engine.commit(m).unwrap().unwrap();
    send(&mut x.lp, 0, 1, &[c]);
    assert_kept(&mut x);
    assert!(!found(&mut x.lp, LATE_MARK));
}

// spec/permissions.md §3, Retain: the removal says for itself, either way, in one commit with its
// rotation; the removed holder is boxed nothing. The node reads the removal, not the default it holds.
#[test]
fn the_removal_overrides_the_default_spec_perm_3() {
    for (edge, say, seed) in [(keeping(Role::Read), false, 9190), (erasing(Role::Read), true, 9200)] {
        let mut x = setup(seed, edge);
        let (d, pb) = (x.d, x.pb);
        let before = x.lp.peers[0].engine.epochs(&d).unwrap().read.newest_held().unwrap().0;
        let done = remove_saying(&mut x.lp, d, pb, say);
        assert_eq!(done.commits.len(), 1, "one commit");
        assert!(done.deliveries.iter().any(|y| matches!(y, osis_node::flows::Delivery::Removal { under, .. } if *under == pb)), "placed as a removal");
        let (after, _) = x.lp.peers[0].engine.epochs(&d).unwrap().read.newest_held().unwrap();
        assert_ne!(before, after, "it rotated");
        let boxes = x.lp.peers[0].engine.get_typed(&d, &ct::SECRETS).unwrap().unwrap().boxes;
        assert!(!boxes.keys().any(|k| k.holder == pb && k.epoch.n == after.n()), "the removed holder is boxed nothing");
        spread(&mut x.lp);
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        assert_eq!(x.lp.peers[1].engine.role_on(&d), None);
        assert!(no_secret(&x.lp, d), "no new epoch reached the removed holder");
        if say {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §3, Retain: changing the default touches no past removal, in either direction: a
// copy stays through a change to erase, nothing comes back on a change to keep.
#[test]
fn a_later_default_touches_no_past_removal_spec_perm_3() {
    for (edge, seed) in [(keeping(Role::Read), 9210), (erasing(Role::Read), 9220)] {
        let keep = edge.1;
        let mut x = setup(seed, edge);
        let d = x.d;
        removed(&mut x);
        set_default(&mut x.lp, 0, d, !keep);
        spread(&mut x.lp);
        x.lp.peers[1].engine.drop_lost_secrets().unwrap();
        if keep {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §2, §3, Retain: a default is an admin's: a member's setting does not reach a
// removal, nor one its author lost the standing for (a demoted admin's, outside the frontier).
#[test]
fn only_a_standing_default_fills_spec_perm_3() {
    let mut x = setup(9225, erasing(Role::Write));
    let (d, pb) = (x.d, x.pb);
    let setting = ct::RequiredRules { retain: true, ..Default::default() };
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &setting).unwrap();
    assert!(x.lp.peers[1].engine.commit(m).is_err(), "not an admin");
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &setting).unwrap();
    let forged = x.lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    send(&mut x.lp, 1, 0, &[forged]);
    x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap();
    spread(&mut x.lp);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert_erased(&mut x);

    let mut x = setup(9227, erasing(Role::Admin));
    let (d, pb) = (x.d, x.pb);
    let mut m = Mutation::new();
    m.set(d, &ct::REQUIRED, &setting).unwrap();
    let fell = x.lp.peers[1].engine.commit(m).unwrap().unwrap();
    let down = Demotion { new: Some(edge_of(Role::Read)), ..remove(pb) };
    x.lp.peers[0].engine.demote(&d, &down).unwrap();
    send(&mut x.lp, 1, 0, &[fell]);
    x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap();
    spread(&mut x.lp);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert_erased(&mut x);
}

// spec/permissions.md §2: `until` 0 is a removal's way of saying retain, nothing else writes it; and a
// lowering says nothing.
#[test]
fn only_a_removal_says_spec_perm_2() {
    let mut x = setup(9228, erasing(Role::Write));
    let (d, pb) = (x.d, x.pb);
    let zero = ct::Edge { until: Some(osis_base::WallMs(0)), ..edge_of(Role::Read) };
    let f = x.f;
    assert!(x.lp.peers[0].engine.grant(&f, &pb, &zero).is_err());
    let e = &mut x.lp.peers[0].engine;
    assert!(e.demote(&d, &Demotion { new: Some(zero), ..remove(pb) }).is_err());
    assert!(e.demote(&d, &Demotion { new: Some(edge_of(Role::Read)), retain: Some(true), ..remove(pb) }).is_err());
}

// spec/commits.md §2: a removal saying retain carries its rotation as any: a writer refuses without it.
#[test]
fn a_removal_saying_keep_without_its_rotation_spec_commits_2() {
    let mut x = setup(9229, erasing(Role::Read));
    let (d, pb) = (x.d, x.pb);
    let mut m = Mutation::new();
    let marker = ct::Edge { until: Some(osis_base::WallMs(0)), ..edge_of(Role::Read) };
    m.op(d, &ct::ROLES, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(Value::Tid(pb)) }).unwrap();
    m.op(d, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(pb))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&marker)) }).unwrap();
    assert!(x.lp.peers[0].engine.commit(m).is_err());
}

// spec/permissions.md §3, Retain: two admins at once, one removal keeping, one erasing, the erasing one
// last by key: the node ends erased in either order, also where it kept on the first.
#[test]
fn concurrent_admins_erase_in_either_order_spec_perm_3() {
    for (keep_first, seed) in [(true, 9260), (false, 9270)] {
        let mut x = setup(seed, keeping(Role::Read));
        let (d, pb) = (x.d, x.pb);
        x.lp.peers.push(forensic_peer(seed + 7, &osis_store::Faults::new()));
        let carol = x.lp.peers[2].engine.tid();
        x.lp.peers[2].engine.create_person(&hosts()).unwrap();
        spread(&mut x.lp);
        x.lp.peers[0].engine.grant(&d, &carol, &edge_of(Role::Admin)).unwrap();
        spread(&mut x.lp);
        let keep = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
        x.lp.peers[2].clock.advance(1_000);
        let erase = *x.lp.peers[2].engine.demote(&d, &saying(pb, false)).unwrap().commits.last().unwrap();
        if keep_first {
            send(&mut x.lp, 0, 1, &[keep]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            assert_kept(&mut x);
            send(&mut x.lp, 2, 1, &[erase]);
        } else {
            send(&mut x.lp, 2, 1, &[erase]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            send(&mut x.lp, 0, 1, &[keep]);
        }
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        assert_erased(&mut x);
    }
}

// spec/permissions.md §2, §3, Retain: a holder leaving says its own word, whatever the default: no
// protocol rule stops it (receivers: osis-perm `self_removal_says_its_own_keep`).
#[test]
fn a_holder_leaving_says_its_own_word_spec_perm_2() {
    for (edge, say, seed) in [(erasing(Role::Read), true, 9235), (keeping(Role::Read), false, 9237)] {
        let mut x = setup(seed, edge);
        let (d, pb) = (x.d, x.pb);
        x.lp.peers[1].engine.demote(&d, &saying(pb, say)).unwrap();
        x.lp.peers[1].engine.drop_lost_secrets().unwrap();
        if say {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
        // the others read the same word: gone from the roster
        spread(&mut x.lp);
        assert!(!x.lp.peers[0].engine.roster(&d).contains_key(&pb));
    }
}

/// Alice's C and her actor P, bob's node holding admin on P, P holding write on C; each thing's
/// default as `(on P, on C)`.
fn nested(seed: u64, (on_p, on_c): (bool, bool)) -> (LocalPeer, Tid, Tid, Tid) {
    let mut lp = LocalPeer::of(vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &osis_store::Faults::new())], seed);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    lp.peers[1].engine.create_person(&hosts()).unwrap();
    spread(&mut lp);
    let bob = lp.peers[1].engine.tid();
    let p = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&p, &bob, &edge_of(Role::Admin)).unwrap();
    let c = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&c, &p, &edge_of(Role::Write)).unwrap();
    if on_p {
        set_default(&mut lp, 0, p, true);
    }
    if on_c {
        set_default(&mut lp, 0, c, true);
    }
    write(&mut lp, c, D_MARK);
    spread(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))));
    (lp, bob, p, c)
}

fn drop_due(lp: &mut LocalPeer) {
    spread(lp);
    lp.peers[1].engine.drop_lost_due().unwrap();
}

// spec/permissions.md §3, Retain: an account kicked retains through its node; the node then removed
// from the account (no default there) erases that copy with the account's: erase wins along a path.
#[test]
fn node_removal_erases_what_its_account_retained_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9300, (false, true));
    lp.peers[0].engine.demote(&c, &remove(p)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))), "the account's kick keeps");
    assert!(lp.peers[1].engine.kept_copies().contains(&c));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), None, "the node's removal erases it");
    assert!(!found(&mut lp, D_MARK));
    assert!(lp.peers[1].engine.kept_copies().is_empty());
}

// spec/permissions.md §3, Retain: a default arriving late, ordered before an `until` ending, ends the copy
// at the next judging; the setting does not wait on it.
#[test]
fn a_late_default_may_end_an_until_copy_spec_perm_3() {
    let at = osis_base::WallMs(T0.0 + 3_600_000);
    let mut x = setup(9601, (ct::Edge { until: Some(at), ..edge_of(Role::Read) }, true));
    let late = set_default(&mut x.lp, 0, x.d, false);
    x.lp.peers[0].clock.set(osis_base::WallMs(at.0 + 1_000));
    x.lp.peers[1].clock.set(osis_base::WallMs(at.0 + 1_000));
    x.lp.peers[1].engine.drop_lost_secrets().unwrap();
    assert_kept(&mut x);
    send(&mut x.lp, 0, 1, &[late]);
    x.lp.peers[1].engine.drop_lost_secrets().unwrap();
    assert_erased(&mut x);
}

// spec/permissions.md §3, Retain: the removal that decides is of the edge the node lost: removed from P
// (no default) C goes though C's default keeps; the same with the default on P keeps C though C has
// none, since P's edge did not end.
#[test]
fn the_edge_lost_decides_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9310, (false, true));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), None);
    assert!(!found(&mut lp, D_MARK));
    let (mut lp, bob, p, c) = nested(9320, (true, false));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))));
    assert!(lp.peers[1].engine.kept_copies().contains(&p) && lp.peers[1].engine.kept_copies().contains(&c));
}

// spec/permissions.md §3, Retain: an edge P's holder never read through (bob joined P after P's edge
// on C ended, saying retain) keeps nothing of C: bob had C another way, whose end says erase.
#[test]
fn an_end_before_the_node_read_the_holder_keeps_nothing_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9330, (false, true));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    lp.peers[0].engine.grant(&c, &bob, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&c, &remove(p)).unwrap();
    lp.peers[0].engine.grant(&p, &bob, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.drop_lost_due().unwrap();
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))), "reads directly");
    lp.peers[0].engine.demote(&c, &saying(bob, false)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), None);
    assert!(!lp.peers[1].engine.kept_copies().contains(&c));
}

// spec/permissions.md §3, Retain: several ways in: the copy stays while one way's end keeps.
#[test]
fn any_path_keeps_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9340, (false, true));
    lp.peers[0].engine.grant(&c, &bob, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&c, &remove(p)).unwrap();
    drop_due(&mut lp);
    assert!(lp.peers[1].engine.kept_copies().is_empty(), "still reads directly");
    lp.peers[0].engine.demote(&c, &saying(bob, false)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))));
    assert!(lp.peers[1].engine.kept_copies().contains(&c));
}

// spec/permissions.md §2, §3 Retain: an `until` passing is a loss the node judges by itself, with no
// role commit behind it and through a restart; the trigger leaves it to node-sync to hear its labels
// out (`Leaving::timed`, from when it was first judged), and the drop reads the default.
#[test]
fn until_ending_spec_perm_3() {
    use osis_node::rotation::LostScope;
    for ((edge, keep), seed) in [(keeping(Role::Read), 9350), (erasing(Role::Read), 9355)] {
        let at = osis_base::WallMs(T0.0 + 3_600_000);
        let mut x = setup(seed, (ct::Edge { until: Some(at), ..edge }, keep));
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        assert_eq!(x.lp.peers[1].engine.next_lost_due(), Some(at.0));
        reopen(&mut x.lp, 1, seed + 2).unwrap();
        assert_eq!(x.lp.peers[1].engine.next_lost_due(), Some(at.0), "the list survives a restart");
        x.lp.peers[1].clock.set(at);
        assert!(x.lp.peers[1].engine.lost_due());
        let d = x.d;
        let r = x.lp.peers[1].engine.forget_lost(LostScope::Due).unwrap();
        assert!(r.actors.is_empty() && r.leaving, "by the time alone: node-sync hears its labels out first");
        assert!(!x.lp.peers[1].engine.lost_due());
        let l = x.lp.peers[1].engine.lost_leaving().unwrap();
        assert_eq!(l.timed.get(&d), Some(&at.0));
        assert_eq!(l.recheck_at, Some(at.0 + osis_node::rotation::LOST_HEARD_WAIT_MS));
        reopen(&mut x.lp, 1, seed + 3).unwrap();
        assert_eq!(x.lp.peers[1].engine.lost_leaving().unwrap(), l, "the record survives a restart");
        // node-sync drops each actor it heard out on its own: `f`, read through `d`, is listed
        // and heard out by itself, so dropping `d` alone leaves it (its own writes may wait)
        let f = x.f;
        x.lp.peers[1].engine.forget_lost(LostScope::Only(&[d])).unwrap();
        assert!(!no_secret(&x.lp, f), "f waits for its own hearing out");
        assert_eq!(x.lp.peers[1].engine.lost_leaving().unwrap().timed.keys().copied().collect::<Vec<_>>(), vec![f]);
        x.lp.peers[1].engine.forget_lost(LostScope::Only(&[f])).unwrap();
        assert!(x.lp.peers[1].engine.lost_leaving().unwrap().timed.is_empty());
        if keep {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §2 (lost access by an `until`): a role commit received on a thing whose edge to
// this node only expired says nothing of that edge: the loss waits as an `until` passing does (a
// renewal may follow it); a removal received acts at once; a renewal held in time keeps access and
// lists the thing again at the new `until`.
#[test]
fn a_commit_beside_an_expired_edge_waits_spec_perm_2() {
    use osis_node::rotation::LostScope;
    let at = osis_base::WallMs(T0.0 + 3_600_000);
    let mut x = setup(9370, (ct::Edge { until: Some(at), ..edge_of(Role::Read) }, false));
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    // a renewal in time: readable, and due again at the new `until`
    let later = osis_base::WallMs(at.0 + 3_600_000);
    x.lp.peers[0].engine.grant(&x.d, &x.pb, &ct::Edge { until: Some(later), ..edge_of(Role::Read) }).unwrap();
    spread(&mut x.lp);
    x.lp.peers[1].clock.set(osis_base::WallMs(at.0 + 1));
    x.lp.peers[0].clock.set(osis_base::WallMs(at.0 + 1));
    let r = x.lp.peers[1].engine.forget_lost(LostScope::Due).unwrap();
    assert!(r.actors.is_empty() && !r.leaving);
    assert_eq!(x.lp.peers[1].engine.next_lost_due(), Some(later.0));
    let d = x.d;
    assert_eq!(read(&mut x.lp, d), Some(s(&big(D_MARK))));
    // the renewal passes; another holder's grant arrives beside the expired edge
    x.lp.peers[1].clock.set(osis_base::WallMs(later.0 + 1));
    x.lp.peers[0].clock.set(osis_base::WallMs(later.0 + 1));
    let pa = x.lp.peers[0].engine.first_admin(&x.d).unwrap();
    let other = thing_of(&mut x.lp, 0, pa);
    x.lp.peers[0].engine.grant(&x.d, &other, &edge_of(Role::Read)).unwrap();
    spread(&mut x.lp);
    assert!(x.lp.peers[1].engine.lost_due());
    let r = x.lp.peers[1].engine.forget_lost(LostScope::Due).unwrap();
    assert!(r.actors.is_empty() && r.leaving, "nothing received ended the edge: heard out first");
    assert!(x.lp.peers[1].engine.lost_leaving().unwrap().timed.contains_key(&d));
    assert!(found(&mut x.lp, D_MARK), "held while its labels are heard out");
    // a removal with no `until` in it: at once
    let mut x = setup(9375, erasing(Role::Read));
    let (d, pb) = (x.d, x.pb);
    x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap();
    spread(&mut x.lp);
    let r = x.lp.peers[1].engine.forget_lost(LostScope::Due).unwrap();
    assert!(!r.actors.is_empty() && !r.leaving);
    assert_erased(&mut x);
}

// spec/permissions.md §3, Retain: an `until` ending reads the default in force at its key: a setting ordered
// after it changes nothing either way, whichever the node held first.
#[test]
fn until_reads_the_default_at_its_key_spec_perm_3() {
    for ((edge, keep), seed) in [(keeping(Role::Read), 9356), (erasing(Role::Read), 9358)] {
        let at = osis_base::WallMs(T0.0 + 3_600_000);
        let mut x = setup(seed, (ct::Edge { until: Some(at), ..edge }, keep));
        let d = x.d;
        x.lp.peers[0].clock.set(osis_base::WallMs(at.0 + 1_000));
        x.lp.peers[1].clock.set(osis_base::WallMs(at.0 + 1_000));
        let flip = set_default(&mut x.lp, 0, d, !keep);
        send(&mut x.lp, 0, 1, &[flip]);
        x.lp.peers[1].engine.drop_lost_secrets().unwrap();
        if keep {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §2, §3 Retain: a removal saying its own `retain` holds at once at a node whose clock
// is far behind the remover's, in the bound a commit applies within (`MAX_DRIFT`): no timer.
#[test]
fn a_removal_saying_keep_ignores_the_clock_spec_perm_3() {
    for (edge, say, seed) in [(erasing(Role::Read), true, 9380), (keeping(Role::Read), false, 9385)] {
        let mut x = setup(seed, edge);
        let behind = T0.0 + 10_000;
        x.lp.peers[0].clock.set(osis_base::WallMs(behind + osis_base::format::MAX_DRIFT_MS - 1_000));
        x.lp.peers[1].clock.set(osis_base::WallMs(behind));
        let (d, pb) = (x.d, x.pb);
        remove_saying(&mut x.lp, d, pb, say);
        spread(&mut x.lp);
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        if say {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §3, Retain: a holder leaving without a word of its own reads the default.
#[test]
fn self_removal_fills_from_the_default_spec_perm_3() {
    for (edge, seed) in [(keeping(Role::Read), 9360), (erasing(Role::Read), 9370)] {
        let keep = edge.1;
        let mut x = setup(seed, edge);
        let (d, pb) = (x.d, x.pb);
        x.lp.peers[1].engine.demote(&d, &remove(pb)).unwrap();
        x.lp.peers[1].engine.drop_lost_secrets().unwrap();
        if keep {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §3, Retain: content waiting when the node dropped stays out, though what it
// waited for arrives.
#[test]
fn a_part_waiting_at_the_removal_stays_out_spec_perm_3() {
    let mut x = setup(9420, keeping(Role::Read));
    let (d, pb) = (x.d, x.pb);
    x.lp.peers.push(forensic_peer(9427, &osis_store::Faults::new()));
    let pc = x.lp.peers[2].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut x.lp);
    let g = *x.lp.peers[0].engine.grant(&d, &pc, &edge_of(Role::Write)).unwrap().commits.last().unwrap();
    send(&mut x.lp, 0, 2, &[g]);
    let mut m = Mutation::new();
    m.set(d, &REG, &s(&big(LATE_MARK))).unwrap();
    let body = x.lp.peers[2].engine.commit(m).unwrap().unwrap();
    send(&mut x.lp, 2, 1, &[body]);
    assert!(!x.lp.peers[1].engine.commit_ids().contains(&body), "its author's chain has not arrived");
    let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
    send(&mut x.lp, 0, 1, &[rm]);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert_kept(&mut x);
    send(&mut x.lp, 0, 1, &[g]);
    x.lp.peers[1].engine.reexamine().unwrap();
    assert_kept(&mut x);
    assert!(!found(&mut x.lp, LATE_MARK), "joined after the drop");
}

// spec/permissions.md §3, Retain; spec/commits.md §5: a waiting part a held purge emptied holds a stripped
// delta: at the removal it goes with the part, and nothing joins the copy when what it waited for comes.
#[test]
fn a_stripped_waiting_part_stays_out_spec_perm_3() {
    let mut x = setup(9460, keeping(Role::Read));
    let (d, pb) = (x.d, x.pb);
    x.lp.peers.push(forensic_peer(9467, &osis_store::Faults::new()));
    let pc = x.lp.peers[2].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut x.lp);
    let g = *x.lp.peers[0].engine.grant(&d, &pc, &edge_of(Role::Write)).unwrap().commits.last().unwrap();
    send(&mut x.lp, 0, 2, &[g]);
    let mut m = Mutation::new();
    m.set(d, &REG, &s(&big(LATE_MARK))).unwrap();
    let body = x.lp.peers[2].engine.commit(m).unwrap().unwrap();
    send(&mut x.lp, 2, 0, &[body]);
    send(&mut x.lp, 2, 1, &[body]);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: body, tid: d, ak: ak("t:reg.0") });
    m.remove_aspect(d, &REG).unwrap();
    let purge = x.lp.peers[0].engine.commit(m).unwrap().unwrap();
    send(&mut x.lp, 0, 1, &[purge]);
    assert!(!found(&mut x.lp, LATE_MARK), "stripped while it waits");
    let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
    send(&mut x.lp, 0, 1, &[rm]);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(x.lp.peers[1].engine.kept_copies().contains(&d));
    let before = read(&mut x.lp, d);
    let n = x.lp.peers[1].engine.commit_ids().len();
    send(&mut x.lp, 0, 1, &[g]);
    x.lp.peers[1].engine.reexamine().unwrap();
    reopen(&mut x.lp, 1, 9468).unwrap();
    assert_eq!(read(&mut x.lp, d), before);
    assert!(!x.lp.peers[1].engine.commit_ids().contains(&body), "nothing joined ({n} commits before)");
    assert!(!found(&mut x.lp, LATE_MARK));
}

// spec/permissions.md §3, Retain: a restart between the removal's apply and the trigger reads the same word.
#[test]
fn restart_before_the_trigger_keeps_spec_perm_3() {
    let mut x = setup(9440, keeping(Role::Read));
    let (d, pb) = (x.d, x.pb);
    x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap();
    spread(&mut x.lp);
    reopen(&mut x.lp, 1, 9442).unwrap();
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert_kept(&mut x);
    reopen(&mut x.lp, 1, 9443).unwrap();
    assert_kept(&mut x);
}

// spec/permissions.md §3, Retain: the node's user may erase a copy, and what hangs on it.
#[test]
fn the_user_drops_a_copy_spec_perm_3() {
    let mut x = setup(9380, keeping(Role::Read));
    removed(&mut x);
    let d = x.d;
    x.lp.peers[1].engine.forget_lost(osis_node::rotation::LostScope::Kept(&[d])).unwrap();
    assert_erased(&mut x);
    reopen(&mut x.lp, 1, 9382).unwrap();
    assert_erased(&mut x);
}

// spec/permissions.md §3, Retain: a re-grant makes the node an ordinary holder: new content joins,
// the mark goes, a later removal judges afresh.
#[test]
fn regrant_ends_the_copy_spec_perm_3() {
    let mut x = setup(9390, keeping(Role::Read));
    removed(&mut x);
    let (d, pb) = (x.d, x.pb);
    x.lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Read)).unwrap();
    write(&mut x.lp, d, LATE_MARK);
    spread(&mut x.lp);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert!(!x.lp.peers[1].engine.kept_copies().contains(&d));
    assert_eq!(read(&mut x.lp, d), Some(s(&big(LATE_MARK))), "reads again");
    assert!(!no_secret(&x.lp, d));
    let pb = x.pb;
    remove_saying(&mut x.lp, d, pb, false);
    spread(&mut x.lp);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert_eq!(read(&mut x.lp, d), None, "this removal says erase");
    assert!(!found(&mut x.lp, D_MARK));
}

// spec/permissions.md §2, §3 Retain; spec/sync.md: a node leaving by its own word, over a real host: its
// removal is placed before it drops, the others see it gone, the node holds the copy, frozen.
#[test]
fn leaving_with_a_copy_over_a_host_spec_perm_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b) = (net.node(9490, &[host]), net.node(9491, &[host]));
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(b, t), Some(s("before")));
    let bt = net.tid(b);
    let done = net.engine(b).demote(&g, &saying(bt, true)).unwrap();
    let acts = net.sync(b).carry_out(done).unwrap();
    net.actions(b, acts);
    net.run();
    assert!(!net.engine(a).roster(&g).contains_key(&bt), "it reached the others");
    assert!(net.engine(b).kept_copies().contains(&g));
    net.write(a, t, "after");
    net.run();
    assert_eq!(net.read(b, t), Some(s("before")), "frozen");
    assert!(net.sync(b).labels().is_empty());
}

// spec/permissions.md §3, Retain; spec/sync.md §2: over a real host a copy leaves the label: no
// session, nothing uploaded, later writes do not reach it, others converge without it.
#[test]
fn copy_is_not_synced_spec_perm_3() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, b) = (net.node(9400, &[host]), net.node(9401, &[host]));
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let t = net.item(a, g, g, "before");
    net.run();
    assert_eq!(net.read(b, t), Some(s("before")));
    let bt = net.tid(b);
    let done = net.engine(a).demote(&g, &saying(bt, true)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    assert!(net.engine(b).kept_copies().contains(&g));
    assert_eq!(net.read(b, t), Some(s("before")), "the copy reads");
    assert!(net.sync(b).labels().is_empty(), "no label synced");
    let l = net.label(a);
    let at_host = net.host_ids(host, &l).len();
    net.write(a, t, "after");
    net.run();
    assert!(net.host_ids(host, &l).len() > at_host);
    assert_eq!(net.read(b, t), Some(s("before")), "frozen");
    net.restart(b, 9402);
    net.run();
    assert_eq!(net.read(b, t), Some(s("before")), "after a restart");
    assert!(net.sync(b).labels().is_empty());
    assert_eq!(net.read(a, t), Some(s("after")));
}

// spec/permissions.md §3, Retain; §7: K takes the target's default when made, so a joiner removal keeps
// under it; the link key goes plain in the same commit.
#[test]
fn a_links_key_takes_the_targets_default_spec_perm_7() {
    for (keep, seed) in [(true, 9410), (false, 9415)] {
        let mut lp = LocalPeer::of(vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &osis_store::Faults::new())], seed);
        let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
        let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
        spread(&mut lp);
        let d = thing_of(&mut lp, 0, pa);
        if keep {
            set_default(&mut lp, 0, d, true);
        }
        write(&mut lp, d, D_MARK);
        let spec = osis_node::flows::LinkSpec { target: d, role: Role::Read, until: None, hosts: hosts(), peers: Vec::new(), single_use: false };
        let (link, _, _) = lp.peers[0].engine.create_link(&pa, &spec).unwrap();
        spread(&mut lp);
        let (k, l) = (link.k, lp.peers[0].engine.roster(&link.k).keys().copied().find(|h| *h != pa).unwrap());
        lp.peers[1].engine.redeem(&link, &pb, false).unwrap();
        spread(&mut lp);
        assert_eq!(read(&mut lp, d), Some(s(&big(D_MARK))));
        assert_eq!(lp.peers[1].engine.get_typed(&k, &ct::REQUIRED).unwrap().is_some_and(|r| r.retain), keep);
        lp.peers[0].engine.revoke_joiner(&k, &l, &pb, None).unwrap();
        drop_due(&mut lp);
        assert_eq!(read(&mut lp, d).is_some(), keep);
        assert_eq!(lp.peers[1].engine.kept_copies().contains(&d), keep);
    }
}

/// A random history of edge writes by alice over C, P and bob (`nested`), in the order it was made.
fn random_history(seed: u64, untils: bool) -> (LocalPeer, Tid, Tid, Vec<osis_base::CommitId>) {
    let mut rng = crate::order::Rng(seed);
    let (mut lp, bob, p, c) = nested(seed, (rng.below(2) == 0, rng.below(2) == 0));
    lp.peers[0].engine.grant(&c, &bob, &edge_of(Role::Read)).unwrap();
    spread(&mut lp);
    let mut ids = Vec::new();
    for _ in 0..3 + rng.below(4) {
        lp.peers[0].clock.advance(1_000);
        lp.peers[1].clock.advance(1_000);
        let (t, h) = [(c, bob), (c, p), (p, bob)][rng.below(3) as usize];
        let keep = rng.below(2) == 0;
        let role = if t == p { Role::Admin } else { Role::Read };
        let live = lp.peers[0].engine.roster(&t).contains_key(&h);
        let done = match (rng.below(if untils { 5 } else { 4 }), live) {
            (0, _) => lp.peers[0].engine.grant(&t, &h, &edge_of(role)).ok(),
            (4, _) => {
                let until = osis_base::WallMs(lp.peers[0].engine.now().0 + 1_500);
                lp.peers[0].engine.grant(&t, &h, &ct::Edge { until: Some(until), ..edge_of(role) }).ok()
            }
            (1, true) => lp.peers[0].engine.demote(&t, &remove(h)).ok(),
            (2, true) => lp.peers[0].engine.demote(&t, &saying(h, keep)).ok(),
            // a removal's fill changes; no receiver reads this
            (3, _) => {
                ids.push(set_default(&mut lp, 0, t, keep));
                None
            }
            _ => None,
        };
        ids.extend(done.into_iter().flat_map(|d| d.commits));
    }
    (lp, p, c, ids)
}

fn any_order_seed(seed: u64) -> u64 {
    any_order(seed, false)
}

/// `untils`: every `until` passed before anything arrives, each arrival judged by hand as well (no
/// role commit need follow one).
fn any_order(seed: u64, untils: bool) -> u64 {
    let judge = |lp: &mut LocalPeer| {
        lp.peers[1].engine.drop_lost_due().unwrap();
        if untils {
            lp.peers[1].engine.drop_lost_secrets().unwrap();
        }
    };
    let past = |lp: &mut LocalPeer| {
        for p in &mut lp.peers {
            p.clock.advance(if untils { 10_000 } else { 0 });
        }
    };
    let (mut whole, p, c, ids) = random_history(seed, untils);
    past(&mut whole);
    send(&mut whole, 0, 1, &ids);
    judge(&mut whole);
    let (mut x, _, _, same) = random_history(seed, untils);
    past(&mut x);
    assert_eq!(ids, same, "the history repeats at a seed");
    let mut order = same;
    let mut rng = crate::order::Rng(seed ^ 0x55);
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i as u64 + 1) as usize);
    }
    for id in &order {
        send(&mut x, 0, 1, &[*id]);
        judge(&mut x);
    }
    if !x.peers[1].engine.pending().is_empty() || !whole.peers[1].engine.pending().is_empty() {
        return 0;
    }
    let (at_once, here) = (whole.peers[1].engine.kept_copies(), x.peers[1].engine.kept_copies());
    // a mark on a re-granted actor stays until a secret comes: that is no copy
    for t in [p, c].into_iter().filter(|t| x.peers[1].engine.role_on(t).is_none()) {
        assert!(!here.contains(&t) || at_once.contains(&t), "{t} kept only by order: {here:?} vs {at_once:?}");
        assert!(!here.contains(&t) || no_secret(&x, t), "a copy with a secret");
    }
    if x.peers[1].engine.role_on(&c).is_none() && !here.contains(&c) {
        assert_eq!(read(&mut x, c), None);
        assert!(!found(&mut x, D_MARK), "erased content in the store");
    }
    u64::from(here.contains(&c))
}

fn any_order_until_seed(seed: u64) -> u64 {
    any_order(seed, true)
}

fn any_order_until_replay(s: u64) -> String {
    format!("OSIS_KEEP_START={s} OSIS_KEEP_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact keep::any_order_until_keeps_no_more_large")
}

// spec/permissions.md §3, Retain: the same with `until` endings, which read the default in force at
// their key, among the writes and settings. Seeds with teeth: a mark not ending when its way's default
// now says erase (133, 162).
#[test]
fn any_order_until_keeps_no_more_spec_perm_3() {
    let seeds = [133, 162, 0, 1, 2, 3, 4, 5];
    osis_base::testenv::run_seeds("keep::any_order_until_keeps_no_more", &seeds, false, any_order_until_replay, any_order_until_seed);
}

/// Seeds: OSIS_KEEP_START, OSIS_KEEP_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn any_order_until_keeps_no_more_large() {
    osis_base::testenv::Seeds::from_env("OSIS_KEEP_START", "OSIS_KEEP_SEEDS", osis_base::testenv::large(0..200)).run("keep::any_order_until_keeps_no_more_large", any_order_until_replay, any_order_until_seed);
}

fn any_order_replay(s: u64) -> String {
    format!("OSIS_KEEP_START={s} OSIS_KEEP_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact keep::any_order_keeps_no_more_large")
}

// spec/permissions.md §3, Retain: in any arrival order, with the trigger run after each commit, a node
// keeps no more than a node given the whole history at once; what it does not keep is gone from the
// store; a copy holds no secret. Seeds with teeth: a kept mark not rechecking that the node read the holder
// (385), the timeline's word not ending a mark (102), a later plain removal not replacing a word (1204).
#[test]
fn any_order_keeps_no_more_spec_perm_3() {
    let seeds = [385, 102, 1204, 11124, 886071, 9700];
    let kept: u64 = osis_base::testenv::run_seeds("keep::any_order_keeps_no_more", &seeds, false, any_order_replay, any_order_seed).into_iter().sum();
    assert!(kept > 0, "some seed kept");
}

/// Seeds: OSIS_KEEP_START, OSIS_KEEP_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn any_order_keeps_no_more_large() {
    osis_base::testenv::Seeds::from_env("OSIS_KEEP_START", "OSIS_KEEP_SEEDS", osis_base::testenv::large(0..200)).run("keep::any_order_keeps_no_more_large", any_order_replay, any_order_seed);
}
