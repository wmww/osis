#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Keep (spec/permissions.md §3): a removed holder's read-only copy.

use crate::common::*;
use crate::flows::{big, edge_of, forensic_peer, hosts, reopen, send, spread, thing_of};
use crate::net::Net;
use osis_base::{Role, Tid, Value};
use osis_commit::PurgeItem;
use osis_node::flows::{Demotion, PreSync};
use osis_node::local_peer::LocalPeer;
use osis_node::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const D_MARK: &str = "KEEP-D-MARK-77a1";
const F_MARK: &str = "KEEP-F-MARK-02bd";
const LATE_MARK: &str = "KEEP-LATE-MARK-4c0e";

fn keeping(role: Role) -> ct::Edge {
    ct::Edge { keep: true, ..edge_of(role) }
}

fn remove(holder: Tid) -> Demotion {
    Demotion { holder, new: None, presync: PreSync::Synced }
}

/// Removes `holder`, the write saying `keep` whatever its edge says: written expired.
fn remove_saying(lp: &mut LocalPeer, target: Tid, holder: Tid, keep: bool) -> osis_node::flows::Done {
    let now = lp.peers[0].engine.now();
    let new = ct::Edge { until: Some(now), keep, ..edge_of(Role::Read) };
    let d = Demotion { holder, new: Some(new), presync: PreSync::Synced };
    lp.peers[0].engine.demote(&target, &d).unwrap()
}

struct Kept {
    lp: LocalPeer,
    /// Bob's person.
    pb: Tid,
    /// Bob holds `edge` on it.
    d: Tid,
    /// Read by bob only through `d`.
    f: Tid,
}

/// Alice's d (bob holding `edge`) and f (d holding read), a marker on each, all at both.
fn setup(seed: u64, edge: ct::Edge) -> Kept {
    let mut lp = LocalPeer::of(vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &osis_store::Faults::new())], seed);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut lp);
    let d = thing_of(&mut lp, 0, pa);
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

// spec/permissions.md §3, Keep: an edge with `keep` ending leaves its holder's node a copy of what
// it read through the edge, an actor below it included, with no secret; it reads and is read-only.
#[test]
fn edge_keep_leaves_a_read_only_copy_spec_perm_3() {
    let mut x = setup(9100, keeping(Role::Write));
    removed(&mut x);
    assert_kept(&mut x);
    assert!(found(&mut x.lp, D_MARK), "held in the store");
    let mut m = Mutation::new();
    m.set(x.d, &REG, &s("no")).unwrap();
    assert!(x.lp.peers[1].engine.commit(m).is_err(), "read-only");
    assert_eq!(read(&mut x.lp, x.d), Some(s(&big(D_MARK))));
}

// spec/permissions.md §3, Keep: an edge without `keep` erases, the core's default.
#[test]
fn default_edge_erases_spec_perm_3() {
    let mut x = setup(9110, edge_of(Role::Write));
    removed(&mut x);
    assert_erased(&mut x);
}

// spec/permissions.md §3, Keep: the copy, its marks and its timers survive a restart; open equals
// rebuild; nothing asks for a secret to read it.
#[test]
fn copy_survives_restart_spec_perm_3() {
    let mut x = setup(9120, keeping(Role::Read));
    removed(&mut x);
    reopen(&mut x.lp, 1, 9122).unwrap();
    assert_kept(&mut x);
    crate::walks::open_equals_rebuild(&mut x.lp.peers[1].engine, &[x.d, x.f], "copy");
    assert_kept(&mut x);
    reopen(&mut x.lp, 1, 9123).unwrap();
    assert_kept(&mut x);
    // still a copy: no write, no late content
    let late = write(&mut x.lp, x.d, LATE_MARK);
    send(&mut x.lp, 0, 1, &[late]);
    assert_eq!(read(&mut x.lp, x.d), Some(s(&big(D_MARK))));
}

// spec/permissions.md §3, Keep: expiry keeps running on a copy, through a restart.
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

// spec/permissions.md §3, Keep: a body received before the removal is in the copy; one after it is
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

// spec/permissions.md §3, Keep: another holder's purge held before the removal goes as anywhere; one
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

// spec/permissions.md §3, Keep: no content joins a copy, whatever the commit also carries.
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

// spec/permissions.md §2, Keep: an invite says no more than it was given: its holder's grant cannot
// say `keep` through an edge without it (receivers: osis-perm `invite_grant_keep_...`), and carries it
// through one with it.
#[test]
fn an_invite_grant_carries_its_edges_keep_spec_perm_2() {
    for (edge, seed) in [(edge_of(Role::Read), 9500), (keeping(Role::Read), 9510)] {
        let keeps = edge.keep;
        let mut lp = LocalPeer::of((0..3).map(|i| forensic_peer(seed + i, &osis_store::Faults::new())).collect(), seed);
        let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
        let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
        let pc = lp.peers[2].engine.create_person(&hosts()).unwrap().0.person;
        spread(&mut lp);
        let d = thing_of(&mut lp, 0, pa);
        lp.peers[0].engine.grant(&d, &pb, &ct::Edge { invite: Some(Role::Read), ..edge }).unwrap();
        spread(&mut lp);
        let forged = lp.peers[1].engine.grant(&d, &pc, &keeping(Role::Read));
        assert_eq!(forged.is_ok(), keeps);
        if !keeps {
            lp.peers[1].engine.grant(&d, &pc, &edge_of(Role::Read)).unwrap();
        }
        spread(&mut lp);
        assert_eq!(lp.peers[0].engine.roster(&d).get(&pc).map(|e| e.keep), Some(keeps));
    }
}

// spec/permissions.md §3, Keep: the write ending the edge says for itself, either way, in one commit
// with its rotation: expired when written, it is a removal, and the removed holder is boxed nothing.
#[test]
fn removal_overrides_the_edge_spec_perm_3() {
    for (edge, say, seed) in [(keeping(Role::Read), false, 9190), (edge_of(Role::Read), true, 9200)] {
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

// spec/permissions.md §2, §3, Keep: a removal resets the value it was written over, so a change to
// erase cannot be missed: a node holding only the removal still holds the edge, and erases once the
// change arrives.
#[test]
fn removal_arrives_with_the_value_it_removes_spec_perm_3() {
    for (rm_first, seed) in [(true, 9210), (false, 9220)] {
        let mut x = setup(seed, keeping(Role::Read));
        let (d, pb) = (x.d, x.pb);
        let fix = *x.lp.peers[0].engine.grant(&d, &pb, &edge_of(Role::Read)).unwrap().commits.last().unwrap();
        let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
        if rm_first {
            send(&mut x.lp, 0, 1, &[rm]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            assert_eq!(x.lp.peers[1].engine.role_on(&d), Some(Role::Read), "the reset names no holder yet");
            assert!(x.lp.peers[1].engine.kept_copies().is_empty());
            send(&mut x.lp, 0, 1, &[fix]);
        } else {
            send(&mut x.lp, 0, 1, &[fix, rm]);
        }
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        assert_erased(&mut x);
    }
}

// spec/permissions.md §3, Keep: two admins at once, one removal keeping, one written expired saying
// erase: the node ends erased in either order, also where it kept on the first.
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
        let new = ct::Edge { until: Some(x.lp.peers[2].engine.now()), ..edge_of(Role::Read) };
        let erase = *x.lp.peers[2].engine.demote(&d, &Demotion { holder: pb, new: Some(new), presync: PreSync::Synced }).unwrap().commits.last().unwrap();
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

// spec/permissions.md §2, §3, Keep: a client does not raise its own edge's keep (receivers: osis-perm
// `self_removal_does_not_raise_keep`).
#[test]
fn a_holder_does_not_raise_its_own_keep_spec_perm_2() {
    let mut x = setup(9235, edge_of(Role::Read));
    let (d, pb) = (x.d, x.pb);
    let new = ct::Edge { keep: true, ..edge_of(Role::Read) };
    assert!(x.lp.peers[1].engine.demote(&d, &Demotion { holder: pb, new: Some(new.clone()), presync: PreSync::Synced }).is_err());
    removed(&mut x);
    assert_erased(&mut x);
}

// spec/permissions.md §3, Keep: a roster snapshot may take the signal out of the walk: read before
// the node judged, there is none and it erases; after, the record stands.
#[test]
fn snapshot_hides_the_signal_spec_perm_3() {
    for (kept_first, seed) in [(false, 9240), (true, 9250)] {
        let mut x = setup(seed, keeping(Role::Read));
        let (d, pb) = (x.d, x.pb);
        let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
        let snap = *x.lp.peers[0].engine.roster_snapshot(&d, None).unwrap().commits.last().unwrap();
        if kept_first {
            send(&mut x.lp, 0, 1, &[rm]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            assert_kept(&mut x);
            send(&mut x.lp, 0, 1, &[snap]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            assert_kept(&mut x);
        } else {
            send(&mut x.lp, 0, 1, &[snap]);
            x.lp.peers[1].engine.drop_lost_due().unwrap();
            assert_eq!(x.lp.peers[1].engine.role_on(&d), None);
            assert_erased(&mut x);
        }
    }
}

/// Alice's C and her actor P, bob's node holding `device` on P, P holding `member` on C.
fn nested(seed: u64, device: ct::Edge, member: ct::Edge) -> (LocalPeer, Tid, Tid, Tid) {
    let mut lp = LocalPeer::of(vec![forensic_peer(seed, &osis_store::Faults::new()), forensic_peer(seed + 1, &osis_store::Faults::new())], seed);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    lp.peers[1].engine.create_person(&hosts()).unwrap();
    spread(&mut lp);
    let bob = lp.peers[1].engine.tid();
    let p = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&p, &bob, &device).unwrap();
    let c = thing_of(&mut lp, 0, pa);
    lp.peers[0].engine.grant(&c, &p, &member).unwrap();
    write(&mut lp, c, D_MARK);
    spread(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))));
    (lp, bob, p, c)
}

fn drop_due(lp: &mut LocalPeer) {
    spread(lp);
    lp.peers[1].engine.drop_lost_due().unwrap();
}

// spec/permissions.md §3, Keep: a person kicked keeps through its device; the device then removed
// from the person (no keep) erases that copy with the person's: erase wins along a path.
#[test]
fn device_removal_erases_what_its_person_kept_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9300, edge_of(Role::Admin), keeping(Role::Write));
    lp.peers[0].engine.demote(&c, &remove(p)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))), "the person's kick keeps");
    assert!(lp.peers[1].engine.kept_copies().contains(&c));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), None, "the device's removal erases it");
    assert!(!found(&mut lp, D_MARK));
    assert!(lp.peers[1].engine.kept_copies().is_empty());
}

// spec/permissions.md §3, Keep: the edge that decides is the one the node lost: removed from P
// (no keep), C goes though P's edge on it says keep; the same with the keep on the node's edge keeps
// C though P's edge on it does not say so, since P's edge did not end.
#[test]
fn the_edge_lost_decides_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9310, edge_of(Role::Admin), keeping(Role::Write));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), None);
    assert!(!found(&mut lp, D_MARK));
    let (mut lp, bob, p, c) = nested(9320, keeping(Role::Admin), edge_of(Role::Write));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))));
    assert!(lp.peers[1].engine.kept_copies().contains(&p) && lp.peers[1].engine.kept_copies().contains(&c));
}

// spec/permissions.md §3, Keep: an edge P's holder never read through (bob joined P after P's edge
// on C ended) keeps nothing of C: bob had C another way, whose end says erase.
#[test]
fn an_end_before_the_node_read_the_holder_keeps_nothing_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9330, edge_of(Role::Admin), keeping(Role::Write));
    lp.peers[0].engine.demote(&p, &remove(bob)).unwrap();
    lp.peers[0].engine.grant(&c, &bob, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&c, &remove(p)).unwrap();
    lp.peers[0].engine.grant(&p, &bob, &edge_of(Role::Admin)).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.drop_lost_due().unwrap();
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))), "reads directly");
    lp.peers[0].engine.demote(&c, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), None);
    assert!(!lp.peers[1].engine.kept_copies().contains(&c));
}

// spec/permissions.md §3, Keep: several ways in: the copy stays while one way's end keeps.
#[test]
fn any_path_keeps_spec_perm_3() {
    let (mut lp, bob, p, c) = nested(9340, edge_of(Role::Admin), keeping(Role::Write));
    lp.peers[0].engine.grant(&c, &bob, &edge_of(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&c, &remove(p)).unwrap();
    drop_due(&mut lp);
    assert!(lp.peers[1].engine.kept_copies().is_empty(), "still reads directly");
    lp.peers[0].engine.demote(&c, &remove(bob)).unwrap();
    drop_due(&mut lp);
    assert_eq!(read(&mut lp, c), Some(s(&big(D_MARK))));
    assert!(lp.peers[1].engine.kept_copies().contains(&c));
}

// spec/permissions.md §3, Keep: an `until` passing is a loss the node acts on by itself, with no role
// commit behind it and through a restart, keeping or erasing as the edge says.
#[test]
fn until_ending_spec_perm_3() {
    for (edge, seed) in [(keeping(Role::Read), 9350), (edge_of(Role::Read), 9355)] {
        let keep = edge.keep;
        let at = osis_base::WallMs(T0.0 + 3_600_000);
        let mut x = setup(seed, ct::Edge { until: Some(at), ..edge });
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        assert_eq!(x.lp.peers[1].engine.next_lost_due(), Some(at.0));
        reopen(&mut x.lp, 1, seed + 2).unwrap();
        x.lp.peers[1].clock.set(at);
        assert!(x.lp.peers[1].engine.lost_due());
        assert!(!x.lp.peers[1].engine.lost_received(), "by the time alone: node-sync hears its labels out first");
        x.lp.peers[1].engine.drop_lost_due().unwrap();
        if keep {
            assert_kept(&mut x);
        } else {
            assert_erased(&mut x);
        }
    }
}

// spec/permissions.md §3, Keep: a holder leaving keeps as its edge says: not its own choice.
#[test]
fn self_removal_keeps_as_the_edge_says_spec_perm_3() {
    for (edge, seed) in [(keeping(Role::Read), 9360), (edge_of(Role::Read), 9370)] {
        let keep = edge.keep;
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

// spec/permissions.md §3, Keep: content waiting when the node dropped stays out, though what it
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
    assert!(!x.lp.peers[1].engine.pending().is_empty(), "its author's chain has not arrived");
    let rm = *x.lp.peers[0].engine.demote(&d, &remove(pb)).unwrap().commits.last().unwrap();
    send(&mut x.lp, 0, 1, &[rm]);
    x.lp.peers[1].engine.drop_lost_due().unwrap();
    assert_kept(&mut x);
    send(&mut x.lp, 0, 1, &[g]);
    x.lp.peers[1].engine.reexamine().unwrap();
    assert_kept(&mut x);
    assert!(!found(&mut x.lp, LATE_MARK), "joined after the drop");
}

// spec/permissions.md §3, Keep; spec/commits.md §5: a waiting part a held purge emptied holds a stripped
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

// spec/permissions.md §3, Keep; §6: a roster snapshot carries the edge's `keep`.
#[test]
fn snapshot_carries_keep_spec_perm_6() {
    let mut x = setup(9430, keeping(Role::Read));
    let d = x.d;
    x.lp.peers[0].engine.roster_snapshot(&d, None).unwrap();
    spread(&mut x.lp);
    assert!(x.lp.peers[1].engine.epoch_start(&d).is_some(), "the walk starts at the snapshot");
    removed(&mut x);
    assert_kept(&mut x);
}

// spec/permissions.md §3, Keep: a restart between the removal's apply and the trigger reads `keep`
// from what it saved.
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

// spec/permissions.md §7: a move's copy keeps the roster's `keep`.
#[test]
fn move_carries_keep_spec_perm_7() {
    let x = setup(9450, keeping(Role::Read));
    let (mut lp, d, pb) = (x.lp, x.d, x.pb);
    let me = lp.peers[0].engine.tid();
    let (copy, _) = lp.peers[0].engine.move_to(&d, &me).unwrap();
    assert!(lp.peers[0].engine.roster(&copy).get(&pb).is_some_and(|e| e.keep));
}

// spec/permissions.md §3, Keep: the node's user may erase a copy, and what hangs on it.
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

// spec/permissions.md §3, Keep: a re-grant makes the node an ordinary holder: new content joins,
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
    removed(&mut x);
    assert_eq!(read(&mut x.lp, d), None, "this edge says erase");
    assert!(!found(&mut x.lp, D_MARK));
}

// spec/permissions.md §3, Keep; spec/sync.md §2: over a real host a copy leaves the label: no
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
    let done = net.engine(a).grant(&g, &bt, &keeping(Role::Read)).unwrap();
    let acts = net.sync(a).carry_out(done).unwrap();
    net.actions(a, acts);
    net.run();
    let done = net.engine(a).demote(&g, &remove(bt)).unwrap();
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

// spec/permissions.md §3, Keep: a link's joiner holds what the link says.
#[test]
fn link_carries_keep_spec_perm_3() {
    let mut lp = LocalPeer::of(vec![forensic_peer(9410, &osis_store::Faults::new()), forensic_peer(9411, &osis_store::Faults::new())], 9410);
    let pa = lp.peers[0].engine.create_person(&hosts()).unwrap().0.person;
    let pb = lp.peers[1].engine.create_person(&hosts()).unwrap().0.person;
    spread(&mut lp);
    let d = thing_of(&mut lp, 0, pa);
    let spec = osis_node::flows::LinkSpec { target: d, role: Role::Read, until: None, hosts: hosts(), peers: Vec::new(), single_use: false, keep: true };
    let (link, _, _) = lp.peers[0].engine.create_link(&pa, &spec).unwrap();
    spread(&mut lp);
    lp.peers[1].engine.redeem(&link, &pb, false).unwrap();
    spread(&mut lp);
    let k = link.k;
    assert!(lp.peers[1].engine.roster(&k).get(&pb).is_some_and(|e| e.keep), "the joiner's edge");
    assert!(lp.peers[0].engine.roster(&d).get(&k).is_some_and(|e| e.keep), "K's edge");
}

/// A random history of edge writes by alice over C, P and bob (`nested`), in the order it was made.
fn random_history(seed: u64) -> (LocalPeer, Tid, Tid, Vec<osis_base::CommitId>) {
    let mut rng = crate::order::Rng(seed);
    let device = if rng.below(2) == 0 { keeping(Role::Admin) } else { edge_of(Role::Admin) };
    let member = if rng.below(2) == 0 { keeping(Role::Write) } else { edge_of(Role::Write) };
    let (mut lp, bob, p, c) = nested(seed, device, member);
    lp.peers[0].engine.grant(&c, &bob, &if rng.below(2) == 0 { keeping(Role::Read) } else { edge_of(Role::Read) }).unwrap();
    spread(&mut lp);
    let mut ids = Vec::new();
    for _ in 0..3 + rng.below(4) {
        lp.peers[0].clock.advance(1_000);
        lp.peers[1].clock.advance(1_000);
        let (t, h) = [(c, bob), (c, p), (p, bob)][rng.below(3) as usize];
        let keep = rng.below(2) == 0;
        let role = if t == p { Role::Admin } else { Role::Read };
        let live = lp.peers[0].engine.roster(&t).contains_key(&h);
        let done = match (rng.below(3), live) {
            (0, _) => lp.peers[0].engine.grant(&t, &h, &ct::Edge { keep, ..edge_of(role) }).ok(),
            (1, true) => lp.peers[0].engine.demote(&t, &remove(h)).ok(),
            (_, true) => {
                let new = ct::Edge { until: Some(lp.peers[0].engine.now()), keep, ..edge_of(role) };
                lp.peers[0].engine.demote(&t, &Demotion { holder: h, new: Some(new), presync: PreSync::Synced }).ok()
            }
            _ => None,
        };
        ids.extend(done.into_iter().flat_map(|d| d.commits));
    }
    (lp, p, c, ids)
}

fn any_order_seed(seed: u64) -> u64 {
    let (mut whole, p, c, ids) = random_history(seed);
    send(&mut whole, 0, 1, &ids);
    whole.peers[1].engine.drop_lost_due().unwrap();
    let (mut x, _, _, same) = random_history(seed);
    assert_eq!(ids, same, "the history repeats at a seed");
    let mut order = same;
    let mut rng = crate::order::Rng(seed ^ 0x55);
    for i in (1..order.len()).rev() {
        order.swap(i, rng.below(i as u64 + 1) as usize);
    }
    for id in &order {
        send(&mut x, 0, 1, &[*id]);
        x.peers[1].engine.drop_lost_due().unwrap();
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

fn any_order_replay(s: u64) -> String {
    format!("OSIS_KEEP_START={s} OSIS_KEEP_SEEDS=1 cargo test --workspace --test it keep::any_order_keeps_no_more_large -- --ignored --exact")
}

// spec/permissions.md §3, Keep: in any arrival order, with the trigger run after each commit, a node
// keeps no more than a node given the whole history at once; what it does not keep is gone from the
// store; a copy holds no secret. FOUND: a kept mark not rechecking that the node read the holder (11124),
// a rotation arriving after the removal giving back a secret (11876), a re-grant with no secret ending
// the mark and a loss then leaving the content unmarked (886071).
#[test]
fn any_order_keeps_no_more_spec_perm_3() {
    let seeds = [11124, 11876, 886071, 886741, 889051, 9700];
    let kept: u64 = osis_base::testenv::run_seeds("keep::any_order_keeps_no_more", &seeds, false, any_order_replay, any_order_seed).into_iter().sum();
    assert!(kept > 0, "some seed kept");
}

/// Seeds: OSIS_KEEP_START, OSIS_KEEP_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn any_order_keeps_no_more_large() {
    osis_base::testenv::Seeds::from_env("OSIS_KEEP_START", "OSIS_KEEP_SEEDS", 0..200).run("keep::any_order_keeps_no_more_large", any_order_replay, any_order_seed);
}
