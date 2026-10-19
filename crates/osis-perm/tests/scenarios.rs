//! Named scenarios of notes/permissions.md and models/membership, layer 1 (spec/permissions.md
//! §2, §5.1, §6, §9). Receipt times give each demoter's frontier.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use common::*;
use osis_core::Role::{Admin, Read, Write};
use osis_core::{Role, Tid};
use osis_perm::{At, Class, Edge, Timeline, WriteId};

fn eval(w: &World) -> Timeline {
    Timeline::evaluate(&w.held())
}

fn role(tl: &Timeline, n: Tid, t: Tid) -> Option<Role> {
    tl.role(&n, &t, At::END)
}

fn edge_role(tl: &Timeline, member: Tid, t: Tid) -> Option<Role> {
    tl.roster(&t, At::END).get(&member).map(|e| e.role)
}

/// Owner O owns G; A1..A3 admins, M writer.
fn group() -> (World, Vec<Tid>, Tid) {
    let mut w = World::new();
    let n = w.nodes(5);
    let g = w.thing(n[0]);
    for &a in &n[1..4] {
        w.set(n[0], g, a, edge(Admin), 1, &n.iter().map(|x| (*x, 1)).collect::<Vec<_>>());
    }
    w.set(n[0], g, n[4], edge(Write), 1, &n.iter().map(|x| (*x, 1)).collect::<Vec<_>>());
    (w, n, g)
}

/// §5.1: mutual removal resolves to the earlier timestamp.
#[test]
fn mutual_removal_earlier_wins() {
    let (mut w, n, g) = group();
    w.set(n[1], g, n[2], None, 2, &[]);
    w.set(n[2], g, n[1], None, 3, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, n[1], g), edge_role(&tl, n[2], g)), (Some(Admin), None));
}

/// §5.1 frontier: a stolen admin device's backdated removals stand iff the node removing the
/// device had received them before its revoke; another admin having seen them is no witness.
#[test]
fn stolen_device_backdated_removals() {
    for owner_saw in [false, true] {
        let (mut w, n, g) = group();
        let recv: Vec<(Tid, u64)> = if owner_saw { vec![(n[3], 5), (n[0], 6)] } else { vec![(n[3], 5)] };
        w.set(n[1], g, n[2], None, 2, &recv);
        w.set(n[1], g, n[4], None, 3, &recv);
        w.set(n[0], g, n[1], None, 10, &[]);
        let tl = eval(&w);
        let expect = if owner_saw { (None, None) } else { (Some(Admin), Some(Write)) };
        assert_eq!((edge_role(&tl, n[2], g), edge_role(&tl, n[4], g)), expect, "owner saw {owner_saw}");
        assert_eq!(edge_role(&tl, n[1], g), None);
    }
}

/// §5.1: the owner's further-backdated revoke of the stolen device cancels its removal.
#[test]
fn owner_further_backdated_revoke_cancels() {
    let (mut w, n, g) = group();
    w.set(n[1], g, n[2], None, 5, &[(n[0], 6)]);
    w.set(n[0], g, n[1], None, 4, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, n[1], g), edge_role(&tl, n[2], g)), (None, Some(Admin)));
    assert!(tl.dropped().is_empty());
}

/// §5.1 step 4: a cycle of removed witnesses validates nothing; a grant seen only by its
/// beneficiary falls with its author.
#[test]
fn self_witnessed_grant_falls() {
    let (mut w, n, g) = group();
    let z = w.nodes(6)[5];
    w.set(n[1], g, z, edge(Admin), 2, &[(z, 2)]);
    w.set(n[0], g, n[1], None, 5, &[]);
    w.set(z, g, n[1], edge(Admin), 6, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, z, g), edge_role(&tl, n[1], g)), (None, None));
}

/// §5.1 step 3-4: two edge-admin paths to doc D through teams T1, T2. Removing one path is no
/// fall; removing the second audits the grant unless that remover had received it.
#[test]
fn two_admin_paths_class_attribution() {
    for seen in [false, true] {
        let mut w = World::new();
        let n = w.nodes(5);
        let (t1, t2, d) = (w.thing(n[0]), w.thing(n[1]), w.thing(n[0]));
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(n[0], t1, n[3], edge(Admin), 0, &all);
        w.set(n[1], t2, n[3], edge(Admin), 0, &all);
        w.set(n[0], d, t1, edge(Admin), 0, &all);
        w.set(n[0], d, t2, edge(Admin), 0, &all);
        let recv: Vec<(Tid, u64)> = if seen { vec![(n[1], 2)] } else { vec![] };
        w.set(n[3], d, n[4], edge(Admin), 1, &recv);
        w.set(n[0], t1, n[3], None, 3, &[]);
        assert_eq!(role(&eval(&w), n[4], d), Some(Admin));
        w.set(n[1], t2, n[3], None, 4, &[]);
        assert_eq!(role(&eval(&w), n[4], d), if seen { Some(Admin) } else { None }, "seen {seen}");
    }
}

/// §5.1 step 4: owner chain plus edge. Whichever path goes first, the removal leaving the
/// node without admin on G audits its edge-class grant.
#[test]
fn chain_and_edge_paths() {
    for edge_first in [true, false] {
        let mut w = World::new();
        let n = w.nodes(5);
        let p = w.thing(n[0]);
        let g = w.thing(p);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(n[0], g, n[3], edge(Admin), 0, &all);
        w.set(n[0], p, n[2], edge(Admin), 0, &all);
        w.set(n[3], g, n[4], edge(Admin), 1, &[]);
        w.set(n[2], p, n[3], edge(Admin), 2, &[]);
        let (te, tp) = if edge_first { (3, 4) } else { (4, 3) };
        w.set(n[2], g, n[3], None, te, &[]);
        w.set(n[0], p, n[3], None, tp, &[]);
        let tl = eval(&w);
        assert_eq!(role(&tl, n[4], g), None, "edge first {edge_first}");
        assert_eq!(tl.class(&n[3], &g, At::END), Class::None);
    }
}

/// §5.1 step 4, transitive: a fall on P audits writes two ownership levels below, but not
/// where the node keeps the owner chain by an admin edge on Q.
#[test]
fn transitive_ownership_audit() {
    for keeps_q in [false, true] {
        let mut w = World::new();
        let n = w.nodes(5);
        let p = w.thing(n[0]);
        let q = w.thing(p);
        let d = w.thing(q);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(n[0], p, n[3], edge(Admin), 0, &all);
        if keeps_q {
            w.set(n[0], q, n[3], edge(Admin), 0, &all);
        }
        let grant = w.set(n[3], d, n[4], edge(Admin), 1, &[]);
        w.set(n[0], p, n[3], None, 3, &[]);
        let tl = eval(&w);
        assert_eq!(role(&tl, n[4], d), if keeps_q { Some(Admin) } else { None }, "keeps Q {keeps_q}");
        assert_eq!(tl.dropped().contains_key(&WriteId::Op(grant, 0)), !keeps_q);
    }
}

/// §2 self-removal: never dropped, so a later demotion of its author cannot hand back what
/// it gave up; the next explicit removal by another node audits as if the member were admin.
#[test]
fn self_removal_finalized_by_explicit_removal() {
    let (mut w, n, g) = group();
    let z = w.nodes(6)[5];
    w.set(n[1], g, n[1], None, 5, &[(n[0], 5)]);
    let forged = w.set(n[1], g, z, edge(Admin), 4, &[]);
    assert_eq!(edge_role(&eval(&w), z, g), Some(Admin));
    w.set(n[0], g, n[1], None, 10, &[]);
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId::Op(forged, 0)));
    assert_eq!(edge_role(&tl, z, g), None);
    assert!(tl.dropped().keys().all(|d| d.commit() == forged));
}

/// Link K: L (node 1) holds (write, invite write) on K owned by sharer 0; J, Z joiners, Y member.
fn link(l_edge: Option<Edge>) -> (World, Vec<Tid>, Tid) {
    let mut w = World::new();
    let n = w.nodes(5);
    let k = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], k, n[1], l_edge, 0, &all);
    w.set(n[0], k, n[4], edge(Write), 0, &all);
    (w, n, k)
}

/// §9 `until` finalization: a backdated join after expiry stands until the sharer's plain
/// removal of L drops it; the honest join stays.
#[test]
fn link_until_backdated_join_finalized() {
    let (mut w, n, k) = link(edge_inv(Write, Some(Write), Some(5)));
    let (l, j, z) = (n[1], n[2], n[3]);
    w.set(l, k, j, edge(Write), 3, &[(n[0], 3)]);
    let forged = w.set(l, k, z, edge(Write), 4, &[]);
    assert_eq!(edge_role(&eval(&w), z, k), Some(Write));
    w.set(n[0], k, l, None, 10, &[]);
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId::Op(forged, 0)));
    let r = tl.roster(&k, At::now(ts(20)));
    assert_eq!((r.get(&j).map(|e| e.role), r.get(&z), r.get(&l)), (Some(Write), None, None));
}

/// §9 single use: a forged earlier redemption burns the link until the sharer's removal of L
/// drops it with its self-removal; then the honest redemption applies.
#[test]
fn single_use_second_redemption_finalized() {
    let (mut w, n, k) = link(edge_inv(Write, Some(Write), None));
    let (l, j, z) = (n[1], n[2], n[3]);
    w.commit(l, 3, &[(k, j, edge(Write)), (k, l, None)], &[(n[0], 4)]);
    let forged = w.commit(l, 2, &[(k, z, edge(Write)), (k, l, None)], &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, j, k), edge_role(&tl, z, k)), (None, Some(Write)));
    w.set(n[0], k, l, None, 10, &[]);
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId::Op(forged, 0)) && tl.dropped().contains_key(&WriteId::Op(forged, 1)));
    assert_eq!((edge_role(&tl, j, k), edge_role(&tl, z, k), edge_role(&tl, l, k)), (Some(Write), None, None));
}

/// §5.1: a redemption's ops are judged separately: the add fails (Z already has an edge) but
/// L's self-removal applies.
#[test]
fn redemption_ops_judged_separately() {
    let (mut w, n, k) = link(edge_inv(Write, Some(Write), None));
    let (l, z) = (n[1], n[3]);
    w.set(n[0], k, z, edge(Write), 2, &[]);
    let r = w.commit(l, 2, &[(k, z, edge(Read)), (k, l, None)], &[]);
    let tl = eval(&w);
    assert!(!tl.is_applied(&WriteId::Op(r, 0)) && tl.is_applied(&WriteId::Op(r, 1)));
    assert_eq!((edge_role(&tl, l, k), edge_role(&tl, z, k)), (None, Some(Write)));
}

/// §5.1 step 1: two holders of one link key redeem at one `ts`; the commit ID decides.
#[test]
fn link_holders_tie_broken_by_commit_id() {
    for j_first in [true, false] {
        let (mut w, n, k) = link(edge_inv(Write, Some(Write), None));
        let (l, j, z) = (n[1], n[2], n[3]);
        let (a, b) = if j_first { (cid(1), cid(2)) } else { (cid(2), cid(1)) };
        w.commit_id(a, l, 3, &[(k, j, edge(Write)), (k, l, None)], &[]);
        w.commit_id(b, l, 3, &[(k, z, edge(Write)), (k, l, None)], &[]);
        let tl = eval(&w);
        let expect = if j_first { (Some(Write), None) } else { (None, Some(Write)) };
        assert_eq!((edge_role(&tl, j, k), edge_role(&tl, z, k)), expect);
    }
}

/// §2 invite power: an invite holder cannot remove, demote or change others, raise itself, or
/// grant above its invite; it can add an actor without an edge.
#[test]
fn invite_holder_limits() {
    let (_, n, _) = link(None);
    let (i, j, z, y) = (n[1], n[2], n[3], n[4]);
    let tries: Vec<(Tid, Option<Edge>)> = vec![
        (y, None),
        (y, edge(Read)),
        (y, edge_inv(Write, Some(Write), None)),
        (j, edge(Read)),
        (i, edge_inv(Admin, Some(Admin), None)),
        (z, edge(Admin)),
    ];
    for (x, e) in tries {
        let (mut w, _, k) = link(edge_inv(Write, Some(Write), None));
        w.set(n[0], k, j, edge_inv(Write, Some(Write), None), 0, &[]);
        let before = eval(&w).roster(&k, At::END);
        let c = w.set(i, k, x, e, 2, &[(n[0], 2)]);
        let tl = eval(&w);
        assert!(!tl.is_applied(&WriteId::Op(c, 0)), "{x:?} := {e:?}");
        assert_eq!(tl.roster(&k, At::END), before);
    }
    let (mut w, _, k) = link(edge_inv(Write, Some(Write), None));
    w.set(i, k, z, edge(Write), 2, &[]);
    assert_eq!(edge_role(&eval(&w), z, k), Some(Write));
    assert_eq!(eval(&w).invite(&i, &k, At::END), Some(Write));
}

/// §2: invitees vouching for each other fail: I1's backdated grant of I2 (removed by the owner,
/// unseen) drops, so I2's re-add of I1 never applies.
#[test]
fn invitees_vouching_for_each_other() {
    let (mut w, n, k) = link(edge_inv(Write, Some(Write), None));
    let (i1, i2) = (n[1], n[2]);
    w.set(i1, k, i2, edge_inv(Write, Some(Write), None), 4, &[(i2, 4)]);
    w.set(n[0], k, i1, None, 5, &[]);
    w.set(i2, k, i1, edge_inv(Write, Some(Write), None), 6, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, i1, k), edge_role(&tl, i2, k)), (None, None));
}

/// §5.1 step 4, invite levels: lowering an invite from write to read audits grants made at
/// invite write; grants made at invite read stay.
#[test]
fn invite_audit_by_level() {
    let (mut w, n, k) = link(edge_inv(Write, Some(Read), None));
    let (i, j, z) = (n[1], n[2], n[3]);
    w.set(i, k, j, edge(Read), 2, &[]);
    w.set(n[0], k, i, edge_inv(Write, Some(Write), None), 3, &[(i, 3)]);
    w.set(i, k, z, edge(Read), 4, &[]);
    w.set(n[0], k, i, edge_inv(Write, Some(Read), None), 6, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, j, k), edge_role(&tl, z, k)), (Some(Read), None));
}

/// Finding: drops are sticky. Admin 1 removes 2 without having received 2's grant of 3; the
/// owner removes 1 without having received that removal: it drops and 2 is back, but 2's
/// grant stays dropped (re-grant repairs).
#[test]
fn sticky_drop_outlives_its_cause() {
    for grantor in [edge_inv(Write, Some(Write), None), edge(Admin)] {
        let mut w = World::new();
        let n = w.nodes(4);
        let g = w.thing(n[0]);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(n[0], g, n[1], edge(Admin), 0, &all);
        w.set(n[0], g, n[2], grantor, 0, &all);
        w.set(n[2], g, n[3], edge(Write), 2, &[(n[0], 2)]);
        w.set(n[1], g, n[2], None, 4, &[]);
        w.set(n[0], g, n[1], None, 6, &[]);
        let tl = eval(&w);
        assert_eq!(tl.roster(&g, At::END).get(&n[2]).copied(), grantor);
        assert_eq!(edge_role(&tl, n[3], g), None);
    }
}

/// §6: a stolen device's snapshot of G is undone by its backdated removal from P (G falls back
/// to the walk); a removal after it, by a remover that had received it, leaves it standing.
#[test]
fn stolen_device_snapshot_undone_by_backdated_removal() {
    for (removal_t, d2_saw, stands) in [(3, true, false), (7, true, true), (7, false, false)] {
        let mut w = World::new();
        let n = w.nodes(6);
        let (d1, d2, a, b, z) = (n[1], n[2], n[3], n[4], n[5]);
        let p = w.thing(n[0]);
        let g = w.thing(p);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(n[0], p, d1, edge(Admin), 0, &all);
        w.set(n[0], p, d2, edge(Admin), 0, &all);
        w.set(n[0], g, a, edge(Admin), 0, &all);
        w.set(n[0], g, b, edge(Write), 0, &all);
        let recv: Vec<(Tid, u64)> = if d2_saw { vec![(d2, 6)] } else { vec![] };
        let s = w.snapshot(d1, g, &[(a, Edge::new(Admin)), (b, Edge::new(Write)), (z, Edge::new(Admin))], 5, &recv);
        w.set(d2, p, d1, None, removal_t, &[]);
        let tl = eval(&w);
        assert_eq!(tl.epoch_start(&g), stands.then_some(s), "removal at {removal_t}, saw {d2_saw}");
        assert_eq!(edge_role(&tl, z, g), stands.then_some(Admin));
        assert_eq!((edge_role(&tl, a, g), edge_role(&tl, b, g)), (Some(Admin), Some(Write)));
    }
}

/// §6: snapshots by an edge admin are never epoch starts; a forged one by a removed device
/// neither (after its removal: no authority; backdated: dropped by the removal's frontier).
#[test]
fn snapshot_authority() {
    let mut w = World::new();
    let n = w.nodes(6);
    let (d1, d2, a, z) = (n[1], n[2], n[3], n[5]);
    let p = w.thing(n[0]);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], p, d1, edge(Admin), 0, &all);
    w.set(n[0], p, d2, edge(Admin), 0, &all);
    w.set(n[0], g, a, edge(Admin), 0, &all);
    w.snapshot(a, g, &[(z, Edge::new(Admin))], 2, &[]);
    w.set(d2, p, d1, None, 4, &[(n[0], 4), (a, 4)]);
    w.snapshot(d1, g, &[(z, Edge::new(Admin))], 8, &[]);
    w.snapshot(d1, g, &[(z, Edge::new(Admin))], 3, &[]);
    let tl = eval(&w);
    assert_eq!(tl.epoch_start(&g), None);
    assert_eq!((edge_role(&tl, a, g), edge_role(&tl, z, g)), (Some(Admin), None));
    let s = w.snapshot(d2, g, &[(a, Edge::new(Admin))], 6, &[]);
    assert_eq!(eval(&w).epoch_start(&g), Some(s));
}

/// §6: a pre-snapshot grant arriving after the snapshot is ignored; post-snapshot churn
/// applies on top, and a verifier holding only the snapshot and later writes agrees.
#[test]
fn owner_snapshot_then_churn_and_compaction() {
    let mut w = World::new();
    let n = w.nodes(6);
    let (a, b, z) = (n[3], n[4], n[5]);
    let g = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    let g1 = w.set(n[0], g, a, edge(Admin), 0, &all);
    let g2 = w.set(n[0], g, b, edge(Write), 0, &all);
    let late = w.set(a, g, z, edge(Admin), 2, &[]);
    let s = w.snapshot(n[0], g, &[(a, Edge::new(Admin)), (b, Edge::new(Write)), (z, Edge::new(Admin))], 5, &[]);
    w.set(z, g, b, edge(Admin), 6, &[]);
    w.set(a, g, z, None, 8, &[]);
    let tl = eval(&w);
    assert_eq!(tl.epoch_start(&g), Some(s));
    assert_eq!((edge_role(&tl, a, g), edge_role(&tl, b, g), edge_role(&tl, z, g)), (Some(Admin), Some(Write), None));
    let compacted = Timeline::evaluate(&w.held_without(&[g1, g2, late].into_iter().collect()));
    assert_eq!(compacted.roster(&g, At::END), tl.roster(&g, At::END));
}

/// §5.1 step 5: the result is a function of the held set, not of its order.
#[test]
fn held_order_irrelevant() {
    let (mut w, n, g) = group();
    w.set(n[1], g, n[2], None, 2, &[]);
    w.set(n[2], g, n[1], None, 2, &[]);
    w.set(n[3], g, n[4], None, 3, &[(n[0], 3)]);
    w.set(n[0], g, n[3], None, 4, &[]);
    let tl = eval(&w);
    w.commits.reverse();
    let tr = eval(&w);
    assert_eq!(tl.roster(&g, At::END), tr.roster(&g, At::END));
    assert_eq!(tl.dropped(), tr.dropped());
}
