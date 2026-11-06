//! Named scenarios of notes/permissions.md and core/test/roles-model, layer 1 (spec/permissions.md
//! §1, §2, §3, §5.1, §7). Receipt times give each demoter's frontier.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::Role::{Admin, Read, Write};
use osis_base::{Role, Tid};
use osis_perm::EdgeEnd;
use osis_perm::{At, Class, Edge, Timeline, WriteId};

fn eval(w: &World) -> Timeline {
    Timeline::evaluate(&w.held())
}

fn role(tl: &Timeline, n: Tid, t: Tid) -> Option<Role> {
    tl.role(&n, &t, At::END)
}

fn edge_role(tl: &Timeline, holder: Tid, t: Tid) -> Option<Role> {
    tl.roster(&t, At::END).get(&holder).map(|e| e.role)
}

/// n0 is G's first admin; A1..A3 admins, M writer.
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

/// §5.1 frontier: a stolen admin node's backdated removals stand iff the node removing the
/// node had received them before its revoke; another admin having seen them is no witness.
#[test]
fn stolen_node_backdated_removals() {
    for remover_saw in [false, true] {
        let (mut w, n, g) = group();
        let recv: Vec<(Tid, u64)> = if remover_saw { vec![(n[3], 5), (n[0], 6)] } else { vec![(n[3], 5)] };
        w.set(n[1], g, n[2], None, 2, &recv);
        w.set(n[1], g, n[4], None, 3, &recv);
        w.set(n[0], g, n[1], None, 10, &[]);
        let tl = eval(&w);
        let expect = if remover_saw { (None, None) } else { (Some(Admin), Some(Write)) };
        assert_eq!((edge_role(&tl, n[2], g), edge_role(&tl, n[4], g)), expect, "remover saw {remover_saw}");
        assert_eq!(edge_role(&tl, n[1], g), None);
    }
}

/// §5.1: the earliest stamp wins between admins removing each other: n0's further-backdated
/// revoke of the stolen node n1 cancels n1's removal of n2. Stated limit until disputes are
/// settled per node (notes/owner-removal-plan.md step 3): n1 backdating further still takes G
/// back, n0 being an ordinary admin.
#[test]
fn further_backdated_revoke_cancels() {
    let (mut w, n, g) = group();
    w.set(n[1], g, n[2], None, 5, &[(n[0], 6)]);
    w.set(n[0], g, n[1], None, 4, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, n[1], g), edge_role(&tl, n[2], g)), (None, Some(Admin)));
    assert!(tl.dropped().is_empty());
    w.set(n[1], g, n[0], None, 3, &[]);
    let tl = eval(&w);
    assert_eq!((edge_role(&tl, n[0], g), edge_role(&tl, n[1], g), edge_role(&tl, n[2], g)), (None, Some(Admin), None));
}

/// §5.1 step 4: a cycle of removed witnesses validates nothing; a grant seen only by its
/// beneficiary falls with its author.
#[test]
fn self_witnessed_grant_falls() {
    let (mut w, n, g) = group();
    let z = w.nodes_salted(1, 99)[0];
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

/// §5.1 step 4: a record edge path plus an edge. Whichever path goes first, the removal leaving
/// the node without admin on G audits its grant.
#[test]
fn record_edge_and_edge_paths() {
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

/// §5.1 step 4, transitive: a fall on P audits writes two record edges below, but not where
/// the node keeps admin on D by an admin edge on Q.
#[test]
fn transitive_record_edge_audit() {
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
        assert_eq!(tl.dropped().contains_key(&WriteId(grant, 0)), !keeps_q);
    }
}

/// §2 self-removal: audits nothing; the next explicit removal by another node (which saw the
/// leave, so the leave stands) audits as if the holder were admin.
#[test]
fn self_removal_finalized_by_explicit_removal() {
    let (mut w, n, g) = group();
    let z = w.nodes_salted(1, 99)[0];
    w.set(n[1], g, n[1], None, 5, &[(n[0], 5)]);
    let forged = w.set(n[1], g, z, edge(Admin), 4, &[]);
    assert_eq!(edge_role(&eval(&w), z, g), Some(Admin));
    w.set(n[0], g, n[1], None, 10, &[]);
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId(forged, 0)));
    assert_eq!(edge_role(&tl, z, g), None);
    assert!(tl.dropped().keys().all(|d| d.commit() == forged));
}

/// §5.1 Frontier (core/test/tla/roles M1, chain-write forgery): after n1 removes n2 having received
/// nothing of n2's, n2's backdated write on n1's own admin edge (admin until 9, stamped 6) is
/// not covered by n1's frontier: it drops and n1 keeps its role.
#[test]
fn removed_admin_cannot_backdate_removers_edge_spec_permissions_5_1() {
    let (mut w, n, g) = group();
    let r = w.set(n[1], g, n[2], None, 8, &[]);
    let forged = w.set(n[2], g, n[1], edge_inv(Admin, None, Some(9)), 6, &[]);
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId(forged, 0)));
    assert!(tl.is_applied(&WriteId(r, 0)));
    assert_eq!(role(&tl, n[1], g), Some(Admin));
    assert_eq!(edge_role(&tl, n[2], g), None);
}

/// §5.1 Frontier: the same forgery by the remover's own grantor. X granted A admin (A got
/// it); A removes X; X's backdated write on A's edge (admin until 9, stamped 6) drops, while
/// X's grant of A, which A's frontier lists, stands.
#[test]
fn grantor_cannot_backdate_removers_edge_spec_permissions_5_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let g = w.thing(n[0]);
    let (a, x) = (n[1], n[2]);
    w.set(n[0], g, x, edge(Admin), 1, &n.iter().map(|y| (*y, 1)).collect::<Vec<_>>());
    let grant = w.set(x, g, a, edge(Admin), 2, &[(a, 2)]);
    let r = w.set(a, g, x, None, 8, &[]);
    let forged = w.set(x, g, a, edge_inv(Admin, None, Some(9)), 6, &[]);
    let tl = eval(&w);
    assert!(tl.is_applied(&WriteId(grant, 0)) && tl.is_applied(&WriteId(r, 0)));
    assert!(tl.dropped().contains_key(&WriteId(forged, 0)));
    assert_eq!(tl.roster(&g, At::END).get(&a).map(|e| (e.role, e.until)), Some((Admin, None)));
    assert_eq!(edge_role(&tl, x, g), None);
}

/// §5.1 Frontier: a chain write the demoter received counts (its frontier lists it), so an
/// admin removes the admin that last set its own edge and keeps what that write gave it.
#[test]
fn received_chain_write_covered_spec_permissions_5_1() {
    let (mut w, n, g) = group();
    let set = w.set(n[2], g, n[1], edge_inv(Admin, Some(Write), None), 3, &[(n[1], 3)]);
    let r = w.set(n[1], g, n[2], None, 8, &[]);
    let tl = eval(&w);
    assert!(tl.is_applied(&WriteId(set, 0)) && tl.is_applied(&WriteId(r, 0)));
    assert!(tl.dropped().is_empty());
    assert_eq!(tl.roster(&g, At::END).get(&n[1]).and_then(|e| e.invite), Some(Write));
}

/// Link K: L (node 1) holds (write, invite write) on K owned by sharer 0; J, Z joiners, Y holder.
fn link(l_edge: Option<Edge>) -> (World, Vec<Tid>, Tid) {
    let mut w = World::new();
    let n = w.nodes(5);
    let k = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], k, n[1], l_edge, 0, &all);
    w.set(n[0], k, n[4], edge(Write), 0, &all);
    (w, n, k)
}

/// §7 `until` finalization: a backdated join after expiry stands until the sharer's plain
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
    assert!(tl.dropped().contains_key(&WriteId(forged, 0)));
    let r = tl.roster(&k, At::now(ts(20)));
    assert_eq!((r.get(&j).map(|e| e.role), r.get(&z), r.get(&l)), (Some(Write), None, None));
}

/// §7 single use: a forged earlier redemption burns the link until the sharer's removal of L
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
    assert!(tl.dropped().contains_key(&WriteId(forged, 0)) && tl.dropped().contains_key(&WriteId(forged, 1)));
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
    assert!(!tl.is_applied(&WriteId(r, 0)) && tl.is_applied(&WriteId(r, 1)));
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
// spec/permissions.md §2 (invite scope)
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
        assert!(!tl.is_applied(&WriteId(c, 0)), "{x:?} := {e:?}");
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

/// §2 self-removal / §5.1: A is the first admin of group G and doc T; X admin of G, G admin of
/// T; X grants Y admin on T unseen by A. A removes G from T: with admin on T by T's record
/// edge this is an explicit demotion, not a self-removal, so Y's grant is dropped. When G's
/// first admin is someone else, the same.
#[test]
fn group_removal_by_first_admin_of_both() {
    for a_first_of_g in [true, false] {
        let mut w = World::new();
        let n = w.nodes(4);
        let (a, x, y, o) = (n[0], n[1], n[2], n[3]);
        let g_first = if a_first_of_g { a } else { o };
        let g = w.thing(g_first);
        let t = w.thing(a);
        w.set(g_first, g, x, edge(Admin), 1, &[]);
        w.set(a, t, g, edge(Admin), 2, &[]);
        let grant = w.set(x, t, y, edge(Admin), 3, &[]);
        let rm = w.set(a, t, g, None, 10, &[]);
        let tl = eval(&w);
        assert_eq!(role(&tl, y, t), None, "A first admin of G {a_first_of_g}");
        assert!(tl.dropped().contains_key(&WriteId(grant, 0)));
        assert_eq!(tl.applied()[&WriteId(rm, 0)].attr, osis_perm::Attr::By(Class::Edge));
    }
}

/// §1: a first admin is an ordinary admin: another admin removes it (its record edge, stored
/// nowhere, ends like any edge), a third grants it read, and its own removal of the remover
/// afterwards applies nothing.
// spec/permissions.md §1 (first admin removable)
#[test]
fn first_admin_removable_by_admins() {
    let (mut w, n, g) = group();
    let tl = eval(&w);
    assert_eq!(edge_role(&tl, n[0], g), Some(Admin), "the record edge is in the roster");
    w.set(n[1], g, n[0], None, 2, &[]);
    let tl = eval(&w);
    assert_eq!(role(&tl, n[0], g), None);
    assert_eq!(edge_role(&tl, n[0], g), None);
    w.set(n[2], g, n[0], edge(Read), 3, &[]);
    let tl = eval(&w);
    assert_eq!(role(&tl, n[0], g), Some(Read));
    w.set(n[0], g, n[1], None, 4, &[]);
    let tl = eval(&w);
    assert_eq!(role(&tl, n[0], g), Some(Read));
    assert_eq!(edge_role(&tl, n[1], g), Some(Admin));
}

/// §1: a first admin that removes its own record edge leaves by self-removal (audits nothing),
/// and a later explicit write on the edge restores it for the audit.
// spec/permissions.md §1 (first admin removable), §2 (self-removal)
#[test]
fn first_admin_leaves_by_self_removal() {
    let (mut w, n, g) = group();
    let leave = w.set(n[0], g, n[0], None, 2, &[]);
    let tl = eval(&w);
    assert!(tl.is_applied(&WriteId(leave, 0)));
    assert!(matches!(tl.applied()[&WriteId(leave, 0)].attr, osis_perm::Attr::SelfRemoval(Class::Edge, t) if t == g));
    assert_eq!(role(&tl, n[0], g), None);
    assert!(tl.lowered_unaudited(&n[0], &g));
    assert_eq!(tl.role_lowered_unaudited(&n[0], &g), Some(Admin));
}

/// §1: edges are written only by admins: a writer's grant, raise or removal never applies.
// spec/permissions.md §1 (role-class by admins)
#[test]
fn writer_cannot_write_edges() {
    let (mut w0, n, g) = group();
    let z = w0.nodes_salted(1, 9)[0];
    for (x, e) in [(z, edge(Read)), (n[4], edge(Admin)), (n[1], None), (n[2], edge(Read))] {
        let mut w = w0.clone();
        let before = eval(&w).roster(&g, At::END);
        let c = w.set(n[4], g, x, e, 2, &[]);
        let tl = eval(&w);
        assert!(!tl.is_applied(&WriteId(c, 0)), "{x:?} := {e:?}");
        assert_eq!(tl.roster(&g, At::END), before);
    }
}

/// §5.1 step 4 (sticky residue, notes/permissions.md): n1 removes n2 (admin) from G, a genuine
/// fall that drops n2's grant of n3 (unseen by n1): no residue. Then n0 removes n1, dropping
/// n1's removal of n2; the grant stays dropped though its cause no longer applies: residue.
#[test]
fn residue_classifies_sticky_and_genuine_spec_perm_5() {
    let mut w = World::new();
    let n = w.nodes(4);
    let g = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], g, n[1], edge(Admin), 0, &all);
    w.set(n[0], g, n[2], edge(Admin), 0, &all);
    w.set(n[2], g, n[3], edge(Write), 2, &[(n[0], 2)]);
    w.set(n[1], g, n[2], None, 4, &[]);
    let tl = eval(&w);
    assert_eq!(tl.dropped().len(), 1);
    assert!(residue(&tl).is_empty(), "a genuine fall is no residue");
    w.set(n[0], g, n[1], None, 6, &[]);
    let tl = eval(&w);
    assert_eq!(tl.dropped().len(), 2);
    assert_eq!(residue(&tl).len(), 1);
}

/// §5.1 (OSIS_PERM_SEED=3313): n2 removes n1 from P unseen, so n1's grant of admin on G to n2
/// does not apply and n2's own lowering of that edge to write is a raise through P's record
/// edge, which k's removal of n2 audits. That removal also drops n2's removal of n1; on the
/// restart n1's grant applies, so at k's removal n2 keeps admin on G by that grant: no fall on
/// G in the settled walk explains the dropped raise (sticky residue, notes/permissions.md).
#[test]
fn self_removal_dropped_with_sticky_residue_spec_permissions_5_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let k = n[0];
    let p = w.thing(k);
    let g = w.thing(p);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, n[1], edge(Admin), 0, &all0);
    w.set(k, p, n[2], edge(Admin), 0, &all0);
    w.set(n[2], p, n[1], None, 2, &[]);
    w.set(n[1], g, n[2], edge(Admin), 6, &[]);
    let lower = w.set(n[2], g, n[2], edge(Write), 18, &[]);
    w.set(k, p, n[2], None, 20, &[]);
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId(lower, 0)));
    assert_eq!(edge_role(&tl, n[2], g), Some(Admin));
    assert_eq!(residue(&tl), std::collections::BTreeSet::from([WriteId(lower, 0)]));
}

/// §5.1 (OSIS_PERM_SEED=1900002, joint): n1's removal of n2's admin on A0 drops n2's grant of
/// admin on A1 to n0, which made n0's grant of that admin on A0 apply: sticky residue, and
/// n0's demotion of n2 on A1 does not apply.
#[test]
fn sticky_residue_of_dropped_grant_spec_permissions_5_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let a0 = w.thing(n[1]);
    let a1 = w.thing(a0);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[1], a1, n[0], edge(Write), 0, &all0);
    w.set(n[1], a1, n[2], edge(Admin), 0, &all0);
    w.set(n[1], a0, a1, edge(Admin), 0, &all0);
    let r = |v: [u64; 3]| -> Vec<(Tid, u64)> { (0..3).map(|i| (n[i], v[i])).collect() };
    w.set(n[0], a0, n[0], edge(Write), 1, &r([1, LATE, 1]));
    let rm = w.set(n[2], a1, n[0], None, 2, &r([LATE, LATE, 2]));
    let grant = w.set(n[2], a1, n[0], edge(Admin), 6, &r([5, 8, 6]));
    w.set(n[0], a0, n[2], edge(Admin), 7, &r([7, 9, 9]));
    let demote = w.set(n[0], a1, n[2], edge(Write), 8, &r([8, 9, 8]));
    w.set(n[1], a0, n[2], None, 8, &r([11, 8, 11]));
    let tl = eval(&w);
    assert_eq!(residue(&tl), std::collections::BTreeSet::from([WriteId(rm, 0), WriteId(grant, 0)]));
    assert!(!tl.is_applied(&WriteId(demote, 0)));
}

/// §5.1 (OSIS_PERM_SEED=52011, joint): n0 (admin on A0, so on A1 through A1's record edge)
/// grants itself admin on A1, then removes A1 from A0; n1, seeing neither, demotes n0 on A0.
/// That audit sees the removal in effect: n0 falls on A0, which drops the removal; on A1 its
/// own grant keeps its class (one class: a path lost while another keeps it is no fall), so
/// the grant stands until an admin of A1 removes it. With A1's edge on A0 back, n0 keeps admin
/// on A0 through A1 in the settled walk: the drop stays as sticky residue.
#[test]
fn audit_drops_removal_not_self_grant_spec_permissions_5_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let a0 = w.thing(n[1]);
    let a1 = w.thing(a0);
    let a2 = w.thing(a0);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[1], a0, n[0], edge(Admin), 0, &all0);
    w.set(n[1], a1, n[1], edge(Admin), 0, &all0);
    w.set(n[1], a2, a0, edge(Admin), 0, &all0);
    w.set(n[1], a0, a1, edge(Admin), 0, &all0);
    w.set(n[1], a1, a2, edge(Admin), 0, &all0);
    let r = |v: [u64; 3]| -> Vec<(Tid, u64)> { (0..3).map(|i| (n[i], v[i])).collect() };
    let grant = w.set(n[0], a1, n[0], edge(Admin), 1, &r([1, LATE, 0]));
    let rm = w.set(n[0], a0, a1, None, 2, &r([2, LATE, LATE]));
    w.set(n[2], a0, n[2], edge(Write), 2, &r([LATE, LATE, 2]));
    w.set(n[2], a2, n[1], edge(Admin), 3, &r([2, 1, 3]));
    w.set(n[1], a0, n[0], edge(Write), 4, &r([3, 4, LATE]));
    w.set(n[2], a2, n[2], None, 5, &r([LATE, LATE, 5]));
    w.set(n[0], a0, n[1], edge(Admin), 7, &r([7, LATE, LATE]));
    let tl = eval(&w);
    assert!(tl.dropped().contains_key(&WriteId(rm, 0)));
    assert!(tl.is_applied(&WriteId(grant, 0)));
    assert_eq!((role(&tl, n[0], a1), role(&tl, n[0], a0)), (Some(Admin), Some(Admin)));
    assert_eq!(residue(&tl), std::collections::BTreeSet::from([WriteId(rm, 0)]));
}

/// §5.1 (OSIS_PERM_SEED=89000): n1 (admin on P, so on G) grants n2 admin on P at 4, then sets
/// n2's edge on G to write at 8, unaware of n2's leave of G at 2. n2 holds G through P at 8, so
/// that write is no fall and audits nothing; k's removal of n1 at 12 drops both n1 writes, and
/// n2's leave stands.
#[test]
fn unseen_leave_stands_spec_permissions_5_1() {
    let mut w = World::new();
    let n = w.nodes(3);
    let k = n[0];
    let p = w.thing(k);
    let g = w.thing(p);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    let only = |i: usize, t: u64| -> Vec<(Tid, u64)> { vec![(n[i], t)] };
    w.set(k, p, n[1], edge(Admin), 0, &all0);
    w.set(k, g, n[2], edge(Admin), 0, &all0);
    let leave = w.set(n[2], g, n[2], None, 2, &only(2, 2));
    w.set(n[1], p, n[2], edge(Admin), 4, &only(1, 4));
    let lower = w.set(n[1], g, n[2], edge(Write), 8, &only(1, 8));
    w.set(k, p, n[1], None, 12, &only(0, 12));
    let tl = eval(&w);
    assert!(tl.is_applied(&WriteId(leave, 0)) && tl.dropped().contains_key(&WriteId(lower, 0)));
    assert_eq!(role(&tl, n[2], g), None);
    assert!(residue(&tl).is_empty());
}

// spec/permissions.md §1 (first admin): O's record names n0 as its first admin, an edge in
// force from the start. n0 grants n1 admin; n1 removes n0. n0's later grants and re-grants
// through the record do nothing: the record gives no power once the edge is gone. On D, whose
// first admin is O, n1 (admin of O) holds admin through D's record edge: its grant on D applies.
#[test]
fn removed_first_admin_has_nothing_left() {
    let mut w = World::new();
    let n = w.nodes(3);
    let o = w.thing(n[0]);
    let d = w.thing(o);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 1)).collect();
    w.set(n[0], o, n[1], edge(Admin), 1, &all);
    let tl = eval(&w);
    assert_eq!(role(&tl, n[0], o), Some(Admin), "the record's edge");
    assert_eq!(edge_role(&tl, n[0], o), Some(Admin));
    for x in &n[..2] {
        assert_eq!(tl.class(x, &o, At::END), Class::Edge);
        assert_eq!(tl.class(x, &d, At::END), Class::Edge, "admin of D's first admin");
    }
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 3)).collect();
    w.set(n[1], o, n[0], None, 2, &all);
    let g0 = w.set(n[0], o, n[2], edge(Write), 6, &all);
    let r0 = w.set(n[0], o, n[0], edge(Admin), 7, &all);
    let gd = w.set(n[1], d, n[2], edge(Write), 8, &all);
    let tl = eval(&w);
    assert_eq!(role(&tl, n[0], o), None, "the first admin is removed like any");
    assert_eq!((role(&tl, n[0], d), tl.class(&n[0], &d, At::END)), (None, Class::None));
    assert_eq!(role(&tl, n[1], o), Some(Admin));
    assert!(!tl.is_applied(&WriteId(g0, 0)) && !tl.is_applied(&WriteId(r0, 0)));
    assert_eq!(role(&tl, n[2], o), None);
    assert!(tl.is_applied(&WriteId(gd, 0)));
    assert_eq!(role(&tl, n[2], d), Some(Write));
}

fn says_retain() -> Option<Edge> {
    Some(Edge::kept_end())
}

fn end_of(tl: &osis_perm::Timeline, g: &Tid, m: &Tid) -> EdgeEnd {
    tl.ended(g, ts(100)).get(m).unwrap().0
}

// spec/permissions.md §3, Retain: the last applied write decides: a removal's own word, last by key, never
// a write that did not apply; an `until` ending has none and reads the default at its key; a live
// edge has no end.
#[test]
fn ended_gives_the_last_applied_word_spec_permissions_3() {
    let (mut w, n, g) = group();
    let z = w.nodes_salted(4, 77);
    // a removal saying retain
    w.set(n[0], g, z[0], edge(Read), 2, &[]);
    w.set(n[0], g, z[0], says_retain(), 3, &[]);
    // a later plain removal over it: erase
    w.set(n[0], g, z[1], edge(Read), 2, &[]);
    w.set(n[0], g, z[1], says_retain(), 3, &[]);
    w.set(n[0], g, z[1], None, 4, &[]);
    // written expired
    w.set(n[0], g, z[2], edge(Read), 2, &[]);
    w.set(n[0], g, z[2], Some(Edge { until: Some(osis_base::WallMs(3)), ..Edge::new(Read) }), 3, &[]);
    // no authority: z[3] is nobody here, its removal saying retain does not apply
    w.set(z[3], g, n[4], says_retain(), 5, &[]);
    w.set(n[0], g, n[4], None, 6, &[]);
    let tl = eval(&w);
    assert_eq!(end_of(&tl, &g, &z[0]), EdgeEnd::Said(true));
    assert_eq!(end_of(&tl, &g, &z[1]), EdgeEnd::Said(false));
    assert!(matches!(end_of(&tl, &g, &z[2]), EdgeEnd::Until(_)));
    assert_eq!(end_of(&tl, &g, &n[4]), EdgeEnd::Said(false), "a write that did not apply");
    assert!(!tl.ended(&g, ts(100)).contains_key(&n[1]), "alive");
}

// spec/permissions.md §2, §3: a holder's self-removal says retain whatever anyone wants, no authority on
// the target needed; a stranger's removal of it decides nothing.
#[test]
fn self_removal_says_its_own_keep_spec_permissions_2() {
    let (mut w, n, g) = group();
    let z = w.nodes_salted(1, 78);
    w.set(z[0], g, n[4], None, 4, &[]);
    assert!(eval(&w).roster(&g, At::END).contains_key(&n[4]), "a stranger's removal");
    w.set(n[4], g, n[4], says_retain(), 5, &[]);
    let tl = eval(&w);
    assert!(!tl.roster(&g, At::END).contains_key(&n[4]));
    assert_eq!(end_of(&tl, &g, &n[4]), EdgeEnd::Said(true));
}

// spec/permissions.md §2: an invite grants: a value saying retain on an absent edge does not apply, so
// an invite holder cannot make a copy stay.
#[test]
fn an_invite_does_not_say_keep_spec_permissions_2() {
    let (mut w, n, g) = group();
    let z = w.nodes_salted(3, 79);
    w.set(n[0], g, z[0], Some(Edge { invite: Some(Read), ..Edge::new(Read) }), 2, &[]);
    w.set(z[0], g, z[1], says_retain(), 3, &[]);
    assert!(!eval(&w).ended(&g, ts(100)).contains_key(&z[1]));
    w.set(z[0], g, z[2], edge(Read), 4, &[]);
    assert!(eval(&w).roster(&g, At::END).contains_key(&z[2]));
}
