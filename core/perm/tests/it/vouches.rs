//! Vouches (spec/permissions.md §5.1 Vouches): hand worlds, each constructed (seed 0) with the
//! corner it checks reached by construction, and each failing with its rule disabled. Worlds of
//! one thing are core/test/roles-model `vouches` worlds (H the remover, node 0; X the removed
//! node, 1), judged by perm and compared with `vouches::judge` (`vouch_diff`); the rest are perm
//! worlds of their own (an actor holder, a rotation, counts of work).

use crate::common::*;
use crate::differential::{auth_of, vouch_diff, vouch_world};
use osis_base::{CommitId, Role, Tid};
use osis_perm::{At, Point, Timeline, Timelines, Validity};
use roles_model::edges::{EHist, EWrite, Edge as MEdge, NEVER};
use roles_model::shrink::LATE as MLATE;
use roles_model::vouches::{self, Rules, Vouch as MVouch, World as VWorld, FIXED};
use roles_model::Role as MR;
use std::collections::BTreeSet;

const FULL: Option<MEdge> = Some(MEdge { role: MR::Admin, until: NEVER, invite: MR::Admin });
const WRITE: Option<MEdge> = Some(MEdge { role: MR::Write, until: NEVER, invite: MR::None });
const H: usize = 0;
const X: usize = 1;

/// A model world under construction.
struct B(VWorld);

impl B {
    fn new(genesis: &[Option<MEdge>]) -> B {
        B(VWorld { h: EHist { genesis: genesis.to_vec(), writes: vec![], recv: vec![], extra: vec![] }, vouches: vec![] })
    }
    /// A one-op commit; `recv` lists (node, time), others never. Returns its commit ID.
    fn op(&mut self, author: usize, x: usize, e: Option<MEdge>, t: u32, recv: &[(usize, u32)]) -> u32 {
        let h = &mut self.0.h;
        let mut r = vec![MLATE; h.n()];
        r[author] = t;
        for &(m, tm) in recv {
            r[m] = tm;
        }
        let id = h.writes.len() as u32;
        h.writes.push(EWrite { author, t, id, ops: vec![(x, e)], fin: false });
        h.recv.push(r);
        id
    }
    fn vouch(&mut self, author: usize, t: u32, removal: u32, lists: &[u32], recv: &[(usize, u32)]) {
        let mut r = vec![MLATE; self.0.h.n()];
        r[author] = t;
        for &(m, tm) in recv {
            r[m] = tm;
        }
        self.0.vouches.push(MVouch { author, t, removal, lists: lists.to_vec(), recv: r, forged: true });
    }
    /// The honest vouches `rules` writes, received by every node a tick after.
    fn honest(mut self, rules: Rules) -> VWorld {
        let n = self.0.h.n();
        self.0.derive(rules, |a, t| {
            let mut r = vec![t + 1; n];
            r[a] = t;
            r
        });
        self.0
    }
}

/// Perm's role of node `x` on the thing, the model's agreeing (`vouch_diff`) under `rules` and
/// every trust set it checks.
fn role(w: &VWorld, rules: Rules, x: usize) -> Option<Role> {
    if let Some(d) = vouch_diff(w, rules) {
        panic!("perm and the model disagree: {d}\n{w}");
    }
    let ew = vouch_world(w);
    auth_of(&Timeline::evaluate(&ew.w.held()), &ew, x).0
}

fn counted(w: &VWorld) -> usize {
    Timeline::evaluate(&vouch_world(w).w.held()).counted().count()
}

/// X shares with K; only W received it; H removes X. W's vouch keeps the grant; without it the
/// grant drops. With H's removal trusted, its seeds read the counting entry as listed too.
#[test]
fn a_grant_only_a_witness_received_stands() {
    let world = |vouched: bool| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
        b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        if vouched { b.honest(FIXED) } else { b.0 }
    };
    assert_eq!(role(&world(true), FIXED, 3), Some(Role::Admin));
    assert_eq!(role(&world(false), FIXED, 3), None);
    for (vouched, want) in [(true, Some(Role::Admin)), (false, None)] {
        let w = world(vouched);
        let ew = vouch_world(&w);
        let trust = osis_perm::Trust { ops: [osis_perm::WriteId(ew.ids[1], 0)].into() };
        let tl = Timeline::evaluate_with(&ew.w.held(), &trust);
        assert_eq!(tl.trusted_active().len(), 1);
        assert_eq!(auth_of(&tl, &ew, 3).0, want, "trusted, vouched {vouched}");
        assert_eq!(auth_of(&tl, &ew, 3).0, model_role(vouches::judge(&w, FIXED, 1 << 1).res.0[3].0));
    }
}

/// W writes only; H grants it admin after the removal: its vouch written then keeps X's grant,
/// and the one written at receipt (W then holding write) does not count.
#[test]
fn a_witness_granted_the_right_after_the_removal_vouches() {
    let world = |rules| {
        let mut b = B::new(&[FULL, FULL, WRITE, None]);
        b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
        b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        b.op(H, 2, FULL, 6, &[(2, 6), (3, 6)]);
        b.honest(rules)
    };
    assert_eq!(role(&world(FIXED), FIXED, 3), Some(Role::Admin));
    let once = Rules { rewrite: false, ..FIXED };
    assert_eq!(role(&world(once), once, 3), None);
}

/// X demotes W to write (only H received it) and grants K write (only W received it); H removes
/// X, then grants W admin again. Each writing keeps or loses K's grant as the model says.
#[test]
fn a_witness_unaware_of_its_own_demotion() {
    let world = |rules| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        b.op(X, 3, WRITE, 3, &[(2, 3), (3, 3)]);
        b.op(X, 2, WRITE, 3, &[(H, 3)]);
        b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        b.op(H, 2, FULL, 6, &[(2, 6), (3, 6)]);
        b.honest(rules)
    };
    assert_eq!(role(&world(FIXED), FIXED, 3), Some(Role::Write));
    let held = Rules { held: true, ..FIXED };
    assert_eq!(role(&world(held), held, 3), None);
    let state = Rules { state: true, ..FIXED };
    assert_eq!(role(&world(state), state, 3), Some(Role::Write));
}

/// X demoted W before the theft; only W received it. W vouches for its own demotion: it stays
/// made.
#[test]
fn a_demotion_only_its_victim_received_stays_made() {
    let world = |vouched: bool| {
        let mut b = B::new(&[FULL, FULL, FULL]);
        b.op(X, 2, WRITE, 1, &[(2, 1)]);
        b.op(H, X, None, 4, &[(2, 5)]);
        if vouched { b.honest(FIXED) } else { b.0 }
    };
    assert_eq!(role(&world(true), FIXED, 2), Some(Role::Write));
    assert_eq!(role(&world(false), FIXED, 2), Some(Role::Admin));
}

/// The thief removes H; H received it and removes X, listing it: trusted, H's removal is void
/// (spec/permissions.md §5.1 Vouches: a commit a frontier keeps applies like any other).
#[test]
fn a_removal_listing_the_thiefs_removal_of_its_author_is_void() {
    let mut b = B::new(&[FULL, FULL, FULL]);
    b.op(X, H, None, 1, &[(H, 2), (2, 2)]);
    b.op(H, X, None, 4, &[(2, 5)]);
    let w = b.honest(FIXED);
    // op 1 (H's removal) trusted alone
    let j = vouches::judge(&w, FIXED, 1 << 1);
    assert_eq!(j.active, 0);
    assert!(vouch_diff(&w, FIXED).is_none());
}

/// Counting clause 4 (survival) and a vouch lost by a later lowering: L vouches for X's grant
/// nobody received; H removes L without having received the vouch: it falls with L. Received
/// by H first (H's frontier lists it), it stands.
#[test]
fn a_vouch_falls_with_a_later_lowering_of_its_author_unless_listed() {
    let world = |h_got: bool| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        let g = b.op(X, 3, FULL, 1, &[(3, 1)]);
        let r = b.op(H, X, None, 4, &[(2, 4), (3, 4)]);
        b.vouch(2, 5, r, &[g], if h_got { &[(H, 5)] } else { &[] });
        b.op(H, 2, None, 6, &[(3, 6)]);
        b.0
    };
    assert_eq!(role(&world(false), FIXED, 3), None);
    assert_eq!(role(&world(true), FIXED, 3), Some(Role::Admin));
}

/// Counting clause 3 (the voucher could write c at its vouch's position): X's own vouch and an
/// outsider's count for nothing; an admin's alike stands (the control).
#[test]
fn a_vouch_by_the_removed_node_or_an_outsider_counts_for_nothing() {
    let world = |voucher: usize| {
        let mut b = B::new(&[FULL, FULL, None, None, FULL]);
        let g = b.op(X, 3, FULL, 1, &[(3, 1)]);
        let r = b.op(H, X, None, 4, &[(2, 4), (3, 4), (4, 4)]);
        b.vouch(voucher, 5, r, &[g], &[(H, 6)]);
        b.0
    };
    for v in [X, 2] {
        assert_eq!(counted(&world(v)), 0);
        assert_eq!(role(&world(v), FIXED, 3), None);
    }
    assert_eq!(role(&world(4), FIXED, 3), Some(Role::Admin));
}

/// X, lowered by H to write with invite read, still invites: it vouches for its own backdated
/// invite grant, which no other node received, and it applies (stated paths close it, A1).
#[test]
fn a_demoted_node_vouches_for_its_own_backdated_invite() {
    let mut b = B::new(&[FULL, FULL, None]);
    let g = b.op(X, 2, Some(MEdge { role: MR::Read, until: NEVER, invite: MR::None }), 2, &[]);
    let r = b.op(H, X, Some(MEdge { role: MR::Write, until: NEVER, invite: MR::Read }), 4, &[(2, 4)]);
    b.vouch(X, 5, r, &[g], &[(H, 5), (2, 5)]);
    let w = b.0;
    assert_eq!(counted(&w), 1);
    assert_eq!(role(&w, FIXED, 2), Some(Role::Read));
}

/// Counting clause 2 (c ordered before R, V's position after R): W's vouch stamped before H's
/// removal counts for nothing; the same vouch a tick after it does, but not for X's commit
/// ordered after the removal it also lists.
#[test]
fn a_vouch_stamped_before_its_removal_counts_for_nothing() {
    let world = |t: u32| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        let g = b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
        let r = b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
        let late = b.op(X, 3, WRITE, 5, &[(2, 5)]);
        b.vouch(2, t, r, &[g, late], &[(H, 9)]);
        b.0
    };
    assert_eq!(role(&world(4), FIXED, 3), None);
    assert_eq!(counted(&world(4)), 0);
    assert_eq!(role(&world(6), FIXED, 3), Some(Role::Admin));
    assert_eq!(counted(&world(6)), 1, "the commit after the removal does not count");
}

/// Counting clause 1 (R applies as an explicit write lowering X's grant): X lowers itself to
/// write (no audit), then H writes X's edge to write: an explicit write that audits X's admin
/// writes (the edge as restored is admin) but takes nothing from X's edge as it stands, so W's
/// vouch keyed by it counts for nothing and X's grant to K stays dropped. Keyed by a removal of
/// X, the same vouch counts (the control).
#[test]
fn a_vouch_keyed_by_a_write_lowering_nothing_counts_for_nothing() {
    let world = |remove: bool| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        let g = b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
        b.op(X, X, WRITE, 2, &[(H, 2), (2, 2), (3, 2)]);
        let r = b.op(H, X, if remove { None } else { WRITE }, 4, &[(2, 5), (3, 4)]);
        b.vouch(2, 6, r, &[g], &[(H, 7)]);
        b.0
    };
    assert_eq!(role(&world(false), FIXED, 3), None);
    assert_eq!(role(&world(true), FIXED, 3), Some(Role::Admin));
}

/// The junk-grant world: X removes Y long before the theft (H received it); Y, holding nothing,
/// writes a junk grant of admin to H stamped before H's removal of X, and vouches for its own
/// removal and its junk: Y stays removed, and the junk revives nobody.
#[test]
fn a_removed_node_writing_a_grant_to_the_remover_stays_removed() {
    const Y: usize = 2;
    let world = |junk: bool| {
        let mut b = B::new(&[FULL, FULL, FULL]);
        let k = b.op(X, Y, None, 1, &[(H, 1)]);
        let r = b.op(H, X, None, 4, &[]);
        if junk {
            let g = b.op(Y, H, FULL, 2, &[]);
            b.vouch(Y, 5, r, &[k, g], &[(H, 5)]);
        }
        b.honest(FIXED)
    };
    assert_eq!(role(&world(false), FIXED, Y), None);
    // Y's vouch for its own removal counts (a node may always write a lowering of its own edge)
    // and keeps it removed; for its junk grant, written without the right, it does not
    assert_eq!(counted(&world(true)), 1);
    assert_eq!(role(&world(true), FIXED, Y), None);
}

/// A removed party's flood of vouches changes nothing: X writes many vouches keyed by H's
/// removal of it and by made-up removals, listing its unseen grant and every commit of its own;
/// the judgment equals the one without them.
#[test]
fn a_removed_partys_flood_of_vouches_changes_nothing() {
    let world = |flood: bool| {
        let mut b = B::new(&[FULL, FULL, FULL, None]);
        let g = b.op(X, 3, FULL, 1, &[(3, 1)]);
        let d = b.op(X, 2, WRITE, 2, &[]);
        let r = b.op(H, X, None, 4, &[(2, 4), (3, 4)]);
        if flood {
            for i in 0..40u32 {
                let key = if i.is_multiple_of(2) { r } else { 100 + i };
                b.vouch(X, 5 + i % 7, key, &[g, d], &[(H, 6), (2, 6)]);
            }
        }
        b.0
    };
    let (a, b) = (vouch_world(&world(true)), vouch_world(&world(false)));
    let (ta, tb) = (Timeline::evaluate(&a.w.held()), Timeline::evaluate(&b.w.held()));
    assert_eq!(ta.counted().count(), 0);
    for x in 0..4 {
        assert_eq!(auth_of(&ta, &a, x), auth_of(&tb, &b, x), "node {x}");
    }
    assert_eq!(ta.dropped().len(), tb.dropped().len());
    assert!(vouch_diff(&world(true), FIXED).is_none());
}

/// What a demotion puts in question is read from the timeline (the second walk, its frontiers as
/// listed) with the demotion appended: H removing K, whom X's vouched grant made admin, demotes K.
#[test]
fn a_demotion_scope_on_a_second_walk() {
    let mut b = B::new(&[FULL, FULL, FULL, None]);
    b.op(X, 3, FULL, 1, &[(2, 1), (3, 1)]);
    b.op(H, X, None, 4, &[(2, 5), (3, 4)]);
    let w = b.honest(FIXED);
    let ew = vouch_world(&w);
    let tl = Timeline::evaluate(&ew.w.held());
    assert_eq!(tl.counted().count(), 1);
    let r = osis_perm::RoleCommit { id: cid(77_777), ts: ts(20), author: ew.nodes[H], actor: ew.nodes[H], frontier: Some(std::sync::Arc::new(osis_perm::Frontier::default())), ops: vec![osis_perm::EdgeOp { target: ew.t, holder: ew.nodes[3], edge: None }] };
    let scope = tl.demotion_scope(r);
    assert!(scope.roles.get(&ew.nodes[3]).is_some_and(|s| s.contains(&ew.t)), "{scope:?}");
}

/// No cycle: W1 and W2 hold admin only through X's grants (each received by both), which H's
/// removal of X drops; each vouches for the grant of the other. The first walk reads no vouch,
/// so neither voucher could write what it lists and nothing counts. The control: W1 an admin
/// by H's grant too, its vouch counts and W2's admin stands.
#[test]
fn vouches_for_each_other_make_no_cycle() {
    let world = |w1_admin: bool| {
        let mut b = B::new(&[FULL, FULL, if w1_admin { FULL } else { None }, None]);
        let c1 = b.op(X, 2, FULL, 1, &[(2, 1), (3, 1)]);
        let c2 = b.op(X, 3, FULL, 2, &[(2, 2), (3, 2)]);
        let r = b.op(H, X, None, 4, &[(2, 5), (3, 5)]);
        b.vouch(2, 6, r, &[c2], &[(H, 7), (3, 7)]);
        b.vouch(3, 6, r, &[c1], &[(H, 7), (2, 7)]);
        b.0
    };
    assert_eq!(counted(&world(false)), 0);
    assert_eq!((role(&world(false), FIXED, 2), role(&world(false), FIXED, 3)), (None, None));
    assert_eq!(counted(&world(true)), 1);
    assert_eq!(role(&world(true), FIXED, 3), Some(Role::Admin));
}

// ---------- perm worlds ----------

/// Nodes H, X, W, Z on a thing T minted by H; X and W admins, Z a reader.
fn perm_world() -> (World, [Tid; 4], Tid) {
    let mut w = World::new();
    let n = w.nodes(4);
    let t = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], t, n[1], edge(Role::Admin), 0, &all);
    w.set(n[0], t, n[2], edge(Role::Admin), 0, &all);
    w.set(n[0], t, n[3], edge(Role::Read), 0, &all);
    (w, [n[0], n[1], n[2], n[3]], t)
}

/// A vouched rotation (a role-class part that is no edge write, spec/permissions.md §5.1 Vouches,
/// "W could write c"): X's rotation of T, which only W received; H removes X. W's vouch keeps it
/// (the removal's frontier, read so by layer 2, lists it); Z's, a reader's, counts for nothing,
/// since a rotation needs write.
#[test]
fn a_vouched_rotation_stands() {
    let world = |voucher: Option<usize>| {
        let (mut w, n, t) = perm_world();
        let rot = w.role_parts(n[1], 1, &[(t, Role::Write)], &[(n[2], 1), (n[3], 1)]);
        let r = w.set(n[0], t, n[1], None, 4, &[(n[2], 5), (n[3], 5)]);
        if let Some(v) = voucher {
            w.vouch(n[v], 6, t, &[(r, &[rot])], &[(n[0], 7)]);
        }
        let tl = Timeline::evaluate(&w.held());
        let at = Point { ts: ts(1), node: n[1], commit: rot };
        (tl.delta_valid(at, &t, Role::Write) == Validity::Valid, tl.counted().count())
    };
    assert_eq!(world(Some(2)), (true, 1));
    assert_eq!(world(Some(3)), (false, 0));
    assert_eq!(world(None), (false, 0));
}

/// Counting clause 2 (c is in question: by R's holder X, or by an author whose class or role
/// falls at R, spec/permissions.md §5.1 Vouches): A, a thing X mints, holds admin on T, X's only
/// admin there; X grants K admin (only W received it); H removes A, demoting X. W's vouch keyed
/// by that removal listing X's grant counts, as it does keyed by a removal of X's own edge (the
/// world where X holds admin on T itself). The same vouch also lists Y's grant of Z (Y an admin
/// R does not demote, its grant received by H): that entry counts for nothing.
#[test]
fn a_vouch_counts_for_a_commit_acting_through_the_removed_holder() {
    let world = |through_actor: bool| {
        let mut w = World::new();
        let n = w.nodes(6);
        let (h, x, wn, k, y, z) = (n[0], n[1], n[2], n[3], n[4], n[5]);
        let t = w.thing(h);
        let a = w.thing(x);
        let all: Vec<(Tid, u64)> = n.iter().map(|q| (*q, 0)).collect();
        let holder = if through_actor { a } else { x };
        w.set(h, t, holder, edge(Role::Admin), 0, &all);
        w.set(h, t, wn, edge(Role::Admin), 0, &all);
        w.set(h, t, y, edge(Role::Admin), 0, &all);
        let g = w.set(x, t, k, edge(Role::Admin), 1, &[(wn, 1), (k, 1)]);
        let gy = w.set(y, t, z, edge(Role::Write), 2, &all);
        let r = w.set(h, t, holder, None, 4, &[(wn, 5), (k, 5)]);
        w.vouch(wn, 6, t, &[(r, &[g, gy])], &[(h, 7)]);
        let tl = Timeline::evaluate(&w.held());
        (tl.role(&k, &t, At::END), tl.counted().map(|(_, c)| c).collect::<Vec<_>>() == vec![g])
    };
    assert_eq!(world(true), (Some(Role::Admin), true));
    assert_eq!(world(false), (Some(Role::Admin), true));
}

/// Counting clause 3 (V is on a thing where c has a role-class part): W's vouch for X's grant
/// on T, written on U (a thing W mints) counts for nothing; on T it counts (the control).
#[test]
fn a_vouch_on_a_thing_the_commit_does_not_write_counts_for_nothing() {
    let world = |on_t: bool| {
        let (mut w, n, t) = perm_world();
        let k = w.nodes_salted(1, 9)[0];
        let u = w.thing(n[2]);
        let g = w.set(n[1], t, k, edge(Role::Admin), 1, &[(n[2], 1), (k, 1)]);
        let r = w.set(n[0], t, n[1], None, 4, &[(n[2], 5), (k, 5)]);
        w.vouch(n[2], 6, if on_t { t } else { u }, &[(r, &[g])], &[(n[0], 7)]);
        let tl = Timeline::evaluate(&w.held());
        (tl.role(&k, &t, At::END), tl.counted().count())
    };
    assert_eq!(world(false), (None, 0));
    assert_eq!(world(true), (Some(Role::Admin), 1));
}

/// A vouch arriving last that keeps a rotation (no edge write: no edge or history change) is
/// reported: the component is reported evaluated, so layer 2 judges T's commits again.
#[test]
fn a_late_vouch_for_a_rotation_is_reported() {
    let (mut w, n, t) = perm_world();
    let rot = w.role_parts(n[1], 1, &[(t, Role::Write)], &[(n[2], 1), (n[3], 1)]);
    let r = w.set(n[0], t, n[1], None, 4, &[(n[2], 5), (n[3], 5)]);
    let v = w.vouch(n[2], 6, t, &[(r, &[rot])], &[(n[0], 7)]);
    let at = Point { ts: ts(1), node: n[1], commit: rot };
    let mut tls = Timelines::new();
    tls.update(&w.held_without(&[v].into()));
    assert_ne!(tls.get(&t).unwrap().delta_valid(at, &t, Role::Write), Validity::Valid);
    let changed = tls.update_touched(&w.held(), &[t].into());
    assert_eq!(tls.get(&t).unwrap().delta_valid(at, &t, Role::Write), Validity::Valid);
    assert!(changed.evaluated.contains(&t), "{changed:?}");
}

/// Validity is a function of the held set (incremental equals from scratch): the world of
/// `a_grant_only_a_witness_received_stands` with W's vouch arriving before the removal and after
/// it, and a later write appended to a component whose walk is a second walk, through
/// `Timelines` (the vouch joins its author's component; the same component met by an edge and
/// by a vouch), each step equal to a fresh evaluation.
#[test]
fn incremental_equals_from_scratch_with_vouches() {
    let (mut w, n, t) = perm_world();
    let (h, x, wn, z) = (n[0], n[1], n[2], n[3]);
    let k = w.nodes_salted(1, 9)[0];
    let g = w.set(x, t, k, edge(Role::Admin), 1, &[(wn, 1), (k, 1)]);
    let r_id = w.fresh_id();
    w.vouch(wn, 6, t, &[(r_id, &[g])], &[(h, 7)]);
    w.commit_id(r_id, h, 4, &[(t, x, None)], &[(wn, 5), (k, 5)]);
    let later = w.fresh_id();
    w.commit_id(later, h, 8, &[(t, z, edge(Role::Write))], &[]);
    let ids: Vec<CommitId> = w.commits.iter().map(|c| c.id).chain([w.vouches[0].id]).collect();
    // every prefix: the vouch before the removal, between it and the later write (appended to a
    // second walk), last
    for order in [vec![0, 1, 2, 3, 6, 4, 5], vec![0, 1, 2, 3, 4, 6, 5], vec![0, 1, 2, 3, 4, 5, 6]] {
        let mut tls = Timelines::new();
        let mut held_ids: BTreeSet<CommitId> = BTreeSet::new();
        for &i in &order {
            held_ids.insert(ids[i]);
            let skip: BTreeSet<CommitId> = ids.iter().filter(|c| !held_ids.contains(c)).copied().collect();
            let held = w.held_without(&skip);
            let touched: BTreeSet<Tid> = [t, k, x, wn, h, z].into();
            tls.update_touched(&held, &touched);
            let fresh = Timeline::evaluate(&held);
            let tl = tls.get(&t).expect("T has a timeline");
            for y in [h, x, wn, z, k] {
                assert_eq!(tl.role(&y, &t, At::END), fresh.role(&y, &t, At::END), "order {order:?} step {i}");
            }
            assert_eq!(tl.counted().collect::<Vec<_>>(), fresh.counted().collect::<Vec<_>>(), "order {order:?} step {i}");
        }
        assert_eq!(tls.get(&t).unwrap().role(&k, &t, At::END), Some(Role::Admin));
    }
}

/// Incremental equals from scratch in every arrival order of X's grant to K (only W received
/// it), H's removal of X, W's vouch for the grant, and H's later removal of W not listing the
/// vouch (the vouch falls with it): each step's roles and counting entries equal a fresh
/// evaluation's, and a role that changes on T is reported (`Changed`: T evaluated, or its edge).
#[test]
fn incremental_equals_from_scratch_in_every_order() {
    let (mut w, n, t) = perm_world();
    let (h, x, wn, z) = (n[0], n[1], n[2], n[3]);
    let k = w.nodes_salted(1, 9)[0];
    let base: BTreeSet<CommitId> = w.commits.iter().map(|c| c.id).collect();
    let g = w.set(x, t, k, edge(Role::Admin), 1, &[(wn, 1), (k, 1)]);
    let r = w.fresh_id();
    let v = w.vouch(wn, 6, t, &[(r, &[g])], &[(k, 7)]);
    w.commit_id(r, h, 4, &[(t, x, None)], &[(wn, 5), (k, 5)]);
    let q = w.set(h, t, wn, None, 8, &[(k, 8)]);
    let moving = [g, r, v, q];
    let nodes = [h, x, wn, z, k];
    let roles = |tl: &Timeline| nodes.map(|y| tl.role(&y, &t, At::END));
    let mut orders = vec![vec![]];
    for _ in 0..moving.len() {
        orders = orders.into_iter().flat_map(|o: Vec<usize>| (0..moving.len()).filter(|i| !o.contains(i)).map(|i| [o.clone(), vec![i]].concat()).collect::<Vec<_>>()).collect();
    }
    let (mut second, mut flips) = (0, 0);
    for order in &orders {
        let mut tls = Timelines::new();
        let mut held_ids = base.clone();
        let touched: BTreeSet<Tid> = [t, k, x, wn, h, z].into();
        tls.update_touched(&w.held_without(&moving.into_iter().collect()), &touched);
        let mut was = roles(tls.get(&t).unwrap());
        for &i in order {
            held_ids.insert(moving[i]);
            let skip: BTreeSet<CommitId> = moving.iter().filter(|c| !held_ids.contains(c)).copied().collect();
            let held = w.held_without(&skip);
            let changed = tls.update_touched(&held, &touched);
            let fresh = Timeline::evaluate(&held);
            let tl = tls.get(&t).expect("T has a timeline");
            let now = roles(tl);
            assert_eq!(now, roles(&fresh), "order {order:?} step {i}");
            assert_eq!(tl.counted().collect::<Vec<_>>(), fresh.counted().collect::<Vec<_>>(), "order {order:?} step {i}");
            second += usize::from(fresh.counted().count() > 0);
            for (y, (a, b)) in nodes.iter().zip(was.iter().zip(now.iter())) {
                if a != b {
                    flips += 1;
                    assert!(changed.evaluated.contains(&t) || changed.edges.contains(&(*y, t)), "order {order:?} step {i}: {y:?} {a:?} -> {b:?} unreported: {changed:?}");
                }
            }
            was = now;
        }
        assert_eq!(was[4], None, "the vouch falls with W's removal");
    }
    assert!(second > 0 && flips > 0, "{second} {flips}");
}

// ---------- work (notes/principles.md, Check scaling) ----------

/// Work counters: (commits walked, vouch entries judged, history entries moved).
fn work() -> (u64, u64, u64) {
    (osis_perm::commits_walked(), osis_perm::vouch::entries_judged(), osis_perm::entries_moved())
}

fn since(a: (u64, u64, u64)) -> (u64, u64, u64) {
    let b = work();
    (b.0 - a.0, b.1 - a.1, b.2 - a.2)
}

/// A write appended to a component holding `n` vouches that cannot count (keyed by removals not
/// held, and by a held grant, which lowers nothing), with `n` more on another component: the
/// work it costs follows its component's walk, never the vouches held.
fn append_work(n: u32) -> (u64, u64, u64) {
    let (mut w, nodes, t) = perm_world();
    let (h, x, wn) = (nodes[0], nodes[1], nodes[2]);
    // another component: its own thing and admin
    let o = w.nodes_salted(1, 7)[0];
    let u = w.thing(o);
    let grant = w.set(h, t, x, edge(Role::Admin), 2, &[]);
    for i in 0..20 {
        w.set(x, t, nodes[3], edge(if i % 2 == 0 { Role::Write } else { Role::Read }), 3 + i, &[]);
    }
    for i in 0..n {
        let made_up = cid(900_000 + i);
        w.vouch(wn, 40, t, &[(made_up, &[grant]), (grant, &[grant])], &[]);
        w.vouch(o, 40, u, &[(made_up, &[made_up])], &[]);
    }
    let mut tls = Timelines::new();
    tls.update(&w.held());
    w.set(h, t, nodes[3], edge(Role::Admin), 50, &[]);
    let before = work();
    tls.update_touched(&w.held(), &[t].into());
    since(before)
}

/// spec/permissions.md §5.1 Vouches (notes/principles.md, Check scaling): a write costs the same
/// with 10 and 100 vouches held where none can count, in its component and in another.
#[test]
fn a_write_never_rescans_the_vouches_held() {
    let (a, b) = (append_work(10), append_work(100));
    eprintln!("a write with 2x10 and 2x100 vouches held: {a:?} {b:?}");
    assert_eq!(a, b, "work at n and 10n vouches: (commits walked, entries judged, entries moved)");
    assert_eq!(a.1, 0);
}

/// A removed party X forges a vouch on each of `k` things of other components (each its own
/// admin and a few writes), keyed by its removal and listing its own commits on T; then a write
/// on one of them: (commits walked, entries judged).
fn forged_elsewhere_work(k: u32) -> (u64, u64) {
    let (mut w, nodes, t) = perm_world();
    let (h, x) = (nodes[0], nodes[1]);
    let g = w.set(x, t, nodes[3], edge(Role::Admin), 1, &[]);
    let r = w.set(h, t, x, None, 4, &[]);
    let pool = w.nodes_salted(2 * k as usize, 20);
    let mut others = Vec::new();
    for i in 0..k as usize {
        let (o, m) = (pool[2 * i], pool[2 * i + 1]);
        let u = w.thing(o);
        for j in 0..5 {
            w.set(o, u, m, edge(if j % 2 == 0 { Role::Write } else { Role::Read }), 1 + j, &[]);
        }
        w.vouch(x, 6, u, &[(r, &[g])], &[]);
        others.push((o, u));
    }
    let mut tls = Timelines::new();
    tls.update(&w.held());
    let (o, u) = others[0];
    w.set(o, u, pool[1], edge(Role::Admin), 50, &[]);
    let before = work();
    tls.update_touched(&w.held(), &[u].into());
    let d = since(before);
    (d.0, d.1)
}

/// spec/permissions.md §5.1 Vouches (Check scaling): vouches forged on things of other
/// components merge nothing: a write on one of them costs the same with 10 and 100 forged.
#[test]
fn forged_vouches_elsewhere_merge_no_components() {
    let (a, b) = (forged_elsewhere_work(10), forged_elsewhere_work(100));
    eprintln!("a write beside 10 and 100 forged vouches on other components: {a:?} {b:?}");
    assert_eq!(a, b);
}

/// A write appended to a component of `n` edge writes holding one counting vouch, which it
/// leaves counting: (commits walked, entries judged, entries moved).
fn counting_append_work(n: u64) -> (u64, u64, u64) {
    let (mut w, nodes, t) = perm_world();
    let (h, x, wn) = (nodes[0], nodes[1], nodes[2]);
    for i in 0..n {
        w.set(h, t, nodes[3], edge(if i % 2 == 0 { Role::Write } else { Role::Read }), 1 + i, &[]);
    }
    let g = w.set(x, t, nodes[3], edge(Role::Admin), n + 1, &[(wn, n + 1)]);
    let r = w.set(h, t, x, None, n + 10, &[(wn, n + 11)]);
    w.vouch(wn, n + 12, t, &[(r, &[g])], &[]);
    let mut tls = Timelines::new();
    tls.update(&w.held());
    assert_eq!(tls.get(&t).unwrap().counted().count(), 1);
    w.set(h, t, wn, edge(Role::Admin), n + 20, &[]);
    let before = work();
    tls.update_touched(&w.held(), &[t].into());
    since(before)
}

/// spec/permissions.md §5.1 Vouches (Check scaling): a write that leaves the counting entries
/// as they were continues both walks: it costs the same at 30 and 300 edge writes of history.
#[test]
fn a_write_beside_a_counting_vouch_continues_both_walks() {
    let (a, b) = (counting_append_work(30), counting_append_work(300));
    eprintln!("a write beside a counting vouch at 30 and 300 edge writes: {a:?} {b:?}");
    assert_eq!(a, b, "(commits walked, entries judged, entries moved)");
}

/// The evaluation of a component with `k` counting vouches for X's grant: (commits walked,
/// entries judged).
fn counting_work(k: usize) -> (u64, u64) {
    let (mut w, nodes, t) = perm_world();
    let (h, x, wn) = (nodes[0], nodes[1], nodes[2]);
    for i in 0..30 {
        w.set(h, t, nodes[3], edge(if i % 2 == 0 { Role::Write } else { Role::Read }), 1 + i, &[]);
    }
    let g = w.set(x, t, nodes[3], edge(Role::Admin), 31, &[(wn, 31)]);
    let r = w.set(h, t, x, None, 40, &[(wn, 41)]);
    for i in 0..k {
        w.vouch(wn, 42 + i as u64, t, &[(r, &[g])], &[]);
    }
    let held = w.held();
    let before = work();
    let tl = Timeline::evaluate(&held);
    assert_eq!(tl.role(&nodes[3], &t, At::END), if k > 0 { Some(Role::Admin) } else { Some(Role::Read) });
    let d = since(before);
    (d.0, d.1)
}

/// spec/permissions.md §5.1 Vouches (Check scaling): counting vouches cost one more walk of their
/// component, whatever their number: 1 and 10 walk alike, and at most twice the walk without.
#[test]
fn counting_vouches_cost_one_walk_of_their_component() {
    let (none, one, ten) = (counting_work(0), counting_work(1), counting_work(10));
    eprintln!("evaluation with 0, 1, 10 counting vouches: {none:?} {one:?} {ten:?}");
    assert_eq!(one.0, ten.0, "commits walked with 1 and 10 counting vouches");
    assert!(one.0 <= 2 * none.0, "{one:?} against {none:?} without");
    assert_eq!((one.1, ten.1), (1, 10), "entries judged: one per entry");
}
