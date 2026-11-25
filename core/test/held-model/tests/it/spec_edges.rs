//! Which edge writes are evidence (spec/permissions.md §4 Evidence of a commit; E1,
//! notes/a2-spec/README.md Open 2): every held edge write on a commit's key hop, on each edge of
//! its stated path and on each edge its own edge writes set, whatever its validity; the entry a
//! reset names (spec/permissions.md §2); pending on missing evidence (spec/commits.md §4
//! Unjudgeable). Hand worlds and the cost a party can force.
use crate::spec_evidence::fails;
use held_model::evidence::names::*;
use held_model::evidence::*;
use roles_model::paths::{self, Set, Thing};
use roles_model::Role;

/// X mints A (K, Q writers), Y mints D (A writes it); X syncs A, Y syncs D, Q syncs A, K (no
/// admin) is hostile.
fn base() -> (World, [usize; 4]) {
    let pw = paths::World::new(&[(X, A), (Y, D)]);
    let mut w = World::new(pw, &[A, D]);
    let n = [w.node(true, &[A]), w.node(true, &[D]), w.node(false, &[A]), w.node(true, &[A])];
    w.write(n[0], |p| p.edge(X, 1, &[], A, K, Role::Write, &[]));
    w.write(n[1], |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    (w, n)
}

/// Cost (finding 15): every edge write on an edge D's bodies use is a copy under D, whoever made
/// it and whether or not it applies: an admin's grants, a writer's finalizes (ending nothing: Q's
/// grant has no `until`), a may-grant holder's grants onto a holder that has one (applying
/// nowhere). 27 more of each are 27 more copies; every property holds. A non-admin's junk alike
/// (`spec_evidence::f11_*`).
#[test]
fn every_edge_write_on_a_used_edge_is_a_copy_spec_permissions_4() {
    let copies = |n: u32, write: &dyn Fn(&mut World, [usize; 4], u32)| {
        let (mut w, nodes) = base();
        w.write(nodes[0], |p| p.push(X, 1, &[], A, paths::Kind::set(K, Role::Write).may_grant()));
        w.write(nodes[0], |p| p.edge(X, 1, &[], A, Q, Role::Write, &[]));
        for i in 0..n {
            write(&mut w, nodes, i);
        }
        w.write(nodes[3], |p| p.content(Q, 2 + n, &[A], D));
        assert_eq!(fails(&w, &Rule::fixed()), vec![]);
        let st = w.run(&Rule::fixed(), |_| {});
        w.copies(&st, D).len()
    };
    let admin = |w: &mut World, n: [usize; 4], i: u32| {
        w.write(n[0], |p| p.edge(X, 2 + i, &[], A, Q, Role::Write, &[]));
    };
    let finalize = |w: &mut World, n: [usize; 4], i: u32| {
        w.write(n[2], |p| p.push(K, 2 + i, &[], A, paths::Kind::finalize(Q)));
    };
    let may_grant = |w: &mut World, n: [usize; 4], i: u32| {
        w.write(n[2], |p| p.push(K, 2 + i, &[], A, paths::Kind::set(Q, Role::Read)));
    };
    for (name, f) in [("admin", &admin as &dyn Fn(&mut World, [usize; 4], u32)), ("finalize", &finalize), ("may-grant", &may_grant)] {
        assert_eq!(copies(30, f) - copies(3, f), 27, "{name}");
    }
}

/// Cost, counted: copies under D are the edge writes on the outside edges its bodies' paths use,
/// one more per re-grant on a used outside edge (role churn; churn inside the unit is bodies), and
/// repeated under every sync ID whose unit carries D (each counts the path things outside its own
/// unit). Flat in writes: `spec_evidence::p6_*`.
#[test]
fn cost_copies_follow_role_churn_on_used_edges_never_writes() {
    for churn in [1, 10] {
        assert_eq!(cost_with(3, 2, 2, churn, 1).copies, 2 + churn);
        assert_eq!(cost_with(3, 2, 0, churn, 1).copies, 0);
    }
    for carried in [1, 2, 4] {
        assert_eq!(cost_with(3, 3, 1, 0, carried).copies_everywhere, 1 + 3 * (carried - 1));
    }
}

/// Finding 9: X removes K and Q (a reader of A) from A in one commit C; K writes D through [A]
/// after it. C's part on Q's edge resets the entry X's grant to Q created, so C applies none of its
/// edge writes until that grant is held (spec/permissions.md §2). Evidence brings every edge write
/// on each edge C sets (`Rule::commit_edges`): D's reader holds the grant, applies C and judges K's
/// write invalid, as the node holding everything. The control (C's own parts alone) leaves D's
/// reader with C waiting, and K's write valid there (P1).
#[test]
fn f9_a_removal_of_two_holders_waits_for_each_creation_spec_permissions_2() {
    let (mut w, [x, _, _, _]) = base();
    let kn = w.node(true, &[A]);
    let g = w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Read, &[]));
    let ids = w.write_parts(x, |p| p.commit(X, 5, &[], A, vec![paths::Kind::set(K, Role::None), paths::Kind::set(Q, Role::None)]));
    let c = w.write(kn, |p| p.content(K, 6, &[A], D));
    assert_eq!(w.creation(ids[1]), Some(g));
    assert_eq!(fails(&w, &Rule::fixed()), vec![]);
    let f = fails(&w, &Rule { commit_edges: false, ..Rule::fixed() });
    assert!(f.iter().any(|f| f.prop == "P1" && f.id == c && f.reader == Some(Verdict::Valid) && f.full == Some(Verdict::Invalid)), "{f:?}");
}

/// The entry a reset names (spec/permissions.md §2 Edge writes): the one the write in force on its
/// edge put in its writer's walk. X grants Q read (g1) and changes it to write (g2); K, a writer of
/// A without admin, grants Q admin (junk, applied nowhere); X's removal of Q names g2's entry. A
/// second removal finds no grant in force: it resets an entry of its own (none named), as does a
/// removal of a holder never granted and of a record edge.
#[test]
fn a_reset_names_the_entry_its_writers_walk_has_in_force_spec_permissions_2() {
    let (mut w, [x, _, k, _]) = base();
    let g1 = w.write(x, |p| p.edge(X, 1, &[], A, Q, Role::Read, &[]));
    let g2 = w.write(x, |p| p.edge(X, 2, &[], A, Q, Role::Write, &[]));
    w.write(k, |p| p.edge(K, 3, &[], A, Q, Role::Admin, &[]));
    let r1 = w.write(x, |p| p.edge(X, 4, &[], A, Q, Role::None, &[]));
    let r2 = w.write(x, |p| p.edge(X, 5, &[], A, Q, Role::None, &[]));
    let never = w.write(x, |p| p.edge(X, 5, &[], A, Z, Role::None, &[]));
    let record = w.write(x, |p| p.edge(X, 6, &[], A, X, Role::None, &[]));
    assert_eq!((w.creation(g1), w.creation(g2), w.creation(r1)), (None, Some(g1), Some(g2)));
    assert_eq!((w.creation(r2), w.creation(never), w.creation(record)), (None, None, None));
}

/// E1's key hop (notes/write-path-design.md §2 E1, Keys K3): X, A's admin, grants a key admin on
/// A; the key, signing as A, grants Q write on A; Q writes D through [A]. The grant rests on its
/// key hop, so D's reader holds the key's grant as a copy beside it and judges Q's write as the
/// node holding everything does (finding 42).
#[test]
fn f42_the_edge_writes_on_a_writes_key_hop_are_evidence_spec_permissions_4() {
    const KEY: Thing = paths::KEYS | 0x40;
    let (mut w, [x, _, _, q]) = base();
    let grant = w.write(x, |p| p.edge(X, 2, &[], A, KEY, Role::Admin, &[]));
    w.write(x, |p| p.push_signed(KEY, A, 3, &[], A, paths::Kind::set(Q, Role::Write)));
    let c = w.write(q, |p| p.content(Q, 4, &[A], D));
    let rule = Rule::fixed();
    assert_eq!(fails(&w, &rule), vec![]);
    let st = w.run(&rule, |_| {});
    assert!(st.entries[&D].contains(&grant));
    assert_eq!(w.verdicts(&w.reader(&rule, &st, D, &Set::new()), &Set::from([c]))[&c], Verdict::Valid);
}

/// Finding 43 (spec/commits.md §4 Unjudgeable): the key hop is a hop. KEY, signing as A (minted by
/// X, so A's record holds no key), grants Q write on A, and Q writes D through [A]. A node holding
/// everything but X's grant to KEY finds no write putting the key hop: the grant, and Q's write
/// resting on it, pend (judged on missing evidence, never invalid for it); with X's grant both are
/// valid.
#[test]
fn f43_a_key_hop_no_write_puts_pends_until_one_is_held_spec_commits_4() {
    use held_model::evidence::Verdict::{Pending, Valid};
    const KEY: Thing = paths::KEYS | 0x40;
    let (mut w, [x, _, _, q]) = base();
    let grant = w.write(x, |p| p.edge(X, 2, &[], A, KEY, Role::Admin, &[]));
    let g = w.write(x, |p| p.push_signed(KEY, A, 3, &[], A, paths::Kind::set(Q, Role::Write)));
    let c = w.write(q, |p| p.content(Q, 4, &[A], D));
    let st = w.run(&Rule::fixed(), |_| {});
    let ids = Set::from([g, c]);
    let lacking: Vec<Verdict> = w.verdicts(&w.full(&st, &Set::from([grant])), &ids).into_values().collect();
    assert_eq!(lacking, [Pending, Pending]);
    let all: Vec<Verdict> = w.verdicts(&w.full(&st, &Set::new()), &ids).into_values().collect();
    assert_eq!(all, [Valid, Valid]);
}

/// spec/commits.md §4 Unjudgeable: an edge write that itself pends is no evidence, and hides none
/// that is: Q's grant to K on A (Q holds nothing there) pends, and K's write on A after it does
/// not, X's grant to K, ordered before both, being evidence. A grant ordered after a part is none:
/// K's write before X's grant to Q pends.
#[test]
fn a_write_that_pends_stalls_no_later_part_spec_commits_4() {
    let (mut w, [x, _, k, q]) = base();
    let forged = w.write(q, |p| p.edge(Q, 3, &[], A, K, Role::Admin, &[]));
    let honest = w.write(k, |p| p.content(K, 4, &[], A));
    let early = w.write(q, |p| p.content(Q, 5, &[], A));
    w.write(x, |p| p.edge(X, 6, &[], A, Q, Role::Write, &[]));
    let all: Set = (0..w.w.commits.len()).collect();
    assert!(w.pend(&all, forged));
    assert!(!w.pend(&all, honest));
    assert!(w.pend(&all, early));
}
