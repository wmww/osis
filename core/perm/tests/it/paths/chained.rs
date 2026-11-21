//! Chained-ness per edge-class part (draft §4 Chained writes; what A2's evidence derivation reads,
//! notes/evidence-derivation.md): `Paths::is_chained` against held-model's `evidence::World::chained`
//! over the differential worlds at every view, and hand worlds of each kind of part (an invite
//! grant by its path's invite, a removal, a finalize by write, a self-removal), with
//! `Changed::chained` reporting each flip, on arrival and on forget.
//! spec/permissions.md §4 (the draft replaces it: spec/permissions.md §4 Chained writes).

use super::incremental::check;
use super::{input, rules, MODES};
use osis_perm::paths::Paths;
use roles_model::paths::{self as m, Id, Kind, View, World};
use roles_model::Role::{Admin, None as Gone, Read, Write};
use std::collections::BTreeSet;

/// Where the walk's chained-ness differs from held-model's at view `v` of `w`, the first part.
pub fn diff(w: &World, v: &View) -> Option<String> {
    let inp = input(w, v);
    let p = Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits);
    let want = held_model::evidence::World::new(w.clone(), &[]).chained(&v.held);
    for (&i, id) in &inp.ids {
        if w.edge_class(i) && p.is_chained(id) != Some(want.contains(&i)) {
            return Some(format!("part {i}: model chained {}, walk {:?}\n{}", want.contains(&i), p.is_chained(id), m::tiny_trace(w)));
        }
    }
    None
}

/// Tiny, content and purge worlds `start..start + n` (purge worlds at every node); the failures,
/// at most three.
fn run(start: u64, n: u64) -> Vec<String> {
    let mut fails: Vec<String> = vec![];
    for i in start..start + n {
        for mode in MODES {
            let t = m::tiny_world(i, mode, &rules());
            fails.extend(diff(&t.w, &t.v).map(|d| format!("tiny {mode:?} world {i}: {d}")));
        }
        let (w, v) = super::content::world(i);
        fails.extend(diff(&w, &v).map(|d| format!("content world {i}: {d}")));
        let pw = m::purge_world(i, &rules());
        for node in pw.nodes() {
            fails.extend(diff(&pw.w, &pw.view_at(node, None)).map(|d| format!("purge world {i} node {node}: {d}")));
        }
        if fails.len() >= 3 {
            break;
        }
    }
    fails.truncate(3);
    fails
}

// spec/permissions.md §4: every edge-class part's chained-ness is the model's.
#[test]
fn chained_parts_agree() {
    let f = run(0, 150);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

/// A held set of every kind of chained part, by H (A's mint admin): X admin; N5 write with the
/// may-grant flag; N5's grant of Z (read, by the flag); Z's grant of Y (read: Z holds no flag, so
/// unchained); X's removal of Z; Q timed write, finalized by N5 (by write); X's leave
/// of A (a self-removal by its empty path).
fn kinds() -> (World, [Id; 7]) {
    use m::{account, A, B, H, N5, X, Z};
    let (q, y) = (m::K, m::M);
    let mut w = account();
    let gx = w.edge(H, 1, &[], A, X, Admin, &[]);
    let gn = w.push(H, 1, &[], A, Kind::set(N5, Write).may_grant());
    let gq = w.edge(H, 1, &[], A, q, Write, &[]);
    w.set_until(gq, 3);
    let inv = w.push(N5, 2, &[], A, Kind::set(Z, Read));
    let junk = w.push(Z, 3, &[], A, Kind::set(y, Read));
    let rz = w.edge(X, 4, &[], A, Z, Gone, &[]);
    let fin = w.push(N5, 5, &[], A, Kind::finalize(q));
    let leave = w.edge(X, 7, &[], A, X, Gone, &[]);
    let _ = (gx, B);
    (w, [gn, inv, junk, rz, fin, leave, gx])
}

// spec/permissions.md §4: draft Chained writes: an invite grant is chained by its path's invite
// (N5 holds write and invite write on A), a grant by a holder with no invite is not; a removal by
// admin, a finalize by write and a self-removal along its empty path are chained.
#[test]
fn each_kind_of_part_is_chained_by_what_it_needs() {
    let (w, [gn, inv, junk, rz, fin, leave, gx]) = kinds();
    let v = View::all(&w);
    assert_eq!(diff(&w, &v), None);
    let inp = input(&w, &v);
    let p = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
    let chained = |i: Id| p.is_chained(&inp.ids[&i]);
    for i in [gn, inv, rz, fin, leave, gx] {
        assert_eq!(chained(i), Some(true), "part {i}");
    }
    assert_eq!(chained(junk), Some(false));
}

// spec/permissions.md §4: chained-ness flips are reported in every arrival order (a part turning
// chained when its path's setter arrives), and on forget: H's grant of N5 forgotten, N5's invite
// grant and finalize are no longer chained, and `Changed::chained` names exactly those.
#[test]
fn chained_flips_are_reported_on_arrival_and_forget() {
    let (w, [gn, inv, _, _, fin, ..]) = kinds();
    let v = View::all(&w);
    let inp = input(&w, &v);
    let full = Paths::evaluate(&inp.records, BTreeSet::new(), &inp.commits);
    // arrivals in reverse: each part turning chained when what it reads arrives
    let mut p = Paths::new(&inp.records, BTreeSet::new());
    for c in inp.commits.iter().rev() {
        let before = p.clone();
        let ch = p.add(std::slice::from_ref(c));
        assert_eq!(check(&before, &p, &ch), None, "adding {:?}", c.id);
    }
    let mut p = full.clone();
    let ch = p.forget(&[inp.ids[&gn].0]);
    assert_eq!(check(&full, &p, &ch), None);
    assert_eq!(ch.chained, BTreeSet::from([inp.ids[&gn], inp.ids[&inv], inp.ids[&fin]]));
    assert_eq!(p.is_chained(&inp.ids[&inv]), Some(false));
}
