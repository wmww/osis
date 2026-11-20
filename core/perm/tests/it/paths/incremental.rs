//! Incremental update is from-scratch evaluation restricted to what changed (notes/perm-paths.md,
//! One definition): commits added one at a time in any arrival order read as the walk of all of
//! them from scratch, and each update's `Changed` names exactly the parts whose status changed
//! and, per edge, the first key from which its history changed.
//! spec: none (the walk's update path; its rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{input, rules, MODES};
use osis_base::{Role, Tid};
use osis_perm::paths::{Changed, History, Paths, Status};
use osis_perm::WriteId;
use roles_model::paths as m;
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};

type Finals = BTreeMap<(Tid, Tid), (Option<Role>, Option<Role>)>;
type Reading = (BTreeMap<WriteId, Status>, BTreeMap<(Tid, Tid), History>, Finals);

fn reading(p: &Paths) -> Reading {
    (p.statuses(), p.histories(), p.finals())
}

/// What changed from `a` to `b`, read from the two readings.
fn diff(a: &Paths, b: &Paths) -> Changed {
    let (sa, ha, _) = reading(a);
    let (sb, hb, _) = reading(b);
    let mut out = Changed::default();
    for (id, s) in &sb {
        if sa.get(id) != Some(s) {
            out.parts.insert(*id);
        }
    }
    let empty = vec![];
    let edges: BTreeSet<&(Tid, Tid)> = ha.keys().chain(hb.keys()).collect();
    for e in edges {
        let (x, y) = (ha.get(e).unwrap_or(&empty), hb.get(e).unwrap_or(&empty));
        let at = x.iter().zip(y).position(|(p, q)| p != q).unwrap_or(x.len().min(y.len()));
        if let Some(k) = x.get(at).map(|p| p.0).into_iter().chain(y.get(at).map(|q| q.0)).min() {
            out.edges.insert(*e, k);
        }
    }
    out
}

/// Tiny world `i` of `mode`, its commits added one at a time in a shuffled order: each `Changed`
/// against the readings, and the end against from scratch.
fn check(i: u64, mode: m::TinyMode) -> Option<String> {
    let t = m::tiny_world(i, mode, &rules());
    let inp = input(&t.w, &t.v);
    let mut order = inp.commits.clone();
    let mut rng = Rng(i);
    for k in (1..order.len()).rev() {
        order.swap(k, rng.below(k + 1));
    }
    let mut p = Paths::new(&inp.records, inp.trust.clone());
    for c in &order {
        let before = p.clone();
        let ch = p.add(std::slice::from_ref(c));
        let want = diff(&before, &p);
        if ch != want {
            return Some(format!("world {i} {mode:?}: adding {:?}: reported {ch:?}, readings differ by {want:?}", c.id));
        }
    }
    let scratch = Paths::evaluate(&inp.records, inp.trust.clone(), &inp.commits);
    (reading(&p) != reading(&scratch)).then(|| format!("world {i} {mode:?}: incremental and from scratch differ"))
}

// Every commit order reads as from scratch, and each update reports what it changed.
#[test]
fn incremental_equals_from_scratch() {
    let fails: Vec<String> = MODES.iter().flat_map(|&mode| (0..200).filter_map(move |i| check(i, mode))).take(3).collect();
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}

// As above, more worlds (a property).
#[test]
#[ignore]
fn paths_incremental_agrees_large() {
    let f: Vec<String> = crate::common::sharded(60_000, 0x5eed_0a1c, |n, seed| {
        let start = crate::common::seeded(seed) % (1 << 40);
        MODES.iter().flat_map(|&mode| (start..start + n.div_ceil(6)).filter_map(move |i| check(i, mode))).take(3).collect::<Vec<_>>()
    })
    .concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}
