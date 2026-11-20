//! How the walk's work scales (notes/perm-paths.md, Cost shapes), counted at n and 10n: a part
//! appended at the end, a backdated part, a lowering applying with drops, a void lowering's check,
//! from scratch. Where step 3a does not meet a shape step 7 owes, the test asserts what is true
//! and notes/perm-paths.md says what is owed.
//! spec: none (cost, notes/perm-paths.md; the rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{CommitId, Role, Tid, Ts, WallMs};
use osis_perm::paths::{Commit, Counts, EdgeWrite, Part, PartKind, Paths, Status};
use osis_perm::{Edge, Frontier, WriteId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn t(n: u32) -> Tid {
    let mut b = [0u8; 15];
    b[..4].copy_from_slice(&n.to_be_bytes());
    Tid::from_bytes(b)
}

const H: u32 = 1;
const X: u32 = 2;
/// Things minted by H, and C minted with A.
const A: u32 = 10;
const B: u32 = 11;
const C: u32 = 12;
/// Holders granted by the histories.
fn holder(i: u32) -> u32 {
    1000 + i
}

fn records() -> BTreeMap<Tid, Tid> {
    BTreeMap::from([(t(A), t(H)), (t(B), t(H)), (t(C), t(A))])
}

/// A commit of one edge write by `signer` at `ts` (whole ms) on `on` along `path`, setting
/// `holder`'s edge to `role` (none: a removal listing nothing).
fn write(id: u64, signer: u32, ts: u64, path: &[u32], on: u32, holder: u32, role: Option<Role>) -> Commit {
    let frontier = Some(Arc::new(Frontier::new([])));
    let ew = EdgeWrite { holder: t(holder), value: role.map(Edge::new), frontier, remains: Some(t(H)), adminless: false };
    Commit { id: cid(id), ts: Ts::make(WallMs(ts), 0).unwrap(), signer: t(signer), parts: vec![Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Edge(ew) }] }
}

fn cid(id: u64) -> CommitId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&id.to_be_bytes());
    CommitId(b)
}

fn delta(a: Counts, b: Counts) -> Counts {
    Counts { steps: b.steps - a.steps, passes: b.passes - a.passes, restarts: b.restarts - a.restarts, setters: b.setters - a.setters, audited: b.audited - a.audited, scratch: b.scratch - a.scratch }
}

/// H grants n holders admin on A, one commit each at ts 10..: a history of n parts.
fn history(n: u32) -> Vec<Commit> {
    (0..n).map(|i| write(100 + i as u64, H, 10 + i as u64, &[], A, holder(i), Some(Role::Admin))).collect()
}

/// The work one `add` of `c` does over `base`.
fn cost_of(base: &[Commit], c: Commit) -> (Counts, Paths) {
    let mut p = Paths::evaluate(&records(), BTreeSet::new(), base);
    let before = p.counts();
    p.add(&[c]);
    (delta(before, p.counts()), p)
}

// A part appended at the end of key order costs its own step, at any history: a grant, a write
// through a path of two hops, and a removal (its audit reads the parts resting on its edge only).
#[test]
fn an_appended_part_costs_its_own_step() {
    for n in [100, 1000] {
        let end = 10 + n as u64 + 5;
        let (d, p) = cost_of(&history(n), write(1, H, end, &[], A, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes, d.restarts, d.audited), (1, 1, 0, 0), "grant at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(1), 0)), Some(Status::Applied));
        // holder 0, admin on A, grants X on C (minted with A) through [A]: two hops
        let (d, p) = cost_of(&history(n), write(2, holder(0), end, &[A], C, X, Some(Role::Read)));
        assert_eq!((d.steps, d.passes), (1, 1), "path at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Applied));
        let (d, p) = cost_of(&history(n), write(3, H, end, &[], A, holder(1), None));
        assert_eq!((d.steps, d.passes, d.restarts, d.audited), (1, 1, 0, 0), "removal at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(3), 0)), Some(Status::Applied));
    }
}

// A backdated part walks again every part after it (step 3a has one walk over every thing):
// work n + 1 at n, also for a part on a thing no part of the history touches. Step 7 owes
// components: the latter then costs its own step.
#[test]
fn a_backdated_part_walks_again_what_follows_it() {
    for n in [100u32, 1000] {
        let (d, _) = cost_of(&history(n), write(1, H, 1, &[], A, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes), (n as u64 + 1, 1), "on A at n {n}: {d:?}");
        let (d, _) = cost_of(&history(n), write(2, H, 1, &[], B, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes), (n as u64 + 1, 1), "on B at n {n}: {d:?}");
    }
}

// A lowering applying with drops restarts once, from its earliest drop: X, granted at 1, grants k
// holders on A at 2; n unrelated grants follow; H removes X at the end listing nothing. The
// restart walks the n grants again (they follow the earliest drop), never the history before it.
#[test]
fn a_lowering_with_drops_restarts_once_from_its_earliest_drop() {
    let k = 5u32;
    for n in [100u32, 1000] {
        let mut base = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        base.extend((0..k).map(|i| write(10 + i as u64, X, 2, &[], A, holder(5000 + i), Some(Role::Admin))));
        base.extend(history(n));
        let end = 10 + n as u64 + 5;
        let (d, p) = cost_of(&base, write(2, H, end, &[], A, X, None));
        assert_eq!(d.restarts, 1, "{d:?}");
        assert_eq!(d.audited, k as u64, "{d:?}");
        // the removal, then from the earliest drop: the n grants and the removal again
        assert_eq!(d.steps, 1 + n as u64 + 1, "{d:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(10 + i as u64), 0)) == Some(Status::Dropped)));
    }
}

/// X grants z0 admin, each zi grants zi+1 (k grants); z(k-1) removes X `voids` times listing
/// nothing: each removal would drop X's grant of z0, its own chain: void.
fn chain(k: u32, voids: u32) -> Vec<Commit> {
    let z = |i: u32| 3000 + i;
    let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin)), write(2, X, 2, &[], A, z(0), Some(Role::Admin))];
    for i in 1..k {
        c.push(write(10 + i as u64, z(i - 1), 2 + i as u64, &[], A, z(i), Some(Role::Admin)));
    }
    for v in 0..voids {
        c.push(write(100_000 + v as u64, z(k - 1), 10_000 + v as u64, &[], A, X, None));
    }
    c
}

// A void lowering's check reads back along its own grant chain (finding 17): one appended void
// removal at the end of a chain of k grants reads about k setters; k of them, k² (accepted:
// notes/a1-spec/README.md, Open 2).
#[test]
fn a_void_check_reads_its_own_grant_chain() {
    let mut per = vec![];
    for k in [10u32, 100] {
        let base = chain(k, 0);
        let (d, p) = cost_of(&base, chain(k, 1).pop().unwrap());
        assert_eq!(p.status(&WriteId(cid(100_000), 0)), Some(Status::Void));
        assert_eq!((d.steps, d.restarts), (1, 0), "{d:?}");
        per.push(d.setters);
        let all = Paths::evaluate(&records(), BTreeSet::new(), &chain(k, k));
        assert_eq!(all.counts().restarts, 0);
        per.push(all.counts().setters);
    }
    // one check: linear in k; k checks: quadratic
    assert!(per[2] >= 9 * per[0] && per[2] <= 11 * per[0], "{per:?}");
    assert!(per[3] >= 90 * per[1], "{per:?}");
}

// From scratch: one step per part (no lowering, no restart), so linear in the parts.
#[test]
fn from_scratch_is_linear_in_the_parts() {
    let small = Paths::evaluate(&records(), BTreeSet::new(), &history(100)).counts();
    let large = Paths::evaluate(&records(), BTreeSet::new(), &history(1000)).counts();
    assert_eq!((small.steps, small.passes, large.steps, large.passes), (100, 1, 1000, 1));
}
