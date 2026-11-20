//! How the walk's work scales (notes/perm-paths.md, Cost shapes), counted at n and 10n: a part
//! appended at the end, a backdated part, a lowering applying with drops, a void lowering's check,
//! from scratch; content (step 3b): a delta appended, a removal cutting n deltas, a cut delta's
//! query, k addenda arriving one at a time. Where step 3a does not meet a shape step 7 owes, the test asserts what is true
//! and notes/perm-paths.md says what is owed.
//! spec: none (cost, notes/perm-paths.md; the rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts, WallMs};
use osis_perm::paths::{By, Commit, Content, Counts, Delta, DeltaClass, EdgeWrite, Part, PartKind, Paths, Status};
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

/// Both walks (the first and the timeline, notes/perm-paths.md) do each walk's work: the walk
/// counts below are per walk, times this.
const W: u64 = 2;

fn delta(a: Counts, b: Counts) -> Counts {
    Counts { steps: b.steps - a.steps, passes: b.passes - a.passes, restarts: b.restarts - a.restarts, setters: b.setters - a.setters, audited: b.audited - a.audited, scratch: b.scratch - a.scratch, content: b.content - a.content, addenda: b.addenda - a.addenda }
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
        assert_eq!((d.steps, d.passes, d.restarts, d.audited), (W, W, 0, 0), "grant at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(1), 0)), Some(Status::Applied));
        // holder 0, admin on A, grants X on C (minted with A) through [A]: two hops
        let (d, p) = cost_of(&history(n), write(2, holder(0), end, &[A], C, X, Some(Role::Read)));
        assert_eq!((d.steps, d.passes), (W, W), "path at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Applied));
        let (d, p) = cost_of(&history(n), write(3, H, end, &[], A, holder(1), None));
        assert_eq!((d.steps, d.passes, d.restarts, d.audited), (W, W, 0, 0), "removal at n {n}: {d:?}");
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
        assert_eq!((d.steps, d.passes), (W * (n as u64 + 1), W), "on A at n {n}: {d:?}");
        let (d, _) = cost_of(&history(n), write(2, H, 1, &[], B, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes), (W * (n as u64 + 1), W), "on B at n {n}: {d:?}");
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
        assert_eq!(d.restarts, W, "{d:?}");
        assert_eq!(d.audited, W * k as u64, "{d:?}");
        // the removal, then from the earliest drop: the n grants and the removal again
        assert_eq!(d.steps, W * (1 + n as u64 + 1), "{d:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(10 + i as u64), 0)) == Some(Status::Dropped)));
    }
}

// Restarts multiply: k lowerings at the end, each dropping one early write, restart k times, each
// from its drop, walking the n parts after it again: about k·n steps (k = 10, n = 100 and 1000:
// tenfold). A party holding admin forces it with its own 3k writes (k holders it grants, one grant
// by each, its removals of them listing nothing). Step 7's components bound it by the component.
#[test]
fn k_lowerings_with_drops_restart_k_times() {
    let k = 10u32;
    let mut per = vec![];
    for n in [100u32, 1000] {
        let y = |i: u32| 7000 + i;
        let mut base: Vec<Commit> = (0..k).map(|i| write(20 + i as u64, H, 1, &[], A, y(i), Some(Role::Admin))).collect();
        base.extend((0..k).map(|i| write(40 + i as u64, y(i), 2, &[], A, holder(8000 + i), Some(Role::Admin))));
        base.extend(history(n));
        let end = 10 + n as u64 + 5;
        base.extend((0..k).map(|i| write(60 + i as u64, H, end + i as u64, &[], A, y(i), None)));
        let p = Paths::evaluate(&records(), BTreeSet::new(), &base);
        let c = p.counts();
        assert_eq!(c.restarts, W * k as u64, "{c:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(40 + i as u64), 0)) == Some(Status::Dropped)));
        per.push(c.steps);
    }
    assert!(per[1] >= 9 * per[0] && per[1] <= 11 * per[0], "{per:?}");
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
        assert_eq!((d.steps, d.restarts), (W, 0), "{d:?}");
        per.push(d.setters);
        let all = Paths::evaluate(&records(), BTreeSet::new(), &chain(k, k));
        assert_eq!(all.counts().restarts, 0);
        per.push(all.counts().setters);
    }
    // one check: linear in k; k checks: quadratic
    assert!(per[2] >= 9 * per[0] && per[2] <= 11 * per[0], "{per:?}");
    assert!(per[3] >= 90 * per[1], "{per:?}");
}

// One void check reads each edge position once (notes/perm-paths.md, The void check): H grants X;
// X grants F admin m times (each resting on X's edge); F grants E admin m times after them (each
// through F's edge); E removes X listing nothing. Its drops are X's m grants of F; chasing each of
// F's grants of E scans F's edge below it, which the check caches per position after the first
// scan: about 2m setters (m = 10 and 100: tenfold), and the removal is void. Mutation: no cache
// (`chk.found` never read): m², a hundredfold.
#[test]
fn a_void_check_reads_each_setter_once() {
    const F: u32 = 20;
    const E: u32 = 21;
    let mut per = vec![];
    for m in [10u32, 100] {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        c.extend((0..m).map(|i| write(100 + i as u64, X, 2 + i as u64, &[], A, F, Some(Role::Admin))));
        c.extend((0..m).map(|i| write(1000 + i as u64, F, 1000 + i as u64, &[], A, E, Some(Role::Admin))));
        let base = c.clone();
        let (d, p) = cost_of(&base, write(9, E, 5000, &[], A, X, None));
        assert_eq!(p.status(&WriteId(cid(9), 0)), Some(Status::Void));
        per.push(d.setters);
    }
    assert!(per[1] >= 9 * per[0] && per[1] <= 11 * per[0], "{per:?}");
}

// From scratch: one step per part (no lowering, no restart), so linear in the parts.
#[test]
fn from_scratch_is_linear_in_the_parts() {
    let small = Paths::evaluate(&records(), BTreeSet::new(), &history(100)).counts();
    let large = Paths::evaluate(&records(), BTreeSet::new(), &history(1000)).counts();
    assert_eq!((small.steps, small.passes, large.steps, large.passes), (W * 100, W, W * 1000, W));
}

/// A content commit of one plain delta by `signer` on `on` along `path` (an addendum: `against`
/// removal listing `list`).
fn content(id: u64, signer: u32, ts: u64, path: &[u32], on: u32, against: Option<(u64, &[u64])>) -> Commit {
    let class = match against {
        Some((r, l)) => DeltaClass::Addendum { removal: cid(r), list: Frontier::new(l.iter().map(|&i| cid(i))) },
        None => DeltaClass::Plain,
    };
    let aspect = Ak::new(if against.is_some() { "addenda.0" } else { "doc.0" }).unwrap();
    let d = Delta { aspect, needs: Role::Write, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class };
    Commit { id: cid(id), ts: Ts::make(WallMs(ts), 0).unwrap(), signer: t(signer), parts: vec![Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), kind: PartKind::Delta(d) }] }
}

/// H grants X admin on A at 1; X writes n deltas on C (minted with A) along [A] at 10..; the
/// history of grants follows.
fn writes(n: u32) -> Vec<Commit> {
    let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
    c.extend((0..n).map(|i| content(200_000 + i as u64, X, 10 + i as u64, &[A], C, None)));
    c.extend(history(n));
    c
}

// spec/permissions.md §5.2: a delta appended at the end costs no walk step and its query reads its
// path's edges alone, whatever the history.
#[test]
fn an_appended_delta_is_a_point_query() {
    let mut per = vec![];
    for n in [100u32, 1000] {
        let end = 10 + n as u64 + 5;
        let (d, p) = cost_of(&writes(n), content(9, X, end, &[A], C, None));
        assert_eq!((d.steps, d.passes, d.addenda), (0, 0, 0), "{d:?}");
        let mut q = Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(9), 0), &mut q), Some(Content::Valid(By::Held)));
        per.push(q.content);
    }
    assert_eq!(per[0], per[1], "{per:?}");
}

// spec/permissions.md §5.2: a removal cutting n deltas costs its own walk step: nothing per delta
// it cuts, and `Changed` names one cut on X's edge; each cut delta's query then reads its path and
// the removal naming it.
#[test]
fn a_removal_cutting_n_deltas_costs_nothing_per_delta() {
    let mut per = vec![];
    for n in [100u32, 1000] {
        let end = 10 + n as u64 + 5;
        let mut p = Paths::evaluate(&records(), BTreeSet::new(), &writes(n));
        let before = p.counts();
        // listing the first delta: it stays, by the list; the rest fall
        let mut r = write(2, H, end, &[], A, X, None);
        if let PartKind::Edge(ew) = &mut r.parts[0].kind {
            ew.frontier = Some(Arc::new(Frontier::new([cid(200_000)])));
        }
        let ch = p.add(&[r]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.content), (W, 0), "{d:?}");
        assert_eq!(ch.cuts.keys().copied().collect::<Vec<_>>(), vec![(t(X), t(A))]);
        assert!(ch.parts.len() == 1 && ch.named.is_empty(), "{ch:?}");
        let mut q = Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(200_000), 0), &mut q), Some(Content::Valid(By::Listed)));
        assert_eq!(p.content_counted(&WriteId(cid(200_001), 0), &mut q), Some(Content::Invalid));
        per.push(q.content);
    }
    assert_eq!(per[0], per[1], "{per:?}");
}

// spec/permissions.md §5.2: k addenda arriving one at a time grow the fixpoint from where it stood:
// work linear in k (k = 100 and 1000: tenfold), not k².
#[test]
fn addenda_arriving_one_at_a_time_cost_linear_work() {
    let mut per = vec![];
    for k in [100u64, 1000] {
        let mut p = Paths::evaluate(&records(), BTreeSet::new(), &writes(10));
        p.add(&[write(2, H, 50, &[], A, X, None)]);
        let before = p.counts();
        for i in 0..k {
            p.add(&[content(300_000 + i, H, 60 + i, &[A], C, Some((2, &[200_000])))]);
        }
        let d = delta(before, p.counts());
        assert_eq!(d.steps, 0, "{d:?}");
        assert_eq!(p.content(&WriteId(cid(200_000), 0)), Some(Content::Valid(By::Vouched)));
        per.push(d.addenda);
    }
    assert!(per[1] >= 9 * per[0] && per[1] <= 11 * per[0], "{per:?}");
}

// spec/permissions.md §5.2: a delta's query reads one cut per hop (the edge's last), however many
// cuts its edge holds: X's delta under k removals of X, each followed by a re-grant, reads the same
// at k = 10 and 100 (valid again by the re-grant).
#[test]
fn a_delta_under_k_cuts_is_a_point_query() {
    let mut per = vec![];
    for k in [10u64, 100] {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin)), content(9, X, 5, &[A], C, None)];
        for i in 0..k {
            c.push(write(10 + 2 * i, H, 10 + 2 * i, &[], A, X, None));
            c.push(write(11 + 2 * i, H, 11 + 2 * i, &[], A, X, Some(Role::Admin)));
        }
        let p = Paths::evaluate(&records(), BTreeSet::new(), &c);
        assert_eq!(p.writes(&t(X), &t(A)).iter().filter(|w| w.cuts(Role::Write)).count() as u64, k);
        let mut q = Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(9), 0), &mut q), Some(Content::Valid(By::Regranted)));
        per.push(q.content);
    }
    assert_eq!(per[0], per[1], "{per:?}");
}

// Owed (notes/perm-paths.md, Cost shapes, attacker-drivable): any update that changes the walk,
// one stranger's edge write that applies nowhere among them, judges every held addendum again
// (the fixpoint from scratch over every thing): k = 100 and 1000 addenda, tenfold work.
#[test]
fn any_walk_change_judges_every_addendum_again() {
    let mut per = vec![];
    for k in [100u64, 1000] {
        let mut c = writes(10);
        c.push(write(2, H, 50, &[], A, X, None));
        c.extend((0..k).map(|i| content(300_000 + i, H, 60 + i, &[A], C, Some((2, &[200_000])))));
        let (d, p) = cost_of(&c, write(3, 99, 5000, &[], A, holder(7), Some(Role::Admin)));
        assert_eq!(p.status(&WriteId(cid(3), 0)), Some(Status::Unapplied));
        per.push(d.addenda);
    }
    assert!(per[1] >= 9 * per[0], "{per:?}");
}
