//! How the walk's work scales (notes/perm-paths.md, Cost shapes; Counts), counted at n and 10n:
//! a part appended at the end, a backdated part (its component alone), a lowering applying with
//! drops, a void lowering's check, from scratch; content: a delta appended, a removal cutting n
//! deltas, a cut delta's query, k addenda arriving one at a time, addenda judged again only where
//! an update reaches them; components: an appended part among c components, a merge, a trusted
//! component, a forget. Each names the mutation that breaks its shape.
//! spec: none (cost, notes/perm-paths.md; the rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts, WallMs};
use osis_perm::paths::{By, Commit, Content, Counts, Delta, DeltaClass, EdgeWrite, Fact, Key, MemStore, Pair, Part, PartKind, Paths, Status, Store};
use std::cell::Cell;
use std::ops::Bound;
use std::rc::Rc;
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

/// The walks doing each walk's work: the timeline alone, since the first walk runs only in a
/// component holding a vouch (notes/perm-paths.md, Two walks) and no world here holds one but
/// `the_first_walk_runs_only_where_a_vouch_is`'s.
const W: u64 = 1;

fn delta(a: Counts, b: Counts) -> Counts {
    Counts {
        steps: b.steps - a.steps,
        passes: b.passes - a.passes,
        restarts: b.restarts - a.restarts,
        setters: b.setters - a.setters,
        audited: b.audited - a.audited,
        scratch: b.scratch - a.scratch,
        content: b.content - a.content,
        addenda: b.addenda - a.addenda,
        merged: b.merged - a.merged,
        chained: b.chained - a.chained,
    }
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

// A backdated part walks again only the parts whose step reads what it changed
// (notes/perm-paths.md, Reach): H removes X from A early, before X's m writes on C (minted with A)
// through [A] and after n grants on A: the removal and X's m writes, the same at n = 100, 1000 and
// 10,000; a grant on B, which nothing reads, its own step. The control: the whole walk
// (`Paths::whole`), every part of the component after the key: n + m + 1.
#[test]
fn a_backdated_part_walks_again_what_reads_its_change() {
    let m = 5u32;
    let base = |n: u32| {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        c.extend(history(n));
        c.extend((0..m).map(|i| write(50 + i as u64, X, 20 + n as u64 + i as u64, &[A], C, holder(9000 + i), Some(Role::Read))));
        c
    };
    for n in [100u32, 1000, 10_000] {
        let (d, p) = cost_of(&base(n), write(2, H, 5, &[], A, X, None));
        // a removal sets no chained point (draft §4: chained writes are never removed)
        assert_eq!((d.steps, d.passes, d.chained), (W * (1 + m as u64), W, 0), "on A at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(50), 0)), Some(Status::Unapplied));
        let (d, _) = cost_of(&base(n), write(3, H, 5, &[], B, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes, d.chained), (W, W, 1), "on B at n {n}: {d:?}");
    }
    let mut p = Paths::whole(&records(), BTreeSet::new());
    p.add(&base(100));
    let before = p.counts();
    p.add(&[write(2, H, 5, &[], A, X, None)]);
    let d = delta(before, p.counts());
    assert_eq!(d.steps, 100 + m as u64 + 1, "{d:?}");
}

/// Things 100.. minted by H, `c` of them.
fn many(c: u32) -> BTreeMap<Tid, Tid> {
    let mut r = records();
    r.extend((0..c).map(|i| (t(100 + i), t(H))));
    r
}

/// H grants `k` holders admin on each of `c` things, at ts 10..: c components of k parts.
fn components(c: u32, k: u32) -> Vec<Commit> {
    (0..c).flat_map(|i| (0..k).map(move |j| write(1_000_000 + (i * k + j) as u64, H, 10 + j as u64, &[], 100 + i, holder(j), Some(Role::Admin)))).collect()
}

// Components bound what an update forgets of the event log (notes/perm-paths.md, Reach, What stays
// component-wide): among c components of k grants and one later removal each, a part appended on
// one costs its own step; one backdated there its step and its own component's removal judged
// again (the verdict given after the walk reached its key), the same at c = 10, 100 and 1000. The
// control: partitioning off (`Paths::single`, one component, walked whole): c(k + 1) + 1.
#[test]
fn a_part_among_c_components_walks_its_own() {
    let k = 20u32;
    let base = |c: u32| {
        let mut b = components(c, k);
        b.extend((0..c).map(|i| write(2_000_000 + i as u64, H, 1000, &[], 100 + i, holder(0), None)));
        b
    };
    for c in [10u32, 100, 1000] {
        let mut p = Paths::evaluate(&many(c), BTreeSet::new(), &base(c));
        let before = p.counts();
        p.add(&[write(1, H, 5000, &[], 100, X, Some(Role::Admin))]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.passes), (W, W), "appended at c {c}: {d:?}");
        let before = p.counts();
        p.add(&[write(2, H, 1, &[], 100, Y, Some(Role::Admin))]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.passes), (W * 2, W), "backdated at c {c}: {d:?}");
    }
    let c = 10;
    let mut p = Paths::single(&many(c), BTreeSet::new());
    p.add(&base(c));
    let before = p.counts();
    p.add(&[write(2, H, 1, &[], 100, Y, Some(Role::Admin))]);
    assert_eq!(delta(before, p.counts()).steps, (c * (k + 1) + 1) as u64);
}

const Y: u32 = 3;

// A merge moves the smaller component's entries into the larger (notes/perm-paths.md, Merge),
// then walks from the joining part's key: A holds 20 holders' grants, B one holder granted n
// times (fewer edges, more entries) and A granted on B; X, granted on A, writes on B along [A]
// at the end, joining them: n's entries do not move. Mutation: no swap in `absorb` (the root
// component, by edges, absorbs the other's maps whatever their size): about 3n moved.
#[test]
fn a_merge_moves_the_smaller_components_entries() {
    let mut per = vec![];
    for n in [100u32, 1000] {
        let mut base: Vec<Commit> = (0..20).map(|i| write(10 + i as u64, H, 2, &[], A, holder(i), Some(Role::Admin))).collect();
        base.push(write(1, H, 1, &[], A, X, Some(Role::Admin)));
        base.push(write(2, H, 1, &[], B, A, Some(Role::Admin)));
        base.extend((0..n).map(|i| write(1000 + i as u64, H, 10 + i as u64, &[], B, Y, Some(Role::Admin))));
        let (d, p) = cost_of(&base, write(3, X, 5000, &[A], B, holder(99), Some(Role::Write)));
        assert_eq!(p.status(&WriteId(cid(3), 0)), Some(Status::Applied));
        assert_eq!((d.steps, d.passes), (W, W), "{d:?}");
        per.push(d.merged);
    }
    assert!(per[0] == per[1] && per[0] < 200, "{per:?}");
}

// A part whose stated path has an edge no held write could set is inert: it is walked by no
// component and joins none (notes/perm-paths.md, Inert parts). Things T0..T(k-1) (100..), each
// T(i) granted admin on T(i+1) by H (k components) and X on T0: a stranger's grant on T(k-1)
// along [T0..T(k-2)] (its first edge held by nobody) walks nothing and merges nothing; X's along
// the same path joins the k components, moving about one component's entries each: k = 100 and
// 1000, tenfold. Mutation: no part inert: the stranger's merges as much as X's.
#[test]
fn a_path_joins_components_only_through_held_edges() {
    let mut per = vec![];
    for k in [100u32, 1000] {
        let mut base = vec![write(1, H, 1, &[], 100, X, Some(Role::Admin))];
        base.extend((1..k).map(|i| write(10 + i as u64, H, 2, &[], 100 + i, 100 + i - 1, Some(Role::Admin))));
        let things: Vec<u32> = (0..k - 1).map(|i| 100 + i).collect();
        let mut p = Paths::evaluate(&many(k), BTreeSet::new(), &base);
        let before = p.counts();
        p.add(&[write(2, 999, 5000, &things, 100 + k - 1, holder(1), Some(Role::Admin))]);
        let d = delta(before, p.counts());
        assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Unapplied));
        assert_eq!((d.steps, d.merged), (0, 0), "the stranger's at k {k}: {d:?}");
        let before = p.counts();
        p.add(&[write(3, X, 5000, &things, 100 + k - 1, holder(1), Some(Role::Admin))]);
        let d = delta(before, p.counts());
        assert_eq!(p.status(&WriteId(cid(3), 0)), Some(Status::Applied));
        assert_eq!(d.steps, W, "X's at k {k}: {d:?}");
        per.push(d.merged);
    }
    assert!(per[1] >= 9 * per[0] && per[1] <= 11 * per[0], "{per:?}");
}

// A trusted component takes an appended part in its own step: the trust set's seeds are counted
// per part and read again only where they change (notes/perm-paths.md, Trust per component). X,
// granted at 1, grants 5 holders at 2 (resting on X's edge); n grants follow; H's removal of X
// at the end is trusted. Mutation: every active trusted write's seeds read again on each update
// (`set_active` puts every trusted write aside and back): about n + 6 steps per walk.
#[test]
fn a_trusted_component_takes_an_appended_part_in_its_own_step() {
    for n in [100u32, 1000] {
        let mut base = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        base.extend((0..5).map(|i| write(10 + i as u64, X, 2, &[], A, holder(5000 + i), Some(Role::Admin))));
        base.extend(history(n));
        let end = 10 + n as u64 + 5;
        base.push(write(2, H, end, &[], A, X, None));
        let trust = BTreeSet::from([WriteId(cid(2), 0)]);
        let mut p = Paths::evaluate(&records(), trust, &base);
        assert_eq!(p.status(&WriteId(cid(10), 0)), Some(Status::Dropped));
        let before = p.counts();
        p.add(&[write(3, H, end + 1, &[], A, holder(7777), Some(Role::Admin))]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.passes, d.scratch), (W, W, 0), "at n {n}: {d:?}");
    }
}

// Forgetting a content commit walks nothing (no verdict of a delta is stored); forgetting an edge
// part walks what read it (notes/perm-paths.md, Forget and update; Reach): X's grant, which no
// part's path reads (X's deltas are content), its own step beside n grants on A and n on B. The
// control: the whole walk, A's n grants after it.
#[test]
fn a_forget_walks_what_read_the_part() {
    for n in [100u32, 1000] {
        let mut base = writes(n);
        base.extend((0..n).map(|i| write(500_000 + i as u64, H, 10 + i as u64, &[], B, holder(i), Some(Role::Admin))));
        let mut p = Paths::evaluate(&records(), BTreeSet::new(), &base);
        let before = p.counts();
        p.forget(&[cid(200_000)]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.passes), (0, 0), "a delta at n {n}: {d:?}");
        let before = p.counts();
        p.forget(&[cid(1)]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.passes), (W, W), "an edge part at n {n}: {d:?}");
        let mut p = Paths::whole(&records(), BTreeSet::new());
        p.add(&base);
        let before = p.counts();
        p.forget(&[cid(1)]);
        assert_eq!(delta(before, p.counts()).steps, n as u64 + 1, "whole at n {n}");
    }
}


// A lowering applying with drops restarts once, from its earliest drop: X, granted at 1, grants k
// holders on A at 2; n unrelated grants follow; H removes X at the end listing nothing. The
// restart walks its k drops again, which nothing reads, never the n grants after them (the
// whole walk: those too).
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
        // the removal, then its drops
        assert_eq!(d.steps, W * (1 + k as u64), "{d:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(10 + i as u64), 0)) == Some(Status::Dropped)));
        let mut p = Paths::whole(&records(), BTreeSet::new());
        p.add(&base);
        let before = p.counts();
        p.add(&[write(2, H, end, &[], A, X, None)]);
        assert_eq!(delta(before, p.counts()).steps, 1 + k as u64 + n as u64 + 1, "whole at n {n}");
    }
}

// Restarts multiply: k lowerings at the end, each dropping one early write, restart k times, each
// walking its drop again (nothing reads it): from scratch n + 4k steps over n + 3k parts. The
// whole walk restarts from each drop through the n parts after it: about k·n (k = 10, n = 100
// and 1000: tenfold), which a party holding admin forces with its own 3k writes (k holders it
// grants, one grant by each, its removals of them listing nothing).
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
        assert_eq!((c.restarts, c.steps), (W * k as u64, n as u64 + 4 * k as u64), "{c:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(40 + i as u64), 0)) == Some(Status::Dropped)));
        let mut w = Paths::whole(&records(), BTreeSet::new());
        w.add(&base);
        per.push(w.counts().steps);
    }
    // the whole walk: k·n and the parts once (1,240 and 11,140)
    assert!(per[1] >= 8 * per[0] && per[1] <= 11 * per[0], "{per:?}");
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

// An update judges again only the addenda it reaches (notes/perm-paths.md, Counting entries and
// addenda, by reach): Y's k addenda along [A] against H's removal of X; a stranger's write that
// applies nowhere, a grant on B and a grant on A after them judge none, at k = 100 and 1000; a
// grant of Y backdated before them reaches every one (its edge changes before their positions):
// tenfold. Mutation: every addendum judged again on each update: k for the others too.
#[test]
fn an_update_judges_again_only_the_addenda_it_reaches() {
    let mut per = vec![];
    for k in [100u64, 1000, 10_000] {
        let mut c = writes(10);
        c.push(write(2, H, 50, &[], A, X, None));
        c.push(write(4, H, 1, &[], A, Y, Some(Role::Admin)));
        c.extend((0..k).map(|i| content(300_000 + i, Y, 60 + i, &[A], C, Some((2, &[200_000])))));
        assert_eq!(Paths::evaluate(&records(), BTreeSet::new(), &c).content(&WriteId(cid(200_000), 0)), Some(Content::Valid(By::Vouched)));
        for w in [write(3, 99, 5000, &[], A, holder(7), Some(Role::Admin)), write(3, H, 5000, &[], B, holder(7), Some(Role::Admin)), write(3, H, 5000, &[], A, holder(7), Some(Role::Admin))] {
            let (d, _) = cost_of(&c, w);
            assert_eq!(d.addenda, 0, "{d:?}");
        }
        let (d, _) = cost_of(&c, write(3, H, 2, &[], A, Y, Some(Role::Admin)));
        per.push(d.addenda);
    }
    assert!(per[1] >= 9 * per[0] && per[1] <= 11 * per[0] && per[2] >= 9 * per[1] && per[2] <= 11 * per[1], "{per:?}");
}

// The first walk (vouch entries unread) runs only in a component holding a vouch
// (notes/perm-paths.md, Two walks): a part appended on A, which holds n grants, costs the
// timeline's step alone; once a vouch is held on A, both walks' (the first walking A from its
// start once). Mutation: the first walk in every component: two steps without the vouch.
#[test]
fn the_first_walk_runs_only_where_a_vouch_is() {
    for n in [100u32, 1000] {
        let end = 10 + n as u64 + 5;
        let (d, _) = cost_of(&history(n), write(1, H, end, &[], A, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes), (1, 1), "no vouch at n {n}: {d:?}");
        let mut base = history(n);
        base.push(Commit { id: cid(2), ts: Ts::make(WallMs(5), 0).unwrap(), signer: t(H), parts: vec![Part { on: t(A), path: vec![], kind: PartKind::Vouch { removal: cid(3), list: Frontier::new([]) } }] });
        let (d, _) = cost_of(&base, write(1, H, end, &[], A, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes), (2, 2), "a vouch at n {n}: {d:?}");
    }
}

/// A `MemStore` counting its lookups (the engine's store index in the wiring).
#[derive(Clone, Default)]
struct Counting {
    inner: MemStore,
    lookups: Rc<Cell<u64>>,
}

impl Counting {
    fn tick(&self) {
        self.lookups.set(self.lookups.get() + 1);
    }
}

impl Store for Counting {
    fn put(&mut self, f: Fact) {
        self.inner.put(f)
    }
    fn remove(&mut self, id: &WriteId) -> Option<Fact> {
        self.inner.remove(id)
    }
    fn get(&self, id: &WriteId) -> Option<Fact> {
        self.tick();
        self.inner.get(id)
    }
    fn of_commit(&self, c: &CommitId, on: Option<&Tid>) -> Vec<WriteId> {
        self.tick();
        self.inner.of_commit(c, on)
    }
    fn listing(&self, c: &CommitId) -> Vec<WriteId> {
        self.tick();
        self.inner.listing(c)
    }
    fn carrying(&self, c: &CommitId) -> Vec<WriteId> {
        self.tick();
        self.inner.carrying(c)
    }
    fn requests(&self, on: &Tid, aspect: &Ak, author: &Tid) -> Vec<WriteId> {
        self.tick();
        self.inner.requests(on, aspect, author)
    }
    fn addenda_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        self.tick();
        self.inner.addenda_through(e, from, to)
    }
    fn through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        self.tick();
        self.inner.through(e, from, to)
    }
    fn valid_addendum(&self, id: &WriteId) -> bool {
        self.tick();
        self.inner.valid_addendum(id)
    }
    fn set_valid_addendum(&mut self, id: &WriteId, valid: bool) {
        self.inner.set_valid_addendum(id, valid)
    }
    fn all(&self) -> Vec<WriteId> {
        self.inner.all()
    }
}

// The walk keeps in memory only edge-class state; delta facts live in the store
// (notes/perm-paths.md, The delta-facts seam): 10 role commits and n content deltas along them
// keep the same in-memory entries at n = 1000 and 10,000, and adding and judging a delta
// appended at the end costs the same store lookups at both (a few per delta, its path's edges
// read from the walk). Mutation: the walk holding every commit it is given (`held` kept for a
// content commit): the entries grow with n.
#[test]
fn delta_facts_live_in_the_store() {
    let mut per = vec![];
    for n in [1000u64, 10_000] {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        c.extend((0..9).map(|i| write(100 + i, H, 2 + i, &[], A, holder(i as u32), Some(Role::Admin))));
        c.extend((0..n).map(|i| content(200_000 + i, X, 20 + i, &[A], C, None)));
        let store = Counting::default();
        let lookups = store.lookups.clone();
        let mut p = Paths::with_store(&records(), BTreeSet::new(), store);
        p.add(&c);
        let foot = p.footprint();
        let before = lookups.get();
        p.add(&[content(9, X, 20 + n + 5, &[A], C, None)]);
        assert_eq!(p.content(&WriteId(cid(9), 0)), Some(Content::Valid(By::Held)));
        per.push((foot, lookups.get() - before));
    }
    assert_eq!(per[0], per[1], "{per:?}");
}

// Disputes are read per candidate in the candidate's component (notes/perm-paths.md, Trust per
// component): X and Y remove each other on A (Y's removal, applying nowhere, a dispute: trusted
// it drops X's), beside n grants and n deltas on B; probing the candidates
// walks A's parts and compares the verdicts its switch reaches: the same work at n = 100 and
// 1000. Mutation: every delta's verdict compared per candidate (`reached` returning `all`):
// content work tenfold.
#[test]
fn a_dispute_probe_reads_its_component_alone() {
    let mut per = vec![];
    for n in [100u64, 1000] {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin)), write(2, H, 1, &[], A, Y, Some(Role::Admin)), write(3, X, 3, &[], A, Y, None), write(4, Y, 4, &[], A, X, None)];
        c.push(write(5, H, 1, &[], B, 88, Some(Role::Admin)));
        c.extend((0..n).map(|i| write(500_000 + i, H, 10 + i, &[], B, holder(i as u32), Some(Role::Admin))));
        c.extend((0..n).map(|i| content(600_000 + i, 88, 10 + i, &[B], 99, None)));
        let mut p = Paths::evaluate(&records(), BTreeSet::new(), &c);
        let mut k = Counts::default();
        let d = p.disputes_counted(&mut k);
        assert!(d.contains(&WriteId(cid(4), 0)), "{d:?}");
        per.push((k.steps, k.content));
    }
    assert_eq!(per[0], per[1], "{per:?}");
}

/// The organisation world (notes/perm-paths.md, Reach): O minted by H, k teams minted by O; H
/// grants Y admin on O at 2; Y grants each team's lead admin on it through [O] at 10..; each lead
/// grants p members write on its team at 5000..; with `removals`, each lead removes its first
/// member at 9000 (listing it: no drops).
fn org(k: u32, p: u32, removals: bool) -> (BTreeMap<Tid, Tid>, Vec<Commit>) {
    let mut recs = records();
    recs.insert(t(O), t(H));
    recs.extend((0..k).map(|i| (t(team(i)), t(O))));
    let mut base = vec![write(1, H, 2, &[], O, Y, Some(Role::Admin))];
    base.extend((0..k).map(|i| write(10 + i as u64, Y, 10 + i as u64, &[O], team(i), lead(i), Some(Role::Admin))));
    for i in 0..k {
        base.extend((0..p).map(|j| write(member(i, j), lead(i), 5000 + (i * p + j) as u64, &[], team(i), member(i, j) as u32, Some(Role::Write))));
        if removals {
            let mut r = write(800_000 + i as u64, lead(i), 9000 + i as u64, &[], team(i), member(i, 0) as u32, None);
            if let PartKind::Edge(ew) = &mut r.parts[0].kind {
                ew.frontier = Some(Arc::new(Frontier::new([cid(member(i, 0))])));
            }
            base.push(r);
        }
    }
    (recs, base)
}

const O: u32 = 20;
fn team(i: u32) -> u32 {
    3000 + i
}
fn lead(i: u32) -> u32 {
    10_000 + i
}
/// A member's tid number and the commit granting it.
fn member(i: u32, j: u32) -> u64 {
    100_000 + (i * 100 + j) as u64
}

/// The work one update does over the organisation world, by reach (`whole`: the whole walk).
fn org_cost(k: u32, p: u32, removals: bool, whole: bool, f: &dyn Fn(&mut Paths)) -> Counts {
    let (recs, base) = org(k, p, removals);
    let mut q = if whole { Paths::whole(&recs, BTreeSet::new()) } else { Paths::new(&recs, BTreeSet::new()) };
    q.add(&base);
    let before = q.counts();
    f(&mut q);
    delta(before, q.counts())
}

// An organisation is one component by design: every team's writes rest on Y's edge on O
// (notes/perm-paths.md, Components). By reach a backdated part costs what reads its change
// (notes/perm-paths.md, Reach), at k = 10, 100 and 1000 teams of p = 5 members:
// - a backdated removal of one team's lead: the removal and that team's p member grants;
// - a backdated lowering with drops (a lead removed after its member grants, listing none): the
//   removal and its p drops, one restart;
// - forgetting one lead's grant: that grant and its team's members;
// - a backdated grant on the hub edge re-stating its value, and a write applying nowhere: 1;
// - a backdated removal of the hub edge (every team's path reads it): all k(1 + p) + 1, inherent.
// The control: the whole walk (`Paths::whole`) walks every team after the key.
#[test]
fn an_organisation_costs_what_reads_the_change() {
    let p = 5u32;
    for k in [10u32, 100, 1000] {
        let pp = p as u64;
        let lead0 = write(2, Y, 100, &[O], team(0), lead(0), None);
        let d = org_cost(k, p, false, false, &|q| {
            q.add(std::slice::from_ref(&lead0));
        });
        assert_eq!((d.steps, d.restarts, d.chained), (1 + pp, 0, 0), "one team's lead removed at k {k}: {d:?}");
        let mut late = write(3, Y, 6000, &[O], team(0), lead(0), None);
        if let PartKind::Edge(ew) = &mut late.parts[0].kind {
            ew.frontier = Some(Arc::new(Frontier::new([])));
        }
        let d = org_cost(k, p, false, false, &|q| {
            q.add(std::slice::from_ref(&late));
        });
        assert_eq!((d.steps, d.restarts, d.audited), (1 + pp, 1, pp), "a lowering with drops at k {k}: {d:?}");
        let d = org_cost(k, p, false, false, &|q| {
            q.forget(&[cid(10)]);
        });
        // the members' grants are no longer chained either
        assert_eq!((d.steps, d.chained), (1 + pp, 1 + pp), "a lead's grant forgotten at k {k}: {d:?}");
        let d = org_cost(k, p, false, false, &|q| {
            q.add(&[write(4, H, 3, &[], O, Y, Some(Role::Admin))]);
        });
        assert_eq!((d.steps, d.chained), (1, 1), "the hub re-granted at k {k}: {d:?}");
        let d = org_cost(k, p, false, false, &|q| {
            q.add(&[write(5, Y, 1, &[O], team(0), X, Some(Role::Admin))]);
        });
        assert_eq!((d.steps, d.chained), (1, 1), "a write applying nowhere at k {k}: {d:?}");
        let d = org_cost(k, p, false, false, &|q| {
            q.add(&[write(6, H, 3, &[], O, Y, None)]);
        });
        assert_eq!(d.steps, 1 + k as u64 * (1 + pp), "the hub removed at k {k}: {d:?}");
    }
    let d = org_cost(100, p, false, true, &|q| {
        q.add(&[write(2, Y, 100, &[O], team(0), lead(0), None)]);
    });
    assert!(d.steps > 100 * p as u64, "the whole walk: {d:?}");
}

// What reach leaves component-wide (notes/perm-paths.md, Reach, What stays component-wide): an
// update forgets every verdict given after the walk reached its key (the event log by reach), so
// the lowerings judged after it, on every team, are judged again: a backdated removal of one
// team's lead where each of k teams' leads removed a member later costs about k more steps
// (1 + p + k: the lowerings judged again, each giving the verdict it had). Without the later
// removals: 1 + p.
#[test]
fn an_organisation_judges_again_the_lowerings_after_the_key() {
    let p = 5u32;
    for k in [10u32, 100, 1000] {
        let d = org_cost(k, p, true, false, &|q| {
            q.add(&[write(2, Y, 100, &[O], team(0), lead(0), None)]);
        });
        assert_eq!(d.steps, 1 + p as u64 + k as u64, "at k {k}: {d:?}");
    }
}

// Teams joined once by a hub's writes stay one component after those writes are forgotten
// (notes/perm-paths.md, Forget and update), and cost no more for it: H's grants of A on each
// team, X (admin on A) writing on each through A, all forgotten; a backdated part on one team
// costs its own step at k = 100 and 1000.
#[test]
fn teams_once_joined_cost_as_if_never_joined() {
    for k in [100u32, 1000] {
        let mut recs = records();
        recs.extend((0..k).map(|i| (t(team(i)), t(H))));
        let mut base = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        base.extend((0..k).map(|i| write(10 + i as u64, H, 10, &[], team(i), lead(i), Some(Role::Admin))));
        let hub: Vec<Commit> = (0..k).flat_map(|i| [write(100_000 + i as u64, H, 20, &[], team(i), A, Some(Role::Admin)), write(200_000 + i as u64, X, 30, &[A], team(i), lead(5000 + i), Some(Role::Write))]).collect();
        base.extend(hub.iter().cloned());
        let mut q = Paths::evaluate(&recs, BTreeSet::new(), &base);
        q.forget(&hub.iter().map(|c| c.id).collect::<Vec<_>>());
        let before = q.counts();
        q.add(&[write(2, H, 5, &[], team(0), X, Some(Role::Write))]);
        assert_eq!(delta(before, q.counts()).steps, W, "at k {k}");
    }
}

// Hostile shapes for reach (notes/perm-paths.md, Reach):
// - a chain where every part walked again changes the next one's edge (X grants z0, each zi
//   grants zi+1), closed into a cycle of holders (the last grants z0 again): a backdated removal
//   of X walks the whole chain once, 1 + k + 1 (bounded by the parts reading what changed, each
//   once per change: the worklist runs forward in key order, so a cycle ends);
// - a part stated along 64 edges, each re-granted m times: indexing it costs its path, about
//   three entries per edge (its readers' and chained-pass indexes), the same at m = 10 and 100;
//   a backdated grant on one of its edges walks that edge's next grant (unchanged after it)
//   alone; a removal of that edge just before it, the removal and the part.
#[test]
fn reach_on_hostile_shapes() {
    let z = |i: u32| 3000 + i;
    for k in [10u32, 100] {
        let mut base = chain(k, 0);
        base.push(write(999_999, z(k - 1), 5000, &[], A, z(0), Some(Role::Admin)));
        let (d, p) = cost_of(&base, write(9, H, 1, &[], A, X, None));
        assert_eq!(d.steps, 1 + k as u64 + 1, "chain of {k}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(999_999), 0)), Some(Status::Unapplied));
    }
    let thing = |i: u32| 50_000 + i;
    let mut per = vec![];
    for m in [10u32, 100] {
        let mut recs = records();
        recs.extend((0..=64).map(|i| (t(thing(i)), t(H))));
        let mut base = vec![write(1, H, 1, &[], thing(0), X, Some(Role::Admin))];
        for r in 0..m {
            base.extend((0..64).map(|i| write(1000 + (r * 64 + i) as u64, H, 10 + r as u64, &[], thing(i + 1), thing(i), Some(Role::Admin))));
        }
        let path: Vec<u32> = (0..64).map(thing).collect();
        let part = write(2, X, 10_000, &path, thing(64), Y, Some(Role::Write));
        let mut p = Paths::evaluate(&recs, BTreeSet::new(), &base);
        let foot = p.footprint();
        let before = p.counts();
        p.add(std::slice::from_ref(&part));
        let d = delta(before, p.counts());
        assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Applied));
        assert_eq!(d.steps, 1, "{d:?}");
        let grown = p.footprint() - foot;
        let before = p.counts();
        p.add(&[write(3, H, 5, &[], thing(6), thing(5), Some(Role::Admin))]);
        let d = delta(before, p.counts());
        assert_eq!(d.steps, 2, "a backdated grant on its fifth edge at m {m}: {d:?}");
        let before = p.counts();
        p.add(&[write(4, H, 9000, &[], thing(6), thing(5), None)]);
        let d = delta(before, p.counts());
        assert_eq!(d.steps, 2, "its fifth edge removed before it at m {m}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Unapplied));
        per.push(grown);
    }
    assert!(per[0] == per[1] && per[0] <= 3 * 64 + 10, "{per:?}");
}
