//! How the walk's work scales (notes/perm-paths.md, Cost shapes; Counts), counted at n and 10n:
//! a part appended at the end, a backdated part (its component alone), a lowering applying with
//! drops, a void lowering's check, from scratch; content: a delta appended, a removal cutting n
//! deltas, a cut delta's query, k addenda arriving one at a time, addenda judged again only where
//! an update reaches them; components: an appended part among c components, a merge, a trusted
//! component, a forget. Each names the mutation that breaks its shape.
//! spec: none (cost, notes/perm-paths.md; the rules are those of spec/permissions.md §5.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::{cid, t};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts, WallMs};
use osis_perm::paths::{By, Commit, Content, Counts, Delta, DeltaClass, EdgeWrite, Fact, List, Holding, Key, MemStore, NameKey, Names, Pair, Part, PartKind, Paths, Right, Status, Store};
use std::cell::Cell;
use std::ops::Bound;
use std::rc::Rc;
use osis_perm::{Edge, Frontier, WriteId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
    let frontier = Some(Arc::new(List::default()));
    let ew = EdgeWrite { holder: t(holder), value: role.map(Edge::new), frontier };
    Commit { id: cid(id), ts: Ts::make(WallMs(ts), 0).unwrap(), signer: t(signer), parts: vec![Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Edge(ew) }] }
}

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

// A backdated part replays its component from its key (issues/perm-eval-cost.md): H removes X
// from A early, before n grants on A and X's m writes on C (minted with A) through [A]: itself
// and the n + m parts after it; a grant on B, a component of its own, its own step.
#[test]
fn a_backdated_part_replays_its_component_from_its_key() {
    let m = 5u32;
    let base = |n: u32| {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin))];
        c.extend(history(n));
        c.extend((0..m).map(|i| write(50 + i as u64, X, 20 + n as u64 + i as u64, &[A], C, holder(9000 + i), Some(Role::Read))));
        c
    };
    for n in [100u32, 1000] {
        let (d, p) = cost_of(&base(n), write(2, H, 5, &[], A, X, None));
        // a removal sets no chained point: the chained pass judges it alone
        assert_eq!((d.steps, d.passes, d.chained), ((n + m + 1) as u64, 1, 1), "on A at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(50), 0)), Some(Status::Unapplied));
        let (d, _) = cost_of(&base(n), write(3, H, 5, &[], B, X, Some(Role::Admin)));
        assert_eq!((d.steps, d.passes, d.chained), (1, 1, 1), "on B at n {n}: {d:?}");
    }
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

// Components bound what an update walks again (notes/perm-paths.md, Components): among c
// components of k grants and one later removal each, a part appended on one costs its own step;
// one backdated there its own component from its key, the same at c = 10, 100 and 1000. The
// control: partitioning off (`Paths::single`, one component): c(k + 1) + 1.
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
        assert_eq!((d.steps, d.passes), (1, 1), "appended at c {c}: {d:?}");
        let before = p.counts();
        p.add(&[write(2, H, 1, &[], 100, Y, Some(Role::Admin))]);
        let d = delta(before, p.counts());
        // its own component from its key: itself, the k grants, the removal, the appended grant
        assert_eq!((d.steps, d.passes), (k as u64 + 3, 1), "backdated at c {c}: {d:?}");
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
        assert_eq!((d.steps, d.passes), (1, 1), "{d:?}");
        per.push(d.merged);
    }
    assert!(per[0] == per[1] && per[0] < 200, "{per:?}");
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
        assert_eq!((d.steps, d.passes, d.scratch), (1, 1, 0), "at n {n}: {d:?}");
    }
}

// Forgetting a content commit walks nothing (no verdict of a delta is stored); forgetting an edge
// part replays its component from its key (notes/perm-paths.md, Forget and update): X's grant,
// before n grants on A, walks those n beside n on B.
#[test]
fn a_forget_replays_its_component_from_the_parts_key() {
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
        assert_eq!((d.steps, d.passes), (n as u64, 1), "an edge part at n {n}: {d:?}");
    }
}

// A lowering applying with drops restarts once, from its earliest drop: X, granted at 1, grants k
// holders on A at 2; n unrelated grants follow; H removes X at the end listing nothing. The
// restart takes its k drops, the n grants after them and the removal again.
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
        assert_eq!(d.steps, (1 + k + n + 1) as u64, "{d:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(10 + i as u64), 0)) == Some(Status::Dropped)));
    }
}

// Restarts multiply: k lowerings at the end, each dropping one early write, restart k times, each
// from its drop through the n parts after it: about k·n (k = 10, n = 100 and 1000: tenfold), which
// a party holding admin forces with its own 3k writes (k holders it grants, one grant by each,
// its removals of them listing nothing). Within spec/requirements.md, Cost: a role change may
// cost the role history after it.
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
        assert_eq!(c.restarts, k as u64, "{c:?}");
        assert!((0..k).all(|i| p.status(&WriteId(cid(40 + i as u64), 0)) == Some(Status::Dropped)));
        per.push(c.steps);
    }
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
    assert_eq!((small.steps, small.passes, large.steps, large.passes), (100, 1, 1000, 1));
}

/// A content commit of one plain delta by `signer` on `on` along `path` (an addendum: `against`
/// removal listing `list`).
fn content(id: u64, signer: u32, ts: u64, path: &[u32], on: u32, against: Option<(u64, &[u64])>) -> Commit {
    let class = match against {
        Some((r, l)) => DeltaClass::Addendum { removal: cid(r), list: Frontier::new(l.iter().map(|&i| cid(i))) },
        None => DeltaClass::Plain,
    };
    let aspect = Ak::new(if against.is_some() { "addenda.0" } else { "doc.0" }).unwrap();
    let d = Delta { aspect, needs: Role::Write, purge_author: 0, purge_by: PurgeBy::AuthorOrAdmin, class };
    Commit { id: cid(id), ts: Ts::make(WallMs(ts), 0).unwrap(), signer: t(signer), parts: vec![Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Delta(d) }] }
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
            ew.frontier = Some(Arc::new(List::new([(t(C), cid(200_000))])));
        }
        let ch = p.add(&[r]);
        let d = delta(before, p.counts());
        assert_eq!((d.steps, d.content), (1, 0), "{d:?}");
        assert_eq!(ch.cuts.keys().copied().collect::<Vec<_>>(), vec![(t(X), t(A))]);
        assert!(ch.parts.len() == 1 && ch.named.is_empty(), "{ch:?}");
        let mut q = Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(200_000), 0), &mut q), Some(Content::Valid(By::Listed)));
        assert_eq!(p.content_counted(&WriteId(cid(200_001), 0), &mut q), Some(Content::Invalid));
        per.push(q.content);
    }
    assert_eq!(per[0], per[1], "{per:?}");
}

/// X's request by whole aspect on C along [A], stamped `ts`.
fn request(id: u64, ts: u64) -> Commit {
    let mut c = content(id, X, ts, &[A], C, None);
    if let PartKind::Delta(d) = &mut c.parts[0].kind {
        d.class = DeltaClass::Purge { names: Names::Aspect };
    }
    c
}

// spec/permissions.md §6: draft a request is an edit; purges a reading: a request by whole
// aspect over n deltas costs the same at n = 100 and 1000: its arrival judges its own right and
// reports one scope (`Changed::purges`), never a list of deltas; a removal of its signer cutting
// its right (restore) reports its scope again, as does the re-grant giving the right back; each
// delta's purge is a point query reading the same at both sizes.
#[test]
fn a_request_over_n_deltas_reports_one_scope() {
    let mut per = vec![];
    for n in [100u32, 1000] {
        let end = 10 + n as u64 + 5;
        let mut p = Paths::evaluate(&records(), BTreeSet::new(), &writes(n));
        let before = p.counts();
        let ch = p.add(&[request(3, end)]);
        let arrive = delta(before, p.counts());
        assert_eq!((ch.purges.len(), arrive.steps), (1, 0), "{ch:?}");
        let mut q = Counts::default();
        assert!(p.is_purged_counted(&WriteId(cid(200_000), 0), &mut q));
        let before = p.counts();
        let ch = p.add(&[write(2, H, end + 1, &[], A, X, None)]);
        let cut = delta(before, p.counts());
        assert!(ch.purges.len() == 1 && !p.is_purged(&WriteId(cid(200_000), 0)));
        let ch = p.add(&[write(4, H, end + 2, &[], A, X, Some(Role::Admin))]);
        assert!(ch.purges.len() == 1 && p.is_purged(&WriteId(cid(200_000), 0)));
        per.push((arrive.content, cut.content, q.content));
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

// spec/permissions.md §5.2 (content): a delta each of k cuts of its edge answers (every removal
// lists it) stands only where every one does, so its query reads each cut once: linear in the cuts
// after it on its path's edges (5 + 2k reads: 7, 9, 25 at k = 1, 2, 10). Who can
// force it: the edge's admins, one cut per raise and lowering.
#[test]
fn a_delta_every_cut_answers_reads_each_cut_once() {
    let mut per = vec![];
    for k in [1u64, 2, 10] {
        let mut c = vec![write(1, H, 1, &[], A, X, Some(Role::Admin)), content(9, X, 5, &[A], C, None)];
        for i in 0..k {
            let mut cut = write(10 + 2 * i, H, 10 + 2 * i, &[], A, X, None);
            if let PartKind::Edge(ew) = &mut cut.parts[0].kind {
                ew.frontier = Some(Arc::new(List::new([(t(C), cid(9))])));
            }
            c.push(cut);
            c.push(write(11 + 2 * i, H, 11 + 2 * i, &[], A, X, Some(Role::Admin)));
        }
        // the last re-grant removed: no re-grant answers it, the lists alone
        c.push(write(10 + 2 * k, H, 10 + 2 * k, &[], A, X, None));
        let p = Paths::evaluate(&records(), BTreeSet::new(), &c);
        let mut q = Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(9), 0), &mut q), Some(Content::Invalid), "k {k}: the last cut lists nothing");
        let mut c2 = c.clone();
        if let Some(PartKind::Edge(ew)) = c2.last_mut().map(|x| &mut x.parts[0].kind) {
            ew.frontier = Some(Arc::new(List::new([(t(C), cid(9))])));
        }
        let p = Paths::evaluate(&records(), BTreeSet::new(), &c2);
        let mut q = Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(9), 0), &mut q), Some(Content::Valid(By::Listed)), "k {k}");
        per.push(q.content);
    }
    let step = per[1] - per[0];
    assert!(step > 0 && per[2] - per[1] == 8 * step, "{per:?}");
}

// An update judges again only the addenda it reaches (notes/perm-paths.md, Addenda, by
// reach): Y's k addenda along [A] against H's removal of X; a stranger's write that
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
    fn latest(&self, key: &NameKey, holding: Holding) -> Option<Ts> {
        self.tick();
        self.inner.latest(key, holding)
    }
    fn requests_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        self.tick();
        self.inner.requests_through(e, from, to)
    }
    fn right(&self, id: &WriteId) -> Right {
        self.tick();
        self.inner.right(id)
    }
    fn set_right(&mut self, id: &WriteId, right: Right) {
        self.inner.set_right(id, right)
    }
    fn own_covers(&self, signer: &Tid) -> Vec<WriteId> {
        self.tick();
        self.inner.own_covers(signer)
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

/// Admins of A, every part in one component (each rests on an edge a held write sets): H grants
/// Y admin (ts 1); Y grants Z (ts 2) and W (ts 3) admin; W grants V read (ts 4); Z grants `n`
/// holders read (ts 10..).
fn admins_of_a(n: u32) -> Vec<Commit> {
    const Y: u32 = 30;
    const Z: u32 = 31;
    const W: u32 = 32;
    const V: u32 = 33;
    let mut c = vec![write(1, H, 1, &[], A, Y, Some(Role::Admin)), write(2, Y, 2, &[], A, Z, Some(Role::Admin)), write(3, Y, 3, &[], A, W, Some(Role::Admin)), write(4, W, 4, &[], A, V, Some(Role::Read))];
    c.extend((0..n).map(|i| write(1000 + i as u64, Z, 10 + i as u64, &[], A, holder(i), Some(Role::Read))));
    c
}

// The budget the walk is built to (spec/requirements.md, Cost: a role change arriving out of
// order may cost in proportion to the role history after it on that thing; issues/
// perm-eval-cost.md). Over `admins_of_a` (n = 100, 1000): (a) a grant appended at the end costs its
// own step at both; (b) a grant by Y backdated to ts 5, before Z's n grants, at most itself and
// the n parts after its key; (c) H removing W at the end listing nothing, dropping W's grant of V
// (one restart): itself, then at most the history from its earliest drop on (the drop, Z's n
// grants, itself again).
#[test]
fn an_update_costs_what_it_changes_at_n_and_10n() {
    let cost = |n: u32, c: Commit| {
        let mut p = Paths::new(&records(), BTreeSet::new());
        p.add(&admins_of_a(n));
        let before = p.counts();
        p.add(&[c]);
        (delta(before, p.counts()), p)
    };
    for n in [100u32, 1000] {
        let end = 20 + n as u64;
        let (d, _) = cost(n, write(7, 31, end, &[], A, X, Some(Role::Read)));
        assert_eq!((d.steps, d.restarts), (1, 0), "appended at n {n}: {d:?}");
        let (d, _) = cost(n, write(8, 30, 5, &[], A, X, Some(Role::Read)));
        assert!(d.steps <= n as u64 + 1 && d.restarts == 0, "backdated at n {n}: {d:?}");
        let (d, p) = cost(n, write(9, H, end, &[], A, 32, None));
        assert!(d.steps <= 1 + (n as u64 + 2) && d.restarts == 1, "removal at n {n}: {d:?}");
        assert_eq!(p.status(&WriteId(cid(4), 0)), Some(Status::Dropped));
    }
}
