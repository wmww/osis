//! The walk on input no model generator makes: the order of a commit's edge writes, hostile
//! shapes (long and made-up paths, cycles, a repeated holder, extreme times; addenda and
//! snapshots naming what they should not), and random soups of parts and
//! deltas. Each must judge without panicking and read the same however its commits
//! arrive, each update's `Changed` exact.
//! spec/permissions.md §1 Path, §5.1 step 1; the
//! update path: notes/perm-paths.md, One definition.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::incremental::{reading, Reading, Tracked};
use super::{cid, commit, ms, own, t};
use osis_base::{Ak, Holder, PurgeBy, Role, SignKey, Tid, Ts, WallMs};
use osis_perm::paths::{Changed, Commit, Content, Delta, DeltaClass, EdgeWrite, List, Names, Part, PartKind, Paths, Status};
use osis_perm::{Edge, Frontier, WriteId};
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn edge(on: u32, path: &[u32], holder: u32, value: Option<Edge>, frontier: Option<&[u64]>) -> Part {
    let frontier = frontier.map(|f| Arc::new(super::whole(&[H, Y, Z, A, LK, T1].map(t), f.iter().map(|&c| cid(c)))));
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Edge(EdgeWrite { holder: Holder::Thing(t(holder)), value, frontier }) }
}

/// Commits arriving one at a time in `order`: each `Changed` equals the readings' difference, and
/// the end reads as `scratch`, the reading from scratch. The first difference, if any.
fn arrive(records: &BTreeMap<Tid, Holder>, trust: &BTreeSet<WriteId>, commits: &[Commit], order: &[usize], scratch: &Reading) -> Option<String> {
    let mut t = Tracked::new(Paths::new(records, trust.clone()));
    for &k in order {
        if let Some(d) = t.step(|p| p.add(std::slice::from_ref(&commits[k]))) {
            return Some(format!("adding commit {k}: {d}"));
        }
    }
    (t.r != *scratch).then(|| "arrival and from scratch differ".to_string())
}

/// Every check of this module on one input: from scratch, arrival forward, backward and in a
/// shuffled order, a switch to each single trusted write and back, the dispute set.
#[track_caller]
fn robust(records: &BTreeMap<Tid, Holder>, commits: &[Commit], rng: &mut Rng) -> Paths {
    let none = BTreeSet::new();
    let n = commits.len();
    let fwd: Vec<usize> = (0..n).collect();
    let back: Vec<usize> = (0..n).rev().collect();
    let shuffled = rng.perm(n);
    let scratch = Tracked::new(Paths::evaluate(records, none.clone(), commits));
    for order in [&fwd, &back, &shuffled] {
        if let Some(d) = arrive(records, &none, commits, order, &scratch.r) {
            panic!("{d}\norder {order:?}\n{commits:#?}");
        }
    }
    // forgetting (notes/perm-paths.md, Forget and update): a commit never added changes nothing;
    // a shuffled half forgotten one at a time reads as from scratch over the rest; added again,
    // as never forgotten
    let mut t = scratch.clone();
    let mut ch = Changed::default();
    assert_eq!(t.step(|p| { ch = p.forget(&[cid(1 << 40)]); ch.clone() }), None);
    assert_eq!(ch, Changed::default());
    let gone: Vec<usize> = shuffled.iter().copied().filter(|&k| k % 2 == 0).collect();
    for &k in &gone {
        assert_eq!(t.step(|p| p.forget(&[commits[k].id])), None, "forgetting {k}\n{commits:#?}");
    }
    let rest: Vec<Commit> = (0..n).filter(|k| !gone.contains(k)).map(|k| commits[k].clone()).collect();
    assert!(t.r == reading(&Paths::evaluate(records, none.clone(), &rest)), "forgetting {gone:?}\n{commits:#?}");
    for &k in &gone {
        assert_eq!(t.step(|p| p.add(std::slice::from_ref(&commits[k]))), None, "adding {k} again\n{commits:#?}");
    }
    assert!(t.r == scratch.r, "forgotten and added again\n{commits:#?}");
    // the dispute set's switches leave the reading as it was
    let _ = t.p.disputes();
    assert!(t.r == reading(&t.p), "the reading after disputes\n{commits:#?}");
    let ids: Vec<WriteId> = t.r.0.keys().copied().collect();
    for id in ids.iter().take(6) {
        for trust in [BTreeSet::from([*id]), BTreeSet::new()] {
            assert_eq!(t.step(|p| p.set_trust(trust.clone())), None, "trust {trust:?}\n{commits:#?}");
            let under = if trust.is_empty() { scratch.r.clone() } else { reading(&Paths::evaluate(records, trust.clone(), commits)) };
            assert!(t.r == under, "trust {trust:?}");
            if !trust.is_empty() && arrive(records, &trust, commits, &shuffled, &under).is_some() {
                panic!("arrival under trust {trust:?} differs\n{commits:#?}");
            }
        }
    }
    t.p
}

const H: u32 = 1;
const Y: u32 = 2;
const Z: u32 = 3;
const A: u32 = 10;
const LK: u32 = 11;
const T1: u32 = 12;

/// A minted by H, LK and T1 minted by A.
fn records() -> BTreeMap<Tid, Holder> {
    super::hand_records([(t(A), t(H)), (t(LK), t(A)), (t(T1), t(A))])
}

// spec/permissions.md §5.1 step 1 (draft): the part setting an edge of the commit's own path
// comes after every other part on its thing, so no part's path is changed by an earlier part of
// its commit: Y, admin on LK, leaves LK and grants Z admin on LK in one commit along the empty
// path; the grant is taken first and applies.
#[test]
fn a_part_is_taken_before_its_commits_own_path_part() {
    let grant = commit(1, ms(1), H, vec![edge(LK, &[A], Y, Some(Edge::new(Role::Admin)), Some(&[]))]);
    let both = commit(2, ms(3), Y, vec![edge(LK, &[], Y, None, None), edge(LK, &[], Z, Some(Edge::new(Role::Admin)), Some(&[]))]);
    let p = Paths::evaluate(&records(), BTreeSet::new(), &[grant, both]);
    assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Applied), "the self-removal");
    assert_eq!(p.status(&WriteId(cid(2), 1)), Some(Status::Applied), "the grant");
}

// spec/permissions.md §2 Finalize: a finalize is a frontier-less removal of ANOTHER holder's grant.
// Z, admin on A, holding admin on T1 until 3, grants N5 write on T1 at 2, then removes its own
// ended grant along [A] carrying no frontier: an explicit removal listing nothing, which drops
// N5's grant (as a finalize it would drop nothing).
#[test]
fn a_frontier_less_removal_of_the_signers_own_grant_is_explicit() {
    const N5: u32 = 4;
    let timed = Some(Edge { until: Some(WallMs(3)), ..Edge::new(Role::Admin) });
    let commits = [
        commit(1, ms(1), H, vec![edge(A, &[], Z, Some(Edge::new(Role::Admin)), Some(&[]))]),
        commit(2, ms(1), H, vec![edge(T1, &[A], Z, timed, Some(&[]))]),
        commit(3, ms(2), Z, vec![edge(T1, &[], N5, Some(Edge::new(Role::Write)), Some(&[]))]),
        commit(4, ms(5), Z, vec![edge(T1, &[A], Z, None, None)]),
    ];
    let p = robust(&records(), &commits, &mut Rng(1));
    assert_eq!(p.status(&WriteId(cid(4), 0)), Some(Status::Applied));
    assert_eq!(p.status(&WriteId(cid(3), 0)), Some(Status::Dropped));
}

// spec/permissions.md §1 Path, §2: hostile shapes judge without panicking, read alike
// however they arrive, and reach no role they should not.
#[test]
fn hostile_shapes_judge_alike_without_panicking() {
    let mut rng = Rng(7);
    let admin = Some(Edge::new(Role::Admin));
    let made_up = |n: u32| (0..n).map(|i| 5000 + i).collect::<Vec<u32>>();
    let gy = commit(1, ms(1), H, vec![edge(A, &[], Y, admin, Some(&[]))]);

    // paths of 0, 64 and 200 made-up things: a stranger's grant applies nowhere
    for n in [0, 64, 200] {
        let c = commit(2, ms(2), 999, vec![edge(T1, &made_up(n), Z, admin, Some(&[]))]);
        let p = robust(&records(), &[gy.clone(), c], &mut rng);
        assert_eq!(p.status(&WriteId(cid(2), 0)), Some(Status::Unapplied), "path of {n}");
    }
    // a path naming a thing twice is bad input, also when the repeat is the signer or the target
    let twice = commit(2, ms(2), Y, vec![edge(T1, &[A, Y], Z, admin, Some(&[]))]);
    let into = commit(3, ms(2), Y, vec![edge(T1, &[A, T1], Z, admin, Some(&[]))]);
    let p = robust(&records(), &[gy.clone(), twice, into], &mut rng);
    assert_eq!((p.status(&WriteId(cid(2), 0)), p.status(&WriteId(cid(3), 0))), (Some(Status::Unapplied), Some(Status::Unapplied)));
    // a part setting an edge of its own path (the record edge its descent ends with), alone and
    // beside another part
    let own = commit(2, ms(2), H, vec![edge(T1, &[A], A, None, Some(&[]))]);
    let mixed = commit(3, ms(3), H, vec![edge(T1, &[A], A, Some(Edge::new(Role::Write)), Some(&[])), edge(T1, &[A], Z, admin, Some(&[]))]);
    robust(&records(), &[gy.clone(), own, mixed], &mut rng);
    // a repeated holder makes the whole commit bad input
    let rep = commit(2, ms(2), Y, vec![edge(A, &[], Z, admin, Some(&[])), edge(A, &[], Z, Some(Edge::new(Role::Read)), Some(&[])), edge(A, &[], 77, admin, Some(&[]))]);
    let p = robust(&records(), &[gy.clone(), rep], &mut rng);
    assert!((0..3).all(|i| p.status(&WriteId(cid(2), i)) == Some(Status::Unapplied)));
    // holders holding each other, and a record cycle (descent bounded by MAX_CHAIN_DEPTH)
    let cyc = super::hand_records([(t(A), t(H)), (t(20), t(21)), (t(21), t(20))]);
    let holders = [
        gy.clone(),
        commit(2, ms(2), Y, vec![edge(A, &[], 20, admin, Some(&[]))]),
        commit(3, ms(3), 20, vec![edge(21, &[], 21, admin, Some(&[]))]),
        commit(4, ms(4), 21, vec![edge(20, &[], 20, admin, Some(&[])), edge(A, &[20], Y, None, Some(&[]))]),
        commit(5, ms(5), H, vec![edge(A, &[], Y, None, Some(&[]))]),
    ];
    robust(&cyc, &holders, &mut rng);
    // extreme times: ts 0 and the greatest; an `until` in the past, at the ts, far ahead
    let until = |u: u64| Some(Edge { until: Some(WallMs(u)), ..Edge::new(Role::Admin) });
    let times = [
        commit(1, Ts::ZERO, H, vec![edge(A, &[], Y, until(0), Some(&[]))]),
        commit(2, Ts::ZERO, H, vec![edge(A, &[], Z, until(u64::MAX), Some(&[]))]),
        commit(3, ms(5), H, vec![edge(A, &[], 30, until(5), Some(&[])), edge(A, &[], 31, until(4), Some(&[]))]),
        commit(4, Ts::MAX, Z, vec![edge(A, &[], Y, None, None)]),
        commit(5, Ts::MAX, Y, vec![edge(A, &[], 40, admin, Some(&[]))]),
    ];
    let p = robust(&records(), &times, &mut rng);
    assert_eq!(p.status(&WriteId(cid(5), 0)), Some(Status::Unapplied), "Y's grant ended at 0");
}

/// A random soup of parts over 8 things: records with cycles, paths repeating things, any holder,
/// value (`until`, may-grant, floor), frontier (naming any commit, held or not), deltas of every
/// class; several parts per commit; ties in `ts` and signer.
pub(super) fn soup(i: u64) -> (BTreeMap<Tid, Holder>, Vec<Commit>) {
    let mut r = Rng(i);
    let thing = |r: &mut Rng| 1 + r.below(8) as u32;
    // a thing's record names a mint admin, or holds its own key; some things have none known
    let mut records = BTreeMap::new();
    for x in 1..=8 {
        match r.below(4) {
            0 => {}
            1 => {
                records.insert(t(x), Holder::Key(own(t(x))));
            }
            _ => {
                records.insert(t(x), Holder::Thing(t(thing(&mut r))));
            }
        }
    }
    // a key: some thing's own, or a stranger's
    let key = |r: &mut Rng| if r.below(4) == 0 { SignKey([0xaa; 32]) } else { own(t(thing(r))) };
    let n = 1 + r.below(10);
    let ids: Vec<u64> = (0..n).map(|_| r.below(40) as u64).collect::<BTreeSet<_>>().into_iter().collect();
    let role = |r: &mut Rng| [Role::Read, Role::Write, Role::Admin][r.below(3)];
    let mut commits = vec![];
    for &id in &ids {
        let mut parts = vec![];
        for _ in 0..1 + r.below(3) {
            let on = t(thing(&mut r));
            let path = (0..r.below(4)).map(|_| t(thing(&mut r))).collect();
            let pick = r.below(8);
            let kind = if pick <= 2 {
                let ids = |r: &mut Rng| Frontier::new((0..r.below(4)).map(|_| cid(r.below(40) as u64)));
                let class = match r.below(5) {
                    0 => DeltaClass::Plain,
                    1 => DeltaClass::RoleClass,
                    2 => DeltaClass::Snapshot { carries: ids(&mut r), stated: BTreeMap::new(), own: false },
                    3 => DeltaClass::Addendum { removal: cid(r.below(40) as u64), list: ids(&mut r) },
                    _ => DeltaClass::Purge { names: Names::Author(t(thing(&mut r))) },
                };
                let needs = [Role::Write, Role::Admin][r.below(2)];
                PartKind::Delta(Delta { aspect: Ak::new(["doc.0", "addenda.0"][r.below(2)]).unwrap(), needs, purge_author: r.below(3) as u32, purge_by: PurgeBy::AuthorOrAdmin, class })
            } else {
                let value = (r.below(4) > 0).then(|| Edge {
                    role: role(&mut r),
                    until: (r.below(3) == 0).then(|| WallMs(r.below(8) as u64)),
                    may_grant: r.below(2) == 0,
                    retain: false,
                    floor: (r.below(6) == 0).then(|| r.below(3) as u64),
                });
                let frontier = (r.below(4) > 0).then(|| Arc::new(List::new((0..r.below(4)).map(|_| (t(thing(&mut r)), cid(r.below(40) as u64))))));
                let holder = if r.below(4) == 0 { Holder::Key(key(&mut r)) } else { Holder::Thing(t(thing(&mut r))) };
                PartKind::Edge(EdgeWrite { holder, value, frontier })
            };
            parts.push(Part { on, path, direct: 0, kind });
        }
        let signer = t(thing(&mut r));
        let key = if r.below(3) == 0 { key(&mut r) } else { own(signer) };
        commits.push(Commit { id: cid(id), ts: ms(r.below(6) as u64), signer, key, parts });
    }
    (records, commits)
}

// The walk reads attacker-written commits: random soups judge without panicking, read as from
// scratch however they arrive (each `Changed` exact), and under each single trusted write.
#[test]
fn random_part_soups_judge_alike_however_they_arrive() {
    for i in 0..400 {
        let (records, commits) = soup(i);
        robust(&records, &commits, &mut Rng(i));
    }
}

fn delta(on: u32, path: &[u32], needs: Role, class: DeltaClass) -> Part {
    let aspect = Ak::new(if matches!(class, DeltaClass::Addendum { .. }) { "addenda.0" } else { "doc.0" }).unwrap();
    Part { on: t(on), path: path.iter().map(|&x| t(x)).collect(), direct: 0, kind: PartKind::Delta(Delta { aspect, needs, purge_author: 0, purge_by: PurgeBy::AuthorOrAdmin, class }) }
}

fn ids(l: &[u64]) -> Frontier {
    Frontier::new(l.iter().map(|&c| cid(c)))
}

// spec/permissions.md §5.1, §5.2: hostile
// addenda and snapshots judge without panicking, read alike however they arrive, and keep
// nothing they should not.
#[test]
fn hostile_addenda_and_snapshots_judge_alike_without_panicking() {
    let mut rng = Rng(11);
    let admin = Some(Edge::new(Role::Admin));
    let gy = commit(1, ms(1), H, vec![edge(A, &[], Y, admin, Some(&[]))]);
    let gz = commit(2, ms(2), Y, vec![edge(A, &[], Z, admin, Some(&[]))]);
    let zc = commit(3, ms(3), Z, vec![delta(T1, &[A], Role::Write, DeltaClass::Plain)]);
    let rz = commit(4, ms(4), H, vec![edge(A, &[], Z, None, Some(&[]))]);
    let base = [gy, gz, zc, rz];
    let with = |more: Vec<Commit>| base.iter().cloned().chain(more).collect::<Vec<_>>();
    // an addendum keyed by a grant and by itself, naming role commits and itself
    for (removal, list) in [(1, vec![2, 1]), (9, vec![9, 3]), (2, vec![3])] {
        let ad = commit(9, ms(6), Y, vec![delta(T1, &[A], Role::Write, DeltaClass::Addendum { removal: cid(removal), list: ids(&list) })]);
        let p = robust(&records(), &with(vec![ad]), &mut rng);
        assert_eq!(p.content(&WriteId(cid(3), 0)), Some(Content::Invalid), "{removal} {list:?}");
    }
    // a snapshot claiming copies of commits not yet made, unknown, role commits and itself:
    // copies are shown, never made valid; one by the removed party after its removal is invalid
    for (signer, ts, carries) in [(Y, 6, vec![3, 30, 31, 1, 9]), (Z, 6, vec![3, 9])] {
        let snap = commit(9, ms(ts), signer, vec![delta(T1, &[A], Role::Write, DeltaClass::Snapshot { carries: ids(&carries), stated: BTreeMap::new(), own: false })]);
        let p = robust(&records(), &with(vec![snap]), &mut rng);
        assert_eq!(p.content(&WriteId(cid(3), 0)), Some(if signer == Y { Content::Copied } else { Content::Invalid }));
        assert!(!p.copies().contains(&cid(9)));
    }
    // deltas along made-up paths, a repeated thing, a purge author past the path
    let made_up: Vec<u32> = (0..64).map(|i| 5000 + i).collect();
    let mut odd = delta(T1, &[A], Role::Write, DeltaClass::Plain);
    if let PartKind::Delta(d) = &mut odd.kind {
        // past its members [Y, A, T1] (index 2 names T1 itself, a member: spec/permissions.md §6)
        d.purge_author = 3;
    }
    let junk = vec![
        commit(9, ms(6), Y, vec![delta(T1, &made_up, Role::Write, DeltaClass::Plain)]),
        commit(10, ms(6), Y, vec![delta(T1, &[A, Y], Role::Write, DeltaClass::Plain)]),
        commit(11, ms(6), Y, vec![odd]),
        commit(12, ms(6), Y, vec![delta(T1, &[A], Role::Write, DeltaClass::Purge { names: Names::Author(t(Z)) })]),
    ];
    let p = robust(&records(), &with(junk), &mut rng);
    for id in 9..=11 {
        assert_eq!(p.content(&WriteId(cid(id), 0)), Some(Content::Invalid), "{id}");
    }
    // Y's request by author Z, off its chain, takes Z's delta by the `admin` class alone (draft §6)
    assert_eq!(p.purged(), BTreeSet::from([WriteId(cid(3), 0)]));
}

// spec/permissions.md §5.2: thousands of addenda naming one commit: judging it reads each once.
#[test]
fn thousands_of_addenda_naming_one_commit_cost_one_read_each() {
    let admin = Some(Edge::new(Role::Admin));
    let mut per = vec![];
    for k in [200u64, 2000] {
        let mut c = vec![
            commit(1, ms(1), H, vec![edge(A, &[], Y, admin, Some(&[]))]),
            commit(2, ms(1), H, vec![edge(A, &[], Z, admin, Some(&[]))]),
            commit(3, ms(3), Z, vec![delta(T1, &[A], Role::Write, DeltaClass::Plain)]),
            commit(4, ms(4), H, vec![edge(A, &[], Z, None, Some(&[]))]),
        ];
        // Z's own (vouching for nothing of its signer), then one by Y that vouches
        c.extend((0..k).map(|i| commit(100 + i, ms(5), Z, vec![delta(T1, &[A], Role::Write, DeltaClass::Addendum { removal: cid(4), list: ids(&[3]) })])));
        c.push(commit(99, ms(6), Y, vec![delta(T1, &[A], Role::Write, DeltaClass::Addendum { removal: cid(4), list: ids(&[3]) })]));
        let p = Paths::evaluate(&records(), BTreeSet::new(), &c);
        let mut n = osis_perm::paths::Counts::default();
        assert_eq!(p.content_counted(&WriteId(cid(3), 0), &mut n), Some(Content::Valid(osis_perm::paths::By::Vouched)));
        per.push(n.content);
    }
    assert!(per[1] <= 11 * per[0] && per[1] >= 9 * per[0], "{per:?}");
}

fn request(on: u32, path: &[u32], names: Names, purge_by: PurgeBy) -> Part {
    let aspect = Ak::new(if names == Names::Destroy { "created.0" } else { "doc.0" }).unwrap();
    let mut p = delta(on, path, Role::Write, DeltaClass::Purge { names });
    if let PartKind::Delta(d) = &mut p.kind {
        d.aspect = aspect;
        d.purge_by = purge_by;
    }
    p
}

// spec/permissions.md §6: draft a request is an edit; What it names: hostile requests judge
// without panicking, read alike however they arrive, and take nothing they should not: by a
// made-up commit, a made-up author, a made-up aspect, along a made-up path, a destruction by the
// removed Z, a request naming its own commit; Y's (admin) by aspect takes Z's delta, by whatever
// path it lists, and Z's copy a held snapshot carries; a copy carried by a snapshot the node does
// not hold is no copy to purge.
#[test]
fn hostile_requests_judge_alike_without_panicking() {
    let mut rng = Rng(12);
    let admin = Some(Edge::new(Role::Admin));
    let base = [
        commit(1, ms(1), H, vec![edge(A, &[], Y, admin, Some(&[]))]),
        commit(2, ms(2), H, vec![edge(A, &[], Z, admin, Some(&[]))]),
        commit(3, ms(3), Z, vec![delta(T1, &[A], Role::Write, DeltaClass::Plain)]),
        commit(4, ms(4), H, vec![edge(A, &[], Z, None, Some(&[3]))]),
    ];
    let with = |more: Vec<Commit>| base.iter().cloned().chain(more).collect::<Vec<_>>();
    let made_up: Vec<u32> = (0..64).map(|i| 5000 + i).collect();
    let mut odd = request(T1, &[A], Names::Aspect, PurgeBy::AuthorOrAdmin);
    if let PartKind::Delta(d) = &mut odd.kind {
        d.aspect = Ak::new("nope.0").unwrap();
    }
    let junk = vec![
        commit(9, ms(6), Y, vec![request(T1, &[A], Names::Commit(cid(999)), PurgeBy::AuthorOrAdmin)]),
        commit(10, ms(6), Y, vec![request(T1, &[A], Names::Author(t(777)), PurgeBy::AuthorOrAdmin)]),
        commit(11, ms(6), Y, vec![odd]),
        commit(12, ms(6), Y, vec![request(T1, &made_up, Names::Aspect, PurgeBy::AuthorOrAdmin)]),
        commit(13, ms(6), Z, vec![request(T1, &[A], Names::Destroy, PurgeBy::Admin)]),
        commit(14, ms(6), Y, vec![request(T1, &[A], Names::Commit(cid(14)), PurgeBy::AuthorOrAdmin)]),
    ];
    let p = robust(&records(), &with(junk), &mut rng);
    assert!(p.purged().is_empty(), "{:?}", p.purged());
    assert_eq!(p.right(&WriteId(cid(13), 0)), Some(Default::default()));
    let by_y = commit(15, ms(6), Y, vec![request(T1, &[A], Names::Aspect, PurgeBy::AuthorOrAdmin)]);
    let p = robust(&records(), &with(vec![by_y]), &mut rng);
    assert_eq!(p.purged(), BTreeSet::from([WriteId(cid(3), 0)]));
    // a snapshot not held: what it carries is no copy here, so nothing names it as one
    let stated = BTreeMap::from([(cid(3), osis_perm::paths::Stated { ts: ms(3), purge_author: t(Z), purge_by: PurgeBy::AuthorOrAdmin })]);
    let snap = commit(16, ms(5), Y, vec![delta(T1, &[A], Role::Write, DeltaClass::Snapshot { carries: ids(&[3]), stated, own: false })]);
    let by_y = commit(15, ms(6), Y, vec![request(T1, &[A], Names::Aspect, PurgeBy::AuthorOrAdmin)]);
    let mut cs = with(vec![by_y, snap]);
    cs.retain(|c| c.id != cid(3));
    let p = robust(&records(), &cs, &mut rng);
    assert!(p.copies().contains(&cid(3)) && p.purged_copies() == BTreeSet::from([cid(3)]));
    cs.retain(|c| c.id != cid(16));
    let p = robust(&records(), &cs, &mut rng);
    assert!(p.copies().is_empty() && p.purged_copies().is_empty());
}

// spec/permissions.md §6: k requests holding a right name one delta: judging it is a point
// lookup per selector naming it and per holding its purge-by asks (the latest stamp of the
// requests holding it), whatever k: k writers' requests by aspect, none holding the right over
// its `admin` purge-by, cost the same at k = 200 and 2000 as at none, and k requests holding no
// right (by the removed Z) are no index entry. Who can force k: any holder of a class's role,
// writing requests of its own.
#[test]
fn thousands_of_requests_naming_one_delta_cost_what_none_do() {
    let admin = Some(Edge::new(Role::Admin));
    let write = Some(Edge::new(Role::Write));
    let mut per = vec![];
    for k in [0u64, 200, 2000] {
        let mut c = vec![
            commit(1, ms(1), H, vec![edge(A, &[], Y, write, Some(&[]))]),
            commit(2, ms(1), H, vec![edge(A, &[], Z, admin, Some(&[]))]),
            commit(3, ms(3), H, vec![{
                let mut d = delta(T1, &[A], Role::Write, DeltaClass::Plain);
                if let PartKind::Delta(x) = &mut d.kind {
                    x.purge_by = PurgeBy::Admin;
                }
                d
            }]),
            commit(4, ms(4), H, vec![edge(A, &[], Z, None, Some(&[]))]),
        ];
        c.extend((0..k).map(|i| commit(100 + i, ms(5), Y, vec![request(T1, &[A], Names::Aspect, PurgeBy::AuthorOrAdmin)])));
        c.extend((0..k).map(|i| commit(100_000 + i, ms(5), Z, vec![request(T1, &[A], Names::Aspect, PurgeBy::AuthorOrAdmin)])));
        let p = Paths::evaluate(&records(), BTreeSet::new(), &c);
        if k > 0 {
            assert_eq!(p.right(&WriteId(cid(100), 0)), Some(osis_perm::paths::Right { admin: false, write: true }));
        }
        let mut n = osis_perm::paths::Counts::default();
        assert!(!p.is_purged_counted(&WriteId(cid(3), 0), &mut n));
        per.push(n.content);
    }
    assert!(per[0] == per[1] && per[1] == per[2] && per[0] <= 4, "{per:?}");
}
