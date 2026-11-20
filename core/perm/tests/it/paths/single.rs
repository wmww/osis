//! The walk by components reads exactly as the walk with partitioning off (`Paths::single`: every
//! part walked, inert or not, in one component): a part's verdict reads only its own component
//! (notes/perm-paths.md, Components). Compared on every differential world kind and on random
//! part soups, from scratch, after arrival in a shuffled order and after forgetting half.
//! spec/permissions.md §5.1, §5.2 (draft: notes/a1-spec/permissions.md §5.1, §5.2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use super::incremental::{check, check_renewed, reading};
use super::{input, rules, MODES};
use crate::common::{seeded, sharded};
use osis_base::Tid;
use osis_base::{Ak, CommitId, PurgeBy, Role, Ts, WallMs};
use osis_perm::paths::{By, Commit, Content, Delta, DeltaClass, EdgeWrite, Fact, Holding, Key, MemStore, NameKey, Names, Pair, Part, PartKind, Paths, Right, Status, Store};
use std::ops::Bound;
use osis_perm::{Edge, Frontier, WriteId};
use std::sync::Arc;
use roles_model::paths as m;
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};

/// Where the walk by components and the single walk read `commits` otherwise (statuses,
/// histories, finals, verdicts, copies, purges, chained points, counting entries, void trusted
/// writes, and with `disputes` the dispute set): the first difference.
pub(super) fn differs(a: &mut Paths, b: &mut Paths, disputes: bool) -> Option<String> {
    if reading(a) != reading(b) {
        let (ra, rb) = (reading(a), reading(b));
        let what = if ra.0 != rb.0 {
            let d: Vec<_> = ra.0.iter().filter(|(k, v)| rb.0.get(k) != Some(v)).map(|(k, v)| (k, v, rb.0.get(k))).collect();
            format!("statuses {d:?}")
        } else if ra.3 != rb.3 {
            "verdicts".into()
        } else {
            "histories, finals, copies, purges or chained points".into()
        };
        return Some(what);
    }
    if a.counting() != b.counting() {
        return Some(format!("counting {:?} / {:?}", a.counting(), b.counting()));
    }
    if a.void_trusted() != b.void_trusted() {
        return Some(format!("void trusted {:?} / {:?}", a.void_trusted(), b.void_trusted()));
    }
    if disputes {
        let (da, db) = (a.disputes(), b.disputes());
        if da != db {
            return Some(format!("disputes {da:?} / {db:?}"));
        }
        // the switches leave the reading as it was
        if differs(a, b, false).is_some() {
            return Some("the reading after disputes".into());
        }
    }
    None
}

/// `commits` from scratch, in a shuffled arrival, and with a shuffled half forgotten: the walk by
/// components against the single walk of the same held set.
pub(super) fn alike(records: &BTreeMap<Tid, Tid>, trust: &BTreeSet<WriteId>, commits: &[Commit], seed: u64, disputes: bool) -> Option<String> {
    let mut one = Paths::single(records, trust.clone());
    one.add(commits);
    let mut by = Paths::evaluate(records, trust.clone(), commits);
    if let Some(d) = differs(&mut by, &mut one, disputes) {
        return Some(format!("from scratch: {d}"));
    }
    let mut rng = Rng(seed);
    let order = rng.perm(commits.len());
    let mut p = Paths::new(records, trust.clone());
    for &k in &order {
        p.add(std::slice::from_ref(&commits[k]));
    }
    if let Some(d) = differs(&mut p, &mut one, false) {
        return Some(format!("arrival {order:?}: {d}"));
    }
    let gone: Vec<usize> = order.iter().copied().filter(|&k| k % 2 == seed as usize % 2).collect();
    p.forget(&gone.iter().map(|&k| commits[k].id).collect::<Vec<_>>());
    let rest: Vec<Commit> = (0..commits.len()).filter(|k| !gone.contains(k)).map(|k| commits[k].clone()).collect();
    let mut one = Paths::single(records, trust.clone());
    one.add(&rest);
    differs(&mut p, &mut one, disputes).map(|d| format!("forgetting {gone:?}: {d}"))
}

/// A comparison of two walks over `(records, trust, commits, seed, disputes)`: the first
/// difference.
pub(super) type Alike = fn(&BTreeMap<Tid, Tid>, &BTreeSet<WriteId>, &[Commit], u64, bool) -> Option<String>;

/// `alike` over tiny worlds of every kind, story worlds at every node, content worlds and soups
/// from `start`: the failures, at most three.
pub(super) fn run(start: u64, n: u64, alike: Alike) -> Vec<String> {
    let mut fails = vec![];
    let mut note = |f: Option<String>, what: &dyn Fn() -> String| {
        if let Some(d) = f {
            fails.push(format!("{}: {d}", what()));
        }
    };
    for mode in MODES {
        for i in start..start + n {
            let t = m::tiny_world(i, mode, &rules());
            let inp = input(&t.w, &t.v);
            note(alike(&inp.records, &inp.trust, &inp.commits, i, i % 4 == 0), &|| format!("tiny {mode:?} world {i}\n{}", m::tiny_trace(&t.w)));
        }
    }
    for i in start..start + n {
        let (w, v) = super::content::world(i);
        let w = super::as_known(&w, &v);
        let inp = input(&w, &v);
        note(alike(&inp.records, &inp.trust, &inp.commits, i, i % 4 == 0), &|| format!("content world {i}\n{}", m::tiny_trace(&w)));
        let (records, commits) = super::shapes::soup(i);
        note(alike(&records, &BTreeSet::new(), &commits, i, true), &|| format!("soup {i}\n{commits:#?}"));
        // a soup under its first edge-class part trusted
        let p = Paths::evaluate(&records, BTreeSet::new(), &commits);
        if let Some(id) = p.statuses().into_keys().next() {
            note(alike(&records, &BTreeSet::from([id]), &commits, i, false), &|| format!("soup {i} trusting {id:?}\n{commits:#?}"));
        }
    }
    for i in start..start + n.div_ceil(20) {
        let s = m::random_world(i, &m::Rules::fixed());
        for node in s.honest().into_iter().chain(s.untrusting()) {
            if !s.sync.contains_key(&node) {
                continue;
            }
            let v = s.view(node, &m::Rules::fixed());
            let w = super::as_known(&s.w, &v);
            let inp = input(&w, &v);
            note(alike(&inp.records, &inp.trust, &inp.commits, i, false), &|| format!("story world {i} node {node}"));
        }
    }
    fails.truncate(3);
    fails
}

// notes/perm-paths.md, Components: a part's verdict reads only its component, so the walk by
// components reads every world as the single walk does, from scratch, on arrival and on forgetting.
#[test]
fn components_read_as_one_walk() {
    let f = run(0, 60, alike);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// As above, more worlds (a property).
#[test]
#[ignore]
fn paths_components_agree_large() {
    let f: Vec<String> = sharded(100_000, 0x5eed_0a1e, |n, seed| run(seeded(seed) % (1 << 40), n.div_ceil(9), alike)).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}

/// A store returning every lookup in the reverse of `MemStore`'s order (the trait promises no
/// order), and keeping the addenda verdicts the walk writes as any store does.
#[derive(Clone, Default)]
struct Reversed(MemStore);

fn rev(mut v: Vec<WriteId>) -> Vec<WriteId> {
    v.reverse();
    v
}

impl Store for Reversed {
    fn put(&mut self, f: Fact) {
        self.0.put(f)
    }
    fn remove(&mut self, id: &WriteId) -> Option<Fact> {
        self.0.remove(id)
    }
    fn get(&self, id: &WriteId) -> Option<Fact> {
        self.0.get(id)
    }
    fn of_commit(&self, c: &CommitId, on: Option<&Tid>) -> Vec<WriteId> {
        rev(self.0.of_commit(c, on))
    }
    fn listing(&self, c: &CommitId) -> Vec<WriteId> {
        rev(self.0.listing(c))
    }
    fn carrying(&self, c: &CommitId) -> Vec<WriteId> {
        rev(self.0.carrying(c))
    }
    fn latest(&self, key: &NameKey, holding: Holding) -> Option<Ts> {
        self.0.latest(key, holding)
    }
    fn requests_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        rev(self.0.requests_through(e, from, to))
    }
    fn right(&self, id: &WriteId) -> Right {
        self.0.right(id)
    }
    fn set_right(&mut self, id: &WriteId, right: Right) {
        self.0.set_right(id, right)
    }
    fn own_covers(&self, signer: &Tid) -> Vec<WriteId> {
        rev(self.0.own_covers(signer))
    }
    fn addenda_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        rev(self.0.addenda_through(e, from, to))
    }
    fn through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        rev(self.0.through(e, from, to))
    }
    fn valid_addendum(&self, id: &WriteId) -> bool {
        self.0.valid_addendum(id)
    }
    fn set_valid_addendum(&mut self, id: &WriteId, valid: bool) {
        self.0.set_valid_addendum(id, valid)
    }
    fn all(&self) -> Vec<WriteId> {
        rev(self.0.all())
    }
}

// notes/perm-paths.md, The delta-facts seam: the walk reads the same through any store keeping
// the trait's contract, whatever order its lookups return in: content worlds and soups through
// `Reversed`, from scratch and on a shuffled arrival with half forgotten, against `MemStore`.
#[test]
fn any_lookup_order_reads_alike() {
    for i in 0..120 {
        let (w, v) = super::content::world(i);
        let w = super::as_known(&w, &v);
        let inp = input(&w, &v);
        let (s, c) = super::shapes::soup(i);
        for (records, trust, commits) in [(&inp.records, &inp.trust, &inp.commits), (&s, &BTreeSet::new(), &c)] {
            let mut p = Paths::with_store(records, trust.clone(), Reversed::default());
            let order = Rng(i).perm(commits.len());
            for &k in &order {
                p.add(std::slice::from_ref(&commits[k]));
            }
            assert!(reading(&p) == reading(&Paths::evaluate(records, trust.clone(), commits)), "world {i}");
            let gone: Vec<CommitId> = order.iter().filter(|&&k| k % 2 == 0).map(|&k| commits[k].id).collect();
            p.forget(&gone);
            let rest: Vec<Commit> = commits.iter().filter(|c| !gone.contains(&c.id)).cloned().collect();
            assert!(reading(&p) == reading(&Paths::evaluate(records, trust.clone(), &rest)), "world {i}, forgetting");
        }
    }
}

fn th(n: u32) -> Tid {
    let mut b = [0u8; 15];
    b[..4].copy_from_slice(&n.to_be_bytes());
    Tid::from_bytes(b)
}

fn cm(n: u64) -> CommitId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    CommitId(b)
}

fn mk(id: u64, ts: u64, signer: u32, parts: Vec<Part>) -> Commit {
    Commit { id: cm(id), ts: Ts::make(WallMs(ts), 0).unwrap(), signer: th(signer), parts }
}

/// An edge write on `on` along `path` setting `holder` to `role` (none: a removal), its frontier
/// listing `list`.
fn ew(on: u32, path: &[u32], holder: u32, role: Option<Role>, list: &[u64]) -> Part {
    let frontier = Some(Arc::new(Frontier::new(list.iter().map(|&c| cm(c)))));
    Part { on: th(on), path: path.iter().map(|&x| th(x)).collect(), kind: PartKind::Edge(EdgeWrite { holder: th(holder), value: role.map(Edge::new), frontier, remains: None, adminless: false }) }
}

fn role_delta(on: u32, path: &[u32]) -> Part {
    let d = Delta { aspect: Ak::new("keys.0").unwrap(), needs: Role::Write, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class: DeltaClass::RoleClass };
    Part { on: th(on), path: path.iter().map(|&x| th(x)).collect(), kind: PartKind::Delta(d) }
}

fn vouch(on: u32, removal: u64, list: &[u64]) -> Part {
    Part { on: th(on), path: vec![], kind: PartKind::Vouch { removal: cm(removal), list: Frontier::new(list.iter().map(|&c| cm(c))) } }
}

const H: u32 = 1;
const M: u32 = 2;
const X: u32 = 3;
const Y: u32 = 4;
const Z: u32 = 5;
const W: u32 = 6;
/// A, B and C minted by H; N by M.
const A: u32 = 10;
const B: u32 = 11;
const C: u32 = 12;
const N: u32 = 20;

fn recs() -> BTreeMap<Tid, Tid> {
    BTreeMap::from([(th(A), th(H)), (th(B), th(H)), (th(C), th(H)), (th(N), th(M))])
}

/// X's role-class delta on N along [A] (A granted admin on N by M) rests on X's edge on A, which
/// H's removal cuts; M's vouch on N keeps it. Nothing but the vouch joins A's edges and N's: the
/// vouch's join is what makes the first walk run where the removal is.
fn vouch_world() -> Vec<Commit> {
    vec![
        mk(1, 1, H, vec![ew(A, &[], X, Some(Role::Admin), &[])]),
        mk(2, 1, M, vec![ew(N, &[], A, Some(Role::Admin), &[])]),
        mk(3, 3, X, vec![role_delta(N, &[A])]),
        mk(4, 5, H, vec![ew(A, &[], X, None, &[])]),
        mk(5, 6, M, vec![vouch(N, 4, &[3])]),
    ]
}

// spec/permissions.md §5.1 Vouches (draft): a vouch on N for a removal on another thing counts,
// whatever joins their edges otherwise: its removal applies as a lowering in the first walk, which
// runs where a vouch is (notes/perm-paths.md, Components: a vouch touches its removal's edges).
// Every arrival order; the single walk alike.
#[test]
fn a_vouch_joins_its_removals_component() {
    let c = vouch_world();
    let id = WriteId(cm(3), 0);
    for order in perms(c.len()) {
        let mut p = Paths::new(&recs(), BTreeSet::new());
        for &k in &order {
            p.add(std::slice::from_ref(&c[k]));
        }
        assert_eq!(p.content(&id), Some(Content::Valid(By::Listed)), "order {order:?}");
    }
    assert_eq!(alike(&recs(), &BTreeSet::new(), &c, 1, true), None);
    let without: Vec<Commit> = c[..4].to_vec();
    assert_eq!(Paths::evaluate(&recs(), BTreeSet::new(), &without).content(&id), Some(Content::Invalid));
}

fn perms(n: usize) -> Vec<Vec<usize>> {
    let mut out = vec![vec![]];
    for k in 0..n {
        out = out.into_iter().flat_map(|o: Vec<usize>| (0..=o.len()).map(move |at| [&o[..at], &[k], &o[at..]].concat())).collect();
    }
    out
}

/// A world of every forget case: a lowering with drops (5, dropping X's grant of Y), a lowering
/// judged void against the grant it rests on (6), a part joining two components (4: H on B along
/// [A]), a commit writing two components (7), a vouch with a counting entry (10 for 9 against 5).
fn forget_world() -> Vec<Commit> {
    let admin = Some(Role::Admin);
    vec![
        mk(1, 1, H, vec![ew(A, &[], X, admin, &[])]),
        mk(2, 2, X, vec![ew(A, &[], Y, admin, &[])]),
        mk(3, 2, H, vec![ew(B, &[], A, admin, &[])]),
        mk(4, 3, H, vec![ew(B, &[A], W, Some(Role::Write), &[])]),
        mk(5, 5, H, vec![ew(A, &[], X, None, &[])]),
        mk(6, 4, Y, vec![ew(A, &[], X, None, &[])]),
        mk(7, 6, H, vec![ew(A, &[], Z, admin, &[]), ew(C, &[], Z, admin, &[])]),
        mk(8, 1, M, vec![ew(N, &[], A, admin, &[])]),
        mk(9, 3, X, vec![role_delta(N, &[A])]),
        mk(10, 7, M, vec![vouch(N, 5, &[9])]),
    ]
}

/// Over every subset of `commits` forgotten at once from all held, under `trust`: `Changed` exact,
/// the reading (counting entries and void trusted writes too) as from scratch over the rest and
/// as the single walk; then added again in reverse order, each `Changed` exact, as all held.
fn every_forget(trust: &BTreeSet<WriteId>, commits: &[Commit]) {
    let n = commits.len();
    let full = Paths::evaluate(&recs(), trust.clone(), commits);
    for mask in 0u32..1 << n {
        let gone: Vec<usize> = (0..n).filter(|k| mask >> k & 1 == 1).collect();
        let rest: Vec<Commit> = (0..n).filter(|k| mask >> k & 1 == 0).map(|k| commits[k].clone()).collect();
        let mut p = full.clone();
        let ch = p.forget(&gone.iter().map(|&k| commits[k].id).collect::<Vec<_>>());
        assert_eq!(check(&full, &p, &ch), None, "forgetting {gone:?} under {trust:?}");
        let mut scratch = Paths::evaluate(&recs(), trust.clone(), &rest);
        assert_eq!(differs(&mut p, &mut scratch, mask % 61 == 0), None, "forgetting {gone:?} under {trust:?}");
        let mut one = Paths::single(&recs(), trust.clone());
        one.add(&rest);
        assert_eq!(differs(&mut p, &mut one, false), None, "forgetting {gone:?} under {trust:?}, single");
        for &k in gone.iter().rev() {
            let before = p.clone();
            let ch = p.add(std::slice::from_ref(&commits[k]));
            assert_eq!(check(&before, &p, &ch), None, "adding {k} again after {gone:?} under {trust:?}");
        }
        assert!(reading(&p) == reading(&full) && p.counting() == full.counting() && p.void_trusted() == full.void_trusted(), "re-added {gone:?} under {trust:?}");
    }
}

// notes/perm-paths.md, Forget and update: every subset of a world of every forget case forgotten
// (a lowering's drops coming back, a void lowering's grant gone, the joining part of a merged
// component, a vouch with its counting entry, a commit writing two components, a trusted write)
// reads as from scratch over the rest and as the single walk, and added again as never forgotten.
#[test]
fn every_forget_of_a_world_of_every_case_reads_as_from_scratch() {
    let c = forget_world();
    let p = Paths::evaluate(&recs(), BTreeSet::new(), &c);
    // the cases are there: 5 drops 2, 6 void, 4 applied joining A and B, the entry counting
    assert_eq!((p.status(&WriteId(cm(2), 0)), p.status(&WriteId(cm(6), 0)), p.status(&WriteId(cm(4), 0))), (Some(Status::Dropped), Some(Status::Void), Some(Status::Applied)));
    assert_eq!(p.counting().len(), 1);
    for trust in [BTreeSet::new(), BTreeSet::from([WriteId(cm(5), 0)]), BTreeSet::from([WriteId(cm(6), 0)])] {
        every_forget(&trust, &c);
    }
}

/// A `doc.0` delta on `on` along `path` of `retention`, its signer its purge author.
fn doc(on: u32, path: &[u32], retention: PurgeBy) -> Part {
    let d = Delta { aspect: Ak::new("doc.0").unwrap(), needs: Role::Write, purge_author: 0, retention, class: DeltaClass::Plain };
    Part { on: th(on), path: path.iter().map(|&x| th(x)).collect(), kind: PartKind::Delta(d) }
}

/// A purge request on `on` along `path` naming `names` on `doc.0` (a destruction: on `created.0`).
fn req(on: u32, path: &[u32], names: Names) -> Part {
    let aspect = Ak::new(if names == Names::Destroy { "created.0" } else { "doc.0" }).unwrap();
    let d = Delta { aspect, needs: Role::Write, purge_author: 0, retention: PurgeBy::AuthorOrAdmin, class: DeltaClass::Purge { names } };
    Part { on: th(on), path: path.iter().map(|&x| th(x)).collect(), kind: PartKind::Delta(d) }
}

/// A world of every purge case (draft §6): H grants X admin on A (1); H's `writer` delta on A
/// (2); X's request by aspect (3) and destruction of A (4); H removes X listing nothing (5: it takes
/// the request's right, not the destruction's: a cut on an edge into A stamped after it); H grants
/// X admin again (6: the request re-granted, as an edit made before the cut would be).
fn purge_world() -> Vec<Commit> {
    let admin = Some(Role::Admin);
    vec![
        mk(1, 1, H, vec![ew(A, &[], X, admin, &[])]),
        mk(2, 2, H, vec![doc(A, &[], PurgeBy::Writer)]),
        mk(3, 3, X, vec![req(A, &[], Names::Aspect)]),
        mk(4, 4, X, vec![req(A, &[], Names::Destroy)]),
        mk(5, 5, H, vec![ew(A, &[], X, None, &[])]),
        mk(6, 6, H, vec![ew(A, &[], X, admin, &[])]),
    ]
}

// spec/permissions.md §6: draft purges a reading, restore: in every arrival order and under every
// subset of the purge world forgotten, purges read as from scratch, `Changed` exact (each request
// whose right moved reported by its scope), the single walk alike; without the destruction the
// removal takes the request's right and the re-grant gives it back.
#[test]
fn every_order_and_forget_of_a_purge_world_reads_as_from_scratch() {
    let c = purge_world();
    let d = WriteId(cm(2), 0);
    let read = |cs: &[Commit]| Paths::evaluate(&recs(), BTreeSet::new(), cs).purged().contains(&d);
    let without = |gone: &[u64]| c.iter().filter(|x| !gone.iter().any(|g| x.id == cm(*g))).cloned().collect::<Vec<_>>();
    assert!(read(&c) && read(&without(&[6])) && read(&without(&[3, 6])));
    assert!(!read(&without(&[4, 6])) && read(&without(&[4])) && read(&without(&[4, 5])));
    for trust in [BTreeSet::new(), BTreeSet::from([WriteId(cm(5), 0)])] {
        every_forget(&trust, &c);
    }
    let scratch = Paths::evaluate(&recs(), BTreeSet::new(), &c);
    for order in perms(c.len()) {
        let mut p = Paths::new(&recs(), BTreeSet::new());
        for &k in &order {
            let before = p.clone();
            let ch = p.add(std::slice::from_ref(&c[k]));
            assert_eq!(check(&before, &p, &ch), None, "order {order:?}, adding {k}");
        }
        assert!(reading(&p) == reading(&scratch), "order {order:?}");
    }
}

/// A destruction racing cuts of its path on an edge into another thing (draft §6 Destruction:
/// such a cut reads as for any request): M grants A admin on N (1); H grants X admin on A (2); M's
/// `writer` delta on N (3); X destroys N along [A] at 5 (4); H's removal of X from A backdated to
/// 4 listing nothing (5: ordered before the destruction, it takes the right); H's removal of X at
/// 6 listing the destruction (6: it keeps it).
fn destruction_race() -> Vec<Commit> {
    let admin = Some(Role::Admin);
    vec![
        mk(1, 1, M, vec![ew(N, &[], A, admin, &[])]),
        mk(2, 1, H, vec![ew(A, &[], X, admin, &[])]),
        mk(3, 2, M, vec![doc(N, &[], PurgeBy::Writer)]),
        mk(4, 5, X, vec![req(N, &[A], Names::Destroy)]),
        mk(5, 4, H, vec![ew(A, &[], X, None, &[])]),
        mk(6, 6, H, vec![ew(A, &[], X, None, &[4])]),
    ]
}

// spec/permissions.md §6: draft Destruction, a cut of its path on another thing's edge reads as for
// any request, in every arrival order and under every subset forgotten: the backdated removal
// ordered before the destruction takes it (the later one's list cannot give back what was never
// held); without it, the later removal keeps it by its list, and takes it listing nothing.
#[test]
fn every_order_and_forget_of_a_destruction_racing_a_cut_reads_as_from_scratch() {
    let c = destruction_race();
    let d = WriteId(cm(3), 0);
    let read = |cs: &[Commit]| Paths::evaluate(&recs(), BTreeSet::new(), cs).purged().contains(&d);
    let without = |gone: &[u64]| c.iter().filter(|x| !gone.iter().any(|g| x.id == cm(*g))).cloned().collect::<Vec<_>>();
    assert!(!read(&c) && read(&without(&[5])) && read(&without(&[5, 6])) && !read(&without(&[4])));
    let mut unlisted = without(&[5]);
    unlisted.retain(|x| x.id != cm(6));
    unlisted.push(mk(6, 6, H, vec![ew(A, &[], X, None, &[])]));
    assert!(!read(&unlisted));
    for trust in [BTreeSet::new(), BTreeSet::from([WriteId(cm(6), 0)])] {
        every_forget(&trust, &c);
    }
    let scratch = Paths::evaluate(&recs(), BTreeSet::new(), &c);
    for order in perms(c.len()) {
        let mut p = Paths::new(&recs(), BTreeSet::new());
        for &k in &order {
            let before = p.clone();
            let ch = p.add(std::slice::from_ref(&c[k]));
            assert_eq!(check(&before, &p, &ch), None, "order {order:?}, adding {k}");
        }
        assert!(reading(&p) == reading(&scratch), "order {order:?}");
    }
}

// A frontier leaf arriving (`update`) that makes a lowering list what it dropped, and going again:
// each as from scratch, `Changed` exact, under every trust of the world.
#[test]
fn a_leaf_arriving_that_lists_a_drop_reads_as_from_scratch() {
    let c = forget_world();
    let mut listing = c.clone();
    listing[4] = mk(5, 5, H, vec![ew(A, &[], X, None, &[2])]);
    for trust in [BTreeSet::new(), BTreeSet::from([WriteId(cm(5), 0)])] {
        let mut p = Paths::evaluate(&recs(), trust.clone(), &c);
        for (now, version) in [(&listing, &listing[4]), (&c, &c[4])] {
            let before = p.clone();
            let ch = p.update(std::slice::from_ref(version));
            assert_eq!(check_renewed(&before, &p, &ch, &BTreeSet::from([cm(5)])), None);
            let mut scratch = Paths::evaluate(&recs(), trust.clone(), now);
            assert_eq!(differs(&mut p, &mut scratch, true), None);
        }
        assert_eq!(Paths::evaluate(&recs(), trust.clone(), &listing).status(&WriteId(cm(2), 0)), Some(Status::Applied));
    }
}

// notes/perm-paths.md, Inert parts: liveness grows in any order. A chain of grants each resting on
// the one before (X grants Y, Y grants Z), two writes each resting on the other's edge (Q grants
// W, W grants Q: neither live while nothing else sets those edges), and H's grant of Q backdated
// before both, which makes the pair live at once: every arrival order reads as from scratch and as
// the single walk, each `Changed` exact.
#[test]
fn liveness_reads_alike_in_every_arrival_order() {
    const Q: u32 = 7;
    let admin = Some(Role::Admin);
    let c = vec![
        mk(1, 1, H, vec![ew(A, &[], X, admin, &[])]),
        mk(2, 2, X, vec![ew(A, &[], Y, admin, &[])]),
        mk(3, 3, Y, vec![ew(A, &[], Z, admin, &[])]),
        mk(4, 2, Q, vec![ew(A, &[], W, admin, &[])]),
        mk(5, 3, W, vec![ew(A, &[], Q, admin, &[])]),
        mk(6, 1, H, vec![ew(A, &[], Q, admin, &[])]),
    ];
    let mut scratch = Paths::evaluate(&recs(), BTreeSet::new(), &c);
    assert!((1..=6).all(|k| scratch.status(&WriteId(cm(k), 0)) == Some(Status::Applied)));
    let pair = Paths::evaluate(&recs(), BTreeSet::new(), &c[3..5]);
    assert!(pair.statuses().values().all(|s| *s == Status::Unapplied));
    for order in perms(c.len()) {
        let mut p = Paths::new(&recs(), BTreeSet::new());
        for &k in &order {
            let before = p.clone();
            let ch = p.add(std::slice::from_ref(&c[k]));
            assert_eq!(check(&before, &p, &ch), None, "order {order:?}, adding {k}");
        }
        assert_eq!(differs(&mut p, &mut scratch, false), None, "order {order:?}");
    }
    assert_eq!(alike(&recs(), &BTreeSet::new(), &c, 3, true), None);
}
