//! The reference graph (spec/sync-set.md), held_model::closure: each test names the
//! property (P1-P6 of notes/closure-model.md) it checks. Where the plan's rule fails a property the
//! test asserts the minimal counterexample, so the finding stays visible and checked.
use held_model::closure::*;
use held_model::gen::Rng;
use std::collections::{BTreeMap, BTreeSet};

const K: Kind = Kind::Independent;
fn p(k: T) -> Kind {
    Kind::Dependent(k)
}
fn worldr(kinds: &[Kind], grants: &[(T, T, Role)]) -> World {
    World { kinds: kinds.to_vec(), grants: grants.iter().map(|&(g, t, r)| ((g, t), r)).collect(), ..World::default() }
}
/// Grants of read.
fn world(kinds: &[Kind], grants: &[(T, T)]) -> World {
    worldr(kinds, &grants.iter().map(|&(g, t)| (g, t, Role::Read)).collect::<Vec<_>>())
}
fn set(xs: &[T]) -> Set {
    xs.iter().copied().collect()
}
fn es(xs: &[(T, T)]) -> Edges {
    xs.iter().copied().collect()
}
fn subsets<X: Copy>(of: &[X]) -> Vec<Vec<X>> {
    (0..1u32 << of.len()).map(|m| of.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, x)| *x).collect()).collect()
}
fn add(from: T, to: T) -> Commit {
    Commit { from, op: Op::Add(to), ephemeral: false }
}
fn role(on: T, g: T, r: Option<Role>) -> Commit {
    Commit { from: on, op: Op::Role(g, r), ephemeral: false }
}
fn tickets(open: &[T], sync_only: &[T]) -> BTreeMap<T, Ticket> {
    open.iter().map(|&t| (t, Ticket::Open)).chain(sync_only.iter().map(|&t| (t, Ticket::SyncOnly))).collect()
}

/// Every world of independent 0, 1 and dependent 2, 3, 4 (keys from 0 or 1), each of 0 and 1 holding no
/// role, sync or read on the other, and any strongs among `cand`.
fn p1_worlds(cand: &[(T, T)]) -> Vec<(World, Edges)> {
    let roles = [None, Some(Role::Sync), Some(Role::Read)];
    let mut out = vec![];
    for kf in 0..8u32 {
        let kinds: Vec<Kind> = [K, K].into_iter().chain((0..3).map(|i| p((kf >> i & 1) as T))).collect();
        for a in roles {
            for b in roles {
                let g: Vec<(T, T, Role)> = [(0, 1, a), (1, 0, b)].into_iter().filter_map(|(g, t, r)| r.map(|r| (g, t, r))).collect();
                for e in subsets(cand) {
                    out.push((worldr(&kinds, &g), es(&e)));
                }
            }
        }
    }
    out
}
const P1_CAND: [(T, T); 9] = [(0, 2), (2, 3), (3, 4), (4, 2), (2, 1), (1, 3), (3, 0), (0, 4), (1, 4)];

/// P1: no leaves (every thing of T's sync unit but T is one T's keys open); every reader of T computes
/// T's sync unit, whatever else it reads; a strong inside a thing T's keys cannot open never changes it.
#[test]
fn p1_units_agree_exhaustive() {
    for (w, e) in p1_worlds(&P1_CAND) {
        for t in [0, 1] {
            let pc = unit(&w, t, &e);
            let keys = w.keys_of(t);
            assert!(pc.iter().all(|&x| x == t || w.opens(&keys, x)), "{w:?} {e:?}");
            for reads in [set(&[t]), set(&[0, 1])] {
                assert_eq!(unit_seen(&w, t, &reads, &e), pc, "{w:?} {e:?} reader of {reads:?}");
            }
            for x in (0..5).filter(|&x| x != t && !w.opens(&keys, x)) {
                for y in 0..5 {
                    let mut e2 = e.clone();
                    if !e2.remove(&(x, y)) {
                        e2.insert((x, y));
                    }
                    assert_eq!(unit(&w, t, &e2), pc, "{w:?} {e:?} toggling {x}->{y}");
                }
            }
        }
    }
}

/// P1 needs the walk to read T's keys, not the reader's. By the reader's keys, a reader of T and
/// U carries U's dependent things under T, a reader of T alone does not, and a shared store under T
/// flips each round for good. By T's keys it settles at once.
#[test]
fn p1_by_readers_keys_undoes_forever() {
    // T=0, U=1; B=2 and C=3 dependent on U; T -> B -> C.
    let w = world(&[K, K, p(1), p(1)], &[]);
    let e = es(&[(0, 2), (2, 3)]);
    let by = |reads: &[T]| unit_with(&w, 0, &w.ring(&set(reads)), &e);
    assert_eq!(by(&[0]), set(&[0]));
    assert_eq!(by(&[0, 1]), set(&[0, 2, 3]));
    let flips = |f: &dyn Fn(&[T]) -> Set| {
        let mut store = Set::new();
        let mut n = 0;
        for _round in 0..10 {
            for reads in [&[0][..], &[0, 1][..]] {
                let mine = f(reads);
                if mine != store {
                    store = mine;
                    n += 1;
                }
            }
        }
        n
    };
    assert_eq!(flips(&by), 20, "by the reader's keys: two changes a round, for good");
    assert_eq!(flips(&|_| unit(&w, 0, &e)), 1, "by T's keys: one change, then settled");
}

/// A random world of independent 0, 1 and dependent 2..6, and a commit history on it: adds, removes naming
/// an earlier add on the same source, and role commits of 0 and 1 on each other.
fn random_history(r: &mut Rng, len: usize) -> (World, Vec<Commit>) {
    let kinds: Vec<Kind> = [K, K].into_iter().chain((2..6).map(|_| p(r.below(2) as T))).collect();
    let mut cs: Vec<Commit> = vec![];
    for _ in 0..len {
        let adds: Vec<C> = (0..cs.len()).filter(|&c| matches!(cs[c].op, Op::Add(_))).collect();
        if r.chance(20) {
            let on = r.below(2) as T;
            cs.push(role(on, 1 - on, [None, Some(Role::Sync), Some(Role::Read)][r.below(3) as usize]));
        } else if !adds.is_empty() && r.chance(30) {
            let a = r.pick(&adds);
            cs.push(Commit { from: cs[a].from, op: Op::Remove(BTreeSet::from([a])), ephemeral: false });
        } else {
            cs.push(add(r.below(6) as T, r.below(6) as T));
        }
    }
    (world(&kinds, &[]), cs)
}

/// What T's sync ID carries of `held`, by the view of `held`.
fn carried_commits(w: &World, cs: &[Commit], held: &BTreeSet<C>, t: T, fix: bool) -> BTreeSet<C> {
    let (wv, e) = (w.with_roles(cs, held), edges(cs, held));
    let cr = Carry { unit: unit(&wv, t, &e), keys: wv.keys_of(t), certify_revokes: fix };
    held.iter().copied().filter(|&c| cr.carries(&cs[c])).collect()
}

/// P1 with grants as data: what T's sync ID carries decides T's sync unit, and having held what it
/// carried earlier changes nothing. Over random histories with role commits of 0 and 1 on each
/// other, a reader holding what T carried after any prefix and what it carries after all
/// computes T's sync unit over all: with role commits carried under the actor they name, in every
/// one. By the plan's words a revocation is carried under neither sync ID, so the earlier grant
/// stands at such a reader (counted; minimal: `p2_revocation_reaches_grantee_only_node`).
#[test]
fn p1_carried_commits_decide_the_unit() {
    let mut r = Rng::new(0);
    let mut differ = 0;
    for _ in 0..1000 {
        let (w, cs) = random_history(&mut r, 8);
        let all: BTreeSet<C> = (0..cs.len()).collect();
        for t in [0, 1] {
            let truth = unit(&w.with_roles(&cs, &all), t, &edges(&cs, &all));
            for fix in [true, false] {
                let now = carried_commits(&w, &cs, &all, t, fix);
                for k in 0..cs.len() {
                    let mut has = carried_commits(&w, &cs, &(0..k).collect(), t, fix);
                    has.extend(&now);
                    let seen = unit(&w.with_roles(&cs, &has), t, &edges(&cs, &has));
                    if fix {
                        assert_eq!(seen, truth, "{w:?} {cs:?} prefix {k}");
                    } else if seen != truth {
                        differ += 1;
                    }
                }
            }
        }
    }
    assert!(differ > 0);
    eprintln!("p1: by the plan's words {differ} of 16000 readers compute a different unit");
}

/// P2: commits reaching readers of T in any order, each reader carrying what its view's sync unit
/// holds and adding or deleting as it changes: once all are delivered every reader carries T's
/// sync unit over all of them, after finitely many changes (at most one per delivery and thing).
#[test]
fn p2_carrying_settles_any_order() {
    let mut r = Rng::new(0);
    let mut most = 0;
    for _ in 0..2000 {
        let (w, cs) = random_history(&mut r, 8);
        let all: BTreeSet<C> = (0..cs.len()).collect();
        let truth = unit(&w.with_roles(&cs, &all), 0, &edges(&cs, &all));
        let readers = [set(&[0]), set(&[0, 1]), set(&[0])];
        let mut order: Vec<(usize, C)> = (0..3).flat_map(|n| (0..cs.len()).map(move |c| (n, c))).collect();
        r.shuffle(&mut order);
        let mut has = vec![BTreeSet::new(); 3];
        let mut carried = vec![Set::from([0]); 3];
        let mut changes = 0;
        for (n, c) in order {
            has[n].insert(c);
            let now = unit_seen(&w.with_roles(&cs, &has[n]), 0, &readers[n], &edges(&cs, &has[n]));
            changes += now.symmetric_difference(&carried[n]).count();
            carried[n] = now;
        }
        assert!(carried.iter().all(|c| *c == truth), "{w:?} {cs:?}");
        assert!(changes <= 3 * cs.len() * w.kinds.len());
        most = most.max(changes);
    }
    eprintln!("p2: at most {most} adds and deletes over 3 readers of 8 commits");
}

/// P2, each holder deleting by its own view: node 0 removes A -> P, drops P with no peer
/// connected and deletes P's entries from T's store; node 1 has concurrently re-added A -> P. Node
/// 1's view still holds P: it keeps P's data, logs it again, and both end holding it. The
/// mutation "gone for everyone" (node 0 deletes P at every holder) leaves P in T's sync unit with no
/// node or store holding its data.
#[test]
fn p2_per_holder_delete_keeps_concurrent_readd() {
    // T=0; A=1, P=2 dependent on T.
    let w = world(&[K, p(0), p(0)], &[]);
    for everyone in [false, true] {
        let mut s = Sync::new(w.clone(), vec![set(&[0]); 2], true);
        s.delete_key = vec![set(&[0]); 2];
        s.write(0, add(0, 1));
        let c1 = s.write(0, add(1, 2));
        let data = s.write(0, add(2, 1)); // P's own content
        assert_eq!(s.settle(5), Some(2));
        s.write(0, Commit { from: 1, op: Op::Remove(BTreeSet::from([c1])), ephemeral: false });
        s.prune(0);
        s.store_round(0);
        assert!(!s.has[0].contains(&data) && !s.store[&0].contains(&data), "node 0 dropped P and deleted its entry");
        if everyone {
            s.has[1].remove(&data);
        }
        s.write(1, add(1, 2)); // concurrent re-add
        s.store_round(1);
        assert_eq!(s.store[&0].contains(&data), !everyone, "node 1 logs P again");
        assert!(s.settle(5).is_some());
        assert!(s.carried(0, 0).contains(&2) && s.carried(1, 0).contains(&2));
        assert_eq!(s.has.iter().any(|h| h.contains(&data)), !everyone, "everyone={everyone}");
    }
}

/// P2/(d): a dependent thing in two sync units gets each edit only under the sync IDs its writer syncs. A
/// (keys from T) is in T's sync unit and Z's (Z granted read on T); a node syncing only Z writes
/// A -> B. A node syncing only T gets it exactly where a node syncing both relays it: by
/// exchanging with both, or through the two stores alone.
#[test]
fn p2_two_units_reach_only_through_a_bridge() {
    // T=0, Z=1 independent; A=2, B=3 dependent on T.
    let w = world(&[K, K, p(0), p(0)], &[(1, 0)]);
    for bridge in [None, Some(false), Some(true)] {
        let mut s = Sync::new(w.clone(), vec![set(&[0]), set(&[1]), if bridge.is_some() { set(&[0, 1]) } else { set(&[]) }], true);
        s.write(0, add(0, 2));
        s.write(1, add(1, 2));
        let ab = s.write(1, add(2, 3));
        for _ in 0..4 {
            if bridge == Some(false) {
                s.exchange(0, 2);
                s.exchange(1, 2);
            }
            (0..3).for_each(|n| s.store_round(n));
        }
        assert_eq!(s.carried(1, 1), set(&[1, 2, 3]));
        assert_eq!(s.has[0].contains(&ab), bridge.is_some(), "bridge {bridge:?}");
        assert_eq!(s.carried(0, 0), if bridge.is_some() { set(&[0, 2, 3]) } else { set(&[0, 2]) });
    }
}

/// P2 FAILS by the plan's words, (b): a revocation never reaches a node that syncs only the
/// grantee where the target is dependent or the grant is a chain. Z granted read on T, A dependent on
/// T, Z -> A; node 0 syncs T and Z and holds Z's delete key, node 1 syncs Z only. Node 0 revokes
/// Z's read on T: by its view A left Z's sync unit and the role commit, on T, is carried under Z by
/// nothing, so node 1 never gets it, keeps A, logs A under Z again each time node 0 deletes it,
/// for good. Carrying a role commit under the sync ID of the actor it names (`certify_revokes`)
/// settles it. An independent target granted directly settles either way: node 1 syncs Y itself while
/// it holds Y, and gets the revocation there.
#[test]
fn p2_revocation_reaches_grantee_only_node() {
    let read = Some(Role::Read);
    // (kinds, setup by node 0, the revocation, node 0's subs, node 1's subs, sync ID node 0
    // deletes under, the thing node 1 must drop)
    type Case = (Vec<Kind>, Vec<Commit>, Commit, Set, Set, T, T);
    let cases: [(&str, Case); 3] = [
        // T=0, Z=1 independent; A=2, B=3 dependent on T; Z read on T; Z -> A -> B.
        ("dependent", (vec![K, K, p(0), p(0)], vec![role(0, 1, read), add(1, 2), add(2, 3)], role(0, 1, None), set(&[0, 1]), set(&[1]), 1, 2)),
        // X=0, W=1, Y=2 independent, B=3 dependent on Y; X read on W, W read on Y; X -> Y -> B.
        ("chain", (vec![K, K, K, p(2)], vec![role(1, 0, read), role(2, 1, read), add(0, 2), add(2, 3)], role(1, 0, None), set(&[0, 1, 2]), set(&[0]), 0, 2)),
        // X=0, Y=1 independent, B=2 dependent on Y; X read on Y; X -> Y -> B.
        ("direct", (vec![K, K, p(1)], vec![role(1, 0, read), add(0, 1), add(1, 2)], role(1, 0, None), set(&[0, 1]), set(&[0]), 0, 1)),
    ];
    for (name, (kinds, setup, revoke, s0, s1, del, gone)) in cases {
        for fix in [false, true] {
            let mut s = Sync::new(world(&kinds, &[]), vec![s0.clone(), s1.clone()], fix);
            s.delete_key[0].insert(del);
            for c in &setup {
                s.write(0, c.clone());
            }
            assert!(s.settle(5).is_some());
            assert!(s.carried(1, del).contains(&gone), "{name}: node 1 holds it under the grantee");
            s.write(0, revoke.clone());
            let settled = s.settle(20);
            let reaches = fix || name == "direct";
            assert_eq!(settled.is_some(), reaches, "{name} fix={fix}");
            assert_eq!(s.carried(1, del).contains(&gone), !reaches, "{name} fix={fix}");
            if reaches {
                assert!(s.agrees());
            }
        }
    }
}

/// P2 and (d) by sync, random: independent 0, 1, 2 and dependent 3..7, three nodes syncing what they read,
/// strong adds and removes, exchanges and store visits in any order, delete keys anywhere. Five
/// modes: grants and revocations racing the rest, with role commits carried under the actor they
/// name (`certify_revokes`) or by the plan's words, each with and without a fourth node reading
/// every sync ID; and fixed grants with no such node.
/// - With `certify_revokes` every run settles (no two nodes undo each other), and with the fourth
///   node every node agrees with every sync ID it syncs.
/// - Fixed grants: every run settles, and every split traces to a dependent thing's edit missing at a
///   node (the plan's limit; an edit of an independent thing reaches each holder, as each syncs it).
/// - By the plan's words some runs never settle or end with a node keeping what a revocation
///   took out (counted; the minimal case is `p2_revocation_reaches_grantee_only_node`).
#[test]
fn p2_sync_settles_random() {
    let mut r = Rng::new(0);
    let (mut split, mut stuck) = (0, 0);
    let runs = 1500;
    for i in 0..runs {
        let mode = i % 5;
        let (fix, bridge, fixed) = (mode < 2 || mode == 4, mode % 2 == 0 && mode < 4, mode == 4);
        let kinds: Vec<Kind> = [K, K, K].into_iter().chain((3..7).map(|_| p(r.below(3) as T))).collect();
        let grants: Vec<(T, T)> = if fixed { (0..3).flat_map(|g| (0..3).map(move |t| (g, t))).filter(|&(g, t)| g != t && r.chance(30)).collect() } else { vec![] };
        let w = world(&kinds, &grants);
        let mut subs: Vec<Set> = (0..3).map(|_| set(&[r.below(3) as T])).collect();
        subs.push(if bridge { set(&[0, 1, 2]) } else { set(&[]) });
        let mut s = Sync::new(w.clone(), subs, fix);
        for n in 0..4 {
            s.delete_key[n] = (0..3).filter(|_| r.chance(50)).collect();
        }
        for k in 0..3 {
            if let Some(n) = (0..3).find(|&n| s.subs[n].contains(&k)) {
                s.write(n, add(k, 3 + r.below(4) as T));
            }
        }
        for _ in 0..20 {
            let n = r.below(3) as usize;
            match r.below(10) {
                0..=2 => {
                    let m = r.below(4) as usize;
                    if m != n {
                        s.exchange(n, m);
                    }
                }
                3 => s.store_round(n),
                _ => {
                    let mine: Vec<T> = s.syncs(n).iter().flat_map(|&k| s.carried(n, k)).collect();
                    if mine.is_empty() {
                        continue;
                    }
                    let x = r.pick(&mine);
                    let vis: Vec<C> = s.has[n].iter().copied().filter(|&c| s.commits[c].from == x && matches!(s.commits[c].op, Op::Add(_))).collect();
                    if !fixed && w.independent(x) && r.chance(50) {
                        let g = (x + 1 + r.below(2) as T) % 3;
                        s.write(n, role(x, g, [None, Some(Role::Sync), Some(Role::Read), Some(Role::Read)][r.below(4) as usize]));
                    } else if !vis.is_empty() && r.chance(30) {
                        let a = r.pick(&vis);
                        s.write(n, Commit { from: x, op: Op::Remove(BTreeSet::from([a])), ephemeral: false });
                    } else {
                        s.write(n, add(x, r.below(7) as T));
                    }
                }
            }
        }
        let settled = s.settle(12).is_some();
        let ok = settled && s.agrees();
        let ctx = || format!("{w:?} {:?} {:?}", s.subs, s.commits);
        if fix {
            assert!(settled, "{}", ctx());
        }
        if fix && bridge {
            assert!(ok, "{}", ctx());
        }
        if fixed && !ok {
            split += 1;
            let dependent = s.missing().iter().any(|(_, _, lacks)| lacks.iter().any(|&c| !w.independent(s.commits[c].from)));
            assert!(dependent, "a split with no dependent thing's edit missing: {}", ctx());
        }
        if !fix {
            stuck += (!settled || bridge && !ok) as usize;
        }
    }
    assert!(split > 0, "the split is reached");
    eprintln!("p2: {split} of {} runs with fixed grants split; {stuck} of {} runs by the plan's words never settle or keep a revoked thing", runs / 5, 2 * runs / 5);
}

/// P3, the plan's worked case: Alice makes X and Y (both independent), X has a strong to Y; Bob has
/// tickets for both, Carol for X only. Bob holds Y; Carol does not, and holds what she would
/// without the strong.
#[test]
fn p3_worked_case() {
    let w = world(&[K, K], &[]);
    let e = es(&[(0, 1)]);
    let bob = NodeView { roots: set(&[0]), tickets: tickets(&[0, 1], &[]) };
    let carol = NodeView { roots: set(&[0]), tickets: tickets(&[0], &[]) };
    assert!(closure(&w, &e, &bob, Walk::Units).held.contains(&1));
    let c = closure(&w, &e, &carol, Walk::Units);
    assert_eq!(c.held, set(&[0]));
    assert_eq!(c, closure(&w, &es(&[]), &carol, Walk::Units));
}

/// (a) Nested sharing: Y independent, X granted read on Y, X -> Y. Y and its dependent things are
/// in X's sync unit: every reader of X holds and reads them with no ticket for Y, a node keeping X
/// unread holds X alone (it reads none of X's strongs; Y's commits go under X's sync ID), and by sync a node reading X only gets Y's commits under X and syncs Y.
/// Without the grant only a holder of Y's ticket holds Y.
#[test]
fn p3_nested_sharing() {
    // X=0, Y=1 independent; B=2 dependent on Y; X -> Y -> B.
    let e = es(&[(0, 1), (1, 2)]);
    let reader = NodeView { roots: set(&[0]), tickets: tickets(&[0], &[]) };
    let store = NodeView { roots: set(&[0]), tickets: tickets(&[], &[0]) };
    let both = NodeView { roots: set(&[0]), tickets: tickets(&[0, 1], &[]) };
    let w = world(&[K, K, p(1)], &[(0, 1)]);
    assert_eq!(unit(&w, 0, &e), set(&[0, 1, 2]));
    let c = closure(&w, &e, &reader, Walk::Units);
    assert_eq!((c.held, c.read), (set(&[0, 1, 2]), set(&[0, 1])));
    let c = closure(&w, &e, &store, Walk::Units);
    // kept unread, X's strongs go unread: it holds X alone (spec/sync-set.md §2)
    assert_eq!((c.held, c.stored, c.read), (set(&[0]), set(&[0]), set(&[])));
    let ungranted = world(&[K, K, p(1)], &[]);
    assert_eq!(unit(&ungranted, 0, &e), set(&[0]));
    assert_eq!(closure(&ungranted, &e, &reader, Walk::Units).held, set(&[0]));
    assert_eq!(closure(&ungranted, &e, &store, Walk::Units).held, set(&[0]));
    assert_eq!(closure(&ungranted, &e, &both, Walk::Units).held, set(&[0, 1, 2]));
    for (w, gets) in [(w, true), (ungranted, false)] {
        let mut s = Sync::new(w, vec![set(&[0, 1]), set(&[0])], true);
        s.write(0, add(0, 1));
        let yb = s.write(0, add(1, 2));
        assert!(s.settle(5).is_some());
        assert_eq!(s.has[1].contains(&yb), gets);
        assert_eq!(s.syncs(1), if gets { set(&[0, 1]) } else { set(&[0]) });
    }
}

/// (b) Removing the strong X -> Y, or Z -> A for a dependent A in two sync units, takes the thing out of
/// the sync unit for every reader alike: each drops it once the removal reaches it, the delete-key
/// holder deletes its entries, and nothing logs them again. (Revoking the grant: see
/// `p2_revocation_reaches_grantee_only_node`.)
#[test]
fn p3_unlinking_takes_it_out_for_every_reader() {
    let read = Some(Role::Read);
    // (kinds, setup, the strong's commit index in setup, node 0's subs, node 1's and 2's, the
    // sync ID, the thing)
    let cases = [
        (vec![K, K, p(1)], vec![role(1, 0, read), add(0, 1), add(1, 2)], 1, set(&[0, 1]), set(&[0]), 0, 1),
        (vec![K, K, p(0), p(0)], vec![role(0, 1, read), add(1, 2), add(2, 3)], 1, set(&[0, 1]), set(&[1]), 1, 2),
    ];
    for (kinds, setup, strong, s0, s1, sid, gone) in cases {
        for fix in [false, true] {
            let mut s = Sync::new(world(&kinds, &[]), vec![s0.clone(), s1.clone(), s1.clone()], fix);
            s.delete_key[0].insert(sid);
            let ids: Vec<C> = setup.iter().map(|c| s.write(0, c.clone())).collect();
            assert!(s.settle(5).is_some());
            assert!(s.carried(2, sid).contains(&gone));
            s.write(1, Commit { from: sid, op: Op::Remove(BTreeSet::from([ids[strong]])), ephemeral: false });
            assert!(s.settle(5).is_some(), "fix={fix}");
            assert!(s.agrees());
            // What stays of it: its role record, the certificate of X's read on it.
            let of_it = |c: &C| s.commits[*c].from == gone && !matches!(s.commits[*c].op, Op::Role(..));
            assert!((1..3).all(|n| !s.carried(n, sid).contains(&gone) && !s.has[n].iter().any(of_it)), "fix={fix}");
            assert!(!s.store[&sid].iter().any(of_it));
        }
    }
}

/// (c) Grants chained through two actors: X opens Y through W by the lowest role along the
/// chain, the best chain counting (sync along it: a reader of X keeps Y unread); W is among X's
/// keys but in X's sync unit only by a strong.
#[test]
fn p3_grant_chains() {
    use Role::*;
    // X=0, W=1, Y=2 independent; X -> Y.
    let e = es(&[(0, 2)]);
    let reader = NodeView { roots: set(&[0]), tickets: tickets(&[0], &[]) };
    let cases: [(&[(T, T, Role)], bool); 7] = [
        (&[(0, 1, Read), (1, 2, Read)], true),
        (&[(0, 1, Write), (1, 2, Read)], true),
        (&[(0, 1, Admin), (1, 2, Admin)], true),
        (&[(0, 1, Sync), (1, 2, Admin)], false),
        (&[(0, 1, Read), (1, 2, Sync)], false),
        (&[(0, 2, Sync), (0, 1, Read), (1, 2, Write)], true),
        (&[(1, 2, Read)], false),
    ];
    for (g, opens) in cases {
        let w = worldr(&[K, K, K], g);
        assert_eq!(w.keys_of(0).contains(&2), opens, "{g:?}");
        assert_eq!(unit(&w, 0, &e), if opens { set(&[0, 2]) } else { set(&[0]) }, "{g:?}");
        let c = closure(&w, &e, &reader, Walk::Units);
        assert_eq!(c.read.contains(&2), opens, "{g:?}");
        // a role of sync alone gives Y's sync secret: kept unread
        assert_eq!(c.held.contains(&2), w.roles_from(0).contains_key(&2), "{g:?}");
        assert!(!unit(&w, 0, &e).contains(&1));
    }
}

/// Every small node world: independent 0, 1, dependent 2, 3 (keys from 0 or 1), grants of read, strongs
/// among a candidate set, node root strongs and tickets.
fn p3_worlds() -> Vec<(World, Edges, NodeView)> {
    let cand = [(0, 1), (0, 2), (2, 3), (3, 1), (1, 2)];
    let tk = [None, Some(Ticket::Open), Some(Ticket::SyncOnly)];
    let mut out = vec![];
    for kf in 0..4u32 {
        let kinds = vec![K, K, p((kf & 1) as T), p((kf >> 1 & 1) as T)];
        for g in subsets(&[(0, 1), (1, 0)]) {
            let w = world(&kinds, &g);
            for e in subsets(&cand) {
                for roots in subsets(&[0, 1, 2]) {
                    for t0 in tk {
                        for t1 in tk {
                            let tickets = [(0, t0), (1, t1)].into_iter().filter_map(|(k, t)| t.map(|t| (k, t))).collect();
                            out.push((w.clone(), es(&e), NodeView { roots: set(&roots), tickets }));
                        }
                    }
                }
            }
        }
    }
    out
}

/// P3: a node reads an independent thing only by keys it holds and stores one unread only inside a sync unit
/// it holds a sync-only ticket for; a strong into or out of an independent thing that it has neither a
/// ticket nor keys for, and that no sync unit it stores unread may hold, never changes what it holds.
#[test]
fn p3_strong_never_changes_what_no_ticket_holds_exhaustive() {
    for (w, e, n) in p3_worlds() {
        let ring = w.ring(&n.tickets.iter().filter(|t| *t.1 == Ticket::Open).map(|t| *t.0).collect());
        let c = closure(&w, &e, &n, Walk::Units);
        let stores: Set = n.tickets.iter().filter(|t| *t.1 == Ticket::SyncOnly).flat_map(|t| w.keys_of(*t.0)).collect();
        assert!(c.read.is_subset(&ring), "{w:?} {e:?} {n:?}");
        assert!(c.stored.is_subset(&stores), "{w:?} {e:?} {n:?}");
        for k in [0, 1].into_iter().filter(|k| !ring.contains(k) && !n.tickets.contains_key(k) && !stores.contains(k)) {
            for y in 0..4 {
                for edge in [(y, k), (k, y)] {
                    let mut e2 = e.clone();
                    if !e2.remove(&edge) {
                        e2.insert(edge);
                    }
                    assert_eq!(closure(&w, &e2, &n, Walk::Units).held, c.held, "{w:?} {e:?} {n:?} toggling {edge:?}");
                }
            }
        }
    }
}

/// P3: what a node's closure holds is carried under a sync ID it syncs (or is its local sync unit).
/// Walked sync unit by sync unit it is; walked by "the closure walks strongs", a dependent thing the sync unit's
/// keys cannot open but the node can leads to things no sync ID it syncs carries. Minimal: X, U
/// independent with open tickets, both node roots; X -> L -> M, L and M dependent on U; X holds no role on U.
#[test]
fn p3_held_is_carried_exhaustive() {
    let mut literal_fails = 0;
    for (w, e, n) in p3_worlds() {
        let c = closure(&w, &e, &n, Walk::Units);
        assert!(c.held.is_subset(&c.carried), "{w:?} {e:?} {n:?} {c:?}");
        let l = closure(&w, &e, &n, Walk::Literal);
        if !l.held.is_subset(&l.carried) {
            literal_fails += 1;
        }
    }
    assert!(literal_fails > 0);
    let w = world(&[K, K, p(1), p(1)], &[]);
    let e = es(&[(0, 2), (2, 3)]);
    let n = NodeView { roots: set(&[0, 1]), tickets: tickets(&[0, 1], &[]) };
    let l = closure(&w, &e, &n, Walk::Literal);
    assert!(l.held.contains(&3) && !l.carried.contains(&3));
    assert_eq!(closure(&w, &e, &n, Walk::Units).held, set(&[0, 1]));
}

/// P3, the making rule: the commit must leave the new thing in the node closure. X and U independent
/// with open tickets: a dependent thing from X under X is admitted; a dependent thing from U referenced
/// only by X is refused, though a held thing references it (X's keys do not open it); an independent
/// thing minted with admin X whose keys the maker holds is admitted, and other readers of X hold it only once
/// X is granted read on it.
#[test]
fn p3_making_rule() {
    // X=0, U=1, Q=4 independent; M=2 dependent on X, N=3 dependent on U.
    let w = world(&[K, K, p(0), p(1), K], &[]);
    let maker = NodeView { roots: set(&[0]), tickets: tickets(&[0, 1, 4], &[]) };
    let other = NodeView { roots: set(&[0]), tickets: tickets(&[0], &[]) };
    assert!(may_make(&w, &es(&[(0, 2)]), &maker, 2));
    assert!(!may_make(&w, &es(&[(0, 3)]), &maker, 3));
    assert!(may_make(&w, &es(&[(0, 4)]), &maker, 4));
    assert!(!may_make(&w, &es(&[(0, 4)]), &other, 4));
    assert!(may_make(&world(&[K, K, p(0), p(1), K], &[(0, 4)]), &es(&[(0, 4)]), &other, 4));
}

// ---- Release ----

#[derive(Clone, Copy, Debug)]
enum Ev {
    Create(usize),
    Add(usize),
    Remove(usize),
    Pass(usize, bool),
}

/// P4, stated behaviour: a strong to a thing the node never got holds nothing. Over every history
/// of up to 4 events (2 nodes, one thing, root strongs) a strong reads as not held once everyone
/// has synced only in this shape: node 0 makes X, node 1 writes a strong to X (it knows the tid),
/// node 0 removes its strong and, with no peer connected, drops X at once (it never waits for an
/// absent peer); node 1 never got X. Or the strong is written after the drop. None of 3 events.
#[test]
fn p4_strong_to_never_fetched_holds_nothing() {
    fn apply(net: &mut Net, ev: Ev) -> bool {
        let x = 2;
        match ev {
            Ev::Create(n) => net.things == 2 && net.create(n, n) == x,
            Ev::Add(n) => {
                if net.things != 3 {
                    return false;
                }
                net.add(n, n, x, false);
                true
            }
            Ev::Remove(n) => net.things == 3 && net.remove(n, n, x).is_some(),
            Ev::Pass(n, with) => {
                let peers: Vec<usize> = if with { vec![1 - n] } else { vec![] };
                net.pass(n, &peers);
                true
            }
        }
    }
    let evs: Vec<Ev> = (0..2).flat_map(|n| [Ev::Create(n), Ev::Add(n), Ev::Remove(n), Ev::Pass(n, false), Ev::Pass(n, true)]).collect();
    let mut dangles: Vec<Vec<String>> = vec![vec![]; 5];
    let mut frontier = vec![(Net::new(2), vec![])];
    for len in 1..=4 {
        let mut next = vec![];
        for (net, h) in &frontier {
            for &ev in &evs {
                let mut n2 = net.clone();
                if !apply(&mut n2, ev) {
                    continue;
                }
                let mut h2: Vec<Ev> = h.clone();
                h2.push(ev);
                let mut q = n2.clone();
                q.quiesce();
                if !q.dangling().is_empty() {
                    dangles[len].push(format!("{h2:?}"));
                }
                next.push((n2, h2));
            }
        }
        frontier = next;
    }
    assert!(dangles[..4].iter().all(|l| l.is_empty()), "{dangles:?}");
    // Two shapes. A strong written after the drop, to a tid known before: a strong to a deleted
    // thing, by the plan's principle. The race: the strong written before the drop, by a node not
    // connected for the dropper's pass (a strong in a node root never leaves its node).
    let race: Vec<&String> = dangles[4].iter().filter(|h| h.starts_with("[Create(0)") && h.find("Add").unwrap() < h.find("Pass").unwrap()).collect();
    assert_eq!(race, ["[Create(0), Remove(0), Add(1), Pass(0, false)]", "[Create(0), Add(1), Remove(0), Pass(0, false)]"]);
    assert!(dangles[4].iter().all(|h| h.find("Add").unwrap() < h.find("Pass").unwrap() || h.ends_with("Add(0)]") || h.ends_with("Add(1)]")));
}

/// P4 (c): the last holder dropping a thing nothing references is the intended outcome.
#[test]
fn p4_last_reference_gone_is_released() {
    let mut net = Net::new(2);
    let x = net.create(0, 0);
    net.pass(1, &[0]);
    net.remove(0, 0, x);
    assert_eq!(net.pass(0, &[1]), set(&[x]));
    net.quiesce();
    assert!(net.nodes.iter().all(|s| s.held.is_empty()) && net.dangling().is_empty());
}

/// P4 (b): a removal reaching a holder before a concurrent re-add makes it drop the thing when
/// no adder is connected, and fetch it again later from the adder, which holds it.
#[test]
fn p4_concurrent_readd_refetched_from_adder() {
    let mut net = Net::new(2);
    let a = net.create(0, 0);
    net.add(1, 1, a, false);
    net.pass(1, &[0]);
    let x = net.create(0, a);
    net.pass(1, &[0]);
    assert!(net.nodes[1].held.contains(&x));
    net.remove(1, a, x); // removes node 0's add
    net.add(0, a, x, false); // concurrent re-add
    assert_eq!(net.pass(1, &[]), set(&[x]), "dropped with nobody connected");
    assert!(net.nodes[0].held.contains(&x));
    net.pass(1, &[0]);
    assert!(net.nodes[1].held.contains(&x), "fetched again from the adder");
    net.quiesce();
    assert!(net.dangling().is_empty());
}

/// A random release history over 3 nodes: makes, strongs from what a node holds to any thing,
/// removes, passes with any peers, and (P6) ephemeral strongs and restarts. Checks at every pass:
/// (a) a node drops only what its own held strongs no longer reach; (d) after the pass every
/// connected peer holds whatever of `n`'s held things its closure reaches. Returns (things dropped
/// and later held again, strongs reading as not held at the end).
fn release_run(r: &mut Rng, ephemeral: bool) -> (usize, usize) {
    let mut net = Net::new(3);
    let mut dropped: Vec<Set> = vec![Set::new(); 3];
    let mut churn = 0;
    for _ in 0..20 {
        let n = r.below(3) as usize;
        let mut froms: Vec<T> = vec![n];
        froms.extend(net.nodes[n].held.iter().copied());
        let shared: Vec<T> = net.shared().collect();
        match r.below(10) {
            0 | 1 if net.things < 8 => {
                net.create(n, r.pick(&froms));
            }
            2..=4 if !shared.is_empty() => {
                let eph = ephemeral && r.chance(50);
                net.add(n, r.pick(&froms), r.pick(&shared), eph);
            }
            5 | 6 if !shared.is_empty() => {
                net.remove(n, r.pick(&froms), r.pick(&shared));
            }
            7 if ephemeral => net.restart(n),
            _ => {
                let peers: Vec<usize> = (0..3).filter(|&q| q != n && r.chance(50)).collect();
                let before = net.nodes[n].held.clone();
                let d = net.pass(n, &peers);
                let reach = net.closure(n);
                assert!(d.iter().all(|x| before.contains(x) && !reach.contains(x)), "(a)");
                for &q in &peers {
                    let wants = net.closure(q);
                    assert!(before.iter().all(|x| !wants.contains(x) || net.nodes[q].held.contains(x)), "(d)");
                }
                dropped[n].extend(d);
            }
        }
        for q in 0..3 {
            let back: Vec<T> = dropped[q].intersection(&net.nodes[q].held).copied().collect();
            churn += back.len();
            for x in back {
                dropped[q].remove(&x);
            }
        }
    }
    net.quiesce();
    (churn, net.dangling().len())
}

/// P4: (a) and (d) hold in every random history; the drops later undone and the dangling strongs it meets
/// are counted (all are of the two shapes above: no adder connected at the drop).
#[test]
fn p4_release_random() {
    let mut r = Rng::new(0);
    let (mut churn, mut dangling) = (0, 0);
    for _ in 0..1500 {
        let (c, l) = release_run(&mut r, false);
        churn += c;
        dangling += l;
    }
    eprintln!("p4: {churn} drops fetched again, {dangling} strongs read as not held, over 1500 runs");
}

/// P6: with ephemeral strongs and restarts, (a) and (d) read the same.
#[test]
fn p6_ephemeral_release_random() {
    let mut r = Rng::new(0);
    let (mut churn, mut dangling) = (0, 0);
    for _ in 0..1500 {
        let (c, l) = release_run(&mut r, true);
        churn += c;
        dangling += l;
    }
    eprintln!("p6: {churn} drops fetched again, {dangling} strongs read as not held, over 1500 runs");
}

/// P6: a thing held only by an ephemeral strong survives a restart while a connected peer still
/// holds the value; with none connected it is dropped and fetched back once the peer is met. Once
/// every holder of the value has restarted it is released everywhere, and no strong dangles.
#[test]
fn p6_restart_drops_only_without_a_peer() {
    for (with_peer, both) in [(true, false), (false, false), (false, true)] {
        let mut net = Net::new(2);
        let a = net.create(0, 0);
        net.add(1, 1, a, false);
        net.pass(1, &[0]);
        let x = net.create(0, a);
        net.add(0, a, x, true); // the ephemeral strong
        let c = net.visible(0, a, x).into_iter().find(|&c| !net.commits[c].ephemeral).unwrap();
        net.remove_adds(0, a, BTreeSet::from([c]));
        net.pass(1, &[0]);
        assert!(net.nodes[1].held.contains(&x));
        net.restart(0);
        if both {
            net.restart(1);
        }
        let d = net.pass(0, if with_peer { &[1][..] } else { &[] });
        assert_eq!(d.contains(&x), !with_peer);
        net.quiesce();
        assert!(net.dangling().is_empty());
        assert_eq!(net.nodes.iter().any(|s| s.held.contains(&x)), !both);
    }
}

fn cost(t: &mut Tree, f: impl FnOnce(&mut Tree)) -> u64 {
    let w = t.work;
    f(t);
    t.work - w
}

/// The P5 shapes at size `n`, each a fresh tree; returns the work of the one edit measured.
/// - fan-in: root -> r_i -> P for n referrers; remove a non-tree referrer, then P's tree edge.
/// - below: P's other referrers are its own children (P -> c_i -> P) and one outside b; remove
///   P's tree edge.
/// - alt: root -> a -> v, root -> b -> v, v -> n leaves; remove a -> v.
/// - deep: root -> a -> v, root -> c_1 -> ... -> c_n -> v; remove a -> v.
/// - release: root -> v -> n leaves; remove root -> v.
/// - add: the release shape's root -> v added last.
fn p5_counts(n: T, anc: bool) -> [u64; 7] {
    let mut t = Tree::new(false, anc);
    for i in 1..=n {
        t.add(0, i);
        t.add(i, n + 1);
    }
    let fan_nontree = cost(&mut t, |t| t.remove(n, n + 1));
    let fan_tree = cost(&mut t, |t| t.remove(1, n + 1));
    assert_eq!(t.held, t.reach());

    // P = 1, a = 2, children 3..n+3, b = n+3 (scanned last).
    let mut t = Tree::new(false, anc);
    t.add(0, 2);
    t.add(2, 1);
    for c in 3..n + 3 {
        t.add(1, c);
        t.add(c, 1);
    }
    t.add(0, n + 3);
    t.add(n + 3, 1);
    let below = cost(&mut t, |t| t.remove(2, 1));
    assert_eq!(t.held, t.reach());

    let mut t = Tree::new(false, anc);
    t.add(0, 1);
    t.add(1, 3);
    t.add(0, 2);
    t.add(2, 3);
    for l in 4..n + 4 {
        t.add(3, l);
    }
    let alt = cost(&mut t, |t| t.remove(1, 3));
    assert_eq!(t.held, t.reach());

    let mut t = Tree::new(false, anc);
    t.add(0, 1);
    t.add(1, 2);
    t.add(0, 3);
    for c in 3..n + 2 {
        t.add(c, c + 1);
    }
    t.add(n + 2, 2);
    let deep = cost(&mut t, |t| t.remove(1, 2));
    assert_eq!(t.held, t.reach());

    let mut t = Tree::new(false, anc);
    for l in 2..n + 2 {
        t.add(1, l);
    }
    let add = cost(&mut t, |t| t.add(0, 1));
    let add_held = cost(&mut t, |t| t.add(0, 2));
    let release = cost(&mut t, |t| t.remove(0, 1));
    assert_eq!(t.held, t.reach());
    [fan_nontree, fan_tree, below, alt, deep, release, add + 0 * add_held]
}

/// P5: work (edges examined and tree steps) at n and 10n. Removing a non-tree referrer and the
/// tree edge of a popular target with referrers outside costs the same at both sizes, as does a
/// tree edge with a shallow alternative when the target's other referrers are tried first
/// (`ancestor_step`); a released or newly reached subtree costs its size. Grows with the wrong
/// thing: a tree edge whose target's other referrers sit below it (fan-in), and an alternative
/// path found by walking a deep parent chain (depth).
#[test]
fn p5_work_counts() {
    let names = ["fan-in non-tree", "fan-in tree edge", "referrers below", "alt path", "deep alt", "release", "add subtree"];
    for anc in [true, false] {
        let (a, b) = (p5_counts(50, anc), p5_counts(500, anc));
        eprintln!("p5 ancestor_step={anc}: {}", names.iter().zip(a.iter().zip(&b)).map(|(n, (x, y))| format!("{n} {x}/{y}")).collect::<Vec<_>>().join(", "));
        assert_eq!(a[0], b[0]);
        assert_eq!(a[1], b[1]);
        assert!(b[2] >= 9 * a[2], "referrers below grows with fan-in");
        assert!(b[5] >= 9 * a[5] && b[5] <= 11 * a[5], "release is its size");
        assert!(b[6] >= 9 * a[6] && b[6] <= 11 * a[6], "add is the subtree");
        if anc {
            assert_eq!(a[3], b[3], "alt path with the ancestor step");
            assert!(b[4] >= 9 * a[4], "deep alt grows with depth");
        } else {
            assert!(b[3] >= 9 * a[3], "alt path without it marks the subtree");
        }
    }
}

// ---- Removing a strong ----

/// P5: the spanning tree with re-anchoring agrees with from-scratch reachability after every edit
/// of random edit sequences with cycles and self-strongs (a cycle no root reaches goes whole).
#[test]
fn p5_tree_matches_reach_random() {
    let mut r = Rng::new(0);
    for i in 0..400 {
        let mut t = Tree::new(false, i % 2 == 0);
        for _ in 0..80 {
            let (u, v) = (r.below(7) as T, 1 + r.below(6) as T);
            if r.chance(55) {
                t.add(u, v);
            } else {
                t.remove(u, v);
            }
            assert_eq!(t.held, t.reach());
            assert!(t.consistent());
        }
    }
}

/// P5 needs the re-attach step: without it (`naive`, "drop the subtree if no referrer is outside"),
/// root -> v -> d and root -> d with d first reached through v, removing root -> v drops d, which
/// root still reaches.
#[test]
fn p5_subtree_drop_needs_reattaching() {
    for naive in [true, false] {
        let mut t = Tree::new(naive, true);
        t.add(0, 1);
        t.add(1, 2);
        t.add(0, 2);
        t.remove(0, 1);
        assert_eq!(t.held.contains(&2), !naive);
        assert_eq!(t.held == t.reach(), !naive);
    }
}


// spec/sync-set.md §2; taking up: Interim (issues/tickets-retired.md): an account takes a grant
// naming it only at a strong to its thing, so its role on T1 by a chain through T0 counts only
// once T0 is reached. Account 0, T0 = 1, T1 = 2 independent: 0 holds sync on T0, T0 sync on T1.
#[test]
fn an_accounts_role_through_an_unreached_thing_counts_nothing() {
    use Role::*;
    let w = worldr(&[K, K, K], &[(0, 1, Sync), (1, 2, Sync)]);
    assert!(w.roles_from_reached(0, &set(&[2])).get(&2).is_none(), "T0 unreached: no role on T1");
    assert_eq!(w.roles_from_reached(0, &set(&[1])).get(&2), Some(&Sync), "T0 reached: sync on T1 through it");
    assert_eq!(w.roles_from(0).get(&2), Some(&Sync), "a thing's chains are not restricted");
}
