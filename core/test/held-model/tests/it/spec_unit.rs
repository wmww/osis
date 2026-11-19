//! The sync unit as one independent thing and its dependents, held_model::unit: each test names
//! the property of notes/closure-model.md (The unit model) it checks. Where the design's rule fails
//! a property the test asserts the smallest world, so the finding stays visible and checked.
use held_model::closure::{Kind, Role, Set, C, T};
use held_model::gen::Rng;
use held_model::unit::*;
use std::collections::BTreeSet;

const K: Kind = Kind::Independent;
fn d(a: T) -> Kind {
    Kind::Dependent(a)
}
fn set(xs: &[T]) -> Set {
    xs.iter().copied().collect()
}
fn add(on: T, to: T) -> Commit {
    Commit { on, op: Op::Add(to) }
}
fn role(on: T, holder: T, r: Option<Role>) -> Commit {
    Commit { on, op: Op::Role(holder, r) }
}
fn rm(on: T, adds: &[C]) -> Commit {
    Commit { on, op: Op::Remove(adds.iter().copied().collect()) }
}
fn subsets<X: Copy>(of: &[X]) -> Vec<Vec<X>> {
    (0..1u32 << of.len()).map(|m| of.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, x)| *x).collect()).collect()
}
/// A static world: one role commit per grant `(holder, target, role)`, one add per strong.
fn world(grants: &[(T, T, Role)], strongs: &[(T, T)]) -> Vec<Commit> {
    grants.iter().map(|&(g, t, r)| role(t, g, Some(r))).chain(strongs.iter().map(|&(x, y)| add(x, y))).collect()
}
const ALL: [Rules; 6] = [
    Rules { member: Member::Role, secrets: Secrets::Holder },
    Rules { member: Member::Role, secrets: Secrets::Chain },
    Rules { member: Member::Role, secrets: Secrets::Steps },
    Rules { member: Member::Any, secrets: Secrets::Holder },
    Rules { member: Member::Any, secrets: Secrets::Chain },
    Rules { member: Member::Any, secrets: Secrets::Steps },
];
fn rule_index(r: Rules) -> usize {
    ALL.iter().position(|&x| x == r).unwrap()
}

/// What a reader of `g` that also reads the units `extra` computes as S(g)'s member blobs: from
/// the commits carried under the units it holds. `transitive` is the negative control: targets
/// reached from `g` through every strong it holds, crossing units.
fn members_seen(kinds: &[Kind], cs: &[Commit], g: T, extra: &Set, r: Rules, transitive: bool) -> Set {
    let t = View::all(kinds, cs);
    let mut units = extra.clone();
    units.insert(g);
    let known: BTreeSet<C> = (0..cs.len()).filter(|&c| !t.under(&cs[c], r.secrets).is_disjoint(&units)).collect();
    let v = View::of(kinds, cs, &known);
    if !transitive {
        return v.members(g, r.member);
    }
    let mut seen = v.unit(g);
    let mut todo: Vec<T> = seen.iter().copied().collect();
    while let Some(x) = todo.pop() {
        for &(a, b) in &v.strongs {
            if a == x && seen.insert(b) {
                todo.push(b);
            }
        }
    }
    seen.into_iter().map(|x| v.ind(x)).filter(|&h| h != g).collect()
}

/// P1 for one world: every reader of each unit G, whatever other units it reads, computes the
/// same member blobs. The first disagreement.
fn p1_world(kinds: &[Kind], cs: &[Commit], r: Rules, transitive: bool) -> Option<String> {
    let t = View::all(kinds, cs);
    let ind: Vec<T> = t.independents().into_iter().collect();
    for &g in &ind {
        let others: Vec<T> = ind.iter().copied().filter(|&x| x != g).collect();
        let mut first: Option<Set> = None;
        for x in subsets(&others) {
            let m = members_seen(kinds, cs, g, &x.iter().copied().collect(), r, transitive);
            match &first {
                None => first = Some(m),
                Some(f) if *f != m => return Some(format!("S({g}): reading only it {f:?}, also reading {x:?} {m:?}")),
                _ => {}
            }
        }
    }
    None
}

/// P2 for one world: a node keeping 0 unread keeps exactly the units a reader of 0 enters (read or
/// kept unread); P2b: that reader reads exactly the units of its closure 0 holds read on.
fn p2_world(kinds: &[Kind], cs: &[Commit], r: Rules, keep: Keep) -> (bool, bool) {
    let t = View::all(kinds, cs);
    let listed = |g| t.members(g, r.member);
    let e = reader(&t, 0, r, &listed);
    let k = keeper(&t, &set(&[0]), keep, &listed);
    let roles = t.roles_from(0);
    let entitled: Set = e.units().into_iter().filter(|h| roles.get(h).is_some_and(|&x| x >= Role::Read)).collect();
    (k == e.units(), e.read == entitled)
}

/// The small family: independent 0, 1, 2; 3 a dependent of 1, 4 of 2; every grant among 0, 1, 2
/// of none, sync or read; every set of strongs among `CAND`.
const KINDS: [Kind; 5] = [K, K, K, Kind::Dependent(1), Kind::Dependent(2)];
const CAND: [(T, T); 7] = [(0, 1), (0, 3), (1, 2), (3, 4), (1, 4), (2, 0), (3, 2)];
const PAIRS: [(T, T); 6] = [(0, 1), (0, 2), (1, 0), (1, 2), (2, 0), (2, 1)];
fn family(i: usize) -> Vec<Commit> {
    let (mut gi, si) = (i / (1 << CAND.len()), i % (1 << CAND.len()));
    let mut grants = vec![];
    for &(a, b) in &PAIRS {
        match gi % 3 {
            1 => grants.push((a, b, Role::Sync)),
            2 => grants.push((a, b, Role::Read)),
            _ => {}
        }
        gi /= 3;
    }
    let strongs: Vec<(T, T)> = CAND.iter().enumerate().filter(|(j, _)| si & (1 << j) != 0).map(|(_, &e)| e).collect();
    world(&grants, &strongs)
}
const FAMILY: usize = 729 << 7;

/// Runs `f` on every world of the family, a thread per core, summing its counts.
fn over_family<const N: usize>(f: impl Fn(&[Commit]) -> [usize; N] + Sync) -> [usize; N] {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        let hs: Vec<_> = (0..threads)
            .map(|k| {
                let f = &f;
                sc.spawn(move || {
                    let mut acc = [0; N];
                    for i in (k..FAMILY).step_by(threads) {
                        for (a, x) in acc.iter_mut().zip(f(&family(i))) {
                            *a += x;
                        }
                    }
                    acc
                })
            })
            .collect();
        hs.into_iter().fold([0; N], |mut acc, h| {
            for (a, x) in acc.iter_mut().zip(h.join().unwrap()) {
                *a += x;
            }
            acc
        })
    })
}

/// P1 over the small family (93312 worlds), per rule, and its negative control.
#[test]
fn p1_readers_compute_one_member_list_exhaustive() {
    let fails = over_family(|cs| {
        let mut out = [0; 7];
        for (i, &r) in ALL.iter().enumerate() {
            out[i] = p1_world(&KINDS, cs, r, false).is_some() as usize;
        }
        out[6] = p1_world(&KINDS, cs, Rules { member: Member::Any, secrets: Secrets::Holder }, true).is_some() as usize;
        out
    });
    // The design's member list depends on grants of a chain that S(G) does not carry: Hole 1.
    assert!(fails[rule_index(Rules::DESIGN)] > 0, "{fails:?}");
    // Today's chain rule carries a chain's grants only where read reaches: a sync link still fails.
    assert!(fails[rule_index(Rules { member: Member::Role, secrets: Secrets::Chain })] > 0, "{fails:?}");
    for s in [Secrets::Holder, Secrets::Chain, Secrets::Steps] {
        assert_eq!(fails[rule_index(Rules { member: Member::Any, secrets: s })], 0, "{fails:?}");
    }
    assert!(fails[6] > 0, "negative control (members by the reader's own walk across units) must fail: {fails:?}");
    eprintln!("p1 failing worlds of {FAMILY} per rule {ALL:?} + control: {fails:?}");
}

/// Hole 1, smallest world: 0 holds sync on 1, 1 holds sync on 2, 0 -> 2. S(0)'s readers that do
/// not read 1 lack 1's grant on 2 (it travels under S(1) and S(2)), so they list nothing; those
/// reading 1 list 2. A writer of each kind visiting S(0)'s store undo each other for good.
#[test]
fn p1_member_list_by_a_chain_of_roles_splits_readers() {
    let kinds = [K, K, K];
    let cs = world(&[(0, 1, Role::Sync), (1, 2, Role::Sync)], &[(0, 2)]);
    for r in [Rules::DESIGN, Rules { member: Member::Role, secrets: Secrets::Chain }] {
        assert_eq!(members_seen(&kinds, &cs, 0, &set(&[]), r, false), set(&[]));
        assert_eq!(members_seen(&kinds, &cs, 0, &set(&[1]), r, false), set(&[2]));
    }
    // With read on 1, today's chain rule carries 1's grant under S(0) too.
    let read = world(&[(0, 1, Role::Read), (1, 2, Role::Sync)], &[(0, 2)]);
    assert!(p1_world(&kinds, &read, Rules { member: Member::Role, secrets: Secrets::Chain }, false).is_none());
    assert!(p1_world(&kinds, &read, Rules::DESIGN, false).is_some());
    assert!(p1_world(&kinds, &cs, Rules { member: Member::Any, secrets: Secrets::Holder }, false).is_none());
    // Over time: writer 0 syncs 0 and 1, writer 1 syncs 0 alone.
    for (member, settles) in [(Member::Role, false), (Member::Any, true)] {
        let mut net = Net::new(kinds.to_vec(), Rules { member, secrets: Secrets::Holder }, vec![set(&[0, 1]), set(&[0])], vec![]);
        for c in cs.clone() {
            net.write(c);
        }
        net.deliver_all();
        assert_eq!(net.settle(20, false).is_some(), settles, "{member:?}");
    }
}

/// P1 over random worlds: 4 independent and 4 dependent things (dependents of dependents too),
/// random grants and strongs.
#[test]
fn p1_readers_compute_one_member_list_random() {
    let mut r = Rng::new(0);
    let mut fails = [0; 6];
    let n = 600;
    for _ in 0..n {
        let (kinds, cs) = random_static(&mut r);
        for (i, &rules) in ALL.iter().enumerate() {
            fails[i] += p1_world(&kinds, &cs, rules, false).is_some() as usize;
        }
    }
    assert!(fails[rule_index(Rules::DESIGN)] > 0, "{fails:?}");
    for s in [Secrets::Holder, Secrets::Chain, Secrets::Steps] {
        assert_eq!(fails[rule_index(Rules { member: Member::Any, secrets: s })], 0, "{fails:?}");
    }
    eprintln!("p1 random failing of {n} per rule: {fails:?}");
}

fn random_static(r: &mut Rng) -> (Vec<Kind>, Vec<Commit>) {
    let mut kinds = vec![K, K, K, K];
    for i in 4..8 {
        kinds.push(d(r.below(i as u64) as T));
    }
    let mut grants = vec![];
    for a in 0..4 {
        for b in 0..4 {
            if a != b && r.chance(30) {
                grants.push((a, b, if r.chance(50) { Role::Sync } else { Role::Read }));
            }
        }
    }
    let strongs: Vec<(T, T)> = (0..r.below(8) + 2).map(|_| (r.below(8) as T, r.below(8) as T)).collect();
    (kinds, world(&grants, &strongs))
}

/// P2 over the small family, per rule: a node keeping 0 unread keeps exactly the units a reader
/// of 0 enters (P2), and that reader reads every unit of its closure 0 holds read on (P2b). The
/// negative controls on the rules that pass: the walk stopping at a unit kept unread (today's
/// keeper), and keeping every listed unit without a credential.
#[test]
fn p2_keeper_reaches_what_a_reader_needs_exhaustive() {
    let fails = over_family(|cs| {
        let mut out = [0; 16];
        for (i, &r) in ALL.iter().enumerate() {
            let (a, b) = p2_world(&KINDS, cs, r, Keep::Reach);
            out[2 * i] = !a as usize;
            out[2 * i + 1] = !b as usize;
        }
        let fixed = Rules { member: Member::Any, secrets: Secrets::Steps };
        out[12] = !p2_world(&KINDS, cs, fixed, Keep::Stop).0 as usize;
        out[13] = !p2_world(&KINDS, cs, fixed, Keep::Listed).0 as usize;
        out
    });
    let at = |r: Rules| (fails[2 * rule_index(r)], fails[2 * rule_index(r) + 1]);
    let (p2, p2b) = at(Rules::DESIGN);
    assert!(p2 > 0 && p2b > 0, "the design fails both (Holes 2 and 3): {fails:?}");
    assert!(at(Rules { member: Member::Role, secrets: Secrets::Steps }).0 > 0, "{fails:?}");
    assert!(at(Rules { member: Member::Any, secrets: Secrets::Holder }).1 > 0, "{fails:?}");
    for s in [Secrets::Chain, Secrets::Steps] {
        assert_eq!(at(Rules { member: Member::Any, secrets: s }), (0, 0), "{fails:?}");
    }
    assert!(fails[12] > 0 && fails[13] > 0, "negative controls must fail: {fails:?}");
    eprintln!("p2 failing worlds of {FAMILY} (P2, P2b) per rule {ALL:?}, then Stop, Listed: {fails:?}");
}

/// P2 over random worlds.
#[test]
fn p2_keeper_reaches_what_a_reader_needs_random() {
    let mut r = Rng::new(0);
    let mut fails = [0; 12];
    let n = 600;
    for _ in 0..n {
        let (kinds, cs) = random_static(&mut r);
        for (i, &rules) in ALL.iter().enumerate() {
            let (a, b) = p2_world(&kinds, &cs, rules, Keep::Reach);
            fails[2 * i] += !a as usize;
            fails[2 * i + 1] += !b as usize;
        }
    }
    for s in [Secrets::Chain, Secrets::Steps] {
        let i = rule_index(Rules { member: Member::Any, secrets: s });
        assert_eq!((fails[2 * i], fails[2 * i + 1]), (0, 0), "{fails:?}");
    }
    eprintln!("p2 random failing of {n} (P2, P2b) per rule: {fails:?}");
}

/// Hole 2, smallest world: 0 reads 1 and 2; 0 -> 1 -> 2; 1 holds no role on 2. A reader of 0
/// enters 1, then 2 by its own secret. S(1) lists nothing (1 cannot enter 2) and S(0) lists 1
/// only, so a node keeping 0 unread keeps {0, 1}: a fresh reader it serves never gets 2.
#[test]
fn p2_keeper_misses_a_unit_reached_through_one_without_a_role() {
    let kinds = [K, K, K];
    let cs = world(&[(0, 1, Role::Read), (0, 2, Role::Read)], &[(0, 1), (1, 2)]);
    let t = View::all(&kinds, &cs);
    let design = |g| t.members(g, Member::Role);
    assert_eq!(reader(&t, 0, Rules::DESIGN, &design).units(), set(&[0, 1, 2]));
    assert_eq!(keeper(&t, &set(&[0]), Keep::Reach, &design), set(&[0, 1]));
    let any = |g| t.members(g, Member::Any);
    assert_eq!(keeper(&t, &set(&[0]), Keep::Reach, &any), set(&[0, 1, 2]));
    // spec/requirements.md Data model's second clause still holds: 1 alone keeps no 2.
    assert_eq!(keeper(&t, &set(&[1]), Keep::Reach, &any), set(&[1]));
}

/// Hole 3, smallest world: 0 reads 1, 1 reads 2, 0 -> 2. A reader of 0 holds 1's read secret but
/// not S(1), so not 2's box to 1: it keeps 2 unread (the steps give the sync secret), though 0
/// holds read on 2. Today's chain rule or read secrets in steps read it.
#[test]
fn p2_reader_by_a_chain_reads_nothing_through_an_unheld_holder() {
    let kinds = [K, K, K];
    let cs = world(&[(0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2)]);
    let t = View::all(&kinds, &cs);
    let l = |g| t.members(g, Member::Any);
    let rd = |s| reader(&t, 0, Rules { member: Member::Any, secrets: s }, &l);
    assert_eq!(rd(Secrets::Holder), Entered { read: set(&[0]), unread: set(&[2]) });
    assert_eq!(rd(Secrets::Chain), Entered { read: set(&[0, 2]), unread: set(&[]) });
    assert_eq!(rd(Secrets::Steps), Entered { read: set(&[0, 2]), unread: set(&[]) });
    // Holding 1 for another reason (a strong) reads 2: the closure of 0 depends on other strongs.
    let cs2 = world(&[(0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2), (0, 1)]);
    let t2 = View::all(&kinds, &cs2);
    assert_eq!(reader(&t2, 0, Rules { member: Member::Any, secrets: Secrets::Holder }, &|g| t2.members(g, Member::Any)).read, set(&[0, 1, 2]));
}

/// A strong to a dependent thing brings its independent's unit (Tess): 0 -> 3, 3 a dependent of 1.
#[test]
fn p2_strong_to_a_dependent_brings_its_unit() {
    let kinds = [K, K, d(1)];
    let cs = world(&[(0, 1, Role::Sync)], &[(0, 2)]);
    let t = View::all(&kinds, &cs);
    assert_eq!(t.members(0, Member::Role), set(&[1]));
    assert_eq!(keeper(&t, &set(&[0]), Keep::Reach, &|g| t.members(g, Member::Role)), set(&[0, 1]));
}

// ---- Over time ----

/// P3: release by reachability, cycles included. 0 lists 1, 1 and 2 list each other; removing
/// 0 -> 1 releases 1 and 2 at the keeper. The negative control (a unit kept while a kept unit
/// lists it) keeps the cycle for good.
#[test]
fn p3_detached_cycle_is_released() {
    for count in [false, true] {
        let mut net = Net::new(vec![K, K, K], Rules::DESIGN, vec![set(&[0, 1, 2])], vec![set(&[0])]);
        for c in [role(1, 0, Some(Role::Sync)), role(2, 1, Some(Role::Sync)), role(1, 2, Some(Role::Sync)), add(0, 1), add(1, 2), add(2, 1)] {
            net.write(c);
        }
        net.deliver_all();
        net.settle(20, count).unwrap();
        assert_eq!(net.kept[0], set(&[0, 1, 2]));
        net.write(rm(0, &[3]));
        net.deliver_all();
        net.settle(20, count).unwrap();
        assert_eq!(net.kept[0] == set(&[0]), !count, "count {count}");
        assert_eq!(net.wrong().is_empty(), !count);
    }
}

/// One scenario: commits every node holds first, then `moves` reaching two writers (syncing
/// every unit) in every order and interleaving, both visiting S's stores together after each and
/// the keeper of 0 passing; then everything delivered and settled. The schedules whose end state
/// is wrong, of how many.
fn every_order(kinds: &[Kind], genesis: &[Commit], moves: &[Commit], lowest_wins: bool) -> (usize, usize) {
    let perms = permutations(moves.len());
    let (mut bad, mut n) = (0, 0);
    let ilv = interleavings(moves.len(), moves.len());
    for pa in &perms {
        for pb in &perms {
            for il in &ilv {
                let all: BTreeSet<T> = kinds.iter().enumerate().filter(|(_, k)| **k == K).map(|(i, _)| i).collect();
                let mut net = Net::new(kinds.to_vec(), Rules::DESIGN, vec![all.clone(), all], vec![set(&[0])]);
                net.lowest_wins = lowest_wins;
                for c in genesis {
                    let c = net.write(c.clone());
                    net.deliver(0, c);
                    net.deliver(1, c);
                }
                let base = net.commits.len();
                for c in moves {
                    net.write(c.clone());
                }
                net.visit_together();
                net.pass(0, false);
                let (mut ia, mut ib) = (0, 0);
                for &who in il {
                    let c = if who == 0 {
                        ia += 1;
                        pa[ia - 1]
                    } else {
                        ib += 1;
                        pb[ib - 1]
                    };
                    net.deliver(who, base + c);
                    net.visit_together();
                    net.pass(0, false);
                }
                net.deliver_all();
                net.settle(20, false);
                n += 1;
                bad += !net.wrong().is_empty() as usize;
            }
        }
    }
    (bad, n)
}
fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![vec![]];
    }
    let mut out = vec![];
    for p in permutations(n - 1) {
        for i in 0..=p.len() {
            let mut q = p.clone();
            q.insert(i, n - 1);
            out.push(q);
        }
    }
    out
}
fn interleavings(a: usize, b: usize) -> Vec<Vec<usize>> {
    match (a, b) {
        (0, 0) => vec![vec![]],
        _ => {
            let mut out = vec![];
            if a > 0 {
                out.extend(interleavings(a - 1, b).into_iter().map(|mut v| {
                    v.insert(0, 0);
                    v
                }));
            }
            if b > 0 {
                out.extend(interleavings(a, b - 1).into_iter().map(|mut v| {
                    v.insert(0, 1);
                    v
                }));
            }
            out
        }
    }
}

/// P4: attach and detach in every arrival order converge (720 schedules a scenario): attach,
/// attach through a dependent, detach; a grant after the strong, its removal, a second add;
/// a cycle attached and its entry detached. The negative control (no lower-ID rule) leaves two
/// blobs for one member where both writers logged it at once.
#[test]
fn p4_attach_detach_every_order_converges() {
    let kinds = [K, K, K, d(1)];
    let g = [role(1, 0, Some(Role::Sync)), role(2, 1, Some(Role::Sync)), role(1, 2, Some(Role::Sync))];
    // genesis has 3 commits: moves are numbered from 3.
    let scenarios: Vec<(Vec<Commit>, Vec<Commit>)> = vec![
        (g.to_vec(), vec![add(0, 1), add(0, 3), rm(0, &[3])]),
        (vec![add(0, 1)], vec![role(1, 0, Some(Role::Sync)), role(1, 0, None), add(0, 1)]),
        ([g.to_vec(), vec![add(0, 1)]].concat(), vec![add(1, 2), add(2, 1), rm(0, &[3])]),
    ];
    let mut dup = 0;
    for (gen, moves) in &scenarios {
        let (bad, n) = every_order(&kinds, gen, moves, true);
        assert_eq!((bad, n), (0, 720), "{moves:?}");
        dup += every_order(&kinds, gen, moves, false).0;
    }
    assert!(dup > 0, "negative control must fail");
}

/// A random history over time: 4 independent and 2 dependent things, two writers, a keeper of 0;
/// commits (strongs added and removed, grants set and removed) delivered at random, visits alone
/// or together, keeper passes, and with `hostile` blobs deleted and forged at random. Settled
/// with everything delivered; whether the end is right.
fn random_net(r: &mut Rng, rules: Rules, syncs: Vec<Set>, hostile: bool, deletes: bool) -> bool {
    let kinds = vec![K, K, K, K, d(1), d(2)];
    let mut net = Net::new(kinds, rules, syncs, vec![set(&[0])]);
    net.deletes = deletes;
    for _ in 0..30 {
        match r.below(10) {
            0..=2 => {
                net.write(add(r.below(6) as T, r.below(6) as T));
            }
            3 => {
                let on = r.below(6) as T;
                let adds: Vec<C> = (0..net.commits.len()).filter(|&c| net.commits[c].on == on && matches!(net.commits[c].op, Op::Add(_))).collect();
                if !adds.is_empty() {
                    net.write(rm(on, &[r.pick(&adds)]));
                }
            }
            4 => {
                let (a, b) = (r.below(4) as T, r.below(4) as T);
                if a != b {
                    net.write(role(b, a, [None, Some(Role::Sync), Some(Role::Read)][r.below(3) as usize]));
                }
            }
            5 | 6 if !net.commits.is_empty() => {
                let c = r.below(net.commits.len() as u64) as C;
                net.deliver(r.below(2) as usize, c);
            }
            7 => net.visit(r.below(2) as usize),
            8 => net.visit_together(),
            _ if hostile && r.chance(50) => {
                let keys: Vec<(T, usize)> = net.store.keys().copied().collect();
                if r.chance(50) && !keys.is_empty() {
                    net.store.remove(&r.pick(&keys));
                } else {
                    let id = net.next_id;
                    net.next_id += 1;
                    net.store.insert((r.below(4) as T, id), r.below(4) as T);
                }
            }
            _ => net.pass(0, false),
        }
    }
    net.deliver_all();
    net.settle(30, false).is_some() && net.wrong().is_empty()
}

/// P4 over random histories: with writers syncing every unit the design converges; with each
/// writer syncing some units only it does not (Hole 1 over time), and the member list by
/// strongs alone does.
#[test]
fn p4_random_histories_converge() {
    let mut r = Rng::new(0);
    let n = 400;
    let every = || vec![set(&[0, 1, 2, 3]), set(&[0, 1, 2, 3])];
    let some = || vec![set(&[0, 1, 2, 3]), set(&[0, 2])];
    let mut fails = [0; 3];
    for _ in 0..n {
        fails[0] += !random_net(&mut r.clone(), Rules::DESIGN, every(), false, true) as usize;
        fails[1] += !random_net(&mut r.clone(), Rules::DESIGN, some(), false, true) as usize;
        fails[2] += !random_net(&mut r.clone(), Rules { member: Member::Any, secrets: Secrets::Holder }, some(), false, true) as usize;
        r.next();
    }
    assert_eq!(fails[0], 0, "{fails:?}");
    assert!(fails[1] > 0, "{fails:?}");
    assert_eq!(fails[2], 0, "{fails:?}");
    eprintln!("p4 random failing of {n}: design all units, design some units, by strongs some units: {fails:?}");
}

/// P5, a hostile writer of a unit deleting or forging member blobs. What the design promises
/// (notes/sync-unit-design.md §2, §3): readers of the unit never read member blobs (they walk its
/// strongs), and a blob outside the required set or one missing is set right by the next honest
/// writer of the unit holding the data; until then a node keeping the unit unread keeps a forged
/// member it holds a credential for, or loses the deleted one. Checked: one honest visit restores
/// the store, and the keeper's next pass its units; over random histories with hostile ops, every
/// run settles right. The negative control (writers deleting nothing outside the set) keeps a
/// forged blob for good.
#[test]
fn p5_hostile_member_blobs_are_set_right_by_one_honest_visit() {
    let mut net = Net::new(vec![K, K, K], Rules::DESIGN, vec![set(&[0, 1, 2])], vec![set(&[0])]);
    for c in [role(1, 0, Some(Role::Sync)), role(2, 0, Some(Role::Sync)), add(0, 1)] {
        net.write(c);
    }
    net.deliver_all();
    net.settle(20, false).unwrap();
    assert_eq!(net.kept[0], set(&[0, 1]));
    // forged: S(0) lists 2, which 0 holds sync on but does not reference
    net.store.insert((0, 100), 2);
    net.pass(0, false);
    assert_eq!(net.kept[0], set(&[0, 1, 2]), "the keeper follows a forged blob it has a credential for");
    let before = net.churn;
    net.visit(0);
    net.pass(0, false);
    assert!(net.wrong().is_empty());
    assert_eq!(net.churn - before, 2, "one delete, one unit dropped");
    // deleted: the keeper drops 1 until an honest writer logs it again
    let k = *net.store.keys().next().unwrap();
    net.store.remove(&k);
    net.pass(0, false);
    assert_eq!(net.kept[0], set(&[0]));
    net.visit(0);
    net.pass(0, false);
    assert!(net.wrong().is_empty());

    let mut r = Rng::new(0);
    let all = || vec![set(&[0, 1, 2, 3]), set(&[0, 1, 2, 3])];
    let (mut ok, mut control) = (0, 0);
    let n = 300;
    for _ in 0..n {
        ok += random_net(&mut r.clone(), Rules::DESIGN, all(), true, true) as usize;
        control += !random_net(&mut r.clone(), Rules::DESIGN, all(), true, false) as usize;
        r.next();
    }
    assert_eq!(ok, n);
    assert!(control > 0, "negative control must fail");
}

/// A release question the unit reading raises (Finding 4): a dependent no strong reaches stays in
/// its unit, and its strongs keep the units they name at a node keeping the unit unread.
#[test]
fn unreached_dependent_keeps_its_targets() {
    // 1 is a dependent of 0 that nothing references; 1 -> 2.
    let kinds = [K, d(0), K];
    let cs = world(&[(0, 2, Role::Sync)], &[(1, 2)]);
    let t = View::all(&kinds, &cs);
    assert_eq!(t.unit(0), set(&[0, 1]));
    assert_eq!(keeper(&t, &set(&[0]), Keep::Reach, &|g| t.members(g, Member::Role)), set(&[0, 2]));
}
