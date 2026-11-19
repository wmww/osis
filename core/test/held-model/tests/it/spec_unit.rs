//! The sync unit as one independent thing and the dependents it reaches, held_model::unit: each
//! test names the property of notes/closure-model.md (The unit model) it checks. Where a rule of
//! the design fails a property the test asserts the smallest world, so the finding stays visible
//! and checked; counts print with `--nocapture`.
use held_model::closure::{Kind, Role, Set, C, T};
use held_model::gen::Rng;
use held_model::unit::*;
use std::collections::{BTreeMap, BTreeSet};

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
fn blob(tag: T, unit: T) -> Blob {
    Blob { tag, unit, paths: BTreeSet::new() }
}
fn with(r: Rules, f: impl FnOnce(&mut Rules)) -> Rules {
    let mut r = r;
    f(&mut r);
    r
}

/// What a reader of `g` that also reads the units `extra` holds: the commits carried under them.
fn seen(kinds: &[Kind], cs: &[Commit], g: T, extra: &[T], unit: Unit) -> View {
    let t = View::all(kinds, cs, unit);
    let mut units: Set = extra.iter().copied().collect();
    units.insert(g);
    let known: BTreeSet<C> = (0..cs.len()).filter(|&c| !t.under(&cs[c]).is_disjoint(&units)).collect();
    View::of(kinds, cs, &known, unit)
}

/// For one world: whether every reader of each unit G, whatever other units it reads, computes
/// the same unit, the same targets for G's member blobs, and the same targets cut by G's roles
/// (`Member::Role`).
fn p1_world(kinds: &[Kind], cs: &[Commit], unit: Unit) -> [bool; 3] {
    let t = View::all(kinds, cs, unit);
    let ind: Vec<T> = t.independents().into_iter().collect();
    let mut agree = [true; 3];
    for &g in &ind {
        let others: Vec<T> = ind.iter().copied().filter(|&x| x != g).collect();
        let mut first: Option<[Set; 3]> = None;
        for x in subsets(&others) {
            let v = seen(kinds, cs, g, &x, unit);
            let now = [v.unit(g), v.targets(g, Member::Target), v.targets(g, Member::Role)];
            match &first {
                Some(f) => (0..3).for_each(|i| agree[i] &= f[i] == now[i]),
                None => first = Some(now),
            }
        }
    }
    agree
}

/// The small family: independent 0, 1, 2; 3 a dependent of 1, 4 of 2; every grant among 0, 1, 2
/// of none, sync or read; every set of strongs among `CAND` (in-unit strongs to the dependents,
/// strongs into another unit's dependent, a cycle).
const KINDS: [Kind; 5] = [K, K, K, Kind::Dependent(1), Kind::Dependent(2)];
const CAND: [(T, T); 8] = [(0, 1), (1, 2), (0, 2), (1, 3), (2, 4), (3, 4), (0, 4), (2, 0)];
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
const FAMILY: usize = 729 << CAND.len();

/// Runs `f` on every `step`-th world of the family, a thread per core, summing its counts.
fn over_family<const N: usize>(step: usize, f: impl Fn(&[Commit]) -> [usize; N] + Sync) -> [usize; N] {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        let hs: Vec<_> = (0..threads)
            .map(|k| {
                let f = &f;
                sc.spawn(move || {
                    let mut acc = [0; N];
                    for i in (k * step..FAMILY).step_by(threads * step) {
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
    let strongs: Vec<(T, T)> = (0..r.below(10) + 2).map(|_| (r.below(8) as T, r.below(8) as T)).collect();
    (kinds, world(&grants, &strongs))
}

// ---- Item 1 and 2: the unit by reach, one blob per target ----

/// P1 for the unit and for its targets (items 1, 2), over the small family (186624 worlds) and 600
/// random worlds: every reader of G computes the same unit and the same targets whatever else it
/// reads. Controls: the unit by reach from every strong the node holds (`Unit::Held`) fails the
/// unit (and the targets, where the dependent it adds has strongs out); targets cut to those G
/// holds a role on (`Member::Role`) fail the targets.
#[test]
fn p1_readers_compute_one_unit_and_one_target_list() {
    let row = |kinds: &[Kind], cs: &[Commit]| {
        let [u, t, tr] = p1_world(kinds, cs, Unit::Reach);
        let [uh, th, _] = p1_world(kinds, cs, Unit::Held);
        [!u, !t, !uh, !th, !tr].map(|b| b as usize)
    };
    let fails = over_family(1, |cs| row(&KINDS, cs));
    let mut r = Rng::new(0);
    let mut rand = [0; 5];
    for _ in 0..600 {
        let (kinds, cs) = random_static(&mut r);
        for (a, x) in rand.iter_mut().zip(row(&kinds, &cs)) {
            *a += x;
        }
    }
    for f in [fails, rand] {
        assert_eq!(f[..2], [0; 2], "{f:?}");
        assert!(f[2] > 0 && f[4] > 0, "controls must fail: {f:?}");
    }
    // The control's smallest world: 0 holds sync on 1, 1 on 2, 0 -> 2. 1's grant on 2 travels
    // under S(1) and S(2), so a reader of 0 alone cuts 2 and one also reading 1 keeps it.
    let cs = world(&[(0, 1, Role::Sync), (1, 2, Role::Sync)], &[(0, 2)]);
    assert_eq!(p1_world(&[K, K, K], &cs, Unit::Reach), [true, true, false]);
    eprintln!("p1 failing (unit, targets) by reach, (unit, targets) Held, targets Role: family of {FAMILY} {fails:?}, random of 600 {rand:?}");
}

/// Item 1 over time: H -> X -> K, X a dependent of H, K independent and H holding sync on K.
/// Removing H -> X releases X: its body entries leave S(H), S(H) stops listing K and the keeper of
/// H drops K. Controls: `Unit::All` keeps both for good; `Unit::Held`, with a second writer holding
/// a strong from another unit to X, never settles (the two writers log and delete X at S(H)).
#[test]
fn unit_by_reach_releases_a_dependent_and_what_only_it_listed() {
    let kinds = vec![K, d(0), K, K];
    let gen = [role(2, 0, Some(Role::Sync)), add(0, 1), add(1, 2)];
    for (unit, released) in [(Unit::Reach, true), (Unit::All, false)] {
        let mut net = Net::new(kinds.clone(), with(Rules::DESIGN, |r| r.unit = unit), vec![set(&[0])], vec![set(&[0])]);
        for c in gen.clone() {
            net.write(c);
        }
        net.deliver_all();
        net.settle(20, false).unwrap();
        assert_eq!(net.kept[0].units(), set(&[0, 2]));
        assert!(net.bodies.contains(&(0, 2)));
        net.write(rm(0, &[1]));
        net.deliver_all();
        net.settle(20, false).unwrap();
        assert!(net.wrong().is_empty(), "{:?}", net.wrong());
        assert_eq!(net.bodies.contains(&(0, 2)), !released, "{unit:?}");
        assert_eq!(net.listed(0).is_empty(), released, "{unit:?}");
        assert_eq!(net.kept[0].units(), if released { set(&[0]) } else { set(&[0, 2]) }, "{unit:?}");
    }
    // Held: writer 1 also syncs 3, which references X; writer 0 syncs H alone.
    let mut net = Net::new(kinds, with(Rules::DESIGN, |r| r.unit = Unit::Held), vec![set(&[0]), set(&[0, 3])], vec![]);
    for c in [role(2, 0, Some(Role::Sync)), add(3, 1), add(1, 2)] {
        net.write(c);
    }
    net.deliver_all();
    assert_eq!(net.settle(20, false), None, "two honest writers of S(0) undo each other for good");
}

/// Pins the cost of issues/unit-dependent-release.md rule 1, and what the naming rule adds to it.
/// G (0) reads H (1); X (2) is a dependent of H that H does not reach; G -> X. X is in no unit:
/// nobody holds it and the strong is carried with no target. Whether S(G) lists H's unit for it
/// depends on history (finding): a writer named it while H reached X, and nothing removes that
/// blob after (no writer can name X's unit any more, so none judges it), so keepers and readers of
/// G keep entering H; had G -> X been written after the release, nothing names it and H is not
/// entered. The two end states hold the same commits.
#[test]
fn pin_a_strong_to_a_dependent_its_unit_dropped() {
    let kinds = vec![K, K, d(1)];
    let run = |order: &[usize]| {
        let all = [role(1, 0, Some(Role::Read)), add(1, 2), add(0, 2), rm(1, &[1])];
        let mut net = Net::new(kinds.clone(), Rules::DESIGN, vec![set(&[0, 1])], vec![set(&[0])]);
        for c in all {
            net.write(c);
        }
        for &c in order {
            net.deliver(0, c);
            net.settle(20, false).unwrap();
        }
        net
    };
    let named = run(&[0, 1, 2, 3]);
    let late = run(&[0, 1, 3, 2]);
    for net in [&named, &late] {
        let t = net.truth();
        assert_eq!(t.in_unit[2], None, "X is in no unit");
        assert_eq!(t.targets(0, Member::Target), set(&[2]));
        assert!(!net.bodies.iter().any(|&(_, c)| net.commits[c].on == 2), "nobody holds X");
        assert_eq!(net.view(0), late.view(0), "the same commits");
    }
    assert_eq!(named.listed(0), vec![blob(2, 1)]);
    assert_eq!(named.kept[0].units(), set(&[0, 1]), "H's unit kept for a strong that holds nothing");
    assert!(late.listed(0).is_empty());
    assert_eq!(late.kept[0].units(), set(&[0]));
    assert!(late.wrong().is_empty());
    assert!(!named.wrong().is_empty(), "the blob no writer can name is outside the stated end state");
}

/// One scenario: commits every writer holds first, then `moves` reaching two writers in every
/// order and interleaving, both visiting the stores together after each and the keeper of 0
/// passing; then everything delivered and settled. The schedules whose end state is wrong or
/// does not settle, of how many.
fn every_order(kinds: &[Kind], syncs: &[Set], genesis: &[Commit], moves: &[Commit], tune: &dyn Fn(&mut Net)) -> (usize, usize) {
    let perms = permutations(moves.len());
    let (mut bad, mut n) = (0, 0);
    let ilv = interleavings(moves.len(), moves.len());
    for pa in &perms {
        for pb in &perms {
            for il in &ilv {
                let mut net = Net::new(kinds.to_vec(), Rules::DESIGN, syncs.to_vec(), vec![set(&[0])]);
                tune(&mut net);
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
                let settled = net.settle(20, false).is_some();
                n += 1;
                bad += !(settled && net.wrong().is_empty()) as usize;
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

/// P4 (item 2): attach and detach in every arrival order (720 schedules a scenario) with writer 0
/// syncing every unit and writer 1 only S(0), so writer 1 cannot name a dependent target: every end
/// state lists exactly the targets some writer can name, once, naming the right unit, with the
/// body entries of each unit's things, the keeper keeping its walk, and quiet. Scenarios: attach,
/// attach a dependent target only writer 0 can name, detach the first; a grant after the strong, its removal, a grant again (the
/// target named by Bootstrap while the grant stands); a cycle attached and its entry detached.
/// Controls: a writer deleting blobs for targets it cannot name undoes writer 0 for good; no
/// lower-ID rule leaves the two blobs two writers log in one visit.
#[test]
fn p4_attach_detach_every_order_converges() {
    let kinds = [K, K, K, d(1)];
    let syncs = [set(&[0, 1, 2]), set(&[0])];
    let g = [role(1, 0, Some(Role::Sync)), role(2, 1, Some(Role::Sync)), role(1, 2, Some(Role::Sync)), add(1, 3)];
    // genesis numbering: moves are numbered after it.
    let scenarios: Vec<(Vec<Commit>, Vec<Commit>)> = vec![
        (g.to_vec(), vec![add(0, 1), add(0, 3), rm(0, &[4])]),
        (vec![add(0, 2)], vec![role(2, 0, Some(Role::Sync)), role(2, 0, None), role(2, 0, Some(Role::Read))]),
        ([g.to_vec(), vec![add(0, 1)]].concat(), vec![add(1, 2), add(2, 1), rm(0, &[4])]),
    ];
    let mut fight = 0;
    for (gen, moves) in &scenarios {
        assert_eq!(every_order(&kinds, &syncs, gen, moves, &|_| {}), (0, 720), "{moves:?}");
        fight += every_order(&kinds, &syncs, gen, moves, &|n| n.delete_unnamed = true).0;
    }
    assert!(fight > 0, "control must fail");
    // Two writers that can both name a target log it in one visit: the lower ID stays.
    for lowest_wins in [true, false] {
        let mut net = Net::new(vec![K, K], Rules::DESIGN, vec![set(&[0, 1]), set(&[0, 1])], vec![]);
        net.lowest_wins = lowest_wins;
        net.write(add(0, 1));
        net.deliver_all();
        net.settle(20, false).unwrap();
        assert_eq!(net.listed(0).len(), if lowest_wins { 1 } else { 2 });
    }
}

/// A random history over time: 4 independent and 2 dependent things, writers with the given
/// syncs, a keeper of 0; commits (strongs added and removed, grants set and removed) delivered at
/// random, visits alone or together, keeper passes, and with `hostile` blobs deleted and forged at
/// random. Then everything delivered and settled: `None` if it does not settle, else what is wrong
/// and the blobs no writer can name (`Net::residue`).
fn random_net(r: &mut Rng, rules: Rules, syncs: Vec<Set>, hostile: bool, tune: &dyn Fn(&mut Net)) -> Option<(Vec<String>, usize)> {
    let kinds = vec![K, K, K, K, d(1), d(2)];
    let mut net = Net::new(kinds, rules, syncs, vec![set(&[0])]);
    tune(&mut net);
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
                net.deliver(r.below(net.syncs.len() as u64) as usize, c);
            }
            7 => net.visit(r.below(net.syncs.len() as u64) as usize),
            8 => net.visit_together(),
            _ if hostile && r.chance(50) => forge(r, &mut net),
            _ => net.pass(0, false),
        }
    }
    net.deliver_all();
    net.settle(40, false)?;
    Some((net.wrong(), residue(&net)))
}
fn forge(r: &mut Rng, net: &mut Net) {
    let keys: Vec<(T, usize)> = net.store.keys().copied().collect();
    if r.chance(50) && !keys.is_empty() {
        net.store.remove(&r.pick(&keys));
    } else {
        let id = net.next_id;
        net.next_id += 1;
        net.store.insert((r.below(4) as T, id), blob(r.below(6) as T, r.below(4) as T));
    }
}
/// Blobs no writer judges: in a unit no writer syncs, or for a live target no writer syncing the
/// unit can name (so none judges the unit it names).
fn residue(net: &Net) -> usize {
    let t = net.truth();
    net.store
        .iter()
        .filter(|(&(g, _), b)| {
            let visitors: Vec<usize> = (0..net.syncs.len()).filter(|&w| net.syncs[w].contains(&g)).collect();
            visitors.is_empty()
                || (t.targets(g, net.rules.member).contains(&b.tag) && !visitors.iter().any(|&w| net.view(w).can_name(&net.syncs[w], b.tag)))
        })
        .count()
}
fn random_syncs(r: &mut Rng) -> Vec<Set> {
    (0..2)
        .map(|_| {
            let mut s: Set = (0..4).filter(|_| r.chance(60)).collect();
            s.insert(r.below(4) as T);
            s
        })
        .collect()
}

/// P4 over random histories (400, each with two writers syncing random units): every run settles
/// (no two honest writers undo each other), and once settled every store lists exactly the targets
/// some writer syncing it can name, with the right bodies and keepers, except for blobs a writer
/// logged while it could name the target and that no writer can name or judge after (finding,
/// `pin_a_strong_to_a_dependent_its_unit_dropped`, `a_blob_named_by_bootstrap_outlives_the_grant`).
#[test]
fn p4_random_histories_settle() {
    let mut r = Rng::new(0);
    let n = 400;
    let (mut unsettled, mut wrong, mut residue_runs) = (0, 0, 0);
    for _ in 0..n {
        let syncs = random_syncs(&mut r);
        match random_net(&mut r.clone(), Rules::DESIGN, syncs, false, &|_| {}) {
            None => unsettled += 1,
            Some((w, res)) => {
                residue_runs += (res > 0) as usize;
                wrong += (!w.is_empty() && res == 0) as usize;
            }
        }
        r.next();
    }
    assert_eq!((unsettled, wrong), (0, 0), "residue runs {residue_runs}");
    eprintln!("p4 random of {n}: unsettled {unsettled}, wrong {wrong}, ending with a blob no writer can name {residue_runs}");
}

/// The residue in its smallest independent form: G (0) holds sync on W (1) and references W and
/// X (2); W holds sync on X. S(G)'s one writer syncs G alone, so it names W (G's grant on W travels
/// under S(G)) and names X only while G holds a direct grant on X. Given and then removed, that
/// grant leaves a blob for X that no writer can name or judge; the keeper of G enters X by W's
/// secret. With the grant never given, the same end state of roles and strongs lists nothing for X
/// and the keeper does not enter it.
#[test]
fn a_blob_named_by_bootstrap_outlives_the_grant() {
    let hist = |first: bool| {
        let mut n = Net::new(vec![K, K, K], Rules::DESIGN, vec![set(&[0])], vec![set(&[0])]);
        let mut cs = vec![role(1, 0, Some(Role::Sync)), add(0, 1), add(0, 2), role(2, 1, Some(Role::Sync))];
        if first {
            cs.push(role(2, 0, Some(Role::Sync)));
        }
        for c in cs {
            n.write(c);
        }
        n.deliver_all();
        n.settle(20, false).unwrap();
        if first {
            n.write(role(2, 0, None));
            n.deliver_all();
            n.settle(20, false).unwrap();
        }
        n
    };
    let (gave, never) = (hist(true), hist(false));
    assert_eq!((gave.truth().grants, gave.truth().strongs), (never.truth().grants, never.truth().strongs));
    assert_eq!(residue(&gave), 1);
    assert_eq!(gave.kept[0].units(), set(&[0, 1, 2]), "W's secret enters X, named by the residue");
    assert_eq!(never.kept[0].units(), set(&[0, 1]), "nothing names X");
}

/// Item 2, role ops: over random settled histories, one role op (a grant set, changed or removed
/// between two independent things) then everything settled again. The design deletes no blob for
/// it and logs only first blobs for targets the op made nameable (Bootstrap); the control
/// (`Member::Role`) logs and deletes because roles changed, or never settles (writers seeing
/// different chains).
#[test]
fn role_ops_write_no_member_blob_but_first_names() {
    let mut r = Rng::new(0);
    let (mut first_names, mut other, mut control) = (0, 0, 0);
    for _ in 0..300 {
        let syncs = random_syncs(&mut r);
        for (member, count) in [(Member::Target, false), (Member::Role, true)] {
            let mut rr = r.clone();
            let mut net = Net::new(vec![K, K, K, K, d(1), d(2)], with(Rules::DESIGN, |x| x.member = member), syncs.clone(), vec![set(&[0])]);
            for _ in 0..8 {
                let c = if rr.chance(50) {
                    add(rr.below(6) as T, rr.below(6) as T)
                } else {
                    let (a, b) = (rr.below(4) as T, (rr.below(3) + 1) as T);
                    role((a + b) % 4, a, Some(if rr.chance(50) { Role::Sync } else { Role::Read }))
                };
                net.write(c);
            }
            net.deliver_all();
            if net.settle(40, false).is_none() {
                continue;
            }
            let before = net.store.clone();
            let tags: BTreeSet<(T, T)> = before.iter().map(|(&(g, _), b)| (g, b.tag)).collect();
            let ops = net.blob_ops;
            let (a, b) = (rr.below(4) as T, (rr.below(3) + 1) as T);
            net.write(role((a + b) % 4, a, [None, Some(Role::Sync), Some(Role::Read)][rr.below(3) as usize]));
            net.deliver_all();
            let settled = net.settle(40, false).is_some();
            assert!(settled || count, "the design settles after a role op");
            let old = |s: &BTreeMap<(T, usize), Blob>| -> Vec<((T, usize), Blob)> {
                s.iter().filter(|(&(g, _), b)| tags.contains(&(g, b.tag))).map(|(k, b)| (*k, b.clone())).collect()
            };
            let new: BTreeSet<(T, T)> = net.store.iter().map(|(&(g, _), b)| (g, b.tag)).filter(|t| !tags.contains(t)).collect();
            let done = net.blob_ops - ops;
            if count {
                control += done + !settled as usize;
            } else if old(&before) == old(&net.store) {
                first_names += new.len();
            } else {
                other += done;
            }
        }
        r.next();
    }
    assert_eq!(other, 0);
    assert!(control > 0);
    eprintln!("role ops: first names {first_names}, other blob ops {other}; control (Member::Role) blob ops {control}");
}

// ---- Item 3: secrets only through entered units ----

/// The reader of 0 and the keeper of 0 over the settled blobs `l`; per property whether it holds:
/// P2 (the keeper enters exactly the units the reader enters, key units alike), P2b (the reader
/// reads exactly the units it entered that 0 holds read on through chains whose holders are units
/// it entered), every unit entered on a chain of such holders (no secret from outside), R's role
/// over any chain on a referenced unit exceeding that oracle (a report), and P2b against R's role
/// over any chain (the key-path property).
fn p2_row(t: &View, r: Rules, l: &BTreeMap<T, Vec<Blob>>, keeper_rules: Rules) -> [bool; 5] {
    let listed = |g| l.get(&g).cloned().unwrap_or_default();
    let rd = walk(t, &set(&[0]), &Set::new(), r, &listed, true);
    let kp = walk(t, &Set::new(), &set(&[0]), keeper_rules, &listed, false);
    let units = rd.units();
    let oracle = t.roles_through(0, &|a| units.contains(&a));
    let p2 = kp.units() == units && kp.keys == rd.keys;
    let p2b = units.iter().all(|h| rd.read.contains(h) == oracle.get(h).is_some_and(|&x| x >= Role::Read));
    let inside = units.iter().all(|h| oracle.contains_key(h));
    let full = t.roles_from(0);
    let referenced: Set = rd.followed().into_iter().flat_map(|g| t.targets(g, r.member)).map(|x| t.ind(x)).filter(|&h| h != 0).collect();
    let exceeds = referenced.iter().any(|h| full.get(h) > oracle.get(h));
    let status = |h: &T| {
        if rd.read.contains(h) {
            Some(Role::Read)
        } else if rd.unread.contains(h) {
            Some(Role::Sync)
        } else {
            None
        }
    };
    let any = referenced.iter().all(|h| status(h) == full.get(h).map(|&x| x.min(Role::Read)));
    [p2, p2b, inside, exceeds, any]
}

const P2_COLS: usize = 16;
/// The P2 columns for one world (failures, except `exceeds` and the extra-unit count):
/// 0-3 design, writers seeing everything: P2, P2b, inside, exceeds; 4-6 design, each unit's writer
/// a reader of it alone: P2, P2b, exceeds; 7-9 controls on the keeper (blobs only where the
/// referrer holds a role; stopping at a unit kept unread; entering with no secret): P2; 10 the
/// depth-free secrets of the first model: inside; 11-13 key paths, writers seeing everything: P2,
/// P2b, P2b against any chain; 14 the design against any chain; 15 key-path units followed as
/// members: units the keeper holds beyond the key-path walk's.
fn p2_world(kinds: &[Kind], cs: &[Commit]) -> [usize; P2_COLS] {
    let t = View::all(kinds, cs, Unit::Reach);
    let de = Rules::DESIGN;
    let full = listing(&t, de, Writers::Full);
    let own = listing(&t, de, Writers::Own);
    let a = p2_row(&t, de, &full, de);
    let b = p2_row(&t, de, &own, de);
    let role_l = listing(&t, with(de, |r| r.member = Member::Role), Writers::Full);
    let c_role = p2_row(&t, de, &role_l, de)[0];
    let c_stop = p2_row(&t, de, &full, with(de, |r| r.follow_unread = false))[0];
    let c_free = p2_row(&t, de, &full, with(de, |r| r.enter = Enter::Free))[0];
    let c_deep = p2_row(&t, with(de, |r| r.enter = Enter::Deep), &full, de)[2];
    let via = listing(&t, Rules::VIA, Writers::Full);
    let p = p2_row(&t, Rules::VIA, &via, Rules::VIA);
    let fol = with(Rules::VIA, |r| r.paths = Paths::Followed);
    let lv = |g: T| via.get(&g).cloned().unwrap_or_default();
    let kv = walk(&t, &Set::new(), &set(&[0]), Rules::VIA, &lv, false).units();
    let kf = walk(&t, &Set::new(), &set(&[0]), fol, &lv, false).units();
    let n = |x: bool| !x as usize;
    [
        n(a[0]),
        n(a[1]),
        n(a[2]),
        a[3] as usize,
        n(b[0]),
        n(b[1]),
        b[3] as usize,
        n(c_role),
        n(c_stop),
        n(c_free),
        n(c_deep),
        n(p[0]),
        n(p[1]),
        n(p[4]),
        n(a[4]),
        kf.difference(&kv).count(),
    ]
}

fn p2_asserts(f: &[usize; P2_COLS]) {
    // Writers seeing everything: the keeper enters what the reader enters, reads what 0 holds read
    // on through the closure, and enters nothing by a secret from outside it.
    assert_eq!(f[0..3], [0; 3], "{f:?}");
    // Writers reading only their own unit's closure: the keeper misses what only the reader names.
    assert!(f[4] > 0, "{f:?}");
    assert_eq!(f[5], 0, "{f:?}");
    assert!(f[7] > 0 && f[8] > 0 && f[9] > 0 && f[10] > 0, "controls must fail: {f:?}");
    assert_eq!(f[11..13], [0; 2], "{f:?}");
    // Key paths do not reach R's role over any chain (findings), nor does the design.
    assert!(f[13] > 0 && f[14] > f[13], "{f:?}");
}

/// Items 3 and 4 over the small family (every 7th world by default, all 186624 in the ignored
/// twin): P2, P2b, entering only through entered units, the chain-exceeds-oracle count, key paths,
/// and the controls (see `p2_world`).
#[test]
fn p2_keeper_enters_what_a_reader_enters_family() {
    let f = over_family(7, |cs| p2_world(&KINDS, cs));
    p2_asserts(&f);
    eprintln!("p2 family 1/7 of {FAMILY}: {f:?}");
}

#[test]
#[ignore]
fn p2_keeper_enters_what_a_reader_enters_family_full() {
    let f = over_family(1, |cs| p2_world(&KINDS, cs));
    p2_asserts(&f);
    eprintln!("p2 family of {FAMILY}: {f:?}");
}

/// The same over 600 random worlds of 4 independent and 4 dependent things.
#[test]
fn p2_keeper_enters_what_a_reader_enters_random() {
    let mut r = Rng::new(0);
    let mut f = [0; P2_COLS];
    for _ in 0..600 {
        let (kinds, cs) = random_static(&mut r);
        for (a, x) in f.iter_mut().zip(p2_world(&kinds, &cs)) {
            *a += x;
        }
    }
    p2_asserts(&f);
    eprintln!("p2 random of 600: {f:?}");
}

/// Finding 2's world, 0 reads 1 and 2, 0 -> 1 -> 2, 1 holding no role on 2. S(1) requires a blob
/// for 2 (no role read). The reader of 0 reads 1 and names 2 itself (Bootstrap: 0's grant on 2
/// travels under S(0)), and enters 2 by 0's secret. Who logs S(1)'s blob: a writer of 1 that can
/// name 2. With S(1)'s only writer reading 1 alone, none does: the keeper of 0 keeps {0, 1}, a
/// fresh reader it serves never gets 2 (finding). With the reader of 0 writing 1, or any writer of
/// 1 that reads 0 or 2, the blob is there and the keeper keeps 2. The control (a list of what the
/// referrer itself can enter) never lists it.
#[test]
fn p2_keeper_misses_what_no_writer_of_the_referrer_can_name() {
    let kinds = [K, K, K];
    let cs = world(&[(0, 1, Role::Read), (0, 2, Role::Read)], &[(0, 1), (1, 2)]);
    let t = View::all(&kinds, &cs, Unit::Reach);
    let de = Rules::DESIGN;
    let own = listing(&t, de, Writers::Own);
    assert!(own[&1].is_empty());
    let lo = |g: T| own.get(&g).cloned().unwrap_or_default();
    let reader = walk(&t, &set(&[0]), &Set::new(), de, &lo, true);
    assert_eq!(reader.read, set(&[0, 1, 2]));
    assert_eq!(walk(&t, &Set::new(), &set(&[0]), de, &lo, false).units(), set(&[0, 1]));
    // The reader of 0 also writes 1: it logs what it names.
    let mut l2 = own.clone();
    l2.insert(1, vec![blob(2, 2)]);
    let l2f = |g: T| l2.get(&g).cloned().unwrap_or_default();
    assert_eq!(walk(&t, &Set::new(), &set(&[0]), de, &l2f, false).units(), set(&[0, 1, 2]));
    // spec/requirements.md Data model's second clause holds: 1 alone keeps no 2.
    let full = listing(&t, de, Writers::Full);
    let lf = |g: T| full.get(&g).cloned().unwrap_or_default();
    assert_eq!(walk(&t, &Set::new(), &set(&[1]), de, &lf, false).units(), set(&[1]));
    let role_l = listing(&t, with(de, |r| r.member = Member::Role), Writers::Full);
    assert!(role_l[&1].is_empty());
}

/// Finding 3's world, the chain-exceeds-oracle case: 0 reads 1, 1 reads 2, 0 -> 2, nothing
/// references 1. 2's step lists 1, whose secret the node does not hold: 2 is not entered, read or
/// unread, though 0 holds read on 2 over the chain (issues/unit-key-paths.md rule 1). The first
/// model's depth-free secrets (control) kept it unread through 1 unentered. A strong 0 -> 1 brings
/// 1 into the closure and 2 is read.
#[test]
fn p2_a_unit_reached_through_a_holder_outside_the_closure() {
    let kinds = [K, K, K];
    let de = Rules::DESIGN;
    let cs = world(&[(0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2)]);
    let t = View::all(&kinds, &cs, Unit::Reach);
    let full = listing(&t, de, Writers::Full);
    let row = p2_row(&t, de, &full, de);
    assert_eq!(row, [true, true, true, true, false]);
    let lf = |g: T| full.get(&g).cloned().unwrap_or_default();
    assert_eq!(walk(&t, &set(&[0]), &Set::new(), de, &lf, true).units(), set(&[0]));
    let deep = walk(&t, &set(&[0]), &Set::new(), with(de, |r| r.enter = Enter::Deep), &lf, true);
    assert_eq!(deep.unread, set(&[2]));
    let cs2 = world(&[(0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2), (0, 1)]);
    let t2 = View::all(&kinds, &cs2, Unit::Reach);
    let f2 = listing(&t2, de, Writers::Full);
    assert_eq!(walk(&t2, &set(&[0]), &Set::new(), de, &|g| f2.get(&g).cloned().unwrap_or_default(), true).read, set(&[0, 1, 2]));
}

/// A strong to a dependent thing brings its independent's unit (Tess): 0 -> 3, 3 a dependent of
/// 1 that 1 reaches; 0 holds sync on 1.
#[test]
fn p2_strong_to_a_dependent_brings_its_unit() {
    let kinds = [K, K, K, d(1)];
    let cs = world(&[(0, 1, Role::Sync)], &[(1, 3), (0, 3)]);
    let t = View::all(&kinds, &cs, Unit::Reach);
    let full = listing(&t, Rules::DESIGN, Writers::Full);
    assert_eq!(full[&0], vec![blob(3, 1)]);
    assert_eq!(walk(&t, &Set::new(), &set(&[0]), Rules::DESIGN, &|g| full.get(&g).cloned().unwrap_or_default(), false).units(), set(&[0, 1]));
}

// ---- Item 4: key paths ----

/// Key paths (§4): G (0) holds read on W (1), W read on H (2), G -> H, nothing references W.
/// A writer syncing G, W and H logs S(G)'s blob for H with the path [W]; the keeper of G enters W for
/// keys (not followed) and H by W's secret; the reader reads H. W's grant on H removed: the writer
/// logs the blob without the path, deletes the old one, and the keeper drops W and H. Control: a
/// path unit followed as a member brings W's own members.
#[test]
fn key_path_followed_and_dropped_with_its_grant() {
    let mut net = Net::new(vec![K, K, K], Rules::VIA, vec![set(&[0, 1, 2])], vec![set(&[0])]);
    for c in [role(1, 0, Some(Role::Read)), role(2, 1, Some(Role::Read)), add(0, 2)] {
        net.write(c);
    }
    net.deliver_all();
    net.settle(20, false).unwrap();
    assert_eq!(net.listed(0), vec![Blob { tag: 2, unit: 2, paths: BTreeSet::from([vec![1]]) }]);
    assert_eq!(net.kept[0], Entered { read: set(&[]), unread: set(&[0, 1, 2]), keys: set(&[1]) });
    let t = net.truth();
    let rd = walk(&t, &set(&[0]), &Set::new(), Rules::VIA, &|g| net.listed(g), true);
    assert_eq!(rd.read, set(&[0, 1, 2]));
    net.write(role(2, 1, None));
    net.deliver_all();
    net.settle(20, false).unwrap();
    assert_eq!(net.listed(0), vec![blob(2, 2)]);
    assert_eq!(net.kept[0].units(), set(&[0]));
    assert!(net.wrong().is_empty());
    // Control: a path unit followed as a member brings what it lists (W -> Y, W holding sync on Y).
    let cs = world(&[(0, 1, Role::Read), (1, 2, Role::Read), (1, 3, Role::Sync)], &[(0, 2), (1, 3)]);
    let t = View::all(&[K, K, K, K], &cs, Unit::Reach);
    let l = listing(&t, Rules::VIA, Writers::Full);
    let lf = |g: T| l.get(&g).cloned().unwrap_or_default();
    assert_eq!(walk(&t, &Set::new(), &set(&[0]), Rules::VIA, &lf, false).units(), set(&[0, 1, 2]));
    assert_eq!(walk(&t, &Set::new(), &set(&[0]), with(Rules::VIA, |r| r.paths = Paths::Followed), &lf, false).units(), set(&[0, 1, 2, 3]));
}

/// Two gaps of key paths against "R's role over any chain" (the item's property), each its
/// smallest world, writers seeing every grant:
/// - a direct grant hides a better chain: G holds sync on H directly and read through W; the
///   blob carries no path ("absent where G holds a role on H directly"), so H is kept unread.
/// - the root's chain, not the referrer's: R reads G and W, W reads H, G -> H; G holds no role on
///   H, so its blob has no path, and H's step lists W, which nothing names: H is not entered.
#[test]
fn key_paths_miss_a_chain_the_referrer_does_not_hold() {
    let via = Rules::VIA;
    let cs = world(&[(0, 2, Role::Sync), (0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2)]);
    let t = View::all(&[K, K, K], &cs, Unit::Reach);
    let l = listing(&t, via, Writers::Full);
    assert_eq!(l[&0], vec![blob(2, 2)]);
    assert_eq!(p2_row(&t, via, &l, via)[4], false);
    let rd = walk(&t, &set(&[0]), &Set::new(), via, &|g| l.get(&g).cloned().unwrap_or_default(), true);
    assert_eq!(rd.unread, set(&[2]));
    let cs = world(&[(0, 1, Role::Read), (0, 3, Role::Read), (3, 2, Role::Read)], &[(0, 1), (1, 2)]);
    let t = View::all(&[K, K, K, K], &cs, Unit::Reach);
    let l = listing(&t, via, Writers::Full);
    assert_eq!(l[&1], vec![blob(2, 2)]);
    let rd = walk(&t, &set(&[0]), &Set::new(), via, &|g| l.get(&g).cloned().unwrap_or_default(), true);
    assert_eq!(rd.units(), set(&[0, 1]));
    assert_eq!(p2_row(&t, via, &l, via)[4], false);
}

/// Forked sides over a grant on a key path (attack (a)): writer 0 never gets the removal of W's
/// grant on H, writer 1 does. Writer 0 logs the blob with the path, writer 1 judges the path gone,
/// deletes it and logs the blob without; writer 0 sees no blob covering its own and logs again:
/// without spec/sync-judgement.md §4's once-per-change-of-ground (not modelled) they never stop.
/// With no key paths the same fork changes no blob.
#[test]
fn key_path_under_forked_sides_never_settles() {
    for (rules, settles) in [(Rules::VIA, false), (Rules::DESIGN, true)] {
        let mut net = Net::new(vec![K, K, K], rules, vec![set(&[0, 1]), set(&[0, 1])], vec![]);
        for c in [role(1, 0, Some(Role::Read)), role(2, 1, Some(Role::Read)), add(0, 2), role(2, 1, None)] {
            net.write(c);
        }
        for c in 0..3 {
            net.deliver(0, c);
            net.deliver(1, c);
        }
        net.deliver(1, 3);
        assert_eq!(net.settle(20, false).is_some(), settles, "{rules:?}");
    }
}

// ---- Item 5: work at a change ----

/// Counts at n and 10n members (item 5, attack (d)): root 0 references a holder 1 (0 holds sync on
/// 1) and n members, each granted to 1; a writer syncs 0 and 1, the keeper keeps 0. Blob operations
/// for: a detach (one delete), a grant on a member (none), a role change on the root (its grant on
/// the holder removed: none; the keeper drops what it can no longer enter). The control
/// (`Member::Role`) deletes a blob per member at that role change. Rotation is not modelled (no
/// epochs): the design rewrites no blob at one by construction (§2, Across G's sync rotations).
#[test]
fn work_at_a_change_counts() {
    let mut rows = vec![];
    for n in [5, 50] {
        for member in [Member::Target, Member::Role] {
            let kinds = vec![K; n + 3];
            let mut net = Net::new(kinds, with(Rules::DESIGN, |r| r.member = member), vec![set(&[0, 1])], vec![set(&[0])]);
            net.write(role(1, 0, Some(Role::Sync)));
            net.write(add(0, 1));
            let first = net.commits.len();
            for m in 2..n + 2 {
                net.write(role(m, 1, Some(Role::Sync)));
                net.write(add(0, m));
            }
            net.deliver_all();
            net.settle(20, false).unwrap();
            assert_eq!(net.listed(0).len(), n + 1);
            assert_eq!(net.kept[0].units().len(), n + 2);
            let ops = |net: &mut Net, c: Commit| {
                let before = net.blob_ops;
                net.write(c);
                net.deliver_all();
                net.settle(20, false).unwrap();
                net.blob_ops - before
            };
            let detach = ops(&mut net, rm(0, &[first + 1]));
            let grant = ops(&mut net, role(3, n + 2, Some(Role::Read)));
            let root = ops(&mut net, role(1, 0, None));
            rows.push((n, member, detach, grant, root, net.kept[0].units().len()));
        }
    }
    for &(n, member, detach, grant, root, kept) in &rows {
        assert_eq!((detach, grant), (1, 0), "{rows:?}");
        match member {
            Member::Target => assert_eq!((root, kept), (0, 1), "{rows:?}"),
            Member::Role => assert_eq!(root, n, "{rows:?}"),
        }
    }
    eprintln!("work (n, member, detach, grant on a member, root role change, kept after): {rows:?}");
}

// ---- Item 6: a hostile writer ----

/// P5 (item 6): writer 0 syncs every unit, writer 1 only S(0), so writer 1 cannot name the
/// dependent target. A forged blob whose target no strong names is deleted by writer 1 (rule 1); one
/// for a live target naming another unit is left by writer 1 (it cannot name the target) and set
/// right by writer 0 (rule 3). The keeper enters a forged unit only where a thing it holds a secret
/// of is on that unit's step. Random hostile histories with writers syncing random units: every run
/// settles, and every wrong end is a blob no honest writer judges (finding): a forgery for a live
/// target no writer of the unit can name, or in a unit no writer visits, stays for good. Control:
/// writers deleting nothing outside the set keep a forged blob for good.
#[test]
fn p5_hostile_member_blobs() {
    let kinds = vec![K, K, K, d(1), K];
    let mut net = Net::new(kinds, Rules::DESIGN, vec![set(&[0, 1, 2, 4]), set(&[0])], vec![set(&[0])]);
    for c in [role(1, 0, Some(Role::Sync)), role(2, 0, Some(Role::Sync)), add(1, 3), add(0, 3)] {
        net.write(c);
    }
    net.deliver_all();
    net.settle(20, false).unwrap();
    assert_eq!(net.listed(0), vec![blob(3, 1)]);
    // No strong names 2: writer 1 deletes it. The keeper had entered 2 (0 is on 2's step).
    net.store.insert((0, 100), blob(2, 2));
    net.pass(0, false);
    assert_eq!(net.kept[0].units(), set(&[0, 1, 2]));
    net.visit(1);
    net.pass(0, false);
    assert!(net.wrong().is_empty());
    // Live target 3 named as unit 2 beside the honest blob; and as unit 4, whose step lists nothing
    // the keeper holds.
    net.store.insert((0, 101), blob(3, 2));
    net.store.insert((0, 102), blob(3, 4));
    net.pass(0, false);
    assert_eq!(net.kept[0].units(), set(&[0, 1, 2]), "enters 2 (0 on its step), not 4");
    net.visit(1);
    assert_eq!(net.listed(0).len(), 3, "writer 1 cannot name 3: it judges nothing");
    net.visit(0);
    net.pass(0, false);
    assert!(net.wrong().is_empty());
    assert_eq!(net.kept[0].units(), set(&[0, 1]));

    let mut r = Rng::new(0);
    let (mut unsettled, mut wrong, mut unjudged, mut control) = (0, 0, 0, 0);
    let n = 300;
    for _ in 0..n {
        let syncs = random_syncs(&mut r);
        match random_net(&mut r.clone(), Rules::DESIGN, syncs.clone(), true, &|_| {}) {
            None => unsettled += 1,
            Some((w, res)) => {
                unjudged += (res > 0) as usize;
                wrong += (!w.is_empty() && res == 0) as usize
            }
        }
        control += random_net(&mut r.clone(), Rules::DESIGN, syncs, true, &|n| n.deletes = false).is_none_or(|(w, _)| !w.is_empty()) as usize;
        r.next();
    }
    assert_eq!((unsettled, wrong), (0, 0));
    assert!(unjudged > 0 && control > 0, "{unjudged} {control}");
    eprintln!("p5 random of {n}: unsettled {unsettled}, wrong {wrong}, ending with a blob no writer judges {unjudged}; control {control}");
}

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
        assert_eq!(net.kept[0].units(), set(&[0, 1, 2]));
        net.write(rm(0, &[3]));
        net.deliver_all();
        net.settle(20, count).unwrap();
        assert_eq!(net.kept[0].units() == set(&[0]), !count, "count {count}");
        assert_eq!(net.wrong().is_empty(), !count);
    }
}
