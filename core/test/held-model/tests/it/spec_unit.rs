//! The sync unit as one independent thing and the dependents it reaches, held_model::unit: each
//! test names the property of notes/closure-model.md (The unit model) it checks and its negative
//! control. Where a rule of the design fails a property the test asserts the smallest world, so the
//! finding stays visible and checked; counts print with `--nocapture`.
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
    Commit { on, op: Op::Add { to, home: None }, side: None }
}
fn addh(on: T, to: T, home: T) -> Commit {
    Commit { on, op: Op::Add { to, home: Some(home) }, side: None }
}
fn role(on: T, holder: T, r: Option<Role>) -> Commit {
    Commit { on, op: Op::Role(holder, r), side: None }
}
fn rm(on: T, dots: &[Dot]) -> Commit {
    Commit { on, op: Op::Remove(dots.iter().copied().collect()), side: None }
}
fn rotate(on: T) -> Commit {
    Commit { on, op: Op::Rotate, side: None }
}
fn sided(c: Commit, s: u8) -> Commit {
    Commit { side: Some(s), ..c }
}
fn subsets<X: Copy>(of: &[X]) -> Vec<Vec<X>> {
    (0..1u32 << of.len()).map(|m| of.iter().enumerate().filter(|(i, _)| m & (1 << i) != 0).map(|(_, x)| *x).collect()).collect()
}
fn ind(kinds: &[Kind], mut x: T) -> T {
    while let Kind::Dependent(a) = kinds[x] {
        x = a;
    }
    x
}
/// A static world: one role commit per grant `(holder, target, role)`, one add per strong, a
/// strong to a dependent thing carrying its independent as home (its writer held the target).
fn world(kinds: &[Kind], grants: &[(T, T, Role)], strongs: &[(T, T)]) -> Vec<Commit> {
    let home = |to: T| (kinds[to] != K).then(|| ind(kinds, to));
    grants
        .iter()
        .map(|&(g, t, r)| role(t, g, Some(r)))
        .chain(strongs.iter().map(|&(x, y)| Commit { on: x, op: Op::Add { to: y, home: home(y) }, side: None }))
        .collect()
}
fn with(r: Rules, f: impl FnOnce(&mut Rules)) -> Rules {
    let mut r = r;
    f(&mut r);
    r
}
fn handle_blobs(bs: &[Blob]) -> Set {
    bs.iter().filter_map(|b| if let Blob::Handle(x) = b { Some(*x) } else { None }).collect()
}

/// What a reader of `g` that also reads the units `extra` holds: the commits carried under them.
fn seen(kinds: &[Kind], cs: &[Commit], g: T, extra: &[T], unit: Unit) -> View {
    let t = View::all(kinds, cs, unit);
    let mut units: Set = extra.iter().copied().collect();
    units.insert(g);
    let known: BTreeSet<C> = (0..cs.len()).filter(|&c| !t.under(&cs[c]).is_disjoint(&units)).collect();
    View::of(kinds, cs, &known, unit)
}

// ---- The small family and random static worlds ----

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
    world(&KINDS, &grants, &strongs)
}
/// 3^6 grant sets times 2^8 strong sets.
const FAMILY: usize = 729 << CAND.len();

/// Runs `f` on every `step`-th world of the family, a thread per core, summing its counts. The
/// family index is grants * 256 + strongs, so a step sharing a factor with 2 or 3 would sample
/// only some strong sets or grant sets.
fn over_family<const N: usize>(step: usize, f: impl Fn(&[Commit]) -> [usize; N] + Sync) -> [usize; N] {
    assert!(step % 2 != 0 && step % 3 != 0, "a step sharing a factor with the family's 2^8 * 3^6 aliases it");
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

/// 4 independent and 4 dependent things, random grants among the independent ones (with
/// `dep_holders` also held by dependent things) and strongs.
fn random_static(r: &mut Rng, dep_holders: bool) -> (Vec<Kind>, Vec<Commit>) {
    let mut kinds = vec![K, K, K, K];
    for i in 4..8 {
        kinds.push(d(r.below(i as u64) as T));
    }
    let mut grants = vec![];
    for a in 0..if dep_holders { 8 } else { 4 } {
        for b in 0..4 {
            if a != b && r.chance(30) {
                grants.push((a, b, if r.chance(50) { Role::Sync } else { Role::Read }));
            }
        }
    }
    let strongs: Vec<(T, T)> = (0..r.below(10) + 2).map(|_| (r.below(8) as T, r.below(8) as T)).collect();
    let cs = world(&kinds, &grants, &strongs);
    (kinds, cs)
}

// ---- The unit by reach ----

/// For one world: whether every reader of each unit G, whatever other units it reads, computes
/// the same unit, the same targets, and the same targets cut by G's roles (`Member::Role`).
fn p1_world(kinds: &[Kind], cs: &[Commit], unit: Unit) -> [bool; 3] {
    let t = View::all(kinds, cs, unit);
    let ind: Vec<T> = t.units().into_iter().collect();
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

/// P1 over every 7th world of the small family (all of it in the ignored twin) and 600 random
/// worlds: every reader of G computes the
/// same unit and the same targets whatever else it reads. Controls: the unit by reach from every
/// strong the node holds (`Unit::Held`) fails the unit; targets cut to those G holds a role on
/// (`Member::Role`) fail the targets.
fn p1_row(kinds: &[Kind], cs: &[Commit]) -> [usize; 5] {
    let [u, t, tr] = p1_world(kinds, cs, Unit::Reach);
    let [uh, th, _] = p1_world(kinds, cs, Unit::Held);
    [!u, !t, !uh, !th, !tr].map(|b| b as usize)
}

#[test]
fn p1_readers_compute_one_unit_and_one_target_list() {
    let fails = over_family(7, |cs| p1_row(&KINDS, cs));
    let mut r = Rng::new(0);
    let mut rand = [0; 5];
    for _ in 0..600 {
        let (kinds, cs) = random_static(&mut r, false);
        for (a, x) in rand.iter_mut().zip(p1_row(&kinds, &cs)) {
            *a += x;
        }
    }
    for f in [fails, rand] {
        assert_eq!(f[..2], [0; 2], "{f:?}");
        assert!(f[2] > 0 && f[4] > 0, "controls must fail: {f:?}");
    }
    // The control's smallest world: 0 holds sync on 1, 1 on 2, 0 -> 2. 1's grant on 2 travels
    // under S(1) and S(2), so a reader of 0 alone cuts 2 and one also reading 1 keeps it.
    let cs = world(&[K, K, K], &[(0, 1, Role::Sync), (1, 2, Role::Sync)], &[(0, 2)]);
    assert_eq!(p1_world(&[K, K, K], &cs, Unit::Reach), [true, true, false]);
    eprintln!("p1 failing (unit, targets) by reach, (unit, targets) Held, targets Role: family 1/7 of {FAMILY} {fails:?}, random of 600 {rand:?}");
}

#[test]
#[ignore]
fn p1_readers_compute_one_unit_and_one_target_list_full() {
    let f = over_family(1, |cs| p1_row(&KINDS, cs));
    assert_eq!(f[..2], [0; 2], "{f:?}");
    assert!(f[2] > 0 && f[4] > 0, "controls must fail: {f:?}");
    eprintln!("p1 family of {FAMILY}: {f:?}");
}

/// Release (§6): H -> X -> K, X a dependent of H, H holding sync on K. Removing H -> X takes X's
/// entries out of S(H), K's handle out, and K out of the keeper of H (K's key stays: the grant
/// stands). Controls: `Unit::All` keeps all three for good; `Unit::Held`, with a second writer of
/// S(H) syncing a unit whose strong targets X, never settles (they log and delete X's entries).
#[test]
fn unit_by_reach_releases_a_dependent_and_what_only_it_listed() {
    let kinds = vec![K, d(0), K, K];
    for (unit, released) in [(Unit::Reach, true), (Unit::All, false)] {
        let mut net = Net::new(kinds.clone(), with(Rules::DESIGN, |r| r.unit = unit), &[(set(&[0]), 0)], &[(set(&[0]), 0, false)]);
        for c in [role(2, 0, Some(Role::Sync)), add(0, 1), add(1, 2)] {
            net.author(0, c);
        }
        net.settle(20, false).unwrap();
        assert_eq!(net.keepers[0].kept.units(), set(&[0, 2]));
        assert!(net.entries.contains(&(0, 2)));
        net.author(0, rm(0, &[(1, 1)]));
        net.settle(20, false).unwrap();
        assert!(net.wrong().is_empty(), "{:?}", net.wrong());
        assert_eq!(net.entries.contains(&(0, 2)), !released, "{unit:?}");
        assert_eq!(handle_blobs(&net.listed(0)).is_empty(), released, "{unit:?}");
        assert_eq!(net.keepers[0].kept.units(), if released { set(&[0]) } else { set(&[0, 2]) }, "{unit:?}");
    }
    let mut net = Net::new(kinds, with(Rules::DESIGN, |r| r.unit = Unit::Held), &[(set(&[0]), 0), (set(&[0, 3]), 0)], &[]);
    for c in [role(2, 0, Some(Role::Sync)), add(3, 1), add(1, 2)] {
        net.write(c);
    }
    net.deliver_all();
    assert_eq!(net.settle(20, false), None, "two honest writers of S(0) undo each other for good");
}

/// Release by reachability (P3): 0 lists 1, 1 and 2 list each other; removing 0 -> 1 releases 1
/// and 2 at the keeper. Control: a unit kept while a kept unit lists it keeps the cycle for good.
#[test]
fn p3_detached_cycle_is_released() {
    for count in [false, true] {
        let mut net = Net::new(vec![K, K, K], Rules::DESIGN, &[(set(&[0, 1, 2]), 0)], &[(set(&[0]), 0, false)]);
        for c in [role(1, 0, Some(Role::Sync)), role(2, 1, Some(Role::Sync)), role(1, 2, Some(Role::Sync)), add(0, 1), add(1, 2), add(2, 1)] {
            net.author(0, c);
        }
        net.settle(20, count).unwrap();
        assert_eq!(net.keepers[0].kept.units(), set(&[0, 1, 2]));
        net.author(0, rm(0, &[(3, 1)]));
        net.settle(20, count).unwrap();
        assert_eq!(net.keepers[0].kept.units() == set(&[0]), !count, "count {count}");
        assert_eq!(net.wrong().is_empty(), !count);
    }
}

// ---- The join's static claim ----

/// The walk from 0 over blobs each unit's own reader computes (`homes` off: strongs carry none).
fn join_own(kinds: &[Kind], cs: &[Commit], homes: bool) -> Set {
    let t = View::all(kinds, cs, Unit::Reach);
    let blobs = |g: T| blobs_of(&seen(kinds, cs, g, &[], Unit::Reach), g, Member::Target, homes);
    walk(&t, false, &set(&[0]), &blobs, Walk::DESIGN).units()
}

/// An oracle written from the truth alone, not from blobs: the least set holding 0 and each unit
/// that carries the target of a live strong from an entered unit and on whose step an entered
/// unit is.
fn oracle(t: &View) -> Set {
    let mut e = set(&[0]);
    loop {
        let mut n = set(&[0]);
        for &(a, x) in t.strongs.keys() {
            if let (Some(g), Some(h)) = (t.in_unit[a], t.in_unit[x]) {
                if g != h && e.contains(&g) && e.iter().any(|&w| w != h && t.on_step(w, h)) {
                    n.insert(h);
                }
            }
        }
        if n == e {
            return e;
        }
        e = n;
    }
}

/// For one world (failures, except the last two counts): 0 every reader of a unit, whatever else
/// it reads, computes its handle and key blobs alike; 1 the walk over blobs each computed by a
/// reader of its unit alone equals the walk over everything written; 2 with homes counted only
/// where the home's unit carries the target it enters exactly what the oracle enters; 3 it enters
/// every unit the oracle enters; 4 (count) it enters more: a home whose unit dropped the target;
/// 5 (count) without homes it enters less.
fn join_world(kinds: &[Kind], cs: &[Commit]) -> [usize; 6] {
    let t = View::all(kinds, cs, Unit::Reach);
    let ind: Vec<T> = t.independents().into_iter().collect();
    let mut alike = true;
    for &g in &ind {
        let others: Vec<T> = ind.iter().copied().filter(|&x| x != g).collect();
        for x in subsets(&others) {
            let v = seen(kinds, cs, g, &x, Unit::Reach);
            alike &= blobs_of(&v, g, Member::Target, true) == blobs_of(&t, g, Member::Target, true);
        }
    }
    let own = join_own(kinds, cs, true);
    let truth = walk(&t, false, &set(&[0]), &|g| blobs_of(&t, g, Member::Target, true), Walk::DESIGN).units();
    let carried = |g: T| -> Vec<Blob> {
        let targets = t.targets(g, Member::Target);
        blobs_of(&t, g, Member::Target, true)
            .into_iter()
            .filter(|b| match b {
                Blob::Handle(h) => targets.iter().any(|&x| t.in_unit[x] == Some(*h)),
                Blob::Key(_) => true,
            })
            .collect()
    };
    let reach = walk(&t, false, &set(&[0]), &carried, Walk::DESIGN).units();
    let o = oracle(&t);
    let bare = join_own(kinds, cs, false);
    assert!(bare.is_subset(&own));
    let n = |x: bool| !x as usize;
    [n(alike), n(own == truth), n(reach == o), n(own.is_superset(&o)), (own != o) as usize, (bare != own) as usize]
}

fn join_asserts(f: &[usize; 6]) {
    assert_eq!(f[0..4], [0; 4], "{f:?}");
    assert!(f[4] > 0 && f[5] > 0, "{f:?}");
}

/// The join's static claim over every 7th world of the family and 600 random worlds: what a unit
/// lists and which keys it holds are functions of what any reader of that unit holds, and the
/// walk over them enters what the oracle enters (see `join_world`).
#[test]
fn join_any_reader_of_a_unit_computes_its_blobs_and_the_walk_is_one() {
    let f = over_family(7, |cs| join_world(&KINDS, cs));
    join_asserts(&f);
    eprintln!("join family 1/7 of {FAMILY}: {f:?}");
    let mut r = Rng::new(0);
    let mut g = [0; 6];
    for _ in 0..600 {
        let (kinds, cs) = random_static(&mut r, false);
        for (a, x) in g.iter_mut().zip(join_world(&kinds, &cs)) {
            *a += x;
        }
    }
    join_asserts(&g);
    eprintln!("join random of 600: {g:?}");
}

#[test]
#[ignore]
fn join_any_reader_of_a_unit_computes_its_blobs_and_the_walk_is_one_full() {
    let f = over_family(1, |cs| join_world(&KINDS, cs));
    join_asserts(&f);
    eprintln!("join family of {FAMILY}: {f:?}");
}

/// The worlds the reading the join replaces failed, under the join, each unit's blobs by a reader
/// of it alone.
#[test]
fn join_on_the_finding_worlds() {
    let k3 = [K, K, K];
    // A node keeping 0 unread reaches what only a reader of 0 could name: 0 reads 1 and 2,
    // 0 -> 1 -> 2. S(1) lists 2's handle, S(0) holds 2's key.
    let a = world(&k3, &[(0, 1, Role::Read), (0, 2, Role::Read)], &[(0, 1), (1, 2)]);
    assert_eq!(join_own(&k3, &a, true), set(&[0, 1, 2]));
    // The requirement's second clause: 1 alone, holding no role on 2, keeps no 2.
    let t = View::all(&k3, &a, Unit::Reach);
    assert_eq!(walk(&t, false, &set(&[1]), &|g| blobs_of(&t, g, Member::Target, true), Walk::DESIGN).units(), set(&[1]));
    // No history: 0 -> 1, 0 -> 2, 0 sync on 1, 1 sync on 2; 0's grant on 2 given and removed, or
    // never given: the same blobs and the same walk (2 by 1's key).
    let never = world(&k3, &[(0, 1, Role::Sync), (1, 2, Role::Sync)], &[(0, 1), (0, 2)]);
    let mut given = never.clone();
    given.push(role(2, 0, Some(Role::Sync)));
    assert_eq!(seen(&k3, &given, 0, &[], Unit::Reach).keys(0), BTreeSet::from([(1, 1), (2, 2)]));
    given.push(role(2, 0, None));
    for g in 0..3 {
        let (x, y) = (seen(&k3, &never, g, &[], Unit::Reach), seen(&k3, &given, g, &[], Unit::Reach));
        assert_eq!(blobs_of(&x, g, Member::Target, true), blobs_of(&y, g, Member::Target, true));
    }
    assert_eq!(join_own(&k3, &given, true), set(&[0, 1, 2]));
    // A strong to a dependent thing brings its unit by its home, whether or not the unit reaches
    // the target: 0 reads 1, 3 a dependent of 1; a strong with no home brings nothing.
    let kd = [K, K, K, d(1)];
    for reached in [false, true] {
        let strongs: &[(T, T)] = if reached { &[(0, 3), (1, 3)] } else { &[(0, 3)] };
        let b = world(&kd, &[(0, 1, Role::Read)], strongs);
        assert_eq!(join_own(&kd, &b, true), set(&[0, 1]));
        assert_eq!(join_own(&kd, &b, false), set(&[0]));
    }
    // A role through a holder outside the closure does not count (notes/sync-unit-scope.md, a role through a holder nothing references; rule
    // 1): 0 holds sync on 1, 1 on 2, 0 -> 2.
    let c = world(&k3, &[(0, 1, Role::Sync), (1, 2, Role::Sync)], &[(0, 2)]);
    assert_eq!(join_own(&k3, &c, true), set(&[0]));
    // 0 reads 1 and 3, 3 reads 2, 0 -> 1 -> 2: 3 is not referenced, so 2 is not entered.
    let k4 = [K, K, K, K];
    let dw = world(&k4, &[(0, 1, Role::Read), (0, 3, Role::Read), (3, 2, Role::Read)], &[(0, 1), (1, 2)]);
    assert_eq!(join_own(&k4, &dw, true), set(&[0, 1]));
}

// ---- Readers and keepers: one walk, secrets only through entered units ----

/// The honest blobs of S(g) with a key for each unit `g` holds a role on by any chain (a control).
fn chain_blobs(t: &View, g: T) -> Vec<Blob> {
    let mut out: Vec<Blob> = t.handles(g, Member::Target, true).into_iter().map(Blob::Handle).collect();
    out.extend(t.roles_from(g).into_keys().filter(|&x| x != g).map(|x| Blob::Key(Key { of: x, names: x, cred: None })));
    out
}

const P2_COLS: usize = 8;
/// The reader of 0 and the keeper of 0 over the honest blobs, for one world (failures, except the
/// count): 0 P2, the keeper enters exactly the units the reader enters; 1 P2b, the reader reads
/// exactly the units it entered that 0 holds read on through chains whose holders are units it
/// entered; 2 every unit entered is on such a chain; 3 (count) 0's role over any chain on a
/// referenced unit exceeds that; 4-5 keeper controls (handles cut to what the referrer holds a
/// role on, stopping at a unit kept unread): P2; 6 the reader by depth-free secrets and a key per
/// chain: 2; 7 the reader against 0's role over any chain.
fn p2_world(kinds: &[Kind], cs: &[Commit]) -> [usize; P2_COLS] {
    let t = View::all(kinds, cs, Unit::Reach);
    let blobs = |g: T| blobs_of(&t, g, Member::Target, true);
    let rd = walk(&t, true, &set(&[0]), &blobs, Walk::DESIGN);
    let kp = walk(&t, false, &set(&[0]), &blobs, Walk::DESIGN);
    let units = rd.units();
    let oracle = t.roles_through(0, &|a| units.contains(&t.ind(a)));
    let p2 = kp.units() == units;
    let p2b = units.iter().all(|h| rd.read.contains(h) == oracle.get(h).is_some_and(|&x| x >= Role::Read));
    let inside = |e: &Entered| e.units().iter().all(|h| oracle.contains_key(h));
    let full = t.roles_from(0);
    let referenced: Set = units.iter().flat_map(|&g| t.targets(g, Member::Target)).map(|x| t.ind(x)).filter(|&h| h != 0).collect();
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
    let keeper = |b: &dyn Fn(T) -> Vec<Blob>, w: Walk| walk(&t, false, &set(&[0]), b, w).units() != units;
    let c_role = keeper(&|g| blobs_of(&t, g, Member::Role, true), Walk::DESIGN);
    let c_stop = keeper(&blobs, Walk { follow_unread: false, ..Walk::DESIGN });
    let deep = walk(&t, true, &set(&[0]), &|g| chain_blobs(&t, g), Walk { enter: Enter::Deep, ..Walk::DESIGN });
    let n = |x: bool| !x as usize;
    [n(p2), n(p2b), n(inside(&rd)), exceeds as usize, c_role as usize, c_stop as usize, n(inside(&deep)), n(any)]
}

fn p2_asserts(f: &[usize; P2_COLS]) {
    assert_eq!(f[0..3], [0; 3], "{f:?}");
    assert!(f[4..7].iter().all(|&x| x > 0), "controls must fail: {f:?}");
    // The rule of §4: a role through a holder outside the closure does not count.
    assert!(f[3] > 0 && f[7] > 0, "{f:?}");
}

/// P2 and P2b over every 7th world of the family (all of it in the ignored twin) and 600 random
/// worlds: the keeper and the reader of a root walk alike and read only by the closure.
#[test]
fn p2_keeper_enters_what_a_reader_enters() {
    let f = over_family(7, |cs| p2_world(&KINDS, cs));
    p2_asserts(&f);
    let mut r = Rng::new(0);
    let mut g = [0; P2_COLS];
    for _ in 0..600 {
        let (kinds, cs) = random_static(&mut r, false);
        for (a, x) in g.iter_mut().zip(p2_world(&kinds, &cs)) {
            *a += x;
        }
    }
    p2_asserts(&g);
    eprintln!("p2 family 1/7 of {FAMILY}: {f:?}; random of 600: {g:?}");
}

#[test]
#[ignore]
fn p2_keeper_enters_what_a_reader_enters_full() {
    let f = over_family(1, |cs| p2_world(&KINDS, cs));
    p2_asserts(&f);
    eprintln!("p2 family of {FAMILY}: {f:?}");
}

/// The smallest chain-exceeds world: 0 reads 1, 1 reads 2, 0 -> 2, nothing references 1. 2's step
/// lists 1, whose secret the node does not hold: 2 is not entered, read or unread. The control (a
/// key per chain, depth-free secrets) keeps it unread through 1 unentered. A strong 0 -> 1 brings 1
/// in and 2 is read.
#[test]
fn p2_a_unit_reached_through_a_holder_outside_the_closure() {
    let k3 = [K, K, K];
    let cs = world(&k3, &[(0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2)]);
    let t = View::all(&k3, &cs, Unit::Reach);
    let blobs = |g: T| blobs_of(&t, g, Member::Target, true);
    assert_eq!(walk(&t, true, &set(&[0]), &blobs, Walk::DESIGN).units(), set(&[0]));
    assert_eq!(walk(&t, true, &set(&[0]), &|g| chain_blobs(&t, g), Walk { enter: Enter::Deep, ..Walk::DESIGN }).unread, set(&[2]));
    assert_eq!(walk(&t, true, &set(&[0]), &|g| chain_blobs(&t, g), Walk::DESIGN).units(), set(&[0]));
    let cs2 = world(&k3, &[(0, 1, Role::Read), (1, 2, Role::Read)], &[(0, 2), (0, 1)]);
    let t2 = View::all(&k3, &cs2, Unit::Reach);
    assert_eq!(walk(&t2, true, &set(&[0]), &|g| blobs_of(&t2, g, Member::Target, true), Walk::DESIGN).read, set(&[0, 1, 2]));
}

/// Item 5, the assumption that a holder of K's sync secret holds the sync-role key of a dependent
/// of K that a target's step lists. A dependent holds a grant with key access only after its
/// keyset part turned invalid (spec/permissions.md §3). World: 0, its dependent 1 reached from 0,
/// 1 holding sync on 2, 0 -> 2. S(0) holds 2's key (1 is of 0's unit) and 2's step lists 1. A
/// reader of 0 knows 1's tid and derives its sync secret: it enters 2. A node keeping 0 unread
/// knows no tid of 0's dependents: it enters 2 only by the key's first credential, and loses it at
/// 2's first rotation (FAILS P2). With the grant held by 0 itself the keeper keeps 2 through the
/// rotation. Over 600 random worlds with dependent holders P2 fails, each time where a step
/// lists a dependent holder.
#[test]
fn p2_a_dependent_holder_is_entered_by_readers_alone() {
    let kinds = vec![K, d(0), K];
    for holder in [1, 0] {
        let mut net = Net::new(kinds.clone(), Rules::DESIGN, &[(set(&[0, 2]), 0)], &[(set(&[0]), 0, false), (set(&[0]), 0, true)]);
        for c in [add(0, 1), role(2, holder, Some(Role::Sync)), add(0, 2)] {
            net.author(0, c);
        }
        net.settle(20, false).unwrap();
        let t = net.truth(0);
        let no_cred = |g: T| blobs_of(&t, g, Member::Target, true);
        let keeper_bare = walk(&t, false, &set(&[0]), &no_cred, Walk::DESIGN).units();
        assert_eq!(keeper_bare, if holder == 1 { set(&[0]) } else { set(&[0, 2]) }, "holder {holder}");
        assert_eq!(walk(&t, true, &set(&[0]), &no_cred, Walk::DESIGN).units(), set(&[0, 2]));
        assert_eq!(net.keepers[0].kept.units(), set(&[0, 2]), "by the first credential");
        net.author(0, rotate(2));
        net.settle(20, false).unwrap();
        assert!(net.wrong().is_empty(), "{:?}", net.wrong());
        assert_eq!(net.keepers[1].kept.units(), set(&[0, 2]), "the reader keeps 2");
        assert_eq!(net.keepers[0].kept.units(), if holder == 1 { set(&[0]) } else { set(&[0, 2]) }, "holder {holder}");
    }
    let mut r = Rng::new(0);
    let (mut fails, mut by_dep) = (0, 0);
    for _ in 0..600 {
        let (kinds, cs) = random_static(&mut r, true);
        let t = View::all(&kinds, &cs, Unit::Reach);
        if p2_world(&kinds, &cs)[0] > 0 {
            fails += 1;
            by_dep += t.grants.keys().any(|&(h, _)| kinds[h] != K && t.in_unit[h].is_some()) as usize;
        }
    }
    assert!(fails > 0 && by_dep == fails, "{fails} {by_dep}");
    eprintln!("p2 with dependent holders, random of 600: keeper != reader in {fails}");
}

// ---- Stores and writers over time ----

/// One scenario, every schedule: `genesis` held by both writers and settled; then `moves` reaching
/// writers 0 and 1 in every order and interleaving, after each either the receiving writer
/// visiting its stores alone or every writer visiting together (both modes), every keeper passing;
/// then everything delivered and settled. Counts: schedules, unsettled, ending wrong, with a
/// single visit leaving a store off what its own entries give, and steps where the reader of 0 and
/// the keeper of 0 on side 0 differ.
fn every_order(kinds: &[Kind], writers: &[(Set, u8)], genesis: &[Commit], moves: &[Commit], rules: Rules, modes: &[bool]) -> [usize; 5] {
    let perms = permutations(moves.len());
    let ilv = interleavings(moves.len(), moves.len());
    let keepers = [(set(&[0]), 0, false), (set(&[0]), 0, true), (set(&[0]), 1, false)];
    let mut out = [0; 5];
    for &together in modes {
        for pa in &perms {
            for pb in &perms {
                for il in &ilv {
                    let mut net = Net::new(kinds.to_vec(), rules, writers, &keepers);
                    for c in genesis {
                        let c = net.write(c.clone());
                        net.deliver(0, c);
                        net.deliver(1, c);
                    }
                    net.settle(20, false).unwrap();
                    let base = net.commits.len();
                    for c in moves {
                        net.write(c.clone());
                    }
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
                        if together {
                            net.visit_together();
                        } else {
                            net.visit_all(who);
                        }
                        net.pass_all(false);
                        out[4] += (net.keepers[0].kept.units() != net.keepers[1].kept.units()) as usize;
                    }
                    net.deliver_all();
                    let settled = net.settle(20, false).is_some();
                    out[0] += 1;
                    out[1] += !settled as usize;
                    out[2] += (settled && !net.wrong().is_empty()) as usize;
                    out[3] += !net.off.is_empty() as usize;
                }
            }
        }
    }
    out
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

/// Items 1 and 2 (blobs at stores, writers with different holdings): writer 0 syncs 0 and 1,
/// writer 1 syncs 0 alone, so each holds what the other lacks while moves arrive; 3 is a dependent
/// of 1 that 1 reaches. Scenarios: attach an independent and a dependent (home 1) and detach the
/// first; a grant after the strong, its removal and a grant again; a cycle attached and its entry
/// detached; a remove racing a re-add; a fork, the two writers on two sides for good (a strong
/// both count, a grant side 0 counts, its removal side 1 counts). In every one of the 1440
/// schedules a scenario: settled, the stated end state, every single visit leaving the store
/// exactly what its own entries give, the reader and the keeper of 0 alike at every step.
/// Controls: judging before the pass leaves stores off what their entries give (transient, it
/// pulls after); deletes off ends wrong; a key logged only by a writer that syncs the target ends
/// wrong (no writer of S(0) syncs 2); each writer judging by its own side alone never settles.
#[test]
fn stores_judged_after_a_complete_pass_in_every_order() {
    let kinds = [K, K, K, d(1)];
    let writers = [(set(&[0, 1]), 0), (set(&[0]), 1)];
    let g = [role(1, 0, Some(Role::Sync)), role(2, 1, Some(Role::Sync)), role(1, 2, Some(Role::Sync)), add(1, 3)];
    let scenarios: Vec<(&str, Vec<Commit>, Vec<Commit>)> = vec![
        ("attach, detach", g.to_vec(), vec![add(0, 1), addh(0, 3, 1), rm(0, &[(4, 1)])]),
        ("grant, removal, grant", vec![add(0, 2)], vec![role(2, 0, Some(Role::Sync)), role(2, 0, None), role(2, 0, Some(Role::Read))]),
        ("cycle", [g.to_vec(), vec![add(0, 1)]].concat(), vec![add(1, 2), add(2, 1), rm(0, &[(4, 1)])]),
        ("re-add", g.to_vec(), vec![add(0, 1), rm(0, &[(4, 1)]), add(0, 1)]),
        ("fork", g.to_vec(), vec![add(0, 2), sided(role(2, 0, Some(Role::Sync)), 0), sided(role(2, 0, None), 1)]),
    ];
    for (name, gen, moves) in &scenarios {
        let f = every_order(&kinds, &writers, gen, moves, Rules::DESIGN, &[false, true]);
        assert_eq!(f, [1440, 0, 0, 0, 0], "{name}");
    }
    // Each control on the scenario it breaks, the receiving writer visiting alone (720 schedules).
    let controls: [(&str, Rules, usize); 4] = [
        ("judge before the pass", with(Rules::DESIGN, |r| r.pass = Pass::After), 0),
        ("deletes off", with(Rules::DESIGN, |r| r.deletes = false), 2),
        ("keys by target syncers", with(Rules::DESIGN, |r| r.keys_by_any = false), 1),
        ("own side", with(Rules::DESIGN, |r| r.any_side = false), 4),
    ];
    let ctl: Vec<[usize; 5]> = controls
        .iter()
        .map(|&(_, rules, i)| every_order(&kinds, &writers, &scenarios[i].1, &scenarios[i].2, rules, &[false]))
        .collect();
    assert!(ctl[0][3] > 0, "judging before the pass: {:?}", ctl[0]);
    assert!(ctl[1][2] > 0 && ctl[2][2] > 0, "{ctl:?}");
    assert!(ctl[3][1] > 0, "own side: {:?}", ctl[3]);
    eprintln!("controls (schedules, unsettled, wrong, off, reader != keeper steps): {:?}", controls.iter().map(|c| c.0).zip(ctl).collect::<Vec<_>>());
}

/// Two writers holding one strong visit S(0) at once and both log its handle: the lower ID stays.
/// Control: with no such rule both stay.
#[test]
fn of_two_alike_blobs_the_lower_id_stays() {
    for lowest_wins in [true, false] {
        let mut net = Net::new(vec![K, K], with(Rules::DESIGN, |r| r.lowest_wins = lowest_wins), &[(set(&[0]), 0), (set(&[0]), 0)], &[]);
        net.write(add(0, 1));
        net.deliver_all();
        net.visit_together();
        net.settle(20, false).unwrap();
        assert_eq!(net.listed(0).len(), if lowest_wins { 1 } else { 2 });
        assert_eq!(net.wrong().is_empty(), lowest_wins);
    }
}

/// Item 1's undo for good: two writers of S(0); writer 0 writes 0 -> 1 and logs it with its
/// handle; writer 1 judges by what peers handed it, never by what the store holds, and deletes the
/// handle at every visit while writer 0 logs it again. With a complete pass first, writer 1 holds
/// the strong before it judges.
#[test]
fn a_writer_judging_by_less_than_the_store_holds_undoes_another_for_good() {
    for (pass, settles) in [(Pass::First, true), (Pass::Never, false), (Pass::After, true)] {
        let mut net = Net::new(vec![K, K], with(Rules::DESIGN, |r| r.pass = pass), &[(set(&[0]), 0), (set(&[0]), 0)], &[]);
        net.author(0, add(0, 1));
        assert_eq!(net.settle(20, false).is_some(), settles, "{pass:?}");
    }
}

/// A random history over time: 4 independent and 2 dependent things, 2 or 3 writers syncing
/// random units, each writing only things it syncs (homes filled by `Net::home`), a reader and a
/// keeper of 0 on side 0 and a keeper of 0 on side 1; strongs added and removed, grants set and
/// removed, rotations, peer deliveries, single and simultaneous visits, keeper passes; with
/// `forks` a third of the commits valid on their writer's side alone; with `hostile` blobs forged
/// and deleted at random (a handle, a key naming any unit, or both; forged keys carry no
/// credential, a secret the forger does not hold). Then everything delivered and settled.
struct Run {
    settled: bool,
    wrong: bool,
    off: bool,
    /// Steps where the side-0 reader and keeper differ.
    split: usize,
    /// Passes where a keeper entered a unit outside every walk over all conceivable blobs.
    escaped: usize,
    /// Keepers lacking at the end a unit their own side's blobs give.
    side_loss: usize,
    net: Net,
}

fn random_net(r: &mut Rng, rules: Rules, walk_by: Walk, hostile: bool, forks: bool) -> Run {
    let kinds = vec![K, K, K, K, d(1), d(2)];
    let writers: Vec<(Set, u8)> = (0..2 + r.below(2))
        .map(|i| {
            let mut s: Set = (0..4).filter(|_| r.chance(50)).collect();
            s.insert(r.below(4) as T);
            (s, if forks { (i % 2) as u8 } else { 0 })
        })
        .collect();
    let mut net = Net::new(kinds, rules, &writers, &[(set(&[0]), 0, false), (set(&[0]), 0, true), (set(&[0]), 1, false)]);
    net.walk = walk_by;
    let (mut split, mut escaped) = (0, 0);
    for _ in 0..40 {
        let w = r.below(net.writers.len() as u64) as usize;
        let mine: Vec<T> = (0..6).filter(|&x| net.writers[w].syncs.contains(&ind(&net.kinds, x))).collect();
        let side = (forks && r.chance(33)).then_some(net.writers[w].side);
        match r.below(12) {
            0..=2 if !mine.is_empty() => {
                let (on, to) = (r.pick(&mine), r.below(6) as T);
                let home = net.home(w, to);
                net.author(w, Commit { on, op: Op::Add { to, home }, side });
            }
            3 if !mine.is_empty() => {
                let on = r.pick(&mine);
                let dots: Vec<Dot> = net.writers[w]
                    .has
                    .iter()
                    .filter_map(|&c| match net.commits[c].op {
                        Op::Add { to, .. } if net.commits[c].on == on => Some((c, to)),
                        _ => None,
                    })
                    .collect();
                if !dots.is_empty() {
                    net.author(w, Commit { side, ..rm(on, &[r.pick(&dots)]) });
                }
            }
            4 => {
                let mine: Vec<T> = net.writers[w].syncs.iter().copied().collect();
                let (t, a) = (r.pick(&mine), r.below(4) as T);
                if a != t {
                    let ro = [None, Some(Role::Sync), Some(Role::Read)][r.below(3) as usize];
                    net.author(w, Commit { side, ..role(t, a, ro) });
                    if ro.is_none() {
                        // The departure's required rotation: a first credential goes stale.
                        net.author(w, rotate(t));
                    }
                }
            }
            5 => {
                let mine: Vec<T> = net.writers[w].syncs.iter().copied().collect();
                net.author(w, rotate(r.pick(&mine)));
            }
            6 if !net.commits.is_empty() => {
                let c = r.below(net.commits.len() as u64) as C;
                net.deliver(w, c);
            }
            7 => {
                let g = r.pick(&net.writers[w].syncs.iter().copied().collect::<Vec<_>>());
                net.visit(w, g);
            }
            8 => net.visit_together(),
            9 | 10 if hostile => forge(r, &mut net),
            _ => {}
        }
        net.pass_all(false);
        split += (net.keepers[0].kept.units() != net.keepers[1].kept.units()) as usize;
        escaped += escapes(&net);
    }
    net.deliver_all();
    let settled = net.settle(40, false).is_some();
    let side_loss = (0..net.keepers.len())
        .filter(|&k| {
            let kp = &net.keepers[k];
            let t = net.truth(kp.side);
            let own = walk(&t, kp.reads, &net.roots(k), &|g| blobs_of(&t, g, Member::Target, true), Walk::DESIGN).units();
            let synced = own.iter().all(|&g| net.writers.iter().any(|w| w.syncs.contains(&g)));
            synced && !own.is_subset(&kp.kept.units())
        })
        .count();
    Run { settled, wrong: !net.wrong().is_empty(), off: !net.off.is_empty(), split, escaped, side_loss, net }
}
fn forge(r: &mut Rng, net: &mut Net) {
    let g = r.below(4) as T;
    let here: Vec<(T, usize)> = net.store.keys().copied().filter(|k| k.0 == g).collect();
    if r.chance(40) && !here.is_empty() {
        net.store.remove(&r.pick(&here));
    } else {
        // A handle, a key, or both for one thing (a key naming any unit).
        let (x, pick) = (r.below(6) as T, r.below(3));
        let mut bs = vec![];
        if pick != 1 {
            bs.push(Blob::Handle(x));
        }
        if pick != 0 {
            bs.push(Blob::Key(Key { of: x, names: r.below(4) as T, cred: None }));
        }
        for b in bs {
            net.store.insert((g, net.next_id), b);
            net.next_id += 1;
        }
    }
}
/// Keepers that entered a unit outside the walk over every handle and every key in every unit
/// (and the credentials honest writers stored): what no forged blob can make a node enter (only a
/// unit whose step lists a thing whose secret it holds through units it entered, or whose secret
/// an honest writer handed it).
fn escapes(net: &Net) -> usize {
    let all = |g: T| -> Vec<Blob> {
        let mut v: Vec<Blob> = (0..net.kinds.len()).flat_map(|x| [Blob::Handle(x), Blob::Key(Key { of: x, names: x, cred: None })]).collect();
        v.extend(net.listed(g));
        v
    };
    (0..net.keepers.len())
        .filter(|&k| {
            let kp = &net.keepers[k];
            let t = net.truth(kp.side);
            let bound = walk(&t, kp.reads, &net.roots(k), &all, Walk::DESIGN).units();
            !kp.kept.units().is_subset(&bound)
        })
        .count()
}

fn tally(runs: impl Iterator<Item = Run>) -> [usize; 6] {
    let mut f = [0; 6];
    for x in runs {
        f[0] += !x.settled as usize;
        f[1] += (x.settled && x.wrong) as usize;
        f[2] += x.off as usize;
        f[3] += x.split;
        f[4] += x.escaped;
        f[5] += x.side_loss;
    }
    f
}

/// Items 1, 2, 4 and 5 over 300 random histories each: plain, forked, hostile, forked and
/// hostile. Every run settles (no two honest writers undo each other), ends in the stated end
/// state at every unit a writer syncs (a forgery or deletion repaired by whichever writer visits),
/// every single visit leaves the store exactly what its own entries give (so the next honest
/// writer of a unit repairs any forgery), the reader and the keeper of 0 enter alike after every
/// step, no keeper enters a unit outside the bound forged blobs allow, and no keeper ends without
/// a unit its own side's blobs give. Controls: deletes off ends wrong (hostile); entering with no
/// secret escapes the bound (hostile); each writer judging by its own side never settles or ends
/// wrong (forked); judging before the pass leaves stores off.
#[test]
fn random_histories_settle_on_the_stores_own_commits() {
    let n = 300;
    let mut rows = vec![];
    for (hostile, forks) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut r = Rng::new(0);
        let seeds: Vec<Rng> = (0..n).map(|_| {
            r.next();
            r.clone()
        }).collect();
        let f = tally(seeds.iter().map(|s| random_net(&mut s.clone(), Rules::DESIGN, Walk::DESIGN, hostile, forks)));
        assert_eq!(f, [0; 6], "hostile {hostile} forks {forks}");
        // Each control on the configuration it breaks.
        let ctl = |rules: Rules, w: Walk| tally(seeds.iter().map(|s| random_net(&mut s.clone(), rules, w, hostile, forks)));
        let (none, mut c) = ([0; 6], [[0; 6]; 4]);
        if hostile && !forks {
            c[0] = ctl(with(Rules::DESIGN, |r| r.deletes = false), Walk::DESIGN);
            c[1] = ctl(Rules::DESIGN, Walk { enter: Enter::Free, ..Walk::DESIGN });
            assert!(c[0][1] > 0, "deletes off: {:?}", c[0]);
            assert!(c[1][4] > 0, "entering with no secret: {:?}", c[1]);
        }
        if forks && !hostile {
            c[2] = ctl(with(Rules::DESIGN, |r| r.any_side = false), Walk::DESIGN);
            assert!(c[2][0] + c[2][1] > 0, "own side: {:?}", c[2]);
        }
        if !forks && !hostile {
            c[3] = ctl(with(Rules::DESIGN, |r| r.pass = Pass::After), Walk::DESIGN);
            assert!(c[3][2] > 0, "judge before the pass: {:?}", c[3]);
        }
        rows.push((hostile, forks, c.map(|x| if x == none { None } else { Some(x) })));
    }
    eprintln!("random of {n} (unsettled, wrong, off, split steps, escapes, side losses) per (hostile, forks): controls deletes off, entering with no secret, own side, judge before the pass: {rows:?}");
}

/// No history (item 3 of the list): a settled random history ends with the same blobs at every
/// synced store and the same keepers as a history writing only its end state (live strongs with
/// their homes, standing grants). Control: deletes off keeps what history left.
#[test]
fn the_end_state_alone_decides_the_blobs() {
    let mut r = Rng::new(0);
    let (mut differ, mut ctl) = (0, 0);
    for _ in 0..200 {
        for (deletes, count) in [(true, &mut differ), (false, &mut ctl)] {
            let rules = with(Rules::DESIGN, |x| x.deletes = deletes);
            let run = random_net(&mut r.clone(), rules, Walk::DESIGN, false, false);
            let net = run.net;
            let t = net.truth(0);
            let ws: Vec<(Set, u8)> = net.writers.iter().map(|w| (w.syncs.clone(), 0)).collect();
            let ks: Vec<(Set, u8, bool)> = net.keepers.iter().map(|k| (k.roots.clone(), k.side, k.reads)).collect();
            let mut fresh = Net::new(net.kinds.clone(), rules, &ws, &ks);
            for (&(a, b), hs) in &t.strongs {
                if hs.is_empty() {
                    fresh.write(add(a, b));
                }
                for &h in hs {
                    fresh.write(addh(a, b, h));
                }
            }
            for (&(g, x), &ro) in &t.grants {
                fresh.write(role(x, g, Some(ro)));
            }
            fresh.deliver_all();
            fresh.settle(40, false).unwrap();
            let strip = |n: &Net, g: T| -> Vec<Blob> {
                let mut v: Vec<Blob> = n.listed(g).into_iter().map(|b| if let Blob::Key(k) = b { Blob::Key(Key { cred: None, ..k }) } else { b }).collect();
                v.sort();
                v
            };
            let same = (0..4).all(|g| strip(&net, g) == strip(&fresh, g))
                && net.keepers.iter().zip(&fresh.keepers).all(|(a, b)| a.kept == b.kept);
            *count += !same as usize;
        }
        r.next();
    }
    assert_eq!(differ, 0);
    assert!(ctl > 0, "control must differ");
    eprintln!("no history over 200: differ {differ}; deletes off {ctl}");
}

// ---- Homes ----

/// A home lives as long as its dot, not its strong: writer 0 (syncing 0 and 1, holding 2 as a
/// dependent of 1) adds 0 -> 2 with home 1; writer 1 (syncing 0 alone, never having held 2 or
/// writer 0's add) adds 0 -> 2 from a bare tid, with no home; writer 0 removes its own dot. The
/// value 0 -> 2 stands throughout, and 1's unit leaves the closure (FAILS "a home lives exactly as
/// long as its strong"; within the bare-ID corner of notes/sync-unit-scope.md, the bare-tid write). Had
/// writer 1 held writer 0's add, it would have copied the home and 1's unit would stay.
#[test]
fn a_home_lives_with_its_dot() {
    for copies in [false, true] {
        let kinds = vec![K, K, d(1)];
        let mut net = Net::new(kinds, Rules::DESIGN, &[(set(&[0, 1]), 0), (set(&[0]), 0)], &[(set(&[0]), 0, false)]);
        net.author(0, role(1, 0, Some(Role::Sync)));
        net.author(0, add(1, 2));
        let h = net.home(0, 2);
        assert_eq!(h, Some(1));
        let a = net.author(0, Commit { on: 0, op: Op::Add { to: 2, home: h }, side: None });
        if copies {
            net.writers[1].has.insert(a);
        }
        let h1 = net.home(1, 2);
        assert_eq!(h1, copies.then_some(1));
        net.author(1, Commit { on: 0, op: Op::Add { to: 2, home: h1 }, side: None });
        net.settle(20, false).unwrap();
        assert_eq!(net.keepers[0].kept.units(), set(&[0, 1]));
        net.author(0, rm(0, &[(a, 2)]));
        net.settle(20, false).unwrap();
        assert!(net.wrong().is_empty());
        assert!(net.truth(0).strongs.contains_key(&(0, 2)), "the strong stands");
        assert_eq!(net.keepers[0].kept.units(), if copies { set(&[0, 1]) } else { set(&[0]) }, "copies {copies}");
    }
}

/// A snapshot carries on each kept dot with its home: over 300 random histories of one thing's
/// strongs (adds with and without homes, removes, covers by a writer holding all of them), a
/// cover changes no handle or home. Control: a cover keeping the values without homes changes
/// them. The fill rule reads held history: a node that once held the homed add, removed and then
/// covered, re-adds from a bare tid with no home; holding the removed add uncovered, with it.
#[test]
fn a_cover_carries_on_the_homes() {
    let kinds = vec![K, K, K, d(1), d(2)];
    let mut r = Rng::new(0);
    let (mut changed, mut ctl) = (0, 0);
    for _ in 0..300 {
        for keep_homes in [true, false] {
            let mut cs: Vec<Commit> = vec![role(1, 0, Some(Role::Sync)), role(2, 0, Some(Role::Sync)), add(1, 3), add(2, 4)];
            for _ in 0..8 {
                let t = View::all(&kinds, &cs, Unit::Reach);
                match r.below(3) {
                    0 => {
                        let to = 1 + r.below(4) as T;
                        cs.push(if r.chance(50) { add(0, to) } else { addh(0, to, ind(&kinds, to)) });
                    }
                    1 => {
                        let dots: Vec<Dot> = (0..cs.len()).filter_map(|c| if let Op::Add { to, .. } = cs[c].op { (cs[c].on == 0).then_some((c, to)) } else { None }).collect();
                        if !dots.is_empty() {
                            cs.push(rm(0, &[r.pick(&dots)]));
                        }
                    }
                    _ => {
                        let covers: BTreeSet<C> = (0..cs.len()).filter(|&c| cs[c].on == 0).collect();
                        let removed: BTreeSet<Dot> = covers.iter().filter_map(|&c| if let Op::Remove(x) = &cs[c].op { Some(x.clone()) } else { None }).flatten().collect();
                        let mut keeps = vec![];
                        for &c in &covers {
                            match &cs[c].op {
                                Op::Add { to, home } if !removed.contains(&(c, *to)) => keeps.push(((c, *to), if keep_homes { *home } else { None })),
                                Op::Cover { keeps: k, .. } => keeps.extend(k.iter().filter(|(d, _)| !removed.contains(d)).map(|&(d, h)| (d, if keep_homes { h } else { None }))),
                                _ => {}
                            }
                        }
                        cs.push(Commit { on: 0, op: Op::Cover { covers, keeps }, side: None });
                        let after = View::all(&kinds, &cs, Unit::Reach);
                        let diff = (t.strongs != after.strongs || t.handles(0, Member::Target, true) != after.handles(0, Member::Target, true)) as usize;
                        if keep_homes {
                            changed += diff;
                        } else {
                            ctl += diff;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(changed, 0);
    assert!(ctl > 0);
    // Held history: writer 0 held the homed add (dot 2 -> 3); removed, then covered.
    let kinds = vec![K, K, K, d(1)];
    for cover in [false, true] {
        let mut net = Net::new(kinds.clone(), Rules::DESIGN, &[(set(&[0]), 0)], &[]);
        let a = net.author(0, addh(0, 3, 1));
        let x = net.author(0, rm(0, &[(a, 3)]));
        if cover {
            net.author(0, Commit { on: 0, op: Op::Cover { covers: BTreeSet::from([a, x]), keeps: vec![] }, side: None });
        }
        assert_eq!(net.home(0, 3), (!cover).then_some(1), "cover {cover}");
    }
    eprintln!("covers changing handles: {changed}; control (homes dropped) {ctl}");
}

// ---- Work at a change ----

/// Counts at n and 10n members (item 7): root 0 references holder 1 (0 holds sync on 1) and n
/// members, each granted to 1; H (n + 2) with dependents; a writer syncs 0 and 1, the keeper keeps
/// 0. Blob operations for: detaching a member (1), attaching it again (1), a strong to a dependent
/// of H with its home (2), its detach (2), a grant to 1 on a new thing (1), the root's grant on
/// the holder removed (1; the keeper then drops every member, the release), a rotation of 1 (0),
/// n strongs into the dependents of H (n + 1). Control: handles cut by roles (`Member::Role`)
/// delete a handle per member at the root's grant removal.
#[test]
fn work_at_a_change_counts() {
    let mut rows = vec![];
    for n in [5, 50] {
        for member in [Member::Target, Member::Role] {
            let h = n + 2;
            let z = n + 3;
            let mut kinds = vec![K; n + 4];
            kinds.extend((0..n).map(|_| d(h)));
            let mut net = Net::new(kinds, with(Rules::DESIGN, |r| r.member = member), &[(set(&[0, 1]), 0)], &[(set(&[0]), 0, false)]);
            net.author(0, role(1, 0, Some(Role::Sync)));
            let first = net.author(0, add(0, 1));
            for m in 2..n + 2 {
                net.author(0, role(m, 1, Some(Role::Sync)));
                net.author(0, add(0, m));
            }
            net.settle(20, false).unwrap();
            assert_eq!(handle_blobs(&net.listed(0)).len(), n + 1);
            assert_eq!(net.keepers[0].kept.units().len(), n + 2);
            let ops = |net: &mut Net, c: Commit| {
                let before = net.blob_ops;
                net.author(0, c);
                net.settle(20, false).unwrap();
                net.blob_ops - before
            };
            let detach = ops(&mut net, rm(0, &[(first + 2, 2)]));
            let attach = ops(&mut net, add(0, 2));
            let to_dep = net.commits.len();
            let attach_dep = ops(&mut net, addh(0, n + 4, h));
            let detach_dep = ops(&mut net, rm(0, &[(to_dep, n + 4)]));
            let grant = ops(&mut net, role(z, 1, Some(Role::Sync)));
            let rotation = ops(&mut net, rotate(1));
            let many = {
                let before = net.blob_ops;
                for x in n + 4..2 * n + 4 {
                    net.author(0, addh(0, x, h));
                }
                net.settle(20, false).unwrap();
                net.blob_ops - before
            };
            let root = ops(&mut net, role(1, 0, None));
            assert!(net.wrong().is_empty(), "{:?}", net.wrong());
            rows.push((n, member, [detach, attach, attach_dep, detach_dep, grant, rotation, many, root], net.keepers[0].kept.units().len()));
        }
    }
    for &(n, member, c, kept) in &rows {
        match member {
            Member::Target => assert_eq!((c, kept), ([1, 1, 2, 2, 1, 0, n + 1, 1], 1), "{rows:?}"),
            Member::Role => assert!(c[7] > n, "{rows:?}"),
        }
    }
    eprintln!("work (n, member, [detach, attach, attach to a dependent, its detach, grant, rotation, n strongs into one unit's dependents, root's grant removed], kept after): {rows:?}");
}


/// A key too many under a fork opens by its first credential: side 0 grants 0 sync on 2, side 1
/// counts no grant (forks are permanent). The key blob stands (side 0 asks for it) and carries 2's
/// sync secret, logged by a side-0 writer; the keeper of 0 on side 1, whose side's step of 2 lists
/// nothing it holds, enters 2 by that credential until 2 rotates (FAILS §2 "A key too many opens
/// nothing"; what it opens is what the side-0 grant's box already gave 0's sync holders, a secret
/// once shared). Without the credential it does not enter.
#[test]
fn a_key_too_many_opens_by_its_credential() {
    let mut net = Net::new(vec![K, K, K], Rules::DESIGN, &[(set(&[0, 2]), 0), (set(&[0]), 1)], &[(set(&[0]), 0, false), (set(&[0]), 1, false)]);
    net.author(0, add(0, 2));
    net.author(0, sided(role(2, 0, Some(Role::Sync)), 0));
    net.settle(20, false).unwrap();
    assert!(net.wrong().is_empty(), "{:?}", net.wrong());
    assert_eq!(net.keepers[0].kept.units(), set(&[0, 2]));
    assert_eq!(net.keepers[1].kept.units(), set(&[0, 2]), "side 1 enters by the credential");
    let t1 = net.truth(1);
    assert_eq!(walk(&t1, false, &set(&[0]), &|g| net.truth_blobs(g), Walk::DESIGN).units(), set(&[0]), "not by its side's step");
    net.author(0, rotate(2));
    net.settle(20, false).unwrap();
    assert_eq!(net.keepers[1].kept.units(), set(&[0]));
    assert_eq!(net.keepers[0].kept.units(), set(&[0, 2]));
}

// ---- Promotion (design §5) ----

fn promote(x: T) -> Commit {
    Commit { on: x, op: Op::Promote, side: None }
}
fn body(x: T) -> Commit {
    Commit { on: x, op: Op::Body { also: None }, side: None }
}
fn mixed(x: T, z: T) -> Commit {
    Commit { on: x, op: Op::Body { also: Some(z) }, side: None }
}
fn void(on: T, c: C) -> Commit {
    Commit { on, op: Op::Void(c), side: None }
}

/// What a reader of unit `g` and of `extra` holds, a promotion staying under its mint admin's unit
/// or not (`p_stays`).
fn seen_p(kinds: &[Kind], cs: &[Commit], g: T, extra: &[T], p_stays: bool) -> View {
    let mut t = View::all(kinds, cs, Unit::Reach);
    t.p_stays = p_stays;
    let mut units: Set = extra.iter().copied().collect();
    units.insert(g);
    let known: BTreeSet<C> = (0..cs.len()).filter(|&c| !t.under(&cs[c]).is_disjoint(&units)).collect();
    let mut v = View::of(kinds, cs, &known, Unit::Reach);
    v.p_stays = p_stays;
    v
}

/// The things a node rooted at `r` holds and reads (the things of the units it enters), walking
/// over blobs each computed by a reader of its unit alone.
fn holds_from(kinds: &[Kind], cs: &[Commit], r: T, reads: bool, p_stays: bool) -> (Set, Set) {
    let t = View::all(kinds, cs, Unit::Reach);
    let mut units = t.units();
    units.extend((kinds.len()..kinds.len() + cs.len()).filter(|&u| t.owner.contains_key(&u)));
    let own: std::collections::BTreeMap<T, Vec<Blob>> =
        units.into_iter().map(|g| (g, blobs_of(&seen_p(kinds, cs, g, &[], p_stays), g, Member::Target, true))).collect();
    let e = walk(&t, reads, &set(&[r]), &|g| own.get(&g).cloned().unwrap_or_default(), Walk::DESIGN);
    let things = |us: &Set| us.iter().flat_map(|&u| t.unit(u)).collect::<Set>();
    (things(&e.units()), things(&e.read))
}

/// The promotion family: 0 a referrer G, 1 = H, 2 = X a dependent of H, 3 = Z a dependent of X,
/// 4 = W another dependent of H; G's grant on H none, sync or read; every set of strongs among
/// `PCAND` (a strong to a dependent carrying its independent before the promotion as home); X
/// promoted.
const PK: [Kind; 5] = [K, K, Kind::Dependent(1), Kind::Dependent(2), Kind::Dependent(1)];
const PCAND: [(T, T); 9] = [(1, 2), (1, 3), (2, 3), (3, 2), (1, 4), (4, 2), (0, 2), (0, 3), (0, 1)];
const PFAMILY: usize = 3 << PCAND.len();
fn promo_family(i: usize) -> Vec<Commit> {
    let grants = [vec![], vec![(0, 1, Role::Sync)], vec![(0, 1, Role::Read)]][i >> PCAND.len()].clone();
    let strongs: Vec<(T, T)> = PCAND.iter().enumerate().filter(|(j, _)| i & (1 << j) != 0).map(|(_, &e)| e).collect();
    world(&PK, &grants, &strongs)
}

const PROMO_COLS: usize = 7;
/// For one world of the family, X promoted (failures, but the count 6): 0 a node rooted at G or H,
/// reading or keeping unread, holds or reads a thing before that it does not after; 1 the same with
/// the promotion leaving S(H) (control); 2 S(G)'s blobs change; 3 S(H)'s blobs change other than
/// X's key and the handles of things of X's subtree its strongs target; 4 after, the keeper and the reader of a root enter different units; 5 after,
/// a reader of a unit computes its blobs differently by what else it reads; 6 (count) a node holds
/// after what it held before plus more.
fn promo_world(cs: &[Commit]) -> [usize; PROMO_COLS] {
    let mut after = cs.to_vec();
    after.push(promote(2));
    let mut out = [0; PROMO_COLS];
    for r in [0, 1] {
        for reads in [false, true] {
            let before = holds_from(&PK, cs, r, reads, true);
            let now = holds_from(&PK, &after, r, reads, true);
            out[0] |= (!before.0.is_subset(&now.0) || !before.1.is_subset(&now.1)) as usize;
            out[6] |= (before != now && before.0.is_subset(&now.0) && before.1.is_subset(&now.1)) as usize;
            let ctl = holds_from(&PK, &after, r, reads, false);
            out[1] |= (!before.0.is_subset(&ctl.0) || !before.1.is_subset(&ctl.1)) as usize;
        }
    }
    let blobs = |cs: &[Commit], g: T| -> BTreeSet<Blob> { blobs_of(&seen_p(&PK, cs, g, &[], true), g, Member::Target, true).into_iter().collect() };
    out[2] = (blobs(cs, 0) != blobs(&after, 0)) as usize;
    let t = View::all(&PK, &after, Unit::Reach);
    let moved = |x: T| t.ind(x) == 2;
    out[3] = blobs(cs, 1)
        .symmetric_difference(&blobs(&after, 1))
        .filter(|b| match b {
            Blob::Handle(x) => !moved(*x),
            Blob::Key(k) => k.of != 2,
        })
        .count();
    for r in [0, 1] {
        let b = |g: T| blobs_of(&seen_p(&PK, &after, g, &[], true), g, Member::Target, true);
        out[4] |= (walk(&t, false, &set(&[r]), &b, Walk::DESIGN).units() != walk(&t, true, &set(&[r]), &b, Walk::DESIGN).units()) as usize;
    }
    let units: Vec<T> = t.units().into_iter().collect();
    for &g in &units {
        let others: Vec<T> = units.iter().copied().filter(|&x| x != g).collect();
        for x in subsets(&others) {
            let v = seen_p(&PK, &after, g, &x, true);
            out[5] |= (v.unit(g) != t.unit(g) || blobs_of(&v, g, Member::Target, true) != blobs_of(&t, g, Member::Target, true)) as usize;
        }
    }
    out
}

/// Promotion statically, over the whole family (1536 worlds): no referrer's blob changes (§5 "No
/// blob of a unit that references X changes"); S(H) gains at most X's key and handle, whatever H
/// holds; after it every reader of a unit computes the same unit and blobs whatever else it reads,
/// and the keeper and the reader of a root enter alike. FAILS "a promotion changes in no way who
/// reaches it" (spec/permissions.md §3 Own secrets add only; design §5 "X and the dependents whose
/// independent it becomes move from H's unit to X's"): a dependent Z of X that H's unit reached
/// directly and X's unit does not reach is in no unit after, and when X itself was reached only
/// through such a Z, H's holders lose X too (smallest worlds below). Control: the promotion leaving
/// S(H) loses X for H's holders in more worlds.
#[test]
fn promotion_moves_x_and_what_x_reaches() {
    let mut f = [0; PROMO_COLS];
    for i in 0..PFAMILY {
        let row = promo_world(&promo_family(i));
        for (a, x) in f.iter_mut().zip(row) {
            *a += x;
        }
    }
    eprintln!("promotion family of {PFAMILY} (loses, loses with P out of S(H), referrer changes, other S(H) changes, keeper != reader, reader split, gains): {f:?}");
    assert_eq!((f[2], f[3], f[4], f[5]), (0, 0, 0, 0), "{f:?}");
    assert!(f[1] > f[0], "control: {f:?}");
    // The finding's smallest worlds. H -> X, H -> Z, Z a dependent of X: Z is in no unit after.
    let a = world(&PK, &[], &[(1, 2), (1, 3)]);
    let mut pa = a.clone();
    pa.push(promote(2));
    assert_eq!(holds_from(&PK, &a, 1, true, true).0, set(&[1, 2, 3]));
    assert_eq!(holds_from(&PK, &pa, 1, true, true).0, set(&[1, 2]));
    // H -> Z -> X: X's handle is in no unit H's holders enter; they lose X and Z.
    let b = world(&PK, &[], &[(1, 3), (3, 2)]);
    let mut pb = b.clone();
    pb.push(promote(2));
    assert_eq!(holds_from(&PK, &b, 1, false, true).0, set(&[1, 2, 3]));
    assert_eq!(holds_from(&PK, &pb, 1, false, true).0, set(&[1]));
    // X unreached before, H -> Z, X -> Z: Z joins X's unit, which H's holders do not enter (the
    // strong's home names H, X's handle is nowhere they look).
    let c = world(&PK, &[], &[(1, 3), (2, 3)]);
    let mut pc = c.clone();
    pc.push(promote(2));
    assert_eq!(holds_from(&PK, &c, 1, false, true).0, set(&[1, 3]));
    assert_eq!(holds_from(&PK, &pc, 1, false, true).0, set(&[1]));
    // The same through a referrer G (sync on H, G -> Z with home H): G's holders lose Z.
    let g = world(&PK, &[(0, 1, Role::Sync)], &[(1, 2), (2, 3), (1, 3), (0, 3)]);
    let mut pg = g.clone();
    pg.push(promote(2));
    assert_eq!(holds_from(&PK, &g, 0, false, true).0, set(&[0, 1, 2, 3]));
    assert_eq!(holds_from(&PK, &pg, 0, false, true).0, set(&[0, 1, 2, 3]), "H -> X lists X: kept");
    assert!(f[0] > 0);
}

/// One promotion scenario over time, every `stride`-th schedule: `genesis` held by each writer a
/// unit it syncs carries, settled; then `moves` reaching writers 0 and 1 in every order and
/// interleaving, each logging a move at once where it arrives (`Net::arrive`, as its author does
/// with no pass first); after each, the receiving writer visiting alone (or every writer together),
/// writers from 2 on (each holding the moves `ticket` names, as a node granted on X holds X's
/// sync ID) visiting, every keeper passing. Then settled. Counts: schedules, unsettled, ending
/// wrong, with a commit lost (`Net::lost`), the most times one entry was logged, failing `end`.
#[allow(clippy::too_many_arguments)]
fn promo_orders(
    kinds: &[Kind],
    writers: &[(Set, u8)],
    keepers: &[(Set, u8, bool)],
    genesis: &[Commit],
    moves: &[Commit],
    ticket: &[usize],
    rules: Rules,
    stride: usize,
    end: &dyn Fn(&Net) -> bool,
) -> [usize; 6] {
    let perms = permutations(moves.len());
    let ilv = interleavings(moves.len(), moves.len());
    let mut out = [0; 6];
    let mut i = 0;
    for together in [false, true] {
        for pa in &perms {
            for pb in &perms {
                for il in &ilv {
                    i += 1;
                    if i % stride != 0 {
                        continue;
                    }
                    let mut net = Net::new(kinds.to_vec(), rules, writers, keepers);
                    net.watch = true;
                    for c in genesis {
                        let c = net.write(c.clone());
                        for w in 0..writers.len() {
                            net.deliver(w, c);
                        }
                    }
                    net.settle(20, false).unwrap();
                    let base = net.commits.len();
                    for c in moves {
                        net.write(c.clone());
                    }
                    for w in 2..writers.len() {
                        for &m in ticket {
                            net.writers[w].has.insert(base + m);
                        }
                    }
                    let (mut ia, mut ib) = (0, 0);
                    for &who in il {
                        let c = if who == 0 {
                            ia += 1;
                            pa[ia - 1]
                        } else {
                            ib += 1;
                            pb[ib - 1]
                        };
                        net.arrive(who, base + c);
                        if together {
                            net.visit_together();
                        } else {
                            net.visit_all(who);
                            for w in 2..writers.len() {
                                net.visit_all(w);
                            }
                        }
                        net.pass_all(false);
                    }
                    let settled = net.settle(20, false).is_some();
                    out[0] += 1;
                    out[1] += !settled as usize;
                    out[2] += (settled && !net.wrong().is_empty()) as usize;
                    out[3] += !net.lost.is_empty() as usize;
                    out[4] = out[4].max(net.inserts.values().copied().max().unwrap_or(0));
                    out[5] += (settled && !end(&net)) as usize;
                }
            }
        }
    }
    out
}

/// The late reader: what a reader holding only S(H)'s entries computes S(H)'s blobs to be, against
/// the truth: it finds in S(H) alone that X moved and where.
fn late_reader_finds(net: &Net, h: T) -> bool {
    let mut v = View::of(&net.kinds, &net.commits, &net.entries_of(h), Unit::Reach);
    v.p_stays = net.rules.p_stays;
    let mut got: Vec<Blob> = blobs_of(&v, h, Member::Target, true);
    got.sort();
    got == net.truth_blobs(h)
}

/// Writer 2 (syncing `x` alone) holds every commit its side's truth puts under x's unit.
fn x_alone_holds_all(net: &Net, x: T) -> bool {
    let t = net.truth(net.writers[2].side);
    if t.kinds[x] != Kind::Independent {
        return true;
    }
    let u = t.sid(x);
    (0..net.commits.len()).filter(|&c| t.under(&net.commits[c]).contains(&u)).all(|c| net.writers[2].has.contains(&c))
}

/// The promotion world: 0 a referrer G holding sync on H (G -> X with home H), 1 = H, 2 = X a
/// dependent of H, 3 = Z a dependent of X (X -> Z), 4 = W another dependent of H; a body on each.
/// Writers: 0 and 1 sync H and X; 2 syncs X alone. Keepers: of H unread and read, of G, a reader
/// of X alone, of H on side 1.
const OK: [Kind; 5] = [K, K, Kind::Dependent(1), Kind::Dependent(2), Kind::Dependent(1)];
fn promo_setup() -> (Vec<Commit>, Vec<(Set, u8, bool)>) {
    let genesis = vec![role(1, 0, Some(Role::Sync)), add(1, 2), add(2, 3), add(1, 4), addh(0, 2, 1), body(2), body(3), body(4)];
    let keepers = vec![(set(&[1]), 0, false), (set(&[1]), 0, true), (set(&[0]), 0, false), (set(&[2]), 0, true), (set(&[1]), 1, false)];
    (genesis, keepers)
}

/// Items (1)-(3) and (5) over time, every `stride`-th schedule of each scenario (1440 in all;
/// a stride shares no factor with 2, 3, 5): the late writer (bodies of X and Z written by a writer
/// lacking P, logged under S(H) where they arrive); P late with a mixed commit on X and W; a
/// dispute (P valid on side 0 only, the writers on two sides); a promotion judged invalid (`Void`)
/// after bodies moved. In each: settled, the stated end state, no commit carried by no store while
/// every holder places it, no keeper losing a commit it held that its side's walk keeps (but the
/// invalid promotion: `a_voided_promotion_strands_what_was_written_under_x`), an entry logged at
/// most twice (once more after a change of ground), a late reader of H finding X's key and handle
/// in S(H) alone, the writer of X alone holding every body of X's unit, the late writer's
/// included. Controls (every 11th): the carrier rule off loses commits; P leaving S(H) leaves the
/// late reader without X; each writer judging by its own side never settles the dispute.
fn promotion_orders(stride: usize) {
    let (genesis, keepers) = promo_setup();
    let base = genesis.len();
    let w2 = |b: u8| vec![(set(&[1, 2]), 0), (set(&[1, 2]), b), (set(&[2]), 0)];
    let end_all = |net: &Net| late_reader_finds(net, 1) && x_alone_holds_all(net, 2);
    let scenarios: Vec<(&str, Vec<Commit>, u8, bool)> = vec![
        ("late writer", vec![promote(2), body(2), body(3)], 0, true),
        ("P late, mixed", vec![promote(2), mixed(2, 4), body(4)], 0, true),
        ("dispute", vec![sided(promote(2), 0), body(2), body(3)], 1, true),
        ("invalid", vec![promote(2), body(2), void(2, base)], 0, false),
    ];
    let n = 1440 / stride;
    for (name, moves, side, x_alone) in &scenarios {
        let ws = if *x_alone { w2(*side) } else { w2(*side)[..2].to_vec() };
        let end = |net: &Net| late_reader_finds(net, 1) && (!*x_alone || x_alone_holds_all(net, 2));
        let f = promo_orders(&OK, &ws, &keepers, &genesis, moves, &[0], Rules::DESIGN, stride, &end);
        eprintln!("{name}: (schedules, unsettled, wrong, lost, most logs of one entry, end failing) {f:?}");
        let lost = if *name == "invalid" { f[3] } else { 0 };
        assert_eq!(f, [n, 0, 0, lost, f[4], 0], "{name}");
        assert!(f[4] <= 2, "{name}: {f:?}");
    }
    let ctl = |rules: Rules, i: usize| promo_orders(&OK, &w2(scenarios[i].2), &keepers, &genesis, &scenarios[i].1, &[0], rules, 11, &end_all);
    let carrier = ctl(with(Rules::DESIGN, |r| r.carrier = false), 0);
    let p_out = ctl(with(Rules::DESIGN, |r| r.p_stays = false), 0);
    let own_side = ctl(with(Rules::DESIGN, |r| r.any_side = false), 2);
    eprintln!("controls: carrier off {carrier:?}, P out of S(H) {p_out:?}, own side {own_side:?}");
    assert!(carrier[3] > 0, "{carrier:?}");
    assert!(p_out[5] > 0, "{p_out:?}");
    assert!(own_side[1] + own_side[2] > 0, "{own_side:?}");
}

#[test]
fn promotion_in_every_order_loses_no_body() {
    promotion_orders(7);
}

#[test]
#[ignore]
fn promotion_in_every_order_loses_no_body_full() {
    promotion_orders(1);
}

/// A promotion judged invalid strands what was written under S(X) (FAILS design §5 "a node keeping
/// the closure unread always holds X's content under one of the two" and the open item's "moves
/// the bodies back"). H = 0, X = 1 its dependent, H -> X; writers A and B sync both; a keeper of H.
/// P; A writes a body of X after P, logged under S(X) alone. The void reaches B first: X is H's
/// again by B's view, so B deletes X's key and handle at S(H) and never syncs S(X) again (no view
/// holding the void has that sync ID); the keeper drops S(X) and holds the body nowhere. Only a
/// node holding the body (A, once it gets the void) logs it under S(H): no node counting P invalid
/// passes S(X), so a body only S(X)'s stores hold stays there for good.
#[test]
fn a_voided_promotion_strands_what_was_written_under_x() {
    let mut net = Net::new(vec![K, d(0)], Rules::DESIGN, &[(set(&[0, 1]), 0), (set(&[0, 1]), 0)], &[(set(&[0]), 0, false)]);
    net.watch = true;
    net.author(0, add(0, 1));
    let p = net.author(0, promote(1));
    net.deliver_all();
    net.settle(20, false).unwrap();
    let sx = 2 + p;
    assert_eq!(net.keepers[0].kept.units(), set(&[0, sx]));
    let b = net.author_logs(0, body(1));
    assert_eq!(net.entries.iter().filter(|e| e.1 == b).collect::<Vec<_>>(), vec![&(sx, b)]);
    net.pass_all(false);
    assert!(net.keepers[0].holds.contains(&b));
    let v = net.write(void(1, p));
    net.arrive(1, v);
    net.visit_all(1);
    net.pass_all(false);
    assert!(!net.units_of(1).contains(&sx), "B no longer syncs S(X)");
    assert!(!net.writers[1].has.contains(&b), "B never passed S(X) for it");
    assert_eq!(net.keepers[0].kept.units(), set(&[0]));
    assert!(!net.keepers[0].holds.contains(&b) && net.entries.contains(&(sx, b)), "held at S(X) alone, which the keeper dropped");
    assert!(!net.lost.is_empty());
    // A, holding the body, gets the void: it logs the body under S(H).
    net.arrive(0, v);
    net.settle(20, false).unwrap();
    assert!(net.wrong().is_empty(), "{:?}", net.wrong());
    assert!(net.keepers[0].holds.contains(&b));
    assert!(net.entries.contains(&(sx, b)), "S(X)'s copy stays: nobody passes S(X)");
}

/// Finding 1's state from a promotion judged invalid (notes/sync-unit-scope.md, promotion): H = 0, X =
/// 1 its dependent, Y = 2 a dependent of X; H -> X -> Y; X promoted, then Y (its mint admin now
/// independent, spec/permissions.md §3). The keeper of H enters X and Y. The void of X's promotion
/// makes X dependent again while Y stays independent with X, a dependent of H's unit, on its
/// step: S(H) holds Y's key and handle; a reader of H derives X's sync secret (it knows X's tid)
/// and keeps Y; the keeper enters Y only by the key's first credential and loses Y at Y's next
/// rotation. Without the void the keeper keeps Y through the rotation; an admin making X
/// independent again (the SHOULD of spec/permissions.md §3) gives it back.
#[test]
fn an_invalid_promotion_leaves_a_dependent_holder() {
    for voided in [true, false] {
        let mut net = Net::new(vec![K, d(0), d(1)], Rules::DESIGN, &[(set(&[0, 1, 2]), 0)], &[(set(&[0]), 0, false), (set(&[0]), 0, true)]);
        net.author(0, add(0, 1));
        net.author(0, add(1, 2));
        let px = net.author(0, promote(1));
        net.author(0, promote(2));
        net.author(0, body(2));
        net.settle(20, false).unwrap();
        assert_eq!(net.keepers[0].kept.units().len(), 3);
        if voided {
            net.author(0, void(1, px));
            net.settle(20, false).unwrap();
            let t = net.truth(0);
            assert_eq!((t.kinds[1], t.kinds[2]), (d(0), K));
            assert!(t.on_step(1, 2) && t.in_unit[1] == Some(0), "Y's step lists X, a dependent of H's unit");
        }
        let units = net.keepers[0].kept.units().len();
        assert_eq!(units, if voided { 2 } else { 3 });
        net.author(0, rotate(2));
        net.settle(20, false).unwrap();
        assert!(net.wrong().is_empty(), "{:?}", net.wrong());
        assert_eq!(net.keepers[1].kept.units().len(), units, "the reader keeps Y");
        assert_eq!(net.keepers[0].kept.units().len(), if voided { 1 } else { 3 }, "voided {voided}");
        if voided {
            net.author(0, promote(1));
            net.settle(20, false).unwrap();
            assert_eq!(net.keepers[0].kept.units().len(), 3, "X independent again");
        }
    }
}

/// Forked promotions (spec/sync-ids.md §2: two admins making X independent at once each record a
/// sync ID; both stand, X's sync ID is the greatest it owns). H = 0, X = 1 its dependent, H -> X;
/// writers A and B sync both, C syncs X alone and holds the first promotion only (its grant came
/// on that side). Every order of the two promotions and a body reaching A and B: settled, the
/// stated end state (X's bodies under the greater sync ID), nothing lost, S(H) holding X's key
/// naming both sync IDs and the keeper of H entering both. FAILS for C, a node syncing X by the
/// lesser sync ID alone: nothing of X travels under it once a writer holds both promotions (the
/// second promotion goes under S(H) and the greater sync ID), so C never learns the greater one
/// and holds X frozen (design §2 Key blobs "each owned one after a forked promotion" serves nodes
/// that enter X through a key blob, not a node granted on X alone).
#[test]
fn forked_promotions_name_both_sync_ids() {
    let kinds = [K, d(0)];
    let writers = [(set(&[0, 1]), 0), (set(&[0, 1]), 0), (set(&[1]), 0)];
    let keepers = [(set(&[0]), 0, false), (set(&[0]), 0, true)];
    let genesis = [add(0, 1), body(1)];
    let (s1, s2) = (2 + 2, 2 + 3);
    let both = |net: &Net| {
        let want = [Blob::Key(Key { of: 1, names: s1, cred: None }), Blob::Key(Key { of: 1, names: s2, cred: None })];
        let t = net.truth(0);
        t.sid(1) == s2 && want.iter().all(|b| net.truth_blobs(0).contains(b)) && net.keepers[0].kept.units() == set(&[0, s1, s2]) && late_reader_finds(net, 0)
    };
    let f = promo_orders(&kinds, &writers, &keepers, &genesis, &[promote(1), promote(1), body(1)], &[0], Rules::DESIGN, 7, &both);
    eprintln!("forked: (schedules, unsettled, wrong, lost, most logs of one entry, end failing) {f:?}");
    assert_eq!(f, [205, 0, 0, 0, f[4], 0]);
    let stuck = promo_orders(&kinds, &writers, &keepers, &genesis, &[promote(1), promote(1), body(1)], &[0], Rules::DESIGN, 7, &|n| x_alone_holds_all(n, 1));
    assert_eq!(stuck[5], 205, "C never holds what the greater sync ID carries: {stuck:?}");
    // By hand: both promotions held by A and B, then A writes a body: C holds neither.
    let mut net = Net::new(kinds.to_vec(), Rules::DESIGN, &writers, &keepers);
    for c in genesis {
        net.write(c);
    }
    let p1 = net.write(promote(1));
    let p2 = net.write(promote(1));
    for w in [0, 1] {
        for c in 0..4 {
            net.deliver(w, c);
        }
    }
    net.writers[2].has.insert(p1);
    net.settle(20, false).unwrap();
    let b = net.author_logs(0, body(1));
    net.settle(20, false).unwrap();
    assert!(net.wrong().is_empty(), "{:?}", net.wrong());
    assert_eq!(net.units_of(2), set(&[s1]));
    assert!(!net.writers[2].has.contains(&p2) && !net.writers[2].has.contains(&b));
    assert!(!net.entries.contains(&(s1, p2)), "nothing names S(X2) under S(X1)");
}

/// What the carrier rule can promise against a hostile writer of S(H): nothing beyond the next
/// honest visit. It binds honest writers; a hostile one deletes X's bodies at S(H) before any
/// carrier exists, as it may delete any entry of S(H) (a bounded writer), and the bodies are
/// carried by no store until an honest writer holding them visits: it logs them under S(X) (and
/// deletes nothing more). A body only stores held is gone, as for any unit.
#[test]
fn a_hostile_writer_deletes_before_a_carrier() {
    let mut net = Net::new(vec![K, d(0)], Rules::DESIGN, &[(set(&[0, 1]), 0)], &[(set(&[0]), 0, false)]);
    net.watch = true;
    net.author(0, add(0, 1));
    let b = net.author(0, body(1));
    net.settle(20, false).unwrap();
    assert!(net.entries.contains(&(0, b)));
    let p = net.author_logs(0, promote(1));
    // Before any visit of S(X): the hostile deletion.
    net.entries.remove(&(0, b));
    net.check_carried("after the hostile delete");
    assert!(!net.lost.is_empty());
    net.settle(20, false).unwrap();
    assert!(net.wrong().is_empty(), "{:?}", net.wrong());
    assert!(net.entries.contains(&(2 + p, b)) && !net.entries.contains(&(0, b)));
}

/// A removal on its way while X is promoted (item 5): 0 = W holds read on H = 1 and references H
/// and X (home H), X = 2 a dependent of H; writers A (syncing W too: the removal travels under
/// S(W)) and B sync H and X, a third syncs W. The removal (W's grant on H gone, with H's rotation),
/// the promotion and a body of X written after both reach A and B in every order of each (A and B
/// alternating). After every step a keeper and a reader of W hold no unit but W's own: the move
/// writes no key of X under S(W), and every key of H there carries a credential the rotation made
/// stale. With steps current in the model, the window the spec accepts (a promoter that lacks the
/// removal boxes X to H's older keyset, spec/permissions.md §3 Own secrets add only) is not
/// modelled.
#[test]
fn a_removed_holder_gains_nothing_by_the_move() {
    let kinds = [K, K, d(1)];
    let writers = [(set(&[0, 1, 2]), 0), (set(&[1, 2]), 0), (set(&[0]), 0)];
    let keepers = [(set(&[0]), 0, false), (set(&[0]), 0, true)];
    let genesis = [role(1, 0, Some(Role::Read)), add(0, 1), addh(0, 2, 1), add(1, 2), body(2)];
    let mut runs = 0;
    for pa in permutations(3) {
        for pb in permutations(3) {
            let mut net = Net::new(kinds.to_vec(), Rules::DESIGN, &writers, &keepers);
            net.watch = true;
            for c in genesis.iter().cloned() {
                let c = net.write(c);
                for w in 0..3 {
                    net.deliver(w, c);
                }
            }
            net.settle(20, false).unwrap();
            assert_eq!(net.keepers[1].kept.units(), set(&[0, 1]));
            let base = net.commits.len();
            for c in [role(1, 0, None), promote(2), body(2), rotate(1)] {
                net.write(c);
            }
            for i in 0..6 {
                let (who, m) = if i % 2 == 0 { (0, pa[i / 2]) } else { (1, pb[i / 2]) };
                net.arrive(who, base + m);
                if m == 0 {
                    net.arrive(who, base + 3);
                }
                net.visit_all(who);
                net.visit_all(2);
                net.pass_all(false);
                assert!(net.keepers.iter().all(|k| k.kept.units() == set(&[0])), "{pa:?} {pb:?} step {i}: {:?}", net.keepers);
            }
            net.deliver_all();
            net.settle(20, false).unwrap();
            assert!(net.wrong().is_empty() && net.lost.is_empty(), "{:?} {:?}", net.wrong(), net.lost);
            runs += 1;
        }
    }
    assert_eq!(runs, 36);
}

/// Work at a promotion (item 6), at n and 10n: G = 0 (sync on H, referencing X and a member with
/// home H), H = 1 with n member dependents each with a body, X = 2 a dependent of H with n bodies
/// and a dependent Z it references, with a body. Promoting X: S(X) gains one entry per commit of
/// X's subtree and P; S(H) loses those and gains P; S(H) gains X's key and handle; S(X) and S(G)
/// change no blob and S(G) no entry. Nothing per member, nothing in the referrer.
#[test]
fn work_at_a_promotion_counts() {
    let mut rows = vec![];
    for n in [5, 50] {
        let z = 3 + n;
        let mut kinds = vec![K, K, d(1)];
        kinds.extend((0..n).map(|_| d(1)));
        kinds.push(d(2));
        let mut net = Net::new(kinds, Rules::DESIGN, &[(set(&[0, 1, 2]), 0)], &[(set(&[0]), 0, false)]);
        for c in [role(1, 0, Some(Role::Sync)), add(1, 2), add(2, z), addh(0, 2, 1), addh(0, 3, 1), body(z)] {
            net.author(0, c);
        }
        for m in 3..3 + n {
            net.author(0, add(1, m));
            net.author(0, body(m));
            net.author(0, body(2));
        }
        net.settle(20, false).unwrap();
        let (entries, store) = (net.entries.clone(), net.store.clone());
        let p = net.author(0, promote(2));
        net.settle(20, false).unwrap();
        assert!(net.wrong().is_empty(), "{:?}", net.wrong());
        let sx = net.kinds.len() + p;
        let x_commits = (0..p).filter(|&c| net.commits[c].on == 2 || net.commits[c].on == z).count();
        let ediff = |g: T| entries.symmetric_difference(&net.entries).filter(|e| e.0 == g).count();
        let bdiff = |g: T| {
            let a: BTreeSet<(usize, Blob)> = store.iter().filter(|(k, _)| k.0 == g).map(|(k, b)| (k.1, *b)).collect();
            let b: BTreeSet<(usize, Blob)> = net.store.iter().filter(|(k, _)| k.0 == g).map(|(k, b)| (k.1, *b)).collect();
            a.symmetric_difference(&b).count()
        };
        let row = [ediff(sx), ediff(1), ediff(0), bdiff(sx), bdiff(1), bdiff(0)];
        assert_eq!(row, [x_commits + 1, x_commits + 1, 0, 0, 2, 0], "n {n}");
        assert_eq!(net.keepers[0].kept.units(), set(&[0, 1, sx]));
        rows.push((n, x_commits, row));
    }
    eprintln!("promotion work (n, commits of X's subtree, [S(X) entries, S(H) entries, S(G) entries, S(X) blobs, S(H) blobs, S(G) blobs]): {rows:?}");
}

/// P1 with promotions (item 2): 300 random static worlds of `random_static` with dependents
/// promoted (each whose mint admin is independent or promoted, at random): every reader of a unit
/// computes the same unit and targets whatever else it reads. Control `Unit::Held` fails.
#[test]
fn p1_with_promotions() {
    let mut r = Rng::new(0);
    let mut f = [0; 5];
    for _ in 0..300 {
        let (kinds, mut cs) = random_static(&mut r, false);
        let mut promoted = Set::new();
        for x in 4..8 {
            if let Kind::Dependent(a) = kinds[x] {
                if (kinds[a] == K || promoted.contains(&a)) && r.chance(40) {
                    promoted.insert(x);
                    cs.push(promote(x));
                    cs.push(body(x));
                }
            }
        }
        for (a, x) in f.iter_mut().zip(p1_row(&kinds, &cs)) {
            *a += x;
        }
    }
    eprintln!("p1 with promotions, random of 300: {f:?}");
    assert_eq!(f[..2], [0; 2], "{f:?}");
    assert!(f[2] > 0, "{f:?}");
}

/// A random history with promotions: 4 independent things and 0's dependent 4, 4's dependent 5,
/// 1's dependent 6, 2's dependent 7; 2 or 3 writers syncing random things, each writing bodies,
/// strongs, removes and grants on what it syncs (logged where they are written), promoting a
/// dependent whose mint admin it counts independent, with `voids` sometimes voiding a promotion it
/// holds, with `forks` a third of the commits valid on their writer's side alone; deliveries,
/// single and simultaneous visits, keeper passes (of 0 on each side, unread and read). Then
/// everything delivered and settled.
fn random_promo(r: &mut Rng, rules: Rules, forks: bool, voids: bool) -> Net {
    let kinds = vec![K, K, K, K, d(0), d(4), d(1), d(2)];
    let writers: Vec<(Set, u8)> = (0..2 + r.below(2))
        .map(|i| {
            let mut s: Set = (0..8).filter(|_| r.chance(50)).collect();
            s.insert(r.below(4) as T);
            // A writer of H syncs what is promoted out of H's unit (its walk enters it: §5).
            let sub: Vec<T> = (4..8).filter(|&x| s.contains(&ind(&kinds, x))).collect();
            s.extend(sub);
            (s, if forks { (i % 2) as u8 } else { 0 })
        })
        .collect();
    let mut net = Net::new(kinds, rules, &writers, &[(set(&[0]), 0, false), (set(&[0]), 0, true), (set(&[0]), 1, false)]);
    net.watch = true;
    for _ in 0..40 {
        let w = r.below(net.writers.len() as u64) as usize;
        let units = net.units_of(w);
        let v = net.side_view(&net.writers[w].has, net.writers[w].side);
        let mine: Vec<T> = (0..8).filter(|&x| v.in_unit[x].is_some_and(|u| units.contains(&u)) || (v.kinds[x] == K && units.contains(&v.sid(x)))).collect();
        let side = (forks && r.chance(33)).then_some(net.writers[w].side);
        match r.below(12) {
            0 | 1 if !mine.is_empty() => {
                let (on, to) = (r.pick(&mine), r.below(8) as T);
                let home = net.home(w, to);
                net.author_logs(w, Commit { on, op: Op::Add { to, home }, side });
            }
            2 | 3 if !mine.is_empty() => {
                let on = r.pick(&mine);
                let also = r.chance(30).then(|| r.pick(&mine));
                net.author_logs(w, Commit { on, op: Op::Body { also }, side });
            }
            4 if !mine.is_empty() => {
                let on = r.pick(&mine);
                let dots: Vec<Dot> = net.writers[w]
                    .has
                    .iter()
                    .filter_map(|&c| match net.commits[c].op {
                        Op::Add { to, .. } if net.commits[c].on == on => Some((c, to)),
                        _ => None,
                    })
                    .collect();
                if !dots.is_empty() {
                    net.author_logs(w, Commit { side, ..rm(on, &[r.pick(&dots)]) });
                }
            }
            5 => {
                let ps: Vec<T> = mine.iter().copied().filter(|&x| v.kinds[x] != K && v.mint[x].is_some_and(|a| v.kinds[a] == K)).collect();
                if !ps.is_empty() {
                    net.author_logs(w, Commit { side, ..promote(r.pick(&ps)) });
                }
            }
            6 if voids => {
                let ps: Vec<C> = net.writers[w].has.iter().copied().filter(|&c| net.commits[c].op == Op::Promote).collect();
                if !ps.is_empty() && r.chance(50) {
                    let p = r.pick(&ps);
                    net.author_logs(w, void(net.commits[p].on, p));
                }
            }
            7 if !net.commits.is_empty() => {
                let c = r.below(net.commits.len() as u64) as C;
                net.deliver(w, c);
            }
            8 | 9 if !units.is_empty() => {
                let g = r.pick(&units.iter().copied().collect::<Vec<_>>());
                net.visit(w, g);
            }
            10 => net.visit_together(),
            _ => {}
        }
        net.pass_all(false);
    }
    net.deliver_all();
    net.settle(40, false);
    net
}

/// Random histories with promotions, 100 per configuration: plain, forked (promotions and grants
/// valid on one side only: disputes), with voids. Every run settles, ends in the stated end state,
/// and (but with voids: `a_voided_promotion_strands_what_was_written_under_x`) no commit is carried
/// by no store while every holder places it and no keeper loses a commit its walk keeps. Control:
/// the carrier rule off loses commits.
#[test]
fn random_histories_with_promotions() {
    let mut rows = vec![];
    for (forks, voids) in [(false, false), (true, false), (false, true)] {
        let mut r = Rng::new(0);
        let mut f = [0; 4];
        let mut ctl = 0;
        for _ in 0..100 {
            r.next();
            let mut net = random_promo(&mut r.clone(), Rules::DESIGN, forks, voids);
            let settled = net.settle(1, false).is_some();
            f[0] += !settled as usize;
            f[1] += (settled && !net.wrong().is_empty()) as usize;
            f[2] += !net.lost.is_empty() as usize;
            f[3] = f[3].max(net.writers.iter().map(|w| w.has.iter().filter(|&&c| net.commits[c].op == Op::Promote).count()).max().unwrap_or(0));
            if !forks && !voids {
                ctl += !random_promo(&mut r.clone(), with(Rules::DESIGN, |x| x.carrier = false), forks, voids).lost.is_empty() as usize;
            }
        }
        rows.push((forks, voids, f, ctl));
        assert_eq!(f[..2], [0, 0], "forks {forks} voids {voids}: {f:?}");
        if !voids {
            assert_eq!(f[2], 0, "forks {forks}: {f:?}");
        }
        if !forks && !voids {
            assert!(ctl > 0, "carrier off must lose: {ctl}");
        }
    }
    eprintln!("random with promotions of 100 (forks, voids, [unsettled, wrong, lost, most promotions held], carrier off lost): {rows:?}");
}
