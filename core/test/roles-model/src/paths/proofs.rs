//! Connection proofs by claimed path (spec/sync-opens.md §2; spec/wire.md §11.2 Prove):
//! a peer proves its node thing P and claims the path [P, A] to its account A, carrying
//! certificate copies of grant writes it picks; a verifier V judges the claim on what it holds
//! with the copies as received evidence, kept with the connection alone (no side recorded, nothing
//! stored), and the proven role reads the proven things' roles on S's thing. Findings: notes/accounts-switch-brief.md,
//! Models.
//!
//! The world: A minted with N1 (its record grant), N1 granting N2 admin and N3 a role, then a few
//! grant writes on A by any of the three (removals, demotions, re-grants, self-removals, any `ts`,
//! each writer's frontier honest over a random part of what came before). V holds an
//! evidence-closed part of them, taken in batches in a random order, its sides recorded as it
//! takes them (Sides, held first). The prover holds every commit and picks any copies V lacks.
//! A holds write on S.
//!
//! Rules (`ProofRules`): `spec`, with `guard` (a reading in which the copies
//! undo a lowering V's own reading applies proves nothing: `undone`), `receipt` (the copies judged
//! with the sides taking them in would record) and `j_path` (the proven role reads a proven thing at the role
//! its claimed path gives: the least of the path's role and the claimed thing's role on S); the
//! control `draft`, without the three.
//! Properties, each a message kind:
//! - `revive`: a proof never stands on a reading in which its copies undo a lowering the
//!   verifier's own reading applies (spec/sync-opens.md §2: a removal on the path ends it).
//! - `receipt`: a proof proves nothing taking its copies in would not (the reading after receiving
//!   them, sides recorded as on any receipt).
//! - `own` (liveness): with no copies the proof is the verifier's own reading.
//! - `fresh` (liveness): a verifier holding no grant write on the claimed edge proves a member by
//!   honest copies (every grant write on that edge, evidence closed) wherever its reading of
//!   everything would, unless they undo a lowering its own reading applies; `waits`: then it does
//!   once it holds what its own evidence brings.
//! - `j-path`: the proven role never trusts a peer above the role its claimed path gives it on S.
//!
//! Counted: proofs a guard denies that the reading of every commit would prove (`denied`: the
//! verifier's own removal standing until its own reading changes), stale proofs (`stale`: V lacks
//! the removal; proven, the reading of everything says removed).

use super::*;
use crate::{each_world, Findings, Rng};

pub const A: Thing = 1;
pub const N1: Thing = 2;
pub const N2: Thing = 3;
pub const N3: Thing = 4;
pub const NODES: [Thing; 3] = [N1, N2, N3];
/// A's role on S.
pub const ON_S: Role = Role::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProofRules {
    pub guard: bool,
    pub receipt: bool,
    pub j_path: bool,
}

impl ProofRules {
    /// The control: spec/sync-opens.md §2 and §4 without the guard, receipt and the path's role.
    pub fn draft() -> ProofRules {
        ProofRules { guard: false, receipt: false, j_path: false }
    }
    pub fn spec() -> ProofRules {
        ProofRules { guard: true, receipt: true, j_path: true }
    }
    pub fn named(mode: &str) -> Option<ProofRules> {
        let f = ProofRules::spec();
        let rest = mode.strip_prefix("proofs").unwrap_or(mode);
        Some(match rest.strip_prefix("-exh").unwrap_or(rest) {
            "" => f,
            "-draft" => ProofRules::draft(),
            "-no-guard" => ProofRules { guard: false, ..f },
            "-no-receipt" => ProofRules { receipt: false, ..f },
            "-no-j" => ProofRules { j_path: false, ..f },
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProofWorld {
    pub w: World,
    /// V's held commits, in the batches it took them in.
    pub batches: Vec<Set>,
}

impl ProofWorld {
    pub fn held(&self) -> Set {
        self.batches.iter().flatten().copied().collect()
    }
}

/// One grant write on A by `signer` at `ts`: `holder` set to `role` (a self-removal where the
/// holder is the signer), its frontier honest over `received` where it lowers.
fn write(w: &mut World, signer: Thing, ts: u32, holder: Thing, role: Role, received: &dyn Fn(Id) -> bool) -> Id {
    let lowers = role < Role::Admin && holder != signer;
    let f = if lowers { w.through((holder, A), |i| received(i)) } else { vec![] };
    w.edge(signer, ts, &[], A, holder, role, &f)
}

/// The setup: N1 (A's mint admin) grants N2 admin and N3 `r3` at 1.
fn setup(r3: Role) -> World {
    let mut w = World::new(&[(N1, A)]);
    w.edge(N1, 1, &[], A, N2, Role::Admin, &[]);
    w.edge(N1, 1, &[], A, N3, r3, &[]);
    w
}

/// A move: signer, holder, role written, `ts`, and whether the signer received what came before
/// (else the setup alone).
pub type Move = (Thing, Thing, Role, u32, bool);

fn play(r3: Role, moves: &[Move]) -> World {
    let mut w = setup(r3);
    for &(s, h, role, ts, knows) in moves {
        let n = w.commits.len();
        write(&mut w, s, ts, h, role, &|i| knows || i < 2 || i >= n);
    }
    w
}

/// V's batches from `held` (closed by evidence over everything) in `order`, cut where `cuts` says.
fn batches(w: &World, picked: &Set, logged: &Set, order: &[usize], cut: impl Fn(usize) -> bool) -> Vec<Set> {
    let held = evidence(w, picked, logged);
    let seq: Vec<Id> = order.iter().copied().filter(|i| held.contains(i)).collect();
    let mut out = vec![Set::new()];
    for (k, i) in seq.into_iter().enumerate() {
        out.last_mut().unwrap().insert(i);
        if cut(k) {
            out.push(Set::new());
        }
    }
    out.retain(|b| !b.is_empty());
    out
}

pub fn random_proof_world(seed: &mut Rng) -> ProofWorld {
    let roles = [Role::None, Role::Read, Role::Write, Role::Admin];
    let r3 = roles[1 + seed.below(3)];
    let moves: Vec<Move> = (0..1 + seed.below(4))
        .map(|_| {
            let s = NODES[seed.below(3)];
            let h = NODES[seed.below(3)];
            let role = if h == s { Role::None } else { roles[seed.below(4)] };
            (s, h, role, 1 + seed.below(8) as u32, seed.below(2) == 0)
        })
        .collect();
    let w = play(r3, &moves);
    let n = w.commits.len();
    let p = 1 + seed.below(3);
    let picked: Set = (0..n).filter(|_| seed.below(4) < p).collect();
    // what V's sources logged with them: everything, or a part (a logger lacking some)
    let logged: Set = if seed.below(2) == 0 { (0..n).collect() } else { (0..n).filter(|_| seed.below(2) == 0).collect() };
    let order = seed.perm(n);
    let cuts: Vec<bool> = (0..n).map(|_| seed.below(2) == 0).collect();
    ProofWorld { batches: batches(&w, &picked, &logged, &order, |k| cuts[k]), w }
}

/// The family: N3 admin; two moves, each by any node, setting any other node to none, read or
/// admin, or leaving, at `ts` 2 or 4, knowing what came before or not; V holding each commit or
/// not (as its sources logged them, so no closure), taking them in key order or its reverse, one
/// at a time.
pub const PROOF_MOVES: usize = 3 * 7 * 2 * 2;
pub const PROOF_FAMILY: usize = PROOF_MOVES * PROOF_MOVES * 16 * 2;

pub fn proof_family(mut k: usize) -> ProofWorld {
    let mut take = |n: usize| {
        let d = k % n;
        k /= n;
        d
    };
    let mut mv = || {
        let s = NODES[take(3)];
        let a = take(7);
        let ts = [2, 4][take(2)];
        let knows = take(2) == 1;
        let (h, role) = if a == 6 {
            (s, Role::None)
        } else {
            let others: Vec<Thing> = NODES.iter().copied().filter(|&o| o != s).collect();
            (others[a % 2], [Role::None, Role::Read, Role::Admin][a / 2])
        };
        (s, h, role, ts, knows)
    };
    let m1 = mv();
    let m2 = mv();
    let w = play(Role::Admin, &[m1, m2]);
    let bits = take(16);
    let picked: Set = (0..4).filter(|i| bits >> i & 1 == 1).collect();
    let mut order: Vec<usize> = (0..4).collect();
    if take(2) == 1 {
        order.reverse();
    }
    // V's sources logged only what V holds: closed over the picked commits alone
    ProofWorld { batches: batches(&w, &picked, &picked, &order, |_| true), w }
}

/// V's trust set after taking in `batches` one by one (Sides, held first: a held lowering its
/// reading applied, no side in its fight yet, whose seed a batch brings, is recorded). V writes
/// nothing, so it has no own sides.
pub fn sides_after(w: &World, rules: &Rules, held: &Set, trust: &Set, batch: &Set) -> Set {
    let now: Set = held.union(batch).copied().collect();
    let v_now = View { held: now, leaves: None, trust: Set::new() };
    let seeds_of = seeds_once(w, rules, &v_now);
    let before = judge(w, rules, &View { held: held.clone(), leaves: None, trust: trust.clone() });
    let mut t = trust.clone();
    for &r in held {
        if trust.contains(&r) || !candidate(w, rules, r) || !before.applied.contains(&r) || before.by_flag.contains(&r) {
            continue;
        }
        if trust.iter().any(|&l| against_by(w, rules, r, l, &seeds_of)) {
            continue;
        }
        if seeds_of(r).iter().any(|j| batch.contains(j)) {
            t.insert(r);
        }
    }
    t
}

pub fn trust_of(w: &World, rules: &Rules, batches: &[Set]) -> Set {
    let (mut held, mut trust) = (Set::new(), Set::new());
    for b in batches {
        trust = sides_after(w, rules, &held, &trust, b);
        held.extend(b);
    }
    trust
}

/// The role P's claimed path [P, A] gives in a reading (its key hop stands at admin: no key
/// writes here).
pub fn path_role(rd: &Reading, p: Thing) -> Role {
    rd.role(p, A)
}

/// What a proof of P with copies `c` proves at V (held `held`, trust `trust`): the role its path
/// gives, None for nothing.
pub fn proven(w: &World, rules: &Rules, pr: ProofRules, held: &Set, trust: &Set, own: &Reading, p: Thing, c: &Set) -> Role {
    let rd = proof_reading(w, rules, pr, held, trust, c);
    if pr.guard && !undone(w, own, &rd).is_empty() {
        return Role::None;
    }
    path_role(&rd, p)
}

/// The reading a proof is judged on: what V holds with the copies, under V's trust set, or
/// (`receipt`) the one taking them in would record.
pub fn proof_reading(w: &World, rules: &Rules, pr: ProofRules, held: &Set, trust: &Set, c: &Set) -> Reading {
    let all: Set = held.union(c).copied().collect();
    let trust = if pr.receipt { sides_after(w, rules, held, trust, c) } else { trust.clone() };
    judge(w, rules, &View { held: all, leaves: None, trust })
}

/// The lowerings (grant writes giving below admin at their `ts`, spec/permissions.md §5.1) V's own
/// reading applies that a reading `rd` undoes: does not apply, with the edge above what the
/// lowering set (not one an earlier lowering made idle).
pub fn undone(w: &World, own: &Reading, rd: &Reading) -> Vec<Id> {
    own.applied
        .iter()
        .copied()
        .filter(|&i| w.lowers(i).is_some())
        .filter(|&i| {
            let (Some(e), Kind::Edge { role, .. }) = (w.sets(i), &w.commits[i].kind) else { return false };
            !rd.applied.contains(&i) && rd.role(e.0, e.1) > *role
        })
        .collect()
}

/// The proven role of a peer whose path to A gives `path` (spec/sync-opens.md §2: A, proven, holds
/// `ON_S` on S).
pub fn j(pr: ProofRules, path: Role) -> Role {
    match path {
        Role::None => Role::None,
        _ if pr.j_path => path.min(ON_S),
        _ => ON_S,
    }
}

pub type ProofStats = Findings<ProofWorld>;

/// Every check on one world, for each prover and each set of copies V lacks (all of them up to
/// 2^7 sets, else 96 drawn).
pub fn proof_check(m: &ProofWorld, pr: ProofRules, st: &mut ProofStats, rng: &mut Rng) {
    let w = &m.w;
    let rules = Rules::fixed();
    let held = m.held();
    let trust = trust_of(w, &rules, &m.batches);
    let own = judge(w, &rules, &View { held: held.clone(), leaves: None, trust: trust.clone() });
    let missing: Vec<Id> = (0..w.commits.len()).filter(|i| !held.contains(i)).collect();
    let all: Set = (0..w.commits.len()).collect();
    let everything = judge(w, &rules, &View { held: all.clone(), leaves: None, trust: trust_of(w, &rules, &[held.clone(), all.difference(&held).copied().collect()]) });
    let copies: Vec<Set> = if missing.len() <= 7 {
        (0..1usize << missing.len()).map(|b| missing.iter().enumerate().filter(|(k, _)| b >> k & 1 == 1).map(|(_, &i)| i).collect()).collect()
    } else {
        std::iter::once(Set::new()).chain((0..95).map(|_| missing.iter().copied().filter(|_| rng.below(2) == 0).collect())).collect()
    };
    st.worlds += 1;
    let mut fails = vec![];
    for p in NODES {
        for c in &copies {
            let got = proven(w, &rules, pr, &held, &trust, &own, p, c);
            st.count("proofs", 1);
            let with: Set = held.union(c).copied().collect();
            let rd = proof_reading(w, &rules, pr, &held, &trust, c);
            // revive: no lowering V's own reading applies is undone where the proof stands
            let undone = undone(w, &own, &rd);
            if got > Role::None && !undone.is_empty() {
                fails.push(format!("revive: P {p} proven {got:?} with copies {c:?}, undoing {undone:?} V's own reading applies"));
            }
            // receipt: no more than taking the copies in proves
            let recv = judge(w, &rules, &View { held: with, leaves: None, trust: sides_after(w, &rules, &held, &trust, c) });
            if got > Role::None && path_role(&recv, p) == Role::None {
                fails.push(format!("receipt: P {p} proven {got:?} with copies {c:?}; taken in, they prove nothing"));
            }
            if c.is_empty() && got != path_role(&own, p) {
                fails.push(format!("own: P {p} with no copies proven {got:?}, V's own reading {:?}", path_role(&own, p)));
            }
            // j-path: the proven role never above the path's role on S
            let jr = j(pr, got);
            if jr > got.min(ON_S) {
                fails.push(format!("j-path: P {p} proven at {got:?} trusted as {jr:?} on S"));
            }
            if got == Role::None && path_role(&everything, p) > Role::None && path_role(&rd, p) > Role::None {
                st.count("denied", 1);
            }
            if got > Role::None && path_role(&everything, p) == Role::None {
                st.count("stale", 1);
            }
        }
        // fresh: V holds no write on (P, A); honest copies (every write on it, closed) prove
        // where the reading of everything does, unless they undo a lowering V's own reading
        // applies; then (waits) once V holds what its own evidence brings, they do
        let on_edge: Set = (0..w.commits.len()).filter(|&i| w.sets(i) == Some((p, A))).collect();
        if p != N1 && on_edge.is_disjoint(&held) {
            let honest: Set = evidence(w, &on_edge, &all).difference(&held).copied().collect();
            let got = proven(w, &rules, pr, &held, &trust, &own, p, &honest);
            let want = path_role(&everything, p);
            let rd = proof_reading(w, &rules, pr, &held, &trust, &honest);
            st.count("fresh", 1);
            if want > Role::None && got == Role::None && undone(w, &own, &rd).is_empty() {
                fails.push(format!("fresh: P {p} by honest copies {honest:?} proves nothing; everything gives {want:?}"));
            }
            if want > Role::None && got == Role::None && !undone(w, &own, &rd).is_empty() {
                st.count("waits", 1);
                let later = evidence(w, &held, &all);
                let t2 = sides_after(w, &rules, &held, &trust, &later.difference(&held).copied().collect());
                let own2 = judge(w, &rules, &View { held: later.clone(), leaves: None, trust: t2.clone() });
                let honest2: Set = honest.difference(&later).copied().collect();
                let got2 = proven(w, &rules, pr, &later, &t2, &own2, p, &honest2);
                let want2 = path_role(&judge(w, &rules, &View { held: later.union(&honest2).copied().collect(), leaves: None, trust: t2 }), p);
                if got2 != want2 {
                    fails.push(format!("waits: P {p} by honest copies {honest:?} denied; with V's own evidence {later:?} proven {got2:?}, its reading {want2:?}"));
                }
            }
        }
    }
    st.failed(fails, m);
}

pub fn proofs_random(from: u64, n: u64, pr: ProofRules) -> ProofStats {
    each_world(0x9f00f, from..from + n, |rng, st: &mut ProofStats| {
        let m = random_proof_world(rng);
        proof_check(&m, pr, st, rng);
    })
}

pub fn proofs_family(pr: ProofRules, stride: usize) -> ProofStats {
    crate::family_on_every_core(PROOF_FAMILY, stride, |k, st: &mut ProofStats| {
        let mut rng = Rng::thread(0, k);
        proof_check(&proof_family(k), pr, st, &mut rng);
    })
}

/// `-- N proofs[-exh][-control]`: N random worlds, or every Nth family world.
pub fn proofs_run(samples: u64, from: u64, mode: &str) -> u64 {
    let Some(pr) = ProofRules::named(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    let st = if mode.starts_with("proofs-exh") { proofs_family(pr, samples.max(1) as usize) } else { proofs_random(from, samples, pr) };
    st.print(mode);
    for (f, m) in &st.fail {
        println!("{f}\n  world: {}", proof_trace(m));
    }
    st.failures
}

pub fn proof_trace(m: &ProofWorld) -> String {
    let w = &m.w;
    let lines: Vec<String> = w
        .commits
        .iter()
        .enumerate()
        .map(|(i, c)| match &c.kind {
            Kind::Edge { holder, role, frontier, .. } => format!("{i}: {} sets {holder} {role:?} at {} listing {:?}", c.signer, c.ts, frontier.values().flatten().collect::<Vec<_>>()),
            k => format!("{i}: {k:?}"),
        })
        .collect();
    format!("{}; V took {:?}", lines.join("; "), m.batches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use Role::{Admin, None as Gone};

    fn own(w: &World, held: &Set, trust: &Set) -> Reading {
        judge(w, &Rules::fixed(), &View { held: held.clone(), leaves: None, trust: trust.clone() })
    }

    // spec: sync-opens.md §2 Connection proofs
    #[test]
    fn a_mint_admin_proves_its_account_by_the_record_edge() {
        let w = setup(Admin);
        let held: Set = (0..2).collect();
        let rd = own(&w, &held, &Set::new());
        for p in NODES {
            assert_eq!(proven(&w, &Rules::fixed(), ProofRules::spec(), &held, &Set::new(), &rd, p, &Set::new()), Admin, "{p}");
        }
    }

    /// The removed node's own counter-removal, carried as a copy: V holds N2's removal of N1 at 5
    /// (applied); N1 carries its removal of N2 at 3, made after it learned of its own. As written
    /// (copies judged beside what V holds, no side recorded) N2's removal has no right and N1 is A
    /// again; taken in by sync, V would record N2's removal as trusted (held first) and N1 stays
    /// removed. The guard keeps V's own lowering.
    #[test]
    fn a_removed_node_carrying_its_counter_removal_proves_nothing() {
        let mut w = setup(Admin);
        let r = write(&mut w, N2, 5, N1, Gone, &|_| true);
        let x = write(&mut w, N1, 3, N2, Gone, &|i| i != r);
        let held: Set = [0, 1, r].into();
        let trust = trust_of(&w, &Rules::fixed(), &[held.clone()]);
        let rd = own(&w, &held, &trust);
        assert_eq!(path_role(&rd, N1), Gone);
        let c: Set = [x].into();
        assert_eq!(proven(&w, &Rules::fixed(), ProofRules::draft(), &held, &trust, &rd, N1, &c), Admin, "as written");
        assert_eq!(proven(&w, &Rules::fixed(), ProofRules { receipt: true, ..ProofRules::draft() }, &held, &trust, &rd, N1, &c), Gone, "taken in");
        assert_eq!(proven(&w, &Rules::fixed(), ProofRules::spec(), &held, &trust, &rd, N1, &c), Gone, "fixed");
    }

    /// A third party's removal of the remover, cherry-picked: N3 removed N2 at 3, but N1 had
    /// removed N3 at 2 (so N3's removal has no right, and N2's removal of N1 at 5 applies). V holds
    /// N2's removal alone; N1 carries N3's removal and not its own of N3. No side helps (N3's
    /// removal is no seed of N2's): received or not, N1 is A again until V holds N1's removal of
    /// N3, which nothing brings it (the copies are kept with the connection alone).
    #[test]
    fn a_cherry_picked_removal_of_the_remover_proves_nothing() {
        let mut w = setup(Admin);
        let wn = write(&mut w, N1, 2, N3, Gone, &|_| true);
        let z = write(&mut w, N3, 3, N2, Gone, &|i| i != wn);
        let r = write(&mut w, N2, 5, N1, Gone, &|i| i < 2);
        let held: Set = [0, 1, r].into();
        let trust = trust_of(&w, &Rules::fixed(), &[held.clone()]);
        let rd = own(&w, &held, &trust);
        let all = judge(&w, &Rules::fixed(), &View::all(&w));
        assert_eq!((path_role(&rd, N1), path_role(&all, N1)), (Gone, Gone));
        let c: Set = [z].into();
        let recv = ProofRules { receipt: true, guard: false, j_path: true };
        assert_eq!(proven(&w, &Rules::fixed(), recv, &held, &trust, &rd, N1, &c), Admin, "taken in");
        assert_eq!(proven(&w, &Rules::fixed(), ProofRules::spec(), &held, &trust, &rd, N1, &c), Gone, "fixed");
    }

    /// Copies judged with the sides taking them in records (control `-no-receipt`): N1's removal of N3
    /// at 4 is a seed of N2's demotion of N1 at 5 that V's reading applies; taken in, V sides with
    /// the demotion and N3 keeps read. Judged under V's trust set as it stands, the copies prove N3
    /// nothing until V receives the removal by sync, which no unit V syncs may carry.
    #[test]
    fn honest_copies_are_judged_with_the_sides_their_receipt_records() {
        let mut w = setup(Role::Read);
        w.edge(N2, 5, &[], A, N1, Role::Read, &[0, 1]);
        let rm = w.edge(N1, 4, &[], A, N3, Gone, &[]);
        w.edge(N1, 2, &[], A, N2, Admin, &[]);
        w.edge(N2, 4, &[], A, N1, Role::Read, &[0, 1, 3, 4]);
        let held: Set = [0, 2, 4, 5].into();
        let trust = trust_of(&w, &Rules::fixed(), &[[4].into(), [0].into(), [2, 5].into()]);
        let rd = own(&w, &held, &trust);
        let c: Set = [1, rm].into();
        assert_eq!(proven(&w, &Rules::fixed(), ProofRules::spec(), &held, &trust, &rd, N3, &c), Role::Read);
        assert_eq!(proven(&w, &Rules::fixed(), ProofRules { receipt: false, ..ProofRules::spec() }, &held, &trust, &rd, N3, &c), Gone);
    }

    /// Without `j_path` the proven role is the proven thing's role on S whatever the path gives: N3 holding read on A is
    /// trusted as a writer of S.
    #[test]
    fn j_reads_the_claimed_path_role() {
        assert_eq!(j(ProofRules::draft(), Role::Read), Role::Write);
        assert_eq!(j(ProofRules::spec(), Role::Read), Role::Read);
    }

    /// The searches at small size: the spec's rules hold, the guard's and the path role's controls fail.
    #[test]
    #[ignore = "property"]
    fn proofs_hold_plain() {
        let st = proofs_random(0, 2000, ProofRules::spec());
        assert_eq!(st.failures, 0, "{:?} {:?}", st.kinds, st.fail.iter().map(|f| &f.0).collect::<Vec<_>>());
        for (mode, kind) in [("proofs-no-guard", "revive"), ("proofs-no-j", "j-path")] {
            let st = proofs_random(0, 2000, ProofRules::named(mode).unwrap());
            assert!(st.kinds.contains_key(kind), "{mode}: {:?}", st.kinds);
        }
    }

    #[test]
    #[ignore = "property"]
    fn proofs_hold_large() {
        let st = proofs_random(0, 20_000, ProofRules::spec());
        st.print("proofs");
        assert_eq!(st.failures, 0, "{:?}", st.fail.iter().map(|f| &f.0).collect::<Vec<_>>());
    }
}
