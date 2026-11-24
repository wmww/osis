//! The own self-removal exception of Encrypting under (spec/crypto.md §4) and the wait it ends on
//! (spec/sync-status.md §2 Held elsewhere; spec/permissions.md §3 Lost access): a holder X of T
//! leaves T by a self-removal made by a node M through a path to X; a node J holding that commit
//! is exempt from the departure's block while the commit is not held elsewhere, and drops T once
//! it is. Findings: notes/accounts-switch-brief.md, Models.
//!
//! The world: nodes N1, N2 (A's admins or writer), B (a member of G) and O (T's admin, staying);
//! things A (the account), G (a group A may administer) and T; grants as `Grants`; X is A or G;
//! M a node holding admin on X. Roles are effective roles (the most over paths, the least along
//! one). T's current epoch e is boxed to its holders before the leave, so every node holding read
//! on T then opens it.
//!
//! Rules (`LeaveRules`): `spec` as written (J is exempt where its own things administer X,
//! whichever node made the leave; any peer holding the commit counts for held elsewhere: core
//! reads no account, so "a node's own other nodes" names nobody); `fixed` (exempt only where J may
//! not rotate T's read role: one that may rotates first, as for any departure; a peer counts for a
//! self-removal only where a thing it proved holds a role on T with the leave applied). Properties:
//! - `content`: what J writes on T after the leave, under e, opens only for the nodes holding T
//!   after it, and J (the departure covers every reader it made);
//! - `log`: J can log the leave under T's sync IDs: exempt, or it may rotate;
//! - `lost`: once every node losing T by the leave has dropped T, a node keeping T holds the leave.

use crate::{each_world, Findings, Rng, Role};

pub const N1: usize = 0;
pub const N2: usize = 1;
pub const B: usize = 2;
pub const O: usize = 3;
pub const NODES: usize = 4;
pub const A: usize = 0;
pub const G: usize = 1;

/// The grants: N1 admin on A; N2 on A; A and B on G; A, G, N1 and B on T; O admin on T.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Grants {
    pub n2_a: Role,
    pub a_g: Role,
    pub b_g: Role,
    pub a_t: Role,
    pub g_t: Role,
    pub n1_t: Role,
    pub b_t: Role,
}

#[derive(Clone, Debug)]
pub struct LeaveWorld {
    pub g: Grants,
    /// The holder leaving T (A or G), the node making the leave, the node judging.
    pub x: usize,
    pub m: usize,
    pub j: usize,
    /// Pairs of nodes syncing T, in order.
    pub syncs: Vec<(usize, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LeaveRules {
    pub may_not_rotate: bool,
    pub staying_sources: bool,
}

impl LeaveRules {
    pub fn spec() -> LeaveRules {
        LeaveRules { may_not_rotate: false, staying_sources: false }
    }
    pub fn fixed() -> LeaveRules {
        LeaveRules { may_not_rotate: true, staying_sources: true }
    }
    pub fn named(mode: &str) -> Option<LeaveRules> {
        let f = LeaveRules::fixed();
        let rest = mode.strip_prefix("leave").unwrap_or(mode);
        Some(match rest.strip_prefix("-exh").unwrap_or(rest) {
            "" => f,
            "-spec" => LeaveRules::spec(),
            "-rotating" => LeaveRules { may_not_rotate: false, ..f },
            "-any-source" => LeaveRules { staying_sources: false, ..f },
            _ => return None,
        })
    }
}

/// A node's role on A, on G and on T (with X's grant on T or without it, after the leave).
pub fn roles(g: &Grants, n: usize, left: Option<usize>) -> [Role; 3] {
    let on_a = match n {
        N1 => Role::Admin,
        N2 => g.n2_a,
        _ => Role::None,
    };
    let on_g = on_a.min(g.a_g).max(if n == B { g.b_g } else { Role::None });
    let (a_t, g_t) = (if left == Some(A) { Role::None } else { g.a_t }, if left == Some(G) { Role::None } else { g.g_t });
    let direct = match n {
        N1 => g.n1_t,
        B => g.b_t,
        O => Role::Admin,
        _ => Role::None,
    };
    [on_a, on_g, direct.max(on_a.min(a_t)).max(on_g.min(g_t))]
}

pub type LeaveStats = Findings<LeaveWorld>;

pub fn leave_check(lw: &LeaveWorld, r: LeaveRules, st: &mut LeaveStats) {
    let (g, x, m, j) = (&lw.g, lw.x, lw.m, lw.j);
    let before = |n: usize| roles(g, n, None);
    let after = |n: usize| roles(g, n, Some(x));
    // a world: X holds a role on T, M administers X
    let x_t = if x == A { g.a_t } else { g.g_t };
    if x_t == Role::None || before(m)[x] != Role::Admin {
        return;
    }
    st.worlds += 1;
    let mut fails = vec![];
    // J's own things administer X: the leave is its own (whichever node made it)
    let own = before(j)[x] == Role::Admin;
    // what J's role on T gives after the leave: writing, and rotating the read role
    let writes = after(j)[2] >= Role::Write;
    let exempt = own && !(r.may_not_rotate && writes);
    if own {
        st.count("own", 1);
        // content: J writes under e only where exempt (else it rotates first, or writes nothing)
        if writes && exempt {
            let leak: Vec<usize> = (0..NODES).filter(|&n| n != j && before(n)[2] >= Role::Read && after(n)[2] < Role::Read).collect();
            if !leak.is_empty() {
                fails.push(format!("content: J {j} writes T under e after X {x} left; nodes {leak:?} hold T no more and open it"));
            }
        }
        if !exempt && !writes {
            fails.push(format!("log: J {j} may not rotate T and is not exempt: its leave cannot be logged"));
        }
    }
    // lost: the leave spreads by syncs among nodes holding T; a node losing T by it drops T once a
    // peer that counts holds it (held elsewhere), and holds and passes nothing of T after
    if j == m {
        let loses = |n: usize| before(n)[2] >= Role::Read && after(n)[2] < Role::Read;
        let counts = |p: usize| !r.staying_sources || after(p)[2] >= Role::Read;
        let mut holds = [false; NODES];
        let mut dropped = [false; NODES];
        holds[m] = true;
        for &(u, v) in &lw.syncs {
            let live = |n: usize| before(n)[2] >= Role::Read && !dropped[n];
            if !live(u) || !live(v) || !(holds[u] || holds[v]) {
                continue;
            }
            holds[u] = true;
            holds[v] = true;
            // each side now sees the other hold it
            for (a, b) in [(u, v), (v, u)] {
                if loses(a) && counts(b) {
                    dropped[a] = true;
                    holds[a] = false;
                }
            }
        }
        let all_dropped = (0..NODES).filter(|&n| loses(n)).all(|n| dropped[n]);
        if all_dropped && !(0..NODES).any(|n| !loses(n) && holds[n]) {
            fails.push(format!("lost: every node leaving T dropped it; no node keeping T holds the leave (syncs {:?})", lw.syncs));
        }
    }
    st.failed(fails, lw);
}

const ROLES: [Role; 4] = [Role::None, Role::Read, Role::Write, Role::Admin];

fn grants(mut k: usize) -> (Grants, usize) {
    let mut take = |n: usize| {
        let d = k % n;
        k /= n;
        d
    };
    let g = Grants {
        n2_a: [Role::Write, Role::Admin][take(2)],
        a_g: [Role::None, Role::Write, Role::Admin][take(3)],
        b_g: [Role::None, Role::Write, Role::Admin][take(3)],
        a_t: ROLES[take(4)],
        g_t: ROLES[take(4)],
        n1_t: [Role::None, Role::Write][take(2)],
        b_t: [Role::None, Role::Read][take(2)],
    };
    (g, k)
}

pub const GRANTS: usize = 2 * 3 * 3 * 4 * 4 * 2 * 2;
pub const PAIRS: [(usize, usize); 6] = [(N1, N2), (N1, B), (N1, O), (N2, B), (N2, O), (B, O)];
/// The family: every grant set, X, M and J, and every sync schedule of up to 3 syncs.
pub const SCHEDULES: usize = 1 + 6 + 36 + 216;
pub const LEAVE_FAMILY: usize = GRANTS * 2 * 4 * 4 * SCHEDULES;

pub fn leave_family(k: usize) -> LeaveWorld {
    let (g, mut k) = grants(k);
    let mut take = |n: usize| {
        let d = k % n;
        k /= n;
        d
    };
    let x = [A, G][take(2)];
    let m = take(4);
    let j = take(4);
    let mut s = take(SCHEDULES);
    let mut syncs = vec![];
    let len = if s == 0 { 0 } else if s < 7 { 1 } else if s < 43 { 2 } else { 3 };
    s -= [0, 1, 7, 43][len];
    for _ in 0..len {
        syncs.push(PAIRS[s % 6]);
        s /= 6;
    }
    LeaveWorld { g, x, m, j, syncs }
}

pub fn random_leave_world(rng: &mut Rng) -> LeaveWorld {
    let (g, _) = grants(rng.below(GRANTS));
    let syncs = (0..rng.below(7)).map(|_| PAIRS[rng.below(6)]).collect();
    LeaveWorld { g, x: [A, G][rng.below(2)], m: rng.below(4), j: rng.below(4), syncs }
}

pub fn leave_run(samples: u64, mode: &str) -> u64 {
    let Some(r) = LeaveRules::named(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    let st: LeaveStats = if mode.starts_with("leave-exh") {
        crate::family_on_every_core(LEAVE_FAMILY, samples.max(1) as usize, |k, st: &mut LeaveStats| leave_check(&leave_family(k), r, st))
    } else {
        each_world(0x1ea7e, 0..samples, |rng, st: &mut LeaveStats| leave_check(&random_leave_world(rng), r, st))
    };
    st.print(mode);
    for (f, w) in &st.fail {
        println!("{f}\n  world: {w:?}");
    }
    st.failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use Role::{Admin, None as Gone, Read, Write};

    fn world(g: Grants, x: usize, m: usize, j: usize, syncs: Vec<(usize, usize)>) -> LeaveWorld {
        LeaveWorld { g, x, m, j, syncs }
    }

    /// A leaves T; N1 also writes T directly. As written N1 is exempt and goes on writing under
    /// T's epoch, which N2 (A's other node, holding T only through A) opens.
    #[test]
    fn a_leaver_that_may_rotate_rotates_first() {
        let g = Grants { n2_a: Admin, a_g: Gone, b_g: Gone, a_t: Write, g_t: Gone, n1_t: Write, b_t: Gone };
        let w = world(g, A, N1, N1, vec![]);
        let mut st = LeaveStats::default();
        leave_check(&w, LeaveRules::spec(), &mut st);
        assert_eq!(st.kinds.keys().collect::<Vec<_>>(), ["content"]);
        let mut st = LeaveStats::default();
        leave_check(&w, LeaveRules::fixed(), &mut st);
        assert_eq!(st.failures, 0);
    }

    /// G (administered by A, B its writer) leaves T: as written N1 writing T directly is exempt and
    /// B, who holds T through G alone, opens what it writes.
    #[test]
    fn a_group_leaving_leaks_to_its_other_members_as_written() {
        let g = Grants { n2_a: Write, a_g: Admin, b_g: Write, a_t: Gone, g_t: Read, n1_t: Write, b_t: Gone };
        let mut st = LeaveStats::default();
        leave_check(&world(g, G, N1, N1, vec![]), LeaveRules::spec(), &mut st);
        assert!(st.fail[0].0.contains("[1, 2]"), "{:?}", st.fail);
    }

    /// A leaves T; N1 makes it and syncs with N2 alone: each sees the other hold it and drops T,
    /// and O never gets the leave. Counting only a peer keeping T, both wait for O.
    #[test]
    fn a_leave_held_only_by_leaving_nodes_is_not_held_elsewhere() {
        let g = Grants { n2_a: Admin, a_g: Gone, b_g: Gone, a_t: Read, g_t: Gone, n1_t: Gone, b_t: Gone };
        let w = world(g, A, N1, N1, vec![(N1, N2)]);
        let mut st = LeaveStats::default();
        leave_check(&w, LeaveRules::spec(), &mut st);
        assert_eq!(st.kinds.keys().collect::<Vec<_>>(), ["lost"]);
        let mut st = LeaveStats::default();
        leave_check(&w, LeaveRules::fixed(), &mut st);
        assert_eq!(st.failures, 0);
    }

    /// Every 101st family world (`-- 1 leave-exh` runs them all), and 20,000 random ones.
    #[test]
    #[ignore = "property"]
    fn leave_family_holds_plain() {
        let run = |r: LeaveRules| -> (LeaveStats, LeaveStats) {
            let fam = crate::family_on_every_core(LEAVE_FAMILY, 101, |k, st: &mut LeaveStats| leave_check(&leave_family(k), r, st));
            let rnd = crate::each_world(0x1ea7e, 0..20_000, |rng, st: &mut LeaveStats| leave_check(&random_leave_world(rng), r, st));
            (fam, rnd)
        };
        for st in <[LeaveStats; 2]>::from(run(LeaveRules::fixed())) {
            assert!(st.worlds > 0 && st.failures == 0, "{:?}", st.fail.iter().map(|f| &f.0).collect::<Vec<_>>());
        }
        for (mode, kind) in [("leave-spec", "content"), ("leave-spec", "lost"), ("leave-rotating", "content"), ("leave-any-source", "lost")] {
            let (fam, rnd) = run(LeaveRules::named(mode).unwrap());
            assert!(fam.kinds.contains_key(kind) && rnd.kinds.contains_key(kind), "{mode}: {:?} {:?}", fam.kinds, rnd.kinds);
        }
    }
}
