//! Throwaway model of the layer-1 membership validity rule (notes/permissions.md,
//! "Validity definition"). Independent of any real implementation. One group actor G;
//! actor i has exactly one node i; actor 0 is G's owner (always admin, unremovable).
//! Run: `cargo run --release` (exhaustive tiers + random sample), `cargo test` (scenarios).

use std::collections::HashSet;

const OWNER: usize = 0;
/// Receipt time meaning "much later than anything else".
const LATE: u32 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
enum Role {
    None,
    Write,
    Admin,
}

#[derive(Clone, Debug)]
struct MWrite {
    author: usize,
    target: usize,
    role: Role,
    t: u32,
}

/// Everything an evaluator holds once all commits, attestations and receipts have spread.
/// Every node eventually receives every write; `recv` is the receipt time on the
/// receiver's clock (author: its own `t`). Node n's attestation answering write r is
/// published when n receives r and covers every write n received before `t(r)`.
#[derive(Clone, Debug)]
struct Hist {
    genesis: Vec<Role>,
    writes: Vec<MWrite>,
    /// [write][node]
    recv: Vec<Vec<u32>>,
    /// [answered write][attester][receiver]
    att_recv: Vec<Vec<Vec<u32>>>,
    /// Content writes (author, t) and their receipts [content][node].
    content: Vec<(usize, u32)>,
    recv_c: Vec<Vec<u32>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Outcome {
    roles: Vec<Role>,
    applied: u64,
}

struct Walk {
    roles: Vec<Role>,
    applied: u64,
    /// Last applied write that took the actor from admin to below.
    adm_rev: Vec<Option<usize>>,
    /// Last applied write that took the actor from write+ to none.
    wr_rev: Vec<Option<usize>>,
    /// valid[r][n]: node n's attestation answering write r is valid.
    att_valid: Vec<Vec<bool>>,
}

/// Which rule variant to evaluate.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Rule {
    /// As written: witnesses are judged by the end-of-walk membership.
    AsWritten,
    /// The write that removed an actor is not itself judged as that actor's write.
    ExemptOwnRevoke,
    /// One forward walk; each removal is judged with the state at its own point
    /// (`Hist::stratified`). Not a fixpoint, so no stable sets.
    Stratified,
    /// Stratified, but write+ nodes witness membership writes (as the notes say today).
    StratifiedW,
}

impl Hist {
    fn n(&self) -> usize {
        self.genesis.len()
    }

    fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| (self.writes[i].t, self.writes[i].author));
        o
    }

    /// Walk the timeline skipping `dropped`, then compute attestation validity.
    fn walk(&self, dropped: u64) -> Walk {
        let n = self.n();
        let mut roles = self.genesis.clone();
        roles[OWNER] = Role::Admin;
        let mut applied = 0u64;
        let mut adm_rev = vec![None; n];
        let mut wr_rev = vec![None; n];
        for i in self.order() {
            let w = &self.writes[i];
            if dropped >> i & 1 == 1 || w.target == OWNER {
                continue;
            }
            if w.author != OWNER && roles[w.author] != Role::Admin {
                continue;
            }
            let old = roles[w.target];
            roles[w.target] = w.role;
            applied |= 1 << i;
            if old == Role::Admin && w.role < Role::Admin {
                adm_rev[w.target] = Some(i);
            }
            if old >= Role::Write && w.role == Role::None {
                wr_rev[w.target] = Some(i);
            }
        }
        let att_valid = self.att_fixpoint(&roles, &wr_rev, applied);
        Walk { roles, applied, adm_rev, wr_rev, att_valid }
    }

    /// Least fixpoint of attestation validity: seeded by attesters with write+ at the end
    /// and by the revoker's own frontier embedded in each applied write; an attestation by
    /// a removed node is valid iff a valid attestation answering that node's removal
    /// shows its receipt before the removal time.
    fn att_fixpoint(&self, roles: &[Role], wr_rev: &[Option<usize>], applied: u64) -> Vec<Vec<bool>> {
        let n = self.n();
        let k = self.writes.len();
        let mut v = vec![vec![false; n]; k];
        for r in 0..k {
            for a in 0..n {
                v[r][a] = roles[a] >= Role::Write || (a == self.writes[r].author && applied >> r & 1 == 1);
            }
        }
        loop {
            let mut changed = false;
            for r in 0..k {
                for a in 0..n {
                    if v[r][a] {
                        continue;
                    }
                    let Some(rv) = wr_rev[a] else { continue };
                    let t = self.writes[rv].t;
                    if (0..n).any(|m| m != a && v[rv][m] && self.att_recv[r][a][m] < t) {
                        v[r][a] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                return v;
            }
        }
    }

    /// One step: writes by actors that end below admin and are not witnessed before
    /// their demotion time.
    fn step(&self, dropped: u64, rule: Rule) -> (u64, Walk) {
        let w = self.walk(dropped);
        let mut out = 0u64;
        for (i, mw) in self.writes.iter().enumerate() {
            let a = mw.author;
            if a == OWNER || w.roles[a] == Role::Admin {
                continue;
            }
            let Some(rv) = w.adm_rev[a] else { continue };
            if rule == Rule::ExemptOwnRevoke && rv == i {
                continue;
            }
            let t = self.writes[rv].t;
            let witnessed = (0..self.n()).any(|m| m != a && w.att_valid[rv][m] && self.recv[i][m] < t);
            if !witnessed {
                out |= 1 << i;
            }
        }
        (out, w)
    }

    /// Replay `prefix` (in timeline order) skipping `dropped`. Writes in `forced` were
    /// applied at their own point and stay applied; others apply iff their author is
    /// admin at that point.
    fn replay(&self, prefix: &[usize], dropped: u64, forced: u64) -> Walk {
        let n = self.n();
        let mut roles = self.genesis.clone();
        roles[OWNER] = Role::Admin;
        let mut applied = 0u64;
        let mut adm_rev = vec![None; n];
        let mut wr_rev = vec![None; n];
        for &i in prefix {
            let w = &self.writes[i];
            if dropped >> i & 1 == 1 || w.target == OWNER {
                continue;
            }
            if forced >> i & 1 == 0 && w.author != OWNER && roles[w.author] != Role::Admin {
                continue;
            }
            let old = roles[w.target];
            roles[w.target] = w.role;
            applied |= 1 << i;
            if old == Role::Admin && w.role < Role::Admin {
                adm_rev[w.target] = Some(i);
            }
            if old >= Role::Write && w.role == Role::None {
                wr_rev[w.target] = Some(i);
            }
        }
        Walk { roles, applied, adm_rev, wr_rev, att_valid: vec![] }
    }

    /// Candidate rule. Walk membership writes once in (HLC, node) order; a write applies
    /// iff its author is admin at that point. When write r at time T takes actors below
    /// admin (normally just its target), those actors' earlier writes and attestations
    /// stay only if received before T by a node that is admin just before r (excluding
    /// the removed ones; the revoker's own frontier counts). Dropping them is replayed
    /// immediately; anyone who thereby loses admin is treated as removed by r too
    /// (closure). r itself always stands. Dropped attestations are permanent; if a pass
    /// drops any, walk again. Terminates: attestation drops only grow.
    fn stratified(&self, witness: Role) -> (Walk, usize) {
        let n = self.n();
        let k = self.writes.len();
        let order = self.order();
        let mut att_drop = vec![vec![false; n]; k];
        let mut passes = 0;
        loop {
            passes += 1;
            let mut new_att_drop = false;
            let mut dropped = 0u64;
            let mut forced = 0u64;
            for pos in 0..order.len() {
                let r = order[pos];
                let w = &self.writes[r];
                let before = self.replay(&order[..pos], dropped, forced).roles;
                if w.target == OWNER || (w.author != OWNER && before[w.author] != Role::Admin) {
                    continue;
                }
                forced |= 1 << r;
                let mut after = self.replay(&order[..=pos], dropped, forced).roles;
                let mut q: Vec<bool> = (0..n).map(|x| before[x] == Role::Admin && after[x] != Role::Admin).collect();
                loop {
                    let witnessed = |recv: &dyn Fn(usize) -> u32, att_drop: &Vec<Vec<bool>>| {
                        (0..n).any(|m| {
                            before[m] >= witness && !q[m] && (m == w.author || !att_drop[r][m]) && recv(m) < w.t
                        })
                    };
                    for &i in &order[..pos] {
                        let x = self.writes[i].author;
                        if x != OWNER && q[x] && !witnessed(&|m| self.recv[i][m], &att_drop) {
                            dropped |= 1 << i;
                        }
                    }
                    for &r2 in &order[..pos] {
                        for x in 0..n {
                            if q[x] && x != OWNER && !att_drop[r2][x] && !witnessed(&|m| self.att_recv[r2][x][m], &att_drop) {
                                att_drop[r2][x] = true;
                                new_att_drop = true;
                            }
                        }
                    }
                    after = self.replay(&order[..=pos], dropped, forced).roles;
                    let mut grew = false;
                    for x in 0..n {
                        if before[x] == Role::Admin && after[x] != Role::Admin && !q[x] {
                            q[x] = true;
                            grew = true;
                        }
                    }
                    if !grew {
                        break;
                    }
                }
            }
            if !new_att_drop {
                let mut w = self.replay(&order, dropped, forced);
                w.att_valid = self.att_fixpoint(&w.roles, &w.wr_rev, w.applied);
                return (w, passes);
            }
        }
    }

    fn droppable(&self) -> u64 {
        let mut m = 0;
        for (i, w) in self.writes.iter().enumerate() {
            if w.author != OWNER {
                m |= 1 << i;
            }
        }
        m
    }

    /// All D with step(D) == D, as distinct outcomes.
    fn stable(&self, rule: Rule) -> Vec<(u64, Outcome)> {
        let mask = self.droppable();
        let mut res = Vec::new();
        let mut d = 0u64;
        loop {
            let (f, w) = self.step(d, rule);
            if f == d {
                res.push((d, Outcome { roles: w.roles, applied: w.applied }));
            }
            // next subset of mask
            d = (d.wrapping_sub(mask)) & mask;
            if d == 0 {
                break;
            }
        }
        res
    }

    /// Iterate from "nobody revoked". Err(cycle length) if it loops.
    fn iterate(&self, rule: Rule, accumulate: bool) -> Result<(u64, Outcome, usize), usize> {
        let mut seen = vec![0u64];
        let mut d = 0u64;
        loop {
            let (f, w) = self.step(d, rule);
            let next = if accumulate { d | f } else { f };
            if next == d {
                return Ok((d, Outcome { roles: w.roles, applied: w.applied }, seen.len()));
            }
            if let Some(p) = seen.iter().position(|&x| x == next) {
                return Err(seen.len() - p);
            }
            seen.push(next);
            d = next;
        }
    }

    /// Layer 2: content validity given a final walk.
    fn content_valid(&self, w: &Walk) -> Vec<bool> {
        self.content
            .iter()
            .enumerate()
            .map(|(c, &(a, _))| {
                if a == OWNER || w.roles[a] >= Role::Write {
                    return true;
                }
                let Some(rv) = w.wr_rev[a] else { return false };
                let t = self.writes[rv].t;
                (0..self.n()).any(|m| m != a && w.att_valid[rv][m] && self.recv_c[c][m] < t)
            })
            .collect()
    }
}

// ---------- history construction ----------

#[cfg_attr(not(test), allow(dead_code))]
struct Builder {
    h: Hist,
}

#[cfg_attr(not(test), allow(dead_code))]
impl Builder {
    fn new(genesis: &[Role]) -> Self {
        Builder {
            h: Hist {
                genesis: genesis.to_vec(),
                writes: vec![],
                recv: vec![],
                att_recv: vec![],
                content: vec![],
                recv_c: vec![],
            },
        }
    }
    /// Membership write; `recv` lists (node, time) receipts, others get LATE.
    fn set(&mut self, author: usize, target: usize, role: Role, t: u32, recv: &[(usize, u32)]) -> usize {
        let n = self.h.n();
        let mut r = vec![LATE; n];
        r[author] = t;
        for &(m, tm) in recv {
            r[m] = tm;
        }
        self.h.writes.push(MWrite { author, target, role, t });
        self.h.recv.push(r);
        self.h.writes.len() - 1
    }
    fn content(&mut self, author: usize, t: u32, recv: &[(usize, u32)]) -> usize {
        let n = self.h.n();
        let mut r = vec![LATE; n];
        r[author] = t;
        for &(m, tm) in recv {
            r[m] = tm;
        }
        self.h.content.push((author, t));
        self.h.recv_c.push(r);
        self.h.content.len() - 1
    }
    /// Attestations are received by everyone the moment they are published.
    fn build(mut self) -> Hist {
        fill_att_immediate(&mut self.h);
        self.h
    }
}

fn fill_att_immediate(h: &mut Hist) {
    let n = h.n();
    h.att_recv = (0..h.writes.len()).map(|r| (0..n).map(|a| vec![h.recv[r][a]; n]).collect()).collect();
}

fn fill_att_late(h: &mut Hist) {
    let n = h.n();
    h.att_recv = (0..h.writes.len())
        .map(|r| (0..n).map(|a| (0..n).map(|m| if m == a { h.recv[r][a] } else { LATE }).collect()).collect())
        .collect();
}

// ---------- search ----------

#[derive(Default)]
struct Stats {
    histories: u64,
    cycles: u64,
    no_stable: u64,
    multi_stable: u64,
    acc_unstable: u64,
    acc_differs: u64,
    order_dep: u64,
    l2_nonmono: u64,
    l1_nonmono: u64,
    ex_cycle: Option<Hist>,
    ex_multi: Option<Hist>,
    ex_none: Option<Hist>,
    ex_acc: Option<Hist>,
    /// Stratified only: differs from the as-written (exempt) iteration where that converges.
    disagree: u64,
    disagree_roles: u64,
    honest_mismatch: u64,
    ex_honest: Option<Hist>,
    max_passes: usize,
    ex_disagree: Option<Hist>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.histories += o.histories;
        self.cycles += o.cycles;
        self.no_stable += o.no_stable;
        self.multi_stable += o.multi_stable;
        self.acc_unstable += o.acc_unstable;
        self.acc_differs += o.acc_differs;
        self.order_dep += o.order_dep;
        self.l2_nonmono += o.l2_nonmono;
        self.l1_nonmono += o.l1_nonmono;
        fn pick(a: &mut Option<Hist>, b: Option<Hist>) {
            if let Some(b) = b {
                if a.as_ref().map_or(true, |a| b.writes.len() < a.writes.len()) {
                    *a = Some(b);
                }
            }
        }
        pick(&mut self.ex_cycle, o.ex_cycle);
        pick(&mut self.ex_multi, o.ex_multi);
        pick(&mut self.ex_none, o.ex_none);
        pick(&mut self.ex_acc, o.ex_acc);
        self.disagree += o.disagree;
        self.disagree_roles += o.disagree_roles;
        self.honest_mismatch += o.honest_mismatch;
        pick(&mut self.ex_honest, o.ex_honest);
        self.max_passes = self.max_passes.max(o.max_passes);
        pick(&mut self.ex_disagree, o.ex_disagree);
    }

    fn print(&self, name: &str, rule: Rule) {
        println!(
            "{name}: {} histories | cycles {} | no stable {} | >1 stable outcome {} | accumulate-variant unstable {} differs {} | order-dependent {} | layer-2 non-monotone {} | layer-1 non-monotone {}",
            self.histories, self.cycles, self.no_stable, self.multi_stable, self.acc_unstable, self.acc_differs,
            self.order_dep, self.l2_nonmono, self.l1_nonmono
        );
        if strat_witness(rule) != Role::None {
            println!(
                "  stratified: differs from converged exempt iteration {} (final roles differ {}) | max passes {} | drops with nobody offline {}",
                self.disagree, self.disagree_roles, self.max_passes, self.honest_mismatch
            );
        }
        for (label, ex) in [("cycle", &self.ex_cycle), ("multiple stable", &self.ex_multi), ("no stable", &self.ex_none), ("accumulate unstable", &self.ex_acc), ("disagreement", &self.ex_disagree), ("drop with nobody offline", &self.ex_honest)] {
            if let Some(h) = ex {
                println!("  smallest {label} example:");
                print_hist(h, rule);
            }
        }
    }
}

fn print_hist(h: &Hist, rule: Rule) {
    println!("    genesis {:?}", h.genesis);
    for i in h.order() {
        let w = &h.writes[i];
        println!("    w{i}: {} sets {} := {:?} at t={} | recv {:?}", w.author, w.target, w.role, w.t, h.recv[i]);
    }
    if strat_witness(rule) != Role::None {
        let (w, p) = h.stratified(strat_witness(rule));
        println!("    stratified -> roles {:?} applied {:#b} ({p} passes)", w.roles, w.applied);
        print_hist(h, Rule::ExemptOwnRevoke);
        return;
    }
    for (d, o) in h.stable(rule) {
        println!("    stable D={d:#b} roles {:?} applied {:#b}", o.roles, o.applied);
    }
    match h.iterate(rule, false) {
        Ok((d, _, steps)) => println!("    iteration -> D={d:#b} after {steps} steps"),
        Err(c) => println!("    iteration cycles with period {c}"),
    }
}

fn check(h: &Hist, st: &mut Stats, rng: Option<&mut Rng>, rule: Rule) {
    st.histories += 1;
    if strat_witness(rule) != Role::None {
        return check_stratified(h, st, rng, strat_witness(rule));
    }
    let stable = h.stable(rule);
    let outcomes: HashSet<&Outcome> = stable.iter().map(|(_, o)| o).collect();
    if outcomes.is_empty() {
        st.no_stable += 1;
        st.ex_none.get_or_insert_with(|| h.clone());
    }
    if outcomes.len() > 1 {
        st.multi_stable += 1;
        st.ex_multi.get_or_insert_with(|| h.clone());
    }
    let it = h.iterate(rule, false);
    if it.is_err() {
        st.cycles += 1;
        st.ex_cycle.get_or_insert_with(|| h.clone());
    }
    let acc = h.iterate(rule, true).expect("accumulate always terminates");
    if !stable.iter().any(|(d, _)| *d == acc.0) {
        st.acc_unstable += 1;
        st.ex_acc.get_or_insert_with(|| h.clone());
    }
    if let Ok(r) = &it {
        if r.1 != acc.1 {
            st.acc_differs += 1;
        }
    }
    let Some(rng) = rng else { return };
    // Order independence: shuffle the input.
    let perm = rng.perm(h.writes.len());
    let sh = permute(h, &perm);
    let a = it.as_ref().ok().map(|r| r.1.roles.clone());
    let b = sh.iterate(rule, false).ok().map(|r| r.1.roles);
    if a != b {
        st.order_dep += 1;
    }
    // Monotone receipt (layer 2 with membership fixed): an earlier receipt at an
    // authorized node never invalidates content.
    if let Ok((d, _, _)) = it {
        let w = h.walk(d);
        let before = h.content_valid(&w);
        if !h.content.is_empty() {
            let c = rng.below(h.content.len());
            let m = rng.below(h.n());
            if w.roles[m] >= Role::Write && m != h.content[c].0 {
                let mut h2 = h.clone();
                h2.recv_c[c][m] = h2.recv_c[c][m].min(rng.below(12) as u32);
                let after = h2.content_valid(&w);
                if before.iter().zip(&after).any(|(b, a)| *b && !*a) {
                    st.l2_nonmono += 1;
                }
            }
        }
        // Layer 1: same for membership writes (expected to fail: a newly valid revoke
        // invalidates its target's later writes).
        let i = rng.below(h.writes.len());
        let m = rng.below(h.n());
        if w.roles[m] >= Role::Write && m != h.writes[i].author {
            let mut h2 = h.clone();
            h2.recv[i][m] = h2.recv[i][m].min(rng.below(12) as u32);
            if let Ok((_, o2, _)) = h2.iterate(rule, false) {
                if w.applied & !o2.applied != 0 {
                    st.l1_nonmono += 1;
                }
            }
        }
    }
}

fn strat_witness(rule: Rule) -> Role {
    match rule {
        Rule::Stratified => Role::Admin,
        Rule::StratifiedW => Role::Write,
        _ => Role::None,
    }
}

fn check_stratified(h: &Hist, st: &mut Stats, rng: Option<&mut Rng>, witness: Role) {
    let (w, passes) = h.stratified(witness);
    st.max_passes = st.max_passes.max(passes);
    if let Ok((_, o, _)) = h.iterate(Rule::ExemptOwnRevoke, false) {
        if o.roles != w.roles || o.applied != w.applied {
            st.disagree += 1;
        }
        if o.roles != w.roles {
            st.disagree_roles += 1;
            st.ex_disagree.get_or_insert_with(|| h.clone());
        }
    }
    // Nobody offline: every node receives every write at its timestamp. Nothing may drop
    // unless two writes share a timestamp (truly concurrent, so not "received before").
    let distinct = h.writes.iter().map(|w| w.t).collect::<HashSet<_>>().len() == h.writes.len();
    let mut honest = h.clone();
    for (i, r) in honest.recv.iter_mut().enumerate() {
        r.fill(h.writes[i].t);
    }
    fill_att_immediate(&mut honest);
    if distinct && honest.stratified(witness).0.roles != honest.walk(0).roles {
        st.honest_mismatch += 1;
        st.ex_honest.get_or_insert_with(|| honest.clone());
    }
    let Some(rng) = rng else { return };
    let perm = rng.perm(h.writes.len());
    if permute(h, &perm).stratified(witness).0.roles != w.roles {
        st.order_dep += 1;
    }
    if !h.content.is_empty() {
        let before = h.content_valid(&w);
        let c = rng.below(h.content.len());
        let m = rng.below(h.n());
        if w.roles[m] >= Role::Write && m != h.content[c].0 {
            let mut h2 = h.clone();
            h2.recv_c[c][m] = h2.recv_c[c][m].min(rng.below(12) as u32);
            if before.iter().zip(&h2.content_valid(&w)).any(|(b, a)| *b && !*a) {
                st.l2_nonmono += 1;
            }
        }
    }
}

fn permute(h: &Hist, perm: &[usize]) -> Hist {
    let mut g = h.clone();
    g.writes = perm.iter().map(|&i| h.writes[i].clone()).collect();
    g.recv = perm.iter().map(|&i| h.recv[i].clone()).collect();
    g.att_recv = perm.iter().map(|&i| h.att_recv[i].clone()).collect();
    g
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn perm(&mut self, n: usize) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            v.swap(i, self.below(i + 1));
        }
        v
    }
}

/// HLCs are strictly increasing per node, so (t, author) is unique.
fn unique_times(h: &Hist) -> bool {
    let mut s = HashSet::new();
    h.writes.iter().all(|w| s.insert((w.t, w.author)))
}

/// Exhaustive: owner, 2 admins, 1 writer. All writes of up to `k` by owner/admins,
/// targets the three non-owners, times {2,4,6}; receipts at non-author nodes from `recv_opts`.
fn exhaustive(k: usize, roles: &[Role], recv_opts: &[u32], late_att: bool, rule: Rule) -> Stats {
    let genesis = [Role::Admin, Role::Admin, Role::Admin, Role::Write];
    let n = genesis.len();
    let mut per_write = Vec::new();
    for author in 0..3 {
        for target in 1..4 {
            for &role in roles {
                for t in [2, 4, 6] {
                    let others: Vec<usize> = (0..n).filter(|&m| m != author).collect();
                    let combos = recv_opts.len().pow(others.len() as u32);
                    for c in 0..combos {
                        let mut r = vec![0; n];
                        r[author] = t;
                        let mut c = c;
                        for &m in &others {
                            r[m] = recv_opts[c % recv_opts.len()];
                            c /= recv_opts.len();
                        }
                        per_write.push((MWrite { author, target, role, t }, r));
                    }
                }
            }
        }
    }
    let total = per_write.len().pow(k as u32);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let per_write = &per_write;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut st = Stats::default();
                    let mut idx = th;
                    while idx < total {
                        let mut x = idx;
                        let mut h = Hist {
                            genesis: genesis.to_vec(),
                            writes: vec![],
                            recv: vec![],
                            att_recv: vec![],
                            content: vec![],
                            recv_c: vec![],
                        };
                        let mut ok = true;
                        let mut prev = 0;
                        for j in 0..k {
                            let wi = x % per_write.len();
                            x /= per_write.len();
                            // canonical order to skip permutations of the same set
                            if j > 0 && wi < prev {
                                ok = false;
                                break;
                            }
                            prev = wi;
                            h.writes.push(per_write[wi].0.clone());
                            h.recv.push(per_write[wi].1.clone());
                        }
                        idx += threads;
                        if !ok || !unique_times(&h) {
                            continue;
                        }
                        if late_att {
                            fill_att_late(&mut h);
                        } else {
                            fill_att_immediate(&mut h);
                        }
                        check(&h, &mut st, None, rule);
                    }
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

fn random_hist(rng: &mut Rng) -> Hist {
    let admins = 2 + rng.below(3);
    let members = 1 + rng.below(2);
    let mut genesis = vec![Role::Admin; 1 + admins];
    genesis.extend(std::iter::repeat(Role::Write).take(members));
    let n = genesis.len();
    let k = 2 + rng.below(7);
    let mut h = Hist { genesis, writes: vec![], recv: vec![], att_recv: vec![], content: vec![], recv_c: vec![] };
    let rt = |rng: &mut Rng, t: u32| -> u32 {
        if rng.below(3) == 0 {
            LATE
        } else {
            (t as i64 + rng.below(6) as i64 - 2).max(0) as u32
        }
    };
    while h.writes.len() < k {
        // members occasionally try membership writes too (always skipped unless granted admin)
        let author = if rng.below(8) == 0 { rng.below(n) } else { rng.below(1 + admins) };
        let target = 1 + rng.below(n - 1);
        let role = [Role::None, Role::None, Role::Write, Role::Admin][rng.below(4)];
        let t = 1 + rng.below(10) as u32;
        if h.writes.iter().any(|w| w.t == t && w.author == author) {
            continue;
        }
        let mut r: Vec<u32> = (0..n).map(|_| rt(rng, t)).collect();
        r[author] = t;
        h.writes.push(MWrite { author, target, role, t });
        h.recv.push(r);
    }
    h.att_recv = (0..k)
        .map(|r| (0..n).map(|a| (0..n).map(|m| if m == a { h.recv[r][a] } else { rt(rng, h.recv[r][a].min(20)) }).collect()).collect())
        .collect();
    for _ in 0..rng.below(4) {
        let a = rng.below(n);
        let t = 1 + rng.below(10) as u32;
        let mut r: Vec<u32> = (0..n).map(|_| rt(rng, t)).collect();
        r[a] = t;
        h.content.push((a, t));
        h.recv_c.push(r);
    }
    h
}

fn random(samples: u64, seed: u64, rule: Rule) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut rng = Rng(seed ^ (th + 1).wrapping_mul(0x9E3779B97F4A7C15));
                    let mut st = Stats::default();
                    for _ in 0..samples / threads {
                        let h = random_hist(&mut rng);
                        check(&h, &mut st, Some(&mut rng), rule);
                    }
                    st
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    let rule = match args.get(2).map(String::as_str) {
        Some("exempt") => Rule::ExemptOwnRevoke,
        Some("strat") => Rule::Stratified,
        Some("stratw") => Rule::StratifiedW,
        _ => Rule::AsWritten,
    };
    println!("rule {rule:?}");
    use Role::*;
    for k in 1..=2 {
        for late in [false, true] {
            exhaustive(k, &[None, Write, Admin], &[1, 3, 5, LATE], late, rule).print(&format!("exhaustive k={k} fine receipts late_att={late}"), rule);
        }
    }
    for late in [false, true] {
        exhaustive(3, &[None, Admin], &[0, LATE], late, rule).print(&format!("exhaustive k=3 coarse receipts late_att={late}"), rule);
    }
    random(samples, 0x5eed, rule).print("random", rule);
}

// ---------- expected outcomes and minimized counterexamples ----------

#[cfg(test)]
mod tests {
    use super::*;
    use Role::*;

    const O: usize = 0;
    const A1: usize = 1;
    const A2: usize = 2;
    const A3: usize = 3;
    const M: usize = 4;
    const G: [Role; 5] = [Admin, Admin, Admin, Admin, Write];
    const RULES: [Rule; 3] = [Rule::ExemptOwnRevoke, Rule::Stratified, Rule::StratifiedW];

    fn eval(h: &Hist, rule: Rule) -> Walk {
        match strat_witness(rule) {
            Role::None => h.walk(h.iterate(rule, false).expect("terminates").0),
            w => h.stratified(w).0,
        }
    }

    #[test]
    fn mutual_removal_earlier_wins() {
        let mut b = Builder::new(&G);
        b.set(A1, A2, None, 2, &[]);
        b.set(A2, A1, None, 3, &[]);
        let h = b.build();
        for rule in RULES {
            let w = eval(&h, rule);
            assert_eq!((w.roles[A1], w.roles[A2]), (Admin, None), "{rule:?}");
        }
    }

    #[test]
    fn stolen_device_backdated_revoke_witnessed() {
        // A1 is a stolen device: backdated removals at t=2,3 reach admin A3 at t=5;
        // owner removes A1 at t=10 without backdating.
        let mut b = Builder::new(&G);
        b.set(A1, A2, None, 2, &[(A3, 5)]);
        b.set(A1, M, None, 3, &[(A3, 5)]);
        b.set(O, A1, None, 10, &[]);
        let h = b.build();
        for rule in RULES {
            let w = eval(&h, rule);
            assert_eq!((w.roles[A1], w.roles[A2], w.roles[M]), (None, None, None), "{rule:?}");
        }
    }

    #[test]
    fn stolen_device_backdated_revoke_seen_by_writer_only() {
        // Same, but only writer M received it: a witness for a membership write must be
        // an admin under Stratified; the write+ rules accept M.
        let mut b = Builder::new(&G);
        b.set(A1, A2, None, 2, &[(M, 5)]);
        b.set(O, A1, None, 10, &[]);
        let h = b.build();
        assert_eq!(eval(&h, Rule::ExemptOwnRevoke).roles[A2], None);
        assert_eq!(eval(&h, Rule::StratifiedW).roles[A2], None);
        assert_eq!(eval(&h, Rule::Stratified).roles[A2], Admin);
    }

    #[test]
    fn owner_further_backdated_revoke_cancels() {
        let mut b = Builder::new(&G);
        b.set(A1, A2, None, 2, &[(A3, 5), (M, 5)]);
        b.set(A1, A3, None, 3, &[(A3, 5), (M, 5)]);
        b.set(O, A1, None, 1, &[]);
        let h = b.build();
        for rule in RULES {
            let w = eval(&h, rule);
            assert_eq!((w.roles[A1], w.roles[A2], w.roles[A3]), (None, Admin, Admin), "{rule:?}");
        }
    }

    #[test]
    fn regrant_validates_intermediate_content() {
        let mut b = Builder::new(&G);
        b.set(O, M, None, 2, &[]);
        b.content(M, 3, &[]); // nobody saw it
        b.set(O, M, Write, 5, &[]);
        let h = b.build();
        for rule in RULES {
            assert_eq!(h.content_valid(&eval(&h, rule)), vec![true], "{rule:?}");
        }
    }

    #[test]
    fn cycle_of_revoked_witnesses_validates_nothing() {
        // A2's content was seen only by A3 and M, who are removed too; their attestations
        // about A2's removal reach only each other.
        let mut b = Builder::new(&G);
        b.content(A2, 1, &[(A3, 1), (M, 1)]);
        b.set(O, A2, None, 4, &[]);
        b.set(O, A3, None, 5, &[]);
        b.set(O, M, None, 6, &[]);
        let mut h = b.build();
        for a in [A3, M] {
            for m in 0..5 {
                h.att_recv[0][a][m] = if m == A3 || m == M { 4 } else { LATE };
            }
        }
        for rule in RULES {
            assert_eq!(h.content_valid(&eval(&h, rule)), vec![false], "{rule:?}");
        }
    }

    /// Counterexample 1: an admin removes itself and nobody receives it before its own
    /// timestamp. As written, the removal makes it a removed actor's unwitnessed write,
    /// dropping it un-removes the actor, and so on.
    #[test]
    fn self_removal_loops_as_written() {
        let mut b = Builder::new(&G);
        b.set(A1, A1, None, 2, &[(O, 3), (A2, 3), (A3, 3), (M, 3)]);
        let h = b.build();
        assert!(h.iterate(Rule::AsWritten, false).is_err());
        assert!(h.stable(Rule::AsWritten).is_empty());
        for rule in RULES {
            assert_eq!(eval(&h, rule).roles[A1], None, "{rule:?}");
        }
    }

    /// Counterexample 2: A1 removes A2 and only A2 (the victim) receives it in time; the
    /// owner then removes A1. If the removal stands, A2 is removed and cannot witness; if
    /// it is dropped, A2 is a member and witnessed it. No stable answer; the exempt rule
    /// still loops.
    #[test]
    fn victim_as_only_witness_loops_as_written() {
        let g = [Admin, Admin, Admin, Write];
        let mut b = Builder::new(&g);
        b.set(A1, A2, None, 2, &[(A2, 1)]);
        b.set(O, A1, None, 4, &[(A1, 1), (3, 1)]);
        let h = b.build();
        for rule in [Rule::AsWritten, Rule::ExemptOwnRevoke] {
            assert!(h.iterate(rule, false).is_err(), "{rule:?}");
            assert!(h.stable(rule).is_empty(), "{rule:?}");
        }
        for rule in [Rule::Stratified, Rule::StratifiedW] {
            let w = eval(&h, rule);
            assert_eq!((w.roles[A1], w.roles[A2]), (None, Admin), "{rule:?}");
        }
    }

    /// Counterexample 3: two stable answers. A2 removes A1, seen by nobody else before t=4;
    /// A1 removes A2 at t=4. Either removal can be the valid one. Iterating from
    /// "nobody revoked" picks the earlier, as intended.
    #[test]
    fn mutual_removal_has_two_stable_answers() {
        let g = [Admin, Admin, Admin, Write];
        let mut b = Builder::new(&g);
        b.set(A2, A1, None, 2, &[(O, 5), (A1, 5), (3, 5)]);
        b.set(A1, A2, None, 4, &[(O, 1), (3, 1)]);
        let h = b.build();
        assert_eq!(h.stable(Rule::AsWritten).len(), 2);
        for rule in RULES {
            let w = eval(&h, rule);
            assert_eq!((w.roles[A1], w.roles[A2]), (None, Admin), "{rule:?}");
        }
    }
}
