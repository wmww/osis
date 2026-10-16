//! One-level model of edges with `until`, invite power and self-removal (spec/permissions.md
//! §2, §5.1, §9). One thing T; node 0 is T's owner (admin, unremovable); every other node is a
//! key actor (admin of itself, so effective invite = its edge's invite). An edge is (role,
//! until, invite ≤ role). A commit (normally one op; a redemption has two) is judged with its
//! author's authority just before it. A commit whose ops all lower the author's own edge in
//! every component is a self-removal: it applies, attributed SelfOnly, even for an admin. An
//! admin's (owner, or an alive admin edge) other commits apply whole, attributed Admin.
//! Otherwise each op takes effect on its own iff it is a self-lowering or adds an edge, role ≤
//! the author's invite, for an actor with no alive edge (invite grant); the commit is
//! attributed Invite if the author holds an invite and it touches anyone else.
//!
//! Audit (demoter-frontier rule of main.rs): `held[x]` is the highest (role, invite) x held
//! since its last audit. An applied Owner/Admin op on x ≠ author leaving x below `held` (admin
//! to below; invite lowered) drops x's earlier applied commits attributed to the lost class
//! (Admin; Invite) that the author had not received before the op's time (its own chain write
//! always counts), and the walk restarts; `held[x]` becomes x's new authority. `until`,
//! self-removal and invite grants never audit, so `held` persists until an explicit write.
//! Links: L has (r, ∞, r) on K; redeem = L's commit adding the redeemer (single use: plus
//! removing L's own edge).
//!
//! Checked (`cargo run --release [samples] edges|edges-prov`, `cargo test`): exhaustive tiers
//! plus random histories for termination, order independence, nothing dropped with nobody
//! offline, projected rosters (a node holding only the writes relevant to one actor, closed
//! under authors, computes that actor's authority as the full node does), writes by actors
//! that never hold admin never lower anyone else, and the residue of a removed actor
//! (`EHist::residue`). Findings: residue is nonzero because drops are sticky
//! (`sticky_drop_outlives_its_cause`); making drops last only while their cause demotes
//! (`Drops::Provenance`) removes it but can cycle (`provenance_cycles_on_removal_ring`).
//! "Joiner lowers someone" counts are an earlier invite grant with a shorter `until` or
//! smaller role preempting a later one (the later add finds an edge): first add wins.

use crate::{Rng, Role};
use std::collections::HashSet;

pub const O: usize = 0;
pub const NEVER: u32 = u32::MAX;
const LATE: u32 = 1000;
/// Time at which final authority is read.
const NOW: u32 = 500;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Edge {
    pub role: Role,
    pub until: u32,
    pub invite: Role,
}

/// (role, invite) an edge grants at time `t`.
pub fn auth(e: Option<Edge>, t: u32) -> (Role, Role) {
    match e {
        Some(e) if t < e.until => (e.role, e.invite),
        _ => (Role::None, Role::None),
    }
}

/// `new` removes `old` or lowers it in every component (role, invite, until).
fn lowers(new: Option<Edge>, old: Option<Edge>) -> bool {
    match (new, old) {
        (None, _) => true,
        (Some(n), Some(o)) => n.role <= o.role && n.invite <= o.invite && n.until <= o.until,
        (Some(_), None) => false,
    }
}

fn max2(a: (Role, Role), b: (Role, Role)) -> (Role, Role) {
    (a.0.max(b.0), a.1.max(b.1))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EWrite {
    pub author: usize,
    pub t: u32,
    pub ops: Vec<(usize, Option<Edge>)>,
}

#[derive(Clone, Debug)]
pub struct EHist {
    pub genesis: Vec<Option<Edge>>,
    pub writes: Vec<EWrite>,
    /// [write][node] receipt time on the receiver's clock; author: its own `t`.
    pub recv: Vec<Vec<u32>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attr {
    Skipped,
    Owner,
    Admin,
    Invite,
    SelfOnly,
}

#[derive(Clone, Debug)]
pub struct EOut {
    pub edges: Vec<Option<Edge>>,
    pub applied: u64,
    pub dropped: u64,
    pub attr: Vec<Attr>,
    pub passes: usize,
    /// Provenance only: the drop set repeated (the walk shown audits nothing).
    pub cycled: bool,
}

/// What happens to drops.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Drops {
    /// No audits (reference).
    Off,
    /// The rule as specified: drops are sticky within an evaluation.
    Sticky,
    /// Candidate fix: a drop lasts only while the demotion that caused it still demotes in
    /// the final walk (not dropped, still lowering its target). Not guaranteed to
    /// terminate; a repeated drop set is reported as a cycle.
    Provenance,
}

impl EOut {
    pub fn auth(&self, x: usize) -> (Role, Role) {
        if x == O {
            (Role::Admin, Role::Admin)
        } else {
            auth(self.edges[x], NOW)
        }
    }
    fn all(&self) -> Vec<(Role, Role)> {
        (0..self.edges.len()).map(|x| self.auth(x)).collect()
    }
}

impl EHist {
    pub fn n(&self) -> usize {
        self.genesis.len()
    }

    pub fn order(&self) -> Vec<usize> {
        let mut o: Vec<usize> = (0..self.writes.len()).collect();
        o.sort_by_key(|&i| (self.writes[i].t, self.writes[i].author));
        o
    }

    /// How commit `w` applies given the edges just before it: its attribution, from the
    /// author's authority alone, and which ops take effect. A non-admin's ops are judged one
    /// by one, so a redemption's self-removal never depends on the redeemer's entry (with
    /// all-or-nothing commits a verifier of L would need every redeemer's entry; projections
    /// then diverge).
    fn judge(&self, w: &EWrite, edges: &[Option<Edge>]) -> (Attr, Vec<bool>) {
        let a = w.author;
        if w.ops.iter().any(|&(x, _)| x == O) {
            return (Attr::Skipped, vec![false; w.ops.len()]);
        }
        let all = vec![true; w.ops.len()];
        if a == O {
            return (Attr::Owner, all);
        }
        // A pure self-removal is never audited, even by an admin: dropping it could only
        // hand its author back what it gave up.
        if w.ops.iter().all(|&(x, new)| x == a && lowers(new, edges[a])) {
            return (Attr::SelfOnly, all);
        }
        let (role, inv) = auth(edges[a], w.t);
        if role == Role::Admin {
            return (Attr::Admin, all);
        }
        let eff: Vec<bool> = w
            .ops
            .iter()
            .map(|&(x, new)| match new {
                _ if x == a => lowers(new, edges[a]),
                Some(e) => auth(edges[x], w.t).0 == Role::None && e.role <= inv && e.invite <= e.role,
                None => false,
            })
            .collect();
        let at = if inv > Role::None && w.ops.iter().any(|&(x, _)| x != a) {
            Attr::Invite
        } else if eff.iter().any(|&b| b) {
            Attr::SelfOnly
        } else {
            Attr::Skipped
        };
        (at, eff)
    }

    /// The timeline. `audit = false` never drops (reference for the nobody-offline check).
    pub fn eval(&self, audit: bool) -> EOut {
        self.eval_mode(if audit { Drops::Sticky } else { Drops::Off })
    }

    pub fn eval_mode(&self, mode: Drops) -> EOut {
        let n = self.n();
        let order = self.order();
        // cause[j]: the demotion whose audit dropped j.
        let mut cause: Vec<Option<usize>> = vec![None; self.writes.len()];
        let mut seen = HashSet::new();
        let mut passes = 0;
        'walk: loop {
            passes += 1;
            let cycled = !seen.insert(cause.clone());
            let dropped = (0..cause.len()).filter(|&j| cause[j].is_some()).fold(0u64, |m, j| m | 1 << j);
            let mut edges = self.genesis.clone();
            let mut held: Vec<(Role, Role)> = edges.iter().map(|&e| auth(e, 0)).collect();
            let mut applied = 0u64;
            let mut attr = vec![Attr::Skipped; self.writes.len()];
            // Last applied commit that set each actor's edge: the actor's chain.
            let mut chain: Vec<Option<usize>> = vec![None; n];
            // Commits that demoted someone (and so audited) in this walk.
            let mut demoting = 0u64;
            for &i in &order {
                if dropped >> i & 1 == 1 {
                    continue;
                }
                let w = &self.writes[i];
                let a = w.author;
                let (at, eff) = self.judge(w, &edges);
                if at == Attr::Skipped {
                    continue;
                }
                applied |= 1 << i;
                attr[i] = at;
                let chain_a = chain[a];
                let mut grew = false;
                for (&(x, new), _) in w.ops.iter().zip(&eff).filter(|(_, &e)| e) {
                    let old = edges[x];
                    edges[x] = new;
                    chain[x] = Some(i);
                    let now = auth(new, w.t);
                    if x == a {
                        // Self-removal audits nothing; an admin raising itself raises `held`.
                        if !lowers(new, old) {
                            held[x] = max2(held[x], now);
                        }
                        continue;
                    }
                    if at == Attr::Invite {
                        held[x] = max2(held[x], now);
                        continue;
                    }
                    let (hr, hi) = held[x];
                    held[x] = now;
                    let lost_admin = hr == Role::Admin && now.0 < Role::Admin;
                    let lost_invite = hi > now.1;
                    if mode == Drops::Off || cycled || !(lost_admin || lost_invite) {
                        continue;
                    }
                    demoting |= 1 << i;
                    for j in 0..self.writes.len() {
                        if j == i || applied >> j & 1 == 0 || self.writes[j].author != x {
                            continue;
                        }
                        if !(lost_admin && attr[j] == Attr::Admin || lost_invite && attr[j] == Attr::Invite) {
                            continue;
                        }
                        let covered = self.recv[j][a] < w.t || chain_a == Some(j);
                        if !covered && cause[j].is_none() {
                            cause[j] = Some(i);
                            grew = true;
                        }
                    }
                }
                if grew {
                    continue 'walk;
                }
            }
            if mode == Drops::Provenance && !cycled {
                let mut undone = false;
                for c in cause.iter_mut() {
                    if c.map_or(false, |r| demoting >> r & 1 == 0) {
                        *c = None;
                        undone = true;
                    }
                }
                if undone {
                    continue 'walk;
                }
            }
            return EOut { edges, applied, dropped, attr, passes, cycled };
        }
    }

    fn keep(&self, keep: &[usize], genesis: Vec<Option<Edge>>) -> EHist {
        EHist {
            genesis,
            writes: keep.iter().map(|&i| self.writes[i].clone()).collect(),
            recv: keep.iter().map(|&i| self.recv[i].clone()).collect(),
        }
    }

    /// What a node verifying actor `z` holds: the start roster's entries and the commits
    /// touching an actor in the closure, which starts at {z} and grows by each held commit's
    /// author (the certificate rule).
    pub fn projected(&self, z: usize) -> EHist {
        let mut c = vec![false; self.n()];
        c[z] = true;
        loop {
            let mut grew = false;
            for w in &self.writes {
                if w.ops.iter().any(|&(x, _)| c[x]) && !c[w.author] {
                    c[w.author] = true;
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        let keep: Vec<usize> = (0..self.writes.len()).filter(|&i| self.writes[i].ops.iter().any(|&(x, _)| c[x])).collect();
        let genesis = (0..self.n()).map(|x| if c[x] { self.genesis[x] } else { None }).collect();
        self.keep(&keep, genesis)
    }

    /// Removed actors: x whose edge only the owner and x itself write, the owner last, by a
    /// plain removal at T_x. Returns the history without each such x's commits the owner had
    /// not received before T_x (what its frontier does not cover), or None if there is no
    /// such x. Those commits should leave no trace. (When another admin removed x first, its
    /// frontier is the one that counts, so such x are excluded; self-removals are never
    /// audited, so they are kept.)
    pub fn residue(&self) -> Option<EHist> {
        let mut cut: Vec<Option<u32>> = vec![None; self.n()];
        let mut other = vec![false; self.n()];
        for &i in &self.order() {
            let w = &self.writes[i];
            for &(x, new) in &w.ops {
                other[x] |= w.author != O && w.author != x;
                if w.author == O {
                    cut[x] = if new.is_none() { Some(w.t) } else { None };
                }
            }
        }
        for x in 0..self.n() {
            if other[x] {
                cut[x] = None;
            }
        }
        if cut.iter().all(Option::is_none) {
            return None;
        }
        let keep: Vec<usize> = (0..self.writes.len())
            .filter(|&j| {
                let w = &self.writes[j];
                let self_only = w.ops.iter().all(|&(x, _)| x == w.author);
                self_only || cut[w.author].map_or(true, |t| self.recv[j][O] < t)
            })
            .collect();
        Some(self.keep(&keep, self.genesis.clone()))
    }

    /// Authors that never hold an admin role (genesis or any write).
    pub fn never_admin(&self) -> Vec<bool> {
        let mut v: Vec<bool> = self.genesis.iter().map(|e| e.map_or(true, |e| e.role < Role::Admin)).collect();
        v[O] = false;
        for w in &self.writes {
            for &(x, new) in &w.ops {
                if new.map_or(false, |e| e.role == Role::Admin) {
                    v[x] = false;
                }
            }
        }
        v
    }

    fn permute(&self, perm: &[usize]) -> EHist {
        self.keep(perm, self.genesis.clone())
    }
}

/// a ≥ b in both components.
fn covers(a: (Role, Role), b: (Role, Role)) -> bool {
    a.0 >= b.0 && a.1 >= b.1
}

// ---------- search ----------

#[derive(Default)]
pub struct Stats {
    histories: u64,
    max_passes: usize,
    cycles: u64,
    order_dep: u64,
    honest_mismatch: u64,
    projections: u64,
    projection_mismatch: u64,
    joiner_lowers: u64,
    residue_checks: u64,
    residue_gain: u64,
    residue_loss: u64,
    ex_cycle: Option<EHist>,
    ex_order: Option<EHist>,
    ex_honest: Option<EHist>,
    ex_projection: Option<EHist>,
    ex_joiner: Option<EHist>,
    ex_gain: Option<EHist>,
    ex_loss: Option<EHist>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.histories += o.histories;
        self.max_passes = self.max_passes.max(o.max_passes);
        self.cycles += o.cycles;
        self.order_dep += o.order_dep;
        self.honest_mismatch += o.honest_mismatch;
        self.projections += o.projections;
        self.projection_mismatch += o.projection_mismatch;
        self.joiner_lowers += o.joiner_lowers;
        self.residue_checks += o.residue_checks;
        self.residue_gain += o.residue_gain;
        self.residue_loss += o.residue_loss;
        fn pick(a: &mut Option<EHist>, b: Option<EHist>) {
            if let Some(b) = b {
                if a.as_ref().map_or(true, |a| b.writes.len() < a.writes.len()) {
                    *a = Some(b);
                }
            }
        }
        pick(&mut self.ex_cycle, o.ex_cycle);
        pick(&mut self.ex_order, o.ex_order);
        pick(&mut self.ex_honest, o.ex_honest);
        pick(&mut self.ex_projection, o.ex_projection);
        pick(&mut self.ex_joiner, o.ex_joiner);
        pick(&mut self.ex_gain, o.ex_gain);
        pick(&mut self.ex_loss, o.ex_loss);
    }

    pub fn print(&self, name: &str, mode: Drops) {
        println!(
            "{name}: {} histories | max passes {} | cycles {} | order-dependent {} | drops with nobody offline {} | projections {} mismatches {} | joiner writes lowering someone {} | removed-actor residue checks {} gains {} losses {}",
            self.histories, self.max_passes, self.cycles, self.order_dep, self.honest_mismatch, self.projections, self.projection_mismatch,
            self.joiner_lowers, self.residue_checks, self.residue_gain, self.residue_loss
        );
        for (label, ex) in [
            ("cycle", &self.ex_cycle),
            ("order dependence", &self.ex_order),
            ("drop with nobody offline", &self.ex_honest),
            ("projection mismatch", &self.ex_projection),
            ("joiner lowering someone", &self.ex_joiner),
            ("residue gain", &self.ex_gain),
            ("residue loss", &self.ex_loss),
        ] {
            if let Some(h) = ex {
                println!("  smallest {label} example:");
                print_hist(h, mode);
            }
        }
    }
}

fn fmt_edge(e: Option<Edge>) -> String {
    match e {
        None => "-".into(),
        Some(e) => {
            let until = if e.until == NEVER { String::new() } else { format!(" until {}", e.until) };
            format!("({:?} inv {:?}{until})", e.role, e.invite)
        }
    }
}

pub fn print_hist(h: &EHist, mode: Drops) {
    println!("    genesis {}", h.genesis.iter().map(|&e| fmt_edge(e)).collect::<Vec<_>>().join(" "));
    let o = h.eval_mode(mode);
    for i in h.order() {
        let w = &h.writes[i];
        let ops: Vec<String> = w.ops.iter().map(|&(x, e)| format!("{x} := {}", fmt_edge(e))).collect();
        println!("    w{i}: {} sets {} at t={} | recv {:?} | {:?}", w.author, ops.join(", "), w.t, h.recv[i], o.attr[i]);
    }
    println!("    -> {:?} applied {:#b} dropped {:#b} ({} passes, cycled {})", o.all(), o.applied, o.dropped, o.passes, o.cycled);
}

fn check(h: &EHist, st: &mut Stats, rng: &mut Rng, mode: Drops) {
    st.histories += 1;
    let o = h.eval_mode(mode);
    st.max_passes = st.max_passes.max(o.passes);
    if o.cycled {
        st.cycles += 1;
        st.ex_cycle.get_or_insert_with(|| h.clone());
    }
    let all = o.all();
    let perm = rng.perm(h.writes.len());
    if h.permute(&perm).eval_mode(mode).all() != all {
        st.order_dep += 1;
        st.ex_order.get_or_insert_with(|| h.clone());
    }
    let distinct = h.writes.iter().map(|w| w.t).collect::<HashSet<_>>().len() == h.writes.len();
    if distinct {
        let mut honest = h.clone();
        for (i, r) in honest.recv.iter_mut().enumerate() {
            r.fill(h.writes[i].t);
        }
        let a = honest.eval_mode(mode);
        if a.dropped != 0 || a.all() != honest.eval(false).all() {
            st.honest_mismatch += 1;
            st.ex_honest.get_or_insert_with(|| honest.clone());
        }
    }
    for z in 1..h.n() {
        st.projections += 1;
        if h.projected(z).eval_mode(mode).auth(z) != all[z] {
            st.projection_mismatch += 1;
            st.ex_projection.get_or_insert_with(|| h.clone());
        }
    }
    // Writes by actors that never hold admin (joiners, link holders, invitees) only add:
    // without them nobody else ends with more.
    let na = h.never_admin();
    if (0..h.writes.len()).any(|j| na[h.writes[j].author]) {
        let keep: Vec<usize> = (0..h.writes.len()).filter(|&j| !na[h.writes[j].author]).collect();
        let o0 = h.keep(&keep, h.genesis.clone()).eval_mode(mode);
        if (1..h.n()).any(|y| !na[y] && !covers(all[y], o0.auth(y))) {
            st.joiner_lowers += 1;
            st.ex_joiner.get_or_insert_with(|| h.clone());
        }
    }
    if let Some(r) = h.residue() {
        st.residue_checks += 1;
        let or = r.eval_mode(mode);
        if (1..h.n()).any(|y| !covers(or.auth(y), all[y])) {
            st.residue_gain += 1;
            st.ex_gain.get_or_insert_with(|| h.clone());
        }
        if (1..h.n()).any(|y| !covers(all[y], or.auth(y))) {
            st.residue_loss += 1;
            st.ex_loss.get_or_insert_with(|| h.clone());
        }
    }
}

fn rand_edge(rng: &mut Rng) -> Edge {
    let role = [Role::Read, Role::Write, Role::Write, Role::Admin][rng.below(4)];
    let invite = [Role::None, Role::None, Role::Read, Role::Write, Role::Admin][rng.below(5)].min(role);
    let until = if rng.below(3) == 0 { 2 + rng.below(8) as u32 } else { NEVER };
    Edge { role, until, invite }
}

/// A random edge lowering `e` in every component, or None.
fn rand_lower(rng: &mut Rng, e: Option<Edge>) -> Option<Edge> {
    let e = e?;
    if rng.below(2) == 0 {
        return None;
    }
    let role = [Role::Read, Role::Write, Role::Admin][rng.below(3)].min(e.role);
    let invite = [Role::None, Role::Read, Role::Write, Role::Admin][rng.below(4)].min(e.invite).min(role);
    let until = if rng.below(2) == 0 { e.until } else { (1 + rng.below(10) as u32).min(e.until) };
    Some(Edge { role, until, invite })
}

fn random_hist(rng: &mut Rng) -> EHist {
    let n = 3 + rng.below(4);
    let mut genesis: Vec<Option<Edge>> = (0..n).map(|_| if rng.below(4) == 0 { None } else { Some(rand_edge(rng)) }).collect();
    genesis[O] = None;
    let k = 2 + rng.below(7);
    let mut h = EHist { genesis, writes: vec![], recv: vec![] };
    let rt = |rng: &mut Rng, t: u32| -> u32 {
        if rng.below(3) == 0 {
            LATE
        } else {
            (t as i64 + rng.below(6) as i64 - 2).max(0) as u32
        }
    };
    while h.writes.len() < k {
        let author = if rng.below(4) == 0 { O } else { 1 + rng.below(n - 1) };
        let t = 1 + rng.below(10) as u32;
        if h.writes.iter().any(|w| w.t == t && w.author == author) {
            continue;
        }
        let other = |rng: &mut Rng| loop {
            let x = 1 + rng.below(n - 1);
            if x != author {
                return x;
            }
        };
        let ops = match rng.below(8) {
            0 | 1 if author != O => vec![(author, rand_lower(rng, h.genesis[author]))],
            2 if author != O => vec![(other(rng), Some(rand_edge(rng))), (author, None)],
            _ => vec![(other(rng), if rng.below(3) == 0 { None } else { Some(rand_edge(rng)) })],
        };
        let mut r: Vec<u32> = (0..n).map(|_| rt(rng, t)).collect();
        r[author] = t;
        h.writes.push(EWrite { author, t, ops });
        h.recv.push(r);
    }
    h
}

fn parallel(f: impl Fn(usize, usize) -> Stats + Sync) -> Stats {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let f = &f;
    let stats: Vec<Stats> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads).map(|th| s.spawn(move || f(th, threads))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

pub fn random(samples: u64, seed: u64, mode: Drops) -> Stats {
    parallel(|th, threads| {
        let mut rng = Rng(seed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
        let mut st = Stats::default();
        for _ in 0..samples / threads as u64 {
            let h = random_hist(&mut rng);
            check(&h, &mut st, &mut rng, mode);
        }
        st
    })
}

/// Exhaustive: owner 0, admin 1, inviter 2 (write, invite write), outsider 3. Every set of
/// `k` commits from a menu: author × target × edge (plus a redemption by 2: add 3 and
/// remove itself), times {2,4,6}, receipts in `recv_opts` at the nodes in `recv_at`
/// (others receive at 0).
pub fn exhaustive(k: usize, edges: &[Option<Edge>], recv_opts: &[u32], recv_at: &[usize], mode: Drops) -> Stats {
    let w = |role, invite| Some(Edge { role, until: NEVER, invite });
    let genesis = vec![None, w(Role::Admin, Role::Admin), w(Role::Write, Role::Write), None];
    let n = genesis.len();
    let mut menu = Vec::new();
    let mut ops_menu: Vec<(usize, Vec<(usize, Option<Edge>)>)> = Vec::new();
    for author in 0..n {
        for target in 1..n {
            for &e in edges {
                ops_menu.push((author, vec![(target, e)]));
            }
        }
    }
    ops_menu.push((2, vec![(3, w(Role::Write, Role::None)), (2, None)]));
    for (author, ops) in &ops_menu {
        for t in [2, 4, 6] {
            let others: Vec<usize> = recv_at.iter().copied().filter(|&m| m != *author).collect();
            let combos = recv_opts.len().pow(others.len() as u32);
            for c in 0..combos {
                let mut r = vec![0; n];
                r[*author] = t;
                let mut c = c;
                for &m in &others {
                    r[m] = recv_opts[c % recv_opts.len()];
                    c /= recv_opts.len();
                }
                menu.push((EWrite { author: *author, t, ops: ops.clone() }, r));
            }
        }
    }
    let total = menu.len().pow(k as u32);
    let menu = &menu;
    let genesis = &genesis;
    parallel(|th, threads| {
        let mut st = Stats::default();
        let mut rng = Rng(0x5eed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
        let mut idx = th;
        'next: while idx < total {
            let mut x = idx;
            idx += threads;
            let mut h = EHist { genesis: genesis.clone(), writes: vec![], recv: vec![] };
            let mut prev = 0;
            for j in 0..k {
                let wi = x % menu.len();
                x /= menu.len();
                // canonical order to skip permutations of the same set
                if j > 0 && wi < prev {
                    continue 'next;
                }
                prev = wi;
                h.writes.push(menu[wi].0.clone());
                h.recv.push(menu[wi].1.clone());
            }
            let mut s = HashSet::new();
            if !h.writes.iter().all(|w| s.insert((w.t, w.author))) {
                continue;
            }
            check(&h, &mut st, &mut rng, mode);
        }
        st
    })
}

pub fn run(samples: u64, mode: Drops) {
    use Role::{Admin, Read, Write};
    let e = |role, invite, until| Some(Edge { role, until, invite });
    let fine = [None, e(Write, Role::None, NEVER), e(Write, Write, NEVER), e(Admin, Admin, NEVER), e(Write, Write, 3), e(Read, Read, NEVER)];
    for k in 1..=2 {
        exhaustive(k, &fine, &[1, 3, 5, LATE], &[0, 1, 2, 3], mode).print(&format!("{mode:?} exhaustive k={k} fine"), mode);
    }
    let coarse = [None, e(Write, Write, NEVER), e(Admin, Admin, NEVER)];
    exhaustive(3, &coarse, &[0, LATE], &[0, 1], mode).print(&format!("{mode:?} exhaustive k=3 coarse"), mode);
    random(samples, 0x5eed, mode).print(&format!("{mode:?} random"), mode);
}

// ---------- scenarios ----------

#[cfg(test)]
mod tests {
    use super::*;
    use Role::{Admin, Read, Write};
    /// No invite / no role.
    const NI: Role = Role::None;

    struct B(EHist);
    impl B {
        fn new(genesis: &[Option<Edge>]) -> Self {
            B(EHist { genesis: genesis.to_vec(), writes: vec![], recv: vec![] })
        }
        /// Commit; `recv` lists (node, time) receipts, others get LATE.
        fn ops(&mut self, author: usize, ops: &[(usize, Option<Edge>)], t: u32, recv: &[(usize, u32)]) -> usize {
            let mut r = vec![LATE; self.0.n()];
            r[author] = t;
            for &(m, tm) in recv {
                r[m] = tm;
            }
            self.0.writes.push(EWrite { author, t, ops: ops.to_vec() });
            self.0.recv.push(r);
            self.0.writes.len() - 1
        }
        fn set(&mut self, author: usize, x: usize, e: Option<Edge>, t: u32, recv: &[(usize, u32)]) -> usize {
            self.ops(author, &[(x, e)], t, recv)
        }
    }

    fn e(role: Role, invite: Role) -> Option<Edge> {
        Some(Edge { role, until: NEVER, invite })
    }
    fn eu(role: Role, invite: Role, until: u32) -> Option<Edge> {
        Some(Edge { role, until, invite })
    }
    fn roles(h: &EHist) -> Vec<(Role, Role)> {
        h.eval(true).all()
    }
    /// Every projection agrees with the full node.
    fn assert_projections(h: &EHist) {
        let all = roles(h);
        for z in 1..h.n() {
            assert_eq!(h.projected(z).eval(true).auth(z), all[z], "projection for {z}");
        }
    }

    // Link: sharer 0 owns K; L = 1; joiners J = 2, Z = 3; Y = 4 an existing member.
    const L: usize = 1;
    const J: usize = 2;
    const Z: usize = 3;
    const Y: usize = 4;
    const NONE: (Role, Role) = (NI, NI);
    const W: (Role, Role) = (Write, NI);

    /// Finalization by `until`: after the link expires at t=5 a holder mints a join of Z
    /// backdated to t=4. It applies (L was alive at 4) until the sharer's plain removal of L
    /// arrives; that removal audits although the timeline already shows L without an edge,
    /// and drops the join, which the sharer had not received. The honest join stays.
    #[test]
    fn link_until_backdated_join_finalized() {
        let mut b = B::new(&[None, eu(Write, Write, 5), None, None, e(Write, NI)]);
        b.set(L, J, e(Write, NI), 3, &[(0, 3)]);
        let forged = b.set(L, Z, e(Write, NI), 4, &[]);
        assert_eq!(roles(&b.0)[Z], W, "applied before finalization");
        b.set(0, L, None, 10, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.dropped, 1 << forged);
        assert_eq!((o.auth(J), o.auth(Z), o.auth(L)), (W, NONE, NONE));
        assert_projections(&b.0);
    }

    /// Finalization by single use: a second holder mints a redemption backdated before the
    /// honest one. Its self-removal makes the honest one fail until the sharer's removal of L
    /// (which had received only the honest one) drops it; then the honest one applies.
    #[test]
    fn single_use_second_redemption_finalized() {
        let mut b = B::new(&[None, e(Write, Write), None, None, e(Write, NI)]);
        b.ops(L, &[(J, e(Write, NI)), (L, None)], 3, &[(0, 4)]);
        let forged = b.ops(L, &[(Z, e(Write, NI)), (L, None)], 2, &[]);
        let o = b.0.eval(true);
        assert_eq!((o.auth(J), o.auth(Z)), (NONE, W), "forged one wins before finalization");
        b.set(0, L, None, 10, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.dropped, 1 << forged);
        assert_eq!((o.auth(J), o.auth(Z), o.auth(L)), (W, NONE, NONE));
        assert_eq!(o.passes, 2);
        assert_projections(&b.0);
    }

    /// Self-removal by an admin audits nothing; the next explicit removal by another node
    /// audits as if it were still admin.
    #[test]
    fn self_removal_finalized_by_explicit_removal() {
        let a = 1;
        let mut b = B::new(&[None, e(Admin, Admin), None, None, e(Write, NI)]);
        b.set(a, a, None, 5, &[(0, 5)]);
        let forged = b.set(a, Z, e(Admin, Admin), 4, &[]); // backdated after leaving
        assert_eq!(roles(&b.0)[Z], (Admin, Admin));
        b.set(0, a, None, 10, &[]);
        let o = b.0.eval(true);
        assert_eq!(o.dropped, 1 << forged);
        assert_eq!(o.auth(Z), NONE);
    }

    /// Old link model (L admin of K, spec before invite power): the same finalization holds,
    /// but any holder can remove an existing member. With an invite edge it cannot.
    #[test]
    fn link_holder_cannot_remove_members() {
        for (edge, y_after) in [(eu(Admin, Admin, 5), NONE), (eu(Write, Write, 5), W)] {
            let mut b = B::new(&[None, edge, None, None, e(Write, NI)]);
            b.set(L, Y, None, 2, &[(0, 2)]);
            assert_eq!(roles(&b.0)[Y], y_after);
        }
    }

    /// Joiners and link holders cannot remove, demote or change others, raise themselves,
    /// or grant above their invite.
    #[test]
    fn invite_holder_limits() {
        let i = 1;
        let base = [None, e(Write, Write), e(Write, Write), None, e(Write, NI)];
        let tries = [
            (Y, None),                  // remove
            (Y, e(Read, NI)),         // demote
            (Y, e(Write, Write)),       // change invite
            (J, e(Read, NI)),         // demote another inviter
            (i, e(Admin, Admin)),       // raise itself
            (i, e(Write, Write)),       // re-set itself (not lowering? equal: a no-op self-removal)
            (Z, e(Admin, NI)),        // grant above invite
        ];
        for (x, edge) in tries {
            let mut b = B::new(&base);
            b.set(i, x, edge, 2, &[(0, 2)]);
            let o = b.0.eval(true);
            let before = B::new(&base).0.eval(true);
            for y in 0..5 {
                assert!(covers(before.auth(y), o.auth(y)) || y == i, "{x} := {edge:?} raised {y}");
                if y != i {
                    assert!(covers(o.auth(y), before.auth(y)), "{x} := {edge:?} lowered {y}");
                }
            }
        }
        // Self-removal then re-adding itself: no edge, so no invite.
        let mut b = B::new(&base);
        b.set(i, i, None, 2, &[]);
        b.set(i, i, e(Write, Write), 3, &[]);
        assert_eq!(roles(&b.0)[i], NONE);
    }

    /// Two invitees vouching for each other: I1 (removed by the owner at t=5) mints a grant
    /// of I2 backdated to t=4 that the owner never received; I2 re-adds I1 at t=6. The grant
    /// is dropped, so I2 never had an edge and its re-add of I1 never applies.
    #[test]
    fn invitees_vouching_for_each_other() {
        let (i1, i2) = (1, 2);
        let mut b = B::new(&[None, e(Write, Write), None, None, None]);
        b.set(i1, i2, e(Write, Write), 4, &[(i2, 4)]);
        b.set(0, i1, None, 5, &[]);
        b.set(i2, i1, e(Write, Write), 6, &[]);
        let o = b.0.eval(true);
        assert_eq!((o.auth(i1), o.auth(i2)), (NONE, NONE));
        assert_projections(&b.0);
    }

    /// Ex-admin plus invitee: removed admin E's backdated grant of an inviter, which the
    /// inviter used, falls with E, and the inviter's grant with it.
    #[test]
    fn ex_admin_and_invitee() {
        let (ea, i) = (1, 2);
        let mut b = B::new(&[None, e(Admin, Admin), None, None, None]);
        b.set(ea, i, e(Write, Write), 2, &[(i, 2)]);
        b.set(i, Z, e(Write, NI), 3, &[]);
        b.set(0, ea, None, 10, &[]);
        let o = b.0.eval(true);
        assert_eq!((o.auth(i), o.auth(Z)), (NONE, NONE));
    }

    /// An inviter re-adding a member the owner removed: legitimate if the owner had seen it
    /// when revoking the inviter's invite, dropped otherwise; backdated before the removal
    /// it is no add (the member still had an edge).
    #[test]
    fn inviter_readds_removed_member_while_revoked() {
        let i = 1;
        for (readd_t, seen, expect) in [(5, false, NONE), (5, true, W), (3, true, NONE)] {
            let mut b = B::new(&[None, e(Write, Write), None, None, e(Write, NI)]);
            b.set(0, Y, None, 4, &[(i, 4)]);
            let recv: &[(usize, u32)] = if seen { &[(0, 5)] } else { &[] };
            b.set(i, Y, e(Write, NI), readd_t, recv);
            b.set(0, i, e(Write, NI), 6, &[]); // revoke the invite only
            let o = b.0.eval(true);
            assert_eq!(o.auth(Y), expect, "re-add at {readd_t}, seen {seen}");
            assert_eq!(o.auth(i), W);
        }
    }

    /// Lowering an invite audits invite grants; changing the role but keeping the invite
    /// audits nothing.
    #[test]
    fn invite_demotion_audits_invite_grants() {
        let i = 1;
        for (new, z_after) in [(e(Write, Read), NONE), (e(Admin, Write), W), (e(Write, Write), W)] {
            let mut b = B::new(&[None, e(Write, Write), None, None, None]);
            b.set(i, Z, e(Write, NI), 3, &[]);
            b.set(0, i, new, 5, &[]);
            assert_eq!(roles(&b.0)[Z], z_after, "{new:?}");
        }
    }

    /// Finding: drops are sticky. Admin 1 removes 2 at t=4 without having received 2's
    /// grant of 3, which the owner had; the owner removes 1 at t=6 without having received
    /// that removal. It is dropped and 2 is back, but 2's grant stays dropped: a removed
    /// admin's dropped write still costs 3 its edge (for an inviter and an admin alike).
    /// `Provenance` (a drop lasts while its cause still demotes) restores it.
    #[test]
    fn sticky_drop_outlives_its_cause() {
        for grantor in [e(Write, Write), e(Admin, Admin)] {
            let mut b = B::new(&[None, e(Admin, Admin), grantor, None]);
            b.set(2, Z, e(Write, NI), 2, &[(0, 2)]);
            b.set(1, 2, None, 4, &[]);
            b.set(0, 1, None, 6, &[]);
            let st = b.0.eval_mode(Drops::Sticky);
            assert_eq!((st.auth(2), st.auth(Z)), (auth(grantor, NOW), NONE));
            let pr = b.0.eval_mode(Drops::Provenance);
            assert_eq!((pr.auth(2), pr.auth(Z)), (auth(grantor, NOW), W));
        }
    }

    /// The same revives a used single-use link: admin E removes L without having received
    /// its redemption; the owner removes E without having received that. The redemption
    /// stays dropped, so J is out and L's edge, invite included, is back.
    #[test]
    fn sticky_drop_revives_single_use_link() {
        let (ea, l, j) = (1, 2, 3);
        let mut b = B::new(&[None, e(Admin, Admin), e(Write, Write), None]);
        b.ops(l, &[(j, e(Write, NI)), (l, None)], 3, &[(0, 3)]);
        b.set(ea, l, None, 4, &[]);
        b.set(0, ea, None, 6, &[]);
        let st = b.0.eval_mode(Drops::Sticky);
        assert_eq!((st.auth(l), st.auth(j)), ((Write, Write), NONE));
        let pr = b.0.eval_mode(Drops::Provenance);
        assert_eq!((pr.auth(l), pr.auth(j)), (NONE, W));
    }

    /// Why drops are sticky: three admins remove each other in a ring, each without having
    /// received the previous removal. With provenance each removal's drop is undone when
    /// the next one falls, forever; sticky drops settle on 3 removed.
    #[test]
    fn provenance_cycles_on_removal_ring() {
        let mut b = B::new(&[None, e(Admin, Admin), e(Admin, Admin), e(Admin, Admin)]);
        b.set(2, 1, None, 2, &[]);
        b.set(3, 2, None, 3, &[]);
        b.set(1, 3, None, 4, &[]);
        assert!(b.0.eval_mode(Drops::Provenance).cycled);
        let st = b.0.eval_mode(Drops::Sticky);
        assert_eq!((st.auth(1), st.auth(2), st.auth(3)), ((Admin, Admin), (Admin, Admin), NONE));
    }

    /// With all-or-nothing commits a redemption's self-removal would hinge on the redeemer's
    /// entry: here 3 already has an edge, so the add fails; L's self-removal must still
    /// apply, or a verifier of L not holding 3's entry would disagree.
    #[test]
    fn redemption_ops_judged_separately() {
        let l = 2;
        let mut b = B::new(&[None, e(Admin, Admin), e(Write, Write), None]);
        b.set(0, Z, e(Write, NI), 2, &[]);
        b.ops(l, &[(Z, e(Write, NI)), (l, None)], 2, &[]);
        assert_eq!(roles(&b.0)[l], NONE);
        assert_projections(&b.0);
    }
}
