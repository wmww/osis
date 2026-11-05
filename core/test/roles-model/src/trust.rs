//! Disputes and trust sets (notes/owner-removal-plan.md step 3, notes/owners.md "F: disputes"),
//! over any walk implementing `Trusting` (`edges`, `joint`).
//!
//! A node's **trust set** T is a set of ops it sides with, each an edge write R by A lowering
//! another holder X's edge (X is R's victim). R's **seeds**: X's writes (on what R puts in
//! question) not listed in R's frontier, whenever stamped, but X's writes on its own edges (a
//! self-removal never contests R; dropping one only keeps X longer). The walk takes T as one more input:
//! - **Shrink**: D starts at the seeds of the active trusted ops (all of T at first); a walk
//!   that leaves an active op unapplied ("void") drops all void ones at once, for good, and
//!   the walk is redone from scratch with the rest. At most |T| + 1 rounds.
//! - **Dispute**: an op R of victim X, unapplied in the settled walk, that applies as an
//!   explicit demotion of X in the walk with R's seeds added to D: R is voided by X's writes R
//!   did not list. Keyed (R, X). A contest by X listing R (X had received it) raises none; a
//!   trusted R raises none, nor does an R a trusted op seeded (its author was rejected).
//! - The result is a pure function of (held writes, T): nothing else is kept between calls,
//!   so switching T, T', T reads as T by construction (the implementation must rebuild D).
//!
//! `check` runs every property search on one history; `Stats` sums them (`roles-model --
//! N disputes`, tier 3).

use crate::shrink::{shrink, Shrink};
use crate::Rng;
use std::fmt::{Debug, Display};

/// A settled walk under a seeded D.
pub struct Walked<R> {
    pub res: R,
    /// Ops applied in the settled walk.
    pub applied: u64,
    /// Ops the settled walk applied as explicit demotions of another holder.
    pub demoting: u64,
}

/// A walk that takes a trust set. Ops are numbered 0..n_ops (at most 64).
pub trait Trusting: Clone + Display + Shrink + Send + Sync {
    /// The result compared across orders and sides: free of op and write indices.
    type Res: PartialEq + Debug + Clone;
    fn n_ops(&self) -> usize;
    fn n_writes(&self) -> usize;
    /// The settled walk with D starting at `d0`.
    fn walk_from(&self, d0: u64) -> Walked<Self::Res>;
    /// The model's own walk, no trust input.
    fn plain(&self) -> Self::Res;
    /// The holder op lowers if it may be trusted (an edge write on another holder's edge,
    /// not a finalize).
    fn victim(&self, op: usize) -> Option<usize>;
    /// The victim's ops on what `op` puts in question that `op`'s frontier does not list.
    fn seeds(&self, op: usize) -> u64;
    /// A key of op stable under reordering the writes: (commit ID, op in commit).
    fn key(&self, op: usize) -> (u32, usize);
    fn permute(&self, perm: &[usize]) -> Self;
    /// The same history with nobody offline (None when two writes share a time).
    fn honest(&self) -> Option<Self>;
    /// Two admins really removing each other: ops R (A lowering X) and W (X lowering A, or
    /// someone who granted A), R not listing W.
    fn mutual(&self) -> bool;
    /// Whether two results give everyone the same edges and roles (drop sets aside).
    fn same_state(&self, a: &Self::Res, b: &Self::Res) -> bool;
    /// Whether `a` and `b` agree on everything outside the reach of `op`'s target.
    fn outside_equal(&self, _op: usize, _a: &Self::Res, _b: &Self::Res) -> bool {
        true
    }
}

/// A node's view under a trust set.
#[derive(Clone, Debug)]
pub struct Side<R> {
    pub res: R,
    /// Trusted ops still in force.
    pub active: u64,
    /// Their seeds.
    pub d0: u64,
    pub applied: u64,
    pub demoting: u64,
    /// Walks redone after a shrink, plus one.
    pub rounds: usize,
    /// Open disputes: (R, victim).
    pub disputes: Vec<(usize, usize)>,
}

fn eligible<H: Trusting>(h: &H) -> u64 {
    (0..h.n_ops()).filter(|&op| h.victim(op).is_some()).fold(0, |m, op| m | 1 << op)
}

fn seeds_of<H: Trusting>(h: &H, active: u64) -> u64 {
    (0..h.n_ops()).filter(|&op| active >> op & 1 == 1).fold(0, |m, op| m | h.seeds(op))
}

/// The walk under trust set `trust` (bit per op), with the shrink rule and open disputes.
pub fn side<H: Trusting>(h: &H, trust: u64) -> Side<H::Res> {
    let mut active = trust & eligible(h);
    let mut rounds = 0;
    loop {
        rounds += 1;
        let d0 = seeds_of(h, active);
        let w = h.walk_from(d0);
        let void = active & !w.applied;
        if void == 0 {
            let disputes = (0..h.n_ops())
                .filter_map(|r| {
                    let x = h.victim(r)?;
                    if (w.applied | d0) >> r & 1 == 1 {
                        return None;
                    }
                    (h.walk_from(d0 | h.seeds(r)).demoting >> r & 1 == 1).then_some((r, x))
                })
                .collect();
            return Side { res: w.res, active, d0, applied: w.applied, demoting: w.demoting, rounds, disputes };
        }
        active &= !void;
    }
}

/// The open disputes alone.
pub fn disputes<H: Trusting>(h: &H, trust: u64) -> Vec<(usize, usize)> {
    side(h, trust).disputes
}

/// A side as a function of the write set: result, active trust and disputes by key.
type Keyed<R> = (R, Vec<(u32, usize)>, Vec<((u32, usize), usize)>);
fn keyed<H: Trusting>(h: &H, s: &Side<H::Res>) -> Keyed<H::Res> {
    let mut act: Vec<_> = (0..h.n_ops()).filter(|&op| s.active >> op & 1 == 1).map(|op| h.key(op)).collect();
    act.sort();
    let mut d: Vec<_> = s.disputes.iter().map(|&(r, x)| (h.key(r), x)).collect();
    d.sort();
    (s.res.clone(), act, d)
}

/// `trust` of `h` as ops of `ph` (the same writes reordered).
fn map_trust<H: Trusting>(h: &H, ph: &H, trust: u64) -> u64 {
    (0..h.n_ops()).filter(|&op| trust >> op & 1 == 1).fold(0, |m, op| m | (0..ph.n_ops()).find(|&q| ph.key(q) == h.key(op)).map_or(0, |q| 1 << q))
}

/// One node picking each new open dispute at random (trust R, or keep the walk's side),
/// until none is new: (final trust set, pick rounds, whether a pick revealed a new dispute).
pub fn pick_all<H: Trusting>(h: &H, rng: &mut Rng) -> (u64, usize, bool) {
    let (mut trust, mut decided, mut iters, mut revealed) = (0u64, 0u64, 0, false);
    loop {
        iters += 1;
        let new: Vec<usize> = side(h, trust).disputes.iter().map(|d| d.0).filter(|&r| decided >> r & 1 == 0).collect();
        if new.is_empty() {
            return (trust, iters, revealed);
        }
        revealed |= iters > 1;
        for r in new {
            decided |= 1 << r;
            if rng.below(2) == 0 {
                trust |= 1 << r;
            }
        }
    }
}

/// The properties checked per history (counters) and the first failing history of each.
pub struct Stats<H> {
    pub histories: u64,
    /// Histories with an open dispute under an empty trust set.
    pub with_dispute: u64,
    /// Of those, histories without two admins really removing each other.
    pub unexplained: u64,
    pub max_disputes: usize,
    pub max_rounds: usize,
    pub max_pick_rounds: usize,
    /// Histories where a pick revealed a dispute not open before it.
    pub revealed: u64,
    /// Empty trust set differs from the plain walk.
    pub base_mismatch: u64,
    /// Disputes with nobody offline.
    pub honest: u64,
    /// Trusting a dispute's R leaves it open or voids R.
    pub pick_open: u64,
    pub picks: u64,
    /// Trusting a dispute's R changes something outside the reach of R's target.
    pub outside: u64,
    /// Same writes reordered, same trust set: another result (empty set or picked set).
    pub order_dep: u64,
    /// T, then T', then T again: not the first result.
    pub switch: u64,
    /// Trusting a demotion that applies anyway changes the result.
    pub trusted_effect: u64,
    pub trusted_tries: u64,
    pub ex: Vec<(&'static str, H)>,
}

impl<H> Default for Stats<H> {
    fn default() -> Self {
        Stats {
            histories: 0,
            with_dispute: 0,
            unexplained: 0,
            max_disputes: 0,
            max_rounds: 0,
            max_pick_rounds: 0,
            revealed: 0,
            base_mismatch: 0,
            honest: 0,
            pick_open: 0,
            picks: 0,
            outside: 0,
            order_dep: 0,
            switch: 0,
            trusted_effect: 0,
            trusted_tries: 0,
            ex: vec![],
        }
    }
}

/// Labels of the checks, for examples and shrinking.
const BASE: &str = "empty trust set differs from the plain walk";
const HONEST: &str = "dispute with nobody offline";
const PICK_OPEN: &str = "pick leaves its dispute open";
const OUTSIDE: &str = "pick changes something outside its target's reach";
const ORDER: &str = "order dependence under equal trust sets";
const SWITCH: &str = "switching back reads differently";
const UNEXPLAINED: &str = "dispute without a mutual removal";
const TRUSTED: &str = "trusting an applied demotion changes the result";

/// Whether `h` still fails check `label` (for shrinking; random choices from a fixed seed).
pub fn fails<H: Trusting>(label: &str, h: &H) -> bool {
    let mut st = Stats::default();
    check(h, &mut st, &mut Rng(0x5eed));
    st.ex.iter().any(|(l, _)| *l == label)
}

impl<H: Trusting> Stats<H> {
    fn note(&mut self, label: &'static str, h: &H) {
        if !self.ex.iter().any(|(l, _)| *l == label) {
            self.ex.push((label, h.clone()));
        }
    }

    pub fn merge(&mut self, o: Stats<H>) {
        self.histories += o.histories;
        self.with_dispute += o.with_dispute;
        self.unexplained += o.unexplained;
        self.max_disputes = self.max_disputes.max(o.max_disputes);
        self.max_rounds = self.max_rounds.max(o.max_rounds);
        self.max_pick_rounds = self.max_pick_rounds.max(o.max_pick_rounds);
        self.revealed += o.revealed;
        self.base_mismatch += o.base_mismatch;
        self.honest += o.honest;
        self.pick_open += o.pick_open;
        self.picks += o.picks;
        self.outside += o.outside;
        self.order_dep += o.order_dep;
        self.switch += o.switch;
        self.trusted_effect += o.trusted_effect;
        self.trusted_tries += o.trusted_tries;
        for (l, h) in o.ex {
            self.note(l, &h);
        }
    }

    /// Failures of the checks that must never fail.
    pub fn hard_failures(&self) -> u64 {
        self.base_mismatch + self.honest + self.outside + self.order_dep + self.switch
    }

    pub fn print(&self, name: &str) {
        let pct = |a: u64, b: u64| if b == 0 { 0.0 } else { 100.0 * a as f64 / b as f64 };
        println!(
            "{name}: {} histories | with a dispute {} ({:.3}%), without a mutual removal {} ({:.3}%) | max disputes {} | max shrink rounds {} | max pick rounds {}, picks revealing a dispute {} | picks {} left open {} | trusting an applied demotion: {} tries, {} changed the result | hard: plain-walk mismatch {}, honest disputes {}, outside reach {}, order-dependent {}, switching {}",
            self.histories, self.with_dispute, pct(self.with_dispute, self.histories), self.unexplained, pct(self.unexplained, self.histories), self.max_disputes, self.max_rounds,
            self.max_pick_rounds, self.revealed, self.picks, self.pick_open, self.trusted_tries, self.trusted_effect, self.base_mismatch, self.honest, self.outside, self.order_dep, self.switch
        );
        for (label, h) in &self.ex {
            let m = shrink(h.clone(), |c: &H| fails(label, c));
            let m = if *label == HONEST { m.honest().unwrap_or(m) } else { m };
            let s = side(&m, 0);
            let ds: Vec<String> = s.disputes.iter().map(|&(r, x)| format!("(op {r} = {:?}, victim {x})", m.key(r))).collect();
            println!("  {label} example (disputes {}):\n{m}", ds.join(" "));
        }
    }
}

/// Every property on one history.
pub fn check<H: Trusting>(h: &H, st: &mut Stats<H>, rng: &mut Rng) {
    st.histories += 1;
    let s0 = side(h, 0);
    if s0.res != h.plain() {
        st.base_mismatch += 1;
        st.note(BASE, h);
    }
    st.max_disputes = st.max_disputes.max(s0.disputes.len());
    if !s0.disputes.is_empty() {
        st.with_dispute += 1;
        if !h.mutual() {
            st.unexplained += 1;
            st.note(UNEXPLAINED, h);
        }
    }
    if let Some(hh) = h.honest() {
        if !side(&hh, 0).disputes.is_empty() {
            st.honest += 1;
            st.note(HONEST, &hh);
        }
    }
    // Picking each open dispute's R alone.
    for &(r, x) in &s0.disputes {
        st.picks += 1;
        let s1 = side(h, 1 << r);
        st.max_rounds = st.max_rounds.max(s1.rounds);
        if s1.active >> r & 1 == 0 || s1.disputes.contains(&(r, x)) {
            st.pick_open += 1;
            st.note(PICK_OPEN, h);
        }
        if !h.outside_equal(r, &s0.res, &s1.res) {
            st.outside += 1;
            st.note(OUTSIDE, h);
        }
    }
    // Trusting a demotion the walk applies anyway.
    for op in (0..h.n_ops()).filter(|&op| s0.demoting >> op & 1 == 1 && h.victim(op).is_some()) {
        st.trusted_tries += 1;
        if !h.same_state(&side(h, 1 << op).res, &s0.res) {
            st.trusted_effect += 1;
            st.note(TRUSTED, h);
        }
    }
    // A node picking until nothing new is open, then order independence and switching.
    let (t, iters, revealed) = pick_all(h, rng);
    st.max_pick_rounds = st.max_pick_rounds.max(iters);
    st.revealed += revealed as u64;
    let st_t = side(h, t);
    st.max_rounds = st.max_rounds.max(st_t.rounds);
    let perm = rng.perm(h.n_writes());
    let ph = h.permute(&perm);
    if keyed(&ph, &side(&ph, 0)) != keyed(h, &s0) || keyed(&ph, &side(&ph, map_trust(h, &ph, t))) != keyed(h, &st_t) {
        st.order_dep += 1;
        st.note(ORDER, h);
    }
    let flip = if t == 0 { s0.disputes.first().map_or(0, |d| 1 << d.0) } else { t & t.wrapping_neg() };
    let _other = side(h, t ^ flip);
    if keyed(h, &side(h, t)) != keyed(h, &st_t) {
        st.switch += 1;
        st.note(SWITCH, h);
    }
}

/// Runs `f` on every thread, merging the stats.
pub fn parallel<H: Trusting>(f: impl Fn(usize, usize) -> Stats<H> + Sync) -> Stats<H> {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let f = &f;
    let stats: Vec<Stats<H>> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads).map(|th| s.spawn(move || f(th, threads))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut all = Stats::default();
    for s in stats {
        all.merge(s);
    }
    all
}

/// `samples` random histories from `gen`, every check on each.
pub fn random<H: Trusting>(samples: u64, seed: u64, gen: impl Fn(&mut Rng) -> H + Sync) -> Stats<H> {
    parallel(|th, threads| {
        let mut rng = Rng(seed ^ (th as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
        let mut st = Stats::default();
        for _ in 0..samples / threads as u64 {
            let h = gen(&mut rng);
            check(&h, &mut st, &mut rng);
        }
        st
    })
}

/// The dispute searches (`roles-model -- N disputes`): exhaustive edge histories (unless
/// `random_only`: `disputes-random`), then `N` random histories per shape of
/// `edges::random_post`, then `N` of `joint::random_post`.
pub fn run(samples: u64, random_only: bool) {
    use crate::edges::{self, Edge, Net, Who, NEVER};
    use crate::{joint, Role::{Admin, Read, Write}};
    const NI: crate::Role = crate::Role::None;
    let e = |role, invite, until| Some(Edge { role, until, invite });
    let fine = [None, e(Write, NI, NEVER), e(Admin, Admin, NEVER), e(Write, Write, 3), e(Read, Read, NEVER)];
    let mut hard = 0;
    for k in (1..=2).filter(|_| !random_only) {
        let st = edges::exhaustive_disputes(k, &fine, &[1, 3, 5, crate::shrink::LATE]);
        st.print(&format!("edges exhaustive k={k} fine"));
        hard += st.hard_failures();
    }
    if !random_only {
        let st = edges::exhaustive_disputes(3, &[None, e(Admin, Admin, NEVER)], &[0, crate::shrink::LATE]);
        st.print("edges exhaustive k=3 coarse");
        hard += st.hard_failures();
    }
    for who in [Who::OneRemover, Who::Rank, Who::RankFreeGrants, Who::Anyone] {
        for net in [Net::Online, Net::Offline] {
            let st = random(samples, 0x5eed, |rng| edges::random_post(rng, who, net));
            st.print(&format!("edges random {who:?} {net:?}"));
            hard += st.hard_failures();
        }
    }
    let st = random(samples, 0x5eed, joint::random_post);
    st.print("joint random post-owner");
    hard += st.hard_failures();
    println!("hard failures {hard}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edges::{self, EHist, EWrite, Edge, Net, Who, NEVER};
    use crate::joint::{self, JHist, JWrite, Owner};
    use crate::shrink::LATE;
    use crate::Role::{self, Admin, Read, Write};

    const NI: Role = Role::None;

    fn e(role: Role, invite: Role, until: u32) -> Option<Edge> {
        Some(Edge { role, until, invite })
    }
    fn admin() -> Option<Edge> {
        e(Admin, Admin, NEVER)
    }

    /// Post-owner edge histories: 0 inert, 1 the first admin.
    struct B(EHist);
    impl B {
        fn new(genesis: &[Option<Edge>]) -> Self {
            B(EHist { genesis: genesis.to_vec(), writes: vec![], recv: vec![] })
        }
        /// Commit with one op; returns its op index (one op per commit here).
        fn op(&mut self, author: usize, x: usize, e: Option<Edge>, t: u32, recv: &[(usize, u32)], fin: bool) -> usize {
            let mut r = vec![LATE; self.0.n()];
            r[author] = t;
            for &(m, tm) in recv {
                r[m] = tm;
            }
            let id = 10 + self.0.writes.len() as u32;
            self.0.writes.push(EWrite { author, t, id, ops: vec![(x, e)], fin });
            self.0.recv.push(r);
            self.0.writes.len() - 1
        }
        fn set(&mut self, author: usize, x: usize, e: Option<Edge>, t: u32, recv: &[(usize, u32)]) -> usize {
            self.op(author, x, e, t, recv, false)
        }
    }

    fn roles(s: &Side<(Vec<(Role, Role)>, Vec<u32>)>) -> Vec<Role> {
        s.res.0.iter().map(|a| a.0).collect()
    }

    /// Every order of the writes reads alike under the same trust set.
    fn assert_order_independent<H: Trusting>(h: &H, trust: u64) {
        let want = keyed(h, &side(h, trust));
        let mut rng = Rng(3);
        for _ in 0..24 {
            let ph = h.permute(&rng.perm(h.n_writes()));
            assert_eq!(keyed(&ph, &side(&ph, map_trust(h, &ph, trust))), want);
        }
    }

    /// Admins 1 and 2 remove each other, neither having seen the other: the earlier stamp
    /// wins and the other removal is a dispute, keyed (R, victim). Trusting it turns the
    /// result around and closes the dispute; untrusting returns to the walk.
    #[test]
    fn mutual_removal_one_dispute() {
        let mut b = B::new(&[None, admin(), admin()]);
        let w = b.set(2, 1, None, 2, &[]);
        let r = b.set(1, 2, None, 3, &[]);
        let s = side(&b.0, 0);
        assert_eq!((roles(&s)[1], roles(&s)[2]), (NI, Admin));
        assert_eq!(s.disputes, vec![(r, 2)]);
        let t = side(&b.0, 1 << r);
        assert_eq!((roles(&t)[1], roles(&t)[2]), (Admin, NI));
        assert!(t.disputes.is_empty() && t.active == 1 << r && t.d0 == 1 << w);
        assert_eq!(side(&b.0, 0).res, s.res);
        // Trusting both: W's seeds (1's writes before W) are empty, R's drop W, so W turns
        // void and shrinks out; R stands.
        let both = side(&b.0, 1 << r | 1 << w);
        assert_eq!((both.res.clone(), both.active, both.rounds), (t.res.clone(), 1 << r, 2));
        assert_order_independent(&b.0, 0);
        assert_order_independent(&b.0, 1 << r);
    }

    /// Kicked admin, variant A: 2 received its removal and contests it. Listing it (stamped
    /// after, as an honest clock does), the contest fails and raises nothing; omitting it
    /// raises a dispute on the contest. Backdated before the removal (within skew, listing
    /// it), the contest wins and the removal is the dispute.
    #[test]
    fn kicked_admin_variant_a() {
        for (seen, wt, want_dispute_on) in [(Some(3), 4, None), (None, 4, Some("contest")), (Some(0), 1, Some("removal"))] {
            let mut b = B::new(&[None, admin(), admin()]);
            let r = b.set(1, 2, None, 2, &seen.map_or(vec![], |s| vec![(2, s)]));
            let w = b.set(2, 1, None, wt, &[]);
            let s = side(&b.0, 0);
            let want = match want_dispute_on {
                None => vec![],
                Some("contest") => vec![(w, 1)],
                _ => vec![(r, 2)],
            };
            assert_eq!(s.disputes, want, "seen {seen:?} t {wt}");
            assert_order_independent(&b.0, 0);
        }
    }

    /// Nobody offline, clocks skewed: a removal whose author had received the other's
    /// earlier-stamped removal (its receipt clock behind the stamp) lists it: no dispute.
    #[test]
    fn listed_removal_raises_none() {
        let mut b = B::new(&[None, admin(), admin()]);
        b.set(2, 1, None, 3, &[(1, 2)]);
        b.set(1, 2, None, 4, &[(2, 6)]);
        assert!(side(&b.0, 0).disputes.is_empty());
    }

    /// `until` and finalize (spec/permissions.md §2): 2 holds admin until 4 and removes 3 at
    /// t=3, unseen by 3. A finalize of 2's ended edge by 3 is no demotion and raises nothing
    /// (it does not even apply: 3 was removed). An explicit removal by 3 instead is voided by
    /// 2's unlisted removal: a dispute.
    #[test]
    fn finalize_raises_none() {
        for fin in [true, false] {
            let mut b = B::new(&[None, admin(), e(Admin, Admin, 4), admin()]);
            b.set(2, 3, None, 3, &[]);
            let f = b.op(3, 2, None, 6, &[], fin);
            let s = side(&b.0, 0);
            assert_eq!(s.disputes, if fin { vec![] } else { vec![(f, 2)] }, "finalize {fin}");
        }
        // A finalize by a writer applies, audits nothing and raises nothing.
        let mut b = B::new(&[None, admin(), e(Write, NI, 4), e(Write, Write, NEVER)]);
        let f = b.op(3, 2, None, 5, &[], true);
        let s = side(&b.0, 0);
        assert!(s.applied >> f & 1 == 1 && s.disputes.is_empty(), "{}", b.0);
    }

    /// Read and write holders and invite grants cannot contest: removing an inviter whose
    /// invite grants the remover never saw drops them (the audit) and raises nothing.
    #[test]
    fn invites_and_lower_roles_raise_none() {
        let mut b = B::new(&[None, admin(), e(Write, Write, NEVER), None, e(Read, NI, NEVER)]);
        let g = b.set(2, 3, e(Write, NI, NEVER), 2, &[]);
        b.set(4, 4, None, 3, &[]);
        b.set(1, 2, None, 4, &[]);
        b.set(1, 4, e(Write, NI, NEVER), 5, &[]);
        let s = side(&b.0, 0);
        assert!(s.disputes.is_empty());
        assert_eq!(s.res.1, vec![b.0.writes[g].id]);
    }

    /// A seed is only what the victim wrote before R: a removed admin re-granted by a third
    /// admin acts again on a node that trusted its removal.
    #[test]
    fn regrant_after_trusted_removal_counts() {
        let mut b = B::new(&[None, admin(), admin(), admin()]);
        b.set(2, 1, None, 2, &[]);
        let r = b.set(1, 2, None, 3, &[]);
        b.set(3, 2, admin(), 5, &[(1, 5), (2, 5)]);
        let late = b.set(2, 3, e(Write, NI, NEVER), 6, &[]);
        let s = side(&b.0, 1 << r);
        assert_eq!(s.active, 1 << r);
        assert!(s.applied >> late & 1 == 1, "{}", b.0);
    }

    /// Joint walk, post-owner: doc D (A0) with admins n0 and n1, doc U (A1) with admin n1
    /// only. n0 and n1 remove each other on D; n1 also grants n2 write on U, unseen by n0.
    /// Trusting n0's removal changes D only; U reads alike on both sides.
    #[test]
    fn outside_reach_unaffected() {
        let w = |author, t, id, target, holder, role| JWrite { author, t, id, target, holder, role };
        let mut genesis = vec![vec![NI; 2]; 5];
        genesis[0][0] = Admin;
        genesis[1][0] = Admin;
        genesis[1][1] = Admin;
        let late = |a: usize, t: u32| (0..3).map(|n| if n == a { t } else { LATE }).collect::<Vec<u32>>();
        let h = JHist {
            nodes: 3,
            owners: vec![Owner::None, Owner::None],
            genesis,
            writes: vec![w(1, 2, 1, 0, 0, NI), w(0, 3, 2, 0, 1, NI), w(1, 1, 3, 1, 2, Write)],
            recv: vec![late(1, 2), late(0, 3), late(1, 1)],
        };
        let s0 = side(&h, 0);
        assert_eq!(s0.disputes, vec![(1, 1)]);
        let s1 = side(&h, 1 << 1);
        assert_eq!((s1.res.1[0][0], s1.res.1[1][0]), (Admin, NI));
        assert!(h.outside_equal(1, &s0.res, &s1.res));
        assert_eq!(s1.res.1[2][1], Write);
        assert_order_independent(&h, 1 << 1);
    }

    /// The searches' hard properties on a sample of each generator, and the exhaustive tier
    /// with one commit.
    #[test]
    fn sample_searches() {
        let mut rng = Rng(11);
        let mut st = Stats::default();
        for (i, who) in [Who::OneRemover, Who::Rank, Who::RankFreeGrants, Who::Anyone].into_iter().enumerate() {
            for net in [Net::Online, Net::Offline] {
                for _ in 0..300 * (1 + 2 * (i == 3) as usize) {
                    let h = edges::random_post(&mut rng, who, net);
                    check(&h, &mut st, &mut rng);
                }
            }
        }
        assert_eq!(st.hard_failures() + st.pick_open, 0);
        let mut js = Stats::default();
        for _ in 0..1500 {
            let h = joint::random_post(&mut rng);
            check(&h, &mut js, &mut rng);
        }
        assert_eq!(js.hard_failures() + js.pick_open, 0);
        assert!(js.with_dispute > 0 && st.with_dispute > 0);
        let ex = edges::exhaustive_disputes(1, &[None, admin(), e(Write, Write, 3)], &[1, LATE]);
        assert_eq!(ex.hard_failures(), 0);
    }
}
