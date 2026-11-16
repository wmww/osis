//! Throwaway model of the role rules (spec/permissions.md §5; findings in
//! notes/role-timeline.md). Independent of any real implementation: a differential oracle for
//! osis-perm. Patched only to follow the spec where it had simplified it (osis-perm's
//! differential runs exposed each): `joint` judges a demotion against the edge restored as
//! if the holder still held its role (spec §5.1) and treats removing a holder one is admin of
//! as a self-removal only without authority on the target (§2). No model exempts the
//! demoter's chain writes: only its frontier covers them (§5.1). Every actor's first admin
//! holds its record edge (admin) in genesis, removable like any edge (§1). Modules by spec
//! section:
//! - `joint`: §5.1 steps 1-5 over several actors (record edges, actor holders, mutual
//!   roles, commit-ID ties); `joint::walk`, `joint::random_hist`. osis-perm `joint_model_agrees`.
//! - `edges`: §2 (`until`, invite power, self-removal) and §7 (links) on one target, with
//!   §5.1 attribution by invite level; `edges::walk`, `edges::random_hist`. osis-perm
//!   `edges_model_agrees`.
//! - `trust`: disputes and trust sets over `edges` and `joint` (notes/disputes.md), below.
//!   osis-perm `trust_model_agrees`.
//! - `content`: §5.2 per-delta content validity: scenarios.
//! - `addenda`: addenda (spec/permissions.md §5.2): layer 2 with several authors over `joint`
//!   timelines (`JHist::steps`), witnesses' addenda as a least fixpoint, bodies dropped and
//!   refetched, forged addenda, cost, which covered commits lists leave out (`Cover`).
//!   Searches `addenda` (random), `addenda-exh` (exhaustive families), `addenda-covers`.
//!   osis-perm `addenda_model_agrees`; results: notes/addenda.md, Addenda model.
//! - `forget`: forgetting a commit's ID under a cover and the remover's own cover
//!   (spec/commits.md §5 Forgetting), per node with real body drops, against listing every
//!   commit. Search `forget`.
//! - `epochs`: account signing epochs (issues/account-signing.md): node removal as
//!   rotation, per-sync-ID list parts and per-thing lists, listings, witnesses' addenda,
//!   successive removals, re-adds, the part bound, forks and thieves (README.md, results).
//!   osis-perm `epochs_model_agrees`.
//! - `custody`: notes/engine-validity-epochs.md, greenfield: seed custody follows holding, the
//!   chain is D's roster, a merge is only a join (README.md, results). osis-engine
//!   `rotation::tests_custody`.
//! - `shrink`: counterexample shrinking (`Shrink` per history type; `shrink::shrink`).
//! Each model's library API: `walk(h)`, the timeline as a pure function of a history;
//! `random_hist`; `quiescent(h)` (every node's walk over the writes in its delivery order
//! agrees with the canonical one); `Display` on a history prints it as a trace. The joint
//! walk's code follows §5.1 step by step (`order`, `authority`, `audit`, `pass`, `eval`).
//! Searches print each counterexample shrunk. `digest` hashes every verdict over random
//! histories: a refactor must keep it (values in notes/test-properties.md, Models).
//! Binary: `cargo run --bin roles-model -- [samples] [mode]`; `cargo test` runs
//! the scenarios.
//!
//! Disputes (`trust`; results in notes/disputes.md, "Model results, committed"). A node's
//! trust set is one more walk input: ops it sides with, each an edge write R by A lowering
//! another holder X. R seeds D with X's writes ordered before R that R's frontier does not
//! list, X's writes lowering its own edges excepted. Shrink: trusted ops a walk leaves unapplied
//! lose their seeds for good, all at once, and the walk is redone from scratch. A dispute is
//! an unapplied R that applies as an explicit demotion of X once its seeds are added to D,
//! keyed (R, X). `edges::random_shaped` limits who may lower whom and who is online. Both
//! walks' `eval_from` takes D's seeds and returns the demotions applied; `edges` models
//! finalizes (`EWrite::fin`, spec/permissions.md §2). Searches: `roles-model -- N disputes`
//! (exhaustive edge tiers, then N random histories per shape: who may lower whom × online or
//! offline, then N joint histories); `disputes-random` skips the exhaustive tiers. Hard
//! properties: no trust set reads as the plain walk; nobody offline raises no dispute;
//! equal trust sets read alike in any write order; T, T', T reads as T; a pick changes
//! nothing outside its target's reach (joint). Reported: disputes per shape and those
//! without a mutual removal, shrink and pick rounds, picks leaving their dispute open, and
//! trusting a demotion that applies anyway changing the result.

pub mod addenda;
pub mod content;
pub mod custody;
pub mod edges;
pub mod epochs;
pub mod forget;
pub mod joint;
pub mod shrink;
pub mod trust;

/// Roles, `None` below read. The build's sync role (below read) is not modelled: §5.1 judges it as
/// read (neither writes nor audits), and invites and attribution are min/max over a total
/// order, so one more level below read adds no new interleaving.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Role {
    None,
    Read,
    Write,
    Admin,
}

/// Honest receipts (spec/permissions.md §4, §5.1): before writing, every author holds its
/// chain certificates, the writes setting edges on its paths and, transitively, on the paths
/// of their authors before them. `writes[j]` = (author, t); `sets(j, x)`: write j may set an
/// edge on node x's paths (an over-approximation is fine: more receipts). `recv[j][x]` drops
/// below write j's own `t` for each such holder (receipt clocks may skew). A `late` write was
/// written last (a backdated forgery, say): nobody but its author ever holds it.
pub fn hold_chains(writes: &[(usize, u32)], late: &[bool], sets: impl Fn(usize, usize) -> bool, recv: &mut [Vec<u32>]) {
    for (j, row) in recv.iter_mut().enumerate() {
        if late.get(j).copied().unwrap_or(false) {
            let author = writes.get(j).map_or(usize::MAX, |w| w.0);
            for (x, r) in row.iter_mut().enumerate() {
                if x != author {
                    *r = 1000; // LATE: never received
                }
            }
        }
    }
    for &(a, ti) in writes {
        let mut stack = vec![(a, ti)];
        let mut seen = std::collections::HashSet::new();
        while let Some((y, bound)) = stack.pop() {
            if !seen.insert((y, bound)) {
                continue;
            }
            for (j, &(aj, tj)) in writes.iter().enumerate() {
                // a write at the same `t` may be ordered before: received just before it
                if tj <= bound && !late.get(j).copied().unwrap_or(false) && sets(j, y) {
                    if let Some(r) = recv.get_mut(j).and_then(|r| r.get_mut(a)) {
                        *r = (*r).min(tj.saturating_sub(1));
                    }
                    stack.push((aj, tj));
                }
            }
        }
    }
}

/// About a quarter of the writes `eligible` allows, tagged as written last (`hold_chains`).
/// Only writes that grant no admin are eligible: nobody honest acts on authority it never
/// received, so a late write never gives anyone the authority behind another write.
pub fn late_writes(rng: &mut Rng, eligible: &[bool]) -> Vec<bool> {
    eligible.iter().map(|e| rng.below(4) == 0 && *e).collect()
}

/// The order in which node `n` received the writes (`recv[write][node]`): by receipt time,
/// never-received (`shrink::LATE`) ones last, ties by index.
pub fn delivery_order(recv: &[Vec<u32>], n: usize) -> Vec<usize> {
    let mut o: Vec<usize> = (0..recv.len()).collect();
    o.sort_by_key(|&j| recv[j].get(n).copied().unwrap_or(shrink::LATE));
    o
}

/// Receipts of a write for a trace: `n0@3` (received at 3), `n1 -` (never); the author left out.
pub fn fmt_recv(recv: &[u32], author: usize) -> String {
    let v: Vec<String> = recv.iter().enumerate().filter(|&(n, _)| n != author).map(|(n, &r)| if r >= shrink::LATE { format!("n{n} -") } else { format!("n{n}@{r}") }).collect();
    format!("recv {}", v.join(", "))
}

/// Counters a search sums over threads.
pub trait Tally: Default + Send {
    fn merge(&mut self, o: Self);
}

impl Tally for u64 {
    fn merge(&mut self, o: u64) {
        *self += o;
    }
}

impl<const N: usize> Tally for [u64; N]
where
    [u64; N]: Default,
{
    fn merge(&mut self, o: Self) {
        for (a, b) in self.iter_mut().zip(o) {
            *a += b;
        }
    }
}

impl<A: Tally, B: Tally> Tally for (A, B) {
    fn merge(&mut self, o: Self) {
        self.0.merge(o.0);
        self.1.merge(o.1);
    }
}

/// `f(thread, threads, tally)` on a thread per core, the tallies summed.
pub fn on_every_core<T: Tally>(f: impl Fn(usize, usize, &mut T) + Sync) -> T {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let f = &f;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|th| {
                s.spawn(move || {
                    let mut t = T::default();
                    f(th, threads, &mut t);
                    t
                })
            })
            .collect();
        hs.into_iter().fold(T::default(), |mut all, h| {
            all.merge(h.join().unwrap());
            all
        })
    })
}

/// Seeded xorshift generator: every history is a seed (0 included).
pub struct Rng(pub u64);
impl Rng {
    /// Thread `th`'s generator of a search seeded `seed`.
    pub fn thread(seed: u64, th: usize) -> Rng {
        Rng(seed ^ (th as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }
    pub fn next(&mut self) -> u64 {
        // (xorshift never leaves a zero state, nor reaches one)
        if self.0 == 0 {
            self.0 = 0x9E37_79B9_7F4A_7C15;
        }
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn perm(&mut self, n: usize) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            v.swap(i, self.below(i + 1));
        }
        v
    }
}


/// Digest of every walk verdict (edges, roles, applied and dropped sets, attributions, passes)
/// over `samples` random histories of each model. A refactor of the rule code must leave it
/// unchanged (`roles-model -- N digest`).
pub fn digest(samples: u64, seed: u64) -> [(&'static str, u64); 2] {
    use std::hash::{Hash, Hasher};
    let mut hs: [std::collections::hash_map::DefaultHasher; 2] = Default::default();
    let mut rng = Rng(seed);
    for _ in 0..samples {
        let h = joint::random_hist(&mut rng);
        format!("{:?}", joint::walk(&h)).hash(&mut hs[0]);
        let h = edges::random_hist(&mut rng);
        format!("{:?}", edges::walk(&h)).hash(&mut hs[1]);
    }
    let [a, b] = hs;
    [("joint", a.finish()), ("edges", b.finish())]
}
