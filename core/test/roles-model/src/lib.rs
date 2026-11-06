//! Throwaway model of the role rules (spec/permissions.md §5; findings in
//! notes/permissions.md). Independent of any real implementation: a differential oracle for
//! osis-perm. Patched only to follow the spec where it had simplified it (osis-perm's
//! differential runs exposed each): `joint` judges a demotion against the edge restored as
//! if the holder still held its role (spec §5.1) and treats removing a holder one is admin of
//! as a self-removal only without authority on the target (§2). No model exempts the
//! demoter's chain writes: only its frontier covers them (§5.1). Every actor's first admin
//! holds its record edge (admin) in genesis, removable like any edge (§1). Modules by spec
//! section:
//! - `single`: §5.1 on one actor, the adopted demoter-frontier rule and rejected variants.
//! - `joint`: §5.1 steps 1-5 over several actors (record edges, actor holders, mutual
//!   roles, commit-ID ties); `joint::walk`, `joint::random_hist`.
//! - `edges`: §2 (`until`, invite power, self-removal) and §7 (links) on one target, with
//!   §5.1 attribution by invite level; `edges::walk`, `edges::random_hist`.
//! - `content`: §5.2 per-delta content validity.
//! - `shrink`: counterexample shrinking (`Shrink` per history type; `shrink::shrink`).
//! - `trust`: disputes and trust sets over `edges` and `joint` (notes/owner-removal-plan.md
//!   step 3), below.
//! Each model's library API: `walk(h)`, the timeline as a pure function of a history;
//! `random_hist`; `quiescent(h)` (every node's walk over the writes in its delivery order
//! agrees with the canonical one); `Display` on a history prints it as a trace. The joint
//! walk's code follows §5.1 step by step (`order`, `authority`, `audit`, `pass`, `eval`).
//! Searches print each counterexample shrunk. `digest` hashes every verdict over random
//! histories: a refactor must keep it (values in notes/testing.md, Models).
//! Binary: `cargo run --bin roles-model -- [samples] [mode]`; `cargo test` runs
//! the scenarios.
//!
//! Disputes (`trust`; results in notes/owners.md, "Model results, committed"). A node's
//! trust set is one more walk input: ops it sides with, each an edge write R by A lowering
//! another holder X. R seeds D with X's writes ordered before R that R's frontier does not
//! list, X's writes on its own edges excepted. Shrink: trusted ops a walk leaves unapplied
//! lose their seeds for good, all at once, and the walk is redone from scratch. A dispute is
//! an unapplied R that applies as an explicit demotion of X once its seeds are added to D,
//! keyed (R, X). `edges::random_shaped` limits who may lower whom and who is online. Both
//! walks gain `eval_from` (D seeded) and the demotions they applied; `edges` gains
//! finalizes (`EWrite::fin`, spec/permissions.md §2). Searches: `roles-model -- N disputes`
//! (exhaustive edge tiers, then N random histories per shape: who may lower whom × online or
//! offline, then N joint histories); `disputes-random` skips the exhaustive tiers. Hard
//! properties: no trust set reads as the plain walk; nobody offline raises no dispute;
//! equal trust sets read alike in any write order; T, T', T reads as T; a pick changes
//! nothing outside its target's reach (joint). Reported: disputes per shape and those
//! without a mutual removal, shrink and pick rounds, picks leaving their dispute open, and
//! trusting a demotion that applies anyway changing the result.

pub mod content;
pub mod edges;
pub mod joint;
pub mod shrink;
pub mod single;
pub mod trust;

/// Roles, `None` below read.
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

/// Seeded xorshift generator: every history is a seed.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
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
pub fn digest(samples: u64, seed: u64) -> [(&'static str, u64); 3] {
    use std::hash::{Hash, Hasher};
    let mut hs: [std::collections::hash_map::DefaultHasher; 3] = Default::default();
    let mut rng = Rng(seed);
    for _ in 0..samples {
        let h = joint::random_hist(&mut rng);
        format!("{:?}", joint::walk(&h)).hash(&mut hs[0]);
        let h = edges::random_hist(&mut rng);
        format!("{:?}", edges::walk(&h)).hash(&mut hs[1]);
        format!("{:?}", h.eval_mode(edges::Drops::Provenance)).hash(&mut hs[2]);
    }
    let [a, b, c] = hs;
    [("joint", a.finish()), ("edges", b.finish()), ("edges-prov", c.finish())]
}
