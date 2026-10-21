//! Throwaway model of the membership rules (spec/permissions.md §5-§6; findings in
//! notes/permissions.md). Independent of any real implementation: a differential oracle for
//! osis-perm. Patched only to follow the spec where it had simplified it (osis-perm's
//! differential runs exposed each): `joint` judges a demotion against the edge restored as
//! if the member still held its role (spec §5.1), ignores edges for the target's owner (§1),
//! and treats removing a member one is admin of as a self-removal only without authority on
//! the target (§2). No model exempts the demoter's chain writes: only its frontier covers
//! them (§5.1). Modules by spec section:
//! - `single`: §5.1 on one actor, the adopted demoter-frontier rule and rejected variants.
//! - `joint`: §5.1 steps 1-5 over several actors (owner chains, actor members, mutual
//!   membership, commit-ID ties); `joint::walk`, `joint::random_hist`.
//! - `edges`: §2 (`until`, invite power, self-removal) and §9 (links) on one target, with
//!   §5.1 attribution by invite level; `edges::walk`, `edges::random_hist`.
//! - `snapshot`: §6 roster snapshots, epoch starts and the tenure ledger on two levels.
//! - `content`: §5.2 per-delta content validity.
//! Binary: `cargo run --release -p membership-model -- [samples] [mode]`; `cargo test` runs
//! the scenarios.

pub mod content;
pub mod edges;
pub mod joint;
pub mod single;
pub mod snapshot;

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
/// below write j's own `t` for each such holder (receipt clocks may skew).
pub fn hold_chains(writes: &[(usize, u32)], sets: impl Fn(usize, usize) -> bool, recv: &mut [Vec<u32>]) {
    for &(a, ti) in writes {
        let mut stack = vec![(a, ti)];
        let mut seen = std::collections::HashSet::new();
        while let Some((y, bound)) = stack.pop() {
            if !seen.insert((y, bound)) {
                continue;
            }
            for (j, &(aj, tj)) in writes.iter().enumerate() {
                // a write at the same `t` may be ordered before: received just before it
                if tj <= bound && sets(j, y) {
                    if let Some(r) = recv.get_mut(j).and_then(|r| r.get_mut(a)) {
                        *r = (*r).min(tj.saturating_sub(1));
                    }
                    stack.push((aj, tj));
                }
            }
        }
    }
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

