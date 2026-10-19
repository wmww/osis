//! Throwaway model of the membership rules (spec/permissions.md §5-§6; findings in
//! notes/permissions.md). Independent of any real implementation: a differential oracle for
//! osis-perm. Patched only to follow the spec where it had simplified it (osis-perm's
//! differential runs exposed each): `joint` judges a demotion against the edge restored as
//! if the member still held its role (spec §5.1), counts as chain writes only the admin edges
//! on the demoter's admin paths, ignores edges for the target's owner (§1), and treats removing
//! a member one is admin of as a self-removal only without authority on the target (§2);
//! `snapshot` counts only admin grants as chain writes. Modules by spec section:
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

