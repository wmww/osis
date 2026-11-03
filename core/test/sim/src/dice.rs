//! The simulator's only randomness: a seeded stream (osis-crypto `SeededRng`).

use osis_crypto::{RngCore, SeededRng};

pub struct Dice(SeededRng);

impl Dice {
    pub fn new(seed: u64) -> Dice {
        Dice(SeededRng::from_u64(seed))
    }
    /// The stream of `(seed, purpose, key)`: what it rolls depends on nothing rolled elsewhere.
    pub fn keyed(seed: u64, purpose: &str, key: &[u64]) -> Dice {
        let mut h = osis_base::hash::Hasher::new();
        h.update(&seed.to_le_bytes());
        h.update(purpose.as_bytes());
        for k in key {
            h.update(&k.to_le_bytes());
        }
        let d = h.finalize();
        Dice::new(d.iter().take(8).fold(0, |x, b| x << 8 | u64::from(*b)))
    }
    pub fn u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    /// Uniform in `0..n` (`0` when `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.0.next_u64() % n }
    }
    pub fn index(&mut self, n: usize) -> usize {
        self.below(n as u64) as usize
    }
    /// True with probability `p` percent.
    pub fn pct(&mut self, p: u32) -> bool {
        self.below(100) < u64::from(p)
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> Option<&'a T> {
        xs.get(self.index(xs.len()))
    }
    /// Uniform in `lo..=hi`.
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            return lo;
        }
        let span = hi.abs_diff(lo).saturating_add(1);
        lo.saturating_add_unsigned(self.below(span))
    }
}
