//! Redial backoff (a P2P listener's relay registrations).

use crate::util::Rng;

/// Exponential backoff with seeded jitter: delay `n` is uniform in `[d/2, d]`, `d = min(base * 2^n, max)`.
#[derive(Clone, Debug)]
pub struct Backoff {
    base_ms: u64,
    max_ms: u64,
    attempt: u32,
    rng: Rng,
}

impl Backoff {
    /// Defaults for redialing a relay (provisional): 500 ms doubling to 60 s.
    pub fn new(seed: u64) -> Backoff {
        Backoff::with(500, 60_000, seed)
    }

    pub fn with(base_ms: u64, max_ms: u64, seed: u64) -> Backoff {
        Backoff { base_ms, max_ms, attempt: 0, rng: Rng::new(seed) }
    }

    pub fn next_delay_ms(&mut self) -> u64 {
        let d = self.base_ms.saturating_mul(1u64.checked_shl(self.attempt).unwrap_or(u64::MAX)).min(self.max_ms);
        self.attempt = self.attempt.saturating_add(1);
        d - self.rng.below(d / 2 + 1).min(d / 2)
    }

    /// After a connection that worked.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}
