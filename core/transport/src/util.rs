//! Small helpers: poison-tolerant locking, a seeded rng, a gate tasks wait on.

use std::future::poll_fn;
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

/// Locks, ignoring poisoning (a panicked test thread must not cascade).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// SplitMix64: seeded, deterministic, not cryptographic (scheduling and fault choices only).
#[derive(Clone, Debug)]
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// In `0..n`; 0 when `n == 0`.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
    pub(crate) fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for c in out.chunks_mut(8) {
            let w = self.next_u64().to_le_bytes();
            for (d, s) in c.iter_mut().zip(w) {
                *d = s;
            }
        }
        out
    }
}

/// Set once; wakes whoever waits for it.
#[derive(Default)]
pub(crate) struct Gate(Mutex<(bool, Vec<Waker>)>);

impl Gate {
    pub(crate) fn close(&self) {
        let ws = {
            let mut g = lock(&self.0);
            g.0 = true;
            std::mem::take(&mut g.1)
        };
        ws.into_iter().for_each(Waker::wake);
    }

    pub(crate) fn is_closed(&self) -> bool {
        lock(&self.0).0
    }

    pub(crate) fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut g = lock(&self.0);
        if g.0 {
            return Poll::Ready(());
        }
        if !g.1.iter().any(|w| w.will_wake(cx.waker())) {
            g.1.push(cx.waker().clone());
        }
        Poll::Pending
    }

    pub(crate) async fn closed(&self) {
        poll_fn(|cx| self.poll_closed(cx)).await
    }
}
