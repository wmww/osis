//! Small helpers: poison-tolerant locking, a seeded rng, a gate tasks wait on, a bounded set of
//! tasks.

use crate::Error;
use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
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
        for c in out.as_chunks_mut::<8>().0 {
            *c = self.next_u64().to_le_bytes();
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

/// `f`, or `Err(Closed)` once `gate` closes.
pub(crate) async fn race<T>(gate: &Gate, f: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
    let mut f = std::pin::pin!(f);
    poll_fn(|cx| if gate.poll_closed(cx).is_ready() { Poll::Ready(Err(Error::Closed)) } else { f.as_mut().poll(cx) }).await
}

/// Tasks in progress, oldest first, each with the gate that ends it (`race`): past `cap` the
/// oldest ends, so they stay bounded without a deadline that refuses slow peers.
pub(crate) struct Bounded {
    cap: usize,
    next: AtomicU64,
    q: Mutex<VecDeque<(u64, Arc<Gate>)>>,
}

impl Bounded {
    pub(crate) fn new(cap: usize) -> Bounded {
        Bounded { cap, next: AtomicU64::default(), q: Mutex::default() }
    }

    /// A task starts: its id and its gate.
    pub(crate) fn start(&self) -> (u64, Arc<Gate>) {
        let (id, gate) = (self.next.fetch_add(1, Ordering::Relaxed), Arc::new(Gate::default()));
        let mut q = lock(&self.q);
        q.push_back((id, gate.clone()));
        while q.len() > self.cap {
            if let Some((_, old)) = q.pop_front() {
                old.close();
            }
        }
        (id, gate)
    }

    /// Task `id` ended.
    pub(crate) fn end(&self, id: u64) {
        lock(&self.q).retain(|(i, _)| *i != id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/sync-transport.md §1: handshakes have no deadline; past the cap the oldest in progress goes
    #[test]
    fn bounded_ends_the_oldest() {
        let b = Bounded::new(2);
        let started: Vec<_> = (0..3).map(|_| b.start()).collect();
        assert_eq!(started.iter().map(|(_, g)| g.is_closed()).collect::<Vec<_>>(), [true, false, false]);
        started.iter().for_each(|(id, _)| b.end(*id));
        assert!(lock(&b.q).is_empty());
    }
}
