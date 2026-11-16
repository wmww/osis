//! A debug-build round guard for loops that run to a fixpoint (node-sync's settle, `LocalPeer`'s
//! wake): a loop that never ends panics naming itself and its last rounds' progress, so a hang
//! fails with a cause instead of running until something kills it. Release builds count nothing.

use std::collections::VecDeque;
use std::fmt::Debug;

/// Rounds whose progress a panic shows (minor consequence: message length; at 0 it shows none,
/// at infinity every round a hang made).
const SHOWN: usize = 4;

/// One run of a loop: call `round` once per round with what the round did.
pub struct LoopGuard<T> {
    name: &'static str,
    rounds: u64,
    /// The bound last derived from the loop's size, and that size described.
    bound: Option<(u64, String)>,
    recent: VecDeque<T>,
}

impl<T: Debug> LoopGuard<T> {
    pub fn new(name: &'static str) -> LoopGuard<T> {
        LoopGuard { name, rounds: 0, bound: None, recent: VecDeque::new() }
    }

    /// One more round, which did `progress`. `bound` gives the most rounds a loop of its size
    /// can take, and that size described: derived after the first round and again whenever
    /// passed (the size may grow while the loop runs), panicking when the loop is past it still.
    pub fn round(&mut self, progress: T, bound: impl Fn() -> (u64, String)) {
        if !cfg!(debug_assertions) {
            return;
        }
        self.rounds += 1;
        if self.recent.len() == SHOWN {
            self.recent.pop_front();
        }
        self.recent.push_back(progress);
        if self.rounds < 2 || self.bound.as_ref().is_some_and(|(b, _)| self.rounds <= *b) {
            return;
        }
        let (b, size) = bound();
        if self.rounds > b {
            #[allow(clippy::panic)]
            {
                panic!("{}: {} rounds, past its bound of {b} ({size}); the last rounds' progress, oldest first: {:?}", self.name, self.rounds, self.recent);
            }
        }
        self.bound = Some((b, size));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (diagnostic: notes/test-harnesses.md, Loop guards). A loop within its bound runs
    // on, the bound derived again when passed as the size grows; past it the panic names the loop,
    // its size and its last rounds.
    #[test]
    fn past_its_bound_a_loop_panics_naming_its_last_rounds() {
        let size = std::cell::Cell::new(3);
        let mut g = LoopGuard::new("probe loop");
        for r in 0..6 {
            if r == 3 {
                size.set(6);
            }
            g.round(r, || (size.get(), format!("size {}", size.get())));
        }
        let e = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.round(6, || (size.get(), format!("size {}", size.get()))))).expect_err("past its bound");
        let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(msg.starts_with("probe loop: 7 rounds, past its bound of 6 (size 6)") && msg.ends_with("[3, 4, 5, 6]"), "{msg}");
    }
}
