//! osis-sim: Deterministic multi-node simulator. Real node engines driven engine-to-engine by a
//! seeded scheduler (`harness`), per-node virtual clocks with skew and drift, message faults
//! (drop, duplicate, delay, reorder), crash and restart over the same `MemoryBackend`; the
//! invariant library (`check`); named scenarios with seed replay (`scenarios`). No tokio, no
//! threads, no I/O. Layer 9 (notes/architecture.md). Notes: notes/test-sim.md.
#![forbid(unsafe_code)]

pub mod check;
pub mod dice;
pub mod harness;
pub mod scenarios;
pub mod workload;

pub use harness::{ClockSpec, Config, Failure, NetFaults, Node, Report, Res, Seeds, Sim, Weights};
pub use scenarios::{BLOCKED, SCENARIOS, blocked, replay, run, setup_seed};
