//! osis-sim: Deterministic multi-node simulator. Real node engines driven engine-to-engine by a
//! seeded scheduler (`harness`), per-node virtual clocks with skew and drift, message faults
//! (drop, duplicate, delay, reorder), crash and restart over the same `MemoryBackend`; the
//! invariant library (`check`); named scenarios with seed replay (`scenarios`). No tokio, no
//! threads, no I/O (notes/architecture.md §2, node sync layer is sans-I/O).
//! Layer 9 (notes/architecture.md). Plan: plans/sim.md. Phase A: commits only (no labels,
//! servers or sync engine yet).
#![forbid(unsafe_code)]

pub mod check;
pub mod dice;
pub mod harness;
pub mod net;
pub mod scenarios;
pub mod workload;

pub use harness::{ClockSpec, Config, Failure, NetFaults, Node, Report, Res, Sim, Weights};
pub use scenarios::{BLOCKED, SCENARIOS, blocked, replay, run};
