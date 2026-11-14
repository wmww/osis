//! osis-sync's one test binary: the harness (notes/sync-test-harness.md) and every sync test on it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod convergence;
mod faults;
mod flows;
mod harness;
mod inbox;
mod keep;
mod session;
mod sims;
mod read;
mod unread;
mod status;
mod store;
mod opens;
mod streams;
mod world;
mod driver;
