//! osis-sync's one test binary: the harness (notes/sync-test-harness.md) and every sync test on it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod harness;
mod inbox;
mod session;
mod read;
mod unread;
mod store;
mod opens;
mod streams;
mod world;
