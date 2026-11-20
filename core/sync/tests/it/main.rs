//! osis-sync's one test binary: the harness (notes/sync-test-harness.md) and every sync test on it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod differential;
mod faults;
mod flows;
mod growth;
mod idle;
mod first;
mod harness;
mod holding;
mod inbox;
mod keep;
mod leave;
mod links;
mod tickets;
mod session;
mod sims;
mod read;
mod retention;
mod status;
mod suspect;
mod store;
mod opens;
mod pieces;
mod streams;
mod world;
mod deletes;
mod delete_keys;
mod again;
mod destruction;
mod driver;
mod duties;
