//! osis-sync's one test binary: the harness (notes/sync-test-harness.md) and every sync test on it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod convergence;
mod ephemeral;
mod faults;
mod flows;
mod growth;
mod harness;
mod inbox;
mod keep;
mod leave;
mod life;
mod links;
mod metadata;
mod session;
mod siblings;
mod shred;
mod sims;
mod read;
mod retain;
mod retention;
mod unread;
mod status;
mod stranded;
mod suspect;
mod store;
mod opens;
mod pieces;
mod streams;
mod world;
mod deletes;
mod again;
mod demotions;
mod destruction;
mod driver;
mod duties;
