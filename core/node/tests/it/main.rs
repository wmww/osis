//! osis-node integration tests: one binary, one module per area (notes/testing.md, Tiers).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod net;
mod cert_judge;
mod corrupt;
mod crash;
mod deletion;
mod deposit_queue;
#[cfg(feature = "driver")]
mod driver;
mod encodings;
mod ephemeral;
mod presence;
mod flows;
mod hostile_server;
mod inbox_life;
mod inbox_retry;
mod keys;
mod labeling;
mod lazy_tree;
mod local_serve;
mod metadata;
mod negative;
mod order;
mod pass_marks;
mod peers;
mod peers_review;
mod receive;
mod replaced_chunks;
mod retention;
mod review;
mod revokes;
mod scale;
mod shred;
mod sync;
mod sync_more;
mod sync_review;
mod sync_round2;
mod synthetic;
mod timed_dead;
mod validity;
mod waits;
mod walks;
mod write;
