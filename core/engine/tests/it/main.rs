//! osis-engine integration tests: one binary, one module per area (notes/testing.md, When tests run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod covered;
mod setting;
mod caches;
mod corrupt;
mod dial;
mod crash;
mod disputes;
mod edits;
mod facade;
mod groups;
mod finalize;
mod encodings;
mod flows;
mod judgment;
mod keys;
mod listing;
mod held;
mod order;
mod parts;
mod receive;
mod sessions;
mod review;
mod shred;
mod synthetic;
mod validity;
mod waits;
mod expiry_model;
mod write;
mod scale;
mod memory;
mod own_secrets;
