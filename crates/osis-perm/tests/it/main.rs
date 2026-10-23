//! osis-perm integration tests: one binary, one module per area (notes/testing.md, Tiers).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod bench;
mod content;
mod differential;
mod incremental;
mod queries;
mod robust;
mod roster;
mod scenarios;
