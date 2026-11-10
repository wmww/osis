//! osis-perm integration tests: one binary, one module per area (notes/testing.md, When tests run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod chain;
mod scale;
mod content;
mod epochs;
mod differential;
mod incremental;
mod queries;
mod robust;
mod scenarios;
