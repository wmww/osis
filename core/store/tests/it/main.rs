//! osis-store integration tests: one binary, one module per area (notes/testing.md, When tests run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod backend;
mod crash;
mod nodelog;
mod paged;
mod record;
mod shred;
mod store;
