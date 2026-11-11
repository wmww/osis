//! osis-host integration tests: one binary, one module per area (notes/testing.md, When tests run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod bounds;
mod file;
mod hub;
mod hygiene;
mod limits;
