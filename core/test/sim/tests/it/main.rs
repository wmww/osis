//! osis-sim integration tests: one binary, one module per area (notes/testing.md, When tests run).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod net;
mod no_server;
mod peers;
mod scale;
mod scenarios;
mod work_sets;
