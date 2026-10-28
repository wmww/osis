//! osis-server integration tests: one binary, one module per area (notes/testing.md, Tiers).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;
mod bounds;
#[cfg(feature = "driver")]
mod driver;
#[cfg(feature = "file-backend")]
mod file;
mod hub;
mod hygiene;
mod limits;
#[cfg(feature = "quic")]
mod quic;
