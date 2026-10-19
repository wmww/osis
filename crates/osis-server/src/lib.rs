//! osis-server: the blind node used as a server (spec/sync.md §4-§9): `BackendStore` (osis-proto's
//! `LabelStore` over an osis-store `Backend`, with the server policy).
//! Layer 6 (notes/architecture.md). Plan: plans/server.md.
#![forbid(unsafe_code)]

pub mod store;

pub use store::{BackendStore, DEPOSIT_ENTRY_BYTES, Policy};
