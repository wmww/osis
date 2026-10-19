//! osis-server: the blind node used as a server (spec/sync.md §4-§9): `BackendStore` (osis-proto's
//! `LabelStore` over an osis-store `Backend`, with the server policy), `Hub` (sans-I/O: server
//! engines per connection, cross-connection notices, sweeps, push replication to peer servers).
//! Layer 6 (notes/architecture.md). Plan: plans/server.md.
#![forbid(unsafe_code)]

pub mod hub;
pub mod replicate;
pub mod store;

pub use hub::{ConnId, Hub, HubOutput};
pub use replicate::Replicator;
pub use store::{BackendStore, DEPOSIT_ENTRY_BYTES, Policy};
