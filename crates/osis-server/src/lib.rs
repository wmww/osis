//! osis-server: the blind node used as a server (spec/sync.md §4-§9): `BackendStore` (osis-proto's
//! `LabelStore` over an osis-store `Backend`, with the server policy), `Hub` (sans-I/O: server
//! engines per connection, cross-connection notices, sweeps, push replication to peer servers),
//! the async `driver` over any osis-transport `Transport` (feature `driver`, default; QUIC: feature
//! `quic`), and the binary's `config`
//! (binary and `serve::run`, which `osis serve` calls: feature `bin`).
//! Layer 6 (notes/architecture.md). Plan: plans/server.md.
#![forbid(unsafe_code)]

pub mod config;
#[cfg(feature = "driver")]
pub mod driver;
pub mod hub;
pub mod replicate;
#[cfg(feature = "bin")]
pub mod serve;
pub mod store;

pub use config::Config;
#[cfg(feature = "driver")]
pub use driver::{Control, Endpoint, Log, run};
pub use hub::{ConnId, Hub, HubOutput};
pub use replicate::Replicator;
pub use store::{BackendStore, DEPOSIT_ENTRY_BYTES, Policy, Swept, Totals};
