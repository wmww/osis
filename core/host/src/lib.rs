//! osis-host: hosting, a node storing and serving labels it need not read (spec/sync.md §4-§9):
//! `HostStore` (osis-proto's `LabelStore` over an osis-store `Backend`, with the `HostPolicy`),
//! `Hub` (sans-I/O: a serving session per connection, cross-connection notices, sweeps, push
//! replication to peer hosts), the async `driver` over any osis-transport `Transport` (feature
//! `driver`, default), and `config` and `serve::run` for `osis serve`. osis-node depends on it,
//! never the reverse: hosting reaches no engine, key or sync state.
//! Layer 6 (notes/architecture.md). Notes: notes/sync.md (Implementation (osis-host)).
#![forbid(unsafe_code)]

pub mod config;
#[cfg(feature = "driver")]
pub mod driver;
pub mod hub;
pub mod replicate;
#[cfg(feature = "driver")]
pub mod serve;
pub mod store;

pub use config::Config;
#[cfg(feature = "driver")]
pub use driver::{Control, Endpoint, Log, run};
pub use hub::{ConnId, Hub, HubOutput};
pub use replicate::Replicator;
pub use store::{HostStore, DEPOSIT_ENTRY_BYTES, HostPolicy, Swept, Totals};
