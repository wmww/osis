//! osis-sync: sync (spec/sync.md and its area files): the node's connections, its store per sync
//! ID, and the judgement over them, as one sans-IO step (`Node::handle`) whose outputs `apply`
//! alone carries out through a `Links`. Sync reads the engine through `osis_engine::sync` only.
//! Modules, one per area, each owning its state (notes/sync.md): `session`, `opens`,
//! `store`, `read`, `unread`, `leave`, `streams`, `inbox`, `status`, `driver`; the types they share in
//! `types`. Layer 8 (notes/architecture.md).
#![forbid(unsafe_code)]

pub mod driver;
pub mod inbox;
pub mod leave;
pub mod opens;
pub mod read;
pub mod session;
pub mod set;
pub mod status;
pub mod store;
pub mod streams;
pub mod types;
pub mod unread;

pub use driver::{Links, Node, PortEvent, apply};
#[cfg(feature = "driver")]
pub use driver::links::TransportLinks;
pub use store::Store;
pub use types::{ConnId, Error, Input, NodeKey, Out, Policy, Result, SyncConfig};
