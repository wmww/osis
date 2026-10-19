//! osis-node: the node. Engine (identity, clock, writing, reads), apply (receiving, pending and
//! parking, atomic apply, validity and un-merge, receipt record), retention (deaths, bounds,
//! expiry, purge, snapshots), undo, engine events; `labeling`, `sync`, `flows` are filled by
//! plans/node-sync.md and plans/membership-flows.md. Module ownership: notes/node.md.
//! Layer 7 (notes/architecture.md). Plans: node-core (done; notes/node.md), plans/node-sync.md,
//! plans/membership-flows.md.
#![forbid(unsafe_code)]

pub mod apply;
pub mod engine;
mod error;
pub mod events;
pub mod flows;
pub mod identity;
pub mod labeling;
pub mod local_peer;
pub mod moves;
pub mod retention;
pub mod rotation;
pub mod sync;
pub mod undo;

pub use apply::{Ingested, Reason};
pub use engine::{Config, Engine, Mutation};
pub use error::{Error, Result};
pub use events::{Cause, Diagnostic, DiagnosticKind, Event, Origin};
pub use identity::Identity;
