//! osis-engine: the node's engine. Engine (identity, clock, writing, reads), apply (receiving,
//! pending and parking, apply, validity and un-merge, receipts), retention (when
//! replaced, bounds, expiry, purge, snapshots), undo, engine events, `labeling`, `flows` and `rotation`
//! (role changes), `local_peer` (engines exchanging commits directly). The sync engine above it is
//! osis-node. Modules: notes/engine.md. Layer 7 (notes/architecture.md).
#![forbid(unsafe_code)]

pub mod apply;
pub mod costs;
pub mod engine;
pub mod ephemeral;
pub mod error;
pub mod events;
pub mod flows;
pub mod identity;
pub mod labeling;
pub mod local_peer;
pub mod retention;
pub mod rotation;
pub mod sides;
pub mod undo;
#[cfg(test)]
mod tests_copy;

pub use apply::{Creation, Ingested, Reason};
pub use engine::{Config, Engine, Mutation};
pub use error::{Error, Result};
pub use ephemeral::Written;
pub use events::{Cause, Diagnostic, DiagnosticKind, Event, CommitChange, Origin};
pub use identity::Identity;
pub use sides::{AccountDisputeInfo, DisputeInfo, Side};
