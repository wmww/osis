//! osis-node: the node. Engine (identity, clock, writing, reads), apply (receiving, pending and
//! parking, atomic apply, validity and un-merge, receipt record), retention (deaths, bounds,
//! expiry, purge, snapshots), undo, engine events; `labeling` and `sync` (the sync
//! engine), `flows` and `rotation` (membership). Modules: notes/node.md.
//! Layer 7 (notes/architecture.md).
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

pub use apply::{Creation, Ingested, Reason};
pub use engine::{Config, Engine, Mutation};
pub use error::{Error, Result};
pub use events::{Cause, Diagnostic, DiagnosticKind, Event, Origin};
pub use identity::Identity;
