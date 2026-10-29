//! osis-engine: the node's engine. Engine (identity, clock, writing, reads), apply (receiving,
//! pending and parking, atomic apply, validity and un-merge, receipt record), retention (deaths,
//! bounds, expiry, purge, snapshots), undo, engine events, `labeling`, `flows` and `rotation`
//! (membership), `local_peer` (engines exchanging commits directly). The sync engine above it is
//! osis-node. Modules: notes/node.md. Layer 7 (notes/architecture.md).
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
pub mod moves;
pub mod retention;
pub mod rotation;
pub mod undo;

pub use apply::{Creation, Ingested, Reason};
pub use engine::{Config, Engine, Mutation};
pub use error::{Error, Result};
pub use ephemeral::Written;
pub use events::{Cause, ChangeId, Diagnostic, DiagnosticKind, EphemeralId, Event, Origin};
pub use identity::Identity;
