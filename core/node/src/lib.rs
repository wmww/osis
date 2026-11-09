//! osis-node: the node. `sync` (the sans-I/O sync engine and its tokio driver) over osis-engine,
//! whose modules it re-exports at the same paths; hosting is osis-host, below it. Modules:
//! notes/engine.md.
//! Layer 8 (notes/architecture.md).
#![forbid(unsafe_code)]

pub mod sync;
pub use sync::proofs::ACCOUNT_RECORD;

pub use osis_engine::{apply, costs, engine, ephemeral, error, events, flows, identity, labeling, local_peer, retention, rotation, sides, undo};
pub use osis_engine::{Cause, Config, Creation, Diagnostic, DiagnosticKind, Engine, Error, Event, CommitChange, Identity, Ingested, Mutation, Origin, Reason, Result, Written};
