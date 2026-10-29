//! osis-node: the node. `sync` (the sans-I/O sync engine and its tokio driver) over osis-engine,
//! whose modules it re-exports at the same paths. Modules: notes/node.md.
//! Layer 8 (notes/architecture.md).
#![forbid(unsafe_code)]

pub mod sync;

pub use osis_engine::{apply, costs, engine, ephemeral, error, events, flows, identity, labeling, local_peer, moves, retention, rotation, undo};
pub use osis_engine::{Cause, ChangeId, Config, Creation, Diagnostic, DiagnosticKind, Engine, EphemeralId, Error, Event, Identity, Ingested, Mutation, Origin, Reason, Result, Written};
