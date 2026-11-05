//! Brute-force reference model of what a node holding a set of commits reads and keeps: apply
//! and waits, validity (actors, invites, roster snapshots, required retention, acting-for), undo,
//! purge, expiry and keep bounds (spec/commits.md §4-§6, spec/crdt.md §4.6-§4.8,
//! spec/permissions.md §5, §7). Slow and small on purpose; every query recomputes from scratch.
//! README.md: input format; AMBIGUITIES.md: the choices the spec left; ASSUMPTIONS.md: what is cut.
pub mod crdt;
pub mod gen;
pub mod model;
pub mod roles;
pub mod types;
pub mod undo;

pub use crdt::Read;
pub use model::{act, evaluate, timeline, DeltaRef, DropWhy, Fate, KeepWhy, LeftoverWhy, Outcome, PartRef};
pub use types::*;
