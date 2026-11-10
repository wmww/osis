//! Brute-force reference model of what a node holding a set of commits reads and keeps: apply
//! and waits, validity (actors, invites, required retention, acting-for), undo,
//! purge, expiry and history modes (spec/commits.md §4-§6, spec/crdt.md §4.6-§4.8,
//! spec/permissions.md §5, §6). Slow and small on purpose; every query recomputes from scratch.
//! Values are crdt-model fragments: crdt-model is the one model of values (join, prune, read,
//! un-merge, strip, death, covering). README.md: input format; AMBIGUITIES.md: the choices the spec left; ASSUMPTIONS.md: what is cut.
pub mod edits;
pub mod fetch;
pub mod gen;
pub mod lifetimes;
pub mod model;
pub mod roles;
pub mod thing_history;
pub mod types;
pub mod undo;

pub use model::{act, cover, creation, evaluate, join, kept_until, signal_kept, snapshot_state, timeline, DeltaRef, Dots, DropWhy, Fate, KeepWhy, LeftoverWhy, Outcome, PartRef};
pub use types::*;
