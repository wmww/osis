//! Brute-force reference model of what a node holding a set of commits reads and keeps: apply
//! and waits, validity (actors, invites, acting-for), undo, purge, expiry and the thing's
//! history setting (spec/commits.md §4-§7, spec/crdt.md §4.6-§4.8,
//! spec/permissions.md §5, §6). Slow and small on purpose; every query recomputes from scratch.
//! Values are crdt-model fragments: crdt-model is the one model of values (join, prune, read,
//! un-merge, strip, death, covering). README.md: input format; AMBIGUITIES.md: the choices the spec left; ASSUMPTIONS.md: what is cut.
pub mod closure;
pub mod connlived;
pub mod edits;
pub mod evidence;
pub mod external;
pub mod fetch;
pub mod freed;
pub mod gen;
pub mod model;
pub mod overlap;
pub mod roles;
pub mod strip;
pub mod thing_history;
pub mod types;
pub mod undo;

pub use model::{act, at_quiet, cover, creation, evaluate, evaluate_with, join, judged, judged_with, promotes, kept_until, snapshot_state, timeline, Dots, DropWhy, Fate, KeepWhy, LeftoverWhy, Outcome, PartRef};
pub use types::*;
