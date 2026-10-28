//! Labeling (spec/sync.md §1-§3, §6-§7): which blobs go under which label
//! (closure, entitlement, projection by retention class), wraps, stamps and deposits, the keys a
//! server's head calls for, delete keys, certificate blobs, and the convergence rule.
//! Synchronous functions over the `Engine`; `sync` acts on them.

mod actors;
mod blobs;
mod certs;
pub mod converge;

pub use actors::GroupLabel;
pub use blobs::{Body, HeadKeys, Sealed, delete_item, open_commit, seal_body};
pub(crate) use blobs::BodyCtx;
pub use converge::{Facts, Hold, Why, classify, may_delete};
pub use certs::Parts;
