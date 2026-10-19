//! osis-perm: membership validity rules as pure logic over an abstract held set
//! (spec/permissions.md): the layer-1 membership timeline with epoch starts and tenure ledgers,
//! layer-2 content validity, roster snapshot production, certificates, purge rights and move
//! resolution. The node implements `HeldSet` and adapts commits into the records of `types`.
//! Layer 1 (notes/architecture.md). Plan: plans/perm.md.
#![forbid(unsafe_code)]

pub mod graph;
pub mod held;
pub mod timeline;
pub mod types;
mod walk;

pub use graph::{Class, Edges, Owner, Owners, Standing};
pub use held::{HeldSet, MemoryHeldSet};
pub use timeline::{At, Timeline};
pub use types::{Dots, Edge, EdgeKey, EdgeOp, Frontier, MembershipCommit, Point, RosterSnapshot, Tenure, WriteId, MEMBERS};
pub use walk::{Applied, Attr, Demotion};
