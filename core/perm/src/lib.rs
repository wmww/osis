//! osis-perm: membership validity rules as pure logic over an abstract held set
//! (spec/permissions.md): the layer-1 membership timeline with epoch starts and tenure ledgers,
//! layer-2 content validity, roster snapshot production, certificates, purge rights and move
//! resolution. The node implements `HeldSet` and adapts commits into the records of `types`.
//! Layer 1 (notes/architecture.md). Design and readings: notes/permissions.md, Implementation.
#![forbid(unsafe_code)]

mod cache;
pub mod cert;
pub mod content;
pub mod graph;
pub mod held;
pub mod incremental;
pub mod moves;
pub mod purge;
pub mod roster;
pub mod scope;
pub mod timeline;
pub mod types;
mod walk;

pub use cert::{project, verify, Certificates};
pub use content::{overlapping, Range, Validity};
pub use graph::{Class, Edges, Owner, Owners, Standing};
pub use held::{HeldSet, MemoryHeldSet};
pub use incremental::{Changed, SaveDone, Saves, Timelines};
pub use moves::{MoveIndex, RESOLUTION_HOPS};
pub use purge::PurgeBy;
pub use roster::RosterState;
pub use scope::DemotionScope;
pub use timeline::{At, Timeline};
pub use types::{Dots, Edge, EdgeOp, Frontier, MembershipCommit, Point, RosterSnapshot, Tenure, WriteId, MEMBERS};
pub use walk::{Applied, Attr, Demotion, Fall};
