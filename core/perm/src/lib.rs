//! osis-perm: role validity rules as pure logic over an abstract held set
//! (spec/permissions.md): the layer-1 role timeline, layer-2 content validity, an account's signing chain, certificates
//! and purge rights. The node implements `HeldSet` and adapts commits into the records of `types`.
//! Layer 1 (notes/architecture.md). Design and readings: notes/perm-impl.md.
#![forbid(unsafe_code)]

mod cache;
mod pset;
pub mod cert;
pub mod chain;
pub mod content;
pub mod epochs;
pub mod graph;
pub mod held;
pub mod incremental;
pub mod purge;
pub mod scope;
pub mod timeline;
pub mod trust;
pub mod types;
mod walk;

pub use cert::{verify, Certificates};
#[doc(hidden)]
pub use cert::chain_steps;
pub use chain::{Chain, Devices, Rotation};
pub use epochs::{AccountCommit, Epochs, ListPath, Listing, EpochStanding, ThingList};
pub use content::{Addendum, AddendumEntry, Validity, Vouching};
pub use graph::{Class, Edges, Records, Standing};
pub use held::{HeldSet, MemoryHeldSet};
pub use incremental::{Changed, SaveDone, Saves, Timelines};
pub use osis_base::PurgeBy;
pub use scope::DemotionScope;
pub use timeline::{At, EdgeEnd, Timeline};
pub use trust::{Detected, Detection, Dispute, Trust, DETECT_MAX};
pub use types::{Edge, EdgeOp, Frontier, RoleCommit, Point, WriteId, ROLES};
pub use walk::{Applied, Attr, Demotion, Fall};
#[doc(hidden)]
pub use walk::{commits_walked, entries_moved, roles_reached, uncounted};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use walk::force_shadow_guard;
