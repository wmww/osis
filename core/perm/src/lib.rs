//! osis-perm: role validity rules as pure logic over an abstract held set
//! (spec/permissions.md): the walk along stated paths (`paths`: the role timeline, content
//! validity, purge rights), the timeline read per holder (`timeline`), an account's signing chain
//! and epochs. The node implements `HeldSet`, giving held commits as the walk's input.
//! Layer 1 (notes/architecture.md). Design and readings: notes/perm-paths.md.
#![forbid(unsafe_code)]

mod count;
mod pset;
pub mod chain;
pub mod epochs;
pub mod graph;
pub mod paths;
pub mod timeline;
pub mod types;

pub use chain::{Chain, Devices, Rotation};
pub use count::{commits_walked, roles_reached, uncounted};
pub use epochs::{AccountCommit, Epochs, ListPath, Listing, EpochStanding, ThingList};
pub use graph::{Class, Edges, Need, Records, Standing};
pub use osis_base::PurgeBy;
pub use timeline::{At, Changed, HeldSet, Timeline};
pub use types::{Edge, EdgeOp, Frontier, RoleCommit, Point, WriteId, ROLES};
