//! osis-perm: role validity rules as pure logic over an abstract held set
//! (spec/permissions.md): the walk along stated paths (`paths`: the role timeline, content
//! validity, purge rights) and the timeline read per holder (`timeline`). The node implements `HeldSet`, giving held commits as the walk's input.
//! Layer 1 (notes/architecture.md). Design and readings: notes/perm-paths.md.
#![forbid(unsafe_code)]

mod count;
pub mod graph;
pub mod paths;
pub mod timeline;
pub mod types;

pub use count::{commits_walked, roles_reached, uncounted};
pub use graph::{Edges, Need, Records};
pub use osis_base::PurgeBy;
pub use timeline::{At, Changed, Held, HeldSet, Timeline};
pub use types::{Grant, GrantOp, Frontier, RoleCommit, Point, WriteId};
