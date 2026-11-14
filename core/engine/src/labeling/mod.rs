//! Labeling (spec/sync-judgement.md §1): which blobs go under which label (closure,
//! entitlement), sections per reader actor, wraps, stamps and deposits, the keys a host's head
//! calls for, delete keys, certificate blobs. Synchronous functions over the `Engine`.

pub(crate) mod actors;
mod blobs;
mod certs;
pub(crate) use certs::judged_valid;
mod judge;
mod proofs;

pub use blobs::{Body, HeadKeys, OpenedBlob, Sealed, delete_item, delete_item_by_level, delete_key, fetch_order, frame_envelope, seal_plain};
pub use blobs::BodyCtx;
pub use certs::{Certs, Parts};
pub use judge::{Judge, Judgment};
