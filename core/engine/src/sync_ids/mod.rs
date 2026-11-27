//! Sync IDs (spec/sync-judgement.md §1): which blobs go under which sync ID (closure,
//! entitlement), sections per independent, wraps, stamps and deposits, the keys a peer's head
//! calls for, delete keys, certificate blobs. Synchronous functions over the `Engine`.

pub(crate) mod actors;
mod blobs;
pub(crate) use blobs::RoleKeyEpochs;
mod certs;
pub(crate) mod entries;
pub(crate) use certs::{Cut, current_keys_in, judged_valid};
pub(crate) mod opened;
pub(crate) mod steps;
pub(crate) mod unread;

pub use blobs::{Body, HeadKeys, OpenedBlob, Sealed, fetch_order, frame_envelope};
pub use blobs::BodyCtx;
pub use certs::{Certs, Parts};
