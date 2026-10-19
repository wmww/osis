//! osis-core: values and their canonical CBOR, tids, ids, format constants, chunker, hashing,
//! `Clock`, `impl_error!` (spec/data-model.md, spec/versioning.md §1). Synchronous, no I/O.
//! Layer 0 (notes/architecture.md). Plan: plans/workspace.md, done and folded into notes/architecture.md.
#![forbid(unsafe_code)]

pub mod cbor;
pub mod chunker;
mod error;
pub mod format;
pub mod hash;
mod ids;
mod time;
mod value;

pub use cbor::{CanonicalBytes, DecodeError, Limits, decode, decode_prefix, encode};
pub use chunker::{ChunkParams, Chunker};
pub use error::{Classified, ErrorClass};
pub use ids::{Ak, AkError, BlobId, CommitId, CreationRecord, LabelId, Link, MAX_AK_BYTES, Role, SchemaId, Tid, TidParseError};
pub use time::{Clock, ManualClock, SystemClock, Ts, WallMs};
pub use value::{Float, Unknown, Value, is_known_tag};
