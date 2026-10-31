//! osis-base: values and their canonical CBOR, tids, ids, format constants, chunker, hashing, hex,
//! base64url, `Clock`, `impl_error!` (spec/data-model.md, spec/versioning.md §1). Synchronous, no I/O.
//! Layer 0 (notes/architecture.md). Surface: notes/architecture.md §7.
#![forbid(unsafe_code)]

pub mod base64url;
pub mod cbor;
pub mod chunker;
mod error;
pub mod format;
pub mod hash;
pub mod hex;
// test support (panics on bad test settings; only tests call it)
#[doc(hidden)]
#[allow(clippy::panic, clippy::expect_used)]
pub mod testenv;
mod ids;
mod time;
mod value;

pub use cbor::{CanonicalBytes, DecodeError, Limits, Place, decode, decode_prefix, encode, item_prefix, visit_items};
pub use chunker::{ChunkParams, Chunker, PageCutter};
pub use error::{Classified, ErrorClass};
pub use ids::{Ak, AkError, BlobId, CommitId, CreationRecord, LabelId, Link, Role, SchemaId, Tid, TidParseError};
pub use time::{Clock, ManualClock, SystemClock, Ts, WallMs};
pub use value::{Float, Unknown, Value, is_known_tag};
