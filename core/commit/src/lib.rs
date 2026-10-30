//! osis-commit: commit headers and blobs, kinds, retention, delete keys, signatures, the
//! builder, delta verification, projection and purge rewrite, chunk trees (`tree`: the one
//! writer and reader, osis-label re-exports it) and linked header lists
//! (spec/commits.md, spec/wire.md §4, §6).
//! Layer 3 (notes/architecture.md). Notes: notes/crdt.md (Implementation (`osis-commit`)).
#![forbid(unsafe_code)]

mod blob;
mod builder;
mod cbor;
mod error;
mod header;
mod project;
pub mod retention;
mod keys;
mod lists;
pub mod tree;
mod validate;
mod verify;

#[cfg(test)]
mod tests;

pub use blob::{CommitBlob, Part};
pub use builder::{AspectWrite, Built, CommitBuilder};
pub use project::{Projection, blob_expiry, prefix_inputs, project, project_resolved, rewrite, strict_subset};
pub use lists::{BlobSink, BlobSource, MAX_LIST_BYTES, MemoryBlobs, read_list, write_list};
pub use error::Error;
pub use header::{AspectEntry, ChunkEntry, DeleteKey, EphClass, FOREVER, Form, Header, Kind, Links, ListField, MAX_SCHEMAS, Origin, PurgeItem, verify_signature};
pub use keys::{Prefix, Secrets, delete_keys};
pub use verify::{Decoded, delta_ctx, verify_blob, verify_part, writer_ctx};
