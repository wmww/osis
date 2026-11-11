//! osis-commit: commit headers and blobs, kinds, retention, delete keys, signatures, the
//! builder, delta verification, sections, prefix groups and the purge rewrite, chunk trees (`tree`: the one
//! writer and reader, osis-label re-exports it) and linked header lists
//! (spec/commits.md, spec/wire.md §4, §6).
//! Layer 3 (notes/architecture.md). Notes: notes/crdt.md (Implementation (`osis-commit`)).
#![forbid(unsafe_code)]

mod blob;
mod builder;
mod cbor;
mod error;
mod header;
mod groups;
pub mod record_blob;
pub mod retention;
mod keys;
mod lists;
pub mod thing_list;
pub mod tree;
mod validate;
mod verify;

#[cfg(test)]
mod tests;

pub use blob::{CommitBlob, Envelope, Opened, Part, Section, Sigs, seal_commit};
pub use builder::{AccountSigner, AspectWrite, Built, CommitBuilder};
pub use groups::{COMMIT_PAST_BLOB, blob_bound, blob_expiry, prefix_expiry, prefix_groups, rewrite, strict_subset};
pub use lists::{BlobSink, BlobSource, MemoryBlobs, read_list, write_list};
pub use osis_base::format::MAX_LIST_BYTES;
pub use error::Error;
pub use header::{AspectEntry, ChunkEntry, DeleteKey, EphClass, FIRST_EPOCH, FOREVER, Form, Header, Kind, Links, ListField, PurgeItem, RotationHeader, frontier_value, verify_merge, verify_signature};
pub use keys::{Prefix, Secrets, delete_keys};
pub use verify::{Decoded, check_entry_keys, delta_ctx, read_part, read_part_whole, stream_part, verify_blob, verify_part, writer_ctx};
