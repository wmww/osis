//! osis-commit: commit headers and blobs, kinds, retention, delete keys, signatures, the
//! builder, delta verification, sections, prefix groups and the purge rewrite, chunk trees (`tree`: the one
//! writer and reader, osis-blob re-exports it) and linked header lists
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
mod sync_cut;
mod keys;
mod lists;
mod path;
pub mod tree;
mod validate;
mod verify;

#[cfg(test)]
mod tests;

pub use blob::{CommitBlob, Contents, Envelope, Opened, OpenedSection, Part, Section, SectionSeal, Sigs, regenerate, seal_commit, seal_commit_keyed, seal_header_only, seal_header_only_keyed};
pub use builder::{AspectWrite, Built, CommitBuilder, SplitWrite};
pub use groups::{COMMIT_PAST_BLOB, blob_expiry, prefix_expiry, prefix_groups, rewrite};
#[cfg(test)]
use groups::blob_bound;
pub use lists::{BlobSink, BlobSource, MemoryBlobs, read_list};
#[cfg(test)]
use lists::write_list;
pub use osis_base::format::MAX_LIST_BYTES;
pub use error::Error;
pub use header::{AspectEntry, PIECED, aspect_position, aspect_range, aspects_on, DeleteKey, EphClass, FOREVER, Form, Header, frontier_ids, put_frontier, Kind, Links, ListField, PurgeItem, Signed, verify_signature};
pub use sync_cut::SyncOnlyCut;
pub use keys::{Prefix, Secrets, delete_keys};
pub use path::{COMMITMENT_LEN, ENTRY_CLASSES, Marks, Path, Paths, Split, ThingPath, entry_len, key_commitment, marks_bytes, path_key};
pub use verify::{Decoded, box_holder, delta_ctx, is_piece, read_part, read_part_whole, stream_part, verify_blob, verify_part, writer_ctx};
