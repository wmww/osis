//! osis-commit: commit headers and blobs, kinds, retention, delete tokens, signatures, the
//! builder, delta verification, projection and purge rewrite, header-list chunk trees
//! (spec/commits.md, spec/wire.md §4, §6).
//! Layer 3 (notes/architecture.md). Plan: plans/commit.md.
#![forbid(unsafe_code)]

mod blob;
mod builder;
mod cbor;
mod error;
mod header;
mod project;
pub mod retention;
mod tokens;
mod tree;
mod validate;
mod verify;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_validate;
#[cfg(test)]
mod tests_verify;
#[cfg(test)]
mod tests_build;
#[cfg(test)]
mod tests_prop;
#[cfg(test)]
mod tests_review;

pub use blob::{CommitBlob, Part};
pub use builder::{AspectWrite, Built, CommitBuilder};
pub use project::{Projection, prefix_inputs, project, rewrite, strict_subset};
pub use tree::{BlobSink, BlobSource, MAX_LIST_BYTES, MemoryBlobs, read_tree, write_tree};
pub use error::Error;
pub use header::{AspectEntry, ChunkEntry, FOREVER, Form, Header, Kind, Links, ListField, MAX_SCHEMAS, Origin, PurgeItem, Token, verify_signature};
pub use tokens::{Prefix, Secrets, TokenSecret, token_secrets};
pub use verify::{Decoded, delta_ctx, verify_blob, verify_part, writer_ctx};
