//! osis-commit: commit headers and blobs, kinds, retention, delete tokens, signatures, the
//! builder, delta verification, projection and purge rewrite, header-list chunk trees
//! (spec/commits.md, spec/wire.md §4, §6).
//! Layer 3 (notes/architecture.md). Plan: plans/commit.md.
#![forbid(unsafe_code)]

mod cbor;
mod error;
mod header;

#[cfg(test)]
mod tests;

pub use error::Error;
pub use header::{AspectEntry, ChunkEntry, FOREVER, Form, Header, Kind, Links, ListField, MAX_SCHEMAS, Origin, PurgeItem, Token, verify_signature};
