//! osis-label: what clients and blind nodes share about blobs and labels: blob framing and
//! wraps, chunk trees and blob-backed pages, labels, registration steps, claim sets, entry boxes,
//! open/stamp/deposit/delete signatures, delete-token checks, inbox blobs, signal envelopes, the
//! `/label` types, addresses, links and recovery cards, bundles (spec/sync.md, spec/wire.md
//! §5, §6, §8-§10, §12, spec/crypto.md §5-§7). Pure functions; randomness injected.
//! Layer 4 (notes/architecture.md). Plans: plans/label.md, plans/large-values.md.
#![forbid(unsafe_code)]

pub mod blob;
mod error;
pub mod step;
pub mod tree;

pub use blob::{Level, Prefix, blob_id, check_size, frame, open, server_prefix, unwrap_any};
pub use error::Error;
pub use step::{ClaimSet, EntryKey, EntryTo, Parent, Reader, Step, StepId, StepKeys, genesis_label, match_secret, open_entry_box, path_to, register, verify_path};
pub use tree::{BlobFetch, BlobReader, BlobSink, BlobWriter, Framing, HashSink, LinkSource, MemoryBlobs, TreeReader, TreeSink, TreeWriter, Written, read_tree, write_tree};
