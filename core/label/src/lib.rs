//! osis-label: what clients and hosts share about blobs and labels: blob framing and
//! wraps, chunk trees and blob-backed pages, labels, registration steps, claim sets, entry boxes,
//! open/stamp/deposit/delete signatures, delete-key checks, inbox blobs, the
//! `label.0` types, addresses, links, bundles (spec/sync.md, spec/wire.md
//! §5, §6, §8-§10, §12, spec/crypto.md §5-§7). Pure functions; randomness injected.
//! Layer 4 (notes/architecture.md). Notes: notes/sync-protocol.md (osis-label); notes/data-model.md (Large values).
#![forbid(unsafe_code)]

pub mod addr;
pub mod auth;
pub mod blob;
pub mod bundle;
mod cbor;
pub mod chunks;
mod error;
pub mod inbox;
pub mod labels;
pub mod link;
pub mod step;
pub mod tree;

pub use addr::{Address, address_from_text, address_from_value, address_to_text};
pub use auth::{DeleteItem, OpenOutcome, PathIndex, Proof, by_from_value, delete_digest, entry_digest, evaluate_open, key_for_levels, sign_deposit, sign_stamp, verify_stamp};
pub use blob::{Class, Group, Level, MAX_GROUPS, Prefix, blob_id, check_size, frame, open, host_prefix, prefix_bytes, unwrap_any, wrap_order};
pub use chunks::{LargeParams, LargeReader, StringReader, ValueWriter, chunk_value, read_value};
pub use bundle::{BundleEvent, BundleReader, BundleWriter, Importer, Record};
pub use error::Error;
pub use inbox::{InboxLabel, InboxPayload, InboxThing, open_inbox_blob, seal_inbox_blob};
pub use labels::{Label, Labels, StepRecord, label_steps, parse_record, step_record, tips};
pub use link::{Peer, ShareLink};
pub use step::{ClaimSet, Parent, Reader, Step, StepId, StepKeys, genesis_label, match_secret, open_entry_box, path_to, register, register_with, verify_path};
pub use tree::{BlobFetch, BlobReader, BlobSink, BlobStore, BlobWriter, Framing, Reuse, HashSink, LinkSource, MemoryBlobs, TreeReader, TreeSink, TreeWriter, Written, read_tree, write_tree};
