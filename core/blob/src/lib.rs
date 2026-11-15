//! osis-blob: what every node knows of blobs and sync IDs, read or not: blob framing and
//! wraps, chunk trees and blob-backed pages, large values, registration steps, claim sets, entry
//! boxes, stamp/deposit/delete signatures, delete-key checks, inbox blobs, the `sync.0` types,
//! addresses, links, bundles (spec/sync.md, spec/wire.md
//! §5, §6, §8-§10, §12, spec/crypto.md §5-§7). Pure functions; randomness injected.
//! Layer 4 (notes/architecture.md). Notes: notes/sync-protocol.md (osis-blob); notes/data-model.md (Large values).
#![forbid(unsafe_code)]

pub mod addr;
pub mod auth;
pub mod blob;
pub mod bundle;
mod cbor;
pub mod chunks;
mod error;
pub mod inbox;
pub mod sync_ids;
pub mod link;
pub mod step;
pub mod tree;

pub use addr::{Address, address_from_text, address_to_text};
pub use auth::{DeleteItem, delete_digest, entry_digest, key_for_levels, sign_deposit, sign_stamp, verify_deposit, verify_stamp};
pub use blob::{Class, Group, Level, Prefix, blob_id, check_size, frame, frame_under, open, clear_prefix, unwrap_any, wrap_order};
pub use chunks::{LargeParams, chunk_value, read_value, string_head};
pub use bundle::{BundleEvent, BundleReader, BundleWriter, Importer, Record};
pub use error::Error;
pub use inbox::{BoxedThing, BoxesPayload, DialHint, GrantSig, HolderKeys, Inbox, InboxPayload, InboxRest, InboxThing, MAX_DIAL_URLS, StrandedNotice, open_inbox_blob, open_inbox_item, seal_boxes_payload, seal_inbox_blob, seal_stranded_notice};
pub use sync_ids::{StepRecord, SyncEntry, SyncIds, parse_record, step_record, sync_steps};
pub use link::{Peer, ShareLink};
pub use step::{ClaimSet, Parent, Reader, Step, StepId, StepKeys, genesis_sync_id, open_entry_box, path_to, register, register_with, verify_path};
pub use tree::{BlobFetch, BlobReader, BlobSink, BlobStore, BlobWriter, Framing, Reuse, HashSink, LinkSource, MemoryBlobs, TreeReader, TreeSink, TreeWriter, Written, linked_prefix_inputs, read_tree, write_tree};
