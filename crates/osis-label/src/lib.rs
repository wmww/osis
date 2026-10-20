//! osis-label: what clients and blind nodes share about blobs and labels: blob framing and
//! wraps, chunk trees and blob-backed pages, labels, registration steps, claim sets, entry boxes,
//! open/stamp/deposit/delete signatures, delete-token checks, inbox blobs, signal envelopes, the
//! `/label` types, addresses, links and recovery cards, bundles (spec/sync.md, spec/wire.md
//! §5, §6, §8-§10, §12, spec/crypto.md §5-§7). Pure functions; randomness injected.
//! Layer 4 (notes/architecture.md). Notes: notes/sync.md (Implementation (osis-label)); plans/large-values.md.
#![forbid(unsafe_code)]

pub mod addr;
pub mod auth;
pub mod blob;
pub mod bundle;
pub mod chunks;
mod error;
pub mod inbox;
pub mod labels;
pub mod link;
pub mod signal;
pub mod step;
pub mod tree;

pub use addr::{Address, address_from_text, address_from_value, address_to_text};
pub use auth::{DeleteItem, OpenOutcome, Proof, PublishAuth, PublishKey, entry_digest, evaluate_open, key_for_level, sign_deposit, sign_stamp, verify_deposit, verify_stamp};
pub use blob::{Level, Prefix, blob_id, check_size, frame, open, server_prefix, unwrap_any};
pub use chunks::{LargeParams, LargeReader, StringReader, ValueWriter, chunk_value, read_value};
pub use bundle::{BundleEvent, BundleReader, BundleWriter, Importer, Record};
pub use error::Error;
pub use inbox::{InboxPayload, InboxThing, open_inbox_blob, seal_inbox_blob};
pub use labels::{Label, Labels, StepRecord, label_path, label_steps, parse_record, step_record, tips};
pub use link::{Peer, RecoveryCard, ShareLink};
pub use signal::{MAX_SIGNAL, SignalBody, open_signal, seal_signal};
pub use step::{ClaimSet, EntryKey, EntryTo, Parent, Reader, Step, StepId, StepKeys, genesis_label, match_secret, open_entry_box, path_to, register, verify_path};
pub use tree::{BlobFetch, BlobReader, BlobSink, BlobStore, BlobWriter, Framing, Reuse, HashSink, LinkSource, MemoryBlobs, TreeReader, TreeSink, TreeWriter, Written, read_tree, write_tree};
