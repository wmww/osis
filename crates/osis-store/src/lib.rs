//! osis-store: encrypted local store (notes/local-store.md): `Backend` (opaque transactional KV
//! plus blob area; `MemoryBackend`, redb behind `file-backend`) and `Store` (encrypted units on a
//! key tree rooted in erasable `RootStorage`). Layer 2 (notes/architecture.md). Plan: plans/store.md.
#![forbid(unsafe_code)]

mod backend;
mod btree;
mod codec;
mod error;
#[cfg(feature = "file-backend")]
mod file;
mod memory;
mod pager;
mod root;
mod store;

pub use backend::{Backend, BackendError, Op, WriteBatch, prefix_end};
#[cfg(feature = "file-backend")]
pub use file::RedbBackend;
pub use error::Error;
pub use memory::{Fault, FaultyBackend, Faults, MemoryBackend};
pub use pager::{StoreConfig, forensic_node_keys, forensic_open};
#[cfg(feature = "file-backend")]
pub use root::FileRoot;
pub use root::{MemoryRoot, RootRecord, RootStorage, RootTier};
pub use store::{AspectUnit, Deaths, PendingKind, Shred, Store, Table, Transaction};
