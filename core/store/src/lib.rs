//! osis-store: encrypted local store (notes/local-store.md): `Backend` (opaque transactional KV
//! plus blob area; `MemoryBackend`, `RedbBackend` over redb) and `Store` (encrypted units on a
//! key tree rooted in erasable `RootStorage`). Layer 2 (notes/architecture.md). Notes: notes/local-store.md.
#![forbid(unsafe_code)]

mod backend;
mod btree;
mod codec;
mod error;
mod file;
mod memory;
mod overlay;
mod pager;
mod root;
mod store;

pub use backend::{Backend, BackendError, KeyValue, Op, WriteBatch, prefix_end};
pub use backend::restrict_to_owner;
pub use file::RedbBackend;
pub use error::Error;
pub use memory::{Fault, FaultyBackend, Faults, MemoryBackend};
pub use pager::{StoreConfig, forensic_node_keys, forensic_open};
pub use root::FileRoot;
pub use root::{MemoryRoot, RootRecord, RootStorage, RootTier};
pub use store::{AspectUnit, Deaths, PendingKind, Shred, Store, Table, Transaction};
