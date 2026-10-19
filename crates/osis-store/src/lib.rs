//! osis-store: encrypted local store (notes/local-store.md): `Backend` (opaque transactional KV
//! plus blob area; `MemoryBackend`, redb behind `file-backend`) and `Store` (encrypted units on a
//! key tree rooted in erasable `RootStorage`). Layer 2 (notes/architecture.md). Plan: plans/store.md.
#![forbid(unsafe_code)]

mod backend;
#[cfg(feature = "file-backend")]
mod file;
mod memory;

pub use backend::{Backend, BackendError, Op, WriteBatch, prefix_end};
#[cfg(feature = "file-backend")]
pub use file::RedbBackend;
pub use memory::{Fault, FaultyBackend, Faults, MemoryBackend};
