//! osis-store: encrypted local store (notes/local-store.md): `Backend` (opaque transactional KV
//! plus blob area; `MemoryBackend`, `RedbBackend` over redb) and `Store` (encrypted units on a
//! key tree rooted in erasable `RootStorage`). Layer 2 (notes/architecture.md). Notes: notes/local-store.md.
#![forbid(unsafe_code)]

mod backend;
mod btree;
mod changed;
mod cipher;
mod codec;
mod error;
mod file;
mod forensic;
mod memory;
mod nodelog;
mod overlay;
mod record;
mod pager;
mod root;
mod store;

pub use backend::{Backend, BackendError, KeyValue, Op, WriteBatch, prefix_end, restrict_to_owner};
pub use file::RedbBackend;
pub use cipher::{BlobArea, CipherHost, CipherTx, Ciphertext, Note, test_copy_shared};
pub use error::Error;
pub use nodelog::{CURSOR_LEN, INCARNATIONS_KEPT, LogRead, LoggedEvent, NodeEvent};
pub use memory::{Fault, Faults, Io, MemoryBackend, Synced};
pub use forensic::{Ciphers, Evidence, Recovered, Section, Source, attack};
pub use pager::StoreConfig;
pub use record::{At, Filter, Member, RECORD_BUDGET, Record, RecordId};
pub use root::{FileRoot, MemoryRoot, RootRecord, RootStorage};
pub use store::{AspectUnit, Pending, PendingKind, Shred, Store, Suspended, Table, Transaction, Writes};
