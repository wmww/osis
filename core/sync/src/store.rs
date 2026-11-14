//! The store per sync ID (spec/sync-ids.md §5-§6, spec/sync-streams.md §3).
//!
//! State: entries, tombstones, blob bytes once per node, paths (steps, claim sets), the node log
//! and cursors, caps and deposit budgets, ephemeral entries in memory. It is the engine's
//! ciphertext door (`osis_store::CipherHost`): `Store` is a cheap handle over one locked store,
//! held by the engine and by `Cx`; the engine locks it only inside its own transactions, sync
//! only between engine calls, so one step never holds both. Every row change stamps, so memos
//! may read it. Expiry and caps giving way run in its `settle`. Depends on osis-store and
//! osis-label crypto; of the engine only the caps record. Decrypts nothing.
//!
//! Not built: every call below. Until it is, the handle is an `osis_store::BlobArea` (blob bytes
//! only) so an engine can run on it.

use crate::types::{Cursor, Entry, Error, RecordId, Result};
use osis_base::{BlobId, SyncId, WallMs};
use osis_engine::Engine;
use osis_engine::sync::Path;
use osis_label::{ClaimSet, DeleteItem, Step};
use osis_proto::Code;
use osis_store::LogRead;
use osis_store::{BlobArea, Ciphertext};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Why an entry left (its tombstone's kind).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombKind {
    /// A Delete it verified.
    Deleted,
    /// Its expiry passed.
    Expired,
    /// This node's own judgement.
    Dropped,
}

/// A Deposit item (spec/wire.md §11.2): the store owner's shape until osis-proto's `msg` holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositItem {
    pub entry: Entry,
}

/// A Behind item (spec/sync-ids.md §6 Behind): the store owner's shape until osis-proto's `msg`
/// holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BehindItem {
    pub step: Step,
}

/// The answer to a Behind item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Code(Code),
}

/// The members a log read covers.
pub type Members = BTreeMap<SyncId, crate::opens::Member>;

/// One node's store.
#[derive(Clone)]
pub struct Store {
    blobs: Arc<Mutex<BlobArea>>,
}

impl Store {
    /// A store over `backend` and `root`, created there if none is.
    pub fn open(backend: Box<dyn osis_store::Backend>, root: Box<dyn osis_store::RootStorage>, rng: Box<dyn osis_crypto::NodeRng>) -> Result<Store> {
        Ok(Store { blobs: BlobArea::open(backend, root, rng)? })
    }

    /// The engine's ciphertext door (its `Engine::create`/`open` argument).
    pub fn cipher(&self) -> Arc<dyn Ciphertext> {
        self.blobs.clone()
    }

    pub fn entry(&self, s: &SyncId, b: &BlobId) -> Option<Entry> {
        let _ = (s, b);
        None
    }

    /// Stamped reads (memo-safe).
    pub fn entries(&self, s: &SyncId) -> impl Iterator<Item = Entry> + use<> {
        let _ = s;
        std::iter::empty()
    }

    /// Logs an own entry (`Added` in the node log).
    pub fn log(&mut self, s: &SyncId, e: Entry, bytes: Option<Vec<u8>>) -> Result<()> {
        let _ = (s, e, bytes);
        Err(Error::NotBuilt("store::log"))
    }

    /// Drops an entry by own judgement; tombstone.
    pub fn drop_entry(&mut self, s: &SyncId, b: &BlobId, kind: TombKind) -> Result<()> {
        let _ = (s, b, kind);
        Err(Error::NotBuilt("store::drop_entry"))
    }

    /// Kept unread pulling a stamped entry.
    pub fn take_stamped(&mut self, s: &SyncId, e: Entry, from: Option<RecordId>) -> Result<Code> {
        let _ = (s, e, from);
        Err(Error::NotBuilt("store::take_stamped"))
    }

    pub fn take_deposit(&mut self, s: &SyncId, d: &DepositItem, from: Option<RecordId>) -> Result<Code> {
        let _ = (s, d, from);
        Err(Error::NotBuilt("store::take_deposit"))
    }

    pub fn take_delete(&mut self, s: &SyncId, d: &DeleteItem, open_by_store_credential: bool) -> Result<Vec<Code>> {
        let _ = (s, d, open_by_store_credential);
        Err(Error::NotBuilt("store::take_delete"))
    }

    pub fn take_register(&mut self, s: &SyncId, step: Step, claims: Option<ClaimSet>) -> Result<Code> {
        let _ = (s, step, claims);
        Err(Error::NotBuilt("store::take_register"))
    }

    pub fn behind(&self, s: &SyncId, item: &BehindItem) -> Result<Answer> {
        let _ = (s, item);
        Err(Error::NotBuilt("store::behind"))
    }

    /// A kept-unread S's registered path.
    pub fn path(&self, s: &SyncId) -> Option<Arc<Path>> {
        let _ = s;
        None
    }

    pub fn read_log(&self, members: &Members, from: Option<&Cursor>, max: usize) -> Result<LogRead> {
        let _ = (members, from, max);
        Err(Error::NotBuilt("store::read_log"))
    }

    /// Leaving S: keys and wraps erased.
    pub fn shred(&mut self, s: &SyncId) -> Result<()> {
        let _ = s;
        Err(Error::NotBuilt("store::shred"))
    }

    /// Expiry and caps giving way; whether anything acted.
    pub fn settle(&mut self, engine: &mut Engine, now: WallMs) -> Result<bool> {
        let _ = (engine, now);
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }

    /// Tests only: this store's copy inside a world copy (`osis_base::copying`), the one the
    /// engine's copy holds.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<Store> {
        Ok(Store { blobs: osis_store::test_copy_shared(&self.blobs, clock)? })
    }
}
