//! The node's one store of ciphertext (notes/sync-store.md): the blob ciphertexts the
//! engine writes and reads live in a store beside the engine's, shared with what that store keeps
//! for others, so a blob is held once. An engine
//! transaction touching blobs locks it (`Ciphertext::begin`) and commits it first: ciphertext is
//! the truth, engine state a cache of it.
//!
//! `BlobArea` is the plain one, a store of blobs only, for an engine with no node (tests).

use crate::backend::lock;
use crate::codec::{R, W};
use crate::store::tail;
use crate::{Error, Store, Suspended};
use osis_base::BlobId;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// A store of blob ciphertexts an engine shares (`Engine::open`): a `Mutex` of a `CipherStore`.
pub trait Ciphertext: Send + Sync + Any {
    /// The store locked for one engine transaction. Dropped uncommitted, it undoes nothing the
    /// engine journaled itself (`CipherStore::release` of what it held) but aborts its durable
    /// writes.
    fn begin(&self) -> CipherTx<'_>;

    /// Tests only: a copy of this store inside a world copy (`osis_base::copying::remap`: every
    /// holder of this handle gets the same copy), on `clock` where the store keeps time.
    #[doc(hidden)]
    fn test_copy(self: Arc<Self>, clock: Arc<dyn osis_base::Clock>) -> Result<Arc<dyn Ciphertext>, Error>;
}

/// An engine transaction's note (`CipherTx::note`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Note {
    pub seq: u64,
    /// Durable blobs it held.
    pub holds: Vec<BlobId>,
    /// Durable blobs it released.
    pub releases: Vec<BlobId>,
    /// Blobs of the commits it forgot (`CipherStore::forgot` applies each): applied after the
    /// engine's store commits, as releases are.
    pub forgot: Vec<BlobId>,
    /// Blobs the engine makes again from then on, with their lengths (`CipherStore::made`):
    /// applied after the engine's store commits, as releases are.
    pub made: Vec<(BlobId, u64)>,
    /// Blobs the engine makes again no more, with their lengths (`CipherStore::unmade`): applied
    /// in the transaction, as holds are; one the engine's store never committed is made again.
    pub unmade: Vec<(BlobId, u64)>,
}

/// A store that can be an engine's ciphertext store, behind a `Mutex` (`Ciphertext`), locked
/// for one engine transaction at a time (`CipherTx`). Blobs the engine holds stay until it
/// releases them; others (what the store keeps for others) may be read too.
pub trait CipherStore: Send + Any {
    /// The store is locked for one engine transaction: its writes until `commit` or `abort` are
    /// that transaction's.
    fn begin(&mut self) {}
    /// Whether the engine holds blob `id`.
    fn held(&mut self, id: &BlobId) -> Result<bool, Error>;
    /// Bytes `offset..offset+len` of blob `id`, held by the engine or not.
    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error>;
    /// Blob `id`'s byte length, held by the engine or not, without reading it.
    fn len(&mut self, id: &BlobId) -> Result<Option<u64>, Error>;
    /// The engine holds `id` with bytes `blob` (stored unless held already; `memory`: in memory
    /// only, never on disk); whether it did not before.
    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Result<bool, Error>;
    /// The engine holds `id` no more: its bytes go once nothing else keeps them. `memory`: the
    /// transaction works on memory data, so a durable blob stays.
    fn release(&mut self, id: &BlobId, memory: bool) -> Result<(), Error>;
    /// The engine forgot blob `id` with its commit (`Note::forgot`): what the store logged of it
    /// as the engine's own goes. A store of blobs only logs nothing.
    fn forgot(&mut self, id: &BlobId) -> Result<(), Error> {
        let _ = id;
        Ok(())
    }
    /// The engine forgot blob `id`'s commit as never received (spec/sync-judgement.md §3 Dropped
    /// bodies): what the store keeps out of it as the engine's own drop ends, in this transaction.
    /// A store of blobs only keeps nothing out.
    fn unreceived(&mut self, id: &BlobId) -> Result<(), Error> {
        let _ = id;
        Ok(())
    }
    /// Sync ID `s` is to be pulled anew from every source, durably in this transaction: a strong
    /// in its sync unit reaches a thing whose record the engine does not hold (spec/sync-judgement.md
    /// §3 Dropped bodies). A store of blobs only syncs nothing.
    fn refetch(&mut self, s: &osis_base::SyncId) -> Result<(), Error> {
        let _ = s;
        Ok(())
    }
    /// The engine makes blob `id` (`len` bytes long) again whenever asked (a commit blob from its
    /// seal, notes/slim-design.md B): the store keeps no bytes of it but those the engine holds,
    /// and counts it held. Applied after the engine's store commits. A store of blobs only keeps
    /// its bytes.
    fn made(&mut self, id: &BlobId, len: u64, memory: bool) -> Result<(), Error> {
        let _ = (id, len, memory);
        Ok(())
    }
    /// The engine makes blob `id` again no more: `bytes`, made a last time, are kept where
    /// anything else names it (`None`: the blob is gone here, its entries held without bytes).
    /// In this transaction, before the engine's store commits.
    fn unmade(&mut self, id: &BlobId, bytes: Option<Vec<u8>>, memory: bool) -> Result<(), Error> {
        let _ = (id, bytes, memory);
        Ok(())
    }
    /// Runs `f` in the store's open transaction (the engine's notes live in its local records).
    fn local(&mut self, f: &mut dyn FnMut(&mut crate::Transaction<'_>) -> Result<(), Error>) -> Result<(), Error>;
    /// Makes this transaction's writes durable.
    fn commit(&mut self) -> Result<(), Error>;
    /// Drops what was written since the last commit.
    fn abort(&mut self);
    /// Tests only: every key the store's tree yields, its open writes committed first.
    #[doc(hidden)]
    fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error>;
    /// Tests only: an exact copy, on `clock` where it keeps time.
    #[doc(hidden)]
    fn test_copy(&self, clock: Arc<dyn osis_base::Clock>) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Local record prefix of the engine transactions' notes (`CipherTx::note`).
const NOTE: &[u8] = b"cipher/note/";

/// A note's row value: hold, release, forgotten, made and unmade counts, then their IDs in that
/// order, each made and unmade one followed by its length.
fn encode_note(n: &Note) -> Vec<u8> {
    let mut w = W::new();
    for c in [n.holds.len(), n.releases.len(), n.forgot.len(), n.made.len(), n.unmade.len()] {
        w.u64(c as u64);
    }
    for id in n.holds.iter().chain(&n.releases).chain(&n.forgot) {
        w.raw(&id.0);
    }
    for (id, len) in n.made.iter().chain(&n.unmade) {
        w.raw(&id.0).u64(*len);
    }
    w.take()
}

/// A note from its local record (key `NOTE || seq`).
fn decode_note(k: &[u8], v: &[u8]) -> Result<Note, Error> {
    let mut r = R::new(v);
    let (h, n, f, m, u) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?);
    let ids = |r: &mut R, n: u64| (0..n).map(|_| r.array().map(BlobId)).collect::<Result<Vec<_>, Error>>();
    let sized = |r: &mut R, n: u64| (0..n).map(|_| Ok((BlobId(r.array()?), r.u64()?))).collect::<Result<Vec<_>, Error>>();
    let (holds, releases, forgot) = (ids(&mut r, h)?, ids(&mut r, n)?, ids(&mut r, f)?);
    let (made, unmade) = (sized(&mut r, m)?, sized(&mut r, u)?);
    if !r.is_empty() {
        return Err(Error::Corrupt("cipher note"));
    }
    Ok(Note { seq: u64::from_be_bytes(tail(k)?), holds, releases, forgot, made, unmade })
}

/// Tests only: `store`'s copy inside a world copy (`osis_base::copying::remap`), so every holder
/// of one store (a node's engine and its sync) shares one copy.
#[doc(hidden)]
pub fn test_copy_shared<T: CipherStore>(store: &Arc<Mutex<T>>, clock: Arc<dyn osis_base::Clock>) -> Result<Arc<Mutex<T>>, Error> {
    if let Some(c) = osis_base::copying::found(store) {
        return Ok(c);
    }
    let copy = lock(store).test_copy(clock)?;
    Ok(osis_base::copying::remap(store, move |_| Mutex::new(copy)))
}

impl<T: CipherStore> Ciphertext for Mutex<T> {
    fn begin(&self) -> CipherTx<'_> {
        let m: &Mutex<dyn CipherStore> = self;
        let mut g = lock(m);
        g.begin();
        CipherTx { g, done: false }
    }

    fn test_copy(self: Arc<Self>, clock: Arc<dyn osis_base::Clock>) -> Result<Arc<dyn Ciphertext>, Error> {
        let copy: Arc<Mutex<T>> = test_copy_shared(&self, clock)?;
        Ok(copy)
    }
}

/// One engine transaction's hold on the ciphertext store (`Ciphertext::begin`): the store's
/// operations, plus the transaction's notes. Dropped uncommitted, it aborts the store's writes.
pub struct CipherTx<'a> {
    g: MutexGuard<'a, dyn CipherStore>,
    done: bool,
}

impl std::ops::Deref for CipherTx<'_> {
    type Target = dyn CipherStore;
    fn deref(&self) -> &Self::Target {
        &*self.g
    }
}

impl std::ops::DerefMut for CipherTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.g
    }
}

impl CipherTx<'_> {
    /// Records, in this transaction, an engine transaction's note (`settle` reads it back after
    /// a crash).
    pub fn note(&mut self, n: &Note) -> Result<(), Error> {
        let (k, v) = ([NOTE, &n.seq.to_be_bytes()].concat(), encode_note(n));
        self.g.local(&mut |t| t.put_local(&k, &v, crate::Shred::No))
    }
    /// The engine transactions noted and not cleared (`unnote`).
    pub fn notes(&mut self) -> Result<Vec<Note>, Error> {
        let mut rows = Vec::new();
        self.g.local(&mut |t| {
            rows = t.scan_local(NOTE, &[], usize::MAX)?;
            Ok(())
        })?;
        rows.into_iter().map(|(k, v)| decode_note(&k, &v)).collect()
    }
    /// Clears engine transaction `seq`'s note.
    pub fn unnote(&mut self, seq: u64) -> Result<(), Error> {
        let k = [NOTE, &seq.to_be_bytes()].concat();
        self.g.local(&mut |t| t.remove_local(&k, crate::Shred::No).map(drop))
    }
    /// Makes this transaction's writes durable.
    pub fn commit(&mut self) -> Result<(), Error> {
        self.done = true;
        self.g.commit()
    }
}

impl Drop for CipherTx<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.g.abort();
        }
    }
}

/// A store of blob ciphertexts only, the engine their one holder: an engine with no node.
pub struct BlobArea {
    store: Store,
    rng: Box<dyn osis_crypto::NodeRng>,
    open: Option<Suspended>,
    mem: HashMap<BlobId, Vec<u8>>,
}

impl BlobArea {
    pub fn new(store: Store, rng: Box<dyn osis_crypto::NodeRng>) -> Arc<Mutex<BlobArea>> {
        Arc::new(Mutex::new(BlobArea { store, rng, open: None, mem: HashMap::new() }))
    }

    /// The one over `backend` and `root`, created there if none is.
    pub fn open(backend: Box<dyn crate::Backend>, root: Box<dyn crate::RootStorage>, mut rng: Box<dyn osis_crypto::NodeRng>) -> Result<Arc<Mutex<BlobArea>>, Error> {
        let store = Store::open_or_create(backend, root, crate::StoreConfig::default(), &mut *rng)?;
        Ok(BlobArea::new(store, rng))
    }

    /// An empty one in memory.
    pub fn memory() -> Result<Arc<Mutex<BlobArea>>, Error> {
        let mut rng = osis_crypto::OsRng;
        let store = Store::create(Box::new(crate::MemoryBackend::new()), Box::new(crate::MemoryRoot::new()), crate::StoreConfig::default(), &mut rng)?;
        Ok(BlobArea::new(store, Box::new(rng)))
    }

    fn run<R>(&mut self, f: impl FnOnce(&mut crate::Transaction<'_>) -> Result<R, Error>) -> Result<R, Error> {
        let BlobArea { store, rng, open, .. } = self;
        let mut t = match open.take() {
            Some(s) => store.resume(s, &mut **rng),
            None => store.transaction(&mut **rng)?,
        };
        let r = f(&mut t);
        *open = Some(t.suspend()?);
        r
    }
}

impl CipherStore for BlobArea {
    fn local(&mut self, f: &mut dyn FnMut(&mut crate::Transaction<'_>) -> Result<(), Error>) -> Result<(), Error> {
        self.run(|t| f(t))
    }

    fn held(&mut self, id: &BlobId) -> Result<bool, Error> {
        Ok(self.read(id, 0, 0)?.is_some())
    }

    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
        if let Some(b) = self.mem.get(id) {
            return Ok(Some(crate::backend::blob_slice(b, offset, len)));
        }
        self.run(|t| t.read_blob(id, offset, len))
    }

    fn len(&mut self, id: &BlobId) -> Result<Option<u64>, Error> {
        if let Some(b) = self.mem.get(id) {
            return Ok(Some(b.len() as u64));
        }
        self.run(|t| t.blob_len(id))
    }

    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Result<bool, Error> {
        if self.held(id)? {
            return Ok(false);
        }
        if memory {
            self.mem.insert(*id, blob);
        } else {
            self.run(|t| t.put_blob(id, blob))?;
        }
        Ok(true)
    }

    fn release(&mut self, id: &BlobId, memory: bool) -> Result<(), Error> {
        if self.mem.remove(id).is_none() && !memory {
            self.run(|t| {
                t.delete_blob(id);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), Error> {
        let BlobArea { store, rng, open, .. } = self;
        let Some(s) = open.take() else { return Ok(()) };
        store.resume(s, &mut **rng).commit()
    }

    fn abort(&mut self) {
        // a suspended transaction dropped aborts
        self.open = None;
    }

    fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        self.commit()?;
        self.store.forensic_keys()
    }

    fn test_copy(&self, _clock: Arc<dyn osis_base::Clock>) -> Result<BlobArea, Error> {
        Ok(BlobArea { store: self.store.test_copy()?, rng: self.rng.test_copy(), open: self.open.as_ref().map(Suspended::test_copy), mem: self.mem.clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A note's row is the bytes the hand-written encoder gave (counts, held, released,
    /// forgotten IDs, made and unmade IDs with lengths), and decodes back. spec: none (a local
    /// record).
    #[test]
    fn note_row_bytes() {
        let n = Note { seq: 7, holds: vec![BlobId([1; 32])], releases: vec![BlobId([2; 32]), BlobId([3; 32])], forgot: vec![BlobId([4; 32])], made: vec![(BlobId([5; 32]), 9)], unmade: vec![(BlobId([6; 32]), 10)] };
        let counts: Vec<u8> = [1u64, 2, 1, 1, 1].iter().flat_map(|c| c.to_be_bytes()).collect();
        let want = [&counts[..], &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], &9u64.to_be_bytes(), &[6; 32], &10u64.to_be_bytes()].concat();
        let v = encode_note(&n);
        assert_eq!(v, want);
        let k = [NOTE, &7u64.to_be_bytes()].concat();
        assert_eq!(decode_note(&k, &v).unwrap(), n);
        assert!(decode_note(&k, &v[..v.len() - 1]).is_err());
    }
}
