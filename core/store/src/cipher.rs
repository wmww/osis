//! The node's one store of ciphertext (issues/net-one-peer.md step 4): the blob ciphertexts the
//! engine writes and reads live in a store beside the engine's (the hub's, `osis_host`'s
//! `HostStore`), shared with what that store keeps for others, so a blob is held once. An engine
//! transaction touching blobs locks it (`Ciphertext::begin`) and commits it first: ciphertext is
//! the truth, engine state a cache of it.
//!
//! `BlobArea` is the plain one, a store of blobs only, for an engine with no node (tests).

use crate::{Error, Store, Suspended};
use osis_base::BlobId;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// A store of blob ciphertexts an engine shares (`Engine::open`): a `Mutex` of a `CipherHost`.
pub trait Ciphertext: Send + Sync + Any {
    /// The store locked for one engine transaction. Dropped uncommitted, it undoes nothing the
    /// engine journaled itself (`CipherTx::release` of what it held) but aborts its durable
    /// writes.
    fn begin(&self) -> Box<dyn CipherTx + '_>;

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
    /// Removals of the store's own rows its holder made in it (`CipherTx::finish` applies each):
    /// applied after the engine's store commits, as releases are.
    pub removals: Vec<Vec<u8>>,
}

/// One engine transaction's view of the ciphertext store. Blobs the engine holds stay until it
/// releases them; others (what the store keeps for others) may be read too.
pub trait CipherTx {
    /// Whether the engine holds blob `id`.
    fn held(&mut self, id: &BlobId) -> Result<bool, Error>;
    /// Bytes `offset..offset+len` of blob `id`, held by the engine or not.
    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error>;
    /// The engine holds `id` with bytes `blob` (stored unless held already; `memory`: in memory
    /// only, never on disk); whether it did not before.
    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Result<bool, Error>;
    /// The engine holds `id` no more: its bytes go once nothing else keeps them. `memory`: the
    /// transaction works on memory data, so a durable blob stays.
    fn release(&mut self, id: &BlobId, memory: bool) -> Result<(), Error>;
    /// Applies removal `op` of the store's own rows (`Note::removals`).
    fn finish(&mut self, op: &[u8]) -> Result<(), Error>;
    /// Records, in this transaction, an engine transaction's note (`settle` reads it back after
    /// a crash).
    fn note(&mut self, note: &Note) -> Result<(), Error>;
    /// The engine transactions noted and not cleared (`unnote`).
    fn notes(&mut self) -> Result<Vec<Note>, Error>;
    /// Clears engine transaction `seq`'s note.
    fn unnote(&mut self, seq: u64) -> Result<(), Error>;
    /// Makes this transaction's writes durable.
    fn commit(&mut self) -> Result<(), Error>;
    /// Tests only: every key the store's tree yields (`Store::forensic_keys`).
    #[doc(hidden)]
    fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error>;
    /// The store itself, for a holder that knows its type (node sync and the hub's store).
    fn any(&mut self) -> &mut dyn Any;
}

/// A store that can be an engine's ciphertext store, behind a `Mutex` (`Ciphertext`): the
/// `CipherTx` operations on the store locked, `abort` dropping what was written since the last
/// commit.
pub trait CipherHost: Send + Any {
    /// The store is locked for one engine transaction: its writes until `commit` or `abort` are
    /// that transaction's.
    fn begin(&mut self) {}
    fn held(&mut self, id: &BlobId) -> Result<bool, Error>;
    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error>;
    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Result<bool, Error>;
    fn release(&mut self, id: &BlobId, memory: bool) -> Result<(), Error>;
    /// Applies a removal of the store's own rows its holder deferred (`CipherTx::finish`): none
    /// in a store of blobs only.
    fn finish(&mut self, op: &[u8]) -> Result<(), Error> {
        let _ = op;
        Err(Error::Corrupt("a removal in a store of blobs only"))
    }
    /// Runs `f` in the store's open transaction (the engine's notes live in its local records).
    fn local(&mut self, f: &mut dyn FnMut(&mut crate::Transaction<'_>) -> Result<(), Error>) -> Result<(), Error>;
    fn commit(&mut self) -> Result<(), Error>;
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

fn decode_note(k: &[u8], v: &[u8]) -> Option<Note> {
    let u64_at = |b: &[u8], i: usize| b.get(i..i + 8).and_then(|x| <[u8; 8]>::try_from(x).ok()).map(u64::from_be_bytes);
    let seq = u64_at(k, NOTE.len())?;
    let (h, r) = (usize::try_from(u64_at(v, 0)?).ok()?, usize::try_from(u64_at(v, 8)?).ok()?);
    let ids_end = h.checked_add(r)?.checked_mul(32)?.checked_add(16)?;
    let ids: Vec<BlobId> = v.get(16..ids_end)?.as_chunks::<32>().0.iter().map(|c| BlobId(*c)).collect();
    let (holds, releases) = (ids.get(..h)?.to_vec(), ids.get(h..)?.to_vec());
    let mut removals = Vec::new();
    let mut rest = v.get(ids_end..)?;
    while !rest.is_empty() {
        let n = usize::try_from(u32::from_be_bytes(rest.get(..4)?.try_into().ok()?)).ok()?;
        removals.push(rest.get(4..4 + n)?.to_vec());
        rest = rest.get(4 + n..)?;
    }
    Some(Note { seq, holds, releases, removals })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Tests only: `store`'s copy inside a world copy (`osis_base::copying::remap`), so every holder
/// of one store (a node's engine, sync engine and hub) shares one copy.
#[doc(hidden)]
pub fn test_copy_shared<T: CipherHost>(store: &Arc<Mutex<T>>, clock: Arc<dyn osis_base::Clock>) -> Result<Arc<Mutex<T>>, Error> {
    let copy = lock(store).test_copy(clock)?;
    Ok(osis_base::copying::remap(store, move |_| Mutex::new(copy)))
}

impl<T: CipherHost> Ciphertext for Mutex<T> {
    fn begin(&self) -> Box<dyn CipherTx + '_> {
        let mut g = lock(self);
        g.begin();
        Box::new(HostTx { g, done: false })
    }

    fn test_copy(self: Arc<Self>, clock: Arc<dyn osis_base::Clock>) -> Result<Arc<dyn Ciphertext>, Error> {
        let copy: Arc<Mutex<T>> = test_copy_shared(&self, clock)?;
        Ok(copy)
    }
}

struct HostTx<'a, T: CipherHost> {
    g: MutexGuard<'a, T>,
    done: bool,
}

impl<T: CipherHost> CipherTx for HostTx<'_, T> {
    fn held(&mut self, id: &BlobId) -> Result<bool, Error> {
        self.g.held(id)
    }
    fn read(&mut self, id: &BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
        self.g.read(id, offset, len)
    }
    fn hold(&mut self, id: &BlobId, blob: Vec<u8>, memory: bool) -> Result<bool, Error> {
        self.g.hold(id, blob, memory)
    }
    fn release(&mut self, id: &BlobId, memory: bool) -> Result<(), Error> {
        self.g.release(id, memory)
    }
    fn finish(&mut self, op: &[u8]) -> Result<(), Error> {
        self.g.finish(op)
    }
    fn note(&mut self, n: &Note) -> Result<(), Error> {
        let mut v = Vec::with_capacity(16 + 32 * (n.holds.len() + n.releases.len()));
        v.extend_from_slice(&(n.holds.len() as u64).to_be_bytes());
        v.extend_from_slice(&(n.releases.len() as u64).to_be_bytes());
        for id in n.holds.iter().chain(&n.releases) {
            v.extend_from_slice(&id.0);
        }
        for op in &n.removals {
            v.extend_from_slice(&(op.len() as u32).to_be_bytes());
            v.extend_from_slice(op);
        }
        let k = [NOTE, &n.seq.to_be_bytes()].concat();
        self.g.local(&mut |t| t.put_local(&k, &v, crate::Shred::No))
    }
    fn notes(&mut self) -> Result<Vec<Note>, Error> {
        let mut rows = Vec::new();
        self.g.local(&mut |t| {
            rows = t.scan_local(NOTE, &[], usize::MAX)?;
            Ok(())
        })?;
        rows.into_iter().map(|(k, v)| decode_note(&k, &v).ok_or(Error::Corrupt("blob note"))).collect()
    }
    fn unnote(&mut self, seq: u64) -> Result<(), Error> {
        let k = [NOTE, &seq.to_be_bytes()].concat();
        self.g.local(&mut |t| t.remove_local(&k, crate::Shred::No).map(drop))
    }
    fn commit(&mut self) -> Result<(), Error> {
        self.done = true;
        self.g.commit()
    }
    fn forensic_keys(&mut self) -> Result<Vec<[u8; 32]>, Error> {
        self.g.forensic_keys()
    }
    fn any(&mut self) -> &mut dyn Any {
        &mut *self.g
    }
}

impl<T: CipherHost> Drop for HostTx<'_, T> {
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

impl CipherHost for BlobArea {
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
        let r = store.resume(s, &mut **rng).commit();
        if r.is_err() {
            let _ = store.reopen();
        }
        r
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
