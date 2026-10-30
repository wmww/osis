//! `LocalPeer`: engines exchanging commits directly, with no labels or servers (the simulator's
//! seed, notes/testing.md, Simulator). Each engine has its own `MemoryBackend`, `ManualClock` and
//! seeded rng; delivery is explicit and order is the caller's. `Package` is plaintext (a direct
//! connection: pairing, or a test of what arrives regardless of keys); `SealedPackage` is what a
//! label carries: each body sealed and wrapped under its reader actor's read secret as node-sync
//! places it, opened only with the read secrets the receiver holds.

use crate::engine::{Config, Engine};
use crate::error::Result;
use crate::events::Event;
use crate::{Ingested, Mutation};
use osis_base::{BlobId, Clock, CommitId, Link, ManualClock, WallMs};
use osis_crypto::SeededRng;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// A commit as it travels: its plaintext blob and the blobs it references.
#[derive(Clone, Debug)]
pub struct Package {
    pub id: CommitId,
    pub bytes: Vec<u8>,
    pub blobs: Vec<(BlobId, Vec<u8>)>,
}

/// A commit as labels carry it (spec/sync.md §1-§3): one sealed blob per body with its wrap
/// under the body's reader actor, and the blobs the commit references (already sealed under
/// link keys). Bodies the sender holds no current read secret for are left out.
#[derive(Clone, Debug)]
pub struct SealedPackage {
    pub id: CommitId,
    pub entries: Vec<SealedEntry>,
    pub blobs: Vec<(BlobId, Vec<u8>)>,
}

/// One sealed body: the reader actor whose secrets open it, the blob and its wrap.
#[derive(Clone, Debug)]
pub struct SealedEntry {
    pub reader: osis_base::Tid,
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub wrap: [u8; osis_crypto::WRAP_LEN],
}

/// One engine with its devices.
pub struct Peer {
    pub engine: Engine,
    pub clock: Arc<ManualClock>,
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    pub events: Receiver<Event>,
}

impl Peer {
    /// A fresh node at wall time `t`.
    pub fn new(seed: u64, t: WallMs) -> Result<Peer> {
        let clock = Arc::new(ManualClock::new(t));
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let c: Arc<dyn Clock> = clock.clone();
        let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        let events = engine.subscribe();
        Ok(Peer { engine, clock, backend, root, events })
    }

    /// Drops the engine and opens it again over the same durable state.
    pub fn restart(&mut self, seed: u64) -> Result<()> {
        let c: Arc<dyn Clock> = self.clock.clone();
        let mut engine = Engine::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        self.events = engine.subscribe();
        self.engine = engine;
        Ok(())
    }

    pub fn drain_events(&self) -> Vec<Event> {
        self.events.try_iter().collect()
    }

    pub fn commit(&mut self, m: Mutation) -> Result<Option<CommitId>> {
        self.engine.commit(m)
    }
}

impl Engine {
    /// A held commit with every blob it references that this node holds (pages, chunks and
    /// header-list trees), for relaying.
    pub fn package(&mut self, id: &CommitId) -> Result<Option<Package>> {
        let Some(bytes) = self.commit_bytes(id)? else { return Ok(None) };
        let mut ids: BTreeSet<BlobId> = BTreeSet::new();
        if let Some(h) = self.header(id) {
            ids.extend(h.chunks.iter().map(|c| c.blob));
            let links: Vec<Link> = osis_commit::ListField::ALL.iter().filter_map(|f| h.links.get(*f).copied()).collect();
            for l in links {
                self.tree_blobs(&l, &h.actor, &mut ids)?;
            }
        }
        let mut blobs = Vec::new();
        for b in ids {
            if let Some(x) = self.blob(&b)? {
                blobs.push((b, x));
            }
        }
        Ok(Some(Package { id: *id, bytes, blobs }))
    }

    /// A held commit sealed as labels carry it (`SealedPackage`): each body framed with a fresh
    /// key (`seal_body`) and wrapped under `wrap_secret` of its reader actor, as node-sync places
    /// it; none under a reader whose read role a known departure leaves uncovered (node-sync's
    /// `read_ok`: `LocalPeer::sealed` rotates first, as its `uncovered` does).
    pub fn seal_package(&mut self, id: &CommitId, rng: &mut dyn osis_crypto::CryptoRngCore) -> Result<Option<SealedPackage>> {
        let Some(pk) = self.package(id)? else { return Ok(None) };
        let mut entries = Vec::new();
        for b in self.bodies(id)? {
            let a = b.reader;
            if !self.core.is_key_actor(&a) && self.run(|tx| crate::rotation::uncovered_roles(tx, &a))?.contains(&osis_base::Role::Read) {
                continue;
            }
            let Some(secret) = self.wrap_secret(&b.reader, Some((id, &b.parts)))? else { continue };
            let s = crate::labeling::seal_body(&b, rng)?;
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
            entries.push(SealedEntry { reader: b.reader, id: s.id, blob: s.blob, wrap });
        }
        Ok(Some(SealedPackage { id: *id, entries, blobs: pk.blobs }))
    }

    /// Opens what it can of a sealed package with the read secrets held (`read_secrets`,
    /// `unwrap_any`, `open_commit`, as node-sync opens a label entry) and ingests each opened
    /// body; the results, empty when nothing opened.
    pub fn open_package(&mut self, pk: &SealedPackage) -> Result<Vec<Ingested>> {
        let mut out = Vec::new();
        for e in &pk.entries {
            let secrets = self.read_secrets(&e.reader);
            let Some((_, key)) = osis_label::unwrap_any(secrets.iter(), &e.id, &e.wrap) else { continue };
            let (pt, _) = crate::labeling::open_commit(&e.blob, &key)?;
            out.push(self.ingest(&pt, pk.blobs.clone())?);
        }
        Ok(out)
    }

    pub(crate) fn tree_blobs(&mut self, root: &Link, actor: &osis_base::Tid, out: &mut BTreeSet<BlobId>) -> Result<()> {
        struct Rec<'e> {
            e: &'e mut Engine,
            seen: Vec<BlobId>,
        }
        impl osis_commit::BlobSource for Rec<'_> {
            fn get(&mut self, link: &Link) -> std::result::Result<Vec<u8>, osis_commit::Error> {
                self.seen.push(link.blob);
                let blob = self.e.blob(&link.blob).map_err(|_| osis_commit::Error::Missing)?.ok_or(osis_commit::Error::Missing)?;
                let (_, pt) = osis_label::open(&blob, &osis_crypto::Secret32::from_bytes(link.key)).map_err(|_| osis_commit::Error::Corrupt)?;
                Ok(pt)
            }
        }
        let Some(dedup) = self.core.dedup(actor) else { return Ok(()) };
        let mut r = Rec { e: self, seen: Vec::new() };
        let _ = osis_commit::read_list(root, &dedup, &mut r, osis_commit::MAX_LIST_BYTES);
        out.extend(r.seen);
        Ok(())
    }
}

/// Engines connected directly.
pub struct LocalPeer {
    pub peers: Vec<Peer>,
    /// Seals `SealedPackage`s (fresh blob keys and salts).
    pub rng: SeededRng,
}

impl LocalPeer {
    /// `n` fresh nodes, seeds derived from `seed`, all at wall time `t`.
    pub fn new(n: usize, seed: u64, t: WallMs) -> Result<LocalPeer> {
        let peers = (0..n).map(|i| Peer::new(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        Ok(LocalPeer::of(peers, seed))
    }

    /// Peers made elsewhere; `seed` seeds the sealing rng.
    pub fn of(peers: Vec<Peer>, seed: u64) -> LocalPeer {
        LocalPeer { peers, rng: SeededRng::from_u64(seed ^ 0x5ea1) }
    }

    pub fn peer(&mut self, i: usize) -> Option<&mut Peer> {
        self.peers.get_mut(i)
    }

    /// Every commit `from` holds (applied), packaged.
    pub fn packages(&mut self, from: usize) -> Result<Vec<Package>> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(Vec::new()) };
        let ids = p.engine.commit_ids();
        let mut out = Vec::new();
        for id in ids {
            if let Some(pk) = p.engine.package(&id)? {
                out.push(pk);
            }
        }
        Ok(out)
    }

    /// Delivers one package to peer `to`.
    pub fn deliver(&mut self, to: usize, pk: &Package) -> Result<Ingested> {
        match self.peers.get_mut(to) {
            Some(p) => p.engine.ingest(&pk.bytes, pk.blobs.clone()),
            None => Ok(Ingested::Duplicate(pk.id)),
        }
    }

    /// Commits `from` holds, sealed (`Engine::seal_package`), after the rotations due before it
    /// encrypts under their reader actors (node-sync's `uncovered`), which go first.
    pub fn sealed(&mut self, from: usize, ids: &[CommitId]) -> Result<Vec<SealedPackage>> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(Vec::new()) };
        let mut readers = BTreeSet::new();
        for id in ids {
            readers.extend(p.engine.bodies(id)?.into_iter().map(|b| b.reader));
        }
        let mut all = Vec::new();
        for a in readers {
            if !p.engine.core.is_key_actor(&a) {
                all.extend(p.engine.ensure_rotated(&a)?.0.commits);
            }
        }
        for id in ids {
            if !all.contains(id) {
                all.push(*id);
            }
        }
        let mut out = Vec::new();
        for id in &all {
            if let Some(pk) = p.engine.seal_package(id, &mut self.rng)? {
                out.push(pk);
            }
        }
        Ok(out)
    }

    /// Delivers sealed packages to `to`, again while any opens (a secret one carries opens
    /// another); the IDs of those none of whose bodies opened.
    pub fn deliver_sealed(&mut self, to: usize, pks: &[SealedPackage]) -> Result<Vec<CommitId>> {
        let Some(p) = self.peers.get_mut(to) else { return Ok(pks.iter().map(|x| x.id).collect()) };
        let mut left: Vec<&SealedPackage> = pks.iter().collect();
        loop {
            let n = left.len();
            let mut next = Vec::new();
            for pk in left {
                if p.engine.open_package(pk)?.is_empty() {
                    next.push(pk);
                }
            }
            left = next;
            if left.len() == n {
                return Ok(left.iter().map(|x| x.id).collect());
            }
        }
    }

    /// Sends everything `from` holds to `to` sealed (`deliver_sealed`); the IDs that did not open.
    pub fn sync_sealed(&mut self, from: usize, to: usize) -> Result<Vec<CommitId>> {
        let ids = self.peers.get_mut(from).map(|p| p.engine.commit_ids()).unwrap_or_default();
        let pks = self.sealed(from, &ids)?;
        self.deliver_sealed(to, &pks)
    }

    /// Sends everything `from` holds to `to` (in `ts` order).
    pub fn sync(&mut self, from: usize, to: usize) -> Result<()> {
        for pk in self.packages(from)? {
            self.deliver(to, &pk)?;
        }
        Ok(())
    }

    /// Syncs every ordered pair until nothing changes (at most `n` rounds).
    pub fn sync_all(&mut self) -> Result<()> {
        let n = self.peers.len();
        for _ in 0..n.max(1) {
            for a in 0..n {
                for b in 0..n {
                    if a != b {
                        self.sync(a, b)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Advances every clock by `ms`.
    pub fn advance(&mut self, ms: u64) {
        for p in &self.peers {
            p.clock.advance(ms);
        }
    }
}
