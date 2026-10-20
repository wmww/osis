//! `LocalPeer`: engines exchanging commit bytes directly, with no labels, servers or
//! encryption under labels (the simulator's seed, plans/sim.md). Each engine has its own
//! `MemoryBackend`, `ManualClock` and seeded rng; delivery is explicit and order is the caller's.

use crate::engine::{Config, Engine};
use crate::error::Result;
use crate::events::Event;
use crate::{Ingested, Mutation};
use osis_core::{BlobId, Clock, CommitId, Link, ManualClock, WallMs};
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

    fn tree_blobs(&mut self, root: &Link, actor: &osis_core::Tid, out: &mut BTreeSet<BlobId>) -> Result<()> {
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
}

impl LocalPeer {
    /// `n` fresh nodes, seeds derived from `seed`, all at wall time `t`.
    pub fn new(n: usize, seed: u64, t: WallMs) -> Result<LocalPeer> {
        let peers = (0..n).map(|i| Peer::new(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        Ok(LocalPeer { peers })
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
