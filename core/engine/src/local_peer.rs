//! `LocalPeer`: engines exchanging commits directly, with no labels or hosts (the simulator's
//! seed, notes/testing.md, Simulator). Each engine has its own `MemoryBackend`, `ManualClock` and
//! seeded rng; delivery is explicit and order is the caller's. `Package` is plaintext (a direct
//! connection: pairing, or a test of what arrives regardless of keys); `SealedPackage` is what a
//! label carries: each body sealed and wrapped under its reader actor's read secret as node-sync
//! places it, opened only with the read secrets the receiver holds.

use crate::engine::{Config, Engine, ReadPoint};
use crate::error::Result;
use crate::events::Event;
use crate::{Ingested, Mutation};
use osis_base::{BlobId, Classified, Clock, CommitId, Link, ManualClock, Tid, WallMs};
use osis_commit::CommitBlob;
use osis_crypto::SeededRng;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::{BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// A commit as it travels: its plaintext blob and the blobs it references.
#[derive(Clone, Debug)]
pub struct Package {
    pub id: CommitId,
    pub bytes: Vec<u8>,
    pub blobs: Vec<(BlobId, Vec<u8>)>,
    /// A rotation's list blob (its thing lists held here), as labels carry it beside it.
    pub lists: Vec<Vec<u8>>,
}

/// A commit as labels carry it (spec/sync.md §1-§3): its one sealed blob with a wrap under
/// each reader actor among its parts, and the blobs the commit references (already sealed
/// under link keys). Readers the sender holds no current read secret for get no wrap.
#[derive(Clone, Debug)]
pub struct SealedPackage {
    pub id: CommitId,
    pub entries: Vec<SealedEntry>,
    pub blobs: Vec<(BlobId, Vec<u8>)>,
}

/// The sealed blob with its wraps: per reader actor among the commit's parts, the wrap under
/// that actor's read secret (as a label of it would carry it).
#[derive(Clone, Debug)]
pub struct SealedEntry {
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub wraps: Vec<(osis_base::Tid, [u8; osis_crypto::WRAP_LEN])>,
}

/// One node: an engine with its clock, store and root.
pub struct Peer {
    pub engine: Engine,
    pub clock: Arc<ManualClock>,
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    pub events: Receiver<Event>,
    /// Opens so far: mixed into each restart's rng seed, so no two opens of one store draw
    /// the same session nonce (spec/crdt.md §2.1) however a test seeds them.
    pub restarts: u64,
    /// What the engine threw out (`receive`).
    pub discarded: Vec<Discarded>,
    /// How many packages the engine threw out so far.
    pub discards: u64,
}

/// A package this peer's engine threw out, as hosts keep it: fetched again as node-sync does
/// (`Peer::receive`).
#[derive(Clone)]
pub struct Discarded {
    bytes: Vec<u8>,
    blobs: Vec<(BlobId, Vec<u8>)>,
    commit: CommitId,
    /// `None`: a part of an applied commit (`Wakes::woken`).
    awaits: Option<Tid>,
}

impl Peer {
    /// Receives a package and stands in for node-sync's fetches: what the engine threw out is
    /// ingested again when `Wakes` names what it awaits. The test's `Engine::ingest` is what
    /// node-sync calls; only the fetching is played here.
    pub fn receive(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>) -> Result<Ingested> {
        self.receive_with(bytes, blobs, &[])
    }

    /// `receive` with the list blobs that came with it (`Engine::ingest_with_lists`).
    pub fn receive_with(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>, lists: &[Vec<u8>]) -> Result<Ingested> {
        let r = self.engine.ingest_with_lists(bytes, blobs.clone(), None, lists);
        if let (Err(e), Ok(b)) = (&r, CommitBlob::decode(bytes)) && e.class() == osis_base::ErrorClass::BadInput {
            self.engine.forget_awaiting(&b.id())?;
        }
        self.note(bytes, &blobs, &r);
        self.wake()?;
        r
    }

    /// Runs what is due (`Engine::tick`) and, as node-sync does after it, fetches again what
    /// the engine threw out that it woke: a commit parked for drift that runs carries the record
    /// a thrown-out one awaits.
    pub fn tick(&mut self) -> Result<()> {
        self.engine.tick()?;
        self.wake()
    }

    /// `Engine::reexamine`, then fetches again what it woke (`tick`).
    pub fn reexamine(&mut self) -> Result<()> {
        self.wake()
    }

    fn note(&mut self, bytes: &[u8], blobs: &[(BlobId, Vec<u8>)], r: &Result<Ingested>) {
        let Ok(b) = CommitBlob::decode(bytes) else { return };
        let id = b.id();
        self.discarded.retain(|d| d.bytes != bytes);
        let applied = self.engine.core.ix.commits.get(&id);
        let awaits = match r {
            Ok(Ingested::Awaits(_, crate::Reason::MissingChain(t) | crate::Reason::UnknownCreated(t))) if applied.is_none() => Some(*t),
            Ok(_) if applied.is_some_and(|m| b.parts.iter().any(|p| m.missing.contains(&p.ai))) => None,
            _ => return,
        };
        self.discards += 1;
        self.discarded.push(Discarded { bytes: bytes.to_vec(), blobs: blobs.to_vec(), commit: id, awaits });
    }

    fn wake(&mut self) -> Result<()> {
        loop {
            self.engine.reexamine()?;
            let w = self.engine.take_wakes();
            let core = &self.engine.core;
            let due = |d: &Discarded| {
                w.reopen_awaits || w.reread.contains(&d.commit) || match &d.awaits {
                    Some(t) => w.records.contains(t) || (w.moved && core.exists(t)),
                    None => w.woken.contains(&d.commit),
                }
            };
            let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.discarded).into_iter().partition(|d| due(d));
            self.discarded = later;
            if now.is_empty() {
                return Ok(());
            }
            for d in now {
                let r = self.engine.ingest(&d.bytes, d.blobs.clone());
                if matches!(&r, Err(e) if e.class() == osis_base::ErrorClass::BadInput) {
                    self.engine.forget_awaiting(&d.commit)?;
                }
                self.note(&d.bytes, &d.blobs, &r);
            }
        }
    }

    /// A fresh node at wall time `t`, its own account's only node.
    pub fn new(seed: u64, t: WallMs) -> Result<Peer> {
        let mut p = Peer::new_bare(seed, t)?;
        p.engine.create_account(&[])?;
        p.engine.take_wakes();
        Ok(p)
    }

    /// A fresh node at wall time `t` that has joined no account yet.
    pub fn new_bare(seed: u64, t: WallMs) -> Result<Peer> {
        let clock = Arc::new(ManualClock::new(t));
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let c: Arc<dyn Clock> = clock.clone();
        let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        engine.take_wakes();
        let events = engine.subscribe();
        Ok(Peer { engine, clock, backend, root, events, restarts: 0, discarded: Vec::new(), discards: 0 })
    }

    /// Drops the engine and opens it again over the same durable state.
    pub fn restart(&mut self, seed: u64) -> Result<()> {
        let c: Arc<dyn Clock> = self.clock.clone();
        self.restarts += 1;
        let seed = seed.wrapping_add(self.restarts.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut engine = Engine::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        self.events = engine.subscribe();
        engine.take_wakes();
        self.engine = engine;
        self.fetch_discarded()
    }

    /// An independent copy of this node as it is now, opened over a copy of its durable state on
    /// a clock of its own: one setup, then several paths from it.
    pub fn fork(&self, seed: u64) -> Result<Peer> {
        let clock = Arc::new(ManualClock::new(self.clock.now_wall_ms()));
        let (backend, root) = (self.backend.copy(), self.root.copy());
        let c: Arc<dyn Clock> = clock.clone();
        let seed = seed.wrapping_add((self.restarts + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut engine = Engine::open(Box::new(backend.clone()), Box::new(root.clone()), Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        let events = engine.subscribe();
        engine.take_wakes();
        let mut p = Peer { engine, clock, backend, root, events, restarts: self.restarts + 1, discarded: self.discarded.clone(), discards: self.discards };
        p.fetch_discarded()?;
        Ok(p)
    }

    /// What node-sync does at a start: every awaiting entry is fetched again.
    pub fn fetch_discarded(&mut self) -> Result<()> {
        self.engine.take_wakes();
        for d in std::mem::take(&mut self.discarded) {
            self.receive(&d.bytes, d.blobs)?;
        }
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
        let lists = self.list_blob(id, None)?.into_iter().collect();
        Ok(Some(Package { id: *id, bytes, blobs, lists }))
    }

    /// A held commit sealed as labels carry it (`SealedPackage`): its blob framed with a fresh
    /// key (`seal`, one section per reader actor) and wrapped under `wrap_secret` of each reader
    /// actor, as node-sync places it; no wrap for a reader whose read role a known departure
    /// leaves uncovered (node-sync's `read_ok`: `LocalPeer::sealed` rotates first, as its
    /// `uncovered` does). `None`: not held, or a reader's current secret not held.
    pub fn seal_package(&mut self, id: &CommitId, rng: &mut dyn osis_crypto::CryptoRngCore) -> Result<Option<SealedPackage>> {
        let Some(pk) = self.package(id)? else { return Ok(None) };
        let Some(b) = self.body(id)? else { return Ok(None) };
        let Some(s) = self.seal(&b, osis_label::Class::of_marker(self.header(id).and_then(|h| h.ephemeral)), &[], rng)? else { return Ok(None) };
        let mut wraps = Vec::new();
        for a in self.reader_actors(id) {
            if !self.core.is_key_actor(&a) && self.run(|tx| { let deps = crate::rotation::departures(tx, &a)?; crate::rotation::blocked_roles_of(tx, &tx.core.writer()?, &a, &deps, crate::rotation::Walk::Place) })?.contains(&osis_base::Role::Read) {
                continue;
            }
            let Some(secret) = self.wrap_secret(&a, Some((id, &b.parts)))? else { continue };
            wraps.push((a, osis_crypto::wrap(&secret, &s.id, &s.key, b.order)?));
        }
        Ok(Some(SealedPackage { id: *id, entries: vec![SealedEntry { id: s.id, blob: s.blob, wraps }], blobs: pk.blobs }))
    }

    /// The reader actors of a held commit's parts, distinct, in part order.
    pub fn reader_actors(&mut self, id: &CommitId) -> Vec<osis_base::Tid> {
        let Some(h) = self.header(id) else { return Vec::new() };
        let mut out = Vec::new();
        for a in &h.aspects {
            let r = self.core.reader_of(&a.tid);
            if !out.contains(&r) {
                out.push(r);
            }
        }
        out
    }

    /// Opens what it can of a sealed package with the read secrets held (`read_secrets`,
    /// `unwrap_any`, `open_commit`, as node-sync opens a label entry) and ingests what opened;
    /// the results, empty when nothing opened (no wrap opened, or no section).
    pub fn open_package(&mut self, pk: &SealedPackage) -> Result<Vec<Ingested>> {
        let mut out = Vec::new();
        for e in &pk.entries {
            let Some(key) = e.wraps.iter().find_map(|(a, w)| osis_label::unwrap_any(self.read_secrets(a).iter(), &e.id, w).map(|x| x.1)) else { continue };
            let o = self.open_commit(&e.blob, &key, None)?;
            if o.commit.parts.is_empty() {
                continue;
            }
            out.push(self.ingest(&o.plaintext, pk.blobs.clone())?);
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
    memo: SyncMemo,
}

/// What `sync_all` need not do again (`Engine::point`: nothing a delivery reads moved).
#[derive(Default)]
struct SyncMemo {
    /// Per sender: its packages, with a hash of each, at a point of its engine.
    sent: HashMap<usize, (ReadPoint, Hashed)>,
    /// (receiver, package hash): delivered as a duplicate that changed nothing, at this point.
    duplicate: HashMap<(usize, u64), ReadPoint>,
}

type Hashed = Arc<Vec<(Package, u64)>>;

impl LocalPeer {
    /// `n` fresh nodes, each its own account, seeds derived from `seed`, all at wall time `t`.
    pub fn new(n: usize, seed: u64, t: WallMs) -> Result<LocalPeer> {
        let peers = (0..n).map(|i| Peer::new(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        Ok(LocalPeer::of(peers, seed))
    }

    /// `n` fresh nodes that have joined no account yet (`Peer::new_bare`).
    pub fn new_bare(n: usize, seed: u64, t: WallMs) -> Result<LocalPeer> {
        let peers = (0..n).map(|i| Peer::new_bare(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        Ok(LocalPeer::of(peers, seed))
    }

    /// Peers made elsewhere; `seed` seeds the sealing rng.
    pub fn of(peers: Vec<Peer>, seed: u64) -> LocalPeer {
        LocalPeer { peers, rng: SeededRng::from_u64(seed ^ 0x5ea1), memo: SyncMemo::default() }
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
            Some(p) => p.receive_with(&pk.bytes, pk.blobs.clone(), &pk.lists),
            None => Ok(Ingested::Duplicate(pk.id)),
        }
    }

    /// Commits `from` holds, sealed (`Engine::seal_package`), after the rotations due before it
    /// encrypts under their reader actors (node-sync's `uncovered`), which go first.
    pub fn sealed(&mut self, from: usize, ids: &[CommitId]) -> Result<Vec<SealedPackage>> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(Vec::new()) };
        let mut readers = BTreeSet::new();
        for id in ids {
            readers.extend(p.engine.reader_actors(id));
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
        self.sync_changed(from, to).map(|_| ())
    }

    /// `packages`, hashed, kept while `from`'s engine stands.
    fn packages_hashed(&mut self, from: usize) -> Result<Hashed> {
        let at = self.peers.get(from).map(|p| p.engine.point()).unwrap_or_default();
        if let Some((_, v)) = self.memo.sent.get(&from).filter(|(p, _)| *p == at) {
            return Ok(v.clone());
        }
        let hash = |pk: &Package| {
            let mut h = DefaultHasher::new();
            (&pk.id, &pk.bytes, &pk.blobs).hash(&mut h);
            h.finish()
        };
        let v: Hashed = Arc::new(self.packages(from)?.into_iter().map(|pk| { let n = hash(&pk); (pk, n) }).collect());
        self.memo.sent.insert(from, (at, v.clone()));
        Ok(v)
    }

    /// `sync`; whether any delivery was more than a duplicate.
    fn sync_changed(&mut self, from: usize, to: usize) -> Result<bool> {
        osis_base::testenv::checkpoint();
        let mut changed = false;
        for (pk, hash) in self.packages_hashed(from)?.iter() {
            let key = (to, *hash);
            let at = self.peers.get(to).map(|p| p.engine.point());
            if at.is_some() && self.memo.duplicate.get(&key).copied() == at {
                continue;
            }
            let dup = matches!(self.deliver(to, pk)?, Ingested::Duplicate(_));
            changed |= !dup;
            if let Some(after) = self.peers.get(to).map(|p| p.engine.point()).filter(|a| dup && Some(*a) == at) {
                self.memo.duplicate.insert(key, after);
            }
        }
        Ok(changed)
    }

    /// Syncs every ordered pair until a round changes nothing (at most `n` rounds). A round in
    /// which every delivery was a duplicate is a fixpoint: the next would deliver the same
    /// packages to the same states.
    pub fn sync_all(&mut self) -> Result<()> {
        let n = self.peers.len();
        for _ in 0..n.max(1) {
            let mut changed = false;
            for a in 0..n {
                for b in 0..n {
                    if a != b {
                        changed |= self.sync_changed(a, b)?;
                    }
                }
            }
            if !changed {
                break;
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
