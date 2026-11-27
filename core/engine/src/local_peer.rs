//! `LocalPeer`: engines exchanging commits directly, with no sync IDs or peers (the simulator's
//! seed, notes/test-sim.md). Each engine has its own `MemoryBackend`, `ManualClock` and
//! seeded rng; delivery is explicit and order is the caller's. `Package` is plaintext (a test of
//! what arrives regardless of keys), its parts noted opened under the receiver's newest current
//! read epoch of their thing as if sealed so (`Engine::note_delivered`); `SealedPackage` is what a
//! sync ID carries: each body sealed and wrapped under its independent's read secret as node-sync
//! places it, opened only with the read secrets the receiver holds.

use crate::engine::{Config, Engine, ReadPoint};
use crate::error::Result;
use crate::events::Event;
use crate::{Ingested, Mutation};
use osis_base::{BlobId, Classified, Clock, CommitId, Link, ManualClock, Tid, WallMs};
use osis_commit::CommitBlob;
use osis_crypto::SeededRng;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;
use std::sync::mpsc::Receiver;

/// A commit as it travels: its plaintext blob and the blobs it references.
#[derive(Clone, Debug)]
pub struct Package {
    pub id: CommitId,
    pub bytes: Vec<u8>,
    pub blobs: Vec<(BlobId, Vec<u8>)>,
}

/// A commit as sync IDs carry it (spec/sync-ids.md §1-§3): its one sealed blob with a wrap under
/// each independent among its parts, and the blobs the commit references (already sealed
/// under link keys). Readers the sender holds no current read secret for get no wrap.
#[derive(Clone, Debug)]
pub struct SealedPackage {
    pub id: CommitId,
    pub entries: Vec<SealedEntry>,
    pub blobs: Vec<(BlobId, Vec<u8>)>,
}

/// The sealed blob with its wraps: per independent among the commit's parts, the wrap under
/// that actor's read secret (as a sync ID of it would carry it).
#[derive(Clone, Debug)]
pub struct SealedEntry {
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub wraps: Vec<(osis_base::Tid, [u8; osis_crypto::WRAP_LEN])>,
}

/// The blob area over `disk`, opened (or created) as a node opens its ciphertext store.
pub fn blob_area(disk: &(MemoryBackend, MemoryRoot), seed: u64) -> Result<Arc<dyn osis_store::Ciphertext>> {
    Ok(osis_store::BlobArea::open(Box::new(disk.0.clone()), Box::new(disk.1.clone()), Box::new(SeededRng::from_u64(seed ^ 0xb10b)))?)
}

/// One node: an engine with its clock, store and root.
pub struct Peer {
    pub engine: Engine,
    pub clock: Arc<ManualClock>,
    pub backend: MemoryBackend,
    pub root: MemoryRoot,
    /// The blob area's backend and root (`osis_store::BlobArea`).
    pub blob_disk: (MemoryBackend, MemoryRoot),
    pub events: Receiver<Event>,
    /// Opens so far: mixed into each restart's rng seed, so no two opens of one store draw
    /// the same session nonce (spec/crdt.md §2.1) however a test seeds them.
    pub restarts: u64,
    /// What the engine threw out (`receive`), and the copies carrying a pending commit.
    pub discarded: Vec<Discarded>,
    /// How many packages the engine threw out so far.
    pub discards: u64,
    /// How many carriers of a commit named for redelivery were ingested again.
    pub redelivered: u64,
    /// The sync IDs the engine pulled anew (`Wakes::pulled_anew`) since a test took them: what
    /// node-sync would fetch again from them is the test's to deliver.
    pub pulled_anew: BTreeSet<osis_base::SyncId>,
    /// The commits of every package `receive` was given: what its sources would list again on a
    /// pull from the start (a test's to deliver).
    pub given: BTreeSet<CommitId>,
    /// The sealed fires offered here (`offer_fires`).
    pub offers: FireOffers,
    /// Every copy taken, by commit, as node-sync's store keeps its entries: opened again when the
    /// engine names a commit it neither holds nor pends (`Engine::take_redeliver`).
    pub entries: BTreeMap<CommitId, Vec<Discarded>>,
}

/// Per sealed fire offered (`Peer::offer_fires`), by the commit it carries: whether it is held,
/// with what its last judgement read, as node-sync's inbox keys a deposit (osis-sync
/// `inbox::held`). An engine of its own (a restart, a fork) starts with none.
#[derive(Clone)]
pub struct FireOffers(osis_base::memo::Effects<CommitId, bool>);

impl Default for FireOffers {
    fn default() -> Self {
        FireOffers(osis_base::memo::Effects::new("peer: fires offered"))
    }
}

/// A package this peer's engine threw out, as peers keep it: fetched again as node-sync does
/// (`Peer::receive`).
#[derive(Clone)]
pub struct Discarded {
    bytes: Vec<u8>,
    /// `bytes` decoded, once.
    blob: Arc<CommitBlob>,
    blobs: Vec<(BlobId, Vec<u8>)>,
    pub commit: CommitId,
    /// A copy carrying a pending commit (or parts of an applied one), as node-sync keeps its
    /// entry: delivered again when the engine names the commit (`Engine::take_redeliver`), kept
    /// while the commit pends; after, kept as a copy of a part it misses (`Wakes`).
    carries: bool,
}

impl Discarded {
    /// Whether this is a pending commit's carrier, not a copy of a missing part.
    pub fn carries(&self) -> bool {
        self.carries
    }
}

/// Whether `b` carries a part applied commit `id` misses.
fn misses(core: &crate::engine::Core, id: &CommitId, b: &CommitBlob) -> bool {
    core.ix.commits.get(id).is_some_and(|m| b.parts.iter().any(|p| m.missing(p.ai)))
}

impl Peer {
    /// Which of `on` anything held or pending here needs (`retention::needed::needs`): a package
    /// on them this node dropped at a pass end is wanted no more than then while that stands
    /// (`LocalPeer::sync`).
    /// `known`: the answers kept at a point of this engine (`SyncMemo::needed`).
    fn needed<'a>(&mut self, on: impl IntoIterator<Item = &'a Tid>, known: &mut Option<(ReadPoint, BTreeMap<Tid, bool>)>) -> Result<BTreeSet<Tid>> {
        let on: BTreeSet<Tid> = on.into_iter().copied().collect();
        if on.is_empty() {
            return Ok(on);
        }
        let point = self.engine.point();
        let mut kept = known.take().filter(|k| k.0 == point).map(|k| k.1).unwrap_or_default();
        let ask: Vec<Tid> = on.iter().filter(|t| !kept.contains_key(*t)).copied().collect();
        if !ask.is_empty() {
            let fresh = self.engine.read(|tx| ask.into_iter().map(|t| Ok((t, !crate::retention::needed::needs(tx, &t)?.is_empty()))).collect::<Result<Vec<_>>>())?;
            // a read settling blobs first moves the point: its answers are the new point's
            if self.engine.point() != point {
                kept.clear();
            }
            kept.extend(fresh);
        }
        let out = on.into_iter().filter(|t| kept.get(t) == Some(&true)).collect();
        *known = Some((self.engine.point(), kept));
        Ok(out)
    }

    /// Receives a package and stands in for node-sync's carriers and fetches: a carrier of what
    /// pends is ingested again when the engine names its commit, a copy of a missing part when
    /// `Wakes` names it. The test's `Engine::ingest` is what
    /// node-sync calls; only the fetching is played here.
    pub fn receive(&mut self, bytes: &[u8], blobs: Vec<(BlobId, Vec<u8>)>) -> Result<Ingested> {
        // decoded once for the harness's own bookkeeping (the engine decodes what it ingests)
        let blob = CommitBlob::decode(bytes).ok().map(Arc::new);
        if let Some(b) = &blob {
            self.engine.note_delivered(b);
            self.given.insert(b.id());
        }
        let r = self.engine.ingest(bytes, blobs.clone());
        // a broken engine invariant leaves the commit unreceived and fails node-sync's step: in a
        // test it fails at once, not as a read difference far from its cause (a caller dropping
        // the result would never see it)
        #[allow(clippy::panic)] // a test harness (tests, the simulator): fail loudly
        if let Err(crate::Error::Corrupt(m)) = &r {
            panic!("receiving fails the node: engine invariant broken: {m}");
        }
        if let Err(e) = &r
            && e.class() == osis_base::ErrorClass::BadInput
            && let Some(b) = &blob
        {
            self.engine.forget_awaiting(&b.id())?;
        }
        if let Some(b) = blob {
            self.note(bytes, b, &blobs, &r);
        }
        self.wake()?;
        r
    }

    /// Runs what is due (`Engine::tick`) and, as node-sync does after it, fetches again what
    /// the engine names (`wake`).
    pub fn tick(&mut self) -> Result<()> {
        self.engine.tick()?;
        self.wake()
    }

    /// `Engine::reexamine`, then fetches again what it woke (`tick`).
    pub fn reexamine(&mut self) -> Result<()> {
        self.wake()
    }

    /// Keeps what node-sync would keep or fetch again: a carrier of a pending commit, or a copy of
    /// a held one with a part of these bytes missing. Any earlier copy of the same bytes goes
    /// (only decodable bytes are kept, so only those match).
    fn note(&mut self, bytes: &[u8], blob: Arc<CommitBlob>, blobs: &[(BlobId, Vec<u8>)], r: &Result<Ingested>) {
        self.discarded.retain(|d| d.bytes != bytes);
        let Ok(i) = r else { return };
        let id = match i {
            Ingested::Applied(x) | Ingested::Duplicate(x) | Ingested::Pending(x, _) | Ingested::Parked(x) | Ingested::TooLarge(x) => *x,
        };
        let kept = self.entries.entry(id).or_default();
        if !kept.iter().any(|d| d.bytes == bytes) {
            kept.push(Discarded { bytes: bytes.to_vec(), blob: blob.clone(), blobs: blobs.to_vec(), commit: id, carries: true });
        }
        if self.engine.core.ix.pending.contains_key(&id) {
            self.discarded.push(Discarded { bytes: bytes.to_vec(), blob, blobs: blobs.to_vec(), commit: id, carries: true });
            return;
        }
        if !misses(&self.engine.core, &id, &blob) {
            return;
        }
        self.discards += 1;
        self.discarded.push(Discarded { bytes: bytes.to_vec(), blob, blobs: blobs.to_vec(), commit: id, carries: false });
    }

    fn wake(&mut self) -> Result<()> {
        // each round ingests some of the entries held at the start (an entry kept is one of
        // those), again only after another's ingest moved the engine: at most every entry once
        // after each other's, (e + 1)^2 rounds. At 0 every redelivery panics; at infinity a wake
        // the engine keeps giving for an ingest that moves nothing hangs the test.
        let e = self.discarded.len() as u64;
        let mut guard = osis_base::loop_guard::LoopGuard::new("LocalPeer::wake (redelivering kept carriers and copies)");
        loop {
            self.engine.reexamine()?;
            // a grant fire that came as a commit: what it carries is taken, as sync's follow does
            self.engine.take_carried()?;
            let w = self.engine.take_wakes();
            self.pulled_anew.extend(w.pulled_anew.iter().copied());
            let again = self.engine.take_redeliver();
            let core = &self.engine.core;
            // a commit named that is neither held nor pending (forgotten to pend again,
            // `apply::atomic::pend_again`): its entries open again, as node-sync's `reopen`
            for c in &again {
                if !core.ix.commits.contains_key(c) && !core.ix.pending.contains_key(c) && !self.discarded.iter().any(|d| d.commit == *c) {
                    self.discarded.extend(self.entries.get(c).into_iter().flatten().cloned());
                }
            }
            // a carrier whose commit pends no more and is not named to deliver again is a copy of
            // a part the applied commit misses, or goes (node-sync keeps the entry, fetched again
            // when the commit is woken)
            self.discarded.retain_mut(|d| {
                if !d.carries || core.ix.pending.contains_key(&d.commit) || again.contains(&d.commit) {
                    return true;
                }
                d.carries = false;
                misses(core, &d.commit, &d.blob)
            });
            let due = |d: &Discarded| {
                if d.carries {
                    return again.contains(&d.commit);
                }
                w.reopen_awaits || w.reread.contains(&d.commit)
            };
            let (now, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.discarded).into_iter().partition(|d| due(d));
            self.discarded = later;
            if now.is_empty() {
                return Ok(());
            }
            let point = self.engine.point();
            let ingested: Vec<CommitId> = now.iter().map(|d| d.commit).collect();
            for d in now {
                self.redelivered += u64::from(d.carries);
                self.engine.note_delivered(&d.blob);
                let r = self.engine.ingest(&d.bytes, d.blobs.clone());
                if matches!(&r, Err(e) if e.class() == osis_base::ErrorClass::BadInput) {
                    self.engine.forget_awaiting(&d.commit)?;
                }
                self.note(&d.bytes, d.blob, &d.blobs, &r);
            }
            for c in &again {
                self.engine.redelivered(c)?;
            }
            let moved = self.engine.point() != point;
            guard.round((ingested, moved), || ((e + 1).pow(2), format!("{e} entries kept at the start")));
        }
    }

    /// This node keeps the nodes `who` (a contact, a peer it will grant): a strong to each in its
    /// node root's `holds.0`, so their records stay once received (spec/commits.md §5 What a held
    /// thing needs; a strong to a thing it holds no role on enters nothing). One commit; none when it keeps each
    /// already.
    pub fn know(&mut self, who: &[osis_base::Tid]) -> Result<()> {
        let root = self.engine.node_root().ok_or(crate::error::Error::Misuse("no node root"))?;
        let kept: BTreeSet<osis_base::Tid> = self.engine.references_from(&root)?.into_iter().filter(|r| r.kind == osis_base::RefKind::Strong && r.ak.as_str() == "holds.0").map(|r| r.target).collect();
        let mut m = Mutation::new();
        for t in who.iter().filter(|t| **t != self.engine.tid() && !kept.contains(*t)) {
            m.op(root, &osis_schema::core_types::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(*t)) })?;
        }
        if !m.is_empty() {
            self.commit(m)?;
        }
        Ok(())
    }

    /// This node's account imports a contact card (spec/sync-inbox.md §5), `link` to a public
    /// profile whose commits it has received: the strong from its account (its node thing where
    /// it acts for none) that redeeming writes (`Engine::redeem_public`), then what the profile
    /// carries taken (its cards).
    pub fn import_contact(&mut self, link: &osis_blob::Locator) -> Result<()> {
        let joiner = self.engine.settings_thing()?.unwrap_or_else(|| self.engine.tid());
        self.engine.redeem_public(link, &joiner)?;
        self.engine.take_carried()?;
        Ok(())
    }

    /// A fresh node at wall time `t`.
    pub fn new(seed: u64, t: WallMs) -> Result<Peer> {
        let clock = Arc::new(ManualClock::new(t));
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let blob_disk = (MemoryBackend::new(), MemoryRoot::new());
        let c: Arc<dyn Clock> = clock.clone();
        let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), blob_area(&blob_disk, seed)?, Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        engine.take_wakes();
        let events = engine.subscribe();
        Ok(Peer { engine, clock, backend, root, blob_disk, events, restarts: 0, discarded: Vec::new(), discards: 0, redelivered: 0, pulled_anew: BTreeSet::new(), given: BTreeSet::new(), offers: FireOffers::default(), entries: BTreeMap::new() })
    }

    /// Drops the engine and opens it again over the same durable state.
    pub fn restart(&mut self, seed: u64) -> Result<()> {
        self.restart_with(seed, Config::default())
    }

    /// `restart` under `cfg`.
    pub fn restart_with(&mut self, seed: u64, cfg: Config) -> Result<()> {
        let c: Arc<dyn Clock> = self.clock.clone();
        self.restarts += 1;
        let seed = seed.wrapping_add(self.restarts.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut engine = Engine::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), blob_area(&self.blob_disk, seed)?, cfg, c, Box::new(SeededRng::from_u64(seed)))?;
        self.events = engine.subscribe();
        engine.take_wakes();
        self.engine = engine;
        self.offers = FireOffers::default();
        self.fetch_discarded()
    }

    /// An independent copy of this node as it is now, opened over a copy of its durable state on
    /// a clock of its own: one setup, then several paths from it.
    pub fn fork(&self, seed: u64) -> Result<Peer> {
        let clock = Arc::new(ManualClock::new(self.clock.now_wall_ms()));
        let (backend, root) = (self.backend.copy(), self.root.copy());
        let blob_disk = (self.blob_disk.0.copy(), self.blob_disk.1.copy());
        let c: Arc<dyn Clock> = clock.clone();
        let seed = seed.wrapping_add((self.restarts + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut engine = Engine::open(Box::new(backend.clone()), Box::new(root.clone()), blob_area(&blob_disk, seed)?, Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
        let events = engine.subscribe();
        engine.take_wakes();
        let mut p = Peer { engine, clock, backend, root, blob_disk, events, restarts: self.restarts + 1, discarded: self.discarded.clone(), discards: self.discards, redelivered: self.redelivered, pulled_anew: self.pulled_anew.clone(), given: self.given.clone(), offers: FireOffers::default(), entries: self.entries.clone() };
        p.fetch_discarded()?;
        Ok(p)
    }

    /// An exact copy of this node as it stands (`Engine::test_copy`), on a clock of its own at
    /// the same time: it goes on exactly as this one would. Its event receiver holds the events
    /// this one's had not read (`&mut`: this one's receiver is replaced by one holding them
    /// too). Inside a world copy (`osis_base::copying`) with the peers it is copied beside.
    pub fn copy(&mut self) -> Result<Peer> {
        osis_base::copying::copying(|| {
            let clock = Arc::new(ManualClock::new(self.clock.now_wall_ms()));
            let c: Arc<dyn Clock> = clock.clone();
            let mut engine = self.engine.test_copy(c)?;
            let pending: Vec<Event> = self.events.try_iter().collect();
            self.events = self.engine.test_subscribe_with(pending.clone());
            let events = engine.test_subscribe_with(pending);
            let (backend, root) = (self.backend.test_copy(), self.root.test_copy());
            let blob_disk = (self.blob_disk.0.test_copy(), self.blob_disk.1.test_copy());
            Ok(Peer { engine, clock, backend, root, blob_disk, events, restarts: self.restarts, discarded: self.discarded.clone(), discards: self.discards, redelivered: self.redelivered, pulled_anew: self.pulled_anew.clone(), given: self.given.clone(), offers: self.offers.clone(), entries: self.entries.clone() })
        })
    }

    /// Offers each of `fires` (`Engine::offer_fire`), with the commit it carries, as node-sync's
    /// inbox judges a deposit (osis-sync `inbox::held`): a fire not held is offered when first
    /// given and again only once something its last offer read moved (a refused offer stands
    /// until what refused it changes). The offers made, with what each opened to.
    pub fn offer_fires<'a>(&mut self, fires: impl IntoIterator<Item = (&'a CommitId, &'a crate::sync::SealedFireOut)>) -> Result<Vec<(&'a crate::sync::SealedFireOut, crate::sync::Opened)>> {
        let given: BTreeMap<CommitId, &crate::sync::SealedFireOut> = fires.into_iter().map(|(c, f)| (*c, f)).collect();
        for c in given.keys() {
            self.offers.0.want(*c);
        }
        let mut out = Vec::new();
        // a key due that this call does not give stays due for the call that does
        for c in self.offers.0.due() {
            let Some(f) = given.get(&c) else { continue };
            let (engine, mut opened) = (&mut self.engine, None);
            self.offers.0.try_settle(&c, || -> Result<bool> {
                if engine.header(&c).is_none() {
                    opened = Some(engine.offer_fire(f)?);
                }
                Ok(engine.header(&c).is_some())
            })?;
            out.extend(opened.map(|o| (*f, o)));
        }
        Ok(out)
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
    /// tree nodes its deltas link, header-list trees), for relaying.
    pub fn package(&mut self, id: &CommitId) -> Result<Option<Package>> {
        Ok(self.package_with_record(id)?.map(|x| x.0))
    }

    /// `package`, with its commit decoded (the record cache's; a pending copy's bytes decoded).
    pub fn package_with_record(&mut self, id: &CommitId) -> Result<Option<(Package, Arc<CommitBlob>)>> {
        // a held record decoded once (the record cache), not encoded and decoded again
        let held = {
            let id = *id;
            self.read(|tx| match tx.get_commit(&id)? {
                Some(b) => Ok(Some((b.encode(), Some(b)))),
                None => Ok(tx.txn.get_pending(&id)?.map(|p| (p.bytes, None))),
            })?
        };
        let Some((bytes, record)) = held else { return Ok(None) };
        let record = match record {
            Some(b) => b,
            None => Arc::new(CommitBlob::decode(&bytes)?),
        };
        let mut ids: BTreeSet<BlobId> = self.body_links_of(&record)?.blobs;
        ids.extend(self.header_list_blobs(id)?);
        let mut blobs = Vec::new();
        for b in ids {
            if let Some(x) = self.blob(&b)? {
                blobs.push((b, x));
            }
        }
        Ok(Some((Package { id: *id, bytes, blobs }, record)))
    }

    /// The parts of held commit `id` the bodies under the sync IDs `synced` hold.
    pub fn carried_under(&mut self, id: &CommitId, synced: &BTreeSet<osis_base::SyncId>) -> Result<Option<BTreeSet<usize>>> {
        let bodies = self.sync_bodies(id)?;
        let mut parts: Option<BTreeSet<usize>> = None;
        for (_, b) in bodies.iter().filter(|((s, _), _)| synced.contains(s)) {
            parts.get_or_insert_default().extend(b.parts.iter().copied());
        }
        Ok(parts)
    }

    /// Held commit `id` holding its parts `parts` alone (`package`; a header alone for none).
    pub fn package_of_parts(&mut self, id: &CommitId, parts: &BTreeSet<usize>) -> Result<Option<Package>> {
        Ok(self.package_with_record(id)?.map(|(pk, b)| holding(&pk, &b, parts)))
    }

    /// The parts of held commit `id` this node sends a node syncing `synced` (`LocalPeer::
    /// packages_under`): those the sync IDs carry (`carried_under`) and its certificate parts
    /// (`certificate_parts`); `None` with neither.
    pub fn sent_parts(&mut self, id: &CommitId, synced: &BTreeSet<osis_base::SyncId>) -> Result<Option<BTreeSet<usize>>> {
        let certs = self.certificate_parts(id);
        Ok(match self.carried_under(id, synced)? {
            Some(mut a) => {
                a.extend(certs);
                Some(a)
            }
            None if !certs.is_empty() => Some(certs),
            None => None,
        })
    }

    /// The certificate parts of held commit `id` (spec/commits.md §5 What a held thing needs:
    /// every part but content, `retention::forget::content`).
    pub fn certificate_parts(&self, id: &CommitId) -> BTreeSet<usize> {
        let Some(m) = self.core.ix.commits.get(id) else { return BTreeSet::new() };
        m.view.aspects.iter().enumerate().filter(|(ai, a)| m.holds(*ai) && !crate::retention::forget::content(&a.ak)).map(|(ai, _)| ai).collect()
    }

    /// The blobs of a held commit's linked header lists that this node holds.
    pub fn header_list_blobs(&mut self, id: &CommitId) -> Result<BTreeSet<BlobId>> {
        let mut ids = BTreeSet::new();
        if let Some(h) = self.header(id) {
            let links: Vec<Link> = osis_commit::ListField::ALL.iter().filter_map(|f| h.links.get(*f).copied()).collect();
            for l in links {
                self.tree_blobs(&l, &h, &mut ids)?;
            }
        }
        Ok(ids.into_iter().filter(|b| self.has_blob(b)).collect())
    }

    /// A held commit sealed as sync IDs carry it (`SealedPackage`): its blob framed with a fresh
    /// key (`seal`, one section per reader) and wrapped under `wrap_secret` of each reader
    /// actor, as node-sync places it; no wrap for a reader whose read role a known departure
    /// leaves uncovered (`LocalPeer::sealed` rotates first, as node-sync's `uncovered` does). `None`: not held, or a reader's current secret not held.
    pub fn seal_package(&mut self, id: &CommitId, rng: &mut dyn osis_crypto::CryptoRngCore) -> Result<Option<SealedPackage>> {
        let Some(pk) = self.package(id)? else { return Ok(None) };
        let Some(b) = self.body(id)? else { return Ok(None) };
        let Some(s) = self.seal(&b, osis_blob::Class::of_marker(self.header(id).and_then(|h| h.ephemeral)), &[], rng)? else { return Ok(None) };
        let mut wraps = Vec::new();
        for a in self.independents(id) {
            if self.run(|tx| crate::rotation::blocked_roles_of(tx, &tx.core.tid(), &a, crate::rotation::Walk::Log))?.contains(&osis_base::Role::Read) {
                continue;
            }
            let Some(secret) = self.wrap_secret(&a, Some((id, &b.parts)))? else { continue };
            wraps.push((a, osis_crypto::wrap(&secret, &s.id, &s.key, b.order)?));
        }
        Ok(Some(SealedPackage { id: *id, entries: vec![SealedEntry { id: s.id, blob: s.blob, wraps }], blobs: pk.blobs }))
    }

    /// The independents of a held commit's parts, distinct, in part order.
    pub fn independents(&mut self, id: &CommitId) -> Vec<osis_base::Tid> {
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
    /// `unwrap_any`, `open_commit`, as node-sync opens a sync ID entry) and ingests what opened;
    /// the results, empty when nothing opened (no wrap opened, or no section).
    #[cfg(test)]
    pub(crate) fn open_package(&mut self, pk: &SealedPackage) -> Result<Vec<Ingested>> {
        Ok(self.open_package_counted(pk)?.0)
    }

    /// `open_package`, with the records taken from sections of things not held here
    /// (`OpenedBlob::records`, taken with the ingest as `open_entry` does) that were new.
    fn open_package_counted(&mut self, pk: &SealedPackage) -> Result<(Vec<Ingested>, usize)> {
        let mut out = Vec::new();
        let mut learned = 0;
        for e in &pk.entries {
            let Some(key) = e.wraps.iter().find_map(|(a, w)| osis_blob::unwrap_any(self.read_secrets(a).iter(), &e.id, w).map(|x| x.1)) else { continue };
            let o = self.open_commit(&e.blob, &key)?;
            if o.commit.parts.is_empty() {
                learned += self.learn_records(o.records)?;
                continue;
            }
            learned += o.records.iter().filter(|r| self.core.created(&r.tid()).is_none()).count();
            out.push(self.ingest_carrying(&o.plaintext, pk.blobs.clone(), o.records)?);
        }
        Ok((out, learned))
    }

    /// The blobs of linked list `root` of header `h` this node holds (keyed by `h`'s
    /// `list_secret`).
    pub(crate) fn tree_blobs(&mut self, root: &Link, h: &osis_commit::Header, out: &mut BTreeSet<BlobId>) -> Result<()> {
        struct Rec<'e> {
            e: &'e mut Engine,
            seen: Vec<BlobId>,
        }
        impl osis_commit::BlobSource for Rec<'_> {
            fn get(&mut self, link: &Link) -> std::result::Result<Vec<u8>, osis_commit::Error> {
                self.seen.push(link.blob);
                let blob = self.e.blob(&link.blob).map_err(|_| osis_commit::Error::Missing)?.ok_or(osis_commit::Error::Missing)?;
                let (_, pt) = osis_blob::open(&blob, &osis_crypto::Secret32::from_bytes(link.key)).map_err(|_| osis_commit::Error::Corrupt)?;
                Ok(pt)
            }
        }
        let Some(dedup) = self.core.dedup(&h.signer) else { return Ok(()) };
        let key = h.list_secret(&dedup);
        let mut r = Rec { e: self, seen: Vec::new() };
        let _ = osis_commit::read_list(root, &key, &mut r, osis_commit::MAX_LIST_BYTES);
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
#[derive(Clone, Default)]
struct SyncMemo {
    /// No fire passes (`LocalPeer::hold_fires`).
    fires_held: bool,
    /// The peers whose fires are held back (`LocalPeer::hold_fires_of`).
    fires_held_of: BTreeSet<usize>,
    /// The sealed fires passed on (`LocalPeer::pass_fires`): (sender, fire, receiver).
    fired: BTreeSet<(usize, crate::flows::inbox::FireId, usize)>,
    /// The sealed fires a peer refused, its setting not enabling their signal (`pass_fires`).
    refused: BTreeSet<(usize, crate::flows::inbox::FireId, usize)>,
    /// Per sender: every commit it sends whole (`packages`), each followed by what packaging it
    /// read, so a move of the sender's engine packages again only the commits whose reads it moved;
    /// each set of sync IDs trims these (`sent`), so a commit is packaged once per change, not once
    /// per receiver.
    whole: HashMap<usize, Packaged>,
    /// Per sender and sync IDs synced: its packages under them, with a hash of each, at a point
    /// of its engine, and each trimmed package kept by the whole package and parts it was cut from.
    sent: HashMap<(usize, Vec<osis_base::SyncId>), Trimmed>,
    /// (receiver, package hash): delivered as a duplicate that changed nothing, at this point.
    duplicate: HashMap<(usize, u64), ReadPoint>,
    /// (receiver, package hash): delivered, then dropped at the end of its pass (whole or some
    /// parts) on things outside the receiver's node closure, needed by nothing held there
    /// (`Engine::settle_needs`), with which of those things something needed then
    /// (`Peer::needed`): offered again only once that moved, as a real node fetches only what
    /// its sync set carries. Without it every pass delivered other accounts' roots again, to
    /// drop them again at its end.
    dropped: HashMap<(usize, u64), BTreeSet<Tid>>,
    /// Per receiver: the packages delivered (not as duplicates) since its last pass end.
    in_pass: HashMap<usize, Vec<(u64, CommitId, Vec<Tid>)>>,
    /// Per receiver: which things something held needs (`Peer::needed`), at this point: asked
    /// by every sender while its engine stands.
    needed: HashMap<usize, (ReadPoint, BTreeMap<Tid, bool>)>,
}

/// A package as sent: with a hash of it and the things its commit is on.
type Sent = (Package, u64, Vec<Tid>);

/// A sender's packages (`Sent`).
type Hashed = Arc<Vec<Arc<Sent>>>;

/// A commit a sender holds, packaged whole (`Engine::package_with_record`): its record and the
/// package's hash beside it.
type Whole = (Sent, Arc<CommitBlob>);

/// A sender's commits packaged whole (`SyncMemo::whole`).
#[derive(Clone)]
struct Packaged {
    /// Per held commit: its package's hash, `None` where it sends none (on its node root alone).
    each: osis_base::memo::Effects<CommitId, Option<u64>>,
    /// The packages `each` settled.
    held: HashMap<CommitId, Arc<Whole>>,
    /// The packages in (`ts`, ID) order, at a point of the engine.
    at: Option<(ReadPoint, Arc<Vec<Arc<Whole>>>)>,
}

impl Default for Packaged {
    fn default() -> Self {
        Packaged { each: osis_base::memo::Effects::new("peer: packages whole"), held: HashMap::new(), at: None }
    }
}

/// A sender's packages under one set of sync IDs (`SyncMemo::sent`).
#[derive(Clone, Default)]
struct Trimmed {
    at: Option<(ReadPoint, Hashed)>,
    /// Per commit: the whole package's hash and the parts sent, and what they gave.
    each: HashMap<CommitId, (u64, BTreeSet<usize>, Arc<Sent>)>,
}

/// A hash of what a package delivers.
fn hash_of(pk: &Package) -> u64 {
    let mut h = DefaultHasher::new();
    (&pk.id, &pk.bytes, &pk.blobs).hash(&mut h);
    h.finish()
}

/// `pk` (whose commit is `b`) holding its parts `parts` alone: a header alone for none.
pub(crate) fn holding(pk: &Package, b: &CommitBlob, parts: &BTreeSet<usize>) -> Package {
    let mut out = pk.clone();
    if b.parts.iter().any(|p| !parts.contains(&p.ai)) {
        out.bytes = osis_commit::rewrite(b, |ai| !parts.contains(&ai)).encode();
    }
    out
}

/// An account as the account library arranges it (spec/permissions.md §8): no rule of core reads
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// A: minted with the node thing as mint admin, independent at its minting.
    pub thing: Tid,
    /// A's inbox (spec/sync-inbox.md §1): minted with admin A, independent, named by A's card on
    /// the profile.
    pub inbox: Tid,
    /// A's profile (spec/sync-inbox.md §5 Contact card): minted with admin A, independent.
    pub profile: Tid,
}

/// Makes an account on `e` as the account library does (spec/permissions.md §8 Making), with the
/// same engine calls, in one transaction: A minted with the node thing as mint admin, its inbox and
/// profile minted with admin A, each independent, held by strongs from A's `holds.0`; the inbox's
/// setting enabling both inbox signals; A's `keys.0` naming the inbox in the commit holding them; A's card on the profile; the node root's strong to A
/// and its `settings^.0` naming A. Then the public's read on the profile, in its own transaction.
pub fn make_account(e: &mut Engine) -> Result<(Account, crate::flows::Done)> {
    use osis_crdt::{Op, PathOp};
    use osis_schema::core_types as ct;
    let root = e.node_root().ok_or(crate::Error::Misuse("no node root"))?;
    let admins = [crate::MintAdmin::Thing(e.tid()), crate::MintAdmin::Minted(0), crate::MintAdmin::Minted(0)];
    let (ts, done) = e.mint_independent(&admins, |ts| {
        let [a, inbox, profile] = ts else { return Err(crate::Error::Misuse("three minted")) };
        // A holding its inbox and profile, and naming the inbox its own (an admin's write: the
        // node is A's mint admin)
        let mut held = Mutation::new();
        for t in [inbox, profile] {
            held.op(*a, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(osis_base::Value::Strong(*t)) })?;
        }
        crate::flows::cards::put_inbox(&mut held, *a, Some(*inbox))?;
        let mut signals = Mutation::new();
        let mut setting = ct::RetentionSetting::default();
        setting.take_inbox_signals();
        signals.set(*inbox, &ct::RETENTION, &setting)?;
        // A's card on the profile, acting as A; its keys filled in once A's `keys.0` is written
        // (`Engine::refresh_cards`)
        let card = crate::flows::cards::put(*profile, *a, &ct::Card::default())?;
        // the node root's in commits of their own: it is local, under no sync ID
        let mut hold = Mutation::new();
        hold.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(osis_base::Value::Strong(*a)) })?;
        let mut settings = Mutation::new();
        settings.set(root, &ct::SETTINGS, &osis_base::Weak(*a))?;
        Ok(vec![held, signals, card, hold, settings])
    })?;
    let [thing, inbox, profile] = ts.as_slice() else { return Err(crate::Error::Misuse("three minted")) };
    // the card carries A's keys and the inbox's
    e.refresh_cards()?;
    // the profile is public (spec/permissions.md §8), as the library's `Account::make` grants it
    let read = ct::Edge { role: osis_base::Role::Read, until: None, may_grant: false, retain: false, floor: None };
    let mut done = done;
    done.commits.extend(e.grant(profile, &Tid::PUBLIC, &read)?.commits);
    Ok((Account { thing: *thing, inbox: *inbox, profile: *profile }, done))
}

impl LocalPeer {
    /// `n` fresh nodes, each its own account, seeds derived from `seed`, all at wall time `t`,
    /// each keeping the others' accounts (`of`).
    pub fn new(n: usize, seed: u64, t: WallMs) -> Result<LocalPeer> {
        let peers = (0..n).map(|i| Peer::new(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        LocalPeer::of(peers, seed)
    }

    /// `new` whose nodes each act for an account of their own (`make_account`), each a contact
    /// of every other: each account holds the others' profiles by their contact cards
    /// (`Peer::import_contact`, holding the accounts' cards), as a contact's node does: the peers
    /// and the accounts.
    #[allow(clippy::indexing_slicing)] // i, j < n
    pub fn accounts(n: usize, seed: u64, t: WallMs) -> Result<(LocalPeer, Vec<osis_base::Tid>)> {
        let mut lp = LocalPeer::new(n, seed, t)?;
        let mut accs = Vec::new();
        for p in lp.peers.iter_mut() {
            accs.push(make_account(&mut p.engine)?.0);
        }
        let ps: Vec<osis_base::Tid> = accs.iter().map(|a| a.thing).collect();
        for (i, a) in accs.iter().enumerate() {
            for j in (0..n).filter(|j| *j != i) {
                for id in lp.peers[i].engine.commit_ids() {
                    if let Some(pk) = lp.peers[i].engine.package(&id)? {
                        lp.deliver(j, &pk)?;
                    }
                }
                let link = lp.peers[i].engine.locator(&a.profile, Vec::new())?.ok_or(crate::Error::Misuse("the profile is not public"))?;
                lp.peers[j].import_contact(&link)?;
            }
        }
        lp.sync_all()?;
        Ok((lp, ps))
    }

    /// `n` nodes of one account (spec/permissions.md §8): peer 0 makes it, each other is paired
    /// in at admin by peer 0 (`pair_into`), then all sync: the peers and the account.
    #[allow(clippy::indexing_slicing)] // peer 0 of n ≥ 1
    pub fn one_account(n: usize, seed: u64, t: WallMs) -> Result<(LocalPeer, Account)> {
        let mut peers = (0..n).map(|i| Peer::new(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        let rest = peers.split_off(1);
        let mut lp = LocalPeer::apart(peers, seed);
        let (acc, _) = make_account(&mut lp.peers[0].engine)?;
        for mut p in rest {
            lp.pair_into(0, &mut p)?;
            lp.peers.push(p);
        }
        lp.sync_all()?;
        Ok((lp, acc))
    }

    /// Adds a fresh node (seeded `seed`) acting for an account of its own, as a contact's node:
    /// it and every other peer hold each other's accounts' commits and a strong to each account.
    /// Its index and account.
    #[allow(clippy::indexing_slicing)] // indices of the net
    pub fn add_account(&mut self, seed: u64) -> Result<(usize, Account)> {
        let t = self.peers.first().map_or(WallMs(0), |p| p.engine.now());
        let mut p = Peer::new(seed, t)?;
        let (acc, _) = make_account(&mut p.engine)?;
        self.peers.push(p);
        let n = self.peers.len() - 1;
        let accounts: Vec<Option<osis_base::Tid>> = self.peers.iter_mut().map(|p| p.engine.settings_thing()).collect::<Result<_>>()?;
        let others: Vec<osis_base::Tid> = accounts.iter().take(n).flatten().copied().collect();
        self.peers[n].know(&others)?;
        for i in 0..n {
            self.peers[i].know(&[acc.thing])?;
            for (from, to) in [(i, n), (n, i)] {
                for id in self.peers[from].engine.commit_ids() {
                    if let Some(pk) = self.peers[from].engine.package(&id)? {
                        self.deliver(to, &pk)?;
                    }
                }
            }
        }
        self.sync_all()?;
        Ok((n, acc))
    }

    /// Pairs fresh node `p` into peer `by`'s account at admin (spec/permissions.md §8 Pairing):
    /// `p` shows its node thing's public key record, `by` writes the grant and hands back the
    /// offer, which `p` takes. The account's things reach `p` by sync after.
    #[allow(clippy::indexing_slicing)] // test harness: a peer index past the net panics
    pub fn pair_into(&mut self, by: usize, p: &mut Peer) -> Result<osis_base::Tid> {
        let a = self.peers[by].engine.settings_thing()?.ok_or(crate::error::Error::Misuse("the pairer acts for no account"))?;
        let (node, keys) = (p.engine.tid(), p.engine.node_keys()?);
        self.peers[by].engine.pair(&a, &node, &keys, osis_base::Role::Admin)?;
        p.engine.take_pairing(&a)?;
        Ok(a)
    }

    /// `new` whose accounts have met no other: none keeps another's chain.
    pub fn new_apart(n: usize, seed: u64, t: WallMs) -> Result<LocalPeer> {
        let peers = (0..n).map(|i| Peer::new(seed.wrapping_mul(1000).wrapping_add(i as u64), t)).collect::<Result<Vec<_>>>()?;
        Ok(LocalPeer::apart(peers, seed))
    }

    /// Every peer keeps every other peer (`Peer::know`).
    pub fn know_all(&mut self) -> Result<()> {
        let all: Vec<osis_base::Tid> = self.peers.iter().map(|p| p.engine.tid()).collect();
        for p in self.peers.iter_mut() {
            p.know(&all)?;
        }
        Ok(())
    }

    /// `new(n, 0, t)`, a copy of the one built per test process (`cached`): a copy costs about
    /// a hundredth of building the nodes.
    #[allow(clippy::panic)] // test harness: a build that fails fails the test
    pub fn fresh(n: usize, t: WallMs) -> LocalPeer {
        LocalPeer::cached(&format!("LocalPeer::fresh/{n}/{}", t.0), || (LocalPeer::new(n, 0, t).unwrap_or_else(|e| panic!("{e}")), ())).0
    }

    /// Peers made elsewhere, each keeping the others' accounts (`know_all`; `sync` and
    /// `sync_all` introduce those made later); `seed` seeds the sealing rng.
    pub fn of(peers: Vec<Peer>, seed: u64) -> Result<LocalPeer> {
        let mut lp = LocalPeer::apart(peers, seed);
        lp.know_all()?;
        Ok(lp)
    }

    /// `of` whose peers keep no other's account.
    pub fn apart(peers: Vec<Peer>, seed: u64) -> LocalPeer {
        LocalPeer { peers, rng: SeededRng::from_u64(seed ^ 0x5ea1), memo: SyncMemo::default() }
    }

    /// An exact copy of every peer, the sealing rng and what `sync_all` keeps (`Peer::copy`).
    pub fn copy(&mut self) -> Result<LocalPeer> {
        osis_base::copying::copying(|| {
            let peers = self.peers.iter_mut().map(Peer::copy).collect::<Result<Vec<_>>>()?;
            Ok(LocalPeer { peers, rng: self.rng.test_copy(), memo: self.memo.clone() })
        })
    }

    /// A copy (`copy`) of the peers `build` makes, with what it returned: built once per test
    /// process per `key`, which names the build and every parameter it takes
    /// (`osis_base::copying::cached`).
    #[allow(clippy::panic)] // test harness: a copy that fails fails the test
    pub fn cached<T: Clone + Send + 'static>(key: &str, build: impl FnOnce() -> (LocalPeer, T)) -> (LocalPeer, T) {
        osis_base::copying::cached(key, build, |(lp, t)| (lp.copy().unwrap_or_else(|e| panic!("copy of {key}: {e}")), t.clone()))
    }

    /// `cached` for a world holding peers beside state that is not `Clone` (a property's run):
    /// `copy` copies it whole, its peers by `copy`.
    #[cfg(test)]
    pub(crate) fn cached_world<W: Send + 'static>(key: &str, build: impl FnOnce() -> W, copy: impl FnOnce(&mut W) -> W) -> W {
        osis_base::copying::cached(key, build, copy)
    }

    /// Every other peer holding no role on `t` is granted read on it through the flow by peer
    /// `admin`, an admin of it, given the grant's commits (as its grant fire carries them), and
    /// holds it (`hold`): each keeps what it receives of `t`, as only content of a thing in the
    /// node closure applies (spec/commits.md §4 Outside the node closure).
    #[allow(clippy::panic, clippy::indexing_slicing)] // test harness: a grant that fails fails the test (and a peer index past the net)
    pub fn share(&mut self, admin: usize, t: Tid) {
        let mut given = Vec::new();
        for j in (0..self.peers.len()).filter(|j| *j != admin) {
            let who = self.peers[j].engine.tid();
            if self.peers[admin].engine.key_role(&t, &who).is_none() {
                let edge = osis_schema::core_types::Edge { role: osis_base::Role::Read, until: None, may_grant: false, retain: false, floor: None };
                let done = self.peers[admin].engine.grant(&t, &who, &edge).unwrap_or_else(|e| panic!("grant {t:?}: {e}"));
                given.push((j, done.commits));
            }
        }
        self.hold(t);
        for (j, commits) in given {
            for c in commits {
                if let Some(pk) = self.peers[admin].engine.package(&c).unwrap_or_else(|e| panic!("package: {e}")) {
                    self.deliver(j, &pk).unwrap_or_else(|e| panic!("deliver: {e}"));
                }
            }
        }
    }

    /// A fresh node with an account of its own (`Peer::new` at peer `admin`'s time, seeded
    /// `seed`, `make_account`) whose account holds `t` and is granted read on it by peer
    /// `admin` through the flow, given the grant's offer alone (a fire on the account's inbox):
    /// it keeps what it is then given of `t` in any order, as content waits until `t` enters its
    /// node closure (spec/commits.md §4 Outside the node closure). Peer `admin` has imported the
    /// account's contact card (`Peer::import_contact`): it holds the account's card.
    #[allow(clippy::panic, clippy::indexing_slicing)] // test harness: a setup that fails fails the test (and a peer index past the net)
    pub fn fresh_reader(&mut self, admin: usize, t: Tid, seed: u64) -> Peer {
        let mut p = Peer::new(seed, self.peers[admin].engine.now()).unwrap_or_else(|e| panic!("fresh node: {e}"));
        let (acc, _) = make_account(&mut p.engine).unwrap_or_else(|e| panic!("account: {e}"));
        for id in p.engine.commit_ids() {
            if let Some(pk) = p.engine.package(&id).unwrap_or_else(|e| panic!("package: {e}")) {
                self.deliver(admin, &pk).unwrap_or_else(|e| panic!("deliver: {e}"));
            }
        }
        let link = p.engine.locator(&acc.profile, Vec::new()).ok().flatten().unwrap_or_else(|| panic!("the profile is not public"));
        self.peers[admin].import_contact(&link).unwrap_or_else(|e| panic!("the account's contact card: {e}"));
        let mut m = Mutation::new();
        m.op(acc.thing, &osis_schema::core_types::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(t)) }).unwrap_or_else(|e| panic!("hold {t:?}: {e}"));
        p.commit(m).unwrap_or_else(|e| panic!("hold {t:?}: {e}"));
        let who = acc.thing;
        let edge = osis_schema::core_types::Edge { role: osis_base::Role::Read, until: None, may_grant: false, retain: false, floor: None };
        let done = self.peers[admin].engine.grant(&t, &who, &edge).unwrap_or_else(|e| panic!("grant {t:?}: {e}"));
        self.pass_fires_to(admin, &mut p).unwrap_or_else(|e| panic!("grant fire to the reader: {e}"));
        for c in &done.commits {
            if let Some(pk) = self.peers[admin].engine.package(c).unwrap_or_else(|e| panic!("package: {e}")) {
                p.receive(&pk.bytes, pk.blobs.clone()).unwrap_or_else(|e| panic!("grant to the reader: {e}"));
            }
        }
        p
    }

    /// Every peer not holding `t` holds it from its node root (`hold_at`).
    pub fn hold(&mut self, t: Tid) {
        for i in 0..self.peers.len() {
            self.hold_at(i, t);
        }
    }

    /// Peer `i` holds `t` from its node root (`Engine::hold`) unless its node closure does: a
    /// node keeps what it receives only while something it holds needs it, so a peer a test
    /// shares a thing with holds it, as a real node takes only what it holds.
    #[allow(clippy::panic)] // test harness: a hold that fails fails the test
    pub fn hold_at(&mut self, i: usize, t: Tid) {
        if let Some(p) = self.peers.get_mut(i).filter(|p| !p.engine.closure_holds(&t)) {
            p.engine.hold(osis_base::Strong(t)).unwrap_or_else(|e| panic!("hold {t:?}: {e}"));
        }
    }

    pub fn peer(&mut self, i: usize) -> Option<&mut Peer> {
        self.peers.get_mut(i)
    }

    /// The IDs of the commits `from` holds (applied) but those on its node root alone: what its
    /// syncs may send (`packages_for`).
    pub fn commit_ids(&self, from: usize) -> BTreeSet<CommitId> {
        let Some(p) = self.peers.get(from) else { return BTreeSet::new() };
        let root = p.engine.node_root();
        p.engine.commit_ids().into_iter().filter(|id| !p.engine.header(id).is_some_and(|h| h.aspects.iter().all(|a| Some(a.tid) == root))).collect()
    }

    /// What `from` sends a node syncing `t`'s sync IDs (as `from` holds them) alone:
    /// `packages_under` them.
    pub fn packages_of(&mut self, from: usize, t: &Tid) -> Result<Vec<Package>> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(Vec::new()) };
        let synced = p.engine.sync_ids(t)?.iter().map(|o| o.id).collect();
        self.packages_under(from, &synced)
    }

    /// What `from` sends peer `to` in a sync: `packages_under` the sync IDs `to` syncs.
    pub fn packages_for(&mut self, from: usize, to: usize) -> Result<Vec<Package>> {
        let synced = self.synced(to)?;
        self.packages_under(from, &synced)
    }

    /// What `from` sends peer `to` once `to` syncs what a sync from `from` brings it to sync (its
    /// sync set after `sync`, on a copy of the world: a grant or rotation it takes moves its sync
    /// IDs): `packages_under` those, for a test handing them over in its own order.
    pub fn packages_to(&mut self, from: usize, to: usize) -> Result<Vec<Package>> {
        let mut c = self.copy()?;
        c.sync(from, to)?;
        let synced = c.synced(to)?;
        self.packages_under(from, &synced)
    }

    /// `packages_to` for `to`, a node apart from this net, given the fires `from` owes it first
    /// (`pass_fires_to`): what `from` sends it once it syncs what those packages bring it to sync (found on a copy of it, handed them again while its
    /// sync set grows).
    pub fn packages_to_peer(&mut self, from: usize, to: &mut Peer) -> Result<Vec<Package>> {
        self.pass_fires_to(from, to)?;
        let mut c = to.copy()?;
        let mut seen = BTreeSet::new();
        loop {
            let synced: BTreeSet<osis_base::SyncId> = c.engine.sync_set()?.ids.keys().copied().collect();
            if !seen.is_empty() && synced.is_subset(&seen) {
                return self.packages_under(from, &seen);
            }
            seen.extend(synced);
            for p in self.packages_under(from, &seen)?.iter() {
                let _ = c.receive(&p.bytes, p.blobs.clone());
            }
        }
    }

    /// The sync IDs peer `i` syncs (`Engine::sync_set`).
    pub fn synced(&mut self, i: usize) -> Result<BTreeSet<osis_base::SyncId>> {
        match self.peers.get_mut(i) {
            Some(p) => Ok(p.engine.sync_set()?.ids.keys().copied().collect()),
            None => Ok(BTreeSet::new()),
        }
    }

    /// What `from` sends a node syncing the sync IDs `synced`, in `packages` order: each held
    /// commit holding the parts those sync IDs carry as `from` sees them (`Engine::carried_under`,
    /// the rule node-sync's bodies follow, spec/sync-judgement.md §1-§2) and its certificate
    /// parts (`Engine::certificate_parts`); a commit with neither is not sent. So a node is never
    /// given content of a thing no sync ID it syncs carries, which would wait there
    /// (spec/commits.md §4 Outside the node closure). Certificates go to every node: they stand
    /// for the routes the harness does not play (contact cards, links, offers, a grant
    /// under its holder's sync ID, pairing), and a node keeps of them only what it needs
    /// (spec/commits.md §5 What a held thing needs).
    pub fn packages_under(&mut self, from: usize, synced: &BTreeSet<osis_base::SyncId>) -> Result<Vec<Package>> {
        Ok(self.packages_hashed(from, synced)?.iter().map(|s| s.0.clone()).collect())
    }

    /// `pk`, a commit peer `from` holds, holding only the parts it sends a node syncing `synced`
    /// (`Engine::sent_parts`; a header alone where it sends none): a package made earlier, trimmed
    /// as `from` sees it now. As it was where `from` holds no such commit.
    pub fn trimmed(&mut self, from: usize, pk: &Package, synced: &BTreeSet<osis_base::SyncId>) -> Result<Package> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(pk.clone()) };
        if p.engine.header(&pk.id).is_none() {
            return Ok(pk.clone());
        }
        let parts = p.engine.sent_parts(&pk.id, synced)?.unwrap_or_default();
        Ok(holding(pk, &CommitBlob::decode(&pk.bytes)?, &parts))
    }

    /// Delivers to `to` the commits of `from`'s certificates for `t` (`Engine::certificates`),
    /// each holding the parts they name (its cut, spec/permissions.md §4 Copies; a header alone
    /// for a header the certificates name alone): what `t`'s sync ID carries beside its bodies
    /// but its record blobs and mintings. A test handing `to` a
    /// commit on `t` by hand sends this first: a pass end drops what nothing held needs, so a
    /// thing is judged only with its certificates delivered again, as a sync of `t` brings it.
    #[cfg(test)]
    pub(crate) fn send_certificates(&mut self, from: usize, to: usize, t: &Tid) -> Result<()> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(()) };
        let certs = p.engine.certificates(t)?;
        let mut cut: BTreeMap<CommitId, BTreeSet<usize>> = certs.commits.clone();
        for id in &certs.headers {
            cut.entry(*id).or_default();
        }
        let mut pks = Vec::new();
        for (id, parts) in &cut {
            pks.extend(p.engine.package_of_parts(id, parts)?);
        }
        for pk in pks {
            self.deliver(to, &pk)?;
        }
        Ok(())
    }

    /// Offers peer `to` each sealed fire another peer owes (spec/sync-inbox.md §3 Sending) on a
    /// thing `to` holds a read secret of, until `to` takes it. A fire `to` refuses fails the test unless the thing's setting, as `to` holds it,
    /// does not enable the signal (the one refusal the rules give); it is
    /// offered again once that setting enables it.
    #[allow(clippy::indexing_slicing, clippy::panic)] // test harness: indexes below the peer count; a refused fire fails the test
    pub fn pass_fires(&mut self, to: usize) -> Result<()> {
        if self.memo.fires_held {
            return Ok(());
        }
        let n = self.peers.len();
        for p in &mut self.peers {
            p.engine.fire_own()?;
            p.wake()?;
        }
        for from in (0..n).filter(|i| *i != to && to < n) {
            if self.memo.fires_held_of.contains(&from) {
                continue;
            }
            for id in self.peers[from].engine.fires_owed() {
                if self.memo.fired.contains(&(from, id, to)) {
                    continue;
                }
                let Some(o) = self.peers[from].engine.core.ix.fires.get(&id).cloned() else { continue };
                if !self.peers[to].engine.epochs(&o.thing).is_some_and(|e| e.read.holds_any()) {
                    continue;
                }
                // one `to` refused is offered again once the thing's setting enables its signal there
                let enabled = |e: &crate::Engine| crate::apply::validity::enabled(&e.core, &o.thing).contains(&o.ak);
                if self.memo.refused.contains(&(from, id, to)) && !enabled(&self.peers[to].engine) {
                    continue;
                }
                let Some(out) = self.peers[from].engine.sealed_fire(&id)? else { continue };
                match self.peers[to].engine.offer_fire(&out)? {
                    crate::sync::Opened::Bad => {
                        assert!(!enabled(&self.peers[to].engine), "peer {to} refused peer {from}'s {:?} fire on {:?}, which its setting enables", o.ak, o.thing);
                        self.memo.refused.insert((from, id, to));
                    }
                    // sealed to a keyset `to` does not hold yet: offered again
                    crate::sync::Opened::NotOpen => {}
                    _ => drop(self.memo.fired.insert((from, id, to))),
                }
            }
        }
        Ok(())
    }

    /// Holds every fire back (`on`) or lets them pass again: a test of what a node does with a
    /// grant's commit before its fire reaches it holds them, delivers, then lets them pass
    /// (fires and commits travel apart).
    pub fn hold_fires(&mut self, on: bool) {
        self.memo.fires_held = on;
    }

    /// Holds back the fires peer `from` owes (`on`) or lets them pass again: a test in which some
    /// peers stay unaware of a write of `from`'s keeps its fire from them as it keeps the commit.
    #[cfg(test)]
    pub(crate) fn hold_fires_of(&mut self, from: usize, on: bool) {
        match on {
            true => drop(self.memo.fires_held_of.insert(from)),
            false => drop(self.memo.fires_held_of.remove(&from)),
        }
    }

    /// Peer `i`, an admin of thing `t`, writes `t`'s setting enabling its inbox signals as an
    /// account's inbox has them and `t`'s card on `t` itself (spec/sync-inbox.md §1).
    #[allow(clippy::panic, clippy::indexing_slicing)] // test harness: a setup that fails fails the test
    pub fn takes_grants(&mut self, i: usize, t: Tid) {
        let mut setting = osis_schema::core_types::RetentionSetting::default();
        setting.take_inbox_signals();
        let mut m = Mutation::new();
        m.set(t, &osis_schema::core_types::RETENTION, &setting).unwrap_or_else(|e| panic!("setting of {t:?}: {e}"));
        self.peers[i].commit(m).unwrap_or_else(|e| panic!("setting of {t:?}: {e}"));
        // its card, its keys filled in once it has them (`Engine::take_cards`)
        let card = crate::flows::cards::put(t, t, &osis_schema::core_types::Card::default()).unwrap_or_else(|e| panic!("card of {t:?}: {e}"));
        self.peers[i].commit(card).unwrap_or_else(|e| panic!("card of {t:?}: {e}"));
        // keysets written before the card carry no KEM key it gives (spec/crypto.md §3): KEM key
        // due rotates them, here at once rather than at a pass's end
        if self.peers[i].engine.core.is_independent(&t) {
            self.peers[i].engine.kem_key_due(&t).unwrap_or_else(|e| panic!("KEM keys of {t:?}: {e}"));
        }
    }

    /// `pass_fires` from peer `from` to `p`, a peer outside the net, every fire each call on a
    /// thing `p` holds a read secret of. A fire `p` refuses
    /// though the thing's setting, as `p` holds it, enables its signal fails the test.
    #[allow(clippy::indexing_slicing, clippy::panic)] // test harness: an index below the peer count; a refused fire fails the test
    pub fn pass_fires_to(&mut self, from: usize, p: &mut Peer) -> Result<()> {
        for id in self.peers[from].engine.fires_owed() {
            let Some(o) = self.peers[from].engine.core.ix.fires.get(&id).cloned() else { continue };
            if !p.engine.epochs(&o.thing).is_some_and(|e| e.read.holds_any()) {
                continue;
            }
            let Some(out) = self.peers[from].engine.sealed_fire(&id)? else { continue };
            let opened = p.engine.offer_fire(&out)?;
            let enabled = crate::apply::validity::enabled(&p.engine.core, &o.thing).contains(&o.ak);
            assert!(!matches!(opened, crate::sync::Opened::Bad) || !enabled, "the peer refused peer {from}'s {:?} fire on {:?}, which its setting enables", o.ak, o.thing);
        }
        Ok(())
    }

    /// Delivers one package to peer `to`, after the fires it is owed (`pass_fires`).
    pub fn deliver(&mut self, to: usize, pk: &Package) -> Result<Ingested> {
        self.pass_fires(to)?;
        match self.peers.get_mut(to) {
            Some(p) => p.receive(&pk.bytes, pk.blobs.clone()),
            None => Ok(Ingested::Duplicate(pk.id)),
        }
    }

    /// Peer `i`'s role duty as sync's `Life` runs it: for each held actor whose
    /// `Engine::role_duty_due` is true, `Engine::ensure_rotated`. The rotations it wrote.
    pub fn role_duties(&mut self, i: usize) -> Result<Vec<CommitId>> {
        let Some(p) = self.peers.get_mut(i) else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for a in p.engine.held_actors() {
            if p.engine.role_duty_due(&a)? {
                out.extend(p.engine.ensure_rotated(&a)?.0.commits);
            }
        }
        Ok(out)
    }

    /// Commits `from` holds, sealed (`Engine::seal_package`) as they stand: the harness makes no
    /// rotation (sync's role duty does: `role_duties`, which a test calls where a node's step
    /// would run it).
    pub fn sealed(&mut self, from: usize, ids: &[CommitId]) -> Result<Vec<SealedPackage>> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for id in ids {
            if let Some(pk) = p.engine.seal_package(id, &mut self.rng)? {
                out.push(pk);
            }
        }
        Ok(out)
    }

    /// Delivers sealed packages to `to`, all again while a pass applies or learns anything (a
    /// secret one carries opens another; a thing one brings in opens its sections in another, as
    /// the sync store opens a parked entry again, spec/sync-judgement.md §1 Sealed sections); the
    /// IDs of those none of whose bodies opened.
    pub fn deliver_sealed(&mut self, to: usize, pks: &[SealedPackage]) -> Result<Vec<CommitId>> {
        self.pass_fires(to)?;
        let Some(p) = self.peers.get_mut(to) else { return Ok(pks.iter().map(|x| x.id).collect()) };
        loop {
            let mut moved = false;
            let mut left = Vec::new();
            for pk in pks {
                let (got, learned) = p.engine.open_package_counted(pk)?;
                moved |= learned > 0 || got.iter().any(|i| matches!(i, Ingested::Applied(_)));
                if got.is_empty() {
                    left.push(pk.id);
                }
            }
            if !moved {
                return Ok(left);
            }
        }
    }

    /// Every peer keeps every other's account (`know_all`), then sends everything `from` holds to
    /// `to` (in `ts` order), but what `to` already took as a duplicate that changed nothing and
    /// still holds whole (`Engine::holds_whole`); a pass, so `to` settles its needs after
    /// (`Engine::settle_needs`).
    pub fn sync(&mut self, from: usize, to: usize) -> Result<()> {
        self.know_all()?;
        self.sync_changed(from, to)?;
        // the pass ended: what it brought that `to` needs nothing of goes
        self.pass_end(to)
    }

    /// Every commit `from` holds (applied), packaged whole, but those on its node root alone
    /// (local: no sync ID carries them, spec/sync-set.md §1), in (`ts`, ID) order, with each
    /// commit's record, hash and things (`SyncMemo::whole`): what `packages_hashed` trims.
    fn whole(&mut self, from: usize) -> Result<Arc<Vec<Arc<Whole>>>> {
        let Some(p) = self.peers.get_mut(from) else { return Ok(Arc::default()) };
        let at = p.engine.point();
        let m = self.memo.whole.entry(from).or_default();
        if let Some((_, v)) = m.at.as_ref().filter(|(w, _)| *w == at) {
            return Ok(v.clone());
        }
        let ids = p.engine.commit_ids();
        let now: HashSet<CommitId> = ids.iter().copied().collect();
        let gone: Vec<CommitId> = m.held.keys().filter(|c| !now.contains(c)).copied().collect();
        for c in gone {
            m.each.unwant(&c);
            m.held.remove(&c);
        }
        for c in &ids {
            m.each.want(*c);
        }
        let root = p.engine.node_root();
        for c in m.each.due() {
            let (e, mut made) = (&mut p.engine, None);
            m.each.try_settle(&c, || -> Result<Option<u64>> {
                if e.header(&c).is_some_and(|h| h.aspects.iter().all(|a| Some(a.tid) == root)) {
                    return Ok(None);
                }
                let Some((pk, b)) = e.package_with_record(&c)? else { return Ok(None) };
                let n = hash_of(&pk);
                let on = b.header.aspects.iter().map(|a| a.tid).collect();
                made = Some(Arc::new(((pk, n, on), b)));
                Ok(Some(n))
            })?;
            match made {
                Some(w) => m.held.insert(c, w),
                None => m.held.remove(&c),
            };
        }
        let v = Arc::new(ids.iter().filter_map(|c| m.held.get(c).cloned()).collect::<Vec<_>>());
        m.at = Some((at, v.clone()));
        Ok(v)
    }

    /// `packages_under(from, synced)`, hashed, kept while `from`'s engine stands: each whole
    /// package (`whole`) holding the parts sent (`Engine::sent_parts`), trimmed again only where
    /// the package or the parts moved.
    fn packages_hashed(&mut self, from: usize, synced: &BTreeSet<osis_base::SyncId>) -> Result<Hashed> {
        let at = self.peers.get(from).map(|p| p.engine.point()).unwrap_or_default();
        let key = (from, synced.iter().copied().collect::<Vec<_>>());
        if let Some((_, v)) = self.memo.sent.get(&key).and_then(|m| m.at.as_ref()).filter(|(p, _)| *p == at) {
            return Ok(v.clone());
        }
        let whole = self.whole(from)?;
        let Some(p) = self.peers.get_mut(from) else { return Ok(Arc::default()) };
        let m = self.memo.sent.entry(key).or_default();
        let mut each = HashMap::new();
        let mut out = Vec::new();
        for w in whole.iter() {
            let ((pk, n, on), b) = &**w;
            let Some(parts) = p.engine.sent_parts(&pk.id, synced)? else { continue };
            let sent = match m.each.remove(&pk.id).filter(|x| x.0 == *n && x.1 == parts) {
                Some(x) => x.2,
                None if b.parts.iter().all(|x| parts.contains(&x.ai)) => Arc::new((pk.clone(), *n, on.clone())),
                None => {
                    let t = holding(pk, b, &parts);
                    let h = hash_of(&t);
                    Arc::new((t, h, on.clone()))
                }
            };
            out.push(sent.clone());
            each.insert(pk.id, (*n, parts, sent));
        }
        let v: Hashed = Arc::new(out);
        *m = Trimmed { at: Some((at, v.clone())), each };
        Ok(v)
    }

    /// `sync`; whether any delivery was more than a duplicate. `from` sends what the sync IDs
    /// `to` syncs carry (`packages_for`), again under those `to` came to sync meanwhile (a grant
    /// bringing a thing in: its sync IDs join in the pass). A package `to` dropped at an earlier
    /// pass end goes only once which of its things `to` needs moved since.
    fn sync_changed(&mut self, from: usize, to: usize) -> Result<bool> {
        self.pass_fires(to)?;
        osis_base::testenv::checkpoint();
        let mut changed = false;
        let mut seen = BTreeSet::new();
        // each round after the first runs once `to` syncs a sync ID not synced before: at most
        // one per sync ID it comes to sync
        loop {
            let synced = self.synced(to)?;
            if changed && synced.is_subset(&seen) {
                return Ok(changed);
            }
            seen.extend(synced.iter().copied());
            if !self.sync_under(from, to, &synced)? {
                return Ok(changed);
            }
            changed = true;
        }
    }

    /// One round of `sync_changed`, to a node syncing `synced`. A package `to` dropped at an
    /// earlier pass end goes only once which of its things `to` needs moved since, checked again
    /// after the rest (what arrived may need it: a thing whose record awaits its parent's).
    fn sync_under(&mut self, from: usize, to: usize, synced: &BTreeSet<osis_base::SyncId>) -> Result<bool> {
        let mut changed = self.send_sync_copies(from, to, synced)?;
        let pks = self.packages_hashed(from, synced)?;
        let dropped: Vec<&Sent> = pks.iter().map(|pk| &**pk).filter(|pk| self.memo.dropped.contains_key(&(to, pk.1))).collect();
        let still = self.still_dropped(to, &dropped)?;
        let mut held_back = Vec::new();
        for pk in pks.iter().map(|pk| &**pk) {
            if still.contains(&pk.1) {
                held_back.push(pk);
            } else {
                changed |= self.offer(to, pk)?;
            }
        }
        loop {
            let still = self.still_dropped(to, &held_back)?;
            let (later, now): (Vec<&Sent>, Vec<&Sent>) = held_back.into_iter().partition(|pk| still.contains(&pk.1));
            if now.is_empty() {
                return Ok(changed);
            }
            for pk in now {
                changed |= self.offer(to, pk)?;
            }
            held_back = later;
        }
    }

    /// The sync copies `from` carries under the sync IDs `to` syncs (`Engine::sync_copies_carried`)
    /// taken at `to` under the thing reading each there, one blob per content (its key standing
    /// for its blob ID): whether any was new there.
    fn send_sync_copies(&mut self, from: usize, to: usize, synced: &BTreeSet<osis_base::SyncId>) -> Result<bool> {
        let mut changed = false;
        for s in synced {
            let Some(p) = self.peers.get_mut(from) else { return Ok(false) };
            let carried = p.engine.sync_copies_carried(s)?;
            if carried.is_empty() {
                continue;
            }
            let Some(q) = self.peers.get_mut(to) else { return Ok(false) };
            let reading = q.engine.read_things_of(s)?;
            for (k, (t, plain)) in carried.iter() {
                let b = osis_base::BlobId(*k);
                if !reading.contains(t) || q.engine.core.ix.sync_copy_on.contains_key(&b) {
                    continue;
                }
                changed |= q.engine.take_sync_copy(t, &b, plain)?;
            }
        }
        Ok(changed)
    }

    /// The hashes of those of `pks` that `to` dropped at a pass end and whose things it needs as
    /// it did then, none of them in its node closure or awaited since (one entering it is fetched again,
    /// spec/sync-judgement.md §3 Dropped bodies).
    fn still_dropped(&mut self, to: usize, pks: &[&Sent]) -> Result<HashSet<u64>> {
        let Some(p) = self.peers.get_mut(to) else { return Ok(HashSet::new()) };
        if pks.is_empty() {
            return Ok(HashSet::new());
        }
        let mut known = self.memo.needed.remove(&to);
        let needed = p.needed(pks.iter().flat_map(|pk| pk.2.iter()), &mut known)?;
        self.memo.needed.extend(known.map(|k| (to, k)));
        let dropped = &self.memo.dropped;
        // one of its things awaited there goes again: what awaits a record learns it from the
        // record blob a pass fetches first (spec/commits.md §4 Records)
        Ok(pks.iter().filter(|pk| dropped.get(&(to, pk.1)).is_some_and(|was| pk.2.iter().all(|t| needed.contains(t) == was.contains(t) && !p.engine.closure_holds(t) && !crate::apply::awaits_record(&p.engine.core, t)))).map(|pk| pk.1).collect())
    }

    /// Delivers `pk` to `to` but where it came back a duplicate that changed nothing at `to` as
    /// it stands, or `to` holds every body of it after such a duplicate; whether it changed
    /// anything.
    fn offer(&mut self, to: usize, (pk, hash, on): &Sent) -> Result<bool> {
        let key = (to, *hash);
        let at = self.peers.get(to).map(|p| p.engine.point());
        if at.is_some() && self.memo.duplicate.get(&key).copied() == at {
            return Ok(false);
        }
        // once a no-op duplicate there, never sent again while `to` holds every body of it:
        // what a sync sends is what the receiver lacks (a body-less part may come back late)
        if self.memo.duplicate.contains_key(&key) && self.peers.get(to).is_some_and(|p| p.engine.holds_whole(&pk.id)) {
            return Ok(false);
        }
        let dup = matches!(self.deliver(to, pk)?, Ingested::Duplicate(_));
        if let Some(after) = self.peers.get(to).map(|p| p.engine.point()).filter(|a| dup && Some(*a) == at) {
            self.memo.duplicate.insert(key, after);
        }
        if !dup {
            self.memo.dropped.remove(&key);
            self.memo.in_pass.entry(to).or_default().push((*hash, pk.id, on.clone()));
        }
        Ok(!dup)
    }

    /// Peer `to`'s pass ended (`Engine::settle_needs`): what it delivered that `to` dropped, on
    /// things outside its node closure, is noted (`SyncMemo::dropped`).
    fn pass_end(&mut self, to: usize) -> Result<()> {
        let Some(p) = self.peers.get_mut(to) else { return Ok(()) };
        p.engine.settle_needs()?;
        let gone: Vec<(u64, Vec<Tid>)> = self.memo.in_pass.remove(&to).unwrap_or_default().into_iter().filter(|(_, id, on)| !p.engine.core.ix.pending.contains_key(id) && !p.engine.holds_whole(id) && !on.iter().any(|t| p.engine.closure_holds(t))).map(|(h, _, on)| (h, on)).collect();
        let mut known = self.memo.needed.remove(&to);
        let needed = p.needed(gone.iter().flat_map(|(_, on)| on.iter()), &mut known)?;
        self.memo.needed.extend(known.map(|k| (to, k)));
        for (hash, on) in gone {
            self.memo.dropped.insert((to, hash), on.into_iter().filter(|t| needed.contains(t)).collect());
        }
        Ok(())
    }

    /// Every peer keeps every other's account (`know_all`), then syncs every ordered pair until a
    /// round changes nothing (at most `n` rounds), then every peer settles its needs
    /// (`Engine::settle_needs`). A round in which every delivery was a duplicate is a fixpoint:
    /// the next would deliver the same packages to the same states.
    pub fn sync_all(&mut self) -> Result<()> {
        self.know_all()?;
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
        self.settle_needs()
    }

    /// Every peer's passes ended (`Engine::settle_needs`): what they brought that nothing held
    /// needs goes.
    pub fn settle_needs(&mut self) -> Result<()> {
        for i in 0..self.peers.len() {
            self.pass_end(i)?;
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

/// An account's pairing and removal as osis-account arranges them (spec/permissions.md §8), on
/// the engine, for the harnesses: the library makes the same writes through the `osis` API.
impl Engine {
    /// What a new node shows the pairing node: its node thing's public key record.
    pub fn node_keys(&mut self) -> Result<osis_blob::Certificates> {
        let me = self.core.tid();
        self.holder_keys(&me)
    }

    /// Pairs node thing `node`, shown by `keys` (`node_keys`), into account `a` at `role`: its
    /// grant on A. `Permission` unless this node holds admin on A; `BadInput` unless `keys` show
    /// `node`'s keys. What the new node is handed besides is A's locator (`locator`).
    pub fn pair(&mut self, a: &Tid, node: &Tid, keys: &osis_blob::Certificates, role: osis_base::Role) -> Result<crate::flows::Done> {
        let me = self.core.tid();
        if self.core.role_now(&me, a) != Some(osis_base::Role::Admin) {
            return Err(crate::error::Error::Permission { tid: *a, needs: osis_base::Role::Admin });
        }
        self.take_holder_keys(node, keys, None)?;
        if self.current_keys(node)?.is_empty() {
            return Err(crate::error::Error::BadInput("pairing: the keys shown are not the node's"));
        }
        let edge = osis_schema::core_types::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        self.grant(a, node, &edge)
    }

    /// Holds account `a` by a strong from the node root and names it in `settings^.0`: the new
    /// node's half of pairing beside redeeming A's locator, by which it reaches A.
    pub fn take_pairing(&mut self, a: &Tid) -> Result<crate::flows::Done> {
        let root = self.core.node_root.ok_or(crate::error::Error::Misuse("no node root"))?;
        let mut done = crate::flows::Done::default();
        let mut m = Mutation::new();
        m.op(root, &osis_schema::core_types::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(osis_base::Value::Strong(*a)) })?;
        m.set(root, &osis_schema::core_types::SETTINGS, &osis_base::Weak(*a))?;
        done.add(self.commit(m)?);
        Ok(done)
    }

    /// Removes node thing `node` from account `a`: the removal of its grant with A's rotation,
    /// saying erase unless `retain`; then its `dial.0` entries on A and on each of `also` (A's
    /// profile) and its `caps^.0` entry on A. `Permission` unless this node holds admin on A.
    pub fn remove_node(&mut self, a: &Tid, node: &Tid, retain: bool, also: &[Tid]) -> Result<crate::flows::Done> {
        use osis_schema::core_types as ct;
        let me = self.core.tid();
        if self.core.role_now(&me, a) != Some(osis_base::Role::Admin) {
            return Err(crate::error::Error::Permission { tid: *a, needs: osis_base::Role::Admin });
        }
        let mut done = self.demote(a, &crate::flows::Demotion { holder: *node, new: None, retain: Some(retain) })?;
        let key = osis_base::Value::Weak(*node);
        let mut m = Mutation::new();
        for t in std::iter::once(*a).chain(also.iter().copied()) {
            if self.role_on(&t) >= Some(osis_base::Role::Write) && self.get_typed(&t, &ct::DIAL)?.unwrap_or_default().contains_key(&osis_base::Weak(*node)) {
                m.op(t, &ct::DIAL, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(key.clone()) })?;
            }
        }
        if self.get_typed(a, &ct::CAPS)?.unwrap_or_default().contains_key(&osis_base::Weak(*node)) {
            m.op(*a, &ct::CAPS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Remove(key) })?;
        }
        if !m.is_empty() {
            done.add(self.commit(m)?);
        }
        Ok(done)
    }
}
