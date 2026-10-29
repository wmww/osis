//! Synced ephemeral data (notes/ephemeral.md Synced ephemeral data): ordinary signed commits
//! with the header's ephemeral marker, of snapshot form (spec/commits.md §2), held in memory
//! (`Remote::held`, the ephemeral commit records) and never stored. Own writes on things in a
//! labeled closure collect in `unsent` and go out as ephemeral commits built here
//! (`take_ephemeral`); signal writes go as relay-only commits. Received ephemeral commits are
//! verified like any commit and judged like compaction snapshots (spec/permissions.md §5.2: a
//! part is valid iff its author could write the aspect at its `ts`, by commit ID); the writes a
//! part carries go with it. Valid parts join the ephemeral state; a held commit whose validity
//! flips rebuilds the aspects it touches from the own writes and the valid held parts (un-merge,
//! spec/crdt.md §4.6). A held commit is dropped once valid held commits list it as absorbed on
//! every aspect it touches (a compaction, `compact_ephemeral`). Relay-only commits are delivered
//! once (`delivered`, bounded) and held by nobody.

use super::{Eph, EphAspect, EphThing};
use crate::engine::Engine;
use crate::engine::secrets::{CommitSecrets, published_keys};
use crate::engine::write::{Creates, required_role, run_ops};
use crate::error::{Error, Result};
use crate::events::{ChangeId, Event, Origin};
use osis_base::format::{MAX_DRIFT_MS, MAX_OWNER_DEPTH};
use osis_base::{Ak, CommitId, CreationRecord, Tid, Ts, Value};
use osis_commit::{AspectWrite, CommitBlob, CommitBuilder, EphClass, Form, Header, Kind, MemoryBlobs};
use osis_crdt::{AnyView, Fragment, Frontiers, Interner, Op, PathOp, Snapshot, Source, SourceKind, Writer};
use osis_crypto::{DeleteSecret, VerifyingKey, dedup_secret};
use osis_perm::{Dots, Point, Validity};
use osis_schema::AspectKey;
use osis_schema::core_types::{CREATED, GROUP, is_membership_class};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// Relay-only commit IDs remembered as delivered (notes/ephemeral.md Bounds): past this count the
/// oldest is forgotten, so a duplicate over a second server may fire twice; resource bound
/// against a hostile writer (0: no dedup, infinity: unbounded memory).
pub const MAX_DELIVERED: usize = 1 << 16;

/// Held bytes of an aspect's ephemeral bodies above which a writer compacts it, besides the
/// "twice its state" rule (notes/ephemeral.md Compaction). Performance switch: 0 compacts per
/// write, infinity never (bodies pile up until a cap).
pub const COMPACT_FLOOR: usize = 64 << 10;

/// One delta of an ephemeral commit to build: thing, aspect, fragment, expiry.
type EphDelta = (Tid, Ak, Fragment, Option<u64>);

/// Unsent own deltas of one aspect by (actor written for, expiry).
type Unsent = BTreeMap<(Tid, Option<u64>), Fragment>;

/// A held ephemeral commit (in memory).
pub(crate) struct Held {
    pub header: Arc<Header>,
    /// (aspect index, fragment, the commits it lists as absorbed) per part held.
    pub parts: Vec<(usize, Fragment, BTreeSet<CommitId>)>,
    /// Per part: valid here (spec/permissions.md §5.2).
    pub valid: Vec<bool>,
    /// Built by this node (its writes are in the own state already).
    pub own: bool,
    /// The approximate bytes of its parts.
    pub bytes: usize,
}

/// The synced side of the ephemeral state.
#[derive(Default)]
pub(crate) struct Remote {
    /// Own deltas not yet in an ephemeral commit, of things that sync: per aspect, per (actor
    /// they were written for, expiry).
    pub unsent: BTreeMap<(Tid, Ak), Unsent>,
    /// Signal writes not yet sent: (thing, aspect, value, `ts`, actor).
    pub signals: Vec<(Tid, Ak, Value, Ts, Tid)>,
    /// Ephemeral things whose record must travel with the next commit.
    pub records: BTreeSet<Tid>,
    /// Things with ephemeral state (or ephemeral things) written while in no labeled closure:
    /// their whole state goes once they enter one.
    pub local: BTreeSet<Tid>,
    /// The ephemeral commit records.
    pub held: BTreeMap<CommitId, Held>,
    /// Commits whose author's record, or a part's thing's, is not here yet (bounded by the sync
    /// layer's caps), retried when the durable state changes.
    pub pending: BTreeMap<CommitId, CommitBlob>,
    /// Ephemeral sessions and the node an `Authors` entry named for them.
    pub sessions: BTreeMap<CommitId, Tid>,
    /// Expiry times of held parts.
    pub timers: BTreeMap<u64, BTreeSet<(CommitId, usize)>>,
    /// Relay-only commits delivered, oldest first, with their `ts` (wall ms).
    pub delivered: VecDeque<(CommitId, u64)>,
    pub delivered_set: BTreeSet<CommitId>,
    /// `Core::generation` when held validity was last judged.
    pub judged_at: u64,
}

/// What became of a received ephemeral commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EphIngest {
    /// Held (new parts joined, or nothing new).
    Held { new: bool },
    /// Signals delivered (relay-only), or nothing: a duplicate or stale.
    Delivered { fired: bool },
    /// Waits for its author's record.
    Pending,
}

/// An ephemeral commit built here: its ID, class and blob (header and parts).
#[derive(Clone, Debug)]
pub struct EphCommit {
    pub id: CommitId,
    pub class: EphClass,
    pub blob: CommitBlob,
}

impl Engine {
    /// Whether `tid` is in some labeled closure here: synced itself, or in a group that is, through
    /// either side of `/group`.
    pub fn ephemeral_synced(&self, tid: &Tid) -> bool {
        let s = &self.core.ix.syncing;
        s.contains(tid) || self.groups_of(tid).iter().any(|g| s.contains(g))
    }

    /// The things of `g`'s closure (`Engine::closure`) and the ephemeral things placed in it,
    /// transitively through the ephemeral side of `/group`.
    pub fn ephemeral_closure(&self, g: &Tid) -> BTreeSet<Tid> {
        let mut out: BTreeSet<Tid> = self.closure(g).iter().copied().collect();
        if self.eph.defs.is_empty() {
            return out;
        }
        let mut stack: Vec<Tid> = out.iter().copied().collect();
        while let Some(t) = stack.pop() {
            if let Some((items, subs)) = self.eph.defs.get(&t) {
                for x in items.iter().chain(subs) {
                    for y in std::iter::once(*x).chain(self.closure(x).iter().copied()) {
                        if out.insert(y) {
                            stack.push(y);
                        }
                    }
                }
            }
        }
        out
    }

    /// Whether `t` is in the closure of `g` (`ephemeral_closure`), without walking it.
    pub fn in_ephemeral_closure(&self, g: &Tid, t: &Tid) -> bool {
        t == g || self.closure(g).contains(t) || self.groups_of(t).contains(g)
    }

    /// Whether own ephemeral writes or signals wait to be sent (`take_ephemeral`).
    pub fn has_unsent(&self) -> bool {
        let r = &self.eph.remote;
        !(r.unsent.is_empty() && r.signals.is_empty() && r.records.is_empty()) || r.local.iter().any(|t| self.ephemeral_synced(t))
    }

    /// Notes an own ephemeral write for sync: it joins `unsent` when the thing syncs, else the
    /// thing waits in `local`.
    pub(super) fn note_written(&mut self, tid: &Tid, ak: &Ak, delta: &Fragment, expires: Option<u64>, actor: Tid) {
        if self.ephemeral_synced(tid) {
            let r = &mut self.eph.remote;
            r.unsent.entry((*tid, ak.clone())).or_default().entry((actor, expires)).or_default().join(delta.clone());
            if self.eph.things.contains_key(tid) {
                self.eph.remote.records.insert(*tid);
            }
        } else {
            self.eph.remote.local.insert(*tid);
        }
    }

    /// Notes an own signal write for sync (things in a labeled closure only).
    pub(super) fn note_signal(&mut self, tid: &Tid, ak: &Ak, v: &Value, ts: Ts, actor: Tid) {
        if self.ephemeral_synced(tid) {
            self.eph.remote.signals.push((*tid, ak.clone(), v.clone(), ts, actor));
            if self.eph.things.contains_key(tid) {
                self.eph.remote.records.insert(*tid);
            }
        }
    }

    /// Notes a new ephemeral thing: its record goes once it is in a labeled closure.
    pub(super) fn note_created(&mut self, tid: &Tid) {
        self.eph.remote.local.insert(*tid);
    }

    /// Builds the ephemeral commits of everything unsent: one relay-only commit for the signals,
    /// one per expiry for state (with the records of the ephemeral things they touch), and the
    /// whole state of things that entered a labeled closure. Each is held here.
    pub fn take_ephemeral(&mut self) -> Result<Vec<EphCommit>> {
        let entered: Vec<Tid> = self.eph.remote.local.iter().filter(|t| self.ephemeral_synced(t)).copied().collect();
        for t in entered {
            self.eph.remote.local.remove(&t);
            if self.eph.things.contains_key(&t) {
                self.eph.remote.records.insert(t);
            }
            let aspects: Vec<(Ak, Fragment)> = self.eph.aspects.get(&t).map(|m| m.iter().map(|(ak, a)| (ak.clone(), whole_unexpiring(a, &self.eph.src))).collect()).unwrap_or_default();
            let me = self.tid();
            for (ak, f) in aspects {
                self.eph.remote.unsent.entry((t, ak)).or_default().entry((me, None)).or_default().join(f);
            }
        }
        let mut out = Vec::new();
        let signals = std::mem::take(&mut self.eph.remote.signals);
        let mut by_actor: BTreeMap<Tid, Vec<EphDelta>> = BTreeMap::new();
        for (tid, ak, v, ts, actor) in signals {
            let w = Writer::new(ts, self.eph.src.clone(), self.eph.next);
            if let Ok(Some((f, r))) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v) }], &AnyView) {
                self.eph.next = r.hi;
                by_actor.entry(actor).or_default().push((tid, ak, f, None));
            }
        }
        for (actor, deltas) in by_actor {
            if let Some(c) = self.build_ephemeral(EphClass::Relay, actor, deltas, &BTreeSet::new(), &BTreeMap::new())? {
                out.push(c);
            }
        }
        let unsent = std::mem::take(&mut self.eph.remote.unsent);
        let records = std::mem::take(&mut self.eph.remote.records);
        let mut by_class: BTreeMap<(Tid, Option<u64>), Vec<EphDelta>> = BTreeMap::new();
        for ((tid, ak), m) in unsent {
            for ((actor, exp), f) in m {
                // an expiry already past: those writes are gone
                if exp.is_some_and(|t| t <= self.now().0) {
                    continue;
                }
                by_class.entry((actor, exp)).or_default().push((tid, ak.clone(), f, exp));
            }
        }
        if by_class.is_empty() && !records.is_empty() {
            by_class.insert((self.tid(), None), Vec::new());
        }
        let mut first = true;
        for ((actor, _), deltas) in by_class {
            let recs = if std::mem::take(&mut first) { records.clone() } else { BTreeSet::new() };
            if let Some(c) = self.build_ephemeral(EphClass::Plain, actor, deltas, &recs, &BTreeMap::new())? {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// The `/created` fragment of ephemeral thing `t`: a register write of its record under the
    /// session source, minted once.
    fn created_fragment(&mut self, t: &Tid) -> Option<Fragment> {
        let th = self.eph.things.get(t)?;
        if let Some(f) = &th.created {
            return Some(f.clone());
        }
        let (rec, ts) = (th.record.to_value(), th.ts);
        let w = Writer::new(ts, self.eph.src.clone(), self.eph.next);
        let (f, r) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(rec) }], &AnyView).ok()??;
        self.eph.next = r.hi;
        if let Some(th) = self.eph.things.get_mut(t) {
            th.created = Some(f.clone());
        }
        Some(f)
    }

    /// Builds, signs and holds one ephemeral commit of `deltas` (thing, aspect, fragment,
    /// expiry), carrying the records of `records` and of the ephemeral things the deltas touch
    /// with their ephemeral owner chains; `absorbed`: per aspect, the held commits it covers.
    /// `None` when it would carry nothing or cannot be built (a delete key not held: reported).
    fn build_ephemeral(&mut self, class: EphClass, actor: Tid, deltas: Vec<EphDelta>, records: &BTreeSet<Tid>, absorbed: &BTreeMap<(Tid, Ak), BTreeSet<CommitId>>) -> Result<Option<EphCommit>> {
        let me = self.tid();
        // the records: of the things written (and of the things named), up their ephemeral chains
        let mut recs: BTreeSet<Tid> = records.clone();
        for (t, _, _, _) in &deltas {
            if self.eph.things.contains_key(t) {
                recs.insert(*t);
            }
        }
        let mut chain: BTreeSet<Tid> = BTreeSet::new();
        for t in recs {
            let mut cur = t;
            for _ in 0..=MAX_OWNER_DEPTH {
                let Some(th) = self.eph.things.get(&cur) else { break };
                if self.core.created(&cur).is_some() || !chain.insert(cur) {
                    break;
                }
                match &th.record {
                    CreationRecord::Thing { owner, .. } => cur = *owner,
                    CreationRecord::KeyActor { .. } => break,
                }
            }
        }
        let mut parts: Vec<EphDelta> = deltas.into_iter().filter(|(t, ak, _, _)| !(chain.contains(t) && ak.as_str() == CREATED.ak())).collect();
        let cak = Ak::new(CREATED.ak()).map_err(|_| Error::Misuse("ak"))?;
        for t in &chain {
            if let Some(f) = self.created_fragment(t) {
                parts.push((*t, cak.clone(), f, None));
            }
        }
        if parts.is_empty() {
            return Ok(None);
        }
        let ts = self.core.hlc.next();
        let creates: Creates = chain.iter().filter_map(|t| self.eph.things.get(t).map(|th| (*t, th.record.clone()))).collect();
        let mut cx = osis_commit::writer_ctx(Kind::ContentSnapshot, ts, me, 0, 0);
        cx.own = Source::commit(CommitId([0; 32]));
        let mut writes = Vec::with_capacity(parts.len());
        let own_session = self.eph.session;
        for (tid, ak, fragment, expires) in parts {
            let mut authors = BTreeMap::new();
            for (d, _) in fragment.writes() {
                if let SourceKind::Commit(c) = d.src.author().kind()
                    && !authors.contains_key(c)
                {
                    let node = if c.0 == own_session { me } else { self.eph.remote.sessions.get(c).copied().unwrap_or(me) };
                    authors.insert(*c, (node, ts));
                }
            }
            let absorbed_here: BTreeMap<CommitId, Tid> = absorbed.get(&(tid, ak.clone())).into_iter().flatten().filter_map(|c| self.eph.remote.held.get(c).map(|h| (*c, h.header.author))).collect();
            let mut nonce = [0u8; osis_crdt::NONCE_LEN];
            self.rng.fill_bytes(&mut nonce);
            let bytes = osis_crdt::encode_snapshot(&Snapshot { nonce, fragment, frontiers: Frontiers::default(), absorbed: absorbed_here, authors }, &cx, None)?;
            let retention = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, ..Default::default() };
            writes.push(AspectWrite { tid, ak, lo: 0, hi: 0, deltas: vec![bytes], retention, expires, schema: None, chunks: Vec::new() });
        }
        let things: Vec<Tid> = writes.iter().map(|w| w.tid).collect();
        let published = self.run(|tx| published_keys(tx, &creates, things))?;
        let mut b = CommitBuilder::new(Kind::ContentSnapshot, ts, me, actor, Form::Commit);
        b.aspects = writes;
        b.ephemeral = Some(class);
        let built = {
            let secrets = CommitSecrets { core: &self.core, actor, created: &creates, published: &published };
            let mut sink = MemoryBlobs::default();
            b.build(&self.core.id.keys().signing, &secrets, &mut sink, &mut *self.rng)
        };
        let built = match built {
            Ok(b) if b.list_blobs.is_empty() => b,
            Ok(_) => {
                self.report_eph("an ephemeral commit too large for inline header lists was not sent");
                return Ok(None);
            }
            Err(e) => {
                self.report_eph(&format!("an ephemeral commit could not be built: {e}"));
                return Ok(None);
            }
        };
        let blob = built.commit;
        let id = blob.id();
        if class == EphClass::Plain {
            let mut interner = Interner::new();
            let mut held_parts = Vec::new();
            for p in &blob.parts {
                let cx = osis_commit::delta_ctx(&blob.header, &id, p.ai, &mut interner)?;
                let s = osis_crdt::decode_snapshot(&p.delta, &cx, &mut interner, None)?;
                held_parts.push((p.ai, s.fragment, s.absorbed.into_keys().collect()));
            }
            let n = held_parts.len();
            let bytes = held_parts.iter().map(|(_, f, _)| f.approx_bytes()).sum();
            self.eph.remote.held.insert(id, Held { header: Arc::new(blob.header.clone()), parts: held_parts, valid: vec![true; n], own: true, bytes });
            for (i, a) in blob.header.aspects.iter().enumerate() {
                if let Some(t) = a.expires {
                    self.eph.remote.timers.entry(t).or_default().insert((id, i));
                }
                self.eph.aspects.entry(a.tid).or_default().entry(a.ak.clone()).or_default().parts.insert((id, i));
            }
            if !absorbed.is_empty() {
                self.drop_absorbed();
            }
        }
        Ok(Some(EphCommit { id, class, blob }))
    }

    fn report_eph(&mut self, detail: &str) {
        self.report(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::EphemeralRefused, tids: Vec::new(), commit: None, peer: None, detail: detail.into() });
    }

    /// The record of `t` as known here: durable, ephemeral, or carried by `carried`.
    fn record_of<'a>(&'a self, t: &Tid, carried: &'a BTreeMap<Tid, CreationRecord>) -> Option<&'a CreationRecord> {
        self.core.created(t).or_else(|| self.eph.things.get(t).map(|e| &e.record)).or_else(|| carried.get(t))
    }

    /// Whether part `ai` of ephemeral commit `h` is valid here (spec/permissions.md §5.2): judged
    /// as its author's snapshot delta at its `ts`, by commit ID; on an ephemeral thing, as a
    /// write on a new thing owned by its nearest durable thing (spec/permissions.md §1). Unknown
    /// records count as invalid until they arrive.
    fn eph_part_valid(&self, h: &Header, id: &CommitId, ai: usize, carried: &BTreeMap<Tid, CreationRecord>) -> bool {
        let Some(a) = h.aspects.get(ai) else { return false };
        let ak = a.ak.as_str();
        if is_membership_class(ak) {
            return false;
        }
        if ak == CREATED.ak() {
            return true;
        }
        // up the ephemeral chain to the nearest durable thing; an ephemeral owner that is the
        // author makes it admin there
        let mut cur = a.tid;
        for _ in 0..=MAX_OWNER_DEPTH {
            if self.core.created(&cur).is_some() {
                if crate::apply::validity::too_deep(&self.core, &cur) {
                    return false;
                }
                let Some(tl) = self.core.timelines.get(&cur) else { return false };
                let point = Point { ts: h.ts, node: h.author, commit: *id };
                return tl.delta_valid(point, &cur, ak, Dots::Commit, required_role(ak)) == Validity::Valid;
            }
            match self.record_of(&cur, carried) {
                Some(CreationRecord::Thing { owner, .. }) if *owner == h.author => return true,
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                Some(CreationRecord::KeyActor { .. }) => return cur == h.author,
                None => return false,
            }
        }
        false
    }

    /// Receives an ephemeral commit blob (verified here; the blob's prefix was checked by the
    /// caller). Bad input is an error.
    pub fn ingest_ephemeral(&mut self, blob: CommitBlob) -> Result<EphIngest> {
        let id = blob.id();
        let h = blob.header.clone();
        let Some(class) = h.ephemeral else { return Err(Error::BadInput("not an ephemeral commit")) };
        let now = self.now().0;
        let at = h.ts.wall_ms().0;
        if class == EphClass::Relay {
            // its only replay window (notes/ephemeral.md Signals)
            if self.eph.remote.delivered_set.contains(&id) || at.saturating_add(MAX_DRIFT_MS) < now || at > now.saturating_add(MAX_DRIFT_MS) {
                return Ok(EphIngest::Delivered { fired: false });
            }
        } else {
            if at > now.saturating_add(MAX_DRIFT_MS) {
                return Ok(EphIngest::Held { new: false });
            }
            if let Some(held) = self.eph.remote.held.get(&id) {
                let have: BTreeSet<usize> = held.parts.iter().map(|p| p.0).collect();
                if blob.parts.iter().all(|p| have.contains(&p.ai)) {
                    return Ok(EphIngest::Held { new: false });
                }
            }
        }
        let author = match self.core.created(&h.author) {
            Some(CreationRecord::KeyActor { public_key, .. }) => VerifyingKey::from_slice(public_key)?,
            Some(_) => return Err(Error::BadInput("author is not a key actor")),
            None => {
                if class == EphClass::Plain {
                    self.eph.remote.pending.insert(id, blob);
                }
                return Ok(EphIngest::Pending);
            }
        };
        osis_commit::verify_signature(&id, &blob.signature, &author)?;
        h.validate()?;
        // records the commit carries (their parts are decoded first: a thing's dedup secret
        // comes from its record)
        let mut interner = Interner::new();
        let mut carried: BTreeMap<Tid, CreationRecord> = BTreeMap::new();
        for p in &blob.parts {
            let Some(a) = h.aspects.get(p.ai) else { return Err(Error::BadInput("part aspect index")) };
            if a.ak.as_str() != CREATED.ak() {
                continue;
            }
            let cx = osis_commit::delta_ctx(&h, &id, p.ai, &mut interner)?;
            let s = osis_crdt::decode_snapshot(&p.delta, &cx, &mut interner, None)?;
            let v = s.fragment.read().ok_or(Error::BadInput("empty /created"))?;
            let rec = CreationRecord::from_value(&v).ok_or(Error::BadInput("/created is not a creation record"))?;
            if rec.tid() != a.tid {
                return Err(Error::BadInput("/created does not hash to its tid"));
            }
            carried.insert(a.tid, rec);
        }
        let mut decoded = Vec::with_capacity(blob.parts.len());
        // a part on a thing whose record is not here yet waits (`rejudge_ephemeral` retries)
        let mut waits = false;
        for p in &blob.parts {
            let Some(a) = h.aspects.get(p.ai) else { continue };
            let Some(rec) = self.record_of(&a.tid, &carried) else {
                waits = true;
                continue;
            };
            let dedup = dedup_secret(rec.nonce());
            match osis_commit::verify_part(&h, &id, p, &dedup, &mut interner, None)? {
                osis_commit::Decoded::Snapshot(s) => decoded.push((p.ai, s)),
                osis_commit::Decoded::Delta(_) => return Err(Error::BadInput("ephemeral commit with a writer delta")),
            }
        }
        for (_, s) in &decoded {
            for (c, (node, _)) in &s.authors {
                if c.0 != self.eph.session {
                    self.eph.remote.sessions.entry(*c).or_insert(*node);
                }
            }
        }
        if class == EphClass::Relay {
            self.eph.remote.delivered_set.insert(id);
            self.eph.remote.delivered.push_back((id, at));
            while self.eph.remote.delivered.len() > MAX_DELIVERED || self.eph.remote.delivered.front().is_some_and(|(_, t)| t.saturating_add(MAX_DRIFT_MS) < now) {
                if let Some((c, _)) = self.eph.remote.delivered.pop_front() {
                    self.eph.remote.delivered_set.remove(&c);
                }
            }
            let mut signals = Vec::new();
            for (ai, s) in decoded {
                let Some(a) = h.aspects.get(ai) else { continue };
                if a.ak.as_str() == CREATED.ak() || !self.eph_part_valid(&h, &id, ai, &carried) {
                    continue;
                }
                if let Some(v) = s.fragment.read() {
                    signals.push((a.tid, a.ak.clone(), v));
                }
            }
            let fired = !signals.is_empty();
            if fired {
                let received = self.now();
                self.core.events.queue(Event::Ephemeral { id: ChangeId::Commit(id), origin: Origin::Remote, author: h.author, actor: h.actor, ts: h.ts, received, changed: Vec::new(), signals });
                self.core.events.flush();
            }
            return Ok(EphIngest::Delivered { fired });
        }
        // the records of ephemeral things it brings
        let received = self.now();
        for (t, rec) in &carried {
            if self.core.created(t).is_none() && !self.eph.things.contains_key(t) {
                let created = decoded.iter().find(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.tid == *t && a.ak.as_str() == CREATED.ak())).map(|(_, s)| s.fragment.clone());
                self.eph.things.insert(*t, EphThing { record: rec.clone(), ts: h.ts, node: h.author, actor: h.actor, received, created });
            }
        }
        let header = Arc::new(h);
        let held = self.eph.remote.held.remove(&id);
        let (mut parts, mut valid) = match held {
            Some(x) => (x.parts, x.valid),
            None => (Vec::new(), Vec::new()),
        };
        let mut changed = Vec::new();
        for (ai, s) in decoded {
            if parts.iter().any(|p| p.0 == ai) {
                continue;
            }
            let Some(a) = header.aspects.get(ai) else { continue };
            if a.expires.is_some_and(|t| t <= now) {
                continue;
            }
            let ok = self.eph_part_valid(&header, &id, ai, &carried);
            let k = parts.len();
            parts.push((ai, s.fragment.clone(), s.absorbed.keys().copied().collect()));
            valid.push(ok);
            if let Some(t) = a.expires {
                self.eph.remote.timers.entry(t).or_default().insert((id, ai));
            }
            let src = self.eph.src.clone();
            let ea = self.eph.aspects.entry(a.tid).or_default().entry(a.ak.clone()).or_default();
            ea.parts.insert((id, ai));
            let _ = k;
            if ok && a.ak.as_str() != CREATED.ak() {
                if ea.own.is_none() {
                    ea.own = Some(ea.state.clone());
                }
                ea.state.join(s.fragment);
                strip_own_expired(ea, &src);
                if a.ak.as_str() == GROUP.ak() {
                    let (t, ak) = (a.tid, a.ak.clone());
                    self.refresh_def(&t, &ak);
                }
                changed.push((a.tid, a.ak.clone()));
            }
        }
        let bytes = parts.iter().map(|(_, f, _)| f.approx_bytes()).sum();
        let new = !changed.is_empty();
        let absorbs = parts.iter().any(|(_, _, a)| !a.is_empty());
        self.eph.remote.held.insert(id, Held { header: header.clone(), parts, valid, own: false, bytes });
        if waits {
            self.eph.remote.pending.insert(id, blob);
        }
        if absorbs {
            self.drop_absorbed();
        }
        changed.sort();
        changed.dedup();
        if !changed.is_empty() {
            self.core.events.queue(Event::Ephemeral { id: ChangeId::Commit(id), origin: Origin::Remote, author: header.author, actor: header.actor, ts: header.ts, received, changed, signals: Vec::new() });
            self.core.events.flush();
        }
        Ok(EphIngest::Held { new })
    }

    /// Drops held commits that valid held commits list as absorbed on every aspect they touch
    /// (a compaction covers them); their parts' writes stay in the state through the cover.
    /// Returns the dropped IDs (`take_dropped_ephemeral`).
    fn drop_absorbed(&mut self) {
        let r = &self.eph.remote;
        let mut covers: BTreeMap<(Tid, Ak), BTreeSet<CommitId>> = BTreeMap::new();
        for h in r.held.values() {
            for ((ai, _, abs), ok) in h.parts.iter().zip(&h.valid) {
                if *ok
                    && !abs.is_empty()
                    && let Some(a) = h.header.aspects.get(*ai)
                {
                    covers.entry((a.tid, a.ak.clone())).or_default().extend(abs.iter().copied());
                }
            }
        }
        if covers.is_empty() {
            return;
        }
        let gone: Vec<CommitId> = r
            .held
            .iter()
            .filter(|(id, h)| {
                h.parts.iter().all(|(ai, _, _)| h.header.aspects.get(*ai).is_some_and(|a| covers.get(&(a.tid, a.ak.clone())).is_some_and(|c| c.contains(id))))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            self.forget_held(&id);
        }
    }

    /// Forgets held commit `id` (its writes stay in the state); queued for `take_dropped_ephemeral`.
    fn forget_held(&mut self, id: &CommitId) {
        let Some(h) = self.eph.remote.held.remove(id) else { return };
        for (ai, _, _) in &h.parts {
            if let Some(a) = h.header.aspects.get(*ai) {
                if let Some(ea) = self.eph.aspects.get_mut(&a.tid).and_then(|m| m.get_mut(&a.ak)) {
                    ea.parts.remove(&(*id, *ai));
                }
                if let Some(t) = a.expires
                    && let Some(s) = self.eph.remote.timers.get_mut(&t)
                {
                    s.remove(&(*id, *ai));
                }
            }
        }
        self.eph.dropped.push(*id);
    }

    /// The held ephemeral commits dropped since the last call (covered by a compaction): the
    /// sync layer forgets their blobs and deletes them where it may.
    pub fn take_dropped_ephemeral(&mut self) -> Vec<CommitId> {
        std::mem::take(&mut self.eph.dropped)
    }

    /// Whether an ephemeral commit is held here.
    pub fn holds_ephemeral(&self, id: &CommitId) -> bool {
        self.eph.remote.held.contains_key(id)
    }

    /// The header of a held ephemeral commit.
    pub fn ephemeral_header(&self, id: &CommitId) -> Option<Arc<Header>> {
        self.eph.remote.held.get(id).map(|h| h.header.clone())
    }

    /// The reader actor of thing `t` (`Engine::reader_of`), through the records of ephemeral
    /// things up to the nearest durable one.
    pub fn ephemeral_reader(&self, t: &Tid) -> Tid {
        let mut cur = *t;
        for _ in 0..=MAX_OWNER_DEPTH {
            if self.core.created(&cur).is_some() {
                return self.core.reader_of(&cur);
            }
            match self.eph.things.get(&cur).map(|e| &e.record) {
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => break,
            }
        }
        self.core.reader_of(&cur)
    }

    /// The delete secrets this node holds for delete keys `keys` of an ephemeral commit's part
    /// on `tid` acting for `actor` (spec/crypto.md §7): those of the chain of `tid`'s nearest
    /// durable thing.
    pub fn ephemeral_delete_secrets_for(&self, tid: &Tid, actor: &Tid, keys: &[osis_commit::DeleteKey]) -> Vec<(u8, DeleteSecret)> {
        let mut cur = *tid;
        for _ in 0..=MAX_OWNER_DEPTH {
            if self.core.created(&cur).is_some() {
                break;
            }
            match self.eph.things.get(&cur).map(|e| &e.record) {
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => break,
            }
        }
        let thing = self.core.delete_chain(&cur);
        let author = self.core.delete_chain(actor);
        keys.iter().filter_map(|k| crate::engine::Core::delete_secret(k.level, &k.key, &thing, &author).map(|d| (k.level, d))).collect()
    }

    /// Judges held ephemeral commits again when the held durable set changed (rights, records),
    /// rebuilds the aspects whose parts flipped (un-merge or re-merge, spec/crdt.md §4.6), retries
    /// commits waiting for their author's record and forgets ephemeral records of things that
    /// became durable.
    pub fn rejudge_ephemeral(&mut self) -> Result<()> {
        if self.eph.remote.judged_at == self.core.generation {
            return Ok(());
        }
        self.eph.remote.judged_at = self.core.generation;
        let durable: Vec<Tid> = self.eph.things.keys().filter(|t| self.core.created(t).is_some()).copied().collect();
        for t in durable {
            self.eph.things.remove(&t);
        }
        let pending: Vec<CommitId> = self.eph.remote.pending.keys().copied().collect();
        for c in pending {
            if let Some(b) = self.eph.remote.pending.remove(&c)
                && let Err(e) = self.ingest_ephemeral(b)
            {
                self.report_eph(&format!("ephemeral commit {c:?}: {e}"));
            }
        }
        let empty = BTreeMap::new();
        let mut flips: BTreeSet<(Tid, Ak)> = BTreeSet::new();
        let ids: Vec<CommitId> = self.eph.remote.held.keys().copied().collect();
        for id in ids {
            let Some(h) = self.eph.remote.held.get(&id) else { continue };
            if h.own {
                continue;
            }
            let header = h.header.clone();
            let now: Vec<bool> = h.parts.iter().map(|(ai, _, _)| self.eph_part_valid(&header, &id, *ai, &empty)).collect();
            let Some(h) = self.eph.remote.held.get_mut(&id) else { continue };
            for (k, ((ai, _, _), ok)) in h.parts.iter().zip(&now).enumerate() {
                if h.valid.get(k) != Some(ok)
                    && let Some(a) = header.aspects.get(*ai)
                {
                    flips.insert((a.tid, a.ak.clone()));
                }
            }
            h.valid = now;
        }
        let mut changed = Vec::new();
        for (t, ak) in flips {
            self.rebuild_aspect(&t, &ak);
            changed.push((t, ak));
        }
        if !changed.is_empty() {
            self.drop_absorbed();
            self.core.events.queue(Event::Changed { cause: crate::events::Cause::Validity, changed });
            self.core.events.flush();
        }
        Ok(())
    }

    /// Rebuilds the ephemeral state of `(t, ak)`: the own writes joined with the valid held parts,
    /// own commits included (un-merge, spec/crdt.md §4.6).
    fn rebuild_aspect(&mut self, t: &Tid, ak: &Ak) {
        let r = &self.eph.remote;
        let Some(ea) = self.eph.aspects.get(t).and_then(|m| m.get(ak)) else { return };
        let mut f = ea.own.clone().unwrap_or_default();
        for (id, ai) in &ea.parts {
            // own held commits too: an own compaction's cover carries others' writes
            let Some(h) = r.held.get(id) else { continue };
            if let Some(k) = h.parts.iter().position(|p| p.0 == *ai)
                && h.valid.get(k).copied().unwrap_or(false)
                && let Some((_, frag, _)) = h.parts.get(k)
            {
                f.join(frag.clone());
            }
        }
        let src = self.eph.src.clone();
        if let Some(ea) = self.eph.aspects.get_mut(t).and_then(|m| m.get_mut(ak)) {
            ea.state = f;
            strip_own_expired(ea, &src);
        }
        if ak.as_str() == GROUP.ak() {
            self.refresh_def(t, ak);
        }
    }

    /// Runs the expiries of held parts due by the corrected clock: their writes are stripped
    /// (spec/crdt.md §4.7) and the parts dropped. Returns the aspects changed.
    pub(super) fn tick_remote(&mut self, now: u64) -> BTreeSet<(Tid, Ak)> {
        let mut changed = BTreeSet::new();
        while let Some(entry) = self.eph.remote.timers.first_entry() {
            if *entry.key() > now {
                break;
            }
            let (_, parts) = entry.remove_entry();
            for (id, ai) in parts {
                let Some(h) = self.eph.remote.held.get_mut(&id) else { continue };
                let Some(k) = h.parts.iter().position(|p| p.0 == ai) else { continue };
                let (_, frag, _) = h.parts.remove(k);
                h.valid.remove(k);
                let header = h.header.clone();
                let empty = h.parts.is_empty();
                let Some(a) = header.aspects.get(ai) else { continue };
                let dots: BTreeSet<osis_crdt::Dot> = frag.writes().into_iter().map(|(d, _)| d).collect();
                if let Some(ea) = self.eph.aspects.get_mut(&a.tid).and_then(|m| m.get_mut(&a.ak)) {
                    ea.parts.remove(&(id, ai));
                    ea.state.strip(&|d| dots.contains(d));
                    if let Some(o) = &mut ea.own {
                        o.strip(&|d| dots.contains(d));
                    }
                }
                if a.ak.as_str() == GROUP.ak() {
                    let (t, ak) = (a.tid, a.ak.clone());
                    self.refresh_def(&t, &ak);
                }
                changed.insert((a.tid, a.ak.clone()));
                if empty {
                    self.eph.remote.held.remove(&id);
                    self.eph.dropped.push(id);
                }
            }
        }
        changed
    }

    /// Compacts the ephemeral state of the aspects of `scope` (all held ones when `None`) this
    /// node may write and whose held writes carry no expiry, when forced or past the
    /// compaction rule (held bodies above twice the state and `COMPACT_FLOOR`): one ephemeral
    /// commit of their current states, listing the held commits it covers as absorbed, which
    /// are dropped here (`take_dropped_ephemeral`). `None` when nothing is compacted.
    pub fn compact_ephemeral(&mut self, scope: Option<&BTreeSet<Tid>>, force: bool) -> Result<Option<EphCommit>> {
        let me = self.tid();
        let ts = Ts::make(self.now(), 0).unwrap_or_default();
        let mut picked: Vec<(Tid, Ak)> = Vec::new();
        for (t, m) in &self.eph.aspects {
            if scope.is_some_and(|s| !s.contains(t)) {
                continue;
            }
            for (ak, ea) in m {
                if ea.parts.is_empty() || !ea.expiring.is_empty() || ak.as_str() == CREATED.ak() {
                    continue;
                }
                let held_bytes: usize = ea.parts.iter().filter_map(|(id, _)| self.eph.remote.held.get(id)).map(|h| h.bytes / h.parts.len().max(1)).sum();
                let expiring = ea.parts.iter().any(|(id, ai)| self.eph.remote.held.get(id).and_then(|h| h.header.aspects.get(*ai)).is_some_and(|a| a.expires.is_some()));
                if expiring || !(force || (held_bytes > COMPACT_FLOOR && held_bytes > 2 * ea.state.approx_bytes())) {
                    continue;
                }
                let things = &self.eph.things;
                let records: crate::engine::write::Records<'_> = &|x| things.get(x).map(|e| &e.record);
                if crate::engine::write::check_authority_with(&self.core, me, records, t, ak.as_str(), ts).is_err() {
                    continue;
                }
                picked.push((*t, ak.clone()));
            }
        }
        if picked.is_empty() {
            return Ok(None);
        }
        let picked_set: BTreeSet<(Tid, Ak)> = picked.iter().cloned().collect();
        // the held commits wholly on picked aspects
        let mut absorbed: BTreeMap<(Tid, Ak), BTreeSet<CommitId>> = BTreeMap::new();
        for (id, h) in &self.eph.remote.held {
            let all = h.parts.iter().all(|(ai, _, _)| h.header.aspects.get(*ai).is_some_and(|a| a.ak.as_str() == CREATED.ak() || picked_set.contains(&(a.tid, a.ak.clone()))));
            if !all {
                continue;
            }
            for (ai, _, _) in &h.parts {
                if let Some(a) = h.header.aspects.get(*ai) {
                    absorbed.entry((a.tid, a.ak.clone())).or_default().insert(*id);
                }
            }
        }
        let deltas: Vec<EphDelta> = picked.iter().filter_map(|(t, ak)| self.eph.state(t, ak).map(|f| (*t, ak.clone(), f.clone(), None))).collect();
        let records: BTreeSet<Tid> = picked.iter().map(|(t, _)| *t).filter(|t| self.eph.things.contains_key(t)).collect();
        // what is compacted needs no separate send
        for k in &picked {
            if let Some(m) = self.eph.remote.unsent.get_mut(k) {
                m.retain(|(_, exp), _| exp.is_some());
                if m.is_empty() {
                    self.eph.remote.unsent.remove(k);
                }
            }
        }
        let c = self.build_ephemeral(EphClass::Plain, me, deltas, &records, &absorbed)?;
        Ok(c)
    }

    /// Tests: an ephemeral commit setting `(tid, ak)` to `v` with no rights check (a forged
    /// write, to test receivers).
    #[doc(hidden)]
    pub fn forge_ephemeral(&mut self, tid: Tid, ak: &Ak, v: Value) -> Result<Option<EphCommit>> {
        let ts = self.core.hlc.next();
        let w = Writer::new(ts, self.eph.src.clone(), self.eph.next);
        let Some((f, r)) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(v) }], &AnyView)? else { return Ok(None) };
        self.eph.next = r.hi;
        let me = self.tid();
        self.build_ephemeral(EphClass::Plain, me, vec![(tid, ak.clone(), f, None)], &BTreeSet::new(), &BTreeMap::new())
    }

    /// Held ephemeral commits and their approximate bytes (tests, diagnostics).
    pub fn held_ephemeral(&self) -> Vec<(CommitId, usize, bool)> {
        self.eph.remote.held.iter().map(|(id, h)| (*id, h.bytes, h.own)).collect()
    }

    /// Forgets the held ephemeral commits `ids` (the sync layer refused or lost them), keeping
    /// the state: nothing is un-merged by forgetting a body.
    pub fn forget_ephemeral(&mut self, ids: &[CommitId]) {
        for id in ids {
            self.forget_held(id);
        }
        self.eph.dropped.retain(|c| !ids.contains(c));
    }
}

/// The whole state of an aspect without the values of own writes that expire (a snapshot never
/// carries those, spec/crdt.md §8).
fn whole_unexpiring(a: &EphAspect, src: &Source) -> Fragment {
    let mut f = a.state.clone();
    for ranges in a.expiring.values() {
        f.strip(&|d| d.src == *src && ranges.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
    }
    f
}

/// Strips own writes already expired from an aspect's state (a join may repeat their records).
fn strip_own_expired(a: &mut EphAspect, src: &Source) {
    if a.expired.is_empty() {
        return;
    }
    let expired = a.expired.clone();
    if a.state.holds_dots(&|d| d.src == *src && expired.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi)) {
        a.state.strip(&|d| d.src == *src && expired.iter().any(|(lo, hi)| *lo <= d.ctr && d.ctr < *hi));
    }
}

impl Eph {
    /// Approximate bytes held in ephemeral commit records from others.
    pub fn remote_bytes(&self) -> usize {
        self.remote.held.values().filter(|h| !h.own).map(|h| h.bytes).sum()
    }
}
