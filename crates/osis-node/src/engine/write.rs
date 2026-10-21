//! Writing (spec/crdt.md §2.3, §4.5, §9; spec/commits.md §1–§3, §5, §6): a `Mutation` collects
//! ops across things; `Engine::commit` resolves them against local state (one delta per
//! aspect, the net effect), takes counters, fills retention and expiry from the schema, pages
//! large deltas, checks this node's role on every touched thing, signs, and applies the commit
//! locally in the same store transaction that reserves its counters, so nothing signed leaves
//! the node before its counters are durable.

use super::blobs::{ListBlobs, TxBlobs};
use super::secrets::CommitSecrets;
use super::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::events::Origin;
use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, PurgeItem, writer_ctx};
use osis_core::{Ak, CommitId, CreationRecord, Role, SchemaId, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, Batch, CounterRange, Delta, Fragment, Op, PathOp, Source, View, Writer, encode_delta};
use osis_label::{BlobWriter, Framing};
use osis_perm::At;
use osis_schema::core_types::{CREATED, is_membership_class};
use osis_schema::{AspectKey, Retention, Schema};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Ops on one aspect.
#[derive(Clone, Debug, Default)]
pub(crate) struct AspectMut {
    pub ops: Vec<PathOp>,
    pub schema: Option<Arc<Schema>>,
    pub retention: Option<Retention>,
    pub expires: Option<u64>,
}

/// A batch of writes that becomes one commit.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub(crate) creates: Vec<CreationRecord>,
    pub(crate) aspects: BTreeMap<(Tid, Ak), AspectMut>,
    pub(crate) actor: Option<Tid>,
    pub(crate) form: Form,
    pub(crate) purge: Vec<PurgeItem>,
    pub(crate) undoes: Option<CommitId>,
    pub(crate) frontier: Option<Value>,
    /// Membership flows judge their own authority (invite grants, self-removals).
    pub(crate) unchecked: bool,
    /// A held key actor that signs instead of the node (commit form).
    pub(crate) signer: Option<Tid>,
    /// A roster snapshot (spec/permissions.md §6): membership kind with the marker.
    pub(crate) roster: bool,
    /// Map entries to reset whatever their liveness here (spec/crdt.md §5.6): an explicit removal
    /// of an edge already removed (membership flows).
    pub(crate) dead_resets: BTreeMap<(Tid, Ak), Vec<osis_crdt::Dot>>,
    /// Chunk and node blobs never reused, written afresh (`Engine::relink`).
    pub(crate) fresh: std::collections::BTreeSet<osis_core::BlobId>,
}

impl Default for Mutation {
    fn default() -> Mutation {
        Mutation::new()
    }
}

fn ak_of<K: AspectKey>(key: &K) -> Result<Ak> {
    Ak::new(key.ak()).map_err(|_| Error::Misuse("invalid AK"))
}

impl Mutation {
    pub fn new() -> Mutation {
        Mutation { creates: Vec::new(), aspects: BTreeMap::new(), actor: None, form: Form::Node, purge: Vec::new(), undoes: None, frontier: None, unchecked: false, signer: None, roster: false, dead_resets: BTreeMap::new(), fresh: Default::default() }
    }

    /// The actor this node acts for (header field 2); default the node itself.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = Some(actor);
        self
    }

    /// Signs as a key actor whose seed the node holds (`Engine::hold_key_actor`): a recovery
    /// key or link key (spec/crypto.md §2). Commit form: its holders share no counters.
    pub fn sign_as(&mut self, key_actor: Tid) -> &mut Self {
        self.signer = Some(key_actor);
        self.form = Form::Commit;
        self
    }

    /// Commit-form dots (spec/commits.md §3).
    pub fn commit_form(&mut self) -> &mut Self {
        self.form = Form::Commit;
        self
    }

    /// Records a new thing; its `/created` goes into this commit.
    pub fn create(&mut self, record: CreationRecord) -> Tid {
        let t = record.tid();
        self.creates.push(record);
        t
    }

    fn entry<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<&mut AspectMut> {
        let ak = ak_of(key)?;
        let e = self.aspects.entry((tid, ak)).or_default();
        if e.schema.is_none()
            && let Some(s) = key.schema()
        {
            e.schema = Some(Arc::new(s.clone()));
        }
        Ok(e)
    }

    /// An op at a path (validated by the crdt against the writer's view).
    pub fn op<K: AspectKey>(&mut self, tid: Tid, key: &K, op: PathOp) -> Result<&mut Self> {
        self.entry(tid, key)?.ops.push(op);
        Ok(self)
    }

    /// Makes the aspect read `v` (structural diff, spec/crdt.md §9).
    pub fn set<K: AspectKey>(&mut self, tid: Tid, key: &K, v: &K::T) -> Result<&mut Self> {
        let v = key.encode(v);
        key.validate(&v)?;
        self.op(tid, key, PathOp { path: Vec::new(), op: Op::Set(v) })
    }

    /// Resets the aspect, then writes `v`.
    pub fn replace<K: AspectKey>(&mut self, tid: Tid, key: &K, v: &K::T) -> Result<&mut Self> {
        let v = key.encode(v);
        key.validate(&v)?;
        self.op(tid, key, PathOp { path: Vec::new(), op: Op::Replace(v) })
    }

    /// Removes the aspect (spec/crdt.md §4.3: absent afterwards).
    pub fn remove_aspect<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<&mut Self> {
        self.op(tid, key, PathOp { path: Vec::new(), op: Op::RemoveAspect })
    }

    /// Retention for this aspect's delta, instead of the schema default (spec/commits.md §5).
    pub fn retention<K: AspectKey>(&mut self, tid: Tid, key: &K, r: Retention) -> Result<&mut Self> {
        self.entry(tid, key)?.retention = Some(r);
        Ok(self)
    }

    /// Expiry T (wall ms) for this aspect's delta (spec/commits.md §6).
    pub fn expires<K: AspectKey>(&mut self, tid: Tid, key: &K, t: WallMs) -> Result<&mut Self> {
        self.entry(tid, key)?.expires = Some(t.0);
        Ok(self)
    }

    /// A purge request item (spec/commits.md §5).
    pub fn purge(&mut self, item: PurgeItem) -> &mut Self {
        self.purge.push(item);
        self
    }

    /// Makes this an undo of `target` (spec/commits.md §7) acting as the mutation's actor; the
    /// mutation may carry no other ops (`Misuse` at commit).
    pub fn undo(&mut self, target: CommitId) -> &mut Self {
        self.undoes = Some(target);
        self
    }

    /// The frontier of an explicit demotion (membership flows).
    pub fn frontier(&mut self, v: Value) -> &mut Self {
        self.frontier = Some(v);
        self
    }

    /// Skips the plain role check (membership flows judge invite grants and self-removals).
    pub(crate) fn unchecked(&mut self) -> &mut Self {
        self.unchecked = true;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.aspects.is_empty() && self.purge.is_empty() && self.undoes.is_none()
    }
}

/// The role a write of `ak` needs (spec/permissions.md §1, §3): admin for edges, `/label`,
/// `/moved`, `/was`, `/tenures`; write for rotations (`/secrets`, `/keys`) and content.
pub(crate) fn required_role(ak: &str) -> Role {
    match ak {
        "/members" | "/label" | "/moved" | "/was" | "/tenures" => Role::Admin,
        _ => Role::Write,
    }
}

pub(crate) fn role_of(core: &Core, node: &Tid, tid: &Tid, ts: Ts) -> Option<Role> {
    core.timelines.get(tid)?.role(node, tid, At::now(ts))
}

/// May `node` (this node or a key actor it signs as) write `ak` of `tid` at `ts`? Things
/// created by the commit take their owner's.
pub(crate) fn check_authority(core: &Core, node: Tid, creates: &[CreationRecord], tid: &Tid, ak: &str, ts: Ts) -> Result<()> {
    let need = required_role(ak);
    let role = match creates.iter().find(|r| r.tid() == *tid) {
        Some(CreationRecord::KeyActor { .. }) => (*tid == node).then_some(Role::Admin),
        Some(CreationRecord::Thing { owner, .. }) if *owner == node => Some(Role::Admin),
        Some(CreationRecord::Thing { owner, .. }) => role_of(core, &node, owner, ts),
        None => role_of(core, &node, tid, ts),
    };
    if role >= Some(need) { Ok(()) } else { Err(Error::Permission { tid: *tid }) }
}

fn run_ops<V: View>(state: &Fragment, w: Writer, ops: &[PathOp], view: &V) -> Result<Option<(Fragment, CounterRange)>> {
    let mut b = Batch::new(state, w);
    for op in ops {
        b.apply(op, view)?;
    }
    Ok(b.finish())
}

/// One aspect's delta before encoding.
pub(crate) struct Resolved {
    pub tid: Tid,
    pub ak: Ak,
    pub fragment: Fragment,
    pub lo: u64,
    pub hi: u64,
    pub schema: Option<Arc<Schema>>,
    /// The schema table entry without a schema held: an import keeps its origin's.
    pub schema_ref: Option<(SchemaId, u64)>,
    pub retention: Option<Retention>,
    pub expires: Option<u64>,
    /// A snapshot delta's frontiers (spec/crdt.md §8).
    pub frontiers: Option<osis_crdt::Frontiers>,
    /// Chunk blobs of large values the delta introduces (ID, prefix salt).
    pub chunks: Vec<(osis_core::BlobId, [u8; 16])>,
    /// Written as one delta per root map entry or set element (a roster snapshot).
    pub split: bool,
}

/// Inputs of a commit other than its deltas.
pub(crate) struct CommitPlan {
    pub kind: Kind,
    pub ts: Ts,
    pub actor: Tid,
    pub form: Form,
    pub creates: Vec<CreationRecord>,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    pub frontier: Option<Value>,
    pub origins: Vec<osis_commit::Origin>,
    /// The signing key actor: the node, or a key actor it holds.
    pub signer: Tid,
}

/// Retention, expiry and blob framing of one aspect's delta in a commit (spec/commits.md §5,
/// §6; spec/crypto.md §7).
pub(crate) fn framing_for(core: &Core, plan: &CommitPlan, tid: &Tid, ak: &Ak, schema: Option<&Schema>, r: Option<Retention>, e: Option<u64>) -> Result<(Retention, Option<u64>, Framing)> {
    let defaults = schema.and_then(|s| s.defaults(ak.as_str()));
    let retention = match plan.kind {
        Kind::ContentSnapshot | Kind::MembershipSnapshot => osis_commit::retention::snapshot_retention(ak.as_str(), defaults.as_ref()),
        _ => osis_commit::retention::write_retention(ak.as_str(), defaults.as_ref(), r)?,
    };
    let expires = match plan.kind {
        Kind::Content => osis_commit::retention::write_expires(ak.as_str(), plan.ts, defaults.as_ref(), e)?,
        _ => None,
    };
    let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates };
    let tokens = osis_commit::token_secrets(&secrets, tid, &retention, plan.kind)?;
    let dedup = osis_commit::Secrets::dedup(&secrets, tid).ok_or(Error::UnknownThing(*tid))?;
    let framing = Framing { dedup, expiry: expires.map(WallMs), tokens: tokens.iter().map(|t| (t.level, t.secret.clone())).collect() };
    Ok((retention, expires, framing))
}

/// The writer's own source: the author node, or for commit form a placeholder commit that
/// sorts below every other commit like the real one will (spec/crdt.md §3.3 rule 2).
fn own_source(form: Form, node: Tid) -> Source {
    match form {
        Form::Node => Source::node(node),
        Form::Commit => Source::commit(osis_core::CommitId([0; 32])),
    }
}

/// The `Authors` a snapshot of `tid` carrying `f` names (spec/crdt.md §8): per commit-form
/// source its recorded author and `ts`; a source of unknown author refuses the snapshot.
fn snapshot_authors(core: &Core, tid: &Tid, f: &osis_crdt::Fragment) -> Result<BTreeMap<CommitId, (Tid, osis_core::Ts)>> {
    let mut out = BTreeMap::new();
    for (d, _) in f.writes() {
        if let osis_crdt::SourceKind::Commit(c) = d.src.kind() {
            let v = core.authors.get(&(*tid, *c)).copied().ok_or(Error::Misuse("a snapshot of a commit-form write whose author is unknown"))?;
            out.insert(*c, v);
        }
    }
    Ok(out)
}

/// Encodes, pages, reserves counters, builds, signs and applies locally. Returns the ID.
pub(crate) fn build_and_apply(tx: &mut Tx<'_>, plan: CommitPlan, deltas: Vec<Resolved>) -> Result<CommitId> {
    let node = plan.signer;
    let mut writes = Vec::with_capacity(deltas.len());
    for d in deltas {
        let (retention, expires, framing) = framing_for(tx.core, &plan, &d.tid, &d.ak, d.schema.as_deref(), d.retention, d.expires)?;
        if expires.is_some() && !plan.purge.is_empty() {
            return Err(Error::Misuse("a commit with a purge request cannot carry expires (spec/commits.md §5)"));
        }
        let mut cx = writer_ctx(plan.kind, plan.ts, node, d.lo, d.hi);
        // own writes already carry the commit-form placeholder (`own_source`), so foreign dots
        // of this node's node-form writes stay node dots
        cx.own = own_source(plan.form, node);
        // a roster snapshot: one delta per edge and per ledger entry (spec/commits.md §2)
        let fragments = if d.split { d.fragment.split_entries() } else { vec![d.fragment] };
        let mut blobs = TxBlobs::new(&mut tx.txn);
        let mut bytes = Vec::with_capacity(fragments.len());
        let mut frontiers = d.frontiers;
        for fragment in fragments {
            let mut nonce = [0u8; osis_crdt::NONCE_LEN];
            tx.rng.fill_bytes(&mut nonce);
            let mut bw = BlobWriter::new(&framing, &mut blobs, &mut *tx.rng);
            bytes.push(match frontiers.take() {
                Some(frontiers) => {
                    let authors = snapshot_authors(tx.core, &d.tid, &fragment)?;
                    osis_crdt::encode_snapshot(&osis_crdt::Snapshot { nonce, fragment, frontiers, authors }, &cx, Some(&mut bw))?
                }
                None => encode_delta(&Delta { nonce, fragment }, &cx, Some(&mut bw))?,
            });
        }
        let mut chunks = std::mem::take(&mut blobs.written);
        // trees written for values the resolved delta does not hold (an edit's item paired
        // with one deleted concurrently) are neither listed nor kept
        let mut own = d.chunks;
        if !own.is_empty() {
            let mut linked = std::collections::BTreeSet::new();
            for b in &bytes {
                linked.extend(super::large::delta_links(tx, &framing.dedup, b)?);
            }
            let (keep, drop): (Vec<_>, Vec<_>) = own.into_iter().partition(|(id, _)| linked.contains(id));
            for (id, _) in &drop {
                tx.txn.delete_blob(id);
            }
            own = keep;
        }
        chunks.extend(own);
        if plan.form == Form::Node && plan.kind.has_own_writes() {
            let first = tx.txn.reserve_counters(&d.tid, &d.ak, d.hi.saturating_sub(d.lo))?;
            if first != d.lo {
                return Err(Error::Misuse("counter moved under the writer"));
            }
        }
        let schema: Option<(SchemaId, u64)> = d.schema.as_ref().filter(|s| s.aspects.contains_key(d.ak.as_str())).map(|s| (s.id, s.revision)).or(d.schema_ref);
        writes.push(AspectWrite { tid: d.tid, ak: d.ak, lo: d.lo, hi: d.hi, deltas: bytes, retention, expires, schema, chunks });
    }
    let mut b = CommitBuilder::new(plan.kind, plan.ts, node, plan.actor, plan.form);
    b.aspects = writes;
    b.purge = plan.purge;
    b.undoes = plan.undoes;
    b.frontier = plan.frontier;
    b.origins = plan.origins;
    let built = {
        let core: &Core = tx.core;
        let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates };
        let mut seed = [0u8; 32];
        tx.rng.fill_bytes(&mut seed);
        let mut list_rng = osis_crypto::SeededRng::from_seed(seed);
        let mut sink = ListBlobs { blobs: TxBlobs::new(&mut tx.txn), rng: &mut list_rng };
        let signing = if node == core.id.tid() { &core.id.keys().signing } else { &core.key_actors.get(&node).ok_or(Error::Misuse("signer not held"))?.keys().signing };
        b.build(signing, &secrets, &mut sink, &mut *tx.rng)
    };
    let built = built?;
    let id = built.commit.id();
    let received = tx.now();
    crate::apply::apply_local(tx, &built.commit, received)?;
    let _ = Origin::Local;
    Ok(id)
}

impl Engine {
    /// A new thing owned by `owner`, created by `m` (spec/data-model.md §1).
    pub fn new_thing(&mut self, m: &mut Mutation, owner: Tid) -> Tid {
        m.create(crate::identity::thing_record(owner, &mut *self.rng))
    }

    /// Commits `m`; `None` when it changes nothing.
    pub fn commit(&mut self, m: Mutation) -> Result<Option<CommitId>> {
        self.run(|tx| commit_in(tx, m))
    }
}

pub(crate) fn commit_in(tx: &mut Tx<'_>, mut m: Mutation) -> Result<Option<CommitId>> {
    let node = match m.signer {
        Some(k) if tx.core.key_actors.contains_key(&k) => k,
        Some(_) => return Err(Error::Misuse("signer not held")),
        None => tx.core.id.tid(),
    };
    if m.undoes.is_some() && !(m.creates.is_empty() && m.aspects.is_empty() && m.purge.is_empty() && m.frontier.is_none()) {
        return Err(Error::Misuse("an undo mutation carries no other ops"));
    }
    let core_schema = Arc::new(osis_schema::core_schema().clone());
    for rec in &m.creates {
        let t = rec.tid();
        if tx.core.created(&t).is_some() {
            return Err(Error::Misuse("thing already exists"));
        }
        let e = m.aspects.entry((t, Ak::new(CREATED.ak()).map_err(|_| Error::Misuse("ak"))?)).or_default();
        e.schema = Some(core_schema.clone());
        e.ops.push(PathOp { path: Vec::new(), op: Op::Set(rec.to_value()) });
    }
    let dead: Vec<(Tid, Ak)> = m.dead_resets.keys().cloned().collect();
    for k in dead {
        m.aspects.entry(k).or_default();
    }
    let membership = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && is_membership_class(ak.as_str()));
    let content = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && !is_membership_class(ak.as_str()));
    if membership && content {
        return Err(Error::Misuse("a commit is either content or membership"));
    }
    let kind = match m.roster {
        true if membership => Kind::RosterSnapshot,
        true => return Err(Error::Misuse("a roster snapshot writes /members and /tenures only")),
        false if membership => Kind::Membership,
        false => Kind::Content,
    };
    if let Some(u) = m.undoes {
        return crate::undo::undo_in(tx, u, m.actor.unwrap_or(node)).map(Some).or_else(|e| match e {
            Error::Misuse("nothing to undo") => Ok(None),
            e => Err(e),
        });
    }
    let ts = tx.core.hlc.next();
    let plan = CommitPlan { kind, ts, actor: m.actor.unwrap_or(node), form: m.form, creates: std::mem::take(&mut m.creates), purge: std::mem::take(&mut m.purge), undoes: None, frontier: m.frontier.take(), origins: Vec::new(), signer: node };
    let mut next_ctr = 1u64;
    let mut deltas = Vec::new();
    for ((tid, ak), mut am) in std::mem::take(&mut m.aspects) {
        let created_here = plan.creates.iter().any(|r| r.tid() == tid);
        if !created_here && tx.core.created(&tid).is_none() {
            return Err(Error::UnknownThing(tid));
        }
        if !m.unchecked {
            check_authority(tx.core, node, &plan.creates, &tid, ak.as_str(), ts)?;
        }
        // a paged state loads what the ops address (map keys, fields), else whole
        match crate::engine::pages::op_paths(&am.ops) {
            Some(paths) => tx.ensure_paths(&tid, &ak, &paths)?,
            None => tx.load(&tid, &ak)?,
        }
        // large atomic values become chunk trees before the ops resolve
        let mut chunks = Vec::new();
        if kind == Kind::Content {
            let (_, _, framing) = framing_for(tx.core, &plan, &tid, &ak, am.schema.as_deref(), am.retention, am.expires)?;
            chunks = super::large::chunk_ops(tx, &tid, &ak, &mut am.ops, am.schema.as_deref(), &framing, &m.fresh)?;
        } else if kind == Kind::RosterSnapshot && ak.as_str() == "/tenures" {
            let (_, _, framing) = framing_for(tx.core, &plan, &tid, &ak, am.schema.as_deref(), am.retention, am.expires)?;
            chunks = super::large::chunk_frontiers(tx, &mut am.ops, &framing)?;
        }
        let lo = match m.form {
            Form::Node => tx.txn.counter(&tid, &ak)?,
            Form::Commit => next_ctr,
        };
        let w = Writer::new(ts, own_source(m.form, node), lo);
        let empty = Fragment::default();
        let state = tx.core.states.get(&(tid, ak.clone())).and_then(Option::as_ref).unwrap_or(&empty);
        let view = am.schema.as_ref().and_then(|s| s.view(ak.as_str()));
        let out = match &view {
            Some(v) => run_ops(state, w, &am.ops, v)?,
            None => run_ops(state, w, &am.ops, &AnyView)?,
        };
        let w2 = Writer::new(ts, own_source(m.form, node), lo);
        let out = match (out, m.dead_resets.get(&(tid, ak.clone())).filter(|d| !d.is_empty())) {
            (o, None) => o,
            (Some((mut f, r)), Some(ds)) => {
                f.join(osis_crdt::reset_entries(&w2, ds));
                Some((f, r))
            }
            (None, Some(ds)) => Some((osis_crdt::reset_entries(&w2, ds), w2.range())),
        };
        let Some((fragment, range)) = out else { continue };
        if m.form == Form::Commit {
            next_ctr = range.hi;
        }
        if let Some(s) = &am.schema {
            tx.core.schemas.entry(s.id).or_insert_with(|| s.clone());
        }
        deltas.push(Resolved { tid, ak, fragment, lo: range.lo, hi: range.hi, schema: am.schema, schema_ref: None, retention: am.retention, expires: am.expires, frontiers: None, chunks, split: kind == Kind::RosterSnapshot });
    }
    if deltas.is_empty() && plan.purge.is_empty() {
        return Ok(None);
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("a purge request needs a delta (reset what it names)"));
    }
    build_and_apply(tx, plan, deltas).map(Some)
}
