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
        Mutation { creates: Vec::new(), aspects: BTreeMap::new(), actor: None, form: Form::Node, purge: Vec::new(), undoes: None, frontier: None, unchecked: false }
    }

    /// The actor this node acts for (header field 2); default the node itself.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = Some(actor);
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

    /// The frontier of an explicit demotion (membership flows).
    pub fn frontier(&mut self, v: Value) -> &mut Self {
        self.frontier = Some(v);
        self
    }

    /// Skips the plain role check (membership flows judge invite grants and self-removals).
    #[allow(dead_code)]
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

/// May this node write `ak` of `tid` at `ts`? Things created by the commit take their owner's.
pub(crate) fn check_authority(core: &Core, creates: &[CreationRecord], tid: &Tid, ak: &str, ts: Ts) -> Result<()> {
    let node = core.id.tid();
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
    pub retention: Option<Retention>,
    pub expires: Option<u64>,
    /// A snapshot delta's frontiers (spec/crdt.md §8).
    pub frontiers: Option<osis_crdt::Frontiers>,
    /// Chunk blobs of large values the delta introduces (ID, prefix salt).
    pub chunks: Vec<(osis_core::BlobId, [u8; 16])>,
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

/// Encodes, pages, reserves counters, builds, signs and applies locally. Returns the ID.
pub(crate) fn build_and_apply(tx: &mut Tx<'_>, plan: CommitPlan, deltas: Vec<Resolved>) -> Result<CommitId> {
    let node = tx.core.id.tid();
    let mut writes = Vec::with_capacity(deltas.len());
    for d in deltas {
        let (retention, expires, framing) = framing_for(tx.core, &plan, &d.tid, &d.ak, d.schema.as_deref(), d.retention, d.expires)?;
        if expires.is_some() && !plan.purge.is_empty() {
            return Err(Error::Misuse("a commit with a purge request cannot carry expires (spec/commits.md §5)"));
        }
        let mut nonce = [0u8; osis_crdt::NONCE_LEN];
        tx.rng.fill_bytes(&mut nonce);
        let cx = writer_ctx(plan.kind, plan.ts, node, d.lo, d.hi);
        let mut blobs = TxBlobs::new(&mut tx.txn);
        let bytes = {
            let mut bw = BlobWriter::new(&framing, &mut blobs, &mut *tx.rng);
            match d.frontiers {
                Some(frontiers) => osis_crdt::encode_snapshot(&osis_crdt::Snapshot { nonce, fragment: d.fragment, frontiers }, &cx, Some(&mut bw))?,
                None => encode_delta(&Delta { nonce, fragment: d.fragment }, &cx, Some(&mut bw))?,
            }
        };
        let mut chunks = std::mem::take(&mut blobs.written);
        chunks.extend(d.chunks);
        if plan.form == Form::Node && plan.kind.has_own_writes() {
            let first = tx.txn.reserve_counters(&d.tid, &d.ak, d.hi.saturating_sub(d.lo))?;
            if first != d.lo {
                return Err(Error::Misuse("counter moved under the writer"));
            }
        }
        let schema: Option<(SchemaId, u64)> = d.schema.as_ref().filter(|s| s.aspects.contains_key(d.ak.as_str())).map(|s| (s.id, s.revision));
        writes.push(AspectWrite { tid: d.tid, ak: d.ak, lo: d.lo, hi: d.hi, deltas: vec![bytes], retention, expires, schema, chunks });
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
        b.build(&core.id.keys().signing, &secrets, &mut sink, &mut *tx.rng)
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
    let node = tx.core.id.tid();
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
    let membership = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && is_membership_class(ak.as_str()));
    let content = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && !is_membership_class(ak.as_str()));
    if membership && content {
        return Err(Error::Misuse("a commit is either content or membership"));
    }
    let kind = if membership { Kind::Membership } else { Kind::Content };
    if let Some(u) = m.undoes {
        return crate::undo::undo_in(tx, u, m.actor.unwrap_or(node)).map(Some).or_else(|e| match e {
            Error::Misuse("nothing to undo") => Ok(None),
            e => Err(e),
        });
    }
    let ts = tx.core.hlc.next();
    let plan = CommitPlan { kind, ts, actor: m.actor.unwrap_or(node), form: m.form, creates: std::mem::take(&mut m.creates), purge: std::mem::take(&mut m.purge), undoes: None, frontier: m.frontier.take(), origins: Vec::new() };
    let mut next_ctr = 1u64;
    let mut deltas = Vec::new();
    for ((tid, ak), mut am) in std::mem::take(&mut m.aspects) {
        let created_here = plan.creates.iter().any(|r| r.tid() == tid);
        if !created_here && tx.core.created(&tid).is_none() {
            return Err(Error::UnknownThing(tid));
        }
        if !m.unchecked {
            check_authority(tx.core, &plan.creates, &tid, ak.as_str(), ts)?;
        }
        // large atomic values become chunk trees before the ops resolve
        let mut chunks = Vec::new();
        if kind == Kind::Content {
            let (_, _, framing) = framing_for(tx.core, &plan, &tid, &ak, am.schema.as_deref(), am.retention, am.expires)?;
            let mut blobs = TxBlobs::new(&mut tx.txn);
            {
                let mut bw = BlobWriter::new(&framing, &mut blobs, &mut *tx.rng);
                for op in &mut am.ops {
                    super::large::chunk_op(op, am.schema.as_deref(), ak.as_str(), &mut bw)?;
                }
            }
            chunks = std::mem::take(&mut blobs.written);
        }
        let lo = match m.form {
            Form::Node => tx.txn.counter(&tid, &ak)?,
            Form::Commit => next_ctr,
        };
        let w = Writer::new(ts, Source::node(node), lo);
        tx.load(&tid, &ak)?;
        let empty = Fragment::default();
        let state = tx.core.states.get(&(tid, ak.clone())).and_then(Option::as_ref).unwrap_or(&empty);
        let view = am.schema.as_ref().and_then(|s| s.view(ak.as_str()));
        let out = match &view {
            Some(v) => run_ops(state, w, &am.ops, v)?,
            None => run_ops(state, w, &am.ops, &AnyView)?,
        };
        let Some((fragment, range)) = out else { continue };
        if m.form == Form::Commit {
            next_ctr = range.hi;
        }
        if let Some(s) = &am.schema {
            tx.core.schemas.entry(s.id).or_insert_with(|| s.clone());
        }
        deltas.push(Resolved { tid, ak, fragment, lo: range.lo, hi: range.hi, schema: am.schema, retention: am.retention, expires: am.expires, frontiers: None, chunks });
    }
    if deltas.is_empty() && plan.purge.is_empty() {
        return Ok(None);
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("a purge request needs a delta (reset what it names)"));
    }
    build_and_apply(tx, plan, deltas).map(Some)
}
