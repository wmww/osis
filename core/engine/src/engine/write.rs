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
use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, PurgeItem, writer_ctx};
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, Batch, CounterRange, Delta, Fragment, Op, PathOp, Source, View, Writer, encode_delta};
use osis_label::{BlobWriter, Framing};
use osis_perm::At;
use osis_schema::core_types::{CREATED, is_role_class};
use osis_schema::{AspectKey, Lifetime, Retention, Schema};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Ops on one aspect.
#[derive(Clone, Debug, Default)]
pub(crate) struct AspectMut {
    pub ops: Vec<PathOp>,
    pub schema: Option<Arc<Schema>>,
    pub retention: Option<Retention>,
    pub expires: Option<u64>,
    /// The key's default expiry (ms after the write): ephemeral writes fill it themselves.
    pub default_expiry: Option<u64>,
}

/// Creation records of a commit by tid (each `tid` is a hash: computed once).
pub(crate) type Creates = BTreeMap<Tid, CreationRecord>;

/// A batch of writes that becomes one commit.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub(crate) creates: Creates,
    pub(crate) aspects: BTreeMap<(Tid, Ak), AspectMut>,
    pub(crate) actor: Option<Tid>,
    /// `Engine::write` holds the batch to `actor`'s own rights first (`Mutation::confine`).
    pub(crate) confined: bool,
    pub(crate) form: Form,
    pub(crate) purge: Vec<PurgeItem>,
    pub(crate) undoes: Option<CommitId>,
    /// With `undoes`: things whose `created.0` the undone commit carries that it saved (drafts
    /// before it, `Engine::revert_change`): their writes are undone, they are not deleted.
    pub(crate) undo_keep: std::collections::BTreeSet<Tid>,
    pub(crate) frontier: Option<Value>,
    /// Role flows judge their own authority (invite grants, self-removals).
    pub(crate) unchecked: bool,
    /// A held key actor that signs instead of the node (commit form).
    pub(crate) signer: Option<Tid>,
    /// A roster snapshot (spec/permissions.md §6): role kind with the marker.
    pub(crate) roster: bool,
    /// Map entries to reset whatever their liveness here (spec/crdt.md §5.6): an explicit removal
    /// of an edge already removed (role flows).
    pub(crate) dead_resets: BTreeMap<(Tid, Ak), Vec<(osis_crdt::Dot, Value)>>,
    /// Chunk and node blobs never reused, written afresh (`Engine::relink`).
    pub(crate) fresh: std::collections::BTreeSet<osis_base::BlobId>,
    /// Things `Engine::write` persists with this batch if ephemeral.
    pub(crate) persist: std::collections::BTreeSet<Tid>,
    /// Ephemeral things deleted by this batch: freed after it (`Engine::write`).
    pub(crate) free: std::collections::BTreeSet<Tid>,
    /// The commit's `ts`, when taken before the commit (a batch with an ephemeral half).
    pub(crate) ts: Option<Ts>,
    /// Placements (thing, group) the commit must not leave unsynced (`require_synced`).
    pub(crate) synced: Vec<(Tid, Tid)>,
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
        Mutation { creates: Creates::new(), aspects: BTreeMap::new(), actor: None, confined: false, form: Form::Node, purge: Vec::new(), undoes: None, undo_keep: Default::default(), frontier: None, unchecked: false, signer: None, roster: false, dead_resets: BTreeMap::new(), fresh: Default::default(), persist: Default::default(), free: Default::default(), ts: None, synced: Vec::new() }
    }

    /// The actor this node acts for (header field 2); default the node itself.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = Some(actor);
        self
    }

    /// Acts for `actor` holding the batch to `actor`'s own rights, not this node's
    /// (`Engine::write`, engine/acting.rs).
    pub fn confine(&mut self, actor: Tid) -> &mut Self {
        self.actor = Some(actor);
        self.confined = true;
        self
    }

    /// Signs as a key actor whose seed the node holds (`Engine::hold_key_actor`): a recovery
    /// key or link key (spec/crypto.md §2). Commit form: its holders share no counters.
    pub fn sign_as(&mut self, key_actor: Tid) -> &mut Self {
        self.signer = Some(key_actor);
        self.form = Form::Commit;
        self
    }

    /// Takes the commit's `ts` now, from the engine's clock, and returns it: for a commit that must
    /// name itself before it exists (a removal's departs mark, spec/crypto.md §4).
    pub fn take_ts(&mut self, e: &mut crate::Engine) -> Ts {
        *self.ts.get_or_insert_with(|| e.core.hlc.next())
    }

    /// Commit-form dots (spec/commits.md §3).
    pub fn commit_form(&mut self) -> &mut Self {
        self.form = Form::Commit;
        self
    }

    /// Records a new thing; its `created.0` goes into this commit.
    pub fn create(&mut self, record: CreationRecord) -> Tid {
        let t = record.tid();
        self.creates.insert(t, record);
        t
    }

    fn entry<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<&mut AspectMut> {
        let ak = ak_of(key)?;
        let defaults = key.defaults();
        let e = self.aspects.entry((tid, ak)).or_insert_with(|| AspectMut { default_expiry: defaults.expires, ..AspectMut::default() });
        if e.schema.is_none() {
            e.schema = key.shared_schema();
        }
        Ok(e)
    }

    /// Persists `tid` with this batch if it is ephemeral (`Engine::write`): a role
    /// operation's or a move's target, persisted by a content commit first.
    pub fn persist(&mut self, tid: Tid) -> &mut Self {
        self.persist.insert(tid);
        self
    }

    /// Frees `tid` after this batch if it is still ephemeral then (`delete`).
    pub fn free(&mut self, tid: Tid) -> &mut Self {
        self.free.insert(tid);
        self
    }

    /// The commit fails `Error::Unsynced` when, after it, `tid` is durable and reaches no
    /// synced (labeled) group while `group`'s own data does: a placement into a group that is
    /// an item of a synced group but no subgroup of one (spec/data-model.md §8).
    pub fn require_synced(&mut self, tid: Tid, group: Tid) -> &mut Self {
        self.synced.push((tid, group));
        self
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

    /// The frontier of an explicit demotion (role flows).
    pub fn frontier(&mut self, v: Value) -> &mut Self {
        self.frontier = Some(v);
        self
    }

    /// Skips the plain role check (role flows judge invite grants and self-removals).
    pub(crate) fn unchecked(&mut self) -> &mut Self {
        self.unchecked = true;
        self
    }

    /// Tests: marks the commit a roster snapshot, whatever roster its writes hold.
    #[doc(hidden)]
    pub fn roster_for_tests(&mut self) -> &mut Self {
        self.roster = true;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.aspects.is_empty() && self.purge.is_empty() && self.undoes.is_none() && self.free.is_empty()
    }
}

/// The role a write of `ak` needs (spec/permissions.md §1, §3, §5.2): admin for edges,
/// `label.0`, `moved.0`, `was.0`, `tenures.0` and admin-only (`^`) aspects; write for rotations
/// (`secrets.0`, `keys.0`) and other content.
pub(crate) fn required_role(ak: &str) -> Role {
    match ak {
        "roles.0" | "label.0" | "moved.0" | "was.0" | "tenures.0" => Role::Admin,
        _ if Ak::markers_of(ak).0 => Role::Admin,
        _ => Role::Write,
    }
}

/// The role a compaction snapshot of `ak` needs (spec/permissions.md §5.2): the strictest any
/// write it carries could need, so admin for `keys.0` and `secrets.0` (admin keysets, inbox,
/// deposit seed, admin boxes and tombstones), else the aspect's role.
pub(crate) fn snapshot_role(ak: &str) -> Role {
    match ak {
        "keys.0" | "secrets.0" => Role::Admin,
        _ => required_role(ak),
    }
}

pub fn role_of(core: &Core, node: &Tid, tid: &Tid, ts: Ts) -> Option<Role> {
    core.timelines.get(tid)?.role(node, tid, At::now(ts))
}

/// Looks up the creation record of a thing not yet held as durable: the commit's own, or an
/// ephemeral thing's (`Engine::write`).
pub(crate) type Records<'a> = &'a dyn Fn(&Tid) -> Option<&'a CreationRecord>;

/// The role `node` has on `tid` at `ts`: things not held as durable (`records`) take their
/// owner's, through owners not held either (spec/permissions.md §1; notes/ephemeral.md Rights).
pub(crate) fn role_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ts: Ts) -> Option<Role> {
    let mut cur = *tid;
    // a deeper chain is invalid anyway (`within_depth`)
    for _ in 0..=osis_base::format::MAX_OWNER_DEPTH {
        return match records(&cur) {
            Some(CreationRecord::KeyActor { .. }) => (cur == node).then_some(Role::Admin),
            Some(CreationRecord::Thing { owner, .. }) if *owner == node => Some(Role::Admin),
            Some(CreationRecord::Thing { owner, .. }) => {
                cur = *owner;
                continue;
            }
            None => role_of(core, &node, &cur, ts),
        };
    }
    None
}

/// May `node` (this node or a key actor it signs as) write `ak` of `tid` at `ts`? Things
/// created by the commit take their owner's, through owners the commit creates too.
pub(crate) fn check_authority(core: &Core, node: Tid, creates: &Creates, tid: &Tid, ak: &str, ts: Ts) -> Result<()> {
    check_authority_with(core, node, &|t| creates.get(t), tid, ak, ts)
}

/// `check_authority` with the records not held as durable looked up by `records`.
pub(crate) fn check_authority_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ak: &str, ts: Ts) -> Result<()> {
    check_role_with(core, node, records, tid, ak, required_role(ak), ts)
}

/// `check_authority_with` needing role `need`.
pub(crate) fn check_role_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ak: &str, need: Role, ts: Ts) -> Result<()> {
    let role = role_with(core, node, records, tid, ts);
    if role >= Some(need) && (ak == CREATED.ak() || core.skip_writer_rules || within_depth(core, records, tid)) { Ok(()) } else { Err(Error::Permission { tid: *tid }) }
}

/// Whether `tid`'s owner chain, through the records not held as durable, reaches a key actor
/// within `MAX_OWNER_DEPTH` owner links (spec/permissions.md §1: a write deeper is invalid).
fn within_depth(core: &Core, records: Records<'_>, tid: &Tid) -> bool {
    let mut cur = *tid;
    for _ in 0..=osis_base::format::MAX_OWNER_DEPTH {
        match records(&cur).or_else(|| core.created(&cur)) {
            Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
            Some(CreationRecord::KeyActor { .. }) => return true,
            None => return false,
        }
    }
    false
}

/// `created.0` of `rec`: one write of its record by a writer at `ts` under `src` from counter
/// `lo`, and the next unused counter.
pub(crate) fn mint_created(rec: &CreationRecord, ts: Ts, src: Source, lo: u64) -> Option<(Fragment, u64)> {
    let w = Writer::new(ts, src, lo);
    let view = osis_schema::core_schema().view(CREATED.ak())?;
    let (f, r) = run_ops(&Fragment::default(), w, &[PathOp { path: Vec::new(), op: Op::Set(rec.to_value()) }], &view).ok()??;
    Some((f, r.hi))
}

/// Whether `f` is exactly what `mint_created` makes of `rec` under some source (spec/commits.md
/// §2): no other write (losing junk every holder would keep) fits.
pub(crate) fn is_minting(f: &Fragment, rec: &CreationRecord) -> bool {
    let writes = f.writes();
    let Some((first, Some(ts))) = writes.first() else { return false };
    if writes.iter().any(|(d, t)| d.src != first.src || *t != Some(*ts)) {
        return false;
    }
    let lo = writes.iter().map(|(d, _)| d.ctr).min().unwrap_or(first.ctr);
    mint_created(rec, *ts, first.src.clone(), lo).is_some_and(|(m, _)| m == *f)
}

pub(crate) fn run_ops<V: View>(state: &Fragment, w: Writer, ops: &[PathOp], view: &V) -> Result<Option<(Fragment, CounterRange)>> {
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
    /// A snapshot delta's frontiers and absorbed commits (spec/crdt.md §8).
    pub frontiers: Option<(osis_crdt::Frontiers, std::collections::BTreeMap<osis_base::CommitId, Tid>)>,
    /// Chunk blobs of large values the delta introduces.
    pub chunks: Vec<osis_base::BlobId>,
    /// Written as one delta per root map entry or set element (a roster snapshot).
    pub split: bool,
    /// Creation records carried beside the delta (a memory commit, `memory_records`).
    pub records: Vec<CreationRecord>,
}

/// Inputs of a commit other than its deltas.
pub(crate) struct CommitPlan {
    pub kind: Kind,
    pub ts: Ts,
    pub actor: Tid,
    pub form: Form,
    pub creates: Creates,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    pub frontier: Option<Value>,
    pub origins: Vec<osis_commit::Origin>,
    /// The signing key actor: the node, or a key actor it holds.
    pub signer: Tid,
    /// The header's blind: chunks and pages are framed under it before the header exists
    /// (spec/crypto.md §7).
    pub blind: [u8; 16],
}

/// A fresh header blind.
pub(crate) fn draw_blind(rng: &mut dyn osis_crypto::CryptoRngCore) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// Retention, expiry and blob framing of one aspect's delta in a commit (spec/commits.md §5,
/// §6; spec/crypto.md §7).
/// `published`: [`super::secrets::published_keys`] of the commit's things.
#[allow(clippy::too_many_arguments)]
pub(crate) fn framing_for(core: &Core, plan: &CommitPlan, published: &BTreeMap<(Tid, osis_base::Role), osis_crypto::VerifyingKey>, tid: &Tid, ak: &Ak, schema: Option<&Schema>, r: Option<Retention>, e: Option<u64>) -> Result<(Retention, Option<u64>, Framing)> {
    let defaults = schema.and_then(|s| s.defaults(ak.as_str()));
    let retention = match plan.kind {
        // a compaction snapshot's own (`Engine::snapshot`), never from schema defaults
        Kind::ContentSnapshot | Kind::RoleSnapshot => r.unwrap_or_else(|| osis_commit::retention::snapshot_retention(ak.as_str(), [], 0)),
        _ => osis_commit::retention::write_retention(ak.as_str(), defaults.as_ref(), r)?,
    };
    let expires = match plan.kind {
        Kind::Content => osis_commit::retention::write_expires(ak.as_str(), plan.ts, defaults.as_ref(), e)?,
        _ => None,
    };
    let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates, published };
    let keys = osis_commit::delete_keys(&secrets, tid, &retention, plan.kind)?;
    let dedup = osis_commit::Secrets::dedup(&secrets, tid).ok_or(Error::UnknownThing(*tid))?;
    let framing = Framing { dedup, expiry: expires.map(WallMs), blind: plan.blind, keys: keys.iter().map(|k| Ok((k.level, k.verifying_key()?))).collect::<std::result::Result<_, osis_commit::Error>>()? };
    Ok((retention, expires, framing))
}

/// The writer's own source: the author node or session, or for commit form a placeholder
/// commit that sorts below every other commit like the real one will (spec/crdt.md §3.3 rule 2).
/// Past this next counter an aspect is written in commit form (spec/crdt.md §2.1): a writer's
/// snapshot frontier may claim any counter of this node up to the wire's 2^63 - 1, which this
/// node then skips (`raise_counter`), and node form above it could not be encoded. Honest
/// writing never nears it; a lie leaves at least 2^62 counters or none.
const MAX_NODE_COUNTER: u64 = 1 << 62;

/// Whether this node may write node form on every aspect of `keys` (spec/crdt.md §2.1): it is
/// sure of the thing's counters (`Core::counters_sure`; a thing `creates` holds has no counters
/// elsewhere) and has not passed `MAX_NODE_COUNTER`.
pub(crate) fn node_form_ok<'a>(tx: &mut Tx<'_>, keys: impl IntoIterator<Item = &'a (Tid, Ak)>, creates: &Creates) -> Result<bool> {
    for (t, ak) in keys {
        if (!creates.contains_key(t) && !tx.core.counters_sure(t)) || tx.txn.counter(t, ak)? > MAX_NODE_COUNTER {
            return Ok(false);
        }
    }
    Ok(true)
}

fn own_source(form: Form, node: Tid) -> Source {
    form.own_source(node, osis_base::CommitId([0; 32]))
}

/// Encodes, pages, reserves counters, builds, signs and applies locally. Returns the ID.
pub(crate) fn build_and_apply(tx: &mut Tx<'_>, plan: CommitPlan, deltas: Vec<Resolved>) -> Result<CommitId> {
    let node = plan.signer;
    let published = super::secrets::published_keys(tx, &plan.creates, deltas.iter().map(|d| d.tid))?;
    let mut writes = Vec::with_capacity(deltas.len());
    for d in deltas {
        let (retention, expires, framing) = framing_for(tx.core, &plan, &published, &d.tid, &d.ak, d.schema.as_deref(), d.retention, d.expires)?;
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
                Some((frontiers, absorbed)) => osis_crdt::encode_snapshot(&osis_crdt::Snapshot { nonce, fragment, frontiers, absorbed }, &cx, Some(&mut bw))?,
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
            let (keep, drop): (Vec<_>, Vec<_>) = own.into_iter().partition(|id| linked.contains(id));
            for id in &drop {
                tx.txn.delete_blob(id);
            }
            own = keep;
        }
        chunks.extend(own);
        if plan.form.counted() && plan.kind.has_own_writes() {
            let first = tx.txn.reserve_counters(&d.tid, &d.ak, d.hi.saturating_sub(d.lo))?;
            if first != d.lo {
                return Err(Error::Misuse("counter moved under the writer"));
            }
        }
        writes.push(AspectWrite { tid: d.tid, ak: d.ak, lo: d.lo, hi: d.hi, deltas: bytes, retention, expires, chunks, records: d.records });
    }
    let mut b = CommitBuilder::new(plan.kind, plan.ts, node, plan.actor, plan.form);
    b.aspects = writes;
    b.purge = plan.purge;
    b.undoes = plan.undoes;
    b.frontier = plan.frontier;
    b.blind = Some(plan.blind);
    b.origins = plan.origins;
    // a session-form commit is a memory commit (spec/commits.md §2, §3)
    b.ephemeral = matches!(plan.form, Form::Session(_)).then_some(osis_commit::EphClass::Plain);
    let built = {
        let core: &Core = tx.core;
        let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates, published: &published };
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
    Ok(id)
}

impl Engine {
    /// The labeled groups whose labels have not passed completely since the sync layer started
    /// (`Core::counters_sure`): its writes on their things use commit form until they have.
    pub fn set_counters_unsure(&mut self, groups: BTreeSet<Tid>) {
        self.core.counters_unsure = Some(groups);
    }

    /// A new thing owned by `owner`, created by `m` (spec/data-model.md §1).
    pub fn new_thing(&mut self, m: &mut Mutation, owner: Tid) -> Tid {
        m.create(self.thing_record(owner))
    }

    /// The creation record of a new thing owned by `owner` (`Mutation::create` writes it).
    pub fn thing_record(&mut self, owner: Tid) -> CreationRecord {
        crate::identity::thing_record(owner, None, &mut *self.rng)
    }

    /// A new copy owned by `owner` that this node creates and imports into (spec/permissions.md §7).
    pub(crate) fn new_copy(&mut self, m: &mut Mutation, owner: Tid) -> Tid {
        let me = self.core.id.tid();
        m.create(crate::identity::thing_record(owner, Some(me), &mut *self.rng))
    }

    /// Commits `m`; `None` when it changes nothing.
    pub fn commit(&mut self, m: Mutation) -> Result<Option<CommitId>> {
        self.run(|tx| commit_in(tx, m))
    }

    /// Commits `m` as a memory commit: session form under this open's session, the ephemeral
    /// marker, every row it derives in the store's memory overlay (no disk I/O, gone at
    /// restart). Benches and tests until memory commits land (issues/eph-unify.md step 3); the
    /// aspects it writes must hold no durable row.
    #[doc(hidden)]
    pub fn commit_in_memory(&mut self, mut m: Mutation) -> Result<Option<CommitId>> {
        m.form = Form::Session(self.eph.session().nonce);
        self.run(|tx| {
            tx.set_memory();
            commit_in(tx, m)
        })
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
    let memory = tx.txn.is_memory();
    for &t in m.creates.keys() {
        if tx.core.created(&t).is_some() {
            return Err(Error::Misuse("thing already exists"));
        }
    }
    // an aspect's class is its key's lifetime marker (spec/commits.md §2): a memory commit
    // writes `~` aspects only, a durable one unmarked ones only (a durable write on a memory thing
    // is a durable commit persisting it, spec/data-model.md §1); tests let a local writer break
    // this, to test receivers
    let class = if memory { Lifetime::Ephemeral } else { Lifetime::Durable };
    if !tx.core.skip_writer_rules && m.aspects.keys().any(|(_, ak)| ak.lifetime() != class) {
        return Err(Error::Misuse(if memory { "a memory commit writes ephemeral aspects only" } else { "a durable commit writes durable aspects only" }));
    }
    if memory {
        // a memory commit's records are held here at once and travel beside its deltas
        // (spec/commits.md §2): a thing made with no write is known all the same
        for rec in std::mem::take(&mut m.creates).into_values() {
            let t = rec.tid();
            tx.txn.put_local(&[super::records::CREATED, t.as_bytes()].concat(), &osis_base::encode(&rec.to_value()), osis_store::Shred::No)?;
            tx.core.ix.held.create_memory(rec);
        }
        tx.core.update_timelines();
    } else {
        // a durable write on a thing held as memory class persists it with its memory owner
        // chain (spec/data-model.md §1)
        for t in m.aspects.keys().map(|k| k.0).collect::<BTreeSet<Tid>>() {
            for (x, rec) in memory_chain(tx.core, &t) {
                m.creates.entry(x).or_insert(rec);
            }
        }
    }
    for (&t, rec) in &m.creates {
        let e = m.aspects.entry((t, Ak::new(CREATED.ak()).map_err(|_| Error::Misuse("ak"))?)).or_default();
        e.schema = Some(core_schema.clone());
        e.ops.push(PathOp { path: Vec::new(), op: Op::Set(rec.to_value()) });
    }
    let dead: Vec<(Tid, Ak)> = m.dead_resets.keys().cloned().collect();
    for k in dead {
        m.aspects.entry(k).or_default();
    }
    let role_commit = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && is_role_class(ak.as_str()));
    let content = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && !is_role_class(ak.as_str()));
    if role_commit && content {
        return Err(Error::Misuse("a commit is either a content or a role commit"));
    }
    let kind = match m.roster {
        true if role_commit => Kind::RosterSnapshot,
        true => return Err(Error::Misuse("a roster snapshot writes roles.0 and tenures.0 only")),
        false if role_commit => Kind::Role,
        false => Kind::Content,
    };
    if let Some(u) = m.undoes {
        return crate::undo::undo_in(tx, u, m.actor.unwrap_or(node), m.ts, &m.undo_keep, m.confined).map(Some).or_else(|e| match e {
            Error::Misuse("nothing to undo") => Ok(None),
            e => Err(e),
        });
    }
    // role commits use commit form: a later commit by the same node can never void
    // them by reusing their counters (spec/commits.md §3)
    if kind != Kind::Content {
        m.form = Form::Commit;
    }
    if m.form == Form::Node && !node_form_ok(tx, m.aspects.keys(), &m.creates)? {
        m.form = Form::Commit;
    }
    let ts = m.ts.unwrap_or_else(|| tx.core.hlc.next());
    let plan = CommitPlan { kind, ts, actor: m.actor.unwrap_or(node), form: m.form, creates: std::mem::take(&mut m.creates), purge: std::mem::take(&mut m.purge), undoes: None, frontier: m.frontier.take(), origins: Vec::new(), signer: node, blind: draw_blind(&mut *tx.rng) };
    let mut next_ctr = 1u64;
    let mut deltas = Vec::new();
    let published = super::secrets::published_keys(tx, &plan.creates, m.aspects.keys().map(|k| k.0))?;
    for ((tid, ak), mut am) in std::mem::take(&mut m.aspects) {
        let created_here = plan.creates.contains_key(&tid);
        if !created_here && tx.core.created_for(&tid, memory).is_none() {
            return Err(Error::UnknownThing(tid));
        }
        if !m.unchecked {
            check_authority(tx.core, node, &plan.creates, &tid, ak.as_str(), ts)?;
        }
        let framing = match kind {
            Kind::Content => Some(framing_for(tx.core, &plan, &published, &tid, &ak, am.schema.as_deref(), am.retention, am.expires)?.2),
            _ => None,
        };
        // what the ops address (map keys, fields, set values: a large one by its link, as the
        // state holds it)
        let paths = match &framing {
            Some(f) => super::pages::op_paths(&am.ops, &mut |v| super::large::lookup_form(v, &f.dedup))?,
            None => super::pages::op_paths(&am.ops, &mut |v| Ok(v.clone()))?,
        };
        // a list edit's items by content hash and its window (what the pages it needs follow from)
        let edits = match &framing {
            Some(f) => super::large::list_edits(&am.ops, am.schema.as_deref(), ak.as_str(), &f.dedup)?,
            None => Vec::new(),
        };
        let attached = tx.load_for_ops(&tid, &ak, paths, &am.ops, &edits)?;
        // large atomic values become chunk trees before the ops resolve
        let mut chunks = Vec::new();
        if let Some(framing) = &framing {
            chunks = super::large::chunk_ops(tx, &tid, &ak, &mut am.ops, &edits, am.schema.as_deref(), framing, &m.fresh)?;
        } else if kind == Kind::RosterSnapshot && ak.as_str() == "tenures.0" {
            let (_, _, framing) = framing_for(tx.core, &plan, &published, &tid, &ak, am.schema.as_deref(), am.retention, am.expires)?;
            chunks = super::large::chunk_frontiers(tx, &mut am.ops, &framing)?;
        }
        let lo = match m.form {
            Form::Commit => next_ctr,
            // a session's counters: rows of memory aspects, gone with the session
            Form::Node | Form::Session(_) => tx.txn.counter(&tid, &ak)?,
        };
        let empty = Fragment::default();
        let view = am.schema.as_ref().and_then(|s| s.view(ak.as_str()));
        // map removals carry their key only where keys are public ids (spec/crdt.md §5.6)
        let keyed = osis_schema::core_types::is_role_class(ak.as_str());
        let run = |tx: &Tx<'_>| {
            let state = tx.cached(&tid, &ak).unwrap_or(&empty);
            let w = Writer::new(ts, own_source(m.form, node), lo).keyed_removals(keyed);
            match &view {
                Some(v) => run_ops(state, w, &am.ops, v),
                None => run_ops(state, w, &am.ops, &AnyView),
            }
        };
        let out = tx.run_attached(&tid, &ak, attached, run)??;
        let w2 = Writer::new(ts, own_source(m.form, node), lo).keyed_removals(keyed);
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
            keep_schema(tx, s, false)?;
        }
        let records = if memory { memory_records(tx.core, &tid, &ak, &am.ops) } else { Vec::new() };
        deltas.push(Resolved { tid, ak, fragment, lo: range.lo, hi: range.hi, schema: am.schema, retention: am.retention, expires: am.expires, frontiers: None, chunks, split: kind == Kind::RosterSnapshot, records });
    }
    if deltas.is_empty() && plan.purge.is_empty() {
        return Ok(None);
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("a purge request needs a delta (reset what it names)"));
    }
    let id = build_and_apply(tx, plan, deltas)?;
    check_synced(tx.core, &m.synced)?;
    Ok(Some(id))
}

/// The memory-class records from `t` up its owner chain (each with its tid): what persisting `t`
/// carries, and what a memory commit on `t` carries beside its delta.
pub(crate) fn memory_chain(core: &Core, t: &Tid) -> Vec<(Tid, CreationRecord)> {
    let mut out = Vec::new();
    let mut cur = *t;
    for _ in 0..=osis_base::format::MAX_OWNER_DEPTH {
        if !core.ix.held.is_memory(&cur) {
            break;
        }
        let Some(rec) = core.created(&cur) else { break };
        out.push((cur, rec.clone()));
        match rec {
            CreationRecord::Thing { owner, .. } => cur = *owner,
            CreationRecord::KeyActor { .. } => break,
        }
    }
    out
}

/// The records a memory commit carries beside its delta on `(tid, ak)` (spec/commits.md §2):
/// the memory chains of `tid` and, on `placed.0~`, of the things its ops place that have `tid`'s
/// reader (a record names its nonce, its dedup secret: never shown to another reader).
fn memory_records(core: &Core, tid: &Tid, ak: &Ak, ops: &[PathOp]) -> Vec<CreationRecord> {
    let mut things = vec![*tid];
    if ak.as_str() == osis_schema::core_types::PLACED.ak() {
        let reader = core.reader_of(tid);
        things.extend(ops.iter().filter_map(|o| match &o.op {
            Op::Add(Value::Tid(x)) if core.reader_of(x) == reader => Some(*x),
            _ => None,
        }));
    }
    let recs: BTreeMap<Tid, CreationRecord> = things.iter().flat_map(|t| memory_chain(core, t)).collect();
    recs.into_values().collect()
}

/// `Mutation::require_synced`, over the state the commit left.
fn check_synced(core: &Core, placed: &[(Tid, Tid)]) -> Result<()> {
    let lab = &core.ix.labeled;
    let in_synced = |x: &Tid| core.ix.groups.of.get(x).is_some_and(|s| s.iter().any(|h| lab.contains(h)));
    for (t, g) in placed {
        if core.durable_created(t).is_some() && !lab.contains(t) && !in_synced(t) && in_synced(g) {
            return Err(Error::Unsynced { tid: *t, group: *g });
        }
    }
    Ok(())
}

/// Records schema `s` as the local schema of each AK it declares, in memory and in the store
/// (`records::SCHEMAS`, one record per AK), unless the one kept has a higher version (a stale
/// app never downgrades it) or the same one and this is a local write, not a registration
/// (`replace`). An equal one writes nothing (every open re-registers). Versions of unrelated
/// schemas claiming one AK compare too: a collision is the convention's failure (spec/versioning.md
/// §3) and this keeps the choice deterministic. The core schema is compiled in, never kept.
pub(crate) fn keep_schema(tx: &mut Tx<'_>, s: &Arc<osis_schema::Schema>, replace: bool) -> Result<()> {
    if s.declares_core() {
        return Ok(());
    }
    let mut bytes = None;
    for ak in s.aspects.keys() {
        if let Some(k) = tx.core.schemas.get(ak)
            && (**k == **s || k.version > s.version || (!replace && k.version == s.version))
        {
            continue;
        }
        tx.core.schemas.insert(ak.clone(), s.clone());
        let b = bytes.get_or_insert_with(|| s.canonical_bytes());
        tx.txn.put_local(&[super::records::SCHEMAS, ak.as_bytes()].concat(), b, osis_store::Shred::No)?;
    }
    Ok(())
}
