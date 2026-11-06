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
use osis_base::{Ak, ChainStep, CommitId, CreationRecord, Role, Tid, Ts, Value, WallMs, owner_chain};
use osis_crdt::{AnyView, Batch, CounterRange, Delta, Fragment, Op, PathOp, Source, Unpaged, View, Writer, encode_delta};
use osis_label::{BlobWriter, Framing};
use osis_perm::At;
use osis_schema::core_types::{CREATED, is_role_class};
use osis_schema::{RawKey, Lifetime, Retention, Schema};
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
    /// Commit-form dots (spec/commits.md §3); else session form.
    pub(crate) commit_form: bool,
    pub(crate) purge: Vec<PurgeItem>,
    pub(crate) undoes: Option<CommitId>,
    /// With `undoes`: things whose `created.0` the undone commit carries that it saved (drafts
    /// before it, `Engine::revert_batch`): their writes are undone, they are not deleted.
    pub(crate) undo_keep: std::collections::BTreeSet<Tid>,
    pub(crate) frontier: Option<Value>,
    /// Role flows judge their own authority (invite grants, self-removals).
    pub(crate) unchecked: bool,
    /// A held key actor that signs instead of the node (commit form).
    pub(crate) signer: Option<Tid>,
    /// Map entries to reset whatever their liveness here (spec/crdt.md §5.6): an explicit removal
    /// of an edge already removed (role flows).
    pub(crate) dead_resets: BTreeMap<(Tid, Ak), Vec<(osis_crdt::Dot, Value)>>,
    /// Map keys holding no entry to reset anyway (spec/permissions.md §2: a removal of a first
    /// admin's record edge, stored nowhere): each gets an entry of the delta's own, at a fresh
    /// counter, holding nothing but the reset, so the removal names its key and its creation is
    /// the delta itself.
    pub(crate) fresh_resets: BTreeMap<(Tid, Ak), Vec<Value>>,
    /// Aspects whose hidden records this commit resets (`Fragment::sweep`, compaction).
    pub(crate) sweeps: BTreeSet<(Tid, Ak)>,
    /// Chunk and node blobs never reused, written afresh (`Engine::relink`).
    pub(crate) fresh: std::collections::BTreeSet<osis_base::BlobId>,
    /// Things `Engine::write` persists with this batch if ephemeral.
    pub(crate) persist: std::collections::BTreeSet<Tid>,
    /// Ephemeral things deleted by this batch: freed after it (`Engine::write`).
    pub(crate) free: std::collections::BTreeSet<Tid>,
    /// The commit's `ts`, when taken before the commit (a batch with an ephemeral half).
    pub(crate) ts: Option<Ts>,
    /// Memberships (thing, group) the commit must not leave unsynced (`require_synced`).
    pub(crate) synced: Vec<(Tid, Tid)>,
}

impl Default for Mutation {
    fn default() -> Mutation {
        Mutation::new()
    }
}

fn ak_of<K: RawKey>(key: &K) -> Result<Ak> {
    Ak::new(key.ak()).map_err(|_| Error::Misuse("invalid AK"))
}

impl Mutation {
    pub fn new() -> Mutation {
        Mutation { creates: Creates::new(), aspects: BTreeMap::new(), actor: None, confined: false, commit_form: false, purge: Vec::new(), undoes: None, undo_keep: Default::default(), frontier: None, unchecked: false, signer: None, dead_resets: BTreeMap::new(), fresh_resets: BTreeMap::new(), sweeps: BTreeSet::new(), fresh: Default::default(), persist: Default::default(), free: Default::default(), ts: None, synced: Vec::new() }
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
        self.commit_form = true;
        self
    }

    /// Takes the commit's `ts` now, from the engine's clock, and returns it.
    pub fn take_ts(&mut self, e: &mut crate::Engine) -> Ts {
        *self.ts.get_or_insert_with(|| e.core.hlc.next())
    }

    /// Commit-form dots (spec/commits.md §3).
    pub fn commit_form(&mut self) -> &mut Self {
        self.commit_form = true;
        self
    }

    /// Records a new thing; its `created.0` goes into this commit.
    pub fn create(&mut self, record: CreationRecord) -> Tid {
        let t = record.tid();
        self.creates.insert(t, record);
        t
    }

    fn entry<K: RawKey>(&mut self, tid: Tid, key: &K) -> Result<&mut AspectMut> {
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
    /// synced (labeled) group while `group`'s own data does: a membership in a group that is
    /// an item of a synced group but no subgroup of one (spec/data-model.md §8).
    pub fn require_synced(&mut self, tid: Tid, group: Tid) -> &mut Self {
        self.synced.push((tid, group));
        self
    }

    /// An op at a path (validated by the crdt against the writer's view).
    pub fn op<K: RawKey>(&mut self, tid: Tid, key: &K, op: PathOp) -> Result<&mut Self> {
        self.entry(tid, key)?.ops.push(op);
        Ok(self)
    }

    /// Makes the aspect read `v` (structural diff, spec/crdt.md §9).
    pub fn set<K: RawKey>(&mut self, tid: Tid, key: &K, v: &K::T) -> Result<&mut Self> {
        let v = key.encode(v);
        key.validate(&v)?;
        self.op(tid, key, PathOp { path: Vec::new(), op: Op::Set(v) })
    }

    /// Resets the aspect, then writes `v`.
    pub fn replace<K: RawKey>(&mut self, tid: Tid, key: &K, v: &K::T) -> Result<&mut Self> {
        let v = key.encode(v);
        key.validate(&v)?;
        self.op(tid, key, PathOp { path: Vec::new(), op: Op::Replace(v) })
    }

    /// Removes the aspect (spec/crdt.md §4.3: absent afterwards).
    pub fn remove_aspect<K: RawKey>(&mut self, tid: Tid, key: &K) -> Result<&mut Self> {
        self.op(tid, key, PathOp { path: Vec::new(), op: Op::RemoveAspect })
    }

    /// Resets the hidden records of `(tid, ak)` (`Fragment::sweep`); the schema gives its retention.
    pub(crate) fn sweep(&mut self, tid: Tid, ak: Ak, schema: Option<Arc<Schema>>) {
        self.aspects.entry((tid, ak.clone())).or_default().schema = schema;
        self.sweeps.insert((tid, ak));
    }

    /// Retention for this aspect's delta, instead of the schema default (spec/commits.md §5).
    pub fn retention<K: RawKey>(&mut self, tid: Tid, key: &K, r: Retention) -> Result<&mut Self> {
        self.entry(tid, key)?.retention = Some(r);
        Ok(self)
    }

    /// Expiry T (wall ms) for this aspect's delta, raised to just after the commit's `ts` if that
    /// has passed it (spec/commits.md §6).
    pub fn expires<K: RawKey>(&mut self, tid: Tid, key: &K, t: WallMs) -> Result<&mut Self> {
        self.entry(tid, key)?.expires = Some(t.0);
        Ok(self)
    }

    /// Expiry T (wall ms) for the delta of every aspect written so far (`expires`).
    pub fn expires_all(&mut self, t: WallMs) -> &mut Self {
        for a in self.aspects.values_mut() {
            a.expires = Some(t.0);
        }
        self
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

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.aspects.is_empty() && self.purge.is_empty() && self.undoes.is_none() && self.free.is_empty()
    }
}

/// The role a write of `ak` needs (spec/permissions.md §1, §3, §5.2): admin for edges,
/// `label.0` and admin-only (`^`) aspects; write for rotations
/// (`secrets.0`, `keys.0`) and other content.
pub(crate) fn required_role(ak: &str) -> Role {
    match ak {
        "roles.0" | "label.0" => Role::Admin,
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

/// The role `node` has on `tid` at `ts`: a thing not held as durable (`records`) has its
/// record edge alone, so a node's role on it is its role on its first admin
/// (spec/permissions.md §1; notes/ephemeral.md Rights).
pub(crate) fn role_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ts: Ts) -> Option<Role> {
    match owner_chain(*tid, |t| records(t).map(CreationRecord::owner_link)).next() {
        Some(ChainStep::Up { admin, .. }) if admin == node => Some(Role::Admin),
        Some(ChainStep::Up { admin, .. }) => role_with(core, node, records, &admin, ts),
        Some(ChainStep::Key(k)) => (k == node).then_some(Role::Admin),
        Some(ChainStep::Unknown(t)) => role_of(core, &node, &t, ts),
        // a deeper chain is invalid anyway (`within_depth`)
        Some(ChainStep::TooDeep) | None => None,
    }
}

/// May `node` (this node or a key actor it signs as) write `ak` of `tid` at `ts`? Things
/// created by the commit take their first admin's, through first admins the commit creates too.
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

/// May `node` act for `actor` at `ts`: it is the actor or holds write on it? A receiver judges a
/// commit invalid otherwise (`validity::acts_for`, spec/permissions.md §5.2).
pub(crate) fn check_acts(core: &Core, node: Tid, records: Records<'_>, actor: &Tid, ts: Ts) -> Result<()> {
    if node == *actor || role_with(core, node, records, actor, ts) >= Some(Role::Write) { Ok(()) } else { Err(Error::Permission { tid: *actor }) }
}

/// Whether `tid`'s record chain, through the records not held as durable, reaches a key actor
/// within `MAX_OWNER_DEPTH` links (spec/permissions.md §1: a write deeper is invalid).
fn within_depth(core: &Core, records: Records<'_>, tid: &Tid) -> bool {
    let end = owner_chain(*tid, |t| records(t).or_else(|| core.created(t)).map(CreationRecord::owner_link)).end();
    matches!(end, ChainStep::Key(_))
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
    /// Creation records carried beside the delta (a memory commit, `memory_records`).
    pub records: Vec<CreationRecord>,
}

/// Inputs of a commit other than its deltas.
#[derive(Clone)]
pub(crate) struct CommitPlan {
    pub kind: Kind,
    pub ts: Ts,
    pub actor: Tid,
    pub form: Form,
    pub creates: Creates,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    pub frontier: Option<Value>,
    /// The signing key actor: the node, or a key actor it holds.
    pub signer: Tid,
    /// The header's blind: chunks and pages are framed under it before the header exists
    /// (spec/crypto.md §7).
    pub blind: [u8; 16],
    /// The commit's expiry (spec/commits.md §6): every delta's.
    pub expires: Option<u64>,
    /// An undo's: `expires` stands, whatever its keys' defaults (`build_one`).
    pub restores: bool,
}

/// A fresh header blind.
pub(crate) fn draw_blind(rng: &mut dyn osis_crypto::CryptoRngCore) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// Retention and expiry of one aspect's delta in a commit of `kind` at `ts` by `signer`
/// (spec/commits.md §5, §6): the thing's required retention fills what the writer did not, and
/// refuses what breaks it; then the given ones, the schema's defaults, the untyped default.
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle(core: &Core, memory: bool, kind: Kind, ts: Ts, signer: Tid, tid: &Tid, ak: &Ak, schema: Option<&Schema>, mut r: Option<Retention>, mut e: Option<u64>) -> Result<(Retention, Option<u64>)> {
    let mut defaults = schema.and_then(|s| s.defaults(ak.as_str()));
    // a hostile test writer writes what it is told
    if kind == Kind::Content && !core.skip_writer_rules && ak.lifetime() != osis_schema::Lifetime::Ephemeral && osis_commit::retention::fixed_retention(ak.as_str()).is_none() && let Some(q) = crate::apply::validity::required_now(core, tid, ak, signer, ts) {
        let want = q.expires_at(ts.wall_ms().0).ok_or(Error::Misuse("expiry out of range"))?;
        if r.is_some_and(|x| x != q.retention()) || e.is_some_and(|x| Some(x) != want) {
            return Err(Error::Misuse("a retention or expiry other than the thing requires"));
        }
        r = Some(q.retention());
        e = want;
        defaults = None;
    }
    let retention = if memory || ak.lifetime() == osis_schema::Lifetime::Ephemeral {
        osis_commit::retention::EPHEMERAL_RETENTION
    } else {
        match kind {
            // a compaction snapshot's own (`Engine::snapshot`), never from schema defaults
            Kind::ContentSnapshot | Kind::RoleSnapshot => r.unwrap_or_else(|| osis_commit::retention::snapshot_retention(ak.as_str(), [], 0)),
            _ => osis_commit::retention::write_retention(ak.as_str(), defaults.as_ref(), r)?,
        }
    };
    let expires = match kind {
        Kind::Content => osis_commit::retention::write_expires(ak.as_str(), ts, defaults.as_ref(), e)?,
        _ => None,
    };
    Ok((retention, expires))
}

/// Blob framing of one aspect's delta in a commit of `plan` with retention `retention`
/// (spec/crypto.md §7): its thing's dedup secret, the commit's expiry and blind, the delete keys
/// the retention calls for. `published`: [`super::secrets::published_keys`] of the commit's things.
pub(crate) fn framing_for(core: &Core, plan: &CommitPlan, published: &BTreeMap<(Tid, osis_base::Role), osis_crypto::VerifyingKey>, tid: &Tid, retention: &Retention) -> Result<Framing> {
    let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates, published };
    let keys = osis_commit::delete_keys(&secrets, tid, retention)?;
    let dedup = osis_commit::Secrets::dedup(&secrets, tid).ok_or(Error::UnknownThing(*tid))?;
    Ok(Framing { dedup, expiry: plan.expires.map(WallMs), blind: plan.blind, keys: keys.iter().map(|k| Ok((k.level, k.verifying_key()?))).collect::<std::result::Result<_, osis_commit::Error>>()? })
}

/// The one expiry of a commit of these deltas (`entries`: thing, AK, retention, expiry; spec/commits.md
/// §5, §6), or `Clash` naming what cannot share a commit: different expiries, a `nobody` delta beside
/// others (a thing's record and `required.0^` go with any), or an expiry beside a record,
/// `required.0^` or a purge request, which carry none. `way`: what the caller can do about it.
fn one_commit(entries: &[(Tid, &Ak, &Retention, Option<u64>)], purge: bool, way: &str) -> Result<Option<u64>> {
    let free = |ak: &Ak| ak.as_str() == CREATED.ak() || ak.as_str() == osis_commit::retention::REQUIRED;
    let name = |t: &Tid, ak: &Ak, e: Option<u64>| match e {
        Some(e) => format!("{t} {ak} (expires at {e})"),
        None => format!("{t} {ak} (does not expire)"),
    };
    let mut bound = entries.iter().filter(|e| !free(e.1));
    let first = bound.next();
    if let Some(a) = first {
        if let Some(b) = bound.clone().find(|b| b.3 != a.3) {
            return Err(Error::Clash(format!("a commit has one expiry, and this write has two: {} and {}. {way}", name(&a.0, a.1, a.3), name(&b.0, b.1, b.3))));
        }
        let nobody = |e: &&(Tid, &Ak, &Retention, Option<u64>)| e.2.by == osis_schema::PurgeBy::Nobody;
        if let (Some(n), Some(o)) = (entries.iter().filter(|e| !free(e.1)).find(nobody), entries.iter().filter(|e| !free(e.1)).find(|e| !nobody(e))) {
            return Err(Error::Clash(format!("a write nobody may purge shares a commit only with others like it: {} {} is one, {} {} is not. {way}", n.0, n.1, o.0, o.1)));
        }
    }
    let expires = first.and_then(|e| e.3);
    if let Some(at) = expires {
        if let Some(r) = entries.iter().find(|e| e.1.as_str() == CREATED.ak()) {
            return Err(Error::Clash(format!("a thing's record never expires, and this write creates or first keeps {}, in a commit expiring at {at}. First commit the thing without an expiry: removing an aspect is enough, and stores no value", r.0)));
        }
        if let Some(r) = entries.iter().find(|e| free(e.1)) {
            return Err(Error::Clash(format!("{} {} never expires, and this commit expires at {at}. {way}", r.0, r.1)));
        }
        if purge {
            return Err(Error::Clash(format!("a purge request never expires, and this commit expires at {at}. {way}")));
        }
    }
    Ok(expires)
}

/// `build_and_apply` of an undo's deltas: with `plan`'s inputs and the one expiry they share
/// (`one_commit`). A delta's expiry is what it copies back or what its thing requires, never its
/// key's default (spec/crdt.md §4.6: none if none expires): the undone commit may have overridden
/// that, and undoing it must not need what it did not.
pub(crate) fn build_one(tx: &mut Tx<'_>, mut plan: CommitPlan, mut deltas: Vec<Resolved>) -> Result<CommitId> {
    let mut settled = Vec::with_capacity(deltas.len());
    for d in &deltas {
        let (r, _) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, plan.signer, &d.tid, &d.ak, d.schema.as_deref(), d.retention, d.expires)?;
        let (_, e) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, plan.signer, &d.tid, &d.ak, None, Some(r), d.expires)?;
        settled.push((r, e));
    }
    let entries: Vec<(Tid, &Ak, &Retention, Option<u64>)> = deltas.iter().zip(&settled).map(|(d, (r, e))| (d.tid, &d.ak, r, *e)).collect();
    plan.expires = one_commit(&entries, !plan.purge.is_empty(), "An undo is one commit, so this cannot be undone while both stand")?;
    plan.restores = true;
    for (d, (r, e)) in deltas.iter_mut().zip(settled) {
        (d.retention, d.expires) = (Some(r), e);
    }
    build_and_apply(tx, plan, deltas)
}

/// The writes of a compacting writer's sweep of `(tid, ak)` at stamp `r` (`Fragment::sweep`), the
/// value-less list saying what is gone here.
pub(crate) fn sweep_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, r: &osis_crdt::Stamp) -> Result<Option<Fragment>> {
    let gone = tx.core.ix.valueless.get(&(*tid, ak.clone())).cloned().unwrap_or_default();
    Ok(tx.state(tid, ak)?.and_then(|st| st.sweep(r, &|d| gone.iter().any(|o| o.owns(d)))))
}

/// The writer's own source: its session, or for commit form a placeholder commit that sorts
/// below every other commit like the real one will (spec/crdt.md §3.3 rule 2).
fn own_source(form: Form, node: Tid) -> Source {
    form.own_source(node, osis_base::CommitId([0; 32]))
}

/// The session nonce a form's counters are kept under (none for commit form).
pub(crate) fn nonce_of(form: Form) -> [u8; osis_crdt::SESSION_NONCE_LEN] {
    match form {
        Form::Session(n) => n,
        Form::Commit => [0; osis_crdt::SESSION_NONCE_LEN],
    }
}

/// Encodes, pages, reserves counters, builds, signs and applies locally. Returns the ID.
pub(crate) fn build_and_apply(tx: &mut Tx<'_>, plan: CommitPlan, deltas: Vec<Resolved>) -> Result<CommitId> {
    let node = plan.signer;
    let published = super::secrets::published_keys(tx, &plan.creates, deltas.iter().map(|d| d.tid))?;
    let mut writes = Vec::with_capacity(deltas.len());
    for d in deltas {
        let (retention, expires) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, plan.signer, &d.tid, &d.ak, d.schema.as_deref(), d.retention, d.expires)?;
        // one expiry per commit (spec/commits.md §6): `one_commit` saw to it
        if expires != plan.expires && !plan.restores {
            return Err(Error::Misuse("a commit's deltas share one expiry"));
        }
        let framing = framing_for(tx.core, &plan, &published, &d.tid, &retention)?;
        let cx = writer_ctx(plan.form, plan.kind, plan.ts, node, d.lo, d.hi);
        let memory = tx.txn.is_memory();
        let mut blobs = TxBlobs::new(&mut tx.txn);
        let mut nonce = [0u8; osis_crdt::NONCE_LEN];
        tx.rng.fill_bytes(&mut nonce);
        // a memory delta is never paged (spec/crdt.md §8): it must fit a blob alone
        let mut bw = BlobWriter::new(&framing, &mut blobs, &mut *tx.rng);
        let sink: &mut dyn osis_crdt::PageSink = if memory { &mut Unpaged } else { &mut bw };
        let fragment = d.fragment;
        let encoded = match d.frontiers {
            Some((frontiers, absorbed)) => osis_crdt::encode_snapshot(&osis_crdt::Snapshot { nonce, fragment, frontiers, absorbed }, &cx, Some(sink)),
            None => encode_delta(&Delta { nonce, fragment }, &cx, Some(sink)),
        };
        let bytes = match encoded {
            Ok(b) => b,
            // past what one unpaged delta may hold (spec/commits.md §2): refused
            Err(_) if memory => return Err(Error::Misuse("an ephemeral delta does not fit a blob")),
            Err(e) => return Err(e.into()),
        };
        let mut chunks = std::mem::take(&mut blobs.written);
        // trees written for values the resolved delta does not hold (an edit's item paired
        // with one deleted concurrently) are neither listed nor kept
        let mut own = d.chunks;
        if !own.is_empty() {
            let linked = super::large::delta_links(tx, &framing.dedup, &bytes)?;
            let (keep, drop): (Vec<_>, Vec<_>) = own.into_iter().partition(|id| linked.contains(id));
            for id in &drop {
                tx.txn.delete_blob(id);
            }
            own = keep;
        }
        chunks.extend(own);
        if plan.form.counted() && plan.kind.has_own_writes() {
            let first = tx.txn.reserve_counters(&d.tid, &d.ak, &nonce_of(plan.form), d.hi.saturating_sub(d.lo))?;
            if first != d.lo {
                return Err(Error::Misuse("counter moved under the writer"));
            }
        }
        // hostile test authors only (`Engine::commit_forged`): the header hashes what is sent
        let bytes = if tx.core.forge_bad.contains(&(d.tid, d.ak.clone())) { osis_base::encode(&osis_base::Value::List(vec![osis_base::Value::Int(1)])) } else { bytes };
        writes.push(AspectWrite { tid: d.tid, ak: d.ak, lo: d.lo, hi: d.hi, delta: bytes, retention, chunks, records: d.records });
    }
    if !plan.purge.is_empty() && plan.expires.is_some() {
        return Err(Error::Misuse("a commit with a purge request cannot carry expires (spec/commits.md §5)"));
    }
    let mut b = CommitBuilder::new(plan.kind, plan.ts, node, plan.actor, plan.form);
    b.expires = plan.expires;
    b.aspects = writes;
    b.purge = plan.purge;
    b.undoes = plan.undoes;
    b.frontier = plan.frontier;
    b.blind = Some(plan.blind);
    // a commit built in a memory transaction is a memory commit (spec/commits.md §2, §3)
    b.ephemeral = tx.txn.is_memory().then_some(osis_commit::EphClass::Plain);
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
    let built = match built {
        // an ephemeral commit past a blob, or a delta past what one unpaged delta may hold, is
        // refused (spec/commits.md §2, spec/sync.md §9): no page carries it
        Err(osis_commit::Error::Build(osis_commit::COMMIT_PAST_BLOB) | osis_commit::Error::Delta(_)) if tx.txn.is_memory() => return Err(Error::Misuse("an ephemeral commit does not fit a blob")),
        b => b?,
    };
    let id = built.commit.id();
    // hostile test authors: the blob as sent, whatever this node's own copy drops of it
    if !tx.core.forge_bad.is_empty() || tx.core.skip_writer_rules {
        tx.core.forged = Some(built.commit.encode());
    }
    let received = tx.now();
    crate::apply::apply_local(tx, &built.commit, received)?;
    Ok(id)
}

impl Engine {
    /// A new thing whose first admin is `admin`, created by `m` (spec/data-model.md §1).
    pub fn new_thing(&mut self, m: &mut Mutation, admin: Tid) -> Tid {
        m.create(self.thing_record(admin))
    }

    /// The creation record of a new thing whose first admin is `admin` (`Mutation::create`
    /// writes it).
    pub fn thing_record(&mut self, admin: Tid) -> CreationRecord {
        crate::identity::thing_record(admin, &mut *self.rng)
    }

    /// Commits `m` as one commit; `None` when it changes nothing. `Clash` when its deltas cannot
    /// share one (spec/commits.md §5, §6).
    pub fn commit(&mut self, m: Mutation) -> Result<Option<CommitId>> {
        self.run(|tx| commit_in(tx, m))
    }
}

/// Commits `m` in `tx` as one commit (`one_commit`); none when it changes nothing.
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
    // a memory-class record carried by a durable commit is the thing persisting
    // (spec/data-model.md §1)
    for &t in m.creates.keys() {
        if tx.core.created_for(&t, memory).is_some() {
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
    let ts = m.ts.unwrap_or_else(|| tx.core.hlc.next());
    if memory {
        // a memory commit's records are held here at once and travel beside its deltas
        // (spec/commits.md §2): a thing made with no write is known all the same
        let (actor, received) = (m.actor.unwrap_or(node), tx.now());
        for rec in std::mem::take(&mut m.creates).into_values() {
            let t = rec.tid();
            tx.txn.put_local(&[super::records::CREATED, t.as_bytes()].concat(), &osis_base::encode(&rec.to_value()), osis_store::Shred::No)?;
            tx.core.ix.held.create_memory(rec);
            tx.core.memory.things.insert(t, super::MemoryThing { ts, node, actor, received, made_here: true });
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
    let dead: Vec<(Tid, Ak)> = m.dead_resets.keys().chain(m.fresh_resets.keys()).chain(&m.sweeps).cloned().collect();
    for k in dead {
        m.aspects.entry(k).or_default();
    }
    let role_commit = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && is_role_class(ak.as_str()));
    let content = m.aspects.keys().any(|(_, ak)| ak.as_str() != CREATED.ak() && !is_role_class(ak.as_str()));
    if role_commit && content {
        return Err(Error::Misuse("a commit is either a content or a role commit"));
    }
    // records alone travel as a role commit: what judging roles needs, fetched first
    // (spec/commits.md §2)
    let records_only = !content && !role_commit && !m.aspects.is_empty();
    let kind = if role_commit || records_only { Kind::Role } else { Kind::Content };
    // a record needs no authority: records alone act for their signer
    if records_only {
        m.actor = None;
    }
    // edge writes are judged without the actor, so a role commit acts for its signer
    // (spec/wire.md §4)
    if kind != Kind::Content && m.actor.is_some_and(|a| a != node) {
        return Err(Error::Misuse("a role commit acts for its signer only"));
    }
    if let Some(u) = m.undoes {
        return crate::undo::undo_in(tx, u, m.actor.unwrap_or(node), m.ts, &m.undo_keep, m.confined).map(Some).or_else(|e| match e {
            Error::Misuse("nothing to undo") => Ok(None),
            e => Err(e),
        });
    }
    let base = CommitPlan { kind, ts, actor: m.actor.unwrap_or(node), form: Form::Commit, creates: std::mem::take(&mut m.creates), purge: std::mem::take(&mut m.purge), undoes: None, frontier: m.frontier.take(), signer: node, blind: draw_blind(&mut *tx.rng), expires: None, restores: false };
    if !m.unchecked {
        check_acts(tx.core, node, &|t| base.creates.get(t), &base.actor, ts)?;
    }
    let mut aspects = Vec::with_capacity(m.aspects.len());
    for ((tid, ak), mut am) in std::mem::take(&mut m.aspects) {
        if !base.creates.contains_key(&tid) && tx.core.created_for(&tid, memory).is_none() {
            return Err(Error::UnknownThing(tid));
        }
        if !m.unchecked {
            check_authority(tx.core, node, &base.creates, &tid, ak.as_str(), ts)?;
        }
        let (r, mut e) = settle(tx.core, memory, kind, ts, node, &tid, &ak, am.schema.as_deref(), am.retention, am.expires)?;
        // a write copying an expiring value expires no later (spec/crdt.md §4.7), so it is a commit
        // expiring then, alone or not at all: refused when any of its ops would outlast it
        // alone (never quietly shortened); a required expiry (spec/commits.md §5) stands
        if kind == Kind::Content && !memory && !tx.core.skip_writer_rules && crate::apply::validity::required_now(tx.core, &tid, &ak, node, ts).is_none() {
            let form = if m.commit_form { Form::Commit } else { Form::Session(tx.core.session.nonce) };
            if let Some(t) = copy_expiry(tx, &tid, &ak, &am, &am.ops, form, node, ts)?.filter(|t| e.is_none_or(|e| *t < e)) {
                let k = (tid, ak.clone());
                let mut alike = !m.dead_resets.contains_key(&k) && !m.sweeps.contains(&k);
                if am.ops.len() > 1 {
                    for op in &am.ops {
                        // an op that does not resolve alone builds on another: refused too
                        alike = alike && copy_expiry(tx, &tid, &ak, &am, std::slice::from_ref(op), form, node, ts).is_ok_and(|x| x == Some(t));
                    }
                }
                if !alike {
                    return Err(Error::Clash(format!("on {tid} {ak} this write goes into a value expiring at {t} and writes what must outlast it: a commit has one expiry. Write them as separate commits")));
                }
                e = settle(tx.core, memory, kind, ts, node, &tid, &ak, am.schema.as_deref(), Some(r), Some(t))?.1;
            }
        }
        (am.retention, am.expires) = (Some(r), e);
        aspects.push(((tid, ak), am));
    }
    let entries: Vec<(Tid, &Ak, &Retention, Option<u64>)> = aspects.iter().filter_map(|((t, ak), am)| Some((*t, ak, am.retention.as_ref()?, am.expires))).collect();
    let way = if m.free.is_empty() { "Write them as separate commits" } else { "A delete removes every aspect of its thing and takes it out of its groups: do these in commits of their own first, then delete" };
    let expires = one_commit(&entries, !base.purge.is_empty(), way)?;
    // role commits use commit form: a later commit by the same node can never void them by
    // reusing their counters; content commits write under this open's session unless asked
    // for commit form (spec/commits.md §3); expiring memory writes under its second session
    // (`Core::expiring`)
    let mut plan = base;
    plan.expires = expires;
    plan.form = if kind != Kind::Content || m.commit_form { Form::Commit } else { Form::Session(if memory && expires.is_some() { tx.core.expiring.nonce } else { tx.core.session.nonce }) };
    let form = plan.form;
    let mut next_ctr = 1u64;
    let mut deltas: Vec<Resolved> = Vec::new();
    let published = super::secrets::published_keys(tx, &plan.creates, aspects.iter().map(|k| k.0.0))?;
    for ((tid, ak), mut am) in aspects {
        // what a `required.0^` delta says is judged from that delta alone: it writes the whole value
        if ak.as_str() == osis_commit::retention::REQUIRED && !tx.core.skip_writer_rules {
            for o in &mut am.ops {
                match (o.path.is_empty(), &o.op) {
                    (true, osis_crdt::Op::Set(v)) => o.op = osis_crdt::Op::Replace(v.clone()),
                    (true, osis_crdt::Op::Replace(_) | osis_crdt::Op::RemoveAspect) => {}
                    _ => return Err(Error::Misuse("required.0^ is written whole")),
                }
            }
            if am.ops.len() > 1 {
                return Err(Error::Misuse("required.0^ is written whole"));
            }
            if am.ops.iter().any(|o| matches!(&o.op, osis_crdt::Op::Replace(v) if <osis_schema::core_types::RequiredRules as osis_schema::Codec>::from_value(v).is_ok_and(|r| !osis_schema::core_types::required_fits(&r)))) {
                return Err(Error::Misuse("required.0^ over MAX_REQUIRED_ENTRIES entries or a prefix over MAX_AK_BYTES"));
            }
            // an entry no write could meet: every governed write would be refused
            let unmeetable = |q: &osis_schema::core_types::Required| osis_commit::retention::write_retention("", None, Some(q.retention())).is_err() || q.expires.is_some_and(|d| d == 0 || d >= osis_commit::FOREVER);
            if am.ops.iter().any(|o| matches!(&o.op, osis_crdt::Op::Replace(v) if <osis_schema::core_types::RequiredRules as osis_schema::Codec>::from_value(v).is_ok_and(|r| r.rules.values().any(unmeetable)))) {
                return Err(Error::Misuse("required.0^ with an entry no write could meet"));
            }
        }
        let retention = am.retention.unwrap_or_default();
        let framing = match kind {
            Kind::Content => Some(framing_for(tx.core, &plan, &published, &tid, &retention)?),
            _ => None,
        };
        // what the ops address (map keys, fields, set values: a large one by its link, as the
        // state holds it); a memory commit holds every value inline (no chunks, no pages)
        let paths = match (&framing, memory) {
            (Some(f), false) => super::pages::op_paths(&am.ops, &mut |v| super::large::lookup_form(v, &f.dedup))?,
            _ => super::pages::op_paths(&am.ops, &mut |v| Ok(v.clone()))?,
        };
        // a list edit's items by content hash and its window (what the pages it needs follow from)
        let edits = match (&framing, memory) {
            (Some(f), false) => super::large::list_edits(&am.ops, am.schema.as_deref(), ak.as_str(), &f.dedup)?,
            _ => Vec::new(),
        };
        let attached = tx.load_for_ops(&tid, &ak, paths, &am.ops, &edits)?;
        // large atomic values become chunk trees before the ops resolve
        let mut chunks = Vec::new();
        if memory {
        } else if let Some(framing) = &framing {
            chunks = super::large::chunk_ops(tx, &tid, &ak, &mut am.ops, &edits, am.schema.as_deref(), framing, &m.fresh)?;
        }
        let lo = match form {
            Form::Commit => next_ctr,
            // a session's counters: memory rows, gone with the session
            Form::Session(n) => tx.txn.counter(&tid, &ak, &n)?,
        };
        let empty = Fragment::default();
        let view = am.schema.as_ref().and_then(|s| s.view(ak.as_str()));
        // map removals carry their key only where keys are public ids (spec/crdt.md §5.6)
        let keyed = osis_schema::core_types::is_role_class(ak.as_str());
        let run = |tx: &Tx<'_>| {
            let state = tx.cached(&tid, &ak).unwrap_or(&empty);
            let w = Writer::new(ts, own_source(form, node), lo).keyed_removals(keyed);
            match &view {
                Some(v) => run_ops(state, w, &am.ops, v),
                None => run_ops(state, w, &am.ops, &AnyView),
            }
        };
        let out = tx.run_attached(&tid, &ak, attached, run)??;
        let w2 = Writer::new(ts, own_source(form, node), lo).keyed_removals(keyed);
        let out = match (out, m.dead_resets.get(&(tid, ak.clone())).filter(|d| !d.is_empty())) {
            (o, None) => o,
            (Some((mut f, r)), Some(ds)) => {
                f.join(osis_crdt::reset_entries(&w2, ds));
                Some((f, r))
            }
            (None, Some(ds)) => Some((osis_crdt::reset_entries(&w2, ds), w2.range())),
        };
        let out = match (out, m.fresh_resets.get(&(tid, ak.clone())).filter(|k| !k.is_empty())) {
            (o, None) => o,
            (o, Some(keys)) => {
                // the counters after the delta's own creations (`lo` when it has none)
                let (mut f, mut r) = o.unwrap_or_else(|| (Fragment::default(), osis_crdt::CounterRange { lo, hi: lo }));
                let ids: Vec<(osis_crdt::Dot, Value)> = keys.iter().zip(r.hi..).map(|(k, c)| (osis_crdt::Dot::new(own_source(form, node), c), k.clone())).collect();
                r.hi = r.hi.saturating_add(u64::try_from(keys.len()).unwrap_or(u64::MAX));
                f.join(osis_crdt::reset_entries(&w2, &ids));
                Some((f, r))
            }
        };
        let out = if m.sweeps.contains(&(tid, ak.clone())) { sweep_of(tx, &tid, &ak, &w2.delta_stamp())?.map(|f| (f, w2.range())) } else { out };
        let Some((fragment, range)) = out else { continue };
        if form == Form::Commit {
            next_ctr = range.hi;
        }
        if let Some(s) = &am.schema {
            keep_schema(tx, s, false)?;
        }
        let records = if memory {
            let added = am.ops.iter().filter_map(|o| match &o.op {
                Op::Add(Value::Tid(x)) => Some(*x),
                _ => None,
            });
            memory_records(tx.core, &tid, &ak, added)
        } else {
            Vec::new()
        };
        let r = Resolved { tid, ak, fragment, lo: range.lo, hi: range.hi, schema: am.schema, retention: am.retention, expires: am.expires, frontiers: None, chunks, records };
        deltas.push(r);
    }
    if deltas.is_empty() && plan.purge.is_empty() {
        // a memory thing made with no write touched its timeline: judged before the
        // transaction ends (nothing written on it yet, so nothing to rebuild)
        if tx.core.stale() {
            crate::apply::validity::rejudge_all(tx, true)?;
        }
        return Ok(None);
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("a purge request needs a delta (reset what it names)"));
    }
    let id = build_and_apply(tx, plan, deltas)?;
    check_synced(tx.core, &m.synced)?;
    Ok(Some(id))
}

/// The earliest expiry still ahead among the writes whose values `ops` (of `am`) on `(tid, ak)`
/// would carry a copy of under their dots (a key its entry's record repeats, an undelete's char;
/// spec/crdt.md §4.7): the ops resolved against the whole state, only where a held delta of the
/// aspect has an expiry ahead.
#[allow(clippy::too_many_arguments)]
fn copy_expiry(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, am: &AspectMut, ops: &[PathOp], form: Form, node: Tid, ts: Ts) -> Result<Option<u64>> {
    let now = tx.now().0;
    let k = (*tid, ak.clone());
    let expiring = tx.core.ix.by_aspect.get(&k).into_iter().flatten().any(|(_, c)| tx.core.ix.commits.get(c).is_some_and(|m| m.header.expires.is_some_and(|t| t > now)));
    if !expiring {
        return Ok(None);
    }
    let lo = match form {
        Form::Commit => 1,
        Form::Session(n) => tx.txn.counter(tid, ak, &n)?,
    };
    let state = tx.state(tid, ak)?.cloned().unwrap_or_default();
    let w = Writer::new(ts, own_source(form, node), lo).keyed_removals(osis_schema::core_types::is_role_class(ak.as_str()));
    let out = match am.schema.as_ref().and_then(|s| s.view(ak.as_str())) {
        Some(v) => run_ops(&state, w, ops, &v)?,
        None => run_ops(&state, w, ops, &AnyView)?,
    };
    let Some((f, _)) = out else { return Ok(None) };
    let mut owners = BTreeSet::new();
    f.owner_dots(&mut owners);
    let mut first: Option<u64> = None;
    for d in owners {
        let Some(Some(t)) = tx.core.write_expiry(tid, ak, &d) else { continue };
        if t <= now || first.is_some_and(|x| x <= t) {
            continue;
        }
        let mut g = f.clone();
        g.strip(&|x| *x == d);
        if g != f {
            first = Some(t);
        }
    }
    Ok(first)
}

/// The memory-class records from `t` up its owner chain (each with its tid): what persisting `t`
/// carries, and what a memory commit on `t` carries beside its delta.
pub(crate) fn memory_chain(core: &Core, t: &Tid) -> Vec<(Tid, CreationRecord)> {
    let mut out = Vec::new();
    for cur in core.owner_chain(t).filter_map(|s| s.thing()) {
        if !core.ix.held.is_memory(&cur) {
            break;
        }
        let Some(rec) = core.created(&cur) else { break };
        out.push((cur, rec.clone()));
    }
    out
}

/// The records a memory commit carries beside its delta on `(tid, ak)` (spec/commits.md §2):
/// the memory chains of `tid` and, on `ephemeral_group.0~`, of the things `members` its delta adds that
/// have `tid`'s reader (a record names its nonce, its dedup secret: never shown to another
/// reader).
pub(crate) fn memory_records(core: &Core, tid: &Tid, ak: &Ak, members: impl Iterator<Item = Tid>) -> Vec<CreationRecord> {
    let mut things = vec![*tid];
    if ak.as_str() == osis_schema::core_types::EPHEMERAL_GROUP.ak() {
        let reader = core.reader_of(tid);
        things.extend(members.filter(|x| core.reader_of(x) == reader));
    }
    let recs: BTreeMap<Tid, CreationRecord> = things.iter().flat_map(|t| memory_chain(core, t)).collect();
    recs.into_values().collect()
}

/// `Mutation::require_synced`, over the state the commit left.
fn check_synced(core: &Core, memberships: &[(Tid, Tid)]) -> Result<()> {
    let lab = &core.ix.labeled;
    let in_synced = |x: &Tid| core.ix.groups.of.get(x).is_some_and(|s| s.iter().any(|h| lab.contains(h)));
    for (t, g) in memberships {
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
