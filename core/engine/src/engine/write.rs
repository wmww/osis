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
use osis_base::{Ak, ChainStep, CommitId, CreationRecord, Role, Tid, Ts, Value, WallMs, record_chain};
use osis_crdt::{AnyView, DeltaBuilder, CounterRange, Delta, Fragment, Op, PathOp, Source, View, Writer, encode_delta};
use osis_blob::{BlobWriter, Framing};
use osis_perm::At;
use osis_schema::core_types::{self as ct, CREATED, is_role_class};
use osis_schema::{RawKey, Retention, Schema};
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
    /// The fire this write replaces (spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// That fire's floor as this node reads it (`osis_commit::AspectEntry::original_floor`).
    pub original_floor: u64,
}

/// Creation records of a commit by tid (each `tid` is a hash: computed once).
pub(crate) type Creates = BTreeMap<Tid, CreationRecord>;

/// Writes that become one commit.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub(crate) creates: Creates,
    pub(crate) aspects: BTreeMap<(Tid, Ak), AspectMut>,
    pub(crate) actor: Option<Tid>,
    /// `Engine::write` holds the mutation to `actor`'s own rights first (`Mutation::confine`).
    pub(crate) confined: bool,
    /// Commit-form dots (spec/commits.md §3); else session form.
    pub(crate) commit_form: bool,
    pub(crate) purge: Vec<PurgeItem>,
    /// Purge items by commit ID, named by their stamp at commit (`Core::purge_item`).
    pub(crate) purge_named: Vec<(CommitId, Tid, Ak)>,
    pub(crate) undoes: Option<CommitId>,
    pub(crate) frontier: Option<osis_perm::Frontier>,
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
    /// The commit's `ts`, when taken before the commit (an ephemeral mutation's, a revert's).
    pub(crate) ts: Option<Ts>,
    /// The header's blind, when taken before the commit (a rotation's departs mark names it).
    pub(crate) blind: Option<[u8; 16]>,
    /// A rotation of the signing account's chain, with the key of each tip a merge names
    /// (spec/crypto.md §9; `flows::signing`).
    pub(crate) rotation: Option<crate::flows::signing::AccountRotation>,
    /// A seed re-seal of an epoch of the signing account's chain (spec/crypto.md §9, Custody).
    pub(crate) reseal: Option<osis_commit::SeedReseal>,
    /// A sealed fire's commit (spec/sync-inbox.md §2): built, never applied here.
    pub(crate) sealed: bool,
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
        Mutation { creates: Creates::new(), aspects: BTreeMap::new(), actor: None, confined: false, commit_form: false, purge: Vec::new(), purge_named: Vec::new(), undoes: None, frontier: None, unchecked: false, signer: None, dead_resets: BTreeMap::new(), fresh_resets: BTreeMap::new(), sweeps: BTreeSet::new(), fresh: Default::default(), ts: None, blind: None, rotation: None, reseal: None, sealed: false }
    }

    /// The actor this node acts for (header field 2); default the node itself.
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = Some(actor);
        self
    }

    /// Acts for `actor` holding the mutation to `actor`'s own rights, not this node's
    /// (`Engine::write`, engine/acting.rs).
    pub fn confine(&mut self, actor: Tid) -> &mut Self {
        self.actor = Some(actor);
        self.confined = true;
        self
    }

    /// Signs as a key actor whose seed the node holds (`Engine::hold_key_actor`): a
    /// key or link key (spec/crypto.md §2), in commit form (its holders share no counters), or
    /// an account held here (`Engine::hold_account`), in a session of its own.
    pub fn sign_as(&mut self, key_actor: Tid) -> &mut Self {
        self.signer = Some(key_actor);
        self
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

    /// The write of `key` on `tid` replaces fire `original` (spec/commits.md §5 Signals), taking
    /// its expiry when it set none.
    pub fn replaces<K: RawKey>(&mut self, tid: Tid, key: &K, original: CommitId) -> Result<&mut Self> {
        self.entry(tid, key)?.replaces = Some(original);
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

    /// A purge request item naming commit `c`'s delta on `(tid, ak)` by its stamp
    /// (`PurgeItem::Commit`): `UnknownCommit` at commit unless its header is held here.
    pub fn purge_commit(&mut self, c: CommitId, tid: Tid, ak: Ak) -> &mut Self {
        self.purge_named.push((c, tid, ak));
        self
    }

    /// Makes this an undo of `target` (spec/commits.md §7) acting as the mutation's actor; the
    /// mutation may carry no other ops (`Misuse` at commit).
    pub fn undo(&mut self, target: CommitId) -> &mut Self {
        self.undoes = Some(target);
        self
    }

    /// The frontier of an explicit demotion (role flows).
    pub fn frontier(&mut self, f: osis_perm::Frontier) -> &mut Self {
        self.frontier = Some(f);
        self
    }

    /// Skips the plain role check (role flows judge invite grants and self-removals).
    pub(crate) fn unchecked(&mut self) -> &mut Self {
        self.unchecked = true;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.aspects.is_empty() && self.purge.is_empty() && self.purge_named.is_empty() && self.undoes.is_none()
    }
}

/// The role a write of `ak` needs (spec/permissions.md §1, §3, §5.2): admin for edges,
/// `sync.0`, an account's seeds (`account.0`) and admin-only (`^`) aspects; write for rotations
/// (`secrets.0`, `keys.0`) and other content.
pub(crate) fn required_role(ak: &str) -> Role {
    match ak {
        "roles.0" | "sync.0" | "account.0" => Role::Admin,
        _ if Ak::markers_of(ak).admin_only => Role::Admin,
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
    core.timelines.role(node, tid, At::now(ts))
}

/// Looks up the creation record of a thing not yet held: the commit's own.
pub(crate) type Records<'a> = &'a dyn Fn(&Tid) -> Option<&'a CreationRecord>;

/// The role `node` has on `tid` at `ts`: a thing not yet held (`records`) has its record edge
/// alone, so a node's role on it is its role on its first admin (spec/permissions.md §1).
pub(crate) fn role_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ts: Ts) -> Option<Role> {
    match record_chain(*tid, |t| records(t).map(CreationRecord::record_link)).next() {
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

/// `check_authority` with the records not yet held looked up by `records`.
pub(crate) fn check_authority_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ak: &str, ts: Ts) -> Result<()> {
    check_role_with(core, node, records, tid, ak, required_role(ak), ts)
}

/// `check_authority_with` needing role `need`.
pub(crate) fn check_role_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ak: &str, need: Role, ts: Ts) -> Result<()> {
    // an open fire needs no role on its thing (spec/permissions.md §5.2 Open fires)
    if Ak::markers_of(ak).open {
        return Ok(());
    }
    let role = role_with(core, node, records, tid, ts);
    if role >= Some(need) && (ak == CREATED.ak() || core.skip_writer_rules || within_depth(core, records, tid)) { Ok(()) } else { Err(Error::Permission { tid: *tid }) }
}

/// Whether this node may write on a held thing now (`may_write`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MayWrite {
    Yes,
    /// Not yet: the thing's minting or the delete keys every write on it lists are not here
    /// (spec/crypto.md §7); they may arrive.
    Later,
    /// Not on what is held: the thing does not exist here (or was destroyed), or the node lacks the role.
    No,
}

/// Whether `node` may write `ak` of held thing `tid` at `ts` needing role `need` (`None`: a write
/// needing none, a listing): the checks `commit_in` and `framing_for` make of a write there, asked
/// first by every write this node makes on its own (answers, covers), so a write it may not make
/// yet waits and never fails the transaction around it.
pub(crate) fn may_write(tx: &mut Tx<'_>, node: Tid, tid: &Tid, ak: &str, need: Option<Role>, ts: Ts) -> Result<MayWrite> {
    if !tx.core.exists(tid) {
        return Ok(MayWrite::No);
    }
    if let Some(need) = need
        && check_role_with(tx.core, node, &|_| None, tid, ak, need, ts).is_err()
    {
        return Ok(MayWrite::No);
    }
    may_write_on(tx, tid)
}

/// `by_thing` with only the things `node` may write `ak` on now, needing `need` (`may_write`, at the
/// next stamp): `None` while one of them may be written on only later, so a write this node owes
/// across things (an answer) waits whole.
pub(crate) fn writable_now<V>(tx: &mut Tx<'_>, node: Tid, by_thing: BTreeMap<Tid, V>, ak: &str, need: Option<Role>) -> Result<Option<BTreeMap<Tid, V>>> {
    let w = writable_split(tx, node, by_thing, ak, need)?;
    Ok((!w.later && w.unheld.is_empty()).then_some(w.now))
}

/// `by_thing` split by when `node` may write `ak` on each (`may_write`, at the next stamp); the
/// things it may never write on are left out.
pub(crate) struct Writable<V> {
    /// Held: written now.
    pub(crate) now: BTreeMap<Tid, V>,
    /// Outside the node closure (a node writes only what it holds, spec/sync-set.md §2 Writing),
    /// writable there otherwise.
    pub(crate) unheld: BTreeMap<Tid, V>,
    /// One may be written on only once its minting or keys arrive.
    pub(crate) later: bool,
}

pub(crate) fn writable_split<V>(tx: &mut Tx<'_>, node: Tid, by_thing: BTreeMap<Tid, V>, ak: &str, need: Option<Role>) -> Result<Writable<V>> {
    let ts = tx.core.hlc.peek();
    let mut w = Writable { now: BTreeMap::new(), unheld: BTreeMap::new(), later: false };
    for (t, v) in by_thing {
        match may_write(tx, node, &t, ak, need, ts)? {
            MayWrite::Yes if tx.core.ix.closure.holds(&t) => {
                w.now.insert(t, v);
            }
            MayWrite::Yes => {
                w.unheld.insert(t, v);
            }
            MayWrite::Later => w.later = true,
            MayWrite::No => {}
        }
    }
    Ok(w)
}

/// `may_write` but for the role: whether the thing takes writes here (`Core::writable`) and this
/// node is ready to write it (`secrets::ready_to_write_in`).
pub(crate) fn may_write_on(tx: &mut Tx<'_>, tid: &Tid) -> Result<MayWrite> {
    if !tx.core.exists(tid) {
        return Ok(MayWrite::No);
    }
    Ok(if tx.core.writable(tid) && super::secrets::ready_to_write_in(tx, tid)? { MayWrite::Yes } else { MayWrite::Later })
}

/// May `node` act for `actor` at `ts`: it is the actor or holds write on it? A receiver judges a
/// commit invalid otherwise (`validity::acts_for`, spec/permissions.md §5.2).
pub(crate) fn check_acts(core: &Core, node: Tid, records: Records<'_>, actor: &Tid, ts: Ts) -> Result<()> {
    if node == *actor || role_with(core, node, records, actor, ts) >= Some(Role::Write) { Ok(()) } else { Err(Error::Permission { tid: *actor }) }
}

/// Whether `tid`'s record chain, through the records not yet held, reaches a key actor
/// within `MAX_CHAIN_DEPTH` links (spec/permissions.md §1: a write deeper is invalid).
fn within_depth(core: &Core, records: Records<'_>, tid: &Tid) -> bool {
    let end = record_chain(*tid, |t| records(t).or_else(|| core.created(t)).map(CreationRecord::record_link)).end();
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
    let mut b = DeltaBuilder::new(state, w);
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
    /// The fire this delta replaces (spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// That fire's floor (`osis_commit::AspectEntry::original_floor`).
    pub original_floor: u64,
    /// A snapshot delta's frontiers, absorbed commits and facts (spec/crdt.md §8).
    pub frontiers: Option<(osis_crdt::Frontiers, std::collections::BTreeMap<osis_base::CommitId, Tid>, osis_crdt::Facts)>,
    /// Chunk blobs of large values the delta introduces.
    pub chunks: Vec<osis_blob::Written>,
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
    pub frontier: Option<osis_perm::Frontier>,
    /// The signing key actor: the node, or a key actor it holds.
    pub signer: Tid,
    /// The header's blind (spec/crypto.md §7: the commit blob's; chunks and pages carry their
    /// own link blinds).
    pub blind: [u8; 16],
    /// The commit's expiry (spec/commits.md §6): every delta's.
    pub expires: Option<u64>,
    /// An undo's: `expires` stands, whatever its keys' defaults (`build_one`).
    pub restores: bool,
    /// The header's rotation of the signer's chain and its merge keys (`Mutation::rotation`).
    pub rotation: Option<crate::flows::signing::AccountRotation>,
    /// The own-cover marker (`retention::snapshot::write_own_cover`).
    pub own_cover: bool,
    /// The header's seed re-seal (`Mutation::reseal`).
    pub reseal: Option<osis_commit::SeedReseal>,
}

/// A fresh header blind.
pub(crate) fn draw_blind(rng: &mut dyn osis_crypto::CryptoRngCore) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// Retention and expiry of one aspect's delta in a commit of `kind` at `ts` (spec/commits.md §5,
/// §6): the given ones, else the expiry the thing's newest valid setting held gives the AK, the
/// schema's defaults, the untyped default. A replace of a fire the setting makes `final` is
/// refused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle(core: &Core, memory: bool, kind: Kind, ts: Ts, tid: &Tid, ak: &Ak, schema: Option<&Schema>, replaces: bool, r: Option<Retention>, mut e: Option<u64>) -> Result<(Retention, Option<u64>)> {
    let defaults = schema.and_then(|s| s.defaults(ak.as_str()));
    // a hostile test writer writes what it is told
    if kind == Kind::Content && !core.skip_writer_rules && !ak.ephemeral() && osis_commit::retention::fixed_retention(ak.as_str()).is_none()
        && let Some(s) = crate::apply::validity::setting_now(core, tid)
        && let Some(q) = s.entry(ak)
    {
        if replaces && q.r#final {
            return Err(Error::Misuse("editing is off here: the thing's setting makes its fires final"));
        }
        if e.is_none() && q.expires.is_some() {
            e = q.expires_at(ts.wall_ms().0).ok_or(Error::Misuse("expiry out of range"))?;
        }
    }
    let retention = if memory || ak.ephemeral() {
        // `writer` (spec/commits.md §2)
        osis_commit::retention::EPHEMERAL_RETENTION
    } else {
        match kind {
            // a compaction snapshot's own (`Engine::snapshot`), never from schema defaults
            Kind::ContentSnapshot | Kind::RoleSnapshot => r.unwrap_or_else(|| osis_commit::retention::snapshot_retention(ak.as_str())),
            // a hostile test writer writes the retention it is told
            _ => match r.filter(|_| core.skip_writer_rules) {
                Some(r) => r,
                None => osis_commit::retention::write_retention(ak.as_str(), defaults.as_ref(), r)?,
            },
        }
    };
    let expires = match kind {
        Kind::Content => osis_commit::retention::write_expires(ak.as_str(), ts, defaults.as_ref(), e)?,
        // an expiring snapshot's: the expiry of the values it carries (spec/crdt.md §8)
        Kind::ContentSnapshot => e,
        _ => None,
    };
    Ok((retention, expires))
}

/// Blob framing of one aspect's delta in a commit of `plan` with retention `retention`
/// (spec/crypto.md §7): its thing's dedup secret, the commit's expiry, the delete keys the
/// retention calls for, of the class of `memory` (a memory commit's blobs are held in memory,
/// spec/wire.md §5). `published`: [`super::secrets::published_keys`] of the commit's things;
/// `keys`: the commit's [`super::secrets::KeyCache`].
pub(crate) fn framing_for(core: &Core, memory: bool, plan: &CommitPlan, published: &BTreeMap<(Tid, osis_base::Role), osis_crypto::VerifyingKey>, keys: &super::secrets::KeyCache, tid: &Tid, retention: &Retention) -> Result<Framing> {
    // a role is of use once its delete keys are here (spec/crypto.md §7): until then this node
    // writes nothing on the thing, whatever the delta's retention (`secrets::usable_role`)
    if !super::secrets::holds_listed_keys(core, &plan.creates, published, keys, tid) {
        return Err(Error::Permission { tid: *tid });
    }
    let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates, published, keys };
    let keys = osis_commit::delete_keys(&secrets, tid, retention)?;
    let dedup = osis_commit::Secrets::dedup(&secrets, tid).ok_or(Error::UnknownThing(*tid))?;
    let class = if memory { osis_blob::Class::Ephemeral } else { osis_blob::Class::Durable };
    Ok(Framing { thing: *tid, dedup, expiry: plan.expires.map(WallMs), class, keys: keys.iter().map(|k| Ok((k.level, k.verifying_key()?))).collect::<std::result::Result<_, osis_commit::Error>>()? })
}

/// A request's delta on its thing (spec/commits.md §5 Purge): `purge.0`, which carries no expiry,
/// where the commit has none; in a commit that `expires`, the commit's other deltas on the thing
/// carry it (`check_request` refuses it naming what it would not reach).
fn place_requests(aspects: &mut Vec<((Tid, Ak), AspectMut)>, expires: Option<u64>) {
    if expires.is_some() {
        aspects.retain(|((_, ak), _)| ak.as_str() != osis_commit::retention::PURGE);
    }
}

/// The one expiry of a commit of these deltas (`entries`: thing, AK, retention, expiry; spec/commits.md
/// §6), or `Clash` naming what cannot share a commit: different expiries.
/// `purge.0` takes no part in the expiry: in a commit that expires it is left out (`place_requests`).
/// `way`: what the caller can do about it.
fn one_commit(entries: &[(Tid, &Ak, &Retention, Option<u64>)], way: &str) -> Result<Option<u64>> {
    let placing = |ak: &Ak| ak.as_str() == osis_commit::retention::PURGE;
    let name = |t: &Tid, ak: &Ak, e: Option<u64>| match e {
        Some(e) => format!("{t} {ak} (expires at {e})"),
        None => format!("{t} {ak} (does not expire)"),
    };
    let mut bound = entries.iter().filter(|e| !placing(e.1));
    let first = bound.next();
    if let Some(a) = first
        && let Some(b) = bound.clone().find(|b| b.3 != a.3)
    {
        return Err(Error::Clash(format!("a commit has one expiry, and this write has two: {} and {}. {way}", name(&a.0, a.1, a.3), name(&b.0, b.1, b.3))));
    }
    Ok(first.and_then(|e| e.3))
}

/// `build_and_apply` of an undo's deltas: with `plan`'s inputs and the one expiry they share
/// (`one_commit`). A delta's expiry is what it copies back or what its thing's setting gives, never its
/// key's default (spec/crdt.md §4.6: none if none expires): the undone commit may have overridden
/// that, and undoing it must not need what it did not.
pub(crate) fn build_one(tx: &mut Tx<'_>, mut plan: CommitPlan, mut deltas: Vec<Resolved>) -> Result<CommitId> {
    let mut settled = Vec::with_capacity(deltas.len());
    for d in &deltas {
        let (r, _) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, &d.tid, &d.ak, d.schema.as_deref(), d.replaces.is_some(), d.retention, d.expires)?;
        let (_, e) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, &d.tid, &d.ak, None, d.replaces.is_some(), Some(r), d.expires)?;
        settled.push((r, e));
    }
    let entries: Vec<(Tid, &Ak, &Retention, Option<u64>)> = deltas.iter().zip(&settled).map(|(d, (r, e))| (d.tid, &d.ak, r, *e)).collect();
    plan.expires = one_commit(&entries, "An undo is one commit, so this cannot be undone while both stand")?;
    plan.restores = true;
    for (d, (r, e)) in deltas.iter_mut().zip(settled) {
        (d.retention, d.expires) = (Some(r), e);
    }
    build_and_apply(tx, plan, deltas)
}

/// The writes of a compacting writer's sweep of `(tid, ak)` at stamp `r` (`Fragment::sweep`).
pub(crate) fn sweep_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, r: &osis_crdt::Stamp) -> Result<Option<Fragment>> {
    tx.load(tid, ak)?;
    let core = &*tx.core;
    Ok(tx.cached(tid, ak).and_then(|st| st.sweep(r, &|d| crate::apply::copies::reflected(core, tid, ak, d))))
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
    let rotation = plan.rotation.clone();
    let built = build(tx, plan, deltas)?;
    let id = built.commit.id();
    // a rotation's thing lists are held before it applies, so what they name never falls here
    if let Some(r) = &rotation {
        crate::flows::lists::keep_certs(tx, &r.certs(id))?;
    }
    // rights are checked before anything leaves the node: a request dropping nothing is refused
    if !tx.core.skip_writer_rules {
        crate::retention::check_request(tx.core, &built.commit.header, &id)?;
    }
    // hostile test authors: the blob as sent, whatever this node's own copy drops of it
    if !tx.core.forge_bad.is_empty() || tx.core.skip_writer_rules {
        tx.core.forged = Some(built.commit.encode());
    }
    let received = tx.now();
    crate::apply::apply_local(tx, &built.commit, built.signed, received)?;
    // the epoch each content part was made under, where it has a floor (spec/crypto.md §5
    // Passing on)
    crate::sync_ids::opened::note_own(tx, &built.commit)?;
    Ok(id)
}

/// Encodes, pages, reserves counters, builds and signs.
fn build(tx: &mut Tx<'_>, plan: CommitPlan, deltas: Vec<Resolved>) -> Result<osis_commit::Built> {
    let node = plan.signer;
    let published = super::secrets::published_keys(tx, &plan.creates, deltas.iter().map(|d| d.tid))?;
    let keys = super::secrets::KeyCache::default();
    let mut writes = Vec::with_capacity(deltas.len());
    for d in deltas {
        let (retention, expires) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, &d.tid, &d.ak, d.schema.as_deref(), d.replaces.is_some(), d.retention, d.expires)?;
        // one expiry per commit (spec/commits.md §6): `one_commit` saw to it
        if expires != plan.expires && !plan.restores {
            return Err(Error::Misuse("a commit's deltas share one expiry"));
        }
        let framing = framing_for(tx.core, tx.txn.is_memory(), &plan, &published, &keys, &d.tid, &retention)?;
        let cx = writer_ctx(plan.form, plan.kind, plan.ts, node, d.lo, d.hi);
        let mut blobs = TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
        let mut nonce = [0u8; osis_crdt::NONCE_LEN];
        tx.rng.fill_bytes(&mut nonce);
        let mut bw = BlobWriter::new(&framing, &mut blobs, &mut *tx.rng);
        let fragment = d.fragment;
        let encoded = match d.frontiers {
            Some((frontiers, absorbed, facts)) => osis_crdt::encode_snapshot(&osis_crdt::Snapshot { nonce, fragment, frontiers, absorbed, facts }, &cx, Some(&mut bw)),
            None => encode_delta(&Delta { nonce, fragment }, &cx, Some(&mut bw)),
        };
        let bytes = encoded?;
        drop(bw);
        // trees written for values the resolved delta does not hold (an edit's item paired
        // with one deleted concurrently) are not kept
        if !d.chunks.is_empty() {
            let linked: BTreeSet<osis_base::BlobId> = super::large::delta_links(tx, &framing.dedup, &bytes)?.iter().map(|l| l.blob).collect();
            for w in d.chunks.iter().filter(|w| !linked.contains(&w.id)) {
                tx.blobs.release(&w.id, tx.txn.is_memory())?;
            }
        }
        if plan.form.counted() && plan.kind.has_own_writes() {
            let first = tx.txn.reserve_counters(&d.tid, &d.ak, &nonce_of(plan.form), d.hi.saturating_sub(d.lo))?;
            if first != d.lo {
                return Err(Error::Misuse("counter moved under the writer"));
            }
        }
        // hostile test authors only (`Engine::commit_forged`): the header hashes what is sent
        let bytes = if tx.core.forge_bad.contains(&(d.tid, d.ak.clone())) { osis_base::encode(&osis_base::Value::List(vec![osis_base::Value::Int(1)])) } else { bytes };
        writes.push(AspectWrite { tid: d.tid, ak: d.ak, lo: d.lo, hi: d.hi, delta: bytes, retention, replaces: d.replaces, original_floor: d.original_floor });
    }
    let mut b = CommitBuilder::new(plan.kind, plan.ts, node, plan.actor, plan.form);
    b.expires = plan.expires;
    b.aspects = writes;
    b.purge = plan.purge;
    b.undoes = plan.undoes;
    b.frontier = plan.frontier.map(|f| f.ids());
    b.blind = Some(plan.blind);
    b.rotation = plan.rotation.as_ref().map(|r| (r.header.clone(), r.merge_keys.clone()));
    b.own_cover = plan.own_cover;
    b.reseal = plan.reseal.clone();
    // a commit built in a memory transaction is a memory commit (spec/commits.md §2, §3)
    b.ephemeral = tx.txn.is_memory().then_some(osis_commit::EphClass::Plain);
    // a merge is signed at the head it names first (`flows::signing::rotate_in`)
    let account = match plan.rotation.as_ref().and_then(|r| r.at.clone()) {
        Some(at) => Some(at),
        None => tx.core.account_signing(&node)?,
    };
    let more = plan.rotation.as_ref().map(|r| r.more.clone()).unwrap_or_default();
    b.account = account.as_ref().map(|(epoch, k)| osis_commit::AccountSigner { epoch: *epoch, inner: k.inner.clone(), node: tx.core.id.tid(), node_key: tx.core.id.keys().signing.clone(), more });
    let built = {
        let core: &Core = tx.core;
        let secrets = CommitSecrets { core, actor: plan.actor, created: &plan.creates, published: &published, keys: &keys };
        let mut seed = [0u8; 32];
        tx.rng.fill_bytes(&mut seed);
        let mut list_rng = osis_crypto::SeededRng::from_seed(seed);
        let mut sink = ListBlobs { blobs: TxBlobs::new(&mut tx.blobs, tx.txn.is_memory()), rng: &mut list_rng };
        let signing = if let Some((_, k)) = &account { &k.signing } else if node == core.id.tid() { &core.id.keys().signing } else { &core.key_actors.get(&node).ok_or(Error::Misuse("signer not held"))?.keys().signing };
        b.build(signing, &secrets, &mut sink, &mut *tx.rng)
    };
    let built = match built {
        // an ephemeral commit past a blob is refused (spec/sync-compaction.md §2): its values are inline, so
        // one past a page makes its delta's root too large (issues/eph-parity.md Large values)
        Err(osis_commit::Error::Build(osis_commit::COMMIT_PAST_BLOB)) if tx.txn.is_memory() => return Err(Error::Misuse("an ephemeral commit does not fit a blob")),
        b => b?,
    };
    Ok(built)
}

impl Engine {
    /// Tests: a new thing whose first admin is `admin`, created by `m` (spec/data-model.md §1) and
    /// held where it lives (`hold_where_it_lives`).
    #[doc(hidden)]
    pub fn new_thing(&mut self, m: &mut Mutation, admin: Tid) -> Tid {
        self.new_expiring_thing(m, admin, None)
    }

    /// Tests: `new_thing` ending at `expires`; `m` expires then.
    #[doc(hidden)]
    pub fn new_expiring_thing(&mut self, m: &mut Mutation, admin: Tid, expires: Option<WallMs>) -> Tid {
        let t = m.create(self.thing_record(admin, expires));
        self.hold_where_it_lives(m, t, admin);
        if let Some(at) = expires {
            m.expires_all(at);
        }
        t
    }

    /// Tests: the record of a new thing under `admin`, its holding strong (`hold_where_it_lives`)
    /// committed first, so the commit that makes it can carry its creation alone.
    #[doc(hidden)]
    pub fn held_record(&mut self, admin: Tid) -> Result<CreationRecord> {
        let rec = self.thing_record(admin, None);
        let mut m = Mutation::new();
        self.hold_where_it_lives(&mut m, rec.tid(), admin);
        self.commit(m)?;
        Ok(rec)
    }

    /// Tests: writes in `m` the strong that holds `t`, made under `admin` (spec/sync-set.md §2
    /// Making a thing): from `admin` where that is a thing `m` makes or the node holds, else from
    /// the account root (what an account's node writes, it writes as the account), else from the
    /// node root.
    #[doc(hidden)]
    #[allow(clippy::expect_used)] // tests: an op on a static core aspect
    pub fn hold_where_it_lives(&self, m: &mut Mutation, t: Tid, admin: Tid) {
        let holder = if m.creates.contains_key(&admin) || self.closure_holds(&admin) {
            Some(admin)
        } else if let Some((_, d)) = self.core.account_and_root() {
            Some(d)
        } else {
            self.core.node_root
        };
        if let Some(h) = holder {
            m.op(h, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(t)) }).expect("holds.0 takes a strong");
        }
    }

    /// The creation record of a new thing whose first admin is `admin`, ending at `expires`
    /// (`None`: never; `Mutation::create` writes it, its commit expiring then).
    pub fn thing_record(&mut self, admin: Tid, expires: Option<WallMs>) -> CreationRecord {
        crate::identity::thing_record(admin, expires.map(|t| t.0), &mut *self.rng)
    }

    /// Commits `m` as one commit; `None` when it changes nothing. `Clash` when its deltas cannot
    /// share one (spec/commits.md §5, §6).
    pub fn commit(&mut self, m: Mutation) -> Result<Option<CommitId>> {
        self.run(|tx| commit_in(tx, m))
    }
}

/// Commits `m` in `tx` as one commit (`one_commit`); none when it changes nothing. Except: a thing
/// made under an account (in no sync unit) has secrets of its own before any content is written
/// on it (spec/permissions.md §3), as `Engine::mint_actor` mints (`keyed_first`). Refused when it
/// would take away a strong the node's roots keep (`roots::kept`), however it is written.
pub(crate) fn commit_in(tx: &mut Tx<'_>, m: Mutation) -> Result<Option<CommitId>> {
    if m.sealed {
        return Err(Error::Misuse("a sealed fire is built by `sealed_commit`"));
    }
    let kept = crate::flows::roots::kept(tx)?;
    let r = keyed_first(tx, m)?;
    crate::flows::roots::still_kept(tx, &kept)?;
    Ok(r)
}

/// `commit_in`'s commits. A thing `m` makes under an account is due own keys
/// (`Core::own_keys_due`); one due that `m` writes content on gets them first: its record in its
/// own-keys rotation where `m` makes it (`rotation::own_secrets_new`), then the rest of `m` under
/// its own keys, the last commit returned. Except an expiring thing's: a role commit never
/// expires, so its record goes alone, in a commit expiring with it. One `m` makes without content goes
/// with `m` as it is, keyed at the transaction's end or by its maker first (a link's K, its sync
/// ID listing L).
fn keyed_first(tx: &mut Tx<'_>, mut m: Mutation) -> Result<Option<CommitId>> {
    for (t, r) in &m.creates {
        if r.first_admin().is_some_and(|a| tx.core.is_account(&a)) {
            tx.core.own_keys_due.insert(*t);
        }
    }
    let content = |t: &Tid| m.aspects.keys().any(|(x, ak)| x == t && ak.as_str() != CREATED.ak() && !is_role_class(ak.as_str()));
    let now: Vec<Tid> = tx.core.own_keys_due.iter().filter(|t| content(t)).copied().collect();
    if now.is_empty() {
        return Ok(commit_or_build(tx, m)?.map(|(id, _)| id));
    }
    let mut done = crate::flows::Done::default();
    let mut records = Mutation::new();
    records.signer = m.signer;
    for t in &now {
        tx.core.own_keys_due.remove(t);
        match m.creates.remove(t) {
            // a role commit never expires: an expiring record goes alone, in a commit expiring with it
            Some(r) if r.expires().is_some() => {
                records.creates.insert(*t, r);
            }
            Some(r) => {
                crate::rotation::own_secrets_new(tx, r, &[], &mut done)?;
            }
            None => {}
        }
    }
    if !records.creates.is_empty() {
        done.add(commit_or_build(tx, records)?.map(|(id, _)| id));
    }
    for t in &now {
        crate::rotation::own_secrets(tx, *t, &mut done)?;
    }
    Ok(commit_or_build(tx, m)?.map(|(id, _)| id).or(done.commits.last().copied()))
}

/// The commit of sealed fire mutation `m` (one fire of an open signal on a thing this node need
/// not hold, spec/sync-inbox.md §2), built and signed, never applied here: the sender holds no
/// setting of the thing and is bound by none (spec/commits.md §5 The setting).
pub(crate) fn sealed_commit(tx: &mut Tx<'_>, mut m: Mutation) -> Result<osis_commit::CommitBlob> {
    m.sealed = true;
    let one = matches!(m.aspects.keys().collect::<Vec<_>>().as_slice(), [(_, ak)] if ak.open());
    if !one || !m.creates.is_empty() || !m.purge.is_empty() || !m.purge_named.is_empty() || m.undoes.is_some() || tx.txn.is_memory() {
        return Err(Error::Misuse("a sealed fire is one fire of an open signal"));
    }
    commit_or_build(tx, m)?.and_then(|(_, b)| b).ok_or(Error::Misuse("a sealed fire writes nothing"))
}

/// `commit_in`, or for a sealed mutation the built commit, unapplied.
pub(crate) fn commit_or_build(tx: &mut Tx<'_>, mut m: Mutation) -> Result<Option<(CommitId, Option<osis_commit::CommitBlob>)>> {
    let sealed = m.sealed;
    let node = match m.signer {
        Some(k) if tx.core.key_actors.contains_key(&k) || tx.core.accounts.contains_key(&k) => k,
        Some(_) => return Err(Error::Misuse("signer not held")),
        // a node writes its own thing as itself: nobody else has rights on it
        None if !(m.aspects.is_empty() && m.creates.is_empty()) && m.aspects.keys().map(|(t, _)| t).chain(m.creates.keys()).all(|t| tx.core.made_nodes_own(t, &m.creates)) => {
            m.actor = None;
            tx.core.id.tid()
        }
        None => tx.core.writer()?,
    };
    if m.undoes.is_some() && !(m.creates.is_empty() && m.aspects.is_empty() && m.purge.is_empty() && m.purge_named.is_empty() && m.frontier.is_none()) {
        return Err(Error::Misuse("an undo mutation carries no other ops"));
    }
    let core_schema = Arc::new(osis_schema::core_schema().clone());
    let memory = tx.txn.is_memory();
    // minted once: a record held ahead of its minting is the one the rotation giving it
    // secrets of its own carries (`rotation::own_secrets_new`)
    for (t, rec) in &m.creates {
        if tx.core.created(t).is_some_and(|r| r != rec || tx.core.mintings(t).next().is_some()) && !tx.core.skip_writer_rules {
            return Err(Error::Misuse("thing already exists"));
        }
    }
    // a thing's record is durable: a memory commit carries none (spec/commits.md §2)
    if memory && !m.creates.is_empty() {
        return Err(Error::Misuse("a memory commit creates nothing"));
    }
    // an aspect's class is its key's `+` marker (spec/commits.md §2); tests let a local writer
    // break this, to test receivers
    if !tx.core.skip_writer_rules && m.aspects.keys().any(|(_, ak)| !crate::apply::fits_class(ak, memory)) {
        return Err(Error::Misuse(if memory { "a memory commit writes ephemeral aspects only" } else { "a durable commit writes durable aspects only" }));
    }
    let ts = m.ts.unwrap_or_else(|| tx.core.hlc.next());
    // a node writes only what it holds (spec/sync-set.md §2 Writing): every thing the commit
    // makes, and every thing it writes not held as it writes, must be held at the transaction's
    // end; a key actor is in no closure; a sealed fire is built, never applied
    if !sealed {
        tx.core.wrote_on.extend(m.creates.iter().filter(|(_, r)| !matches!(r, CreationRecord::KeyActor { .. })).map(|(t, _)| *t));
        let unheld: Vec<Tid> = m.aspects.keys().map(|(t, _)| *t).filter(|t| !m.creates.contains_key(t) && !tx.core.is_key_actor(t) && !tx.core.ix.closure.holds(t)).collect();
        tx.core.wrote_on.extend(unheld);
    }
    // every minting's commit expires with its record (spec/commits.md §5 Destruction)
    for (&t, rec) in &m.creates {
        if rec.expires().is_some_and(|x| x <= ts.wall_ms().0) && !tx.core.skip_writer_rules {
            return Err(Error::Clash(format!("{t} expires at {}, which has passed", rec.expires().unwrap_or(0))));
        }
        let e = m.aspects.entry((t, Ak::new(CREATED.ak()).map_err(|_| Error::Misuse("ak"))?)).or_default();
        e.schema = Some(core_schema.clone());
        e.ops.push(PathOp { path: Vec::new(), op: Op::Set(rec.to_value()) });
        e.expires = rec.expires();
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
    let records_only = !content && !role_commit && !m.aspects.is_empty() && m.aspects.values().all(|a| a.expires.is_none());
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
        return crate::undo::undo_in(tx, u, m.actor.unwrap_or(node), m.ts, m.confined).map(|c| Some((c, None))).or_else(|e| match e {
            Error::Misuse("nothing to undo") => Ok(None),
            e => Err(e),
        });
    }
    for (c, tid, ak) in std::mem::take(&mut m.purge_named) {
        let item = tx.core.purge_item(&c, tid, ak).ok_or(Error::UnknownCommit(c))?;
        m.purge.push(item);
    }
    let base = CommitPlan { kind, ts, actor: m.actor.unwrap_or(node), form: Form::Commit, creates: std::mem::take(&mut m.creates), purge: std::mem::take(&mut m.purge), undoes: None, frontier: m.frontier.take(), signer: node, blind: m.blind.unwrap_or_else(|| draw_blind(&mut *tx.rng)), expires: None, restores: false, rotation: m.rotation.take(), reseal: m.reseal.take() , own_cover: false };
    if !m.unchecked {
        check_acts(tx.core, node, &|t| base.creates.get(t), &base.actor, ts)?;
    }
    let mut aspects = Vec::with_capacity(m.aspects.len());
    for ((tid, ak), mut am) in std::mem::take(&mut m.aspects) {
        // a sealed fire's thing: known by its public key record alone
        if !base.creates.contains_key(&tid) && !(if sealed { tx.core.created(&tid).is_some() } else { tx.core.writable(&tid) }) {
            return Err(Error::UnknownThing(tid));
        }
        if !m.unchecked {
            check_authority(tx.core, node, &base.creates, &tid, ak.as_str(), ts)?;
        }
        // a content write is written under the setting: one known and not held yet is waited
        // for, never read as none (`secrets::usable_role`, spec/commits.md §5 The setting)
        if kind == Kind::Content && !sealed && super::secrets::awaits_setting(tx.core, &tid) {
            return Err(Error::Permission { tid });
        }
        let (r, e) = {
            if let Some(o) = am.replaces {
                if !tx.core.skip_writer_rules && (memory || kind != Kind::Content || !super::edits::durable_signal(&ak)) {
                    return Err(Error::Misuse("only a durable signal's fire is replaced"));
                }
                // an edit ends with its original (spec/commits.md §5 Signals)
                am.expires = am.expires.or_else(|| tx.core.ix.commits.get(&o).and_then(|m| m.header.expires));
                // the original's floor (the floor of the epoch it was opened or written under): a
                // node granted without history after it lists the edit nowhere, as it holds no
                // version of the original (spec/commits.md §5 Signals, spec/crypto.md §4)
                am.original_floor = match tx.core.ix.commits.get(&o).and_then(|m| m.aspect(&tid, &ak)) {
                    Some(oai) => crate::sync_ids::opened::part_floor(tx, &o, oai, &tid)?.unwrap_or(0),
                    None => 0,
                };
                #[cfg(test)]
                if let Some(f) = tx.core.lie_floor {
                    am.original_floor = f;
                }
            }
            settle(tx.core, memory, kind, ts, &tid, &ak, am.schema.as_deref(), am.replaces.is_some(), am.retention, am.expires)?
        };
        // a signal write is a whole value, history from the start (spec/commits.md §5 Signals)
        if ak.signal() && !tx.core.skip_writer_rules {
            if !matches!(am.ops.as_slice(), [op] if op.path.is_empty() && matches!(op.op, Op::Set(_))) || m.dead_resets.contains_key(&(tid, ak.clone())) {
                return Err(Error::Misuse("a signal is fired once per commit: one set at the root"));
            }
            // a fire is history from its own `ts`: one the settings held would not keep would be
            // in no history at all
            let wall = ts.wall_ms().0;
            if !memory && !sealed && crate::retention::history::of(tx.core, &tid, &ak).leaves_at(Some(wall), ts) <= wall {
                return Err(Error::Misuse("a fire is history: the thing's setting keeps no history for this signal"));
            }
        }
        // a role commit never expires, so it creates no expiring thing
        if ak.as_str() == CREATED.ak() && !tx.core.skip_writer_rules && let Some(want) = base.creates.get(&tid).map(CreationRecord::expires)
            && e != want
        {
            return Err(Error::Clash(format!("{tid} expires, and a commit of roles does not: create it in a write of its own")));
        }
        (am.retention, am.expires) = (Some(r), e);
        aspects.push(((tid, ak), am));
    }
    let entries: Vec<(Tid, &Ak, &Retention, Option<u64>)> = aspects.iter().filter_map(|((t, ak), am)| Some((*t, ak, am.retention.as_ref()?, am.expires))).collect();
    let expires = one_commit(&entries, "Write them as separate commits")?;
    place_requests(&mut aspects, expires);
    // role commits use commit form: a later commit by the same node can never void them by
    // reusing their counters; content commits write under this open's session unless asked
    // for commit form (spec/commits.md §3); expiring memory writes under its second session
    // (`Core::expiring`)
    let mut plan = base;
    plan.expires = expires;
    plan.form = if kind != Kind::Content || m.commit_form || (plan.signer != tx.core.id.tid() && !tx.core.is_account(&plan.signer)) { Form::Commit } else { Form::Session(tx.core.nonce_as(&plan.signer, if memory && expires.is_some() { tx.core.expiring.nonce } else { tx.core.session.nonce })) };
    let form = plan.form;
    let mut next_ctr = 1u64;
    let mut deltas: Vec<Resolved> = Vec::new();
    let published = super::secrets::published_keys(tx, &plan.creates, aspects.iter().map(|k| k.0.0))?;
    let keys = super::secrets::KeyCache::default();
    for ((tid, ak), mut am) in aspects {
        // a `retention^.0` delta is read alone: it writes the whole value
        if ak.as_str() == osis_commit::retention::RETENTION && !tx.core.skip_writer_rules {
            for o in &mut am.ops {
                match (o.path.is_empty(), &o.op) {
                    (true, osis_crdt::Op::Set(v)) => o.op = osis_crdt::Op::Replace(v.clone()),
                    (true, osis_crdt::Op::Replace(_)) => {}
                    _ => return Err(Error::Misuse("retention^.0 is written whole")),
                }
            }
            if am.ops.len() > 1 {
                return Err(Error::Misuse("retention^.0 is written whole"));
            }
            if am.ops.iter().any(|o| matches!(&o.op, osis_crdt::Op::Replace(v) if osis_schema::core_types::retention_setting(v).is_none())) {
                return Err(Error::Misuse("retention^.0 that is no setting: a key that is no AK, or over MAX_RETENTION_ENTRIES entries"));
            }
            // an entry no write could take: a zero or endless expiry, a history bound out of range
            let bad = |q: &osis_schema::core_types::RetentionEntry| !osis_commit::retention::entry_fits(q);
            if am.ops.iter().any(|o| matches!(&o.op, osis_crdt::Op::Replace(v) if osis_schema::core_types::retention_setting(v).is_some_and(|r| r.rules.values().chain(&r.default).any(bad)))) {
                return Err(Error::Misuse("retention^.0 with an entry out of range"));
            }
            // purge on replace is one way: the floors joined over every held valid setting
            // carried, this write's stamp where the current one purged on replace
            // (spec/commits.md §5 One way)
            let all = crate::apply::validity::settings(tx.core, &tid);
            let held: Vec<(osis_base::Ts, &osis_schema::core_types::RetentionSetting)> = all.iter().map(|(p, x)| (p.ts, &**x)).collect();
            for o in &mut am.ops {
                if let osis_crdt::Op::Replace(v) = &mut o.op
                    && let Some(mut s) = osis_schema::core_types::retention_setting(v)
                {
                    osis_commit::retention::carry_floors(&mut s, &held, plan.ts);
                    *v = osis_schema::Codec::to_value(&s);
                }
            }
        }
        let retention = am.retention.unwrap_or_default();
        let framing = match kind {
            Kind::Content => Some(framing_for(tx.core, memory, &plan, &published, &keys, &tid, &retention)?),
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
        // depth counts a value as read (spec/data-model.md §5): checked before large values
        // become links, which count as leaves after
        let view = am.schema.as_ref().and_then(|s| s.view(ak.as_str()));
        let deep = |op: &PathOp| match &view {
            Some(v) => osis_crdt::out_of_profile(op, v),
            None => osis_crdt::out_of_profile(op, &AnyView),
        };
        if am.ops.iter().any(deep) {
            return Err(osis_crdt::Error::Mismatch("value nested deeper than MAX_VALUE_DEPTH or enum case above i64::MAX").into());
        }
        // large atomic values become chunk trees before the ops resolve, a memory commit's held
        // in memory (spec/data-model.md §6)
        let mut chunks = Vec::new();
        if let Some(framing) = &framing {
            chunks = super::large::chunk_ops(tx, &tid, &ak, &mut am.ops, &edits, am.schema.as_deref(), framing, &m.fresh)?;
        }
        // a sealed fire carries its value inline: its receivers fetch no blob of it
        if sealed && !chunks.is_empty() {
            return Err(Error::Misuse("a sealed fire's value fits inline"));
        }
        let lo = match form {
            Form::Commit => next_ctr,
            // a session's counters: memory rows, gone with the session
            Form::Session(n) => tx.txn.counter(&tid, &ak, &n)?,
        };
        let empty = Fragment::default();
        // map removals carry their key only where keys are public ids (spec/crdt.md §5.6)
        let keyed = osis_schema::core_types::is_role_class(ak.as_str());
        // a hostile writer (tests) mints a held record again: as over no state
        let remint = tx.core.skip_writer_rules && ak.as_str() == CREATED.ak();
        let w = seeing(tx, &tid, &ak, &am.ops, Writer::new(ts, own_source(form, node), lo).keyed_removals(keyed))?;
        let run = |tx: &Tx<'_>| {
            let state = if remint { &empty } else { tx.cached(&tid, &ak).unwrap_or(&empty) };
            let w = w.clone();
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
        let r = Resolved { tid, ak, fragment, lo: range.lo, hi: range.hi, schema: am.schema, retention: am.retention, expires: am.expires, replaces: am.replaces, original_floor: am.original_floor, frontiers: None, chunks };
        deltas.push(r);
    }
    if deltas.is_empty() && plan.purge.is_empty() {
        return Ok(None);
    }
    // a request is placed under its thing's sync IDs by a delta on the thing (spec/commits.md §5
    // Purge): in a commit that expires, one of its own writes there (`place_requests`), which may
    // write nothing
    if plan.expires.is_some()
        && let Some(p) = plan.purge.iter().find(|p| !deltas.iter().any(|d| d.tid == *p.tid()))
    {
        return Err(Error::Clash(format!("a purge goes under a write of its thing, and this commit writes nothing on {}. Write the purge as a commit of its own", p.tid())));
    }
    if sealed {
        let built = build(tx, plan, deltas)?;
        return Ok(Some((built.commit.id(), Some(built.commit))));
    }
    let id = build_and_apply(tx, plan, deltas)?;
    Ok(Some((id, None)))
}

/// `w` for ops `ops` on aspect `(tid, ak)`: a removal of a tid among them covers the parts held
/// as headers only too (`header_only_parts`, spec/crdt.md §5.5).
pub(crate) fn seeing(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, ops: &[PathOp], w: Writer) -> Result<Writer> {
    if !ops.iter().any(|o| matches!(o.op, Op::Remove(Value::Weak(_)))) {
        return Ok(w);
    }
    Ok(w.seen_headers(header_only_parts(tx, tid, ak)?))
}

/// The parts of aspect `(tid, ak)` this node holds as headers only, by their dots (spec/crdt.md
/// §2.4): valid here, not received yet (`Hold::Missing`), and not stamped below a held root
/// reset, which leaves them nothing. What a removal of a tid there covers beside the elements
/// held (§5.5).
fn header_only_parts(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<osis_crdt::DotRange>> {
    let cs: Vec<CommitId> = tx.core.ix.missing.get(&(ak.clone(), *tid)).into_iter().flatten().copied().collect();
    if cs.is_empty() {
        return Ok(Vec::new());
    }
    // the root's reset, held whatever pages are loaded
    tx.load_lazy(tid, ak)?;
    let reset = tx.cached(tid, ak).and_then(Fragment::reset).map(|r| r.ts);
    let mut out = Vec::new();
    for c in cs {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let Some(a) = m.aspect(tid, ak).filter(|ai| m.valid_at(*ai) && m.missing(*ai)).and_then(|ai| m.view.aspects.get(ai)) else { continue };
        if a.lo < a.hi && reset.is_none_or(|r| m.view.ts >= r) {
            out.push(osis_crdt::DotRange { first: osis_crdt::Dot::new(m.view.form.own_source(m.view.author, c), a.lo), hi: a.hi });
        }
    }
    Ok(out)
}

/// Records schema `s` as the local schema of each AK it declares, in memory and in the store
/// (`records::SCHEMAS`, one record per AK), unless the one kept has a higher revision (a stale
/// app never downgrades it) or the same one and this is a local write, not a registration
/// (`replace`). An equal one writes nothing (every open re-registers). Revisions of unrelated
/// schemas claiming one AK compare too: a collision is the convention's failure (spec/versioning.md
/// §3) and this keeps the choice deterministic. The core schema is compiled in, never kept.
pub(crate) fn keep_schema(tx: &mut Tx<'_>, s: &Arc<osis_schema::Schema>, replace: bool) -> Result<()> {
    if s.declares_core() {
        return Ok(());
    }
    let mut bytes = None;
    for ak in s.aspects.keys() {
        if let Some(k) = tx.core.schemas.get(ak)
            && (**k == **s || k.revision > s.revision || (!replace && k.revision == s.revision))
        {
            continue;
        }
        tx.core.schemas.insert(ak.clone(), s.clone());
        let b = bytes.get_or_insert_with(|| s.canonical_bytes());
        tx.txn.put_local(&[super::records::SCHEMAS, ak.as_bytes()].concat(), b, osis_store::Shred::No)?;
    }
    Ok(())
}
