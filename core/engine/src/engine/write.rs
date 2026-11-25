//! Writing (spec/crdt.md §2.3, §4.5, §9; spec/commits.md §1–§3, §5, §6): a `Mutation` collects
//! ops across things; `Engine::commit` resolves them against local state (one delta per
//! aspect, the net effect), takes counters, fills purge-by and expiry from the schema, pages
//! large deltas, checks this node's role on every touched thing, signs, and applies the commit
//! locally in the same store transaction that reserves its counters, so nothing signed leaves
//! the node before its counters are durable.

use super::blobs::{ListBlobs, TxBlobs};
use super::secrets::CommitSecrets;
use super::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::sync::units::Written;
use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, PurgeItem, writer_ctx};
use osis_base::{Ak, ChainStep, CommitId, CreationRecord, Holder, Role, Tid, Ts, Value, WallMs, record_chain};
use osis_crdt::{AnyView, DeltaBuilder, CounterRange, Delta, Fragment, Op, PathOp, Source, View, Writer, encode_delta};
use osis_blob::{BlobWriter, Framing};
use osis_perm::At;
use osis_perm::graph::Need;
use osis_schema::core_types::{self as ct, CREATED, is_role_class};
use osis_schema::{RawKey, PurgeBy, Schema};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Ops on one aspect.
#[derive(Clone, Debug, Default)]
pub(crate) struct AspectMut {
    pub ops: Vec<PathOp>,
    pub schema: Option<Arc<Schema>>,
    pub purge_by: Option<PurgeBy>,
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

/// The first epochs of the things a commit mints with a key, from its rotation from none
/// (spec/permissions.md §3): their delete base is themselves, at those epochs.
pub(crate) type Minted = BTreeMap<Tid, osis_keys::ActorEpochs>;

/// Writes that become one commit.
#[derive(Clone, Debug)]
pub struct Mutation {
    pub(crate) creates: Creates,
    pub(crate) minted: Minted,
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
    /// Role flows judge their own authority (may-grant grants, self-removals).
    pub(crate) unchecked: bool,
    /// The thing signed as where it is not the node's (commit form).
    pub(crate) signer: Option<Tid>,
    /// Map entries to reset whatever their liveness here (spec/crdt.md §5.6): an explicit removal
    /// of an edge already removed (role flows).
    pub(crate) dead_resets: BTreeMap<(Tid, Ak), Vec<(osis_crdt::Dot, Value)>>,
    /// Map keys holding no entry to reset anyway (spec/permissions.md §2: a removal of a mint
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
        Mutation { creates: Creates::new(), minted: Minted::new(), aspects: BTreeMap::new(), actor: None, confined: false, commit_form: false, purge: Vec::new(), purge_named: Vec::new(), undoes: None, frontier: None, unchecked: false, signer: None, dead_resets: BTreeMap::new(), fresh_resets: BTreeMap::new(), sweeps: BTreeSet::new(), fresh: Default::default(), ts: None, blind: None, sealed: false }
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

    /// Signs as `thing` by a key this node holds holding a grant on it (spec/permissions.md §1
    /// Signed as; `Core::key_for`): its record's key, else a key granted on it, in commit form
    /// (its key holders share no counters).
    pub fn sign_as(&mut self, thing: Tid) -> &mut Self {
        self.signer = Some(thing);
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

    /// The setting of `t` this mutation writes whole, if it does.
    pub(crate) fn setting_of(&self, t: &Tid) -> Option<ct::RetentionSetting> {
        let a = self.aspects.get(&(*t, ak_of(&ct::RETENTION).ok()?))?;
        match a.ops.iter().rev().find(|o| o.path.is_empty()) {
            Some(PathOp { op: Op::Set(v) | Op::Replace(v), .. }) => ct::RETENTION.decode(v).ok(),
            _ => None,
        }
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

    /// Resets the hidden records of `(tid, ak)` (`Fragment::sweep`); the schema gives its purge-by.
    pub(crate) fn sweep(&mut self, tid: Tid, ak: Ak, schema: Option<Arc<Schema>>) {
        self.aspects.entry((tid, ak.clone())).or_default().schema = schema;
        self.sweeps.insert((tid, ak));
    }

    /// Purge-by for this aspect's delta, instead of the schema default (spec/commits.md §5).
    pub fn purge_by<K: RawKey>(&mut self, tid: Tid, key: &K, r: PurgeBy) -> Result<&mut Self> {
        self.entry(tid, key)?.purge_by = Some(r);
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

    /// Skips the plain role check (role flows judge may-grant grants and self-removals).
    pub(crate) fn unchecked(&mut self) -> &mut Self {
        self.unchecked = true;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.creates.is_empty() && self.aspects.is_empty() && self.purge.is_empty() && self.purge_named.is_empty() && self.undoes.is_none()
    }
}

/// The role a write of `ak` needs (spec/permissions.md §1, §3, §5.2): admin for edges,
/// `sync.0` and admin-only (`^`) aspects; write for rotations
/// (`secrets.0`, `keys.0`) and other content.
pub(crate) fn required_role(ak: &str) -> Role {
    match ak {
        "roles.0" | "signers.0" | "sync.0" => Role::Admin,
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
    core.timelines().role(node, tid, At::now(ts))
}

/// What a fire its thing's setting keeps no history for fails with (spec/commits.md §5 Signals:
/// a fire is history, so one in none cannot be written).
pub(crate) const FIRE_IN_NO_HISTORY: &str = "a fire is history: the thing's setting keeps no history for this signal";

/// Looks up the creation record of a thing not yet held: the commit's own.
pub(crate) type Records<'a> = &'a dyn Fn(&Tid) -> Option<&'a CreationRecord>;

/// The role `node` has on `tid` at `ts`: a thing not yet held (`records`) has its record edge
/// alone, so a node's role on it is its role on its mint admin (spec/permissions.md §1).
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

/// May `node` (its node thing or a link key it signs as) write `ak` of `tid` at `ts`? Things not
/// held yet (`records`: those the commit creates) take their mint admin's, through mint admins
/// the commit creates too.
pub(crate) fn check_authority(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ak: &str, ts: Ts) -> Result<()> {
    check_role(core, node, records, tid, ak, required_role(ak), ts)
}

/// `check_authority` needing role `need`.
pub(crate) fn check_role(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, ak: &str, need: Role, ts: Ts) -> Result<()> {
    let role = role_with(core, node, records, tid, ts);
    if role >= Some(need) && (ak == CREATED.ak() || core.skip_writer_rules || within_depth(core, records, tid)) {
        return Ok(());
    }
    // an external fire by a party holding no write: only while the thing's current setting
    // enables its signal (spec/permissions.md §5.2 External fires)
    if Ak::markers_of(ak).external {
        let enabled = Ak::new(ak).is_ok_and(|a| crate::apply::validity::setting_now(core, tid).is_some_and(|s| s.enables(&a)));
        return if enabled { Ok(()) } else { Err(Error::NotEnabled { tid: *tid, ak: ak.to_string() }) };
    }
    Err(Error::Permission { tid: *tid, needs: need })
}

/// Whether this node may write on a held thing now (`may_write`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MayWrite {
    Yes,
    /// Not yet: the thing's minting, the setting this node knows it has, or (a snapshot) the
    /// establishment of an epoch a write it carries was read under is not here; they may arrive.
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
        && check_role(tx.core, node, &|_| None, tid, ak, need, ts).is_err()
    {
        return Ok(MayWrite::No);
    }
    may_write_on(tx, tid)
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
/// node holds the setting they are written under (`secrets::awaits_setting`).
pub(crate) fn may_write_on(tx: &mut Tx<'_>, tid: &Tid) -> Result<MayWrite> {
    if !tx.core.exists(tid) {
        return Ok(MayWrite::No);
    }
    Ok(if tx.core.writable(tid) && !super::secrets::awaits_setting(tx.core, tid) { MayWrite::Yes } else { MayWrite::Later })
}

/// The path a commit signed by `signer` states where no path is found for what it writes (a
/// fire valid by its thing's setting alone, a relayed signal's snapshot, a writer past the rules
/// naming `actor`): empty for the signer itself, else `actor` alone, named as purge author.
pub(crate) fn plain_path(signer: Tid, actor: Tid) -> osis_commit::Path {
    if actor == signer { osis_commit::Path::default() } else { osis_commit::Path::through(actor) }
}

/// A path found (`path_with`): the things listed, the hops marked direct, and whether its last hop
/// is a record edge.
pub(crate) type Found = (Vec<Tid>, osis_base::format::PathMarks, bool);

/// The path from `node` into `tid` giving at least `need` at `ts` (spec/permissions.md §1 Path):
/// `Found`, the fewest edges, then the fewest hops marked direct: a mint ancestor's direct edge
/// giving it is stated, marked, before the descent (`osis_perm::graph::View::ways_to`). A thing the commit creates
/// (`records`) is reached as its mint admin is, then by its record edge. `None`: no path gives it.
pub(crate) fn path_with(core: &Core, node: Tid, records: Records<'_>, tid: &Tid, need: Need, ts: Ts) -> Option<Found> {
    if *tid == node {
        return Some((Vec::new(), 0, true));
    }
    match record_chain(*tid, |t| records(t).map(CreationRecord::record_link)).next() {
        Some(ChainStep::Up { admin, .. }) => {
            // the record edge gives admin, so may-grant: the path to the mint admin needs the role alone
            let (mut listed, marks, descent) = path_with(core, node, records, &admin, Need::Role(need.role()), ts)?;
            // reached by a direct edge, the mint admin is listed; by descent, the descent goes on
            if !descent {
                listed.push(admin);
            }
            Some((listed, marks, true))
        }
        Some(ChainStep::Unknown(t)) => core.timelines().path_now(&node, &t, need, ts),
        Some(ChainStep::Key(_) | ChainStep::TooDeep) | None => None,
    }
}

/// The paths a commit states (spec/wire.md §4 field 2).
pub(crate) enum Stated {
    /// One path in the clear (`CommitBuilder::path`).
    One(osis_commit::Path),
    /// The split form (`CommitBuilder::split`): the purge author, each thing's path and its marks.
    Split(Option<Tid>, BTreeMap<Tid, (Vec<Tid>, osis_base::format::PathMarks)>),
}

/// What a commit states (spec/wire.md §4 field 2; notes/path-form.md The engine's choice). Each
/// thing it writes gets its own path: the path from the signer giving the strictest role its
/// aspects need there (`path_with`, memoized per (thing, role)), through the thing the commit
/// acts for, named as purge author, where it acts for one (to it, it, then its path to the
/// thing). One path in the clear where every thing's own path is read off one `Path`
/// (`Path::one_of`) and that path tells no reader of a thing written a roster fact it could not
/// read already (`clear_tells_nothing`); else the split form. Never a longer route for one thing
/// so that one path serves all. A role commit states `role_path`. A commit where no path gives the role on a thing it writes states
/// `plain_path` (a fire valid by its thing's setting); acting as a thing through which no path
/// gives the role is refused. A path listing more than `MAX_PATH_THINGS` things is refused.
pub(crate) fn stated_paths(core: &Core, plan: &CommitPlan, writes: &[AspectWrite], edges: &[(Tid, Holder, Option<osis_perm::Edge>)]) -> Result<Stated> {
    let (node, actor) = (plan.signer, plan.actor);
    let fallback = Stated::One(plain_path(node, actor));
    if plan.kind.is_role() {
        let real = role_path(core, plan, writes, edges)?;
        return Ok(Stated::One(real.unwrap_or_else(|| plain_path(node, node))));
    }
    let mut need: BTreeMap<Tid, Role> = BTreeMap::new();
    for w in writes {
        let r = if plan.kind.is_compaction() { snapshot_role(w.ak.as_str()) } else { required_role(w.ak.as_str()) };
        let e = need.entry(w.tid).or_insert(r);
        *e = (*e).max(r);
    }
    let records: Records<'_> = &|t| plan.creates.get(t);
    // each thing's own path, and whether its last hop is a record edge
    let mut each: BTreeMap<Tid, (osis_commit::Path, bool)> = BTreeMap::new();
    for (t, r) in need {
        let path = if actor == node {
            path_with(core, node, records, &t, Need::Role(r), plan.ts).map(|(things, direct, rec)| (osis_commit::Path { purge: 0, things, direct }, rec))
        } else {
            // Open (notes/a1-spec/README.md Open 16): acting for a thing not on this thing's path
            // is refused below
            path_with(core, node, records, &actor, Need::Role(r), plan.ts).zip(path_with(core, actor, records, &t, Need::Role(r), plan.ts)).map(|((to, to_marks, _), (from, from_marks, rec))| {
                let purge = to.len() + 1;
                // `from`'s hops follow `to`'s and the hop into the actor
                let direct = to_marks | from_marks << purge;
                (osis_commit::Path { purge, things: to.into_iter().chain([actor]).chain(from).collect(), direct }, rec)
            })
        };
        let Some(path) = path.filter(|(p, _)| p.things.iter().collect::<BTreeSet<_>>().len() == p.things.len() && !p.things.contains(&node)) else {
            // acting as a thing whose authority does not reach the write is refused: no path
            // through it gives the role (spec/permissions.md §1 Path); a writer past the rules
            // (tests: `skip_writer_rules`) states the thing alone
            if actor != node && !core.skip_writer_rules {
                return Err(Error::Permission { tid: t, needs: r });
            }
            return Ok(fallback);
        };
        if path.0.things.len() > osis_base::format::MAX_PATH_THINGS {
            return Err(Error::Misuse("a path through more than MAX_PATH_THINGS (64) holders"));
        }
        each.insert(t, path);
    }
    if each.is_empty() {
        return Ok(fallback);
    }
    if let Some(q) = osis_commit::Path::one_of(each.iter().map(|(t, (p, _))| (t, p)), node, actor)
        && clear_tells_nothing(core, plan, &q, &each)
        && !forced_split(each.len())
    {
        return Ok(Stated::One(q));
    }
    let author = (actor != node).then_some(actor);
    // each thing's listed things: its own path as `Path::to` reads it, the thing itself listed
    // last where it is the purge author
    let paths = each.into_iter().map(|(t, (p, _))| (t, (p.things, p.direct))).collect();
    Ok(Stated::Split(author, paths))
}

/// How a role commit's edge writes on a thing reach it where that is not by the signer's role
/// there (spec/permissions.md §2), read off what they write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoleWay {
    /// An may-grant grant of this role (the signer holds no admin on the thing and the commit puts a
    /// grant): the path giving may-grant at it on the thing (§2 Path's may-grant).
    MayGrant(Role),
    /// A self-removal of this holder's grant (every edge write on the thing lowers that grant, and
    /// it is the signer's own or the one the signer's admin on the thing rests on alone,
    /// `validity::self_removal`): the path ending at the holder, giving admin on it (§2
    /// Self-removal; the empty path where the holder is the signer, or the key signing as it).
    Leave(Tid),
}

/// The way of `edges` (a role commit's edge writes, (target, holder, new edge)) on thing `t`.
fn role_way(core: &Core, plan: &CommitPlan, t: &Tid, edges: &[(Tid, Holder, Option<osis_perm::Edge>)]) -> Option<RoleWay> {
    let on: Vec<(Holder, Option<osis_perm::Edge>)> = edges.iter().filter(|(x, _, _)| x == t).map(|(_, h, e)| (*h, *e)).collect();
    let (h, _) = on.first()?;
    let node = plan.signer;
    let old = |m: &Holder| match (core.timelines().get(t), m) {
        (Some(tl), Holder::Thing(m)) => tl.edges_at(None).get(m, t).copied(),
        (_, Holder::Key(k)) => core.timelines().key_grant(k, t),
        (None, Holder::Thing(m)) => (core.mint_admin(t) == Some(*m)).then(|| osis_perm::Edge::new(Role::Admin)),
    };
    // a removal of an absent grant lowers (spec/permissions.md §2 Self-removal)
    let lowers = on.iter().all(|(m, e)| m == h && osis_perm::types::lowers(e.as_ref(), old(m).as_ref()));
    // a key lowering its own grant on the thing it signs as states no thing (§2 Self-removal)
    let signing = plan.key.or_else(|| plan.creates.get(&node).or_else(|| core.created(&node)).and_then(CreationRecord::key));
    let own_key = |k: &osis_base::SignKey| *t == node && Some(*k) == signing;
    match h {
        Holder::Thing(h) if lowers && (*h == node || crate::apply::validity::self_removal(core, &node, t, h, plan.ts)) => return Some(RoleWay::Leave(*h)),
        Holder::Key(k) if lowers && own_key(k) => return Some(RoleWay::Leave(node)),
        _ => {}
    }
    let records: Records<'_> = &|x| plan.creates.get(x);
    let puts = on.iter().filter_map(|(_, e)| e.filter(|e| !e.says_retain()).map(|e| e.role)).max();
    match puts {
        Some(r) if role_with(core, node, records, t, plan.ts) < Some(Role::Admin) => Some(RoleWay::MayGrant(r)),
        _ => None,
    }
}

/// The one path a role commit states (notes/a1-spec/README.md step 3, Role paths; a role commit
/// never states the split form, spec/wire.md §4): for each thing it writes, the path from the
/// signer giving its role there (`role_with`, so a rotation reaches every role it rotates and an
/// admin's edge write admin), shortest by edges as for content (`path_with`); a compaction
/// snapshot's, the role it needs (`snapshot_role`); a may-grant grant's, the path giving the grant's
/// role as may-grant; a self-removal's, the path ending at the holder (`role_way`). A grant the
/// signer gives itself on a thing it reaches by descent states a path not ending at the signer
/// (which would make it a self-removal): the path to the thing's mint admin, then the mint admin
/// (its record edge the last hop). One `Path` serves every thing a role commit writes
/// (`Path::one_of`). `None` where no path gives what a thing needs.
fn role_path(core: &Core, plan: &CommitPlan, writes: &[AspectWrite], edges: &[(Tid, Holder, Option<osis_perm::Edge>)]) -> Result<Option<osis_commit::Path>> {
    let node = plan.signer;
    let records: Records<'_> = &|t| plan.creates.get(t);
    let things: BTreeSet<Tid> = writes.iter().map(|w| w.tid).collect();
    let mut each: BTreeMap<Tid, osis_commit::Path> = BTreeMap::new();
    for t in things {
        let found = match role_way(core, plan, &t, edges) {
            Some(RoleWay::Leave(h)) => path_with(core, node, records, &h, Need::Role(Role::Admin), plan.ts).map(|(mut listed, marks, _)| {
                if h != node {
                    listed.push(h);
                }
                (listed, marks)
            }),
            Some(RoleWay::MayGrant(r)) => path_with(core, node, records, &t, Need::MayGrant(r), plan.ts).map(|(listed, marks, _)| (listed, marks)),
            None => {
                let need = if plan.kind.is_compaction() { writes.iter().filter(|w| w.tid == t).map(|w| snapshot_role(w.ak.as_str())).max() } else { role_with(core, node, records, &t, plan.ts) };
                let found = need.and_then(|r| path_with(core, node, records, &t, Need::Role(r), plan.ts));
                let own = edges.iter().any(|(x, h, _)| *x == t && *h == Holder::Thing(node));
                match (found, plan.creates.get(&t).or_else(|| core.created(&t)).and_then(CreationRecord::mint_admin)) {
                    (Some((listed, _, _)), Some(m)) if own && listed.is_empty() && m != node => path_with(core, node, records, &m, Need::Role(Role::Admin), plan.ts).map(|(mut l, marks, _)| {
                        l.push(m);
                        (l, marks)
                    }),
                    (found, _) => found.map(|(listed, marks, _)| (listed, marks)),
                }
            }
        };
        let Some((listed, direct)) = found.filter(|(l, _)| l.iter().collect::<BTreeSet<_>>().len() == l.len() && !l.contains(&node)) else { return Ok(None) };
        if listed.len() > osis_base::format::MAX_PATH_THINGS {
            return Err(Error::Misuse("a path through more than MAX_PATH_THINGS (64) holders"));
        }
        each.insert(t, osis_commit::Path { purge: 0, things: listed, direct });
    }
    let one = osis_commit::Path::one_of(each.iter(), node, node);
    // the shape rules (spec/commits.md §2: one grant per role commit) give one path; a hostile
    // writer past them (`skip_writer_rules`: edge writes on several things) states the empty one
    debug_assert!(one.is_some() || each.is_empty() || core.skip_writer_rules, "a role commit's things are reached along one path: {each:?}");
    Ok(one)
}

#[cfg(test)]
thread_local! {
    /// Lib tests (`apply::tests_validity::split_and_clear_forms_apply_alike_spec_wire_4`): every
    /// commit writing two things or more states the split form, so a suite checks it behaves as the
    /// clear form for the same write. No build outside the lib's tests has it.
    pub(crate) static FORCE_SPLIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the split form is forced for a commit writing `things` things (`FORCE_SPLIT`).
fn forced_split(things: usize) -> bool {
    #[cfg(test)]
    {
        things >= 2 && FORCE_SPLIT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        let _ = things;
        false
    }
}

// For Tess 3 (notes/path-form.md, One path): the rule below closes what the clear
// form shows; "accept" drops it (one path wherever one serves), "always seal" never states the
// clear form for a commit writing two things or more.
/// Whether one path `q` in the clear tells no reader of a thing the commit writes a roster fact
/// it could not read already (notes/path-form.md, One path). Every thing's chain up to
/// the end is a prefix of each reader's own. On the empty path every thing hangs off the signer:
/// that the signer holds a role on what it writes is what "written by the signer" shows. Else what
/// `q` adds, for a thing `t` one hop past its end (not the end itself), is `t`'s last edge, read by
/// the readers of every other thing `w` written.
/// They read it already where `t` derives its read secret from `w` (`w` on `t`'s record chain up
/// to `t`'s independent: `w`'s readers read `t` whole, roster and record), or where that edge is
/// `t`'s record edge (by descent) and `w` descends from `t` (`w`'s readers hold `w`'s record chain,
/// `t`'s record on it).
fn clear_tells_nothing(core: &Core, plan: &CommitPlan, q: &osis_commit::Path, each: &BTreeMap<Tid, (osis_commit::Path, bool)>) -> bool {
    let Some(end) = q.things.last() else { return true };
    let rec = |t: &Tid| plan.creates.get(t).or_else(|| core.created(t)).cloned();
    let independent = |t: &Tid| independent_in(core, t);
    // `w` on `t`'s record chain, `t` included, stopping past `t`'s independent (`upto`) or not
    let on_chain = |t: &Tid, w: &Tid, upto: bool| {
        let mut x = Some(*t);
        for _ in 0..=osis_base::format::MAX_CHAIN_DEPTH + 1 {
            let Some(cur) = x else { return false };
            if cur == *w {
                return true;
            }
            if upto && independent(&cur) {
                return false;
            }
            x = rec(&cur).and_then(|r| r.mint_admin());
        }
        false
    };
    each.iter().filter(|(t, _)| *t != end).all(|(t, (_, by_record))| each.keys().filter(|w| *w != t).all(|w| on_chain(t, w, true) || (*by_record && on_chain(w, t, false))))
}

/// Whether thing `t` reads by its own secrets when a content commit applies: held as
/// independent, or one minted with a key (spec/crypto.md §3). A thing a content commit makes is dependent
/// in it: only a role commit writing its `keys.0` makes it independent, and a role commit states
/// no split path (`stated_paths`).
fn independent_in(core: &Core, t: &Tid) -> bool {
    core.ix.independent.contains(t) || core.created(t).is_some_and(|r| r.mint_admin().is_none())
}

/// The read roles secret the path key of thing `t` (written by commit `plan`) is derived from
/// (spec/crypto.md §5 Path entry): of `t`'s independent (up its record chain, the commit's own
/// records first), at the newest current epoch held, which its sections go under; else the
/// newest whose roles secret is held (a holder left unboxed at the current epoch, spec/crypto.md
/// §4 Low floor, writes on); else a fresh random one, so the write is never refused for its path
/// (notes/path-form.md): only the encryptions of `t`'s parts, which carry the key, open the entry.
fn path_secret(core: &Core, plan: &CommitPlan, t: &Tid, rng: &mut dyn osis_crypto::CryptoRngCore) -> osis_crypto::Secret32 {
    held_path_secret(core, plan, t).unwrap_or_else(|| osis_crypto::Secret32::random(rng))
}

fn held_path_secret(core: &Core, plan: &CommitPlan, t: &Tid) -> Option<osis_crypto::Secret32> {
    let mut x = *t;
    for _ in 0..=osis_base::format::MAX_CHAIN_DEPTH + 1 {
        if independent_in(core, &x) {
            break;
        }
        match plan.creates.get(&x).or_else(|| core.created(&x)).and_then(CreationRecord::mint_admin) {
            Some(up) => x = up,
            None => break,
        }
    }
    let e = core.epochs(&x)?;
    osis_keys::wrap_epoch(&e.read).and_then(|ep| e.read.roles_secret(&ep)).or_else(|| e.read.held_roles().pop().map(|(_, s)| s))
}

/// May `node` act for `actor` at `ts`: it is the actor or holds write on it? A receiver judges a
/// commit invalid otherwise: its path through the actor gives nothing (spec/permissions.md §1 Path).
// Interim (issues/stated-path-certificates.md): the writer reads its stated paths alone
pub(crate) fn check_acts(core: &Core, node: Tid, records: Records<'_>, actor: &Tid, ts: Ts) -> Result<()> {
    if node == *actor || role_with(core, node, records, actor, ts) >= Some(Role::Write) { Ok(()) } else { Err(Error::Permission { tid: *actor, needs: Role::Write }) }
}

/// Whether `tid`'s record chain, through the records not yet held, reaches a thing minted with a key
/// within `MAX_CHAIN_DEPTH` links (spec/permissions.md §1: a write deeper is invalid).
pub(crate) fn within_depth(core: &Core, records: Records<'_>, tid: &Tid) -> bool {
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
    pub purge_by: Option<PurgeBy>,
    pub expires: Option<u64>,
    /// The fire this delta replaces (spec/commits.md §5 Signals).
    pub replaces: Option<CommitId>,
    /// That fire's floor (`osis_commit::AspectEntry::original_floor`).
    pub original_floor: u64,
    /// A snapshot delta's state (`fragment` unused), frontiers, absorbed commits and facts
    /// (spec/crdt.md §8).
    pub snapshot: Option<SnapshotPart>,
    /// Chunk blobs of large values the delta introduces.
    pub chunks: Vec<osis_blob::Written>,
}

/// A snapshot delta (spec/crdt.md §8): its state, read a page at a time as it is encoded.
pub(crate) struct SnapshotPart {
    pub state: crate::retention::snapshot::SnapState,
    pub frontiers: osis_crdt::Frontiers,
    pub absorbed: std::collections::BTreeMap<osis_base::CommitId, Tid>,
    pub facts: osis_crdt::Facts,
}

/// Inputs of a commit other than its deltas.
#[derive(Clone)]
pub(crate) struct CommitPlan {
    pub kind: Kind,
    pub ts: Ts,
    pub actor: Tid,
    pub form: Form,
    pub creates: Creates,
    pub minted: Minted,
    pub purge: Vec<PurgeItem>,
    pub undoes: Option<CommitId>,
    pub frontier: Option<osis_perm::Frontier>,
    /// The thing it is signed as: the node, or a thing a key it holds holds a grant on.
    pub signer: Tid,
    /// The key it is signed by where that is not `signer`'s record's (the header names it).
    pub key: Option<osis_base::SignKey>,
    /// The header's blind (spec/crypto.md §7: the commit blob's; chunks and pages carry their
    /// own link blinds).
    pub blind: [u8; 16],
    /// The commit's expiry (spec/commits.md §6): every delta's.
    pub expires: Option<u64>,
    /// An undo's: `expires` stands, whatever its keys' defaults (`build_one`).
    pub restores: bool,
    /// The own-cover marker (`retention::snapshot::write_own_cover`).
    pub own_cover: bool,
    /// The adminless mark, where the commit needs it (`Engine::leaving_adminless`).
    pub adminless: bool,
}

/// A fresh header blind.
pub(crate) fn draw_blind(rng: &mut dyn osis_crypto::CryptoRngCore) -> [u8; 16] {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b
}

/// Purge-by and expiry of one aspect's delta in a commit of `kind` at `ts` (spec/commits.md §5,
/// §6): the given ones, else the expiry the thing's newest valid setting held gives the AK, the
/// schema's defaults, the untyped default. A replace of a fire the setting makes `final` is
/// refused.
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle(core: &Core, memory: bool, kind: Kind, ts: Ts, tid: &Tid, ak: &Ak, schema: Option<&Schema>, replaces: bool, r: Option<PurgeBy>, mut e: Option<u64>) -> Result<(PurgeBy, Option<u64>)> {
    let defaults = schema.and_then(|s| s.defaults(ak.as_str()));
    // a hostile test writer writes what it is told
    if kind == Kind::Content && !core.skip_writer_rules && !ak.ephemeral() && osis_commit::retention::fixed_purge_by(ak.as_str()).is_none()
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
    let purge_by = if memory || ak.ephemeral() {
        // `writer` (spec/commits.md §2)
        osis_commit::retention::EPHEMERAL_PURGE_BY
    } else {
        match kind {
            // a compaction snapshot's own (`Engine::snapshot`), never from schema defaults
            Kind::ContentSnapshot | Kind::RoleSnapshot => r.unwrap_or_else(|| osis_commit::retention::snapshot_purge_by(ak.as_str())),
            // a hostile test writer writes the purge-by it is told
            _ => match r.filter(|_| core.skip_writer_rules) {
                Some(r) => r,
                None => osis_commit::retention::write_purge_by(ak.as_str(), defaults.as_ref(), r)?,
            },
        }
    };
    let expires = match kind {
        Kind::Content => osis_commit::retention::write_expires(ak.as_str(), ts, defaults.as_ref(), e)?,
        // an expiring snapshot's: the expiry of the values it carries (spec/crdt.md §8)
        Kind::ContentSnapshot => e,
        _ => None,
    };
    Ok((purge_by, expires))
}

/// Blob framing of one aspect's delta in a commit of `plan` with purge-by `purge_by`
/// (spec/crypto.md §7): its thing's dedup secret, the commit's expiry, the delete keys the
/// purge-by calls for, of the class of `memory` (a memory commit's blobs are held in memory,
/// spec/wire.md §5). `published`: [`super::secrets::published_keys`] of the commit's things;
/// `keys`: the commit's [`super::secrets::KeyCache`].
pub(crate) fn framing_for(core: &Core, memory: bool, plan: &CommitPlan, published: &BTreeMap<(Tid, osis_base::Role), osis_crypto::VerifyingKey>, keys: &super::secrets::KeyCache, tid: &Tid, purge_by: &PurgeBy) -> Result<Framing> {
    // a writer knowing no step of the thing's delete base writes nothing on it, whatever the
    // delta's purge-by (spec/crypto.md §7 Header list)
    if !super::secrets::holds_listed_keys(core, &plan.creates, &plan.minted, published, keys, tid) {
        return Err(Error::Permission { tid: *tid, needs: Role::Write });
    }
    let secrets = CommitSecrets { core, purge_author: plan.actor, created: &plan.creates, minted: &plan.minted, published, keys };
    let keys = osis_commit::delete_keys(&secrets, tid, purge_by)?;
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

/// The one expiry of a commit of these deltas (`entries`: thing, AK, purge-by, expiry; spec/commits.md
/// §6), or `Clash` naming what cannot share a commit: different expiries.
/// `purge.0` takes no part in the expiry: in a commit that expires it is left out (`place_requests`).
/// `way`: what the caller can do about it.
fn one_commit(entries: &[(Tid, &Ak, &PurgeBy, Option<u64>)], way: &str) -> Result<Option<u64>> {
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
        let (r, _) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, &d.tid, &d.ak, d.schema.as_deref(), d.replaces.is_some(), d.purge_by, d.expires)?;
        let (_, e) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, &d.tid, &d.ak, None, d.replaces.is_some(), Some(r), d.expires)?;
        settled.push((r, e));
    }
    let entries: Vec<(Tid, &Ak, &PurgeBy, Option<u64>)> = deltas.iter().zip(&settled).map(|(d, (r, e))| (d.tid, &d.ak, r, *e)).collect();
    plan.expires = one_commit(&entries, "An undo is one commit, so this cannot be undone while both stand")?;
    plan.restores = true;
    for (d, (r, e)) in deltas.iter_mut().zip(settled) {
        (d.purge_by, d.expires) = (Some(r), e);
    }
    build_and_apply(tx, plan, deltas)
}

/// The writes of a compacting writer's sweep of `(tid, ak)` at stamp `r` (`Fragment::sweep`).
pub(crate) fn sweep_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, r: &osis_crdt::Stamp) -> Result<Option<Fragment>> {
    let Some(st) = crate::retention::snapshot::SnapState::stored(tx, tid, ak, crate::retention::snapshot::Carries::AllBut(Vec::new()))? else { return Ok(None) };
    let core = &*tx.core;
    let reflected = |d: &osis_crdt::Dot| crate::apply::copies::reflected(core, tid, ak, d);
    let out = st.walk(&mut tx.txn, tid, ak, |p| osis_crdt::sweep_paged(p, r, &reflected))?;
    // debug builds: the sweep read a page at a time is the whole state's
    #[cfg(debug_assertions)]
    if let Some(idx) = &st.pages {
        osis_base::costs::paused(|| -> Result<()> {
            let mut whole = tx.cached(tid, ak).cloned().unwrap_or_default();
            super::pages::load_all(&mut tx.txn, tid, ak, &mut idx.clone(), &mut whole)?;
            let core = &*tx.core;
            assert_eq!(out, whole.sweep(r, &|d| crate::apply::copies::reflected(core, tid, ak, d)), "a sweep read a page at a time is the whole state's");
            Ok(())
        })?;
    }
    Ok(out)
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
    let built = build(tx, plan, deltas)?;
    let id = built.commit.id();
    // rights are checked before anything leaves the node: a request dropping nothing is refused
    if !tx.core.skip_writer_rules {
        crate::retention::check_request(tx.core, &built.commit.header, &id)?;
    }
    // hostile test authors: the blob as sent, whatever this node's own copy drops of it
    if !tx.core.forge_bad.is_empty() || tx.core.skip_writer_rules {
        tx.core.forged.insert(id, built.commit.encode());
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
    let published = super::secrets::published_keys(tx, &plan.creates, &plan.minted, deltas.iter().map(|d| d.tid))?;
    let keys = super::secrets::KeyCache::default();
    // the mark goes only on a commit that needs it: one marking nothing it leaves would say
    // more than its author meant
    let adminless = plan.adminless && crate::apply::validity::needs_adminless_mark(tx.core, deltas.iter().map(|d| (d.tid, &d.ak, &d.fragment)));
    let edges = if plan.kind == Kind::Role { crate::apply::validity::edge_writes(tx.core, deltas.iter().map(|d| (d.tid, &d.ak, &d.fragment))) } else { Vec::new() };
    let mut writes = Vec::with_capacity(deltas.len());
    for d in deltas {
        let (purge_by, expires) = settle(tx.core, tx.txn.is_memory(), plan.kind, plan.ts, &d.tid, &d.ak, d.schema.as_deref(), d.replaces.is_some(), d.purge_by, d.expires)?;
        // one expiry per commit (spec/commits.md §6): `one_commit` saw to it
        if expires != plan.expires && !plan.restores {
            return Err(Error::Misuse("a commit's deltas share one expiry"));
        }
        let framing = framing_for(tx.core, tx.txn.is_memory(), &plan, &published, &keys, &d.tid, &purge_by)?;
        let cx = writer_ctx(plan.form, plan.kind, plan.ts, node, d.lo, d.hi);
        #[cfg(debug_assertions)]
        if let Some(s) = &d.snapshot {
            osis_base::costs::paused(|| s.state.check_whole(tx, &d.tid, &d.ak, s, &cx))?;
        }
        let mut blobs = TxBlobs::new(&mut tx.blobs, tx.txn.is_memory());
        let mut nonce = [0u8; osis_crdt::NONCE_LEN];
        tx.rng.fill_bytes(&mut nonce);
        let mut bw = BlobWriter::new(&framing, &mut blobs, &mut *tx.rng);
        let bytes = match &d.snapshot {
            Some(s) => s.state.walk(&mut tx.txn, &d.tid, &d.ak, |st| osis_crdt::encode_paged_snapshot(&nonce, st, &s.frontiers, &s.absorbed, &s.facts, &cx, Some(&mut bw)))?,
            None => encode_delta(&Delta { nonce, fragment: d.fragment }, &cx, Some(&mut bw))?,
        };
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
        writes.push(AspectWrite { tid: d.tid, ak: d.ak, lo: d.lo, hi: d.hi, delta: bytes, purge_by, replaces: d.replaces, original_floor: d.original_floor });
    }
    let stated = stated_paths(tx.core, &plan, &writes, &edges)?;
    let mut b = CommitBuilder::new(plan.kind, plan.ts, node, osis_commit::Path::default(), plan.form);
    match stated {
        Stated::One(p) => {
            b.path = p;
        }
        Stated::Split(author, paths) => {
            let things = paths.into_iter().map(|(t, listed)| (t, (listed, path_secret(tx.core, &plan, &t, &mut *tx.rng)))).collect();
            b.split = Some(osis_commit::SplitWrite { author, things });
        }
    }
    b.expires = plan.expires;
    b.aspects = writes;
    b.purge = plan.purge;
    b.undoes = plan.undoes;
    b.frontier = plan.frontier.map(|f| f.ids());
    b.blind = Some(plan.blind);
    b.own_cover = plan.own_cover;
    b.adminless = adminless;
    // a commit built in a memory transaction is a memory commit (spec/commits.md §2, §3)
    b.ephemeral = tx.txn.is_memory().then_some(osis_commit::EphClass::Plain);
    let built = {
        let core: &Core = tx.core;
        let secrets = CommitSecrets { core, purge_author: plan.actor, created: &plan.creates, minted: &plan.minted, published: &published, keys: &keys };
        let mut seed = [0u8; 32];
        tx.rng.fill_bytes(&mut seed);
        let mut list_rng = osis_crypto::SeededRng::from_seed(seed);
        let mut sink = ListBlobs { blobs: TxBlobs::new(&mut tx.blobs, tx.txn.is_memory()), rng: &mut list_rng };
        // the key the plan was made for: the one `key_for` gives (its named key the header's)
        let signing = match core.key_for(&node) {
            Some((s, k)) if k == plan.key => s,
            _ => return Err(Error::Misuse("no key held with a grant on the signer")),
        };
        b.name_key = plan.key.is_some();
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
    /// Tests: a new thing whose mint admin is `admin`, created by `m` (spec/data-model.md §1) and
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

    /// Tests: the record of a new thing minted with admin `admin`, its holding strong (`hold_where_it_lives`)
    /// committed first, so the commit that makes it can carry its creation alone.
    #[doc(hidden)]
    pub fn held_record(&mut self, admin: Tid) -> Result<CreationRecord> {
        let rec = self.thing_record(admin, None);
        let mut m = Mutation::new();
        self.hold_where_it_lives(&mut m, rec.tid(), admin);
        self.commit(m)?;
        Ok(rec)
    }

    /// Tests: writes in `m` the strong that holds `t`, minted with admin `admin` (spec/sync-set.md §2
    /// Making a thing): from `admin` where that is a thing `m` makes or the node holds, else from
    /// the node root, as for the node thing (its sync unit is itself alone, spec/sync-set.md §1).
    #[doc(hidden)]
    #[allow(clippy::expect_used)] // tests: an op on a static core aspect
    pub fn hold_where_it_lives(&self, m: &mut Mutation, t: Tid, admin: Tid) {
        let holder = if admin != self.core.me() && (m.creates.contains_key(&admin) || self.closure_holds(&admin)) {
            Some(admin)
        } else {
            self.core.node_root
        };
        if let Some(h) = holder {
            m.op(h, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(t)) }).expect("holds.0 takes a strong");
        }
    }

    /// The creation record of a new thing whose mint admin is `admin`, ending at `expires`
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

/// Commits `m` in `tx` as one commit (`one_commit`); none when it changes nothing.
pub(crate) fn commit_in(tx: &mut Tx<'_>, m: Mutation) -> Result<Option<CommitId>> {
    if m.sealed {
        return Err(Error::Misuse("a sealed fire is built by `sealed_commit`"));
    }
    Ok(commit_or_build(tx, m)?.map(|(id, _)| id))
}

/// The commit of sealed fire mutation `m` (one fire of an external signal on a thing this node need
/// not hold, spec/sync-inbox.md §2), built and signed, never applied here: the sender holds no
/// setting of the thing and is bound by none (spec/commits.md §5 The setting).
pub(crate) fn sealed_commit(tx: &mut Tx<'_>, mut m: Mutation) -> Result<osis_commit::CommitBlob> {
    m.sealed = true;
    let one = matches!(m.aspects.keys().collect::<Vec<_>>().as_slice(), [(_, ak)] if ak.external());
    if !one || !m.creates.is_empty() || !m.purge.is_empty() || !m.purge_named.is_empty() || m.undoes.is_some() || tx.txn.is_memory() {
        return Err(Error::Misuse("a sealed fire is one fire of an external signal"));
    }
    commit_or_build(tx, m)?.and_then(|(_, b)| b).ok_or(Error::Misuse("a sealed fire writes nothing"))
}

/// `commit_in`, or for a sealed mutation the built commit, unapplied.
pub(crate) fn commit_or_build(tx: &mut Tx<'_>, mut m: Mutation) -> Result<Option<(CommitId, Option<osis_commit::CommitBlob>)>> {
    let sealed = m.sealed;
    let (node, key) = match m.signer {
        Some(s) => (s, tx.core.key_for(&s).ok_or(Error::Misuse("no key held with a grant on the signer"))?.1),
        None => (tx.core.me(), None),
    };
    if m.undoes.is_some() && !(m.creates.is_empty() && m.aspects.is_empty() && m.purge.is_empty() && m.purge_named.is_empty() && m.frontier.is_none()) {
        return Err(Error::Misuse("an undo mutation carries no other ops"));
    }
    let core_schema = Arc::new(osis_schema::core_schema().clone());
    let memory = tx.txn.is_memory();
    // minted once: a record held ahead of its minting is the one the rotation making it
    // independent carries (`rotation::own_secrets_new`)
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
    // a node writes only what it holds (spec/sync-set.md §2 Writing, Making a thing): every thing
    // the commit makes, and every thing it writes not held as it writes, must be held at the
    // transaction's end; a thing made with its role entries alone may be held as a holder
    // (`Written::Holder`); a sealed fire is built, never applied.
    if !sealed {
        let role_only = |t: &Tid| m.aspects.keys().filter(|(x, _)| x == t).all(|(_, ak)| ak.as_str() == CREATED.ak() || is_role_class(ak.as_str()));
        let made = m.creates.keys().map(|t| if role_only(t) { Written::Holder(*t) } else { Written::Held(*t) });
        let unheld = m.aspects.keys().map(|(t, _)| *t).filter(|t| !m.creates.contains_key(t) && !tx.core.ix.closure.holds(t)).map(Written::Held);
        let written: Vec<Written> = made.chain(unheld).collect();
        tx.core.wrote_on.extend(written);
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
    // under `Engine::leaving_adminless`, an edge write may carry the adminless mark (`build`)
    let adminless = tx.core.leave_adminless && kind == Kind::Role && m.aspects.keys().any(|(_, ak)| crate::apply::validity::edge_ak(ak.as_str()));
    let base = CommitPlan { kind, ts, actor: m.actor.unwrap_or(node), form: Form::Commit, creates: std::mem::take(&mut m.creates), minted: std::mem::take(&mut m.minted), purge: std::mem::take(&mut m.purge), undoes: None, frontier: m.frontier.take(), signer: node, key, blind: m.blind.unwrap_or_else(|| draw_blind(&mut *tx.rng)), expires: None, restores: false, own_cover: false, adminless };
    if !m.unchecked {
        check_acts(tx.core, node, &|t| base.creates.get(t), &base.actor, ts)?;
    }
    let mut aspects = Vec::with_capacity(m.aspects.len());
    for ((tid, ak), mut am) in std::mem::take(&mut m.aspects) {
        // a sealed fire's thing: known by its public key record alone
        if !base.creates.contains_key(&tid) && !(if sealed { tx.core.created(&tid).is_some() } else { tx.core.writable(&tid) }) {
            return Err(Error::UnknownThing(tid));
        }
        // a sealed fire's sender holds no setting of the thing and is bound by none: its
        // readers judge it (spec/sync-inbox.md §2)
        if !m.unchecked && !sealed {
            check_authority(tx.core, node, &|t| base.creates.get(t), &tid, ak.as_str(), ts)?;
        }
        // a content write is written under the setting: one known and not held yet is waited
        // for, never read as none (`secrets::usable_role`, spec/commits.md §5 The setting)
        if kind == Kind::Content && !sealed && super::secrets::awaits_setting(tx.core, &tid) {
            return Err(Error::Permission { tid, needs: Role::Write });
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
            settle(tx.core, memory, kind, ts, &tid, &ak, am.schema.as_deref(), am.replaces.is_some(), am.purge_by, am.expires)?
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
                return Err(Error::Misuse(FIRE_IN_NO_HISTORY));
            }
        }
        // a role commit never expires, so it creates no expiring thing
        if ak.as_str() == CREATED.ak() && !tx.core.skip_writer_rules && let Some(want) = base.creates.get(&tid).map(CreationRecord::expires)
            && e != want
        {
            return Err(Error::Clash(format!("{tid} expires, and a commit of roles does not: create it in a write of its own")));
        }
        (am.purge_by, am.expires) = (Some(r), e);
        aspects.push(((tid, ak), am));
    }
    let entries: Vec<(Tid, &Ak, &PurgeBy, Option<u64>)> = aspects.iter().filter_map(|((t, ak), am)| Some((*t, ak, am.purge_by.as_ref()?, am.expires))).collect();
    let expires = one_commit(&entries, "Write them as separate commits")?;
    place_requests(&mut aspects, expires);
    // role commits use commit form: a later commit by the same node can never void them by
    // reusing their counters; content commits write under this open's session unless asked
    // for commit form (spec/commits.md §3); expiring memory writes under its second session
    // (`Core::expiring`)
    let mut plan = base;
    plan.expires = expires;
    plan.form = if kind != Kind::Content || m.commit_form || plan.signer != tx.core.id.tid() { Form::Commit } else { Form::Session(tx.core.nonce_as(&plan.signer, if memory && expires.is_some() { tx.core.expiring.nonce } else { tx.core.session.nonce })) };
    let form = plan.form;
    let mut next_ctr = 1u64;
    let mut deltas: Vec<Resolved> = Vec::new();
    let published = super::secrets::published_keys(tx, &plan.creates, &plan.minted, aspects.iter().map(|k| k.0.0))?;
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
        let purge_by = am.purge_by.unwrap_or_default();
        let framing = match kind {
            Kind::Content => Some(framing_for(tx.core, memory, &plan, &published, &keys, &tid, &purge_by)?),
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
        let lo = match form {
            Form::Commit => next_ctr,
            // a session's counters: memory rows, gone with the session
            Form::Session(n) => tx.txn.counter(&tid, &ak, &n)?,
        };
        let attached = tx.load_for_ops(&tid, &ak, paths, &am.ops, &edits, &osis_crdt::Dot::new(own_source(form, node), lo))?;
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
        let r = Resolved { tid, ak, fragment, lo: range.lo, hi: range.hi, schema: am.schema, purge_by: am.purge_by, expires: am.expires, replaces: am.replaces, original_floor: am.original_floor, snapshot: None, chunks };
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
            out.push(osis_crdt::DotRange { first: osis_crdt::Dot::new(m.view.form.own_source(m.view.signer, c), a.lo), hi: a.hi });
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
