//! Actors, entitlement and closure (spec/sync-ids.md §2, spec/sync-judgement.md §1, spec/sync-set.md §2): a thing's independent (the thing if it
//! is independent, else its mint admin's), who may read it, and the sync IDs of an independent
//! thing (`sync.0`).

use osis_base::memo::{Memo, Stamped};
use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{ChainStep, SyncId, Role, Tid};
use crate::sync::{OwnedSyncId, Path};
use osis_crypto::{RoleKey, role_key};
use osis_blob::{ClaimSet, Step, StepId};
use osis_schema::core_types as ct;
use crate::identity::Identity;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Whether sync ID `id`, its steps as `steps` records them, belongs to the thing whose epochs held
/// here are `epochs` (spec/sync-ids.md §4 Owner; `Core::owns_sync_id`).
///
/// Invariant: an entry of g's `sync.0` counts as g's sync ID, on every path that reads it, only
/// when some step on a verified path from the sync ID's genesis step bears a sync key that a sync
/// secret of g held here derives. Any admin of g writes g's `sync.0` and may name any sync ID
/// there; the steps chain by signature to the genesis delete key, which the sync ID commits to and
/// only the owner's admins held, so a step bearing g's sync key is an owner admin's own word that g
/// owns it. An entry failing this is ignored here, never judged invalid: the check turns on the
/// secrets this node holds. While this node holds no sync secret of g's own (it reads g by derived
/// secrets, which no step bears) the entries are hints (`OwnedSyncId::hint`).
pub(crate) fn owns(held: &BTreeSet<[u8; 32]>, id: &SyncId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
    // the genesis first (every holder holds the older secrets, so usually it bears one): one
    // step verified; else the tree verified once (`verified_depths`), not a path per bearing step
    let (genesis, deeper): (Vec<(&StepId, &Step)>, Vec<_>) = steps.iter().map(|(k, (s, _))| (k, s)).filter(|(_, s)| held.contains(&s.keys.sync.to_bytes())).partition(|(_, s)| s.prev.is_none());
    if genesis.iter().any(|(k, s)| s.id() == **k && s.sync_id == *id && s.verify_genesis().is_ok()) {
        return true;
    }
    if deeper.is_empty() {
        return false;
    }
    let depth = verified_depths(steps);
    deeper.iter().any(|(k, s)| s.sync_id == *id && depth.contains_key(k))
}

/// The recorded path of a sync ID from its steps (spec/sync-ids.md §5 Path): genesis to head, the
/// head being the newest recorded step (`head_of`). `None` when no step's path verifies.
pub(crate) fn recorded_path(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<Path> {
    let head = head_of(steps)?;
    let mut path = Vec::new();
    let mut at = Some(head);
    while let Some((s, c)) = at.and_then(|id| steps.get(&id)) {
        path.push((s.clone(), c.clone()));
        at = s.prev;
    }
    path.reverse();
    Some(Path { steps: path })
}

/// The head a node reading S takes from its `sync.0` (spec/sync-ids.md §3 "the newest step its
/// `sync.0` records"): of the tips whose path from genesis verifies, the deepest; ties (two admins
/// stepping at once) by lowest step ID. The spec names no order for a forked tree: this is its
/// simplest reading.
pub(crate) fn head_of(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<StepId> {
    head_at(steps).map(|(k, _)| k)
}

/// `head_of` with its depth (its path's steps after the genesis).
pub(crate) fn head_at(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<(StepId, usize)> {
    let parents: BTreeSet<StepId> = steps.values().filter_map(|(s, _)| s.prev).collect();
    let depth = verified_depths(steps);
    steps.keys().filter(|k| !parents.contains(k)).filter_map(|k| Some((*k, *depth.get(k)?))).min_by_key(|(k, n)| (std::cmp::Reverse(*n), *k))
}

/// The depth of each step whose path from its genesis step verifies (`osis_blob::verify_path`:
/// each step under its own ID, the genesis by its own delete key, each child by its parent's),
/// each signature checked once, from the genesis steps down.
pub(crate) fn verified_depths(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> BTreeMap<StepId, usize> {
    let mut children: BTreeMap<StepId, Vec<StepId>> = BTreeMap::new();
    let mut todo: Vec<(StepId, usize)> = Vec::new();
    for (id, (s, _)) in steps {
        if s.id() != *id {
            continue;
        }
        match s.prev {
            Some(p) => children.entry(p).or_default().push(*id),
            None if s.verify_genesis().is_ok() => todo.push((*id, 0)),
            None => {}
        }
    }
    let mut out = BTreeMap::new();
    while let Some((id, d)) = todo.pop() {
        out.insert(id, d);
        let Some((parent, _)) = steps.get(&id) else { continue };
        for c in children.remove(&id).unwrap_or_default() {
            if steps.get(&c).is_some_and(|(s, _)| s.verify_child(parent).is_ok()) {
                todo.push((c, d + 1));
            }
        }
    }
    out
}

/// The delete keys owing an endorsement of S's recorded head (spec/sync-ids.md §6 Steps): each
/// key some step off the recorded path bears, that step shallower than the head and its fork (its
/// deepest ancestor on the recorded path) bearing another key, while no recorded-path step deeper
/// than every such step of that key carries an endorsement by it. A store on such a step takes no
/// branch of the recorded path but by one (§6 Register).
pub(crate) fn endorsements_owed(o: &OwnedSyncId) -> BTreeSet<[u8; 32]> {
    let at: BTreeMap<StepId, usize> = o.path.steps.iter().enumerate().map(|(i, (st, _))| (st.id(), i)).collect();
    // per off-path step: its fork's index and its depth, filled down each branch once
    let mut placed: BTreeMap<StepId, (usize, usize)> = BTreeMap::new();
    let mut deepest: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    for (id, x) in o.tree.iter() {
        if at.contains_key(id) {
            continue;
        }
        let mut chain = vec![(*id, x)];
        let base = loop {
            let Some((_, cur)) = chain.last() else { break None };
            let Some(prev) = cur.prev.filter(|_| chain.len() <= o.tree.len()) else { break None };
            if let Some(j) = at.get(&prev) {
                break Some((*j, j + 1));
            }
            if let Some(p) = placed.get(&prev) {
                break Some(*p);
            }
            let Some(next) = o.tree.get(&prev) else { break None };
            chain.push((prev, next));
        };
        let Some((fork, mut depth)) = base else { continue };
        for (cid, _) in chain.iter().rev() {
            depth += 1;
            placed.insert(*cid, (fork, depth));
        }
        let Some(&(fork, depth)) = placed.get(id) else { continue };
        let Some((f, _)) = o.path.steps.get(fork) else { continue };
        if depth < o.path.steps.len() && f.keys.delete != x.keys.delete {
            let d = deepest.entry(x.keys.delete.to_bytes()).or_default();
            *d = (*d).max(depth);
        }
    }
    deepest
        .into_iter()
        .filter(|(d, depth)| !o.path.steps.iter().skip(*depth).any(|(st, _)| o.endorsed.get(&st.id()).is_some_and(|e| e.contains_key(d))))
        .map(|(d, _)| d)
        .collect()
}

/// The sync IDs decoded `sync.0` `m` of `g` records that `g` owns here (`Core::owns_sync_id`),
/// each with its recorded path; records that do not parse are skipped.
pub(crate) fn owned_in(core: &Core, g: &Tid, m: &ct::SyncIds) -> Vec<OwnedSyncId> {
    recorded_in(core, g, m, false)
}

/// `owned_in`, or with `any` every sync ID `m` records, judged or not, as hints.
fn recorded_in(core: &Core, g: &Tid, m: &ct::SyncIds, any: bool) -> Vec<OwnedSyncId> {
    let hint = any || !core.holds_own_sync(g);
    m.iter()
        .filter_map(|(id, l)| {
            let steps = osis_blob::sync_steps(l).ok()?;
            if !any && !core.owns_sync_id(g, id, &steps) {
                return None;
            }
            let tree = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
            let endorsed = Arc::new(osis_blob::sync_endorsements(l, &steps));
            Some(OwnedSyncId { id: *id, path: Arc::new(recorded_path(&steps)?), tree: Arc::new(tree), endorsed, hint })
        })
        .collect()
}

impl Core {
    /// Whether this node holds a sync secret of `g`'s own (`owns` judges `g`'s `sync.0` by it;
    /// without one its entries are hints).
    pub(crate) fn holds_own_sync(&self, g: &Tid) -> bool {
        self.own_record(g).is_some_and(|e| e.sync.holds_any()) || self.unread(g).holds_any()
    }

    /// Whether `g` owns sync ID `id` here (`owns`): judged once this node holds a sync secret of
    /// `g`'s own, else taken as a hint.
    pub(crate) fn owns_sync_id(&self, g: &Tid, id: &SyncId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
        !self.holds_own_sync(g) || owns(&self.held_sync_keys(g), id, steps)
    }

    /// The sync keys (spec/sync-ids.md §3) of the sync secrets of `g` held here, reading-only
    /// ones included (`memo`: a key derivation per secret, asked at every write listing a step).
    pub(crate) fn held_sync_keys(&self, g: &Tid) -> Arc<BTreeSet<[u8; 32]>> {
        self.held_sync_keys.get(g, || {
            let e = self.epochs(g);
            let mut out: BTreeSet<[u8; 32]> = e.iter().flat_map(|e| e.sync.held_newest_first()).map(|(_, s)| role_key(RoleKey::Sync, s).verifying_key().to_bytes()).collect();
            // kept unread: the sync secrets a step bears (`sync_ids::unread`)
            out.extend(self.unread(g).secrets.values().map(crate::sync_ids::unread::sync_key));
            Arc::new(out)
        })
    }

    /// The independent of `t`, whose read role reads its deltas: `t` if independent,
    /// else the nearest record-chain thing that has them (one minted with a key is its own).
    pub fn reader_of(&self, t: &Tid) -> Tid {
        // the actor whose secrets `t`'s derive from, up the record chain
        self.secret_actor(t).unwrap_or(*t)
    }

    /// The thing whose secrets `t`'s derive from: up the record chain to a thing with secrets of
    /// its own, one minted with a key at the latest (independent from its minting).
    pub fn secret_actor(&self, t: &Tid) -> Option<Tid> {
        for step in self.record_chain(t) {
            let cur = step.thing()?;
            // independent by its role commits or by a box of its own a step bears (`counts_independent`:
            // an edge piece carries no rotation that made a granted epoch current)
            if self.counts_independent(&cur) {
                return Some(cur);
            }
            match step {
                ChainStep::Up { .. } => {}
                ChainStep::Key(k) => return Some(k),
                _ => return None,
            }
        }
        None
    }

    /// Actor `x`'s role on actor `a` now as far as grants with key access give it (spec/crypto.md
    /// §4 Holds, Key access, Destroyed: a keyless grant, one closing a cycle of actor grants, and
    /// a destroyed thing read nothing through them): what gives, takes and opens `a`'s secrets.
    /// Read on the memo clock (`role_now`).
    pub(crate) fn keyed_role_now(&self, x: &Tid, a: &Tid) -> Option<Role> {
        let role = self.role_now(x, a);
        if role.is_none() || crate::rotation::members::key_skip(self).is_empty() {
            return role;
        }
        role.min(crate::rotation::members::role_for_keys(self, x, a))
    }

    /// Whether actor `x` reads actor `a` now (`keyed_role_now`).
    pub(crate) fn reads_now(&self, x: &Tid, a: &Tid) -> bool {
        self.keyed_role_now(x, a) >= Some(Role::Read)
    }

    /// Whether actor `x` may read thing `t` now: `t`'s secrets derive from `x`'s, or `x` holds
    /// read or above on the actor they derive from (spec/sync-judgement.md §1, entitlement),
    /// through grants with key access (`reads_now`), or the public reads it by its own grant
    /// there (`public_reads`). An actor up the record chain of an independent thing reads it only
    /// by its role there: a record edge lowered or removed takes that role (spec/permissions.md §1).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        let Some(a) = self.secret_actor(t) else { return false };
        a == *x || self.reads_now(x, &a) || self.public_reads(&a)
    }
}

impl Engine {
    /// The keyless actor grants held here, each (target, holder) (spec/crypto.md §4 Key access):
    /// for tests modelling what reads through grants.
    #[doc(hidden)]
    pub fn keyless_grants(&self) -> BTreeSet<(Tid, Tid)> {
        (*self.core.timelines().keyless()).clone()
    }

    /// Things with a `sync.0` state.
    pub fn things_with_sync_ids(&self) -> Vec<Tid> {
        self.core.ix.sync_recorded.iter().copied().collect()
    }

    /// The sync IDs `g` owns as its `sync.0` records them (`owns`), each with its recorded path;
    /// hints while this node holds no sync secret of `g`'s own (`held_sync_ids`). Decoded once
    /// per write of the `sync.0` or of what its copies carry (`Core::sync_ids`), a destroyed
    /// thing's too. A `sync.0` the store refuses to read is the error, read again at the next ask.
    pub(crate) fn owned_sync_ids(&mut self, g: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        Memo::get_in(self, |e| &e.core.sync_ids, g, |e| {
            // none of `g`'s admins' word held (spec/sync-ids.md §2: a sync holder learns none):
            // the steps its sync copies carry alone (`Core::copies_speak`)
            if e.core.copies_speak(g) {
                return Ok(Arc::new(held_sync_ids(&e.core, g, &e.core.unread(g).steps)));
            }
            use osis_schema::RawKey;
            // a destroyed thing's too: its `sync.0` stays (`retention::destroy`), read past `exists`
            let ak = crate::flows::ak(ct::SYNC.ak())?;
            let v = e.read(|tx| Ok(tx.state(g, &ak)?.and_then(osis_crdt::Fragment::read)))?;
            // the state alone: a sync copy's steps speak for `g` only beside none of its admins'
            // word (`Core::copies_speak`)
            let m = match v {
                Some(v) => ct::SYNC.decode(&v)?,
                None => Default::default(),
            };
            Ok::<_, crate::error::Error>(Arc::new(held_sync_ids(&e.core, g, &m)))
        })
    }
}

/// The sync IDs this node holds for `g`, its `sync.0` recording `m`: those `m` records that `g`
/// owns here (`owned_in`), else a followed link's (`followed`), else, `g` followed by the public
/// entry (spec/sync-set.md §2), each `m` records as hints: the secrets its entry box gave bear
/// the newest steps, which the recorded `sync.0` reaches only once the pass brings them.
pub(crate) fn held_sync_ids(core: &Core, g: &Tid, m: &ct::SyncIds) -> Vec<OwnedSyncId> {
    let out = owned_in(core, g, m);
    if !out.is_empty() {
        return out;
    }
    if let Some(h) = followed(core, g) {
        return vec![h];
    }
    match core.ix.closure.follows_public(g) {
        true => recorded_in(core, g, m, true),
        false => Vec::new(),
    }
}

/// The links this node redeems (`Engine::follow_link`, `follow_public`): a share link's K, or a
/// public link's target, to its sync ID from the link text and a share link's key L, read per key
/// three ways (by K; by L, an author this node writes as; by sync ID), so a reader asking about
/// one link, actor or sync ID moves only when that one does, not at every link followed or let
/// go. Each key L is kept exactly while some followed link names it, so it goes with the last link
/// naming it (`Engine::settle_link_key`). In memory only (`Core::followed_links`).
#[derive(Clone, Default)]
pub(crate) struct FollowedLinks {
    /// Per link K (a public link: its target), its sync ID and key (a public link: none).
    by_k: Stamped<Tid, (SyncId, Option<Tid>)>,
    /// Per link key L, the links K it is the key of.
    by_actor: Stamped<Tid, BTreeSet<Tid>>,
    /// Per link key L, its identity from the seed: kept exactly while `by_actor` names L.
    keys: BTreeMap<Tid, Arc<Identity>>,
    /// Per sync ID, the links K whose text names it.
    by_sync: Stamped<SyncId, BTreeSet<Tid>>,
}

impl FollowedLinks {
    /// Link `k`'s sync ID and key (none: a public link), read per K.
    pub(crate) fn get(&self, k: &Tid) -> Option<(SyncId, Option<Tid>)> {
        self.by_k.get(k).copied()
    }

    pub(crate) fn contains(&self, k: &Tid) -> bool {
        self.by_k.contains_key(k)
    }

    /// A cursor over the links followed from now on, each as it is followed (`Feed`).
    pub(crate) fn followed_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.by_k.feed()
    }

    /// Every link followed: a read of all of them.
    pub(crate) fn all(&self) -> &BTreeMap<Tid, (SyncId, Option<Tid>)> {
        &self.by_k
    }

    /// Whether `a` is the key of a link followed, read per actor.
    pub(crate) fn is_key(&self, a: &Tid) -> bool {
        self.by_actor.contains_key(a)
    }

    /// Link key `l` while a followed link names it.
    pub(crate) fn key(&self, l: &Tid) -> Option<&Arc<Identity>> {
        self.keys.get(l)
    }

    /// The links whose text names sync ID `s`, read per sync ID.
    pub(crate) fn naming(&self, s: &SyncId) -> BTreeSet<Tid> {
        self.by_sync.get(s).cloned().unwrap_or_default()
    }

    /// Follows link `k` under sync ID `s` and key `l` (none: a public link); the same again moves
    /// nothing. Returns the key `k` was followed under before, if any.
    pub(crate) fn insert(&mut self, k: Tid, s: SyncId, l: Option<Arc<Identity>>) -> Option<Tid> {
        let lt = l.as_ref().map(|l| l.tid());
        if self.by_k.get(&k) == Some(&(s, lt)) {
            return None;
        }
        let old = self.remove(&k);
        self.by_k.update_fed(k, |_| Some((s, lt)));
        if let Some(l) = l {
            Self::add(&mut self.by_actor, l.tid(), k);
            self.keys.insert(l.tid(), l);
        }
        Self::add(&mut self.by_sync, s, k);
        old
    }

    /// Lets link `k` go: its key, if it was followed with one (gone here with the last link naming
    /// it).
    pub(crate) fn remove(&mut self, k: &Tid) -> Option<Tid> {
        let (s, l) = self.by_k.remove(k)?;
        Self::take(&mut self.by_sync, &s, k);
        let l = l?;
        Self::take(&mut self.by_actor, &l, k);
        if !self.by_actor.contains_key(&l) {
            self.keys.remove(&l);
        }
        Some(l)
    }

    fn add<K: Ord + std::hash::Hash + Clone>(m: &mut Stamped<K, BTreeSet<Tid>>, at: K, k: Tid) {
        let mut ks = m.get(&at).cloned().unwrap_or_default();
        ks.insert(k);
        m.insert(at, ks);
    }

    fn take<K: Ord + std::hash::Hash + Clone>(m: &mut Stamped<K, BTreeSet<Tid>>, at: &K, k: &Tid) {
        let mut ks = m.get(at).cloned().unwrap_or_default();
        ks.remove(k);
        match ks.is_empty() {
            true => drop(m.remove(at)),
            false => drop(m.insert(at.clone(), ks)),
        }
    }
}

/// A link being redeemed (`Engine::follow_link`): K's sync ID from its link text, followed with no
/// recorded path while the link text is all this node has of it (spec/sync-set.md §2). The link
/// text is untrusted: its K must be a link's K or unknown here (`followable`), and its sync ID no
/// other thing's here (no applied `sync.0` records it, no other followed link names it), else it
/// is nobody's.
fn followed(core: &Core, k: &Tid) -> Option<OwnedSyncId> {
    let (s, _) = core.followed_links.get(k)?;
    let ix = &core.ix;
    let elsewhere = ix.sync_recorders.get(&s).is_some_and(|x| x.iter().any(|t| t != k))
        || core.followed_links.naming(&s).iter().any(|t| t != k);
    (followable(core, k) && !elsewhere).then(|| OwnedSyncId { id: s, path: Arc::new(crate::sync::Path::default()), tree: Arc::default(), endorsed: Arc::default(), hint: true })
}

/// Whether followed link `k` may be a link's K here: a thing this node holds only as a link's K
/// (its creation record has the `link` field), or one it knows nothing of yet (no record). A link text naming any other thing as K changes nothing of it.
/// A public link's target may be any thing: its sync ID counts only where no held `sync.0` of the
/// target's records one (`held_sync_ids`) and no other's records it (`followed`).
pub(crate) fn followable(core: &Core, k: &Tid) -> bool {
    match core.followed_links.get(k) {
        None => false,
        Some((_, None)) => true,
        Some((_, Some(_))) => core.created(k).is_none_or(|r| r.link_target().is_some()),
    }
}
