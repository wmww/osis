//! Actors, entitlement and closure (spec/sync-ids.md §2, spec/sync-judgement.md §1, spec/sync-set.md §2): a thing's reader actor (the thing if it
//! has secrets of its own, else its first admin), who may read it, and the sync IDs of a thing with
//! own keys (`sync.0`).

use osis_base::memo::{Memo, Stamped};
use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{ChainStep, SyncId, Role, Tid};
use crate::sync::{OwnedSyncId, Path};
use osis_crypto::{RoleKey, role_key};
use osis_keys::ActorEpochs;
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
pub(crate) fn owns(epochs: Option<&ActorEpochs>, id: &SyncId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
    let Some(e) = epochs else { return false };
    let held: BTreeSet<[u8; 32]> = e.sync.held_newest_first().into_iter().map(|(_, s)| role_key(RoleKey::Sync, s).verifying_key().to_bytes()).collect();
    // the genesis first (every holder holds the older secrets, so usually it bears one): one
    // step verified, not a path per bearing step
    let mut bearing: Vec<(bool, &StepId)> = steps.iter().filter(|(_, (s, _))| held.contains(&s.keys.sync.to_bytes())).map(|(k, (s, _))| (s.prev.is_some(), k)).collect();
    if bearing.is_empty() {
        return false;
    }
    bearing.sort();
    let plain: BTreeMap<StepId, Step> = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
    bearing.into_iter().any(|(_, k)| osis_blob::path_to(&plain, k).is_ok_and(|p| p.first().is_some_and(|g| g.sync_id == *id)))
}

/// The recorded path of a sync ID from its steps (spec/sync-ids.md §5 Path): genesis to head, the
/// head being the newest recorded step (`head_of`). `None` when no step's path verifies.
pub(crate) fn recorded_path(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<Path> {
    let head = head_of(steps)?;
    let plain: BTreeMap<StepId, Step> = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
    let path = osis_blob::path_to(&plain, &head).ok()?;
    Some(Path { steps: path.into_iter().map(|s| { let c = steps.get(&s.id()).and_then(|(_, c)| c.clone()); (s, c) }).collect() })
}

/// The head a node reading S takes from its `sync.0` (spec/sync-ids.md §3 "the newest step its
/// `sync.0` records"): of the tips whose path from genesis verifies, the deepest; ties (two admins
/// stepping at once) by lowest step ID. The spec names no order for a forked tree: this is its
/// simplest reading.
pub(crate) fn head_of(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<StepId> {
    let parents: BTreeSet<StepId> = steps.values().filter_map(|(s, _)| s.prev).collect();
    let plain: BTreeMap<StepId, Step> = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
    steps.keys().filter(|k| !parents.contains(k)).filter_map(|k| Some((osis_blob::path_to(&plain, k).ok()?.len(), *k))).min_by_key(|(n, k)| (std::cmp::Reverse(*n), *k)).map(|(_, k)| k)
}

/// The sync IDs a destroyed thing `g`'s kept `sync.0` value `v` records that `g` owns here
/// (`Core::owns_sync_id`), each with its recorded path; records that do not parse are skipped.
/// A destroyed thing's are its own, never hints: `hint` is false.
pub(crate) fn owned_in_value(core: &Core, g: &Tid, v: &osis_base::Value) -> Vec<OwnedSyncId> {
    use osis_schema::RawKey;
    let mut out = ct::SYNC.decode(v).map(|m| owned_in(core, g, &m)).unwrap_or_default();
    for o in &mut out {
        o.hint = false;
    }
    out
}

/// `owned_in_value` of a decoded `sync.0`.
pub(crate) fn owned_in(core: &Core, g: &Tid, m: &ct::SyncIds) -> Vec<OwnedSyncId> {
    let hint = !core.holds_own_sync(g);
    m.iter()
        .filter_map(|(id, l)| {
            let steps = osis_blob::sync_steps(l).ok()?;
            if !core.owns_sync_id(g, id, &steps) {
                return None;
            }
            Some(OwnedSyncId { id: *id, path: Arc::new(recorded_path(&steps)?), hint })
        })
        .collect()
}

impl Core {
    /// Whether this node holds a sync secret of `g`'s own (`owns` judges `g`'s `sync.0` by it;
    /// without one its entries are hints).
    pub(crate) fn holds_own_sync(&self, g: &Tid) -> bool {
        self.own_record(g).is_some_and(|e| e.sync.holds_any())
    }

    /// Whether `g` owns sync ID `id` here (`owns`): judged once this node holds a sync secret of
    /// `g`'s own, else taken as a hint.
    pub(crate) fn owns_sync_id(&self, g: &Tid, id: &SyncId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
        !self.holds_own_sync(g) || owns(self.epochs(g).as_deref(), id, steps)
    }

    /// The reader actor of `t`, whose read role reads its deltas: `t` with secrets of its own,
    /// else the nearest record-chain actor that has them (a key actor is its own).
    pub fn reader_of(&self, t: &Tid) -> Tid {
        // the actor whose secrets `t`'s derive from, up the record chain
        self.secret_actor(t).unwrap_or(*t)
    }

    /// The actor whose secrets `t`'s derive from: up the record chain to a thing with secrets of
    /// its own or a key actor.
    pub fn secret_actor(&self, t: &Tid) -> Option<Tid> {
        for step in self.record_chain(t) {
            let cur = step.thing()?;
            if self.ix.own_keys.contains(&cur) || Some(cur) == self.me() {
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
    /// §4 Holds, Key access: a keyless grant, one closing a cycle of actor grants, reads nothing
    /// through it): what gives, takes and opens `a`'s secrets. Read on the memo clock
    /// (`role_now`); an account root has no grants.
    pub(crate) fn keyed_role_now(&self, x: &Tid, a: &Tid) -> Option<Role> {
        let role = self.role_now(x, a);
        if role.is_none() || self.timelines.keyless().is_empty() || self.root_holders(a).is_some() {
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
    /// through grants with key access (`reads_now`). An actor up the record chain of one with
    /// secrets of its own reads it only by its role there: a record edge lowered or removed
    /// takes that role (spec/permissions.md §1).
    /// This node's own account root reads as the account does (its readers are the
    /// account's nodes); another account root reads as itself: what this node seals,
    /// boxes or opens never reads another account's grants as its own (chain placement alone
    /// widens that, `Engine::cert_reads_in`).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        let x = &self.account_and_root().filter(|(_, d)| d == x).map_or(*x, |(p, _)| p);
        let Some(a) = self.secret_actor(t) else { return false };
        a == *x || self.reads_now(x, &a)
    }
}

impl Engine {
    /// The keyless actor grants held here, each (target, holder) (spec/crypto.md §4 Key access):
    /// for tests modelling what reads through grants.
    #[doc(hidden)]
    pub fn keyless_grants(&self) -> BTreeSet<(Tid, Tid)> {
        (*self.core.timelines.keyless()).clone()
    }

    /// Whether actor `x` may read thing `t` (entitlement, spec/sync-judgement.md §1).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        self.core.may_read(x, t)
    }

    /// Things with a `sync.0` state.
    pub fn things_with_sync_ids(&self) -> Vec<Tid> {
        self.core.ix.sync_recorded.iter().copied().collect()
    }

    /// The sync IDs `g` owns as its `sync.0` records them (`owns`), each with its recorded path;
    /// hints while this node holds no sync secret of `g`'s own. Decoded once per write of the
    /// `sync.0` (`Core::sync_ids`). A destroyed thing has the ones its destruction kept
    /// (`Indexes::destroyed_sync_ids`), its record held or not. A `sync.0` the store refuses to
    /// read is the error, read again at the next ask.
    pub(crate) fn owned_sync_ids(&mut self, g: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        if let Some(kept) = self.core.ix.destroyed_sync_ids.get(g) {
            return Ok(kept.clone());
        }
        if self.core.created(g).is_none() {
            return Ok(Arc::new(followed(self, g).map(|h| vec![h]).unwrap_or_else(|| ticket_hints(self, g))));
        }
        Memo::get_in(self, |e| &e.core.sync_ids, g, |e| {
            let m = e.get_typed(g, &ct::SYNC)?.unwrap_or_default();
            let mut out = owned_in(&e.core, g, &m);
            match out.is_empty() {
                true => out = followed(e, g).map(|h| vec![h]).unwrap_or_else(|| ticket_hints(e, g)),
                // a ticket's sync ID no held `sync.0` records: two admins giving g secrets at
                // once each made one, and this node may hold only the other's record (a forged
                // one opens nothing, and goes with its ticket)
                false => out.extend(ticket_hints(e, g).into_iter().filter(|o| !m.contains_key(&o.id))),
            }
            Ok::<_, crate::error::Error>(Arc::new(out))
        })
    }
}

/// The links this node redeems (`Engine::follow_link`): link K to its sync ID from the link text
/// and its link key L, read per key three ways (by K; by L, an author this node writes as; by
/// sync ID), so a reader asking about one link, actor or sync ID moves only when that one does,
/// not at every link followed or let go. Each key L is kept exactly while some followed link names
/// it, so it goes with the last link naming it (`Engine::settle_key_actor`). In memory only
/// (`Core::followed_links`).
#[derive(Clone, Default)]
pub(crate) struct FollowedLinks {
    by_k: Stamped<Tid, (SyncId, Tid)>,
    /// Per link key L, the links K it is the key of.
    by_actor: Stamped<Tid, BTreeSet<Tid>>,
    /// Per link key L, its identity from the seed: kept exactly while `by_actor` names L.
    keys: BTreeMap<Tid, Arc<Identity>>,
    /// Per sync ID, the links K whose text names it.
    by_sync: Stamped<SyncId, BTreeSet<Tid>>,
}

impl FollowedLinks {
    /// Link `k`'s sync ID and key, read per K.
    pub(crate) fn get(&self, k: &Tid) -> Option<(SyncId, Tid)> {
        self.by_k.get(k).copied()
    }

    pub(crate) fn contains(&self, k: &Tid) -> bool {
        self.by_k.contains_key(k)
    }

    /// Every link followed: a read of all of them.
    pub(crate) fn all(&self) -> &BTreeMap<Tid, (SyncId, Tid)> {
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

    /// Follows link `k` under sync ID `s` and key `l`; the same again moves nothing. Returns the
    /// key `k` was followed under before, if any.
    pub(crate) fn insert(&mut self, k: Tid, s: SyncId, l: Arc<Identity>) -> Option<Tid> {
        let lt = l.tid();
        if self.by_k.get(&k) == Some(&(s, lt)) {
            return None;
        }
        let old = self.remove(&k);
        self.by_k.insert(k, (s, lt));
        Self::add(&mut self.by_actor, lt, k);
        Self::add(&mut self.by_sync, s, k);
        self.keys.insert(lt, l);
        old
    }

    /// Lets link `k` go: its key, if it was followed (gone here with the last link naming it).
    pub(crate) fn remove(&mut self, k: &Tid) -> Option<Tid> {
        let (s, l) = self.by_k.remove(k)?;
        Self::take(&mut self.by_actor, &l, k);
        Self::take(&mut self.by_sync, &s, k);
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
/// other thing's here (no applied `sync.0` records it, no destroyed thing or other followed link
/// names it), else it is nobody's.
fn followed(e: &Engine, k: &Tid) -> Option<OwnedSyncId> {
    let (s, _) = e.core.followed_links.get(k)?;
    let ix = &e.core.ix;
    let elsewhere = ix.sync_recorders.get(&s).is_some_and(|x| !x.is_empty())
        || ix.destroyed_sync_ids.values().any(|v| v.iter().any(|o| o.id == s))
        || e.core.followed_links.naming(&s).iter().any(|t| t != k);
    (followable(e, k) && !elsewhere).then(|| OwnedSyncId { id: s, path: Arc::new(crate::sync::Path::default()), hint: true })
}

/// The sync IDs the held tickets for `g` name (spec/sync-inbox.md §5 Ticket sync IDs: its
/// issuer's word until a held `sync.0` records `g`'s), as hints with no recorded path. Each is
/// untrusted: one another thing owns here (an applied `sync.0` records it, a destroyed thing
/// keeps it, a followed link names it) is not `g`'s, so a forged one cuts nothing off.
fn ticket_hints(e: &Engine, g: &Tid) -> Vec<OwnedSyncId> {
    let ix = &e.core.ix;
    let theirs = |s: &SyncId| {
        ix.sync_recorders.get(s).is_some_and(|x| x.iter().any(|t| t != g)) || ix.destroyed_sync_ids.values().any(|v| v.iter().any(|o| o.id == *s)) || !e.core.followed_links.naming(s).is_empty()
    };
    let ids: BTreeSet<SyncId> = ix.closure.ticket_ids(g).into_iter().map(|(s, _)| s).filter(|s| !theirs(s)).collect();
    ids.into_iter().map(|id| OwnedSyncId { id, path: Arc::new(crate::sync::Path::default()), hint: true }).collect()
}

/// Whether followed link `k` may be a link's K here: a thing this node holds only as a link's K
/// (its creation record has the `link` field), or one it knows nothing of yet (no record or
/// destruction). A link text naming any other thing as K changes nothing of it.
pub(crate) fn followable(e: &Engine, k: &Tid) -> bool {
    if !e.core.followed_links.contains(k) {
        return false;
    }
    match e.core.created(k) {
        Some(r) => r.link_target().is_some(),
        None => !e.core.ix.destroyed_sync_ids.contains_key(k),
    }
}
