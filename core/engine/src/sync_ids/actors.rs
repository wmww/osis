//! Actors, entitlement and closure (spec/sync-ids.md §2, spec/sync-judgement.md §1, spec/sync-set.md §2): a thing's independent (the thing if it
//! is independent, else its mint admin's), who may read it, and the sync IDs of an independent
//! thing (`sync.0`).

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
    let hint = !core.holds_own_sync(g);
    m.iter()
        .filter_map(|(id, l)| {
            let steps = osis_blob::sync_steps(l).ok()?;
            if !core.owns_sync_id(g, id, &steps) {
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
        self.own_record(g).is_some_and(|e| e.sync.holds_any())
    }

    /// Whether `g` owns sync ID `id` here (`owns`): judged once this node holds a sync secret of
    /// `g`'s own, else taken as a hint.
    pub(crate) fn owns_sync_id(&self, g: &Tid, id: &SyncId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
        !self.holds_own_sync(g) || owns(self.epochs(g).as_deref(), id, steps)
    }

    /// The independent of `t`, whose read role reads its deltas: `t` if independent,
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
            if self.ix.independent.contains(&cur) || Some(cur) == self.me() {
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
        if role.is_none() || self.timelines().keyless().is_empty() || self.root_holders(a).is_some() {
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
        (*self.core.timelines().keyless()).clone()
    }

    /// Things with a `sync.0` state.
    pub fn things_with_sync_ids(&self) -> Vec<Tid> {
        self.core.ix.sync_recorded.iter().copied().collect()
    }

    /// The sync IDs `g` owns as its `sync.0` records them (`owns`), each with its recorded path;
    /// hints while this node holds no sync secret of `g`'s own (`held_sync_ids`). Decoded once
    /// per write of the `sync.0` (`Core::sync_ids`), a destroyed thing's too. A `sync.0` the store
    /// refuses to read is the error, read again at the next ask.
    pub(crate) fn owned_sync_ids(&mut self, g: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        if self.core.created(g).is_none() {
            return Ok(Arc::new(held_sync_ids(&self.core, g, &ct::SyncIds::default())));
        }
        Memo::get_in(self, |e| &e.core.sync_ids, g, |e| {
            use osis_schema::RawKey;
            // a destroyed thing's too: its `sync.0` stays (`retention::destroy`), read past `exists`
            let ak = crate::flows::ak(ct::SYNC.ak())?;
            let v = e.read(|tx| Ok(tx.state(g, &ak)?.and_then(osis_crdt::Fragment::read)))?;
            let m = match v {
                Some(v) => ct::SYNC.decode(&v)?,
                None => Default::default(),
            };
            Ok::<_, crate::error::Error>(Arc::new(held_sync_ids(&e.core, g, &m)))
        })
    }
}

/// The sync IDs this node holds for `g`, its `sync.0` recording `m`: those `m` records that `g`
/// owns here (`owned_in`), else a followed link's (`followed`) or its held tickets' (`ticket_hints`).
pub(crate) fn held_sync_ids(core: &Core, g: &Tid, m: &ct::SyncIds) -> Vec<OwnedSyncId> {
    let mut out = owned_in(core, g, m);
    match out.is_empty() {
        true => out = followed(core, g).map(|h| vec![h]).unwrap_or_else(|| ticket_hints(core, g)),
        // a ticket's sync ID no held `sync.0` records: two admins giving g secrets at once each
        // made one, and this node may hold only the other's record (a forged one opens nothing,
        // and goes with its ticket)
        false => out.extend(ticket_hints(core, g).into_iter().filter(|o| !m.contains_key(&o.id))),
    }
    out
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

    /// A cursor over the links followed from now on, each as it is followed (`Feed`).
    pub(crate) fn followed_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.by_k.feed()
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
        self.by_k.update_fed(k, |_| Some((s, lt)));
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
/// other thing's here (no applied `sync.0` records it, no other followed link names it), else it
/// is nobody's.
fn followed(core: &Core, k: &Tid) -> Option<OwnedSyncId> {
    let (s, _) = core.followed_links.get(k)?;
    let ix = &core.ix;
    let elsewhere = ix.sync_recorders.get(&s).is_some_and(|x| !x.is_empty())
        || core.followed_links.naming(&s).iter().any(|t| t != k);
    (followable(core, k) && !elsewhere).then(|| OwnedSyncId { id: s, path: Arc::new(crate::sync::Path::default()), tree: Arc::default(), endorsed: Arc::default(), hint: true })
}

/// The sync IDs the held tickets for `g` name (Interim (issues/tickets-retired.md): its
/// issuer's word until a held `sync.0` records `g`'s), as hints with no recorded path. Each is
/// untrusted: one another thing owns here (an applied `sync.0` records it, a followed link names
/// it) is not `g`'s, so a forged one cuts nothing off.
fn ticket_hints(core: &Core, g: &Tid) -> Vec<OwnedSyncId> {
    let ix = &core.ix;
    let theirs = |s: &SyncId| {
        ix.sync_recorders.get(s).is_some_and(|x| x.iter().any(|t| t != g)) || !core.followed_links.naming(s).is_empty()
    };
    let ids: BTreeSet<SyncId> = ix.closure.ticket_ids(g).into_iter().map(|(s, _)| s).filter(|s| !theirs(s)).collect();
    ids.into_iter().map(|id| OwnedSyncId { id, path: Arc::new(crate::sync::Path::default()), tree: Arc::default(), endorsed: Arc::default(), hint: true }).collect()
}

/// Whether followed link `k` may be a link's K here: a thing this node holds only as a link's K
/// (its creation record has the `link` field), or one it knows nothing of yet (no record). A link text naming any other thing as K changes nothing of it.
pub(crate) fn followable(core: &Core, k: &Tid) -> bool {
    if !core.followed_links.contains(k) {
        return false;
    }
    core.created(k).is_none_or(|r| r.link_target().is_some())
}
