//! Actors, entitlement and closure (spec/sync-ids.md §2, spec/sync-judgement.md §1, spec/sync-set.md §2): a thing's independent (the thing if it
//! is independent, else its mint admin's), who may read it, and the sync IDs of an independent
//! thing (`sync.0`).

use osis_base::memo::{Memo, Stamped};
use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::{ChainStep, CommitId, SyncId, Role, Tid};
use crate::sync::{OwnedSyncId, Path};
use osis_crypto::{RoleKey, role_key};
use osis_blob::{Step, StepId};
use osis_schema::core_types as ct;
use crate::identity::Identity;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The recorded path of a sync ID from its steps (spec/sync-ids.md §5 Path): genesis to head, the
/// head being the newest recorded step (`head_of`). `None` when no step's path verifies.
pub(crate) fn recorded_path(steps: &BTreeMap<StepId, Step>) -> Option<Path> {
    let head = head_of(steps)?;
    let mut path = Vec::new();
    let mut at = Some(head);
    while let Some(s) = at.and_then(|id| steps.get(&id)) {
        path.push(s.clone());
        at = s.prev;
    }
    path.reverse();
    Some(Path { steps: path })
}

/// The head a node reading S takes from its `sync.0` (spec/sync-ids.md §3 "the newest step its
/// `sync.0` records"): of the tips whose path from genesis verifies, the deepest; ties (two admins
/// stepping at once) by lowest step ID. The spec names no order for a forked tree: this is its
/// simplest reading.
pub(crate) fn head_of(steps: &BTreeMap<StepId, Step>) -> Option<StepId> {
    head_at(steps).map(|(k, _)| k)
}

/// `head_of` with its depth (its path's steps after the genesis).
pub(crate) fn head_at(steps: &BTreeMap<StepId, Step>) -> Option<(StepId, usize)> {
    let parents: BTreeSet<StepId> = steps.values().filter_map(|s| s.prev).collect();
    let depth = verified_depths(steps);
    steps.keys().filter(|k| !parents.contains(k)).filter_map(|k| Some((*k, *depth.get(k)?))).min_by_key(|(k, n)| (std::cmp::Reverse(*n), *k))
}

/// The depth of each step whose path from its genesis step verifies (`osis_blob::verify_path`:
/// each step under its own ID, the genesis by its own delete key, each child by its parent's),
/// each signature checked once, from the genesis steps down.
pub(crate) fn verified_depths(steps: &BTreeMap<StepId, Step>) -> BTreeMap<StepId, usize> {
    let mut children: BTreeMap<StepId, Vec<StepId>> = BTreeMap::new();
    let mut todo: Vec<(StepId, usize)> = Vec::new();
    for (id, s) in steps {
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
        let Some(parent) = steps.get(&id) else { continue };
        for c in children.remove(&id).unwrap_or_default() {
            if steps.get(&c).is_some_and(|s| s.verify_child(parent).is_ok()) {
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
    let at: BTreeMap<StepId, usize> = o.path.steps.iter().enumerate().map(|(i, st)| (st.id(), i)).collect();
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
        let Some(f) = o.path.steps.get(fork) else { continue };
        if depth < o.path.steps.len() && f.keys.delete != x.keys.delete {
            let d = deepest.entry(x.keys.delete.to_bytes()).or_default();
            *d = (*d).max(depth);
        }
    }
    deepest
        .into_iter()
        .filter(|(d, depth)| !o.path.steps.iter().skip(*depth).any(|st| o.endorsed.get(&st.id()).is_some_and(|e| e.contains_key(d))))
        .map(|(d, _)| d)
        .collect()
}

/// Sync ID `id` of `g` with its recorded path from decoded `sync.0` `m` (none recorded, or none
/// whose path verifies: an empty path), `hint` as given.
fn owned(m: &ct::SyncIds, id: SyncId, hint: bool) -> OwnedSyncId {
    let steps = m.get(&id).and_then(|l| Some((l, osis_blob::sync_steps(l).ok()?)));
    let (path, tree, endorsed) = match steps {
        Some((l, steps)) => (recorded_path(&steps).unwrap_or_default(), steps.clone(), osis_blob::sync_endorsements(l, &steps)),
        None => Default::default(),
    };
    OwnedSyncId { id, path: Arc::new(path), tree: Arc::new(tree), endorsed: Arc::new(endorsed), hint }
}

impl Core {
    /// Whether this node holds a sync secret of `g`'s own (`owns` judges `g`'s `sync.0` by it;
    /// without one its entries are hints).
    pub(crate) fn holds_own_sync(&self, g: &Tid) -> bool {
        self.own_record(g).is_some_and(|e| e.sync.holds_any()) || self.unread(g).holds_any()
    }

    /// `g`'s sync ID by its seed or its `keys.0` (spec/sync-ids.md §4 Owner), with whether it is
    /// a hint: the one `g`'s genesis seed gives where this node holds the seed; else the one its
    /// `keys.0` names, a hint while this node holds no sync secret of `g`'s own (it reads `g` by
    /// derived secrets, which no step bears), else only once a step on a verified path of it
    /// (`Indexes::steps`) bears the sync key of one held here (`Some(None)` until then). `None`
    /// where neither names one.
    ///
    /// Invariant: the sync ID `g`'s `keys.0` names counts as `g`'s, on every path that reads it,
    /// only so. Any admin of `g` writes `g`'s `keys.0` and may name any sync ID there; the steps
    /// chain by signature to the genesis delete key, which the sync ID commits to and only the
    /// owner's admins held, so a step bearing `g`'s sync key is an owner admin's own word that
    /// `g` owns it. One failing this is ignored here, never judged invalid: the check turns on
    /// the secrets this node holds.
    pub(crate) fn named_sync_id(&self, g: &Tid) -> Option<Option<(SyncId, bool)>> {
        if let Some(id) = self.seeded_sync_id(g) {
            return Some(Some((id, false)));
        }
        let id = *self.ix.keys_sync_id.get(g)?;
        if !self.holds_own_sync(g) {
            return Some(Some((id, true)));
        }
        let held = self.held_sync_keys(g);
        let bears = self.ix.steps.get(g).is_some_and(|r| r.steps.values().any(|s| s.sync_id == id && held.contains(&s.sync)));
        Some(bears.then_some((id, false)))
    }

    /// The sync ID `g`'s genesis seed gives, where this node holds the seed (spec/sync-ids.md §4
    /// Owner) and `g` has a sync ID: its `keys.0` names one or its `sync.0` records that one (a
    /// dependent thing's seed derives, but it has no sync ID of its own).
    pub(crate) fn seeded_sync_id(&self, g: &Tid) -> Option<SyncId> {
        let id = self.epochs(g).and_then(|e| e.genesis().map(osis_blob::genesis_sync_id))?;
        let recorded = self.ix.steps.get(g).is_some_and(|r| r.steps.values().any(|s| s.sync_id == id));
        (self.ix.keys_sync_id.contains_key(g) || recorded).then_some(id)
    }

    /// The sync keys (spec/sync-ids.md §3) of the sync secrets of `g` held here, reading-only
    /// ones included (`memo`: a key derivation per secret, asked at every write listing a step).
    pub(crate) fn held_sync_keys(&self, g: &Tid) -> Arc<BTreeSet<[u8; 32]>> {
        self.held_sync_keys.get(g, || {
            let e = self.epochs(g);
            let mut out: BTreeSet<[u8; 32]> = e.iter().flat_map(|e| e.sync.held_newest_first()).map(|(_, s)| role_key(RoleKey::Sync, s).verifying_key().to_bytes()).collect();
            // kept unread: the sync secrets held (`sync_ids::unread`)
            out.extend(self.unread(g).candidates.values().map(crate::sync_ids::unread::sync_key));
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
            // a grantee holds no rotation that made a granted epoch current)
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

    /// `g`'s sync ID by the owner rule (`held_sync_ids`), with its recorded path. Decoded once per
    /// write of what it reads (`Core::sync_ids`), a destroyed thing's too. A `sync.0` the store refuses to read is the error, read again at the next ask.
    pub(crate) fn owned_sync_ids(&mut self, g: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        Memo::get_in(self, |e| &e.core.sync_ids, g, |e| e.read(|tx| held_sync_ids(tx, g)).map(Arc::new))
    }
}

/// `g`'s `sync.0` state as held here (a destroyed thing's too: it stays, `retention::destroy`).
fn recorded(tx: &mut Tx<'_>, g: &Tid) -> Result<ct::SyncIds> {
    use osis_schema::RawKey;
    let ak = crate::flows::ak(ct::SYNC.ak())?;
    Ok(match tx.state(g, &ak)?.and_then(osis_crdt::Fragment::read) {
        Some(v) => ct::SYNC.decode(&v)?,
        None => Default::default(),
    })
}

/// `g`'s sync ID here (spec/sync-ids.md §4 Owner), at most one but for what `g` is followed by:
/// the one its seed or `keys.0` names (`Core::named_sync_id`); else the sync IDs it follows `g` by
/// (`followed`), as hints. Any other `sync.0` entry is ignored.
pub(crate) fn held_sync_ids(tx: &mut Tx<'_>, g: &Tid) -> Result<Vec<OwnedSyncId>> {
    let m = recorded(tx, g)?;
    match tx.core.named_sync_id(g) {
        Some(o) => Ok(o.into_iter().map(|(id, hint)| owned(&m, id, hint)).collect()),
        None => followed(tx, g),
    }
}

/// `g`'s sync ID by its seed or its `keys.0` (`Core::named_sync_id`), hints included, never one
/// it is followed by.
pub(crate) fn owner_sync_id(tx: &mut Tx<'_>, g: &Tid) -> Result<Option<OwnedSyncId>> {
    let Some((id, hint)) = tx.core.named_sync_id(g).flatten() else { return Ok(None) };
    let m = recorded(tx, g)?;
    Ok(Some(owned(&m, id, hint)))
}

/// The things this node follows by a locator or link being redeemed (`Engine::follow_link`,
/// `follow_public`) or by held grant signals (`Engine::take_fire`): per thing, the sync IDs it is
/// followed under and a share link's key L, read per key three ways (by thing; by L, an author
/// this node writes as; by sync ID), so a reader asking about one thing, actor or sync ID moves
/// only when that one does. Each key L is kept exactly while some followed link names it, so it
/// goes with the last link naming it (`Engine::settle_link_key`). In memory only
/// (`Core::followed_links`); the held signals' rows are the engine's (`flows::inbox`).
///
/// Invariant (spec/sync-inbox.md §5 Grant signal): a thing is followed under every sync ID that
/// a link being redeemed for it or a followed signal naming it names, none displacing another,
/// so what is followed depends on which values are held, never on the order they came in. Who
/// writes them: a link text is its sharer's; a signal is anyone's holding its holder's card. A
/// sync ID none of them gives is judged by the owner rule (`held_sync_ids`).
#[derive(Clone, Default)]
pub(crate) struct FollowedLinks {
    /// Per thing followed, its sync IDs and its link's key (none: a locator or signals alone).
    by_k: Stamped<Tid, (BTreeSet<SyncId>, Option<Tid>)>,
    /// Per link key L, the links K it is the key of.
    by_actor: Stamped<Tid, BTreeSet<Tid>>,
    /// Per link key L, its identity from the seed: kept exactly while `by_actor` names L.
    keys: BTreeMap<Tid, Arc<Identity>>,
    /// Per sync ID, the things followed under it.
    by_sync: Stamped<SyncId, BTreeSet<Tid>>,
    /// The links being redeemed (`insert`): per K (a locator: its target), its sync ID from the
    /// link text and its key (a locator: none).
    links: BTreeMap<Tid, (SyncId, Option<Arc<Identity>>)>,
    /// Per thing a followed grant signal names, per sync ID such signals name, the signals.
    signals: BTreeMap<Tid, BTreeMap<SyncId, BTreeSet<CommitId>>>,
    /// Each followed signal's inbox: the thing its fire is on.
    inboxes: BTreeMap<CommitId, Tid>,
    /// Per thing a followed signal names, the inboxes holding such signals, read per thing.
    fired_on: Stamped<Tid, BTreeSet<Tid>>,
    /// A count written at each change of `signals`: what a reader of them all reads
    /// (`signals_read`), so it moves as any signal is followed or let go.
    signals_moved: Stamped<(), u64>,
    /// The held grant signals (`flows::inbox` rows), followed or not: read from their rows at the
    /// engine's first take (`Engine::take_carried`), `None` until then.
    pub(crate) held_signals: Option<BTreeMap<CommitId, Signal>>,
}

/// A held grant signal's values (spec/data-model.md §9 `grant@~0`): the thing it names, that
/// thing's sync ID as it names it, and the holder told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Signal {
    pub thing: Tid,
    pub sync_id: SyncId,
    pub holder: Tid,
}

impl FollowedLinks {
    /// Thing `k`'s sync IDs and link key (none: a locator or signals alone), read per K.
    pub(crate) fn get(&self, k: &Tid) -> Option<(BTreeSet<SyncId>, Option<Tid>)> {
        self.by_k.get(k).cloned()
    }

    pub(crate) fn contains(&self, k: &Tid) -> bool {
        self.by_k.contains_key(k)
    }

    /// A cursor over the things followed from now on, each as it is followed (`Feed`).
    pub(crate) fn followed_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.by_k.feed()
    }

    /// Every thing followed: a read of all of them.
    pub(crate) fn all(&self) -> &BTreeMap<Tid, (BTreeSet<SyncId>, Option<Tid>)> {
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

    /// The things followed under sync ID `s`, read per sync ID.
    pub(crate) fn naming(&self, s: &SyncId) -> BTreeSet<Tid> {
        self.by_sync.get(s).cloned().unwrap_or_default()
    }

    /// Follows link `k` under sync ID `s` and key `l` (none: a locator); the same again moves
    /// nothing. Returns the key `k` was followed under before, if any.
    pub(crate) fn insert(&mut self, k: Tid, s: SyncId, l: Option<Arc<Identity>>) -> Option<Tid> {
        self.links.insert(k, (s, l));
        self.refresh(k)
    }

    /// Lets link `k` go: returns its key, if it was followed with one (gone here with the last
    /// link naming it). A thing a followed signal names stays followed under the signals' IDs.
    pub(crate) fn remove(&mut self, k: &Tid) -> Option<Tid> {
        self.links.remove(k);
        self.refresh(*k)
    }

    /// Follows thing `x` under sync ID `s` for held grant signal `c`, fired on `inbox`.
    pub(crate) fn follow_signal(&mut self, x: Tid, s: SyncId, c: CommitId, inbox: Tid) {
        self.signals.entry(x).or_default().entry(s).or_default().insert(c);
        self.inboxes.insert(c, inbox);
        self.bump();
        self.refresh(x);
    }

    /// Grant signal `c` naming `x` under `s` is followed no more: `s` goes unless another
    /// followed signal or a link names it for `x`.
    pub(crate) fn unfollow_signal(&mut self, x: &Tid, s: &SyncId, c: &CommitId) {
        let Some(m) = self.signals.get_mut(x) else { return };
        if let Some(cs) = m.get_mut(s) {
            cs.remove(c);
            if cs.is_empty() {
                m.remove(s);
            }
        }
        if m.is_empty() {
            self.signals.remove(x);
        }
        self.inboxes.remove(c);
        self.bump();
        self.refresh(*x);
    }

    /// The holders of the followed signals naming `x` under `s` (spec/sync-opens.md §4: each
    /// thing naming S to this node).
    pub(crate) fn signal_holders(&self, x: &Tid, s: &SyncId) -> Vec<Tid> {
        let held = self.held_signals.as_ref();
        self.signals.get(x).and_then(|m| m.get(s)).into_iter().flatten().filter_map(|c| held?.get(c).map(|g| g.holder)).collect()
    }

    /// The link being redeemed for `k` under `s`: its key (none: a locator); `None` when none is.
    pub(crate) fn link_of(&self, k: &Tid, s: &SyncId) -> Option<Option<&Arc<Identity>>> {
        self.links.get(k).filter(|(x, _)| x == s).map(|(_, l)| l.as_ref())
    }

    /// Whether signal `c` naming `x` under `s` is followed.
    pub(crate) fn follows_signal(&self, x: &Tid, s: &SyncId, c: &CommitId) -> bool {
        self.signals.get(x).and_then(|m| m.get(s)).is_some_and(|cs| cs.contains(c))
    }

    /// `signals`, read as a whole: a memo over it moves at any change.
    pub(crate) fn signals_read(&self) -> &BTreeMap<Tid, BTreeMap<SyncId, BTreeSet<CommitId>>> {
        let _ = self.signals_moved.get(&());
        &self.signals
    }

    fn bump(&mut self) {
        let n = self.signals_moved.get(&()).copied().unwrap_or(0);
        self.signals_moved.insert((), n.wrapping_add(1));
    }

    /// Whether a followed grant signal naming `x` is fired on `inbox` (read per thing).
    pub(crate) fn fired_on(&self, x: &Tid, inbox: &Tid) -> bool {
        self.fired_on.get(x).is_some_and(|is| is.contains(inbox))
    }

    /// Sets `k`'s entry from its link and signals: the same again moves nothing. Returns the key
    /// `k` was followed under before, if it moved.
    fn refresh(&mut self, k: Tid) -> Option<Tid> {
        let on: BTreeSet<Tid> = self.signals.get(&k).into_iter().flat_map(|m| m.values().flatten()).filter_map(|c| self.inboxes.get(c)).copied().collect();
        if self.fired_on.get(&k).map_or(!on.is_empty(), |was| *was != on) {
            match on.is_empty() {
                true => drop(self.fired_on.remove(&k)),
                false => drop(self.fired_on.insert(k, on)),
            }
        }
        let link = self.links.get(&k).cloned();
        let mut ids: BTreeSet<SyncId> = self.signals.get(&k).map(|m| m.keys().copied().collect()).unwrap_or_default();
        ids.extend(link.as_ref().map(|(s, _)| *s));
        let l = link.and_then(|(_, l)| l);
        let lt = l.as_ref().map(|l| l.tid());
        match self.by_k.get(&k) {
            Some((i, t)) if *i == ids && *t == lt => return None,
            None if ids.is_empty() => return None,
            _ => {}
        }
        let old = self.unset(&k);
        if ids.is_empty() {
            return old;
        }
        for s in &ids {
            Self::add(&mut self.by_sync, *s, k);
        }
        self.by_k.update_fed(k, |_| Some((ids, lt)));
        if let Some(l) = l {
            Self::add(&mut self.by_actor, l.tid(), k);
            self.keys.insert(l.tid(), l);
        }
        old
    }

    fn unset(&mut self, k: &Tid) -> Option<Tid> {
        let (ids, l) = self.by_k.remove(k)?;
        for s in &ids {
            Self::take(&mut self.by_sync, s, k);
        }
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

/// The sync IDs followed for thing `k` (a link being redeemed, a locator, held grant signals:
/// `FollowedLinks`), each a hint with no recorded path while followed values are all this node
/// has of it (spec/sync-set.md §2), where `k` may be followed here (`followable`).
///
/// The sync IDs `k` is followed by here: those of a link, locator or held grant signals
/// (`FollowedLinks`), where `k` may be followed here (`followable`), and those the sync-only
/// cuts taken here give it (spec/sync.md §3 Kept for T), each a hint with its recorded path
/// (spec/sync-set.md §2).
///
/// Invariant: a followed sync ID counts for `k` unless another thing owns it here by the owner
/// rule (`held_sync_ids`, not as a hint), and nothing else displaces it: a link text, signal or
/// cut naming a sync ID another thing proves its own changes nothing of that thing (it moves no
/// kept-unread store to read), and a forged `sync.0`, signal or cut naming `k`'s sync ID for
/// another thing takes nothing from `k`. Who writes each input: the followed values are a link's
/// sharer's or a signal's sender's (anyone holding the holder's card); a cut is anyone's who may
/// log under a sync ID of a holder; another thing's `keys.0` is its admins'; the keys judged are
/// this node's.
fn followed(tx: &mut Tx<'_>, k: &Tid) -> Result<Vec<OwnedSyncId>> {
    let mut ids = tx.core.cut_sync_ids(k);
    if let Some((f, _)) = tx.core.followed_links.get(k)
        && followable(tx.core, k)
    {
        ids.extend(f);
    }
    let m = recorded(tx, k)?;
    let mut out = Vec::new();
    for s in ids {
        let others: BTreeSet<Tid> = tx.core.ix.sync_recorders.get(&s).into_iter().flatten().filter(|t| *t != k).copied().collect();
        let mut theirs = false;
        for t in others {
            if tx.core.named_sync_id(&t).flatten() == Some((s, false)) {
                theirs = true;
                break;
            }
        }
        if !theirs {
            out.push(owned(&m, s, true));
        }
    }
    Ok(out)
}

/// Whether followed link `k` may be a link's K here: a thing this node holds only as a link's K
/// (its creation record has the `link` field), or one it knows nothing of yet (no record). A link text naming any other thing as K changes nothing of it.
/// A locator's target may be any thing: its sync ID counts only where the owner rule gives the
/// target none (`held_sync_ids`) and no other thing owns it (`followed`).
pub(crate) fn followable(core: &Core, k: &Tid) -> bool {
    match core.followed_links.get(k) {
        None => false,
        Some((_, None)) => true,
        Some((_, Some(_))) => core.created(k).is_none_or(|r| r.link_target().is_some()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/sync-inbox.md §5 (Grant signal), spec/sync-hostile.md (a forged signal names a sync ID
    // that gives nothing): two held grant signals name X, one by X's own sync ID, the other by
    // another (a forger's: anyone holding the holder's card may fire one). X is followed under
    // both, whichever comes first, and under its own still once the forged one goes. Fails with
    // the newest signal's sync ID displacing the other.
    #[test]
    fn a_signals_sync_id_is_never_displaced_by_another_spec_sync_inbox_5() {
        let x = Tid::from_bytes([1; 15]);
        let (own, forged) = (SyncId([2; 16]), SyncId([3; 16]));
        let (c_own, c_forged) = (CommitId([4; 32]), CommitId([5; 32]));
        for forged_last in [false, true] {
            let mut f = FollowedLinks::default();
            let order = if forged_last { [(own, c_own), (forged, c_forged)] } else { [(forged, c_forged), (own, c_own)] };
            for (s, c) in order {
                f.follow_signal(x, s, c, Tid::from_bytes([6; 15]));
            }
            assert_eq!(f.get(&x).map(|(ids, _)| ids), Some([own, forged].into()), "forged last {forged_last}: X followed under both");
            assert!(f.naming(&own).contains(&x) && f.naming(&forged).contains(&x));
            f.unfollow_signal(&x, &forged, &c_forged);
            assert_eq!(f.get(&x).map(|(ids, _)| ids), Some([own].into()), "forged last {forged_last}: its own stays");
            assert!(f.naming(&forged).is_empty());
        }
    }
}
