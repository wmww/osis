//! Actors, entitlement and closure (spec/sync-ids.md §2, spec/sync-judgement.md §1, spec/sync-set.md §2): a thing's reader actor (the thing if it
//! has secrets of its own, else its first admin), who may read it, a group's closure and its
//! sync IDs (`sync.0`).

use osis_base::memo::Memo;
use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{ChainStep, SyncId, Role, Tid};
use crate::sync::{OwnedSyncId, Path};
use osis_crypto::{LabelRole, label_role_key};
use osis_keys::ActorEpochs;
use osis_label::{ClaimSet, Step, StepId};
use osis_schema::core_types as ct;
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
    let held: BTreeSet<[u8; 32]> = e.sync.held_newest_first().into_iter().map(|(_, s)| label_role_key(LabelRole::Sync, s).verifying_key().to_bytes()).collect();
    // the genesis first (every holder holds the older secrets, so usually it bears one): one
    // step verified, not a path per bearing step
    let mut bearing: Vec<(bool, &StepId)> = steps.iter().filter(|(_, (s, _))| held.contains(&s.keys.sync.to_bytes())).map(|(k, (s, _))| (s.prev.is_some(), k)).collect();
    if bearing.is_empty() {
        return false;
    }
    bearing.sort();
    let plain: BTreeMap<StepId, Step> = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
    bearing.into_iter().any(|(_, k)| osis_label::path_to(&plain, k).is_ok_and(|p| p.first().is_some_and(|g| g.label == *id)))
}

/// The recorded path of a sync ID from its steps (spec/sync-ids.md §5 Path): genesis to head, the
/// head being the newest recorded step (`head_of`). `None` when no step's path verifies.
pub(crate) fn recorded_path(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<Path> {
    let head = head_of(steps)?;
    let plain: BTreeMap<StepId, Step> = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
    let path = osis_label::path_to(&plain, &head).ok()?;
    Some(Path { steps: path.into_iter().map(|s| { let c = steps.get(&s.id()).and_then(|(_, c)| c.clone()); (s, c) }).collect() })
}

/// The head a node reading S takes from its `sync.0` (spec/sync-ids.md §3 "the newest step its
/// `sync.0` records"): of the tips whose path from genesis verifies, the deepest; ties (two admins
/// stepping at once) by lowest step ID. The spec names no order for a forked tree: this is its
/// simplest reading.
pub(crate) fn head_of(steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> Option<StepId> {
    let parents: BTreeSet<StepId> = steps.values().filter_map(|(s, _)| s.prev).collect();
    let plain: BTreeMap<StepId, Step> = steps.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
    steps.keys().filter(|k| !parents.contains(k)).filter_map(|k| Some((osis_label::path_to(&plain, k).ok()?.len(), *k))).min_by_key(|(n, k)| (std::cmp::Reverse(*n), *k)).map(|(_, k)| k)
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
            let steps = osis_label::sync_steps(l).ok()?;
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

    /// Whether actor `x` may read thing `t` now: `t`'s secrets derive from `x`'s, or `x` holds
    /// read or above on the actor they derive from (spec/sync-judgement.md §1, entitlement).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        let Some(a) = self.secret_actor(t) else { return false };
        if self.record_chain(&a).filter_map(|s| s.thing()).any(|c| c == *x) {
            return true;
        }
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
        crate::engine::write::role_of(self, x, &a, ts) >= Some(Role::Read)
    }
}

impl Engine {
    /// A group's actor (spec/sync-judgement.md §1): the group if it has secrets of its own, else its base
    /// actor.
    pub fn group_actor(&self, g: &Tid) -> Tid {
        self.core.reader_of(g)
    }

    /// Whether actor `x` may read thing `t` (entitlement, spec/sync-judgement.md §1).
    pub fn may_read(&self, x: &Tid, t: &Tid) -> bool {
        self.core.may_read(x, t)
    }

    /// The things of a group's closure (spec/sync-set.md §2): the group and every thing it contains
    /// through `group.0`, transitively through subgroups. The same `Arc` while it does not change
    /// (`Groups::closure`), so node-sync reuses what it derived from it.
    pub fn closure(&self, g: &Tid) -> std::sync::Arc<BTreeSet<Tid>> {
        self.core.ix.groups.closure(g)
    }

    /// Things with a `sync.0` state.
    pub fn things_with_sync_ids(&self) -> Vec<Tid> {
        self.core.ix.sync_recorded.iter().copied().collect()
    }

    /// The inbox of actor `a` (spec/sync-inbox.md §1): the sync ID its `keys.0` names.
    pub fn inbox(&mut self, a: &Tid) -> Option<SyncId> {
        self.get_typed(a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox).map(|i| i.sync_id)
    }

    /// The inboxes here (spec/sync-inbox.md §1): per sync ID, the actors with secrets held here whose
    /// `keys.0` names it. Usually one: an admin may write any sync ID there, and a blob is tried
    /// under each, so naming another actor's inbox hides nothing from it.
    pub fn inbox_actors(&mut self) -> Arc<BTreeMap<SyncId, Vec<Tid>>> {
        let read = |e: &mut Engine| {
            let mut by: BTreeMap<SyncId, Vec<Tid>> = BTreeMap::new();
            for a in e.core.ix.secrets.keys().chain(e.core.accounts.keys()).copied().collect::<BTreeSet<_>>() {
                if let Some(l) = e.get_typed(&a, &ct::KEYS)?.and_then(|k| k.inbox).map(|i| i.sync_id) {
                    by.entry(l).or_default().push(a);
                }
            }
            Ok::<_, crate::error::Error>(Arc::new(by))
        };
        // a `keys.0` the store refused to read: no inbox known now, read again at the next ask
        Memo::get_in(self, |e| &e.core.inbox_actors, &(), read).unwrap_or_default()
    }

    /// The sync IDs `g` owns as its `sync.0` records them (`owns`), each with its recorded path;
    /// hints while this node holds no sync secret of `g`'s own. Decoded once per write of the
    /// `sync.0` (`Core::sync_ids`). A destroyed thing keeping nothing has the ones its destruction
    /// kept (`Indexes::destroyed_sync_ids`). A `sync.0` the store refuses to read is the error, read
    /// again at the next ask.
    pub(crate) fn owned_sync_ids(&mut self, g: &Tid) -> Result<Arc<Vec<OwnedSyncId>>> {
        if self.core.created(g).is_none() {
            return Ok(self.core.ix.destroyed_sync_ids.get(g).cloned().unwrap_or_default());
        }
        Memo::get_in(self, |e| &e.core.sync_ids, g, |e| {
            let m = e.get_typed(g, &ct::SYNC)?.unwrap_or_default();
            let mut out = owned_in(&e.core, g, &m);
            // a sync ID a taken inbox blob named, until a `sync.0` here gives one (spec/sync-
            // inbox.md §2): followed with no recorded path
            if out.is_empty()
                && let Some(s) = e.core.ix.inbox_hints.get(g)
            {
                out.push(OwnedSyncId { id: *s, path: Arc::new(crate::sync::Path::default()), hint: true });
            }
            Ok::<_, crate::error::Error>(Arc::new(out))
        })
    }
}
