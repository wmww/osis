//! Actors, entitlement and closure (spec/sync-ids.md §2, spec/sync-judgement.md §1, spec/sync-set.md §2): a thing's reader actor (the thing if it
//! has secrets of its own, else its first admin), who may read it, a group's closure and its labels.

use osis_base::memo::Memo;
use crate::engine::{Core, Engine};
use crate::error::Result;
use osis_base::{ChainStep, LabelId, Role, Tid};
use osis_crypto::{LabelRole, label_role_key};
use osis_keys::ActorEpochs;
use osis_label::{ClaimSet, Step, StepId};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A label of a group as its `label.0` records it (spec/sync-ids.md §4).
#[derive(Clone, Debug, PartialEq)]
pub struct GroupLabel {
    pub group: Tid,
    pub id: LabelId,
    /// Steps by ID with their claim sets when recorded.
    pub steps: BTreeMap<StepId, (Step, Option<ClaimSet>)>,
}

/// Whether label `id`, its steps as `steps` records them, belongs to the group whose epochs held
/// here are `epochs` (spec/sync-ids.md §4, owner; `Core::owns_label`).
///
/// Invariant: an entry of g's `label.0` counts as g's label, on every path that reads it (the
/// labels node-sync syncs, registers at, filters and empties once g is destroyed, g's own label
/// and inbox, what goes when g is forgotten), only when some step on a verified path from the
/// label's genesis step bears a sync key that a sync secret of g held here derives. Any admin of g
/// writes g's `label.0` and may name any label there; the steps chain by signature to the genesis
/// delete key, which the label ID commits to and only the owner's admins held, so a step bearing
/// g's sync key is an owner admin's own word that g owns it. An entry failing this is ignored
/// here, never judged invalid: the check turns on the secrets this node holds. While this node
/// holds no sync secret of g's own (it reads g by derived secrets, which no step bears, until the
/// commit giving g's own reaches it under these very labels) the entries are its admins' word, as
/// a label hint is its sender's.
pub(crate) fn owns(epochs: Option<&ActorEpochs>, id: &LabelId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
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

fn group_label(g: &Tid, id: &LabelId, l: &ct::Label) -> Option<Arc<GroupLabel>> {
    let steps = osis_label::label_steps(l).ok()?;
    Some(Arc::new(GroupLabel { group: *g, id: *id, steps }))
}

/// The labels of `g` a `label.0` value `v` records, owned or not (`owns`); records that do not
/// parse are skipped.
pub(crate) fn group_labels_in(g: &Tid, v: &osis_base::Value) -> Vec<Arc<GroupLabel>> {
    use osis_schema::RawKey;
    ct::LABEL.decode(v).map(|m| m.iter().filter_map(|(id, l)| group_label(g, id, l)).collect()).unwrap_or_default()
}

impl GroupLabel {
    /// The tips of the step tree (the newest step of each branch).
    pub fn tips(&self) -> Vec<StepId> {
        let parents: BTreeSet<StepId> = self.steps.values().filter_map(|(s, _)| s.prev).collect();
        self.steps.keys().filter(|k| !parents.contains(k)).copied().collect()
    }

    /// The step's child on the label's tree, if recorded (the first by ID when forked).
    pub fn child_of(&self, id: &StepId) -> Option<&Step> {
        self.steps.values().map(|(s, _)| s).find(|s| s.prev == Some(*id))
    }
}

impl Core {
    /// Whether `g` owns label `id` here (`owns`): judged once this node holds a sync secret of
    /// `g`'s own, else taken.
    pub(crate) fn owns_label(&self, g: &Tid, id: &LabelId, steps: &BTreeMap<StepId, (Step, Option<ClaimSet>)>) -> bool {
        if !self.own_record(g).is_some_and(|e| e.sync.holds_any()) {
            return true;
        }
        owns(self.epochs(g).as_deref(), id, steps)
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

    /// Things with a `label.0` state.
    pub fn labeled_groups(&self) -> Vec<Tid> {
        self.core.ix.labeled.iter().copied().collect()
    }

    /// The inbox of actor `a` (spec/sync-inbox.md §1): the sync ID its `keys.0` names.
    pub fn inbox(&mut self, a: &Tid) -> Option<LabelId> {
        self.get_typed(a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox).map(|i| i.label)
    }

    /// The inboxes here (spec/sync-inbox.md §1): per sync ID, the actors with secrets held here whose
    /// `keys.0` names it. Usually one: an admin may write any sync ID there, and a blob is tried
    /// under each, so naming another actor's inbox hides nothing from it.
    pub fn inbox_actors(&mut self) -> Arc<BTreeMap<LabelId, Vec<Tid>>> {
        let read = |e: &mut Engine| {
            let mut by: BTreeMap<LabelId, Vec<Tid>> = BTreeMap::new();
            for a in e.core.ix.secrets.keys().chain(e.core.accounts.keys()).copied().collect::<BTreeSet<_>>() {
                if let Some(l) = e.get_typed(&a, &ct::KEYS)?.and_then(|k| k.inbox).map(|i| i.label) {
                    by.entry(l).or_default().push(a);
                }
            }
            Ok::<_, crate::error::Error>(Arc::new(by))
        };
        // a `keys.0` the store refused to read: no inbox known now, read again at the next ask
        Memo::get_in(self, |e| &e.core.inbox_actors, &(), read).unwrap_or_default()
    }

    /// Whether `g` has a label here.
    pub fn labeled(&mut self, g: &Tid) -> bool {
        !self.labels_of(g).is_empty()
    }

    /// The labels `label.0` of `g` records; records that do not parse are skipped.
    pub fn group_labels(&mut self, g: &Tid) -> Result<Vec<GroupLabel>> {
        Ok(self.labels_of(g).iter().map(|l| (**l).clone()).collect())
    }

    /// `group_labels`, shared: decoded once per write of the `label.0` (`Core::labels`). A
    /// `label.0` the store refuses to read gives none, and is read again at the next ask.
    pub fn labels_of(&mut self, g: &Tid) -> Vec<Arc<GroupLabel>> {
        self.labels_read(g).unwrap_or_default()
    }

    /// `labels_of`, with a read the store refused as the error: what a memo reading labels
    /// asks, so it keeps no answer built on a failed read.
    pub fn labels_read(&mut self, g: &Tid) -> Result<Vec<Arc<GroupLabel>>> {
        if self.core.created(g).is_none() {
            // a destroyed thing keeping nothing: the labels node-sync empties (`emptying`)
            return Ok(if self.emptying(g) { self.core.ix.destroyed_labels.get(g).cloned().unwrap_or_default() } else { Vec::new() });
        }
        Memo::get_in(self, |e| &e.core.labels, g, |e| {
            let mut out = Vec::new();
            for (id, l) in &e.get_typed(g, &ct::LABEL)?.unwrap_or_default() {
                out.extend(group_label(g, id, l).filter(|l| e.core.owns_label(g, &l.id, &l.steps)));
            }
            Ok::<_, crate::error::Error>(out)
        })
    }
}
