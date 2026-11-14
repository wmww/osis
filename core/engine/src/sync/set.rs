//! The sync set and what a reader of S acts with (spec/sync-set.md §1-§2, spec/sync-ids.md §3,
//! spec/sync-opens.md §4): the synced group's closure filtered by the secrets held, the recorded
//! path and the keys held per step, current read secrets, static entries, the claim key; and
//! this node's caps.

use super::{Caps, Holding, OwnedSyncId, ReadCredentials, SyncSet, ThingCaps, ThingSync};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_crypto::{Epoch, Secret32, SigningSecret, X25519Secret};
use osis_label::StepId;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;
use std::sync::Arc;

impl Engine {
    /// This node's synced group (spec/sync-set.md §1): its entry in `synced^.0` on its account's
    /// devices actor D; `None` before it has read one.
    pub(crate) fn synced_group(&mut self) -> Result<Option<Tid>> {
        let Some((_, d)) = self.core.account_devices() else { return Ok(None) };
        let me = self.core.id.tid();
        Ok(self.get_typed(&d, &ct::SYNCED)?.and_then(|m| m.get(&me).copied()))
    }

    /// The group whose closure this node syncs: its synced group, or before it has read one, its
    /// account's D (home's closure, spec/sync-set.md §1). `None` for a node of no account.
    pub(super) fn sync_root(&mut self) -> Result<Option<Tid>> {
        let home = self.core.account_devices().map(|(_, d)| d);
        Ok(self.synced_group()?.or(home))
    }

    /// The things every synced group of the account lists (`synced^.0`'s groups' closures): what
    /// an invitation is not in (spec/sync-set.md §4).
    pub(crate) fn synced_closures(&mut self) -> Result<BTreeSet<Tid>> {
        let Some((_, d)) = self.core.account_devices() else { return Ok(BTreeSet::new()) };
        let groups: Vec<Tid> = self.get_typed(&d, &ct::SYNCED)?.map(|m| m.into_values().collect()).unwrap_or_else(|| vec![d]);
        let mut out = BTreeSet::new();
        for g in groups {
            out.extend(self.closure(&g).iter().copied());
        }
        Ok(out)
    }

    /// Whether this node holds a read secret of `t` (spec/sync.md §3: read exactly while one is held).
    fn holds_read(&self, t: &Tid) -> bool {
        self.core.epochs(t).is_some_and(|e| e.role(Role::Read).holds_any())
    }

    /// The things the sync set is judged over (spec/sync-set.md §2): the synced group's closure
    /// (the engine's closure `Arc`, the same while it does not change), with each destroyed thing
    /// whose own sync IDs are being emptied (spec/sync-judgement.md §5). Walked through groups this
    /// node reads only: a thing kept unread lists nothing here.
    pub(crate) fn sync_things_now(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        let closure = match self.sync_root()? {
            Some(root) => self.closure(&root),
            None => Arc::new(BTreeSet::new()),
        };
        let mut emptying: Vec<Tid> = self.core.ix.destroyed_sync_ids.keys().filter(|t| self.core.ix.destroyed_secrets.contains(t)).copied().collect();
        // links being redeemed (spec/sync-set.md §2)
        emptying.extend(self.core.followed_links.keys().filter(|k| crate::labeling::actors::followable(self, k)).copied());
        if emptying.iter().all(|t| closure.contains(t)) {
            return Ok(closure);
        }
        Ok(Arc::new(closure.iter().copied().chain(emptying).collect()))
    }

    /// How this node syncs thing `t` of `sync_things` (spec/sync-set.md §2): its home sync ID read
    /// while a read secret of it is held (a destroyed thing being emptied: its own sync IDs), kept
    /// unread while only its sync record is; a thing with secrets of its own and neither is
    /// unsyncable; a plain thing has none of its own. Reads only `t`'s keys.
    pub(crate) fn thing_sync_now(&mut self, t: &Tid) -> Result<ThingSync> {
        if self.core.created(t).is_none() && self.core.ix.destroyed_secrets.contains(t) {
            let ids: Vec<SyncId> = self.owned_sync_ids(t)?.iter().map(|o| o.id).collect();
            if !ids.is_empty() {
                return Ok(ThingSync::Read(ids));
            }
        }
        if self.core.has_own_secrets(t)
            && self.holds_read(t)
            && let Some(home) = home_of(&self.owned_sync_ids(t)?)
        {
            return Ok(ThingSync::Read(vec![home]));
        }
        // a link being redeemed: its sync ID read while followed, whatever is held of K yet, while
        // it is K's (`followable`; from the link text until K's own `sync.0` records it)
        if let Some((s, _)) = self.core.followed_links.get(t).copied()
            && crate::labeling::actors::followable(self, t)
            && self.owned_sync_ids(t)?.iter().any(|o| o.id == s)
        {
            return Ok(ThingSync::Read(vec![s]));
        }
        if let Some(r) = self.core.ix.sync_records.get(t).cloned() {
            // a record's sync IDs are its payloads' word (spec/sync-inbox.md §2): one a held
            // `sync.0` gives another thing is that thing's, never kept unread for this one
            let mut ids = Vec::new();
            for s in &r.sync_ids {
                if self.sync_owner_of(s)?.is_none_or(|o| o == *t) {
                    ids.push(*s);
                }
            }
            return Ok(ThingSync::Unread(ids));
        }
        Ok(if self.core.has_own_secrets(t) { ThingSync::Unsyncable } else { ThingSync::Plain })
    }

    /// The sync set, whole (`sync_things` and `thing_sync` of each).
    pub(crate) fn sync_set_now(&mut self) -> Result<Arc<SyncSet>> {
        let mut set = SyncSet::default();
        for t in self.sync_things_now()?.iter() {
            match self.thing_sync(t)? {
                ThingSync::Read(ids) => set.ids.extend(ids.into_iter().map(|s| (s, (*t, Holding::Read)))),
                // two records naming one sync ID (both owners unknown here): the first keeps it
                ThingSync::Unread(ids) => {
                    for s in ids {
                        set.ids.entry(s).or_insert((*t, Holding::Unread));
                    }
                }
                ThingSync::Unsyncable => {
                    set.unsyncable.insert(*t);
                }
                ThingSync::Plain => {}
            }
        }
        Ok(Arc::new(set))
    }

    /// What a reader of `s` opens and acts with: its thing's recorded path's head, the keys held
    /// per recorded step, the current read secrets (`ActorEpochs::current`, the engine's Current
    /// with its history-less floors; with none current, the newest held, spec/sync-opens.md §4),
    /// and the static entries of the thing's read roster. `None` when `s` is no sync ID this node
    /// reads.
    pub(crate) fn read_credentials_now(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        let Some((t, o)) = self.read_sync_id(s)? else { return Ok(None) };
        let mut c = ReadCredentials { head: o.path.steps.last().map(|(s, _)| s.clone()), ..Default::default() };
        for (step, _) in &o.path.steps {
            c.keys.insert(step.id(), self.head_keys(&t, step)?);
        }
        c.read_secrets = self.current_read_secrets(&t);
        for k in self.static_listed(&t)? {
            c.statics.insert(osis_crypto::static_entry(s, &k));
        }
        if let Some((fs, l)) = self.core.followed_links.get(&t).copied()
            && fs == *s
            && let Some(id) = self.core.key_actors.get(&l)
        {
            c.acting.push(id.keys().signing.clone());
        }
        c.roster = self.roster_digest(&t);
        if let Some(e) = self.core.epochs(&t) {
            c.sync_keys = e.role(Role::Sync).held_newest_first().into_iter().map(|(ep, x)| (ep, osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, x))).collect();
            for (step, _) in o.path.steps.iter().rev() {
                let sync = e.role(Role::Sync).held_newest_first().into_iter().find(|(_, x)| osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, x).verifying_key() == step.keys.sync);
                if let Some((_, x)) = sync {
                    c.proofs.push((step.id(), osis_crypto::kdf::sync_proof(&osis_crypto::label_role_seed(osis_crypto::LabelRole::Sync, x))));
                }
            }
        }
        Ok(Some(Arc::new(c)))
    }

    /// Thing `t`'s read secrets at its current epochs (history-less floors), else its newest
    /// held: what an open of its sync ID proves and what a commit on it shows (spec/sync-inbox.md
    /// §2 Re-send).
    pub(crate) fn current_read_secrets(&self, t: &Tid) -> Vec<(Epoch, Secret32)> {
        let Some(e) = self.core.epochs(t) else { return Vec::new() };
        let read = e.role(Role::Read);
        let current: Vec<(Epoch, Secret32)> = read.current().into_iter().filter_map(|ep| Some((ep, read.secret(&ep)?.clone()))).collect();
        match current.is_empty() {
            true => read.held_newest_first().into_iter().take(1).map(|(ep, s)| (ep, s.clone())).collect(),
            false => current,
        }
    }

    /// The held valid rotation commits of read sync ID `s`'s thing whose established epoch
    /// supersedes read epoch `e` (spec/sync-opens.md §6: an ended member's `until`); empty when
    /// `s` is not read here or none does.
    pub(crate) fn rotations_superseding_now(&mut self, s: &SyncId, e: &Epoch) -> Result<Vec<CommitId>> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(Vec::new()) };
        let Some(ep) = self.core.epochs(&t) else { return Ok(Vec::new()) };
        let read = ep.role(Role::Read);
        Ok(read.epochs().filter(|(_, i)| i.established.is_some() && i.superseded_epochs().contains(e)).flat_map(|(_, i)| i.rotations.keys().copied()).collect())
    }

    /// The thing whose sync ID `s` is, read here, with its record (`sync_ids`).
    fn read_sync_id(&mut self, s: &SyncId) -> Result<Option<(Tid, OwnedSyncId)>> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(None) };
        if !matches!(self.thing_sync_now(&t)?, ThingSync::Read(ids) if ids.contains(s)) {
            return Ok(None);
        }
        Ok(self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s).map(|o| (t, o.clone())))
    }

    /// The claim key of this node for step `step` of `s` (spec/sync-ids.md §3): from the X25519
    /// half of a read KEM key it holds (its node key, its account's epoch keys, the read keysets
    /// of the actors holding the thing's reader actor that it holds), the one the step's claim set
    /// lists. `None` when no held key is listed (or the claim set is not held).
    pub(crate) fn claim_key_now(&mut self, s: &SyncId, step: &StepId) -> Result<Option<SigningSecret>> {
        let Some((t, o)) = self.read_sync_id(s)? else { return Ok(None) };
        let Some((st, Some(claims))) = o.path.steps.iter().find(|(x, _)| x.id() == *step) else { return Ok(None) };
        let listed: BTreeSet<[u8; 32]> = claims.claims.iter().copied().collect();
        let mut keys: Vec<X25519Secret> = vec![self.core.id.keys().kem.x25519().clone()];
        for a in self.core.accounts.keys().copied().collect::<Vec<_>>() {
            keys.extend(self.account_kems(&a).iter().map(|k| k.x25519().clone()));
        }
        let reader = self.core.reader_of(&t);
        for (m, _) in self.core.key_holders(&reader) {
            if let Some(e) = self.core.epochs(&m) {
                keys.extend(e.role(Role::Read).held_newest_first().into_iter().map(|(_, s)| osis_crypto::role_kem(s).x25519().clone()));
            }
        }
        for k in &keys {
            if let Ok(c) = st.claim_key(k)
                && listed.contains(&c.verifying_key().to_bytes())
            {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    /// The thing that owns sync ID `s` here by its `sync.0` (`sync_ids`); `None` when none does.
    pub(crate) fn sync_owner_of(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        let mut things: Vec<Tid> = self.core.ix.sync_recorders.get(s).into_iter().flatten().copied().collect();
        // a thing a taken inbox blob named it for (O(hints held))
        things.extend(self.core.ix.inbox_hints.iter().filter(|(_, x)| x.0 == *s).map(|(t, _)| *t));
        things.extend(self.core.followed_links.iter().filter(|(_, x)| x.0 == *s).map(|(t, _)| *t));
        for t in things {
            if self.owned_sync_ids(&t)?.iter().any(|o| o.id == *s) {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    /// The digest of `t`'s roster as J reads it: its reader actor's holders for keys with their
    /// roles (`key_holders`), sorted.
    fn roster_digest(&self, t: &Tid) -> [u8; 32] {
        let a = self.core.reader_of(t);
        let mut holders = self.core.key_holders(&a);
        holders.sort();
        let v = osis_base::Value::List(holders.into_iter().map(|(m, r)| osis_base::Value::List(vec![osis_base::Value::Tid(m), osis_base::Value::Int(i64::from(r.id()))])).collect());
        osis_base::hash::hash(&osis_base::encode(&v))
    }

    /// `caps^.0` of this node (spec/data-model.md §9; absent: the defaults, an empty policy).
    pub(crate) fn caps_now(&mut self) -> Result<Arc<Caps>> {
        let me = self.core.id.tid();
        let c = self.get_typed(&me, &ct::CAPS)?.unwrap_or_default();
        Ok(Arc::new(Caps { policy: c.policy, things: c.things.into_iter().map(|(t, x)| (t, ThingCaps { entries: x.entries, bytes: x.bytes })).collect() }))
    }
}

/// A thing's home sync ID among those it owns (two admins giving it secrets at once made two: the
/// higher ID, as `flows::home_sync_id`).
fn home_of(ids: &[OwnedSyncId]) -> Option<SyncId> {
    ids.iter().map(|o| o.id).max()
}
