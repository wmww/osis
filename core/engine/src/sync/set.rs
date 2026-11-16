//! The sync set and what a reader of S acts with (spec/sync-ids.md §3, spec/sync-opens.md §4):
//! the node closure filtered by the secrets held, the recorded
//! path and the keys held per step, current read secrets, static entries, the claim key; and
//! this node's caps.

use super::{Caps, Holding, OwnedSyncId, ReadCredentials, SyncSet, ThingCaps, ThingSync};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_crypto::{Epoch, Secret32, SigningSecret, X25519Secret};
use osis_blob::StepId;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

impl Engine {
    /// Whether this node holds a read secret of `t` (spec/sync.md §3: read exactly while one is held).
    fn holds_read(&self, t: &Tid) -> bool {
        self.core.epochs(t).is_some_and(|e| e.role(Role::Read).holds_any())
    }

    /// The things the sync set is judged over: the node closure (spec/sync-set.md §2) walked
    /// through no thing sourced at another node (§5, `Closure::synced`), with the links being
    /// redeemed. A memo of
    /// the whole, for a listing: per thing `in_sync_things`, entering `things_entered`.
    pub fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_things, &(), |e| {
            let mut out: BTreeSet<Tid> = e.core.ix.closure.synced_things().copied().collect();
            osis_base::costs::count("sync: things walked", out.len() as u64);
            out.extend(e.core.followed_links.all().keys().filter(|k| crate::sync_ids::actors::followable(e, k)).copied());
            Ok(Arc::new(out))
        })
    }

    /// `sync_things`'s answer for `t` alone: reads only `t`'s rows.
    pub fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        Ok(crate::sync_ids::actors::followable(self, t) || self.core.ix.closure.synced(t))
    }

    /// The things that may have entered `sync_things` since `f`'s last read (its first: every
    /// one): each that entered the sync set's walk since, and the links being
    /// redeemed (few). Leaving needs no feed: `in_sync_things` moves.
    pub(crate) fn things_entered(&mut self, f: &mut super::ThingsFeed) -> Result<Vec<Tid>> {
        let Some(at) = f.0.as_mut() else {
            let ix = &self.core.ix;
            f.0 = Some(super::Entered { held: ix.closure.synced_feed() });
            return Ok(self.sync_things()?.iter().copied().collect());
        };
        let mut out = at.held.added();
        out.extend(self.core.followed_links.all().keys().copied());
        osis_base::costs::count("sync: things entered", out.len() as u64);
        Ok(out)
    }

    /// Sets the sync units the handle reads and writes at another node (spec/sync-set.md §5):
    /// `elsewhere`, of which those also in `homing` (moved home, catching up) sync here; the
    /// others `sync_things` walks no path through, the account root aside: it is never cut. A
    /// client of this node reads nothing of any of them (`readable_by`). Between transactions.
    pub fn set_sourced(&mut self, elsewhere: BTreeSet<Tid>, homing: &BTreeSet<Tid>) -> Result<()> {
        let root = self.account_root();
        let cut: BTreeSet<Tid> = elsewhere.difference(homing).filter(|g| Some(**g) != root && Some(**g) != self.core.node_root).copied().collect();
        self.core.ix.closure.set_cut(self.core.node_root, cut)?;
        self.core.sourced_elsewhere = elsewhere;
        Ok(())
    }

    /// Whether sync unit `g` syncs here (spec/sync-set.md §5): the sync set's walk reaches it and
    /// it is synced under a sync ID of its own. Reads only `g`'s rows.
    pub fn syncs_here(&mut self, g: &Tid) -> Result<bool> {
        Ok(self.in_sync_things(g)? && matches!(self.thing_sync(g)?, ThingSync::Read(ids) | ThingSync::Unread(ids) if !ids.is_empty()))
    }

    /// spec/sync-set.md §5 (moving home): history is complete here for sync unit `g` and each
    /// thing of it the sync set holds (spec/sync-status.md §3): each sync ID of the sync set
    /// carrying one of them, read here, has a complete pass noted. True when none does. A memo
    /// per sync unit.
    pub fn caught_up(&mut self, g: &Tid) -> Result<bool> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.caught_up, g, |e| e.caught_up_fresh(g))
    }

    fn caught_up_fresh(&mut self, g: &Tid) -> Result<bool> {
        let mut ids = self.carrying_now(g, true)?;
        for x in self.sync_unit(g).iter() {
            if self.in_sync_things(x)? {
                ids.extend(self.carrying_now(x, true)?);
            }
        }
        for s in ids {
            if self.sync_holder(&s)?.is_some_and(|(_, h)| h == Holding::Read) && !self.core.ix.passes.contains_key(&s) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// How this node syncs thing `t` of `sync_things`: its home sync ID read while a read secret
    /// of it is held; a thing with secrets of its own and none is unsyncable; a plain thing has none of its own. Reads only `t`'s keys.
    pub(crate) fn thing_sync_now(&mut self, t: &Tid) -> Result<ThingSync> {
        // read: by its own keys, or on a ticket's word (its sync ID the ticket's until a held
        // `sync.0` records it, spec/sync-inbox.md §5 Ticket sync IDs)
        if (self.core.has_own_secrets(t) || self.core.ix.closure.on_ticket(t))
            && self.holds_read(t)
        {
            let ids = synced(&self.owned_sync_ids(t)?);
            if !ids.is_empty() {
                return Ok(ThingSync::Read(ids));
            }
        }
        // a link being redeemed: its sync ID read while followed, whatever is held of K yet, while
        // it is K's (`followable`; from the link text until K's own `sync.0` records it)
        if let Some((s, _)) = self.core.followed_links.get(t)
            && crate::sync_ids::actors::followable(self, t)
            && self.owned_sync_ids(t)?.iter().any(|o| o.id == s)
        {
            return Ok(ThingSync::Read(vec![s]));
        }
        // kept unread: in the node closure by a sync secret alone (spec/sync.md §3)
        if self.kept_unread(t) {
            let ids = synced(&self.owned_sync_ids(t)?);
            if !ids.is_empty() {
                return Ok(ThingSync::Unread(ids));
            }
        }
        Ok(if self.core.has_own_secrets(t) { ThingSync::Unsyncable } else { ThingSync::Plain })
    }

    /// The sync set, whole (`sync_things` and `thing_sync` of each), each sync ID's entry folded
    /// as `rows` folds it.
    pub(crate) fn sync_set_now(&mut self) -> Result<Arc<SyncSet>> {
        let mut by_sync: BTreeMap<SyncId, BTreeMap<Tid, Holding>> = BTreeMap::new();
        let mut set = SyncSet::default();
        let things = self.sync_things()?;
        osis_base::costs::count("sync: set folded", things.len() as u64);
        for t in things.iter() {
            let (ids, h) = match self.thing_sync(t)? {
                ThingSync::Read(ids) => (ids, Holding::Read),
                ThingSync::Unread(ids) => (ids, Holding::Unread),
                ThingSync::Unsyncable => {
                    set.unsyncable.insert(*t);
                    continue;
                }
                ThingSync::Plain => continue,
            };
            for s in ids {
                by_sync.entry(s).or_default().insert(*t, h);
            }
        }
        set.ids = by_sync.iter().filter_map(|(s, m)| Some((*s, super::rows::fold(m)?))).collect();
        Ok(Arc::new(set))
    }

    /// What a reader of `s` opens and acts with: per thing whose read secrets open `s`
    /// (`opening_things`, each one judged), its recorded path's head and the keys held per
    /// recorded step, its current read secrets (`ActorEpochs::current`, the engine's Current with
    /// its history-less floors; with none current, the newest held, spec/sync-opens.md §4), and
    /// the static entries of its read roster. `None` when `s` is no sync ID this node reads.
    pub(crate) fn read_credentials_now(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        let things = self.opening_things(s)?;
        if things.is_empty() {
            return Ok(None);
        }
        let mut c = ReadCredentials::default();
        for t in things {
            let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s).cloned() else { continue };
            self.credentials_of(&mut c, s, &t, &o)?;
        }
        Ok(Some(Arc::new(c)))
    }

    /// Adds what thing `t` of `s` (owning it as `o`) opens and acts with to `c`.
    fn credentials_of(&mut self, c: &mut ReadCredentials, s: &SyncId, t: &Tid, o: &OwnedSyncId) -> Result<()> {
        if let Some((st, _)) = o.path.steps.last() {
            c.head = Some(st.clone());
        }
        for (step, _) in &o.path.steps {
            c.keys.insert(step.id(), self.head_keys(t, step)?);
        }
        c.read_secrets.extend(self.current_read_secrets(t));
        for k in self.static_listed(t)? {
            c.statics.insert(osis_crypto::static_entry(s, &k));
        }
        if let Some((fs, l)) = self.core.followed_links.get(t)
            && fs == *s
            && let Some(id) = self.core.key_actors.get(&l)
        {
            c.acting.push(id.keys().signing.clone());
        }
        if let Some(e) = self.core.epochs(t) {
            // each held sync secret's key derived once (a curve multiplication), then matched per step
            let held: Vec<(Epoch, Secret32, SigningSecret)> = e
                .role(Role::Sync)
                .held_newest_first()
                .into_iter()
                .map(|(ep, x)| {
                    let seed = osis_crypto::role_key_seed(osis_crypto::RoleKey::Sync, x);
                    (ep, seed.clone(), SigningSecret::from_seed(&seed))
                })
                .collect();
            for (step, _) in o.path.steps.iter().rev() {
                if let Some((_, seed, _)) = held.iter().find(|(_, _, k)| k.verifying_key() == step.keys.sync) {
                    c.proofs.push((step.id(), osis_crypto::kdf::sync_proof(seed)));
                }
            }
            c.sync_keys.extend(held.into_iter().map(|(ep, _, k)| (ep, k)));
        }
        Ok(())
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

    /// The held valid rotation commits of read sync ID `s`'s things whose established epoch
    /// supersedes read epoch `e` (spec/sync-opens.md §6: an ended member's `until`); empty when
    /// `s` is not read here or none does.
    pub fn rotations_superseding(&mut self, s: &SyncId, e: &Epoch) -> Result<Vec<CommitId>> {
        let mut out = Vec::new();
        for t in self.opening_things(s)? {
            let Some(ep) = self.core.epochs(&t) else { continue };
            let read = ep.role(Role::Read);
            out.extend(read.epochs().filter(|(_, i)| i.established.is_some() && i.superseded_epochs().contains(e)).flat_map(|(_, i)| i.rotations.keys().copied()));
        }
        Ok(out)
    }

    /// The thing whose recorded path `s` is (an entry of its `sync.0`, no hint), read here or by
    /// the read secrets of it still held (`opening_things`: a sync ID sync still syncs after it
    /// left the sync set), with that record. A rule reading S's steps or its actor's keys acts on
    /// it alone; a sync ID only tickets name records no path, so none.
    pub(crate) fn read_sync_id(&mut self, s: &SyncId) -> Result<Option<(Tid, OwnedSyncId)>> {
        for t in self.opening_things(s)? {
            if let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint) {
                return Ok(Some((t, o.clone())));
            }
        }
        Ok(None)
    }

    /// The claim key of this node for step `step` of `s` (spec/sync-ids.md §3): from the X25519
    /// half of a read KEM key it holds (its node key, its account's epoch keys, the read keysets
    /// of the actors holding the thing's reader actor that it holds), the one the step's claim set
    /// lists. `None` when no held key is listed (or the claim set is not held).
    pub fn claim_key(&mut self, s: &SyncId, step: &StepId) -> Result<Option<SigningSecret>> {
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

    /// `s`'s things and how this node holds `s`: every thing owning `s` (`sync_things_of`) whose
    /// `thing_sync` lists it, read while any reads it (`rows::fold`). The sync set's entry for
    /// `s` when the closure holds them.
    pub fn sync_holder(&mut self, s: &SyncId) -> Result<Option<super::Held>> {
        let mut m = BTreeMap::new();
        for t in self.sync_things_of(s)? {
            match self.thing_sync(&t)? {
                ThingSync::Read(ids) if ids.contains(s) => m.insert(t, Holding::Read),
                ThingSync::Unread(ids) if ids.contains(s) => m.insert(t, Holding::Unread),
                _ => None,
            };
        }
        Ok(super::rows::fold(&m))
    }

    /// The thing of `s`'s things whose `sync.0` records `s` (no hint), with that record: what a
    /// rule reading S's steps acts on. A sync ID only tickets name records no path, so none.
    pub(crate) fn recorded_owner(&mut self, s: &SyncId) -> Result<Option<(Tid, OwnedSyncId)>> {
        for t in self.sync_things_of(s)? {
            if let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint) {
                return Ok(Some((t, o.clone())));
            }
        }
        Ok(None)
    }

    /// `s`'s things: every thing owning sync ID `s` here (`owned_sync_ids` lists it), by a held
    /// `sync.0`, as a followed link's, or on the word of the
    /// held tickets naming it (spec/sync-inbox.md §5 Ticket sync IDs: a sync ID several things'
    /// tickets name is each one's, whatever their order).
    pub(crate) fn sync_things_of(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        let mut things: BTreeSet<Tid> = self.core.ix.sync_recorders.get(s).into_iter().flatten().copied().collect();
        things.extend(self.core.followed_links.naming(s));
        // a thing whose held tickets name it (`ticket_hints`)
        things.extend(self.core.ix.closure.naming_ticket_id(s));
        let mut out = Vec::new();
        for t in things {
            if self.owned_sync_ids(&t)?.iter().any(|o| o.id == *s) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// `caps^.0` of this node, on its node root (spec/data-model.md §9, spec/sync-set.md §1;
    /// absent: the defaults, an empty policy).
    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        let Some(root) = self.core.node_root else { return Ok(Arc::default()) };
        let c = self.get_typed(&root, &ct::CAPS)?.unwrap_or_default();
        Ok(Arc::new(Caps { policy: c.policy, things: c.things.into_iter().map(|(t, x)| (t.0, ThingCaps { entries: x.entries, bytes: x.bytes })).collect() }))
    }
}

/// The sync IDs synced for a thing owning `ids`: its home among those a held `sync.0` records
/// (two admins giving it secrets at once made two: the higher ID, as `flows::home_sync_id`), and
/// each its tickets name that no held `sync.0` records (their issuers' word, spec/sync-inbox.md §5
/// Ticket sync IDs): a forged one beside the genuine keeps the genuine one fetched, and a node
/// holding one admin's record reaches the other's. Empty when it owns none.
fn synced(ids: &[OwnedSyncId]) -> Vec<SyncId> {
    let ticket = |o: &&OwnedSyncId| o.hint && o.path.steps.is_empty();
    let home = ids.iter().filter(|o| !ticket(o)).map(|o| o.id).max();
    home.into_iter().chain(ids.iter().filter(ticket).map(|o| o.id)).collect()
}
