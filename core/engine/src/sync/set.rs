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
    /// through no thing sourced at another node (§5, `Closure::synced`), with the holders held
    /// for keys and the links being redeemed. A holder held for keys syncs its sync ID for role
    /// entries alone (`thing_holdings`). A memo of
    /// the whole, for a listing: per thing `in_sync_things`, entering `things_entered`.
    pub fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_things, &(), |e| {
            let mut out: BTreeSet<Tid> = e.core.ix.closure.synced_things().copied().collect();
            out.extend(e.core.ix.closure.keys().copied());
            osis_base::costs::count("sync: things walked", out.len() as u64);
            out.extend(e.core.followed_links.all().keys().filter(|k| crate::sync_ids::actors::followable(&e.core, k)).copied());
            Ok(Arc::new(out))
        })
    }

    /// `sync_things`'s answer for `t` alone: reads only `t`'s rows.
    pub fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        Ok(crate::sync_ids::actors::followable(&self.core, t) || self.core.ix.closure.synced(t) || self.core.ix.closure.for_keys(t))
    }

    /// The things that may have entered `sync_things` since `f`'s last read (its first: every
    /// one): each that entered the sync set's walk since, and each link followed since (a link
    /// stays followable from its follow until K is made as no link's, so one followed before
    /// that left enters again only by being followed again). Leaving needs no feed:
    /// `in_sync_things` moves.
    pub(crate) fn things_entered(&mut self, f: &mut super::ThingsFeed) -> Result<Vec<Tid>> {
        let Some(at) = f.0.as_mut() else {
            let ix = &self.core.ix;
            f.0 = Some(super::Entered { held: ix.closure.synced_feed(), keys: ix.closure.keys_feed(), links: self.core.followed_links.followed_feed() });
            return Ok(self.sync_things()?.iter().copied().collect());
        };
        let mut out = at.held.added();
        out.extend(at.keys.added());
        out.extend(at.links.added());
        osis_base::costs::count("sync: things entered", out.len() as u64);
        Ok(out)
    }

    /// Sets the sync units the handle reads and writes at another node (spec/sync-set.md §5):
    /// `elsewhere`, of which those also in `moving_back` (moving back, catching up) sync here; the
    /// others `sync_things` walks no path through, the node root aside: it is never cut. A
    /// client of this node reads nothing of any of them (`readable_by`). Between transactions.
    pub fn set_sourced(&mut self, elsewhere: BTreeSet<Tid>, moving_back: &BTreeSet<Tid>) -> Result<()> {
        let cut: BTreeSet<Tid> = elsewhere.difference(moving_back).filter(|g| Some(**g) != self.core.node_root).copied().collect();
        self.core.ix.closure.set_cut(self.core.node_root, cut)?;
        self.core.sourced_elsewhere = elsewhere;
        Ok(())
    }

    /// Whether sync unit `g` syncs here (spec/sync-set.md §5): the sync set's walk reaches it and
    /// it is synced under a sync ID of its own. Reads only `g`'s rows.
    pub fn syncs_here(&mut self, g: &Tid) -> Result<bool> {
        Ok(self.in_sync_things(g)? && matches!(self.thing_sync(g)?, ThingSync::Read(ids) | ThingSync::Unread(ids) if !ids.is_empty()))
    }

    /// spec/sync-set.md §5 (Moving back): history is complete here for sync unit `g` and each
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
            // history is the content's: a sync ID held for keys carries none of it here
            if self.sync_holder(&s)?.is_some_and(|(_, h)| h == Holding::Read) && !self.core.ix.passes.contains_key(&s) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// How this node syncs thing `t` of `sync_things`: its sync ID read while a read secret
    /// of it is held; an independent thing and none is unsyncable; a dependent thing has none of its own. Reads only `t`'s keys.
    pub(crate) fn thing_sync_now(&mut self, t: &Tid) -> Result<ThingSync> {
        // read: by its own secrets, independent by a box alone (spec/permissions.md §4 Key part:
        // an edge piece holds no rotation that made a granted epoch current, which is a body
        // under the sync ID it opens)
        if self.core.counts_independent(t) && self.holds_read(t) {
            let ids = synced(&self.owned_sync_ids(t)?);
            if !ids.is_empty() {
                return Ok(ThingSync::Read(ids));
            }
        }
        // a link being redeemed: its sync ID read while followed, whatever is held of K yet, while
        // it is K's (`followable`; from the link text until K's own `sync.0` records it)
        if let Some((s, _)) = self.core.followed_links.get(t)
            && crate::sync_ids::actors::followable(&self.core, t)
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
        Ok(if self.core.is_independent(t) { ThingSync::Unsyncable } else { ThingSync::Dependent })
    }

    /// The sync IDs thing `t` of `sync_things` is synced under, each with how it is held
    /// (spec/sync.md §3): read by a read secret of a thing the node closure reads, for keys by
    /// one of a holder held for keys (spec/sync-set.md §2), kept unread by a sync secret alone.
    /// Reads `t`'s keys and whether it is held for keys.
    pub(crate) fn thing_holdings(&mut self, t: &Tid) -> Result<Vec<(SyncId, Holding)>> {
        Ok(match self.thing_sync(t)? {
            ThingSync::Read(ids) => {
                // a link being redeemed is read whatever else holds its thing
                let h = if self.core.ix.closure.for_keys(t) && !crate::sync_ids::actors::followable(&self.core, t) { Holding::Keys } else { Holding::Read };
                ids.into_iter().map(|s| (s, h)).collect()
            }
            ThingSync::Unread(ids) => ids.into_iter().map(|s| (s, Holding::Unread)).collect(),
            ThingSync::Unsyncable | ThingSync::Dependent => Vec::new(),
        })
    }

    /// The sync set, whole (`sync_things` and `thing_holdings` of each), each sync ID's entry
    /// folded as `rows` folds it.
    pub(crate) fn sync_set_now(&mut self) -> Result<Arc<SyncSet>> {
        let mut by_sync: BTreeMap<SyncId, BTreeMap<Tid, Holding>> = BTreeMap::new();
        let mut set = SyncSet::default();
        let things = self.sync_things()?;
        osis_base::costs::count("sync: set folded", things.len() as u64);
        for t in things.iter() {
            if self.thing_sync(t)? == ThingSync::Unsyncable {
                set.unsyncable.insert(*t);
            }
            for (s, h) in self.thing_holdings(t)? {
                by_sync.entry(s).or_default().insert(*t, h);
            }
        }
        set.ids = by_sync.iter().filter_map(|(s, m)| Some((*s, super::rows::fold(m)?))).collect();
        Ok(Arc::new(set))
    }

    /// What a reader of `s` opens and acts with: per thing whose read secrets open `s`
    /// (`opening_things`, each one judged), its recorded path's head and the keys held per
    /// recorded step, its current read secrets (the engine's Current with
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

    /// The write key this node holds at step `step` of `s` (`read_credentials`' keys there,
    /// `write`): what it stamps under at that step. Kept per (sync ID, step) from its first ask
    /// (`Core::step_write_keys`, a `memo::Cutoff`, refreshed by `follow`): every entry of `s`
    /// judged reads it, while what it is derived from (the things opening `s`, their sync IDs
    /// and epochs) moves at each link or key of theirs.
    pub fn step_write_key(&mut self, s: &SyncId, step: &StepId) -> Result<Option<SigningSecret>> {
        Ok(osis_base::memo::Cutoff::get_in(self, |e| &e.core.step_write_keys, &(*s, *step), |e, (s, step)| e.step_write_key_now(s, step))?.0)
    }

    /// `step_write_key` derived anew: as `credentials_of` keys each step, the last thing opening
    /// `s` whose recorded path has `step`.
    pub(crate) fn step_write_key_now(&mut self, s: &SyncId, step: &StepId) -> Result<WriteKey> {
        let mut out = None;
        for t in self.opening_things(s)? {
            let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s).cloned() else { continue };
            if let Some((st, _)) = o.path.steps.iter().find(|(st, _)| st.id() == *step) {
                out = self.head_write_key(&t, st);
            }
        }
        Ok(WriteKey(out))
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
            && let Some(id) = self.core.link_keys.get(&l)
        {
            c.acting.push(id.signing().clone());
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
    /// it alone; a sync ID only a followed link names records no path, so none.
    pub(crate) fn read_sync_id(&mut self, s: &SyncId) -> Result<Option<(Tid, OwnedSyncId)>> {
        for t in self.opening_things(s)? {
            if let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint) {
                return Ok(Some((t, o.clone())));
            }
        }
        Ok(None)
    }

    /// The claim key of this node for step `step` of `s` (spec/sync-ids.md §3): from the X25519
    /// half of a read KEM key it holds (its node thing's read keysets, those of the things holding
    /// the thing's independent that it holds), the one the step's claim set lists. `None` when no held key is listed (or the claim set is not held).
    pub fn claim_key(&mut self, s: &SyncId, step: &StepId) -> Result<Option<SigningSecret>> {
        let Some((t, o)) = self.read_sync_id(s)? else { return Ok(None) };
        let Some((st, Some(claims))) = o.path.steps.iter().find(|(x, _)| x.id() == *step) else { return Ok(None) };
        let listed: BTreeSet<[u8; 32]> = claims.claims.iter().copied().collect();
        let mut keys: Vec<X25519Secret> = Vec::new();
        let reader = self.core.reader_of(&t);
        let me = self.core.me();
        for m in std::iter::once(me).chain(self.core.key_holders(&reader).into_iter().map(|(m, _)| m).filter(|m| *m != me)) {
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
            if let Some((_, h)) = self.thing_holdings(&t)?.into_iter().find(|(x, _)| x == s) {
                m.insert(t, h);
            }
        }
        Ok(super::rows::fold(&m))
    }

    /// The thing of `s`'s things whose `sync.0` records `s` (no hint), with that record: what a
    /// rule reading S's steps acts on. A sync ID only a followed link names records no path, so none.
    pub(crate) fn recorded_owner(&mut self, s: &SyncId) -> Result<Option<(Tid, OwnedSyncId)>> {
        for t in self.sync_things_of(s)? {
            if let Some(o) = self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint) {
                return Ok(Some((t, o.clone())));
            }
        }
        Ok(None)
    }

    /// The held sync secrets of kept-unread `s`'s things, by epoch: those its boxes give and
    /// those held from the node's own reading (a node lowered to sync keeps its sync secrets,
    /// `rotation::lost`); every one of its things alike (spec/sync.md §3 Kept sync IDs, Held
    /// sync secrets).
    pub fn kept_sync_secrets(&mut self, s: &SyncId) -> Vec<(osis_crypto::Epoch, osis_crypto::Secret32)> {
        let Ok(things) = self.sync_things_of(s) else { return Vec::new() };
        let mut out = Vec::new();
        for t in things {
            if let Some(e) = self.core.epochs(&t) {
                out.extend(e.role(osis_base::Role::Sync).held_newest_first().into_iter().map(|(ep, x)| (ep, x.clone())));
            }
        }
        out
    }

    /// `s`'s things: every thing owning sync ID `s` here (`owned_sync_ids` lists it), by a held
    /// `sync.0` or as a followed link's.
    pub(crate) fn sync_things_of(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        let mut things: BTreeSet<Tid> = self.core.ix.sync_recorders.get(s).into_iter().flatten().copied().collect();
        things.extend(self.core.followed_links.naming(s));
        let mut out = Vec::new();
        for t in things {
            if self.owned_sync_ids(&t)?.iter().any(|o| o.id == *s) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// The thing holding this node's settings: its node root's `settings^.0` (spec/sync-set.md
    /// §1), written only by this node.
    pub fn settings_thing(&mut self) -> Result<Option<Tid>> {
        let Some(root) = self.core.node_root else { return Ok(None) };
        Ok(self.get_typed(&root, &ct::SETTINGS)?.map(|w| w.0))
    }

    /// This node's caps: its node thing's entry in the `caps^.0` of the thing holding its
    /// settings (spec/data-model.md §9, spec/sync-set.md §1; absent: the defaults, an empty
    /// policy). That thing's admins write the entry; what it may set is storage limits alone.
    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        let Some(s) = self.settings_thing()? else { return Ok(Arc::default()) };
        let me = osis_schema::Codec::to_value(&osis_base::Weak(self.core.me()));
        let c = match self.get_at(&s, &ct::CAPS.name(), &[osis_crdt::PathSeg::Key(me)])? {
            Some(v) => <ct::Caps as osis_schema::Codec>::from_value(&v).unwrap_or_default(),
            None => ct::Caps::default(),
        };
        Ok(Arc::new(Caps { policy: c.policy, things: c.things.into_iter().map(|(t, x)| (t.0, ThingCaps { entries: x.entries, bytes: x.bytes })).collect() }))
    }
}

/// A write key, told apart by its public key (`Core::step_write_keys`' rows).
#[derive(Clone)]
pub(crate) struct WriteKey(pub(crate) Option<SigningSecret>);

impl PartialEq for WriteKey {
    fn eq(&self, o: &WriteKey) -> bool {
        self.0.as_ref().map(SigningSecret::verifying_key) == o.0.as_ref().map(SigningSecret::verifying_key)
    }
}

impl std::fmt::Debug for WriteKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.as_ref().map(SigningSecret::verifying_key).fmt(f)
    }
}

/// The sync IDs synced for a thing owning `ids`: its sync ID, the greatest a held `sync.0` records
/// (two admins giving it secrets at once made two, as `flows::sync_id_of`), and
/// the one a followed link names that no held `sync.0` records (the link text's word,
/// `sync_ids::actors::followed`). Empty when it owns none.
fn synced(ids: &[OwnedSyncId]) -> Vec<SyncId> {
    let linked = |o: &&OwnedSyncId| o.hint && o.path.steps.is_empty();
    let own = ids.iter().filter(|o| !linked(o)).map(|o| o.id).max();
    own.into_iter().chain(ids.iter().filter(linked).map(|o| o.id)).collect()
}
