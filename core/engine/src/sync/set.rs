//! The sync set and what a reader of S acts with (spec/sync-ids.md §3, spec/sync-opens.md §4):
//! the node closure filtered by the secrets held, the recorded path and the keys held per step;
//! and this node's caps.

use super::{Caps, Holding, OwnedSyncId, ReadCredentials, SyncSet, ThingCaps, ThingSync};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_crypto::{Epoch, Secret32, SigningSecret};
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
            out.extend(e.core.followed_links.all().keys().filter(|k| crate::sync_ids::actors::followable(&e.core, k)).copied());
            Ok(Arc::new(out))
        })
    }

    /// `sync_things`'s answer for `t` alone: reads only `t`'s rows.
    pub fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        let cl = &self.core.ix.closure;
        Ok(crate::sync_ids::actors::followable(&self.core, t) || cl.synced(t))
    }

    /// The things that may have entered `sync_things` since `f`'s last read (its first: every
    /// one): each that entered the sync set's walk since, and each link followed since (a link
    /// stays followable from its follow until K is made as no link's, so one followed before
    /// that left enters again only by being followed again). Leaving needs no feed:
    /// `in_sync_things` moves.
    pub(crate) fn things_entered(&mut self, f: &mut super::ThingsFeed) -> Result<Vec<Tid>> {
        let Some(at) = f.0.as_mut() else {
            let ix = &self.core.ix;
            f.0 = Some(super::Entered { held: ix.closure.synced_feed(), links: self.core.followed_links.followed_feed() });
            return Ok(self.sync_things()?.iter().copied().collect());
        };
        let mut out = at.held.added();
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
            // history is the content's: a sync ID held as a stub carries none of it here
            if self.sync_holder(&s)?.is_some_and(|(_, h)| h == Holding::Read) && !self.core.ix.passes.contains_key(&s) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// How this node syncs thing `t` of `sync_things`: its sync ID read while a read secret
    /// of it is held; an independent thing and none is unsyncable; a dependent thing has none of its own. Reads only `t`'s keys.
    pub(crate) fn thing_sync_now(&mut self, t: &Tid) -> Result<ThingSync> {
        // read: by its own secrets, independent by a box alone (a grantee holds no rotation that
        // made a granted epoch current: it is a body under the sync ID the box opens)
        if self.core.counts_independent(t) && self.holds_read(t) {
            // its sync ID (spec/sync-ids.md §4 Owner), or the ones a followed link names
            let ids: Vec<SyncId> = self.owned_sync_ids(t)?.iter().map(|o| o.id).collect();
            if !ids.is_empty() {
                return Ok(ThingSync::Read(ids));
            }
        }
        // kept unread: the node closure keeps it unread (spec/sync-set.md §2: a strong reaches it
        // at sync); a thing held as a stub alone is followed as one, whatever secrets it holds
        if self.kept_unread(t) {
            // the sync ID kept for it (spec/sync.md §3 Kept for T)
            let ids: Vec<SyncId> = self.owned_sync_ids(t)?.iter().map(|o| o.id).collect();
            if !ids.is_empty() {
                return Ok(ThingSync::Unread(ids));
            }
        }
        // a link or signals followed, where no secret held syncs it: each sync ID followed read
        // while followed, whatever is held of K yet, while it is K's (`followable`, and no other
        // thing's by the owner rule; from the link text until K's own `sync.0` records it)
        if let Some((ids, _)) = self.core.followed_links.get(t)
            && crate::sync_ids::actors::followable(&self.core, t)
        {
            let owned = self.owned_sync_ids(t)?;
            let ids: Vec<SyncId> = ids.into_iter().filter(|s| owned.iter().any(|o| o.id == *s)).collect();
            if !ids.is_empty() {
                return Ok(ThingSync::Read(ids));
            }
        }
        // held as a stub by a sync-only cut: the sync ID it names is followed (spec/sync.md §3
        // Kept for T), its holders' claim keys open it (spec/permissions.md §4 Stub)
        let cut = self.core.cut_sync_ids(t);
        if !cut.is_empty() && self.core.ix.closure.stub_only(t) {
            let owned = self.owned_sync_ids(t)?;
            let ids: Vec<SyncId> = cut.into_iter().filter(|s| owned.iter().any(|o| o.id == *s)).collect();
            if !ids.is_empty() {
                return Ok(ThingSync::Read(ids));
            }
        }
        Ok(if self.core.is_independent(t) { ThingSync::Unsyncable } else { ThingSync::Dependent })
    }

    /// The sync IDs thing `t` of `sync_things` is synced under, each with how it is held
    /// (spec/sync.md §3): read by a read secret of a thing the node closure reads, or followed;
    /// as a stub where it is held as a stub alone (spec/sync-set.md §2 Holding a stub: its role
    /// entries alone), whatever it holds of it; kept unread by a sync secret alone. Reads `t`'s keys.
    pub(crate) fn thing_holdings(&mut self, t: &Tid) -> Result<Vec<(SyncId, Holding)>> {
        let read = if self.core.ix.closure.stub_only(t) { Holding::Stub } else { Holding::Read };
        Ok(match self.thing_sync(t)? {
            ThingSync::Read(ids) => ids.into_iter().map(|s| (s, read)).collect(),
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
    /// (`opening_things`, each one judged), its recorded path's head, the keys held per recorded
    /// step and the sync proofs and keys of the sync secrets held. `None` when `s` is no sync ID
    /// this node reads.
    pub(crate) fn read_credentials_now(&mut self, s: &SyncId) -> Result<Option<Arc<ReadCredentials>>> {
        let opening = self.opening_things(s)?;
        let things = if opening.is_empty() { self.sync_things_of(s)? } else { opening.clone() };
        if things.is_empty() {
            return Ok(None);
        }
        let mut c = ReadCredentials::default();
        for t in &opening {
            let Some(o) = self.owned_sync_ids(t)?.iter().find(|o| o.id == *s).cloned() else { continue };
            self.credentials_of(&mut c, t, &o)?;
        }
        // claim keys at the recorded head and the heard one, where no held secret opens by proof
        let held: BTreeSet<[u8; 32]> = c.held_proofs.iter().map(|(_, k)| *k).collect();
        let heard = self.core.heard.get(s).and_then(|p| p.last().cloned());
        let mut at: Vec<osis_blob::Step> = c.head.iter().cloned().chain(heard).filter(|st| !held.contains(&st.keys.sync.to_bytes())).collect();
        at.dedup_by_key(|st| st.step_key);
        if !at.is_empty() {
            let claimants = self.claimants(s, &things);
            for st in &at {
                c.claim_keys.extend(claimants.each().filter_map(|(_, k)| super::claim_key_at(k, s, &st.step_key)).map(|x| (st.keys.sync.to_bytes(), x)));
            }
        }
        Ok(Some(Arc::new(c)))
    }

    /// The claim keys a node keeping `s` unread tests at `step`, a head none of its sync secrets
    /// derives (spec/sync-opens.md §4 Admissible, tests): of each holder it reaches S's thing
    /// through (`claimants`), the public's among them.
    pub fn unread_claim_keys(&mut self, s: &SyncId, step: &osis_blob::Step) -> Result<Vec<SigningSecret>> {
        let things = self.sync_things_of(s)?;
        Ok(self.claimants(s, &things).each().filter_map(|(_, k)| super::claim_key_at(k, s, &step.step_key)).collect())
    }

    /// The holders this node reaches `s`'s things `things` through (spec/sync-opens.md §4
    /// Admissible, tests): its own things (its node thing, the things it holds a grant on, its
    /// link keys), each holder of a thing's independent it holds a read secret of (by the role
    /// entries held), each thing naming `s` to it (a sync-only cut's unit's thing and the chain
    /// holders it names, a holder whose claim gave it a sync secret, a followed signal's holder, a
    /// followed link's key), and the public where it redeems a locator or the public holds a role there (at any
    /// step), or where it holds `s` without reading it (at its head).
    pub(crate) fn claimants(&mut self, s: &SyncId, things: &[Tid]) -> super::Claimants {
        let me = self.core.tid();
        let mut holders: BTreeSet<Tid> = std::iter::once(me).chain(self.core.timelines().edges_at(None).targets(&me).copied()).collect();
        let mut keys: Vec<(Option<Tid>, osis_crypto::KemSecret)> = Vec::new();
        let mut public = false;
        let mut public_at_head = false;
        for t in things {
            public_at_head |= self.kept_unread(t) || self.core.ix.closure.stub_only(t);
            let reader = self.core.reader_of(t);
            for (m, _) in self.core.key_holders(&reader) {
                match m.is_public() {
                    true => public = true,
                    false => drop(holders.insert(m)),
                }
            }
            holders.extend(self.core.followed_links.signal_holders(t, s));
            // a held stub's carrying unit's thing, and the chain holders it names: the thing a
            // sync-only cut naming `s` came under, and its holders
            for c in self.core.ix.sync_cuts_of.get(t).into_iter().flatten().filter_map(|b| self.core.ix.sync_cuts.get(b)).filter(|c| c.cut.sync_id == *s) {
                holders.insert(c.under);
                holders.extend(c.cut.holders.iter().copied());
            }
            // a holder whose claim gave this node a sync secret of it
            holders.extend(self.core.ix.claim_syncs.get(t).into_iter().flatten().filter(|(_, x)| x == s).map(|(h, _)| *h));
            match self.core.followed_links.link_of(t, s) {
                Some(None) => public = true,
                Some(Some(l)) => keys.extend(l.link_read_kem().cloned().map(|k| (None, k))),
                None => {}
            }
        }
        // a claim is sealed to the keyset its box of its role is to: a read claim to a read
        // keyset, a sync claim to a sync keyset (spec/sync-ids.md §3 Claims)
        for m in holders {
            let Some(e) = self.core.epochs(&m) else { continue };
            for (_, x) in e.role(Role::Read).held_newest_first().into_iter().chain(e.role(Role::Sync).held_newest_first()) {
                let k = x.kem();
                if !keys.iter().any(|(_, y)| y.public() == k.public()) {
                    keys.push((Some(m), k.clone()));
                }
            }
        }
        super::Claimants { keys, public, public_at_head }
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
            if let Some(st) = o.path.steps.iter().find(|st| st.id() == *step) {
                out = self.head_write_key(&t, st);
            }
        }
        Ok(WriteKey(out))
    }

    /// Adds what thing `t` of `s` (owning it as `o`) opens and acts with to `c`.
    fn credentials_of(&mut self, c: &mut ReadCredentials, t: &Tid, o: &OwnedSyncId) -> Result<()> {
        if let Some(st) = o.path.steps.last() {
            c.head = Some(st.clone());
        }
        for step in &o.path.steps {
            c.keys.insert(step.id(), self.head_keys(t, step)?);
        }
        if let Some(e) = self.core.epochs(t) {
            // each held sync secret's key and proof derived once (a curve multiplication), then
            // matched per step
            let held: Vec<([u8; 32], [u8; 32])> = e
                .role(Role::Sync)
                .held_newest_first()
                .into_iter()
                .map(|(_, x)| {
                    let seed = osis_crypto::role_key_seed(osis_crypto::RoleKey::Sync, x);
                    (osis_crypto::kdf::sync_proof(&seed), SigningSecret::from_seed(&seed).verifying_key().to_bytes())
                })
                .collect();
            for step in o.path.steps.iter().rev() {
                if let Some((p, _)) = held.iter().find(|(_, k)| *k == step.keys.sync.to_bytes()) {
                    c.proofs.push((step.id(), *p));
                }
            }
            c.held_proofs.extend(held);
        }
        Ok(())
    }

    /// The read secrets of each thing opening `s` at its current epochs (history-less floors),
    /// else its newest held: what orders the wraps of `s`'s entries (`osis_blob::wrap_order`).
    pub fn current_read_secrets(&mut self, s: &SyncId) -> Result<Vec<Secret32>> {
        let mut out = Vec::new();
        for t in self.opening_things(s)? {
            let Some(e) = self.core.epochs(&t) else { continue };
            let read = e.role(Role::Read);
            let current: Vec<Secret32> = read.current().into_iter().filter_map(|ep| Some(read.secret(&ep)?.secret().clone())).collect();
            match current.is_empty() {
                true => out.extend(read.held_newest_first().into_iter().take(1).map(|(_, s)| s.secret().clone())),
                false => out.extend(current),
            }
        }
        Ok(out)
    }

    /// The held valid rotation commits of read sync ID `s`'s things whose established epoch
    /// supersedes sync epoch `e` (spec/sync-opens.md §6: an ended member's `until`); empty when
    /// `s` is not read here or none does.
    pub fn rotations_superseding(&mut self, s: &SyncId, e: &Epoch) -> Result<Vec<CommitId>> {
        let mut out = Vec::new();
        for t in self.opening_things(s)? {
            let Some(ep) = self.core.epochs(&t) else { continue };
            let sync = ep.role(Role::Sync);
            out.extend(sync.epochs().filter(|(_, i)| i.established.is_some() && i.superseded_epochs().contains(e)).flat_map(|(_, i)| i.rotations.keys().copied()));
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
                out.extend(e.role(osis_base::Role::Sync).held_newest_first().into_iter().map(|(ep, x)| (ep, x.secret().clone())));
            }
            // those held kept unread (`sync_ids::unread`), judged by the caller against the steps
            // registered with this node
            out.extend(self.core.unread(&t).candidates.iter().rev().map(|(e, x)| (*e, x.clone())));
        }
        out.sort_by_key(|x| std::cmp::Reverse(x.0));
        out.dedup_by(|a, b| a.0 == b.0);
        out
    }

    /// `s`'s things: every thing owning sync ID `s` here (`owned_sync_ids` lists it), by a held
    /// `sync.0`, as a followed link's or by a sync-only cut.
    pub(crate) fn sync_things_of(&mut self, s: &SyncId) -> Result<Vec<Tid>> {
        let mut things: BTreeSet<Tid> = self.core.ix.sync_recorders.get(s).into_iter().flatten().copied().collect();
        things.extend(self.core.followed_links.naming(s));
        things.extend(self.core.ix.sync_cut_things.get(s).into_iter().flatten().copied());
        let mut out = Vec::new();
        for t in things {
            if self.owned_sync_ids(&t)?.iter().any(|o| o.id == *s) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// The thing holding this node's settings (spec/sync-set.md §1): the one its node root's
    /// `settings^.0` names, written only by this node, while its node thing holds a grant of
    /// write or admin on it (acts for it).
    pub fn settings_thing(&mut self) -> Result<Option<Tid>> {
        let Some(t) = self.settings_named()? else { return Ok(None) };
        Ok(self.core.edge_now(&t, &self.core.tid()).is_some_and(|e| e.role >= Role::Write).then_some(t))
    }

    /// The thing this node's root's `settings^.0` names, whatever this node holds of it: where a
    /// node paired to an account keeps its settings before it enters it (spec/permissions.md §8).
    pub fn settings_named(&mut self) -> Result<Option<Tid>> {
        let Some(root) = self.core.node_root else { return Ok(None) };
        Ok(self.get_typed(&root, &ct::SETTINGS)?.map(|w| w.0))
    }

    /// This node's caps: its node thing's entry in the `caps^.0` of the thing holding its
    /// settings (spec/data-model.md §9, spec/sync-set.md §1; absent: the defaults, an empty
    /// policy). That thing's admins write the entry; what it may set is storage limits alone.
    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        let Some(s) = self.settings_thing()? else { return Ok(Arc::default()) };
        let me = osis_schema::Codec::to_value(&osis_base::Weak(self.core.tid()));
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

