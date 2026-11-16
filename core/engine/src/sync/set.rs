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
use std::collections::BTreeSet;
use std::sync::Arc;

impl Engine {
    /// Whether this node holds a read secret of `t` (spec/sync.md §3: read exactly while one is held).
    fn holds_read(&self, t: &Tid) -> bool {
        self.core.epochs(t).is_some_and(|e| e.role(Role::Read).holds_any())
    }

    /// The things the sync set is judged over: the node closure (spec/sync-set.md §2) walked
    /// through no thing sourced at another node (§5), with each destroyed thing whose own sync
    /// IDs are kept until emptied and the links being redeemed. A memo: built again in O(the
    /// node closure) when a thing enters or leaves it.
    pub fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_things, &(), |e| {
            let mut out: BTreeSet<Tid> = match e.core.ix.closure.cut.is_empty() {
                true => e.core.ix.closure.things().copied().collect(),
                false => e.core.ix.closure.uncut(e.core.node_root),
            };
            osis_base::costs::count("sync: things walked", out.len() as u64);
            out.extend(e.core.ix.destroyed_sync_ids.keys().copied());
            out.extend(e.core.followed_links.all().keys().filter(|k| crate::sync_ids::actors::followable(e, k)).copied());
            Ok(Arc::new(out))
        })
    }

    /// `sync_things`'s answer for `t` alone: reads only `t`'s rows while nothing is sourced
    /// elsewhere.
    pub fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        if self.core.ix.destroyed_sync_ids.contains_key(t) || crate::sync_ids::actors::followable(self, t) {
            return Ok(true);
        }
        if self.core.ix.closure.cut.is_empty() {
            return Ok(self.core.ix.closure.holds(t));
        }
        Ok(self.sync_things()?.contains(t))
    }

    /// The things that may have entered `sync_things` since `f`'s last read (its first: every
    /// one): each that entered the node closure or was destroyed since, every thing when the cut
    /// moved, and the links being redeemed (few). Leaving needs no feed: `in_sync_things` moves.
    pub(crate) fn things_entered(&mut self, f: &mut super::ThingsFeed) -> Result<Vec<Tid>> {
        let cut: BTreeSet<Tid> = self.core.ix.closure.cut.iter().copied().collect();
        let Some(at) = f.0.as_mut() else {
            let ix = &self.core.ix;
            f.0 = Some(super::Entered { held: ix.closure.feed(), destroyed: ix.destroyed_sync_ids.feed(), cut });
            return Ok(self.sync_things()?.iter().copied().collect());
        };
        let mut out = at.held.added();
        out.extend(at.destroyed.added());
        if at.cut != cut {
            at.cut = cut;
            out.extend(self.sync_things()?.iter().copied());
        }
        out.extend(self.core.followed_links.all().keys().copied());
        osis_base::costs::count("sync: things entered", out.len() as u64);
        Ok(out)
    }

    /// Sets the sync units the handle reads and writes at another node (spec/sync-set.md §5):
    /// `elsewhere`, of which those also in `homing` (moved home, catching up) sync here; the
    /// others `sync_things` walks no path through, the account root aside: it is never cut. A
    /// client of this node reads nothing of any of them (`readable_by`). Between transactions.
    pub fn set_sourced(&mut self, elsewhere: BTreeSet<Tid>, homing: &BTreeSet<Tid>) {
        let root = self.account_root();
        let cut: BTreeSet<Tid> = elsewhere.difference(homing).filter(|g| Some(**g) != root).copied().collect();
        let cl = &mut self.core.ix.closure;
        for t in cl.cut.iter().copied().collect::<Vec<_>>() {
            if !cut.contains(&t) {
                cl.cut.remove(&t);
            }
        }
        cl.cut.extend(cut);
        self.core.sourced_elsewhere = elsewhere;
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
    /// of it is held (a destroyed thing: every own sync ID its destruction kept, from its
    /// destruction until they are emptied, spec/sync-judgement.md §5); a thing with secrets of its
    /// own and none is unsyncable; a plain thing has none of its own. Reads only `t`'s keys.
    pub(crate) fn thing_sync_now(&mut self, t: &Tid) -> Result<ThingSync> {
        // kept only while its secrets are (`keep_sync_ids` needs them, which read its `sync.0`;
        // `forget_destroyed` drops the row before them)
        if let Some(kept) = self.core.ix.destroyed_sync_ids.get(t) {
            return Ok(ThingSync::Read(kept.iter().map(|o| o.id).collect()));
        }
        if self.core.has_own_secrets(t)
            && self.holds_read(t)
            && let Some(home) = home_of(&self.owned_sync_ids(t)?)
        {
            return Ok(ThingSync::Read(vec![home]));
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
        if self.kept_unread(t)
            && let Some(home) = home_of(&self.owned_sync_ids(t)?)
        {
            return Ok(ThingSync::Unread(vec![home]));
        }
        Ok(if self.core.has_own_secrets(t) { ThingSync::Unsyncable } else { ThingSync::Plain })
    }

    /// The sync set, whole (`sync_things` and `thing_sync` of each).
    pub(crate) fn sync_set_now(&mut self) -> Result<Arc<SyncSet>> {
        let mut set = SyncSet::default();
        let things = self.sync_things()?;
        osis_base::costs::count("sync: set folded", things.len() as u64);
        for t in things.iter() {
            match self.thing_sync(t)? {
                ThingSync::Read(ids) => set.ids.extend(ids.into_iter().map(|s| (s, (*t, Holding::Read)))),
                // a sync ID synced for several things (`kept_things`): the first keeps it
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
        if let Some((fs, l)) = self.core.followed_links.get(&t)
            && fs == *s
            && let Some(id) = self.core.key_actors.get(&l)
        {
            c.acting.push(id.keys().signing.clone());
        }
        if let Some(e) = self.core.epochs(&t) {
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
            c.sync_keys = held.into_iter().map(|(ep, _, k)| (ep, k)).collect();
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
    pub fn rotations_superseding(&mut self, s: &SyncId, e: &Epoch) -> Result<Vec<CommitId>> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(Vec::new()) };
        let Some(ep) = self.core.epochs(&t) else { return Ok(Vec::new()) };
        let read = ep.role(Role::Read);
        Ok(read.epochs().filter(|(_, i)| i.established.is_some() && i.superseded_epochs().contains(e)).flat_map(|(_, i)| i.rotations.keys().copied()).collect())
    }

    /// The thing whose sync ID `s` is, read here or by the read secrets of it still held
    /// (`opening_thing`: a sync ID sync still syncs after it left the sync set), with its record
    /// (`sync_ids`).
    pub(crate) fn read_sync_id(&mut self, s: &SyncId) -> Result<Option<(Tid, OwnedSyncId)>> {
        let Some(t) = self.opening_thing(s)? else { return Ok(None) };
        Ok(self.owned_sync_ids(&t)?.iter().find(|o| o.id == *s).map(|o| (t, o.clone())))
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

    /// The thing that owns sync ID `s` here by its `sync.0` (`sync_ids`); `None` when none does.
    /// `s`'s thing and how this node's keys let it hold `s`, whatever lists the thing: its owner
    /// (by `sync.0`, a destroyed thing's kept sync IDs, or a ticket naming it) whose
    /// `thing_sync` lists `s`. The sync set's entry for `s` when the closure holds that thing.
    pub fn sync_holder(&mut self, s: &SyncId) -> Result<Option<(Tid, Holding)>> {
        let owners: Vec<Tid> = self.sync_owner_of(s)?.into_iter().collect();
        for t in owners {
            match self.thing_sync(&t)? {
                ThingSync::Read(ids) if ids.contains(s) => return Ok(Some((t, Holding::Read))),
                ThingSync::Unread(ids) if ids.contains(s) => return Ok(Some((t, Holding::Unread))),
                _ => {}
            }
        }
        Ok(None)
    }

    pub(crate) fn sync_owner_of(&mut self, s: &SyncId) -> Result<Option<Tid>> {
        let mut things: Vec<Tid> = self.core.ix.sync_recorders.get(s).into_iter().flatten().copied().collect();
        // a destroyed thing's kept own sync IDs (`owned_sync_ids`)
        things.extend(self.core.ix.destroyed_sync_ids.iter().filter(|(_, v)| v.iter().any(|o| o.id == *s)).map(|(t, _)| *t));
        things.extend(self.core.followed_links.naming(s));
        for t in things {
            if self.owned_sync_ids(&t)?.iter().any(|o| o.id == *s) {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    /// `caps^.0` of this node, on its node root (spec/data-model.md §9, spec/sync-set.md §1;
    /// absent: the defaults, an empty policy).
    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        let Some(root) = self.core.node_root else { return Ok(Arc::default()) };
        let c = self.get_typed(&root, &ct::CAPS)?.unwrap_or_default();
        Ok(Arc::new(Caps { policy: c.policy, things: c.things.into_iter().map(|(t, x)| (t.0, ThingCaps { entries: x.entries, bytes: x.bytes })).collect() }))
    }
}

/// A thing's home sync ID among those it owns (two admins giving it secrets at once made two: the
/// higher ID, as `flows::home_sync_id`).
fn home_of(ids: &[OwnedSyncId]) -> Option<SyncId> {
    ids.iter().map(|o| o.id).max()
}
