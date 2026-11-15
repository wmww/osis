//! The sync set and what a reader of S acts with (spec/sync-set.md §1-§2, spec/sync-ids.md §3,
//! spec/sync-opens.md §4): the synced group's closure filtered by the secrets held, the recorded
//! path and the keys held per step, current read secrets, static entries, the claim key; and
//! this node's caps.

use super::{Caps, Holding, OwnedSyncId, ReadCredentials, SyncSet, ThingCaps, ThingSync};
use crate::engine::records;
use crate::engine::{Engine, Tx};
use crate::error::Result;
use osis_base::{CommitId, Role, SyncId, Tid};
use osis_crypto::{Epoch, Secret32, SigningSecret, X25519Secret};
use osis_blob::StepId;
use osis_schema::core_types as ct;
use osis_store::Shred;
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

    /// The things the sync set is judged over (spec/sync-set.md §2): N's closure, each closure
    /// walked through no group sourced at another node (spec/sync-set.md §5, `Groups::
    /// sync_closure`), with each destroyed thing whose own sync IDs are kept
    /// (`Indexes::destroyed_sync_ids`: from its destruction until they are emptied,
    /// spec/sync-judgement.md §5). Walked through groups this node reads only: a thing kept unread
    /// lists nothing here. A memo: the same `Arc` while nothing it read moved; built again in
    /// O(N's closure) when one did.
    pub(crate) fn sync_things_now(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_things, &(), |e| {
            let mut emptying: Vec<Tid> = e.core.ix.destroyed_sync_ids.keys().copied().collect();
            // links being redeemed (spec/sync-set.md §2)
            emptying.extend(e.core.followed_links.keys().filter(|k| crate::sync_ids::actors::followable(e, k)).copied());
            // home is never sourced away (spec/sync-set.md §5): D, which `set_sourced_now` never
            // cuts, roots the walk too, so the engine's own records on it (sync record keeps,
            // inbox marks, accepts) and what is filed under it sync even where a cut group holds D
            let home = e.core.account_devices().map(|(_, d)| d);
            e.rooted(home, emptying, |g, t| g.sync_closure(t))
        })
    }

    /// `sync_things_now`'s answer for `t` alone: a destroyed thing being emptied or a link being
    /// redeemed, or a root of N's closure (the sync root, home, a thing shared here) among the
    /// groups whose sync closure holds `t` (`Groups::sync_enclosing`). Reads only those rows, so
    /// it moves when `t` enters or leaves and with nothing else of the closure.
    pub(crate) fn in_sync_things_now(&mut self, t: &Tid) -> Result<bool> {
        if self.core.ix.destroyed_sync_ids.contains_key(t) || crate::sync_ids::actors::followable(self, t) {
            return Ok(true);
        }
        let [root, home] = self.sync_roots()?;
        let ix = &self.core.ix;
        Ok(ix.groups.sync_enclosing(t).iter().any(|a| Some(*a) == root || Some(*a) == home || ix.shared_here.contains(a)))
    }

    /// The sync root and home (D): the roots of N's closure besides the things shared here.
    fn sync_roots(&mut self) -> Result<[Option<Tid>; 2]> {
        Ok([self.sync_root()?, self.core.account_devices().map(|(_, d)| d)])
    }

    /// The things that may have entered `sync_things` since `f`'s last read (its first, and the
    /// first after a reload: every one): each thing that entered a sync closure (`Groups::sync_gained_feed`) or was destroyed
    /// since, the sync closure of each root new since (a share; the synced group read first),
    /// and the links being redeemed (followed links, few: whether one is followable moves with
    /// its record, sync record and destruction). Leaving needs no feed: `in_sync_things` moves.
    pub(crate) fn things_entered_now(&mut self, f: &mut super::ThingsFeed) -> Result<Vec<Tid>> {
        let roots = self.sync_roots()?;
        // a reload's fresh index feeds the old cursors nothing: started again, every thing
        let Some(at) = f.0.as_mut().filter(|at| at.loads == self.loads()) else {
            let ix = &self.core.ix;
            f.0 = Some(Entered { gained: ix.groups.sync_gained_feed(), destroyed: ix.destroyed_sync_ids.feed(), shared: ix.shared_here.feed(), roots, loads: self.loads() });
            return Ok(self.sync_things_now()?.iter().copied().collect());
        };
        let mut out = at.gained.added();
        out.extend(at.destroyed.added());
        let mut new: Vec<Tid> = at.shared.added();
        new.extend(roots.iter().flatten().filter(|r| !at.roots.contains(&Some(**r))));
        at.roots = roots;
        for r in new {
            let c = self.core.ix.groups.sync_closure(&r);
            osis_base::costs::count("sync: things walked", c.len() as u64);
            out.extend(c.iter().copied());
        }
        out.extend(self.core.followed_links.keys().copied());
        osis_base::costs::count("sync: things entered", out.len() as u64);
        Ok(out)
    }

    /// N's closure uncut (spec/sync-set.md §2): what unsyncing keeps (`forget_local`).
    pub(crate) fn node_closure(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        self.rooted(None, Vec::new(), |g, t| g.closure(t))
    }

    /// The sync root's closure by `closure`, with that of `home` and of each thing shared here
    /// (spec/sync-set.md §2 Shared here), and `extra`: one copy of the root's closure at most.
    fn rooted(&mut self, home: Option<Tid>, extra: Vec<Tid>, closure: impl Fn(&crate::engine::groups::Groups, &Tid) -> Arc<BTreeSet<Tid>>) -> Result<Arc<BTreeSet<Tid>>> {
        let base = match self.sync_root()? {
            Some(root) => closure(&self.core.ix.groups, &root),
            None => Arc::new(BTreeSet::new()),
        };
        let groups = &self.core.ix.groups;
        let mut more = BTreeSet::new();
        // a root inside another's closure adds nothing: its own closure is part of that one
        for t in home.iter().chain(self.core.ix.shared_here.iter()) {
            if !base.contains(t) && !more.contains(t) {
                let c = closure(groups, t);
                osis_base::costs::count("sync: things walked", c.len() as u64);
                more.extend(c.iter().filter(|x| !base.contains(*x)).copied());
            }
        }
        more.extend(extra.into_iter().filter(|t| !base.contains(t)));
        if more.is_empty() {
            return Ok(base);
        }
        osis_base::costs::count("sync: things walked", base.len() as u64);
        more.extend(base.iter().copied());
        Ok(Arc::new(more))
    }

    /// Sets the groups the handle reads and writes at another node (spec/sync-set.md §5):
    /// `elsewhere`, of which those also in `homing` (moved home, catching up) sync here; the
    /// others `sync_things` leaves out with what it reaches only through them, home (D) aside: it
    /// is never cut. A client of this node reads nothing of any of them (`readable_by`). Between
    /// transactions; cost: what is below each group whose state moved.
    pub(crate) fn set_sourced_now(&mut self, elsewhere: BTreeSet<Tid>, homing: &BTreeSet<Tid>) {
        let home = self.core.account_devices().map(|(_, d)| d);
        self.core.ix.groups.set_cut(elsewhere.difference(homing).filter(|g| Some(**g) != home).copied().collect());
        self.core.sourced_elsewhere = elsewhere;
    }

    /// spec/sync-set.md §5 (moving home): history is complete here for group `g` and each thing
    /// of its closure the sync set holds (spec/sync-status.md §3): each sync ID of the sync set
    /// carrying one of them, read here, has a complete pass noted. True when none does: nothing
    /// here syncs it. A memo per group: O(its closure times the groups enclosing each) when
    /// something it read moved (asked only while the group moves home).
    pub(crate) fn caught_up_now(&mut self, g: &Tid) -> Result<bool> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.caught_up, g, |e| e.caught_up_fresh(g))
    }

    fn caught_up_fresh(&mut self, g: &Tid) -> Result<bool> {
        let set = self.sync_set()?;
        let things = self.sync_things()?;
        // every read sync ID carrying g or a thing of its closure: their own and their enclosing
        // groups', a group outside g listing one of them included
        let mut ids = self.carrying_now(g, true)?;
        for x in self.closure(g).iter().filter(|x| things.contains(*x)) {
            ids.extend(self.carrying_now(x, true)?);
        }
        Ok(ids.iter().filter(|s| set.ids.get(*s).is_some_and(|(_, h)| *h == Holding::Read)).all(|s| self.core.ix.passes.contains_key(s)))
    }

    /// How this node syncs thing `t` of `sync_things` (spec/sync-set.md §2): its home sync ID read
    /// while a read secret of it is held (a destroyed thing: every own sync ID its destruction
    /// kept, from its destruction until they are emptied, spec/sync-judgement.md §5), kept unread
    /// while only its sync record is; a thing with secrets of its own and neither is unsyncable; a
    /// plain thing has none of its own. Reads only `t`'s keys.
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
        if let Some((s, _)) = self.core.followed_links.get(t).copied()
            && crate::sync_ids::actors::followable(self, t)
            && self.owned_sync_ids(t)?.iter().any(|o| o.id == s)
        {
            return Ok(ThingSync::Read(vec![s]));
        }
        if let Some(r) = self.core.ix.sync_records.get(t).cloned() {
            // a record's sync IDs are its payloads' word (spec/sync-inbox.md §2): one a held
            // `sync.0` gives another thing is that thing's, never kept unread for this one; one
            // kept for several things is synced for those tied to it when any is
            let mut ids = Vec::new();
            for s in &r.sync_ids {
                let kept = self.kept_records_now(s);
                if self.sync_owner_of(s)?.is_none_or(|o| o == *t) && super::kept_things(s, &kept).any(|(x, _)| x == t) {
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
        if let Some((fs, l)) = self.core.followed_links.get(&t).copied()
            && fs == *s
            && let Some(id) = self.core.key_actors.get(&l)
        {
            c.acting.push(id.keys().signing.clone());
        }
        c.roster = self.roster_digest(&t);
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
    pub(crate) fn rotations_superseding_now(&mut self, s: &SyncId, e: &Epoch) -> Result<Vec<CommitId>> {
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
    /// `s`'s thing and how this node's keys let it hold `s`, whatever lists the thing: its owner
    /// (by `sync.0`, a destroyed thing's kept sync IDs, or a sync record naming it) whose
    /// `thing_sync` lists `s`. The sync set's entry for `s` when the closure holds that thing.
    pub(crate) fn sync_holder_now(&mut self, s: &SyncId) -> Result<Option<(Tid, Holding)>> {
        let mut owners: Vec<Tid> = self.sync_owner_of(s)?.into_iter().collect();
        owners.extend(self.core.ix.record_ids.get(s).into_iter().flatten().copied());
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
        // a thing a taken inbox blob named it for
        things.extend(self.core.ix.hinted.get(s).into_iter().flatten().copied());
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

/// `t` joins this node's shared set (spec/sync-set.md §2 Shared here): a grant on it this node
/// writes as its account to an actor other than the account or a node.
pub(crate) fn share_here(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    if !tx.core.ix.shared_here.contains(t) {
        tx.core.ix.shared_here.insert(*t);
        tx.txn.put_local(&[records::SHARED_HERE, t.as_bytes()].concat(), &[], Shred::No)?;
    }
    Ok(())
}

/// `t` leaves this node's shared set (spec/sync-set.md §2 Shared here): unsynced here, or
/// forgotten. Nothing when it is not in it.
pub(crate) fn unshare_here(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    if tx.core.ix.shared_here.remove(t) {
        tx.txn.remove_local(&[records::SHARED_HERE, t.as_bytes()].concat(), Shred::No)?;
    }
    Ok(())
}

/// A started `ThingsFeed`: its cursors and the roots it last saw.
#[derive(Clone, Debug)]
pub(crate) struct Entered {
    gained: osis_base::memo::Feed<Tid>,
    destroyed: osis_base::memo::Feed<Tid>,
    shared: osis_base::memo::Feed<Tid>,
    roots: [Option<Tid>; 2],
    /// The engine's loads when started (`Engine::reload` replaces the index its cursors read).
    loads: u64,
}

/// A thing's home sync ID among those it owns (two admins giving it secrets at once made two: the
/// higher ID, as `flows::home_sync_id`).
fn home_of(ids: &[OwnedSyncId]) -> Option<SyncId> {
    ids.iter().map(|o| o.id).max()
}
