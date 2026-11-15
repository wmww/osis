//! The sync set and what a reader of S acts with (spec/sync-set.md §1-§2, spec/sync-ids.md §3,
//! spec/sync-opens.md §4): N's closure filtered by the secrets held, the recorded
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
    pub fn sync_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_things, &(), |e| {
            let mut emptying: Vec<Tid> = e.core.ix.destroyed_sync_ids.keys().copied().collect();
            // links being redeemed (spec/sync-set.md §2)
            emptying.extend(e.core.followed_links.all().keys().filter(|k| crate::sync_ids::actors::followable(e, k)).copied());
            // home is never sourced away (spec/sync-set.md §5): D, which `set_sourced` never
            // cuts, roots the walk too, so the engine's own records on it (sync record keeps,
            // inbox marks, accepts) and what is filed under it sync even where a cut group holds D
            let home = e.core.account_devices().map(|(_, d)| d);
            e.rooted(home, emptying, |g, t| g.sync_closure(t))
        })
    }

    /// `sync_things`'s answer for `t` alone: a destroyed thing being emptied or a link being
    /// redeemed, or a root of N's closure (the sync root, home, a thing shared here) among the
    /// groups whose sync closure holds `t` (`Groups::sync_enclosing`). Reads only those rows, so
    /// it moves when `t` enters or leaves and with nothing else of the closure.
    pub fn in_sync_things(&mut self, t: &Tid) -> Result<bool> {
        if self.core.ix.destroyed_sync_ids.contains_key(t) || crate::sync_ids::actors::followable(self, t) {
            return Ok(true);
        }
        let [root, home] = self.sync_roots()?;
        let enclosing = self.core.ix.groups.sync_enclosing(t);
        // shared here only while this node is a node of its account (`shared_here`)
        let member = self.core.member().is_some();
        for a in enclosing.iter() {
            if Some(*a) == root || Some(*a) == home || member && self.shares(a)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The sync root and home (D): the roots of N's closure besides the things shared here. A
    /// memo: every follow of the sync set's rows asks it, and the synced group is a state read.
    fn sync_roots(&mut self) -> Result<[Option<Tid>; 2]> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.sync_roots, &(), |e| Ok([e.sync_root()?, e.core.account_devices().map(|(_, d)| d)]))
    }

    /// The things that may have entered `sync_things` since `f`'s last read (its first: every
    /// one; `f` lives in the core a reload replaces): each thing that entered a sync closure (`Groups::sync_gained_feed`) or was destroyed
    /// since, the sync closure of each root new since (a share; the synced group read first),
    /// and the links being redeemed (followed links, few: whether one is followable moves with
    /// its record, sync record and destruction). Leaving needs no feed: `in_sync_things` moves.
    pub(crate) fn things_entered(&mut self, f: &mut super::ThingsFeed) -> Result<Vec<Tid>> {
        let roots = self.sync_roots()?;
        let shared = self.shared_here()?;
        let Some(at) = f.0.as_mut() else {
            let ix = &self.core.ix;
            f.0 = Some(Entered { gained: ix.groups.sync_gained_feed(), destroyed: ix.destroyed_sync_ids.feed(), shared, roots });
            return Ok(self.sync_things()?.iter().copied().collect());
        };
        let mut out = at.gained.added();
        out.extend(at.destroyed.added());
        let mut new: Vec<Tid> = shared.difference(&at.shared).copied().collect();
        at.shared = shared;
        new.extend(roots.iter().flatten().filter(|r| !at.roots.contains(&Some(**r))));
        at.roots = roots;
        for r in new {
            let c = self.core.ix.groups.sync_closure(&r);
            osis_base::costs::count("sync: things walked", c.len() as u64);
            out.extend(c.iter().copied());
        }
        out.extend(self.core.followed_links.all().keys().copied());
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
        let shared = self.shared_here()?;
        let groups = &self.core.ix.groups;
        let mut more = BTreeSet::new();
        // a root inside another's closure adds nothing: its own closure is part of that one
        for t in home.iter().chain(shared.iter()) {
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
    pub fn set_sourced(&mut self, elsewhere: BTreeSet<Tid>, homing: &BTreeSet<Tid>) {
        let home = self.core.account_devices().map(|(_, d)| d);
        self.core.ix.groups.set_cut(elsewhere.difference(homing).filter(|g| Some(**g) != home).copied().collect());
        self.core.sourced_elsewhere = elsewhere;
    }

    /// spec/sync-set.md §5 (moving home): history is complete here for group `g` and each thing
    /// of its closure the sync set holds (spec/sync-status.md §3): each sync ID of the sync set
    /// carrying one of them, read here, has a complete pass noted. True when none does: nothing
    /// here syncs it. A memo per group: O(its closure times the groups enclosing each) when
    /// something it read moved (asked only while the group moves home).
    pub fn caught_up(&mut self, g: &Tid) -> Result<bool> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.caught_up, g, |e| e.caught_up_fresh(g))
    }

    fn caught_up_fresh(&mut self, g: &Tid) -> Result<bool> {
        // every read sync ID carrying g or a thing of its closure: their own and their enclosing
        // groups', a group outside g listing one of them included
        let mut ids = self.carrying_now(g, true)?;
        for x in self.closure(g).iter() {
            if self.in_sync_things(x)? {
                ids.extend(self.carrying_now(x, true)?);
            }
        }
        for s in ids {
            if self.sync_held(&s)?.is_some_and(|(_, h)| h == Holding::Read) && !self.core.ix.passes.contains_key(&s) {
                return Ok(false);
            }
        }
        Ok(true)
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
        if let Some((s, _)) = self.core.followed_links.get(t)
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
                let kept = self.kept_records(s);
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
    /// (by `sync.0`, a destroyed thing's kept sync IDs, or a sync record naming it) whose
    /// `thing_sync` lists `s`. The sync set's entry for `s` when the closure holds that thing.
    pub fn sync_holder(&mut self, s: &SyncId) -> Result<Option<(Tid, Holding)>> {
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
        things.extend(self.core.followed_links.naming(s));
        for t in things {
            if self.owned_sync_ids(&t)?.iter().any(|o| o.id == *s) {
                return Ok(Some(t));
            }
        }
        Ok(None)
    }

    /// `caps^.0` of this node (spec/data-model.md §9; absent: the defaults, an empty policy).
    pub fn caps(&mut self) -> Result<Arc<Caps>> {
        let me = self.core.id.tid();
        let c = self.get_typed(&me, &ct::CAPS)?.unwrap_or_default();
        Ok(Arc::new(Caps { policy: c.policy, things: c.things.into_iter().map(|(t, x)| (t, ThingCaps { entries: x.entries, bytes: x.bytes })).collect() }))
    }
}

/// This node stops sharing `t` (spec/sync-set.md §2 Shared here): unsynced here, or forgotten.
/// The account's grants on it, live or ended (`Core::account_grants`), are marked, so it is
/// shared again only by a grant not marked (a new one), and it stays local no more
/// (`Core::stays_local`). Nothing when the account wrote none.
pub(crate) fn unshare_here(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    for c in tx.core.account_grants(t) {
        if tx.core.ix.unshared.insert(*t, c) {
            tx.txn.put_local(&[records::UNSHARED, t.as_bytes(), &c.0].concat(), &[], Shred::No)?;
        }
    }
    Ok(())
}

/// Loads the unshare marks (`unshare_here`).
pub(crate) fn load_unshared(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || crate::error::Error::Corrupt("unshared");
    let mut rows = Vec::new();
    tx.scan(records::UNSHARED, |k, _| {
        let (t, c) = k.split_at_checked(15).ok_or_else(bad)?;
        rows.push((Tid::from_bytes(t.try_into().map_err(|_| bad())?), CommitId(c.try_into().map_err(|_| bad())?)));
        Ok(())
    })?;
    for (t, c) in rows {
        tx.core.ix.unshared.insert(t, c);
    }
    Ok(())
}

/// At an open: drops each unshare mark whose grant's commit is held no more, so the marks stay
/// bounded by the role commits held.
pub(crate) fn prune_unshared(e: &mut Engine) -> Result<()> {
    let gone: Vec<(Tid, CommitId)> = e.core.ix.unshared.iter().flat_map(|(t, cs)| cs.iter().map(move |c| (*t, *c))).filter(|(_, c)| e.core.ix.held.edge_commit(c).is_none()).collect();
    if gone.is_empty() {
        return Ok(());
    }
    e.run(|tx| {
        for (t, c) in gone {
            tx.core.ix.unshared.remove(&t, &c);
            tx.txn.remove_local(&[records::UNSHARED, t.as_bytes(), &c.0].concat(), Shred::No)?;
        }
        Ok(())
    })
}

impl crate::engine::Core {
    /// The edge writes in force on `t` that this node's account wrote (header actor), each
    /// granting a live edge to an actor other than the account or one of its nodes (spec/sync-set.md
    /// §2 Shared here). Reads `t`'s edges, the holders' standing on D, and the clock up to the
    /// next `until`.
    pub(crate) fn account_shares(&self, t: &Tid) -> Vec<CommitId> {
        let Some(account) = self.me() else { return Vec::new() };
        let Some(on) = self.timelines.on(t) else { return Vec::new() };
        let me = self.id.tid();
        let mut out = Vec::new();
        for (h, e) in on.holders() {
            if h == account || h == me || self.own_node(&h) {
                continue;
            }
            if e.until.is_some_and(|u| self.time.until(Some(u.0)) >= u.0) {
                continue;
            }
            if let Some(c) = on.in_force(&h)
                && self.ix.held.edge_commit(&c).is_some_and(|rc| rc.actor == account)
            {
                out.push(c);
            }
        }
        out
    }

    /// The role commits on `t` this node's account wrote (header actor) granting an edge on it to
    /// an actor other than the account or one of its nodes, of any validity and whatever followed:
    /// the grants that share `t` or once did. O(role commits on `t`).
    pub(crate) fn account_grants(&self, t: &Tid) -> Vec<CommitId> {
        let Some(account) = self.me() else { return Vec::new() };
        let me = self.id.tid();
        let outside = |h: &Tid| *h != account && *h != me && !self.own_node(h);
        self.ix.held.commits_on(t).iter().filter(|c| c.actor == account && c.ops.iter().any(|o| o.target == *t && o.edge.is_some() && outside(&o.holder))).map(|c| c.id).collect()
    }

    /// Whether `t`, out of N's closure, stays local here rather than being forgotten
    /// (spec/sync-set.md §3 Unsyncing; spec/requirements.md: shared with no one, it stays local):
    /// a grant of the account's on it (`account_grants`), live or ended, that this node did not
    /// stop sharing (`unshare_here` marked none such).
    pub(crate) fn stays_local(&self, t: &Tid) -> bool {
        let marked = self.ix.unshared.get(t);
        self.account_grants(t).iter().any(|c| marked.is_none_or(|m| !m.contains(c)))
    }
}

impl Engine {
    /// Whether this node shares `t` (spec/sync-set.md §2 Shared here): a grant on it that its
    /// account wrote is live (`Core::account_shares`) and not marked unshared here. A memo per
    /// thing, so every node of the account judges it from the role commits it holds alike.
    pub(crate) fn shares(&mut self, t: &Tid) -> Result<bool> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.shares, t, |e| {
            let marked = e.core.ix.unshared.get(t).cloned().unwrap_or_default();
            Ok(e.core.account_shares(t).iter().any(|c| !marked.contains(c)))
        })
    }

    /// The things kept here that sync no more (spec/sync-set.md §3 Unsyncing): out of the sync set's
    /// things, staying local (`Core::stays_local`: a share that ended, unsynced by no one here).
    /// O(things the account ever granted on): for status and an unsync, not per change.
    pub fn kept_local(&mut self) -> Result<BTreeSet<Tid>> {
        let Some(account) = self.core.member() else { return Ok(BTreeSet::new()) };
        let granted: Vec<Tid> = self.core.ix.held.granted_by(&account).copied().collect();
        let mut out = BTreeSet::new();
        for t in granted {
            if self.core.stays_local(&t) && !self.in_sync_things(&t)? {
                out.insert(t);
            }
        }
        Ok(out)
    }

    /// The things this node shares (`shares`), among those its account ever granted on
    /// (`Held::granted_by`). A memo: built again in O(those things), each one's answer a memo.
    pub(crate) fn shared_here(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        osis_base::memo::Memo::get_in(self, |e| &e.core.shared_here, &(), |e| {
            // a node that left its account shares nothing as it (spec/permissions.md §3, Lost access)
            let Some(account) = e.core.member() else { return Ok(Arc::default()) };
            let granted: Vec<Tid> = e.core.ix.held.granted_by(&account).copied().collect();
            let mut out = BTreeSet::new();
            for t in granted {
                if e.shares(&t)? {
                    out.insert(t);
                }
            }
            Ok(Arc::new(out))
        })
    }
}

/// A started `ThingsFeed`: its cursors and the roots it last saw.
#[derive(Clone, Debug)]
pub(crate) struct Entered {
    gained: osis_base::memo::Feed<Tid>,
    destroyed: osis_base::memo::Feed<Tid>,
    /// The things shared here when last read.
    shared: Arc<BTreeSet<Tid>>,
    roots: [Option<Tid>; 2],
}

/// A thing's home sync ID among those it owns (two admins giving it secrets at once made two: the
/// higher ID, as `flows::home_sync_id`).
fn home_of(ids: &[OwnedSyncId]) -> Option<SyncId> {
    ids.iter().map(|o| o.id).max()
}
