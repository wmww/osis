//! perm's held set (notes/architecture.md §2: the node implements `HeldSet`): applied role
//! commits by target and `created.0` records, indexed by commit and by holder, journaled for
//! rollback, and remembering which things' inputs changed since perm last looked
//! (`take_touched`), so the timelines re-partition only around them. A role commit of an
//! account that does not count by the epoch rule (spec/permissions.md §5.5) stays held but no
//! timeline reads it (`set_counted`): the filter runs before the timeline.
//!
//! Reads and changes are stamped for memos (`memo::Stamps`): a record by its thing
//! (`created`), everything else per key of each map. `Timelines` holds perm's timelines over
//! it, its reads stamped by what they can see (`Read`).

use super::journal::Journaled;
use osis_base::memo::{Stamps, UndoableStamps};
use osis_base::{CommitId, CreationRecord, RecordLink, Role, Tid};
use osis_perm::RoleCommit;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Debug)]
enum Undo {
    Created(Tid, Option<CreationRecord>),
    AddedCommit(Arc<RoleCommit>),
    Removed(Arc<RoleCommit>),
    Counted(CommitId, bool),
    Touched(CommitId),
}

#[derive(Clone, Debug, Default)]
pub struct Held {
    commits: BTreeMap<Tid, Vec<Arc<RoleCommit>>>,
    created: BTreeMap<Tid, CreationRecord>,
    /// Holder -> things it is named on (edge writes, a creation record naming its mint admin), with counts.
    holders: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Thing -> holders named on it (the same pairs as `holders`).
    named: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Thing -> holders an edge write puts a grant for on it, with counts: the edges a path may
    /// climb (a removal names a holder but gives it none).
    granted: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Mint admin -> the things whose creation record names it: the record chain's
    /// links down (spec/permissions.md §1).
    mint_admin_of: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Commit -> its edge commit held here.
    ids: BTreeMap<CommitId, Arc<RoleCommit>>,
    log: Vec<Undo>,
    touched: BTreeSet<Tid>,
    /// Commits whose reading by the walk (`validity::reading`) may have changed since
    /// `take_touched_commits`.
    touched_commits: BTreeSet<CommitId>,
    /// Things whose edge writes (any validity) or record changed since `take_ever`: what a chain
    /// walk reads of them (`Timelines::ever_moved`); `touched` also names a commit's author.
    ever: BTreeSet<Tid>,
    /// The same, for `take_moved`.
    moved: BTreeSet<Tid>,
    /// Things whose creation record `create` added since `take_records`.
    records: Vec<Tid>,
    /// Holders a thing stopped naming since `take_unnamed` (`retention::destroy`: a destroyed one may
    /// have lost its last dependent).
    unnamed: BTreeSet<Tid>,
    /// Role commits held that do not count (an account's at a closed epoch no word names):
    /// left out of what perm reads (`Held::counted`). By ID, whether held or not, so a
    /// commit re-derived (`add_commit`) keeps its standing.
    uncounted: BTreeSet<CommitId>,
    /// Stamps `created`, per thing.
    records_read: UndoableStamps,
    /// Stamps everything else, per key of each map (`Row`).
    rest: UndoableStamps,
    /// Stamps each (holder, thing) pair of `holders` as it comes or goes (`is_named`,
    /// `pairs_feed`).
    pairs: UndoableStamps,
}

/// A key of `Held`'s maps, as `Held::rest` stamps it.
#[derive(Hash)]
enum Row<'a> {
    /// The holders named on anything (`holders`): moved as one comes or goes.
    Holders,
    Commits(&'a Tid),
    Holder(&'a Tid),
    Named(&'a Tid),
    Granted(&'a Tid),
    MintAdminOf(&'a Tid),
    Id(&'a CommitId),
}

fn named(c: &RoleCommit) -> Vec<(Tid, Tid)> {
    c.ops.iter().map(|o| (o.holder, o.target)).collect()
}

impl Held {
    /// The record of `t`.
    pub fn created(&self, t: &Tid) -> Option<&CreationRecord> {
        self.records_read.read(t);
        self.created.get(t)
    }
    /// Every thing whose record is held.
    pub fn things(&self) -> impl Iterator<Item = &Tid> {
        self.records_read.read_all();
        self.created.keys()
    }
    /// The held things whose record names `t` as mint admin (one link down the record
    /// chain).
    pub fn mint_admin_of(&self, t: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::MintAdminOf(t));
        self.mint_admin_of.get(t).into_iter().flatten()
    }
    /// The actors named as a holder on some thing (edge writes, a creation record naming its
    /// mint admin).
    pub fn holders(&self) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::Holders);
        self.holders.keys()
    }
    /// Edge commits with a write on `t`, of any validity.
    pub fn commits_on(&self, t: &Tid) -> &[Arc<RoleCommit>] {
        self.rest.read(&Row::Commits(t));
        self.commits.get(t).map(Vec::as_slice).unwrap_or_default()
    }
    /// Things `holder` is named on as a holder (edge writes, a creation record naming its mint admin).
    pub fn named_on(&self, holder: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::Holder(holder));
        self.holders.get(holder).into_iter().flat_map(|m| m.keys())
    }

    /// Whether `holder` is named on `thing` (`named_on`): a read of that pair alone.
    pub fn is_named(&self, holder: &Tid, thing: &Tid) -> bool {
        self.pairs.read(&(*holder, *thing));
        self.holders.get(holder).is_some_and(|m| m.contains_key(thing))
    }

    /// Whether an edge write on `thing` (of any validity) names `holder`: `is_named` but for a
    /// creation record naming its mint admin alone. O(the edge commits on `thing`).
    pub fn named_by_write(&self, holder: &Tid, thing: &Tid) -> bool {
        self.commits_on(thing).iter().any(|r| r.ops.iter().any(|o| o.target == *thing && o.holder == *holder))
    }

    /// Whether `holder` is named on `thing` by an edge write (`named_by_write`), not by `thing`'s
    /// record alone: where holder rules apply (spec/permissions.md §4 Key part).
    pub fn is_holder_by_write(&self, holder: &Tid, thing: &Tid) -> bool {
        self.is_named(holder, thing) && (self.created(thing).and_then(CreationRecord::mint_admin) != Some(*holder) || self.named_by_write(holder, thing))
    }

    /// A reader's cursor over the (holder, thing) pairs a naming is added to from now on
    /// (`is_named`, `is_holder_by_write`): one named and then undone is given too.
    pub fn pairs_feed(&self) -> osis_base::memo::Feed<(Tid, Tid)> {
        self.pairs.feed()
    }

    /// Holders named on `thing` (edge writes, a creation record naming its mint admin).
    pub fn holders_of(&self, thing: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::Named(thing));
        self.named.get(thing).into_iter().flatten()
    }

    /// Holders an edge write puts a grant for on `thing`, of any validity and whatever followed.
    pub fn granted_on(&self, thing: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::Granted(thing));
        self.granted.get(thing).into_iter().flat_map(|m| m.keys())
    }

    /// `from` and everything authority flows to from them: what they own, the things they are
    /// named on as holders, transitively (spec/permissions.md §1: paths climb record links and
    /// role edges). A change of authority at `from` changes it only there.
    pub fn reach(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        walk(from, |t, s| s.extend(self.mint_admin_of(t).chain(self.named_on(t))))
    }

    /// `from` and everything authority comes to them from: their mint admins and the
    /// holders named on them, transitively (the search `reach` answers forward). A changed edge
    /// to holder `z` changes the roles only of `upstream({z})`.
    pub fn upstream(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        walk(from, |t, s| s.extend(self.created(t).and_then(CreationRecord::mint_admin).into_iter().chain(self.holders_of(t).copied())))
    }

    /// `from` and everything below them by record links: the things whose record chains hold
    /// them.
    pub fn below(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        walk(from, |t, s| s.extend(self.mint_admin_of(t)))
    }

    /// Who named whom on `t` with `role` or above, as (signer, holder), of any validity and whatever
    /// followed, by edge writes.
    fn named_with(&self, t: &Tid, role: Role) -> impl Iterator<Item = (Tid, Tid)> {
        self.commits_on(t).iter().flat_map(move |r| r.ops.iter().filter(move |o| o.target == *t && o.edge.as_ref().is_some_and(|e| e.role >= role)).map(|o| (r.signer, o.holder)))
    }

    /// `t`'s possible admins (spec/commits.md §4): the least set holding `t` and, with each member, its
    /// mint admin and any holder named with admin on it by an edge write a member signed; of any validity and whatever followed. So a forger is in it only if a
    /// member named it, and held inputs only grow, so it does, whatever the order: use it where
    /// "could this signer ever have been admin" must not depend on arrival (a timeline read does).
    /// A member need not hold admin on the thing it signs for: it could as well have named the holder
    /// on `t`. Linear in the role writes on its members.
    pub fn ever_admins(&self, t: &Tid) -> BTreeSet<Tid> {
        let mut set = BTreeSet::from([*t]);
        let mut todo = vec![*t];
        // holders named by a signer not (yet) in the set
        let mut waiting: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
        while let Some(c) = todo.pop() {
            let mut named = waiting.remove(&c).unwrap_or_default();
            if let Some(RecordLink::Admin(x)) = self.created(&c).map(CreationRecord::record_link) {
                named.push(x);
            }
            for (by, h) in self.named_with(&c, Role::Admin) {
                if set.contains(&by) { named.push(h) } else { waiting.entry(by).or_default().push(h) }
            }
            for h in named {
                if set.insert(h) {
                    todo.push(h);
                }
            }
        }
        set
    }

    /// `t`'s possible writers: the least set holding the possible admins of `t` and of each member,
    /// and any holder named with write or above on `t` or a member by one of that thing's possible
    /// admins, of any validity (a member's writers reach `t` through it). Monotone as `ever_admins`
    /// is, so a forger is in it only if a possible admin named it.
    pub fn ever_writers(&self, t: &Tid) -> BTreeSet<Tid> {
        let (mut set, mut todo, mut seen) = (BTreeSet::new(), vec![*t], BTreeSet::from([*t]));
        while let Some(c) = todo.pop() {
            let admins = self.ever_admins(&c);
            for (by, h) in self.named_with(&c, Role::Write) {
                if admins.contains(&by) {
                    set.insert(h);
                    if seen.insert(h) {
                        todo.push(h);
                    }
                }
            }
            for a in admins {
                set.insert(a);
                if seen.insert(a) {
                    todo.push(a);
                }
            }
        }
        set
    }

    /// Whether `t`'s record chain ends at a key actor within `MAX_CHAIN_DEPTH` links, mint-admin
    /// links counted, by the records held (spec/permissions.md §1): nothing written on a thing
    /// failing it applies; unknown fails (forgetting a record never makes a deep part count).
    /// Reads each record of the chain. O(`MAX_CHAIN_DEPTH`).
    pub fn chain_held(&self, t: &Tid) -> bool {
        matches!(osis_base::record_chain(*t, |x| self.created(x).map(CreationRecord::record_link)).end(), osis_base::ChainStep::Key(_))
    }

    fn set_created(&mut self, t: Tid, r: Option<CreationRecord>) -> Option<CreationRecord> {
        self.records_read.wrote(&t, r.is_some());
        let old = match r {
            Some(r) => {
                if let Some(up) = r.mint_admin() {
                    self.mint_admin_of.entry(up).or_default().insert(t);
                    self.rest.wrote(&Row::MintAdminOf(&up), true);
                }
                self.created.insert(t, r)
            }
            None => self.created.remove(&t),
        };
        let same = matches!((&old, self.created.get(&t)), (Some(o), Some(n)) if o == n);
        if let Some(up) = old.as_ref().and_then(|o| o.mint_admin())
            && self.created.get(&t).is_none_or(|n| n.mint_admin() != Some(up))
            && let Some(s) = self.mint_admin_of.get_mut(&up)
        {
            s.remove(&t);
            if s.is_empty() {
                self.mint_admin_of.remove(&up);
            }
            self.rest.wrote(&Row::MintAdminOf(&up), self.mint_admin_of.contains_key(&up));
        }
        if same {
            // the same record: nothing perm reads changed
            return old;
        }
        // a thing's mint admin is named on it by its record (spec/permissions.md §1)
        let genesis = |r: Option<&CreationRecord>| match r {
            Some(CreationRecord::Thing { admin, .. }) => vec![(*admin, t)],
            _ => Vec::new(),
        };
        let (was, now) = (genesis(old.as_ref()), genesis(self.created.get(&t)));
        if was != now {
            self.count(was, false);
            self.count(now, true);
        }
        self.touched.insert(t);
        self.ever.insert(t);
        self.moved.insert(t);
        old
    }

    fn count(&mut self, pairs: Vec<(Tid, Tid)>, add: bool) {
        for (m, t) in pairs {
            if !self.holders.contains_key(&m) {
                self.rest.wrote(&Row::Holders, true);
            }
            let e = self.holders.entry(m).or_default();
            let n = e.entry(t).or_default();
            if add {
                *n += 1;
                // every naming added feeds the pair, not only its first: an edge write naming a
                // mint admin its record names already makes it a holder by write
                // (`is_holder_by_write`)
                self.pairs.wrote_added(&(m, t), true, true);
                self.named.entry(t).or_default().insert(m);
            } else {
                *n = n.saturating_sub(1);
                // stamped at every naming taken, as at every one added: a rollback's undo
                // stamps again each key the undone write stamped (`memo::undoing`)
                self.pairs.wrote(&(m, t), *n > 0);
                if *n == 0 {
                    e.remove(&t);
                    self.unnamed.insert(m);
                    if let Some(x) = self.named.get_mut(&t) {
                        x.remove(&m);
                        if x.is_empty() {
                            self.named.remove(&t);
                        }
                    }
                }
            }
            if e.is_empty() {
                self.holders.remove(&m);
                self.rest.wrote(&Row::Holders, true);
            }
            self.rest.wrote(&Row::Holder(&m), self.holders.contains_key(&m));
            self.rest.wrote(&Row::Named(&t), self.named.contains_key(&t));
        }
    }

    fn count_granted(&mut self, c: &RoleCommit, add: bool) {
        for o in c.ops.iter().filter(|o| o.edge.is_some()) {
            let on = self.granted.entry(o.target).or_default();
            let n = on.entry(o.holder).or_default();
            if add {
                *n += 1;
            } else {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    on.remove(&o.holder);
                }
            }
            if on.is_empty() {
                self.granted.remove(&o.target);
            }
            self.rest.wrote(&Row::Granted(&o.target), self.granted.contains_key(&o.target));
        }
    }

    fn put_commit(&mut self, c: Arc<RoleCommit>) {
        let targets: BTreeSet<Tid> = c.ops.iter().map(|o| o.target).collect();
        for t in &targets {
            self.commits.entry(*t).or_default().push(c.clone());
            self.rest.wrote(&Row::Commits(t), true);
        }
        self.moved.extend(targets.iter().copied());
        self.ever.extend(targets.iter().copied());
        self.touched.extend(targets);
        self.touched.insert(c.signer);
        self.moved.insert(c.signer);
        self.count(named(&c), true);
        self.count_granted(&c, true);
        self.rest.wrote(&Row::Id(&c.id), true);
        self.touched_commits.insert(c.id);
        self.ids.insert(c.id, c);
    }

    /// Takes out the commit with this ID (exactly this Arc).
    fn take(&mut self, id: &CommitId) -> Option<Arc<RoleCommit>> {
        let c = self.ids.remove(id)?;
        self.touched_commits.insert(*id);
        self.rest.wrote(&Row::Id(id), false);
        for o in &c.ops {
            if let Some(v) = self.commits.get_mut(&o.target) {
                v.retain(|x| !Arc::ptr_eq(x, &c));
                if v.is_empty() {
                    self.commits.remove(&o.target);
                }
            }
            self.rest.wrote(&Row::Commits(&o.target), self.commits.contains_key(&o.target));
            self.touched.insert(o.target);
            self.ever.insert(o.target);
            self.moved.insert(o.target);
        }
        self.count(named(&c), false);
        self.count_granted(&c, false);
        Some(c)
    }

    /// Adds a creation record under its tid.
    pub fn create(&mut self, record: CreationRecord) {
        let t = record.tid();
        self.records.push(t);
        let old = self.set_created(t, Some(record));
        self.log.push(Undo::Created(t, old));
    }

    /// Forgets a thing's record (`retention::destroy`: the thing was destroyed).
    pub fn forget_record(&mut self, t: &Tid) {
        let old = self.set_created(*t, None);
        self.log.push(Undo::Created(*t, old));
    }

    pub fn add_commit(&mut self, c: RoleCommit) {
        // an ID is held once: a re-derived commit replaces the earlier
        if let Some(removed) = self.take(&c.id) {
            self.log.push(Undo::Removed(removed));
        }
        let c = Arc::new(c);
        self.put_commit(c.clone());
        self.log.push(Undo::AddedCommit(c));
    }

    /// The edge commit held under this ID where it counts (`set_counted`): what the timeline
    /// reads.
    pub fn counted(&self, id: &CommitId) -> Option<Arc<RoleCommit>> {
        self.rest.read(&Row::Id(id));
        self.ids.get(id).filter(|_| !self.uncounted.contains(id)).cloned()
    }

    /// The edge commit held under this ID.
    pub fn edge_commit(&self, id: &CommitId) -> Option<&RoleCommit> {
        self.rest.read(&Row::Id(id));
        self.ids.get(id).map(|c| &**c)
    }

    /// Whether the role commit `id` counts (spec/permissions.md §5.5): one that does not stays
    /// held, read by no timeline. A change touches what the commit writes, so perm judges it again.
    pub fn set_counted(&mut self, id: CommitId, counts: bool) {
        if self.uncounted.contains(&id) != counts {
            return;
        }
        self.mark_counted(id, counts);
        self.log.push(Undo::Counted(id, !counts));
    }

    fn mark_counted(&mut self, id: CommitId, counts: bool) {
        if counts {
            self.uncounted.remove(&id);
        } else {
            self.uncounted.insert(id);
        }
        self.touched_commits.insert(id);
        if let Some(c) = self.ids.get(&id) {
            // what perm reads of its targets (`edge_commits`) moved
            for o in &c.ops {
                self.rest.wrote(&Row::Commits(&o.target), true);
            }
            let targets: Vec<Tid> = c.ops.iter().map(|o| o.target).chain([c.signer]).collect();
            self.moved.extend(targets.iter().copied());
            self.ever.extend(targets.iter().copied());
            self.touched.extend(targets);
        }
    }

    /// Drops the edge writes of the commit with this ID: a commit applying none
    /// (`validity::add_role_commit`), or one no longer held. Invariant: perm reads only held
    /// commits (`apply::unindex`), so its held set is a function of the held commits, as an open
    /// finds it.
    pub fn remove(&mut self, id: &CommitId) {
        if let Some(c) = self.take(id) {
            self.log.push(Undo::Removed(c));
        }
    }

    /// Things whose creation record was added since the last call.
    /// `t`'s record counts as arrived again: its destruction fell, and what awaited it is judged again.
    pub fn record_back(&mut self, t: Tid) {
        self.records.push(t);
    }

    pub fn take_records(&mut self) -> Vec<Tid> {
        std::mem::take(&mut self.records)
    }

    /// Things whose held inputs changed since the last call of this one (`apply::waits`).
    pub fn take_moved(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.moved)
    }

    /// Holders some thing stopped naming since the last call.
    pub fn take_unnamed(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.unnamed)
    }

    /// Things whose held inputs changed since the last `take_touched`.
    pub fn touched(&self) -> &BTreeSet<Tid> {
        &self.touched
    }

    /// Things whose held inputs changed since the last call.
    pub fn take_touched(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.touched)
    }

    /// Notes that the walk's reading of commit `id` may have changed (it was indexed or
    /// unindexed, or an input of `validity::reading` moved); a rollback notes it again, so the
    /// timeline follows the restored index.
    pub fn touch_commit(&mut self, id: CommitId) {
        self.touched_commits.insert(id);
        self.log.push(Undo::Touched(id));
    }

    /// Whether a change of the held set waits for the timeline.
    pub fn is_touched(&self) -> bool {
        !self.touched.is_empty() || !self.touched_commits.is_empty()
    }

    /// The commits touched since the last call (`touch_commit`, an edge commit added, removed or
    /// counted otherwise).
    pub fn take_touched_commits(&mut self) -> BTreeSet<CommitId> {
        std::mem::take(&mut self.touched_commits)
    }

    /// Things whose edge writes or record changed since the last call (`ever`).
    pub fn take_ever(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.ever)
    }
}

impl Journaled for Held {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}", self.commits, self.created, self.holders, self.named, self.granted, self.mint_admin_of, self.ids, self.uncounted)
    }
    type Mark = usize;
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> usize {
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
        osis_base::memo::undoing(|| {
            while self.log.len() > m {
                let Some(u) = self.log.pop() else { break };
                match u {
                    Undo::Created(t, old) => {
                        self.set_created(t, old);
                    }
                    Undo::AddedCommit(c) => {
                        self.take(&c.id);
                    }
                    Undo::Removed(c) => self.put_commit(c),
                    Undo::Counted(id, counts) => self.mark_counted(id, counts),
                    Undo::Touched(id) => {
                        self.touched_commits.insert(id);
                    }
                }
            }
        })
    }
}

impl Held {
    /// Things with a held edge write or record.
    pub fn all_things(&self) -> Vec<Tid> {
        self.rest.read_all();
        self.records_read.read_all();
        let mut s: BTreeSet<Tid> = self.commits.keys().copied().collect();
        s.extend(self.created.keys().copied());
        s.into_iter().collect()
    }
    /// The edge commits on `thing` that count (`set_counted`).
    pub fn edge_commits(&self, thing: &Tid) -> Vec<Arc<RoleCommit>> {
        self.rest.read(&Row::Commits(thing));
        let Some(cs) = self.commits.get(thing) else { return Vec::new() };
        if self.uncounted.is_empty() {
            return cs.clone();
        }
        cs.iter().filter(|c| !self.uncounted.contains(&c.id)).cloned().collect()
    }
}

/// perm's timeline over the held set (`Core::timelines`), its reads stamped at the grain each
/// sees (`Read`): the whole of it (`get`), what is written on a thing's edges (`on`), the roles
/// on a thing (`roles_on`, `role`), each moved only by what it can see; and the keyless actor
/// grants over it (`keyless`), kept up to date at each update.
#[derive(Clone, Default)]
pub struct Timelines {
    of: osis_perm::Timeline,
    stamps: TlStamps,
    /// The keyless actor grants (target, holder) (`rotation::members::keyless_in`, spec/crypto.md
    /// §4 Key access).
    keyless: Arc<BTreeSet<(Tid, Tid)>>,
    /// The ways into a thing (`osis_perm::Timeline::ways_now`) searched since the edges last
    /// changed, each with the ts it was searched at and the `until` it holds before.
    ways: Ways,
}

/// `Timelines::ways`: a cache of the current edges.
#[derive(Default)]
struct Ways(std::sync::Mutex<BTreeMap<(Tid, osis_perm::Need), WaysAt>>);
type WaysAt = (Arc<osis_perm::graph::Ways>, osis_base::Ts, Option<osis_base::WallMs>);

impl Clone for Ways {
    fn clone(&self) -> Ways {
        Ways(std::sync::Mutex::new(self.0.lock().map(|m| m.clone()).unwrap_or_default()))
    }
}

impl Ways {
    fn clear(&mut self) {
        *self = Ways::default();
    }
}

/// `Timelines`' stamps, a table per kind of read (`Read`), each named for it (`Effects` causes).
#[derive(Clone)]
struct TlStamps {
    whole: Stamps,
    into: Stamps,
    held: Stamps,
    ever: Stamps,
    things: Stamps,
    known: Stamps,
    keyless: Stamps,
}

impl Default for TlStamps {
    fn default() -> Self {
        TlStamps {
            whole: Stamps::named("timelines: whole"),
            into: Stamps::named("timelines: into"),
            held: Stamps::named("timelines: held"),
            ever: Stamps::named("timelines: ever"),
            things: Stamps::named("timelines: things"),
            known: Stamps::named("timelines: known"),
            keyless: Stamps::named("timelines: keyless"),
        }
    }
}

impl TlStamps {
    fn of(&self, r: &Read) -> &Stamps {
        match r {
            Read::Whole => &self.whole,
            Read::Into(_) => &self.into,
            Read::Held(_) => &self.held,
            Read::Ever(_) => &self.ever,
            Read::Things => &self.things,
            Read::Known(_) => &self.known,
            Read::Keyless => &self.keyless,
        }
    }
    fn all(&self) -> [&Stamps; 7] {
        [&self.whole, &self.into, &self.held, &self.ever, &self.things, &self.known, &self.keyless]
    }
    fn read(&self, r: &Read) {
        self.of(r).read(r);
    }
    fn wrote(&self, r: &Read, present: bool) {
        self.of(r).wrote(r, present);
    }
    fn read_all(&self) {
        self.all().into_iter().for_each(Stamps::read_all);
    }
    fn wrote_all(&self) {
        self.all().into_iter().for_each(Stamps::wrote_all);
    }
}

/// What a read of `Timelines` is stamped by.
#[derive(Hash)]
enum Read {
    /// The whole timeline: moved by every update that changed the walk.
    Whole,
    /// The history of the edges into a thing (its record edge included): moved by a change of
    /// one (`osis_perm::Changed::edges`) or of its record.
    Into(Tid),
    /// The edge writes held on a thing, applied or not: moved by any change of its held inputs.
    Held(Tid),
    /// The edge writes held on a thing, any validity, and its record: what a chain walk reads of
    /// it, moved by `ever_moved`.
    Ever(Tid),
    /// The set of things known to the timeline.
    Things,
    /// Whether the timeline knows a thing (its record or an edge write on it held).
    Known(Tid),
    /// `Timelines::keyless`: moved when it changes.
    Keyless,
}

impl std::ops::Deref for Timelines {
    type Target = osis_perm::Timeline;
    fn deref(&self) -> &osis_perm::Timeline {
        self.stamps.read_all();
        &self.of
    }
}

/// A thing's edges in the timeline (`Timelines::on`): what is read of them depends on the
/// history of the edges into it alone (spec/permissions.md §5.1: its roster, each holder's
/// standing, the writes applied on them), and on the edge writes held on it (`held`).
pub struct On<'a> {
    tl: &'a osis_perm::Timeline,
    thing: Tid,
    stamps: &'a TlStamps,
}

impl<'a> On<'a> {
    /// The whole timeline, for what depends on more than the thing's edges (a write's
    /// authority): read whole (`Timelines::get`).
    pub fn whole(&self) -> &'a osis_perm::Timeline {
        self.stamps.read(&Read::Whole);
        self.tl
    }
    /// The edge writes held on it, applied or not (`Timeline::held_on`).
    pub fn held(&self) -> impl Iterator<Item = (osis_perm::WriteId, &'a RoleCommit, &'a osis_perm::EdgeOp)> + 'a {
        self.stamps.read(&Read::Held(self.thing));
        let (tl, thing) = (self.tl, self.thing);
        tl.held_on_owned(thing)
    }
    /// Whether one of them applies (`Timeline::is_applied`).
    pub fn is_applied(&self, w: &osis_perm::WriteId) -> bool {
        self.tl.is_applied(w)
    }
    /// `holder`'s edge on it just before `point` (`None`: now).
    pub fn edge_at(&self, holder: &Tid, point: Option<osis_perm::Point>) -> Option<osis_perm::Edge> {
        self.tl.edges_at(point).get(holder, &self.thing).copied()
    }
    /// Its holders by their current edges, its record edge included while it stands.
    pub fn holders(&self) -> Vec<(Tid, osis_perm::Edge)> {
        self.tl.edges_at(None).holders(&self.thing).map(|(m, e)| (*m, *e)).collect()
    }
    /// Its roster at `at` (`Timeline::roster`).
    pub fn roster(&self, at: osis_perm::At) -> BTreeMap<Tid, osis_perm::Edge> {
        self.tl.roster(&self.thing, at)
    }
    /// The edge write on it in force for `holder` (`Timeline::in_force`).
    pub fn in_force(&self, holder: &Tid) -> Option<osis_base::CommitId> {
        self.tl.in_force(holder, &self.thing)
    }
    /// The applied edge writes on it (`Timeline::applied_on`).
    pub fn applied(&self) -> impl Iterator<Item = (&'a RoleCommit, &'a osis_perm::EdgeOp)> + 'a {
        self.stamps.read(&Read::Held(self.thing));
        let (tl, thing) = (self.tl, self.thing);
        tl.held_on_owned(thing).filter(move |(w, _, _)| tl.is_applied(w)).map(|(_, c, o)| (c, o))
    }
    /// The holders whose edge on it ended by `ts` (`Timeline::ended`).
    pub fn holders_gone(&self, ts: osis_base::Ts) -> BTreeMap<Tid, (bool, Option<osis_perm::Point>, Role)> {
        self.tl.ended(&self.thing, ts)
    }
    /// The holders whose edge on it is lowered at `ts` (`Timeline::lowered`).
    pub fn holders_lowered(&self, ts: osis_base::Ts) -> BTreeSet<Tid> {
        self.tl.lowered(&self.thing, ts)
    }
    /// `Timeline::standing_since` of it.
    pub fn standing_since(&self) -> BTreeMap<Tid, Option<osis_perm::Point>> {
        self.tl.standing_since(&self.thing)
    }
}

impl Timelines {
    /// The timeline where it knows `thing` (a record or an edge write on it held), read whole.
    pub fn get(&self, thing: &Tid) -> Option<&osis_perm::Timeline> {
        self.stamps.read(&Read::Known(*thing));
        if !self.of.knows(thing) {
            return None;
        }
        self.stamps.read(&Read::Whole);
        Some(&self.of)
    }

    /// `thing`'s edges, read alone (`On`). `None` where the timeline does not know it.
    pub fn on(&self, thing: &Tid) -> Option<On<'_>> {
        self.stamps.read(&Read::Known(*thing));
        if !self.of.knows(thing) {
            return None;
        }
        self.stamps.read(&Read::Into(*thing));
        Some(On { tl: &self.of, thing: *thing, stamps: &self.stamps })
    }

    /// Every node's effective role on `thing` at `at` over the edges not in `skip`, each named
    /// (target, holder) (`Timeline::roles_on`): a walk back from it reads the edges into each
    /// node that reaches it and nothing else, so the answer moves with those alone.
    pub fn roles_on(&self, thing: &Tid, at: osis_perm::At, skip: &BTreeSet<(Tid, Tid)>) -> Arc<BTreeMap<Tid, Role>> {
        let roles = Arc::new(self.of.roles_on_without(thing, at, skip));
        for t in roles.keys() {
            self.stamps.read(&Read::Into(*t));
        }
        roles
    }

    /// `node`'s effective role on `thing` on the current edges at `ts`, and the earliest `until`
    /// before which the answer holds (`Timeline::roles_on_now`), read as `roles_on` is.
    pub fn role_now(&self, node: &Tid, thing: &Tid, ts: osis_base::Ts) -> (Option<Role>, Option<osis_base::WallMs>) {
        let (roles, until) = self.roles_now(thing, ts);
        (roles.get(node).copied(), until)
    }

    /// The path from `node` into `thing` giving `need` on the current edges at `ts`
    /// (`osis_perm::Timeline::path_now`): the things listed, the hops marked direct, and whether
    /// its last hop is a record edge.
    pub fn path_now(&self, node: &Tid, thing: &Tid, need: osis_perm::Need, ts: osis_base::Ts) -> Option<(Vec<Tid>, osis_base::format::PathMarks, bool)> {
        // the search reads the edges into everything that reaches `thing`
        self.stamps.read(&Read::Whole);
        let held = |e: &WaysAt| e.1 <= ts && e.2.is_none_or(|u| ts.wall_ms() < u);
        let cached = self.ways.0.lock().ok().and_then(|m| m.get(&(*thing, need)).filter(|e| held(e)).map(|e| e.0.clone()));
        let ways = match cached {
            Some(w) => w,
            None => {
                let (w, expires) = self.of.ways_now(thing, need, ts);
                let w = Arc::new(w);
                if let Ok(mut m) = self.ways.0.lock() {
                    m.insert((*thing, need), (w.clone(), ts, expires));
                }
                w
            }
        };
        ways.path(self.of.records(), node)
    }

    /// Every actor's effective role on `thing` on the current edges at `ts`, and the earliest
    /// `until` before which they hold, read as `roles_on` is.
    pub fn roles_now(&self, thing: &Tid, ts: osis_base::Ts) -> (Arc<BTreeMap<Tid, Role>>, Option<osis_base::WallMs>) {
        self.roles_now_without(thing, ts, &BTreeSet::new())
    }

    /// `roles_now` over the edges not in `skip`, each named (target, holder).
    pub fn roles_now_without(&self, thing: &Tid, ts: osis_base::Ts, skip: &BTreeSet<(Tid, Tid)>) -> (Arc<BTreeMap<Tid, Role>>, Option<osis_base::WallMs>) {
        let (roles, until) = self.of.roles_on_now_without(thing, ts, skip);
        for t in roles.keys().chain([thing]) {
            self.stamps.read(&Read::Into(*t));
        }
        (Arc::new(roles), until)
    }

    /// `node`'s effective role on `thing` at `at` (`roles_on`).
    pub fn role(&self, node: &Tid, thing: &Tid, at: osis_perm::At) -> Option<Role> {
        self.roles_on(thing, at, &BTreeSet::new()).get(node).copied()
    }

    /// The keyless actor grants held, (target, holder) (`rotation::members::key_access`).
    pub fn keyless(&self) -> Arc<BTreeSet<(Tid, Tid)>> {
        self.stamps.read(&Read::Keyless);
        self.keyless.clone()
    }

    /// Every thing the timeline knows, read as a set.
    pub fn things(&self) -> BTreeSet<Tid> {
        self.stamps.read(&Read::Things);
        self.of.things()
    }

    /// Stamps what an update over `touched` things changed (`c`).
    fn moved(&mut self, touched: &BTreeSet<Tid>, c: &osis_perm::Changed) {
        // the whole of it as role state: a delta coming or going moves no edge write's
        // standing and no edge (what reads a delta's verdict is judged again by `Changed::reached`)
        let w = &c.walk;
        if !c.ops.is_empty() || !c.created.is_empty() || !c.held.is_empty() || !w.edges.is_empty() || !w.cuts.is_empty() || !w.regrant.is_empty() || !w.chained.is_empty() {
            self.stamps.wrote(&Read::Whole, true);
        }
        if !c.created.is_empty() || c.edges().next().is_some() {
            self.ways.clear();
        }
        for t in touched.iter().chain(&c.held) {
            self.stamps.wrote(&Read::Held(*t), true);
        }
        for t in c.created.iter().chain(c.edges().map(|(_, t)| t)) {
            self.stamps.wrote(&Read::Into(*t), true);
        }
        // a thing is known by its record or an edge write on it: both are its held inputs
        for t in &c.known {
            self.stamps.wrote(&Read::Known(*t), true);
        }
        if !c.known.is_empty() {
            self.stamps.wrote(&Read::Things, true);
        }
        // a keyless grant closes a cycle of actor grants (spec/crypto.md §4 Key access): judged
        // anew where an actor's grant moved (a holder that is no key actor) or a record came or
        // went other than a new leaf's (its record edge is in no cycle: it holds nothing)
        let records = self.of.records();
        let leaf = |t: &Tid| records.link(t).is_some() && records.mint_admin_of(t).is_empty() && !self.of.holds_edge(t);
        if c.edges().any(|(h, _)| !records.is_key(h)) || c.created.iter().any(|t| !leaf(t)) {
            self.rekey();
        }
    }

    /// Brings `keyless` up to date with the edge state.
    fn rekey(&mut self) {
        let new = crate::rotation::members::keyless_in(&self.of);
        if *self.keyless != new {
            self.keyless = Arc::new(new);
            self.stamps.wrote(&Read::Keyless, true);
        }
    }

    /// Stamps the things whose edge writes or record the last update was given changed
    /// (`Held::take_ever`), once the timeline read them.
    pub fn ever_moved(&mut self, things: &BTreeSet<Tid>) {
        for t in things {
            self.stamps.wrote(&Read::Ever(*t), true);
        }
    }

    /// Brings the timeline up to the held set (`osis_perm::Timeline::update`): `commits` whose
    /// reading may have changed, `touched` things whose held inputs did.
    pub fn update(&mut self, held: &dyn osis_perm::HeldSet, commits: &BTreeSet<osis_base::CommitId>, touched: &BTreeSet<Tid>) -> osis_perm::Changed {
        let c = self.of.update(held, commits, touched);
        self.moved(touched, &c);
        c
    }

    /// The timeline changed by `f` in a way that may move any thing's (a trust set switched):
    /// every read moves and `keyless` is judged anew.
    pub fn change<T>(&mut self, f: impl FnOnce(&mut osis_perm::Timeline) -> T) -> T {
        self.stamps.wrote_all();
        self.ways.clear();
        let out = f(&mut self.of);
        self.keyless = Arc::new(crate::rotation::members::keyless_in(&self.of));
        out
    }

    /// The timeline with no read stamped, for a reading that stamps what it reads itself
    /// (`read_ever`: chain certificates).
    pub fn unstamped(&self) -> &osis_perm::Timeline {
        &self.of
    }

    /// Stamps a read of the edge writes held on `t`, of any validity, and its record (`Read::Ever`).
    pub fn read_ever(&self, t: &Tid) {
        self.stamps.read(&Read::Ever(*t));
    }

    /// The timeline for a reading that changes it and puts it back (`Timeline::disputes`).
    pub fn aside(&mut self) -> &mut osis_perm::Timeline {
        &mut self.of
    }
}

/// `from` and everything `next` (pushing the next steps from a thing) leads to, transitively.
fn walk(from: &BTreeSet<Tid>, next: impl Fn(&Tid, &mut Vec<Tid>)) -> BTreeSet<Tid> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<Tid> = from.iter().copied().collect();
    while let Some(t) = stack.pop() {
        if out.insert(t) {
            next(&t, &mut stack);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::Ts;
    use osis_perm::{Edge, EdgeOp};

    fn thing(admin: Tid, n: u8) -> CreationRecord {
        CreationRecord::Thing { admin, nonce: [n; 32], link: None, expires: None }
    }
    fn actor(n: u8) -> CreationRecord {
        CreationRecord::KeyActor { alg: 1, public_key: vec![n; 32], nonce: [n; 32], account: false }
    }
    fn grant(id: u64, by: Tid, on: Tid, to: Tid, role: Role) -> RoleCommit {
        let mut c = [0; 32];
        c[..8].copy_from_slice(&id.to_be_bytes());
        RoleCommit { id: CommitId(c), ts: Ts::make(osis_base::WallMs(1), 0).unwrap(), signer: by, listed: Vec::new(), direct: 0, frontier: None, ops: vec![EdgeOp { target: on, holder: to, edge: Some(Edge::new(role)) }] }
    }

    /// The held set alone as the walk reads it: each counting edge commit along the empty path.
    struct Bare<'a>(&'a Held);
    impl osis_perm::HeldSet for Bare<'_> {
        fn created(&self, t: &Tid) -> Option<CreationRecord> {
            self.0.created(t).cloned()
        }
        fn signed_as(&self, signer: &Tid) -> Vec<CommitId> {
            self.0.ids.values().filter(|c| c.signer == *signer).map(|c| c.id).collect()
        }
        fn commit(&self, id: &CommitId) -> Option<osis_perm::Held> {
            let c = self.0.counted(id)?;
            Some(osis_perm::Held { id: *id, ts: c.ts, signer: c.signer, parts: Vec::new(), role: Some(c), carriers: Vec::new() })
        }
    }

    /// Brings `tl` up to `h`.
    fn sync(h: &mut Held, tl: &mut Timelines) {
        let (touched, commits) = (h.take_touched(), h.take_touched_commits());
        tl.update(&Bare(h), &commits, &touched);
    }

    /// The timeline of `h` from scratch.
    fn scratch(h: &Held) -> osis_perm::Timeline {
        let mut tl = osis_perm::Timeline::default();
        tl.update(&Bare(h), &h.ids.keys().copied().collect(), &h.all_things().into_iter().collect());
        tl
    }

    /// The definition (spec/commits.md §4) by brute force, to judge the worklist by.
    fn least(h: &Held, t: Tid) -> BTreeSet<Tid> {
        let mut set = BTreeSet::from([t]);
        loop {
            let mut next = set.clone();
            for c in &set {
                if let Some(RecordLink::Admin(x)) = h.created(c).map(CreationRecord::record_link) {
                    next.insert(x);
                }
                for r in h.commits_on(c).iter().filter(|r| set.contains(&r.signer)) {
                    next.extend(r.ops.iter().filter(|o| o.target == *c && o.edge.as_ref().is_some_and(|e| e.role >= Role::Admin)).map(|o| o.holder));
                }
            }
            if next == set {
                return set;
            }
            set = next;
        }
    }


    // spec: none (internal: notes/engine.md, Derived values). Each read of the held set is
    // stamped by what it read: a memo of it keeps the answer a fresh read gives through any
    // change and undo (an edge commit added, removed, counted or not; a record created or
    // forgotten), and a change elsewhere reads nothing again.
    #[test]
    fn held_reads_move_with_what_they_read() {
        use osis_base::memo::Memo;
        // each read alone, by its index here: a memo reading two would move with either
        let read = |h: &Held, (r, t): &(u8, Tid)| -> Vec<[u8; 32]> {
            let ids = |cs: &[Arc<RoleCommit>]| cs.iter().map(|c| c.id.0).collect::<Vec<_>>();
            let tids = |ts: &mut dyn Iterator<Item = &Tid>| ts.map(|t| *t.as_bytes()).map(|b| { let mut x = [0; 32]; x[..15].copy_from_slice(&b); x }).collect::<Vec<_>>();
            match r {
                0 => ids(h.commits_on(t)),
                1 => ids(&h.edge_commits(t)),
                2 => tids(&mut h.holders_of(t)),
                3 => tids(&mut h.named_on(t)),
                4 => tids(&mut h.granted_on(t)),
                _ => tids(&mut h.mint_admin_of(t)),
            }
        };
        let memo: Memo<(u8, Tid), Vec<[u8; 32]>> = Memo::new("test held read");
        let by_id: Memo<CommitId, Option<CommitId>> = Memo::new("test held commit");
        let a: Vec<CreationRecord> = (0..3).map(actor).collect();
        let at: Vec<Tid> = a.iter().map(|x| x.tid()).collect();
        let (g, t) = (thing(at[0], 10), thing(at[1], 11));
        let all = [at[0], at[1], at[2], g.tid(), t.tid()];
        let mut h = Held::default();
        let c1 = grant(1, at[0], g.tid(), at[1], Role::Admin);
        let c2 = grant(2, at[1], t.tid(), at[2], Role::Write);
        let check = |h: &Held| {
            for id in [c1.id, c2.id] {
                assert_eq!(by_id.get(&id, || h.edge_commit(&id).map(|c| c.id)), h.edge_commit(&id).map(|c| c.id), "{id:?}");
            }
            for x in &all {
                for r in 0..6 {
                    let k = (r, *x);
                    assert_eq!(memo.get(&k, || read(h, &k)), read(h, &k), "read {r} of {x:?}");
                }
            }
        };
        let runs = || osis_base::costs::take().iter().filter(|x| x.0 == "test held read").map(|x| x.2).sum::<u64>();
        for x in a.iter().chain([&g]) {
            h.create(x.clone());
        }
        check(&h);
        h.create(t.clone());
        check(&h);
        h.add_commit(c1.clone());
        check(&h);
        osis_base::costs::take();
        h.add_commit(c2.clone());
        check(&h);
        // what reads g alone (and the mint admins, unnamed on either commit) stays
        assert_eq!(runs(), 5, "of t: its commits (twice), holders and grants; its new holder's things");
        let m = h.mark();
        h.set_counted(c2.id, false);
        check(&h);
        h.remove(&c1.id);
        check(&h);
        h.forget_record(&t.tid());
        check(&h);
        h.rollback_to(m);
        check(&h);
        h.set_counted(c2.id, false);
        h.set_counted(c2.id, true);
        check(&h);
    }

    // spec: none (internal: notes/engine.md, Derived values). Each read of the timelines moves
    // with what it can see: a thing's edges (`on`) and the roles on it with the edges into what
    // reaches it, the writes held on a thing with them, the keyless grants with their value; a memo of each keeps the answer a fresh read
    // gives through grants, a write applying nothing, removals, records, a cycle of actor grants
    // and an undo, and a grant on one actor reads nothing of another again.
    #[test]
    fn timeline_reads_move_with_what_they_read() {
        use osis_base::memo::Memo;
        use osis_perm::At;
        type Answer = Vec<String>;
        let read = |tl: &Timelines, (r, t): &(u8, Tid)| -> Answer {
            match r {
                0 => tl.on(t).map(|o| o.holders()).iter().map(|x| format!("{x:?}")).collect(),
                1 => tl.on(t).map(|o| o.roster(At::END)).iter().map(|x| format!("{x:?}")).collect(),
                2 => tl.on(t).map(|o| o.standing_since()).iter().map(|x| format!("{x:?}")).collect(),
                3 => vec![format!("{:?}", tl.roles_on(t, At::KEYS, &tl.keyless()))],
                4 => vec![format!("{:?}", tl.roles_on(t, At::END, &BTreeSet::new()))],
                5 => tl.things().iter().map(|x| format!("{x:?}")).collect(),
                6 => tl.on(t).iter().flat_map(|o| o.held()).map(|x| format!("{x:?}")).collect(),
                _ => vec![format!("{:?}", tl.keyless())],
            }
        };
        let memo: Memo<(u8, Tid), Answer> = Memo::new("test timeline read");
        let a: Vec<CreationRecord> = (0..4).map(actor).collect();
        let at: Vec<Tid> = a.iter().map(|x| x.tid()).collect();
        let (g1, g2, x, y, late) = (thing(at[0], 10), thing(at[0], 11), thing(at[0], 12), thing(at[0], 13), thing(at[3], 14));
        let things: Vec<Tid> = at.iter().copied().chain([&g1, &g2, &x, &y, &late].map(|r| r.tid())).collect();
        let (mut h, mut tl) = (Held::default(), Timelines::default());
        let update = |h: &mut Held, tl: &mut Timelines| {
            sync(h, tl);
        };
        let check = |tl: &Timelines| {
            for t in &things {
                for r in 0..8 {
                    let k = (r, *t);
                    assert_eq!(memo.get(&k, || read(tl, &k)), read(tl, &k), "read {r} of {t:?}");
                }
            }
        };
        let runs = || osis_base::costs::take().iter().filter(|x| x.0 == "test timeline read").map(|x| x.2).sum::<u64>();
        for r in a.iter().chain([&g1, &g2, &x, &y]) {
            h.create(r.clone());
        }
        update(&mut h, &mut tl);
        check(&tl);
        let c1 = grant(1, at[0], g1.tid(), at[1], Role::Write);
        h.add_commit(c1.clone());
        update(&mut h, &mut tl);
        check(&tl);
        osis_base::costs::take();
        h.add_commit(grant(2, at[0], g2.tid(), at[2], Role::Write));
        update(&mut h, &mut tl);
        check(&tl);
        // g2's holders, roster, standings, roles on it (twice) and writes held,
        // and the writes held on its author (a held input of every thing the commit names);
        // nothing of g1 or a1
        assert_eq!(runs(), 7, "a grant on g2");
        // a write by a party without authority applies nothing: held on g1, nothing else moves
        h.add_commit(grant(5, at[3], g1.tid(), at[3], Role::Admin));
        update(&mut h, &mut tl);
        check(&tl);
        // a cycle of actor grants: one of them is keyless
        h.add_commit(grant(3, at[0], y.tid(), x.tid(), Role::Read));
        update(&mut h, &mut tl);
        check(&tl);
        assert!(tl.keyless().is_empty());
        h.add_commit(grant(4, at[0], x.tid(), y.tid(), Role::Read));
        update(&mut h, &mut tl);
        check(&tl);
        assert_eq!(tl.keyless().len(), 1, "the later grant closing the cycle");
        let m = h.mark();
        h.remove(&c1.id);
        h.forget_record(&g2.tid());
        update(&mut h, &mut tl);
        check(&tl);
        h.rollback_to(m);
        update(&mut h, &mut tl);
        check(&tl);
        h.remove(&grant(3, at[0], y.tid(), x.tid(), Role::Read).id);
        update(&mut h, &mut tl);
        check(&tl);
        assert!(tl.keyless().is_empty());
        // a thing new to the timelines: the set of them moves, and its record edge
        h.create(late);
        update(&mut h, &mut tl);
        check(&tl);
    }

    // spec: none (internal: notes/engine.md, Derived values). The same, differential: random
    // edge writes (grants, removals, retains, `until`s; authors with and without authority) over
    // key actors and things under them and under each other, records created and forgotten,
    // commits removed, counted or not, and undos; after each update a memo of every read through
    // the timelines answers as a fresh read, and the keyless grants kept per component are those
    // of one evaluation of everything (`osis_keys::key_access` over all actor grants).
    #[test]
    fn timeline_reads_match_a_fresh_read_through_random_writes() {
        use osis_base::memo::Memo;
        use osis_perm::At;
        let (now, later) = (At::now(Ts::make(osis_base::WallMs(5), 0).unwrap()), At::now(Ts::make(osis_base::WallMs(9), 0).unwrap()));
        let read = |tl: &Timelines, (r, t): &(u8, Tid)| -> String {
            let on = || tl.on(t);
            match r {
                0 => format!("{:?}", on().map(|o| o.holders())),
                1 => format!("{:?}", on().map(|o| o.roster(At::END))),
                2 => format!("{:?}", on().map(|o| o.roster(now))),
                3 => format!("{:?}", on().map(|o| o.standing_since())),
                4 => format!("{:?}", on().map(|o| o.held().map(|(w, c, op)| (w, c.id, op.clone(), o.is_applied(&w), o.edge_at(&op.holder, Some(c.point())))).collect::<Vec<_>>())),
                5 => format!("{:?}", tl.roles_on(t, At::END, &BTreeSet::new())),
                6 => format!("{:?}", tl.roles_on(t, At::KEYS, &BTreeSet::new())),
                7 => format!("{:?}", tl.roles_on(t, now, &BTreeSet::new())),
                8 => format!("{:?}", tl.roles_on(t, At::KEYS, &tl.keyless())),
                9 => format!("{:?}", tl.things()),
                10 => format!("{:?}", tl.keyless()),
                _ => format!("{:?}", tl.get(t).map(|x| (x.applied_writes(), x.dropped_writes()))),
            }
        };
        let mut seed = 0x5eed_u64;
        let mut rng = move |n: usize| -> usize {
            seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            ((z ^ (z >> 31)) % n as u64) as usize
        };
        let roles = [Role::Read, Role::Write, Role::Admin];
        for world in 0..48u32 {
            let memo: Memo<(u8, Tid), String> = Memo::new("test timeline random");
            let keys: Vec<CreationRecord> = (0..3).map(actor).collect();
            // things under key actors, then under things (depth up to 3)
            let mut recs: Vec<CreationRecord> = keys.clone();
            for n in 0..6u8 {
                let admin = recs[rng(recs.len())].tid();
                recs.push(thing(admin, 40 + n));
            }
            let all: Vec<Tid> = recs.iter().map(|r| r.tid()).collect();
            let (mut h, mut tl) = (Held::default(), Timelines::default());
            for r in recs.iter().filter(|_| rng(3) > 0) {
                h.create(r.clone());
            }
            let (mut ids, mut marks, mut next) = (Vec::new(), Vec::new(), 0u64);
            for step in 0..60 {
                match rng(10) {
                    0..=4 => {
                        next += 1;
                        let pick = |rng: &mut dyn FnMut(usize) -> usize| all[rng(all.len())];
                        let (by, on, to) = (pick(&mut rng), pick(&mut rng), pick(&mut rng));
                        let edge = match rng(6) {
                            0 => None,
                            1 => Some(Edge::kept_end()),
                            2 => Some(Edge { until: Some(osis_base::WallMs(3 + rng(5) as u64)), ..Edge::new(roles[rng(3)]) }),
                            _ => Some(Edge::new(roles[rng(3)])),
                        };
                        let mut c = grant(next, by, on, to, Role::Read);
                        c.ts = Ts::make(osis_base::WallMs(1 + rng(4) as u64), next).unwrap();
                        c.ops[0].edge = edge;
                        ids.push(c.id);
                        h.add_commit(c);
                    }
                    5 if !ids.is_empty() => h.remove(&ids[rng(ids.len())]),
                    6 => {
                        let r = &recs[rng(recs.len())];
                        if h.created(&r.tid()).is_some() { h.forget_record(&r.tid()) } else { h.create(r.clone()) }
                    }
                    7 if !ids.is_empty() => h.set_counted(ids[rng(ids.len())], rng(2) == 0),
                    8 => marks.push(h.mark()),
                    _ => {
                        if let Some(m) = marks.pop() {
                            h.rollback_to(m);
                        }
                    }
                }
                sync(&mut h, &mut tl);
                for t in &all {
                    for r in 0..12 {
                        let k = (r, *t);
                        assert_eq!(memo.get(&k, || read(&tl, &k)), read(&tl, &k), "world {world} step {step}: read {r} of {t:?}");
                    }
                }
                let full = scratch(&h);
                let mut grants = Vec::new();
                for (t, on) in full.standing_since_all(None) {
                    for (m, since) in on {
                        if !matches!(h.created(&m), Some(CreationRecord::KeyActor { .. })) {
                            grants.push(osis_keys::Grant { order: (1u8, since), target: t, holder: m });
                        }
                    }
                }
                assert_eq!(*tl.keyless(), osis_keys::key_access(grants), "world {world} step {step}: keyless grants");
                // perm's walks kept per thing too, the clock moving past an `until` among them
                for (t, at) in all.iter().filter(|t| tl.of.knows(t)).flat_map(|t| [At::KEYS, now, later].map(|at| (t, at))) {
                    assert_eq!(*tl.roles_on(t, at, &BTreeSet::new()), full.roles_on_without(t, at, &BTreeSet::new()), "world {world} step {step}: roles on {t:?} at {at:?}");
                }
            }
        }
    }

    // spec/commits.md §4: a thing's possible admins are a function of what is held, in any order; more held only adds; what a signer outside them writes adds nothing, a chain of forgeries included.
    #[test]
    fn possible_admins_least_and_order_free_spec_commits_4() {
        let mut r = 0x9E37_79B9_7F4A_7C15u64;
        let mut rng = move |n: u64| {
            r ^= r << 13;
            r ^= r >> 7;
            r ^= r << 17;
            r % n
        };
        for _ in 0..300 {
            let actors: Vec<CreationRecord> = (0..5).map(actor).collect();
            let a: Vec<Tid> = actors.iter().map(|x| x.tid()).collect();
            let g = thing(a[0], 10);
            let t = thing(g.tid(), 11);
            let ids = [t.tid(), g.tid(), a[0], a[1], a[2], a[3], a[4]];
            let mut inputs: Vec<RoleCommit> = (0..rng(14)).map(|i| {
                let (by, on, to) = (a[rng(5) as usize], ids[rng(4) as usize], ids[rng(7) as usize]);
                let role = if rng(4) == 0 { Role::Write } else { Role::Admin };
                grant(i, by, on, to, role)
            }).collect();
            let base = |h: &mut Held| {
                for x in actors.iter().chain([&g, &t]) {
                    h.create(x.clone());
                }
            };
            let mut one = Held::default();
            base(&mut one);
            inputs.iter().for_each(|i| one.add_commit(i.clone()));
            let want = one.ever_admins(&t.tid());
            assert_eq!(want, least(&one, t.tid()));
            let writers = one.ever_writers(&t.tid());
            assert!(want.is_subset(&writers));
            // a shuffled order: every prefix a subset, the end alike
            for k in (1..inputs.len()).rev() {
                inputs.swap(k, rng(k as u64 + 1) as usize);
            }
            let mut h = Held::default();
            base(&mut h);
            let mut last = h.ever_admins(&t.tid());
            for i in &inputs {
                h.add_commit(i.clone());
                let now = h.ever_admins(&t.tid());
                assert!(last.is_subset(&now));
                last = now;
            }
            assert_eq!(last, want);
            assert_eq!(h.ever_writers(&t.tid()), writers);
            // forgeries by an outsider and by whom it names: nothing moves
            if let Some(out) = a.iter().copied().find(|x| !want.contains(x)) {
                let puppet = actor(99).tid();
                h.add_commit(grant(1000, out, t.tid(), out, Role::Admin));
                h.add_commit(grant(1001, out, t.tid(), puppet, Role::Admin));
                h.add_commit(grant(1002, puppet, t.tid(), a[0], Role::Admin));
                assert_eq!(h.ever_admins(&t.tid()), want);
                if !writers.contains(&out) {
                    assert_eq!(h.ever_writers(&t.tid()), writers);
                }
            }
            assert!(want.contains(&a[0]), "the mint admin's mint admin");
        }
    }
}
