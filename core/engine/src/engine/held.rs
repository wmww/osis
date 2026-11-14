//! perm's held set (notes/architecture.md §2: the node implements `HeldSet`): applied role
//! commits by target, `created.0` records, indexed by commit and by
//! holder, journaled for rollback, and remembering which things' inputs changed since perm last
//! looked (`take_touched`), so the timelines re-partition only around them. A role commit of an
//! account that does not count by the epoch rule (spec/permissions.md §5.5) stays held but no
//! timeline reads it (`set_counted`): the filter runs before the timeline.
//!
//! Reads and changes are stamped for memos (`memo::Stamps`): a record by its thing
//! (`created`), everything else per key of each map. `Timelines` holds perm's timelines over
//! it, its reads stamped by what they can see (`Read`).

use super::journal::Journaled;
use osis_base::memo::Stamps;
use osis_base::{CommitId, CreationRecord, RecordLink, Role, Tid};
use osis_perm::{HeldSet, RoleCommit};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Debug)]
enum Undo {
    Created(Tid, Option<CreationRecord>),
    AddedCommit(Arc<RoleCommit>),
    Removed(Arc<RoleCommit>),
    Counted(CommitId, bool),
}

#[derive(Clone, Debug, Default)]
pub struct Held {
    commits: BTreeMap<Tid, Vec<Arc<RoleCommit>>>,
    created: BTreeMap<Tid, CreationRecord>,
    /// Holder -> things it is named on (edge writes, a creation record naming its first admin), with counts.
    holders: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Thing -> holders named on it (the same pairs as `holders`).
    named: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Thing -> holders an edge write puts a grant for on it, with counts: the edges a path may
    /// climb (a removal names a holder but gives it none).
    granted: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// First admin -> the things whose creation record names it: the record chain's
    /// links down (spec/permissions.md §1).
    first_admin_of: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Commit -> its edge commit held here.
    ids: BTreeMap<CommitId, Arc<RoleCommit>>,
    log: Vec<Undo>,
    touched: BTreeSet<Tid>,
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
    /// left out of what perm reads (`HeldSet::edge_commits`). By ID, whether held or not, so a
    /// commit re-derived (`add_commit`) keeps its standing.
    uncounted: BTreeSet<CommitId>,
    /// Stamps `created`, per thing.
    records_read: Stamps,
    /// Stamps everything else, per key of each map (`Row`).
    rest: Stamps,
    /// Stamps each (holder, thing) pair of `holders` as it comes or goes (`is_named`,
    /// `pairs_feed`).
    pairs: Stamps,
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
    FirstAdminOf(&'a Tid),
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
    /// The held things whose record names `t` as first admin (one link down the record
    /// chain).
    pub fn first_admin_of(&self, t: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::FirstAdminOf(t));
        self.first_admin_of.get(t).into_iter().flatten()
    }
    /// The actors named as a holder on some thing (edge writes, a creation record naming its
    /// first admin).
    pub fn holders(&self) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::Holders);
        self.holders.keys()
    }
    /// Edge commits with a write on `t`, of any validity.
    pub fn commits_on(&self, t: &Tid) -> &[Arc<RoleCommit>] {
        self.rest.read(&Row::Commits(t));
        self.commits.get(t).map(Vec::as_slice).unwrap_or_default()
    }
    /// Things `holder` is named on as a holder (edge writes, a creation record naming its first admin).
    pub fn named_on(&self, holder: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest.read(&Row::Holder(holder));
        self.holders.get(holder).into_iter().flat_map(|m| m.keys())
    }

    /// Whether `holder` is named on `thing` (`named_on`), a read of that pair alone.
    pub fn is_named(&self, holder: &Tid, thing: &Tid) -> bool {
        self.pairs.read(&(*holder, *thing));
        self.holders.get(holder).is_some_and(|m| m.contains_key(thing))
    }

    /// A reader's cursor over the (holder, thing) pairs named from now on (`is_named`): one
    /// named and then undone is given too.
    pub fn pairs_feed(&self) -> osis_base::memo::Feed<(Tid, Tid)> {
        self.pairs.feed()
    }

    /// Holders named on `thing` (edge writes, a creation record naming its first admin).
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
        let mut out = BTreeSet::new();
        let mut stack: Vec<Tid> = from.iter().copied().collect();
        while let Some(t) = stack.pop() {
            if !out.insert(t) {
                continue;
            }
            stack.extend(self.first_admin_of(&t).copied());
            stack.extend(self.named_on(&t).copied());
        }
        out
    }

    /// Everyone granted on `t` (`granted_on`), for old node-sync's `downstream`.
    pub fn named_holders(&self, t: &Tid) -> Vec<Tid> {
        self.granted_on(t).copied().collect()
    }

    /// `from` and everything authority comes to them from: their first admins and the
    /// holders named on them, transitively (the search `reach` answers forward). A changed edge
    /// to holder `z` changes the roles only of `upstream({z})`.
    pub fn upstream(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<Tid> = from.iter().copied().collect();
        while let Some(t) = stack.pop() {
            if !out.insert(t) {
                continue;
            }
            if let Some(CreationRecord::Thing { admin, .. }) = self.created(&t) {
                stack.push(*admin);
            }
            stack.extend(self.holders_of(&t).copied());
        }
        out
    }

    /// `from` and everything below them by record links: the things whose record chains hold
    /// them.
    pub fn below(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<Tid> = from.iter().copied().collect();
        while let Some(t) = stack.pop() {
            if out.insert(t) {
                stack.extend(self.first_admin_of(&t).copied());
            }
        }
        out
    }

    /// Who named whom on `t` with `role` or above, as (signer, holder), of any validity and whatever
    /// followed, by edge writes.
    fn named_with(&self, t: &Tid, role: Role) -> impl Iterator<Item = (Tid, Tid)> {
        self.commits_on(t).iter().flat_map(move |r| r.ops.iter().filter(move |o| o.target == *t && o.edge.as_ref().is_some_and(|e| e.role >= role)).map(|o| (r.author, o.holder)))
    }

    /// `t`'s possible admins (spec/commits.md §4): the least set holding `t` and, with each member, its
    /// first admin and any holder named with admin on it by an edge write a member signed; of any validity and whatever followed. So a forger is in it only if a
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

    fn set_created(&mut self, t: Tid, r: Option<CreationRecord>) -> Option<CreationRecord> {
        self.records_read.wrote(&t, r.is_some());
        let old = match r {
            Some(r) => {
                if let Some(up) = r.first_admin() {
                    self.first_admin_of.entry(up).or_default().insert(t);
                    self.rest.wrote(&Row::FirstAdminOf(&up), true);
                }
                self.created.insert(t, r)
            }
            None => self.created.remove(&t),
        };
        let same = matches!((&old, self.created.get(&t)), (Some(o), Some(n)) if o == n);
        if let Some(up) = old.as_ref().and_then(|o| o.first_admin())
            && self.created.get(&t).is_none_or(|n| n.first_admin() != Some(up))
            && let Some(s) = self.first_admin_of.get_mut(&up)
        {
            s.remove(&t);
            if s.is_empty() {
                self.first_admin_of.remove(&up);
            }
            self.rest.wrote(&Row::FirstAdminOf(&up), self.first_admin_of.contains_key(&up));
        }
        if same {
            // the same record: nothing perm reads changed
            return old;
        }
        // a thing's first admin is named on it by its record (spec/permissions.md §1)
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
                if *n == 1 {
                    self.pairs.wrote_added(&(m, t), true, true);
                }
                self.named.entry(t).or_default().insert(m);
            } else {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    e.remove(&t);
                    self.pairs.wrote(&(m, t), false);
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
        self.touched.insert(c.author);
        self.moved.insert(c.author);
        self.count(named(&c), true);
        self.count_granted(&c, true);
        self.rest.wrote(&Row::Id(&c.id), true);
        self.ids.insert(c.id, c);
    }

    /// Takes out the commit with this ID (exactly this Arc).
    fn take(&mut self, id: &CommitId) -> Option<Arc<RoleCommit>> {
        let c = self.ids.remove(id)?;
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
        if let Some(c) = self.ids.get(&id) {
            // what perm reads of its targets (`edge_commits`) moved
            for o in &c.ops {
                self.rest.wrote(&Row::Commits(&o.target), true);
            }
            let targets: Vec<Tid> = c.ops.iter().map(|o| o.target).chain([c.author]).collect();
            self.moved.extend(targets.iter().copied());
            self.ever.extend(targets.iter().copied());
            self.touched.extend(targets);
        }
    }

    /// Drops the commit with this ID.
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

    /// Things whose edge writes or record changed since the last call (`ever`).
    pub fn take_ever(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.ever)
    }
}

impl Journaled for Held {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}", self.commits, self.created, self.holders, self.named, self.granted, self.first_admin_of, self.ids, self.uncounted)
    }
    type Mark = usize;
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> usize {
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
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
            }
        }
    }
}

impl HeldSet for Held {
    fn things(&self) -> Vec<Tid> {
        self.rest.read_all();
        self.records_read.read_all();
        let mut s: BTreeSet<Tid> = self.commits.keys().copied().collect();
        s.extend(self.created.keys().copied());
        s.into_iter().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<RoleCommit>> {
        self.rest.read(&Row::Commits(thing));
        let Some(cs) = self.commits.get(thing) else { return Vec::new() };
        if self.uncounted.is_empty() {
            return cs.clone();
        }
        cs.iter().filter(|c| !self.uncounted.contains(&c.id)).cloned().collect()
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        self.records_read.read(thing);
        self.created.get(thing).cloned()
    }
}

/// perm's timelines over the held set (`Core::timelines`), its reads stamped at the grain each
/// sees (`Read`): a thing's whole timeline (`get`), what is written on a thing's edges (`on`),
/// the roles on a thing (`roles_on`, `role`), each moved only by what it can see; and the
/// keyless actor grants over them (`keyless`), kept up to date at each update.
#[derive(Clone)]
pub struct Timelines {
    of: osis_perm::Timelines,
    stamps: Stamps,
    /// The keyless actor grants (target, holder): the union of each component's
    /// (`rotation::members::keyless_in`, spec/crypto.md §4 Key access: a keyless grant closes a
    /// cycle of actor grants, which lies in one component).
    keyless: Arc<BTreeSet<(Tid, Tid)>>,
}

/// What a read of `Timelines` is stamped by.
#[derive(Hash)]
enum Read {
    /// The timeline of a thing's component: moved by every update that evaluated or continued
    /// it (`osis_perm::Timelines::changed`) or was given the thing.
    Whole(Tid),
    /// The history of the edges into a thing (its record edge included): moved by a change of
    /// one (`osis_perm::Changed::edges`) or of its record.
    Into(Tid),
    /// The edge writes held on a thing, applied or not: moved by any change of its held inputs.
    Held(Tid),
    /// The edge writes held on a thing, any validity, and its record: what a chain walk reads of
    /// it (`certificates`), moved by `ever_moved`.
    Ever(Tid),
    /// The set of things with a timeline.
    Things,
    /// `Timelines::keyless`: moved when it changes.
    Keyless,
}

impl Default for Timelines {
    fn default() -> Self {
        Timelines { of: osis_perm::Timelines::new(), stamps: Stamps::default(), keyless: Arc::default() }
    }
}

impl std::ops::Deref for Timelines {
    type Target = osis_perm::Timelines;
    fn deref(&self) -> &osis_perm::Timelines {
        self.stamps.read_all();
        &self.of
    }
}

/// A thing's edges in its timeline (`Timelines::on`): what is read of them depends on the
/// history of the edges into it alone (spec/permissions.md §5.1: its roster, each holder's
/// standing, the writes applied on them), and on the edge writes held on it (`held`).
pub struct On<'a> {
    tl: &'a osis_perm::Timeline,
    thing: Tid,
    stamps: &'a Stamps,
}

impl<'a> On<'a> {
    /// The whole timeline, for what depends on more than the thing's edges (a write's
    /// authority): read whole (`Timelines::get`).
    pub fn whole(&self) -> &'a osis_perm::Timeline {
        self.stamps.read(&Read::Whole(self.thing));
        self.tl
    }
    /// The edge writes held on it, applied or not (`Timeline::held_on`).
    pub fn held(&self) -> impl Iterator<Item = (osis_perm::WriteId, &'a RoleCommit, &'a osis_perm::EdgeOp)> + 'a {
        self.stamps.read(&Read::Held(self.thing));
        self.tl.held_on(&self.thing)
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
        self.tl.applied_on(&self.thing)
    }
    /// `Timeline::standing_since` of it.
    pub fn standing_since(&self) -> BTreeMap<Tid, Option<osis_perm::Point>> {
        self.tl.standing_since(&self.thing)
    }
}

impl Timelines {
    /// The timeline of the component holding `thing`, read whole.
    pub fn get(&self, thing: &Tid) -> Option<&osis_perm::Timeline> {
        self.stamps.read(&Read::Whole(*thing));
        self.of.get(thing)
    }

    /// `thing`'s edges, read alone (`On`). `None` without a timeline, read as the set of things:
    /// a thing gains one with no edge into it changing (a write naming it that sets nothing).
    pub fn on(&self, thing: &Tid) -> Option<On<'_>> {
        let Some(tl) = self.of.get(thing) else {
            self.stamps.read(&Read::Things);
            return None;
        };
        self.stamps.read(&Read::Into(*thing));
        Some(On { tl, thing: *thing, stamps: &self.stamps })
    }

    /// Every node's effective role on `thing` at `at` over the edges not in `skip`, each named
    /// (target, holder) (`Timeline::roles_on`): a walk back from it reads the edges into each
    /// node that reaches it and nothing else, so the answer moves with those alone.
    /// Empty without a timeline, read as the set of things.
    pub fn roles_on(&self, thing: &Tid, at: osis_perm::At, skip: &BTreeSet<(Tid, Tid)>) -> Arc<BTreeMap<Tid, Role>> {
        let Some(tl) = self.of.get(thing) else {
            self.stamps.read(&Read::Things);
            return Arc::default();
        };
        let roles = if skip.is_empty() { tl.roles_on(thing, at) } else { Arc::new(tl.roles_on_without(thing, at, skip)) };
        for t in roles.keys() {
            self.stamps.read(&Read::Into(*t));
        }
        roles
    }

    /// `node`'s chain certificates for `thing` (`Timeline::certificates`), read by what they are
    /// made of: the held inputs of each thing that ever reaches `thing` and of each thing whose
    /// record goes (`Read::Held`), so a change elsewhere in the component moves none of it. Empty
    /// without a timeline, read as the set of things.
    pub fn certificates(&self, node: &Tid, thing: &Tid) -> osis_perm::Certificates {
        self.chains(thing, |tl| tl.certificates(node, thing), Some(node))
    }

    /// Every node's chain certificates for `thing` (`Timeline::certificates_into`), read as
    /// `certificates` is.
    pub fn certificates_into(&self, thing: &Tid) -> osis_perm::Certificates {
        self.chains(thing, |tl| tl.certificates_into(&BTreeSet::from([*thing])), None)
    }

    fn chains(&self, thing: &Tid, f: impl FnOnce(&osis_perm::Timeline) -> osis_perm::Certificates, node: Option<&Tid>) -> osis_perm::Certificates {
        let Some(tl) = self.of.get(thing) else {
            self.stamps.read(&Read::Things);
            return osis_perm::Certificates::default();
        };
        let out = f(tl);
        for t in tl.ever_into(thing).iter().chain(&out.created).chain(node) {
            self.stamps.read(&Read::Ever(*t));
        }
        out
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

    /// Every thing with a timeline, read as a set: what each one's are needs its own read.
    pub fn things(&self) -> impl Iterator<Item = &Tid> {
        self.stamps.read(&Read::Things);
        self.of.things()
    }

    /// Stamps what an update given `touched` changed (`c`), from how many things had a timeline
    /// before it (`had`).
    fn moved(&mut self, touched: &BTreeSet<Tid>, c: &osis_perm::Changed, had: usize) {
        for t in touched.iter().chain(self.of.changed()) {
            self.stamps.wrote(&Read::Whole(*t), true);
        }
        for t in touched {
            self.stamps.wrote(&Read::Held(*t), true);
        }
        // a record that came or went (`created` also names a thing only joining a component):
        // its record edge
        let records: BTreeSet<Tid> = c.created.intersection(touched).copied().collect();
        for t in records.iter().chain(c.edges.iter().map(|(_, t)| t)) {
            self.stamps.wrote(&Read::Into(*t), true);
        }
        let has = self.of.things().len();
        debug_assert!(has >= had, "an update removed things from the timelines");
        if has != had {
            self.stamps.wrote(&Read::Things, true);
        }
        self.rekey(c, &records);
    }

    /// Brings `keyless` up to date with an update's changes (`c`, the records that came or went
    /// `records`): each component holding the target of a changed edge of an actor (a holder
    /// that is no key actor) or such a record is judged anew. Elsewhere no actor grant's standing
    /// or order moved, and components only merging or splitting change no component's grants.
    fn rekey(&mut self, c: &osis_perm::Changed, records: &BTreeSet<Tid>) {
        let of = &self.of;
        let actor = |h: &Tid, t: &Tid| of.get(t).is_some_and(|tl| !tl.records().is_key(h));
        let mut comps: Vec<&osis_perm::Timeline> = Vec::new();
        for t in c.edges.iter().filter(|(h, t)| actor(h, t)).map(|(_, t)| t).chain(records) {
            if let Some(tl) = of.get(t)
                && !comps.iter().any(|x| std::ptr::eq(*x, tl))
            {
                comps.push(tl);
            }
        }
        let within = |t: &Tid| of.get(t).is_some_and(|tl| comps.iter().any(|x| std::ptr::eq(*x, tl)));
        let old: BTreeSet<(Tid, Tid)> = self.keyless.iter().filter(|(t, _)| within(t)).copied().collect();
        let new: BTreeSet<(Tid, Tid)> = comps.iter().flat_map(|tl| crate::rotation::members::keyless_in(tl)).collect();
        if old != new {
            let k = Arc::make_mut(&mut self.keyless);
            k.retain(|x| !old.contains(x));
            k.extend(new);
            self.stamps.wrote(&Read::Keyless, true);
        }
    }

    /// Stamps the things whose edge writes or record the last update was given changed
    /// (`Held::take_ever`), once the timelines read them.
    pub fn ever_moved(&mut self, things: &BTreeSet<Tid>) {
        for t in things {
            self.stamps.wrote(&Read::Ever(*t), true);
        }
    }

    pub fn update_touched(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>) -> osis_perm::Changed {
        let had = self.of.things().len();
        let c = self.of.update_touched(held, touched);
        self.moved(touched, &c, had);
        c
    }

    pub fn update_touched_cached(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>, saved: &mut dyn FnMut(&Tid) -> Option<Vec<u8>>, salt: &[u8]) -> osis_perm::Changed {
        let had = self.of.things().len();
        let c = self.of.update_touched_cached(held, touched, saved, salt);
        self.moved(touched, &c, had);
        c
    }

    /// The timelines changed by `f` in a way that may move any thing's (a trust set switched):
    /// every read moves and `keyless` is judged anew.
    pub fn change<T>(&mut self, f: impl FnOnce(&mut osis_perm::Timelines) -> T) -> T {
        self.stamps.wrote_all();
        let out = f(&mut self.of);
        self.keyless = Arc::new(self.of.each().flat_map(crate::rotation::members::keyless_in).collect());
        out
    }

    /// The timelines' bookkeeping, which moves no timeline: dispute detection's switch and
    /// findings, what was saved, the tests' path switch.
    pub fn aside(&mut self) -> &mut osis_perm::Timelines {
        &mut self.of
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::Ts;
    use osis_perm::{Edge, EdgeOp};

    fn thing(admin: Tid, n: u8) -> CreationRecord {
        CreationRecord::Thing { admin, nonce: [n; 32], link: None }
    }
    fn actor(n: u8) -> CreationRecord {
        CreationRecord::KeyActor { alg: 1, public_key: vec![n; 32], nonce: [n; 32], account: false }
    }
    fn grant(id: u64, by: Tid, on: Tid, to: Tid, role: Role) -> RoleCommit {
        let mut c = [0; 32];
        c[..8].copy_from_slice(&id.to_be_bytes());
        RoleCommit { id: CommitId(c), ts: Ts::make(osis_base::WallMs(1), 0).unwrap(), author: by, actor: by, frontier: None, ops: vec![EdgeOp { target: on, holder: to, edge: Some(Edge::new(role)) }] }
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
                for r in h.commits_on(c).iter().filter(|r| set.contains(&r.author)) {
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
                1 => ids(&HeldSet::edge_commits(h, t)),
                2 => tids(&mut h.holders_of(t)),
                3 => tids(&mut h.named_on(t)),
                4 => tids(&mut h.granted_on(t)),
                _ => tids(&mut h.first_admin_of(t)),
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
        // what reads g alone (and the first admins, unnamed on either commit) stays
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
    // and an undo, and a grant on one group reads nothing of another again.
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
                5 => tl.things().map(|x| format!("{x:?}")).collect(),
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
            let touched = h.take_touched();
            tl.update_touched(h, &touched);
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
        use osis_perm::{At, Timeline};
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
                9 => format!("{:?}", tl.things().collect::<Vec<_>>()),
                10 => format!("{:?}", tl.keyless()),
                _ => format!("{:?}", tl.get(t).map(|x| (x.applied().clone(), x.dropped().clone()))),
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
                let touched = h.take_touched();
                tl.update_touched(&h, &touched);
                for t in &all {
                    for r in 0..12 {
                        let k = (r, *t);
                        assert_eq!(memo.get(&k, || read(&tl, &k)), read(&tl, &k), "world {world} step {step}: read {r} of {t:?}");
                    }
                }
                let full = Timeline::evaluate(&h);
                let mut grants = Vec::new();
                for (t, on) in full.standing_since_all() {
                    for (m, since) in on {
                        if !matches!(h.created(&m), Some(CreationRecord::KeyActor { .. })) {
                            grants.push(osis_keys::Grant { order: (1u8, since), target: t, holder: m });
                        }
                    }
                }
                assert_eq!(*tl.keyless(), osis_keys::key_access(grants), "world {world} step {step}: keyless grants");
                // perm's walks kept per thing too, the clock moving past an `until` among them
                for (t, at) in all.iter().filter(|t| tl.of.get(t).is_some()).flat_map(|t| [At::KEYS, now, later].map(|at| (t, at))) {
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
            assert!(want.contains(&a[0]), "the first admin's first admin");
        }
    }
}
