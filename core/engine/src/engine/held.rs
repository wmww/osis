//! perm's held set (notes/architecture.md §2: the node implements `HeldSet`): applied role
//! commits by target, `created.0` records, indexed by commit and by
//! holder, journaled for rollback, and remembering which things' inputs changed since perm last
//! looked (`take_touched`), so the timelines re-partition only around them. A role commit of an
//! account that does not count by the epoch rule (spec/permissions.md §5.5) stays held but no
//! timeline reads it (`set_counted`): the filter runs before the timeline.
//!
//! Reads and changes are stamped for memos (`memo::Stamps`): a record by its thing
//! (`created`), everything else as one whole. `Timelines` holds perm's timelines over it,
//! stamped per thing.

use super::journal::Journaled;
use super::memo::Stamps;
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
    /// First admin -> the things whose creation record names it: the record chain's
    /// links down (spec/permissions.md §1).
    first_admin_of: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Commit -> its edge commit held here.
    ids: BTreeMap<CommitId, Arc<RoleCommit>>,
    log: Vec<Undo>,
    touched: BTreeSet<Tid>,
    /// The same, for `take_moved`.
    moved: BTreeSet<Tid>,
    /// Things whose creation record `create` added since `take_records`.
    records: Vec<Tid>,
    /// Role commits held that do not count (an account's at a closed epoch no word names):
    /// left out of what perm reads (`HeldSet::edge_commits`). By ID, whether held or not, so a
    /// commit re-derived (`add_commit`) keeps its standing.
    uncounted: BTreeSet<CommitId>,
    /// Stamps `created`, per thing.
    records_read: Stamps,
    /// Stamps everything else, as one.
    rest_read: Stamps,
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
    /// The held things whose record names `t` as first admin (one link down the record
    /// chain).
    pub fn first_admin_of(&self, t: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest_read.read_all();
        self.first_admin_of.get(t).into_iter().flatten()
    }
    /// The actors named as a holder on some thing (edge writes, a creation record naming its
    /// first admin).
    pub fn holders(&self) -> impl Iterator<Item = &Tid> {
        self.rest_read.read_all();
        self.holders.keys()
    }
    /// Edge commits with a write on `t`, of any validity.
    pub fn commits_on(&self, t: &Tid) -> &[Arc<RoleCommit>] {
        self.rest_read.read_all();
        self.commits.get(t).map(Vec::as_slice).unwrap_or_default()
    }
    /// Things `holder` is named on as a holder (edge writes, a creation record naming its first admin).
    pub fn named_on(&self, holder: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest_read.read_all();
        self.holders.get(holder).into_iter().flat_map(|m| m.keys())
    }

    /// Holders named on `thing` (edge writes, a creation record naming its first admin).
    pub fn holders_of(&self, thing: &Tid) -> impl Iterator<Item = &Tid> {
        self.rest_read.read_all();
        self.named.get(thing).into_iter().flatten()
    }

    /// `from` and everything authority flows to from them: what they own, the things they are
    /// named on as holders, transitively (spec/permissions.md §1: paths climb record links and
    /// role edges). A change of authority at `from` changes it only there.
    pub fn reach(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        self.rest_read.read_all();
        let mut out = BTreeSet::new();
        let mut stack: Vec<Tid> = from.iter().copied().collect();
        while let Some(t) = stack.pop() {
            if !out.insert(t) {
                continue;
            }
            stack.extend(self.first_admin_of.get(&t).into_iter().flatten().copied());
            stack.extend(self.named_on(&t).copied());
        }
        out
    }

    /// Everyone named as a holder on `t`, of any validity and whatever followed.
    pub fn named_holders(&self, t: &Tid) -> Vec<Tid> {
        self.named_with(t, Role::Read).map(|(_, h)| h).collect()
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

    /// `t`'s possible holders of `role` (spec/commits.md §4): possible admins for admin, possible
    /// writers below.
    pub fn ever_holders(&self, t: &Tid, role: Role) -> BTreeSet<Tid> {
        if role == Role::Admin { self.ever_admins(t) } else { self.ever_writers(t) }
    }

    fn set_created(&mut self, t: Tid, r: Option<CreationRecord>) -> Option<CreationRecord> {
        self.records_read.wrote(&t, r.is_some());
        self.rest_read.wrote_all();
        let old = match r {
            Some(r) => {
                if let Some(up) = r.first_admin() {
                    self.first_admin_of.entry(up).or_default().insert(t);
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
        self.moved.insert(t);
        old
    }

    fn count(&mut self, pairs: Vec<(Tid, Tid)>, add: bool) {
        for (m, t) in pairs {
            let e = self.holders.entry(m).or_default();
            let n = e.entry(t).or_default();
            if add {
                *n += 1;
                self.named.entry(t).or_default().insert(m);
            } else {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    e.remove(&t);
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
            }
        }
    }

    fn put_commit(&mut self, c: Arc<RoleCommit>) {
        let targets: BTreeSet<Tid> = c.ops.iter().map(|o| o.target).collect();
        for t in &targets {
            self.commits.entry(*t).or_default().push(c.clone());
        }
        self.moved.extend(targets.iter().copied());
        self.touched.extend(targets);
        self.touched.insert(c.author);
        self.moved.insert(c.author);
        self.count(named(&c), true);
        self.rest_read.wrote_all();
        self.ids.insert(c.id, c);
    }

    /// Takes out the commit with this ID (exactly this Arc).
    fn take(&mut self, id: &CommitId) -> Option<Arc<RoleCommit>> {
        let c = self.ids.remove(id)?;
        self.rest_read.wrote_all();
        for o in &c.ops {
            if let Some(v) = self.commits.get_mut(&o.target) {
                v.retain(|x| !Arc::ptr_eq(x, &c));
                if v.is_empty() {
                    self.commits.remove(&o.target);
                }
            }
            self.touched.insert(o.target);
            self.moved.insert(o.target);
        }
        self.count(named(&c), false);
        Some(c)
    }

    /// Adds a creation record under its tid.
    pub fn create(&mut self, record: CreationRecord) {
        let t = record.tid();
        self.records.push(t);
        let old = self.set_created(t, Some(record));
        self.log.push(Undo::Created(t, old));
    }

    /// Forgets a thing's record (`retention::end`: the thing ended).
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
        self.rest_read.read_all();
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
            let targets: Vec<Tid> = c.ops.iter().map(|o| o.target).chain([c.author]).collect();
            self.moved.extend(targets.iter().copied());
            self.touched.extend(targets);
        }
        self.rest_read.wrote_all();
    }

    /// Drops the commit with this ID.
    pub fn remove(&mut self, id: &CommitId) {
        if let Some(c) = self.take(id) {
            self.log.push(Undo::Removed(c));
        }
    }

    /// Things whose creation record was added since the last call.
    /// `t`'s record counts as arrived again: its ending fell, and what awaited it is judged again.
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

    /// Things whose held inputs changed since the last `take_touched`.
    pub fn touched(&self) -> &BTreeSet<Tid> {
        &self.touched
    }

    /// Things whose held inputs changed since the last call.
    pub fn take_touched(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.touched)
    }
}

impl Journaled for Held {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?} {:?} {:?} {:?}", self.commits, self.created, self.holders, self.named, self.first_admin_of, self.ids, self.uncounted)
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
        self.rest_read.read_all();
        let mut s: BTreeSet<Tid> = self.commits.keys().copied().collect();
        s.extend(self.created.keys().copied());
        s.into_iter().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<RoleCommit>> {
        self.rest_read.read_all();
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

/// perm's timelines over the held set (`Core::timelines`), stamped per thing: an update stamps
/// the things whose inputs it was given and those whose timeline it evaluated or continued
/// (`osis_perm::Timelines::changed`: every other thing's answers are unchanged).
#[derive(Clone)]
pub struct Timelines {
    of: osis_perm::Timelines,
    stamps: Stamps,
}

impl Default for Timelines {
    fn default() -> Self {
        Timelines { of: osis_perm::Timelines::new(), stamps: Stamps::default() }
    }
}

impl std::ops::Deref for Timelines {
    type Target = osis_perm::Timelines;
    fn deref(&self) -> &osis_perm::Timelines {
        self.stamps.read_all();
        &self.of
    }
}

impl Timelines {
    /// The timeline of the component holding `thing`.
    pub fn get(&self, thing: &Tid) -> Option<&osis_perm::Timeline> {
        self.stamps.read(thing);
        self.of.get(thing)
    }

    fn moved(&mut self, touched: &BTreeSet<Tid>) {
        for t in touched.iter().chain(self.of.changed()) {
            self.stamps.wrote(t, true);
        }
    }

    pub fn update_touched(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>) -> osis_perm::Changed {
        let c = self.of.update_touched(held, touched);
        self.moved(touched);
        c
    }

    pub fn update_touched_cached(&mut self, held: &dyn HeldSet, touched: &BTreeSet<Tid>, saved: &mut dyn FnMut(&Tid) -> Option<Vec<u8>>, salt: &[u8]) -> osis_perm::Changed {
        let c = self.of.update_touched_cached(held, touched, saved, salt);
        self.moved(touched);
        c
    }

    /// The timelines to change in a way that may move any thing's.
    pub fn change(&mut self) -> &mut osis_perm::Timelines {
        self.stamps.wrote_all();
        &mut self.of
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
        CreationRecord::Thing { admin, nonce: [n; 32], link: false }
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
                let puppet = Tid::of_record(&actor(99));
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
