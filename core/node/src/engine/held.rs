//! perm's held set (notes/architecture.md §2: the node implements `HeldSet`): applied membership
//! commits by target, roster snapshots by thing, `/created` records, indexed by commit and by
//! member, journaled for rollback, and remembering which things' inputs changed since perm last
//! looked (`take_touched`), so the timelines re-partition only around them.

use super::journal::Journaled;
use osis_core::{CommitId, CreationRecord, Tid};
use osis_perm::{HeldSet, MembershipCommit, RosterSnapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug)]
enum Undo {
    Created(Tid, Option<CreationRecord>),
    AddedCommit(Arc<MembershipCommit>),
    AddedSnapshot(Arc<RosterSnapshot>),
    Removed(Vec<Arc<MembershipCommit>>, Vec<Arc<RosterSnapshot>>),
}

/// What one commit ID holds: its edge commit and its roster snapshots (one per thing).
type Records = (Option<Arc<MembershipCommit>>, Vec<Arc<RosterSnapshot>>);

#[derive(Debug, Default)]
pub(crate) struct Held {
    commits: BTreeMap<Tid, Vec<Arc<MembershipCommit>>>,
    snapshots: BTreeMap<Tid, Vec<Arc<RosterSnapshot>>>,
    created: BTreeMap<Tid, CreationRecord>,
    /// Member -> things it is named on (edge writes, rosters, ledgers), with counts.
    members: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Thing -> members named on it (the same pairs as `members`).
    named: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Owner -> things it owns (by creation records).
    owned: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Commit -> what it holds here (an ID's edge commit and roster snapshots).
    ids: BTreeMap<CommitId, Records>,
    log: Vec<Undo>,
    touched: BTreeSet<Tid>,
    /// Count changes (rollbacks included), of anything and of what `validity::reaches` reads:
    /// the edge writes, a record replaced or removed, and a new record of a thing named as a
    /// member or owning a held thing (its owner link) (`apply::waits`).
    generation: u64,
    edges: u64,
    /// Things whose creation record `create` added since `take_records`.
    records: Vec<Tid>,
}

fn named(c: &MembershipCommit) -> Vec<(Tid, Tid)> {
    c.ops.iter().map(|o| (o.member, o.target)).collect()
}

fn named_snapshot(s: &RosterSnapshot) -> Vec<(Tid, Tid)> {
    s.roster.keys().chain(s.ledger.iter().map(|t| &t.member)).map(|m| (*m, s.thing)).collect()
}

impl Held {
    pub fn created(&self, t: &Tid) -> Option<&CreationRecord> {
        self.created.get(t)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn edges(&self) -> u64 {
        self.edges
    }
    pub fn snapshots_of(&self, t: &Tid) -> &[Arc<RosterSnapshot>] {
        self.snapshots.get(t).map(Vec::as_slice).unwrap_or_default()
    }
    /// Things `member` is named on as a member (edge writes, rosters, ledgers).
    pub fn named_on(&self, member: &Tid) -> impl Iterator<Item = &Tid> {
        self.members.get(member).into_iter().flat_map(|m| m.keys())
    }

    /// Members named on `thing` (edge writes, rosters, ledgers).
    pub fn members_of(&self, thing: &Tid) -> impl Iterator<Item = &Tid> {
        self.named.get(thing).into_iter().flatten()
    }

    /// `from` and everything authority flows to from them: what they own, the things they are
    /// named on as members, transitively (spec/permissions.md §1: paths climb owner links and
    /// membership edges). A change of authority at `from` changes it only there.
    pub fn reach(&self, from: &BTreeSet<Tid>) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<Tid> = from.iter().copied().collect();
        while let Some(t) = stack.pop() {
            if !out.insert(t) {
                continue;
            }
            stack.extend(self.owned.get(&t).into_iter().flatten().copied());
            stack.extend(self.named_on(&t).copied());
        }
        out
    }

    fn set_created(&mut self, t: Tid, r: Option<CreationRecord>) -> Option<CreationRecord> {
        let old = match r {
            Some(r) => {
                if let CreationRecord::Thing { owner, .. } = &r {
                    self.owned.entry(*owner).or_default().insert(t);
                }
                self.created.insert(t, r)
            }
            None => self.created.remove(&t),
        };
        if let Some(CreationRecord::Thing { owner, .. }) = &old
            && self.created.get(&t).is_none_or(|n| !matches!(n, CreationRecord::Thing { owner: o, .. } if o == owner))
            && let Some(s) = self.owned.get_mut(owner)
        {
            s.remove(&t);
        }
        self.touched.insert(t);
        self.generation += 1;
        // `reaches` climbs from a member to its owners: a record of a member or of an owner
        // of held things may complete a path
        if old.is_some() || self.members.contains_key(&t) || self.owned.get(&t).is_some_and(|o| !o.is_empty()) {
            self.edges += 1;
        }
        old
    }

    fn count(&mut self, pairs: Vec<(Tid, Tid)>, add: bool) {
        for (m, t) in pairs {
            let e = self.members.entry(m).or_default();
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
                self.members.remove(&m);
            }
        }
    }

    fn put_commit(&mut self, c: Arc<MembershipCommit>) {
        let targets: BTreeSet<Tid> = c.ops.iter().map(|o| o.target).collect();
        for t in &targets {
            self.commits.entry(*t).or_default().push(c.clone());
        }
        self.touched.extend(targets);
        self.touched.insert(c.author);
        self.count(named(&c), true);
        self.generation += 1;
        self.edges += 1;
        let id = c.id;
        self.ids.entry(id).or_default().0 = Some(c);
    }

    fn put_snapshot(&mut self, s: Arc<RosterSnapshot>) {
        self.snapshots.entry(s.thing).or_default().push(s.clone());
        self.touched.insert(s.thing);
        self.count(named_snapshot(&s), true);
        self.generation += 1;
        self.edges += 1;
        self.ids.entry(s.id).or_default().1.push(s);
    }

    /// Takes out every commit and snapshot with this ID (exactly these Arcs).
    fn take(&mut self, id: &CommitId) -> (Vec<Arc<MembershipCommit>>, Vec<Arc<RosterSnapshot>>) {
        let Some((c, ss)) = self.ids.remove(id) else { return (Vec::new(), Vec::new()) };
        self.generation += 1;
        self.edges += 1;
        let mut cs = Vec::new();
        if let Some(c) = c {
            for o in &c.ops {
                if let Some(v) = self.commits.get_mut(&o.target) {
                    v.retain(|x| !Arc::ptr_eq(x, &c));
                    if v.is_empty() {
                        self.commits.remove(&o.target);
                    }
                }
                self.touched.insert(o.target);
            }
            self.count(named(&c), false);
            cs.push(c);
        }
        for s in &ss {
            if let Some(v) = self.snapshots.get_mut(&s.thing) {
                v.retain(|x| !Arc::ptr_eq(x, s));
                if v.is_empty() {
                    self.snapshots.remove(&s.thing);
                }
            }
            self.touched.insert(s.thing);
            self.count(named_snapshot(s), false);
        }
        (cs, ss)
    }

    /// Adds a creation record under its tid.
    pub fn create(&mut self, record: CreationRecord) {
        let t = record.tid();
        self.records.push(t);
        let old = self.set_created(t, Some(record));
        self.log.push(Undo::Created(t, old));
    }

    pub fn add_commit(&mut self, c: MembershipCommit) {
        // an ID is held once: a re-derived commit replaces the earlier
        let removed = self.take(&c.id);
        if !removed.0.is_empty() || !removed.1.is_empty() {
            self.log.push(Undo::Removed(removed.0, removed.1));
        }
        let c = Arc::new(c);
        self.put_commit(c.clone());
        self.log.push(Undo::AddedCommit(c));
    }

    pub fn add_snapshot(&mut self, s: RosterSnapshot) {
        let s = Arc::new(s);
        self.put_snapshot(s.clone());
        self.log.push(Undo::AddedSnapshot(s));
    }

    /// The edge commit held under this ID.
    pub fn edge_commit(&self, id: &CommitId) -> Option<&MembershipCommit> {
        self.ids.get(id).and_then(|r| r.0.as_deref())
    }

    /// Drops every commit and snapshot with this ID.
    pub fn remove(&mut self, id: &CommitId) {
        let (cs, ss) = self.take(id);
        self.log.push(Undo::Removed(cs, ss));
    }

    /// Things whose creation record was added since the last call.
    pub fn take_records(&mut self) -> Vec<Tid> {
        std::mem::take(&mut self.records)
    }

    /// Things whose held inputs changed since the last call.
    pub fn take_touched(&mut self) -> BTreeSet<Tid> {
        std::mem::take(&mut self.touched)
    }
}

impl Journaled for Held {
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        while let Some(u) = self.log.pop() {
            match u {
                Undo::Created(t, old) => {
                    self.set_created(t, old);
                }
                Undo::AddedCommit(c) => {
                    self.take(&c.id);
                }
                Undo::AddedSnapshot(s) => {
                    // only this snapshot: others of the ID stay
                    let (cs, mut ss) = self.take(&s.id);
                    ss.retain(|x| !Arc::ptr_eq(x, &s));
                    for c in cs {
                        self.put_commit(c);
                    }
                    for x in ss {
                        self.put_snapshot(x);
                    }
                }
                Undo::Removed(cs, ss) => {
                    for c in cs {
                        self.put_commit(c);
                    }
                    for s in ss {
                        self.put_snapshot(s);
                    }
                }
            }
        }
    }
}

impl HeldSet for Held {
    fn things(&self) -> Vec<Tid> {
        let mut s: BTreeSet<Tid> = self.commits.keys().copied().collect();
        s.extend(self.snapshots.keys().copied());
        s.extend(self.created.keys().copied());
        s.into_iter().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<MembershipCommit>> {
        self.commits.get(thing).cloned().unwrap_or_default()
    }
    fn roster_snapshots(&self, thing: &Tid) -> Vec<Arc<RosterSnapshot>> {
        self.snapshots.get(thing).cloned().unwrap_or_default()
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        self.created.get(thing).cloned()
    }
}
