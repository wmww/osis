//! perm's held set (notes/architecture.md §2: the node implements `HeldSet`): applied role
//! commits by target, roster snapshots by thing, `created.0` records, indexed by commit and by
//! holder, journaled for rollback, and remembering which things' inputs changed since perm last
//! looked (`take_touched`), so the timelines re-partition only around them.

use super::journal::Journaled;
use osis_base::{CommitId, CreationRecord, Owner, Role, Tid};
use osis_perm::{HeldSet, RoleCommit, RosterSnapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug)]
enum Undo {
    Created(Tid, Option<Rec>),
    AddedCommit(Arc<RoleCommit>),
    AddedSnapshot(Arc<RosterSnapshot>),
    AddedWithheld(Arc<RosterSnapshot>),
    Removed(Taken),
}

/// A commit ID's edge commit, walked snapshots and withheld snapshots.
type Taken = (Vec<Arc<RoleCommit>>, Vec<Arc<RosterSnapshot>>, Vec<Arc<RosterSnapshot>>);

/// A held creation record and whether it is memory class (an ephemeral thing's, carried by a
/// memory commit or made here; gone at restart, notes/ephemeral.md).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rec {
    record: CreationRecord,
    memory: bool,
}

/// What one commit ID holds: its edge commit, its roster snapshots (one per thing) and those withheld
/// from the walk (`add_withheld`).
type Records = (Option<Arc<RoleCommit>>, Vec<Arc<RosterSnapshot>>, Vec<Arc<RosterSnapshot>>);

#[derive(Debug, Default)]
pub struct Held {
    commits: BTreeMap<Tid, Vec<Arc<RoleCommit>>>,
    snapshots: BTreeMap<Tid, Vec<Arc<RosterSnapshot>>>,
    created: BTreeMap<Tid, Rec>,
    /// Holder -> things it is named on (edge writes, rosters, ledgers, an ownerless record), with counts.
    holders: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Thing -> holders named on it (the same pairs as `holders`).
    named: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Owner -> things it owns (by creation records).
    owned: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Commit -> what it holds here (an ID's edge commit and roster snapshots).
    ids: BTreeMap<CommitId, Records>,
    log: Vec<Undo>,
    touched: BTreeSet<Tid>,
    /// Count changes (rollbacks included), of anything and of what `validity::reaches` reads:
    /// the edge writes, a record replaced or removed, and a new record of a thing named as a
    /// holder or owning a held thing (its owner link) (`apply::waits`).
    generation: u64,
    edges: u64,
    /// Things whose creation record `create` added since `take_records`.
    records: Vec<Tid>,
}

fn named(c: &RoleCommit) -> Vec<(Tid, Tid)> {
    c.ops.iter().map(|o| (o.holder, o.target)).collect()
}

fn named_snapshot(s: &RosterSnapshot) -> Vec<(Tid, Tid)> {
    s.roster.keys().chain(s.ledger.iter().map(|t| &t.holder)).map(|m| (*m, s.thing)).collect()
}

impl Held {
    /// The record of `t`, durable or memory class.
    pub fn created(&self, t: &Tid) -> Option<&CreationRecord> {
        self.created.get(t).map(|r| &r.record)
    }
    /// The held things whose record names `t` as owner.
    pub fn owned(&self, t: &Tid) -> impl Iterator<Item = &Tid> {
        self.owned.get(t).into_iter().flatten()
    }
    /// Whether `t`'s record is held and memory class.
    pub fn is_memory(&self, t: &Tid) -> bool {
        self.created.get(t).is_some_and(|r| r.memory)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn edges(&self) -> u64 {
        self.edges
    }
    /// Edge commits with a write on `t`, of any validity.
    pub fn commits_on(&self, t: &Tid) -> &[Arc<RoleCommit>] {
        self.commits.get(t).map(Vec::as_slice).unwrap_or_default()
    }
    pub fn snapshots_of(&self, t: &Tid) -> &[Arc<RosterSnapshot>] {
        self.snapshots.get(t).map(Vec::as_slice).unwrap_or_default()
    }
    /// Things `holder` is named on as a holder (edge writes, rosters, ledgers).
    pub fn named_on(&self, holder: &Tid) -> impl Iterator<Item = &Tid> {
        self.holders.get(holder).into_iter().flat_map(|m| m.keys())
    }

    /// Holders named on `thing` (edge writes, rosters, ledgers).
    pub fn holders_of(&self, thing: &Tid) -> impl Iterator<Item = &Tid> {
        self.named.get(thing).into_iter().flatten()
    }

    /// `from` and everything authority flows to from them: what they own, the things they are
    /// named on as holders, transitively (spec/permissions.md §1: paths climb owner links and
    /// role edges). A change of authority at `from` changes it only there.
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

    /// `t`'s possible admins (spec/commits.md §4): the least set holding `t` and, with each member, its
    /// owner or first admin and any holder named with admin on it by an edge write, roster or ledger
    /// entry a member signed; of any validity and whatever followed. So a forger is in it only if a
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
            if let Some(Owner::Actor(x) | Owner::Ownerless(x)) = self.created(&c).map(CreationRecord::owner_link) {
                named.push(x);
            }
            let edges = self.commits_on(&c).iter().flat_map(|r| r.ops.iter().filter(|o| o.target == c && o.edge.as_ref().is_some_and(|e| e.role >= Role::Admin)).map(|o| (r.author, o.holder)));
            let snaps = self.snapshots_of(&c).iter().flat_map(|s| {
                let roster = s.roster.iter().filter(|(_, e)| e.role >= Role::Admin).map(|(h, _)| *h);
                roster.chain(s.ledger.iter().filter(|l| l.role >= Role::Admin).map(|l| l.holder)).map(|h| (s.author, h))
            });
            for (by, h) in edges.chain(snaps) {
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

    fn set_created(&mut self, t: Tid, r: Option<Rec>) -> Option<Rec> {
        let old = match r {
            Some(r) => {
                if let CreationRecord::Thing { owner, .. } = &r.record {
                    self.owned.entry(*owner).or_default().insert(t);
                }
                self.created.insert(t, r)
            }
            None => self.created.remove(&t),
        };
        let class_only = matches!((&old, self.created.get(&t)), (Some(o), Some(n)) if o.record == n.record);
        if let Some(Rec { record: CreationRecord::Thing { owner, .. }, .. }) = &old
            && self.created.get(&t).is_none_or(|n| !matches!(&n.record, CreationRecord::Thing { owner: o, .. } if o == owner))
            && let Some(s) = self.owned.get_mut(owner)
        {
            s.remove(&t);
            if s.is_empty() {
                self.owned.remove(owner);
            }
        }
        if class_only {
            // persisted: the same record, nothing perm reads changed
            return old;
        }
        // an ownerless thing's first admin is named on it by its record (spec/permissions.md §1)
        let genesis = |r: Option<&Rec>| match r.map(|r| &r.record) {
            Some(CreationRecord::Ownerless { admin, .. }) => vec![(*admin, t)],
            _ => Vec::new(),
        };
        let (was, now) = (genesis(old.as_ref()), genesis(self.created.get(&t)));
        if was != now {
            self.count(was, false);
            self.count(now, true);
            self.edges += 1;
        }
        self.touched.insert(t);
        self.generation += 1;
        // `reaches` climbs from a holder to its owners: a record of a holder or of an owner
        // of held things may complete a path
        if old.is_some() || self.holders.contains_key(&t) || self.owned.contains_key(&t) {
            self.edges += 1;
        }
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

    fn put_withheld(&mut self, s: Arc<RosterSnapshot>) {
        self.touched.insert(s.thing);
        self.count(named_snapshot(&s), true);
        self.generation += 1;
        self.edges += 1;
        self.ids.entry(s.id).or_default().2.push(s);
    }

    /// Takes out every commit and snapshot with this ID (exactly these Arcs).
    fn take(&mut self, id: &CommitId) -> Taken {
        let Some((c, ss, ws)) = self.ids.remove(id) else { return Taken::default() };
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
        for s in &ws {
            self.touched.insert(s.thing);
            self.count(named_snapshot(s), false);
        }
        (cs, ss, ws)
    }

    /// Adds a creation record under its tid, durable (a memory one held becomes durable:
    /// persisted).
    pub fn create(&mut self, record: CreationRecord) {
        self.put_record(record, false);
    }

    /// Adds the memory-class record of an ephemeral thing (a durable or memory one held stays).
    pub fn create_memory(&mut self, record: CreationRecord) {
        if !self.created.contains_key(&record.tid()) {
            self.put_record(record, true);
        }
    }

    fn put_record(&mut self, record: CreationRecord, memory: bool) {
        let t = record.tid();
        self.records.push(t);
        let old = self.set_created(t, Some(Rec { record, memory }));
        self.log.push(Undo::Created(t, old));
    }

    /// Drops memory-class record `t` (a freed ephemeral thing); a durable one stays.
    pub fn free(&mut self, t: &Tid) {
        if self.is_memory(t) {
            let old = self.set_created(*t, None);
            self.log.push(Undo::Created(*t, old));
        }
    }

    pub fn add_commit(&mut self, c: RoleCommit) {
        // an ID is held once: a re-derived commit replaces the earlier
        let removed = self.take(&c.id);
        if !removed.0.is_empty() || !removed.1.is_empty() || !removed.2.is_empty() {
            self.log.push(Undo::Removed(removed));
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

    /// A held snapshot out of the walk (spec/permissions.md §6): perm does not see it, but the
    /// holders it names stay named (`holders_of`): an applied part's holder leads the search of
    /// `validity::reaches` whether the walk applies it or not (spec/commits.md §4), so what applies
    /// never reads whether a snapshot is withheld.
    pub fn add_withheld(&mut self, s: RosterSnapshot) {
        let s = Arc::new(s);
        self.put_withheld(s.clone());
        self.log.push(Undo::AddedWithheld(s));
    }

    /// Whether snapshot `id` of `thing` is in the walk.
    pub fn walks(&self, id: &CommitId, thing: &Tid) -> bool {
        self.ids.get(id).is_some_and(|r| r.1.iter().any(|s| s.thing == *thing))
    }

    /// The edge commit held under this ID.
    pub fn edge_commit(&self, id: &CommitId) -> Option<&RoleCommit> {
        self.ids.get(id).and_then(|r| r.0.as_deref())
    }

    /// Drops every commit and snapshot with this ID.
    pub fn remove(&mut self, id: &CommitId) {
        let taken = self.take(id);
        self.log.push(Undo::Removed(taken));
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

impl Held {
    fn put_back(&mut self, (cs, ss, ws): Taken) {
        for c in cs {
            self.put_commit(c);
        }
        for s in ss {
            self.put_snapshot(s);
        }
        for s in ws {
            self.put_withheld(s);
        }
    }
}

impl Journaled for Held {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?} {:?} {:?} {:?}", self.commits, self.snapshots, self.created, self.holders, self.named, self.owned, self.ids)
    }
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
                Undo::AddedSnapshot(s) | Undo::AddedWithheld(s) => {
                    // only this snapshot: others of the ID stay
                    let (cs, mut ss, mut ws) = self.take(&s.id);
                    ss.retain(|x| !Arc::ptr_eq(x, &s));
                    ws.retain(|x| !Arc::ptr_eq(x, &s));
                    self.put_back((cs, ss, ws));
                }
                Undo::Removed(taken) => self.put_back(taken),
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
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<RoleCommit>> {
        self.commits.get(thing).cloned().unwrap_or_default()
    }
    fn roster_snapshots(&self, thing: &Tid) -> Vec<Arc<RosterSnapshot>> {
        self.snapshots.get(thing).cloned().unwrap_or_default()
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        self.created.get(thing).map(|r| r.record.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::Ts;
    use osis_perm::{Edge, EdgeOp};

    fn thing(owner: Tid, n: u8) -> CreationRecord {
        CreationRecord::Thing { owner, nonce: [n; 32], creator: None }
    }
    fn actor(n: u8) -> CreationRecord {
        CreationRecord::KeyActor { alg: 1, public_key: vec![n; 32], nonce: [n; 32] }
    }
    fn grant(id: u64, by: Tid, on: Tid, to: Tid, role: Role) -> RoleCommit {
        let mut c = [0; 32];
        c[..8].copy_from_slice(&id.to_be_bytes());
        RoleCommit { id: CommitId(c), ts: Ts::make(osis_base::WallMs(1), 0).unwrap(), author: by, actor: by, frontier: None, ops: vec![EdgeOp { target: on, holder: to, edge: Some(Edge::new(role)) }] }
    }
    fn roster(id: u64, by: Tid, on: Tid, to: Tid, role: Role) -> RosterSnapshot {
        let mut c = [1; 32];
        c[..8].copy_from_slice(&id.to_be_bytes());
        RosterSnapshot { id: CommitId(c), ts: Ts::make(osis_base::WallMs(1), 0).unwrap(), author: by, actor: by, thing: on, roster: BTreeMap::from([(to, Edge::new(role))]), ledger: Vec::new() }
    }

    fn ledger(id: u64, by: Tid, on: Tid, to: Tid, role: Role) -> RosterSnapshot {
        let mut s = roster(id, by, on, to, Role::Read);
        s.roster.clear();
        s.ledger.push(osis_perm::Tenure { holder: to, role, since: None, until: osis_perm::Point { ts: s.ts, node: by, commit: s.id }, frontier: None });
        s
    }

    /// The definition (spec/commits.md §4) by brute force, to judge the worklist by.
    fn least(h: &Held, t: Tid) -> BTreeSet<Tid> {
        let mut set = BTreeSet::from([t]);
        loop {
            let mut next = set.clone();
            for c in &set {
                if let Some(Owner::Actor(x) | Owner::Ownerless(x)) = h.created(c).map(CreationRecord::owner_link) {
                    next.insert(x);
                }
                for r in h.commits_on(c).iter().filter(|r| set.contains(&r.author)) {
                    next.extend(r.ops.iter().filter(|o| o.target == *c && o.edge.as_ref().is_some_and(|e| e.role >= Role::Admin)).map(|o| o.holder));
                }
                for s in h.snapshots_of(c).iter().filter(|s| set.contains(&s.author)) {
                    next.extend(s.roster.iter().filter(|(_, e)| e.role >= Role::Admin).map(|(x, _)| *x));
                    next.extend(s.ledger.iter().filter(|l| l.role >= Role::Admin).map(|l| l.holder));
                }
            }
            if next == set {
                return set;
            }
            set = next;
        }
    }

    #[derive(Clone)]
    enum In {
        G(RoleCommit),
        S(RosterSnapshot),
    }
    fn add(h: &mut Held, i: &In) {
        match i {
            In::G(c) => h.add_commit(c.clone()),
            In::S(s) => h.add_snapshot(s.clone()),
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
            let mut inputs: Vec<In> = (0..rng(14)).map(|i| {
                let (by, on, to) = (a[rng(5) as usize], ids[rng(4) as usize], ids[rng(7) as usize]);
                let role = if rng(4) == 0 { Role::Write } else { Role::Admin };
                match rng(6) {
                    0 => In::S(roster(i, by, on, to, role)),
                    1 => In::S(ledger(i, by, on, to, role)),
                    _ => In::G(grant(i, by, on, to, role)),
                }
            }).collect();
            let base = |h: &mut Held| {
                for x in actors.iter().chain([&g, &t]) {
                    h.create(x.clone());
                }
            };
            let mut one = Held::default();
            base(&mut one);
            inputs.iter().for_each(|i| add(&mut one, i));
            let want = one.ever_admins(&t.tid());
            assert_eq!(want, least(&one, t.tid()));
            // a shuffled order: every prefix a subset, the end alike
            for k in (1..inputs.len()).rev() {
                inputs.swap(k, rng(k as u64 + 1) as usize);
            }
            let mut h = Held::default();
            base(&mut h);
            let mut last = h.ever_admins(&t.tid());
            for i in &inputs {
                add(&mut h, i);
                let now = h.ever_admins(&t.tid());
                assert!(last.is_subset(&now));
                last = now;
            }
            assert_eq!(last, want);
            // forgeries by an outsider and by whom it names: nothing moves
            if let Some(out) = a.iter().copied().find(|x| !want.contains(x)) {
                let puppet = Tid::of_record(&actor(99));
                h.add_commit(grant(1000, out, t.tid(), out, Role::Admin));
                h.add_commit(grant(1001, out, t.tid(), puppet, Role::Admin));
                h.add_commit(grant(1002, puppet, t.tid(), a[0], Role::Admin));
                h.add_snapshot(roster(1003, puppet, t.tid(), out, Role::Admin));
                assert_eq!(h.ever_admins(&t.tid()), want);
            }
            assert!(want.contains(&a[0]), "the owner's owner");
        }
    }
}
