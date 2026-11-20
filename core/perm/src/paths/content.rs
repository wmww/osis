//! Content (draft §5.2): a delta's validity derived at read from the second walk's per-edge
//! state, its chained points and what names the delta (notes/perm-paths.md, Step 3b design).
//! Delta facts are read through the `Store` seam the engine backs with its store index
//! (notes/perm-paths.md, The delta-facts seam); in memory stay only role commits' facts and the
//! frontiers naming commits. Addenda validity is the one stored verdict (a least fixpoint), judged
//! again for the addenda an update reached (notes/perm-paths.md, Counting entries and addenda,
//! by reach).

use super::path::shape;
use super::walk::{Counts, Key, Walk};
use super::{By, Changed, Commit, Content, DeltaClass, PartKind};
use crate::types::{Frontier, WriteId};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::Arc;

/// An edge: (holder, target).
pub type Pair = (Tid, Tid);

/// A held delta's facts: everything content reads of it.
#[derive(Clone, Debug, PartialEq)]
pub struct Fact {
    pub id: WriteId,
    pub ts: Ts,
    pub signer: Tid,
    /// The start of its `ts` (draft §5.2 Position).
    pub pos: Key,
    pub on: Tid,
    pub aspect: Ak,
    pub needs: Role,
    pub class: FactClass,
    /// Its path's edges (none where its members name a thing twice).
    pub hops: Vec<Pair>,
    /// Its members name no thing twice and its purge author index is within its path.
    pub well: bool,
    pub purge_author: Option<Tid>,
    pub retention: PurgeBy,
    /// [signer, A1..Ak].
    pub chain: Vec<Tid>,
}

impl Fact {
    pub fn commit(&self) -> CommitId {
        self.id.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum FactClass {
    Plain,
    Role,
    Snapshot(Frontier),
    /// Its removal and list.
    Addendum(CommitId, Frontier),
    /// A request by author.
    Purge(Tid),
}

/// The delta facts content reads, by point lookups (notes/perm-paths.md, The delta-facts seam):
/// the engine backs it with its store index, `MemStore` keeps it in memory. Its indexes follow
/// `put` and `remove`; the stored addenda verdicts are its too.
pub trait Store: Clone {
    fn put(&mut self, f: Fact);
    fn remove(&mut self, id: &WriteId) -> Option<Fact>;
    fn get(&self, id: &WriteId) -> Option<Fact>;
    /// The deltas of commit `c` (on thing `on`).
    fn of_commit(&self, c: &CommitId, on: Option<&Tid>) -> Vec<WriteId>;
    /// The addenda whose list holds `c`.
    fn listing(&self, c: &CommitId) -> Vec<WriteId>;
    /// The snapshots carrying `c`.
    fn carrying(&self, c: &CommitId) -> Vec<WriteId>;
    /// The requests by `author` on (`on`, `aspect`).
    fn requests(&self, on: &Tid, aspect: &Ak, author: &Tid) -> Vec<WriteId>;
    /// The addenda with edge `e` on their path, positioned within (`from`, `to`).
    fn addenda_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId>;
    /// Every delta with edge `e` on its path, positioned within (`from`, `to`): the index that
    /// turns `Changed` into the deltas to judge again.
    fn through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId>;
    fn valid_addendum(&self, id: &WriteId) -> bool;
    fn set_valid_addendum(&mut self, id: &WriteId, valid: bool);
    /// Every delta held (full readings: tests, disputes).
    fn all(&self) -> Vec<WriteId>;
}

/// `Store` in memory.
#[derive(Clone, Default)]
pub struct MemStore {
    facts: BTreeMap<WriteId, Fact>,
    by_commit_on: BTreeMap<(CommitId, Tid), BTreeSet<WriteId>>,
    listing: BTreeMap<CommitId, BTreeSet<WriteId>>,
    carrying: BTreeMap<CommitId, BTreeSet<WriteId>>,
    requests: BTreeMap<(Tid, Ak, Tid), BTreeSet<WriteId>>,
    addenda_on: BTreeMap<Pair, BTreeSet<(Key, WriteId)>>,
    through: BTreeMap<Pair, BTreeSet<(Key, WriteId)>>,
    valid: BTreeSet<WriteId>,
}

/// The entries of `m[e]` positioned within (`from`, `to`).
fn in_range(m: &BTreeMap<Pair, BTreeSet<(Key, WriteId)>>, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
    let lo = WriteId(CommitId([0; 32]), 0);
    let hi = WriteId(CommitId([u8::MAX; 32]), u32::MAX);
    let from = match from {
        Bound::Included(k) => Bound::Included((k, lo)),
        Bound::Excluded(k) => Bound::Excluded((k, hi)),
        Bound::Unbounded => Bound::Unbounded,
    };
    let to = match to {
        Bound::Included(k) => Bound::Included((k, hi)),
        Bound::Excluded(k) => Bound::Excluded((k, lo)),
        Bound::Unbounded => Bound::Unbounded,
    };
    m.get(e).into_iter().flat_map(|s| s.range((from, to))).map(|x| x.1).collect()
}

impl MemStore {
    /// Every index entry `f` has: (commit, thing), what it lists or carries, its request key,
    /// its addenda edges.
    fn index(&mut self, f: &Fact, add: bool) {
        fn set<K: Ord, V: Ord>(m: &mut BTreeMap<K, BTreeSet<V>>, k: K, v: V, add: bool) {
            if add {
                m.entry(k).or_default().insert(v);
            } else if let Some(s) = m.get_mut(&k) {
                s.remove(&v);
                if s.is_empty() {
                    m.remove(&k);
                }
            }
        }
        set(&mut self.by_commit_on, (f.commit(), f.on), f.id, add);
        for e in &f.hops {
            set(&mut self.through, *e, (f.pos, f.id), add);
        }
        match &f.class {
            FactClass::Addendum(_, list) => {
                for x in list.commits() {
                    set(&mut self.listing, *x, f.id, add);
                }
                for e in &f.hops {
                    set(&mut self.addenda_on, *e, (f.pos, f.id), add);
                }
            }
            FactClass::Snapshot(carries) => {
                for x in carries.commits() {
                    set(&mut self.carrying, *x, f.id, add);
                }
            }
            FactClass::Purge(author) => set(&mut self.requests, (f.on, f.aspect.clone(), *author), f.id, add),
            FactClass::Plain | FactClass::Role => {}
        }
    }
}

impl Store for MemStore {
    fn put(&mut self, f: Fact) {
        self.index(&f, true);
        self.facts.insert(f.id, f);
    }
    fn remove(&mut self, id: &WriteId) -> Option<Fact> {
        let f = self.facts.remove(id)?;
        self.index(&f, false);
        self.valid.remove(id);
        Some(f)
    }
    fn get(&self, id: &WriteId) -> Option<Fact> {
        self.facts.get(id).cloned()
    }
    fn of_commit(&self, c: &CommitId, on: Option<&Tid>) -> Vec<WriteId> {
        match on {
            Some(on) => self.by_commit_on.get(&(*c, *on)).into_iter().flatten().copied().collect(),
            None => self.by_commit_on.range((*c, Tid::from_bytes([0; 15]))..).take_while(|(k, _)| k.0 == *c).flat_map(|(_, v)| v.iter().copied()).collect(),
        }
    }
    fn listing(&self, c: &CommitId) -> Vec<WriteId> {
        self.listing.get(c).into_iter().flatten().copied().collect()
    }
    fn carrying(&self, c: &CommitId) -> Vec<WriteId> {
        self.carrying.get(c).into_iter().flatten().copied().collect()
    }
    fn requests(&self, on: &Tid, aspect: &Ak, author: &Tid) -> Vec<WriteId> {
        self.requests.get(&(*on, aspect.clone(), *author)).into_iter().flatten().copied().collect()
    }
    fn addenda_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        in_range(&self.addenda_on, e, from, to)
    }
    fn through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        in_range(&self.through, e, from, to)
    }
    fn valid_addendum(&self, id: &WriteId) -> bool {
        self.valid.contains(id)
    }
    fn set_valid_addendum(&mut self, id: &WriteId, valid: bool) {
        if valid {
            self.valid.insert(*id);
        } else {
            self.valid.remove(id);
        }
    }
    fn all(&self) -> Vec<WriteId> {
        self.facts.keys().copied().collect()
    }
}

/// What a held role commit is, for the counting rule and the addenda rule (content commits are
/// the store's alone).
#[derive(Clone)]
pub(super) struct CommitFacts {
    /// Its commit-level key (part 0) where it has an edge-class part, else the start of its `ts`.
    pub key: Key,
    pub signer: Tid,
    /// The things it has a role-class part on (edge-class parts and role-class deltas).
    pub role_on: BTreeSet<Tid>,
    /// The edges its parts rest on (their paths', and the edges its self-removals lower), each
    /// with the thing of the part resting on it.
    pub rests: BTreeSet<(Tid, Pair)>,
    /// Its edge writes' frontiers.
    lists: Vec<(WriteId, Arc<Frontier>)>,
}

#[derive(Clone)]
pub(super) struct Facts<S> {
    mint: BTreeMap<Tid, Tid>,
    /// The held role commits (a commit with a role-class part).
    pub commits: BTreeMap<CommitId, CommitFacts>,
    /// Per commit, the frontiers (edge writes) listing it.
    named: BTreeMap<CommitId, BTreeSet<WriteId>>,
    /// Removals by (commit, thing): the counting entries, each keeping the commit's parts on its
    /// vouch's thing (draft §5.1 Vouches).
    counted: BTreeMap<(CommitId, Tid), Vec<CommitId>>,
    pub store: S,
    pub counts: Counts,
}

impl<S: Store> Facts<S> {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>, store: S) -> Facts<S> {
        Facts { mint: records.clone(), commits: BTreeMap::new(), named: BTreeMap::new(), counted: BTreeMap::new(), store, counts: Counts::default() }
    }

    fn record(&self, e: Pair) -> bool {
        self.mint.get(&e.1) == Some(&e.0)
    }

    /// Whether commit `c` is held here (as a role commit, or by its deltas).
    pub(super) fn holds(&self, c: &CommitId) -> bool {
        self.commits.contains_key(c) || !self.store.of_commit(c, None).is_empty()
    }

    /// Entries kept in memory: role commits and the frontiers' names.
    pub(super) fn footprint(&self) -> u64 {
        (self.commits.len() + self.named.values().map(BTreeSet::len).sum::<usize>() + self.counted.len()) as u64
    }

    /// Takes in new commits (the walks took their edge-class parts). Returns the new deltas, the
    /// snapshots' carried commits, the role commits and the addenda that arrived.
    pub(super) fn take(&mut self, commits: &[&Commit]) -> Taken {
        let mut out = Taken::default();
        for c in commits {
            let start = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            let mut cf = CommitFacts { key: start, signer: c.signer, role_on: BTreeSet::new(), rests: BTreeSet::new(), lists: vec![] };
            let mut role = false;
            let mut facts = vec![];
            for (ix, p) in (0u32..).zip(c.parts.iter()) {
                let id = WriteId(c.id, ix);
                match &p.kind {
                    PartKind::Edge(ew) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, Some(ew.holder), true);
                        cf.role_on.insert(p.on);
                        role = true;
                        cf.rests.extend(sh.hops.iter().map(|&e| (p.on, e)));
                        if sh.leave {
                            cf.rests.insert((p.on, (ew.holder, p.on)));
                        }
                        if let Some(f) = &ew.frontier {
                            cf.lists.push((id, f.clone()));
                        }
                    }
                    PartKind::Vouch { .. } => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, None, true);
                        cf.role_on.insert(p.on);
                        role = true;
                        cf.rests.extend(sh.hops.iter().map(|&e| (p.on, e)));
                    }
                    PartKind::Delta(d) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, None, false);
                        cf.rests.extend(sh.hops.iter().map(|&e| (p.on, e)));
                        let chain: Vec<Tid> = std::iter::once(c.signer).chain(p.path.iter().copied()).collect();
                        let purge_author = usize::try_from(d.purge_author).ok().and_then(|i| chain.get(i).copied());
                        let class = match &d.class {
                            DeltaClass::Plain => FactClass::Plain,
                            DeltaClass::RoleClass => {
                                cf.role_on.insert(p.on);
                                role = true;
                                FactClass::Role
                            }
                            DeltaClass::Snapshot { carries } => {
                                out.carried.extend(carries.commits().iter().copied());
                                FactClass::Snapshot(carries.clone())
                            }
                            DeltaClass::Addendum { removal, list } => FactClass::Addendum(*removal, list.clone()),
                            DeltaClass::PurgeByAuthor { author } => FactClass::Purge(*author),
                        };
                        facts.push(Fact {
                            id,
                            ts: c.ts,
                            signer: c.signer,
                            pos: Key::start(c.ts),
                            on: p.on,
                            aspect: d.aspect.clone(),
                            needs: d.needs,
                            class,
                            hops: sh.hops,
                            well: sh.well && purge_author.is_some(),
                            purge_author,
                            retention: d.retention,
                            chain,
                        });
                        out.deltas.push(id);
                    }
                }
            }
            // an addendum written by a role commit is no addendum: it names nothing
            for f in facts {
                if !role && matches!(f.class, FactClass::Addendum(..)) {
                    out.addenda.push(f.id);
                }
                self.store.put(f);
            }
            if role {
                // ordered for the counting rule as its parts are: by its edge-class parts' key,
                // else at the start of its `ts` (§5.2 Position)
                if !c.parts.iter().any(|p| matches!(p.kind, PartKind::Edge(_) | PartKind::Vouch { .. })) {
                    cf.key = Key::start(c.ts);
                }
                for (id, f) in &cf.lists {
                    for x in f.commits() {
                        self.named.entry(*x).or_default().insert(*id);
                    }
                }
                out.roles.insert(c.id);
                self.commits.insert(c.id, cf);
            }
        }
        out
    }

    /// Forgets held commits: each delta leaves the store (no verdict was stored but an
    /// addendum's); a frontier, an addendum or a snapshot forgotten changes what names the
    /// commits it listed or carried, which `carried` reports. Work: per delta its path and lists.
    pub(super) fn forget(&mut self, commits: &[CommitId]) -> Taken {
        let mut out = Taken::default();
        for c in commits {
            if let Some(cf) = self.commits.remove(c) {
                out.roles.insert(*c);
                for (id, f) in &cf.lists {
                    for x in f.commits() {
                        if let Some(set) = self.named.get_mut(x) {
                            set.remove(id);
                            if set.is_empty() {
                                self.named.remove(x);
                            }
                        }
                        out.carried.insert(*x);
                    }
                }
            }
            for id in self.store.of_commit(c, None) {
                let Some(f) = self.store.remove(&id) else { continue };
                match &f.class {
                    FactClass::Addendum(_, list) => out.carried.extend(list.commits()),
                    FactClass::Snapshot(carries) => out.carried.extend(carries.commits()),
                    _ => {}
                }
            }
        }
        out
    }

    /// What the held snapshots of commits `cs` carry (a list naming one names those).
    pub(super) fn carried_by(&self, cs: &BTreeSet<CommitId>) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        for c in cs {
            for id in self.store.of_commit(c, None) {
                if let Some(FactClass::Snapshot(carries)) = self.store.get(&id).map(|f| f.class) {
                    out.extend(carries.commits());
                }
            }
        }
        out
    }

    // ---- counting entries as lists ----

    pub(super) fn set_counted(&mut self, entries: &BTreeSet<(CommitId, CommitId, Tid)>) {
        self.counted.clear();
        for (r, c, on) in entries {
            self.counted.entry((*c, *on)).or_default().push(*r);
        }
    }

    // ---- judging a delta ----

    /// Whether `f` is an addendum: one of a content commit.
    fn is_addendum(&self, f: &Fact) -> bool {
        matches!(f.class, FactClass::Addendum(..)) && !self.commits.contains_key(&f.commit())
    }

    /// The addenda listing commit `c`.
    fn addenda_listing(&self, c: &CommitId) -> Vec<WriteId> {
        self.store.listing(c).into_iter().filter(|a| !self.commits.contains_key(&a.0)).collect()
    }

    /// The namers of delta `d`: the frontiers and addenda listing its commit, or a snapshot of
    /// its thing and aspect carrying it.
    fn namers(&self, d: &Fact, counts: &mut Counts) -> Vec<Namer> {
        let mut commits = vec![d.commit()];
        for s in self.carriers(&d.commit()) {
            counts.content += 1;
            if let Some(sd) = self.store.get(&s)
                && sd.on == d.on
                && sd.aspect == d.aspect
                && sd.commit() != d.commit()
            {
                commits.push(sd.commit());
            }
        }
        let mut out = vec![];
        for c in commits {
            out.extend(self.named.get(&c).into_iter().flatten().map(|&w| Namer::Write(w)));
            out.extend(self.addenda_listing(&c).into_iter().map(Namer::Addendum));
        }
        counts.content += out.len() as u64;
        out
    }

    /// Whether `id` is an applied cut, below `r`, of an edge of `hops`; its key.
    fn cut_on(tl: &Walk, id: &WriteId, r: Role, hops: &[Pair]) -> Option<Key> {
        tl.applied_write(id).filter(|(e, a)| a.cuts(r) && hops.contains(e)).map(|(_, a)| a.key)
    }

    /// (a): every hop gives `needs` just before the delta's position and no cut of its path
    /// below `needs` is ordered after it.
    fn holds_role(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        d.hops.iter().all(|(h, t)| {
            counts.content += 1;
            tl.role_before(h, t, &d.pos) >= Some(d.needs) && tl.last_cut(h, t, d.needs).is_none_or(|k| k < d.pos)
        })
    }

    /// (b): a cut of its path below `needs` lists its commit (its frontier, or a counting entry).
    fn listed(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        let by_frontier = self.namers(d, counts).iter().any(|n| matches!(n, Namer::Write(id) if Self::cut_on(tl, id, d.needs, &d.hops).is_some()));
        by_frontier
            || self.counted.get(&(d.commit(), d.on)).into_iter().flatten().any(|r| {
                counts.content += 1;
                tl.parts_of(r).iter().any(|id| Self::cut_on(tl, id, d.needs, &d.hops).is_some())
            })
    }

    /// Whether the delta is content an addendum may vouch for: a plain delta or an addendum of a
    /// content commit carrying no purge request.
    fn vouchable(&self, d: &Fact) -> bool {
        matches!(d.class, FactClass::Plain | FactClass::Addendum(..))
            && !self.commits.contains_key(&d.commit())
            && !self.store.of_commit(&d.commit(), None).iter().any(|id| self.store.get(id).is_some_and(|f| matches!(f.class, FactClass::Purge(_))))
    }

    /// Whether addendum `a` (assumed valid) vouches for delta `d` (draft §5.2 Addenda).
    fn vouches(&self, tl: &Walk, a: &Fact, d: &Fact, counts: &mut Counts) -> bool {
        let FactClass::Addendum(removal, _) = &a.class else { return false };
        if a.on != d.on || a.signer == d.signer || !self.vouchable(d) || !d.well {
            return false;
        }
        let need = d.needs.max(Role::Write);
        let path = a.hops.iter().all(|(h, t)| {
            counts.content += 1;
            tl.role_before(h, t, &a.pos) >= Some(need)
        });
        path && tl.parts_of(removal).iter().any(|id| Self::cut_on(tl, id, d.needs, &d.hops).is_some_and(|k| k >= d.pos && k < a.pos))
    }

    /// (d): its path is re-granted for `needs` and it is positioned after the latest of each
    /// edge's first chained write giving `needs` (a record edge: from the start).
    fn regranted(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        let mut bound: Option<Key> = None;
        for &(h, t) in &d.hops {
            counts.content += 1;
            if tl.final_of(&h, &t) < Some(d.needs) {
                return false;
            }
            if !self.record((h, t)) {
                let Some(k) = tl.first_chained(&h, &t, d.needs) else { return false };
                bound = Some(bound.map_or(k, |b| b.max(k)));
            }
        }
        bound.is_none_or(|b| d.pos > b)
    }

    /// Valid by (a), (b) or (d), addenda aside.
    fn base(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> Option<By> {
        if !d.well {
            None
        } else if self.holds_role(tl, d, counts) {
            Some(By::Held)
        } else if self.listed(tl, d, counts) {
            Some(By::Listed)
        } else if self.regranted(tl, d, counts) {
            Some(By::Regranted)
        } else {
            None
        }
    }

    /// Valid, and by what (draft §5.2: held, listed, vouched for by a valid addendum, re-granted).
    fn valid(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> Option<By> {
        match self.base(tl, d, counts) {
            Some(By::Regranted) | None if self.vouched(tl, d, counts) => Some(By::Vouched),
            b => b,
        }
    }

    fn vouched(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        self.vouchable(d)
            && self.namers(d, counts).iter().any(|n| match n {
                Namer::Addendum(a) => self.store.valid_addendum(a) && self.store.get(a).is_some_and(|ad| self.vouches(tl, &ad, d, counts)),
                Namer::Write(_) => false,
            })
    }

    pub(super) fn content(&self, tl: &Walk, id: &WriteId, counts: &mut Counts) -> Option<Content> {
        let d = self.store.get(id)?;
        Some(match self.valid(tl, &d, counts) {
            Some(b) => Content::Valid(b),
            None if self.copied(tl, &d, counts) => Content::Copied,
            None => Content::Invalid,
        })
    }

    /// The held snapshots carrying held commit `c`: none for a role commit, which no snapshot
    /// carries (draft §5.2 Copies: role commits are never compacted).
    fn carriers(&self, c: &CommitId) -> Vec<WriteId> {
        if self.commits.contains_key(c) { vec![] } else { self.store.carrying(c) }
    }

    /// Carried by a valid snapshot of its thing and aspect.
    fn copied(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        self.carriers(&d.commit()).iter().any(|s| {
            counts.content += 1;
            self.store.get(s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect && sd.commit() != d.commit() && self.valid(tl, &sd, counts).is_some())
        })
    }

    /// A held delta's hops and position.
    pub(super) fn rests(&self, id: &WriteId) -> Option<(Vec<Pair>, Key)> {
        self.store.get(id).map(|d| (d.hops, d.pos))
    }

    /// What names a held delta: the addenda listing its commit (or a snapshot carrying it), the
    /// snapshots of its thing and aspect carrying it, the requests by its purge author on its
    /// thing and aspect.
    pub(super) fn naming(&self, id: &WriteId) -> Vec<WriteId> {
        let Some(d) = self.store.get(id) else { return vec![] };
        let mut out: Vec<WriteId> = vec![];
        for n in self.namers(&d, &mut Counts::default()) {
            if let Namer::Addendum(a) = n {
                out.push(a);
            }
        }
        out.extend(self.carriers(&d.commit()).into_iter().filter(|s| self.store.get(s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect)));
        if let Some(pa) = d.purge_author {
            out.extend(self.store.requests(&d.on, &d.aspect, &pa));
        }
        out
    }

    pub(super) fn ids(&self) -> Vec<WriteId> {
        self.store.all()
    }

    /// Commits a valid snapshot carries that no valid held delta of its thing and aspect is.
    pub(super) fn copies(&self, tl: &Walk, counts: &mut Counts) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        for id in self.store.all() {
            let Some(s) = self.store.get(&id) else { continue };
            let FactClass::Snapshot(carries) = &s.class else { continue };
            if self.valid(tl, &s, counts).is_none() {
                continue;
            }
            for c in carries.commits().iter().filter(|c| !self.commits.contains_key(c)) {
                let valid_held = self.store.of_commit(c, Some(&s.on)).iter().filter_map(|n| self.store.get(n)).any(|d| d.aspect == s.aspect && self.valid(tl, &d, counts).is_some());
                if !valid_held && *c != s.commit() {
                    out.insert(*c);
                }
            }
        }
        out
    }

    /// Whether a valid request by author holds the right over delta `id` (draft §6, the `author`
    /// class): a request on its thing and aspect stamped after it, naming exactly its purge
    /// author, whose chain holds that author, valid as a delta needing write along its path.
    pub(super) fn purged(&self, tl: &Walk, id: &WriteId, counts: &mut Counts) -> bool {
        let Some(d) = self.store.get(id) else { return false };
        let (FactClass::Plain, Some(pa), true) = (&d.class, d.purge_author, d.retention.author()) else { return false };
        self.store.requests(&d.on, &d.aspect, &pa).iter().any(|q| {
            counts.content += 1;
            self.store.get(q).is_some_and(|qd| qd.ts > d.ts && qd.chain.contains(&pa) && self.valid(tl, &qd, counts).is_some())
        })
    }

    // ---- addenda: the least fixpoint, by reach ----

    /// Judges again the addenda an update reached (notes/perm-paths.md, Counting entries and
    /// addenda, by reach): those `ch` reaches as it reaches any delta (an edge of its path in
    /// `edges` before its position, in `cuts` at or after it, in `regrant`; its commit in
    /// `named`), those `fresh`, and every addendum their lists name, in turn (F). F leaves the
    /// valid set; its members valid by (a), (b), (d) or by a valid namer outside F join it again
    /// and vouch in turn. Outside F no read changed. The addenda whose validity changed.
    pub(super) fn addenda_update(&mut self, tl: &Walk, ch: &Changed, fresh: &[WriteId]) -> BTreeSet<WriteId> {
        let mut counts = Counts::default();
        let mut f: BTreeSet<WriteId> = fresh.iter().copied().collect();
        for (e, k) in &ch.edges {
            f.extend(self.store.addenda_through(e, Bound::Excluded(*k), Bound::Unbounded));
        }
        for (e, k) in &ch.cuts {
            f.extend(self.store.addenda_through(e, Bound::Unbounded, Bound::Included(*k)));
        }
        for e in &ch.regrant {
            f.extend(self.store.addenda_through(e, Bound::Unbounded, Bound::Unbounded));
        }
        for c in &ch.named {
            f.extend(self.store.of_commit(c, None).into_iter().filter(|id| self.store.get(id).is_some_and(|x| self.is_addendum(&x))));
        }
        f.retain(|a| !self.commits.contains_key(&a.0));
        let mut todo: Vec<WriteId> = f.iter().copied().collect();
        while let Some(a) = todo.pop() {
            let Some(ad) = self.store.get(&a) else { continue };
            let FactClass::Addendum(_, list) = &ad.class else { continue };
            for c in list.commits() {
                counts.addenda += 1;
                for t in self.targets(c, ad.on) {
                    if self.store.get(&t).is_some_and(|x| self.is_addendum(&x)) && f.insert(t) {
                        todo.push(t);
                    }
                }
            }
        }
        let was: BTreeSet<WriteId> = f.iter().filter(|a| self.store.valid_addendum(a)).copied().collect();
        for a in &f {
            self.store.set_valid_addendum(a, false);
        }
        let mut queue: Vec<WriteId> = vec![];
        for a in &f {
            counts.addenda += 1;
            if let Some(d) = self.store.get(a)
                && self.is_addendum(&d)
                && (self.base(tl, &d, &mut counts).is_some() || self.vouched(tl, &d, &mut counts))
            {
                queue.push(*a);
            }
        }
        self.spread(tl, queue, &mut counts);
        self.counts.add(&counts);
        f.into_iter().filter(|a| was.contains(a) != self.store.valid_addendum(a)).collect()
    }

    /// The worklist: each addendum popped turns valid and the addenda its list names that it
    /// vouches for are pushed.
    fn spread(&mut self, tl: &Walk, mut queue: Vec<WriteId>, counts: &mut Counts) {
        while let Some(a) = queue.pop() {
            if self.store.valid_addendum(&a) {
                continue;
            }
            self.store.set_valid_addendum(&a, true);
            let Some(ad) = self.store.get(&a) else { continue };
            let FactClass::Addendum(_, list) = &ad.class else { continue };
            for c in list.commits() {
                counts.addenda += 1;
                for t in self.targets(c, ad.on) {
                    if self.store.valid_addendum(&t) {
                        continue;
                    }
                    if let Some(td) = self.store.get(&t)
                        && self.is_addendum(&td)
                        && self.vouches(tl, &ad, &td, counts)
                    {
                        queue.push(t);
                    }
                }
            }
        }
    }

    /// The deltas `ch` reaches whose validity may have moved (a hop in `edges` before its
    /// position, in `cuts` at or after it, in `regrant`; its commit in `named`; reported in
    /// `parts`), and those an addendum reported names: an addendum is the one namer validity
    /// reads (snapshots and requests move copies and purges alone).
    pub(super) fn reached(&self, ch: &Changed) -> BTreeSet<WriteId> {
        let mut out: BTreeSet<WriteId> = BTreeSet::new();
        for (e, k) in &ch.edges {
            out.extend(self.store.through(e, Bound::Excluded(*k), Bound::Unbounded));
        }
        for (e, k) in &ch.cuts {
            out.extend(self.store.through(e, Bound::Unbounded, Bound::Included(*k)));
        }
        for e in &ch.regrant {
            out.extend(self.store.through(e, Bound::Unbounded, Bound::Unbounded));
        }
        for c in &ch.named {
            out.extend(self.store.of_commit(c, None));
        }
        for id in &ch.parts {
            let Some(f) = self.store.get(id) else { continue };
            out.insert(*id);
            if let FactClass::Addendum(_, list) = &f.class {
                for c in list.commits() {
                    out.extend(self.targets(c, f.on));
                }
            }
        }
        out
    }

    /// The held deltas on `on` a list entry `c` names: `c`'s own, and where `c` is a snapshot of
    /// `on`, those of its thing and aspect it carries.
    fn targets(&self, c: &CommitId, on: Tid) -> Vec<WriteId> {
        let own = self.store.of_commit(c, Some(&on));
        let mut out = own.clone();
        for s in own {
            let Some(sf) = self.store.get(&s) else { continue };
            let FactClass::Snapshot(carries) = &sf.class else { continue };
            for x in carries.commits() {
                out.extend(self.store.of_commit(x, Some(&on)).into_iter().filter(|n| self.store.get(n).is_some_and(|d| d.aspect == sf.aspect)));
            }
        }
        out
    }
}

/// Who names a commit in a list.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Namer {
    Write(WriteId),
    Addendum(WriteId),
}

/// What `Facts::take` found, or `Facts::forget` let go.
#[derive(Default)]
pub(super) struct Taken {
    pub deltas: Vec<WriteId>,
    /// Commits whose namers changed: carried by a snapshot taken or forgotten, listed by an
    /// addendum or a frontier forgotten.
    pub carried: BTreeSet<CommitId>,
    /// The role commits taken or forgotten.
    pub roles: BTreeSet<CommitId>,
    /// The new addenda.
    pub addenda: Vec<WriteId>,
}
