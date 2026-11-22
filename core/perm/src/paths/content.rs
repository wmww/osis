//! Content (draft §5.2): a delta's validity derived at read from the walk's per-edge state,
//! its chained points and what names the delta (notes/perm-paths.md, Step 3b design).
//! Delta facts are read through the `Store` seam the engine backs with its store index
//! (notes/perm-paths.md, The delta-facts seam); in memory stay only role commits' facts and the
//! frontiers naming commits. Addenda validity (a least fixpoint) and purge requests' rights are
//! the stored verdicts, judged again for those an update reached (notes/perm-paths.md, Addenda,
//! by reach; Purges).

use super::path::shape;
use super::walk::{Counts, Key, Walk};
use super::{By, Changed, Commit, Content, DeltaClass, List, Names, PartKind, Right, Scope, Stated};
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
    pub purge_by: PurgeBy,
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
    /// What it carries, what it states of each, and whether it is its signer's own cover.
    Snapshot { carries: Frontier, stated: BTreeMap<CommitId, Stated>, own: bool },
    /// Its removal and list.
    Addendum(CommitId, Frontier),
    /// A purge request.
    Purge(Names),
}

impl Fact {
    /// A purge request's scope.
    pub fn scope(&self) -> Option<Scope> {
        let FactClass::Purge(names) = self.class else { return None };
        Some(Scope { on: self.on, aspect: self.aspect.clone(), names, ts: self.ts })
    }
}

/// The key a request is indexed by: its thing, its aspect (none for a destruction), what it
/// names.
pub type NameKey = (Tid, Option<Ak>, Names);

fn name_key(f: &Fact) -> Option<NameKey> {
    let FactClass::Purge(names) = f.class else { return None };
    Some((f.on, (names != Names::Destroy).then(|| f.aspect.clone()), names))
}

/// What a delta's purge asks of the requests naming it (draft §6 The right): one holding admin
/// (any purge-by); one holding write (`writer`); one holding write whose chain holds this purge
/// author (`author_or_admin`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Holding {
    Admin,
    Write,
    WriteFor(Tid),
}

/// The holdings a request with right `r` and fact `f` is indexed under.
fn holdings(f: &Fact, r: Right) -> BTreeSet<Holding> {
    let mut out = BTreeSet::new();
    if r.admin {
        out.insert(Holding::Admin);
    }
    if r.write {
        out.insert(Holding::Write);
        out.extend(f.chain.iter().map(|t| Holding::WriteFor(*t)));
    }
    out
}

/// The delta facts content reads, by point lookups (notes/perm-paths.md, The delta-facts seam):
/// the engine backs it with its store index, `MemStore` keeps it in memory. Its indexes follow
/// `put` and `remove`; the stored addenda verdicts are its too.
pub trait Store {
    fn put(&mut self, f: Fact);
    fn remove(&mut self, id: &WriteId) -> Option<Fact>;
    fn get(&self, id: &WriteId) -> Option<Fact>;
    /// The deltas of commit `c` (on thing `on`).
    fn of_commit(&self, c: &CommitId, on: Option<&Tid>) -> Vec<WriteId>;
    /// The addenda whose list holds `c`.
    fn listing(&self, c: &CommitId) -> Vec<WriteId>;
    /// The snapshots carrying `c`.
    fn carrying(&self, c: &CommitId) -> Vec<WriteId>;
    /// The greatest stamp of the requests indexed by `key` (thing, aspect, what they name) whose
    /// stored right (`set_right`) gives `holding`: a delta's purge is a point lookup, whatever
    /// the number of requests naming it.
    fn latest(&self, key: &NameKey, holding: Holding) -> Option<Ts>;
    /// The requests with edge `e` on their path, positioned within (`from`, `to`).
    fn requests_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId>;
    /// A request's stored right (none until set).
    fn right(&self, id: &WriteId) -> Right;
    /// Sets a request's stored right: it is in `requests` while it holds one.
    fn set_right(&mut self, id: &WriteId, right: Right);
    /// The own covers signed by `signer`.
    fn own_covers(&self, signer: &Tid) -> Vec<WriteId>;
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
    requests: BTreeMap<(NameKey, Holding), BTreeSet<(Ts, WriteId)>>,
    requests_on: BTreeMap<Pair, BTreeSet<(Key, WriteId)>>,
    rights: BTreeMap<WriteId, Right>,
    own: BTreeMap<Tid, BTreeSet<WriteId>>,
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
    /// Every index entry `f` has: (commit, thing), what it lists or carries, its request edges,
    /// its addenda edges, an own cover's signer (a request's named key follows its right).
    fn index(&mut self, f: &Fact, add: bool) {
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
            FactClass::Snapshot { carries, own, .. } => {
                for x in carries.commits() {
                    set(&mut self.carrying, *x, f.id, add);
                }
                if *own {
                    set(&mut self.own, f.signer, f.id, add);
                }
            }
            FactClass::Purge(_) => {
                for e in &f.hops {
                    set(&mut self.requests_on, *e, (f.pos, f.id), add);
                }
            }
            FactClass::Plain | FactClass::Role => {}
        }
    }
}

/// Adds `v` to `m[k]`, or takes it out (and an emptied entry).
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

impl Store for MemStore {
    fn put(&mut self, f: Fact) {
        self.index(&f, true);
        self.facts.insert(f.id, f);
    }
    fn remove(&mut self, id: &WriteId) -> Option<Fact> {
        self.set_right(id, Right::default());
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
    fn latest(&self, key: &NameKey, holding: Holding) -> Option<Ts> {
        self.requests.get(&(key.clone(), holding)).and_then(|s| s.last()).map(|x| x.0)
    }
    fn requests_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        in_range(&self.requests_on, e, from, to)
    }
    fn right(&self, id: &WriteId) -> Right {
        self.rights.get(id).copied().unwrap_or_default()
    }
    fn set_right(&mut self, id: &WriteId, right: Right) {
        let was = self.right(id);
        if was == right {
            return;
        }
        let Some(f) = self.facts.get(id) else { return };
        let Some(key) = name_key(f) else { return };
        let (old, new) = (holdings(f, was), holdings(f, right));
        for h in old.symmetric_difference(&new) {
            set(&mut self.requests, (key.clone(), *h), (f.ts, *id), new.contains(h));
        }
        if right.any() {
            self.rights.insert(*id, right);
        } else {
            self.rights.remove(id);
        }
    }
    fn own_covers(&self, signer: &Tid) -> Vec<WriteId> {
        self.own.get(signer).into_iter().flatten().copied().collect()
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

/// What a held role commit is, for the addenda rule, own covers and could hold (content commits
/// are the store's alone).
#[derive(Clone)]
pub(super) struct CommitFacts {
    signer: Tid,
    /// Its edge writes' frontiers.
    lists: Vec<(WriteId, Arc<List>)>,
    /// The edges its edge writes set, each with the role it sets (spec/commits.md §4
    /// Could hold the right).
    sets: Vec<(Pair, Role)>,
}

#[derive(Clone)]
pub(super) struct Facts<S> {
    mint: BTreeMap<Tid, Tid>,
    /// The held role commits (a commit with a role-class part).
    commits: BTreeMap<CommitId, CommitFacts>,
    /// Per (commit, thing), the frontiers (edge writes) whose leaf of the thing lists it; under
    /// no thing, those naming the commit whole (`List::whole`).
    named: BTreeMap<(CommitId, Option<Tid>), BTreeSet<WriteId>>,
    /// Per edge, how many held edge writes set it at each role (`Role::ALL`'s order), whatever
    /// their validity: what a node that cannot judge reads (Could hold the right).
    ever: BTreeMap<Pair, [u32; 4]>,
    pub store: S,
    pub counts: Counts,
}

impl<S: Store> Facts<S> {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>, store: S) -> Facts<S> {
        Facts { mint: records.clone(), commits: BTreeMap::new(), named: BTreeMap::new(), ever: BTreeMap::new(), store, counts: Counts::default() }
    }

    /// The edge writes whose list names commit `c`'s parts on `on`.
    fn named_on(&self, c: &CommitId, on: &Tid) -> impl Iterator<Item = WriteId> + '_ {
        let c = *c;
        [Some(*on), None].into_iter().flat_map(move |t| self.named.get(&(c, t))).flatten().copied()
    }

    /// A record that came: `t`'s mint admin.
    pub(super) fn add_record(&mut self, t: Tid, admin: Tid) {
        self.mint.insert(t, admin);
    }

    fn record(&self, e: Pair) -> bool {
        self.mint.get(&e.1) == Some(&e.0)
    }

    /// Whether commit `c` is held here (as a role commit, or by its deltas).
    pub(super) fn holds(&self, c: &CommitId) -> bool {
        self.commits.contains_key(c) || !self.store.of_commit(c, None).is_empty()
    }

    /// Entries kept in memory: role commits, the frontiers' names, the edges role writes set.
    pub(super) fn footprint(&self) -> u64 {
        (self.commits.len() + self.named.values().map(BTreeSet::len).sum::<usize>() + self.ever.len()) as u64
    }

    /// Takes in new commits (the walks took their edge-class parts). Returns the new deltas, the
    /// snapshots' carried commits, the role commits and the addenda that arrived.
    pub(super) fn take(&mut self, commits: &[&Commit]) -> Taken {
        let mut out = Taken::default();
        for c in commits {
            let mut cf = CommitFacts { signer: c.signer, lists: vec![], sets: vec![] };
            let mut role = false;
            let mut facts = vec![];
            for (ix, p) in (0u32..).zip(c.parts.iter()) {
                let id = WriteId(c.id, ix);
                match &p.kind {
                    PartKind::Edge(ew) => {
                        role = true;
                        if let Some(f) = &ew.frontier {
                            cf.lists.push((id, f.clone()));
                        }
                        if let Some(v) = &ew.value {
                            cf.sets.push(((ew.holder, p.on), v.role));
                        }
                    }
                    PartKind::Delta(d) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.direct, p.on, None, false);
                        let chain: Vec<Tid> = std::iter::once(c.signer).chain(p.path.iter().copied()).collect();
                        let purge_author = usize::try_from(d.purge_author).ok().and_then(|i| chain.get(i).copied());
                        let class = match &d.class {
                            DeltaClass::Plain => FactClass::Plain,
                            DeltaClass::RoleClass => {
                                role = true;
                                FactClass::Role
                            }
                            DeltaClass::Snapshot { carries, stated, own } => {
                                out.carried.extend(carries.commits().iter().copied());
                                FactClass::Snapshot { carries: carries.clone(), stated: stated.clone(), own: *own }
                            }
                            DeltaClass::Addendum { removal, list } => FactClass::Addendum(*removal, list.clone()),
                            DeltaClass::Purge { names } => FactClass::Purge(*names),
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
                            purge_by: d.purge_by,
                            chain,
                        });
                        out.deltas.push(id);
                    }
                    PartKind::None => {}
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
                for (id, f) in &cf.lists {
                    for (t, x) in f.keys() {
                        self.named.entry((x, t)).or_default().insert(*id);
                    }
                }
                for (e, r) in &cf.sets {
                    if let Some(n) = self.ever.entry(*e).or_default().get_mut(level(*r)) {
                        *n += 1;
                    }
                }
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
                for (e, r) in &cf.sets {
                    if let Some(n) = self.ever.get_mut(e) {
                        if let Some(x) = n.get_mut(level(*r)) {
                            *x = x.saturating_sub(1);
                        }
                        if *n == [0; 4] {
                            self.ever.remove(e);
                        }
                    }
                }
                for (id, f) in &cf.lists {
                    for (t, x) in f.keys() {
                        if let Some(set) = self.named.get_mut(&(x, t)) {
                            set.remove(id);
                            if set.is_empty() {
                                self.named.remove(&(x, t));
                            }
                        }
                        out.carried.insert(x);
                    }
                }
            }
            for id in self.store.of_commit(c, None) {
                // a request holding a right takes it with it
                let right = self.store.right(&id);
                let Some(f) = self.store.remove(&id) else { continue };
                match &f.class {
                    FactClass::Addendum(_, list) => out.carried.extend(list.commits()),
                    FactClass::Snapshot { carries, .. } => out.carried.extend(carries.commits()),
                    FactClass::Purge(_) if right.any() => out.scopes.extend(f.scope()),
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
                if let Some(FactClass::Snapshot { carries, .. }) = self.store.get(&id).map(|f| f.class) {
                    out.extend(carries.commits());
                }
            }
        }
        out
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
            out.extend(self.named_on(&c, &d.on).map(Namer::Write));
            out.extend(self.addenda_listing(&c).into_iter().map(Namer::Addendum));
        }
        counts.content += out.len() as u64;
        out
    }

    /// Whether `id` is an applied cut, below `r`, of an edge of `hops`: that edge and its key.
    fn cut_on(tl: &Walk, id: &WriteId, r: Role, hops: &[Pair]) -> Option<(Pair, Key)> {
        tl.applied_write(id).filter(|(e, a)| a.cuts(r) && hops.contains(e)).map(|(e, a)| (e, a.key))
    }

    /// (a): every hop gives `r` just before the delta's position and no cut of its path below
    /// `r` is ordered at or after it (a destruction of thing `spare` reads no cut on an edge into
    /// it ordered after it: draft §6 Destruction).
    fn holds_role(&self, tl: &Walk, d: &Fact, r: Role, spare: Option<Tid>, counts: &mut Counts) -> bool {
        d.hops.iter().all(|&(h, t)| {
            counts.content += 1;
            tl.role_before(&h, &t, &d.pos) >= Some(r) && (spare == Some(t) || tl.last_cut(&h, &t, r).is_none_or(|k| k < d.pos))
        })
    }

    /// The edge writes answering `d` (draft §5.2 Content): those whose frontier names its commit,
    /// and with `addenda` the removal parts a valid addendum naming it vouches against. Each answers its own cut alone (`stands`).
    fn answered(&self, tl: &Walk, d: &Fact, addenda: bool, counts: &mut Counts) -> BTreeSet<WriteId> {
        let mut out = BTreeSet::new();
        for n in self.namers(d, counts) {
            match n {
                Namer::Write(id) => {
                    out.insert(id);
                }
                Namer::Addendum(a) if addenda && self.store.valid_addendum(&a) => {
                    if let Some(ad) = self.store.get(&a) {
                        out.extend(self.vouches(tl, &ad, d, counts));
                    }
                }
                Namer::Addendum(_) => {}
            }
        }
        out
    }

    /// Whether `d` stands for `r` against every cut of its path below `r` (draft §5.2 Content):
    /// per hop, every cut ordered at or after it (read: as `holds_role`) is answered, and the hop
    /// gives `r` just before it, or its last write before it is an answered cut that the hop gave
    /// `r` just before, read at `d`'s `ts`. A cut's answer speaks for that cut alone: valid as if
    /// the cuts answering it had not cut it, the others standing.
    fn stands(tl: &Walk, d: &Fact, r: Role, spare: Option<Tid>, answered: &BTreeSet<WriteId>, counts: &mut Counts) -> bool {
        d.hops.iter().all(|&(h, t)| {
            counts.content += 1;
            let later = if spare == Some(t) { vec![] } else { tl.cuts_from(&h, &t, r, &d.pos) };
            counts.content += later.len() as u64;
            later.iter().all(|c| answered.contains(c))
                && (tl.role_before(&h, &t, &d.pos) >= Some(r)
                    || tl.last_before(&h, &t, &d.pos).is_some_and(|(id, a)| a.cuts(r) && answered.contains(&id) && a.before.filter(|v| v.alive_at(Some(d.pos.ts))).map(|v| v.role) >= Some(r)))
        })
    }

    /// (b): it stands against every cut of its path below `r`, each answered by its own
    /// frontier.
    fn listed(&self, tl: &Walk, d: &Fact, r: Role, spare: Option<Tid>, counts: &mut Counts) -> bool {
        let answered = self.answered(tl, d, false, counts);
        !answered.is_empty() && Self::stands(tl, d, r, spare, &answered, counts)
    }

    /// Whether the delta is content an addendum may vouch for: a plain delta or an addendum of a
    /// content commit carrying no purge request.
    fn vouchable(&self, d: &Fact) -> bool {
        matches!(d.class, FactClass::Plain | FactClass::Addendum(..))
            && !self.commits.contains_key(&d.commit())
            && !self.store.of_commit(&d.commit(), None).iter().any(|id| self.store.get(id).is_some_and(|f| matches!(f.class, FactClass::Purge(_))))
    }

    /// The cuts of `d`'s path addendum `a` (assumed valid) vouches against for `d` (draft §5.2
    /// Addenda): its removal's parts cutting the path below what `d` needs, ordered after `d` and
    /// before `a`, where its other conditions hold.
    fn vouches(&self, tl: &Walk, a: &Fact, d: &Fact, counts: &mut Counts) -> Vec<WriteId> {
        let FactClass::Addendum(removal, _) = &a.class else { return vec![] };
        if a.on != d.on || a.signer == d.signer || !self.vouchable(d) || !d.well {
            return vec![];
        }
        let need = d.needs.max(Role::Write);
        let path = a.hops.iter().all(|(h, t)| {
            counts.content += 1;
            tl.role_before(h, t, &a.pos) >= Some(need)
        });
        if !path {
            return vec![];
        }
        tl.parts_of(removal).into_iter().filter(|id| Self::cut_on(tl, id, d.needs, &d.hops).is_some_and(|(_, k)| k >= d.pos && k < a.pos)).collect()
    }

    /// (d): its path is re-granted for `r` and it is positioned after the latest of each edge's
    /// first write giving `r` made by right (a record edge: from the start).
    fn regranted(&self, tl: &Walk, d: &Fact, r: Role, counts: &mut Counts) -> bool {
        let mut bound: Option<Key> = None;
        for &(h, t) in &d.hops {
            counts.content += 1;
            if tl.final_of(&h, &t) < Some(r) {
                return false;
            }
            if !self.record((h, t)) {
                let Some(k) = tl.first_by_right(&h, &t, r) else { return false };
                bound = Some(bound.map_or(k, |b| b.max(k)));
            }
        }
        bound.is_none_or(|b| d.pos > b)
    }

    /// An own cover (draft §5.2 Own cover): its path gave the role it needs just before its
    /// position, and an explicit lowering the timeline applies, signed by its signer, ordered at
    /// or after it, lists it.
    fn own_cover(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        let FactClass::Snapshot { own: true, .. } = d.class else { return false };
        let gave = d.hops.iter().all(|(h, t)| {
            counts.content += 1;
            tl.role_before(h, t, &d.pos) >= Some(d.needs)
        });
        gave && self.named_on(&d.commit(), &d.on).any(|w| {
            let w = &w;
            counts.content += 1;
            tl.applied_write(w).is_some_and(|(_, a)| a.explicit && a.key.signer == d.signer && a.key >= d.pos && a.value.filter(|v| v.alive_at(Some(a.key.ts))).map(|v| v.role) < Some(Role::Admin))
        })
    }

    /// Valid by (a), (b) or (d), an own cover by its removal, addenda aside.
    fn base(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> Option<By> {
        if !d.well {
            None
        } else if self.holds_role(tl, d, d.needs, None, counts) {
            Some(By::Held)
        } else if self.listed(tl, d, d.needs, None, counts) {
            Some(By::Listed)
        } else if self.regranted(tl, d, d.needs, counts) {
            Some(By::Regranted)
        } else if self.own_cover(tl, d, counts) {
            Some(By::OwnCover)
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

    /// It stands against every cut of its path, each answered by its own list or by a valid
    /// addendum vouching against it, an addendum among them.
    fn vouched(&self, tl: &Walk, d: &Fact, counts: &mut Counts) -> bool {
        if !self.vouchable(d) {
            return false;
        }
        let lists = self.answered(tl, d, false, counts);
        let answered = self.answered(tl, d, true, counts);
        answered.len() > lists.len() && Self::stands(tl, d, d.needs, None, &answered, counts)
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
    /// snapshots of its thing and aspect carrying it.
    pub(super) fn naming(&self, id: &WriteId) -> Vec<WriteId> {
        let Some(d) = self.store.get(id) else { return vec![] };
        let mut out: Vec<WriteId> = vec![];
        for n in self.namers(&d, &mut Counts::default()) {
            if let Namer::Addendum(a) = n {
                out.push(a);
            }
        }
        out.extend(self.carriers(&d.commit()).into_iter().filter(|s| self.store.get(s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect)));
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
            let FactClass::Snapshot { carries, .. } = &s.class else { continue };
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

    // ---- purges (draft §6): a reading, by point query over the requests holding a right ----

    /// Whether request `q` holds role `r` (draft §6 Holding a role): exactly where a delta of it
    /// needing `r` would be valid by (a), (b) or (d), no addendum vouching; a destruction reads no
    /// cut on an edge into its own thing ordered after it.
    fn holds_right(&self, tl: &Walk, q: &Fact, r: Role, counts: &mut Counts) -> bool {
        let spare = matches!(q.class, FactClass::Purge(Names::Destroy)).then_some(q.on);
        q.well && (self.holds_role(tl, q, r, spare, counts) || self.listed(tl, q, r, spare, counts) || self.regranted(tl, q, r, counts))
    }

    /// The right request `q` holds: admin, and write (none for a destruction, which holds the
    /// `admin` right alone).
    fn right_fact(&self, tl: &Walk, q: &Fact, counts: &mut Counts) -> Right {
        let FactClass::Purge(names) = q.class else { return Right::default() };
        Right { admin: self.holds_right(tl, q, Role::Admin, counts), write: names != Names::Destroy && self.holds_right(tl, q, Role::Write, counts) }
    }

    /// A held request's right, judged now (a point query along its path).
    pub(super) fn right_of(&self, tl: &Walk, id: &WriteId, counts: &mut Counts) -> Option<Right> {
        let q = self.store.get(id).filter(|q| matches!(q.class, FactClass::Purge(_)))?;
        Some(self.right_fact(tl, &q, counts))
    }

    /// Whether a request holding a right names the delta (or copy) of `commit` on `on`'s `aspect`
    /// stamped `ts`, of purge author `author` and `purge_by`, and holds a right over it: `admin`
    /// over any; `writer` (write) over a `writer` delta; `author` (write, its path holding the
    /// delta's purge author) over an `author_or_admin` one (draft §6). Per selector naming it (by
    /// that author, by the aspect, by that commit, a destruction of the thing) a point lookup of
    /// the latest request holding what its purge-by asks: one stamped after it names it (a
    /// destruction: whatever its stamp).
    #[allow(clippy::too_many_arguments)]
    fn purged_by(&self, on: Tid, aspect: &Ak, commit: CommitId, ts: Ts, author: Option<Tid>, purge_by: PurgeBy, counts: &mut Counts) -> bool {
        let mut keys: Vec<(NameKey, Option<Ts>)> = vec![((on, None, Names::Destroy), None)];
        for names in [Names::Aspect, Names::Commit(commit)].into_iter().chain(author.map(Names::Author)) {
            keys.push(((on, Some(aspect.clone()), names), Some(ts)));
        }
        let asks: Vec<Holding> = [Some(Holding::Admin)]
            .into_iter()
            .chain([match purge_by {
                PurgeBy::Admin => None,
                PurgeBy::Writer => Some(Holding::Write),
                PurgeBy::AuthorOrAdmin => author.map(Holding::WriteFor),
            }])
            .flatten()
            .collect();
        keys.iter().any(|(k, after)| {
            asks.iter().any(|h| {
                counts.content += 1;
                self.store.latest(k, *h).is_some_and(|t| after.is_none_or(|a| t > a))
            })
        })
    }

    /// Whether a request holds a right over held plain delta `id`, by its own facts.
    pub(super) fn purged(&self, id: &WriteId, counts: &mut Counts) -> bool {
        let Some(d) = self.store.get(id) else { return false };
        matches!(d.class, FactClass::Plain) && self.purged_by(d.on, &d.aspect, d.commit(), d.ts, d.purge_author, d.purge_by, counts)
    }

    /// Whether a request holds a right over the copy of commit `c` on `on`'s `aspect`, `c` held
    /// there by no delta: shown by a valid held snapshot of `on`'s `aspect`, and named and held a
    /// right over by the facts every such snapshot states of it.
    pub(super) fn copy_purged(&self, tl: &Walk, c: &CommitId, on: &Tid, aspect: &Ak, counts: &mut Counts) -> bool {
        let mut shown = false;
        let mut stated: Vec<Stated> = vec![];
        for s in self.carriers(c) {
            counts.content += 1;
            let Some(sf) = self.store.get(&s) else { continue };
            let FactClass::Snapshot { stated: st, .. } = &sf.class else { continue };
            if sf.on == *on && sf.aspect == *aspect && sf.commit() != *c && self.valid(tl, &sf, counts).is_some() {
                shown = true;
                stated.extend(st.get(c));
            }
        }
        shown && self.copy_purged_by(c, on, aspect, &stated, counts)
    }

    /// `copy_purged` once its valid carriers' statements are read: by every fact stated (one
    /// stating none states nothing; with none stated, only a destruction names it), `c` held there
    /// by no delta.
    fn copy_purged_by(&self, c: &CommitId, on: &Tid, aspect: &Ak, stated: &[Stated], counts: &mut Counts) -> bool {
        if self.store.of_commit(c, Some(on)).iter().any(|id| self.store.get(id).is_some_and(|d| d.aspect == *aspect)) {
            return false;
        }
        if stated.is_empty() {
            return self.store.latest(&(*on, None, Names::Destroy), Holding::Admin).is_some();
        }
        stated.iter().all(|f| self.purged_by(*on, aspect, *c, f.ts, Some(f.purge_author), f.purge_by, counts))
    }

    /// Every copy of a commit held by no delta on its snapshot's thing and aspect that a request
    /// holds a right over (each snapshot judged once).
    pub(super) fn purged_copies(&self, tl: &Walk, counts: &mut Counts) -> BTreeSet<CommitId> {
        let mut shown: BTreeMap<(CommitId, Tid, Ak), Vec<Stated>> = BTreeMap::new();
        for id in self.store.all() {
            let Some(s) = self.store.get(&id) else { continue };
            let FactClass::Snapshot { carries, stated, .. } = &s.class else { continue };
            if self.valid(tl, &s, counts).is_none() {
                continue;
            }
            for c in carries.commits().iter().filter(|c| !self.commits.contains_key(c) && **c != s.commit()) {
                shown.entry((*c, s.on, s.aspect.clone())).or_default().extend(stated.get(c));
            }
        }
        shown.into_iter().filter(|((c, on, aspect), st)| self.copy_purged_by(c, on, aspect, st, counts)).map(|((c, ..), _)| c).collect()
    }

    /// Judges again the rights of the requests an update reached, as it reaches any delta (an
    /// edge of its path in `edges` before its position, in `cuts` at or after it, in `regrant`;
    /// its commit in `named`), and of those `fresh`; stores each right that changed. The scopes
    /// of the requests whose right changed (a fresh one: that holds one).
    pub(super) fn rights_update(&mut self, tl: &Walk, ch: &Changed, fresh: &[WriteId]) -> BTreeSet<Scope> {
        let mut counts = Counts::default();
        let mut f: BTreeSet<WriteId> = fresh.iter().copied().collect();
        for (e, k) in &ch.edges {
            f.extend(self.store.requests_through(e, Bound::Excluded(*k), Bound::Unbounded));
        }
        for (e, k) in &ch.cuts {
            f.extend(self.store.requests_through(e, Bound::Unbounded, Bound::Included(*k)));
        }
        for e in &ch.regrant {
            f.extend(self.store.requests_through(e, Bound::Unbounded, Bound::Unbounded));
        }
        for c in &ch.named {
            f.extend(self.store.of_commit(c, None));
        }
        let mut out = BTreeSet::new();
        for q in f {
            let Some(qf) = self.store.get(&q).filter(|x| matches!(x.class, FactClass::Purge(_))) else { continue };
            let now = self.right_fact(tl, &qf, &mut counts);
            if now != self.store.right(&q) {
                self.store.set_right(&q, now);
                out.extend(qf.scope());
            }
        }
        self.counts.add(&counts);
        out
    }

    /// The own covers that a lowering among `parts` (whose status changed) lists, by its signer:
    /// such a cover's validity reads that lowering (draft §5.2 Own cover).
    pub(super) fn own_listed(&self, parts: &BTreeSet<WriteId>) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        for id in parts {
            let Some(cf) = self.commits.get(&id.0).filter(|cf| cf.lists.iter().any(|(w, _)| w == id)) else { continue };
            for s in self.store.own_covers(&cf.signer) {
                let on = self.store.get(&s).map(|f| f.on);
                if on.is_some_and(|on| self.named_on(&s.0, &on).any(|n| n == *id)) {
                    out.insert(s.0);
                }
            }
        }
        out
    }

    /// Whether held request `id` could hold role `r`: each edge of its path a record edge or
    /// set at `r` or above by some held edge write (spec/commits.md §4 Could hold the right).
    pub(super) fn could_give(&self, id: &WriteId, r: Role) -> Option<bool> {
        let q = self.store.get(id).filter(|q| matches!(q.class, FactClass::Purge(_)))?;
        let from = level(r);
        Some(q.well && q.hops.iter().all(|e| self.record(*e) || self.ever.get(e).is_some_and(|n| n.iter().skip(from).any(|x| *x > 0))))
    }

    /// Whether held request `id` could hold the right over a delta of `purge_by` and purge
    /// author `author`: admin, or write where the class allows a writer (a destruction: admin).
    pub(super) fn could_hold(&self, id: &WriteId, purge_by: PurgeBy, author: Option<&Tid>) -> Option<bool> {
        let q = self.store.get(id).filter(|q| matches!(q.class, FactClass::Purge(_)))?;
        let writer = !matches!(q.class, FactClass::Purge(Names::Destroy))
            && match purge_by {
                PurgeBy::Admin => false,
                PurgeBy::Writer => true,
                PurgeBy::AuthorOrAdmin => author.is_some_and(|a| q.chain.contains(a)),
            };
        Some(self.could_give(id, Role::Admin)? || (writer && self.could_give(id, Role::Write)?))
    }

    // ---- addenda: the least fixpoint, by reach ----

    /// Judges again the addenda an update reached (notes/perm-paths.md, Addenda, by
    /// reach): those `ch` reaches as it reaches any delta (an edge of its path in
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
    /// vouches against a cut for, and that now stand against every cut, are pushed.
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
                        && !self.vouches(tl, &ad, &td, counts).is_empty()
                        && self.vouched(tl, &td, counts)
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
            let FactClass::Snapshot { carries, .. } = &sf.class else { continue };
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
    /// The new addenda.
    pub addenda: Vec<WriteId>,
    /// The scopes of the requests forgotten holding a right.
    pub scopes: BTreeSet<Scope>,
}

/// A role's place in `Role::ALL`.
fn level(r: Role) -> usize {
    Role::ALL.iter().position(|&x| x == r).unwrap_or(0)
}
