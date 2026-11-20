//! Content (draft §5.2): a delta's validity derived at read from the second walk's per-edge
//! state, its chained points and what names the delta (notes/perm-paths.md, Step 3b design).
//! Stored per delta: its facts alone. Addenda validity is the one stored verdict (a least
//! fixpoint), judged again for the addenda an update reached (notes/perm-paths.md, Counting
//! entries and addenda, by reach).

use super::path::shape;
use super::walk::{Counts, Key, Walk};
use super::{By, Changed, Commit, Content, DeltaClass, PartKind};
use crate::types::{Frontier, WriteId};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Pair = (Tid, Tid);

/// What a held commit is, for the counting rule and the addenda rule.
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
    /// It carries a purge request.
    purge: bool,
    /// It is a role commit: it has a role-class part.
    role: bool,
    /// Its edge writes' frontiers.
    lists: Vec<(WriteId, Arc<Frontier>)>,
}

#[derive(Clone)]
enum Class {
    Plain,
    Role,
    Snapshot(Frontier),
    Addendum(CommitId, Frontier),
    Purge(Tid),
}

/// One held delta's facts.
#[derive(Clone)]
struct D {
    id: WriteId,
    commit: CommitId,
    ts: Ts,
    signer: Tid,
    /// The start of its `ts` (draft §5.2 Position).
    pos: Key,
    on: Tid,
    aspect: Ak,
    needs: Role,
    class: Class,
    hops: Vec<Pair>,
    /// Its members name no thing twice and its purge author index is within its path.
    well: bool,
    purge_author: Option<Tid>,
    retention: PurgeBy,
    /// [signer, A1..Ak].
    chain: Vec<Tid>,
}

/// Who names a commit in a list.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Namer {
    Write(WriteId),
    Addendum(usize),
}

#[derive(Clone, Default)]
pub(super) struct Facts {
    mint: BTreeMap<Tid, Tid>,
    pub commits: BTreeMap<CommitId, CommitFacts>,
    deltas: BTreeMap<usize, D>,
    next: usize,
    ids: BTreeMap<WriteId, usize>,
    by_commit_on: BTreeMap<(CommitId, Tid), Vec<usize>>,
    named: BTreeMap<CommitId, BTreeSet<Namer>>,
    carried: BTreeMap<CommitId, BTreeSet<usize>>,
    requests: BTreeMap<(Tid, Ak, Tid), BTreeSet<usize>>,
    /// The held addenda (an addendum of a role commit is none), and by each edge of their paths.
    addenda: BTreeSet<usize>,
    addenda_on: BTreeMap<Pair, BTreeSet<(Key, usize)>>,
    valid_addenda: BTreeSet<usize>,
    /// Removals by (commit, thing): the counting entries, each keeping the commit's parts on its
    /// vouch's thing (draft §5.1 Vouches).
    counted: BTreeMap<(CommitId, Tid), Vec<CommitId>>,
    pub counts: Counts,
}

impl Facts {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>) -> Facts {
        Facts { mint: records.clone(), ..Facts::default() }
    }

    fn record(&self, e: Pair) -> bool {
        self.mint.get(&e.1) == Some(&e.0)
    }

    /// Takes in new commits (the walks took their edge-class parts). Returns the new deltas, the
    /// snapshots' carried commits, the role commits and the addenda that arrived.
    pub(super) fn take(&mut self, commits: &[&Commit]) -> Taken {
        let mut out = Taken::default();
        for c in commits {
            let start = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            let mut cf = CommitFacts { key: start, signer: c.signer, role_on: BTreeSet::new(), rests: BTreeSet::new(), purge: false, role: false, lists: vec![] };
            for (ix, p) in (0u32..).zip(c.parts.iter()) {
                let id = WriteId(c.id, ix);
                match &p.kind {
                    PartKind::Edge(ew) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, Some(ew.holder), true);
                        cf.role_on.insert(p.on);
                        cf.role = true;
                        cf.rests.extend(sh.hops.iter().map(|&e| (p.on, e)));
                        if sh.leave {
                            cf.rests.insert((p.on, (ew.holder, p.on)));
                        }
                        if let Some(f) = &ew.frontier {
                            for x in f.commits() {
                                self.named.entry(*x).or_default().insert(Namer::Write(id));
                            }
                            cf.lists.push((id, f.clone()));
                        }
                    }
                    PartKind::Vouch { .. } => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, None, true);
                        cf.role_on.insert(p.on);
                        cf.role = true;
                        cf.rests.extend(sh.hops.iter().map(|&e| (p.on, e)));
                    }
                    PartKind::Delta(d) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, None, false);
                        cf.rests.extend(sh.hops.iter().map(|&e| (p.on, e)));
                        let chain: Vec<Tid> = std::iter::once(c.signer).chain(p.path.iter().copied()).collect();
                        let purge_author = usize::try_from(d.purge_author).ok().and_then(|i| chain.get(i).copied());
                        let class = match &d.class {
                            DeltaClass::Plain => Class::Plain,
                            DeltaClass::RoleClass => {
                                cf.role_on.insert(p.on);
                                cf.role = true;
                                Class::Role
                            }
                            DeltaClass::Snapshot { carries } => {
                                out.carried.extend(carries.commits().iter().copied());
                                Class::Snapshot(carries.clone())
                            }
                            DeltaClass::Addendum { removal, list } => {
                                Class::Addendum(*removal, list.clone())
                            }
                            DeltaClass::PurgeByAuthor { author } => {
                                cf.purge = true;
                                Class::Purge(*author)
                            }
                        };
                        let n = self.next;
                        self.next += 1;
                        let pos = Key::start(c.ts);
                        self.deltas.insert(n, D {
                            id,
                            commit: c.id,
                            ts: c.ts,
                            signer: c.signer,
                            pos,
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
                        self.ids.insert(id, n);
                        self.by_commit_on.entry((c.id, p.on)).or_default().push(n);
                        out.deltas.push(id);
                    }
                }
            }
            // indexes that read the whole commit (an addendum written by a role commit is no
            // addendum: it names nothing)
            for n in self.by_commit_on.range((c.id, Tid::from_bytes([0; 15]))..).take_while(|(k, _)| k.0 == c.id).flat_map(|(_, v)| v.clone()).collect::<Vec<_>>() {
                let Some(d) = self.deltas.get(&n) else { continue };
                match &d.class {
                    Class::Addendum(_, list) if !cf.role => {
                        for x in list.commits() {
                            self.named.entry(*x).or_default().insert(Namer::Addendum(n));
                        }
                        for e in &d.hops {
                            self.addenda_on.entry(*e).or_default().insert((d.pos, n));
                        }
                        self.addenda.insert(n);
                        out.addenda.push(n);
                    }
                    Class::Snapshot(carries) => {
                        for x in carries.commits() {
                            self.carried.entry(*x).or_default().insert(n);
                        }
                    }
                    Class::Purge(author) => {
                        self.requests.entry((d.on, d.aspect.clone(), *author)).or_default().insert(n);
                    }
                    _ => {}
                }
            }
            // ordered for the counting rule as its parts are: by its edge-class parts' key, else
            // at the start of its `ts` (§5.2 Position)
            if !c.parts.iter().any(|p| matches!(p.kind, PartKind::Edge(_) | PartKind::Vouch { .. })) {
                cf.key = Key::start(c.ts);
            }
            if cf.role {
                out.roles.insert(c.id);
            }
            self.commits.insert(c.id, cf);
        }
        out
    }

    /// Forgets held commits: each delta leaves the indexes (no verdict was stored but an
    /// addendum's); a frontier, an addendum or a snapshot forgotten changes what names the
    /// commits it listed or carried, which `carried` reports. Work: per delta its path and lists.
    pub(super) fn forget(&mut self, commits: &[CommitId]) -> Taken {
        let mut out = Taken::default();
        for c in commits {
            let Some(cf) = self.commits.remove(c) else { continue };
            if cf.role {
                out.roles.insert(*c);
            }
            // a frontier's namers go with its commit's edge writes
            for (id, f) in &cf.lists {
                for x in f.commits() {
                    if let Some(set) = self.named.get_mut(x) {
                        set.remove(&Namer::Write(*id));
                    }
                    out.carried.insert(*x);
                }
            }
            let keys: Vec<(CommitId, Tid)> = self.by_commit_on.range((*c, Tid::from_bytes([0; 15]))..).take_while(|(k, _)| k.0 == *c).map(|(k, _)| *k).collect();
            for k in keys {
                for n in self.by_commit_on.remove(&k).unwrap_or_default() {
                    let Some(d) = self.deltas.remove(&n) else { continue };
                    self.ids.remove(&d.id);
                    match &d.class {
                        Class::Addendum(_, list) => {
                            for x in list.commits() {
                                if let Some(set) = self.named.get_mut(x) {
                                    set.remove(&Namer::Addendum(n));
                                }
                                out.carried.insert(*x);
                            }
                            for e in &d.hops {
                                if let Some(set) = self.addenda_on.get_mut(e) {
                                    set.remove(&(d.pos, n));
                                }
                            }
                            self.addenda.remove(&n);
                            self.valid_addenda.remove(&n);
                        }
                        Class::Snapshot(carries) => {
                            for x in carries.commits() {
                                if let Some(set) = self.carried.get_mut(x) {
                                    set.remove(&n);
                                }
                                out.carried.insert(*x);
                            }
                        }
                        Class::Purge(author) => {
                            if let Some(set) = self.requests.get_mut(&(d.on, d.aspect.clone(), *author)) {
                                set.remove(&n);
                            }
                        }
                        Class::Plain | Class::Role => {}
                    }
                }
            }
        }
        out
    }

    /// What the held snapshots of commits `cs` carry (a list naming one names those).
    pub(super) fn carried_by(&self, cs: &BTreeSet<CommitId>) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        for c in cs {
            for (_, ns) in self.by_commit_on.range((*c, Tid::from_bytes([0; 15]))..).take_while(|(k, _)| k.0 == *c) {
                for n in ns {
                    if let Some(Class::Snapshot(carries)) = self.deltas.get(n).map(|d| &d.class) {
                        out.extend(carries.commits());
                    }
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

    /// The namers of delta `d`: what lists its commit, or a snapshot of its thing and aspect
    /// carrying it.
    fn namers(&self, d: &D, counts: &mut Counts) -> Vec<Namer> {
        let mut out: Vec<Namer> = self.named.get(&d.commit).into_iter().flatten().copied().collect();
        for &s in self.carriers(&d.commit) {
            counts.content += 1;
            let Some(sd) = self.deltas.get(&s) else { continue };
            if sd.on == d.on && sd.aspect == d.aspect && sd.commit != d.commit {
                out.extend(self.named.get(&sd.commit).into_iter().flatten().copied());
            }
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
    fn holds(&self, tl: &Walk, d: &D, counts: &mut Counts) -> bool {
        d.hops.iter().all(|(h, t)| {
            counts.content += 1;
            tl.role_before(h, t, &d.pos) >= Some(d.needs) && tl.last_cut(h, t, d.needs).is_none_or(|k| k < d.pos)
        })
    }

    /// (b): a cut of its path below `needs` lists its commit (its frontier, or a counting entry).
    fn listed(&self, tl: &Walk, d: &D, counts: &mut Counts) -> bool {
        let by_frontier = self.namers(d, counts).iter().any(|n| matches!(n, Namer::Write(id) if Self::cut_on(tl, id, d.needs, &d.hops).is_some()));
        by_frontier
            || self.counted.get(&(d.commit, d.on)).into_iter().flatten().any(|r| {
                counts.content += 1;
                tl.parts_of(r).iter().any(|id| Self::cut_on(tl, id, d.needs, &d.hops).is_some())
            })
    }

    /// Whether the delta is content an addendum may vouch for: a plain delta or an addendum of a
    /// content commit carrying no purge request.
    fn vouchable(&self, d: &D) -> bool {
        matches!(d.class, Class::Plain | Class::Addendum(..)) && self.commits.get(&d.commit).is_some_and(|c| !c.purge && !c.role)
    }

    /// Whether addendum `a` (assumed valid) vouches for delta `d` (draft §5.2 Addenda).
    fn vouches(&self, tl: &Walk, a: &D, d: &D, counts: &mut Counts) -> bool {
        let Class::Addendum(removal, _) = &a.class else { return false };
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
    fn regranted(&self, tl: &Walk, d: &D, counts: &mut Counts) -> bool {
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
    fn base(&self, tl: &Walk, d: &D, counts: &mut Counts) -> Option<By> {
        if !d.well {
            None
        } else if self.holds(tl, d, counts) {
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
    fn valid(&self, tl: &Walk, d: &D, counts: &mut Counts) -> Option<By> {
        match self.base(tl, d, counts) {
            Some(By::Regranted) | None if self.vouched(tl, d, counts) => Some(By::Vouched),
            b => b,
        }
    }

    fn vouched(&self, tl: &Walk, d: &D, counts: &mut Counts) -> bool {
        self.vouchable(d)
            && self.namers(d, counts).iter().any(|n| match n {
                Namer::Addendum(a) => self.valid_addenda.contains(a) && self.deltas.get(a).is_some_and(|ad| self.vouches(tl, ad, d, counts)),
                Namer::Write(_) => false,
            })
    }

    pub(super) fn content(&self, tl: &Walk, id: &WriteId, counts: &mut Counts) -> Option<Content> {
        let d = self.deltas.get(self.ids.get(id)?)?;
        Some(match self.valid(tl, d, counts) {
            Some(b) => Content::Valid(b),
            None if self.copied(tl, d, counts) => Content::Copied,
            None => Content::Invalid,
        })
    }

    /// The held snapshots carrying held commit `c`: none for a role commit, which no snapshot
    /// carries (draft §5.2 Copies: role commits are never compacted).
    fn carriers(&self, c: &CommitId) -> impl Iterator<Item = &usize> {
        self.carried.get(c).filter(|_| self.commits.get(c).is_some_and(|f| !f.role)).into_iter().flatten()
    }

    /// Carried by a valid snapshot of its thing and aspect.
    fn copied(&self, tl: &Walk, d: &D, counts: &mut Counts) -> bool {
        self.carriers(&d.commit).any(|&s| {
            counts.content += 1;
            self.deltas.get(&s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect && sd.commit != d.commit && self.valid(tl, sd, counts).is_some())
        })
    }

    /// A held delta's hops and position.
    pub(super) fn rests(&self, id: &WriteId) -> Option<(Vec<Pair>, Key)> {
        self.ids.get(id).and_then(|n| self.deltas.get(n)).map(|d| (d.hops.clone(), d.pos))
    }

    /// What names a held delta: the addenda listing its commit (or a snapshot carrying it), the
    /// snapshots of its thing and aspect carrying it, the requests by its purge author on its
    /// thing and aspect.
    pub(super) fn naming(&self, id: &WriteId) -> Vec<WriteId> {
        let Some(d) = self.ids.get(id).and_then(|n| self.deltas.get(n)) else { return vec![] };
        let mut out: Vec<usize> = vec![];
        for n in self.namers(d, &mut Counts::default()) {
            if let Namer::Addendum(a) = n {
                out.push(a);
            }
        }
        out.extend(self.carriers(&d.commit).copied().filter(|&s| self.deltas.get(&s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect)));
        if let Some(pa) = d.purge_author {
            let key = (d.on, d.aspect.clone(), pa);
            out.extend(self.requests.get(&key).into_iter().flatten().copied());
        }
        out.into_iter().filter_map(|n| self.deltas.get(&n)).map(|x| x.id).collect()
    }

    pub(super) fn ids(&self) -> impl Iterator<Item = &WriteId> {
        self.ids.keys()
    }

    /// Commits a valid snapshot carries that no valid held delta of its thing and aspect is.
    pub(super) fn copies(&self, tl: &Walk, counts: &mut Counts) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        for s in self.deltas.values() {
            let Class::Snapshot(carries) = &s.class else { continue };
            if self.valid(tl, s, counts).is_none() {
                continue;
            }
            for c in carries.commits().iter().filter(|c| self.commits.get(c).is_none_or(|f| !f.role)) {
                let valid_held = self.by_commit_on.get(&(*c, s.on)).into_iter().flatten().filter_map(|n| self.deltas.get(n)).any(|d| d.aspect == s.aspect && self.valid(tl, d, counts).is_some());
                if !valid_held && *c != s.commit {
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
        let Some(d) = self.ids.get(id).and_then(|n| self.deltas.get(n)) else { return false };
        let (Class::Plain, Some(pa), true) = (&d.class, d.purge_author, d.retention.author()) else { return false };
        self.requests.get(&(d.on, d.aspect.clone(), pa)).into_iter().flatten().any(|&q| {
            counts.content += 1;
            self.deltas.get(&q).is_some_and(|qd| qd.ts > d.ts && qd.chain.contains(&pa) && self.valid(tl, qd, counts).is_some())
        })
    }

    // ---- addenda: the least fixpoint, by reach ----

    /// Judges again the addenda an update reached (notes/perm-paths.md, Counting entries and
    /// addenda, by reach): those `ch` reaches as it reaches any delta (an edge of its path in
    /// `edges` before its position, in `cuts` at or after it, in `regrant`; its commit in
    /// `named`), those `fresh`, and every addendum their lists name, in turn (F). F leaves the
    /// valid set; its members valid by (a), (b), (d) or by a valid namer outside F join it again
    /// and vouch in turn. Outside F no read changed. The addenda whose validity changed.
    pub(super) fn addenda_update(&mut self, tl: &Walk, ch: &Changed, fresh: &[usize]) -> BTreeSet<WriteId> {
        let mut counts = Counts::default();
        let mut f: BTreeSet<usize> = fresh.iter().copied().collect();
        let low = (Key::start(Ts::ZERO), 0);
        for (e, k) in &ch.edges {
            f.extend(self.addenda_on.get(e).into_iter().flat_map(|x| x.range((std::ops::Bound::Excluded((*k, usize::MAX)), std::ops::Bound::Unbounded))).map(|x| x.1));
        }
        for (e, k) in &ch.cuts {
            f.extend(self.addenda_on.get(e).into_iter().flat_map(|x| x.range(low..=(*k, usize::MAX))).map(|x| x.1));
        }
        for e in &ch.regrant {
            f.extend(self.addenda_on.get(e).into_iter().flatten().map(|x| x.1));
        }
        for c in &ch.named {
            f.extend(self.by_commit_on.range((*c, Tid::from_bytes([0; 15]))..).take_while(|(k, _)| k.0 == *c).flat_map(|(_, v)| v.iter()).filter(|n| self.addenda.contains(n)));
        }
        let mut todo: Vec<usize> = f.iter().copied().collect();
        while let Some(a) = todo.pop() {
            let Some(Class::Addendum(_, list)) = self.deltas.get(&a).map(|d| &d.class) else { continue };
            let on = self.deltas.get(&a).map(|d| d.on);
            for c in list.commits() {
                counts.addenda += 1;
                for t in on.map(|on| self.targets(c, on)).unwrap_or_default() {
                    if self.addenda.contains(&t) && f.insert(t) {
                        todo.push(t);
                    }
                }
            }
        }
        let was: BTreeSet<usize> = self.valid_addenda.intersection(&f).copied().collect();
        let mut valid = std::mem::take(&mut self.valid_addenda);
        for a in &f {
            valid.remove(a);
        }
        self.valid_addenda = valid;
        let mut queue: Vec<usize> = vec![];
        for &a in &f {
            counts.addenda += 1;
            if let Some(d) = self.deltas.get(&a)
                && self.addenda.contains(&a)
                && (self.base(tl, d, &mut counts).is_some() || self.vouched(tl, d, &mut counts))
            {
                queue.push(a);
            }
        }
        let mut valid = std::mem::take(&mut self.valid_addenda);
        self.spread(tl, &mut valid, queue, &mut counts);
        self.valid_addenda = valid;
        self.counts.add(&counts);
        f.iter().filter(|a| was.contains(a) != self.valid_addenda.contains(a)).filter_map(|a| self.deltas.get(a)).map(|d| d.id).collect()
    }

    /// The worklist: each addendum popped joins `valid` and the addenda its list names that it
    /// vouches for are pushed.
    fn spread(&self, tl: &Walk, valid: &mut BTreeSet<usize>, mut queue: Vec<usize>, counts: &mut Counts) {
        while let Some(a) = queue.pop() {
            if !valid.insert(a) {
                continue;
            }
            let Some(ad) = self.deltas.get(&a) else { continue };
            let Class::Addendum(_, list) = &ad.class else { continue };
            for c in list.commits() {
                counts.addenda += 1;
                for t in self.targets(c, ad.on) {
                    if valid.contains(&t) {
                        continue;
                    }
                    if let Some(td) = self.deltas.get(&t)
                        && matches!(td.class, Class::Addendum(..))
                        && self.addenda.contains(&t)
                        && self.vouches(tl, ad, td, counts)
                    {
                        queue.push(t);
                    }
                }
            }
        }
    }

    /// The held deltas on `on` a list entry `c` names: `c`'s own, and where `c` is a snapshot of
    /// `on`, those of its thing and aspect it carries.
    fn targets(&self, c: &CommitId, on: Tid) -> Vec<usize> {
        let mut out: Vec<usize> = self.by_commit_on.get(&(*c, on)).cloned().unwrap_or_default();
        for &s in self.by_commit_on.get(&(*c, on)).into_iter().flatten() {
            let Some(Class::Snapshot(carries)) = self.deltas.get(&s).map(|d| &d.class) else { continue };
            let aspect = self.deltas.get(&s).map(|d| d.aspect.clone());
            for x in carries.commits() {
                out.extend(self.by_commit_on.get(&(*x, on)).into_iter().flatten().filter(|&n| self.deltas.get(n).map(|d| d.aspect.clone()) == aspect));
            }
        }
        out
    }
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
    pub addenda: Vec<usize>,
}
