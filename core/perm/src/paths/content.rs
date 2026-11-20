//! Content (draft §5.2): a delta's validity derived at read from the second walk's per-edge
//! state, the chained points and what names the delta (notes/perm-paths.md, Step 3b design).
//! Stored per delta: its facts alone. Stored per edge: the first chained key giving write and
//! admin (draft §4 Chained writes), kept by one pass over the held edge writes with an undo
//! stack. Addenda validity is the one stored verdict (a least fixpoint), recomputed after an
//! update that may change it.

use super::path::shape;
use super::walk::{Counts, Key, Walk};
use super::{By, Commit, Content, DeltaClass, PartKind};
use crate::types::{Edge, Frontier, WriteId};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};

type Pair = (Tid, Tid);
type Lvl = Option<Role>;
/// A chained set undone by a rollback: its commit's key, the edge, its level and first keys before.
type ChainUndo = (Key, Pair, Option<(Lvl, Lvl)>, Option<[Option<Key>; 2]>);

/// What a held commit is, for the counting rule and the addenda rule.
#[derive(Clone)]
pub(super) struct CommitFacts {
    /// Its commit-level key (part 0).
    pub key: Key,
    pub signer: Tid,
    /// The things it has a role-class part on (edge-class parts and role-class deltas).
    pub role_on: BTreeSet<Tid>,
    /// The edges its parts rest on (their paths', and the edges its self-removals lower).
    pub rests: BTreeSet<Pair>,
    /// It carries a purge request.
    purge: bool,
    /// It is a role commit: it has a role-class part.
    role: bool,
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
#[derive(Clone, Copy)]
enum Namer {
    Write(WriteId),
    Addendum(usize),
}

/// A held edge write, for the chained pass.
#[derive(Clone)]
struct Ew {
    e: Pair,
    hops: Vec<Pair>,
    /// Well, no self-removal, no finalize, a value: it may set its edge.
    sets: Option<Edge>,
    ts: Ts,
}

#[derive(Clone, Default)]
pub(super) struct Facts {
    mint: BTreeMap<Tid, Tid>,
    pub commits: BTreeMap<CommitId, CommitFacts>,
    deltas: Vec<D>,
    ids: BTreeMap<WriteId, usize>,
    by_commit_on: BTreeMap<(CommitId, Tid), Vec<usize>>,
    named: BTreeMap<CommitId, Vec<Namer>>,
    carried: BTreeMap<CommitId, Vec<usize>>,
    requests: BTreeMap<(Tid, Ak, Tid), Vec<usize>>,
    addenda: Vec<usize>,
    valid_addenda: BTreeSet<usize>,
    /// (removal, commit) by commit: the counting entries (draft §5.1 Vouches).
    counted: BTreeMap<CommitId, Vec<CommitId>>,
    // the chained pass
    writes: BTreeMap<Key, Ew>,
    /// Per edge the highest role and invite chained writes set (record edges: admin, implicit).
    level: BTreeMap<Pair, (Lvl, Lvl)>,
    /// Per edge the first chained key giving write, and giving admin.
    first: BTreeMap<Pair, [Option<Key>; 2]>,
    chain_undo: Vec<ChainUndo>,
    /// While an update runs: each touched edge's first chained keys before it.
    chain_journal: BTreeMap<Pair, Option<[Option<Key>; 2]>>,
    pub counts: Counts,
}

fn give_invite(role: Lvl, field: Lvl) -> Lvl {
    if role == Some(Role::Admin) { role } else { field.min(role) }
}

fn lvl_ix(r: Role) -> usize {
    usize::from(r == Role::Admin)
}

impl Facts {
    pub(super) fn new(records: &BTreeMap<Tid, Tid>) -> Facts {
        Facts { mint: records.clone(), ..Facts::default() }
    }

    fn record(&self, e: Pair) -> bool {
        self.mint.get(&e.1) == Some(&e.0)
    }

    /// Takes in new commits (the walks took their edge-class parts; `key` reads a part's key
    /// there). Returns the new deltas, the snapshots' carried commits, whether a role-class part,
    /// an addendum or a snapshot arrived, and the earliest new edge write's key.
    pub(super) fn take(&mut self, commits: &[&Commit], key: impl Fn(&WriteId) -> Option<Key>) -> Taken {
        let mut out = Taken::default();
        for c in commits {
            let start = Key { ts: c.ts, signer: c.signer, commit: c.id, part: 0 };
            let mut cf = CommitFacts { key: start, signer: c.signer, role_on: BTreeSet::new(), rests: BTreeSet::new(), purge: false, role: false };
            for (ix, p) in (0u32..).zip(c.parts.iter()) {
                let id = WriteId(c.id, ix);
                match &p.kind {
                    PartKind::Edge(ew) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, Some(ew.holder), true);
                        cf.role_on.insert(p.on);
                        cf.role = true;
                        cf.rests.extend(sh.hops.iter().copied());
                        if sh.leave {
                            cf.rests.insert((ew.holder, p.on));
                        }
                        if let Some(f) = &ew.frontier {
                            for x in f.commits() {
                                self.named.entry(*x).or_default().push(Namer::Write(id));
                            }
                        }
                        let finalize = ew.value.is_none() && ew.frontier.is_none() && !sh.leave && ew.holder != c.signer;
                        let sets = ew.value.filter(|_| sh.well && !sh.leave && !finalize);
                        if let Some(k) = key(&id) {
                            out.edge_from = Some(out.edge_from.map_or(k, |f: Key| f.min(k)));
                            self.writes.insert(k, Ew { e: (ew.holder, p.on), hops: sh.hops, sets, ts: c.ts });
                        }
                        out.role = true;
                    }
                    PartKind::Vouch { .. } => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, None, true);
                        cf.role_on.insert(p.on);
                        cf.role = true;
                        cf.rests.extend(sh.hops);
                        out.role = true;
                    }
                    PartKind::Delta(d) => {
                        let sh = shape(&self.mint, c.signer, &p.path, p.on, None, false);
                        cf.rests.extend(sh.hops.iter().copied());
                        let chain: Vec<Tid> = std::iter::once(c.signer).chain(p.path.iter().copied()).collect();
                        let purge_author = usize::try_from(d.purge_author).ok().and_then(|i| chain.get(i).copied());
                        let class = match &d.class {
                            DeltaClass::Plain => Class::Plain,
                            DeltaClass::RoleClass => {
                                cf.role_on.insert(p.on);
                                cf.role = true;
                                out.role = true;
                                Class::Role
                            }
                            DeltaClass::Snapshot { carries } => {
                                out.snapshot = true;
                                out.carried.extend(carries.commits().iter().copied());
                                Class::Snapshot(carries.clone())
                            }
                            DeltaClass::Addendum { removal, list } => {
                                out.addendum = true;
                                Class::Addendum(*removal, list.clone())
                            }
                            DeltaClass::PurgeByAuthor { author } => {
                                cf.purge = true;
                                Class::Purge(*author)
                            }
                        };
                        let n = self.deltas.len();
                        let pos = Key::start(c.ts);
                        self.deltas.push(D {
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
                let Some(d) = self.deltas.get(n) else { continue };
                match &d.class {
                    Class::Addendum(_, list) if !cf.role => {
                        for x in list.commits() {
                            self.named.entry(*x).or_default().push(Namer::Addendum(n));
                        }
                        self.addenda.push(n);
                    }
                    Class::Snapshot(carries) => {
                        for x in carries.commits() {
                            self.carried.entry(*x).or_default().push(n);
                        }
                    }
                    Class::Purge(author) => {
                        self.requests.entry((d.on, d.aspect.clone(), *author)).or_default().push(n);
                    }
                    _ => {}
                }
            }
            self.commits.insert(c.id, cf);
        }
        out
    }

    // ---- the chained pass (draft §4 Chained writes) ----

    /// Rolls the chained pass back to `p` and replays every held edge write from there, commit by
    /// commit: a write is chained where every edge of its path is a record edge or set at admin
    /// by a chained write of an earlier commit (an invite grant: its role on each edge but the
    /// last, an invite of it on the last); a chained write sets its edge at the role and invite it
    /// sets, `until` disregarded.
    pub(super) fn chain_from(&mut self, p: Key) {
        let p = p.commit_start();
        while self.chain_undo.last().is_some_and(|u| u.0 >= p) {
            let Some((_, e, lv, fi)) = self.chain_undo.pop() else { break };
            self.chain_note(e);
            match lv {
                Some(v) => self.level.insert(e, v),
                None => self.level.remove(&e),
            };
            match fi {
                Some(v) => self.first.insert(e, v),
                None => self.first.remove(&e),
            };
        }
        let todo: Vec<(Key, Ew)> = self.writes.range(p..).map(|(k, w)| (*k, w.clone())).collect();
        let mut i = 0;
        while i < todo.len() {
            let commit = todo.get(i).map(|t| t.0.commit);
            let mut sets: Vec<(Key, Pair, Edge)> = vec![];
            while let Some((k, w)) = todo.get(i).filter(|t| Some(t.0.commit) == commit) {
                i += 1;
                let Some(v) = w.sets else { continue };
                let role = |h: &Pair| if self.record(*h) { Some(Role::Admin) } else { self.level.get(h).and_then(|l| l.0) };
                let inv = |h: &Pair| if self.record(*h) { Some(Role::Admin) } else { self.level.get(h).and_then(|l| l.1) };
                let admin = w.hops.iter().all(|h| role(h) == Some(Role::Admin));
                let lvl = (v.invite <= Some(v.role) && v.role < Role::Admin && v.alive_at(Some(w.ts))).then_some(Some(v.role));
                let invited = lvl.is_some_and(|l| w.hops.split_last().is_some_and(|(last, before)| inv(last) >= l && before.iter().all(|h| role(h) >= l)));
                if admin || invited {
                    sets.push((*k, w.e, v));
                }
            }
            for (k, e, v) in sets {
                self.chain_note(e);
                let old_l = self.level.get(&e).copied();
                let old_f = self.first.get(&e).copied();
                self.chain_undo.push((k.commit_start(), e, old_l, old_f));
                let (r0, i0) = old_l.unwrap_or((None, None));
                self.level.insert(e, (r0.max(Some(v.role)), i0.max(give_invite(Some(v.role), v.invite))));
                if v.role < Role::Write {
                    continue;
                }
                let f = self.first.entry(e).or_insert([None, None]);
                for (n, r) in [Role::Write, Role::Admin].into_iter().enumerate() {
                    if v.role >= r
                        && let Some(slot) = f.get_mut(n)
                        && slot.is_none()
                    {
                        *slot = Some(k);
                    }
                }
            }
        }
    }

    /// Per edge, the first chained keys giving write and admin.
    pub(super) fn chained(&self) -> BTreeMap<Pair, [Option<Key>; 2]> {
        self.first.clone()
    }

    fn chain_note(&mut self, e: Pair) {
        let was = self.first.get(&e).copied();
        self.chain_journal.entry(e).or_insert(was);
    }

    /// The edges whose first chained keys changed since the last call.
    pub(super) fn chain_changed(&mut self) -> BTreeSet<Pair> {
        let j = std::mem::take(&mut self.chain_journal);
        j.into_iter().filter(|(e, was)| self.first.get(e).copied() != *was).map(|(e, _)| e).collect()
    }

    // ---- counting entries as lists ----

    pub(super) fn set_counted(&mut self, pairs: &BTreeSet<(CommitId, CommitId)>) {
        self.counted.clear();
        for (r, c) in pairs {
            self.counted.entry(*c).or_default().push(*r);
        }
    }

    // ---- judging a delta ----

    /// The namers of delta `d`: what lists its commit, or a snapshot of its thing and aspect
    /// carrying it.
    fn namers(&self, d: &D, counts: &mut Counts) -> Vec<Namer> {
        let mut out: Vec<Namer> = self.named.get(&d.commit).cloned().unwrap_or_default();
        for &s in self.carried.get(&d.commit).into_iter().flatten() {
            counts.content += 1;
            let Some(sd) = self.deltas.get(s) else { continue };
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
            || self.counted.get(&d.commit).into_iter().flatten().any(|r| {
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
                let Some(k) = self.first.get(&(h, t)).and_then(|f| f.get(lvl_ix(d.needs)).copied().flatten()) else { return false };
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
                Namer::Addendum(a) => self.valid_addenda.contains(a) && self.deltas.get(*a).is_some_and(|ad| self.vouches(tl, ad, d, counts)),
                Namer::Write(_) => false,
            })
    }

    pub(super) fn content(&self, tl: &Walk, id: &WriteId, counts: &mut Counts) -> Option<Content> {
        let d = self.deltas.get(*self.ids.get(id)?)?;
        Some(match self.valid(tl, d, counts) {
            Some(b) => Content::Valid(b),
            None if self.copied(tl, d, counts) => Content::Copied,
            None => Content::Invalid,
        })
    }

    /// Carried by a valid snapshot of its thing and aspect.
    fn copied(&self, tl: &Walk, d: &D, counts: &mut Counts) -> bool {
        self.carried.get(&d.commit).into_iter().flatten().any(|&s| {
            counts.content += 1;
            self.deltas.get(s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect && sd.commit != d.commit && self.valid(tl, sd, counts).is_some())
        })
    }

    /// A held delta's hops and position.
    pub(super) fn rests(&self, id: &WriteId) -> Option<(Vec<Pair>, Key)> {
        self.ids.get(id).and_then(|&n| self.deltas.get(n)).map(|d| (d.hops.clone(), d.pos))
    }

    /// What names a held delta: the addenda listing its commit (or a snapshot carrying it), the
    /// snapshots of its thing and aspect carrying it, the requests by its purge author on its
    /// thing and aspect.
    pub(super) fn naming(&self, id: &WriteId) -> Vec<WriteId> {
        let Some(d) = self.ids.get(id).and_then(|&n| self.deltas.get(n)) else { return vec![] };
        let mut out: Vec<usize> = vec![];
        for n in self.namers(d, &mut Counts::default()) {
            if let Namer::Addendum(a) = n {
                out.push(a);
            }
        }
        out.extend(self.carried.get(&d.commit).into_iter().flatten().copied().filter(|&s| self.deltas.get(s).is_some_and(|sd| sd.on == d.on && sd.aspect == d.aspect)));
        if let Some(pa) = d.purge_author {
            out.extend(self.requests.get(&(d.on, d.aspect.clone(), pa)).into_iter().flatten().copied());
        }
        out.into_iter().filter_map(|n| self.deltas.get(n)).map(|x| x.id).collect()
    }

    pub(super) fn ids(&self) -> impl Iterator<Item = &WriteId> {
        self.ids.keys()
    }

    /// Commits a valid snapshot carries that no valid held delta of its thing and aspect is.
    pub(super) fn copies(&self, tl: &Walk, counts: &mut Counts) -> BTreeSet<CommitId> {
        let mut out = BTreeSet::new();
        for s in &self.deltas {
            let Class::Snapshot(carries) = &s.class else { continue };
            if self.valid(tl, s, counts).is_none() {
                continue;
            }
            for c in carries.commits() {
                let valid_held = self.by_commit_on.get(&(*c, s.on)).into_iter().flatten().filter_map(|&n| self.deltas.get(n)).any(|d| d.aspect == s.aspect && self.valid(tl, d, counts).is_some());
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
        let Some(d) = self.ids.get(id).and_then(|&n| self.deltas.get(n)) else { return false };
        let (Class::Plain, Some(pa), true) = (&d.class, d.purge_author, d.retention.author()) else { return false };
        self.requests.get(&(d.on, d.aspect.clone(), pa)).into_iter().flatten().any(|&q| {
            counts.content += 1;
            self.deltas.get(q).is_some_and(|qd| qd.ts > d.ts && qd.chain.contains(&pa) && self.valid(tl, qd, counts).is_some())
        })
    }

    // ---- addenda: the least fixpoint ----

    /// Recomputes which addenda are valid; the addenda whose validity changed.
    pub(super) fn addenda_fixpoint(&mut self, tl: &Walk) -> BTreeSet<WriteId> {
        let mut counts = Counts::default();
        let was = std::mem::take(&mut self.valid_addenda);
        let mut queue: Vec<usize> = vec![];
        for &a in &self.addenda {
            counts.addenda += 1;
            if let Some(d) = self.deltas.get(a)
                && self.base(tl, d, &mut counts).is_some()
            {
                queue.push(a);
            }
        }
        let mut valid = BTreeSet::new();
        while let Some(a) = queue.pop() {
            if !valid.insert(a) {
                continue;
            }
            let Some(ad) = self.deltas.get(a) else { continue };
            let Class::Addendum(_, list) = &ad.class else { continue };
            for c in list.commits() {
                counts.addenda += 1;
                for t in self.targets(c, ad.on) {
                    if valid.contains(&t) {
                        continue;
                    }
                    if let Some(td) = self.deltas.get(t)
                        && matches!(td.class, Class::Addendum(..))
                        && self.addenda.contains(&t)
                        && self.vouches(tl, ad, td, &mut counts)
                    {
                        queue.push(t);
                    }
                }
            }
        }
        self.valid_addenda = valid;
        self.counts.add(&counts);
        was.symmetric_difference(&self.valid_addenda).filter_map(|&n| self.deltas.get(n)).map(|d| d.id).collect()
    }

    /// The held deltas on `on` a list entry `c` names: `c`'s own, and where `c` is a snapshot of
    /// `on`, those of its thing and aspect it carries.
    fn targets(&self, c: &CommitId, on: Tid) -> Vec<usize> {
        let mut out: Vec<usize> = self.by_commit_on.get(&(*c, on)).cloned().unwrap_or_default();
        for &s in self.by_commit_on.get(&(*c, on)).into_iter().flatten() {
            let Some(Class::Snapshot(carries)) = self.deltas.get(s).map(|d| &d.class) else { continue };
            let aspect = self.deltas.get(s).map(|d| d.aspect.clone());
            for x in carries.commits() {
                out.extend(self.by_commit_on.get(&(*x, on)).into_iter().flatten().filter(|&&n| self.deltas.get(n).map(|d| d.aspect.clone()) == aspect));
            }
        }
        out
    }
}

/// What `Facts::take` found.
#[derive(Default)]
pub(super) struct Taken {
    pub deltas: Vec<WriteId>,
    pub carried: BTreeSet<CommitId>,
    pub role: bool,
    pub addendum: bool,
    pub snapshot: bool,
    pub edge_from: Option<Key>,
}
