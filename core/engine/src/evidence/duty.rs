//! A3's delivery duty, the targets side (notes/a3-spec/permissions.md §4 The delivery duty;
//! notes/evidence-derivation.md, The duty's targets): for each held removal taking write away on
//! (h, t) (reach's removals), every thing reached from t by chained writes giving write or above
//! and record edges, at any time, followed to the end, over the node's held writes and the writes it
//! reads under the targets it holds for the duty (`duty_add`); each with the runner's mode there by
//! its own role (`set_role`): stamp where it holds write or above, deposit where read, none below.
//! Standing: kept as the graph, the removals and the roles move. The sync side (osis-sync, A3 brief
//! 4) loops over `duty()`, skipping the targets where a source already showed the copy.

use super::*;

/// How a runner logs a removal's copy under a target's own sync ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// Its role there gives write: logged as its own entry.
    Stamp,
    /// Its role there gives read only: deposited, for a writer there to log.
    Deposit,
}

/// One (removal, target) this node runs the duty for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Run<C, T> {
    /// The removal's copy (commit ID, the thing it is on: t).
    pub removal: CopyId<C, T>,
    /// The thing whose own sync ID it is logged under (never a dependent: a thing with no sync ID
    /// of its own, whose enclosing units get it from their readers' required sets).
    pub target: T,
    pub mode: Mode,
    /// The edge the walk reached the target by (None: t itself).
    pub via: Option<Edge<T>>,
}

/// What a removal reaches: each thing with the edge first reached by (None: its target).
pub type Reached<T> = BTreeMap<T, Option<Edge<T>>>;

type Parts<C, T, K> = Vec<Part<C, T, K>>;

/// The duty's state: what the node reads for it, its roles, and per removal what it reaches.
#[derive(Clone, Debug)]
pub(super) struct Duty<C, T, K> {
    /// Copies held for the duty only (read under a target's own sync ID): edges of the walk, no
    /// evidence of anything.
    held: BTreeMap<CopyId<C, T>, Parts<C, T, K>>,
    /// Their chained parts giving write.
    graph: Graph<C, T>,
    /// The node's own role on each thing, by a path, as its walk reads it.
    roles: BTreeMap<T, Role>,
    /// Things with no sync ID of their own: walked through, never targets.
    dependents: BTreeSet<T>,
    /// Per removal the things it reaches, each with the edge first reached by.
    runs: BTreeMap<CopyId<C, T>, Reached<T>>,
    /// Reverse: thing → removals reaching it.
    reached_by: BTreeMap<T, BTreeSet<CopyId<C, T>>>,
}

impl<C: Ord + Copy, T: Ord + Copy, K> Default for Duty<C, T, K> {
    fn default() -> Self {
        Duty { held: BTreeMap::new(), graph: Graph::new(), roles: BTreeMap::new(), dependents: BTreeSet::new(), runs: BTreeMap::new(), reached_by: BTreeMap::new() }
    }
}

impl<C, T, K> Evidence<C, T, K>
where
    C: Ord + Copy + Debug,
    T: Ord + Copy + Debug,
    K: Ord + Copy + Debug,
{
    /// The node's own role on `t` by a path (None: none), as its walk reads it: who runs the duty
    /// there and how (`runs`).
    pub fn set_role(&mut self, t: T, role: Option<Role>) {
        match role {
            Some(r) => self.duty.roles.insert(t, r),
            None => self.duty.roles.remove(&t),
        };
    }

    /// Whether `t` is a dependent (a thing with no sync ID of its own): the duty walks through it
    /// and never runs there.
    pub fn set_dependent(&mut self, t: T, dependent: bool) {
        if dependent {
            self.duty.dependents.insert(t);
        } else {
            self.duty.dependents.remove(&t);
        }
    }

    /// A copy read for the duty under a target's own sync ID (a grant naming the target as holder),
    /// held while that hold lasts: its chained writes giving write are edges of the duty's walk,
    /// nothing else. Taken again with these facts if already held.
    pub fn duty_add(&mut self, c: CopyId<C, T>, parts: Vec<Part<C, T, K>>) {
        if self.duty.held.contains_key(&c) {
            self.duty_forget(&c);
        }
        let mut todo = Todo::default();
        for (i, e) in duty_edges(&c, &parts) {
            if self.duty.graph.insert(e, (c, i)) && !self.ix.writes.has(&e) {
                todo.duty_new.push(e);
            }
        }
        self.duty.held.insert(c, parts);
        self.settle(todo);
    }

    /// A copy no longer held for the duty.
    pub fn duty_forget(&mut self, c: &CopyId<C, T>) {
        self.duty_forget_all([*c]);
    }

    /// Copies no longer held for the duty, at once (a hold's end: every copy read under that
    /// target): each removal they cut is walked again once, not once per copy.
    pub fn duty_forget_all(&mut self, cs: impl IntoIterator<Item = CopyId<C, T>>) {
        let mut todo = Todo::default();
        for c in cs {
            let Some(parts) = self.duty.held.remove(&c) else { continue };
            for (i, e) in duty_edges(&c, &parts) {
                if self.duty.graph.remove(&e, &(c, i)) && !self.ix.writes.has(&e) {
                    todo.duty_cut.push(e);
                }
            }
        }
        self.settle(todo);
    }

    /// Every (removal, target) the node runs the duty for now, with its mode: the targets it holds
    /// read or above on (by `set_role`), no dependent among them.
    pub fn duty(&self) -> Vec<Run<C, T>> {
        self.duty.runs.iter().flat_map(|(r, m)| m.iter().filter_map(move |(t, via)| self.runs(r, *t).map(|mode| Run { removal: *r, target: *t, mode, via: *via }))).collect()
    }

    /// The things removal `r` reaches (whatever the node's role there), each with the edge it was
    /// first reached by.
    pub fn reached(&self, r: &CopyId<C, T>) -> Option<&Reached<T>> {
        self.duty.runs.get(r)
    }

    /// Who runs the duty for removal `r` at target `t`, and how: the one predicate (notes/a3-spec
    /// README.md OPEN 2: every honest holder reading the target, *taken*; a narrowing of who runs is
    /// a change here). A dependent is no target.
    fn runs(&self, _r: &CopyId<C, T>, t: T) -> Option<Mode> {
        if self.duty.dependents.contains(&t) {
            return None;
        }
        match self.duty.roles.get(&t) {
            Some(r) if *r >= Role::Write => Some(Mode::Stamp),
            Some(r) if *r >= Role::Read => Some(Mode::Deposit),
            _ => None,
        }
    }

    /// Copy `c` is a removal with a duty: one of its parts is a held chained removal taking write
    /// away (reach's removals).
    fn duty_removal(&self, c: &CopyId<C, T>) -> bool {
        self.ix.removals_on.get(&c.1).is_some_and(|s| s.range((*c, 0)..=(*c, usize::MAX)).next().is_some())
    }

    /// The things the duty's walk steps to from `x`: over the held graph and the duty's.
    fn duty_next(&self, x: T) -> BTreeSet<T> {
        self.ix.writes.next(true, x).chain(self.duty.graph.next(true, x)).collect()
    }

    /// Breadth-first from `start` (reached by `via`) over the duty's walk, past `known`.
    fn duty_walk(&self, start: T, via: Option<Edge<T>>, known: &Reached<T>, n: &mut usize) -> Reached<T> {
        let mut out = BTreeMap::from([(start, via)]);
        let mut todo = vec![start];
        while let Some(x) = todo.pop() {
            *n += 1;
            for y in self.duty_next(x) {
                *n += 1;
                if known.contains_key(&y) || out.contains_key(&y) {
                    continue;
                }
                out.insert(y, Some((x, y)));
                todo.push(y);
            }
        }
        out
    }

    /// Moves the duty: `redo` (removals that came, went or changed) computed from nothing, those
    /// reaching both ends of an edge gone from the walk too; then each removal reaching the holder
    /// of a new edge walks on from its target (O(what it newly reaches)).
    pub(super) fn settle_duty(&mut self, redo: BTreeSet<CopyId<C, T>>, new: Vec<Edge<T>>, cut: Vec<Edge<T>>) {
        if !self.cfg.duty {
            return;
        }
        let mut redo = redo;
        for e in cut {
            if self.ix.writes.has(&e) || self.duty.graph.has(&e) {
                continue;
            }
            if let (Some(a), Some(b)) = (self.duty.reached_by.get(&e.0), self.duty.reached_by.get(&e.1)) {
                redo.extend(a.intersection(b).copied());
            }
        }
        let mut n = 0;
        for r in &redo {
            for t in self.duty.runs.remove(r).unwrap_or_default().keys() {
                remove_from(&mut self.duty.reached_by, t, r);
            }
            if self.duty_removal(r) {
                let m = self.duty_walk(r.1, None, &BTreeMap::new(), &mut n);
                for t in m.keys() {
                    self.duty.reached_by.entry(*t).or_default().insert(*r);
                }
                self.duty.runs.insert(*r, m);
            }
        }
        for e in new {
            for r in self.duty.reached_by.get(&e.0).cloned().unwrap_or_default() {
                if redo.contains(&r) {
                    continue;
                }
                let Some(known) = self.duty.runs.get(&r) else { continue };
                if known.contains_key(&e.1) {
                    continue;
                }
                let m = self.duty_walk(e.1, Some(e), known, &mut n);
                for t in m.keys() {
                    self.duty.reached_by.entry(*t).or_default().insert(r);
                }
                if let Some(known) = self.duty.runs.get_mut(&r) {
                    known.extend(m);
                }
            }
        }
        self.counts.duty += n;
    }

    /// `check`'s part: the duty's graph against what it holds, each removal's reach against a
    /// walk from nothing, the reverse index.
    pub(super) fn check_duty(&self) -> Result<(), String> {
        if !self.cfg.duty {
            return if self.duty.runs.is_empty() { Ok(()) } else { Err("duties kept with Config::duty off".into()) };
        }
        let mut g = Graph::new();
        for (c, parts) in &self.duty.held {
            for (i, e) in duty_edges(c, parts) {
                g.insert(e, (*c, i));
            }
        }
        if g != self.duty.graph {
            return Err("the duty's graph does not hold exactly its chained writes".into());
        }
        let removals: BTreeSet<CopyId<C, T>> = self.ix.removals_on.values().flatten().map(|p| p.0).collect();
        if removals.iter().ne(self.duty.runs.keys()) {
            return Err(format!("duties {:?}, removals {removals:?}", self.duty.runs.keys().collect::<Vec<_>>()));
        }
        let mut by: BTreeMap<T, BTreeSet<CopyId<C, T>>> = BTreeMap::new();
        for (r, m) in &self.duty.runs {
            let scratch = self.duty_walk(r.1, None, &BTreeMap::new(), &mut 0);
            if scratch.keys().ne(m.keys()) {
                return Err(format!("duty of {r:?}: reaches {:?}, from scratch {:?}", m.keys().collect::<Vec<_>>(), scratch.keys().collect::<Vec<_>>()));
            }
            for (t, via) in m {
                by.entry(*t).or_default().insert(*r);
                // the edge first reached by: a walk edge into it from a thing reached (None: t)
                let ok = match via {
                    None => *t == r.1,
                    Some(e) => e.1 == *t && m.contains_key(&e.0) && (self.ix.writes.has(e) || self.duty.graph.has(e)),
                };
                if !ok {
                    return Err(format!("duty of {r:?}: {t:?} reached by {via:?}, no edge of its walk"));
                }
            }
        }
        if by != self.duty.reached_by {
            return Err("the duty's reverse index (thing → removals) is stale".into());
        }
        Ok(())
    }
}

/// The chained parts of a copy giving write: (part, edge).
fn duty_edges<C: Copy, T: Copy, K>(c: &CopyId<C, T>, parts: &[Part<C, T, K>]) -> Vec<(usize, Edge<T>)> {
    parts.iter().enumerate().filter_map(|(i, p)| match &p.kind {
        Kind::Write(w) if p.chained && w.gives_write => Some((i, (w.holder, c.1))),
        _ => None,
    }).collect()
}
