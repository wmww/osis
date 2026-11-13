//! `groups.0` (spec/data-model.md §8): every group whose items, directly or through subgroups
//! (cycles allowed), contain the thing. Kept incrementally: a `group.0` change recomputes only the
//! changed group and the groups above it (O(their reach)), never every group. A join refreshes
//! the definition from the tids it touches (`touched`, `refresh`), reading only their records.

use super::Engine;
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Value};
use osis_crdt::{Dot, DotRange, Fragment, PathSeg};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A `group.0` definition: (items, subgroups).
pub(crate) type Def = (BTreeSet<Tid>, BTreeSet<Tid>);

/// `group.0` field ids (spec/data-model.md §8).
pub(crate) const ITEMS: u64 = 0;
pub(crate) const SUBGROUPS: u64 = 1;

/// The definition a `group.0` state holds: its items and subgroups read field by field.
pub(crate) fn def_of(f: &Fragment) -> Option<Def> {
    let tids = |field: u64| -> BTreeSet<Tid> {
        match f.at(&[PathSeg::Field(field)]).and_then(|x| x.read()) {
            Some(Value::Set(s)) => s.into_iter().filter_map(|v| if let Value::Tid(t) = v { Some(t) } else { None }).collect(),
            _ => BTreeSet::new(),
        }
    };
    let present = f.present();
    let d = (tids(ITEMS), tids(SUBGROUPS));
    (present || !d.0.is_empty() || !d.1.is_empty()).then_some(d)
}

/// What `delta` newly lists when joined into a group's state `before`.
pub(crate) fn gains(before: Option<&Fragment>, delta: &Fragment) -> BTreeSet<Tid> {
    let def = |f: &Fragment| def_of(f).unwrap_or_default();
    let (items, subs) = before.map(def).unwrap_or_default();
    let mut after = before.cloned().unwrap_or_default();
    after.join(delta.clone());
    let (i, s) = def(&after);
    i.difference(&items).chain(s.difference(&subs)).copied().collect()
}

/// The tids whose listing in group `g`'s `group.0` a join of `delta` may change: those its
/// elements hold and those of the state's records at its reach (`Fragment::reach`: an element it
/// resets, a record of a tid it removes), read from the pages the join touches anyway. `None`
/// where it resets a position (read the whole state after).
pub(crate) fn touched(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak, delta: &Fragment) -> Result<Option<BTreeSet<Tid>>> {
    if delta.has_position_reset() {
        return Ok(None);
    }
    tx.load_lazy(g, ak)?;
    let touch = super::pages::touch_of(delta, tx.core.pages.get(&(*g, ak.clone())));
    tx.ensure_touch(g, ak, &touch)?;
    let mut out = BTreeSet::new();
    let mut add = |f: &Fragment| {
        f.each_value(&mut |v| {
            if let Value::Tid(t) = v {
                out.insert(*t);
            }
        })
    };
    add(delta);
    if let Some(st) = tx.cached(g, ak) {
        add(&st.reach(delta));
    }
    Ok(Some(out))
}

/// Refreshes group `g`'s definition in the index for the tids `tids` (`touched`) after a join,
/// reading only their records (a paged state's value index): O(the change), not O(the group).
/// A join without a position reset leaves a present state present, so a group listed stays
/// listed; one not listed yet is read whole.
pub(crate) fn refresh(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak, tids: &BTreeSet<Tid>) -> Result<()> {
    if !tx.core.ix.groups.defs.contains_key(g) {
        return crate::apply::observe_state(tx, g, ak);
    }
    let paths: Vec<Vec<PathSeg>> = tids.iter().flat_map(|t| [ITEMS, SUBGROUPS].map(|f| vec![PathSeg::Field(f), PathSeg::Key(Value::Tid(*t))])).collect();
    tx.ensure_paths(g, ak, &paths)?;
    // the live ones among them, per field (what is loaded holds every record of each)
    let live = |f: u64| -> BTreeSet<Tid> {
        match tx.cached(g, ak).and_then(|s| s.read_at(&[PathSeg::Field(f)])) {
            Some(Value::Set(s)) => s.into_iter().filter_map(|v| if let Value::Tid(t) = v { Some(t) } else { None }).filter(|t| tids.contains(t)).collect(),
            _ => BTreeSet::new(),
        }
    };
    let (items, subs) = (live(ITEMS), live(SUBGROUPS));
    let Some(was) = tx.core.ix.groups.defs.get(g) else { return Ok(()) };
    let same = |now: &BTreeSet<Tid>, was: &BTreeSet<Tid>| tids.iter().all(|t| now.contains(t) == was.contains(t));
    if !(same(&items, &was.0) && same(&subs, &was.1)) {
        let mut def = was.clone();
        for t in tids {
            for (now, d) in [(&items, &mut def.0), (&subs, &mut def.1)] {
                if now.contains(t) {
                    d.insert(*t);
                } else {
                    d.remove(t);
                }
            }
        }
        // an ephemeral membership carries nothing durable away (`Core::note_cut`)
        if !tx.core.memory_tx {
            tx.core.note_cut(g, Some(&def));
        }
        tx.core.ix.groups.set(*g, Some(def));
    }
    #[cfg(debug_assertions)]
    check_refreshed(tx, g, ak)?;
    Ok(())
}

/// Debug builds: the definition `refresh` left equals the whole state's (unseen: the cache as it
/// was, no cost recorded).
#[cfg(debug_assertions)]
fn check_refreshed(tx: &mut super::Tx<'_>, g: &Tid, ak: &Ak) -> Result<()> {
    let k = (*g, ak.clone());
    let cached = (tx.core.states.get(&k).cloned(), tx.core.pages.get(&k).cloned());
    let whole = crate::costs::paused(|| -> Result<_> { Ok(crate::apply::atomic::group_def(tx.state(g, ak)?.and_then(Fragment::read))) })?;
    match cached.0 {
        Some(s) => tx.core.states.insert(k.clone(), s),
        None => tx.core.states.remove(&k),
    };
    match cached.1 {
        Some(p) => tx.core.pages.insert(k, p),
        None => tx.core.pages.remove(&k),
    };
    debug_assert_eq!(tx.core.ix.groups.defs.get(g), whole.as_ref(), "the group index of {g:?} refreshed from a join differs from its whole state");
    Ok(())
}

impl Engine {
    /// Groups containing the thing, transitively (`groups.0`).
    pub fn groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.ix.groups.of.get(tid).cloned().unwrap_or_default()
    }

    /// The groups whose closure holds the thing (spec/sync.md §3): itself, the groups containing
    /// it, and the groups above it through subgroup lists.
    pub fn enclosing(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.ix.groups.enclosing(tid)
    }

    /// The groups whose `group.0` lists the thing directly: (as an item, as a subgroup). From
    /// the in-memory group index, rebuilt from the definitions at open.
    pub fn listed_in(&self, tid: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        let ix = &self.core.ix.groups;
        // a group listing it as an item contains it: `of` is a superset of those
        let items = ix.of.get(tid).into_iter().flatten().filter(|g| ix.defs.get(g).is_some_and(|d| d.0.contains(tid))).copied().collect();
        (items, ix.parents_of(tid).collect())
    }
}

impl Engine {
    /// The groups whose `group.0` may list `t`, as an item and as a subgroup: what a delete of `t`
    /// removes it from (spec/crdt.md §5.5, §4.6). `listed_in`, and every group with a part of its
    /// `group.0` held as a header only (`header_only_parts`), in both: what that part lists is not
    /// known here.
    pub fn listing_groups(&mut self, t: &Tid) -> Result<(BTreeSet<Tid>, BTreeSet<Tid>)> {
        let t = *t;
        self.run(|tx| listing_groups(tx, &t))
    }
}

/// `Engine::listing_groups`.
pub(crate) fn listing_groups(tx: &mut super::Tx<'_>, t: &Tid) -> Result<(BTreeSet<Tid>, BTreeSet<Tid>)> {
    let (mut items, mut subs) = {
        let ix = &tx.core.ix.groups;
        let items: BTreeSet<Tid> = ix.of.get(t).into_iter().flatten().filter(|g| ix.defs.get(g).is_some_and(|d| d.0.contains(t))).copied().collect();
        (items, ix.parents_of(t).collect::<BTreeSet<Tid>>())
    };
    let gak = Ak::new(osis_schema::RawKey::ak(&osis_schema::core_types::GROUP)).map_err(|_| crate::error::Error::Misuse("ak"))?;
    let partial: Vec<Tid> = tx.core.ix.missing.range((gak.clone(), Tid::from_bytes([0; 15]))..).take_while(|((ak, _), _)| *ak == gak).map(|((_, g), _)| *g).collect();
    for g in partial {
        if g == *t || items.contains(&g) && subs.contains(&g) {
            continue;
        }
        if !header_only_parts(tx, &g, &gak)?.is_empty() {
            items.insert(g);
            subs.insert(g);
        }
    }
    Ok((items, subs))
}

/// `w` for ops `ops` on aspect `(tid, ak)`: a removal of a tid among them covers the parts held
/// as headers only too (`header_only_parts`, spec/crdt.md §5.5).
pub(crate) fn seeing(tx: &mut super::Tx<'_>, tid: &Tid, ak: &Ak, ops: &[osis_crdt::PathOp], w: osis_crdt::Writer) -> Result<osis_crdt::Writer> {
    if !ops.iter().any(|o| matches!(o.op, osis_crdt::Op::Remove(Value::Tid(_)))) {
        return Ok(w);
    }
    Ok(w.seen_headers(header_only_parts(tx, tid, ak)?))
}

/// The parts of aspect `(tid, ak)` this node holds as headers only, by their dots (spec/crdt.md
/// §2.4): valid here, not received yet (`Hold::Missing`, but one forgotten with its released
/// thing), and not stamped below a held root reset, which leaves them nothing. What a removal of
/// a tid there covers beside the elements held (§5.5).
pub(crate) fn header_only_parts(tx: &mut super::Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<DotRange>> {
    let cs: Vec<CommitId> = tx.core.ix.missing.get(&(ak.clone(), *tid)).into_iter().flatten().copied().collect();
    if cs.is_empty() {
        return Ok(Vec::new());
    }
    // the root's reset, held whatever pages are loaded
    tx.load_lazy(tid, ak)?;
    let reset = tx.cached(tid, ak).and_then(Fragment::reset).map(|r| r.ts);
    let mut out = Vec::new();
    for c in cs {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let Some(a) = m.aspect(tid, ak).filter(|ai| m.valid_at(*ai) && m.missing(*ai) && m.missing_as(*ai) != Some(super::Missing::Forgot)).and_then(|ai| m.view.aspects.get(ai)) else { continue };
        if a.lo < a.hi && reset.is_none_or(|r| m.view.ts >= r) {
            out.push(DotRange { first: Dot::new(m.view.form.own_source(m.view.author, c), a.lo), hi: a.hi });
        }
    }
    Ok(out)
}

impl Engine {
    /// Whether a synced group carries `t`: a labeled group's closure holds it (`enclosing`).
    pub fn carried(&self, t: &Tid) -> bool {
        self.core.carried(t)
    }
}

impl super::Core {
    /// `Engine::carried`.
    pub(crate) fn carried(&self, t: &Tid) -> bool {
        self.ix.groups.enclosing(t).iter().any(|g| self.ix.labeled.contains(g))
    }

    /// Before group `g`'s definition becomes `def`: each subgroup it cuts while a synced group
    /// carries `g` (`cut_subs`), whatever cut it (a write here or elsewhere, an expiry).
    pub(crate) fn note_cut(&mut self, g: &Tid, def: Option<&Def>) {
        let Some((_, was)) = self.ix.groups.defs.get(g) else { return };
        let cut: Vec<Tid> = was.iter().filter(|s| !def.is_some_and(|d| d.1.contains(*s))).copied().collect();
        if !cut.is_empty() && self.ix.groups.above(g).iter().any(|a| self.ix.labeled.contains(a)) {
            self.cut_subs.extend(cut);
        }
    }

    /// At the end of a transaction (before its journal is committed): the things the closures
    /// of the subgroups it cut held when it began (each subgroup itself included) that no synced
    /// group carries now, destroyed ones aside (`Engine::report_cut`).
    pub(crate) fn stranded_by_cut(&mut self) -> Vec<Tid> {
        let cut = std::mem::take(&mut self.cut_subs);
        if cut.is_empty() {
            return Vec::new();
        }
        let was = self.ix.groups.before();
        let held: BTreeSet<Tid> = cut.iter().flat_map(|s| self.ix.groups.reach_before(&was, s)).collect();
        held.into_iter().filter(|t| !self.carried(t) && !self.destroyed(t)).collect()
    }
}

impl Engine {
    /// After a transaction: a `NotSynced` diagnostic for each thing of `stranded`
    /// (`Core::stranded_by_cut`) that holds content (spec/requirements.md, Offline and network):
    /// it stays on this node. A deleted thing stays as nothing.
    pub(crate) fn report_cut(&mut self, stranded: Vec<Tid>, now: osis_base::WallMs) {
        for t in stranded {
            if self.has_content(&t).unwrap_or(true) {
                let detail = "a subgroup left the synced group that held it: this stays on this node".into();
                self.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::NotSynced, tids: vec![t], commit: None, peer: None, detail }, now);
            }
        }
    }
}

/// The `group.0` definitions and what they derive.
#[derive(Clone, Debug, Default)]
pub struct Groups {
    /// `group.0` of each group thing: (items, subgroups).
    pub defs: BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>,
    /// Subgroup -> groups listing it.
    parents: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Thing -> groups containing it, transitively (`groups.0`).
    pub of: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Group -> its closure (spec/sync.md §3): itself, its subgroups and the things it contains,
    /// transitively (groups listing something). The same `Arc` while the closure does not
    /// change, so node-sync reuses what it derived from it (`Arc::ptr_eq`).
    pub closures: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    /// Definitions replaced by the running transaction (`Journaled`).
    log: Vec<(Tid, Option<Def>)>,
    /// Things whose `groups_of` answer the running transaction changed (`Event::Groups`).
    pub(crate) moved: BTreeSet<Tid>,
}

impl Groups {
    /// What `g` reaches through its definition and its subgroups': (the things it contains,
    /// its closure). The closure adds `g` and every subgroup on the way.
    fn reach(&self, g: &Tid) -> (BTreeSet<Tid>, BTreeSet<Tid>) {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some((items, subs)) = self.defs.get(&x) {
                out.extend(items.iter().copied());
                stack.extend(subs.iter().copied());
            }
        }
        seen.extend(out.iter().copied());
        (out, seen)
    }

    /// The definitions the running transaction's journal replaced, as they were when it began.
    fn before(&self) -> BTreeMap<Tid, Option<&Def>> {
        let mut was = BTreeMap::new();
        for (x, d) in &self.log {
            was.entry(*x).or_insert(d.as_ref());
        }
        was
    }

    /// `g`'s closure when the running transaction began: `reach` over `was` (`before`) and the
    /// definitions it did not replace.
    fn reach_before(&self, was: &BTreeMap<Tid, Option<&Def>>, g: &Tid) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some((items, subs)) = was.get(&x).copied().unwrap_or(self.defs.get(&x)) {
                out.extend(items.iter().copied());
                stack.extend(subs.iter().copied());
            }
        }
        out.extend(seen);
        out
    }

    /// `g` and every group above it through subgroup lists.
    pub(crate) fn above(&self, g: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                stack.extend(self.parents.get(&x).into_iter().flatten().copied());
            }
        }
        seen
    }

    /// The groups whose closure holds `t`: `t`, the groups containing it and those above it.
    pub(crate) fn enclosing(&self, t: &Tid) -> BTreeSet<Tid> {
        let mut out = self.above(t);
        out.extend(self.of.get(t).into_iter().flatten().copied());
        out
    }

    /// Removes `a`'s closure and what derives from it; the closure, if any.
    fn unlist(&mut self, a: &Tid) -> Option<Arc<BTreeSet<Tid>>> {
        let old = self.closures.remove(a)?;
        // `a` is in `of[a]` only when it reaches itself, a subgroup in its closure is in `of[a]`
        // only when also contained: removing `a` is right either way
        for x in old.iter() {
            if let Some(s) = self.of.get_mut(x) {
                s.remove(a);
                if s.is_empty() {
                    self.of.remove(x);
                }
            }
        }
        Some(old)
    }

    /// Lists `a`'s closure, keeping `old` (its closure before) when it is unchanged.
    fn list(&mut self, a: &Tid, old: Option<Arc<BTreeSet<Tid>>>) {
        let (r, c) = self.reach(a);
        for x in &r {
            self.of.entry(*x).or_default().insert(*a);
        }
        if c.len() > 1 || !r.is_empty() {
            let c = match old {
                Some(o) if *o == c => o,
                _ => Arc::new(c),
            };
            self.closures.insert(*a, c);
        }
    }

    /// The groups listing `g` as a subgroup.
    pub(crate) fn parents_of(&self, g: &Tid) -> impl Iterator<Item = Tid> + '_ {
        self.parents.get(g).into_iter().flatten().copied()
    }

    /// The closure of `g`: itself, its subgroups and every thing it contains, transitively.
    pub fn closure(&self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        self.closures.get(g).cloned().unwrap_or_else(|| Arc::new(BTreeSet::from([*g])))
    }

    /// Sets (or with `None` removes) the definition of group `g` and updates what derives from it.
    pub fn set(&mut self, g: Tid, def: Option<(BTreeSet<Tid>, BTreeSet<Tid>)>) {
        if self.defs.get(&g) == def.as_ref() {
            return;
        }
        self.log.push((g, self.defs.get(&g).cloned()));
        self.apply(g, def)
    }

    fn apply(&mut self, g: Tid, def: Option<(BTreeSet<Tid>, BTreeSet<Tid>)>) {
        let above = self.above(&g);
        let was = self.defs.get(&g).cloned().unwrap_or_default();
        let now = def.clone().unwrap_or_default();
        self.moved.extend(was.0.symmetric_difference(&now.0).chain(was.1.symmetric_difference(&now.1)).copied());
        let mut old = BTreeMap::new();
        for a in &above {
            if let Some(c) = self.unlist(a) {
                old.insert(*a, c);
            }
        }
        if let Some((_, subs)) = self.defs.remove(&g) {
            for s in subs {
                if let Some(p) = self.parents.get_mut(&s) {
                    p.remove(&g);
                    if p.is_empty() {
                        self.parents.remove(&s);
                    }
                }
            }
        }
        if let Some(d) = def {
            for s in &d.1 {
                self.parents.entry(*s).or_default().insert(g);
            }
            self.defs.insert(g, d);
        }
        for a in &above {
            let before = old.remove(a);
            let was = before.clone().unwrap_or_default();
            self.list(a, before);
            let now = self.closures.get(a).cloned().unwrap_or_default();
            if !Arc::ptr_eq(&was, &now) {
                self.moved.extend(was.symmetric_difference(&now).copied());
                // what the group holds is an answer too (a listing of its writes)
                self.moved.insert(*a);
            }
        }
    }

    /// Sets a definition without deriving (`rebuild` follows): loading every group at open.
    pub fn set_def(&mut self, g: Tid, def: Option<(BTreeSet<Tid>, BTreeSet<Tid>)>) {
        if let Some((_, subs)) = self.defs.remove(&g) {
            for s in subs {
                if let Some(p) = self.parents.get_mut(&s) {
                    p.remove(&g);
                }
            }
        }
        if let Some(d) = def {
            for s in &d.1 {
                self.parents.entry(*s).or_default().insert(g);
            }
            self.defs.insert(g, d);
        }
    }

    /// Derives everything from the definitions: O(sum of each group's reach).
    pub fn rebuild(&mut self) {
        self.of.clear();
        self.closures.clear();
        let gs: Vec<Tid> = self.defs.keys().copied().collect();
        for g in gs {
            self.list(&g, None);
        }
    }
}

impl super::journal::Journaled for Groups {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?} {:?} {:?} {:?}", self.defs, self.parents, self.of, self.closures)
    }
    type Mark = (usize, BTreeSet<Tid>);
    fn commit(&mut self) {
        self.log.clear();
    }
    fn mark(&mut self) -> Self::Mark {
        (self.log.len(), self.moved.clone())
    }
    fn rollback_to(&mut self, (m, moved): Self::Mark) {
        while self.log.len() > m {
            let Some((g, def)) = self.log.pop() else { break };
            self.apply(g, def);
        }
        // a change rolled back is told by no event; the transaction's earlier steps still are
        self.moved = moved;
    }
}



#[cfg(test)]
mod tests {
    use super::Groups;
    use osis_base::Tid;
    use std::collections::{BTreeMap, BTreeSet};

    fn t(n: u8) -> Tid {
        Tid::from_bytes([n; 15])
    }

    /// The reference: every group's reach from scratch.
    fn naive(defs: &BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>) -> BTreeMap<Tid, BTreeSet<Tid>> {
        let mut g = Groups { defs: defs.clone(), ..Default::default() };
        let mut out: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
        for k in defs.keys() {
            for x in g.reach(k).0 {
                out.entry(x).or_default().insert(*k);
            }
        }
        g.rebuild();
        assert_eq!(g.of, out);
        out
    }

    // spec/data-model.md §8: `groups.0` holds every group containing the thing through items and
    // subgroups (cycles allowed); incremental updates equal a recomputation from scratch.
    #[test]
    fn incremental_groups_spec_data_model_8() {
        let mut rng = osis_crypto::SeededRng::from_u64(0);
        let mut g = Groups::default();
        let mut defs = BTreeMap::new();
        for _ in 0..400 {
            let n = |rng: &mut osis_crypto::SeededRng| (osis_crypto::RngCore::next_u32(rng) % 12) as u8;
            let k = t(n(&mut rng));
            let def = if n(&mut rng) < 2 {
                None
            } else {
                let items: BTreeSet<Tid> = (0..n(&mut rng) % 4).map(|_| t(n(&mut rng) + 20)).collect();
                let subs: BTreeSet<Tid> = (0..n(&mut rng) % 3).map(|_| t(n(&mut rng))).collect();
                Some((items, subs))
            };
            match &def {
                Some(d) => defs.insert(k, d.clone()),
                None => defs.remove(&k),
            };
            g.set(k, def);
            assert_eq!(g.of, naive(&defs));
            // spec/sync.md §3: a closure is the group, its subgroups at any depth and their items
            for a in defs.keys() {
                let (mut want, mut seen) = (BTreeSet::new(), BTreeSet::new());
                let mut stack = vec![*a];
                while let Some(x) = stack.pop() {
                    if seen.insert(x) && let Some((items, subs)) = defs.get(&x) {
                        want.extend(items.iter().copied());
                        stack.extend(subs.iter().copied());
                    }
                }
                want.extend(seen);
                assert_eq!(*g.closure(a), want);
                for t in &want {
                    assert!(g.enclosing(t).contains(a));
                }
            }
            for (a, c) in &g.closures {
                assert!(defs.contains_key(a) && c.len() > 1 || g.of.get(a).is_some_and(|s| s.contains(a)));
            }
        }
    }
}
