//! `/groups` (spec/data-model.md §8): every group whose items, directly or through subgroups
//! (cycles allowed), contain the thing. Kept incrementally: a `/group` change recomputes only the
//! changed group and the groups above it (O(their reach)), never every group.

use osis_base::Tid;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A `/group` definition: (items, subgroups).
pub(crate) type Def = (BTreeSet<Tid>, BTreeSet<Tid>);

/// The `/group` definitions and what they derive.
#[derive(Clone, Debug, Default)]
pub struct Groups {
    /// `/group` of each group thing: (items, subgroups).
    pub defs: BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>,
    /// Subgroup -> groups listing it.
    parents: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Thing -> groups containing it, transitively (`/groups`).
    pub of: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Group -> its closure: itself and the things it contains, transitively (groups that
    /// contain something). The same `Arc` while the closure does not change, so node-sync
    /// reuses what it derived from it (`Arc::ptr_eq`).
    pub closures: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    /// Definitions replaced by the running transaction (`Journaled`).
    log: Vec<(Tid, Option<Def>)>,
}

impl Groups {
    /// Things `g` contains through its definition and its subgroups'.
    fn reach(&self, g: &Tid) -> BTreeSet<Tid> {
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
        out
    }

    /// `g` and every group above it through subgroup lists.
    fn above(&self, g: &Tid) -> BTreeSet<Tid> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![*g];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                stack.extend(self.parents.get(&x).into_iter().flatten().copied());
            }
        }
        seen
    }

    /// Removes `a`'s closure and what derives from it; the closure, if any.
    fn unlist(&mut self, a: &Tid) -> Option<Arc<BTreeSet<Tid>>> {
        let old = self.closures.remove(a)?;
        // `a` itself is in `of[a]` only when `a` reaches itself: removing it is right either way
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
        let r = self.reach(a);
        for x in &r {
            self.of.entry(*x).or_default().insert(*a);
        }
        if !r.is_empty() {
            let mut c = r;
            c.insert(*a);
            let c = match old {
                Some(o) if *o == c => o,
                _ => Arc::new(c),
            };
            self.closures.insert(*a, c);
        }
    }

    /// The closure of `g`: itself and every thing it contains.
    pub fn closure(&self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        self.closures.get(g).cloned().unwrap_or_else(|| Arc::new(BTreeSet::from([*g])))
    }

    /// Sets (or with `None` removes) the definition of group `g` and updates what derives from it.
    pub fn set(&mut self, g: Tid, def: Option<(BTreeSet<Tid>, BTreeSet<Tid>)>) {
        if self.defs.get(&g) == def.as_ref() {
            return;
        }
        self.log.push((g, self.defs.get(&g).cloned()));
        self.apply(g, def);
    }

    fn apply(&mut self, g: Tid, def: Option<(BTreeSet<Tid>, BTreeSet<Tid>)>) {
        let above = self.above(&g);
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
            self.list(a, old.remove(a));
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
    fn commit(&mut self) {
        self.log.clear();
    }
    fn rollback(&mut self) {
        while let Some((g, def)) = self.log.pop() {
            self.apply(g, def);
        }
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
            for x in g.reach(k) {
                out.entry(x).or_default().insert(*k);
            }
        }
        g.rebuild();
        assert_eq!(g.of, out);
        out
    }

    // spec/data-model.md §8: `/groups` holds every group containing the thing through items and
    // subgroups (cycles allowed); incremental updates equal a recomputation from scratch.
    #[test]
    fn incremental_groups_spec_data_model_8() {
        let mut rng = osis_crypto::SeededRng::from_u64(8);
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
            let mut inv: BTreeMap<Tid, BTreeSet<Tid>> = BTreeMap::new();
            for (x, gs) in &g.of {
                for a in gs {
                    inv.entry(*a).or_default().insert(*x);
                }
            }
            for (a, c) in &g.closures {
                let mut want = inv.remove(a).unwrap_or_default();
                want.insert(*a);
                assert_eq!(**c, want);
            }
            assert!(inv.is_empty());
        }
    }
}
