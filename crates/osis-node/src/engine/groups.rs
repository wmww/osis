//! `/groups` (spec/data-model.md §8): every group whose items, directly or through subgroups
//! (cycles allowed), contain the thing. Kept incrementally: a `/group` change recomputes only the
//! changed group and the groups above it (O(their reach)), never every group.

use super::Core;
use osis_core::Tid;
use std::collections::{BTreeMap, BTreeSet};

/// The `/group` definitions and what they derive.
#[derive(Clone, Debug, Default)]
pub(crate) struct Groups {
    /// `/group` of each group thing: (items, subgroups).
    pub defs: BTreeMap<Tid, (BTreeSet<Tid>, BTreeSet<Tid>)>,
    /// Subgroup -> groups listing it.
    parents: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Thing -> groups containing it, transitively (`/groups`).
    pub of: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Group -> things it contains, transitively (its closure without itself).
    pub items: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Definitions replaced by the running transaction (`Journaled`).
    log: Vec<(Tid, Option<(BTreeSet<Tid>, BTreeSet<Tid>)>)>,
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

    fn unlist(&mut self, a: &Tid) {
        for x in self.items.remove(a).unwrap_or_default() {
            if let Some(s) = self.of.get_mut(&x) {
                s.remove(a);
                if s.is_empty() {
                    self.of.remove(&x);
                }
            }
        }
    }

    fn list(&mut self, a: &Tid) {
        let r = self.reach(a);
        for x in &r {
            self.of.entry(*x).or_default().insert(*a);
        }
        if !r.is_empty() {
            self.items.insert(*a, r);
        }
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
        for a in &above {
            self.unlist(a);
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
            self.list(a);
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
        self.items.clear();
        let gs: Vec<Tid> = self.defs.keys().copied().collect();
        for g in gs {
            self.list(&g);
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

impl Core {
    /// The things of group `g`'s closure without `g` itself.
    pub(crate) fn group_items(&self, g: &Tid) -> BTreeSet<Tid> {
        self.groups.items.get(g).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::Groups;
    use osis_core::Tid;
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
            assert_eq!(g.items, inv);
        }
    }
}
