//! Public things in a sync unit (spec/sync-set.md §2 T's keys open, Public pieces; spec/permissions.md
//! §1 The public), a greenfield model: whether a unit's logger and its readers agree on the unit when
//! the public's read counts as opening a thing, and what a reader must be carried to know it.
//! Properties and hand worlds in tests/it/spec_public.rs; findings in notes/public-and-cards-brief.md
//! (Models).
//!
//! One unit thing T. Its logger (a writer of T holding every thing) computes T's sync unit and logs
//! under T's sync ID the bodies of each thing of the unit and, under `Rule::pieces`, the public's
//! edge piece on each independent thing a strong of the unit reaches. A reader of T is served only
//! that sync ID (a store keeping T unread): it knows the public's grant on X only from what it reads
//! there, and it knows a grant on X only once it counts X in the unit or holds a piece of it. Its
//! unit is the least fixpoint from knowing nothing (entry founded, spec/sync-set.md §2 First entry).
//!
//! Abstracted: grants among things (T's keys) are known to every node, as their key parts give
//! them; the public's grants and a public thing's grants as holder are known only as above; one
//! world state, no timing.
use super::{unit_with, Kind, Role, Set, World, T};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct Net {
    /// Kinds and grants among things.
    pub w: World,
    /// The public's grant on each independent thing it holds one on.
    pub public: BTreeMap<T, Role>,
    pub strongs: super::Edges,
    /// The unit thing.
    pub t: T,
}

/// `Rule::SPEC` is the spec; the controls each drop or widen one clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// T's keys open what the public reads (off: only what T reads).
    pub clause: bool,
    /// T's unit carries the public's edge pieces on what its strongs reach.
    pub pieces: bool,
    /// The public's read counts through holders it reads (public read on H, H read on X), not only
    /// by its grant on X itself.
    pub chains: bool,
    /// Pieces only on the independent things a strong reaches (on: not on the independent of a
    /// dependent thing a strong reaches).
    pub exact: bool,
}

impl Rule {
    pub const SPEC: Rule = Rule { clause: true, pieces: true, chains: false, exact: false };
}

impl Net {
    /// The independent things the public reads, by the public's grants on `known` things and, with
    /// `chains`, the grants of things it reads on `known` things.
    fn public_reads(&self, rule: Rule, known: &Set) -> Set {
        let mut out: Set = self.public.iter().filter(|&(x, &r)| r >= Role::Read && known.contains(x)).map(|(&x, _)| x).collect();
        if rule.chains {
            loop {
                let more: Set = self.w.grants.iter().filter(|&(&(h, x), &r)| out.contains(&h) && r >= Role::Read && known.contains(&x) && !self.w.keyless.contains(&(h, x))).map(|(&(_, x), _)| x).collect();
                if more.is_subset(&out) {
                    break;
                }
                out.extend(more);
            }
        }
        out
    }

    /// T's sync unit when the public's grants on `known` things are known.
    fn unit_knowing(&self, rule: Rule, known: &Set) -> Set {
        let mut keys = self.w.keys_of(self.t);
        if rule.clause {
            keys.extend(self.public_reads(rule, known));
        }
        unit_with(&self.w, self.t, &keys, &self.strongs)
    }

    fn all(&self) -> Set {
        (0..self.w.kinds.len()).collect()
    }

    /// The unit the logger logs: it knows every grant.
    pub fn logged(&self, rule: Rule) -> Set {
        self.unit_knowing(rule, &self.all())
    }

    /// The independents of the things a strong of `unit` reaches (`exact`: of the independent things
    /// alone, the control).
    pub fn reached(&self, rule: Rule, unit: &Set) -> Set {
        let of = |b: T| match self.w.kinds[b] {
            Kind::Independent => Some(b),
            Kind::Dependent(i) => (!rule.exact).then_some(i),
        };
        self.strongs.iter().filter(|&&(a, _)| unit.contains(&a)).filter_map(|&(_, b)| of(b)).collect()
    }

    /// The things whose public pieces T's sync ID carries.
    pub fn pieces(&self, rule: Rule) -> Set {
        if !rule.pieces {
            return Set::new();
        }
        self.reached(rule, &self.logged(rule)).into_iter().filter(|x| self.public.contains_key(x)).collect()
    }

    /// The unit a reader served only T's sync ID computes: the least fixpoint over what it knows.
    pub fn read(&self, rule: Rule) -> Set {
        let logged = self.logged(rule);
        let pieces = self.pieces(rule);
        let mut known = Set::new();
        loop {
            let unit = self.unit_knowing(rule, &known);
            // a thing's grants are known from its bodies it reads in the unit, or from its piece
            let next: Set = unit.intersection(&logged).copied().chain(pieces.iter().copied()).collect();
            if next == known {
                return unit;
            }
            known = next;
        }
    }

    /// The things the public reads (by its own grant on their independent) that a strong of T's unit
    /// reaches: what every reader of T should be carried.
    pub fn owed(&self, rule: Rule) -> Set {
        let logged = self.logged(rule);
        let public = |b: T| {
            let i = match self.w.kinds[b] {
                Kind::Independent => b,
                Kind::Dependent(i) => i,
            };
            self.public.get(&i).is_some_and(|&r| r >= Role::Read)
        };
        self.strongs.iter().filter(|&&(a, b)| logged.contains(&a) && public(b)).map(|&(_, b)| b).collect()
    }
}

/// A random world: `n` things (0 is T, independent), kinds, grants among independent things, the
/// public's grants and strongs, from `seed`.
pub fn random(seed: u64, n: usize) -> Net {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut next = |m: u64| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s % m
    };
    let mut kinds = vec![Kind::Independent];
    for x in 1..n {
        let k = next(3);
        let ind: Vec<T> = (0..x).filter(|&y| kinds[y] == Kind::Independent).collect();
        kinds.push(if k == 0 { Kind::Dependent(ind[next(ind.len() as u64) as usize]) } else { Kind::Independent });
    }
    let mut net = Net { w: World { kinds, ..World::default() }, ..Net::default() };
    let roles = [Role::Sync, Role::Read];
    for h in 0..n {
        for x in 0..n {
            if h != x && net.w.independent(h) && net.w.independent(x) && next(4) == 0 {
                net.w.grants.insert((h, x), roles[next(2) as usize]);
            }
        }
    }
    for x in 1..n {
        if net.w.independent(x) && next(2) == 0 {
            net.public.insert(x, roles[next(2) as usize]);
        }
    }
    for a in 0..n {
        for b in 0..n {
            if a != b && next(3) == 0 {
                net.strongs.insert((a, b));
            }
        }
    }
    net
}
