//! Public pieces over time (spec/sync-set.md §2 Public pieces, First entry; spec/permissions.md §4
//! Key part), a greenfield model beside `closure::public`: what a reader of a unit thing T, served
//! only T's sync ID, needs carried there to read a public thing X, or a dependent D of it, as X
//! rotates and the public is granted and removed. Properties and hand worlds in
//! tests/it/spec_public.rs; findings in notes/public-and-cards-brief.md (Models).
//!
//! X's history is a list of role commits: `Grant` (the public read, with history: its open box at
//! X's current epoch), `Rot` (a rotation: a new epoch, boxing the public open while its grant is
//! set), `Remove` (the public's removal with its rotation). T strongs either X or D (X's
//! dependent); the public reads X while its newest grant commit is a `Grant`. Under T's sync ID go
//! X's role commits as bodies when X is in T's unit (each opens with the epoch it is sectioned
//! under, the one before the epoch it gives: spec/crypto.md §5 Who wraps under what), and the
//! public pieces as certificate copies (sectioned under their blob key: they open for every T
//! reader). Holding an epoch's secret gives every earlier one (history boxes; floors aside).
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ev {
    Grant,
    Rot,
    Remove,
}

/// What T's public pieces on X are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pieces {
    /// The public's edge piece (spec/permissions.md §4 Key part): the commits writing its grant,
    /// a removal among them, and each role commit boxing it once the grant is set.
    Edge,
    /// Only the commits writing the public's grant (a removal among them): the role commits
    /// boxing it at later epochs are left out (control).
    GrantOnly,
    /// The edge piece, carried only while the public reads X (control: a removal is not carried).
    WhileRead,
}

#[derive(Clone, Debug)]
pub struct World {
    pub evs: Vec<Ev>,
    /// T's strong reaches D (X's dependent), else X itself.
    pub to_dep: bool,
}

/// A role commit of X: its index, the epoch it gives or boxes at, and whether it boxes the public.
struct Rc {
    i: usize,
    epoch: usize,
    boxes_public: bool,
    /// The epoch its X section is under: the one before the epoch it gives or boxes, the first
    /// epoch's own for a commit at it (spec/crypto.md §5 Who wraps under what).
    under: usize,
}

impl World {
    /// X's role commits after the first `k` events.
    fn commits(&self, k: usize) -> Vec<Rc> {
        let (mut epoch, mut public) = (0, false);
        let mut out = Vec::new();
        for (i, &e) in self.evs[..k].iter().enumerate() {
            match e {
                Ev::Grant => public = true,
                Ev::Rot => epoch += 1,
                Ev::Remove => {
                    public = false;
                    epoch += 1;
                }
            }
            out.push(Rc { i, epoch, boxes_public: public, under: epoch.saturating_sub(1) });
        }
        out
    }

    /// Whether the public reads X after `k` events, and X's current epoch.
    pub fn state(&self, k: usize) -> (bool, usize) {
        let c = self.commits(k);
        let public = self.evs[..k].iter().rev().find(|e| **e != Ev::Rot).is_some_and(|e| *e == Ev::Grant);
        (public, c.last().map_or(0, |r| r.epoch))
    }

    /// The pieces T's sync ID carries after `k` events (indices of X's role commits).
    fn pieces(&self, rule: Pieces, k: usize) -> BTreeSet<usize> {
        let (public, _) = self.state(k);
        if rule == Pieces::WhileRead && !public {
            return BTreeSet::new();
        }
        let mut set = false;
        let mut out = BTreeSet::new();
        for (i, &e) in self.evs[..k].iter().enumerate() {
            let take = match e {
                Ev::Grant | Ev::Remove => true,
                Ev::Rot => set && rule != Pieces::GrantOnly,
            };
            if take {
                out.insert(i);
            }
            set = match e {
                Ev::Grant => true,
                Ev::Remove => false,
                Ev::Rot => set,
            };
        }
        out
    }

    /// A reader of T served T's sync ID at each step up to `k`, keeping every copy it was served
    /// (copies are held, never unlearned): whether it counts X public, and the newest epoch of X
    /// it holds the secret of.
    pub fn reader(&self, rule: Pieces, k: usize) -> (bool, Option<usize>) {
        let mut copies = BTreeSet::new();
        for j in 0..=k {
            copies.extend(self.pieces(rule, j));
        }
        let commits = self.commits(k);
        // whether the public reads X, by the newest grant commit among the copies
        let public = copies.iter().rev().map(|&i| self.evs[i]).find(|e| *e != Ev::Rot).is_some_and(|e| e == Ev::Grant);
        // X's bodies are under T's sync ID while X is in T's unit (T strongs X, the public reads it)
        let bodies = !self.to_dep && public;
        let mut held: Option<usize> = None;
        loop {
            let before = held;
            for c in &commits {
                if !c.boxes_public {
                    continue;
                }
                let copy = copies.contains(&c.i);
                let body = bodies && held.is_some_and(|h| h >= c.under);
                if copy || body {
                    held = Some(held.map_or(c.epoch, |h| h.max(c.epoch)));
                }
            }
            if held == before {
                return (public, held);
            }
        }
    }

    /// `agree`: the reader counts X public exactly when it is; `reads`: where it is, the reader
    /// holds X's current epoch (it opens what is written to X, or D, now).
    pub fn breaks(&self, rule: Pieces) -> (bool, bool) {
        let (mut agree, mut reads) = (false, false);
        for k in 0..=self.evs.len() {
            let (public, epoch) = self.state(k);
            let (seen, held) = self.reader(rule, k);
            agree |= seen != public;
            reads |= public && held != Some(epoch);
        }
        (agree, reads)
    }
}

/// Every history of up to `n` events, T strongs X or D.
pub fn all(n: usize) -> Vec<World> {
    let mut out = vec![];
    let mut hs: Vec<Vec<Ev>> = vec![vec![]];
    for _ in 0..n {
        let next: Vec<Vec<Ev>> = hs.iter().flat_map(|h| [Ev::Grant, Ev::Rot, Ev::Remove].map(|e| [h.clone(), vec![e]].concat())).collect();
        hs.extend(next.clone());
        hs = hs.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
    }
    for evs in hs {
        for to_dep in [false, true] {
            out.push(World { evs: evs.clone(), to_dep });
        }
    }
    out
}
