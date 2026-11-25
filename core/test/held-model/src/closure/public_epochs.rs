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

// ---- Who hears the public's grant changes (spec/sync-opens.md §4 the public entry, §6 Ending
// opens; spec/sync-set.md §5 Source) ----
//
// The pieces above assume a logger of T holding X. Nodes that read or hold X only through the
// public have no such logger: they hear X's role commits from X's own sync ID, at a source that
// reads X (here `R`, holding every commit and step) and opens it toward them by some credential.
// A history interleaves X's events with syncs of one party with R:
// - `P` reads X by the public alone: a public link's redeemer (it tests the public entry while it
//   redeems, entering X once it holds the public's grant), or a reader of a unit carrying X (or a
//   dependent of X) by the public's grant (it syncs X's sync ID, served X's role commits): the same
//   party to this model. It releases X, syncing it no more, once it holds a removal of the public.
// - `K` keeps X unread (an account holding sync on X, a strong to it): R opens X toward it by J
//   (sync holder), registers its steps there and serves it every entry, which K reads only under
//   the epochs it holds.
// Every event writes a step (spec/permissions.md §3: a step is due as the public's read starts and
// at each read rotation); it lists the public entry exactly while the public reads X, and its entry
// box for the public (open) holds its epoch. No per-reader record: R knows nothing of P or K but
// what they show.

/// The open rule under test. `Rule::SPEC` is the spec; each control drops or widens one clause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heard {
    /// A reader shows S's public entry while a recorded step lists it, not only its newest: a Hit
    /// on it past the newest step listing it opens a member ended at once (off: only while its
    /// newest step lists it, a control).
    pub lapsed: bool,
    /// A member opened on a lapsed public entry is ended at once, served up to the rotation
    /// superseding the newest listing step's epoch (off: served whole, a control).
    pub ended: bool,
    /// A node reading X by the public tests the public entry while it holds the public's grant,
    /// not only while it redeems (off: a control).
    pub tests: bool,
    /// A node keeping S unread whose head lists the public entry reads S by it, as a redeemer
    /// does (off: a control).
    pub store: bool,
}

impl Heard {
    pub const SPEC: Heard = Heard { lapsed: true, ended: true, tests: true, store: true };
}

/// One step of a history: an event on X, or a sync of one party with R.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    X(Ev),
    SyncP,
    SyncK,
}

/// What a party holds: the commits served it, the newest epoch an entry box gave it, whether it
/// entered X (P: it holds the public's grant) or released it.
#[derive(Clone, Debug, Default)]
pub struct Party {
    pub served: BTreeSet<usize>,
    pub entry: Option<usize>,
    pub entered: bool,
    pub gone: bool,
}

/// Whether some property broke: `agree` (a party still holding X counts it public exactly when it
/// is, after a final sync), `reads` (where public, it holds X's current epoch then), `sealed` (no
/// commit written past the public's removal, while it does not read X, is served to a party that
/// holds no role).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Broke {
    pub agree: bool,
    pub reads: bool,
    pub sealed: bool,
}

impl World {
    /// Whether the step written after the first `k` events lists the public entry, and its epoch.
    fn step(&self, k: usize) -> (bool, usize) {
        self.state(k)
    }

    /// The newest epoch a party holds and whether it counts X public, from the commits served it
    /// it can open (each under the epoch before the one it gives) and its entry boxes.
    pub fn view(&self, p: &Party, k: usize) -> (bool, Option<usize>) {
        let commits = self.commits(k);
        let mut held = p.entry;
        loop {
            let before = held;
            for c in &commits {
                if c.boxes_public && p.served.contains(&c.i) && held.is_some_and(|h| h >= c.under) {
                    held = Some(held.map_or(c.epoch, |h| h.max(c.epoch)));
                }
            }
            if held == before {
                break;
            }
        }
        let open = |c: &Rc| p.served.contains(&c.i) && held.is_some_and(|h| h >= c.under);
        let public = commits.iter().rev().filter(|c| open(c)).map(|c| self.evs[c.i]).find(|e| *e != Ev::Rot).is_some_and(|e| e == Ev::Grant);
        (public, held)
    }

    /// R opens S toward a party testing the public entry after `k` events: `Some(full)` where it
    /// shows it (full: its newest step lists it), the commits it serves.
    fn public_open(&self, rule: Heard, k: usize) -> Option<BTreeSet<usize>> {
        let listing = (0..=k).rev().find(|&j| self.step(j).0)?;
        if listing != k && !rule.lapsed {
            return None;
        }
        if listing == k || !rule.ended {
            return Some((0..k).collect());
        }
        // ended at once: up to the rotation superseding the listing step's epoch (the removal)
        let until = (listing..k).find(|&i| self.evs[i] == Ev::Remove).unwrap_or(k - 1);
        Some((0..=until).collect())
    }

    fn sync_p(&self, rule: Heard, p: &mut Party, k: usize, broke: &mut Broke) {
        if p.gone {
            return;
        }
        let (counts, held) = self.view(p, k);
        let (listed, epoch) = self.step(k);
        let tests_public = !p.entered || (rule.tests && counts);
        let mut served = BTreeSet::new();
        if let Some(s) = self.public_open(rule, k).filter(|_| tests_public) {
            served.extend(s);
            if listed {
                p.entry = p.entry.max(Some(epoch));
            }
        }
        // R shows its current read secret; P tests those it holds
        if held == Some(epoch) {
            served.extend(0..k);
        }
        if !listed {
            let last_remove = (0..k).rev().find(|&i| self.evs[i] == Ev::Remove);
            broke.sealed |= served.iter().any(|&i| last_remove.is_some_and(|r| i > r));
        }
        p.served.extend(served);
        let (counts, _) = self.view(p, k);
        if !p.entered && counts {
            p.entered = true;
        } else if p.entered && !counts {
            p.gone = true;
        }
    }

    fn sync_k(&self, rule: Heard, q: &mut Party, k: usize) {
        // J: a sync holder; R registers its steps (K's head is R's newest) and serves it all
        q.served.extend(0..k);
        let (listed, epoch) = self.step(k);
        if rule.store && listed {
            // K reads S by the public entry its head lists: the answer's entry box
            q.entry = q.entry.max(Some(epoch));
        }
    }

    /// Runs `steps` (events on X among them: `self.evs` is ignored), then a final sync of each
    /// party, and judges the properties.
    pub fn heard(steps: &[Step], rule: Heard) -> Broke {
        let evs: Vec<Ev> = steps.iter().filter_map(|s| if let Step::X(e) = s { Some(*e) } else { None }).collect();
        let w = World { evs, to_dep: false };
        let (mut p, mut q, mut broke, mut k) = (Party::default(), Party::default(), Broke::default(), 0);
        for s in steps.iter().chain(&[Step::SyncP, Step::SyncK]) {
            match s {
                Step::X(_) => k += 1,
                Step::SyncP => w.sync_p(rule, &mut p, k, &mut broke),
                Step::SyncK => w.sync_k(rule, &mut q, k),
            }
        }
        let (public, epoch) = w.state(k);
        for (party, holds) in [(&p, !p.gone), (&q, true)] {
            let (counts, held) = w.view(party, k);
            if holds {
                broke.agree |= counts != public;
                broke.reads |= public && held != Some(epoch);
            }
        }
        broke
    }
}

/// Every history of up to `n` steps.
pub fn histories(n: usize) -> Vec<Vec<Step>> {
    let all = [Step::X(Ev::Grant), Step::X(Ev::Rot), Step::X(Ev::Remove), Step::SyncP, Step::SyncK];
    let mut out: Vec<Vec<Step>> = vec![vec![]];
    let mut last = out.clone();
    for _ in 0..n {
        last = last.iter().flat_map(|h| all.iter().map(|s| [h.clone(), vec![*s]].concat())).collect();
        out.extend(last.iter().cloned());
    }
    out
}
