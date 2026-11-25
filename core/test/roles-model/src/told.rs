//! A removed node learns its removal (spec/sync-opens.md §4 Departed, §6; spec/sync-streams.md §4;
//! spec/crypto.md §5 Who wraps under what, taking): a reader judging a peer departed opens the
//! thing's sync ID toward it only ended, on any read secret it holds of an epoch superseded here,
//! and serves it the thing's role entries alone up to the first-logged position of the commit
//! taking its read under its **taking epoch** (the newest epoch held here among those what gave it
//! read boxed it), and the entries telling its departure: that entry, and the record blob under
//! that epoch carrying the records judging the commit needs. With no such entry here nothing opens.
//!
//! The world: thing A with nodes N0 and N1 (admins: each removes, rotates and re-seals), N2 (a
//! member from the start), N3 (paired by N0: a grant boxing it every epoch N0 holds, its record
//! minted then), and X, a stranger. N0 to N2 hold epoch 0 and each other's records; N3 knows N0's
//! and its own. Events: syncs of two nodes (each side logs what it holds and serves the other what
//! it judges it may hold, repeated until nothing moves), N0 and N1 hearing each other's role commits
//! by another route (their account's sync ID: nothing logged under A), N1 or N2 writing content,
//! N0 or N1 rotating (boxing every member it judges one), N0 pairing N3, a node's reset (gone: no
//! designated device), and one removal of N2 or N3 by N0 or N1. A remover holding the removed
//! node's grant knows the departure: its removal rotates, boxing the node nothing (a **knowing**
//! removal, wrapped under an epoch it supersedes). One that does not hold it (N3's pairing unseen)
//! removes **blind**: a plain role commit, logged under the newest epoch, and nodes judging the
//! departure later rotate before they encrypt. A node judging a member's departure, whose current
//! epoch does not cover it, rotates at once if an admin; a node that may not rotate writes no
//! content until it holds a covering epoch. Role commits and record blobs are logged whatever the
//! departure (certificates). A record blob is logged by each node holding a role commit: the
//! general one carrying the signers' records, and, at a node judging the departure, one under the
//! removal's taking epoch carrying the remover's record, each competing only within its epoch's
//! class. Of two entries of one commit a node opens, it keeps the one under the removal's taking
//! epoch, else the newer (a spare by blob ID may go either way). A node judging its own removal
//! (the removal held and its signer's record known) erases A.
//!
//! Rules (`ToldRules`): `spec`, and controls `close` (a departed peer is opened nothing), `fire`
//! (closed, and the remover alone tells the node by meeting it), `newest` (only the newest
//! superseded epoch is shown), `full` (served content too), `late` (served up to the log end),
//! `untold` (no taking epoch: the removal logged under the newest epoch, records only in the
//! general blob), `uncovering` (the taking epoch is the newest held covering no departure, not the
//! epoch boxed to it by what gave it read), `boxed` (the newest held epoch boxed to it), `range` (`until` grows to the told entries' positions and
//! serves every role entry up to it), `rotation-until` (`until` the first rotation superseding the
//! shown epoch, not the removal's taking entry), `spare` (of two entries of the removal, the newer kept, its
//! taking epoch's or not), `no-record` (no record blob under the taking epoch), `hack`
//! (no departure record blob; the general one sealed under the taking epoch). Properties:
//! - `told`: the removed node learns its removal from any member that judges it departed and
//!   holds an epoch it holds superseded, the remover gone or not;
//! - `notice`: of what a node judging it departed serves it, nothing it opens is content, a role
//!   commit made by a node that had judged the removal (but the removal and a rotation superseding
//!   an epoch it holds), or a record minted so (but the remover's).

use crate::Findings;
use std::collections::BTreeSet;

pub const N0: usize = 0;
pub const N1: usize = 1;
pub const N2: usize = 2;
pub const N3: usize = 3;
pub const X: usize = 4;
pub const NODES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Ev {
    Sync(usize, usize),
    Write(usize),
    Rotate(usize),
    Pair,
    Hear,
    Reset(usize),
    /// Remover, removed.
    Remove(usize, usize),
    Skip,
}

#[derive(Clone, Debug)]
pub struct ToldWorld {
    pub evs: Vec<Ev>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ToldRules {
    Spec,
    Close,
    Fire,
    Newest,
    Full,
    Late,
    Untold,
    Uncovering,
    Boxed,
    Range,
    RotationUntil,
    Spare,
    NoRecord,
    Hack,
}

impl ToldRules {
    pub fn named(mode: &str) -> Option<ToldRules> {
        let rest = mode.strip_prefix("told").unwrap_or(mode);
        Some(match rest.strip_prefix("-exh").unwrap_or(rest) {
            "" => ToldRules::Spec,
            "-close" => ToldRules::Close,
            "-fire" => ToldRules::Fire,
            "-newest" => ToldRules::Newest,
            "-full" => ToldRules::Full,
            "-late" => ToldRules::Late,
            "-untold" => ToldRules::Untold,
            "-uncovering" => ToldRules::Uncovering,
            "-boxed" => ToldRules::Boxed,
            "-range" => ToldRules::Range,
            "-rotation-until" => ToldRules::RotationUntil,
            "-spare" => ToldRules::Spare,
            "-no-record" => ToldRules::NoRecord,
            "-hack" => ToldRules::Hack,
            _ => return None,
        })
    }
    /// The removal goes under its taking epoch at a node judging the departure.
    fn taking(self) -> bool {
        self != ToldRules::Untold
    }
    /// A record blob of the remover's record goes under the taking epoch.
    fn departure_records(self) -> bool {
        !matches!(self, ToldRules::Untold | ToldRules::NoRecord | ToldRules::Hack)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Rot,
    Pair,
    Reseal,
    Remove,
    Write,
    Records,
}

#[derive(Clone, Debug)]
struct Commit {
    kind: Kind,
    signer: usize,
    /// The epoch a rotation (a knowing removal among them) makes.
    makes: Option<usize>,
    /// (node, epoch) boxes it gives.
    boxes: Vec<(usize, usize)>,
    /// The epochs a rotation supersedes: those current at its rotator.
    supersedes: Vec<usize>,
    /// A rotation made knowing the removal.
    covers: bool,
    /// A record blob's records.
    records: Vec<usize>,
    /// Made by a node that had judged the removal.
    knew: bool,
}

impl Commit {
    fn role(&self) -> bool {
        self.kind != Kind::Write
    }
}

#[derive(Clone, Debug, Default)]
struct Node {
    /// Commits held: made, heard, or opened from a log entry.
    known: BTreeSet<usize>,
    /// Entries of A in the order first logged: (commit, epoch wrapped under), opened or not.
    log: Vec<(usize, usize)>,
    recs: [bool; NODES],
    gone: bool,
    erased: bool,
}

struct State {
    r: ToldRules,
    commits: Vec<Commit>,
    /// Per epoch above 0, the commit making it.
    maker: Vec<usize>,
    n: [Node; NODES],
    /// (commit, remover, removed).
    removal: Option<(usize, usize, usize)>,
    pair: Option<usize>,
    /// Records minted by a node that had judged the removal.
    late: [bool; NODES],
}

impl State {
    fn new(r: ToldRules) -> State {
        let mut n: [Node; NODES] = Default::default();
        for i in [N0, N1, N2] {
            for k in [N0, N1, N2] {
                n[i].recs[k] = true;
            }
        }
        State { r, commits: vec![], maker: vec![usize::MAX], n, removal: None, pair: None, late: [false; NODES] }
    }
    fn epoch_commit(&self, e: usize) -> Option<&Commit> {
        (e > 0).then(|| &self.commits[self.maker[e]])
    }
    fn covers(&self, e: usize) -> bool {
        self.epoch_commit(e).is_some_and(|c| c.covers)
    }
    fn held(&self, a: usize) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        if a <= N2 {
            out.insert(0);
        }
        for &c in &self.n[a].known {
            for &(h, e) in &self.commits[c].boxes {
                if h == a {
                    out.insert(e);
                }
            }
        }
        out
    }
    fn superseded_at(&self, a: usize, e: usize) -> bool {
        self.n[a].known.iter().any(|&c| self.commits[c].supersedes.contains(&e))
    }
    fn current(&self, a: usize) -> Vec<usize> {
        self.held(a).into_iter().filter(|&e| !self.superseded_at(a, e)).collect()
    }
    /// Whether `a` holds a box of epoch `e` to `h`.
    fn boxed_to(&self, a: usize, h: usize, e: usize) -> bool {
        (e == 0 && h <= N2) || self.n[a].known.iter().any(|&c| self.commits[c].boxes.contains(&(h, e)))
    }
    fn judges_member(&self, a: usize, b: usize) -> bool {
        b <= N2 || (b == N3 && self.pair.is_some_and(|p| self.n[a].known.contains(&p)))
    }
    fn applied(&self, a: usize) -> bool {
        self.removal.is_some_and(|(c, by, _)| self.n[a].known.contains(&c) && self.n[a].recs[by])
    }
    fn departed_at(&self, a: usize, b: usize) -> bool {
        self.removal.is_some_and(|(_, _, who)| who == b) && self.applied(a) && self.judges_member(a, b)
    }
    /// The removed node, where `a` judges its departure.
    fn departure(&self, a: usize) -> Option<usize> {
        let (_, _, who) = self.removal?;
        self.departed_at(a, who).then_some(who)
    }
    fn member(&self, a: usize) -> bool {
        let n = &self.n[a];
        !n.gone && !n.erased && a != X && (a != N3 || self.judges_member(N3, N3))
    }
    fn admin(a: usize) -> bool {
        a == N0 || a == N1
    }
    /// The removal's taking epoch at `a`: the newest epoch held there boxed to the departed node
    /// (`uncovering`: covering no departure).
    fn taking_epoch(&self, a: usize) -> Option<usize> {
        let who = self.departure(a)?;
        if !self.r.taking() {
            return None;
        }
        let held = self.held(a);
        match self.r {
            ToldRules::Uncovering => held.into_iter().rev().find(|&e| !self.covers(e)),
            ToldRules::Boxed => held.into_iter().rev().find(|&e| self.boxed_to(a, who, e)),
            // what gave it read boxed it: N2's start, N3's pairing
            _ => {
                let given: BTreeSet<usize> = match self.pair {
                    Some(p) if who == N3 => self.commits[p].boxes.iter().map(|b| b.1).collect(),
                    _ => [0].into(),
                };
                held.into_iter().rev().find(|e| given.contains(e))
            }
        }
    }
    /// The epoch `a` logs commit `c` under now (`None`: not now).
    fn log_epoch(&self, a: usize, c: usize) -> Option<usize> {
        let x = &self.commits[c];
        if self.removal.is_some_and(|(r, _, _)| r == c) {
            if let Some(e) = self.taking_epoch(a) {
                return Some(e);
            }
        }
        // a commit giving epochs: under the newest held one they supersede
        let given: Vec<usize> = x.boxes.iter().map(|b| b.1).filter(|&e| e > 0).collect();
        if !given.is_empty() {
            let mut sup: BTreeSet<usize> = x.supersedes.iter().copied().collect();
            for &g in &given {
                sup.extend(self.epoch_commit(g).map(|m| m.supersedes.clone()).unwrap_or_default());
            }
            let held = self.held(a);
            return sup.into_iter().rev().find(|e| held.contains(e));
        }
        let newest = self.current(a).last().copied()?;
        if x.kind == Kind::Write && self.departure(a).is_some() && !self.covers(newest) {
            return None;
        }
        Some(newest)
    }
    fn add(&mut self, a: usize, mut c: Commit) -> usize {
        c.knew = self.applied(a);
        if let Some(e) = c.makes {
            debug_assert_eq!(e, self.maker.len());
            self.maker.push(self.commits.len());
        }
        self.commits.push(c);
        let i = self.commits.len() - 1;
        self.n[a].known.insert(i);
        i
    }
    fn next_epoch(&self) -> usize {
        self.maker.len()
    }
    /// A rotation by `a`, boxing every member it judges one but a departed one.
    fn rotate(&mut self, a: usize, kind: Kind) -> usize {
        let e = self.next_epoch();
        let gone = self.departure(a);
        let boxes = (0..NODES).filter(|&m| m != X && self.judges_member(a, m) && Some(m) != gone).map(|m| (m, e)).collect();
        let c = Commit { kind, signer: a, makes: Some(e), boxes, supersedes: self.current(a), covers: gone.is_some(), records: vec![], knew: false };
        self.add(a, c)
    }
    /// Opens what `a` can of its log; a removed node judging its removal erases A.
    fn absorb(&mut self, a: usize) {
        loop {
            let held = self.held(a);
            let mut moved = false;
            for i in 0..self.n[a].log.len() {
                let (c, e) = self.n[a].log[i];
                if held.contains(&e) && self.n[a].known.insert(c) {
                    moved = true;
                }
                if held.contains(&e) && self.commits[c].kind == Kind::Records {
                    for k in self.commits[c].records.clone() {
                        moved |= !self.n[a].recs[k];
                        self.n[a].recs[k] = true;
                    }
                }
            }
            if !moved {
                break;
            }
        }
        if self.removal.is_some_and(|(_, _, who)| who == a) && self.applied(a) {
            self.n[a].erased = true;
            self.n[a].log.clear();
        }
    }
    fn opens(&self, a: usize, e: usize) -> bool {
        self.held(a).contains(&e)
    }
    /// Records `a`'s general record blob carries: the signers of the role commits it holds, N3's
    /// once paired, of those it knows.
    fn general_records(&self, a: usize) -> Vec<usize> {
        let mut s: BTreeSet<usize> = self.n[a].known.iter().map(|&c| &self.commits[c]).filter(|c| c.role() && c.kind != Kind::Records).map(|c| c.signer).collect();
        if self.pair.is_some_and(|p| self.n[a].known.contains(&p)) {
            s.insert(N3);
        }
        s.into_iter().filter(|&k| self.n[a].recs[k]).collect()
    }
    /// The records the class of a record blob under `e` needs at `a`: the remover's under the
    /// taking epoch, else the general set.
    fn class_needs(&self, a: usize, e: usize) -> Vec<usize> {
        match self.removal {
            Some((_, by, _)) if self.r.departure_records() && self.taking_epoch(a) == Some(e) => vec![by].into_iter().filter(|&k| self.n[a].recs[k]).collect(),
            _ => self.general_records(a),
        }
    }
    /// One settling step at `a`: rotate, re-seal, log, drop spares and lost record blobs.
    fn settle_once(&mut self, a: usize) -> bool {
        self.absorb(a);
        if !self.member(a) {
            return false;
        }
        let before = (self.commits.len(), self.n[a].log.clone());
        if State::admin(a) && self.departure(a).is_some() && self.current(a).iter().any(|&e| !self.covers(e)) {
            self.rotate(a, Kind::Rot);
        }
        if State::admin(a) && self.current(a).iter().all(|&e| self.departure(a).is_none() || self.covers(e)) {
            let gone = self.departure(a);
            for m in [N0, N1, N2, N3] {
                if m == a || !self.judges_member(a, m) || Some(m) == gone {
                    continue;
                }
                for e in self.current(a) {
                    if !self.boxed_to(a, m, e) {
                        self.add(a, Commit { kind: Kind::Reseal, signer: a, makes: None, boxes: vec![(m, e)], supersedes: vec![], covers: false, records: vec![], knew: false });
                    }
                }
            }
        }
        // log what it holds
        let known: Vec<usize> = self.n[a].known.iter().copied().collect();
        for c in known {
            let x = &self.commits[c];
            if x.kind == Kind::Records || (x.kind == Kind::Write && x.signer != a) {
                continue;
            }
            let Some(e) = self.log_epoch(a, c) else { continue };
            let has = self.n[a].log.iter().any(|&(y, f)| y == c && self.opens(a, f) && (f == e || Some(c) != self.removal.map(|r| r.0) || self.taking_epoch(a).is_none()));
            if !has {
                self.n[a].log.push((c, e));
            }
        }
        // spares: of two opened entries of a commit, the one under the taking epoch, else the newer
        let taking = self.taking_epoch(a);
        let mut keep = vec![];
        for &(c, e) in &self.n[a].log {
            if self.commits[c].kind == Kind::Records || !self.opens(a, e) {
                keep.push(true);
                continue;
            }
            let rank = |f: usize| (self.r != ToldRules::Spare && Some(f) == taking && self.removal.is_some_and(|r| r.0 == c), f);
            let best = self.n[a].log.iter().filter(|&&(y, f)| y == c && self.opens(a, f)).map(|&(_, f)| rank(f)).max().unwrap();
            keep.push(rank(e) == best);
        }
        let mut it = keep.into_iter();
        let mut seen = BTreeSet::new();
        self.n[a].log.retain(|&(c, e)| it.next().unwrap() && (self.commits[c].kind == Kind::Records || seen.insert((c, e))));
        // record blobs: per class (the epoch it opens under), one carrying what the class needs
        let mut classes = vec![];
        if let Some(e) = self.current(a).last().copied() {
            let e = if self.r == ToldRules::Hack { taking.unwrap_or(e) } else { e };
            classes.push(e);
        }
        if let (true, Some(e)) = (self.r.departure_records(), taking) {
            classes.push(e);
        }
        for e in classes {
            let need = self.class_needs(a, e);
            if need.is_empty() {
                continue;
            }
            let has = self.n[a].log.iter().any(|&(c, f)| f == e && self.commits[c].kind == Kind::Records && self.commits[c].records == need);
            if !has {
                let c = self.add(a, Commit { kind: Kind::Records, signer: a, makes: None, boxes: vec![], supersedes: vec![], covers: false, records: need, knew: false });
                self.n[a].log.push((c, e));
            }
        }
        // of two record blobs of a class, the one carrying what it needs with fewer others wins
        let log = self.n[a].log.clone();
        let keep: Vec<bool> = log.iter().map(|&(c, e)| {
            if self.commits[c].kind != Kind::Records || !self.opens(a, e) {
                return true;
            }
            let need = self.class_needs(a, e);
            let score = |c: usize| {
                let r = &self.commits[c].records;
                (need.iter().filter(|k| r.contains(k)).count(), std::cmp::Reverse(r.len()), std::cmp::Reverse(c))
            };
            log.iter().filter(|&&(y, f)| f == e && self.commits[y].kind == Kind::Records).all(|&(y, _)| score(y) <= score(c))
        }).collect();
        let mut it = keep.into_iter();
        self.n[a].log.retain(|_| it.next().unwrap());
        before != (self.commits.len(), self.n[a].log.clone())
    }
    fn settle(&mut self, a: usize) {
        for _ in 0..64 {
            if !self.settle_once(a) {
                return;
            }
        }
        panic!("settle did not converge");
    }
    fn take(&mut self, b: usize, es: &[(usize, usize)]) {
        for &x in es {
            if !self.n[b].log.contains(&x) {
                self.n[b].log.push(x);
            }
        }
    }
}

pub type ToldStats = Findings<ToldWorld>;

pub fn told_check(w: &ToldWorld, r: ToldRules, st: &mut ToldStats) {
    if w.evs.iter().filter(|e| matches!(e, Ev::Remove(..))).count() != 1 {
        return;
    }
    let mut s = State::new(r);
    let mut fails = vec![];
    let mut could = false;
    for &ev in &w.evs {
        match ev {
            Ev::Skip => {}
            Ev::Reset(n) => s.n[n].gone = true,
            Ev::Write(n) => {
                if s.member(n) {
                    let c = s.add(n, Commit { kind: Kind::Write, signer: n, makes: None, boxes: vec![], supersedes: vec![], covers: false, records: vec![], knew: false });
                    match s.log_epoch(n, c) {
                        Some(e) => s.n[n].log.push((c, e)),
                        None => {
                            s.n[n].known.remove(&c);
                        }
                    }
                    s.settle(n);
                }
            }
            Ev::Rotate(n) => {
                if s.member(n) {
                    s.rotate(n, Kind::Rot);
                    s.settle(n);
                }
            }
            Ev::Pair => {
                if s.n[N0].gone || s.pair.is_some() {
                    continue;
                }
                let boxes = s.held(N0).into_iter().map(|e| (N3, e)).collect();
                let p = s.add(N0, Commit { kind: Kind::Pair, signer: N0, makes: None, boxes, supersedes: vec![], covers: false, records: vec![], knew: false });
                s.pair = Some(p);
                s.late[N3] = s.commits[p].knew;
                s.settle(N0);
                s.n[N3].known.insert(p);
                s.n[N3].recs[N0] = true;
                s.n[N3].recs[N3] = true;
                let all = s.n[N0].log.clone();
                s.take(N3, &all);
                s.settle(N3);
            }
            Ev::Hear => {
                if s.n[N0].gone || s.n[N1].gone {
                    continue;
                }
                let role: BTreeSet<usize> = s.n[N0].known.union(&s.n[N1].known).copied().filter(|&c| s.commits[c].role() && s.commits[c].kind != Kind::Records).collect();
                for a in [N0, N1] {
                    s.n[a].known.extend(role.iter().copied());
                    for k in 0..NODES {
                        s.n[a].recs[k] = s.n[N0].recs[k] || s.n[N1].recs[k];
                    }
                }
                s.settle(N0);
                s.settle(N1);
            }
            Ev::Remove(by, who) => {
                if s.n[by].gone || (who == N3 && s.pair.is_none()) {
                    return;
                }
                let knowing = s.judges_member(by, who);
                let c = if knowing {
                    // its rotation boxes the removed node nothing
                    let e = s.next_epoch();
                    let boxes = (0..NODES).filter(|&m| m != X && m != who && s.judges_member(by, m)).map(|m| (m, e)).collect();
                    let c = Commit { kind: Kind::Remove, signer: by, makes: Some(e), boxes, supersedes: s.current(by), covers: true, records: vec![], knew: false };
                    s.add(by, c)
                } else {
                    s.add(by, Commit { kind: Kind::Remove, signer: by, makes: None, boxes: vec![], supersedes: vec![], covers: false, records: vec![], knew: false })
                };
                s.removal = Some((c, by, who));
                st.count(if knowing { "knowing" } else { "blind" }, 1);
                s.settle(by);
            }
            Ev::Sync(u, v) => {
                let who = s.removal.map(|r| r.2);
                for (a, b) in [(u, v), (v, u)] {
                    if Some(b) == who && s.member(a) && s.member(b) && s.departed_at(a, b) && shown(&s, a, b, false).is_some() {
                        could = true;
                    }
                }
                loop {
                    let before: Vec<_> = s.n.iter().map(|n| (n.log.clone(), n.erased)).collect();
                    for (a, b) in [(u, v), (v, u)] {
                        s.settle(a);
                        serve(&mut s, a, b, &mut fails);
                        s.settle(b);
                    }
                    if before == s.n.iter().map(|n| (n.log.clone(), n.erased)).collect::<Vec<_>>() {
                        break;
                    }
                }
            }
        }
    }
    if s.removal.is_none() {
        return;
    }
    st.worlds += 1;
    let who = s.removal.unwrap().2;
    if could && !s.n[who].erased {
        fails.push(format!("told: N{who} synced with a member judging it departed and did not learn its removal"));
    }
    st.failed(fails, w);
}

/// The epoch removed node `b`'s Hit opens at `a`: the newest it holds that `a` holds superseded
/// (`newest`: only `a`'s newest superseded epoch is shown).
fn shown(s: &State, a: usize, b: usize, newest: bool) -> Option<usize> {
    let sup: Vec<usize> = s.held(a).into_iter().filter(|&e| s.superseded_at(a, e)).collect();
    let sup: Vec<usize> = if newest { sup.last().into_iter().copied().collect() } else { sup };
    let mine = s.held(b);
    sup.into_iter().rev().find(|e| mine.contains(e))
}

/// Server `a` serves node `b` what it judges `b` may hold, where `b` opens toward `a`.
fn serve(s: &mut State, a: usize, b: usize, fails: &mut Vec<String>) {
    if !s.member(a) || !s.member(b) {
        return;
    }
    let departed = s.departed_at(a, b);
    if s.judges_member(a, b) && !departed {
        let all = s.n[a].log.clone();
        s.take(b, &all);
        return;
    }
    if !departed {
        return;
    }
    let (rc, by, _) = s.removal.unwrap();
    let log = s.n[a].log.clone();
    let taking = s.taking_epoch(a);
    // the entries telling b its departure: the removal under its taking epoch, the record blob
    // under it
    let tells = |s: &State, (c, e): (usize, usize)| (c == rc && Some(e) == taking) || (s.commits[c].kind == Kind::Records && Some(e) == taking && s.r.departure_records());
    let served: Vec<(usize, usize)> = match s.r {
        ToldRules::Close => vec![],
        ToldRules::Fire => {
            if a == by { log.iter().copied().filter(|x| x.0 == rc).collect() } else { vec![] }
        }
        r => {
            let Some(e) = shown(s, a, b, r == ToldRules::Newest) else { return };
            let first = log.iter().position(|&(c, _)| s.commits[c].supersedes.contains(&e));
            // until: the first-logged position here of the removal under its taking epoch (none
            // logged: nothing opens); the first rotation superseding the shown epoch where the
            // rule has no taking epoch (and `range`, `hack`, `rotation-until`); the log's end
            // (`late`)
            let mut until = match r {
                ToldRules::Late => log.len().checked_sub(1),
                ToldRules::Untold | ToldRules::Range | ToldRules::Hack | ToldRules::RotationUntil => first.or(log.len().checked_sub(1)),
                _ => match log.iter().position(|&(c, f)| c == rc && Some(f) == taking) {
                    Some(p) => Some(p),
                    None => return,
                },
            };
            if r == ToldRules::Range || r == ToldRules::Hack {
                // until grows to the told entries (the hack: the record blob under the taking epoch)
                let told = log.iter().enumerate().filter(|&(_, &x)| tells(s, x) || (r == ToldRules::Hack && s.commits[x.0].kind == Kind::Records && Some(x.1) == taking)).map(|(i, _)| i).max();
                until = until.max(told);
            }
            let Some(until) = until else { return };
            let spec = !matches!(r, ToldRules::Range | ToldRules::Hack);
            log.iter().enumerate().filter(|&(i, &(c, e))| (i <= until && (r == ToldRules::Full || r == ToldRules::Late || s.commits[c].role())) || (spec && tells(s, (c, e)))).map(|(_, &x)| x).collect()
        }
    };
    // what b gains: a commit made knowing its removal that it opens and did not hold, a record
    // minted so, content
    let mine = s.held(b);
    for &(c, e) in &served {
        let x = &s.commits[c];
        if !mine.contains(&e) {
            continue;
        }
        let gain = match x.kind {
            Kind::Write => Some("content"),
            Kind::Records => x.records.iter().any(|&k| s.late[k] && k != by && !s.n[b].recs[k]).then_some("a record minted knowing its removal"),
            _ => {
                let telling = c == rc || x.supersedes.iter().any(|e| mine.contains(e));
                (x.knew && !telling && !s.n[b].known.contains(&c)).then_some("a role commit made knowing its removal")
            }
        };
        if let Some(g) = gain {
            fails.push(format!("notice: node {a}, judging N{b} departed, served it {g}: {x:?} under {e}"));
        }
    }
    s.take(b, &served);
}

/// Events a slot draws from: syncs of every pair, writes by N1 and N2, rotations by N0 and N1, a
/// pairing, hearing, the admins' resets, nothing.
pub fn alphabet() -> Vec<Ev> {
    let mut out = vec![];
    for u in 0..NODES {
        for v in u + 1..NODES {
            out.push(Ev::Sync(u, v));
        }
    }
    out.extend([Ev::Write(N1), Ev::Write(N2), Ev::Rotate(N0), Ev::Rotate(N1), Ev::Pair, Ev::Hear, Ev::Reset(N0), Ev::Reset(N1), Ev::Skip]);
    out
}

pub const SLOTS: usize = 5;
pub const REMOVALS: [(usize, usize); 4] = [(N0, N2), (N1, N2), (N0, N3), (N1, N3)];

/// The family's size: every event in each of `SLOTS` slots, and each removal before any of them or
/// after the last.
pub fn family_size() -> usize {
    alphabet().len().pow(SLOTS as u32) * (SLOTS + 1) * REMOVALS.len()
}

pub fn told_family(mut k: usize) -> ToldWorld {
    let al = alphabet();
    let (by, who) = REMOVALS[k % REMOVALS.len()];
    k /= REMOVALS.len();
    let at = k % (SLOTS + 1);
    k /= SLOTS + 1;
    let mut evs = vec![];
    for i in 0..SLOTS {
        if i == at {
            evs.push(Ev::Remove(by, who));
        }
        evs.push(al[k % al.len()]);
        k /= al.len();
    }
    if at == SLOTS {
        evs.push(Ev::Remove(by, who));
    }
    ToldWorld { evs }
}

pub fn told_run(samples: u64, mode: &str) -> u64 {
    let Some(r) = ToldRules::named(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    let st: ToldStats = crate::family_on_every_core(family_size(), samples.max(1) as usize, |k, st: &mut ToldStats| told_check(&told_family(k), r, st));
    st.print(mode);
    for (f, w) in &st.fail {
        println!("{f}\n  world: {w:?}");
    }
    st.failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ev::*;

    fn kinds(evs: Vec<Ev>, r: ToldRules) -> Vec<String> {
        let mut st = ToldStats::default();
        told_check(&ToldWorld { evs }, r, &mut st);
        for (f, _) in &st.fail {
            eprintln!("{r:?}: {f}");
        }
        st.kinds.keys().cloned().collect()
    }

    /// N0 removes N2 and is reset; N2 meets N1 alone. Spec: N1 tells it. Closed, or told by the
    /// remover's fire alone, it never learns.
    #[test]
    fn a_removed_node_learns_from_a_member_the_remover_gone() {
        let w = vec![Sync(N0, N1), Remove(N0, N2), Sync(N0, N1), Reset(N0), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w.clone(), ToldRules::Close), ["told"]);
        assert_eq!(kinds(w, ToldRules::Fire), ["told"]);
    }

    /// N2 misses a rotation before its removal: it holds an older epoch than the one the removal
    /// supersedes. Showing every superseded epoch, a member tells it; showing only the newest, it
    /// never learns.
    #[test]
    fn a_removed_node_an_epoch_behind_learns() {
        let w = vec![Rotate(N0), Remove(N0, N2), Sync(N0, N1), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Newest), ["told"]);
    }

    /// N1 writes before and after it holds the removal; N2 is served its role entries up to the
    /// removal alone. Served content, or up to the log's end, it gains more than its notice.
    #[test]
    fn a_removed_node_gains_nothing_but_its_notice() {
        let w = vec![Write(N1), Remove(N0, N2), Sync(N0, N1), Write(N1), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w.clone(), ToldRules::Full), ["notice"]);
        assert_eq!(kinds(w, ToldRules::Late), ["notice"]);
    }

    /// A node paired after the removal tells N2; a stranger opens nothing.
    #[test]
    fn a_node_paired_after_the_removal_tells_and_a_stranger_cannot() {
        assert!(kinds(vec![Remove(N0, N2), Pair, Reset(N0), Sync(N2, X), Sync(N2, N3)], ToldRules::Spec).is_empty());
        assert_eq!(kinds(vec![Remove(N0, N2), Pair, Reset(N0), Sync(N2, N3)], ToldRules::Fire), ["told"]);
    }

    /// N1 removes N3 never having held its pairing, so its removal rotates nothing, and N3 lacks
    /// N1's record; N0 hears of it by another route, rotates, and N1 is reset. N0 tells N3: the
    /// removal under the epoch N3 holds and a record blob of N1's record under it. Logged under the
    /// newest epoch (the rule before), or without the record blob, N3 never learns.
    #[test]
    fn a_blind_removal_tells_the_removed_node() {
        let w = vec![Pair, Remove(N1, N3), Hear, Reset(N1), Sync(N0, N3)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w.clone(), ToldRules::Untold), ["told"]);
        assert_eq!(kinds(w, ToldRules::NoRecord), ["told"]);
    }

    /// As above, N1 having rotated (boxing N3 nothing: it never held the pairing) before its
    /// removal: N0 holds that epoch too, covering nothing. Under the newest epoch covering no
    /// departure N3 cannot open the removal; under the newest boxed to it, it can.
    #[test]
    fn a_blind_removal_after_a_rotation_not_boxing_the_node_tells_it() {
        let w = vec![Pair, Rotate(N1), Remove(N1, N3), Hear, Sync(N0, N3)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Uncovering), ["told"]);
    }

    /// N1 rotates (boxing N3 nothing) and removes N3 blind, logging the removal under its new
    /// epoch; N0 takes that entry, judges the departure and logs the removal under the epoch N3's
    /// pairing boxed it. Keeping the newer entry as spare, N3 opens neither.
    #[test]
    fn the_taking_entry_never_loses_as_spare() {
        let w = vec![Rotate(N1), Pair, Remove(N1, N3), Sync(N0, N1), Sync(N0, N3)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Spare), ["told"]);
    }

    /// N1 removes N2 beside N3's pairing: a commit giving N3 an epoch (the
    /// pairing, a re-seal into the covering rotation) is wrapped under the epoch it supersedes,
    /// which N2 holds, made knowing the removal and logged before the entries
    /// telling N2. Served those entries alone, N2 gains nothing else; `until` grown to them
    /// (`range`, `hack`) serves it the giving commit too.
    #[test]
    fn a_removed_node_is_served_its_telling_entries_alone() {
        let w = vec![Pair, Remove(N1, N2), Sync(N0, N1), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Hack), ["notice"]);
        let w = vec![Sync(N0, N2), Pair, Remove(N1, N2), Hear, Sync(N2, N3), Sync(N0, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Range), ["notice"]);
    }

    /// N0 removes N2 (knowing) and pairs N3, the pairing wrapped under epoch 0, which N2 holds; N1
    /// rotates unaware, boxing N2 its epoch, and N0 takes that rotation. N2's Hit opens on N1's
    /// epoch, whose superseding rotation N0 logs after the pairing: `until` there serves N2 the
    /// pairing, made knowing the removal. Up to the removal's taking entry, nothing
    /// past its judgement.
    #[test]
    fn until_is_the_taking_entry() {
        let w = vec![Remove(N0, N2), Pair, Rotate(N1), Sync(N1, N2), Sync(N0, N1), Sync(N0, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::RotationUntil), ["notice"]);
    }

    /// Every 101st family world (`-- 1 told-exh` runs them all): spec holds; each control fails
    /// its property.
    #[test]
    #[ignore = "property"]
    fn told_family_holds_plain() {
        let run = |r: ToldRules| crate::family_on_every_core(family_size(), 101, |k, st: &mut ToldStats| told_check(&told_family(k), r, st));
        let st = run(ToldRules::Spec);
        assert!(st.worlds > 0 && st.failures == 0, "{:?}", st.fail);
        for (r, kind) in [
            (ToldRules::Close, "told"),
            (ToldRules::Fire, "told"),
            (ToldRules::Newest, "told"),
            (ToldRules::Full, "notice"),
            (ToldRules::Late, "notice"),
            (ToldRules::Untold, "told"),
            (ToldRules::Uncovering, "told"),
            (ToldRules::Boxed, "told"),
            (ToldRules::Range, "notice"),
            (ToldRules::Spare, "told"),
            (ToldRules::NoRecord, "told"),
            (ToldRules::Hack, "notice"),
        ] {
            assert!(run(r).kinds.contains_key(kind), "{r:?}");
        }
    }
}
