//! A removed node learns its removal (spec/sync-opens.md §4 Departed, §6; spec/sync-streams.md §4;
//! spec/permissions.md §4 Notices): a reader judging a peer departed opens the
//! thing's sync ID toward it only ended, on any read secret it holds of an epoch superseded here,
//! and serves it the **notices** of the commit taking its read alone, `until` the first-logged
//! one. A notice is one entry carrying that commit with the records judging it needs (the
//! remover's), **sealed to the removed node's own key** and wrapped as any entry: under the
//! logging member's newest current epoch, once that covers the departure (a member that may not
//! rotate logs none until it holds one), one per removal among the entries a member opens. The
//! removed node opens it by its key, a member by its wrap. With no notice here nothing opens.
//!
//! The world: thing A with nodes N0 and N1 (admins: each removes, rotates and re-seals), N2 (a
//! member from the start), N3 (paired by N0: a grant boxing it every epoch N0 holds, its record
//! minted then), X, a stranger, and L, a reader lowered to sync before the world starts: it keeps
//! epoch 0 (as a hostile one would), is boxed nothing, and stores every entry N1 holds when they
//! sync (a store of A). N0 to N2 hold epoch 0 and each other's records; N3 knows N0's
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
//! departure (certificates), the removal as any role commit. A record blob is logged by each node
//! holding a role commit, under its newest epoch, carrying the signers' records. Of two entries of
//! one commit a node opens, it keeps the newer (a spare by blob ID may go either way); a notice is
//! no entry of its commit and competes with none. A node judging its own removal (the removal
//! held and its signer's record known) erases A.
//!
//! Rules (`ToldRules`): `spec`, and controls `fire` (a departed peer is opened nothing, and the
//! remover alone tells the node by meeting it), `newest` (only the newest superseded epoch is
//! shown), `full` (served content too, up to the notice), `untold` (no notice), `taking` (a notice under its taking epoch,
//! the newest held among those what gave the removed node read boxed it, opened by every holder
//! of that epoch), `blocked` (wrapped under the newest current epoch, covering the departure or
//! not), `rotation-until` (the notices and the role entries up to the first rotation superseding
//! the shown epoch, as `until` was), `no-record` (a notice without the remover's record),
//! `all-records` (a notice carrying every record the logger's record blob carries).
//! Properties:
//! - `told`: the removed node learns its removal from any member that judges it departed, holds
//!   an epoch it holds superseded and may encrypt (its newest current epoch covers the
//!   departure), the remover gone or not;
//! - `notice`: of what a node judging it departed serves it, nothing it opens is content, a role
//!   commit made by a node that had judged the removal (but the removal and a rotation superseding
//!   an epoch it holds), or a record minted so (but the remover's);
//! - `lowered`: L opens no notice (each is of a removal after its own departure).

use crate::Findings;
use std::collections::BTreeSet;

pub const N0: usize = 0;
pub const N1: usize = 1;
pub const N2: usize = 2;
pub const N3: usize = 3;
pub const X: usize = 4;
pub const L: usize = 5;
pub const NODES: usize = 6;

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
    Fire,
    Newest,
    Full,
    Untold,
    Taking,
    Blocked,
    RotationUntil,
    NoRecord,
    AllRecords,
}

impl ToldRules {
    pub fn named(mode: &str) -> Option<ToldRules> {
        let rest = mode.strip_prefix("told").unwrap_or(mode);
        Some(match rest.strip_prefix("-exh").unwrap_or(rest) {
            "" => ToldRules::Spec,
            "-fire" => ToldRules::Fire,
            "-newest" => ToldRules::Newest,
            "-full" => ToldRules::Full,
            "-untold" => ToldRules::Untold,
            "-taking" => ToldRules::Taking,
            "-blocked" => ToldRules::Blocked,
            "-rotation-until" => ToldRules::RotationUntil,
            "-no-record" => ToldRules::NoRecord,
            "-all-records" => ToldRules::AllRecords,
            _ => return None,
        })
    }
    /// A node judging the departure logs a notice.
    fn logs(self) -> bool {
        self != ToldRules::Untold
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
    /// A notice of the removal: it and its `records`.
    Notice,
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
    /// A notice: the node it is sealed to (`taking`: none, opened by its epoch alone).
    to: Option<usize>,
    /// Made by a node that had judged the removal.
    knew: bool,
}

impl Commit {
    fn role(&self) -> bool {
        self.kind != Kind::Write
    }
    /// A role commit of A's (no record blob or notice).
    fn role_commit(&self) -> bool {
        !matches!(self.kind, Kind::Write | Kind::Records | Kind::Notice)
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
        if a <= N2 || a == L {
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
        !n.gone && !n.erased && a != X && a != L && (a != N3 || self.judges_member(N3, N3))
    }
    fn admin(a: usize) -> bool {
        a == N0 || a == N1
    }
    /// The notice `a` logs now, if any: (the epoch it goes under, the node it is sealed to).
    /// Spec: sealed to the departed node, under `a`'s newest current epoch once that covers the
    /// departure (`blocked`: covering or not); `taking`: under the newest epoch held of those
    /// what gave it read boxed it (N2's start, N3's pairing), sealed to no one.
    fn notice_epoch(&self, a: usize) -> Option<(usize, Option<usize>)> {
        let who = self.departure(a)?;
        if !self.r.logs() {
            return None;
        }
        if self.r == ToldRules::Taking {
            let given: BTreeSet<usize> = match self.pair {
                Some(p) if who == N3 => self.commits[p].boxes.iter().map(|b| b.1).collect(),
                _ => [0].into(),
            };
            return self.held(a).into_iter().rev().find(|e| given.contains(e)).map(|e| (e, None));
        }
        let newest = self.current(a).last().copied()?;
        (self.r == ToldRules::Blocked || self.covers(newest)).then_some((newest, Some(who)))
    }
    /// Whether `a` holds a covering epoch as its newest current one: it may encrypt.
    fn may_encrypt(&self, a: usize) -> bool {
        self.current(a).last().is_some_and(|&e| self.covers(e))
    }
    /// Whether `a` opens entry (`c`, `e`): by the epoch, or a notice sealed to it.
    fn opens_entry(&self, a: usize, c: usize, e: usize) -> bool {
        self.opens(a, e) || (self.commits[c].kind == Kind::Notice && self.commits[c].to == Some(a))
    }
    /// The epoch `a` logs commit `c` under now (`None`: not now).
    fn log_epoch(&self, a: usize, c: usize) -> Option<usize> {
        let x = &self.commits[c];
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
        let c = Commit { kind, signer: a, makes: Some(e), boxes, supersedes: self.current(a), covers: gone.is_some(), records: vec![], to: None, knew: false };
        self.add(a, c)
    }
    /// Opens what `a` can of its log; a removed node judging its removal erases A.
    fn absorb(&mut self, a: usize) {
        loop {
            let held = self.held(a);
            let mut moved = false;
            for i in 0..self.n[a].log.len() {
                let (c, e) = self.n[a].log[i];
                let opens = held.contains(&e) || (self.commits[c].kind == Kind::Notice && self.commits[c].to == Some(a));
                if opens && self.n[a].known.insert(c) {
                    moved = true;
                }
                if opens && self.commits[c].kind == Kind::Notice && self.n[a].known.insert(self.removal.map_or(c, |r| r.0)) {
                    moved = true;
                }
                if opens && matches!(self.commits[c].kind, Kind::Records | Kind::Notice) {
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
        let mut s: BTreeSet<usize> = self.n[a].known.iter().map(|&c| &self.commits[c]).filter(|c| c.role_commit()).map(|c| c.signer).collect();
        if self.pair.is_some_and(|p| self.n[a].known.contains(&p)) {
            s.insert(N3);
        }
        s.into_iter().filter(|&k| self.n[a].recs[k]).collect()
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
                        self.add(a, Commit { kind: Kind::Reseal, signer: a, makes: None, boxes: vec![(m, e)], supersedes: vec![], covers: false, records: vec![], to: None, knew: false });
                    }
                }
            }
        }
        // log what it holds
        let known: Vec<usize> = self.n[a].known.iter().copied().collect();
        for c in known {
            let x = &self.commits[c];
            if matches!(x.kind, Kind::Records | Kind::Notice) || (x.kind == Kind::Write && x.signer != a) {
                continue;
            }
            let Some(e) = self.log_epoch(a, c) else { continue };
            if !self.n[a].log.iter().any(|&(y, f)| y == c && self.opens(a, f)) {
                self.n[a].log.push((c, e));
            }
        }
        // a notice of the removal: the remover's record with it; one among the entries it opens
        // (`taking`: one per taking epoch)
        if let (Some((e, to)), Some((_, by, _))) = (self.notice_epoch(a), self.removal) {
            let has = self.n[a].log.iter().any(|&(c, f)| self.commits[c].kind == Kind::Notice && (if to.is_some() { self.opens(a, f) } else { f == e }));
            if !has {
                let records = match self.r {
                    ToldRules::NoRecord => vec![],
                    ToldRules::AllRecords => self.general_records(a),
                    _ => vec![by],
                };
                let c = self.add(a, Commit { kind: Kind::Notice, signer: a, makes: None, boxes: vec![], supersedes: vec![], covers: false, records, to, knew: false });
                self.n[a].log.push((c, e));
            }
        }
        // spares: of two opened entries of a commit, the newer
        let mut keep = vec![];
        for &(c, e) in &self.n[a].log {
            if matches!(self.commits[c].kind, Kind::Records | Kind::Notice) || !self.opens(a, e) {
                keep.push(true);
                continue;
            }
            let best = self.n[a].log.iter().filter(|&&(y, f)| y == c && self.opens(a, f)).map(|&(_, f)| f).max().unwrap();
            keep.push(e == best);
        }
        let mut it = keep.into_iter();
        let mut seen = BTreeSet::new();
        self.n[a].log.retain(|&(c, e)| it.next().unwrap() && (matches!(self.commits[c].kind, Kind::Records | Kind::Notice) || seen.insert((c, e))));
        // a record blob under the newest epoch carrying the signers' records
        if let Some(e) = self.current(a).last().copied() {
            let need = self.general_records(a);
            let has = need.is_empty() || self.n[a].log.iter().any(|&(c, f)| f == e && self.commits[c].kind == Kind::Records && self.commits[c].records == need);
            if !has {
                let c = self.add(a, Commit { kind: Kind::Records, signer: a, makes: None, boxes: vec![], supersedes: vec![], covers: false, records: need, to: None, knew: false });
                self.n[a].log.push((c, e));
            }
        }
        // of two record blobs under an epoch, the one carrying what it needs with fewer others wins
        let need = self.general_records(a);
        let log = self.n[a].log.clone();
        let keep: Vec<bool> = log.iter().map(|&(c, e)| {
            if self.commits[c].kind != Kind::Records || !self.opens(a, e) {
                return true;
            }
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
                    let c = s.add(n, Commit { kind: Kind::Write, signer: n, makes: None, boxes: vec![], supersedes: vec![], covers: false, records: vec![], to: None, knew: false });
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
                let p = s.add(N0, Commit { kind: Kind::Pair, signer: N0, makes: None, boxes, supersedes: vec![], covers: false, records: vec![], to: None, knew: false });
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
                let role: BTreeSet<usize> = s.n[N0].known.union(&s.n[N1].known).copied().filter(|&c| s.commits[c].role_commit()).collect();
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
                    let c = Commit { kind: Kind::Remove, signer: by, makes: Some(e), boxes, supersedes: s.current(by), covers: true, records: vec![], to: None, knew: false };
                    s.add(by, c)
                } else {
                    s.add(by, Commit { kind: Kind::Remove, signer: by, makes: None, boxes: vec![], supersedes: vec![], covers: false, records: vec![], to: None, knew: false })
                };
                s.removal = Some((c, by, who));
                st.count(if knowing { "knowing" } else { "blind" }, 1);
                s.settle(by);
            }
            Ev::Sync(u, v) => {
                let who = s.removal.map(|r| r.2);
                for (a, b) in [(u, v), (v, u)] {
                    if Some(b) == who && s.member(a) && s.member(b) && s.departed_at(a, b) && s.may_encrypt(a) && shown(&s, a, b, false).is_some() {
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
    for &(c, e) in &s.n[L].log {
        if s.commits[c].kind == Kind::Notice && s.opens_entry(L, c, e) {
            fails.push(format!("lowered: L opens a notice of N{who}'s removal under {e}"));
        }
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
    // a store of A: every entry
    if b == L && s.member(a) {
        let all = s.n[a].log.clone();
        s.take(L, &all);
        return;
    }
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
    let notice = |s: &State, c: usize| s.commits[c].kind == Kind::Notice;
    let served: Vec<(usize, usize)> = match s.r {
        ToldRules::Fire => {
            if a == by { log.iter().copied().filter(|x| x.0 == rc).collect() } else { vec![] }
        }
        r => {
            let Some(e) = shown(s, a, b, r == ToldRules::Newest) else { return };
            // until: the first-logged notice here (none logged: nothing opens)
            let Some(until) = log.iter().position(|&(c, _)| notice(s, c)) else { return };
            log.iter().enumerate().filter(|&(i, &(c, _))| match r {
                ToldRules::Full => i <= until || notice(s, c),
                // as `until` was: up to the first rotation superseding the shown epoch
                ToldRules::RotationUntil => notice(s, c) || (s.commits[c].role() && log.iter().position(|&(y, _)| s.commits[y].supersedes.contains(&e)).is_some_and(|f| i <= f)),
                _ => notice(s, c),
            }).map(|(_, &x)| x).collect()
        }
    };
    // what b gains: a commit made knowing its removal that it opens and did not hold, a record
    // minted so, content
    let mine = s.held(b);
    for &(c, e) in &served {
        let x = &s.commits[c];
        if !s.opens_entry(b, c, e) {
            continue;
        }
        let gain = match x.kind {
            Kind::Write => Some("content"),
            Kind::Records | Kind::Notice => x.records.iter().any(|&k| s.late[k] && k != by && !s.n[b].recs[k]).then_some("a record minted knowing its removal"),
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

/// Events a slot draws from: syncs of every pair but L, N1's with L, writes by N1 and N2, rotations by N0 and N1, a
/// pairing, hearing, the admins' resets, nothing.
pub fn alphabet() -> Vec<Ev> {
    let mut out = vec![];
    for u in 0..X + 1 {
        for v in u + 1..X + 1 {
            out.push(Ev::Sync(u, v));
        }
    }
    out.push(Ev::Sync(N1, L));
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

    /// N0 removes N2 and is reset; N2 meets N1 alone. Spec: N1 tells it. Told by the remover's
    /// fire alone, it never learns.
    #[test]
    fn a_removed_node_learns_from_a_member_the_remover_gone() {
        let w = vec![Sync(N0, N1), Remove(N0, N2), Sync(N0, N1), Reset(N0), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
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

    /// N1 writes before it holds the removal; N2 is served its notice alone. Served content up to
    /// the notice, it gains more than its notice.
    #[test]
    fn a_removed_node_gains_nothing_but_its_notice() {
        let w = vec![Write(N1), Remove(N0, N2), Sync(N0, N1), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Full), ["notice"]);
    }

    /// A node paired after the removal tells N2; a stranger opens nothing.
    #[test]
    fn a_node_paired_after_the_removal_tells_and_a_stranger_cannot() {
        assert!(kinds(vec![Remove(N0, N2), Pair, Reset(N0), Sync(N2, X), Sync(N2, N3)], ToldRules::Spec).is_empty());
        assert_eq!(kinds(vec![Remove(N0, N2), Pair, Reset(N0), Sync(N2, N3)], ToldRules::Fire), ["told"]);
    }

    /// N1 removes N3 never having held its pairing, so its removal rotates nothing, and N3 lacks
    /// N1's record; N0 hears of it by another route, rotates, and N1 is reset. N0 tells N3: a
    /// notice under the epoch N3 holds, carrying N1's record. With no notice, or one without the
    /// record, N3 never learns.
    #[test]
    fn a_blind_removal_tells_the_removed_node() {
        let w = vec![Pair, Remove(N1, N3), Hear, Reset(N1), Sync(N0, N3)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w.clone(), ToldRules::Untold), ["told"]);
        assert_eq!(kinds(w, ToldRules::NoRecord), ["told"]);
    }

    /// As above, N1 having rotated (boxing N3 nothing: it never held the pairing) before its
    /// removal: N3 holds none of N0's newer epochs, and opens the notice by its own key.
    #[test]
    fn a_blind_removal_after_a_rotation_not_boxing_the_node_tells_it() {
        let w = vec![Pair, Rotate(N1), Remove(N1, N3), Hear, Sync(N0, N3)];
        assert!(kinds(w, ToldRules::Spec).is_empty());
    }

    /// N0 removes N2, a member from the start, and L stores what N1 holds. Under the taking epoch
    /// (epoch 0, which L kept) L opens N2's notice; sealed to N2, L opens nothing.
    #[test]
    fn a_lowered_reader_opens_no_later_removal() {
        let w = vec![Remove(N0, N2), Sync(N0, N1), Sync(N1, L)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Taking), ["lowered"]);
    }

    /// N1 removes N3 blind; N2, which may not rotate, judges the departure before any admin
    /// rotates, and N1 takes its log (judging the departure then, it rotates). Wrapped under N2's
    /// newest epoch, epoch 0, L opens the notice; N2 logs none until it holds a covering epoch.
    #[test]
    fn a_member_that_may_not_rotate_waits_for_a_covering_epoch() {
        let w = vec![Pair, Sync(N0, N2), Remove(N1, N3), Sync(N1, N2), Sync(N1, L)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Blocked), ["lowered"]);
    }

    /// N1 removes N2 beside N3's pairing: a re-seal giving N3 the covering rotation's epoch is
    /// wrapped under the epoch it supersedes, which N2 holds, made knowing the removal and logged
    /// before the notice. Served the notices alone, N2 gains
    /// nothing else; served every entry up to the notice (`full`), it gains the giving commit.
    #[test]
    fn a_removed_node_is_served_its_notices_alone() {
        let w = vec![Sync(N0, N2), Pair, Remove(N1, N2), Hear, Sync(N2, N3), Sync(N0, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Full), ["notice"]);
    }

    /// N0 removes N2 (knowing) and pairs N3, the pairing wrapped under epoch 0, which N2 holds; N1
    /// rotates unaware, boxing N2 its epoch, and N0 takes that rotation. N2's Hit opens on N1's
    /// epoch, whose superseding rotation N0 logs after the pairing: `until` there serves N2 the
    /// pairing, made knowing the removal. Served the notice alone, nothing past its judgement.
    #[test]
    fn a_rotation_until_serves_past_the_removal() {
        let w = vec![Remove(N0, N2), Pair, Rotate(N1), Sync(N1, N2), Sync(N0, N1), Sync(N0, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::RotationUntil), ["notice"]);
    }

    /// N0 removes N2 and then pairs N3 (N3's record minted knowing the removal), taking N3's
    /// record blob; N1 hears of both by another route, with N3's record, and logs its own notice.
    /// Carrying the remover's record alone, it serves N2 nothing more; carrying every record N1's
    /// record blob carries, it serves N2 N3's record.
    #[test]
    fn a_notice_carries_the_removers_record_alone() {
        let w = vec![Remove(N0, N2), Pair, Sync(N0, N3), Hear, Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::AllRecords), ["notice"]);
    }

    /// Every 101st family world (`-- 1 told-exh` runs them all): spec holds; each control fails
    /// its property in one of them (searched until one does).
    #[test]
    #[ignore = "property"]
    fn told_family_holds_plain() {
        let st = crate::family_on_every_core(family_size(), 101, |k, st: &mut ToldStats| told_check(&told_family(k), ToldRules::Spec, st));
        assert!(st.worlds > 0 && st.failures == 0, "{:?}", st.fail);
        for (r, kind) in [
            (ToldRules::Fire, "told"),
            (ToldRules::Newest, "told"),
            (ToldRules::Full, "notice"),
            (ToldRules::Untold, "told"),
            (ToldRules::Taking, "lowered"),
            (ToldRules::Blocked, "lowered"),
            (ToldRules::NoRecord, "told"),
            (ToldRules::AllRecords, "notice"),
        ] {
            let fails = crate::family_any(family_size(), 101, |k| {
                let mut st = ToldStats::default();
                told_check(&told_family(k), r, &mut st);
                st.kinds.contains_key(kind)
            });
            assert!(fails, "{r:?}");
        }
    }
}
