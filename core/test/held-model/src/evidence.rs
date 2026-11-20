//! Evidence completeness (notes/redesign-plan.md M2; notes/write-path-design.md §2, §6): a model
//! of what each sync ID carries as evidence for the writes whose bodies it carries, and of whether
//! a reader holding one sync ID alone judges those writes as a node holding everything does.
//! Properties in tests/it/spec_evidence.rs, findings in notes/evidence-model-findings.md.
//!
//! Judging is roles-model `paths` (`Rules::fixed`, the rule A1 builds): a commit states a path,
//! judged along it; a lowering lists a frontier; vouches, addenda, re-grants as there. On top:
//! - **Pending** (`pend`): a commit pends at a node while an edge of its path (or the remaining
//!   admin edge it names) that is no record edge has no held edge write ordered before it, or the
//!   latest such write pends (notes/write-path-design.md §2 What follows, its smallest reading).
//! - **Sync IDs and units.** Signers have no sync ID; every other thing in `sids` has its own, and
//!   a unit per sync ID: the thing and the members `Ev::Join`/`Ev::Leave` give it. Which things a
//!   unit holds is the closure model's question (`closure::unit`), so here it is an input in time.
//!   A thing outside `sids` (a dependent thing) is carried only in the units holding it.
//! - **Bodies.** A commit's body is under every sync ID whose unit holds the thing it writes
//!   (roles-model commits write one thing: a copy per (commit, thing) is per commit here).
//! - **The required set** of sync ID S over a held set H (`World::req`): the evidence closure
//!   (`paths::evidence`: every held edge write on an edge of a seed's path or on the remaining
//!   admin edge a lowering names, every held vouch against a held removal, closed under the same
//!   for what it adds) of the seeds: the bodies; the grants naming S's thing as holder (a holder's
//!   grants travel under its sync ID: taken-ness is not modelled, every grant counts); and every
//!   held lowering of an edge (h, t) whose **reach** (held edge writes giving write or above, at any
//!   time, joining t to a thing of the unit) is held, with that reach (a removal is logged for good
//!   where its holder could write: notes/write-path-design.md §2, A3). What of it lies on things
//!   outside the unit is a copy, the rest bodies.
//! - **Delivery** (`Placement`): nodes sync sync IDs (`Node::syncs`, closed under the standing duty:
//!   a node syncing S syncs every sync ID of a thing in S's unit) and hold what those carry and what
//!   they wrote. An honest node logs under each sync ID it syncs what its own view requires there;
//!   an entry no syncing node requires is deleted (a delete-key holder deletes, a holder whose view
//!   requires it logs again: the union). The thief logs its own bodies and the grants they rest on,
//!   never a lowering. The remover's errand (`Errand`): it logs its lowering under the own sync ID
//!   of the lowered edge's target and of the things that target holds grants on (`Direct`, read
//!   from the target's taken grants), or of everything reached by taken grants (`Transitive`).
//! - **Readers.** A reader holding one sync ID holds its entries, sees frontier leaves for its
//!   unit's things and (`Leaves::Evidence`) for every thing a held edge write is on, and trusts
//!   what the world trusts that it holds. The node holding everything sees every leaf.
//!
//! Left out: records (static, `paths::World::records`), keys and sealing, rotations, `@` signals,
//! covers, the deposit path, invites as a reach (a removal's reach is write), taken-ness of a grant,
//! multi-thing role commits, how units are computed (an input: `closure` checks the walk).

use roles_model::paths::{self, Edge, Id, Kind, Rules, Set, Thing, Things, View};
use roles_model::Role;
use std::collections::BTreeMap;

pub type Sid = Thing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Pending,
    Valid,
    Invalid,
}

/// When copies are logged and when they leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// The design (notes/write-path-design.md §2: "a function of the commits U holds", "logged
    /// by any node holding them and U"): every honest syncing node logs what its view requires
    /// now, and what nobody requires leaves.
    Function,
    /// The literal "logged with the commit that needs it, leaving with it": a commit's copies are
    /// placed when the commit is logged under the sync ID (by the node logging it, from its view
    /// then; a body where the thing is in the unit then, else a copy) and leave once every commit
    /// they were placed for left; nothing is placed again when a unit changes.
    AtLog,
}

/// Where the remover logs its lowering besides the sync IDs it syncs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errand {
    Off,
    /// The target's own sync ID and those of the things it holds grants on (its taken grants,
    /// under its own sync ID).
    Direct,
    /// Every thing reached from the target by taken grants, each read under the reached thing's
    /// own sync ID, held for the errand.
    Transitive,
}

/// What travels by errand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Lowerings only ("only removals travel at once").
    Lowerings,
    /// A lowering, and every later edge write on its edge (a re-grant) and vouch against it,
    /// written by any honest node holding the lowering, to the same sync IDs.
    Edge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaves {
    /// A reader sees the leaves of its unit's things and of every thing a held edge write is on.
    Evidence,
    /// Its unit's things only.
    Unit,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rule {
    pub placement: Placement,
    pub errand: Errand,
    pub scope: Scope,
    pub leaves: Leaves,
    /// The errand is a standing duty: the remover logs again whenever its view shows a new
    /// target (a holder raised later); false, once, as the lowering is written.
    pub standing: bool,
}

impl Rule {
    /// The plan's reading (notes/redesign-plan.md A2, A3).
    pub fn design() -> Rule {
        Rule { placement: Placement::Function, errand: Errand::Direct, scope: Scope::Lowerings, leaves: Leaves::Evidence, standing: true }
    }
    /// The design with the findings' fixes (notes/evidence-model-findings.md): the errand follows
    /// taken grants to the end.
    pub fn fixed() -> Rule {
        Rule { errand: Errand::Transitive, ..Rule::design() }
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub honest: bool,
    pub syncs: Things,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ev {
    /// The commit is written by its node (`World::by`).
    Write(Id),
    /// The thing joins the sync ID's unit (a strong added), or leaves it.
    Join(Thing, Sid),
    Leave(Thing, Sid),
}

#[derive(Clone, Debug)]
pub struct World {
    pub w: paths::World,
    pub rules: Rules,
    pub sids: Things,
    /// The units before the first event (a sync ID's own thing is always in its unit).
    pub units: BTreeMap<Sid, Things>,
    pub events: Vec<Ev>,
    pub nodes: Vec<Node>,
    /// The node writing each commit.
    pub by: Vec<usize>,
    pub trust: Set,
}

/// Where the model stands after some events.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub step: usize,
    pub written: Set,
    /// Commits released or covered at every node (`World::forget`).
    pub forgotten: Set,
    pub units: BTreeMap<Sid, Things>,
    pub entries: BTreeMap<Sid, Set>,
    /// Per node what it holds (`Placement::Function`: kept while a sync ID it syncs requires it).
    pub held: Vec<Set>,
    /// `Placement::AtLog`: what errands logged, never unplaced.
    pub errands: BTreeMap<Sid, Set>,
    /// `Placement::AtLog`: per (sync ID, copy), the commits it was placed for.
    pub placed: BTreeMap<(Sid, Id), Set>,
    /// A settle that did not reach a fixpoint.
    pub unsettled: bool,
    /// Logging rounds over all settles (cost).
    pub rounds: usize,
}

const ROUNDS: usize = 40;

impl World {
    pub fn new(w: paths::World, sids: &[Thing]) -> World {
        let sids: Things = sids.iter().copied().collect();
        let units = sids.iter().map(|&s| (s, Things::from([s]))).collect();
        World { w, rules: Rules::fixed(), sids, units, events: vec![], nodes: vec![], by: vec![], trust: Set::new() }
    }
    pub fn node(&mut self, honest: bool, syncs: &[Thing]) -> usize {
        self.nodes.push(Node { honest, syncs: syncs.iter().copied().collect() });
        self.nodes.len() - 1
    }
    /// A commit written now by node `n` (`f` pushes it to the paths world).
    pub fn write(&mut self, n: usize, f: impl FnOnce(&mut paths::World) -> Id) -> Id {
        let i = f(&mut self.w);
        assert_eq!(i, self.by.len(), "one commit per write");
        // a node writes only what it holds: it syncs the thing written and its path's things
        let c = &self.w.commits[i];
        let mine: Vec<Thing> = c.path.iter().copied().chain([c.on]).filter(|x| self.sids.contains(x)).collect();
        self.nodes[n].syncs.extend(mine);
        self.by.push(n);
        self.events.push(Ev::Write(i));
        i
    }
    pub fn join(&mut self, x: Thing, s: Sid) {
        self.events.push(Ev::Join(x, s));
    }
    pub fn leave(&mut self, x: Thing, s: Sid) {
        self.events.push(Ev::Leave(x, s));
    }
    /// In the unit from the start.
    pub fn member(&mut self, x: Thing, s: Sid) {
        self.units.get_mut(&s).unwrap().insert(x);
    }
    pub fn on(&self, i: Id) -> Thing {
        self.w.commits[i].on
    }
    fn holder(&self, i: Id) -> Option<Thing> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, .. } => Some(*holder),
            _ => None,
        }
    }
    /// A removal: an edge write giving below write at its own `ts` (none, read, or an `until`
    /// passed), but a finalize. (`paths::World::lowers` counts every write below admin, a fresh
    /// grant of write included.) A demotion from admin to write is not one here.
    pub fn removes(&self, i: Id) -> Option<Edge> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, role, until, finalize: false, .. } if paths::alive((*role, *until), self.w.commits[i].ts) < Role::Write => Some((*holder, self.on(i))),
            _ => None,
        }
    }
    /// A held edge write giving write or above (any `until`): a reach.
    fn gives_write(&self, i: Id) -> Option<Edge> {
        match &self.w.commits[i].kind {
            Kind::Edge { holder, role, .. } if *role >= Role::Write => Some((*holder, self.on(i))),
            _ => None,
        }
    }

    // ---- What a sync ID requires ----

    /// The held grants (write or above, any time) joining `t` to a thing of `unit`; None when
    /// none does. Empty when `t` is in the unit.
    pub fn reach(&self, t: Thing, unit: &Things, h: &Set) -> Option<Set> {
        if unit.contains(&t) {
            return Some(Set::new());
        }
        let grants: Vec<(Id, Edge)> = h.iter().filter_map(|&i| self.gives_write(i).map(|e| (i, e))).collect();
        let mut fwd = Things::from([t]);
        loop {
            let n = fwd.len();
            fwd.extend(grants.iter().filter(|(_, e)| fwd.contains(&e.0)).map(|(_, e)| e.1).collect::<Vec<_>>());
            if fwd.len() == n {
                break;
            }
        }
        let mut back: Things = unit.clone();
        loop {
            let n = back.len();
            back.extend(grants.iter().filter(|(_, e)| back.contains(&e.1)).map(|(_, e)| e.0).collect::<Vec<_>>());
            if back.len() == n {
                break;
            }
        }
        if !fwd.iter().any(|x| unit.contains(x)) {
            return None;
        }
        Some(grants.iter().filter(|(_, e)| fwd.contains(&e.0) && back.contains(&e.1)).map(|(i, _)| *i).collect())
    }
    /// The seeds of S's required set over `h`, its unit `unit`.
    fn seeds(&self, rule: &Rule, s: Sid, unit: &Things, h: &Set) -> Set {
        let mut seed: Set = h.iter().copied().filter(|&i| unit.contains(&self.on(i)) || self.holder(i) == Some(s)).collect();
        for &l in h {
            if let Some((hd, t)) = self.removes(l) {
                if let Some(r) = self.reach(t, unit, h) {
                    seed.insert(l);
                    seed.extend(r);
                    if rule.scope == Scope::Edge {
                        seed.extend(h.iter().copied().filter(|&j| self.w.sets(j) == Some((hd, t)) && self.w.key(l) < self.w.key(j)));
                    }
                }
            }
        }
        seed
    }
    /// S's required set over held set `h` with units `units`: bodies and copies.
    pub fn req(&self, rule: &Rule, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set) -> Set {
        paths::evidence(&self.w, &self.seeds(rule, s, &units[&s], h), h)
    }
    /// The bodies S carries of `h`.
    pub fn bodies(&self, s: Sid, units: &BTreeMap<Sid, Things>, h: &Set) -> Set {
        h.iter().copied().filter(|&i| units[&s].contains(&self.on(i))).collect()
    }
    /// The copies among S's entries: commits on things outside its unit.
    pub fn copies(&self, st: &State, s: Sid) -> Set {
        st.entries[&s].iter().copied().filter(|&i| !st.units[&s].contains(&self.on(i))).collect()
    }

    // ---- Delivery ----

    /// The sync IDs node `n` syncs: its own, closed under the standing duty.
    pub fn syncs(&self, n: usize, units: &BTreeMap<Sid, Things>) -> Things {
        let mut sy: Things = self.nodes[n].syncs.iter().copied().filter(|s| self.sids.contains(s)).collect();
        loop {
            let more: Vec<Thing> = sy.iter().flat_map(|s| units[s].iter().copied()).filter(|x| self.sids.contains(x) && !sy.contains(x)).collect();
            if more.is_empty() {
                return sy;
            }
            sy.extend(more);
        }
    }
    fn own(&self, st: &State, n: usize) -> Set {
        st.written.iter().copied().filter(|&i| self.by[i] == n && !st.forgotten.contains(&i)).collect()
    }
    /// What the thief logs under S: its own bodies there and the grants (no lowering) they rest on.
    fn thief_logs(&self, s: Sid, units: &BTreeMap<Sid, Things>, held: &Set, own: &Set) -> Set {
        let mine: Set = own.iter().copied().filter(|&i| units[&s].contains(&self.on(i))).collect();
        paths::evidence(&self.w, &mine, held).into_iter().filter(|&i| own.contains(&i) || self.removes(i).is_none()).collect()
    }
    /// The commits node `n`'s errand carries: its own lowerings, and under `Scope::Edge` its own
    /// later edge writes on a held lowering's edge and vouches against a held lowering; each with
    /// the target whose sync IDs it goes to.
    fn errand_items(&self, rule: &Rule, own: &Set, held: &Set, fresh: &Set) -> Vec<(Id, Thing)> {
        let mut out = vec![];
        for &i in own {
            if !rule.standing && !fresh.contains(&i) {
                continue;
            }
            if let Some((_, t)) = self.removes(i) {
                out.push((i, t));
                continue;
            }
            if rule.scope != Scope::Edge {
                continue;
            }
            let lowered = |e: Edge, after: Option<Id>| held.iter().any(|&l| self.removes(l) == Some(e) && after.is_none_or(|a| self.w.key(l) < self.w.key(a)));
            match &self.w.commits[i].kind {
                Kind::Edge { .. } if lowered(self.w.sets(i).unwrap(), Some(i)) => out.push((i, self.on(i))),
                Kind::Vouch { removal, .. } if held.contains(removal) => {
                    if let Some((_, t)) = self.removes(*removal) {
                        out.push((i, t));
                    }
                }
                _ => {}
            }
        }
        out
    }
    /// Where an errand for target `t` logs, and what node `n` holds once it held each of those
    /// for the errand: the target's own sync ID and those its taken grants (grants naming it,
    /// under its own sync ID) reach, one level (`Direct`) or all (`Transitive`).
    fn errand_targets(&self, rule: &Rule, st: &State, t: Thing, held: &Set) -> (Things, Set) {
        let mut seen = Things::new();
        let mut todo = vec![(t, 0)];
        let mut h = held.clone();
        while let Some((x, depth)) = todo.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Some(e) = st.entries.get(&x) {
                h.extend(e.iter().copied());
            }
            if rule.errand == Errand::Direct && depth >= 1 {
                continue;
            }
            for &j in &h.clone() {
                if let Some((hd, y)) = self.gives_write(j) {
                    if hd == x {
                        todo.push((y, depth + 1));
                    }
                }
            }
        }
        (seen.into_iter().filter(|x| self.sids.contains(x)).collect(), h)
    }
    /// Runs node `n`'s errands over `held`: what each sync ID gains.
    fn errands(&self, rule: &Rule, st: &State, n: usize, held: &Set, fresh: &Set) -> BTreeMap<Sid, Set> {
        let mut out: BTreeMap<Sid, Set> = BTreeMap::new();
        if !self.nodes[n].honest {
            return out;
        }
        let own = self.own(st, n);
        // a grant naming a holder goes under the holder's sync ID by its granter (spec/sync-inbox.md
        // §5 Delivery of a grant)
        for &i in &own {
            if let Some(hd) = self.holder(i).filter(|hd| self.sids.contains(hd)) {
                out.entry(hd).or_default().extend(paths::evidence(&self.w, &Set::from([i]), held));
            }
        }
        if rule.errand == Errand::Off {
            return out;
        }
        for (i, t) in self.errand_items(rule, &own, held, fresh) {
            let (targets, h) = self.errand_targets(rule, st, t, held);
            for x in targets {
                let reach = self.reach(t, &st.units[&x], &h).unwrap_or_default();
                let mut seed = reach;
                seed.insert(i);
                out.entry(x).or_default().extend(paths::evidence(&self.w, &seed, &h));
            }
        }
        out
    }

    /// The state before any event.
    pub fn start(&self) -> State {
        let entries = self.sids.iter().map(|&s| (s, Set::new())).collect();
        State { units: self.units.clone(), entries, held: vec![Set::new(); self.nodes.len()], ..State::default() }
    }
    /// Applies event `k`, then lets the nodes log until nothing moves.
    pub fn apply(&self, rule: &Rule, st: &mut State, k: usize) {
        let mut fresh = Set::new();
        match self.events[k] {
            Ev::Write(i) => {
                st.written.insert(i);
                fresh.insert(i);
            }
            Ev::Join(x, s) => {
                st.units.get_mut(&s).unwrap().insert(x);
            }
            Ev::Leave(x, s) => {
                st.units.get_mut(&s).unwrap().remove(&x);
                if rule.placement == Placement::AtLog {
                    self.unplace(st, s, |i| self.on(i) == x);
                }
            }
        }
        st.step = k + 1;
        self.settle(rule, st, &fresh);
    }
    /// `AtLog`: removes S's bodies matching `gone` and every copy left placed for nothing.
    fn unplace(&self, st: &mut State, s: Sid, gone: impl Fn(Id) -> bool) {
        let bodies: Vec<Id> = st.entries[&s].iter().copied().filter(|&i| gone(i) && !st.placed.contains_key(&(s, i))).collect();
        let e = st.entries.get_mut(&s).unwrap();
        for b in &bodies {
            e.remove(b);
        }
        let mut drop = vec![];
        for ((s2, c), by) in st.placed.iter_mut() {
            if *s2 != s {
                continue;
            }
            for b in &bodies {
                by.remove(b);
            }
            if gone(*c) {
                by.clear();
            }
            if by.is_empty() {
                drop.push(*c);
            }
        }
        for c in drop {
            st.placed.remove(&(s, c));
            if !st.errands.get(&s).is_some_and(|e| e.contains(&c)) {
                st.entries.get_mut(&s).unwrap().remove(&c);
            }
        }
    }
    /// Every event in order; `each` sees the state after each.
    pub fn run(&self, rule: &Rule, mut each: impl FnMut(&State)) -> State {
        let mut st = self.start();
        for k in 0..self.events.len() {
            self.apply(rule, &mut st, k);
            each(&st);
        }
        st
    }
    /// The commit `i` released or covered at every node: it and what only it needed leave.
    pub fn forget(&self, rule: &Rule, st: &mut State, i: Id) {
        st.forgotten.insert(i);
        for h in st.held.iter_mut() {
            h.remove(&i);
        }
        for e in st.errands.values_mut() {
            e.remove(&i);
        }
        if rule.placement == Placement::AtLog {
            for s in self.sids.clone() {
                self.unplace(st, s, |c| c == i);
            }
        } else {
            for e in st.entries.values_mut() {
                e.remove(&i);
            }
        }
        self.settle(rule, st, &Set::new());
    }
    fn settle(&self, rule: &Rule, st: &mut State, fresh: &Set) {
        let mut fresh = fresh.clone();
        for _ in 0..ROUNDS {
            st.rounds += 1;
            let before = (st.entries.clone(), st.held.clone());
            match rule.placement {
                Placement::Function => self.round_function(rule, st, &fresh),
                Placement::AtLog => self.round_atlog(rule, st, &fresh),
            }
            // an errand at writing runs in the first round only
            fresh.clear();
            if (st.entries.clone(), st.held.clone()) == before {
                return;
            }
        }
        st.unsettled = true;
    }
    fn round_function(&self, rule: &Rule, st: &mut State, fresh: &Set) {
        // nothing is kept for its past: an errand's entry stays while a holder's view requires it
        let mut new: BTreeMap<Sid, Set> = self.sids.iter().map(|&s| (s, Set::new())).collect();
        for n in 0..self.nodes.len() {
            let sy = self.syncs(n, &st.units);
            let own = self.own(st, n);
            let mut held: Set = st.held[n].iter().chain(&own).copied().chain(sy.iter().flat_map(|s| st.entries[s].iter().copied())).filter(|i| !st.forgotten.contains(i)).collect();
            // keep only what a synced sync ID requires, and its own writes
            loop {
                let keep: Set = sy.iter().flat_map(|&s| self.req(rule, s, &st.units, &held)).chain(own.iter().copied()).filter(|i| held.contains(i)).collect();
                if keep == held {
                    break;
                }
                held = keep;
            }
            for &s in &sy {
                let logs = if self.nodes[n].honest { self.req(rule, s, &st.units, &held) } else { self.thief_logs(s, &st.units, &held, &own) };
                new.get_mut(&s).unwrap().extend(logs);
            }
            for (s, items) in self.errands(rule, st, n, &held, fresh) {
                new.get_mut(&s).unwrap().extend(items);
            }
            st.held[n] = held;
        }
        st.entries = new;
    }
    fn round_atlog(&self, rule: &Rule, st: &mut State, fresh: &Set) {
        for n in 0..self.nodes.len() {
            let sy = self.syncs(n, &st.units);
            let own = self.own(st, n);
            let honest = self.nodes[n].honest;
            let held: Set = own.iter().copied().chain(sy.iter().flat_map(|s| st.entries[s].iter().copied())).filter(|i| !st.forgotten.contains(i)).collect();
            for &s in &sy {
                let unit = st.units[&s].clone();
                for &c in &held {
                    let body = unit.contains(&self.on(c)) || self.holder(c) == Some(s);
                    if !body || st.entries[&s].contains(&c) || (!honest && !own.contains(&c)) {
                        continue;
                    }
                    st.entries.get_mut(&s).unwrap().insert(c);
                    for e in paths::evidence(&self.w, &Set::from([c]), &held) {
                        if e == c || unit.contains(&self.on(e)) || (!honest && self.removes(e).is_some()) {
                            continue;
                        }
                        st.entries.get_mut(&s).unwrap().insert(e);
                        st.placed.entry((s, e)).or_default().insert(c);
                    }
                }
            }
            st.held[n] = held.clone();
            for (s, items) in self.errands(rule, st, n, &held, fresh) {
                st.errands.entry(s).or_default().extend(items.iter().copied());
                st.entries.get_mut(&s).unwrap().extend(items);
            }
        }
    }

    // ---- Judging ----

    /// The edges a commit's verdict reads edge writes of: its path's and the remaining admin edge
    /// it names.
    pub fn edges_of(&self, i: Id) -> Vec<Edge> {
        let mut e = self.w.hops(i).to_vec();
        if let Kind::Edge { relies: Some(n), .. } = &self.w.commits[i].kind {
            e.push((*n, self.on(i)));
        }
        e
    }
    /// `i` pends over `h`: an edge it reads, no record edge, has no held edge write ordered before
    /// it, or the latest such write pends.
    pub fn pend(&self, h: &Set, i: Id) -> bool {
        let before = |j: Id| if self.w.edge_class(i) { self.w.key(j) < self.w.key(i) } else { self.w.commits[j].ts < self.w.commits[i].ts };
        self.edges_of(i).into_iter().filter(|e| !self.w.records.contains(e)).any(|e| {
            match h.iter().copied().filter(|&j| self.w.sets(j) == Some(e) && before(j)).max_by_key(|&j| self.w.key(j)) {
                None => true,
                Some(j) => self.pend(h, j),
            }
        })
    }
    /// The verdict on each of `ids` at a node judging from `v`.
    pub fn verdicts(&self, v: &View, ids: &Set) -> BTreeMap<Id, Verdict> {
        let rd = paths::judge(&self.w, &self.rules, v);
        ids.iter()
            .map(|&i| {
                let ok = if self.w.edge_class(i) { rd.applied.contains(&i) } else { rd.valid.contains(&i) || rd.copied.contains(&i) };
                (i, if self.pend(&v.held, i) { Verdict::Pending } else if ok { Verdict::Valid } else { Verdict::Invalid })
            })
            .collect()
    }
    /// What a reader holding sync ID `s` alone judges from (its held set minus `without`).
    pub fn reader(&self, rule: &Rule, st: &State, s: Sid, without: &Set) -> View {
        let held: Set = st.entries[&s].difference(without).copied().collect();
        self.reader_of(rule, &st.units[&s], held)
    }
    fn reader_of(&self, rule: &Rule, unit: &Things, held: Set) -> View {
        let mut leaves = unit.clone();
        if rule.leaves == Leaves::Evidence {
            leaves.extend(held.iter().filter(|&&i| self.w.edge_class(i)).map(|&i| self.on(i)));
        }
        let trust = self.trust.intersection(&held).copied().collect();
        View { held, leaves: Some(leaves), trust }
    }
    /// What the node holding everything written (and not forgotten) judges from.
    pub fn full(&self, st: &State, without: &Set) -> View {
        let held: Set = st.written.iter().copied().filter(|i| !st.forgotten.contains(i) && !without.contains(i)).collect();
        let trust = self.trust.intersection(&held).copied().collect();
        View { held, leaves: None, trust }
    }
    /// What S should carry as bodies: every written commit on its unit's things.
    pub fn owed_bodies(&self, st: &State, s: Sid) -> Set {
        self.bodies(s, &st.units, &self.full(st, &Set::new()).held)
    }
}

// ---- Properties: failures, each named ----

#[derive(Clone, Debug, PartialEq)]
pub struct Fail {
    pub prop: &'static str,
    pub step: usize,
    pub sid: Sid,
    pub id: Id,
    pub reader: Option<Verdict>,
    pub full: Option<Verdict>,
}

impl World {
    /// P1 (and P2 for commits under several sync IDs): the reader of each sync ID judges every
    /// body it should carry as the node holding everything does (a body it lacks is judged
    /// absent: `None`).
    pub fn p1(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let fv = self.verdicts(&self.full(st, &Set::new()), &st.written);
        let mut out = vec![];
        let mut seen: BTreeMap<Id, Vec<(Sid, Option<Verdict>)>> = BTreeMap::new();
        for &s in &self.sids {
            let owed = self.owed_bodies(st, s);
            let v = self.reader(rule, st, s, &Set::new());
            let rv = self.verdicts(&v, &owed.intersection(&v.held).copied().collect());
            for &i in &owed {
                let r = rv.get(&i).copied();
                seen.entry(i).or_default().push((s, r));
                if r.is_none() && !self.nodes[self.by[i]].honest {
                    // the thief logs its own writes where it likes
                    continue;
                }
                if r != Some(fv[&i]) {
                    out.push(Fail { prop: if r.is_none() { "P1-carried" } else { "P1" }, step: st.step, sid: s, id: i, reader: r, full: Some(fv[&i]) });
                }
            }
        }
        for (i, per) in seen {
            let per: Vec<_> = per.into_iter().filter(|x| x.1.is_some()).collect();
            if per.len() > 1 && per.iter().any(|x| x.1 != per[0].1) {
                out.push(Fail { prop: "P2", step: st.step, sid: per[0].0, id: i, reader: per[0].1, full: per.iter().find(|x| x.1 != per[0].1).unwrap().1 });
            }
        }
        out
    }
    /// P3: every lowering by an honest node that the full closure of a sync ID's bodies holds is
    /// carried there and judged required by its reader from its own holdings.
    pub fn p3(&self, rule: &Rule, st: &State) -> Vec<Fail> {
        let all = self.full(st, &Set::new()).held;
        let mut out = vec![];
        for &s in &self.sids {
            let closure = paths::evidence(&self.w, &self.owed_bodies(st, s), &all);
            let held = &st.entries[&s];
            let req = self.req(rule, s, &st.units, held);
            for &l in &closure {
                if self.removes(l).is_some() && self.nodes[self.by[l]].honest && !req.contains(&l) {
                    out.push(Fail { prop: "P3", step: st.step, sid: s, id: l, reader: None, full: None });
                }
            }
        }
        out
    }
    /// P4: what a sync ID holds is what its reader requires (copies held are a function of the
    /// commits held: nothing outlives the commits it was needed for); and forgetting each content
    /// body changes no other verdict at the reader and leaves nothing only it needed.
    pub fn p4(&self, rule: &Rule, st: &State, forget_each: bool) -> Vec<Fail> {
        let mut out = vec![];
        for &s in &self.sids {
            let held = &st.entries[&s];
            let req = self.req(rule, s, &st.units, held);
            for &i in held.difference(&req) {
                if self.nodes[self.by[i]].honest {
                    out.push(Fail { prop: "P4-held", step: st.step, sid: s, id: i, reader: None, full: None });
                }
            }
        }
        if !forget_each {
            return out;
        }
        for &s in &self.sids {
            let before_v = self.reader(rule, st, s, &Set::new());
            let content: Vec<Id> = self.bodies(s, &st.units, &st.entries[&s]).into_iter().filter(|&i| matches!(self.w.commits[i].kind, Kind::Content)).collect();
            for i in content {
                let mut st2 = st.clone();
                self.forget(rule, &mut st2, i);
                let after_v = self.reader(rule, &st2, s, &Set::new());
                let rest: Set = after_v.held.intersection(&self.bodies(s, &st2.units, &before_v.held)).copied().collect();
                let (a, b) = (self.verdicts(&before_v, &rest), self.verdicts(&after_v, &rest));
                for j in &rest {
                    if a[j] != b[j] {
                        out.push(Fail { prop: "P4-forget", step: st.step, sid: s, id: *j, reader: Some(b[j]), full: Some(a[j]) });
                    }
                }
                let needed_only_by_i = |c: Id| {
                    let others: Set = self.bodies(s, &st2.units, &st2.entries[&s]);
                    !self.req(rule, s, &st2.units, &others.union(&st2.entries[&s]).copied().collect()).contains(&c)
                };
                for &c in st2.entries[&s].iter() {
                    if !st2.units[&s].contains(&self.on(c)) && needed_only_by_i(c) && self.nodes[self.by[c]].honest {
                        out.push(Fail { prop: "P4-grow", step: st.step, sid: s, id: c, reader: None, full: None });
                    }
                }
            }
        }
        out
    }
    /// P5, arrival order: for each body and each strict part of its evidence the reader holds,
    /// the reader missing that part judges the body as the node holding everything but that part
    /// does (`local`, a failure), and counts where it judges (not pending) otherwise than once
    /// everything arrived while some missing part is ordered before the body (`provisional`).
    pub fn p5_order(&self, rule: &Rule, st: &State, cap: usize) -> (Vec<Fail>, usize) {
        let mut out = vec![];
        let mut provisional = 0;
        for &s in &self.sids {
            let held = st.entries[&s].clone();
            let bodies = self.bodies(s, &st.units, &held);
            for &i in &bodies {
                let ev: Vec<Id> = paths::evidence(&self.w, &Set::from([i]), &held).into_iter().filter(|&j| j != i).take(cap).collect();
                let fin = self.verdicts(&self.reader(rule, st, s, &Set::new()), &Set::from([i]))[&i];
                for mask in 1..(1u32 << ev.len()) {
                    let y: Set = ev.iter().enumerate().filter(|(b, _)| mask >> b & 1 == 1).map(|(_, &j)| j).collect();
                    let r = self.verdicts(&self.reader(rule, st, s, &y), &Set::from([i]))[&i];
                    let f = self.verdicts(&self.full(st, &y), &Set::from([i]))[&i];
                    if r != f {
                        out.push(Fail { prop: "P5-order", step: st.step, sid: s, id: i, reader: Some(r), full: Some(f) });
                    }
                    let early = y.iter().any(|&j| self.w.commits[j].ts <= self.w.commits[i].ts);
                    if r != Verdict::Pending && r != fin && early {
                        provisional += 1;
                    }
                }
            }
        }
        (out, provisional)
    }
}

// ---- Worlds ----

pub mod names {
    use super::Thing;
    /// The mint admin of A, its remover.
    pub const X: Thing = 1;
    /// A member signer of A; the thief once removed.
    pub const K: Thing = 2;
    /// Another member signer of A.
    pub const Q: Thing = 3;
    /// A holder K grants on A (vouch worlds).
    pub const Z: Thing = 4;
    /// The mint admin of O, D and R (the organization's side; Risk 4: the raiser).
    pub const Y: Thing = 5;
    /// O's mint admin where O stands apart from Y.
    pub const W: Thing = 6;
    pub const A: Thing = 10;
    pub const O: Thing = 11;
    pub const D: Thing = 12;
    pub const R: Thing = 13;
    /// A dependent of R (no sync ID of its own).
    pub const E: Thing = 14;
}

/// The family's shape (`family`): each field one dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    /// K writes D through [A, O] (O holding write on D) rather than [A].
    pub via_org: bool,
    /// 0: D under its own sync ID only; 1: D in R's unit from the start; 2: D joins R's unit after
    /// K's first write; 3: D leaves R's unit after K's first write; 4: O (on K's path) and D in
    /// R's unit, O leaving after K's first write (as 1 without via_org).
    pub units: u8,
    /// The remover lists K's first write.
    pub listed: bool,
    /// K, stolen, writes D after the removal.
    pub thief: bool,
    /// X re-grants K after the removal.
    pub regrant: bool,
    /// Q's addendum on D lists K's first write.
    pub addendum: bool,
    /// A's role on D (or O's) is read at the removal, raised to write by Y after it (Risk 4);
    /// K's first write is then absent.
    pub raised: bool,
    /// Q syncs D; Q syncs R; Y syncs A (else no honest node syncs both A and Y's things but Q).
    pub q_d: bool,
    pub q_r: bool,
    pub y_a: bool,
    /// O is minted by W, a node syncing O alone, rather than by Y.
    pub org_apart: bool,
    /// K holds admin on A and grants Z write on A after its first write; Z writes D; the removal
    /// does not list the grant and Q (admin) vouches for it.
    pub vouch: bool,
}

pub const FAMILY: usize = 2 * 5 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2;

impl Shape {
    pub fn nth(mut i: usize) -> Shape {
        let mut take = |n: usize| {
            let v = i % n;
            i /= n;
            v
        };
        Shape {
            via_org: take(2) == 1,
            units: take(5) as u8,
            listed: take(2) == 1,
            thief: take(2) == 1,
            regrant: take(2) == 1,
            addendum: take(2) == 1,
            raised: take(2) == 1,
            q_d: take(2) == 1,
            q_r: take(2) == 1,
            y_a: take(2) == 1,
            org_apart: take(2) == 1,
            vouch: take(2) == 1,
        }
    }
}

/// The stolen-node story over units. X mints A (the account; K and Q its members), Y mints D, R
/// and O (or W does); A reaches D directly or through O; K writes D, X removes K, and the shape's
/// other moves. Nodes: X (syncs A), Y (D, R), W (O), Q (A), K (the thief: A, O, D, R), Z; each
/// also syncs what it writes.
pub fn family(sh: Shape) -> World {
    use names::*;
    let pw = paths::World::new(&[(X, A), (if sh.org_apart { W } else { Y }, O), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let x = w.node(true, &[A]);
    let y = w.node(true, &if sh.y_a { vec![D, R, A] } else { vec![D, R] });
    let o = if sh.org_apart { w.node(true, &[O]) } else { y };
    let mut q_syncs = vec![A];
    if sh.q_d {
        q_syncs.push(D);
    }
    if sh.q_r {
        q_syncs.push(R);
    }
    let q = w.node(true, &q_syncs);
    let k = w.node(false, &[A, O, D, R]);
    let path: Vec<Thing> = if sh.via_org { vec![A, O] } else { vec![A] };
    match sh.units {
        1 | 3 => w.member(D, R),
        4 => {
            w.member(D, R);
            if sh.via_org {
                w.member(O, R);
            }
        }
        _ => {}
    }
    let member = if sh.vouch { Role::Admin } else { Role::Write };
    w.write(x, |p| p.edge(X, 1, &[], A, K, member, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, member, &[]));
    let on_d = if sh.raised { Role::Read } else { Role::Write };
    let (holder, last) = if sh.via_org { (O, D) } else { (A, D) };
    if sh.via_org {
        let ow = if sh.org_apart { W } else { Y };
        w.write(o, |p| p.edge(ow, 2, &[], O, A, Role::Write, &[]));
    }
    w.write(y, |p| p.edge(Y, 2, &[], last, holder, on_d, &[]));
    let first = if sh.raised { None } else { Some(w.write(k, |p| p.content(K, 3, &path, D))) };
    match sh.units {
        2 => w.join(D, R),
        3 => w.leave(D, R),
        4 if sh.via_org => w.leave(O, R),
        _ => {}
    }
    let zn = w.node(true, &[]);
    let gz = if sh.vouch { Some(w.write(k, |p| p.edge(K, 4, &[], A, Z, Role::Write, &[]))) } else { None };
    if gz.is_some() {
        w.write(zn, |p| p.content(Z, 5, &path, D));
    }
    let listed: Vec<Id> = if sh.listed { first.into_iter().collect() } else { vec![] };
    let r = w.write(x, |p| p.edge(X, 6, &[], A, K, Role::None, &listed));
    if let Some(gz) = gz {
        w.write(q, |p| p.vouch(Q, 7, &[], A, r, &[gz]));
    }
    if sh.raised {
        w.write(y, |p| p.edge(Y, 7, &[], last, holder, Role::Write, &[]));
    }
    if sh.addendum {
        if let Some(f) = first {
            w.write(q, |p| p.addendum(Q, 7, &path, D, r, &[f]));
        }
    }
    if sh.thief {
        w.write(k, |p| p.content(K, 8, &path, D));
    }
    if sh.regrant {
        w.write(x, |p| p.edge(X, 9, &[], A, K, Role::Write, &[]));
    }
    w
}

/// A random world (sampled searches): the family's cast (X minting A, Y minting D and R, W
/// minting O; members K, Q, Z of A; K the thief), its starting grants at random roles, then `len`
/// moves drawn from: a member's content on D or O along [A] or [A, O] (sometimes backdated), X
/// removing or re-granting a member (a random frontier of what it could have received), K
/// granting Z, Q vouching or writing an addendum against a held removal, Y or W raising or
/// lowering A's or O's edge, retags among the four things; random node sync sets beside each mint admin syncing
/// its things.
pub fn random(seed: u64, len: usize) -> World {
    use names::*;
    let mut rng = roles_model::Rng::thread(seed, 0);
    let pw = paths::World::new(&[(X, A), (W, O), (Y, D), (Y, R)]);
    let mut w = World::new(pw, &[A, O, D, R]);
    let things = [A, O, D, R];
    for &(x, s) in &[(D, R), (O, R), (O, D), (D, O)] {
        if rng.below(3) == 0 {
            w.member(x, s);
        }
    }
    // every sync ID has an honest node syncing it: its mint admin's
    let pick = |rng: &mut roles_model::Rng, mine: &[Thing]| -> Vec<Thing> { things.iter().copied().filter(|t| mine.contains(t) || rng.below(3) == 0).collect() };
    let (x, y, wn, q, z) = (w.node(true, &pick(&mut rng, &[A])), w.node(true, &pick(&mut rng, &[D, R])), w.node(true, &pick(&mut rng, &[O])), w.node(true, &pick(&mut rng, &[])), w.node(true, &pick(&mut rng, &[])));
    let k = w.node(false, &[]);
    let roles = [Role::Read, Role::Write, Role::Admin];
    let up = |rng: &mut roles_model::Rng| roles[1 + rng.below(2)];
    let (rk, rq) = (up(&mut rng), up(&mut rng));
    w.write(x, |p| p.edge(X, 1, &[], A, K, rk, &[]));
    w.write(x, |p| p.edge(X, 1, &[], A, Q, rq, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, A, Role::Write, &[]));
    w.write(wn, |p| p.edge(W, 1, &[], O, A, Role::Write, &[]));
    w.write(y, |p| p.edge(Y, 1, &[], D, O, Role::Write, &[]));
    let mut ts = 2;
    for _ in 0..len {
        ts += rng.below(2) as u32;
        let bts = if rng.below(5) == 0 && ts > 3 { ts - 2 } else { ts };
        let removals: Vec<Id> = (0..w.by.len()).filter(|&j| w.removes(j).is_some_and(|e| e.1 == A)).collect();
        match rng.below(10) {
            0..=2 => {
                let (sg, n) = [(K, k), (Q, q), (Z, z)][rng.below(3)];
                let path: Vec<Thing> = if rng.below(2) == 0 { vec![A] } else { vec![A, O] };
                let on = if path.len() == 1 && rng.below(3) == 0 { O } else { D };
                w.write(n, |p| p.content(sg, bts, &path, on));
            }
            3 | 4 => {
                let m = [K, Q, Z][rng.below(3)];
                let role = if rng.below(2) == 0 { Role::None } else { up(&mut rng) };
                let front: Vec<Id> = (0..w.by.len()).filter(|&j| w.w.hops(j).contains(&(m, A)) && rng.below(2) == 0).collect();
                w.write(x, |p| p.edge(X, bts, &[], A, m, role, if role == Role::None { &front } else { &[] }));
            }
            5 => {
                w.write(k, |p| p.edge(K, bts, &[], A, Z, Role::Write, &[]));
            }
            6 if !removals.is_empty() => {
                let r = removals[rng.below(removals.len())];
                let list: Vec<Id> = (0..w.by.len()).filter(|&j| j != r && rng.below(2) == 0).collect();
                let vouches: Vec<Id> = list.iter().copied().filter(|&j| w.w.edge_class(j) && w.on(j) == A).collect();
                let adds: Vec<Id> = list.iter().copied().filter(|&j| !w.w.edge_class(j) && w.on(j) == D).collect();
                if rng.below(2) == 0 {
                    w.write(q, |p| p.vouch(Q, bts, &[], A, r, &vouches));
                } else {
                    w.write(q, |p| p.addendum(Q, bts, &[A], D, r, &adds));
                }
            }
            7 => {
                let role = [Role::None, Role::Read, Role::Write][rng.below(3)];
                match rng.below(3) {
                    0 => w.write(y, |p| p.edge(Y, bts, &[], D, A, role, &[])),
                    1 => w.write(y, |p| p.edge(Y, bts, &[], D, O, role, &[])),
                    _ => w.write(wn, |p| p.edge(W, bts, &[], O, A, role, &[])),
                };
            }
            _ => {
                let (xx, ss) = (things[rng.below(4)], things[rng.below(4)]);
                if xx != ss {
                    if rng.below(2) == 0 {
                        w.join(xx, ss);
                    } else {
                        w.leave(xx, ss);
                    }
                }
            }
        }
    }
    w
}

// ---- Cost (P6) ----

/// Copies and bodies under D's sync ID after `n` writes by K on D along a path of `k` holder
/// things, `outside` of which lie outside D's unit (the rest in it): each holder thing H_j granted
/// write on the next by X, the last on D.
pub fn cost(n: usize, k: usize, outside: usize) -> (usize, usize) {
    use names::*;
    assert!(outside <= k && k <= 4);
    let hs: Vec<Thing> = (0..k as Thing).map(|j| 20 + j).collect();
    let mut recs: Vec<Edge> = hs.iter().map(|&h| (X, h)).collect();
    recs.push((X, D));
    let pw = paths::World::new(&recs);
    let mut sids = hs.clone();
    sids.push(D);
    let mut w = World::new(pw, &sids);
    for &h in &hs[outside..] {
        w.member(h, D);
    }
    let mut syncs = sids.clone();
    syncs.push(D);
    let x = w.node(true, &syncs);
    if let Some(&h0) = hs.first() {
        w.write(x, |p| p.edge(X, 1, &[], h0, K, Role::Write, &[]));
    }
    for j in 0..k {
        let next = hs.get(j + 1).copied().unwrap_or(D);
        let h = hs[j];
        w.write(x, |p| p.edge(X, 1, &[], next, h, Role::Write, &[]));
    }
    for c in 0..n {
        w.write(x, |p| p.content(if k == 0 { X } else { K }, 2 + c as u32, &hs, D));
    }
    let st = w.run(&Rule::design(), |_| {});
    let copies = w.copies(&st, D).len();
    (copies, st.entries[&D].len() - copies)
}
