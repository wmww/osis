//! Greenfield model of the per-part strip (notes/whole-commits.md, Strip): one commit's blobs under
//! one sync ID S, held by readers of S and a store K keeping S unread, while parts of the commit
//! become gone (a purge request, a covering snapshot past its bounds) at the nodes that read them.
//!
//! - `World`: the commit's parts, the ones in S's body (every reader of S opens those) and the
//!   others (sections of things outside S's sync unit, opened only by nodes reading them
//!   elsewhere), the parts that go, and per node what it opens, which delete keys it holds and
//!   whether it writes S.
//! - The protocol (`Net`), per node, from its own view alone: a blob holding an opened gone part
//!   is must-not-hold (it leaves the own log once the rest is logged as the rewrite; a key holder
//!   deletes it at K once K shows a carrier of each live body part); of two blobs with the same
//!   body parts, fewer sections wins in the own log (deleted at K only when identical, the higher
//!   ID); a blob lacking a body part another blob carries, that the node still needs, is
//!   redundant (deleted at K). A node logs a body again at K once per change of its ground (§4).
//! - The oracle reads the history alone: what each store must hold at quiescence.
//!
//! Abstracted: a part is one section; gone is final (no fall); a cover's snapshot is no blob
//! here (the carrier of a covered part is outside the commit); every node is honest; the ground
//! of a body part (its request or snapshot) travels under S with the deletes it causes
//! (spec/sync-judgement.md §3 Role entries first) when `World::ground_under_s`.
use crate::gen::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub type P = usize;
pub type Parts = BTreeSet<P>;

#[derive(Clone, Debug)]
pub struct World {
    pub parts: usize,
    /// S's body: the parts S's actor reads. Every reader of S opens them.
    pub body: Parts,
    /// The parts that go (purged, or covered past their bounds).
    pub gone: Parts,
    /// Per node: the parts it opens (the body and some others).
    pub reads: Vec<Parts>,
    /// Per node: the parts whose delete keys it holds (a Delete of a blob needs every part's).
    pub keys: Vec<Parts>,
    pub writer: Vec<bool>,
    /// The ground of a gone body part travels under S: a node learns it from K before acting
    /// there (Role entries first).
    pub ground_under_s: bool,
}

/// Rules the protocol may leave out, to see what each one holds up.
#[derive(Clone, Copy, Debug, Default)]
pub struct Off {
    /// Delete a must-not-hold blob at K without a carrier shown there.
    pub carriers: bool,
    /// The own log's blob keeps a section it cannot open that any held blob carries (not only
    /// one every held blob carries).
    pub fewer: bool,
    /// Log a body again at K on every exchange (no stand per change of ground).
    pub stand: bool,
    /// Delete at K a blob that only differs in sections this node cannot open.
    pub sealed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Node learns that a part it opens is gone.
    Learn(usize, P),
    /// Node exchanges with K.
    Exchange(usize),
    /// Node pulls another reader's own log.
    Pull(usize, usize),
}

#[derive(Clone, Debug, Default)]
struct Store {
    blobs: BTreeMap<u32, Parts>,
    tomb: BTreeSet<u32>,
}

#[derive(Clone, Debug)]
struct NodeState {
    own: Store,
    gone: Parts,
    /// §4: the ground (gone parts known) at which it last logged the body again at K.
    stand: Option<usize>,
}

pub struct Net<'a> {
    w: &'a World,
    off: Off,
    nodes: Vec<NodeState>,
    k: Store,
    /// Gone body parts whose ground K holds.
    k_gone: Parts,
    next: u32,
    pub steps: u64,
}

impl<'a> Net<'a> {
    pub fn new(w: &'a World, off: Off) -> Net<'a> {
        let whole: Parts = (0..w.parts).collect();
        let store = Store { blobs: [(0, whole)].into_iter().collect(), tomb: BTreeSet::new() };
        let nodes = (0..w.reads.len()).map(|_| NodeState { own: store.clone(), gone: Parts::new(), stand: None }).collect();
        Net { w, off, nodes, k: store, k_gone: Parts::new(), next: 1, steps: 0 }
    }

    fn need(&self, n: usize) -> Parts {
        self.w.body.difference(&self.nodes[n].gone).copied().collect()
    }

    fn stale(&self, n: usize, b: &Parts) -> bool {
        b.iter().any(|p| self.w.reads[n].contains(p) && self.nodes[n].gone.contains(p))
    }

    /// Blob `id` (`b`) at K is redundant beside the others of `set` in n's view, so n deletes it:
    /// another carries every body part it does and either a needed one more, or the same with
    /// fewer sections, each of the extra ones opened here (`Off::sealed`: any), or the same
    /// sections and a lower ID.
    fn redundant(&self, n: usize, id: u32, b: &Parts, set: &BTreeMap<u32, Parts>) -> bool {
        let need = self.need(n);
        let body = |x: &Parts| -> Parts { x.intersection(&self.w.body).copied().collect() };
        set.iter().filter(|(i, x)| **i != id && !self.stale(n, x)).any(|(i, x)| {
            let (bb, bx) = (body(b), body(x));
            if !bb.is_subset(&bx) {
                return false;
            }
            if bx.difference(&bb).any(|p| need.contains(p)) {
                return true;
            }
            if bb != bx {
                return false;
            }
            if x == b {
                return *i < id;
            }
            if !x.is_subset(b) {
                return false;
            }
            self.off.sealed || b.difference(x).all(|p| self.w.reads[n].contains(p))
        })
    }

    /// The blob n's own log holds of the commit: every part n opens in a held blob and does not
    /// know gone, and every section it cannot open that each held blob carries (`Off::fewer`:
    /// that any held blob carries). `None`: it lacks a part it needs.
    fn target(&self, n: usize) -> Option<Parts> {
        let st = &self.nodes[n];
        let reads = &self.w.reads[n];
        let blobs: Vec<&Parts> = st.own.blobs.values().collect();
        let all: Parts = blobs.iter().copied().flatten().copied().collect();
        let t: Parts = all
            .into_iter()
            .filter(|p| match reads.contains(p) {
                true => !st.gone.contains(p),
                false => self.off.fewer || blobs.iter().all(|b| b.contains(p)),
            })
            .collect();
        let need = self.need(n);
        (!need.is_empty() && need.is_subset(&t)).then_some(t)
    }

    fn fresh(&mut self) -> u32 {
        self.next += 1;
        self.next - 1
    }

    /// The own log settles to its target: a held blob equal to it stands (the lowest ID), else a
    /// fresh encryption of it is logged; every other blob leaves (tombstoned). With no body part
    /// needed, every blob leaves.
    fn settle(&mut self, n: usize) {
        // nothing of S's body needed here: nothing under S is this node's to log
        if self.need(n).is_empty() {
            let all: Vec<u32> = self.nodes[n].own.blobs.keys().copied().collect();
            for i in all {
                self.nodes[n].own.blobs.remove(&i);
                self.nodes[n].own.tomb.insert(i);
            }
            return;
        }
        let Some(t) = self.target(n) else { return };
        let id = match self.nodes[n].own.blobs.iter().find(|(_, b)| **b == t) {
            Some((id, _)) => *id,
            None => {
                let id = self.fresh();
                self.nodes[n].own.blobs.insert(id, t.clone());
                id
            }
        };
        let others: Vec<u32> = self.nodes[n].own.blobs.keys().copied().filter(|i| *i != id).collect();
        for i in others {
            self.nodes[n].own.blobs.remove(&i);
            self.nodes[n].own.tomb.insert(i);
        }
    }

    fn take(&mut self, n: usize, from: &BTreeMap<u32, Parts>) {
        for (id, b) in from {
            if !self.nodes[n].own.tomb.contains(id) && !self.nodes[n].own.blobs.contains_key(id) && !self.stale(n, b) {
                self.nodes[n].own.blobs.insert(*id, b.clone());
            }
        }
        self.settle(n);
    }

    pub fn step(&mut self, e: Event) {
        self.steps += 1;
        match e {
            Event::Learn(n, p) => {
                if self.w.reads[n].contains(&p) && self.w.gone.contains(&p) {
                    self.nodes[n].gone.insert(p);
                    self.settle(n);
                }
            }
            Event::Pull(n, m) => {
                let from = self.nodes[m].own.blobs.clone();
                self.take(n, &from);
            }
            Event::Exchange(n) => self.exchange(n),
        }
    }

    fn exchange(&mut self, n: usize) {
        if self.w.ground_under_s {
            let body_gone: Parts = self.nodes[n].gone.intersection(&self.w.body).copied().collect();
            self.k_gone.extend(body_gone);
            let learnt: Parts = self.k_gone.iter().filter(|p| self.w.reads[n].contains(p)).copied().collect();
            if !learnt.is_subset(&self.nodes[n].gone) {
                self.nodes[n].gone.extend(learnt);
                self.settle(n);
            }
        }
        let kb = self.k.blobs.clone();
        self.take(n, &kb);
        // K takes n's own log
        let own = self.nodes[n].own.blobs.clone();
        for (id, b) in &own {
            if !self.k.tomb.contains(id) {
                self.k.blobs.entry(*id).or_insert_with(|| b.clone());
            }
        }
        // deletes at K
        let need = self.need(n);
        let kb = self.k.blobs.clone();
        for (id, b) in &kb {
            if !b.is_subset(&self.w.keys[n]) {
                continue;
            }
            let carried = |s: &Self| need.is_disjoint(b) || kb.iter().filter(|(i, x)| *i != id && s.k.blobs.contains_key(i) && !s.stale(n, x)).any(|(_, x)| need.intersection(b).all(|p| x.contains(p)));
            let go = (self.stale(n, b) && (self.off.carriers || carried(self))) || self.redundant(n, *id, b, &self.k.blobs.clone());
            if go {
                self.k.blobs.remove(id);
                self.k.tomb.insert(*id);
            }
        }
        // §4: every own blob deleted there and K short of what n needs: logged again once per
        // change of ground
        let ground = self.nodes[n].gone.len();
        let k_carries = self.k.blobs.values().filter(|b| !self.stale(n, b)).any(|b| need.is_subset(b));
        if !k_carries && (self.off.stand || self.nodes[n].stand != Some(ground)) {
            if let Some(r) = self.target(n) {
                let id = self.fresh();
                self.nodes[n].stand = Some(ground);
                self.nodes[n].own.blobs.insert(id, r.clone());
                self.k.blobs.insert(id, r);
                self.settle(n);
            }
        }
    }

    /// Every live body part is carried at K: no delete leaves K without one.
    pub fn k_carries_live(&self) -> bool {
        self.w.body.difference(&self.w.gone).all(|p| self.k.blobs.values().any(|b| b.contains(p)))
    }

    fn fingerprint(&self) -> Vec<(Vec<u32>, Parts)> {
        let mut out: Vec<(Vec<u32>, Parts)> = self.nodes.iter().map(|s| (s.own.blobs.keys().copied().collect(), s.gone.clone())).collect();
        out.push((self.k.blobs.keys().copied().collect(), self.k_gone.clone()));
        out
    }
}

/// What the oracle says of a store at quiescence, from the world alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Diff {
    /// A live body part lost at K.
    LostAtK,
    /// No quiescence within the bound.
    NoQuiet,
    /// A node's own log holds a blob with a part it knows gone, or not one blob (none where S's
    /// whole body is gone).
    OwnLog(usize, Vec<Parts>),
    /// K holds a blob carrying a gone part that a node opening it, holding every key it needs and
    /// writing S, could have deleted; or two blobs where such a node could have deleted one.
    AtK(Vec<Parts>),
}

pub fn world(r: &mut Rng, nodes: usize, parts: usize) -> World {
    let body_n = 1 + r.below(parts as u64) as usize;
    let body: Parts = (0..body_n).collect();
    let gone: Parts = (0..parts).filter(|_| r.chance(40)).collect();
    let reads = (0..nodes).map(|_| (0..parts).filter(|p| body.contains(p) || r.chance(50)).collect()).collect();
    let keys = (0..nodes).map(|_| (0..parts).filter(|_| r.chance(70)).collect()).collect();
    let writer = (0..nodes).map(|_| r.chance(70)).collect();
    World { parts, body, gone, reads, keys, writer, ground_under_s: r.chance(70) }
}

pub fn history(r: &mut Rng, w: &World, len: usize) -> Vec<Event> {
    let n = w.reads.len();
    let mut learn: Vec<Event> = (0..n).flat_map(|i| w.gone.iter().filter(move |p| w.reads[i].contains(p)).map(move |p| Event::Learn(i, *p))).collect();
    r.shuffle(&mut learn);
    let mut out = Vec::new();
    for _ in 0..len {
        if !learn.is_empty() && r.chance(30) {
            out.push(learn.remove(0));
        } else if r.chance(60) {
            out.push(Event::Exchange(r.below(n as u64) as usize));
        } else {
            out.push(Event::Pull(r.below(n as u64) as usize, r.below(n as u64) as usize));
        }
    }
    out.extend(learn);
    out
}

/// Plays `h`, checks K never loses a live part, then runs every node against K and each other to
/// quiescence and compares with the oracle.
pub fn run(w: &World, h: &[Event], off: Off) -> Result<(), Diff> {
    let mut net = Net::new(w, off);
    for e in h {
        net.step(*e);
        if !net.k_carries_live() {
            return Err(Diff::LostAtK);
        }
    }
    let n = w.reads.len();
    let mut quiet = false;
    for _ in 0..50 {
        let before = net.fingerprint();
        for i in 0..n {
            net.step(Event::Exchange(i));
            for j in 0..n {
                net.step(Event::Pull(i, j));
            }
            if !net.k_carries_live() {
                return Err(Diff::LostAtK);
            }
        }
        if net.fingerprint() == before {
            quiet = true;
            break;
        }
    }
    if !quiet {
        return Err(Diff::NoQuiet);
    }
    for i in 0..n {
        let blobs: Vec<Parts> = net.nodes[i].own.blobs.values().cloned().collect();
        let known: Parts = w.gone.intersection(&w.reads[i]).copied().collect();
        let want = usize::from(!w.body.is_subset(&w.gone));
        if blobs.len() != want || blobs.iter().any(|b| !b.is_disjoint(&known)) {
            return Err(Diff::OwnLog(i, blobs));
        }
    }
    let at_k: Vec<Parts> = net.k.blobs.values().cloned().collect();
    let could = |b: &Parts, p: &P| (0..n).any(|i| w.writer[i] && w.reads[i].contains(p) && b.is_subset(&w.keys[i]));
    if at_k.iter().any(|b| b.intersection(&w.gone).any(|p| could(b, p))) {
        return Err(Diff::AtK(at_k));
    }
    // two at K where a node holding every key of the one that should go could delete it
    if at_k.len() > 1 {
        let wanted: Parts = (0..w.parts).filter(|p| !w.gone.contains(p)).collect();
        let sole = at_k.iter().filter(|b| **b == wanted).count() == 1;
        let deletable = at_k.iter().filter(|b| **b != wanted).all(|b| (0..n).any(|i| b.is_subset(&w.keys[i]) && b.difference(&wanted).all(|p| w.reads[i].contains(p))));
        if sole && deletable {
            return Err(Diff::AtK(at_k));
        }
    }
    Ok(())
}
