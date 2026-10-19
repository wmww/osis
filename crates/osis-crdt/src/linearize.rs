//! Linearization of a sequence (spec/crdt.md §6): the anchor tree with cycles broken, traversed
//! depth-first from HEAD, then the `END` elements. A deterministic function of the state; never
//! recursive, and bounded: each element is demoted at most twice. Works on indices into the
//! dot-ordered records (anchors resolve by binary search), so a pass is a few linear sweeps and
//! one sort of each sibling list.

use crate::seq::{Anchor, SeqElem};
use crate::stamp::{Dot, Stamp};
use std::collections::BTreeMap;

/// The placement of every placed element (deleted, content-less and bare anchors included).
pub(crate) struct Placement {
    /// Placed elements in order; hidden ones (unknown anchor, §6.1) are absent.
    pub order: Vec<Dot>,
    /// Chosen parent of `order[i]`: `None` for HEAD and `END`.
    pub parent: Vec<Option<Dot>>,
}

/// Placement by index: node `i < real` is the `i`-th record in dot order, the rest are virtual
/// `Derived` anchors.
pub(crate) struct Placed<'a> {
    pub dots: Vec<&'a Dot>,
    pub elems: Vec<&'a SeqElem>,
    /// Placed real nodes in order.
    pub order: Vec<usize>,
    /// Chosen parent node per node.
    pub parent: Vec<Option<usize>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Edge {
    Head,
    Node(usize),
    Hidden,
    End,
}

struct Graph<'a> {
    dots: Vec<&'a Dot>,
    pos: Vec<&'a [(Stamp, Anchor)]>,
    real: usize,
    /// Candidate per element: 0 = `cur`, 1 = `prev`, 2 = `END` (§6.2).
    cand: Vec<u8>,
    edge: Vec<Edge>,
}

impl Graph<'_> {
    fn lookup(&self, x: &Dot) -> Option<usize> {
        let (real, virt) = self.dots.split_at(self.real);
        real.binary_search(&x).ok().or_else(|| virt.binary_search(&x).ok().map(|j| self.real + j))
    }
    fn compute(&self, i: usize) -> Edge {
        let c = self.cand.get(i).copied().unwrap_or(2);
        let Some((_, a)) = self.pos.get(i).and_then(|p| p.get(usize::from(c))) else { return Edge::End };
        match a {
            Anchor::Head => Edge::Head,
            Anchor::Dot(x) => match self.lookup(x) {
                Some(j) => Edge::Node(j),
                // unknown anchor: hidden on `cur`, `END` on `prev` (§6.2 step 3)
                None if c == 0 => Edge::Hidden,
                None => Edge::End,
            },
        }
    }
    fn parent(&self, i: usize) -> Option<usize> {
        match self.edge.get(i) {
            Some(Edge::Node(j)) => Some(*j),
            _ => None,
        }
    }
    /// Stamp of the chosen edge (`None` on `END`).
    fn stamp(&self, i: usize) -> Option<&Stamp> {
        let c = usize::from(self.cand.get(i).copied().unwrap_or(2));
        self.pos.get(i).and_then(|p| p.get(c)).map(|p| &p.0)
    }
    /// Demotes the element of `cycle` whose current edge has the smallest stamp (§6.2 step 2).
    fn demote(&mut self, cycle: &[usize]) -> Option<usize> {
        let v = *cycle.iter().min_by(|a, b| self.stamp(**a).cmp(&self.stamp(**b)).then_with(|| self.dots.get(**a).cmp(&self.dots.get(**b))))?;
        let has_prev = self.pos.get(v).is_some_and(|p| p.len() > 1);
        if let Some(c) = self.cand.get_mut(v) {
            *c = if *c == 0 && has_prev { 1 } else { 2 };
        }
        let e = self.compute(v);
        if let Some(x) = self.edge.get_mut(v) {
            *x = e;
        }
        Some(v)
    }
}

/// Places the elements of a sequence (§6), by index.
pub(crate) fn place_idx(elems: &BTreeMap<Dot, SeqElem>) -> Placed<'_> {
    // anchors naming a `Derived` dot not in the state are bare anchors at END (§6.1)
    let mut virt: Vec<&Dot> = elems
        .values()
        .flat_map(|e| e.pos.iter())
        .filter_map(|(_, a)| match a {
            Anchor::Dot(d) if d.src.is_derived() && !elems.contains_key(d) => Some(d),
            _ => None,
        })
        .collect();
    virt.sort();
    virt.dedup();
    let real = elems.len();
    let n = real + virt.len();
    let mut g = Graph { dots: Vec::with_capacity(n), pos: Vec::with_capacity(n), real, cand: vec![0; n], edge: Vec::new() };
    let mut refs = Vec::with_capacity(real);
    for (d, e) in elems {
        g.dots.push(d);
        g.pos.push(&e.pos);
        refs.push(e);
    }
    for d in virt {
        g.dots.push(d);
        g.pos.push(&[]);
    }
    g.edge = (0..n).map(|i| g.compute(i)).collect();
    break_cycles(&mut g);
    let (order, parent) = traverse(&g);
    Placed { dots: g.dots, elems: refs, order, parent }
}

/// Places the elements of a sequence (§6), by dot.
pub(crate) fn place(elems: &BTreeMap<Dot, SeqElem>) -> Placement {
    let p = place_idx(elems);
    let dot = |i: usize| p.dots.get(i).map(|d| (*d).clone());
    Placement {
        order: p.order.iter().filter_map(|i| dot(*i)).collect(),
        parent: p.order.iter().map(|i| p.parent.get(*i).copied().flatten().and_then(dot)).collect(),
    }
}

/// Demotes edges until the parent graph is acyclic (§6.2). Cycles are vertex-disjoint and each
/// demotion is forced, so any walk may demote the cycle it finds. A node whose parent path ends at
/// HEAD, END or a hidden anchor is on no cycle and only cycle members change edges, so that mark
/// persists; within a round every node is walked once. Later rounds start from the victims, the
/// only nodes whose new edge can close a cycle.
fn break_cycles(g: &mut Graph) {
    let n = g.dots.len();
    let mut term = vec![false; n];
    let mut mark = vec![0usize; n];
    let mut at = vec![0usize; n];
    let mut path: Vec<usize> = Vec::new();
    let mut starts: Vec<usize> = (0..n).collect();
    let mut round = 0usize;
    while !starts.is_empty() {
        round += 1;
        let mut victims = Vec::new();
        for s in std::mem::take(&mut starts) {
            path.clear();
            let mut cur = s;
            let reached = loop {
                if term.get(cur) != Some(&false) {
                    break true;
                }
                if mark.get(cur) == Some(&round) {
                    // seen this round: on this walk it closes a cycle, else an earlier walk settled it
                    let k = at.get(cur).copied().unwrap_or(usize::MAX);
                    if path.get(k) == Some(&cur) {
                        let cyc: Vec<usize> = path.get(k..).map(<[usize]>::to_vec).unwrap_or_default();
                        if let Some(v) = g.demote(&cyc) {
                            victims.push(v);
                        }
                    }
                    break false;
                }
                if let Some(m) = mark.get_mut(cur) {
                    *m = round;
                }
                if let Some(a) = at.get_mut(cur) {
                    *a = path.len();
                }
                path.push(cur);
                match g.parent(cur) {
                    Some(p) => cur = p,
                    None => break true,
                }
            };
            if reached {
                for i in &path {
                    if let Some(t) = term.get_mut(*i) {
                        *t = true;
                    }
                }
            }
        }
        starts = victims;
    }
}


/// Depth-first from HEAD (children greatest stamp first), then the `END` elements by dot with
/// their subtrees (§6.1, §6.2 step 3). Returns the placed real nodes and every node's parent.
fn traverse(g: &Graph) -> (Vec<usize>, Vec<Option<usize>>) {
    let n = g.dots.len();
    // children lists in one array (HEAD is slot n, END slot n + 1)
    let slot = |e: Edge| match e {
        Edge::Node(j) => Some(j),
        Edge::Head => Some(n),
        Edge::End => Some(n + 1),
        Edge::Hidden => None,
    };
    let mut start = vec![0usize; n + 3];
    for e in &g.edge {
        if let Some(s) = slot(*e).and_then(|s| start.get_mut(s + 1)) {
            *s += 1;
        }
    }
    for k in 1..start.len() {
        let prev = start.get(k - 1).copied().unwrap_or(0);
        if let Some(s) = start.get_mut(k) {
            *s += prev;
        }
    }
    let mut fill = start.clone();
    let mut kids = vec![0usize; start.last().copied().unwrap_or(0)];
    for (i, e) in g.edge.iter().enumerate() {
        if let Some(f) = slot(*e).and_then(|s| fill.get_mut(s)) {
            if let Some(k) = kids.get_mut(*f) {
                *k = i;
            }
            *f += 1;
        }
    }
    let range = |s: usize| start.get(s).copied().unwrap_or(0)..start.get(s + 1).copied().unwrap_or(0);
    for s in 0..=n {
        if let Some(c) = kids.get_mut(range(s)).filter(|c| c.len() > 1) {
            c.sort_by(|a, b| g.stamp(*b).cmp(&g.stamp(*a)).then_with(|| g.dots.get(*a).cmp(&g.dots.get(*b))));
        }
    }
    // END elements by dot ascending: node indices are already in dot order per part
    if let Some(c) = kids.get_mut(range(n + 1)) {
        c.sort_by(|a, b| g.dots.get(*a).cmp(&g.dots.get(*b)));
    }
    let mut stack: Vec<usize> = kids.get(range(n + 1)).unwrap_or_default().iter().rev().copied().collect();
    stack.extend(kids.get(range(n)).unwrap_or_default().iter().rev());
    let mut done = vec![false; n];
    let mut order = Vec::with_capacity(g.real);
    while let Some(i) = stack.pop() {
        match done.get_mut(i) {
            Some(d) if !*d => *d = true,
            _ => continue,
        }
        if i < g.real {
            order.push(i);
        }
        stack.extend(kids.get(range(i)).unwrap_or_default().iter().rev());
    }
    let parent = (0..n).map(|i| g.parent(i)).collect();
    (order, parent)
}
