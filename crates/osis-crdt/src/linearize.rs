//! Linearization of a sequence (spec/crdt.md §6): the anchor tree with cycles broken, traversed
//! depth-first from HEAD, then the `END` elements. A deterministic function of the state; never
//! recursive, and bounded: each element is demoted at most twice.

use crate::seq::{Anchor, SeqElem};
use crate::stamp::{Dot, Stamp};
use std::collections::{BTreeMap, HashMap};

/// The placement of every placed element (deleted, content-less and bare anchors included).
pub(crate) struct Placement {
    /// Placed elements in order; hidden ones (unknown anchor, §6.1) are absent.
    pub order: Vec<Dot>,
    /// Chosen parent of `order[i]`: `None` for HEAD and `END`.
    pub parent: Vec<Option<Dot>>,
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
    idx: HashMap<&'a Dot, usize>,
    /// Candidate per element: 0 = `cur`, 1 = `prev`, 2 = `END` (§6.2).
    cand: Vec<u8>,
}

impl Graph<'_> {
    fn edge(&self, i: usize) -> Edge {
        let c = self.cand.get(i).copied().unwrap_or(2);
        let Some((_, a)) = self.pos.get(i).and_then(|p| p.get(usize::from(c))) else { return Edge::End };
        match a {
            Anchor::Head => Edge::Head,
            Anchor::Dot(x) => match self.idx.get(x) {
                Some(j) => Edge::Node(*j),
                // unknown anchor: hidden on `cur`, `END` on `prev` (§6.2 step 3)
                None if c == 0 => Edge::Hidden,
                None => Edge::End,
            },
        }
    }
    fn parent(&self, i: usize) -> Option<usize> {
        match self.edge(i) {
            Edge::Node(j) => Some(j),
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
        Some(v)
    }
}

/// Places the elements of a sequence (§6).
pub(crate) fn place(elems: &BTreeMap<Dot, SeqElem>) -> Placement {
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
    let mut g = Graph { dots: Vec::with_capacity(real + virt.len()), pos: Vec::with_capacity(real + virt.len()), idx: HashMap::new(), cand: Vec::new() };
    for (d, e) in elems {
        g.dots.push(d);
        g.pos.push(&e.pos);
    }
    for d in virt {
        g.dots.push(d);
        g.pos.push(&[]);
    }
    g.idx = g.dots.iter().enumerate().map(|(i, d)| (*d, i)).collect();
    g.cand = vec![0; g.dots.len()];
    break_cycles(&mut g);
    traverse(&g, real)
}

/// Demotes edges until the parent graph is acyclic (§6.2). Cycles are vertex-disjoint; after the
/// first whole scan only a demoted element's new edge can close a cycle, so later rounds walk from
/// the victims only.
fn break_cycles(g: &mut Graph) {
    let n = g.dots.len();
    // whole scan: colour 0 unvisited, 1 on the current walk, 2 done
    let mut colour = vec![0u8; n];
    let mut at = vec![0usize; n];
    let mut victims = Vec::new();
    for start in 0..n {
        if colour.get(start) != Some(&0) {
            continue;
        }
        let mut path = Vec::new();
        let mut cur = start;
        loop {
            match colour.get(cur) {
                Some(1) => {
                    let from = at.get(cur).copied().unwrap_or(0);
                    if let Some(v) = path.get(from..).and_then(|c: &[usize]| g.demote(c)) {
                        victims.push(v);
                    }
                    break;
                }
                Some(0) => {}
                _ => break,
            }
            if let Some(c) = colour.get_mut(cur) {
                *c = 1;
            }
            if let Some(a) = at.get_mut(cur) {
                *a = path.len();
            }
            path.push(cur);
            match g.parent(cur) {
                Some(p) => cur = p,
                None => break,
            }
        }
        for i in path {
            if let Some(c) = colour.get_mut(i) {
                *c = 2;
            }
        }
    }
    // later rounds: a new cycle passes through a victim of the previous round
    let mut seen = vec![0usize; n];
    let mut walk = 0usize;
    while !victims.is_empty() {
        let mut next = Vec::new();
        for v in std::mem::take(&mut victims) {
            walk += 1;
            let mut path = Vec::new();
            let mut cur = v;
            loop {
                if seen.get(cur) == Some(&walk) {
                    if cur == v
                        && let Some(x) = g.demote(&path)
                    {
                        next.push(x);
                    }
                    break;
                }
                if let Some(s) = seen.get_mut(cur) {
                    *s = walk;
                }
                path.push(cur);
                match g.parent(cur) {
                    Some(p) => cur = p,
                    None => break,
                }
            }
        }
        victims = next;
    }
}

/// Depth-first from HEAD (children greatest stamp first), then the `END` elements by dot with
/// their subtrees (§6.1, §6.2 step 3). Only the first `real` nodes are emitted.
fn traverse(g: &Graph, real: usize) -> Placement {
    let n = g.dots.len();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut head = Vec::new();
    let mut ends = Vec::new();
    for i in 0..n {
        match g.edge(i) {
            Edge::Head => head.push(i),
            Edge::End => ends.push(i),
            Edge::Node(j) => {
                if let Some(c) = children.get_mut(j) {
                    c.push(i);
                }
            }
            Edge::Hidden => {}
        }
    }
    let by_stamp = |a: &usize, b: &usize| g.stamp(*b).cmp(&g.stamp(*a)).then_with(|| g.dots.get(*a).cmp(&g.dots.get(*b)));
    head.sort_by(by_stamp);
    for c in children.iter_mut() {
        c.sort_by(by_stamp);
    }
    ends.sort_by(|a, b| g.dots.get(*a).cmp(&g.dots.get(*b)));
    let mut stack: Vec<usize> = ends.into_iter().rev().collect();
    stack.extend(head.into_iter().rev());
    let mut done = vec![false; n];
    let mut out = Placement { order: Vec::with_capacity(real), parent: Vec::with_capacity(real) };
    while let Some(i) = stack.pop() {
        match done.get_mut(i) {
            Some(d) if !*d => *d = true,
            _ => continue,
        }
        if i < real
            && let Some(d) = g.dots.get(i)
        {
            out.order.push((*d).clone());
            out.parent.push(g.parent(i).and_then(|p| g.dots.get(p)).map(|p| (*p).clone()));
        }
        if let Some(cs) = children.get(i) {
            stack.extend(cs.iter().rev());
        }
    }
    out
}
