//! The cached placement of a sequence (spec/crdt.md §6): built by one whole pass
//! (`linearize::place_idx`), then followed through joins that add elements or change flags and
//! content; any other change drops it and the next use rebuilds it.
//!
//! A new element anchored at HEAD or at a single-element record is the first child of its
//! anchor when its edge stamp beats every existing child's, so in depth-first order it comes
//! right after the anchor. It closes no cycle (nothing anchors at it unless a write waits for
//! its dot, which falls back), so no demotion changes. A flag or content write moves nothing;
//! only visibility changes. Everything else (moves, resets, range splits, an older concurrent
//! insert below newer siblings, `Derived` dots) falls back to a whole pass.

use crate::linearize::{Placement, place_idx};
use crate::seq::{Anchor, SeqElem, is_visible};
use crate::seq_span::{Elems, elem, find};
use crate::stamp::{Dot, Stamp};
use std::collections::{HashMap, HashSet};

/// Flag writes of one delta followed one by one (a scan each); more take one pass.
const FLAG_SCANS: usize = 8;
/// Runs of new elements one delta may splice in (a scan each); more rebuild.
const RUN_SCANS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Lin {
    pub p: Placement,
    /// Whether node `p.order[i]` is visible.
    shown: Vec<bool>,
    /// Visible elements in order.
    pub vis: Vec<Dot>,
    /// Anchors naming no element.
    waiting: HashSet<Dot>,
}

/// How the cache follows one record of a delta, decided against the state before it joins.
pub(crate) enum Plan {
    /// A new element created at `anchor`; whether the anchor's element is held.
    New { stamp: Stamp, anchor: Anchor, known: bool },
    /// Flag or content writes to the record of this span, whose position writes and creation
    /// stay as they were.
    Flags { span: u64, pos: Vec<(Stamp, Anchor)>, created: bool },
}

impl Lin {
    pub(crate) fn build(elems: &Elems, text: bool) -> Lin {
        let placed = place_idx(elems);
        let p = Placement::of(&placed);
        let shown = placed.order.iter().filter_map(|i| placed.nodes.get(*i)).map(|n| is_visible(&n.elem, text)).collect::<Vec<_>>();
        let vis = p.order.iter().zip(&shown).filter(|(_, s)| **s).map(|(d, _)| d.clone()).collect();
        Lin { p, shown, vis, waiting: placed.waiting }
    }

    /// The plan for joining record `(dot, de)` into `elems`; `None`: rebuild.
    pub(crate) fn plan(&self, elems: &Elems, dot: &Dot, de: &SeqElem) -> Option<Plan> {
        match find(elems, dot) {
            None => {
                if de.span != 1 || dot.src.is_derived() {
                    return None;
                }
                let (stamp, anchor) = de.created.clone()?;
                if de.pos.len() != 1 || de.pos.first().is_none_or(|(s, a)| *s != stamp || *a != anchor) {
                    return None;
                }
                let known = match &anchor {
                    Anchor::Head => true,
                    Anchor::Dot(x) if x.src.is_derived() => return None,
                    Anchor::Dot(x) => match find(elems, x) {
                        Some((_, r)) if r.span != 1 => return None,
                        r => r.is_some(),
                    },
                };
                Some(Plan::New { stamp, anchor, known })
            }
            Some((k, r)) => {
                if k != dot || r.span != de.span || de.created.as_ref().is_some_and(|c| r.created.as_ref() != Some(c)) {
                    return None;
                }
                if !de.pos.iter().all(|p| r.pos.iter().any(|q| q.0 == p.0)) {
                    return None;
                }
                Some(Plan::Flags { span: r.span, pos: r.pos.clone(), created: r.created.is_some() })
            }
        }
    }

    /// Follows a joined delta by its records' plans, in dot order; `false`: rebuild. New
    /// elements are spliced in as runs after the existing node they follow (one scan per run),
    /// flag and content writes flip visibility.
    pub(crate) fn follow(&mut self, elems: &Elems, text: bool, plans: Vec<(Dot, Plan)>) -> bool {
        // runs of new elements by the existing node (`None`: HEAD) they follow, with the first
        // element's edge stamp
        let mut runs: Vec<(Option<Dot>, Stamp, Vec<Dot>)> = Vec::new();
        // the run holding each new element; `None`: hidden
        let mut new: HashMap<Dot, Option<usize>> = HashMap::new();
        let mut flags: Vec<Dot> = Vec::new();
        for (dot, plan) in plans {
            let Some(r) = elems.get(&dot) else { return false };
            match plan {
                Plan::New { stamp, anchor, known } => {
                    // a write waiting for this dot now gets placed: rebuild
                    if r.span != 1 || r.pos.len() != 1 || r.pos.first().is_none_or(|(s, a)| *s != stamp || *a != anchor) || self.waiting.contains(&dot) {
                        return false;
                    }
                    let key = match anchor {
                        Anchor::Head => None,
                        Anchor::Dot(x) => Some(x),
                    };
                    if !known {
                        // hidden until its anchor arrives (§6.1)
                        self.waiting.extend(key);
                        new.insert(dot, None);
                        continue;
                    }
                    let run = match key.as_ref().and_then(|x| new.get(x)) {
                        // below a hidden new element
                        Some(None) => None,
                        // right after a new element, which must end its run
                        Some(Some(i)) => {
                            let Some((_, _, run)) = runs.get_mut(*i) else { return false };
                            if run.last() != key.as_ref() {
                                return false;
                            }
                            run.push(dot.clone());
                            Some(*i)
                        }
                        // the first child of an existing node: a run of its own
                        None => {
                            if runs.len() >= RUN_SCANS || runs.iter().any(|(k, _, _)| *k == key) {
                                return false;
                            }
                            runs.push((key, stamp, vec![dot.clone()]));
                            Some(runs.len() - 1)
                        }
                    };
                    new.insert(dot, run);
                }
                Plan::Flags { span, pos, created } => {
                    if r.span != span || r.pos != pos || r.created.is_some() != created {
                        return false;
                    }
                    // a range record has no content: never visible
                    if span == 1 {
                        flags.push(dot);
                    }
                }
            }
        }
        for (key, stamp, run) in runs {
            let at = match &key {
                None => 0,
                Some(x) => match self.p.order.iter().position(|d| d == x) {
                    Some(i) => i + 1,
                    // below a hidden node: hidden too
                    None => continue,
                },
            };
            // the anchor's first child in the order has the greatest edge stamp of its children
            if self.child_stamp(elems, at, &key).is_some_and(|c| c >= stamp) {
                return false;
            }
            let shown: Vec<bool> = run.iter().map(|d| elems.get(d).is_some_and(|r| is_visible(r, text))).collect();
            let k = self.visible_before(at);
            let vis: Vec<Dot> = run.iter().zip(&shown).filter(|(_, s)| **s).map(|(d, _)| d.clone()).collect();
            self.vis.splice(k..k, vis);
            let parents: Vec<Option<Dot>> = std::iter::once(key).chain(run.iter().take(run.len().saturating_sub(1)).cloned().map(Some)).collect();
            let p = &mut self.p;
            p.parent.splice(at..at, parents);
            p.span.splice(at..at, run.iter().map(|_| 1));
            p.created.splice(at..at, run.iter().map(|_| true));
            p.last.splice(at..at, run.iter().cloned());
            p.order.splice(at..at, run);
            self.shown.splice(at..at, shown);
        }
        if flags.len() > FLAG_SCANS {
            let set: HashSet<&Dot> = flags.iter().collect();
            for (d, sh) in self.p.order.iter().zip(self.shown.iter_mut()) {
                if set.contains(d) {
                    *sh = elems.get(d).is_some_and(|r| is_visible(r, text));
                }
            }
            self.vis = self.p.order.iter().zip(&self.shown).filter(|(_, s)| **s).map(|(d, _)| d.clone()).collect();
            return true;
        }
        for dot in flags {
            let Some(i) = self.p.order.iter().position(|d| *d == dot) else { continue };
            let now = elems.get(&dot).is_some_and(|r| is_visible(r, text));
            let Some(was) = self.shown.get_mut(i) else { return false };
            if *was == now {
                continue;
            }
            *was = now;
            let k = self.visible_before(i);
            if now {
                self.vis.insert(k, dot);
            } else if k < self.vis.len() {
                self.vis.remove(k);
            }
        }
        true
    }

    /// The edge stamp of node `order[at]` if it is a child of `key` (`None`: HEAD): its
    /// greatest position write naming `key` (a demoted edge is the `prev` one, §6.2).
    fn child_stamp(&self, elems: &Elems, at: usize, key: &Option<Dot>) -> Option<Stamp> {
        let c = self.p.order.get(at)?;
        if key.is_some() && self.p.parent.get(at)? != key {
            return None;
        }
        let want = key.clone().map_or(Anchor::Head, Anchor::Dot);
        let e = elem(elems, c)?;
        e.pos.iter().find(|(_, a)| *a == want).map(|(s, _)| s.clone())
    }

    /// Visible nodes before position `i` of the order.
    fn visible_before(&self, i: usize) -> usize {
        self.shown.get(..i).map_or(0, |s| s.iter().filter(|b| **b).count())
    }
}
