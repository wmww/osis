//! The views on screen (notes/fast-design.md): a tree of nodes, each a graph node. A change runs the
//! marked nodes only, parents first; a parent that came out different reconciles its children,
//! and what is not marked does not run. Toolkit-free: the shell is a `Surface`.

use crate::view::graph::{Graph, NodeId, Shown};
use crate::view::{NodePath, Section, ViewSpec, WindowState};
use crate::views::{child_path, child_specs, shown};
use osis::Result;
use std::collections::HashMap;

/// Where the tree's nodes appear.
pub trait Surface {
    /// The view at `path` shows `out`. Returns whether its place was rebuilt, so that its
    /// children's are new.
    fn show(&mut self, path: &str, out: &Section) -> Result<bool>;
    /// The view at `path` left the tree.
    fn gone(&mut self, path: &str);
}

struct Node {
    id: NodeId,
    /// `Shown::seq` when the surface last got this node.
    seq: u64,
    spec: ViewSpec,
    depth: usize,
    children: Vec<NodePath>,
}

/// What the window's views are.
#[derive(Default)]
pub struct Tree {
    nodes: HashMap<NodePath, Node>,
    by_id: HashMap<NodeId, NodePath>,
}

impl Tree {
    /// Puts `spec` at `path` as a root (its children follow), or brings it up to date.
    pub fn show(&mut self, window: &WindowState, surface: &mut impl Surface, path: &str, spec: &ViewSpec) -> Result<()> {
        self.visit(window, surface, path, spec, 0, true)
    }

    /// Takes every node off.
    pub fn clear(&mut self, window: &WindowState, surface: &mut impl Surface) {
        for (path, n) in self.nodes.drain() {
            window.graph.hide(n.id);
            surface.gone(&path);
        }
        self.by_id.clear();
        window.graph.collect();
    }

    /// Runs what was marked since the last call, parents first. A failing node leaves the others
    /// updated and fails the call.
    pub fn update(&mut self, window: &WindowState, surface: &mut impl Surface) -> Result<()> {
        Graph::drain(&window.graph);
        let mut todo: Vec<(usize, NodePath, ViewSpec)> = Vec::new();
        for id in window.graph.take_pending() {
            if let Some(p) = self.by_id.get(&id)
                && let Some(n) = self.nodes.get(p)
            {
                todo.push((n.depth, p.clone(), n.spec.clone()));
            }
        }
        todo.sort_by_key(|t| t.0);
        let mut failed = None;
        for (depth, path, spec) in todo {
            // a parent's reconcile may have taken it
            if !self.nodes.contains_key(&path) {
                continue;
            }
            if let Err(e) = self.visit(window, surface, &path, &spec, depth, false) {
                failed.get_or_insert(e);
            }
        }
        window.graph.collect();
        failed.map_or(Ok(()), Err)
    }

    /// `spec` at `path`: asked of the graph, given to the surface when `force` or it came out
    /// different; where the surface rebuilt it, its children are reconciled the same way.
    fn visit(&mut self, window: &WindowState, surface: &mut impl Surface, path: &str, spec: &ViewSpec, depth: usize, force: bool) -> Result<()> {
        let Shown { id, seq, value } = shown(&window.graph, path, spec)?;
        let old = self.nodes.get(path);
        if !force && old.is_some_and(|n| n.seq == seq && n.id == id) {
            return Ok(());
        }
        if let Some(n) = old
            && n.id != id
        {
            window.graph.hide(n.id);
            self.by_id.remove(&n.id);
        }
        let rebuilt = surface.show(path, &value)?;
        let kept = self.nodes.remove(path);
        let mut children = kept.map(|n| n.children).unwrap_or_default();
        if rebuilt || force {
            let mut new = Vec::new();
            let blocks: Vec<_> = value.blocks.iter().chain(value.foot.iter()).cloned().collect();
            for (key, child, _) in child_specs(&blocks) {
                new.push((child_path(path, &key), child));
            }
            let mine: std::collections::HashSet<&NodePath> = new.iter().map(|(p, _)| p).collect();
            for c in children.iter().filter(|c| !mine.contains(c)) {
                self.remove(window, surface, c);
            }
            children = new.iter().map(|(p, _)| p.clone()).collect();
            self.nodes.insert(path.to_string(), Node { id, seq, spec: spec.clone(), depth, children });
            self.by_id.insert(id, path.to_string());
            for (p, c) in new {
                self.visit(window, surface, &p, &c, depth + 1, true)?;
            }
            return Ok(());
        }
        self.nodes.insert(path.to_string(), Node { id, seq, spec: spec.clone(), depth, children });
        self.by_id.insert(id, path.to_string());
        Ok(())
    }

    fn remove(&mut self, window: &WindowState, surface: &mut impl Surface, path: &str) {
        let Some(n) = self.nodes.remove(path) else { return };
        window.graph.hide(n.id);
        self.by_id.remove(&n.id);
        surface.gone(path);
        for c in n.children {
            self.remove(window, surface, &c);
        }
    }
}
