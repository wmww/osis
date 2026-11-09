//! The views on screen (notes/fast-design.md): a tree of nodes, each a graph node. A change runs the
//! marked nodes only, parents first; a parent that came out different reconciles its children,
//! and what is not marked does not run. Toolkit-free: the shell is a `Surface`.

use crate::view::graph::{Graph, NodeId, Shown};
use crate::view::{NodePath, Section, ViewSpec, WindowState};
use crate::views::{child_path, child_specs, mount};
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
    /// `Shown::seq` when the surface last got this node; 0 (never a node's seq) when it has nothing.
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

    /// Takes every node off. What left is freed by the next `update`, unless asked for again by then.
    pub fn clear(&mut self, window: &WindowState, surface: &mut impl Surface) {
        for (path, n) in self.nodes.drain() {
            window.graph.hide(n.id);
            surface.gone(&path);
        }
        self.by_id.clear();
    }

    /// Runs what was marked since the last call, parents first. A failing node leaves the others
    /// updated and fails the call.
    pub fn update(&mut self, window: &WindowState, surface: &mut impl Surface) -> Result<()> {
        Graph::drain(&window.graph);
        let mut todo: Vec<(usize, NodeId, NodePath)> = Vec::new();
        for id in window.graph.take_pending() {
            if let Some(p) = self.by_id.get(&id)
                && let Some(n) = self.nodes.get(p)
            {
                todo.push((n.depth, id, p.clone()));
            }
        }
        todo.sort_by_key(|t| t.0);
        let mut failed = None;
        for (depth, id, path) in todo {
            // a parent's reconcile may have taken it, or put another spec in its place
            let Some(spec) = self.nodes.get(&path).filter(|n| n.id == id).map(|n| n.spec.clone()) else { continue };
            if let Err(e) = self.visit(window, surface, &path, &spec, depth, false) {
                failed.get_or_insert(e);
            }
        }
        window.graph.collect();
        failed.map_or(Ok(()), Err)
    }

    /// `spec` at `path`: asked of the graph, given to the surface when `force` or it came out
    /// different; where the surface rebuilt it, its children are reconciled the same way. A node
    /// that fails stays in the tree, with nothing shown if its place was new, so that the read
    /// that recovers marks it.
    fn visit(&mut self, window: &WindowState, surface: &mut impl Surface, path: &str, spec: &ViewSpec, depth: usize, force: bool) -> Result<()> {
        let id = mount(&window.graph, path, spec);
        let (seen, children) = match self.nodes.remove(path) {
            Some(n) if n.id == id => (n.seq, n.children),
            Some(n) => {
                window.graph.hide(n.id);
                self.by_id.remove(&n.id);
                (0, n.children)
            }
            None => (0, Vec::new()),
        };
        self.nodes.insert(path.to_string(), Node { id, seq: seen, spec: spec.clone(), depth, children: children.clone() });
        self.by_id.insert(id, path.to_string());
        let Shown { seq, value, .. } = match Graph::shown::<Section>(&window.graph, id) {
            Ok(s) => s,
            Err(e) => {
                if force && let Some(n) = self.nodes.get_mut(path) {
                    n.seq = 0;
                }
                return Err(e);
            }
        };
        if !force && seen == seq {
            return Ok(());
        }
        let rebuilt = surface.show(path, &value)?;
        if let Some(n) = self.nodes.get_mut(path) {
            n.seq = seq;
        }
        if !rebuilt && !force {
            return Ok(());
        }
        let blocks: Vec<_> = value.blocks.iter().chain(value.foot.iter()).cloned().collect();
        let new: Vec<(NodePath, ViewSpec)> = child_specs(&blocks).into_iter().map(|(key, child, _)| (child_path(path, &key), child)).collect();
        let mine: std::collections::HashSet<&NodePath> = new.iter().map(|(p, _)| p).collect();
        for c in children.iter().filter(|c| !mine.contains(c)) {
            self.remove(window, surface, c);
        }
        if let Some(n) = self.nodes.get_mut(path) {
            n.children = new.iter().map(|(p, _)| p.clone()).collect();
        }
        let mut failed = None;
        for (p, c) in new {
            if let Err(e) = self.visit(window, surface, &p, &c, depth + 1, true) {
                failed.get_or_insert(e);
            }
        }
        failed.map_or(Ok(()), Err)
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
