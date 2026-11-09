//! View types (notes/app.md Terms): content views, the opener, the tile. Only this registry
//! lists them; a view type never names another except by the spec it hands a child.

mod chrome;
mod collection;
mod look;
mod note;
mod opener;
mod raw;
mod tile;

pub use opener::open_spec;

use crate::view::{Block, Cx, Placed, Section, ViewSpec, WindowState, source};
use crate::store::Reader;
use osis::{Result, Tid};
use std::rc::Rc;

/// One part of a content view: a facet, shown when it applies or, with `always`, regardless.
#[derive(Clone, Copy, Debug)]
pub struct Part {
    pub facet: &'static str,
    pub always: bool,
}

pub const fn part(facet: &'static str) -> Part {
    Part { facet, always: false }
}
pub const fn always(facet: &'static str) -> Part {
    Part { facet, always: true }
}

/// Code that turns a subject and config into `Block`s.
pub struct ViewType {
    pub id: &'static str,
    pub label: &'static str,
    /// `None`: never selected by fit. Otherwise whether the aspects present fit.
    pub fits: Option<fn(&Reader, Tid) -> Result<bool>>,
    /// The facets a content view assembles (empty for other view types).
    pub parts: &'static [Part],
    /// Offered whenever it fits, even while the thing carries none of its aspects: its fit says the
    /// thing can hold them (a choice not made yet), so an empty view is still the way to make it.
    pub always_offered: bool,
    /// Set for a view type that is not a stack of parts.
    pub custom: Option<fn(&Cx, &ViewSpec) -> Result<Section>>,
}

/// The raw view.
pub use raw::RAW;

/// Kit's view types, in fit-tie order.
pub fn kit() -> [&'static ViewType; 8] {
    [&collection::VIEW, &look::VIEW, &note::VIEW, &RAW, &opener::OPENER, &opener::BAR, &chrome::CHROME, &tile::TILE]
}

/// `view` at `path`, its `Block`s and pinned foot. An unknown view type is empty.
pub fn render(cx: &Cx, path: &str, spec: &ViewSpec) -> Result<Rc<Section>> {
    let (path, spec2, window) = (path.to_string(), spec.clone(), Rc::downgrade(cx.window.inner()));
    cx.memo(("render", path.clone(), spec.clone()), move |r| {
        let Some(window) = window.upgrade().map(WindowState::from) else { return Ok(Section::default()) };
        let cx = Cx::node(r.clone(), window, path.clone(), spec2.config.clone());
        let Some(v) = cx.registry.view(&spec2.view_type) else { return Ok(Section::default()) };
        if let Some(f) = v.custom {
            return f(&cx, &spec2);
        }
        let mut out = Section::default();
        for p in v.parts {
            let Some(f) = cx.registry.facet(p.facet) else { continue };
            if p.always || f.applies(&cx, spec2.subject)? {
                let s = f.show(&cx, spec2.subject)?;
                out.blocks.extend(s.blocks);
                out.foot.extend(s.foot);
                out.follow_end |= s.follow_end;
            }
        }
        Ok(out)
    })
}

/// A node of the tree, its children expanded: what a test reads.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub path: String,
    pub spec: ViewSpec,
    pub out: Section,
    pub children: Vec<Node>,
}

/// The child path of `key` under `path`.
pub fn child_path(path: &str, key: &str) -> String {
    format!("{path}/{key}")
}

/// The child views a node's blocks name.
pub fn child_specs(blocks: &[Block]) -> Vec<(String, ViewSpec, bool)> {
    let mut out = Vec::new();
    for b in blocks {
        match b {
            Block::View { key, spec } => out.push((key.clone(), spec.clone(), false)),
            Block::Filled { key, spec, below, .. } => {
                out.push((key.clone(), spec.clone(), true));
                out.extend(child_specs(below));
            }
            Block::Entries(Placed::Views { views, .. }) => out.extend(views.iter().map(|(k, s)| (k.clone(), s.clone(), false))),
            _ => {}
        }
    }
    out
}

/// `spec` at `path` and everything below it.
pub fn expand(cx: &Cx, path: &str, spec: &ViewSpec) -> Result<Node> {
    let out = (*render(cx, path, spec)?).clone();
    let mut children = Vec::new();
    for (key, s, _) in child_specs(&out.blocks) {
        children.push(expand(cx, &child_path(path, &key), &s)?);
    }
    Ok(Node { path: path.to_string(), spec: spec.clone(), out, children })
}

impl Node {
    /// This node and every descendant, depth first.
    pub fn walk(&self) -> Vec<&Node> {
        let mut v = vec![self];
        for c in &self.children {
            v.extend(c.walk());
        }
        v
    }
    /// The first node of this view type.
    pub fn find(&self, view_type: &str) -> Option<&Node> {
        self.walk().into_iter().find(|n| n.spec.view_type == view_type)
    }
    /// Every block in the tree.
    pub fn blocks(&self) -> Vec<&Block> {
        self.walk().into_iter().flat_map(|n| n.out.blocks.iter()).collect()
    }
}

/// The main colour of `t`'s page.
pub fn main_color(cx: &Reader, t: Tid) -> Result<Option<String>> {
    source::main_color(cx, t)
}

/// `t` opened: the opener's tree (`Summary`'s words beside it for a test).
pub fn page(cx: &Cx, t: Tid) -> Result<Node> {
    expand(cx, &format!("page:{t}"), &open_spec(t))
}

