//! View types (notes/app.md Terms): content views, the opener, the tile. Only this registry
//! lists them; a view type never names another except by the spec it hands a child.

mod chrome;
mod collection;
mod look;
mod note;
mod opener;
mod raw;
mod shell;
mod tile;

pub use opener::open_spec;
pub use shell::RAIL;

use crate::view::graph::{Graph, NodeId};
use crate::view::{Block, Cx, Placed, Section, ViewSpec, source};
use crate::store::{Data, Reader};
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
    /// A subject the cost harness shows this view with (usually one line through an `Offer`), so a
    /// view without one does not compile (notes/fast-design.md).
    pub sample: fn(&Data) -> Tid,
}

/// A new thing through the offer `id`, for a `sample` (`sample` has no error; a sample is only ever
/// run by the harness, where a panic names the failure).
#[allow(clippy::expect_used)]
pub fn sample_offer(d: &Data, id: &str) -> Tid {
    crate::facets::create(d, id).expect("sample: an offer that does not work")
}

/// A named note with a body, for a `sample`.
#[allow(clippy::expect_used)]
pub fn sample_note(d: &Data) -> Tid {
    let t = sample_offer(d, "note");
    let mut w = d.db.write();
    let set = w.at(t, osis::core::NAME).set(&"A note".to_string()).and_then(|()| w.at(t, osis::core::BODY).set(&"Text".to_string()));
    set.expect("sample: a note");
    w.commit().expect("sample: a note");
    t
}

/// A tag holding two notes, for a `sample`.
#[allow(clippy::expect_used)]
pub fn sample_collection(d: &Data) -> Tid {
    let tag = sample_offer(d, "tag");
    for _ in 0..2 {
        d.add_tag(sample_note(d), tag).expect("sample: an item");
    }
    tag
}

/// An account group, for a `sample`: what kit's views of the account show.
#[allow(clippy::expect_used)]
pub fn sample_main(d: &Data) -> Tid {
    d.main_group().expect("sample: an account group")
}

/// The raw view.
pub use raw::RAW;

/// Kit's view types, in fit-tie order.
pub fn kit() -> [&'static ViewType; 10] {
    [&collection::VIEW, &look::VIEW, &note::VIEW, &RAW, &opener::OPENER, &opener::BAR, &chrome::CHROME, &tile::TILE, &shell::RESULTS, &shell::CREATING]
}

type RenderKey = (&'static str, String, ViewSpec);

fn render_key(path: &str, spec: &ViewSpec) -> RenderKey {
    ("render", path.to_string(), spec.clone())
}

fn compute(r: &Reader, (_, path, spec): &RenderKey) -> Result<Section> {
    let Some(window) = r.window_state() else { return Ok(Section::default()) };
    window.graph.add_render();
    let cx = Cx::node(r.clone(), window, path.clone(), spec.config.clone());
    let Some(v) = cx.registry.view(&spec.view_type) else { return Ok(Section::default()) };
    if let Some(f) = v.custom {
        return f(&cx, spec);
    }
    let mut out = Section::default();
    for p in v.parts {
        let Some(f) = cx.registry.facet(p.facet) else { continue };
        if p.always || f.applies(&cx, spec.subject)? {
            let s = f.show(&cx, spec.subject)?;
            out.blocks.extend(s.blocks);
            out.foot.extend(s.foot);
            out.follow_end |= s.follow_end;
        }
    }
    Ok(out)
}

/// `view` at `path`, its `Block`s and pinned foot. An unknown view type is empty.
pub fn render(cx: &Reader, path: &str, spec: &ViewSpec) -> Result<Rc<Section>> {
    cx.memo(render_key(path, spec), compute)
}

/// `spec` at `path` as a node on screen, for the tree to ask (`Graph::shown`).
pub(crate) fn mount(graph: &Rc<Graph>, path: &str, spec: &ViewSpec) -> NodeId {
    let k = render_key(path, spec);
    Graph::mount(graph, k.clone(), move |r| compute(r, &k))
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

