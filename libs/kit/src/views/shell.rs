//! The shell's two slots that show more than a nested view: search results and the New chips.

use super::ViewType;
use crate::facets::members::creating as is_creating;
use crate::view::arrange::one;
use crate::view::paged::{Item, Row, Shape, Style, page_of};
use crate::view::search::{Paste, classify, search};
use crate::view::{Block, Cx, QUERY, Section, ViewSpec};
use crate::store::Reader;
use osis::{Result, Tid};
use std::collections::HashMap;

/// The config flag of results shown in the rail.
pub const RAIL: &str = "rail";

/// One row of the results.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Hit {
    Label(&'static str),
    Thing(Tid, Option<String>),
}

impl Row for (usize, Hit) {
    fn key(&self) -> String {
        match &self.1 {
            Hit::Label(l) => format!("label {l}"),
            Hit::Thing(t, _) => format!("{}/{t}", self.0),
        }
    }
}

/// Result rows, and where each key is.
type Hits = (Vec<(usize, Hit)>, HashMap<String, usize>);

/// The results for `q` as rows, with where each key is: built once per query and per change.
fn hits(r: &Reader, (_, q): &(&'static str, String)) -> Result<Hits> {
    let f = search(r, q)?;
    let mut rows = Vec::new();
    let section = |label: &'static str, v: Vec<(Tid, Option<String>)>, rows: &mut Vec<(usize, Hit)>, at: usize| {
        if !v.is_empty() {
            rows.push((at, Hit::Label(label)));
            rows.extend(v.into_iter().map(|(t, s)| (at, Hit::Thing(t, s))));
        }
    };
    section("Scopes", f.scopes.iter().map(|t| (*t, None)).collect(), &mut rows, 0);
    section("Things", f.named.iter().map(|t| (*t, None)).collect(), &mut rows, 1);
    section("Mentions", f.mentions.iter().map(|(t, s)| (*t, Some(s.clone()))).collect(), &mut rows, 2);
    section("In those scopes", f.in_scopes.iter().map(|t| (*t, None)).collect(), &mut rows, 3);
    let index = rows.iter().enumerate().map(|(i, x)| (x.key(), i)).collect();
    Ok((rows, index))
}

fn results(cx: &Cx, spec: &ViewSpec) -> Result<Section> {
    let rail = spec.config.flag(RAIL);
    let query = cx.local(QUERY)?;
    let q = query.trim();
    let mut b = Vec::new();
    if q.is_empty() {
        return Ok(Section::of(b));
    }
    match classify(q) {
        Paste::Link => b.push(Block::Line("Press Enter to open this link.".into())),
        Paste::Peer => b.push(Block::Line("Press Enter to add this peer.".into())),
        Paste::Query => {}
    }
    let found = cx.memo(("hits", q.to_string()), hits)?;
    if found.0.is_empty() && matches!(classify(q), Paste::Query) {
        b.push(Block::Line(format!("Nothing matches “{q}”.")));
    }
    let shape = Shape { cols: if rail { 1 } else { 0 }, ..Shape::new(if rail { Style::Row } else { Style::Card }) };
    b.push(cx.list(
        "results",
        shape,
        |at, n| Ok(page_of(&found.0, |k| found.1.get(k).copied(), at, n)),
        |cx, (_, h): &(usize, Hit)| {
            Ok(match h {
                Hit::Label(l) => Some(Item::Label((*l).to_string())),
                Hit::Thing(t, snip) => one(cx, *t).map(|mut e| {
                    if let Some(s) = snip {
                        e.text = s.clone();
                    }
                    Item::Entry(e)
                }),
            })
        },
    )?);
    Ok(Section::of(b))
}

fn creating(cx: &Cx, _: &ViewSpec) -> Result<Section> {
    let show = is_creating(cx)? && cx.local(QUERY)?.trim().is_empty();
    Ok(Section::of(if show { vec![Block::Chips(cx.offer_chips(None)?)] } else { Vec::new() }))
}

/// What `creating` shows only while New is open.
#[allow(clippy::expect_used)]
fn sample_creating(d: &crate::store::Data) -> osis::Tid {
    let win = d.window().expect("sample: a window");
    let mut w = d.db.write();
    let set = w.at(win, crate::schema::CREATING).path(osis::Path::root().push("shell")).set(&true);
    set.expect("sample: creating");
    w.commit().expect("sample: creating");
    super::sample_main(d)
}

pub static RESULTS: ViewType = ViewType { id: "results", label: "Results", fits: None, parts: &[], always_offered: false, custom: Some(results), sample: super::sample_main, grow: None };
pub static CREATING: ViewType = ViewType { id: "creating", label: "New", fits: None, parts: &[], always_offered: false, custom: Some(creating), sample: sample_creating, grow: None };
