//! The shell's two slots that show more than a nested view: search results and the New chips.

use super::ViewType;
use crate::facets::members::creating as is_creating;
use crate::view::arrange;
use crate::view::search::{Paste, classify, search};
use crate::view::{Block, Cx, Entry, Placed, QUERY, Run, Section, ViewSpec};
use osis::Result;

/// The config flag of results shown in the rail.
pub const RAIL: &str = "rail";

fn results(cx: &Cx, spec: &ViewSpec) -> Result<Section> {
    let rail = spec.config.flag(RAIL);
    let query = cx.local(QUERY)?;
    let q = query.trim();
    let cols = if rail { 1 } else { 0 };
    let run = |es: Vec<Entry>| {
        let r = Run { entries: es, cols, ..Run::default() };
        Block::Entries(if rail { Placed::Rows(r) } else { Placed::Cards(r) })
    };
    let mut b = Vec::new();
    if q.is_empty() {
        return Ok(Section::of(b));
    }
    match classify(q) {
        Paste::Link => b.push(Block::Line("Press Enter to open this link.".into())),
        Paste::Peer => b.push(Block::Line("Press Enter to add this peer.".into())),
        Paste::Query => {}
    }
    let f = search(cx, q)?;
    if f.is_empty() && matches!(classify(q), Paste::Query) {
        b.push(Block::Line(format!("Nothing matches “{q}”.")));
    }
    for (label, v) in [("Scopes", &f.scopes), ("Things", &f.named)] {
        if !v.is_empty() {
            b.push(Block::Label(label.into()));
            b.push(run(arrange::one_each(cx, v)));
        }
    }
    if !f.mentions.is_empty() {
        b.push(Block::Label("Mentions".into()));
        let mut es = Vec::new();
        for (t, snip) in &f.mentions {
            let mut e = arrange::one_each(cx, &[*t]);
            if let Some(x) = e.first_mut() {
                x.text = snip.clone();
            }
            es.extend(e);
        }
        b.push(run(es));
    }
    if !f.in_scopes.is_empty() {
        b.push(Block::Label("In those scopes".into()));
        b.push(run(arrange::one_each(cx, &f.in_scopes)));
    }
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

pub static RESULTS: ViewType = ViewType { id: "results", label: "Results", fits: None, parts: &[], always_offered: false, custom: Some(results), sample: super::sample_main };
pub static CREATING: ViewType = ViewType { id: "creating", label: "New", fits: None, parts: &[], always_offered: false, custom: Some(creating), sample: sample_creating };
