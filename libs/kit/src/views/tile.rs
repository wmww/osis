//! The tile: a thing from its summary.

use super::ViewType;
use crate::view::paged::{Shape, Style, page_of};
use crate::view::{Cx, Entry, Section, ViewSpec};
use osis::Result;

fn tile(cx: &Cx, spec: &ViewSpec) -> Result<Section> {
    let e = Entry::of(spec.subject, &cx.summary(spec.subject)?);
    let shape = Shape { cols: 1, ..Shape::new(Style::Row) };
    let one = [spec.subject];
    Ok(Section::of(vec![cx.list("tile", shape, |at, n| Ok(page_of(&one, |_| Some(0), at, n)), |_, _: &osis::Tid| Ok(Some(e.clone())))?]))
}

pub static TILE: ViewType = ViewType { id: "tile", label: "Tile", fits: None, parts: &[], always_offered: false, custom: Some(tile), sample: super::sample_note, grow: None };
