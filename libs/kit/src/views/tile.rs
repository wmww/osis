//! The tile: a thing from its summary.

use super::ViewType;
use crate::view::{Block, Cx, Entry, Placed, Run, Section, ViewSpec};
use osis::Result;

fn tile(cx: &Cx<'_>, spec: &ViewSpec) -> Result<Section> {
    let e = Entry::of(spec.subject, &cx.summary(spec.subject)?);
    Ok(Section::of(vec![Block::Entries(Placed::Rows(Run { entries: vec![e], cols: 1, ..Run::default() }))]))
}

pub static TILE: ViewType = ViewType { id: "tile", label: "Tile", fits: None, parts: &[], custom: Some(tile) };
