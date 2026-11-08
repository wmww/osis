use super::{Part, ViewType, always};
use crate::view::Cx;
use osis::{Result, Tid};

fn fits(cx: &Cx<'_>, t: Tid) -> Result<bool> {
    Ok(cx.applies("body", t)? || cx.applies("name", t)? || cx.aspects(t)?.is_empty())
}

const PARTS: &[Part] = &[always("name"), always("body")];

pub static VIEW: ViewType = ViewType { id: "note", label: "Note", fits: Some(fits), parts: PARTS, custom: None };
