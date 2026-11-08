use super::{Part, ViewType, always};
use crate::view::Cx;
use osis::{Result, Tid};

fn fits(cx: &Cx<'_>, t: Tid) -> Result<bool> {
    cx.applies("members", t)
}

const PARTS: &[Part] = &[always("name"), always("members")];

pub static VIEW: ViewType = ViewType { id: "collection", label: "Collection", fits: Some(fits), parts: PARTS, always_offered: false, custom: None };
