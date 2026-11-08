use super::{Part, ViewType, always, part};
use crate::view::Cx;
use osis::{Result, Tid};

fn fits(cx: &Cx<'_>, t: Tid) -> Result<bool> {
    cx.applies("members", t)
}

const PARTS: &[Part] = &[always("name"), always("members"), part("look")];

pub static VIEW: ViewType = ViewType { id: "collection", label: "Collection", fits: Some(fits), parts: PARTS, custom: None };
